/*
 * local_udp_process.c
 */

#define _GNU_SOURCE

#include <pthread.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>

#include "netdev.h"
#include "util.h"
#include "dns-conf.h"
#include "kdns.h"
#include "forward.h"
#include "view_update.h"
#include "db_update.h"
#include "query.h"
#include "kdns-adap.h"
#include "local_udp_process.h"

extern domain_fwd_addrs_ctrl g_fwd_addrs_ctrl;

rte_rwlock_t local_udp_lock;
struct kdns local_udp_kdns;
static struct query *local_udp_query;

static int local_udp_process_query(char *snd_buf, ssize_t snd_len, char *rvc_buf, ssize_t rcv_len, dns_addr_t *id_addr, int timeout) {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd == -1) {
        log_msg(LOG_ERR, "local_udp_process_query sock errno=%d, errinfo=%s\n", errno, strerror(errno));
        return -1;
    }

    struct timeval tv = {timeout, 0};
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        log_msg(LOG_ERR, "local_udp_process_query socket option SO_RCVTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }
    if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        log_msg(LOG_ERR, "local_udp_process_query socket option SO_SNDTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    int ret = sendto(sock_fd, snd_buf, snd_len, 0, &id_addr->addr, id_addr->addrlen);
    if (ret <= 0) {
        log_msg(LOG_ERR, "local_udp_process_query send errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    struct sockaddr src_addr;
    socklen_t src_len = sizeof(struct sockaddr);
    ret = recvfrom(sock_fd, rvc_buf, rcv_len, 0, &src_addr, &src_len);
    if (ret <= 0) {
        log_msg(LOG_ERR, "local_udp_process_query recvfrom errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    close(sock_fd);
    return ret;
}

static int local_udp_process_forward(int sfd, char *buf, int buf_len, struct sockaddr_in *caddr, uint16_t id, uint16_t qtype, char *domain) {
    (void)id;
    int i = 0;
    int rlen = 0;
    int fwd_mode;
    int fwd_timeout;
    int servers_len;
    dns_addr_t server_addrs[FWD_MAX_ADDRS];
    char recv_buf[EDNS_MAX_MESSAGE_LEN];

    pthread_rwlock_rdlock(&__fwd_lock);
    fwd_mode = g_fwd_addrs_ctrl.mode;
    fwd_timeout = g_fwd_addrs_ctrl.timeout;
    domain_fwd_addrs *fwd_addrs = fwd_addrs_find(domain, &g_fwd_addrs_ctrl);
    servers_len = fwd_addrs->servers_len;
    memcpy(&server_addrs, &fwd_addrs->server_addrs, sizeof(fwd_addrs->server_addrs));
    pthread_rwlock_unlock(&__fwd_lock);

    if (fwd_mode == FWD_MODE_DISABLE) {
        return 0;
    }

    for (; i < servers_len; ++i) {
        rlen = local_udp_process_query(buf, buf_len, recv_buf, sizeof(recv_buf), &server_addrs[i], fwd_timeout);
        if (rlen > 0) {
            break;
        }

        char ip_src_str[INET_ADDRSTRLEN] = {0};
        char ip_dst_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &caddr->sin_addr, ip_src_str, sizeof(ip_src_str));
        inet_ntop(AF_INET, &((struct sockaddr_in *)&server_addrs[i].addr)->sin_addr, ip_dst_str, sizeof(ip_dst_str));
        log_msg(LOG_ERR, "Failed to send udp request: %s, type %d, to %s, from: %s, trycnt: %d\n",
                domain, qtype, ip_dst_str, ip_src_str, i);
    }

    if (rlen > 0) {
        if (sendto(sfd, recv_buf, rlen, 0, (struct sockaddr *)caddr, sizeof(struct sockaddr)) == -1) {
            log_msg(LOG_ERR, "Failed to send udp response: %s, type %d, to %s\n", domain, qtype, inet_ntoa(caddr->sin_addr));
            return -1;
        }
    }
    return 0;
}

static void *thread_local_udp_process(void *arg) {
    char *ip = (char *)arg;
    int sfd, rlen, slen;
    socklen_t addr_len;
    uint16_t flags_old;
    struct sockaddr_in saddr, caddr;
    char buf[EDNS_MAX_MESSAGE_LEN];

    sleep(30);

    sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sfd < 0) {
        log_msg(LOG_ERR, "Failed to create udp socket, errno=%d, errinfo=%s\n", errno, strerror(errno));
        exit(1);
    }

    bzero(&saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(ip);
    saddr.sin_port = htons(53);
    if (bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        log_msg(LOG_ERR, "Failed to bind udp, ip %s, errno=%d, errinfo=%s\n", ip, errno, strerror(errno));
        exit(1);
    }

    log_msg(LOG_INFO, "Accepting local udp querys, form %s...\n", ip);
    while (1) {
        addr_len = sizeof(struct sockaddr);
        rlen = recvfrom(sfd, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&caddr, &addr_len);

        /*
        * Minimum query size is:
        *
        *     Size of the header (12)
        *   + Root domain name   (1)
        *   + Query class        (2)
        *   + Query type         (2)
        */
        if (rlen <= 0 || (uint16_t)rlen < DNS_HEAD_SIZE + 1 + sizeof(uint16_t) + sizeof(uint16_t)) {
            log_msg(LOG_ERR, "local query from %s packet size %d illegal, drop\n", inet_ntoa(caddr.sin_addr), rlen);
            continue;
        }

        query_reset(local_udp_query);
        local_udp_query->sip = *(uint32_t *)&caddr.sin_addr;
        local_udp_query->maxMsgLen = sizeof(buf);
        local_udp_query->packet->data = (uint8_t *)buf;
        local_udp_query->packet->position += rlen;
        buffer_flip(local_udp_query->packet);

        memcpy(&flags_old, local_udp_query->packet->data + 2, 2);

        view_query_master_process(local_udp_query);
        rte_rwlock_read_lock(&local_udp_lock);
        if (query_process(local_udp_query, &local_udp_kdns) != QUERY_FAIL) {
            buffer_flip(local_udp_query->packet);
        }
        rte_rwlock_read_unlock(&local_udp_lock);

        if (GET_RCODE(local_udp_query->packet) == RCODE_REFUSE) {
            memcpy(buf + 2, &flags_old, 2);
            local_udp_process_forward(sfd, buf, rlen, &caddr, GET_ID(local_udp_query->packet), local_udp_query->qtype,
                                      (char *)domain_name_to_string(local_udp_query->qname, NULL));
            continue;
        }

        slen = buffer_remaining(local_udp_query->packet);
        if (slen > 0) {
            if (sendto(sfd, buf, slen, 0, (struct sockaddr *)&caddr, sizeof(struct sockaddr)) == -1) {
                log_msg(LOG_ERR, "response query %s to %s, send error, errno=%d, errinfo=%s\n",
                        (char *)domain_name_to_string(local_udp_query->qname, NULL), inet_ntoa(caddr.sin_addr), errno, strerror(errno));
            }
        }
    }
}

int local_udp_process_init(char *ip) {
    rte_rwlock_init(&local_udp_lock);
    kdns_prepare_init(&local_udp_kdns, &local_udp_query);

    pthread_t *thread_id = (pthread_t *)xalloc(sizeof(pthread_t));
    pthread_create(thread_id, NULL, thread_local_udp_process, (void *)ip);
    pthread_setname_np(*thread_id, "kdns_local_proc");
    return 0;
}

int local_udp_domian_databd_update(struct domin_info_update *update) {
    rte_rwlock_write_lock(&local_udp_lock);
    int ret = domaindata_update(local_udp_kdns.db, update);
    rte_rwlock_write_unlock(&local_udp_lock);
    return ret;
}

