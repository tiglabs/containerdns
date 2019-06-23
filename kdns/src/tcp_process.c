/*
 * tcp+process.c 
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
#include "tcp_process.h"

extern domain_fwd_addrs_ctrl g_fwd_addrs_ctrl;

rte_rwlock_t tcp_lock;
struct kdns tcp_kdns;
static struct query *tcp_query;
struct netif_queue_stats tcp_stats;

void tcp_statsdata_get(struct netif_queue_stats *sta) {
    sta->dns_fwd_rcv_tcp = tcp_stats.dns_fwd_rcv_tcp;
    sta->dns_fwd_snd_tcp = tcp_stats.dns_fwd_snd_tcp;
    sta->dns_fwd_lost_tcp = tcp_stats.dns_fwd_lost_tcp;
    sta->dns_pkts_rcv_tcp = tcp_stats.dns_pkts_rcv_tcp;
    sta->dns_pkts_snd_tcp = tcp_stats.dns_pkts_snd_tcp;
}

void tcp_statsdata_reset(void) {
    memset(&tcp_stats, 0, sizeof(tcp_stats));
}

int tcp_domian_databd_update(struct domin_info_update *update) {
    rte_rwlock_write_lock(&tcp_lock);
    int ret = domaindata_update(tcp_kdns.db, update);
    rte_rwlock_write_unlock(&tcp_lock);
    return ret;
}

static int tcp_process_query(char *snd_buf, ssize_t snd_len, char *rvc_buf, ssize_t rcv_len, dns_addr_t *id_addr, int timeout) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1) {
        log_msg(LOG_ERR, "tcp_process_query sock errno=%d, errinfo=%s\n", errno, strerror(errno));
        return -1;
    }

    struct timeval tv = {timeout, 0};
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        log_msg(LOG_ERR, "tcp_process_query socket option SO_RCVTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }
    if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        log_msg(LOG_ERR, "tcp_process_query socket option SO_SNDTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    int ret = connect(sock_fd, &id_addr->addr, id_addr->addrlen);
    if (-1 == ret) {
        log_msg(LOG_ERR, "tcp_process_query connect errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    ret = send(sock_fd, snd_buf, snd_len, 0);
    if (ret <= 0) {
        log_msg(LOG_ERR, "tcp_process_query send errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    ret = recv(sock_fd, rvc_buf, rcv_len, 0);
    if (ret <= 0) {
        log_msg(LOG_ERR, "tcp_process_query recv errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }
    close(sock_fd);
    return ret;
}

static int tcp_process_forward(int sfd, char *buf, int buf_len, struct sockaddr_in *caddr, uint16_t id, uint16_t qtype, char *domain) {
    (void)id;
    int i = 0;
    int rlen = 0;
    int fwd_mode;
    int fwd_timeout;
    int servers_len;
    dns_addr_t server_addrs[FWD_MAX_ADDRS];
    char recv_buf[TCP_MAX_MESSAGE_LEN];

    pthread_rwlock_rdlock(&__fwd_lock);
    fwd_mode = g_fwd_addrs_ctrl.mode;
    fwd_timeout = g_fwd_addrs_ctrl.timeout;
    domain_fwd_addrs *fwd_addrs = fwd_addrs_find(domain, &g_fwd_addrs_ctrl);
    servers_len = fwd_addrs->servers_len;
    memcpy(&server_addrs, &fwd_addrs->server_addrs, sizeof(fwd_addrs->server_addrs));
    pthread_rwlock_unlock(&__fwd_lock);

    tcp_stats.dns_fwd_rcv_tcp++;
    if (fwd_mode == FWD_MODE_DISABLE) {
        tcp_stats.dns_fwd_lost_tcp++;
        return 0;
    }

    for (; i < servers_len; i++) {
        rlen = tcp_process_query(buf, buf_len, recv_buf, sizeof(recv_buf), &server_addrs[i], fwd_timeout);
        if (rlen > 0) {
            break;
        }

        char ip_src_str[INET_ADDRSTRLEN] = {0};
        char ip_dst_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &caddr->sin_addr, ip_src_str, sizeof(ip_src_str));
        inet_ntop(AF_INET, &((struct sockaddr_in *)&server_addrs[i].addr)->sin_addr, ip_dst_str, sizeof(ip_dst_str));
        log_msg(LOG_ERR, "Failed to send tcp request: %s, type %d, to %s, from: %s, trycnt: %d\n",
                domain, qtype, ip_dst_str, ip_src_str, i);
        tcp_stats.dns_fwd_lost_tcp++;
    }

    if (rlen > 0) {
        if (send(sfd, recv_buf, rlen, 0) == -1) {
            tcp_stats.dns_fwd_lost_tcp++;
            log_msg(LOG_ERR, "Failed to send tcp response: %s, type %d, to %s\n", domain, qtype, inet_ntoa(caddr->sin_addr));
            return -1;
        }
        tcp_stats.dns_fwd_snd_tcp++;
    }
    return 0;
}

static int tcp_recv(int fd, char *buf, int len) {
    int bytes_transmitted = 0;
    while (bytes_transmitted < len) {
        int recv_len = recv(fd, buf + bytes_transmitted, len - bytes_transmitted, 0);
        if (recv_len == -1) {
            log_msg(LOG_ERR, "call recv len %d error, ret=%d, errno=%d, errinfo=%s\n", len, recv_len, errno, strerror(errno));
            return -1;
        } else if (recv_len == 0) {
            /* EOF */
            return 0;
        }

        bytes_transmitted += recv_len;
    }
    return bytes_transmitted;
}

static void *thread_tcp_process(void *arg) {
    char *ip = (char *)arg;
    int sfd, cfd, slen;
    socklen_t addr_len;
    uint16_t flags_old;
    struct sockaddr_in saddr, caddr;
    char buf[TCP_MAX_MESSAGE_LEN];

    sleep(30);

    sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sfd < 0) {
        log_msg(LOG_ERR, "Failed to create tcp socket, errno=%d, errinfo=%s\n", errno, strerror(errno));
        exit(1);
    }

    bzero(&saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(ip);;
    saddr.sin_port = htons(53);
    if (bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        log_msg(LOG_ERR, "Failed to bind tcp, ip %s, errno=%d, errinfo=%s\n", ip, errno, strerror(errno));
        exit(1);
    }

    if (listen(sfd, 100) == -1) {
        log_msg(LOG_ERR, "Failed to listen, ip %s, errno=%d, errinfo=%s\n", ip, errno, strerror(errno));
        exit(1);
    }

    log_msg(LOG_INFO, "Accepting tcp querys, form %s...\n", ip);
    while (1) {
        addr_len = sizeof(struct sockaddr);
        cfd = accept(sfd, (struct sockaddr *)&caddr, &addr_len);
        if (cfd == -1) {
            log_msg(LOG_ERR, "Failed to accept, ip %s, errno=%d, errinfo=%s\n", ip, errno, strerror(errno));
            continue;
        }
        struct timeval tv = {2, 0};
        if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            log_msg(LOG_ERR, "set socket option SO_RCVTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
            close(cfd);
            continue;
        }
        if (setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
            log_msg(LOG_ERR, "set socket option SO_SNDTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
            close(cfd);
            continue;
        }
        while (1) {
            int bytes_transmitted = 0;
            bytes_transmitted = tcp_recv(cfd, buf, 2);  //recv query len first
            if (bytes_transmitted != 2) {
                if (bytes_transmitted < 0) {
                    log_msg(LOG_ERR, "failed recv len %d from %s\n", 2, inet_ntoa(caddr.sin_addr));
                }
                close(cfd);
                break;
            }

            /*
             * Minimum query size is:
             *
             *     Size of the header (12)
             *   + Root domain name   (1)
             *   + Query class        (2)
             *   + Query type         (2)
             */
            uint16_t tcp_query_len = 0;
            memcpy(&tcp_query_len, buf, 2);
            tcp_query_len = ntohs(tcp_query_len);
            if (tcp_query_len < DNS_HEAD_SIZE + 1 + sizeof(uint16_t) + sizeof(uint16_t)) {
                log_msg(LOG_ERR, "tcp query from %s packet size %d illegal, drop\n", inet_ntoa(caddr.sin_addr), tcp_query_len);
                close(cfd);
                break;
            }

            bytes_transmitted = tcp_recv(cfd, buf + 2, tcp_query_len);
            if (bytes_transmitted != tcp_query_len) {
                if (bytes_transmitted < 0) {
                    log_msg(LOG_ERR, "failed recv len %d from %s\n", tcp_query_len, inet_ntoa(caddr.sin_addr));
                }
                close(cfd);
                break;
            }

            query_reset(tcp_query);
            tcp_query->sip = *(uint32_t *)&caddr.sin_addr;
            tcp_query->maxMsgLen = sizeof(buf);
            tcp_query->packet->data = (uint8_t *)(buf + 2);  //skip len
            tcp_query->packet->position += 2 + tcp_query_len;
            buffer_flip(tcp_query->packet);

            memcpy(&flags_old, tcp_query->packet->data + 2, 2);

            view_query_process(tcp_query);
            rte_rwlock_read_lock(&tcp_lock);
            if (query_process(tcp_query, &tcp_kdns) != QUERY_FAIL) {
                buffer_flip(tcp_query->packet);
            }
            rte_rwlock_read_unlock(&tcp_lock);

            if (GET_RCODE(tcp_query->packet) == RCODE_REFUSE) {
                memcpy((buf + 2) + 2, &flags_old, 2);
                tcp_process_forward(cfd, buf, tcp_query_len + 2, &caddr, GET_ID(tcp_query->packet), tcp_query->qtype,
                                    (char *)domain_name_to_string(tcp_query->qname, NULL));
                continue;
            }

            tcp_stats.dns_pkts_rcv_tcp++;
            slen = buffer_remaining(tcp_query->packet);
            if (slen > 0) {
                uint16_t len = htons(slen);
                memcpy(buf, &len, 2);
                if (send(cfd, buf, slen + 2, 0) == -1) {
                    log_msg(LOG_ERR, "response query %s to %s, send error, errno=%d, errinfo=%s\n",
                            (char *)domain_name_to_string(tcp_query->qname, NULL), inet_ntoa(caddr.sin_addr), errno, strerror(errno));
                }
                tcp_stats.dns_pkts_snd_tcp++;
            }
        }
    }
}

int tcp_process_init(char *ip) {
    rte_rwlock_init(&tcp_lock);
    kdns_prepare_init(&tcp_kdns, &tcp_query);

    pthread_t *thread_id = (pthread_t *)xalloc(sizeof(pthread_t));
    pthread_create(thread_id, NULL, thread_tcp_process, (void *)ip);
    pthread_setname_np(*thread_id, "kdns_tcp_proc");
    return 0;
}
