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

extern struct dns_config *g_dns_cfg;
extern domain_fwd_addrs_ctrl g_fwd_addrs_ctrl;

struct kdns kdns_tcp;
static struct query *query_tcp = NULL;
struct netif_queue_stats tcp_stats;

void tcp_statsdata_get(struct netif_queue_stats *sta) {
    sta->dns_fwd_rcv_tcp = tcp_stats.dns_fwd_rcv_tcp;
    sta->dns_fwd_snd_tcp = tcp_stats.dns_fwd_snd_tcp;
    sta->dns_pkts_rcv_tcp = tcp_stats.dns_pkts_rcv_tcp;
    sta->dns_pkts_snd_tcp = tcp_stats.dns_pkts_snd_tcp;

    return;
}

void tcp_statsdata_reset(void) {
    memset(&tcp_stats, 0, sizeof(tcp_stats));
    return;
}

int tcp_domian_databd_update(struct domin_info_update *update) {
    int ret = domaindata_update(kdns_tcp.db, update);
    free(update);
    return ret;
}

static int dns_do_remote_tcp_query(char *snd_buf, ssize_t snd_len, char *rvc_buf, ssize_t rcv_len, dns_addr_t *id_addr, int timeout) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        log_msg(LOG_ERR, "dns_do_remote_tcp_query sock errno=%d, errinfo=%s\n", errno, strerror(errno));
        return -1;
    }

    struct timeval tv = {timeout, 0};
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        log_msg(LOG_ERR, "dns_do_remote_tcp_query socket option SO_RCVTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }
    if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        log_msg(LOG_ERR, "dns_do_remote_tcp_query socket option SO_SNDTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    int connResult = connect(sock_fd, &id_addr->addr, id_addr->addrlen);
    if (-1 == connResult) {
        log_msg(LOG_ERR, "dns_do_remote_tcp_query connect errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    int ret = send(sock_fd, snd_buf, snd_len, 0);
    if (ret <= 0) {
        log_msg(LOG_ERR, "dns_do_remote_tcp_query send errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }

    memset(rvc_buf, 0, rcv_len);
    ret = recv(sock_fd, rvc_buf, rcv_len - 1, 0);
    if (ret <= 0) {
        log_msg(LOG_ERR, "dns_do_remote_tcp_query recv errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;
    }
    close(sock_fd);
    return ret;
}

static int dns_handle_tcp_remote(int respond_sock, char *snd_pkt, uint16_t old_id, int snd_len, char *domain, uint16_t qtype, struct sockaddr_in *pin) {
    (void)old_id;
    int i = 0;
    int retfwd = 0;
    char recv_buf[TCP_MAX_MESSAGE_LEN] = {0};
    int fwd_timeout;
    int servers_len;
    dns_addr_t server_addrs[FWD_MAX_ADDRS];

    tcp_stats.dns_fwd_rcv_tcp++;

    pthread_rwlock_rdlock(&__fwd_lock);
    fwd_timeout = g_fwd_addrs_ctrl.timeout;
    domain_fwd_addrs *fwd_addrs = fwd_addrs_find(domain);
    servers_len = fwd_addrs->servers_len;
    memcpy(&server_addrs, &fwd_addrs->server_addrs, sizeof(fwd_addrs->server_addrs));
    pthread_rwlock_unlock(&__fwd_lock);

    for (;i < servers_len; i++){
        retfwd = dns_do_remote_tcp_query(snd_pkt, snd_len, recv_buf, TCP_MAX_MESSAGE_LEN, &server_addrs[i], fwd_timeout);
        if (retfwd > 0) {
            break;
        }

        char ip_src_str[INET_ADDRSTRLEN] = {0};
        char ip_dst_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &pin->sin_addr, ip_src_str, sizeof(ip_src_str));
        inet_ntop(AF_INET, &((struct sockaddr_in *)&server_addrs[i].addr)->sin_addr, ip_dst_str, sizeof(ip_dst_str));
        log_msg(LOG_ERR, "Failed to requset %s, type %d, to %s:%d, from: %s, trycnt:%d\n", domain, qtype,
                ip_dst_str, ntohs(((struct sockaddr_in *)&server_addrs[i].addr)->sin_port), ip_src_str, i);
    }

    if (retfwd > 0) {
        if (send(respond_sock, recv_buf, retfwd, 0) == -1) {
            log_msg(LOG_ERR, "last send error %s\n", domain);
            return -1;
        }
        tcp_stats.dns_fwd_snd_tcp++;
    }
    return 0;
}

static int dns_tcp_recv(int fd, char *buf, int len) {
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

static void *dns_tcp_process(void *arg) {
    char *ip = (char *)arg;
    struct sockaddr_in sin, pin;
    int sock_descriptor, temp_sock_descriptor;
    socklen_t address_size;
    char buf[TCP_MAX_MESSAGE_LEN];

    query_tcp = query_create();

    sleep(30);

    sock_descriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    bzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ip);;
    sin.sin_port = htons(53);
    if (bind(sock_descriptor, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        log_msg(LOG_ERR, "call bind err \n");
        exit(1);
    }
    if (listen(sock_descriptor, 100) == -1) {
        log_msg(LOG_ERR, "call listen err \n");
        exit(1);
    }
    printf("Accpting connections...\n");

    while (1) {
        address_size = sizeof(pin);
        temp_sock_descriptor = accept(sock_descriptor, (struct sockaddr *)&pin, &address_size);
        if (temp_sock_descriptor == -1) {
            log_msg(LOG_ERR, "call accept error\n");
            continue;
        }
        struct timeval tv = {2, 0};
        if (setsockopt(temp_sock_descriptor, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            log_msg(LOG_ERR, "set socket option SO_RCVTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
            close(temp_sock_descriptor);
            continue;
        }
        if (setsockopt(temp_sock_descriptor, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
            log_msg(LOG_ERR, "set socket option SO_SNDTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
            close(temp_sock_descriptor);
            continue;
        }
        while (1) {
            int bytes_transmitted = 0;
            bytes_transmitted = dns_tcp_recv(temp_sock_descriptor, buf, 2);  //recv query len first
            if (bytes_transmitted != 2) {
                if (bytes_transmitted < 0) {
                    log_msg(LOG_ERR, "failed recv len %d from %s\n", 2, inet_ntoa(pin.sin_addr));
                }
                close(temp_sock_descriptor);
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
            uint16_t tcp_query_len = ntohs(*(uint16_t *)buf);
            if (tcp_query_len < DNS_HEAD_SIZE + 1 + sizeof(uint16_t) + sizeof(uint16_t)) {
                log_msg(LOG_ERR, "tcp query from %s packet size %d illegal, drop\n", inet_ntoa(pin.sin_addr), tcp_query_len);
                close(temp_sock_descriptor);
                break;
            }

            bytes_transmitted = dns_tcp_recv(temp_sock_descriptor, buf + 2, tcp_query_len);
            if (bytes_transmitted != tcp_query_len) {
                if (bytes_transmitted < 0) {
                    log_msg(LOG_ERR, "failed recv len %d from %s\n", tcp_query_len, inet_ntoa(pin.sin_addr));
                }
                close(temp_sock_descriptor);
                break;
            }

            query_reset(query_tcp);
            query_tcp->maxMsgLen = TCP_MAX_MESSAGE_LEN;
            query_tcp->packet->data = (uint8_t *)(buf + 2);  //skip len

            uint16_t flags_old;
            memcpy(&flags_old, query_tcp->packet->data + 2, 2);

            query_tcp->packet->position += 2 + tcp_query_len;
            buffer_flip(query_tcp->packet);

            query_tcp->sip = *(uint32_t *)&pin.sin_addr;
            view_query_tcp(query_tcp);

            if (query_process(query_tcp, &kdns_tcp) != QUERY_FAIL) {
                buffer_flip(query_tcp->packet);
            }

            if (GET_RCODE(query_tcp->packet) == RCODE_REFUSE) {
                memcpy((buf + 2) + 2, &flags_old, 2);
                dns_handle_tcp_remote(temp_sock_descriptor, buf, GET_ID(query_tcp->packet), 2 + tcp_query_len,
                                      (char *)domain_name_to_string(query_tcp->qname, NULL), query_tcp->qtype, &pin);
                continue;
            }

            tcp_stats.dns_pkts_rcv_tcp++;
            int retLen = buffer_remaining(query_tcp->packet);
            if (retLen > 0) {
                uint16_t len = htons(retLen);
                memcpy(buf, &len, 2);
                if (send(temp_sock_descriptor, buf, retLen + 2, 0) == -1) {
                    log_msg(LOG_ERR, "response query %s to %s, send error, errno=%d, errinfo=%s\n",
                            (char *)domain_name_to_string(query_tcp->qname, NULL), inet_ntoa(pin.sin_addr), errno, strerror(errno));
                }
                tcp_stats.dns_pkts_snd_tcp++;
            }
        }
    }
}

int dns_tcp_process_init(char *ip) {
    memset(&kdns_tcp, 0, sizeof(kdns_tcp));
    if (dnsdata_prepare(&kdns_tcp) != 0) {
        log_msg(LOG_ERR, "server tcp preparation failed,could not be started\n");
        exit(-1);
    }

    pthread_t *thread_tcp_process = (pthread_t *)xalloc(sizeof(pthread_t));
    pthread_create(thread_tcp_process, NULL, dns_tcp_process, (void *)ip);
    pthread_setname_np(*thread_tcp_process, "kdns_tcp_proc");
    return 0;
}

