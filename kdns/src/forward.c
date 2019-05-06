/*
 * forward.c 
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
#include <time.h>
#include <jansson.h>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_udp.h>
#include <arpa/inet.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include "netdev.h"
#include "util.h"
#include "forward.h"
#include "dns-conf.h"
#include "hashMap.h"
#include "metrics.h"
#include "query.h"

#define FWD_RING_SIZE               (65536)
#define FWD_HASH_SIZE               (0x3FFFF)
#define FWD_LOCK_SIZE               (0xF)
#define FWD_PKTMBUF_CACHE_DEF       (256)

#define FWD_CACHE_NOT_FIND          (0x0)
#define FWD_CACHE_FIND              (0x1)
#define FWD_CACHE_EXPIRING          (0x2)
#define FWD_CACHE_EXPIRED           (0x3)

#define FWD_QUERY_NOT_FIND          (0x0)
#define FWD_QUERY_FIND              (0x1)

#define FWD_CTRL_FLAG_DIRECT        (0x1 << 0)           //fwd mode: direct
#define FWD_CTRL_FLAG_CACHE         (0x1 << 1)           //fwd mode: cache
#define FWD_CTRL_FLAG_DETECT        (0x1 << 2)           //cache expiring detect, no need to response

typedef struct {
    uint16_t qtype;
    char domain_name[FWD_MAX_DOMAIN_NAME_LEN];
    char data[EDNS_MAX_MESSAGE_LEN];
    int data_len;
    time_t time_expired;
} fwd_cache;

typedef struct {
    uint16_t qtype;
    char *domain_name;
} fwd_cache_check;

typedef struct {
    char *data;
    int *data_len;
    int status;
} fwd_cache_query;

typedef struct {
    struct rte_mbuf *pkt;
    uint32_t src_addr;
    uint16_t id;
    uint16_t qtype;
    char domain_name[FWD_MAX_DOMAIN_NAME_LEN];

    uint32_t ctrl_flag;
    uint64_t query_time;
    int timeout;   //second
    int current_server;
    int servers_len;
    dns_addr_t server_addrs[FWD_MAX_ADDRS];
} fwd_qnode;    //query/response node

typedef struct {
    int sfd;
    hashMap *query_hmap;
    struct query *query_rsp;
    struct rte_mempool *pktmbuf_pool;
    struct rte_ring *expired_ring;

    char rwbuf[EDNS_MAX_MESSAGE_LEN];
    int rwlen;
} fwd_manage;

typedef struct {
    fwd_qnode *query;
    fwd_manage *manage;

    uint16_t new_id;
    uint64_t time_expired;  //us
} fwd_cnode;    //fwd ctrl node

typedef struct {
    uint16_t id;
    uint16_t qtype;
    char *domain_name;
} fwd_cnode_check;

typedef struct {
    fwd_qnode *query;
    int status;
} fwd_cnode_query;

pthread_rwlock_t __fwd_lock;
domain_fwd_addrs_ctrl fwd_addrs_ctrl[MAX_CORES];
domain_fwd_addrs_ctrl g_fwd_addrs_ctrl;

static struct rte_ring *g_fwd_query_ring;
static struct rte_ring *g_fwd_response_ring;

static hashMap *g_fwd_cache_hash;

static rte_atomic64_t dns_fwd_rcv;      /* Total number of receive forward packets */
static rte_atomic64_t dns_fwd_snd;      /* Total number of response forward packets */
static rte_atomic64_t dns_fwd_lost;     /* Total number of lost response forward packets */

static void fwd_cache_update(fwd_qnode *qnode, char *cache_data, int cache_data_len);

static void fwd_cache_del(fwd_qnode *qnode);

static int fwd_cache_lookup(fwd_qnode *qnode, char *cache_data, int *cache_data_len);

void fwd_statsdata_get(struct netif_queue_stats *sta) {
    sta->dns_fwd_rcv_udp = rte_atomic64_read(&dns_fwd_rcv);
    sta->dns_fwd_snd_udp = rte_atomic64_read(&dns_fwd_snd);
    sta->dns_fwd_lost_udp = rte_atomic64_read(&dns_fwd_lost);
}

void fwd_statsdata_reset(void) {
    rte_atomic64_clear(&dns_fwd_rcv);
    rte_atomic64_clear(&dns_fwd_snd);
    rte_atomic64_clear(&dns_fwd_lost);
}

int fwd_query_enqueue(struct rte_mbuf *pkt, uint32_t src_addr, uint16_t id, uint16_t qtype, char *domain_name) {
    fwd_qnode *query;
    unsigned cid = rte_lcore_id();

    rte_atomic64_inc(&dns_fwd_rcv);
    if (fwd_addrs_ctrl[cid].mode == FWD_MODE_DISABLE) {
        rte_atomic64_inc(&dns_fwd_lost);
        rte_pktmbuf_free(pkt);
        return 0;
    }

    query = xalloc_array_zero(1, sizeof(fwd_qnode));
    query->pkt = pkt;
    query->src_addr = src_addr;
    query->id = id;
    query->qtype = qtype;
    strcpy(query->domain_name, domain_name);
    if (fwd_addrs_ctrl[cid].mode == FWD_MODE_DIRECT) {
        query->ctrl_flag |= FWD_CTRL_FLAG_DIRECT;
    } else if (fwd_addrs_ctrl[cid].mode == FWD_MODE_CACHE) {
        query->ctrl_flag |= FWD_CTRL_FLAG_CACHE;
    }

#ifdef ENABLE_KDNS_FWD_METRICS
    query->query_time = time_now_usec();
#endif

    query->timeout = fwd_addrs_ctrl[cid].timeout;
    domain_fwd_addrs *fwd_addrs = fwd_addrs_find(query->domain_name, &fwd_addrs_ctrl[cid]);
    query->current_server = 0;
    query->servers_len = fwd_addrs->servers_len;
    memcpy(&query->server_addrs, &fwd_addrs->server_addrs, sizeof(fwd_addrs->server_addrs));

    int ret = rte_ring_mp_enqueue(g_fwd_query_ring, (void *)query);
    if (unlikely(-EDQUOT == ret)) {
        log_msg(LOG_ERR, "fwd query ring quota exceeded\n");
        ret = 0;
    } else if (unlikely(-ENOBUFS == ret)) {
        log_msg(LOG_ERR, "Failed to enqueue query: %s, type: %d, from: %s\n, fwd query ring not enough room",
                domain_name, qtype, inet_ntoa(*(struct in_addr *)&src_addr));
        rte_atomic64_inc(&dns_fwd_lost);
        rte_pktmbuf_free(pkt);
        free(query);
    } else if (unlikely(ret)) {
        log_msg(LOG_ERR, "Failed to enqueue query: %s, type: %d, from: %s\n, fwd query ring unkown error(%d)",
                domain_name, qtype, inet_ntoa(*(struct in_addr *)&src_addr), ret);
        rte_atomic64_inc(&dns_fwd_lost);
        rte_pktmbuf_free(pkt);
        free(query);
    }

    return ret;
}

unsigned fwd_response_dequeue(struct rte_mbuf **pkts, unsigned pkts_cnt) {
    unsigned i;
    fwd_qnode *response[NETIF_MAX_PKT_BURST];

    pkts_cnt = RTE_MIN(rte_ring_count(g_fwd_response_ring), pkts_cnt);
    while (pkts_cnt > 0 && unlikely(rte_ring_dequeue_bulk(g_fwd_response_ring, (void **)response, pkts_cnt) != 0)) {
        pkts_cnt = (uint16_t)RTE_MIN(rte_ring_count(g_fwd_response_ring), pkts_cnt);
    }
    if (pkts_cnt > 0) {
        for (i = 0; i < pkts_cnt; ++i) {
            pkts[i] = response[i]->pkt;
#ifdef ENABLE_KDNS_FWD_METRICS
            metrics_domain_update(response[i]->domain_name, response[i]->query_time);
            metrics_domain_clientIp_update(response[i]->domain_name, response[i]->query_time, response[i]->src_addr);
#endif
            free(response[i]);
        }
        rte_atomic64_add(&dns_fwd_snd, pkts_cnt);
    }

    return pkts_cnt;
}

static int fwd_query_response(fwd_manage *manage, fwd_qnode *query) {
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip4_hdr;
    struct udp_hdr *udp_hdr;
    char *query_data;
    struct ether_hdr pkt_eth_hdr;
    struct ipv4_hdr pkt_ipv4_hdr;
    struct udp_hdr pkt_udp_hdr;

    if (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) {
        rte_pktmbuf_free(query->pkt);
        free(query);
        return 0;
    }

    eth_hdr = rte_pktmbuf_mtod(query->pkt, struct ether_hdr*);
    ip4_hdr = rte_pktmbuf_mtod_offset(query->pkt, struct ipv4_hdr *, sizeof(struct ether_hdr));
    udp_hdr = rte_pktmbuf_mtod_offset(query->pkt, struct udp_hdr*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    query_data = rte_pktmbuf_mtod_offset(query->pkt, char*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));

    init_eth_header(&pkt_eth_hdr, &(eth_hdr->d_addr), &(eth_hdr->s_addr), ETHER_TYPE_IPv4);
    init_ipv4_header(&pkt_ipv4_hdr, ip4_hdr->dst_addr, ip4_hdr->src_addr, sizeof(struct udp_hdr) + manage->rwlen);
    init_udp_header(&pkt_udp_hdr, udp_hdr->dst_port, udp_hdr->src_port, manage->rwlen);

    memcpy(eth_hdr, &pkt_eth_hdr, sizeof(struct ether_hdr));
    memcpy(ip4_hdr, &pkt_ipv4_hdr, sizeof(struct ipv4_hdr));
    memcpy(udp_hdr, &pkt_udp_hdr, sizeof(struct udp_hdr));
    query->pkt->pkt_len = manage->rwlen + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);
    query->pkt->data_len = query->pkt->pkt_len;
    query->pkt->l2_len = sizeof(struct ether_hdr);
    query->pkt->vlan_tci = ETHER_TYPE_IPv4;
    query->pkt->l3_len = sizeof(struct ipv4_hdr);
    memcpy(query_data, manage->rwbuf, manage->rwlen);

    uint16_t orig_id = htons(query->id);
    memcpy(query_data, &orig_id, 2);

    int ret = rte_ring_mp_enqueue(g_fwd_response_ring, (void *)query);
    if (unlikely(-EDQUOT == ret)) {
        log_msg(LOG_ERR, "fwd response ring quota exceeded\n");
        ret = 0;
    } else if (unlikely(-ENOBUFS == ret)) {
        log_msg(LOG_ERR, "Failed to enqueue response: %s, type: %d, from: %s, fwd response ring not enough room\n",
                query->domain_name, query->qtype, inet_ntoa(*(struct in_addr *)&query->src_addr));
        rte_atomic64_inc(&dns_fwd_lost);
        rte_pktmbuf_free(query->pkt);
        free(query);
    } else if (unlikely(ret)) {
        log_msg(LOG_ERR, "Failed to enqueue response: %s, type: %d, from: %s, fwd response ring unkown error(%d)\n",
                query->domain_name, query->qtype, inet_ntoa(*(struct in_addr *)&query->src_addr), ret);
        rte_atomic64_inc(&dns_fwd_lost);
        rte_pktmbuf_free(query->pkt);
        free(query);
    }

    return ret;
}

static int fwd_response_process(fwd_manage *manage) {
    int rsp_cnt = 0;
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(struct sockaddr);

    do {
        manage->rwlen = recvfrom(manage->sfd, manage->rwbuf, EDNS_MAX_MESSAGE_LEN, 0, (struct sockaddr *)&src_addr, &src_len);
        if (manage->rwlen <= 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                log_msg(LOG_ERR, "recvfrom failed, recv_len %d, errno=%d, errinfo=%s\n", manage->rwlen, errno, strerror(errno));
            }
            break;
        }

        struct query *query_rsp = manage->query_rsp;
        query_reset(query_rsp);
        query_rsp->sip = src_addr.sin_addr.s_addr;
        query_rsp->maxMsgLen = EDNS_MAX_MESSAGE_LEN;
        query_rsp->packet->data = (uint8_t *)manage->rwbuf;
        query_rsp->packet->position += manage->rwlen;
        buffer_flip(query_rsp->packet);

        if (buffer_getlimit(query_rsp->packet) < DNS_HEAD_SIZE) {
            log_msg(LOG_ERR, "recvfrom %s packet size %d illegal, drop\n", inet_ntoa(src_addr.sin_addr), manage->rwlen);
            continue;
        }
        if (GET_FLAG_QR(query_rsp->packet) == 0) {
            log_msg(LOG_ERR, "recvfrom %s dns query, not response, drop\n", inet_ntoa(src_addr.sin_addr));
            continue;
        }
        query_rsp->opcode = GET_OPCODE(query_rsp->packet);
        if (query_rsp->opcode != OPCODE_QUERY) {
            log_msg(LOG_ERR, "recvfrom %s opcode %d illegal, drop\n", inet_ntoa(src_addr.sin_addr), query_rsp->opcode);
            continue;
        }
        if (!process_query_section(query_rsp)) {
            log_msg(LOG_ERR, "recvfrom %s process query section failed, drop\n", inet_ntoa(src_addr.sin_addr));
            continue;
        }

        fwd_cnode_check cnode_check;
        cnode_check.id = GET_ID(query_rsp->packet);
        cnode_check.qtype = query_rsp->qtype;
        cnode_check.domain_name = (char *)domain_name_to_string(query_rsp->qname, NULL);

        fwd_cnode_query out;
        out.query = NULL;
        out.status = FWD_QUERY_NOT_FIND;

        hmap_lookup(manage->query_hmap, cnode_check.domain_name, &cnode_check, &out);
        if (out.status == FWD_QUERY_NOT_FIND) {
            log_msg(LOG_ERR, "recvfrom %s domain name %s, type %d, id 0x%x not found, drop\n",
                    inet_ntoa(src_addr.sin_addr), cnode_check.domain_name, cnode_check.qtype, cnode_check.id);
            continue;
        }
        hmap_del(manage->query_hmap, cnode_check.domain_name, &cnode_check);

        fwd_cache_update(out.query, manage->rwbuf, manage->rwlen);
        fwd_query_response(manage, out.query);
    } while (++rsp_cnt < 64);

    return rsp_cnt;
}

static int fwd_query_forward_sendto(int fd, char *data, ssize_t data_len, dns_addr_t *id_addr) {
    int try_cnt = 0;
    do {
        if (sendto(fd, data, data_len, 0, &id_addr->addr, id_addr->addrlen) == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                log_msg(LOG_ERR, "sendto failed, errno=%d, errinfo=%s\n", errno, strerror(errno));
                return -1;
            }
            continue;
        }
        return 0;
    } while (++try_cnt < 16);
    return -1;
}

static int fwd_query_forward_send(fwd_cnode *cnode) {
    struct ipv4_hdr *ip4_hdr;
    struct udp_hdr *udp_hdr;
    char *query_data;
    int query_len;

    fwd_qnode *query = cnode->query;
    ip4_hdr = rte_pktmbuf_mtod_offset(query->pkt, struct ipv4_hdr *, sizeof(struct ether_hdr));
    udp_hdr = rte_pktmbuf_mtod_offset(query->pkt, struct udp_hdr*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    query_data = rte_pktmbuf_mtod_offset(query->pkt, char*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
    query_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct udp_hdr);

    uint16_t new_id = htons(cnode->new_id);
    memcpy(query_data, &new_id, 2);
    for (; query->current_server < query->servers_len; ++query->current_server) {
        dns_addr_t *server_addrs = &query->server_addrs[query->current_server];

        if (fwd_query_forward_sendto(cnode->manage->sfd, query_data, query_len, server_addrs) != 0) {
            char ip_src_str[INET_ADDRSTRLEN] = {0};
            char ip_dst_str[INET_ADDRSTRLEN] = {0};

            inet_ntop(AF_INET, (struct in_addr *)&ip4_hdr->src_addr, ip_src_str, sizeof(ip_src_str));
            inet_ntop(AF_INET, &((struct sockaddr_in *)&server_addrs->addr)->sin_addr, ip_dst_str, sizeof(ip_dst_str));
            log_msg(LOG_ERR, "Failed to send %s: %s, type %d, to %s, from: %s, trycnt: %d\n",
                    (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) ? "detect" : "request",
                    query->domain_name, query->qtype, ip_dst_str, ip_src_str, query->current_server);
            continue;
        }
        return 0;
    }
    return -1;
}

static int fwd_cnode_get_id(fwd_manage *manage, fwd_qnode *query, uint16_t *new_id) {
    int try_cnt = 0;

    fwd_cnode_check cnode_check;
    cnode_check.qtype = query->qtype;
    cnode_check.domain_name = query->domain_name;
    do {
        cnode_check.id = (uint16_t)rand();
        if (HASH_NODE_FIND != hmap_lookup(manage->query_hmap, query->domain_name, &cnode_check, NULL)) {
            *new_id = cnode_check.id;
            return 0;
        }
    } while (++try_cnt < 64);

    return -1;
}

static int fwd_query_forward(fwd_manage *manage, fwd_qnode *query) {
    fwd_cnode *cnode;
    uint16_t new_id;

    if (fwd_cnode_get_id(manage, query, &new_id) != 0) {
        log_msg(LOG_ERR, "Failed to get new query id for %s: %s, type %d, from: %s, drop\n",
                (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) ? "detect" : "request",
                query->domain_name, query->qtype, inet_ntoa(*(struct in_addr *)&(query->src_addr)));
        rte_atomic64_inc(&dns_fwd_lost);
        rte_pktmbuf_free(query->pkt);
        free(query);
        return -1;
    }

    cnode = xalloc_array_zero(1, sizeof(fwd_cnode));
    cnode->query = query;
    cnode->manage = manage;
    cnode->new_id = new_id;
    cnode->time_expired = time_now_usec() + query->timeout * 1000 * 1000;

    if (fwd_query_forward_send(cnode) != 0) {
        log_msg(LOG_ERR, "Failed to send %s: %s, type %d, to all server, from: %s, drop\n",
                (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) ? "detect" : "request",
                query->domain_name, query->qtype, inet_ntoa(*(struct in_addr *)&(query->src_addr)));
        rte_atomic64_inc(&dns_fwd_lost);
        rte_pktmbuf_free(query->pkt);
        free(query);
        free(cnode);
        return -1;
    }

    fwd_cnode_check cnode_check;
    cnode_check.id = new_id;
    cnode_check.qtype = query->qtype;
    cnode_check.domain_name = query->domain_name;
    hmap_update(manage->query_hmap, query->domain_name, (void *)&cnode_check, (void *)cnode);
    return 0;
}

static inline int fwd_pktmbuf_copy_data(struct rte_mbuf *seg, const struct rte_mbuf *m) {
    if (rte_pktmbuf_tailroom(seg) < m->data_len) {
        log_msg(LOG_ERR, "insufficient data_len of mbuf\n");
        return -1;
    }

    seg->port = m->port;
    seg->vlan_tci = m->vlan_tci;
    seg->hash = m->hash;
    seg->tx_offload = m->tx_offload;
    seg->ol_flags = m->ol_flags;
    seg->packet_type = m->packet_type;
    seg->vlan_tci_outer = m->vlan_tci_outer;
    seg->data_len = m->data_len;
    seg->pkt_len = seg->data_len;
    rte_memcpy(rte_pktmbuf_mtod(seg, void *), rte_pktmbuf_mtod(m, void *), rte_pktmbuf_data_len(seg));

    return 0;
}

static inline struct rte_mbuf *fwd_pktmbuf_copy(struct rte_mbuf *m, struct rte_mempool *mp) {
    struct rte_mbuf *m_dup, *seg, **prev;
    uint32_t pktlen;
    uint8_t nseg;

    m_dup = rte_pktmbuf_alloc(mp);
    if (unlikely(m_dup == NULL)) {
        return NULL;
    }

    seg = m_dup;
    prev = &seg->next;
    pktlen = m->pkt_len;
    nseg = 0;

    do {
        nseg++;
        if (fwd_pktmbuf_copy_data(seg, m) < 0) {
            rte_pktmbuf_free(m_dup);
            return NULL;
        }
        *prev = seg;
        prev = &seg->next;
    } while ((m = m->next) != NULL && (seg = rte_pktmbuf_alloc(mp)) != NULL);

    *prev = NULL;
    m_dup->nb_segs = nseg;
    m_dup->pkt_len = pktlen;

    /* Allocation of new indirect segment failed */
    if (unlikely(seg == NULL)) {
        rte_pktmbuf_free(m_dup);
        return NULL;
    }

    __rte_mbuf_sanity_check(m_dup, 1);
    return m_dup;
}

static int fwd_query_detect(fwd_manage *manage, fwd_qnode *query) {
    fwd_qnode *new_query;
    struct rte_mbuf *new_pkt;

    new_pkt = fwd_pktmbuf_copy(query->pkt, manage->pktmbuf_pool);
    if (new_pkt == NULL) {
        log_msg(LOG_ERR, "Failed to copy query pkt: %s, type %d, from: %s, drop\n",
                query->domain_name, query->qtype, inet_ntoa(*(struct in_addr *)&(query->src_addr)));
        return -1;
    }
    new_query = xalloc_array_zero(1, sizeof(fwd_qnode));
    new_query->pkt = new_pkt;
    new_query->src_addr = query->src_addr;
    new_query->id = query->id;
    new_query->qtype = query->qtype;
    strcpy(new_query->domain_name, query->domain_name);

    new_query->ctrl_flag = query->ctrl_flag | FWD_CTRL_FLAG_DETECT;
    new_query->query_time = query->query_time;
    new_query->timeout = query->timeout;
    new_query->current_server = 0;
    new_query->servers_len = query->servers_len;
    memcpy(&new_query->server_addrs, &query->server_addrs, sizeof(query->server_addrs));

    return fwd_query_forward(manage, new_query);
}

static int fwd_query_process(fwd_manage *manage) {
    int fwd_cnt = 0;
    fwd_qnode *query;

    do {
        if (rte_ring_mc_dequeue(g_fwd_query_ring, (void **)&query) != 0) {
            break;
        }

        int status = fwd_cache_lookup(query, manage->rwbuf, &manage->rwlen);
        if (status == FWD_CACHE_FIND) {
            fwd_query_response(manage, query);
        } else if (status == FWD_CACHE_EXPIRING) {
            fwd_query_detect(manage, query);
            fwd_query_response(manage, query);
        } else {
            fwd_query_forward(manage, query);
        }
    } while (++fwd_cnt < 64);

    return fwd_cnt;
}

static int fwd_expired_process(fwd_manage *manage) {
    int exp_cnt = 0;
    fwd_qnode *query;

    do {
        if (rte_ring_sc_dequeue(manage->expired_ring, (void **)&query) != 0) {
            break;
        }

        int status = fwd_cache_lookup(query, manage->rwbuf, &manage->rwlen);
        if (++query->current_server < query->servers_len) {
            if (status == FWD_CACHE_FIND) {
                fwd_query_response(manage, query);
            } else {
                fwd_query_forward(manage, query);
            }
        } else {
            if (status == FWD_CACHE_FIND) {
                fwd_query_response(manage, query);
            } else if (status == FWD_CACHE_EXPIRING) {
                fwd_query_response(manage, query);
            } else if (status == FWD_CACHE_EXPIRED) {
                log_msg(LOG_ERR, "Failed to deal %s: %s, type %d, to all server, from: %s, time_expired, use expired cache\n",
                        (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) ? "detect" : "request",
                        query->domain_name, query->qtype, inet_ntoa(*(struct in_addr *)&(query->src_addr)));
                fwd_cache_update(query, manage->rwbuf, manage->rwlen);
                fwd_query_response(manage, query);
            } else {
                log_msg(LOG_ERR, "Failed to deal %s: %s, type %d, to all server, from: %s, time_expired, drop\n",
                        (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) ? "detect" : "request",
                        query->domain_name, query->qtype, inet_ntoa(*(struct in_addr *)&(query->src_addr)));
                rte_atomic64_inc(&dns_fwd_lost);
                rte_pktmbuf_free(query->pkt);
                free(query);
            }
        }
    } while (++exp_cnt);

    return exp_cnt;
}

static int fwd_cnode_equal_check(char *key, hashNode *node, void *check) {
    (void)key;
    fwd_cnode *cnode = (fwd_cnode *)node->data;
    fwd_cnode_check *cnode_check = (fwd_cnode_check *)check;

    if (cnode->new_id == cnode_check->id && cnode->query->qtype == cnode_check->qtype
        && strcmp(cnode->query->domain_name, cnode_check->domain_name) == 0) {
        return 1;
    }
    return 0;
}

static int fwd_cnode_equal_query(hashNode *node, void *output) {
    if (output) {
        fwd_cnode *cnode = (fwd_cnode *)node->data;
        fwd_cnode_query *out = (fwd_cnode_query *)output;

        out->query = cnode->query;
        out->status = FWD_QUERY_FIND;
        return 1;
    }
    return 0;
}

static int fwd_cnode_expired_check(hashNode *node, void *arg) {
    uint64_t *time_now = (uint64_t *)arg;
    fwd_cnode *cnode = (fwd_cnode *)node->data;

    if (cnode->time_expired < *time_now) {
        fwd_qnode *query = cnode->query;

        char ip_src_str[INET_ADDRSTRLEN] = {0};
        char ip_dst_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, (struct in_addr *)&query->src_addr, ip_src_str, sizeof(ip_src_str));
        inet_ntop(AF_INET, &((struct sockaddr_in *)&query->server_addrs[query->current_server].addr)->sin_addr, ip_dst_str, sizeof(ip_dst_str));
        log_msg(LOG_ERR, "Failed to deal %s: %s, type %d, to %s, from: %s, trycnt: %d, time_expired, add to expired ring\n",
                (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) ? "detect" : "request",
                query->domain_name, query->qtype, ip_dst_str, ip_src_str, query->current_server);

        int ret = rte_ring_sp_enqueue(cnode->manage->expired_ring, (void *)cnode->query);
        if (unlikely(-EDQUOT == ret)) {
            log_msg(LOG_ERR, "expired ring quota exceeded\n");
        } else if (unlikely(-ENOBUFS == ret)) {
            log_msg(LOG_ERR, "Failed to enqueue %s to expired ring: %s, type: %d, from: %s, expired ring not enough room\n",
                    (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) ? "detect" : "request", query->domain_name, query->qtype, ip_src_str);
            rte_atomic64_inc(&dns_fwd_lost);
            rte_pktmbuf_free(query->pkt);
            free(query);
        } else if (unlikely(ret)) {
            log_msg(LOG_ERR, "Failed to enqueue %s to expired ring: %s, type: %d, from: %s, expired ring unkown error(%d)\n",
                    (query->ctrl_flag & FWD_CTRL_FLAG_DETECT) ? "detect" : "request", query->domain_name, query->qtype, ip_src_str, ret);
            rte_atomic64_inc(&dns_fwd_lost);
            rte_pktmbuf_free(query->pkt);
            free(query);
        }

        return 1;
    }
    return 0;
}

static hashMap *fwd_query_hmap_init(void) {
    return hmap_create(FWD_HASH_SIZE, FWD_LOCK_SIZE, elfHashDomain,
                       fwd_cnode_equal_check, fwd_cnode_equal_query, fwd_cnode_expired_check, NULL);
}

static int fwd_socket_init(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        log_msg(LOG_ERR, "create socket failed, errno=%d, errinfo=%s\n", errno, strerror(errno));
        exit(-1);
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        log_msg(LOG_ERR, "fcntl F_GETFL failed, errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(fd);
        exit(-1);
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_msg(LOG_ERR, "fcntl F_SETFL O_NONBLOCK failed, errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(fd);
        exit(-1);
    }

    return fd;
}

static void *thread_fwd_process(void *arg) {
    intptr_t thread_num = (intptr_t)arg;
    uint64_t start, now;
    char name[32] = {0};

    fwd_manage *manage = xalloc_array_zero(1, sizeof(fwd_manage));
    manage->sfd = fwd_socket_init();
    manage->query_hmap = fwd_query_hmap_init();
    manage->query_rsp = query_create();

    snprintf(name, sizeof(name), "fwd_pktmbuf_pool_%ld", thread_num);
    manage->pktmbuf_pool = rte_pktmbuf_pool_create(name, g_dns_cfg->comm.fwd_mbuf_num,
                                                   FWD_PKTMBUF_CACHE_DEF, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (manage->pktmbuf_pool == NULL) {
        log_msg(LOG_ERR, "Failed to create fwd pktmbuf pool %ld: %s\n", thread_num, rte_strerror(rte_errno));
        exit(-1);
    }

    snprintf(name, sizeof(name), "fwd_expired_ring_%ld", thread_num);
    manage->expired_ring = rte_ring_create(name, FWD_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (manage->expired_ring == NULL) {
        log_msg(LOG_ERR, "Failed to create fwd expired ring %ld: %s\n", thread_num, rte_strerror(rte_errno));
        exit(-1);
    }

    srand((int)time(NULL));
    start = time_now_usec();
    log_msg(LOG_INFO, "Starting thread_fwd_process %ld\n", thread_num);
    while (1) {
        int exp_cnt = fwd_expired_process(manage);
        int rsp_cnt = fwd_response_process(manage);
        int fwd_cnt = fwd_query_process(manage);

        now = time_now_usec();
        if (now - start >= 200 * 1000) {    //200ms
            hmap_check_expired(manage->query_hmap, (void *)&now);
            start = now;
        }

        if (exp_cnt == 0 && rsp_cnt == 0 && fwd_cnt == 0) {
            usleep(1000);   //1ms
        }
    }
    return NULL;
}

static void *thread_fwd_cache_expired_cleanup(void *arg) {
    (void)arg;
    int del_nums = 0;

    while (1) {
        sleep(600);
        time_t time_now = time(NULL);
        del_nums = hmap_check_expired(g_fwd_cache_hash, (void *)&time_now);
        if (del_nums) {
            log_msg(LOG_INFO, "fwd cache expired: %d record dels\n", del_nums);
        }
    }
    return NULL;
}

static void fwd_cache_update(fwd_qnode *qnode, char *cache_data, int cache_data_len) {
    if (qnode->ctrl_flag & FWD_CTRL_FLAG_DIRECT) {
        return;
    }

    fwd_cache *new_node = xalloc_zero(sizeof(fwd_cache));

    new_node->qtype = qnode->qtype;
    new_node->data_len = cache_data_len;
    new_node->time_expired = time(NULL) + 60;
    strcpy(new_node->domain_name, qnode->domain_name);
    memcpy(new_node->data, cache_data, cache_data_len);

    fwd_cache_check check;
    check.qtype = qnode->qtype;
    check.domain_name = qnode->domain_name;
    hmap_update(g_fwd_cache_hash, qnode->domain_name, (void *)&check, (void *)new_node);
}

static void fwd_cache_del(fwd_qnode *qnode) {
    if (qnode->ctrl_flag & FWD_CTRL_FLAG_DIRECT) {
        return;
    }

    fwd_cache_check del_node;

    del_node.qtype = qnode->qtype;
    del_node.domain_name = qnode->domain_name;

    hmap_del(g_fwd_cache_hash, qnode->domain_name, (void *)&del_node);
}

static int fwd_cache_lookup(fwd_qnode *qnode, char *cache_data, int *cache_data_len) {
    if (qnode->ctrl_flag & FWD_CTRL_FLAG_DIRECT) {
        return FWD_CACHE_NOT_FIND;
    }

    fwd_cache_check check;
    check.qtype = qnode->qtype;
    check.domain_name = qnode->domain_name;

    fwd_cache_query output;
    output.data = cache_data;
    output.data_len = cache_data_len;
    output.status = FWD_CACHE_NOT_FIND;

    hmap_lookup(g_fwd_cache_hash, qnode->domain_name, &check, &output);
    return output.status;
}

static int fwd_cache_equal_check(char *key, hashNode *node, void *check) {
    (void)key;
    fwd_cache *cache = (fwd_cache *)node->data;
    fwd_cache_check *cache_check = (fwd_cache_check *)check;

    if (cache->qtype == cache_check->qtype && strcmp(cache->domain_name, cache_check->domain_name) == 0) {
        return 1;
    }
    return 0;
}

static int fwd_cache_equal_query(hashNode *node, void *output) {
    if (output) {
        fwd_cache *cache = (fwd_cache *)node->data;
        fwd_cache_query *out = (fwd_cache_query *)output;

        memcpy(out->data, cache->data, cache->data_len);
        *out->data_len = cache->data_len;
        if (cache->time_expired < time(NULL)) {
            out->status = FWD_CACHE_EXPIRED;
        } else if (cache->time_expired < time(NULL) + 10) {
            out->status = FWD_CACHE_EXPIRING;
        } else {
            out->status = FWD_CACHE_FIND;
        }
        return 1;
    }
    return 0;
}

static int fwd_cache_expired_check(hashNode *node, void *arg) {
    time_t *time_now = (time_t *)arg;
    fwd_cache *cache = (fwd_cache *)node->data;

    // 60S time_expired, we del it 600s later
    if (cache->time_expired + 600 < *time_now) {
        log_msg(LOG_INFO, "domain name: %s, type: %d, time_expired\n", cache->domain_name, cache->qtype);
        return 1;
    }
    return 0;
}

static int fwd_cache_query_all(hashNode *node, void *arg) {
    struct tm tmp_tm;
    char time_buf[32];

    fwd_cache *cache = (fwd_cache *)node->data;
    json_t *array = (json_t *)arg;

    localtime_r(&cache->time_expired, &tmp_tm);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tmp_tm);

    json_t *value = json_pack("{s:s, s:i, s:s}", "Domain", cache->domain_name, "Type", cache->qtype, "ExpiredTime", time_buf);
    json_array_append_new(array, value);
    return 1;
}

static void fwd_cache_init(void) {
    g_fwd_cache_hash = hmap_create(FWD_HASH_SIZE, FWD_LOCK_SIZE, elfHashDomain,
                                   fwd_cache_equal_check, fwd_cache_equal_query, fwd_cache_expired_check, fwd_cache_query_all);
}

void *fwd_caches_get(__attribute__((unused))struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response) {
    json_t *array = json_array();
    if (!array) {
        log_msg(LOG_ERR, "unable to create array\n");
        return NULL;
    }

    hmap_get_all(g_fwd_cache_hash, (void *)array);

    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    return (void *)str_ret;
}

void *fwd_caches_delete(__attribute__((unused))struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    hmap_del_all(g_fwd_cache_hash);

    char *post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return (void *)post_ok;
}

static domain_fwd_addrs *fwd_addrs_parse(const char *domain_suffix, char *addrs) {
    struct addrinfo *addr_ip;
    struct addrinfo hints;
    char *token;
    char buf[512];
    char dns_addrs[512] = {0};
    const char *def_port = "53";
    int i = 0, r = 0;

    strncpy(dns_addrs, addrs, MIN(sizeof(dns_addrs), strlen(addrs)));
    domain_fwd_addrs *fwd_addrs = xalloc_array_zero(1, sizeof(domain_fwd_addrs));
    fwd_addrs->servers_len = 1;
    memcpy(fwd_addrs->domain_name, domain_suffix, strlen(domain_suffix));

    char *pch = strchr(dns_addrs, ',');
    while (pch != NULL) {
        fwd_addrs->servers_len++;
        pch = strchr(pch + 1, ',');
    }
    if (fwd_addrs->servers_len > FWD_MAX_ADDRS) {
        log_msg(LOG_INFO, "domain_suffix :%s remote addr :%s, fwd addrs %d truncate to %d\n", domain_suffix, dns_addrs, fwd_addrs->servers_len, FWD_MAX_ADDRS);
        fwd_addrs->servers_len = FWD_MAX_ADDRS;
    }

    log_msg(LOG_INFO, "domain_suffix :%s remote addr :%s\n", domain_suffix, dns_addrs);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    token = strtok(dns_addrs, ",");
    while (token && i < fwd_addrs->servers_len) {
        char *port;
        memset(buf, 0, sizeof(buf));
        strncpy(buf, token, sizeof(buf) - 1);
        port = (strrchr(buf, ':'));
        if (port) {
            *port = '\0';
            port++;
        } else {
            port = (char *)def_port;
        }
        if (0 != (r = getaddrinfo(buf, port, &hints, &addr_ip))) {
            log_msg(LOG_ERR, "err getaddrinfo, errno=%d, errinfo=%s\n", errno, strerror(errno));
            exit(-1);
        }
        fwd_addrs->server_addrs[i].addr = *(addr_ip->ai_addr);
        fwd_addrs->server_addrs[i].addrlen = addr_ip->ai_addrlen;
        freeaddrinfo(addr_ip);
        i++;
        token = strtok(0, ",");
    }
    return fwd_addrs;
}

static domain_fwd_addrs **fwd_zones_addrs_parse(char *addrs, int *fwd_zone_num) {
    int zone_idx = 1;
    char *zone_info = NULL;
    char buf[512];
    char zone_addr[512];
    char fwd_addrs[512] = {0};
    char zone_name[FWD_MAX_DOMAIN_NAME_LEN];
    char *tmp_ptr;

    if (!addrs || strlen(addrs) == 0) {
        return NULL;
    }
    strncpy(fwd_addrs, addrs, MIN(sizeof(fwd_addrs), strlen(addrs)));

    log_msg(LOG_INFO, "fwd_zones_addrs_parse fwd_addrs %s\n", fwd_addrs);
    char *pch = strchr(fwd_addrs, '%');
    while (pch != NULL) {
        zone_idx++;
        pch = strchr(pch + 1, '%');
    }

    *fwd_zone_num = zone_idx;
    domain_fwd_addrs **tmp_fwd_addrs = xalloc_array_zero(zone_idx, sizeof(domain_fwd_addrs *));
    zone_idx = 0;
    zone_info = strtok_r(fwd_addrs, "%", &tmp_ptr);
    while (zone_info) {
        char *pos;
        memset(buf, 0, sizeof(buf));
        memset(zone_name, 0, FWD_MAX_DOMAIN_NAME_LEN);
        memset(zone_addr, 0, sizeof(zone_addr));
        strncpy(buf, zone_info, sizeof(buf) - 1);
        pos = (strrchr(buf, '@'));
        if (pos) {
            if (pos - buf >= FWD_MAX_DOMAIN_NAME_LEN) {
                log_msg(LOG_ERR, "domain name legth greater than %d\n", FWD_MAX_DOMAIN_NAME_LEN);
                exit(-1);
            }

            memcpy(zone_name, buf, pos - buf);
            memcpy(zone_addr, pos + 1, strlen(buf) + buf - pos - 1);
            tmp_fwd_addrs[zone_idx] = fwd_addrs_parse(zone_name, zone_addr);
        } else {
            log_msg(LOG_ERR, "wrong fmt %s\n", zone_info);
            exit(-1);
        }
        zone_idx++;
        zone_info = strtok_r(NULL, "%", &tmp_ptr);
    }

    return tmp_fwd_addrs;
}

int fwd_def_addrs_reload(char *addrs) {
    domain_fwd_addrs *new_def_fwd_addrs = NULL;
    domain_fwd_addrs *old_def_fwd_addrs = NULL;

    if (!addrs) {
        return -1;
    }

    new_def_fwd_addrs = fwd_addrs_parse("defulat.zone", addrs);
    if (new_def_fwd_addrs) {
        pthread_rwlock_wrlock(&__fwd_lock);
        old_def_fwd_addrs = g_fwd_addrs_ctrl.default_addrs;
        g_fwd_addrs_ctrl.default_addrs = new_def_fwd_addrs;
        pthread_rwlock_unlock(&__fwd_lock);
    }

    if (old_def_fwd_addrs) {
        free(old_def_fwd_addrs);
    }
    return 0;
}

int fwd_zones_addrs_reload(char *addrs) {
    int i;
    int new_zone_num = 0;
    int old_zone_num = 0;
    domain_fwd_addrs **new_fwd_addrs = NULL;
    domain_fwd_addrs **old_fwd_addrs = NULL;

    if (!addrs) {
        return -1;
    }

    new_fwd_addrs = fwd_zones_addrs_parse(addrs, &new_zone_num);
    pthread_rwlock_wrlock(&__fwd_lock);
    old_fwd_addrs = g_fwd_addrs_ctrl.zones_addrs;
    old_zone_num = g_fwd_addrs_ctrl.zones_addrs_num;

    g_fwd_addrs_ctrl.zones_addrs = new_fwd_addrs;
    g_fwd_addrs_ctrl.zones_addrs_num = new_zone_num;
    pthread_rwlock_unlock(&__fwd_lock);

    if (old_fwd_addrs) {
        for (i = 0; i < old_zone_num; ++i) {
            free(old_fwd_addrs[i]);
        }
        free(old_fwd_addrs);
    }
    return 0;
}

int fwd_timeout_reload(int timeout) {
    pthread_rwlock_wrlock(&__fwd_lock);
    g_fwd_addrs_ctrl.timeout = timeout;
    pthread_rwlock_unlock(&__fwd_lock);
    return 0;
}

static int fwd_mode_parse(char *mode) {
    log_msg(LOG_INFO, "fwd_mode_parse mode: %s.\n", mode);
    if (strcmp(mode, "disable") == 0) {
        return FWD_MODE_DISABLE;
    } else if (strcmp(mode, "direct") == 0) {
        return FWD_MODE_DIRECT;
    } else if (strcmp(mode, "cache") == 0) {
        return FWD_MODE_CACHE;
    } else {
        return FWD_MODE_CACHE;
    }
}

int fwd_mode_reload(char *mode) {
    if (!mode) {
        return -1;
    }

    int new_fwd_mode = fwd_mode_parse(mode);
    pthread_rwlock_wrlock(&__fwd_lock);
    g_fwd_addrs_ctrl.mode = new_fwd_mode;
    pthread_rwlock_unlock(&__fwd_lock);

    return 0;
}

static domain_fwd_addrs *fwd_addrs_clone(domain_fwd_addrs *src) {
    domain_fwd_addrs *dst = xalloc_array_zero(1, sizeof(domain_fwd_addrs));
    strcpy(dst->domain_name, src->domain_name);
    dst->servers_len = src->servers_len;
    memcpy(&dst->server_addrs, &src->server_addrs, sizeof(src->server_addrs));

    return dst;
}

static void fwd_addrs_ctrl_clone(domain_fwd_addrs_ctrl *dst, domain_fwd_addrs_ctrl *src) {
    int i;

    dst->mode = src->mode;
    dst->timeout = src->timeout;
    dst->default_addrs = fwd_addrs_clone(src->default_addrs);
    dst->zones_addrs_num = src->zones_addrs_num;
    dst->zones_addrs = xalloc_array_zero(src->zones_addrs_num, sizeof(domain_fwd_addrs *));
    for (i = 0; i < src->zones_addrs_num; ++i) {
        dst->zones_addrs[i] = fwd_addrs_clone(src->zones_addrs[i]);
    }
}

static void fwd_addrs_ctrl_free(domain_fwd_addrs_ctrl *ctrl) {
    int i;

    free(ctrl->default_addrs);
    for (i = 0; i < ctrl->zones_addrs_num; ++i) {
        free(ctrl->zones_addrs[i]);
    }
    free(ctrl->zones_addrs);
}

int fwd_addrs_reload_proc(unsigned cid) {
    pthread_rwlock_rdlock(&__fwd_lock);
    fwd_addrs_ctrl_free(&fwd_addrs_ctrl[cid]);
    fwd_addrs_ctrl_clone(&fwd_addrs_ctrl[cid], &g_fwd_addrs_ctrl);
    pthread_rwlock_unlock(&__fwd_lock);
    return 0;
}

domain_fwd_addrs *fwd_addrs_find(char *domain_name, domain_fwd_addrs_ctrl *ctrl) {
    int i = 0;
    for (; i < ctrl->zones_addrs_num; ++i) {
        int zone_len = strlen(ctrl->zones_addrs[i]->domain_name);
        int domain_len = strlen(domain_name);
        if ((domain_len >= zone_len) &&
            strncmp(domain_name + domain_len - zone_len, ctrl->zones_addrs[i]->domain_name, strlen(ctrl->zones_addrs[i]->domain_name)) == 0) {
            return ctrl->zones_addrs[i];
        }
    }
    return ctrl->default_addrs;
}

int fwd_server_init(void) {
    int i;
    pthread_rwlockattr_t attr;

    (void)pthread_rwlockattr_init(&attr);
    (void)pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    (void)pthread_rwlock_init(&__fwd_lock, &attr);

    g_fwd_addrs_ctrl.mode = fwd_mode_parse(g_dns_cfg->comm.fwd_mode);
    g_fwd_addrs_ctrl.timeout = g_dns_cfg->comm.fwd_timeout;
    g_fwd_addrs_ctrl.default_addrs = fwd_addrs_parse("defulat.zone", g_dns_cfg->comm.fwd_def_addrs);
    g_fwd_addrs_ctrl.zones_addrs = fwd_zones_addrs_parse(g_dns_cfg->comm.fwd_addrs, &g_fwd_addrs_ctrl.zones_addrs_num);
    for (i = 0; i < MAX_CORES; ++i) {
        fwd_addrs_ctrl_clone(&fwd_addrs_ctrl[i], &g_fwd_addrs_ctrl);
    }

    rte_atomic64_init(&dns_fwd_rcv);
    rte_atomic64_init(&dns_fwd_snd);
    rte_atomic64_init(&dns_fwd_lost);

    fwd_cache_init();
#ifdef ENABLE_KDNS_FWD_METRICS
    fwd_metrics_init();
#endif

    g_fwd_query_ring = rte_ring_create("fwd_query_ring", FWD_RING_SIZE, rte_socket_id(), 0);
    if (!g_fwd_query_ring) {
        log_msg(LOG_ERR, "Failed to create fwd query ring: %s\n", rte_strerror(rte_errno));
        exit(-1);
    }
    g_fwd_response_ring = rte_ring_create("fwd_response_ring", FWD_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
    if (!g_fwd_response_ring) {
        log_msg(LOG_ERR, "Failed to create fwd response ring: %s\n", rte_strerror(rte_errno));
        exit(-1);
    }

    intptr_t tnum;
    for (tnum = 0; tnum < g_dns_cfg->comm.fwd_threads; ++tnum) {
        pthread_t *thread_id = (pthread_t *)xalloc(sizeof(pthread_t));
        pthread_create(thread_id, NULL, thread_fwd_process, (void *)tnum);

        char tname[16];
        snprintf(tname, sizeof(tname), "kdns_udp_fwd_%ld", tnum);
        pthread_setname_np(*thread_id, tname);
    }

    pthread_t *thread_cache_expired = (pthread_t *)xalloc(sizeof(pthread_t));
    pthread_create(thread_cache_expired, NULL, thread_fwd_cache_expired_cleanup, (void *)NULL);
    pthread_setname_np(*thread_cache_expired, "kdns_fcache_clr");

    return 0;
}
