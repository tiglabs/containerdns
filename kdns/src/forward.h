#ifndef _FORWARD_H_
#define _FORWARD_H_

#define _GNU_SOURCE

#include <pthread.h>
#include <rte_mbuf.h>
#include <arpa/inet.h>
#include <rte_rwlock.h>

#include "dns.h"
#include "netdev.h"

#define FWD_MAX_ADDRS               (16)

extern pthread_rwlock_t __fwd_lock;

typedef enum {
    FWD_MODE_TYPE_DISABLE,
    FWD_MODE_TYPE_DIRECT,
    FWD_MODE_TYPE_CACHE,
    FWD_MODE_TYPE_MAX,
} fwd_mode_type;

static const char *fwd_mode_str_array[FWD_MODE_TYPE_MAX] = {
    "disable",
    "direct",
    "cache"
};

static inline const char *fwd_mode_type_str(fwd_mode_type type) {
    if (unlikely(type < 0 || type >= FWD_MODE_TYPE_MAX)) {
        return "illegal type";
    }
    return fwd_mode_str_array[type];
}

typedef struct {
    struct sockaddr addr;
    socklen_t addrlen;
} dns_addr_t;

typedef struct {
    char domain_name[MAXDOMAINLEN];
    int servers_len;
    dns_addr_t server_addrs[FWD_MAX_ADDRS];
} domain_fwd_addrs;

typedef struct {
    int mode;
    int timeout;    //second
    domain_fwd_addrs *default_addrs;
    int zones_addrs_num;
    domain_fwd_addrs *zones_addrs;
} domain_fwd_ctrl;

domain_fwd_addrs *fwd_addrs_find(char *domain_name, domain_fwd_ctrl *ctrl);

int fwd_mode_parse(const char *entry);

int fwd_ctrl_master_reload(int mode, int timeout, char *def_addrs, char *zone_addrs);

int fwd_ctrl_slave_reload(int mode, int timeout, char *def_addrs, char *zone_addrs, unsigned slave_lcore);

void fwd_statsdata_get(struct netif_queue_stats *sta);

void fwd_statsdata_reset(void);

unsigned fwd_response_dequeue(struct rte_mbuf **pkts, unsigned pkts_cnt);

int fwd_query_enqueue(struct rte_mbuf *pkt, uint32_t src_addr, uint16_t id, uint16_t qtype, char *domain_name);

int fwd_server_init(void);

void *fwd_caches_get(__attribute__((unused))struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response);

void *fwd_caches_delete(__attribute__((unused))struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response);

#endif  /*_FORWARD_H_*/
