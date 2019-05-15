#ifndef _FORWARD_H_
#define _FORWARD_H_

#define _GNU_SOURCE

#include <pthread.h>
#include <rte_mbuf.h>
#include <arpa/inet.h>
#include <rte_rwlock.h>

#include "netdev.h"

#define FWD_MAX_DOMAIN_NAME_LEN     (255)
#define FWD_MAX_ADDRS               (16)

#define FWD_MODE_DISABLE            (0x0)
#define FWD_MODE_DIRECT             (0x1)
#define FWD_MODE_CACHE              (0x2)

extern pthread_rwlock_t __fwd_lock;

typedef struct {
    struct sockaddr addr;
    socklen_t addrlen;
} dns_addr_t;

typedef struct {
    char domain_name[FWD_MAX_DOMAIN_NAME_LEN];
    int servers_len;
    dns_addr_t server_addrs[FWD_MAX_ADDRS];
} domain_fwd_addrs;

typedef struct {
    int mode;
    int timeout;    //second
    domain_fwd_addrs *default_addrs;
    int zones_addrs_num;
    domain_fwd_addrs **zones_addrs;
} domain_fwd_addrs_ctrl;

domain_fwd_addrs *fwd_addrs_find(char *domain_name, domain_fwd_addrs_ctrl *ctrl);

int fwd_zones_addrs_reload(char *addrs);

int fwd_def_addrs_reload(char *addrs);

int fwd_timeout_reload(int timeout);

int fwd_mode_reload(char *mode);

int fwd_addrs_reload_proc(unsigned cid);

void fwd_statsdata_get(struct netif_queue_stats *sta);

void fwd_statsdata_reset(void);

unsigned fwd_response_dequeue(struct rte_mbuf **pkts, unsigned pkts_cnt);

int fwd_query_enqueue(struct rte_mbuf *pkt, uint32_t src_addr, uint16_t id, uint16_t qtype, char *domain_name);

int fwd_server_init(void);

void *fwd_caches_get(__attribute__((unused))struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response);

void *fwd_caches_delete(__attribute__((unused))struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response);

#endif  /*_FORWARD_H_*/
