

#ifndef	_FORWARD_H_
#define	_FORWARD_H_

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
    char  domain_name[FWD_MAX_DOMAIN_NAME_LEN];
    int servers_len;
    dns_addr_t server_addrs[FWD_MAX_ADDRS];
} domain_fwd_addrs;

typedef struct {
    int mode;
    int timeout;
    domain_fwd_addrs *default_addrs;
    int zones_addrs_num;
    domain_fwd_addrs **zones_addrs;
} domain_fwd_addrs_ctrl;

int fwd_server_init(void);
int dns_handle_remote(struct rte_mbuf *pkt,uint16_t old_id,uint16_t qtype,uint32_t src_addr, char *domain);
uint16_t fwd_pkts_dequeue(struct rte_mbuf **mbufs,uint16_t pkts_cnt);
domain_fwd_addrs *fwd_addrs_find(char * domain_name);
int dns_tcp_process_init(char *ip);
void fwd_statsdata_get(struct netif_queue_stats *sta);
void fwd_statsdata_reset(void);

int fwd_def_addrs_reload(char *addrs);
int fwd_zones_addrs_reload(char *addrs);
int fwd_timeout_reload(int timeout);
int fwd_mode_reload(char *mode);
#endif	/*_FORWARD_H_*/
