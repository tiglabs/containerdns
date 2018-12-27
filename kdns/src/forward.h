

#ifndef	_FORWARD_H_
#define	_FORWARD_H_

#include <arpa/inet.h>
#include <rte_rwlock.h>
#define FWD_MAX_DOMAIN_NAME_LEN  255

rte_rwlock_t __fwd_lock;

typedef struct {
   struct sockaddr *addr;
   socklen_t addrlen;
 } dns_addr_t;

typedef struct {
   char  domain_name[FWD_MAX_DOMAIN_NAME_LEN];
   int servers_len;
   dns_addr_t *server_addrs;
 } domain_fwd_addrs;

int remote_sock_init(char * fwd_addrs, char * fwd_def_addr,int fwd_threads);
int dns_handle_remote(struct rte_mbuf *pkt,uint16_t old_id,uint16_t qtype,char *domain);
uint16_t fwd_pkts_dequeue(struct rte_mbuf **mbufs,uint16_t pkts_len);
domain_fwd_addrs * find_zone_fwd_addrs(char * domain_name);
int dns_tcp_process_init(char *ip);
void fwd_statsdata_get(struct netif_queue_stats *sta);
void fwd_statsdata_reset();

int fwd_def_addrs_reload(char *addrs);
int fwd_addrs_reload(char *addrs);
#endif	/*_FORWARD_H_*/
