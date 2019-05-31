#ifndef _DNS_PROCESS_
#define _DNS_PROCESS_
#include <rte_mbuf.h>
#include "netdev.h"

int packet_l3_handle(struct rte_mbuf *pkt, struct netif_queue_conf *conf, unsigned lcore_id);
int process_slave(__attribute__((unused)) void *arg);
void process_master(__attribute__((unused)) void *arg);



#endif
