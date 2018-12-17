#ifndef _TCP_PROCESS_H_
#define _TCP_PROCESS_H_

#include <arpa/inet.h>

void tcp_statsdata_get(struct netif_queue_stats *sta);
void tcp_statsdata_reset();
#endif  /*_TCP_PROCESS_H_*/

