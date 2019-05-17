#ifndef _TCP_PROCESS_H_
#define _TCP_PROCESS_H_

#include <arpa/inet.h>
#include "db_update.h"

void tcp_statsdata_get(struct netif_queue_stats *sta);

void tcp_statsdata_reset(void);

int tcp_process_init(char *ip);

int tcp_domian_databd_update(struct domin_info_update *update);

#endif  /*_TCP_PROCESS_H_*/

