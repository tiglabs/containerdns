#ifndef _TCP_PROCESS_H_
#define _TCP_PROCESS_H_

#include <arpa/inet.h>
#include "db_update.h"

void tcp_statsdata_get(struct netif_queue_stats *sta);

void tcp_statsdata_reset(void);

int tcp_process_init(void);

int tcp_domian_databd_update(struct domin_info_update *update);

int tcp_zones_reload(char *del_zones, char *add_zones);

#endif  /*_TCP_PROCESS_H_*/

