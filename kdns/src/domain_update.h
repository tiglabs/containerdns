#ifndef __DOMAIN_UPDATE_H__
#define __DOMAIN_UPDATE_H__

#include "db_update.h"

#define DNS_STATUS_INIT    "init"
#define DNS_STATUS_RUN     "running"

void domian_info_exchange_run( int port);

void domain_msg_ring_create(unsigned lcore_id);
void domain_msg_master_process(void);
void domain_msg_slave_process(void);

void domain_list_del_zone(char* zone);
#endif
