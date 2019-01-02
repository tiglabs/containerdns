#ifndef __DOMAIN_UPDATE_H__
#define __DOMAIN_UPDATE_H__

#include "db_update.h"

#define DNS_STATUS_INIT    "init"
#define DNS_STATUS_RUN     "running"

void domian_info_exchange_run( int port);

void domain_msg_ring_create(void);
void doman_msg_master_process(void);
void doman_msg_slave_process(void);

void domain_set_kdns_status(const char* status);
void domain_list_del_zone(char* zone);
#endif
