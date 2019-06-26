#ifndef __DOMAIN_UPDATE_H__
#define __DOMAIN_UPDATE_H__

#include "db_update.h"

#define DNS_STATUS_INIT    "init"
#define DNS_STATUS_RUN     "running"

void domian_info_exchange_run(int port);

void domain_list_del_zone(char *zone);

void domain_msg_slave_process(ctrl_msg *msg, unsigned slave_lcore);

void domain_msg_master_process(ctrl_msg *msg);

void domain_info_master_init(void);

#endif
