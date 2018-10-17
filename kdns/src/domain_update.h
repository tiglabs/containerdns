#ifndef __DOMAIN_UPDATE_H__
#define __DOMAIN_UPDATE_H__

#include "db_update.h"

void domian_info_exchange_run( int port);

void domain_msg_ring_create(void);
void doman_msg_master_process(void);
void doman_msg_slave_process(void);

#endif
