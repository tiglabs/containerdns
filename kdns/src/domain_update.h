#ifndef __DOMAIN_UPDATE_H__
#define __DOMAIN_UPDATE_H__

#include "db_update.h"

#define DNS_STATUS_INIT    "init"
#define DNS_STATUS_RUN     "running"

void domian_info_exchange_run(uint16_t web_port, int ssl_enable, char *key_pem_file, char *cert_pem_file);

int domain_list_del_zones(char *del_zones);

void domain_info_master_init(void);

#endif
