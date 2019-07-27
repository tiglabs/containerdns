#ifndef _NSD_APAPTER_H_
#define _NSD_APAPTER_H_

#include "query.h"
#include "kdns.h"
#include "util.h"

int kdns_init(char *zones, unsigned lcore_id);

int kdns_prepare_init(struct kdns *kdns, struct query **query, char *zones);

kdns_query_st *dns_packet_proess(uint32_t sip, uint8_t *query_data, int query_len, unsigned lcore_id);

int check_pid(const char *pid_file);

void write_pid(const char *pid_file);

int kdns_zones_realod(struct kdns* kdns, char *del_zones, char *add_zones);

int kdns_slave_zones_realod(char *del_zones, char *add_zones, unsigned lcore_id);

#endif
