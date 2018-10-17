#ifndef _NSD_APAPTER_H_
#define _NSD_APAPTER_H_

#include "query.h"
#include "kdns.h"
#include "util.h"


int kdns_init(unsigned lcore_id);

kdns_query_st* dns_packet_proess(struct rte_mbuf *pkt ,uint32_t sip, int offset, int received); 
int check_pid(const char *pid_file);
void write_pid(const char *pid_file);
void kdns_zones_soa_create(struct  domain_store *db,char * zonesName);

#endif
