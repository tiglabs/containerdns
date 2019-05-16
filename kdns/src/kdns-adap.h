#ifndef _NSD_APAPTER_H_
#define _NSD_APAPTER_H_

#include "query.h"
#include "kdns.h"
#include "util.h"

int dnsdata_prepare(struct kdns * kdns);
int kdns_init(unsigned lcore_id);
int kdns_prepare_init(struct kdns *kdns, struct query **query);

kdns_query_st* dns_packet_proess(struct rte_mbuf *pkt ,uint32_t sip, int offset, int received); 
int check_pid(const char *pid_file);
void write_pid(const char *pid_file);
void kdns_zones_soa_create(struct  domain_store *db,char * zonesName);

#endif
