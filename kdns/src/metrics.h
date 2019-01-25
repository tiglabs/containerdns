#ifndef _METRICS_H_
#define _METRICS_H_

#include <stdio.h>
#include <time.h>
#include "webserver.h"


typedef struct metrics_metrics{
	uint64_t minTime     ;  
	uint64_t maxTime     ;    
	uint64_t timeSum     ;    
	uint64_t metrics  [4];
}metrics_metrics_st;


uint64_t time_now_usec(void);
void fwd_metrics_init(void);

void metrics_domain_clientIp_update(char *domain, int64_t timeStart, uint32_t src_addr);

void metrics_domain_update(char *domain, int64_t timeStart);

void* metrics_domains_get( __attribute__((unused)) struct connection_info_struct *con_info,
    __attribute__((unused))char *url, int * len_response);
void* metrics_domains_clientIp_get( __attribute__((unused)) struct connection_info_struct *con_info,
    __attribute__((unused))char *url, int * len_response);

void metrics_data_update(  metrics_metrics_st* metrics,uint64_t diff_us);

#endif  /*_METRICS_H_*/

