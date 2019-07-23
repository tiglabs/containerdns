#define _GNU_SOURCE
#include <sys/time.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <rte_rwlock.h>
#include <string.h>
#include <jansson.h>

#include "hashMap.h"
#include "util.h"
#include "metrics.h"
#include "dns-conf.h"


#define METRICS_HASH_SIZE                0x3FFFF
#define METRICS_LOCK_SIZE                0xF

// 10 minutes
#define METRICS_TIME_EXPIRED  ( 10*60*1000*1000)

#define METRICS_MAX_NAME_LEN  255


// domain query metrics 
typedef struct metrics_domain{
	uint64_t requestCount  ;       
	uint64_t lastQueryTime ; // unix time us
	uint64_t firstQueryTime ;// unix time us
	metrics_metrics_st metrics;
  
}metrics_domain_st;

 // domain+clinetIp query metrics
 typedef struct metrics_domain_clientIp{
    char  domain_name[METRICS_MAX_NAME_LEN];
    uint32_t src_addr; 
	uint64_t requestCount  ;        
	uint64_t lastQueryTime ; // unix time us
	uint64_t firstQueryTime ;// unix time us
}metrics_domain_clientIp_st;

static hashMap *g_metrics_fwd_domains = NULL;
static hashMap *g_metrics_fwd_domains_client = NULL;

static json_t * json_metrics_fwd_domains = NULL; 
static json_t * json_metrics_fwd_clieintIp = NULL; 

static rte_rwlock_t metrics_lock;

static char *g_dns_host_name = NULL;

uint64_t time_now_usec(void){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (0LL + 1000 * 1000) * tv.tv_sec  + tv.tv_usec ;
}


static int metrics_check_equal(char *key, hashNode *node, __attribute__((unused))void *check){
    if (strcmp(key,node->key)==0){
        return 1;
    }
    return 0;
}

void metrics_data_update(  metrics_metrics_st* metrics,uint64_t diff_us){

     if (diff_us > metrics->maxTime){
        metrics->maxTime = diff_us;     
     }
     if (diff_us < metrics->minTime){
        metrics->minTime = diff_us;     
     }
     // 10 us
     if (diff_us <= 10){
        metrics->metrics[0]++;   
     }else if((10 < diff_us) && (diff_us <= 100)){
         metrics->metrics[1]++; 
     }else if((100 < diff_us) && (diff_us <= 1000)){
         metrics->metrics[2]++; 
     }else{
         metrics->metrics[3]++; 
     }
     metrics->timeSum += diff_us;
     return;
}


static int metrics_domain_query(hashNode *node, void* input){

     metrics_domain_st *mNode = (metrics_domain_st*) node->data;

     uint64_t *p_time_start  = (uint64_t*)input;
     uint64_t time_now = time_now_usec();

     uint64_t diff = time_now - *p_time_start;
     mNode->requestCount++;
     mNode->lastQueryTime = time_now;
     metrics_data_update(&mNode->metrics, diff);
     return 1;
}



static int metrics_domain_clientIp_query(hashNode *node, void* input){

     uint64_t *p_time_start  = (uint64_t*)input;

     metrics_domain_clientIp_st *mNode = (metrics_domain_clientIp_st*) node->data;
     mNode->requestCount++;
     mNode->lastQueryTime  = *p_time_start;
     return 1;
}



static int metrics_domain_query_all_and_reset(hashNode *node, void* arg){

     metrics_domain_st *mNode = (metrics_domain_st*) node->data;

     json_t * array  = (json_t *)arg;

     json_t *value = json_pack("{s:s, s:f, s:f, s:f, s:f,s:f, s:f, s:f, s:f, s:f, s:f}",
                    "Domain", node->key, "QueryNum", (double)mNode->requestCount, "FirstQueryTime", (double)mNode->firstQueryTime,
                    "LastQueryTime",(double)mNode->lastQueryTime,"MinTime", (double)mNode->metrics.minTime,"MaxTime", (double)mNode->metrics.maxTime,
                    "SumTime",(double)mNode->metrics.timeSum,"metrics1",(double)mNode->metrics.metrics[0],"metrics2",(double)mNode->metrics.metrics[1],
                    "metrics3",(double)mNode->metrics.metrics[2],"metrics4",(double)mNode->metrics.metrics[3]);

     memset(&mNode->metrics, 0, sizeof(metrics_metrics_st));
     mNode->metrics.minTime = 0xffff;

     json_array_append_new(array, value);
     return 1;
}

static int metrics_domain_clientip_query_all(hashNode *node, void* arg){

     metrics_domain_clientIp_st *mNode = (metrics_domain_clientIp_st*) node->data;
     json_t * array  = (json_t *)arg;

     json_t *value = json_pack("{s:s, s:s, s:f, s:f, s:f,s:i}",
                    "Domain", mNode->domain_name,"Host", g_dns_host_name, "QueryNum", (double)mNode->requestCount, "FirstQueryTime", (double)mNode->firstQueryTime,
                    "LastQueryTime",(double)mNode->lastQueryTime,"SourceIP", mNode->src_addr);

     json_array_append_new(array, value);
     return 1;
}

static int metrics_domian_expired_check(hashNode *node,void *now){
    uint64_t *time_now = (uint64_t *)now;
    metrics_domain_st *mNode = (metrics_domain_st*) node->data;
    //printf("metrics_domian_expired_check : %s\n",node->key);
    if (mNode->lastQueryTime + METRICS_TIME_EXPIRED < *time_now){
        return 1;   
    }   
    return 0; 
}

static int metrics_clientIp_expired_check(hashNode *node,void *now){
    uint64_t *time_now = (uint64_t *)now;
    //printf("metrics_clientIp_expired_check : %s\n",node->key);
    metrics_domain_clientIp_st *mNode = (metrics_domain_clientIp_st*) node->data;
    // 
    if (mNode->lastQueryTime + METRICS_TIME_EXPIRED < *time_now){
        return 1;   
    }   
    return 0; 
}


void metrics_domain_update(char *domain, int64_t timeStart){
    
    if (HASH_NODE_FIND == hmap_lookup(g_metrics_fwd_domains, domain, NULL, (void*)&timeStart)){
        return; 
    }
   
    metrics_domain_st * newNode = xalloc_zero(sizeof(metrics_domain_st));
    newNode->firstQueryTime = newNode->lastQueryTime = timeStart;
    newNode->requestCount = 1;
    newNode->metrics.minTime = 0xffff; 
    hmap_update(g_metrics_fwd_domains, domain, NULL, (void*)newNode);
}

void metrics_domain_clientIp_update(char *domain, int64_t timeStart, uint32_t src_addr){

    char  key[METRICS_MAX_NAME_LEN]= {0};
    sprintf(key,"%s-%d",domain, src_addr);
    
    if (HASH_NODE_FIND == hmap_lookup(g_metrics_fwd_domains_client, key, NULL, (void*)&timeStart)){
        return; 
    }
    metrics_domain_clientIp_st * newNode = xalloc_zero(sizeof(metrics_domain_clientIp_st));
    newNode->firstQueryTime = newNode->lastQueryTime = timeStart;
    memcpy(newNode->domain_name,domain,strlen(domain));
    newNode->src_addr = src_addr;
    newNode->requestCount = 1;
  
    hmap_update(g_metrics_fwd_domains_client, key, NULL, (void*)newNode);
}


static void *thread_metrics_expired_cleanup(void *arg){
    (void)arg;
    int del_nums = 0;

    while (1) {
        sleep(600);
        uint64_t time_now = time_now_usec();
        del_nums = hmap_check_expired(g_metrics_fwd_domains, (void *)&time_now);
        if (del_nums) {
            log_msg(LOG_INFO, "metrics fwd domains expired: %d record dels\n", del_nums);
        }

        del_nums = hmap_check_expired(g_metrics_fwd_domains_client, (void *)&time_now);
        if (del_nums) {
            log_msg(LOG_INFO, "metrics fwd domains client expired: %d record dels\n", del_nums);
        }
    }
    return NULL;
}

static void *thread_metrics_domain_getAll(void *arg){
	 (void)arg;
     //sleep 2s let cleanup thread run first
     sleep(2);
     json_t * array_tmp = NULL;
     while (1){
         sleep(600);

         array_tmp = json_array();
         if(!array_tmp){
             log_msg(LOG_ERR,"unable to create array\n");
              continue;
         }             
         hmap_get_all(g_metrics_fwd_domains, (void*)array_tmp); 

         rte_rwlock_write_lock(&metrics_lock);
         json_decref(json_metrics_fwd_domains);
         json_metrics_fwd_domains = array_tmp;
         rte_rwlock_write_unlock(&metrics_lock);
    }
     return NULL;
}

static void *thread_metrics_domain_clientIp_getAll(void *arg){
	 (void)arg;
     sleep(2);
     json_t * array_tmp = NULL;
     while (1){
         sleep(600);

         array_tmp = json_array();
         if(!array_tmp){
             log_msg(LOG_ERR,"unable to create array\n");
              continue;
         }             
         hmap_get_all(g_metrics_fwd_domains_client, (void*)array_tmp); 

         rte_rwlock_write_lock(&metrics_lock);
         json_decref(json_metrics_fwd_clieintIp);
         json_metrics_fwd_clieintIp = array_tmp;
         rte_rwlock_write_unlock(&metrics_lock);
    }
     return NULL;
}



void* metrics_domains_get( __attribute__((unused)) struct connection_info_struct *con_info,__attribute__((unused))char *url, int * len_response)
{
    char *str_ret = NULL;
    rte_rwlock_read_lock(&metrics_lock);
    if (json_metrics_fwd_domains != NULL){
        str_ret = json_dumps(json_metrics_fwd_domains, JSON_COMPACT);
    }else{
        str_ret = strdup("nodata");
    }
    rte_rwlock_read_unlock(&metrics_lock);
    *len_response = strlen(str_ret);
    return (void* )str_ret;
}

void* metrics_domains_clientIp_get( __attribute__((unused)) struct connection_info_struct *con_info,__attribute__((unused))char *url, int * len_response)
{
    char *str_ret = NULL;
    rte_rwlock_read_lock(&metrics_lock);
    if (json_metrics_fwd_clieintIp != NULL){
        str_ret = json_dumps(json_metrics_fwd_clieintIp, JSON_COMPACT);
    }else{
        str_ret = strdup("nodata");
    }
    rte_rwlock_read_unlock(&metrics_lock);
    *len_response = strlen(str_ret);
    return (void* )str_ret;
}

int metrics_host_reload(char *host_name) {
    char *tmp = g_dns_host_name;
    g_dns_host_name = strdup(host_name);
    if (tmp) {
        free(tmp);
    }
    return 0;
}

void fwd_metrics_init(void) {
    g_metrics_fwd_domains = hmap_create(METRICS_HASH_SIZE, METRICS_LOCK_SIZE, elfHashDomain,
        metrics_check_equal, metrics_domain_query, metrics_domian_expired_check, metrics_domain_query_all_and_reset); 
    g_metrics_fwd_domains_client = hmap_create(METRICS_HASH_SIZE, METRICS_LOCK_SIZE, elfHashDomain,
        metrics_check_equal, metrics_domain_clientIp_query, metrics_clientIp_expired_check, metrics_domain_clientip_query_all); 
    
    json_metrics_fwd_domains = json_array();
    if(!json_metrics_fwd_domains){
        log_msg(LOG_ERR,"unable to create array\n");
        exit(-1);
    }
    json_metrics_fwd_clieintIp = json_array();

    if(!json_metrics_fwd_clieintIp){
        log_msg(LOG_ERR,"unable to create array\n");
        exit(-1);
    }
    g_dns_host_name = strdup(g_dns_cfg->comm.metrics_host);

    rte_rwlock_init(&metrics_lock);  

    // cache date expired clean up thread
    pthread_t *thread_cache_expired = (pthread_t *)  xalloc(sizeof(pthread_t));  
    pthread_create(thread_cache_expired, NULL, thread_metrics_expired_cleanup, (void*)NULL);
    pthread_setname_np(*thread_cache_expired, "kdns_mcache_clr");

   // sleep(3);

    // metrics_domains thread
    pthread_t *thread_domain_metrics = (pthread_t *)  xalloc(sizeof(pthread_t));  
    pthread_create(thread_domain_metrics, NULL, thread_metrics_domain_getAll, (void*)NULL);
    pthread_setname_np(*thread_domain_metrics, "kdns_domain_get");

    // metrics_domains_clientIp thread
    pthread_t *thread_domain_clientIp_metrics = (pthread_t *)  xalloc(sizeof(pthread_t));  
    pthread_create(thread_domain_clientIp_metrics, NULL, thread_metrics_domain_clientIp_getAll, (void*)NULL);
    pthread_setname_np(*thread_domain_clientIp_metrics, "kdns_cip_get");
} 


