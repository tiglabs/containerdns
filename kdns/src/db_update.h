#ifndef __DB_UPDATE_H__
#define __DB_UPDATE_H__

#include "domain_store.h"
#include "zone.h"
#include "kdns.h"

#define DB_MAX_NAME_LEN  255


enum db_action {
 DOMAN_ACTION_ADD ,
 DOMAN_ACTION_DEL 
};

typedef struct domin_info_update{
    enum db_action   action;
 	uint32_t         ttl;
    uint16_t         type;
    uint16_t         prio;
    uint16_t         weight;
    uint16_t         port;
    uint32_t         maxAnswer;
    unsigned int     hashValue ; // hash check
    

    uint16_t         lb_mode;
    uint16_t         lb_weight;

    char  view_name[DB_MAX_NAME_LEN];
    
    char  type_str[DB_MAX_NAME_LEN];
    char  zone_name[DB_MAX_NAME_LEN];
    char  domain_name[DB_MAX_NAME_LEN];
    char  host[DB_MAX_NAME_LEN];
    struct domin_info_update *next;  
}domin_info_update_st;

int domaindata_update(struct  domain_store *db, struct domin_info_update * update);
int domaindata_soa_insert(struct  domain_store *db,char *zone_name);
int domaindata_srv_insert(struct  domain_store *db,char *zone_name,char *domain_name, char * host,uint16_t prio,uint16_t weight,
uint16_t port, uint32_t ttl,uint32_t maxAnswer);
int domaindata_srv_delete(struct  domain_store *db,char *zone_name,char *domain_name, char * host,uint16_t prio,uint16_t weight,
uint16_t port, uint32_t ttl ,uint32_t maxAnswer);
int domaindata_cname_insert(struct  domain_store *db,char *zone_name,char *domain_name, char * host, uint32_t ttl,uint32_t maxAnswer);
int domaindata_cname_delete(struct  domain_store *db,char *zone_name,char *domain_name);
int domaindata_a_insert(struct  domain_store *db,char *zone_name,char *domain_name, char* view_name, char * ip_addr, uint32_t ttl,
                       uint16_t lb_mode,uint16_t lb_weight,uint32_t maxAnswer);
int domaindata_a_delete(struct  domain_store *db,char *zone_name,char *domain_name, char* view_name, char * ip_addr, uint32_t ttl);
int domaindata_ptr_insert(struct domain_store *db, char *zone_name, char *domain_name, char *host, uint32_t ttl, uint32_t maxAnswer);
int domaindata_ptr_delete(struct domain_store *db, char *zone_name, char *domain_name, char *host, uint32_t ttl, uint32_t maxAnswer);

#endif
