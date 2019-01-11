/*
 * data_update.c 
 */
#include <stdlib.h>
#include "db_update.h"
#include "util.h"


static rrset_type *  do_domaindata_insert(struct  domain_store *db,zone_type * zo,const domain_name_st * dname  ,rr_type *rr,uint32_t maxAnswer ){

	rrset_type *rrset;

    // insert domain
    //domain_name_st * dname = domain_name_make(db->domain,1);
    domain_type* owner = domain_table_insert(db->domains,dname,maxAnswer);

    rr->owner = owner;

    /* Do we have this type of rrset already? */
    rrset = domain_find_rrset(rr->owner, zo, rr->type);
    if (!rrset) {
        rrset = (rrset_type *) xalloc_zero(sizeof(rrset_type));
        rrset->zone = zo;
        rrset->rr_count = 1;
        rrset->rrs = (rr_type *) xalloc_zero(sizeof(rr_type));
        rrset->rrs[0] = *rr;

        /* Add it */
        domain_add_rrset(rr->owner, rrset);
    } else {
        int i;
        rr_type* o;
        if (rrset->rrs[0].ttl != rr->ttl) {
            log_msg(LOG_ERR,"TTL  does not match\n");
            return NULL;        
        }

        /* Search for possible duplicates... */
        for (i = 0; i < rrset->rr_count; i++) {
            if (!zrdatacmp(rr->type, rr, &rrset->rrs[i])) {
                break;
            }
        }

        /* Discard the duplicates... */
        if (i < rrset->rr_count) {
            return NULL;
        }
        if(rrset->rr_count == 65535) {
            log_msg(LOG_ERR,"too many RRs for domain RRset");
            return NULL;
        }

        /* Add it... */
        o = rrset->rrs;
        rrset->rrs = (rr_type *) xalloc_array_zero(rrset->rr_count + 1, sizeof(rr_type));
        memcpy(rrset->rrs, o, (rrset->rr_count) * sizeof(rr_type));
        free(o);
        rrset->rrs[rrset->rr_count] = *rr;
        ++rrset->rr_count;
    } 
    return rrset ;
}

static int  do_domaindata_delete(struct  domain_store *db,zone_type * zo,const domain_name_st * dname  ,rr_type *rr ){

	rrset_type *rrset;
    domain_type* domain = domain_table_find(db->domains,dname);
    if (domain == NULL){
       log_msg(LOG_ERR,"domain not find :%s \n",domain_name_get(dname));
       return -1;
    }

    /* Do we have this type of rrset already? */
    rrset = domain_find_rrset(domain, zo, rr->type);
    if (!rrset) {
        log_msg(LOG_ERR,"rrset not find :%s \n",domain_name_get(dname));
       return -1;
    } else {
        int rrnum;
        /* Search for the val ... */
        for (rrnum = 0; rrnum < rrset->rr_count; rrnum ++) {
            if (!zrdatacmp(rr->type, rr, &rrset->rrs[rrnum])) {
                break;
            }
        }
        // find
   
        if (rrnum < rrset->rr_count) {   
             rr_lower_usage(db, &rrset->rrs[rrnum]);
             if(rrset->rr_count == 1) {
                rrset_delete(db, domain, rrset);
                rrset_zero_nonexist_check(domain, NULL);
                domain_table_deldomain(db, domain);
             }else{
                rr_type* rrs_orig = rrset->rrs;
                add_rdata_to_recyclebin( &rrset->rrs[rrnum]);
                if(rrnum < rrset->rr_count-1)
                    rrset->rrs[rrnum] = rrset->rrs[rrset->rr_count-1];
                memset(&rrset->rrs[rrset->rr_count-1], 0, sizeof(rr_type));

                /* realloc the rrs array one smaller */
                rrset->rrs = xalloc_array_zero(rrset->rr_count-1,  sizeof(rr_type));
                if(!rrset->rrs) {
                    log_msg(LOG_ERR,"out of memory, %s:%d", __FILE__, __LINE__);
                    exit(1);
                }
                memcpy(rrset->rrs,rrs_orig,(rrset->rr_count-1) * sizeof(rr_type));
                free(rrs_orig);
                rrset->rr_count --;  
             }          
        }
    } 
    return 0 ;
}

static 
int do_domaindata_delete_all(struct  domain_store *db,zone_type * zo,const domain_name_st * dname ){

    domain_type* owner = domain_table_find(db->domains,dname);  
    if (owner == NULL){
          log_msg(LOG_ERR,"can not find domain: %s \n",domain_name_get(dname));
          return -1;    
    }
    rrset_type *rrset;

/* delete all rrsets of the zone */
	while((rrset = domain_find_any_rrset(owner, zo))) {
		/* lower usage can delete other domains */
		rrset_lower_usage(db, rrset);
		/* rrset del does not delete our domain(yet) */
		rrset_delete(db, owner, rrset);
     }
 
    domain_table_deldomain(db,owner);
    return 0;    
}


static void
db_zadd_rdata_domain( struct  domain_store *db,char *domain_name,rr_type * rr_insert)
{

    const domain_name_st* dname = domain_name_parse((const char*)domain_name);
    domain_type* owner = domain_table_insert(db->domains,dname,0);

   	if (rr_insert->rdata_count >= MAXRDATALEN) {
		log_msg(LOG_ERR,"too many rdata elements");
	} else {
        rr_insert->rdatas[rr_insert->rdata_count].domain = owner;
        owner->usage ++; /* new reference to domain */
        ++rr_insert->rdata_count;
	}
}

static void
db_zadd_rdata_wireformat(rr_type * rr_insert, uint16_t *data)
{
	if (rr_insert->rdata_count >= MAXRDATALEN) {
		log_msg(LOG_ERR,"too many rdata elements");
	} else {
		rr_insert->rdatas[rr_insert->rdata_count].data = data;
		++ rr_insert->rdata_count;
	}
}



int domaindata_soa_insert(struct  domain_store *db,char *zone_name){
    const domain_name_st* zname = domain_name_parse((const char*)zone_name);    
    if (zname == NULL) {
        log_msg(LOG_ERR," illegal zone name %s\n", zone_name);
        return -1;
    }
    	/* find zone to go with it, or create it */
	zone_type * zo = domain_store_find_zone(db, zname);
	if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;		
	}

    rr_type * rr_insert =  (rr_type *) xalloc_zero(sizeof(rr_type));
    rr_insert->klass      = CLASS_IN;
    rr_insert->type       = TYPE_SOA;
    rr_insert->rdata_count = 0;

    char z_name[64]={0};
    snprintf(z_name, sizeof(z_name), "ns1.%s", zone_name);
    rr_insert->rdatas =  xalloc_array_zero( MAXRDATALEN, sizeof(rdata_atom_type));

    db_zadd_rdata_domain(db,z_name,rr_insert);//ns
    snprintf(z_name, sizeof(z_name), "mail.%s", zone_name);
    db_zadd_rdata_domain(db,z_name,rr_insert);//email
    db_zadd_rdata_wireformat(rr_insert, zparser_conv_serial("2017070809"));//serial number
    db_zadd_rdata_wireformat(rr_insert, zparser_conv_serial("3600"));//refresh
    db_zadd_rdata_wireformat(rr_insert, zparser_conv_serial("900"));//retry
    db_zadd_rdata_wireformat(rr_insert, zparser_conv_serial("1209600"));//expire
    db_zadd_rdata_wireformat(rr_insert, zparser_conv_serial("1800"));//  ttl

    domain_type* owner = domain_table_insert(db->domains,zname,0);
    rrset_type *  rrset = do_domaindata_insert(db,zo,zname, rr_insert,0);
    if (rrset == NULL) {
        add_rdata_to_recyclebin(rr_insert);
        free(rr_insert);
        return -1;
    }
        
        apex_rrset_checks(rrset,owner);
    free(rr_insert);
        return 0;
    }

int domaindata_srv_insert(struct domain_store *db, char *zone_name, char *domain_name, char *host, uint16_t prio, 
    uint16_t weight,uint16_t port, uint32_t ttl,uint32_t maxAnswer ){
    const domain_name_st* zname = domain_name_parse((const char *)zone_name);    
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    const  domain_name_st* hostDomain = domain_name_parse((const char *) host); 
    if (zname == NULL || dname == NULL || hostDomain == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s or host domain %s\n", zone_name, domain_name, host);
        return -1;
    }
   /* find zone to go with it, or create it */
	zone_type * zo = domain_store_find_zone(db, zname);
	if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;
    }
    domain_type* owner = domain_table_insert(db->domains, hostDomain, maxAnswer);//domain_table_find
    if (owner == NULL) {
       log_msg(LOG_ERR,"err can not find domain : %s\n", host);
        return -1;		
	}

   rr_type * rr_insert =  (rr_type *) xalloc_zero(sizeof(rr_type));
   rr_insert->klass      = CLASS_IN;
   rr_insert->type       = TYPE_SRV;
   rr_insert->ttl        = ttl;
   rr_insert->rdata_count = 0;
   rr_insert->rdatas =  xalloc_array_zero( MAXRDATALEN, sizeof(rdata_atom_type));

    char string[32];
    sprintf(string,"%d",prio); 
    db_zadd_rdata_wireformat(rr_insert, zparser_conv_short(string));//prio
    sprintf(string,"%d",weight); 
    db_zadd_rdata_wireformat(rr_insert, zparser_conv_short(string));//weight
    sprintf(string,"%d",port); 
    db_zadd_rdata_wireformat(rr_insert, zparser_conv_short(string));//port

    rr_insert->rdatas[rr_insert->rdata_count].domain = owner;
	owner->usage ++; /* new reference to domain */
	++rr_insert->rdata_count;
     
    rrset_type *  rrset = do_domaindata_insert(db,zo,dname, rr_insert,maxAnswer);
    if (rrset == NULL) {
        add_rdata_to_recyclebin(rr_insert);
        free(rr_insert);
        return -1;
    }

    free(rr_insert);
    return 0;
}

int domaindata_srv_delete(struct domain_store *db, char *zone_name, char *domain_name, char *host, uint16_t prio, 
                            uint16_t weight, uint16_t port, uint32_t ttl,uint32_t maxAnswer){
    const domain_name_st* zname = domain_name_parse((const char*)zone_name);    
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    const domain_name_st* hostDomain = domain_name_parse((const char*)host); 
    if (zname == NULL || dname == NULL || hostDomain == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s or host domain %s\n", zone_name, domain_name, host);
        return -1;
    }
   /* find zone to go with it, or create it */
	zone_type * zo = domain_store_find_zone(db, zname);
	if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;		
	}
    domain_type* owner = domain_table_insert(db->domains, hostDomain, maxAnswer);//domain_table_find
    if (owner == NULL) {
       log_msg(LOG_ERR,"err can not find domain : %s\n", host);
    }

   rr_type * rr_del=  (rr_type *) xalloc_zero(sizeof(rr_type));
   rr_del->klass      = CLASS_IN;
   rr_del->type       = TYPE_SRV;
   rr_del->ttl        = ttl;
   rr_del->rdata_count = 0;
   rr_del->rdatas =  xalloc_array_zero(MAXRDATALEN, sizeof(rdata_atom_type));

    char string[32];
    sprintf(string,"%d",prio); 
    db_zadd_rdata_wireformat(rr_del, zparser_conv_short(string));//prio
    sprintf(string,"%d",weight); 
    db_zadd_rdata_wireformat(rr_del, zparser_conv_short(string));//weight
    sprintf(string,"%d",port); 
    db_zadd_rdata_wireformat(rr_del, zparser_conv_short(string));//port

    rr_del->rdatas[rr_del->rdata_count].domain = owner;
	++rr_del->rdata_count;
     
   int ret = do_domaindata_delete(db,zo,dname,rr_del);
   add_rdata_to_recyclebin(rr_del);
   free(rr_del);
   return ret;
}

int domaindata_cname_insert(struct domain_store *db, char *zone_name, char *domain_name, char *host, uint32_t ttl, uint32_t maxAnswer){
    const domain_name_st* zname = domain_name_parse( (const char*)zone_name);    
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    const domain_name_st* hostDomain = domain_name_parse((const char*)host); 
    if (zname == NULL || dname == NULL || hostDomain == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s or host domain %s\n", zone_name, domain_name, host);
        return -1;
    }
   /* find zone to go with it, or create it */
	zone_type * zo = domain_store_find_zone(db, zname);
	if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;
    }
    domain_type* owner = domain_table_insert(db->domains, hostDomain, maxAnswer);//domain_table_find
    if (owner == NULL) {
       log_msg(LOG_ERR,"err can not find domain : %s\n", host);
        return -1;		
	}

   rr_type * rr_insert =  (rr_type *) xalloc_zero(sizeof(rr_type));
   rr_insert->klass      = CLASS_IN;
   rr_insert->type       = TYPE_CNAME;
   rr_insert->ttl        = ttl;
   rr_insert->rdata_count = 0;
   rr_insert->rdatas =  xalloc_array_zero( MAXRDATALEN, sizeof(rdata_atom_type));

    rr_insert->rdatas[rr_insert->rdata_count].domain = owner;
	owner->usage ++; /* reference to domain */
	++rr_insert->rdata_count;
     
    rrset_type *  rrset = do_domaindata_insert(db,zo,dname, rr_insert,maxAnswer);
    if (rrset == NULL) {
        add_rdata_to_recyclebin(rr_insert);
        free(rr_insert);
        return -1;
    }
        
        free (rr_insert);
        return 0;
    }

int domaindata_cname_delete(struct  domain_store *db, char *zone_name, char *domain_name){
    const domain_name_st *zname = domain_name_parse((const char *)zone_name);
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    if (zname == NULL || dname == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s\n", zone_name, domain_name);
    return -1;
}
   /* find zone to go with it, or create it */
	zone_type * zo = domain_store_find_zone(db, zname);
	if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;		
	}

   return do_domaindata_delete_all(db,zo,dname);
}

int domaindata_ptr_insert(struct domain_store *db, char *zone_name, char *domain_name, char *host, uint32_t ttl, uint32_t maxAnswer) {
    const domain_name_st *zname = domain_name_parse((const char*)zone_name);
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    const domain_name_st *hostDomain = domain_name_parse((const char *)host);
    if (zname == NULL || dname == NULL || hostDomain == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s or host domain %s\n", zone_name, domain_name, host);
        return -1;
    }
    /* find zone to go with it, or create it */
    zone_type * zo = domain_store_find_zone(db, zname);
    if (!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;
    }
    domain_type* owner = domain_table_insert(db->domains, hostDomain, maxAnswer);//domain_table_find
    if (owner == NULL) {
       log_msg(LOG_ERR,"err can not find domain : %s\n", host);
        return -1;
    }

    rr_type *rr_insert      = (rr_type *)xalloc_zero(sizeof(rr_type));
    rr_insert->klass        = CLASS_IN;
    rr_insert->type         = TYPE_PTR;
    rr_insert->ttl          = ttl;
    rr_insert->rdata_count  = 0;
    rr_insert->rdatas       = xalloc_array_zero( MAXRDATALEN, sizeof(rdata_atom_type));

    rr_insert->rdatas[rr_insert->rdata_count].domain = owner;
    owner->usage++; /* new reference to domain */
    ++rr_insert->rdata_count;

    rrset_type *rrset = do_domaindata_insert(db, zo, dname, rr_insert, maxAnswer);
    if (rrset == NULL) {
        add_rdata_to_recyclebin(rr_insert);
        free (rr_insert);
        return -1;
    }

    free (rr_insert);
    return 0;
}

int domaindata_ptr_delete(struct domain_store *db, char *zone_name, char *domain_name, char *host, uint32_t ttl, uint32_t maxAnswer) {
    const domain_name_st *zname = domain_name_parse((const char*)zone_name);
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    const domain_name_st *hostDomain = domain_name_parse((const char*)host);
    if (zname == NULL || dname == NULL || hostDomain == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s or host domain %s\n", zone_name, domain_name, host);
        return -1;
    }
    /* find zone to go with it, or create it */
    zone_type * zo = domain_store_find_zone(db, zname);
    if (!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;
    }
    domain_type *owner = domain_table_insert(db->domains, hostDomain, maxAnswer);//domain_table_find
    if (owner == NULL) {
       log_msg(LOG_ERR,"err can not find domain : %s\n", host);
    }

    rr_type *rr_del         = (rr_type *)xalloc_zero(sizeof(rr_type));
    rr_del->klass           = CLASS_IN;
    rr_del->type            = TYPE_PTR;
    rr_del->ttl             = ttl;
    rr_del->rdata_count     = 0;
    rr_del->rdatas          = xalloc_array_zero(MAXRDATALEN, sizeof(rdata_atom_type));

    rr_del->rdatas[rr_del->rdata_count].domain = owner;
    ++rr_del->rdata_count;

    int ret = do_domaindata_delete(db, zo, dname, rr_del);
    add_rdata_to_recyclebin(rr_del);
    free(rr_del);
    return ret;
}

int domaindata_a_insert(struct  domain_store *db,char *zone_name,char *domain_name, char*view_name, char * ip_addr, uint32_t ttl,
                       uint16_t lb_mode,uint16_t lb_weight,uint32_t maxAnswer ){
    const domain_name_st *zname = domain_name_parse((const char *)zone_name);
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    if (zname == NULL || dname == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s\n", zone_name, domain_name);
        return -1;
    }
    /* find zone to go with it, or create it */
    zone_type *zo = domain_store_find_zone(db, zname);
    if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;      
    }

    rr_type * rr_insert =  (rr_type *) xalloc_zero(sizeof(rr_type));
    rr_insert->klass          = CLASS_IN;
    rr_insert->type           = TYPE_A;
    rr_insert->ttl            = ttl;
    rr_insert->lb_mode        = lb_mode;
    rr_insert->lb_weight      = lb_weight;
    rr_insert->lb_weight_cur  = lb_weight;
    snprintf(rr_insert->view_name, 32, "%s", view_name);
    
    rr_insert->rdatas =  xalloc_array_zero( MAXRDATALEN, sizeof(rdata_atom_type));
    uint16_t * dataA = zparser_conv_a(ip_addr);

    rr_insert->rdatas[0].data = dataA;
    rr_insert->rdata_count =1; 

    rrset_type * rrset =  do_domaindata_insert(db,zo,dname, rr_insert,maxAnswer);
    if (rrset == NULL){
        add_rdata_to_recyclebin(rr_insert);
        free (rr_insert);
        return -1;
    }

    free (rr_insert);
    return 0;
}

int domaindata_a_delete(struct  domain_store *db,char *zone_name,char *domain_name,char* view_name,char * ip_addr, uint32_t ttl){
    const domain_name_st *zname = domain_name_parse((const char *)zone_name);
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    if (zname == NULL || dname == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s\n", zone_name, domain_name);
        return -1;
    }
    /* find zone to go with it, or create it */
    zone_type *zo = domain_store_find_zone(db, zname);
    if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;      
}

    rr_type * rr_del =  (rr_type *) xalloc_zero(sizeof(rr_type));
    rr_del->klass      = CLASS_IN;
    rr_del->type       = TYPE_A;
    rr_del->ttl        = ttl;
    snprintf(rr_del->view_name, 32, "%s", view_name);
    
    rr_del->rdatas =  xalloc_array_zero(MAXRDATALEN, sizeof(rdata_atom_type));
    uint16_t * dataA = zparser_conv_a(ip_addr);

    rr_del->rdatas[0].data = dataA;
    rr_del->rdata_count =1; 

   int ret = do_domaindata_delete(db,zo,dname,rr_del);
   add_rdata_to_recyclebin( rr_del);
   free(rr_del);
   return ret;
}



int domaindata_aaaa_insert(struct  domain_store *db,char *zone_name,char *domain_name, char*view_name, char * ip_addr, uint32_t ttl,
                       uint16_t lb_mode,uint16_t lb_weight,uint32_t maxAnswer ){
    const domain_name_st *zname = domain_name_parse((const char *)zone_name);
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    if (zname == NULL || dname == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s\n", zone_name, domain_name);
        return -1;
    }
    /* find zone to go with it, or create it */
    zone_type *zo = domain_store_find_zone(db, zname);
    if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;      
    }

    rr_type * rr_insert =  (rr_type *) xalloc_zero(sizeof(rr_type));
    rr_insert->klass          = CLASS_IN;
    rr_insert->type           = TYPE_AAAA;
    rr_insert->ttl            = ttl;
    rr_insert->lb_mode        = lb_mode;
    rr_insert->lb_weight      = lb_weight;
    rr_insert->lb_weight_cur  = lb_weight;
    snprintf(rr_insert->view_name, 32, "%s", view_name);
    
    rr_insert->rdatas =  xalloc_array_zero( MAXRDATALEN, sizeof(rdata_atom_type));
    uint16_t * dataA = zparser_conv_aaaa(ip_addr);

    rr_insert->rdatas[0].data = dataA;
    rr_insert->rdata_count =1; 

    rrset_type * rrset =  do_domaindata_insert(db,zo,dname, rr_insert,maxAnswer);
    if (rrset == NULL){
        add_rdata_to_recyclebin(rr_insert);
        free (rr_insert);
        return -1;
    }

    free (rr_insert);
    return 0;
}


int domaindata_aaaa_delete(struct  domain_store *db,char *zone_name,char *domain_name,char* view_name,char * ip_addr, uint32_t ttl){
    const domain_name_st *zname = domain_name_parse((const char *)zone_name);
    const domain_name_st *dname = domain_name_parse((const char *)domain_name);
    if (zname == NULL || dname == NULL) {
        log_msg(LOG_ERR," illegal zone name %s or domain name %s\n", zone_name, domain_name);
        return -1;
    }
    /* find zone to go with it, or create it */
    zone_type *zo = domain_store_find_zone(db, zname);
    if(!zo) {
        log_msg(LOG_ERR," not find the zone, zone name %s\n", zone_name);
        return -1;      
}

    rr_type * rr_del =  (rr_type *) xalloc_zero(sizeof(rr_type));
    rr_del->klass      = CLASS_IN;
    rr_del->type       = TYPE_AAAA;
    rr_del->ttl        = ttl;
    snprintf(rr_del->view_name, 32, "%s", view_name);
    
    rr_del->rdatas =  xalloc_array_zero(MAXRDATALEN, sizeof(rdata_atom_type));
    uint16_t * dataA = zparser_conv_aaaa(ip_addr);

    rr_del->rdatas[0].data = dataA;
    rr_del->rdata_count =1; 

   int ret = do_domaindata_delete(db,zo,dname,rr_del);
   add_rdata_to_recyclebin( rr_del);
   free(rr_del);
   return ret;
}


int domaindata_update(struct  domain_store *db, struct domin_info_update* update){
     if (update->type == TYPE_A){
         if (update->action == DOMAN_ACTION_DEL){
            return domaindata_a_delete(db,update->zone_name,update->domain_name,update->view_name,update->host,update->ttl);
         }else if (update->action == DOMAN_ACTION_ADD){
            return domaindata_a_insert(db,update->zone_name,update->domain_name,update->view_name,update->host,update->ttl,
                update->lb_mode,update->lb_weight,update->maxAnswer);
         }else{
            log_msg(LOG_ERR,"err action\n");
            return -2;
         }
     }else if (update->type == TYPE_AAAA){
         if (update->action == DOMAN_ACTION_DEL){         
             return domaindata_aaaa_delete(db,update->zone_name,update->domain_name,update->view_name,update->host,update->ttl);          
         }else if (update->action == DOMAN_ACTION_ADD){
             return domaindata_aaaa_insert(db,update->zone_name,update->domain_name,update->view_name,update->host,update->ttl,
                update->lb_mode,update->lb_weight,update->maxAnswer);
         }else{
             log_msg(LOG_ERR,"err action\n");
             return -2;
         }
     }else if (update->type == TYPE_PTR){
         if (update->action == DOMAN_ACTION_DEL){
            return domaindata_ptr_delete(db,update->zone_name,update->domain_name,update->host,update->ttl,update->maxAnswer);
         }else if (update->action == DOMAN_ACTION_ADD){
            return domaindata_ptr_insert(db,update->zone_name,update->domain_name,update->host,update->ttl,update->maxAnswer);
         }else{
            log_msg(LOG_ERR,"err action\n");
            return -2;
         }
     }else if (update->type == TYPE_CNAME){
         //todo
         if (update->action == DOMAN_ACTION_DEL){
            return domaindata_cname_delete(db,update->zone_name,update->domain_name);
         }else if (update->action == DOMAN_ACTION_ADD){
            return domaindata_cname_insert(db,update->zone_name,update->domain_name,update->host,update->ttl,update->maxAnswer);
         }else{
            log_msg(LOG_ERR,"err action\n");
            return -2;
         }
     }else if (update->type == TYPE_SRV){
         //todo
         if (update->action == DOMAN_ACTION_DEL){
            return domaindata_srv_delete(db,update->zone_name,update->domain_name,update->host,update->prio, 
            update->weight,update->port,update->ttl,update->maxAnswer);
         }else if (update->action == DOMAN_ACTION_ADD){
            return domaindata_srv_insert(db,update->zone_name,update->domain_name,update->host,update->prio, 
              update->weight,update->port,update->ttl,update->maxAnswer);
         }else{
            log_msg(LOG_ERR,"err action\n");
            return -2;
         }
     }
     return 0;
}