/*
 * data_update.c
 */
#include <stdlib.h>
#include "db_update.h"
#include "util.h"

static rrset_type *do_domaindata_insert(struct domain_store *db, zone_type *zo, const domain_name_st *dname, rr_type *rr, uint32_t maxAnswer)
{
    rrset_type *rrset;

    // insert domain
    //domain_name_st *dname = domain_name_make(db->domain, 1);
    domain_type *owner = domain_table_insert(db->domains, dname, maxAnswer);
    rr->owner          = owner;

    /* Do we have this type of rrset already? */
    rrset = domain_find_rrset(rr->owner, zo, rr->type);
    if (!rrset) {
        rrset           = (rrset_type *)xalloc_zero(sizeof(rrset_type));
        rrset->zone     = zo;
        rrset->rr_count = 1;
        rrset->rrs      = (rr_type *)xalloc_zero(sizeof(rr_type));
        rrset->rrs[0]   = *rr;

        /* Add it */
        domain_add_rrset(rr->owner, rrset);
    } else {
        int i;
        rr_type *o;
        /* Search for possible duplicates... */
        for (i = 0; i < rrset->rr_count; i++) {
            if (!strcmp(rrset->rrs[i].view_name, rr->view_name) 
                    && (rrset->rrs[i].ttl != rr->ttl || rrset->rrs[i].lb_mode != rr->lb_mode)) {
                log_msg(LOG_ERR, "ttl or lb_mode not match in same view\n");
                return NULL;
            }
            /* Discard the duplicates... */
            if (!zrdatacmp(rr->type, rr, &rrset->rrs[i]) && !strcmp(rrset->rrs[i].view_name, rr->view_name)) {
                return NULL;
            }
            if (rr->type == TYPE_CNAME && !strcmp(rrset->rrs[i].view_name, rr->view_name)) {
                log_msg(LOG_ERR, "multiple CNAMEs at the same name in same view\n");
                return NULL;
            }
        }
        if (rrset->rr_count == 65535) {
            log_msg(LOG_ERR, "too many RRs for domain RRset\n");
            return NULL;
        }

        /* Add it... */
        o = rrset->rrs;
        rrset->rrs = (rr_type *)xalloc_array_zero(rrset->rr_count + 1, sizeof(rr_type));
        memcpy(rrset->rrs, o, (rrset->rr_count) * sizeof(rr_type));
        free(o);
        rrset->rrs[rrset->rr_count] = *rr;
        ++rrset->rr_count;
    }
    return rrset;
}

static int do_domaindata_delete(struct domain_store *db, zone_type *zo, const domain_name_st *dname, rr_type *rr)
{
    rrset_type *rrset;
    domain_type *domain = domain_table_find(db->domains, dname);
    if (domain == NULL) {
        log_msg(LOG_ERR, "domain not find: %s\n", domain_name_get(dname));
        return -1;
    }

    /* Do we have this type of rrset already? */
    rrset = domain_find_rrset(domain, zo, rr->type);
    if (!rrset) {
        log_msg(LOG_ERR, "rrset not find: %s\n", domain_name_get(dname));
        return -1;
    } else {
        int rrnum;
        /* Search for the val ... */
        for (rrnum = 0; rrnum < rrset->rr_count; rrnum++) {
            if (!zrdatacmp(rr->type, rr, &rrset->rrs[rrnum]) && !strcmp(rrset->rrs[rrnum].view_name, rr->view_name)) {
                break;
            }
        }

        // find
        if (rrnum < rrset->rr_count) {
            rr_lower_usage(db, &rrset->rrs[rrnum]);
            if (rrset->rr_count == 1) {
                rrset_delete(db, domain, rrset);
                rrset_zero_nonexist_check(domain, NULL);
                domain_table_deldomain(db, domain);
            } else {
                rr_type *rrs_orig = rrset->rrs;
                add_rdata_to_recyclebin(&rrset->rrs[rrnum]);
                if (rrnum < rrset->rr_count - 1) {
                    rrset->rrs[rrnum] = rrset->rrs[rrset->rr_count - 1];
                }
                memset(&rrset->rrs[rrset->rr_count - 1], 0, sizeof(rr_type));

                /* realloc the rrs array one smaller */
                rrset->rrs = xalloc_array_zero(rrset->rr_count - 1, sizeof(rr_type));
                if (!rrset->rrs) {
                    log_msg(LOG_ERR, "out of memory, %s:%d\n", __FILE__, __LINE__);
                    exit(1);
                }
                memcpy(rrset->rrs, rrs_orig, (rrset->rr_count - 1) * sizeof(rr_type));
                free(rrs_orig);
                rrset->rr_count--;
            }
        }
    }
    return 0;
}

static void db_zadd_rdata_domain(rr_type *rr, domain_type *domain)
{
    if (rr->rdata_count >= MAXRDATALEN) {
        log_msg(LOG_ERR, "too many rdata elements\n");
    } else {
        rr->rdatas[rr->rdata_count++].domain = domain;
        domain->usage++; /* new reference to domain */
    }
}

static void db_zadd_rdata_wireformat(rr_type *rr, uint16_t *data)
{
    if (rr->rdata_count >= MAXRDATALEN) {
        log_msg(LOG_ERR, "too many rdata elements\n");
    } else {
        rr->rdatas[rr->rdata_count++].data = data;
    }
}

int domaindata_soa_insert(struct domain_store *db, char *zone_name)
{
    const domain_name_st *zname = domain_name_parse((const char *)zone_name);
    if (zname == NULL) {
        log_msg(LOG_ERR, "illegal zone name: %s\n", zone_name);
        return -1;
    }
    zone_type *zo = domain_store_find_zone(db, zname);
    if (zo == NULL) {
        log_msg(LOG_ERR, "not find the zone, zone name: %s\n", zone_name);
        free((void *)zname);
        return -1;
    }

    char string[64] = {0};
    snprintf(string, sizeof(string), "ns1.%s", zone_name);
    const domain_name_st *ns1_name = domain_name_parse((const char *)string);
    domain_type          *ns1_own  = domain_table_insert(db->domains, ns1_name, 0);
    free((void *)ns1_name);

    snprintf(string, sizeof(string), "mail.%s", zone_name);
    const domain_name_st *mail_name = domain_name_parse((const char *)string);
    domain_type          *mail_own  = domain_table_insert(db->domains, mail_name, 0);
    free((void *)mail_name);

    rr_type rr;
    memset(&rr, 0, sizeof(rr));
    rr.rdata_count = 0;
    rr.klass       = CLASS_IN;
    rr.type        = TYPE_SOA;

    rr.rdatas = xalloc_array_zero(MAXRDATALEN, sizeof(rdata_atom_type));
    db_zadd_rdata_domain(&rr, ns1_own);                                //ns
    db_zadd_rdata_domain(&rr, mail_own);                               //mail
    db_zadd_rdata_wireformat(&rr, zparser_conv_serial("2017070809"));  //serial number
    db_zadd_rdata_wireformat(&rr, zparser_conv_serial("3600"));        //refresh
    db_zadd_rdata_wireformat(&rr, zparser_conv_serial("900"));         //retry
    db_zadd_rdata_wireformat(&rr, zparser_conv_serial("1209600"));     //expire
    db_zadd_rdata_wireformat(&rr, zparser_conv_serial("1800"));        //  ttl

    rrset_type *rrset = do_domaindata_insert(db, zo, zname, &rr, 0);
    if (rrset == NULL) {
        rr_lower_usage(db, &rr);
        add_rdata_to_recyclebin(&rr);
        free((void *)zname);
        return -1;
    }

    domain_type *owner = domain_table_find(db->domains, zname);
    if (owner) {
        apex_rrset_checks(rrset, owner);
    }
    free((void *)zname);
    return 0;
}

int domaindata_update(struct domain_store *db, struct domin_info_update *update)
{
    if (update->type != TYPE_A && update->type != TYPE_AAAA && update->type != TYPE_PTR 
            && update->type != TYPE_CNAME && update->type != TYPE_SRV) {
        log_msg(LOG_ERR, "err type: %u\n", update->type);
        return -1;
    }
    if (update->action != DOMAN_ACTION_ADD && update->action != DOMAN_ACTION_DEL) {
        log_msg(LOG_ERR, "err action: %u\n", update->action);
        return -1;
    }

    const domain_name_st *zname = domain_name_parse((const char *)update->zone_name);
    if (zname == NULL) {
        log_msg(LOG_ERR, "illegal zone name: %s\n", update->zone_name);
        return -1;
    }
    zone_type *zo = domain_store_find_zone(db, zname);
    if (zo == NULL) {
        log_msg(LOG_ERR, "not find the zone, zone name: %s\n", update->zone_name);
        free((void *)zname);
        return -1;
    }
    free((void *)zname);

    domain_type *hostOwner = NULL;
    if (update->type == TYPE_PTR || update->type == TYPE_CNAME || update->type == TYPE_SRV) {
        const domain_name_st *hostDomain = domain_name_parse((const char *)update->host);
        if (hostDomain == NULL) {
            log_msg(LOG_ERR, "illegal host domain: %s\n", update->host);
            return -1;
        }
        hostOwner = domain_table_find(db->domains, hostDomain);
        if (hostOwner == NULL && update->action == DOMAN_ACTION_ADD) {
            hostOwner = domain_table_insert(db->domains, hostDomain, update->maxAnswer);
        }
        free((void *)hostDomain);
        if (hostOwner == NULL) {
            log_msg(LOG_ERR, "err: action %s but can not find domain: %s\n",
                    update->action == DOMAN_ACTION_ADD ? "add" : "del", update->host);
            return -1;
        }
    }

    const domain_name_st *dname = domain_name_parse((const char *)update->domain_name);
    if (dname == NULL) {
        log_msg(LOG_ERR, "illegal domain name: %s\n", update->domain_name);
        return -1;
    }

    rr_type rr;
    memset(&rr, 0, sizeof(rr));
    rr.rdata_count   = 0;
    rr.klass         = CLASS_IN;
    rr.type          = update->type;
    rr.ttl           = update->ttl;
    rr.lb_mode       = update->lb_mode;
    rr.lb_weight     = update->lb_weight;
    rr.lb_weight_cur = update->lb_weight;
    snprintf(rr.view_name, MAX_VIEW_NAME_LEN, "%s", update->view_name);

    rr.rdatas = xalloc_array_zero(MAXRDATALEN, sizeof(rdata_atom_type));
    if (update->type == TYPE_A) {
        db_zadd_rdata_wireformat(&rr, zparser_conv_a(update->host));
    } else if (update->type == TYPE_AAAA) {
        db_zadd_rdata_wireformat(&rr, zparser_conv_aaaa(update->host));
    } else if (update->type == TYPE_PTR) {
        db_zadd_rdata_domain(&rr, hostOwner);
    } else if (update->type == TYPE_CNAME) {
        db_zadd_rdata_domain(&rr, hostOwner);
    } else if (update->type == TYPE_SRV) {
        char string[32];
        sprintf(string, "%d", update->prio);
        db_zadd_rdata_wireformat(&rr, zparser_conv_short(string));  // prio
        sprintf(string, "%d", update->weight);
        db_zadd_rdata_wireformat(&rr, zparser_conv_short(string));  // weight
        sprintf(string, "%d", update->port);
        db_zadd_rdata_wireformat(&rr, zparser_conv_short(string));  // port
        db_zadd_rdata_domain(&rr, hostOwner);
    }

    if (update->action == DOMAN_ACTION_ADD) {
        rrset_type *rrset = do_domaindata_insert(db, zo, dname, &rr, update->maxAnswer);
        if (rrset == NULL) {
            rr_lower_usage(db, &rr);
            add_rdata_to_recyclebin(&rr);
            free((void *)dname);
            return -1;
        }
        free((void *)dname);
        return 0;
    } else {
        int ret = do_domaindata_delete(db, zo, dname, &rr);
        rr_lower_usage(db, &rr);
        add_rdata_to_recyclebin(&rr);
        free((void *)dname);
        return ret;
    }
}
