/*
 * domain_update.c 
 */
#include <jansson.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <rte_ring.h>
#include <rte_rwlock.h>
#include <rte_ethdev.h>

#include "webserver.h"
#include "db_update.h"
#include "domain_update.h"
#include "util.h"
#include "netdev.h"
#include "view_update.h"
#include "tcp_process.h"
#include "local_udp_process.h"
#include "forward.h"
#include "hashMap.h"
#include "metrics.h"

#define DOMAIN_HASH_SIZE    (0x3FFFF)

extern struct kdns dpdk_dns[MAX_CORES];

static char *kdns_status;
static struct web_instance *dins;

//record all the domain infos, we process it in master core.
static int g_domain_num;
static rte_rwlock_t domian_list_lock;
static struct domin_info_update *g_domian_hash_list[DOMAIN_HASH_SIZE + 1];

static void domain_list_operate(struct domin_info_update *msg, unsigned int hashValue) {
    struct domin_info_update *pre;
    struct domin_info_update *find;

    unsigned int hashId = hashValue & DOMAIN_HASH_SIZE;
    pre = find = g_domian_hash_list[hashId];
    while (find) {
        if (find->hashValue == hashValue
                && find->type == msg->type && strcmp(find->domain_name, msg->domain_name) == 0
                && strcmp(find->host, msg->host) == 0 && strcmp(find->view_name, msg->view_name) == 0) {
            if (msg->type == TYPE_SRV) {
                if (find->prio == msg->prio && find->weight == msg->weight && find->port == msg->port) {
                    break;
                }
            } else {
                break;
            }
        }
        pre = find;
        find = find->next;
    }
    if (msg->action == DOMAN_ACTION_ADD) {
        if (find == NULL) {
            //add to head
            msg->next = g_domian_hash_list[hashId];
            g_domian_hash_list[hashId] = msg;
            g_domain_num++;
            msg->hashValue = hashValue;
        } else {
            free(msg);
        }
    } else {
        if (find != NULL && pre != NULL) {
            if (find == g_domian_hash_list[hashId]) {
                g_domian_hash_list[hashId] = find->next;
            } else {
                pre->next = find->next;
            }
            free(find);
            g_domain_num--;
        }
        free(msg);
    }
}

static void domain_list_del_pre_zone(char *zone_name) {
    struct domin_info_update *pre;
    struct domin_info_update *find;
    struct domin_info_update *tmp;

    rte_rwlock_write_lock(&domian_list_lock);
    int i;
    for (i = 0; i < DOMAIN_HASH_SIZE; i++) {
        pre = find = g_domian_hash_list[i];
        while (find) {
            if (strcmp(find->zone_name, zone_name) == 0) {
                if (find == g_domian_hash_list[i]) {
                    g_domian_hash_list[i] = find->next;
                    pre = g_domian_hash_list[i];
                } else {
                    pre->next = find->next;
                }
                tmp = find;
                find = find->next;
                free(tmp);
                g_domain_num--;
            } else {
                pre = find;
                find = find->next;
            }
        }
    }
    rte_rwlock_write_unlock(&domian_list_lock);
}

void domain_list_del_zone(char *zones) {
    char *name, *tmp;
    char zoneTmp[ZONES_STR_LEN] = {0};

    log_msg(LOG_INFO, "domain list del zones: %s.\n", zones);

    memcpy(zoneTmp, zones, strlen(zones));
    name = strtok_r(zoneTmp, ",", &tmp);
    while (name) {
        domain_list_del_pre_zone(name);
        name = strtok_r(0, ",", &tmp);
    }
}

static void domain_info_update(struct domin_info_update *msg) {
    rte_rwlock_write_lock(&domian_list_lock);
    unsigned int hash_v = elfHashDomain(msg->domain_name);
    domain_list_operate(msg, hash_v);
    rte_rwlock_write_unlock(&domian_list_lock);
}

static int send_domain_msg_to_master(struct domin_info_update *msg) {
    msg->cmsg.type = CTRL_MSG_TYPE_DOMAIN;
    msg->cmsg.len = sizeof(struct domin_info_update);

    return ctrl_msg_master_ingress((void **)&msg, 1);
}

static inline int ipv4_address_check(const char *str) {
    struct in_addr addr;
    return inet_pton(AF_INET, str, (void *)&addr);
}

static inline int ipv6_address_check(const char *str) {
    struct in6_addr addr6;
    return inet_pton(AF_INET6, str, (void *)&addr6);
}

static struct domin_info_update *do_domaindata_parse(enum db_action action, json_t *json_data) {
    struct domin_info_update *update = xalloc_zero(sizeof(struct domin_info_update));
    update->action = action;

    /* parse json object */
    const char *value;
    /* get zone name */
    json_t *json_key = json_object_get(json_data, "zoneName");
    if (!json_key || !json_is_string(json_key)) {
        log_msg(LOG_ERR, "zoneName does not exist or is not string!");
        goto _parse_err;
    }
    value = json_string_value(json_key);
    snprintf(update->zone_name, strlen(value) + 1, "%s", value);

    /* get domain name */
    json_key = json_object_get(json_data, "domainName");
    if (!json_key || !json_is_string(json_key)) {
        log_msg(LOG_ERR, "domainName does not exist or is not string!");
        goto _parse_err;
    }
    value = json_string_value(json_key);
    snprintf(update->domain_name, strlen(value) + 1, "%s", value);

    /* get ttl */
    json_key = json_object_get(json_data, "ttl");
    if (!json_key || !json_is_integer(json_key)) {
        update->ttl = 30;
    } else {
        update->ttl = json_integer_value(json_key);
    }

    /* get maxAnswer */
    json_key = json_object_get(json_data, "maxAnswer");
    if (!json_key || !json_is_integer(json_key)) {
        update->maxAnswer = 0;
    } else {
        update->maxAnswer = json_integer_value(json_key);
    }

    /* get view name */
    json_key = json_object_get(json_data, "viewName");
    if (!json_key || !json_is_string(json_key)) {
        memcpy(update->view_name, DEFAULT_VIEW_NAME, strlen(DEFAULT_VIEW_NAME));
    } else {
        value = json_string_value(json_key);
        snprintf(update->view_name, strlen(value) + 1, "%s", value);
    }

    /* get type name */
    json_key = json_object_get(json_data, "type");
    if (!json_key || !json_is_string(json_key)) {
        log_msg(LOG_ERR, "type does not exist or is not string!");
        goto _parse_err;
    }
    value = json_string_value(json_key);
    snprintf(update->type_str, strlen(value) + 1, "%s", value);
    if (strcmp(update->type_str, "A") == 0) {
        update->type = TYPE_A;
    } else if (strcmp(update->type_str, "AAAA") == 0) {
        update->type = TYPE_AAAA;
    } else if (strcmp(update->type_str, "PTR") == 0) {
        update->type = TYPE_PTR;
    } else if (strcmp(update->type_str, "CNAME") == 0) {
        update->type = TYPE_CNAME;
    } else if (strcmp(update->type_str, "SRV") == 0) {
        update->type = TYPE_SRV;
    } else {
        log_msg(LOG_ERR, "type not support!");
        goto _parse_err;
    }
    if ((update->type == TYPE_A) || (update->type == TYPE_AAAA)) {
        /* get lb info */
        json_key = json_object_get(json_data, "lbMode");
        if (!json_key || !json_is_integer(json_key)) {
            update->lb_mode = 0;
        } else {
            update->lb_mode = json_integer_value(json_key);
        }
        json_key = json_object_get(json_data, "lbWeight");
        if (!json_key || !json_is_integer(json_key)) {
            update->lb_weight = 0;
        } else {
            update->lb_weight = json_integer_value(json_key);
        }
        if ((update->lb_mode == 2) && (update->lb_weight == 0)) {
            update->lb_weight = 1;
        }
        /* get ip addr */
        json_key = json_object_get(json_data, "host");
        if (!json_key || !json_is_string(json_key)) {
            log_msg(LOG_ERR, "host does not exist or is not string!");
            goto _parse_err;
        }
        value = json_string_value(json_key);
        if ((update->type == TYPE_A) && (ipv4_address_check(value) <= 0)) {
            log_msg(LOG_ERR, "host is bad ipv4 addr\n!");
            goto _parse_err;
        }
        if ((update->type == TYPE_AAAA) && (ipv6_address_check(value) <= 0)) {
            log_msg(LOG_ERR, "host is bad ipv6 addr\n!");
            goto _parse_err;
        }
        snprintf(update->host, strlen(value) + 1, "%s", value);
    } else if (update->type == TYPE_PTR || update->type == TYPE_CNAME) {
        /* get host */
        json_key = json_object_get(json_data, "host");
        if (!json_key || !json_is_string(json_key)) {
            log_msg(LOG_ERR, "host does not exist or is not string!");
            goto _parse_err;
        }
        value = json_string_value(json_key);
        snprintf(update->host, strlen(value) + 1, "%s", value);
    } else if (update->type == TYPE_SRV) {
        /* get host */
        json_key = json_object_get(json_data, "host");
        if (!json_key || !json_is_string(json_key)) {
            log_msg(LOG_ERR, "ipAddr does not exist or is not string!");
            goto _parse_err;
        }
        value = json_string_value(json_key);
        snprintf(update->host, strlen(value) + 1, "%s", value);

        /* get priority */
        json_key = json_object_get(json_data, "priority");
        if (!json_key || !json_is_integer(json_key)) {
            log_msg(LOG_ERR, "priority does not exist or is not int!");
            goto _parse_err;
        }
        update->prio = json_integer_value(json_key);

        /* get weight */
        json_key = json_object_get(json_data, "weight");
        if (!json_key || !json_is_integer(json_key)) {
            log_msg(LOG_ERR, "weight does not exist or is not int!");
            goto _parse_err;
        }
        update->weight = json_integer_value(json_key);

        /* get port */
        json_key = json_object_get(json_data, "port");
        if (!json_key || !json_is_integer(json_key)) {
            log_msg(LOG_ERR, "port does not exist or is not int!");
            goto _parse_err;
        }
        update->port = json_integer_value(json_key);
    }
    return update;

_parse_err:
    free(update);
    return NULL;
}

static void *domaindata_parse(enum db_action action, struct connection_info_struct *con_info, int *len_response) {
    char *post_ok, *parse_err;

    if (action == DOMAN_ACTION_ADD) {
        log_msg(LOG_INFO, "add data = %s\n", (char *)con_info->uploaddata);
    } else {
        log_msg(LOG_INFO, "del data = %s\n", (char *)con_info->uploaddata);
    }

    json_error_t jerror;
    json_t *json_response = json_loads(con_info->uploaddata, 0, &jerror);
    if (!json_response) {
        log_msg(LOG_ERR, "load json string failed: %s %s (line %d, col %d)\n",
                jerror.text, jerror.source, jerror.line, jerror.column);
        goto _parse_err;
    }
    if (!json_is_object(json_response)) {
        log_msg(LOG_ERR, "load json string failed: not an object!\n");
        goto _parse_err;
    }

    struct domin_info_update *update = do_domaindata_parse(action, json_response);
    if (update == NULL) {
        goto _parse_err;
    }
    send_domain_msg_to_master(update);
    json_decref(json_response);

    post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return post_ok;

_parse_err:
    if (json_response) {
        json_decref(json_response);
    }
    parse_err = strdup("parse data err\n");
    *len_response = strlen(parse_err);
    return (void *)parse_err;
}

static void *domaindata_parse_all(enum db_action action, struct connection_info_struct *con_info, int *len_response) {
    char *post_ok, *parse_err;

    if (action == DOMAN_ACTION_ADD) {
        log_msg(LOG_INFO, "add data = %s\n", (char *)con_info->uploaddata);
    } else {
        log_msg(LOG_INFO, "del data = %s\n", (char *)con_info->uploaddata);
    }

    json_error_t jerror;
    json_t *json_response = json_loads(con_info->uploaddata, 0, &jerror);
    if (!json_response) {
        log_msg(LOG_ERR, "load json string failed: %s %s (line %d, col %d)\n",
                jerror.text, jerror.source, jerror.line, jerror.column);
        goto _parse_err;
    }
    if (!json_is_array(json_response)) {
        log_msg(LOG_ERR, "load json string failed: not an array!");
        goto _parse_err;
    }

    size_t domains_count = json_array_size(json_response);
    size_t i_num;
    for (i_num = 0; i_num < domains_count; i_num++) {
        int ret = 0;
        int retry_num = 5;
        struct domin_info_update *update;

        json_t *array_elem = json_array_get(json_response, i_num);
        if (!json_is_object(array_elem)) {
            log_msg(LOG_ERR, "load json string failed: not an object!\n");
            json_decref(array_elem);
            goto _parse_err;
        }

_retry:
        update = do_domaindata_parse(action, array_elem);
        if (update == NULL) {
            json_decref(array_elem);
            goto _parse_err;
        }

        ret = send_domain_msg_to_master(update);
        if ((ret != 1) && (retry_num > 0)) {
            retry_num--;
            usleep(200000); //200ms
            goto _retry;
        }
        json_decref(array_elem);
    }
    json_decref(json_response);

    post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return (void *)post_ok;

_parse_err:
    if (json_response) {
        json_decref(json_response);
    }
    parse_err = strdup("parse data err\n");
    *len_response = strlen(parse_err);
    return (void *)parse_err;
}

static void *domain_post(struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    return domaindata_parse(DOMAN_ACTION_ADD, con_info, len_response);
}

static void *domains_post_all(struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    return domaindata_parse_all(DOMAN_ACTION_ADD, con_info, len_response);
}

static void *domains_delete_all(struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    return domaindata_parse_all(DOMAN_ACTION_DEL, con_info, len_response);
}

static void *domain_del(struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    return domaindata_parse(DOMAN_ACTION_DEL, con_info, len_response);
}

static void *domains_get(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    log_msg(LOG_INFO, "domain_get() in \n");

    char *out_err = NULL;
    json_t *array = json_array();
    if (!array) {
        out_err = strdup("unable to create array");
        *len_response = strlen(out_err);
        log_msg(LOG_ERR, "%s\n", out_err);
        log_msg(LOG_INFO, "domain_get() err out \n");
        return (void *)out_err;
    }

    json_t *value = NULL;
    struct domin_info_update *domain_info;

    rte_rwlock_read_lock(&domian_list_lock);
    int i;
    for (i = 0; i < DOMAIN_HASH_SIZE; i++) {
        domain_info = g_domian_hash_list[i];
        while (domain_info) {
            switch (domain_info->type) {
            case TYPE_A:
                value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i}", "type", "A",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "viewName", domain_info->view_name, "ttl", domain_info->ttl, "maxAnswer", domain_info->maxAnswer,
                                  "lbMode", domain_info->lb_mode, "lbWeight", domain_info->lb_weight);
                break;
            case TYPE_AAAA:
                value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i}", "type", "AAAA",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "viewName", domain_info->view_name, "ttl", domain_info->ttl, "maxAnswer", domain_info->maxAnswer,
                                  "lbMode", domain_info->lb_mode, "lbWeight", domain_info->lb_weight);
                break;
            case TYPE_PTR:
                value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i}", "type", "PTR",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "viewName", domain_info->view_name, "ttl", domain_info->ttl, "maxAnswer", domain_info->maxAnswer);
                break;
            case TYPE_CNAME:
                value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i}", "type", "CNAME",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "viewName", domain_info->view_name, "ttl", domain_info->ttl, "maxAnswer", domain_info->maxAnswer);
                break;
            case TYPE_SRV:
                value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i, s:i}", "type", "SRV",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "viewName", domain_info->view_name, "ttl", domain_info->ttl, "priority", domain_info->prio,
                                  "weight", domain_info->weight, "port", domain_info->port, "maxAnswer", domain_info->maxAnswer);
                break;
            default:
                log_msg(LOG_ERR, "wrong type(%d) domain:%s\n", domain_info->type, domain_info->domain_name);
            }

            json_array_append_new(array, value);
            domain_info = domain_info->next;
        }
    }
    rte_rwlock_read_unlock(&domian_list_lock);

    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    log_msg(LOG_INFO, "domain_get() out \n");
    return (void *)str_ret;
}

static void *domain_get(__attribute__((unused)) struct connection_info_struct *con_info, char *url, int *len_response) {
    log_msg(LOG_INFO, "domain_get() in \n");

    char *out_err = NULL;
    json_t *array = json_array();
    if (!array) {
        out_err = strdup("unable to create array");
        *len_response = strlen(out_err);
        log_msg(LOG_ERR, "%s\n", out_err);
        log_msg(LOG_INFO, "domain_get() err out \n");
        return (void *)out_err;
    }

    json_t *value = NULL;
    char domain[128] = {0};
    char *ptr = strrchr(url, '/');
    sprintf(domain, "%s", ptr + 1);

    unsigned int hashValue = elfHashDomain(domain);
    unsigned int hashId = hashValue & DOMAIN_HASH_SIZE;

    rte_rwlock_read_lock(&domian_list_lock);
    struct domin_info_update *domain_info = g_domian_hash_list[hashId];
    while (domain_info) {
        if (domain_info->hashValue == hashValue &&
            strcmp(domain_info->domain_name, domain) == 0) {
            switch (domain_info->type) {
            case TYPE_A:
                value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i}", "type", "A",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "viewName", domain_info->view_name, "ttl", domain_info->ttl, "maxAnswer", domain_info->maxAnswer,
                                  "lbMode", domain_info->lb_mode, "lbWeight", domain_info->lb_weight);
                break;
            case TYPE_AAAA:
                value = json_pack("{s:s, s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i}", "type", "AAAA",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "viewName", domain_info->view_name, "ttl", domain_info->ttl, "maxAnswer", domain_info->maxAnswer,
                                  "lbMode", domain_info->lb_mode, "lbWeight", domain_info->lb_weight);
                break;
            case TYPE_PTR:
                value = json_pack("{s:s, s:s, s:s, s:s, s:i}", "type", "PTR",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "ttl", domain_info->ttl);
                break;
            case TYPE_CNAME:
                value = json_pack("{s:s, s:s, s:s, s:s, s:i}", "type", "CNAME",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "ttl", domain_info->ttl);
                break;
            case TYPE_SRV:
                value = json_pack("{s:s, s:s, s:s, s:s, s:i, s:i, s:i, s:i}", "type", "SRV",
                                  "domainName", domain_info->domain_name, "host", domain_info->host, "zoneName", domain_info->zone_name,
                                  "ttl", domain_info->ttl, "priority", domain_info->prio, "weight", domain_info->weight, "port", domain_info->port);
                break;
            default:
                log_msg(LOG_ERR, "wrong type(%d) domain:%s\n", domain_info->type, domain_info->domain_name);
            }
            json_array_append_new(array, value);
        }
        domain_info = domain_info->next;
    }
    rte_rwlock_read_unlock(&domian_list_lock);

    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    log_msg(LOG_INFO, "domain_get() out \n");
    return (void *)str_ret;
}

static int domain_num_get(void) {
    int num = 0;
    rte_rwlock_read_lock(&domian_list_lock);
    num = g_domain_num;
    rte_rwlock_read_unlock(&domian_list_lock);
    return num;
}

static void *kdns_status_post(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    if (kdns_status) {
        free(kdns_status);
    }
    kdns_status = strdup(DNS_STATUS_RUN);

    char *post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return (void *)post_ok;
}

static void *kdns_status_get(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    char *get_ok = strdup(kdns_status);
    *len_response = strlen(get_ok);
    return (void *)get_ok;
}

static void *statistics_percore_get(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    unsigned lcore_id;

    json_t *array = json_array();
    if (!array) {
        char *err = strdup("unable to create array");
        *len_response = strlen(err);
        log_msg(LOG_ERR, "%s\n", err);
        return (void *)err;
    }

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        struct netif_queue_conf *conf = netif_queue_conf_get(lcore_id);
        struct netif_queue_stats *sta_lcore = &conf->stats;

        json_t *value = json_pack("{s:i, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f,\
                                    s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f,\
                                    s:f, s:f, s:f, s:f, s:f}",
                                  "slave_lcore", lcore_id, "pkts_rcv", (double)sta_lcore->pkts_rcv,
                                  "dns_pkts_rcv", (double)sta_lcore->dns_pkts_rcv, "dns_pkts_snd", (double)sta_lcore->dns_pkts_snd,
                                  "pkt_dropped", (double)sta_lcore->pkt_dropped, "pkts_2kni", (double)sta_lcore->pkts_2kni,
                                  "pkts_icmp", (double)sta_lcore->pkts_icmp, "pkt_len_err", (double)sta_lcore->pkt_len_err,
                                  "dns_lens_rcv", (double)sta_lcore->dns_lens_rcv, "dns_lens_snd", (double)sta_lcore->dns_lens_snd,
                                  "tcp_pkts_rcv", (double)sta_lcore->dns_pkts_rcv_tcp, "tcp_pkts_snd", (double)sta_lcore->dns_pkts_snd_tcp,
                                  "tcp_fwd_rcv", (double)sta_lcore->dns_fwd_rcv_tcp, "tcp_fwd_snd", (double)sta_lcore->dns_fwd_snd_tcp,
                                  "tcp_fwd_lost", (double)sta_lcore->dns_fwd_lost_tcp, "udp_fwd_rcv", (double)sta_lcore->dns_fwd_rcv_udp,
                                  "udp_fwd_snd", (double)sta_lcore->dns_fwd_snd_udp, "udp_fwd_lost", (double)sta_lcore->dns_fwd_lost_udp,
                                  "metrics-maxtime", (double)sta_lcore->metrics.maxTime, "metrics-mintime", (double)sta_lcore->metrics.minTime,
                                  "metrics-sumtime", (double)sta_lcore->metrics.timeSum, "metrics1", (double)sta_lcore->metrics.metrics[0],
                                  "metrics2", (double)sta_lcore->metrics.metrics[1], "metrics3", (double)sta_lcore->metrics.metrics[2],
                                  "metrics4", (double)sta_lcore->metrics.metrics[3]);

        if (!value) {
            log_msg(LOG_ERR, "json_pack err for slave core %u\n", lcore_id);
            continue;
        }
        json_array_append_new(array, value);
    }

    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    return (void *)str_ret;
}

static void *statistics_get(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    struct netif_queue_stats sta = {0};
    netif_statsdata_get(&sta);
    tcp_statsdata_get(&sta);
    fwd_statsdata_get(&sta);

    json_t *value = json_pack("{s:i, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f,\
                                s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f,\
                                s:f, s:f, s:f, s:f, s:f}",
                              "domain_num", domain_num_get(), "pkts_rcv", (double)sta.pkts_rcv,
                              "dns_pkts_rcv", (double)sta.dns_pkts_rcv, "dns_pkts_snd", (double)sta.dns_pkts_snd,
                              "pkt_dropped", (double)sta.pkt_dropped, "pkts_2kni", (double)sta.pkts_2kni,
                              "pkts_icmp", (double)sta.pkts_icmp, "pkt_len_err", (double)sta.pkt_len_err,
                              "dns_lens_rcv", (double)sta.dns_lens_rcv, "dns_lens_snd", (double)sta.dns_lens_snd,
                              "tcp_pkts_rcv", (double)sta.dns_pkts_rcv_tcp, "tcp_pkts_snd", (double)sta.dns_pkts_snd_tcp,
                              "tcp_fwd_rcv", (double)sta.dns_fwd_rcv_tcp, "tcp_fwd_snd", (double)sta.dns_fwd_snd_tcp,
                              "tcp_fwd_lost", (double)sta.dns_fwd_lost_tcp, "udp_fwd_rcv", (double)sta.dns_fwd_rcv_udp,
                              "udp_fwd_snd", (double)sta.dns_fwd_snd_udp, "udp_fwd_lost", (double)sta.dns_fwd_lost_udp,
                              "metrics-maxtime", (double)sta.metrics.maxTime, "metrics-mintime", (double)sta.metrics.minTime,
                              "metrics-sumtime", (double)sta.metrics.timeSum, "metrics1", (double)sta.metrics.metrics[0],
                              "metrics2", (double)sta.metrics.metrics[1], "metrics3", (double)sta.metrics.metrics[2],
                              "metrics4", (double)sta.metrics.metrics[3]);

    if (!value) {
        char *err = strdup("json_pack err");
        *len_response = strlen(err);
        return (void *)err;
    }

    char *str_ret = json_dumps(value, JSON_COMPACT);
    json_decref(value);
    *len_response = strlen(str_ret);
    return (void *)str_ret;
}

static void *statistics_reset(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    netif_statsdata_reset();
    tcp_statsdata_reset();
    fwd_statsdata_reset();

    char *post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return (void *)post_ok;
}

static void *statistics_port_get(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    uint8_t port_id = 0;
    unsigned lcore_id;
    struct rte_eth_stats eth_stats;

    int ret = rte_eth_stats_get(port_id, &eth_stats);
    if (ret != 0) {
        char *err = strdup("unable to get eth stats");
        *len_response = strlen(err);
        log_msg(LOG_ERR, "%s, ret %d\n", err, ret);
        return (void *)err;
    }

    json_t *array = json_array();
    if (!array) {
        char *err = strdup("unable to create array");
        *len_response = strlen(err);
        log_msg(LOG_ERR, "%s\n", err);
        return (void *)err;
    }

    json_t *value = json_pack("{s:i, s:f, s:f, s:f, s:f, s:f, s:f, s:f, s:f}",
                              "port", port_id, "ipackets", (double)eth_stats.ipackets,
                              "opackets", (double)eth_stats.opackets, "ibytes", (double)eth_stats.ibytes,
                              "obytes", (double)eth_stats.obytes, "imissed", (double)eth_stats.imissed,
                              "ierrors", (double)eth_stats.ierrors, "oerrors", (double)eth_stats.oerrors,
                              "rx_nombuf", (double)eth_stats.rx_nombuf);

    if (!value) {
        log_msg(LOG_ERR, "json_pack err for port %u\n", port_id);
    } else {
        json_array_append_new(array, value);
    }

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        json_t *value = NULL;
        struct netif_queue_conf *conf = netif_queue_conf_get(lcore_id);
        if (conf->rx_queue_id < RTE_ETHDEV_QUEUE_STAT_CNTRS && conf->tx_queue_id < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
            value = json_pack("{s:i, s:i, s:i, s:f, s:f, s:f, s:f, s:f}",
                              "slave_lcore", lcore_id, "rx_queue", conf->rx_queue_id, "tx_queue", conf->tx_queue_id,
                              "q_ipackets", (double)eth_stats.q_ipackets[conf->rx_queue_id],
                              "q_opackets", (double)eth_stats.q_opackets[conf->tx_queue_id],
                              "q_ibytes", (double)eth_stats.q_ibytes[conf->rx_queue_id],
                              "q_obytes", (double)eth_stats.q_obytes[conf->tx_queue_id],
                              "q_errors", (double)eth_stats.q_errors[conf->rx_queue_id]);
        } else if (conf->rx_queue_id < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
            value = json_pack("{s:i, s:i, s:f, s:f, s:f}",
                              "slave_lcore", lcore_id, "rx_queue", conf->rx_queue_id,
                              "q_ipackets", (double)eth_stats.q_ipackets[conf->rx_queue_id],
                              "q_ibytes", (double)eth_stats.q_ibytes[conf->rx_queue_id],
                              "q_errors", (double)eth_stats.q_errors[conf->rx_queue_id]);
        } else if (conf->tx_queue_id < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
            value = json_pack("{s:i, s:i, s:f, s:f}",
                              "slave_lcore", lcore_id, "tx_queue", conf->tx_queue_id,
                              "q_opackets", (double)eth_stats.q_opackets[conf->tx_queue_id],
                              "q_obytes", (double)eth_stats.q_obytes[conf->tx_queue_id]);
        } else {
            continue;
        }

        if (!value) {
            log_msg(LOG_ERR, "json_pack err for slave core %u, rx queue %u, tx queue %u\n",
                    lcore_id, conf->rx_queue_id, conf->tx_queue_id);
            continue;
        }
        json_array_append_new(array, value);
    }

    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    return (void *)str_ret;
}

static void *statistics_port_reset(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    uint8_t port_id = 0;

    rte_eth_stats_reset(port_id);

    char *post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return (void *)post_ok;
}

static void *local_metrics_reset(__attribute__((unused)) struct connection_info_struct *con_info, __attribute__((unused)) char *url, int *len_response) {
    netif_statsdata_metrics_reset();

    char *post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return (void *)post_ok;
}

void domian_info_exchange_run(int port) {
    dins = webserver_new(port);
    web_endpoint_add("POST", "/kdns/domain", dins, &domain_post);
    web_endpoint_add("POST", "/kdns/alldomains", dins, &domains_post_all);
    web_endpoint_add("GET", "/kdns/domain", dins, &domains_get);
    web_endpoint_add("GET", "/kdns/perdomain/", dins, &domain_get);
    web_endpoint_add("DELETE", "/kdns/domain", dins, &domain_del);
    web_endpoint_add("DELETE", "/kdns/alldomains", dins, &domains_delete_all);

    web_endpoint_add("POST", "/kdns/status", dins, &kdns_status_post);
    web_endpoint_add("GET", "/kdns/status", dins, &kdns_status_get);

    web_endpoint_add("GET", "/kdns/statistics/get", dins, &statistics_get);
    web_endpoint_add("POST", "/kdns/statistics/reset", dins, &statistics_reset);

    web_endpoint_add("GET", "/kdns/statistics/percore/get", dins, &statistics_percore_get);
    web_endpoint_add("GET", "/kdns/statistics/port/get", dins, &statistics_port_get);
    web_endpoint_add("POST", "/kdns/statistics/port/reset", dins, &statistics_port_reset);

    web_endpoint_add("POST", "/kdns/view", dins, &view_post);
    web_endpoint_add("GET", "/kdns/view", dins, &view_get);
    //web_endpoint_add("GET","/kdns/perview",dins,&domain_get);
    web_endpoint_add("DELETE", "/kdns/view", dins, &view_del);

    web_endpoint_add("POST", "/kdns/allview", dins, &views_post_all);
    web_endpoint_add("DELETE", "/kdns/allview", dins, &views_delete_all);

    web_endpoint_add("POST", "/kdns/metrics/resetlocal", dins, &local_metrics_reset);

#ifdef ENABLE_KDNS_FWD_METRICS
    web_endpoint_add("GET", "/kdns/metrics/domains", dins, &metrics_domains_get);
    web_endpoint_add("GET", "/kdns/metrics/clientIp", dins, &metrics_domains_clientIp_get);
#endif

    web_endpoint_add("GET", "/kdns/forward/caches", dins, &fwd_caches_get);
    web_endpoint_add("DELETE", "/kdns/forward/caches", dins, &fwd_caches_delete);

    webserver_run(dins);
    return;
}

void domain_msg_slave_process(ctrl_msg *msg, unsigned slave_lcore) {
    domaindata_update(dpdk_dns[slave_lcore].db, (struct domin_info_update *)msg);
    free(msg);
}

void domain_msg_master_process(ctrl_msg *msg) {
    struct domin_info_update *update = (struct domin_info_update *)msg;

    tcp_domian_databd_update(update);
    local_udp_domian_databd_update(update);
    domain_info_update(update);
}

void domain_info_master_init(void) {
    int i;

    kdns_status = strdup(DNS_STATUS_INIT);
    rte_rwlock_init(&domian_list_lock);
    for (i = 0; i <= DOMAIN_HASH_SIZE; i++) {
        g_domian_hash_list[i] = NULL;
    }
}
