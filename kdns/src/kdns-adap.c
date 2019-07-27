#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "kdns-adap.h"
#include "kdns.h"
#include "util.h"
#include "query.h"
#include "dns-conf.h"
#include "db_update.h"
#include "view_update.h"

#define MAX_CORES 64

static struct query *queries[MAX_CORES];
struct kdns dpdk_dns[MAX_CORES];

void write_pid(const char *pid_file) {
    /* get pid string */
    char val[16];
    size_t len = snprintf(val, sizeof(val), "%u\n", (uint32_t)getpid());
    if (len <= 0) {
        log_msg(LOG_ERR, "create pid file error (%s)", strerror(errno));
    }
    /* create pid file */
    int pidfd = open(pid_file, O_CREAT | O_TRUNC | O_WRONLY /*| O_NOFOLLOW*/, 0644);
    if (pidfd < 0) {
        log_msg(LOG_ERR, "unable to create pid_file '%s': %s", pid_file, strerror(errno));
    }
    /*  write pid string to it */
    ssize_t r = write(pidfd, val, (uint32_t)len);
    if (r == -1) {
        log_msg(LOG_ERR, "unable to write pid_file: %s", strerror(errno));
    } else if ((size_t)r != len) {
        log_msg(LOG_ERR, "unable to write pid_file: wrote %u of %u bytes.", (uint32_t)r, (uint32_t)len);
    }

    close(pidfd);
}

int check_pid(const char *pid_file) {
    if (access(pid_file, F_OK) == 0) {
        FILE *pf = fopen(pid_file, "r");
        if (pf == NULL) {
            log_msg(LOG_ERR, "Pid file '%s' exists and can not be read.\n", pid_file);
            return -1;
        }
        pid_t pidv;
        if (fscanf(pf, "%d", &pidv) == 1 && kill(pidv, 0) == 0) {
            fclose(pf);
            log_msg(LOG_ERR, "Pid file '%s' exists. process already running?\n", pid_file);
            return -2;
        }
        if (pf != NULL) {
            fclose(pf);
        }
    }
    return 0;
}

static void kdns_zones_soa_create(struct domain_store *db, char *zones) {
    char *name, *tmp;
    char zone_tmp[MAX_CONFIG_STR_LEN] = {0};

    if (strlen(zones) == 0) {
        return;
    }

    strncpy(zone_tmp, zones, sizeof(zone_tmp) - 1);
    name = strtok_r(zone_tmp, ",", &tmp);
    while (name) {
        domaindata_soa_insert(db, name);
        name = strtok_r(0, ",", &tmp);
    }
    return;
}

static void kdns_domain_store_zones_create(struct domain_store *db, char *zones) {
    char *name, *tmp;
    char zone_tmp[MAX_CONFIG_STR_LEN] = {0};

    if (strlen(zones) == 0) {
        return;
    }

    strncpy(zone_tmp, zones, sizeof(zone_tmp) - 1);
    name = strtok_r(zone_tmp, ",", &tmp);
    while (name) {
        const domain_name_st *dname = (const domain_name_st *)domain_name_parse(name);
        /* find zone to go with it, or create it */
        zone_type *zone = domain_store_find_zone(db, dname);
        if (!zone) {
            zone = domain_store_zone_create(db, dname);
        }
        free((void *)dname);
        name = strtok_r(0, ",", &tmp);
    }
    return;
}

static void kdns_domain_store_zones_delete(struct domain_store *db, char *zones) {
    char *name, *tmp;
    char zone_tmp[MAX_CONFIG_STR_LEN] = {0};

    if (strlen(zones) == 0) {
        return;
    }

    strncpy(zone_tmp, zones, sizeof(zone_tmp) - 1);
    name = strtok_r(zone_tmp, ",", &tmp);
    while (name) {
        const domain_name_st *dname = (const domain_name_st *)domain_name_parse(name);
        /* find zone to go with it, or create it */
        zone_type *zone = domain_store_find_zone(db, dname);
        if (zone) {
            delete_zone_rrs(db, zone);
            domain_store_zone_delete(db, zone);
        }
        free((void *)dname);
        name = strtok_r(0, ",", &tmp);
    }
    return;
}

int kdns_prepare_init(struct kdns *kdns, struct query **query, char *zones) {
    *query = query_create();
    if (*query == NULL) {
        log_msg(LOG_ERR, "failed to create query.");
        exit(-1);
    }

    memset(kdns, 0, sizeof(struct kdns));
    kdns->db = domain_store_open();
    if (kdns->db == NULL) {
        log_msg(LOG_ERR, "failed to open the database.\n");
        exit(-1);
    }
    kdns_domain_store_zones_create(kdns->db, zones);
    kdns_zones_soa_create(kdns->db, zones);
    return 0;
}

int kdns_init(char *zones, unsigned lcore_id) {
    return kdns_prepare_init(&dpdk_dns[lcore_id], &queries[lcore_id], zones);
}

kdns_query_st *dns_packet_proess(uint32_t sip, uint8_t *query_data, int query_len, unsigned lcore_id) {
    kdns_query_st *query = queries[lcore_id];

    query_reset(query);

    query->packet->data = query_data;
    query->packet->position += query_len;
    query->sip = sip;
    view_query_slave_process(query, lcore_id);

    buffer_flip(query->packet);

    if (query_process(query, &dpdk_dns[lcore_id]) != QUERY_FAIL) {
        buffer_flip(query->packet);
    }

    return query;
}

int kdns_zones_realod(struct kdns *kdns, char *del_zones, char *add_zones) {
    kdns_domain_store_zones_delete(kdns->db, del_zones);

    kdns_domain_store_zones_create(kdns->db, add_zones);
    kdns_zones_soa_create(kdns->db, add_zones);
    return 0;
}

int kdns_slave_zones_realod(char *del_zones, char *add_zones, unsigned lcore_id) {
    //log_msg(LOG_INFO, "slave lcore %u reload zones: del: %s, add: %s.\n", lcore_id, del_zones, add_zones);
    return kdns_zones_realod(&dpdk_dns[lcore_id], del_zones, add_zones);
}
