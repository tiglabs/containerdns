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

int dnsdata_prepare(struct kdns * kdns) {
    if (( kdns->db = domain_store_open()) == NULL) {
        log_msg(LOG_ERR,"unable to open the database \n");
        exit(-1);
    } 

    domain_store_zones_check_create( kdns,g_dns_cfg->comm.zones);

    kdns_zones_soa_create( kdns->db,g_dns_cfg->comm.zones);
    return 0;
}

void write_pid(const char *pid_file)
{
    /* get pid string */
    char val[16];
    size_t len = snprintf(val, sizeof(val), "%u\n", (uint32_t)getpid());
    if (len <= 0) {
        log_msg(LOG_ERR, "create pid file error (%s)", strerror(errno));
    }
    /* create pid file */
    int pidfd = open(pid_file, O_CREAT | O_TRUNC |  O_WRONLY /*| O_NOFOLLOW*/, 0644);
    if (pidfd < 0) {
        log_msg(LOG_ERR, "unable to create pid_file '%s': %s", pid_file, strerror(errno));
    }
    /*  write pid string to it */
    ssize_t r = write(pidfd, val, (uint32_t)len);
    if (r == -1) {
        log_msg(LOG_ERR, "unable to write pid_file: %s", strerror(errno));
    } else if ((size_t)r != len) {
       log_msg(LOG_ERR,"unable to write pid_file: wrote"
                " %u of %u bytes.", (uint32_t)r, (uint32_t)len);
    }

    close(pidfd);
}


int check_pid(const char *pid_file)
{
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



void kdns_zones_soa_create(struct  domain_store *db,char * zonesName){

    char zoneTmp[1024] = {0};
    char *name, *tmp;
    memcpy(zoneTmp,zonesName, strlen(zonesName));
    
    name = strtok_r(zoneTmp, ",", &tmp);
    while (name)
    { 
        domaindata_soa_insert(db,name);
        name = strtok_r(0, ",", &tmp);
    }
    return;
}

int kdns_prepare_init(struct kdns *kdns, struct query **query) {
    *query = query_create();
    memset(kdns, 0, sizeof(struct kdns));
    if (dnsdata_prepare(kdns) != 0 || *query == NULL) {
        log_msg(LOG_ERR, "server preparation failed, could not be started");
        exit(-1);
    }
    return 0;
}

int kdns_init(unsigned lcore_id) {
    return kdns_prepare_init(&dpdk_dns[lcore_id], &queries[lcore_id]);
}

kdns_query_st *dns_packet_proess(uint32_t sip, uint8_t *query_data, int query_len, unsigned lcore_id) {
    kdns_query_st *query = queries[lcore_id];

    query_reset(query);

    query->packet->data = query_data;
    query->packet->position += query_len;
    query->sip = sip;
    view_query_slave_process(query, lcore_id);

    buffer_flip(query->packet);

    if(query_process(query, &dpdk_dns[lcore_id]) != QUERY_FAIL) {
        buffer_flip(query->packet);
    }

    return query;
}
