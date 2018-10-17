#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <rte_cfgfile.h>
#include "dns-conf.h"
#include "util.h"

#include "parser.h"

#define DEF_CONFIG_LOG_FILE "/export/log/kdns/kdns.log"

#define DEF_FWD_ADDRS "8.8.8.8:53,114.114.114.114:53"

struct dns_config *g_dns_cfg;


static void
dpdk_config_init(struct rte_cfgfile *cfgfile, struct dpdk_config *cfg,
                 const char *proc_name) {
    const char *entry;
    char buffer[128];

    /* proc name */
    cfg->argv[cfg->argc++] = strdup(proc_name);

    /* EAL */
    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "cores");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "-l%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    } else {
        printf("No EAL/cores options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "memory");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "--socket-mem=%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    } else {
        printf("No EAL/memory options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "mem-channels");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "-n%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    } else {
        printf("No EAL/mem-channels options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "hugefile-prefix");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "--file-prefix=%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "log-level");
    if (entry) {
        snprintf(buffer, sizeof(buffer), "--log-level=%s", entry);
        cfg->argv[cfg->argc++] = strdup(buffer);
    }

}

static void
common_config_init(struct rte_cfgfile *cfgfile, struct comm_config *cfg){
    const char *entry;
    
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "log-file");
    if (entry) {
         cfg->log_file = strdup(entry);   
    }else{
        cfg->log_file = strdup(DEF_CONFIG_LOG_FILE); 
    }
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-def-addrs");
    if (entry) {
         cfg->fwd_def_addrs = strdup(entry);   
    }else{
        cfg->fwd_def_addrs = strdup(DEF_FWD_ADDRS); 
    }
    
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-addrs");
    if (entry) {
         cfg->fwd_addrs = strdup(entry);   
    }else{
        cfg->fwd_addrs = ""; 
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-thread-num");
    if (entry) {
         if (parser_read_uint16(&cfg->fwd_threads, entry) < 0){
             printf("Cannot read COMMON/fwd-thread-num = %s.\n", entry);
             exit(-1);
         }
          
    }else{
        cfg->fwd_threads = 1; 
    }

    
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "web-port");
    if (entry && parser_read_uint16(&cfg->web_port, entry) < 0) {
        printf("Cannot read COMMON/web-port = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "ssl-enable");
    if (entry) {
         cfg->ssl_enable = parser_read_arg_bool(entry);   
    }else{
        printf("Cannot read COMMON/ssl-enable.\n");
        exit(-1); 
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "key-pem-file");
    if (entry) {
         cfg->key_pem_file = strdup(entry);   
    }else{
        printf("Cannot read COMMON/key-pem-file.\n");
        exit(-1); 
    }
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "cert-pem-file");
    if (entry) {
         cfg->cert_pem_file = strdup(entry);   
    }else{
        printf("Cannot read COMMON/cert-pem-file.\n");
        exit(-1); 
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "zones");
    if (entry){
        cfg->zones = strdup(entry);
    }else {
        printf("Cannot read COMMON/zones.\n");
        exit(-1);
    }
}



static void
netdev_config_init(struct rte_cfgfile *cfgfile, struct netdev_config *cfg) {
    const char *entry;

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "name-prefix");
    if (entry) {
        cfg->name_prefix = strdup(entry);
    }
    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "mode");
    if (entry) {
        cfg->mode = strdup(entry);
    }


    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "mbuf-num");
    if (entry && parser_read_uint16(&cfg->mbuf_num, entry) < 0) {
        printf("Cannot read NETDEV/mbuf-num = %s.\n", entry);
        exit(-1);
    }

    
    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "kni-mbuf-num");
    if (entry && parser_read_uint16(&cfg->kni_mbuf_num, entry) < 0) {
        printf("Cannot read NETDEV/kni-mbuf-num = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "rxqueue-len");
    if (entry && parser_read_uint16(&cfg->rxq_desc_num, entry) < 0) {
        printf("Cannot read NETDEV/rxqueue-len = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "txqueue-len");
    if (entry && parser_read_uint16(&cfg->txq_desc_num, entry) < 0) {
        printf("Cannot read NETDEV/txqueue-len = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "rxqueue-num");
    if (entry && parser_read_uint16(&cfg->rxq_num, entry) < 0) {
        printf("Cannot read NETDEV/rxqueue-num = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "txqueue-num");
    if (entry && parser_read_uint16(&cfg->txq_num, entry) < 0) {
        printf("Cannot read NETDEV/txqueue-num = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "kni-ipv4");
    if (entry) {
        if (parse_ipv4_addr(entry, (struct in_addr *)&cfg->kni_ip) < 0) {
            printf("Cannot read NETDEV/kni-ipv4 = %s\n", entry);
            exit(-1);
        }
    } else {
        printf("No NETDEV/kni-ipv4 options.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "kni-vip");
    if (entry) {
       cfg->kni_vip = strdup(entry);
    } else {
        printf("No NETDEV/kni-vip options.\n");
        exit(-1);
    }
}


void
config_file_load( char *cfgfile_path, char *proc_name) {
    struct rte_cfgfile *cfgfile;

    g_dns_cfg = xalloc(sizeof(struct dns_config));
    if (!g_dns_cfg) {
        printf("Cannot alloc memory for config.\n");
        exit(-1);
    }
    memset(g_dns_cfg, 0, sizeof(struct dns_config));


    cfgfile = rte_cfgfile_load(cfgfile_path, 0);
    if (!cfgfile) {
        printf("Load config file failed: %s\n", cfgfile_path);
        exit(-1);
    }
    dpdk_config_init(cfgfile, &g_dns_cfg->dpdk, proc_name);
    netdev_config_init(cfgfile, &g_dns_cfg->netdev);
    common_config_init(cfgfile, &g_dns_cfg->comm);

    rte_cfgfile_close(cfgfile);
}


