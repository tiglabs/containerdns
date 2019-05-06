#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <rte_cfgfile.h>
#include "dns-conf.h"
#include "util.h"
#include "domain_update.h"
#include "forward.h"
#include "kdns-adap.h"

#include "parser.h"

#define DEF_CONFIG_LOG_FILE "/export/log/kdns/kdns.log"
#define DEF_FWD_ADDRS "8.8.8.8:53,114.114.114.114:53"

#define RELOAD_ZONES                (0x1 << 0)
#define RELOAD_FWD_MODE             (0x1 << 1)
#define RELOAD_FWD_TIMEOUT          (0x1 << 2)
#define RELOAD_FWD_DEFAULT_ADDRS    (0x1 << 3)
#define RELOAD_FWD_ZONES_ADDRS      (0x1 << 4)
static rte_atomic16_t g_reload_perflag[MAX_CORES] = {RTE_ATOMIC16_INIT(0)};
static uint16_t g_reload_flag;

struct dns_config *g_dns_cfg;
struct dns_config *g_reload_dns_cfg = NULL;
struct zones_reload *g_reload_zone = NULL;
extern struct kdns dpdk_dns[MAX_CORES];
extern struct kdns kdns_tcp;

static void dpdk_config_init(struct rte_cfgfile *cfgfile, struct dpdk_config *cfg, const char *proc_name) {
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

static void common_config_init(struct rte_cfgfile *cfgfile, struct comm_config *cfg) {
    const char *entry;

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "log-file");
    if (entry) {
        cfg->log_file = strdup(entry);
    } else {
        cfg->log_file = strdup(DEF_CONFIG_LOG_FILE);
    }
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-def-addrs");
    if (entry) {
        cfg->fwd_def_addrs = strdup(entry);
    } else {
        cfg->fwd_def_addrs = strdup(DEF_FWD_ADDRS);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-addrs");
    if (entry) {
        cfg->fwd_addrs = strdup(entry);
    } else {
        cfg->fwd_addrs = strdup("");
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-thread-num");
    if (entry) {
        if (parser_read_uint16(&cfg->fwd_threads, entry) < 0) {
            printf("Cannot read COMMON/fwd-thread-num = %s.\n", entry);
            exit(-1);
        }

    } else {
        cfg->fwd_threads = 1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-timeout");
    if (entry) {
        if (parser_read_uint16(&cfg->fwd_timeout, entry) < 0) {
            printf("Cannot read COMMON/fwd-timeout = %s.\n", entry);
            exit(-1);
        }
    } else {
        cfg->fwd_timeout = 2;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-mode");
    if (entry) {
        cfg->fwd_mode = strdup(entry);
    } else {
        cfg->fwd_mode = strdup("cache");
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "web-port");
    if (entry && parser_read_uint16(&cfg->web_port, entry) < 0) {
        printf("Cannot read COMMON/web-port = %s.\n", entry);
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "ssl-enable");
    if (entry) {
        cfg->ssl_enable = parser_read_arg_bool(entry);
    } else {
        printf("Cannot read COMMON/ssl-enable.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "key-pem-file");
    if (entry) {
        cfg->key_pem_file = strdup(entry);
    } else {
        printf("Cannot read COMMON/key-pem-file.\n");
        exit(-1);
    }
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "cert-pem-file");
    if (entry) {
        cfg->cert_pem_file = strdup(entry);
    } else {
        printf("Cannot read COMMON/cert-pem-file.\n");
        exit(-1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "zones");
    if (entry) {
        cfg->zones = strdup(entry);
    } else {
        printf("Cannot read COMMON/zones.\n");
        exit(-1);
    }
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "metrics-host");
    if (entry) {
        cfg->metrics_host = strdup(entry);
    } else {
        cfg->metrics_host = strdup("dns-metrics_host ^^");
    }
}

static void netdev_config_init(struct rte_cfgfile *cfgfile, struct netdev_config *cfg) {
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

void config_file_load(char *cfgfile_path, char *proc_name) {
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

static int common_config_reload_init(struct rte_cfgfile *cfgfile, struct comm_config *cfg) {
    const char *entry;

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "log-file");
    if (entry) {
        cfg->log_file = strdup(entry);
    } else {
        cfg->log_file = strdup(DEF_CONFIG_LOG_FILE);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-def-addrs");
    if (entry) {
        cfg->fwd_def_addrs = strdup(entry);
    } else {
        cfg->fwd_def_addrs = strdup(DEF_FWD_ADDRS);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-addrs");
    if (entry) {
        cfg->fwd_addrs = strdup(entry);
    } else {
        cfg->fwd_addrs = strdup("");
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-timeout");
    if (entry) {
        if (parser_read_uint16(&cfg->fwd_timeout, entry) < 0) {
            printf("Cannot read COMMON/fwd-timeout = %s.\n", entry);
            exit(-1);
        }
    } else {
        cfg->fwd_timeout = 2;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-mode");
    if (entry) {
        cfg->fwd_mode = strdup(entry);
    } else {
        cfg->fwd_mode = strdup("cache");
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "zones");
    if (entry) {
        cfg->zones = strdup(entry);
    } else {
        log_msg(LOG_ERR, "Cannot read COMMON/zones.");
        return -1;
    }
    return 0;
}

static int config_file_reload(char *cfgfile_path) {
    int ret = 0;
    struct rte_cfgfile *cfgfile;

    if (!g_reload_zone) {
        g_reload_zone = xalloc(sizeof(struct zones_reload));
        if (!g_reload_zone) {
            log_msg(LOG_ERR, "Cannot alloc memory for g_reload_zone.");
            return -1;
        }
    }
    memset(g_reload_zone, 0, sizeof(struct zones_reload));

    if (!g_reload_dns_cfg) {
        g_reload_dns_cfg = xalloc(sizeof(struct dns_config));
        if (!g_reload_dns_cfg) {
            log_msg(LOG_ERR, "Cannot alloc memory for g_reload_dns_cfg.");
            return -1;
        }
    }
    memset(g_reload_dns_cfg, 0, sizeof(struct dns_config));

    cfgfile = rte_cfgfile_load(cfgfile_path, 0);
    if (!cfgfile) {
        log_msg(LOG_ERR, "Open config file failed: %s", cfgfile_path);
        return -1;
    }

    ret = common_config_reload_init(cfgfile, &g_reload_dns_cfg->comm);
    if (ret) {
        log_msg(LOG_ERR, "Load config file failed: %s", cfgfile_path);
    }
    rte_cfgfile_close(cfgfile);
    return ret;
}

static int config_log_file_reload_proc(void) {
    int ret = 0;

    if (!g_reload_dns_cfg->comm.log_file)
        return -1;

    log_msg(LOG_INFO, "reload log file name %s", g_reload_dns_cfg->comm.log_file);
    if (strcmp(g_reload_dns_cfg->comm.log_file, g_dns_cfg->comm.log_file)) {
        ret = log_file_reload(g_reload_dns_cfg->comm.log_file);
        if (ret) {
            log_msg(LOG_ERR, "reload log file error.");
            return ret;
        }

        free(g_dns_cfg->comm.log_file);
        g_dns_cfg->comm.log_file = g_reload_dns_cfg->comm.log_file;
        g_reload_dns_cfg->comm.log_file = NULL;

        log_msg(LOG_INFO, "reload log file success.");
        return 0;
    }

    log_msg(LOG_INFO, "reload log file does not change.");
    return 0;
}

static int config_fwd_def_addrs_reload_proc(void) {
    int ret = 0;

    if (!g_reload_dns_cfg->comm.fwd_def_addrs)
        return -1;

    log_msg(LOG_INFO, "reload fwd_def_addrs old_fwd_def_addrs=(%s),new_fwd_def_addrs=(%s).",
            g_dns_cfg->comm.fwd_def_addrs, g_reload_dns_cfg->comm.fwd_def_addrs);

    if (strcmp(g_reload_dns_cfg->comm.fwd_def_addrs, g_dns_cfg->comm.fwd_def_addrs)) {
        ret = fwd_def_addrs_reload(g_reload_dns_cfg->comm.fwd_def_addrs);
        if (ret) {
            log_msg(LOG_ERR, "reload fwd_def_addrs error.");
            return ret;
        }

        free(g_dns_cfg->comm.fwd_def_addrs);
        g_dns_cfg->comm.fwd_def_addrs = g_reload_dns_cfg->comm.fwd_def_addrs;
        g_reload_dns_cfg->comm.fwd_def_addrs = NULL;

        g_reload_flag |= RELOAD_FWD_DEFAULT_ADDRS;
        log_msg(LOG_INFO, "reload fwd_def_addrs success.");
        return 0;
    }

    log_msg(LOG_INFO, "reload fwd_def_addrs does not change.");
    return 0;
}

static int config_fwd_zones_addrs_reload_proc(void) {
    int ret;

    if (!g_reload_dns_cfg->comm.fwd_addrs)
        return -1;

    log_msg(LOG_INFO, "reload fwd_addrs old_fwd_addrs=(%s),new_fwd_addrs=(%s).",
            g_dns_cfg->comm.fwd_addrs, g_reload_dns_cfg->comm.fwd_addrs);

    if (strcmp(g_reload_dns_cfg->comm.fwd_addrs, g_dns_cfg->comm.fwd_addrs)) {
        ret = fwd_zones_addrs_reload(g_reload_dns_cfg->comm.fwd_addrs);
        if (ret) {
            log_msg(LOG_ERR, "reload fwd_addrs error.");
            return ret;
        }

        free(g_dns_cfg->comm.fwd_addrs);
        g_dns_cfg->comm.fwd_addrs = g_reload_dns_cfg->comm.fwd_addrs;
        g_reload_dns_cfg->comm.fwd_addrs = NULL;

        g_reload_flag |= RELOAD_FWD_ZONES_ADDRS;
        log_msg(LOG_INFO, "reload fwd_addrs success.");
        return 0;
    }

    log_msg(LOG_INFO, "reload fwd_addrs does not change.");
    return 0;
}

static int config_fwd_timeout_reload_proc(void) {
    int ret;

    log_msg(LOG_INFO, "reload fwd_timeout old_fwd_timeout=(%d), new_fwd_timeout=(%d).",
            g_dns_cfg->comm.fwd_timeout, g_reload_dns_cfg->comm.fwd_timeout);

    if (g_reload_dns_cfg->comm.fwd_timeout != g_dns_cfg->comm.fwd_timeout) {
        ret = fwd_timeout_reload(g_reload_dns_cfg->comm.fwd_timeout);
        if (ret) {
            log_msg(LOG_ERR, "reload fwd_timeout error.");
            return ret;
        }

        g_dns_cfg->comm.fwd_timeout = g_reload_dns_cfg->comm.fwd_timeout;

        g_reload_flag |= RELOAD_FWD_TIMEOUT;
        log_msg(LOG_INFO, "reload fwd_timeout success.");
        return 0;
    }

    log_msg(LOG_INFO, "reload fwd_timeout does not change.");
    return 0;
}

static int config_fwd_mode_reload_proc(void) {
    int ret;

    if (!g_reload_dns_cfg->comm.fwd_mode)
        return -1;

    log_msg(LOG_INFO, "reload fwd_mode old_fwd_mode=(%s), new_fwd_mode=(%s).",
            g_dns_cfg->comm.fwd_mode, g_reload_dns_cfg->comm.fwd_mode);

    if (strcmp(g_reload_dns_cfg->comm.fwd_mode, g_dns_cfg->comm.fwd_mode)) {
        ret = fwd_mode_reload(g_reload_dns_cfg->comm.fwd_mode);
        if (ret) {
            log_msg(LOG_ERR, "reload fwd_mode error.");
            return ret;
        }

        free(g_dns_cfg->comm.fwd_mode);
        g_dns_cfg->comm.fwd_mode = g_reload_dns_cfg->comm.fwd_mode;
        g_reload_dns_cfg->comm.fwd_mode = NULL;

        g_reload_flag |= RELOAD_FWD_MODE;
        log_msg(LOG_INFO, "reload fwd_mode success.");
        return 0;
    }

    log_msg(LOG_INFO, "reload fwd_mode does not change.");
    return 0;
}

static int zones_find(char *name, char *zone) {
    char name_buf[ZONES_STR_LEN] = {0};
    char zone_buf[ZONES_STR_LEN] = {0};

    snprintf(name_buf, sizeof(name_buf), ",%s,", name);
    snprintf(zone_buf, sizeof(zone_buf), ",%s,", zone);

    if (strstr(zone_buf, name_buf))
        return 1;

    return 0;
}

static int zones_cmp(char *first_zone, char *sec_zone, char *cmp_zone, int cmp_len) {
    char tmp_zone[ZONES_STR_LEN] = {0};
    char *name;
    int len = 0;
    int find = 0;

    memcpy(tmp_zone, first_zone, MIN(sizeof(tmp_zone), strlen(first_zone)));

    name = strtok(tmp_zone, ",");
    while (name) {
        find = zones_find(name, sec_zone);
        if (!find) {
            if (strlen(cmp_zone)) {
                snprintf(cmp_zone + len, cmp_len - len, ",%s", name);
            } else {
                snprintf(cmp_zone + len, cmp_len - len, "%s", name);
            }
            len = strlen(cmp_zone);
        }
        name = strtok(0, ",");
    }

    return 0;
}

static int zones_realod_add_proc(struct kdns *lcore_kdns) {
    if (!strlen(g_reload_zone->add_zone))
        return 0;

    domain_store_zones_check_create(lcore_kdns, g_reload_zone->add_zone);
    kdns_zones_soa_create(lcore_kdns->db, g_reload_zone->add_zone);
    return 0;
}

static int zones_realod_del_proc(struct kdns *lcore_kdns) {
    if (!strlen(g_reload_zone->del_zone))
        return 0;

    domain_store_zones_check_delete(lcore_kdns, g_reload_zone->del_zone);
    return 0;
}

static int zones_reload_slave_proc(unsigned cid) {
    struct kdns *lcore_kdns = &dpdk_dns[cid];
    zones_realod_del_proc(lcore_kdns);
    zones_realod_add_proc(lcore_kdns);
    return 0;
}

static int zones_reload_master_proc(void) {
    zones_realod_del_proc(&kdns_tcp);
    zones_realod_add_proc(&kdns_tcp);
    domain_list_del_zone(g_reload_zone->del_zone);
    return 0;
}

int config_reload_pre_core(void) {
    unsigned cid = rte_lcore_id();

    uint16_t reload_flag = rte_atomic16_read(&g_reload_perflag[cid]);
    if (reload_flag == 0) {
        return 0;
    }

    if (rte_get_master_lcore() == cid) {
        if (reload_flag & RELOAD_ZONES) {
            zones_reload_master_proc();
        }
    } else {
        if (reload_flag & RELOAD_ZONES) {
            zones_reload_slave_proc(cid);
        }
    }

    rte_atomic16_clear(&g_reload_perflag[cid]);
    return 0;
}

static int zones_reload(char *new_zone) {
    int ret = 0;

    ret = zones_cmp(new_zone, g_dns_cfg->comm.zones, g_reload_zone->add_zone, sizeof(g_reload_zone->add_zone));
    if (ret) {
        log_msg(LOG_ERR, "zones compare error. new_zone=[%s], old_zone=[%s]", new_zone, g_dns_cfg->comm.zones);
        return ret;
    }
    log_msg(LOG_INFO, "reload add zones: %s.", g_reload_zone->add_zone);

    ret = zones_cmp(g_dns_cfg->comm.zones, new_zone, g_reload_zone->del_zone, sizeof(g_reload_zone->del_zone));
    if (ret) {
        log_msg(LOG_ERR, "zones compare error. new_zone=[%s], old_zone=[%s]", new_zone, g_dns_cfg->comm.zones);
        return ret;
    }
    log_msg(LOG_INFO, "reload delete zones: %s.", g_reload_zone->del_zone);

    return 0;
}

static int config_zones_reload_proc(void) {
    int ret = 0;

    if (!g_reload_dns_cfg->comm.zones)
        return -1;

    log_msg(LOG_INFO, "reload new zones %s", g_reload_dns_cfg->comm.zones);
    log_msg(LOG_INFO, "reload old zones %s", g_dns_cfg->comm.zones);
    if (strcmp(g_reload_dns_cfg->comm.zones, g_dns_cfg->comm.zones)) {
        ret = zones_reload(g_reload_dns_cfg->comm.zones);
        if (ret) {
            log_msg(LOG_ERR, "reload zones error.");
            return ret;
        }

        free(g_dns_cfg->comm.zones);
        g_dns_cfg->comm.zones = g_reload_dns_cfg->comm.zones;
        g_reload_dns_cfg->comm.zones = NULL;

        g_reload_flag |= RELOAD_ZONES;
        log_msg(LOG_INFO, "reload zones success.");
        return 0;
    }

    log_msg(LOG_INFO, "reload zones does not change.");
    return 0;
}

static void config_reload_free(void) {
    if (!g_reload_dns_cfg) {
        return;
    }

    if (g_reload_dns_cfg->comm.log_file) {
        free(g_reload_dns_cfg->comm.log_file);
        g_reload_dns_cfg->comm.log_file = NULL;
    }

    if (g_reload_dns_cfg->comm.fwd_def_addrs) {
        free(g_reload_dns_cfg->comm.fwd_def_addrs);
        g_reload_dns_cfg->comm.fwd_def_addrs = NULL;
    }

    if (g_reload_dns_cfg->comm.fwd_addrs) {
        free(g_reload_dns_cfg->comm.fwd_addrs);
        g_reload_dns_cfg->comm.fwd_addrs = NULL;
    }

    if (g_reload_dns_cfg->comm.fwd_mode) {
        free(g_reload_dns_cfg->comm.fwd_mode);
        g_reload_dns_cfg->comm.fwd_mode = NULL;
    }

    if (g_reload_dns_cfg->comm.zones) {
        free(g_reload_dns_cfg->comm.zones);
        g_reload_dns_cfg->comm.zones = NULL;
    }
}

int config_reload_proc(char *dns_cfgfile) {
    int ret = 0, i = 0;

    log_msg(LOG_INFO, "start reload config file %s", dns_cfgfile);

    g_reload_flag = 0;
    ret = config_file_reload(dns_cfgfile);
    if (ret)
        goto _out;

    ret = config_log_file_reload_proc();
    if (ret)
        goto _out;

    ret = config_fwd_def_addrs_reload_proc();
    if (ret)
        goto _out;

    ret = config_fwd_zones_addrs_reload_proc();
    if (ret)
        goto _out;

    ret = config_fwd_timeout_reload_proc();
    if (ret)
        goto _out;

    ret = config_fwd_mode_reload_proc();
    if (ret)
        goto _out;

    ret = config_zones_reload_proc();
    if (ret)
        goto _out;

_out:
    if (g_reload_flag) {
        for (i = 0; i < MAX_CORES; ++i) {
            rte_atomic16_set(&g_reload_perflag[i], g_reload_flag);
        }
    }

    config_reload_free();
    return ret;
}
