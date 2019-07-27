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
#include "rate_limit.h"
#include "netdev.h"
#include "tcp_process.h"
#include "local_udp_process.h"

#define UPDATE_ZONES                (0x1 << 0)
#define UPDATE_FWD_MODE             (0x1 << 1)
#define UPDATE_FWD_TIMEOUT          (0x1 << 2)
#define UPDATE_FWD_DEF_ADDRS        (0x1 << 3)
#define UPDATE_FWD_ZONES_ADDRS      (0x1 << 4)
#define UPDATE_ALL_PER_SECOND       (0x1 << 5)
#define UPDATE_FWD_PER_SECOND       (0x1 << 6)
#define UPDATE_CLIENT_NUM           (0x1 << 7)

struct dns_config *g_dns_cfg;
struct dns_config *g_reload_dns_cfg;

static void dns_config_init(struct dns_config *cfg) {
    memset(cfg, 0, sizeof(struct dns_config));

    cfg->netdev.mode = 0;                   //rss
    cfg->netdev.mbuf_num = 65535;
    cfg->netdev.rxq_desc_num = 1024;
    cfg->netdev.txq_desc_num = 2048;
    strncpy(cfg->netdev.kni_name_prefix, "kdns", sizeof(cfg->netdev.kni_name_prefix) - 1);
    cfg->netdev.kni_mbuf_num = 8191;

    strncpy(cfg->comm.log_file, "/export/log/kdns/kdns.log", sizeof(cfg->comm.log_file) - 1);
    strncpy(cfg->comm.metrics_host, "dns-metrics_host ^^", sizeof(cfg->comm.metrics_host) - 1);
    cfg->comm.fwd_mode = FWD_MODE_TYPE_CACHE;
    cfg->comm.fwd_threads = 1;
    cfg->comm.fwd_timeout = 2;
    cfg->comm.fwd_mbuf_num = 1023;
    strncpy(cfg->comm.fwd_def_addrs, "8.8.8.8:53,114.114.114.114:53", sizeof(cfg->comm.fwd_def_addrs) - 1);
    cfg->comm.web_port = 5500;
    cfg->comm.ssl_enable = 0;               //disable ssl
    cfg->comm.all_per_second = 0;           //disable rate-limit
    cfg->comm.fwd_per_second = 0;           //disable fwd rate-limit
    cfg->comm.client_num = 16384;
}

static int eal_config_load(struct rte_cfgfile *cfgfile, struct eal_config *cfg, const char *proc_name) {
    const char *entry;

    /* proc name */
    strncpy(cfg->argv[cfg->argc++], proc_name, DPDK_MAX_ARG_LEN - 1);

    /* EAL */
    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "cores");
    if (entry) {
        snprintf(cfg->argv[cfg->argc++], DPDK_MAX_ARG_LEN, "-l%s", entry);
    } else {
        printf("No EAL/cores options.\n");
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "memory");
    if (entry) {
        snprintf(cfg->argv[cfg->argc++], DPDK_MAX_ARG_LEN, "--socket-mem=%s", entry);
    } else {
        printf("No EAL/memory options.\n");
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "mem-channels");
    if (entry) {
        snprintf(cfg->argv[cfg->argc++], DPDK_MAX_ARG_LEN, "-n%s", entry);
    } else {
        printf("No EAL/mem-channels options.\n");
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "hugefile-prefix");
    if (entry) {
        snprintf(cfg->argv[cfg->argc++], DPDK_MAX_ARG_LEN, "--file-prefix=%s", entry);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "EAL", "log-level");
    if (entry) {
        snprintf(cfg->argv[cfg->argc++], DPDK_MAX_ARG_LEN, "--log-level=%s", entry);
    }

    return 0;
}

static int netdev_config_load(struct rte_cfgfile *cfgfile, struct netdev_config *cfg) {
    const char *entry;

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "mode");
    if (entry) {
        cfg->mode = netdev_mode_parse(entry);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "mbuf-num");
    if (entry && parser_read_uint32(&cfg->mbuf_num, entry) < 0) {
        printf("Cannot read NETDEV/mbuf-num = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "rxqueue-len");
    if (entry && parser_read_uint16(&cfg->rxq_desc_num, entry) < 0) {
        printf("Cannot read NETDEV/rxqueue-len = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "txqueue-len");
    if (entry && parser_read_uint16(&cfg->txq_desc_num, entry) < 0) {
        printf("Cannot read NETDEV/txqueue-len = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "rxqueue-num");
    if (entry) {
        if (parser_read_uint16(&cfg->rxq_num, entry) < 0) {
            printf("Cannot read NETDEV/rxqueue-num = %s.\n", entry);
            return -1;
        }
    } else {
        printf("No NETDEV/rxqueue-num options.\n");
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "txqueue-num");
    if (entry) {
        if (parser_read_uint16(&cfg->txq_num, entry) < 0) {
            printf("Cannot read NETDEV/txqueue-num = %s.\n", entry);
            return -1;
        }
    } else {
        printf("No NETDEV/txqueue-num options.\n");
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "name-prefix");
    if (entry) {
        strncpy(cfg->kni_name_prefix, entry, sizeof(cfg->kni_name_prefix) - 1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "kni-mbuf-num");
    if (entry && parser_read_uint32(&cfg->kni_mbuf_num, entry) < 0) {
        printf("Cannot read NETDEV/kni-mbuf-num = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "NETDEV", "kni-vip");
    if (entry) {
        struct in_addr tmp;
        if (parse_ipv4_addr(entry, &tmp) < 0) {
            printf("Cannot read NETDEV/kni-vip = %s\n", entry);
            return -1;
        }
        strncpy(cfg->kni_vip, entry, sizeof(cfg->kni_vip) - 1);
    } else {
        printf("No NETDEV/kni-vip options.\n");
        return -1;
    }

    return 0;
}

static int common_config_load(struct rte_cfgfile *cfgfile, struct comm_config *cfg) {
    const char *entry;

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "log-file");
    if (entry) {
        strncpy(cfg->log_file, entry, sizeof(cfg->log_file) - 1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "metrics-host");
    if (entry) {
        strncpy(cfg->metrics_host, entry, sizeof(cfg->metrics_host) - 1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "zones");
    if (entry) {
        strncpy(cfg->zones, entry, sizeof(cfg->zones) - 1);
    } else {
        printf("No COMMON/zones options.\n");
        return -1;
    }

    //fwd config
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-mode");
    if (entry && (cfg->fwd_mode = fwd_mode_parse(entry)) < 0) {
        printf("Cannot read COMMON/fwd-mode = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-thread-num");
    if (entry && parser_read_uint16(&cfg->fwd_threads, entry) < 0) {
        printf("Cannot read COMMON/fwd-thread-num = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-timeout");
    if (entry && parser_read_uint16(&cfg->fwd_timeout, entry) < 0) {
        printf("Cannot read COMMON/fwd-timeout = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-mbuf-num");
    if (entry && parser_read_uint32(&cfg->fwd_mbuf_num, entry) < 0) {
        printf("Cannot read COMMON/fwd-mbuf-num = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-def-addrs");
    if (entry) {
        strncpy(cfg->fwd_def_addrs, entry, sizeof(cfg->fwd_def_addrs) - 1);
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-addrs");
    if (entry) {
        strncpy(cfg->fwd_zones_addrs, entry, sizeof(cfg->fwd_zones_addrs) - 1);
    }

    //web config
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "web-port");
    if (entry && parser_read_uint16(&cfg->web_port, entry) < 0) {
        printf("Cannot read COMMON/web-port = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "ssl-enable");
    if (entry && (cfg->ssl_enable = parser_read_arg_bool(entry)) < 0) {
        printf("Cannot read COMMON/ssl-enable = %s.\n", entry);
        return -1;
    }

    if (cfg->ssl_enable) {
        entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "key-pem-file");
        if (entry) {
            strncpy(cfg->key_pem_file, entry, sizeof(cfg->key_pem_file) - 1);
        } else {
            printf("No COMMON/key-pem-file options.\n");
            return -1;
        }

        entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "cert-pem-file");
        if (entry) {
            strncpy(cfg->cert_pem_file, entry, sizeof(cfg->cert_pem_file) - 1);
        } else {
            printf("No COMMON/cert-pem-file options.\n");
            return -1;
        }
    }

    //rate limit config
    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "all-per-second");
    if (entry && parser_read_uint32(&cfg->all_per_second, entry) < 0) {
        printf("Cannot read COMMON/all-per-second = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "fwd-per-second");
    if (entry && parser_read_uint32(&cfg->fwd_per_second, entry) < 0) {
        printf("Cannot read COMMON/fwd-per-second = %s.\n", entry);
        return -1;
    }

    entry = rte_cfgfile_get_entry(cfgfile, "COMMON", "client-num");
    if (entry && parser_read_uint32(&cfg->client_num, entry) < 0) {
        printf("Cannot read COMMON/client-num = %s.\n", entry);
        return -1;
    }

    return 0;
}

static int config_file_load(struct dns_config *cfg, char *cfgfile_path, char *proc_name) {
    int ret = 0;

    struct rte_cfgfile *cfgfile = rte_cfgfile_load(cfgfile_path, 0);
    if (cfgfile == NULL) {
        printf("Load config file failed: %s\n", cfgfile_path);
        return -1;
    }

    ret |= eal_config_load(cfgfile, &cfg->eal, proc_name);
    ret |= netdev_config_load(cfgfile, &cfg->netdev);
    ret |= common_config_load(cfgfile, &cfg->comm);

    rte_cfgfile_close(cfgfile);
    return ret;
}

static void dns_config_dump(struct dns_config *cfg) {
    int i;
    char tmp[MAX_CONFIG_STR_LEN] = {0};

    log_msg(LOG_INFO, "EAL config:\n");
    for (i = 0; i < cfg->eal.argc; ++i) {
        sprintf(tmp + strlen(tmp), "%s ", cfg->eal.argv[i]);
    }
    log_msg(LOG_INFO, "\t %s", tmp);
    log_msg(LOG_INFO, "\n");

    log_msg(LOG_INFO, "NETDEV config:\n");
    log_msg(LOG_INFO, "\t mode: %s\n", cfg->netdev.mode == 0 ? "rss" : "other");
    log_msg(LOG_INFO, "\t mbuf-num: %u\n", cfg->netdev.mbuf_num);
    log_msg(LOG_INFO, "\t rxqueue-len: %u\n", cfg->netdev.rxq_desc_num);
    log_msg(LOG_INFO, "\t txqueue-len: %u\n", cfg->netdev.txq_desc_num);
    log_msg(LOG_INFO, "\t rxqueue-num: %u\n", cfg->netdev.rxq_num);
    log_msg(LOG_INFO, "\t txqueue-num: %u\n", cfg->netdev.txq_num);
    log_msg(LOG_INFO, "\t name-prefix: %s\n", cfg->netdev.kni_name_prefix);
    log_msg(LOG_INFO, "\t kni-mbuf-num: %u\n", cfg->netdev.kni_mbuf_num);
    log_msg(LOG_INFO, "\t kni-vip: %s\n", cfg->netdev.kni_vip);
    log_msg(LOG_INFO, "\n");

    log_msg(LOG_INFO, "COMMON config:\n");
    log_msg(LOG_INFO, "\t log-file: %s\n", cfg->comm.log_file);
    log_msg(LOG_INFO, "\t metrics-host: %s\n", cfg->comm.metrics_host);
    log_msg(LOG_INFO, "\t zones: %s\n", cfg->comm.zones);
    log_msg(LOG_INFO, "\t fwd-mode: %s\n", fwd_mode_type_str(cfg->comm.fwd_mode));
    log_msg(LOG_INFO, "\t fwd-thread-num: %u\n", cfg->comm.fwd_threads);
    log_msg(LOG_INFO, "\t fwd-timeout: %u\n", cfg->comm.fwd_timeout);
    log_msg(LOG_INFO, "\t fwd-mbuf-num: %u\n", cfg->comm.fwd_mbuf_num);
    log_msg(LOG_INFO, "\t fwd-def-addrs: %s\n", cfg->comm.fwd_def_addrs);
    log_msg(LOG_INFO, "\t fwd-addrs: %s\n", cfg->comm.fwd_zones_addrs);
    log_msg(LOG_INFO, "\t web-port: %u\n", cfg->comm.web_port);
    log_msg(LOG_INFO, "\t ssl-enable: %u\n", cfg->comm.ssl_enable);
    log_msg(LOG_INFO, "\t key-pem-file: %s\n", cfg->comm.key_pem_file);
    log_msg(LOG_INFO, "\t cert-pem-file: %s\n", cfg->comm.cert_pem_file);
    log_msg(LOG_INFO, "\t all-per-second: %u\n", cfg->comm.all_per_second);
    log_msg(LOG_INFO, "\t fwd-per-second: %u\n", cfg->comm.fwd_per_second);
    log_msg(LOG_INFO, "\t client-num: %u\n", cfg->comm.client_num);
    log_msg(LOG_INFO, "\n");
}

typedef char (*zone_str)[MAXDOMAINLEN];
static zone_str zones_parse(char *zones, int *num) {
    int idx = 0;
    char *tmp, *name;
    zone_str zones_array;
    char zone_tmp[MAX_CONFIG_STR_LEN] = {0};

    if (zones == NULL || strlen(zones) == 0) {
        *num = 0;
        return NULL;
    }

    *num = 1;
    strncpy(zone_tmp, zones, sizeof(zone_tmp) - 1);
    char *pch = strchr(zone_tmp, ',');
    while (pch != NULL) {
        (*num)++;
        pch = strchr(pch + 1, ',');
    }
    if (*num == 0) {
        return NULL;
    }

    zones_array = xalloc_array_zero(*num, MAXDOMAINLEN);
    name = strtok_r(zone_tmp, ",", &tmp);
    while (name) {
        strncpy(zones_array[idx++], name, MAXDOMAINLEN - 1);
        name = strtok_r(0, ",", &tmp);
    }

    return zones_array;
}

static int zones_reload_parse(char *new_zones, char *old_zones, char *del_zone, char *add_zone) {
    int i, j;
    int new_zones_num = 0, old_zones_num = 0;
    zone_str new_zones_array, old_zones_array;

    new_zones_array = zones_parse(new_zones, &new_zones_num);
    old_zones_array = zones_parse(old_zones, &old_zones_num);

    for (i = 0; i < new_zones_num; ++i) {
        for (j = 0; j < old_zones_num; ++j) {
            if (strcasecmp(new_zones_array[i], old_zones_array[j]) == 0) {
                break;
            }
        }
        if (j == old_zones_num) {
            int len = strlen(add_zone);
            if (len) {
                sprintf(add_zone + len, ",%s", new_zones_array[i]);
            } else {
                sprintf(add_zone, "%s", new_zones_array[i]);
            }
        }
    }
    log_msg(LOG_INFO, "reload zones, add: %s.", add_zone);

    for (i = 0; i < old_zones_num; ++i) {
        for (j = 0; j < new_zones_num; ++j) {
            if (strcasecmp(old_zones_array[i], new_zones_array[j]) == 0) {
                break;
            }
        }
        if (j == new_zones_num) {
            int len = strlen(del_zone);
            if (len) {
                sprintf(del_zone + len, ",%s", old_zones_array[i]);
            } else {
                sprintf(del_zone, "%s", old_zones_array[i]);
            }
        }
    }
    log_msg(LOG_INFO, "reload zones, del: %s.", del_zone);

    if (new_zones_array) {
        free(new_zones_array);
    }
    if (old_zones_array) {
        free(old_zones_array);
    }
    return 0;
}

static int send_config_msg_to_master(struct config_update *msg) {
    msg->cmsg.type = CTRL_MSG_TYPE_UPDATE_CONFIG;
    msg->cmsg.len = sizeof(struct config_update);

    return ctrl_msg_master_ingress((void **)&msg, 1) == 1 ? 0 : -1;
}

int dns_config_reload(char *cfgfile_path, char *proc_name) {
    if (!g_reload_dns_cfg) {
        g_reload_dns_cfg = xalloc(sizeof(struct dns_config));
        if (!g_reload_dns_cfg) {
            log_msg(LOG_ERR, "Cannot alloc memory for g_reload_dns_cfg.");
            return -1;
        }
    }
    dns_config_init(g_reload_dns_cfg);

    if (config_file_load(g_reload_dns_cfg, cfgfile_path, proc_name) < 0) {
        log_msg(LOG_ERR, "Failed to reload config file %s.\n", cfgfile_path);
        return -1;
    }

    uint32_t reload_flag = 0;
    struct comm_config *new = &g_reload_dns_cfg->comm;
    struct comm_config *old = &g_dns_cfg->comm;

    if (strcmp(new->log_file, old->log_file)) {
        log_msg(LOG_INFO, "reload log file, new: %s, old: %s.", new->log_file, old->log_file);
        if (log_file_reload(new->log_file) == 0) {
            strncpy(old->log_file, new->log_file, sizeof(old->log_file) - 1);
        } else {
            log_msg(LOG_ERR, "reload log file error: %s.", new->log_file);
        }
    }
    dns_config_dump(g_reload_dns_cfg);

    if (strcmp(new->metrics_host, old->metrics_host)) {
        log_msg(LOG_INFO, "reload metrics host, new: %s, old: %s.", new->metrics_host, old->metrics_host);
        if (metrics_host_reload(new->metrics_host) == 0) {
            strncpy(old->metrics_host, new->metrics_host, sizeof(old->metrics_host) - 1);
        } else {
            log_msg(LOG_ERR, "reload metrics host error: %s.", new->metrics_host);
        }
    }

    if (strcasecmp(new->zones, old->zones)) {
        log_msg(LOG_INFO, "reload zones, new: %s.", new->zones);
        log_msg(LOG_INFO, "reload zones, old: %s.", old->zones);
        reload_flag |= UPDATE_ZONES;
    }
    if (new->fwd_mode != old->fwd_mode) {
        log_msg(LOG_INFO, "reload fwd mode, new: %s, old: %s.", fwd_mode_type_str(new->fwd_mode), fwd_mode_type_str(old->fwd_mode));
        reload_flag |= UPDATE_FWD_MODE;
    }
    if (new->fwd_timeout != old->fwd_timeout) {
        log_msg(LOG_INFO, "reload fwd timeout, new: %d, old: %d.", new->fwd_timeout, old->fwd_timeout);
        reload_flag |= UPDATE_FWD_TIMEOUT;
    }
    if (strcasecmp(new->fwd_def_addrs, old->fwd_def_addrs)) {
        log_msg(LOG_INFO, "reload fwd def addrs, new: %s, old: %s.", new->fwd_def_addrs, old->fwd_def_addrs);
        reload_flag |= UPDATE_FWD_DEF_ADDRS;
    }
    if (strcasecmp(new->fwd_zones_addrs, old->fwd_zones_addrs)) {
        log_msg(LOG_INFO, "reload fwd zones addrs, new: %s, old: %s.", new->fwd_zones_addrs, old->fwd_zones_addrs);
        reload_flag |= UPDATE_FWD_ZONES_ADDRS;
    }
    if (new->all_per_second != old->all_per_second) {
        log_msg(LOG_INFO, "reload all per second, new: %d, old: %d.", new->all_per_second, old->all_per_second);
        reload_flag |= UPDATE_ALL_PER_SECOND;
    }
    if (new->fwd_per_second != old->fwd_per_second) {
        log_msg(LOG_INFO, "reload fwd per second, new: %d, old: %d.", new->fwd_per_second, old->fwd_per_second);
        reload_flag |= UPDATE_FWD_PER_SECOND;
    }
    if (new->client_num != old->client_num) {
        log_msg(LOG_INFO, "reload client num, new: %d, old: %d.", new->client_num, old->client_num);
        reload_flag |= UPDATE_CLIENT_NUM;
    }
    if (reload_flag) {
        struct config_update *update = xalloc_zero(sizeof(struct config_update));

        update->flags = reload_flag;
        if (update->flags & UPDATE_ZONES) {
            zones_reload_parse(new->zones, old->zones, update->del_zones, update->add_zones);
        }
        if (update->flags & (UPDATE_FWD_MODE | UPDATE_FWD_TIMEOUT | UPDATE_FWD_DEF_ADDRS | UPDATE_FWD_ZONES_ADDRS)) {
            update->fwd_mode = new->fwd_mode;
            update->fwd_timeout = new->fwd_timeout;
            strncpy(update->fwd_def_addrs, new->fwd_def_addrs, sizeof(update->fwd_def_addrs) - 1);
            strncpy(update->fwd_zones_addrs, new->fwd_zones_addrs, sizeof(update->fwd_zones_addrs) - 1);
        }
        if (update->flags & (UPDATE_ALL_PER_SECOND | UPDATE_FWD_PER_SECOND | UPDATE_CLIENT_NUM)) {
            update->all_per_second = new->all_per_second;
            update->fwd_per_second = new->fwd_per_second;
            update->client_num = new->client_num;
        }

        if (send_config_msg_to_master(update) != 0) {
            log_msg(LOG_ERR, "reload send update msg to master error.");
            return -1;
        }
        strncpy(old->zones, new->zones, sizeof(old->zones) - 1);
        old->fwd_mode = new->fwd_mode;
        old->fwd_timeout = new->fwd_timeout;
        strncpy(old->fwd_def_addrs, new->fwd_def_addrs, sizeof(old->fwd_def_addrs) - 1);
        strncpy(old->fwd_zones_addrs, new->fwd_zones_addrs, sizeof(old->fwd_zones_addrs) - 1);
        old->all_per_second = new->all_per_second;
        old->fwd_per_second = new->fwd_per_second;
        old->client_num = new->client_num;
    }
    return 0;
}

static int dns_config_master_process(ctrl_msg *msg) {
    struct config_update *update = (struct config_update *)msg;

    if (update->flags & UPDATE_ZONES) {
        tcp_zones_reload(update->del_zones, update->add_zones);
        local_udp_zones_reload(update->del_zones, update->add_zones);
        domain_list_del_zones(update->del_zones);
    }

    if (update->flags & (UPDATE_FWD_MODE | UPDATE_FWD_TIMEOUT | UPDATE_FWD_DEF_ADDRS | UPDATE_FWD_ZONES_ADDRS)) {
        fwd_ctrl_master_reload(update->fwd_mode, update->fwd_timeout, update->fwd_def_addrs, update->fwd_zones_addrs);
    }
    free(update);
    return 0;
}

static int dns_config_slave_process(ctrl_msg *msg, unsigned slave_lcore) {
    struct config_update *update = (struct config_update *)msg;

    if (update->flags & UPDATE_ZONES) {
        kdns_slave_zones_realod(update->del_zones, update->add_zones, slave_lcore);
    }
    if (update->flags & (UPDATE_FWD_TIMEOUT | UPDATE_FWD_MODE | UPDATE_FWD_DEF_ADDRS | UPDATE_FWD_ZONES_ADDRS)) {
        fwd_ctrl_slave_reload(update->fwd_mode, update->fwd_timeout, update->fwd_def_addrs, update->fwd_zones_addrs, slave_lcore);
    }
    if (update->flags & (UPDATE_ALL_PER_SECOND | UPDATE_FWD_PER_SECOND | UPDATE_CLIENT_NUM)) {
        rate_limit_reload(update->all_per_second, update->fwd_per_second, update->client_num, slave_lcore);
    }
    free(update);
    return 0;
}

int dns_config_load(char *cfgfile_path, char *proc_name) {
    ctrl_msg_reg(CTRL_MSG_TYPE_UPDATE_CONFIG, CTRL_MSG_FLAG_MASTER_SYNC_SLAVE, dns_config_master_process, dns_config_slave_process);

    g_dns_cfg = xalloc(sizeof(struct dns_config));
    if (!g_dns_cfg) {
        printf("Cannot alloc memory for config.\n");
        exit(-1);
    }
    dns_config_init(g_dns_cfg);

    if (config_file_load(g_dns_cfg, cfgfile_path, proc_name) < 0) {
        printf("Failed to load config file %s.\n", cfgfile_path);
        exit(-1);
    }
    log_open(g_dns_cfg->comm.log_file);
    dns_config_dump(g_dns_cfg);

    return 0;
}
