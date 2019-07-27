#ifndef __DNSCONF_H__
#define __DNSCONF_H__

#include <stdint.h>
#include "ctrl_msg.h"
#include "zone.h"

#define DPDK_MAX_ARG_NUM    (32)
#define DPDK_MAX_ARG_LEN    (128)
#define MAX_CONFIG_STR_LEN  (2048)

struct config_update {
    ctrl_msg cmsg;
    uint32_t flags;

    char del_zones[MAX_CONFIG_STR_LEN];
    char add_zones[MAX_CONFIG_STR_LEN];

    int fwd_mode;
    int fwd_timeout;
    char fwd_def_addrs[MAX_CONFIG_STR_LEN];
    char fwd_zones_addrs[MAX_CONFIG_STR_LEN];

    uint32_t all_per_second;
    uint32_t fwd_per_second;
    uint32_t client_num;
};

struct comm_config {
    char log_file[MAX_CONFIG_STR_LEN];
    char metrics_host[32];
    char zones[MAX_CONFIG_STR_LEN];

    int fwd_mode;
    uint16_t fwd_threads;
    uint16_t fwd_timeout;
    uint32_t fwd_mbuf_num;
    char fwd_def_addrs[MAX_CONFIG_STR_LEN];
    char fwd_zones_addrs[MAX_CONFIG_STR_LEN];

    uint16_t web_port;
    int ssl_enable;
    char key_pem_file[MAX_CONFIG_STR_LEN];
    char cert_pem_file[MAX_CONFIG_STR_LEN];

    uint32_t all_per_second;
    uint32_t fwd_per_second;
    uint32_t client_num;
};

struct netdev_config {
    int mode;              //rss: 0, other: 1

    uint32_t mbuf_num;
    uint16_t rxq_desc_num;
    uint16_t txq_desc_num;
    uint16_t rxq_num;
    uint16_t txq_num;

    char kni_name_prefix[32];
    uint32_t kni_mbuf_num;
    uint32_t kni_ip;
    char kni_vip[32];
    uint32_t kni_gateway;
};

struct eal_config {
    int argc;
    char argv[DPDK_MAX_ARG_NUM][DPDK_MAX_ARG_LEN];
};

struct dns_config {
    struct eal_config eal;
    struct netdev_config netdev;
    struct comm_config comm;
};

extern struct dns_config *g_dns_cfg;

int dns_config_load(char *cfgfile_path, char *proc_name);

int dns_config_reload(char *cfgfile_path, char *proc_name);

#endif
