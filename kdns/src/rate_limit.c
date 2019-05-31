/*
 * rate_limit.c
 */

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_hash.h>
#include <rte_mbuf.h>
#include <rte_meter.h>
#include <rte_cycles.h>
#include <arpa/inet.h>

#include "kdns.h"
#include "dns-conf.h"
#include "rate_limit.h"

#if defined(RTE_MACHINE_CPUFLAG_SSE4_2) || defined(RTE_MACHINE_CPUFLAG_CRC32)
#define EM_HASH_CRC 1
#endif

#ifdef EM_HASH_CRC
#include <rte_hash_crc.h>

#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>

#define DEFAULT_HASH_FUNC       rte_jhash
#endif

#define EXCEEDED_LOG_PER_SECOND     (1)

typedef struct {
    uint32_t client_num;
    uint32_t rl_ps[RATE_LIMIT_TYPE_MAX];
} rate_limit_ctrl;

typedef struct {
    uint32_t exceeded_cnt;
    struct rte_meter_srtcm rl_meter[RATE_LIMIT_TYPE_MAX];
} rate_limit_hnode;

static rate_limit_ctrl rl_ctrl[MAX_CORES];
static struct rte_hash *rl_hmap[MAX_CORES];
static rate_limit_hnode *rl_harray[MAX_CORES];

static const char *rl_type_str_array[RATE_LIMIT_TYPE_MAX] = {
    "all",
    "fwd",
    "exceeded log"
};

static inline const char *rate_limit_type_str(rate_limit_type type) {
    if (unlikely(type < 0 || type >= RATE_LIMIT_TYPE_MAX)) {
        return "illegal type";
    }

    return rl_type_str_array[type];
}

int rate_limit(uint32_t sip, rate_limit_type type, unsigned lcore_id) {
    int ret;
    uint64_t now;
    rate_limit_hnode *hnode;

    if (unlikely(type < 0 || type >= RATE_LIMIT_TYPE_MAX)) {
        log_msg(LOG_ERR, "rate limit illegal type %d\n", type);
        return 0;
    }
    if (rl_ctrl[lcore_id].rl_ps[type] == 0 || rl_ctrl[lcore_id].client_num == 0) {
        return 0;
    }

    ret = rte_hash_lookup(rl_hmap[lcore_id], (const void *)&sip);
    if (ret < 0) {
        ret = rte_hash_add_key(rl_hmap[lcore_id], (const void *)&sip);
        if (ret < 0) {
            log_msg(LOG_ERR, "Failed to insert sip %s to hash table %d, ret %d!", inet_ntoa(*(struct in_addr *)&sip), lcore_id, ret);
            return 0;
        }
    }

    now = rte_rdtsc();
    hnode = &rl_harray[lcore_id][ret];
    if (rte_meter_srtcm_color_blind_check(&hnode->rl_meter[type], now, 1) == e_RTE_METER_RED) {
        ++hnode->exceeded_cnt;
        if (rte_meter_srtcm_color_blind_check(&hnode->rl_meter[RATE_LIMIT_TYPE_EXCEEDED_LOG], now, 1) != e_RTE_METER_RED) {
            log_msg(LOG_ERR, "query from %s, %s rate limit exceeded %d, drop\n", inet_ntoa(*(struct in_addr *)&sip), rate_limit_type_str(type), hnode->exceeded_cnt);
            hnode->exceeded_cnt = 0;
        }
        return -1;
    }

    return 0;
}

int rate_limit_init(unsigned lcore_id) {
    int ret;
    uint32_t i;
    char name[RTE_HASH_NAMESIZE];
    struct rte_hash_parameters hash_params;
    struct rte_meter_srtcm_params meter_params[RATE_LIMIT_TYPE_MAX];
    rate_limit_hnode tmp;

    rl_ctrl[lcore_id].client_num = g_dns_cfg->comm.client_num;
    rl_ctrl[lcore_id].rl_ps[RATE_LIMIT_TYPE_ALL] = g_dns_cfg->comm.all_per_second;
    rl_ctrl[lcore_id].rl_ps[RATE_LIMIT_TYPE_FWD] = g_dns_cfg->comm.fwd_per_second;
    rl_ctrl[lcore_id].rl_ps[RATE_LIMIT_TYPE_EXCEEDED_LOG] = EXCEEDED_LOG_PER_SECOND;
    if (rl_ctrl[lcore_id].client_num == 0 || (rl_ctrl[lcore_id].rl_ps[RATE_LIMIT_TYPE_ALL] == 0 && rl_ctrl[lcore_id].rl_ps[RATE_LIMIT_TYPE_FWD] == 0)) {
        log_msg(LOG_INFO, "rate limit is disabled!\n");
        return 0;
    }

    if (rl_hmap[lcore_id] == NULL) {
        hash_params.name = name,
        hash_params.entries = rl_ctrl[lcore_id].client_num,
        hash_params.key_len = sizeof(uint32_t),
        hash_params.hash_func = DEFAULT_HASH_FUNC,
        hash_params.hash_func_init_val = 0,
        hash_params.socket_id = rte_socket_id(),
        snprintf(name, sizeof(name), "rl_hmap_%u", lcore_id);
        rl_hmap[lcore_id] = rte_hash_create(&hash_params);
        if (rl_hmap[lcore_id] == NULL) {
            log_msg(LOG_ERR, "Failed to create hash table: %s!\n", name);
            exit(-1);
        }
    }

    if (rl_harray[lcore_id] == NULL) {
        snprintf(name, sizeof(name), "rl_harray_%u", lcore_id);
        rl_harray[lcore_id] = rte_calloc(name, rl_ctrl[lcore_id].client_num, sizeof(rate_limit_hnode), 0);
        if (rl_harray[lcore_id] == NULL) {
            log_msg(LOG_ERR, "Failed to malloc hash array: %s!\n", name);
            exit(-1);
        }
    }

    memset(&tmp, 0, sizeof(tmp));
    for (i = 0; i < RATE_LIMIT_TYPE_MAX; ++i) {
        if (rl_ctrl[lcore_id].rl_ps[i]) {
            meter_params[i].cir = rl_ctrl[lcore_id].rl_ps[i];
            meter_params[i].cbs = rl_ctrl[lcore_id].rl_ps[i];
            meter_params[i].ebs = rl_ctrl[lcore_id].rl_ps[i] / 2;

            ret = rte_meter_srtcm_config(&tmp.rl_meter[i], &meter_params[i]);
            if (ret) {
                log_msg(LOG_ERR, "Failed to init %s meter srtcm config!\n", rate_limit_type_str(i));
                exit(-1);
            }
        }
    }
    for (i = 0; i < rl_ctrl[lcore_id].client_num; ++i) {
        memcpy(&rl_harray[lcore_id][i], &tmp, sizeof(rate_limit_hnode));
    }
    return 0;
}

void rate_limit_uninit(unsigned lcore_id) {
    if (rl_harray[lcore_id]) {
        rte_free(rl_harray[lcore_id]);
        rl_harray[lcore_id] = NULL;
    }
    if (rl_hmap[lcore_id]) {
        rte_hash_free(rl_hmap[lcore_id]);
        rl_hmap[lcore_id] = NULL;
    }
}

int rate_limit_reload(unsigned lcore_id) {
    if (rl_ctrl[lcore_id].client_num != g_dns_cfg->comm.client_num) {
        rate_limit_uninit(lcore_id);
    }

    rate_limit_init(lcore_id);
    return 0;
}