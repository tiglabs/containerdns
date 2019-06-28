/*
 * ctrl_msg.c
 */

#include <rte_eal.h>
#include <rte_kni.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_launch.h>
#include <rte_malloc.h>
#include <rte_prefetch.h>

#include "kdns.h"
#include "netdev.h"
#include "ctrl_msg.h"
#include "dns-conf.h"
#include "kdns-adap.h"
#include "rate_limit.h"
#include "domain_update.h"
#include "view_update.h"
#include "process.h"

#define CTRL_RING_SZ        (65536)

static unsigned master_lcore;
static struct rte_ring *ctrl_msg_ring[MAX_CORES];

static int ctrl_msg_ingress(struct rte_ring *ring, void **msg, uint16_t msg_cnt) {
    uint16_t nb_tx;

    nb_tx = rte_ring_enqueue_burst(ring, msg, msg_cnt);
    if (unlikely(nb_tx < msg_cnt)) {
        uint16_t s_cnt = nb_tx;
        log_msg(LOG_ERR, "%s packet loss due to full ring, loss %d\n", ring->name, msg_cnt - nb_tx);
        do {
            free(msg[nb_tx]);
        } while (++nb_tx < msg_cnt);
        return s_cnt;
    }
    return nb_tx;
}

int ctrl_msg_master_ingress(void **msg, uint16_t msg_cnt) {
    return ctrl_msg_ingress(ctrl_msg_ring[master_lcore], msg, msg_cnt);
}

int ctrl_msg_slave_ingress(void **msg, uint16_t msg_cnt, unsigned slave_lcore) {
    return ctrl_msg_ingress(ctrl_msg_ring[slave_lcore], msg, msg_cnt);
}

uint16_t ctrl_msg_slave_process(unsigned slave_lcore) {
    uint16_t i, nb_rx;
    ctrl_msg *msg[NETIF_MAX_PKT_BURST];

    nb_rx = rte_ring_dequeue_burst(ctrl_msg_ring[slave_lcore], (void **)msg, NETIF_MAX_PKT_BURST);
    if (likely(nb_rx == 0)) {
        return 0;
    }

    for (i = 0; i < nb_rx; ++i) {
        switch (msg[i]->type) {
        case CTRL_MSG_TYPE_DOMAIN:
            domain_msg_slave_process(msg[i], slave_lcore);
            break;
        case CTRL_MSG_TYPE_VIEW:
            view_msg_slave_process(msg[i], slave_lcore);
            break;
        case CTRL_MSG_TYPE_TO_KNI:
            log_msg(LOG_ERR, "unexpected msg CTRL_MSG_TYPE_TO_KNI on slave_lcore %u\n", slave_lcore);
            free(msg[i]);
            break;
        case CTRL_MSG_TYPE_TO_TX:
            kni_msg_slave_process(msg[i], slave_lcore);
            break;
        default:
            log_msg(LOG_ERR, "unknow msg type %d on slave_lcore %u\n", msg[i]->type, slave_lcore);
            free(msg[i]);
            break;
        }
    }
    return nb_rx;
}

uint16_t ctrl_msg_master_process(void) {
    uint16_t i, nb_copy, nb_rx;
    ctrl_msg *msg[NETIF_MAX_PKT_BURST];
    ctrl_msg *msg_copy[NETIF_MAX_PKT_BURST];

    nb_rx = rte_ring_dequeue_burst(ctrl_msg_ring[master_lcore], (void **)msg, NETIF_MAX_PKT_BURST);
    if (likely(nb_rx == 0)) {
        return 0;
    }

    unsigned lcore_id;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        nb_copy = 0;
        for (i = 0; i < nb_rx; ++i) {
            if (msg[i]->type == CTRL_MSG_TYPE_DOMAIN || msg[i]->type == CTRL_MSG_TYPE_VIEW) {
                msg_copy[nb_copy] = xalloc_zero(msg[i]->len);
                memcpy(msg_copy[nb_copy], msg[i], msg[i]->len);
                ++nb_copy;
            }
        }
        if (nb_copy) {
            ctrl_msg_ingress(ctrl_msg_ring[lcore_id], (void **)msg_copy, nb_copy);
        } else {
            break;
        }
    }
    for (i = 0; i < nb_rx; ++i) {
        switch (msg[i]->type) {
        case CTRL_MSG_TYPE_DOMAIN:
            domain_msg_master_process(msg[i]);
            break;
        case CTRL_MSG_TYPE_VIEW:
            view_msg_master_process(msg[i]);
            break;
        case CTRL_MSG_TYPE_TO_KNI:
            kni_msg_master_process(msg[i]);
            break;
        case CTRL_MSG_TYPE_TO_TX:
            log_msg(LOG_ERR, "unexpected msg CTRL_MSG_TYPE_TO_TX on master_lcore\n");
            free(msg[i]);
            break;
        default:
            log_msg(LOG_ERR, "unknow msg type %d on master_lcore\n", msg[i]->type);
            free(msg[i]);
            break;
        }
    }
    return nb_rx;
}

void ctrl_msg_init(void) {
    unsigned lcore_id;
    char ring_name[32];

    master_lcore = rte_get_master_lcore();
    RTE_LCORE_FOREACH(lcore_id) {
        snprintf(ring_name, sizeof(ring_name), "ctrl_msg_ring_%u", lcore_id);
        if (lcore_id == master_lcore) {
            ctrl_msg_ring[lcore_id] = rte_ring_create(ring_name, CTRL_RING_SZ, rte_socket_id(), RING_F_SC_DEQ);
        } else {
            ctrl_msg_ring[lcore_id] = rte_ring_create(ring_name, CTRL_RING_SZ, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        }
        if (ctrl_msg_ring[lcore_id] == NULL) {
            log_msg(LOG_ERR, "Cannot create %s\n", ring_name);
            exit(-1);
        }
    }
}
