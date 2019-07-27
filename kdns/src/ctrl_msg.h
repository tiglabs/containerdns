#ifndef KDNS_CTRL_MSG_H
#define KDNS_CTRL_MSG_H

#include "netdev.h"

#define CTRL_MSG_FLAG_MASTER_SYNC_SLAVE (0x1 << 0)

typedef enum {
    CTRL_MSG_TYPE_UPDATE_DOMAIN,
    CTRL_MSG_TYPE_UPDATE_VIEW,
    CTRL_MSG_TYPE_MBUF_TO_KNI,
    CTRL_MSG_TYPE_MBUF_TO_TX,
    CTRL_MSG_TYPE_UPDATE_CONFIG,
    CTRL_MSG_TYPE_MAX,
} ctrl_msg_type;

typedef struct {
    ctrl_msg_type type;
    uint32_t len;

    char data[0];
} ctrl_msg;

typedef struct {
    ctrl_msg cmsg;

    uint16_t mbufs_cnts;
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
} ctrl_mbufs_msg;

typedef int (*ctrl_msg_master_cb)(ctrl_msg *msg);

typedef int (*ctrl_msg_slave_cb)(ctrl_msg *msg, unsigned slave_lcore);

int ctrl_msg_reg(ctrl_msg_type type, int ctrl_flag, ctrl_msg_master_cb master_cb, ctrl_msg_slave_cb slave_cb);

int ctrl_msg_slave_ingress(void **msg, uint16_t msg_cnt, unsigned slave_lcore);

int ctrl_msg_master_ingress(void **msg, uint16_t msg_cnt);

uint16_t ctrl_msg_slave_process(unsigned slave_lcore);

uint16_t ctrl_msg_master_process(void);

void ctrl_msg_init(void);

#endif //KDNS_CTRL_MSG_H
