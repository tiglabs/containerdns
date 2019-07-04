#ifndef KDNS_CTRL_MSG_H
#define KDNS_CTRL_MSG_H

#include "netdev.h"

typedef enum {
    CTRL_MSG_TYPE_DOMAIN,
    CTRL_MSG_TYPE_VIEW,
    CTRL_MSG_TYPE_TO_KNI,
    CTRL_MSG_TYPE_TO_TX,
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

int ctrl_msg_slave_ingress(void **msg, uint16_t msg_cnt, unsigned slave_lcore);

int ctrl_msg_master_ingress(void **msg, uint16_t msg_cnt);

uint16_t ctrl_msg_slave_process(unsigned slave_lcore);

uint16_t ctrl_msg_master_process(void);

void ctrl_msg_init(void);

#endif //KDNS_CTRL_MSG_H
