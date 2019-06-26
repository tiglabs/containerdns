#ifndef KDNS_CTRL_MSG_H
#define KDNS_CTRL_MSG_H

typedef enum {
    CTRL_MSG_TYPE_DOMAIN,
    CTRL_MSG_TYPE_VIEW,
    CTRL_MSG_TYPE_MAX,
} ctrl_msg_type;

typedef struct {
    ctrl_msg_type type;
    uint32_t len;

    char data[0];
} ctrl_msg;

int ctrl_msg_master_ingress(void **msg, uint16_t msg_cnt);

uint16_t ctrl_msg_slave_process(unsigned slave_lcore);

uint16_t ctrl_msg_master_process(void);

void ctrl_msg_init(void);

#endif //KDNS_CTRL_MSG_H
