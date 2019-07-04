#ifndef __VIEW_UPDATE_H__
#define __VIEW_UPDATE_H__

#include "kdns.h"
#include "view.h"
#include "webserver.h"
#include "query.h"
#include "ctrl_msg.h"

typedef struct view_info_update {
    ctrl_msg cmsg;

    enum view_action action;

    char cidrs[MAX_VIEW_NAME_LEN];
    char view_name[MAX_VIEW_NAME_LEN];

    struct view_info_update *next;
} view_info_update_st;

void *view_post(struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response);

void *view_del(struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response);

void *views_post_all(struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response);

void *views_delete_all(struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response);

void *view_get(__attribute__((unused)) struct connection_info_struct *con_info, char *url, int *len_response);

void view_query_slave_process(struct query *query, unsigned slave_lcore);

void view_query_master_process(struct query *query);

void view_msg_slave_process(ctrl_msg *msg, unsigned slave_lcore);

void view_msg_master_process(ctrl_msg *msg);

void view_master_init(void);

#endif
