#ifndef __VIEW_UPDATE_H__
#define __VIEW_UPDATE_H__

#include "kdns.h"
#include "view.h"
#include "webserver.h"
#include "query.h"

typedef struct view_info_update{
    enum view_action   action;
    
    char  cidrs[MAX_VIEW_NAME_LEN];
    char  view_name[MAX_VIEW_NAME_LEN];

    struct view_info_update *next;  
}view_info_update_st;

void view_msg_slave_process(void);
void view_msg_master_process(void);
void view_msg_ring_create(void);
void* view_post(struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response);
void* view_del(struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response);
void* views_post_all(struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response);
void* views_delete_all(struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response);

void* view_get( __attribute__((unused)) struct connection_info_struct *con_info, char* url, int * len_response);
void  view_query_tcp(struct query *query_tcp);


#endif
