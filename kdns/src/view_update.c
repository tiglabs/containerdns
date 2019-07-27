/*
 * view_update.c 
 */

#include <rte_ring.h>
#include <rte_rwlock.h>
#include <jansson.h>
#include "domain_store.h"
#include "view_update.h"
#include "kdns.h"
#include "ctrl_msg.h"

extern struct kdns dpdk_dns[MAX_CORES];

static view_tree_t *view_master_tree;
static rte_rwlock_t view_master_lock;

static int send_view_msg_to_master(struct view_info_update *msg) {
    msg->cmsg.type = CTRL_MSG_TYPE_UPDATE_VIEW;
    msg->cmsg.len = sizeof(struct view_info_update);

    return ctrl_msg_master_ingress((void **)&msg, 1) == 1 ? 0 : -1;
}

static struct view_info_update *do_view_parse(enum view_action action, json_t *json_data) {
    struct view_info_update *update = xalloc_zero(sizeof(struct view_info_update));
    update->action = action;
    const char *view_name;

    /* get view name  */
    json_t *json_key = json_object_get(json_data, "viewName");
    if (!json_key || !json_is_string(json_key)) {
        log_msg(LOG_ERR, "viewName does not exist or is not string!");
        goto _parse_err;
    }
    view_name = json_string_value(json_key);
    snprintf(update->view_name, strlen(view_name) + 1, "%s", view_name);

    /* get cidrs  */
    json_key = json_object_get(json_data, "cidrs");
    if (!json_key || !json_is_string(json_key)) {
        log_msg(LOG_ERR, "view cidrs does not exist or is not string!");
        goto _parse_err;
    }
    view_name = json_string_value(json_key);
    snprintf(update->cidrs, strlen(view_name) + 1, "%s", view_name);
    return update;

_parse_err:
    free(update);
    return NULL;
}

static void *view_parse(enum view_action action, struct connection_info_struct *con_info, int *len_response) {
    char *post_ok, *parse_err;

    if (action == ACTION_ADD) {
        log_msg(LOG_INFO, "add data = %s\n", (char *)con_info->uploaddata);
    } else {
        log_msg(LOG_INFO, "del data = %s\n", (char *)con_info->uploaddata);
    }

    /* parse json object */
    json_error_t jerror;
    json_t *json_response = json_loads(con_info->uploaddata, 0, &jerror);
    if (!json_response) {
        log_msg(LOG_ERR, "load json string  failed: %s %s (line %d, col %d)\n",
                jerror.text, jerror.source, jerror.line, jerror.column);
        goto _parse_err;
    }
    if (!json_is_object(json_response)) {
        log_msg(LOG_ERR, "load json string failed: not an object!\n");
        goto _parse_err;
    }

    struct view_info_update *update = do_view_parse(action, json_response);
    if (update == NULL) {
        goto _parse_err;
    }
    send_view_msg_to_master(update);
    json_decref(json_response);

    post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return post_ok;

_parse_err:
    if (json_response) {
        json_decref(json_response);
    }
    parse_err = strdup("parse data err\n");
    *len_response = strlen(parse_err);
    return parse_err;
}

static void *view_parse_all(enum view_action action, struct connection_info_struct *con_info, int *len_response) {
    char *post_ok, *parse_err;

    if (action == ACTION_ADD) {
        log_msg(LOG_INFO, "add all data = %s\n", (char *)con_info->uploaddata);
    } else {
        log_msg(LOG_INFO, "del all data = %s\n", (char *)con_info->uploaddata);
    }

    json_error_t jerror;
    json_t *json_response = json_loads(con_info->uploaddata, 0, &jerror);
    if (!json_response) {
        log_msg(LOG_ERR, "load json string  failed: %s %s (line %d, col %d)\n",
                jerror.text, jerror.source, jerror.line, jerror.column);
        goto _parse_err;
    }
    if (!json_is_array(json_response)) {
        log_msg(LOG_ERR, "load json string failed: not an array!");
        goto _parse_err;
    }

    size_t domains_count = json_array_size(json_response);
    size_t i_num;
    for (i_num = 0; i_num < domains_count; i_num++) {
        int ret = 0;
        int retry_num = 5;
        struct view_info_update *update;

        json_t *array_elem = json_array_get(json_response, i_num);
        if (!json_is_object(array_elem)) {
            log_msg(LOG_ERR, "load json string failed: not an object!\n");
            json_decref(array_elem);
            goto _parse_err;
        }

_retry:
        update = do_view_parse(action, array_elem);
        if (update == NULL) {
            json_decref(array_elem);
            goto _parse_err;
        }

        ret = send_view_msg_to_master(update);
        if ((ret != 1) && (retry_num > 0)) {
            retry_num--;
            usleep(200000); //200ms
            goto _retry;
        }
        json_decref(array_elem);
    }
    json_decref(json_response);

    post_ok = strdup("OK\n");
    *len_response = strlen(post_ok);
    return post_ok;

_parse_err:
    if (json_response) {
        json_decref(json_response);
    }
    parse_err = strdup("parse data err\n");
    *len_response = strlen(parse_err);
    return parse_err;
}

void *view_post(struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response) {
    return view_parse(ACTION_ADD, con_info, len_response);
}

void *view_del(struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response) {
    return view_parse(ACTION_DEL, con_info, len_response);
}

void *views_post_all(struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response) {
    return view_parse_all(ACTION_ADD, con_info, len_response);
}

void *views_delete_all(struct connection_info_struct *con_info, __attribute__((unused))char *url, int *len_response) {
    return view_parse_all(ACTION_DEL, con_info, len_response);
}

static int do_view_msg_update(struct view_tree *tree, struct view_info_update *update) {
    return view_operate(tree, update->cidrs, update->view_name, update->action);
}

static void do_view_info_get(void *arg1, view_value_t *data) {
    json_t *array = (json_t *)arg1;
    json_t *value = json_pack("{s:s, s:s}", "viewName", data->view_name, "cidrs", data->cidrs);
    json_array_append_new(array, value);
}

void *view_get(__attribute__((unused)) struct connection_info_struct *con_info, char *url, int *len_response) {
    (void)url;
    log_msg(LOG_INFO, "view_get() in \n");
    char *outErr = NULL;

    json_t *array = json_array();

    if (!array) {
        log_msg(LOG_ERR, "unable to create array\n");
        outErr = strdup("unable to create array");
        goto err_out;
    }
    rte_rwlock_read_lock(&view_master_lock);
    view_tree_dump(view_master_tree->root, (void *)array, do_view_info_get);
    rte_rwlock_read_unlock(&view_master_lock);

    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    log_msg(LOG_INFO, "view_get() out \n");
    return (void *)str_ret;

err_out:
    *len_response = strlen(outErr);
    log_msg(LOG_INFO, "domain_get() err out \n");
    return (void *)outErr;
}

void view_query_slave_process(struct query *query, unsigned slave_lcore) {
    view_value_t *data = view_find(dpdk_dns[slave_lcore].db->viewtree, (uint8_t *)&query->sip, 32);
    if (data != VIEW_NO_NODE) {
        snprintf(query->view_name, MAX_VIEW_NAME_LEN, "%s", data->view_name);
    }
}

void view_query_master_process(struct query *query) {
    rte_rwlock_read_lock(&view_master_lock);
    view_value_t *data = view_find(view_master_tree, (uint8_t *)&query->sip, 32);
    if (data != VIEW_NO_NODE) {
        snprintf(query->view_name, MAX_VIEW_NAME_LEN, "%s", data->view_name);
    }
    rte_rwlock_read_unlock(&view_master_lock);
}

static int view_msg_slave_process(ctrl_msg *msg, unsigned slave_lcore) {
    int ret = do_view_msg_update(dpdk_dns[slave_lcore].db->viewtree, (struct view_info_update *)msg);
    free(msg);
    return ret;
}

static int view_msg_master_process(ctrl_msg *msg) {
    rte_rwlock_write_lock(&view_master_lock);
    int ret = do_view_msg_update(view_master_tree, (struct view_info_update *)msg);
    rte_rwlock_write_unlock(&view_master_lock);
    free(msg);
    return ret;
}

void view_master_init(void) {
    ctrl_msg_reg(CTRL_MSG_TYPE_UPDATE_VIEW, CTRL_MSG_FLAG_MASTER_SYNC_SLAVE, view_msg_master_process, view_msg_slave_process);

    rte_rwlock_init(&view_master_lock);
    view_master_tree = view_tree_create();
}
