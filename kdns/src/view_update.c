/*
 * view_update.c 
 */

#include <rte_ring.h>
#include <rte_rwlock.h>
#include <jansson.h>
#include "domain_store.h"
#include "view_update.h"
#include "kdns.h"
 
#define MSG_RING_SIZE  65536


extern struct kdns dpdk_dns[MAX_CORES];

static struct rte_ring *view_msg_ring[MAX_CORES];

static view_tree_t * view_tree_master = NULL;
static rte_rwlock_t view_lock_master;


static void send_view_msg_to_master(struct view_info_update *msg){ 
    
    unsigned cid_master = rte_get_master_lcore();
    
    assert(msg);
    int res = rte_ring_enqueue(view_msg_ring[cid_master],(void *) msg);

    if (unlikely(-EDQUOT == res)) {
        log_msg(LOG_ERR," msg_ring of master lcore %d quota exceeded\n", cid_master);
   } else if (unlikely(-ENOBUFS == res)) {
        log_msg(LOG_ERR," msg_ring of master lcore %d is full\n", cid_master);
        free(msg);
   } else if (res) {
        log_msg(LOG_ERR,"unkown error %d for rte_ring_enqueue master lcore %d\n", res,cid_master);
        free(msg);
   } 
   return ;
}


static void* view_parse(enum view_action   action,struct connection_info_struct *con_info , int * len_response)
{
    char * post_ok = strdup("OK\n");
    char * parseErr = NULL;
    
    if (action == ACTION_ADD){        
        log_msg(LOG_INFO,"add data = %s\n",(char *)con_info->uploaddata);
    }else{ 
        log_msg(LOG_INFO,"del data = %s\n",(char *)con_info->uploaddata);
    }
    *len_response = strlen(post_ok);

  
   struct view_info_update *update = calloc(1,sizeof(struct view_info_update));
   update->action = action;
    /* parse json object */
    json_error_t jerror;
    const char * view_name ;
    json_t *json_response = json_loads(con_info->uploaddata, 0, &jerror); 
    if (!json_response) {
        log_msg(LOG_ERR,"load json string  failed: %s %s (line %d, col %d)\n",
                jerror.text, jerror.source, jerror.line, jerror.column);
        goto parse_err;
    }
    if (!json_is_object(json_response)) {
        log_msg(LOG_ERR,"load json string failed: not an object!\n");
        json_decref(json_response);
        goto parse_err;
    }

    /* get view name  */
    json_t *json_key = json_object_get(json_response, "viewName");
    if (!json_key || !json_is_string(json_key))  {
        log_msg(LOG_ERR,"viewName does not exist or is not string!");
        json_decref(json_response);
        goto parse_err;
    }
    view_name = json_string_value(json_key);
    snprintf(update->view_name, strlen(view_name)+1, "%s", view_name);
    
    /* get cidrs  */
    json_key = json_object_get(json_response, "cidrs");
    if (!json_key || !json_is_string(json_key))  {
        log_msg(LOG_ERR,"view cidrs does not exist or is not string!");
        json_decref(json_response);
        goto parse_err;
    }
    view_name = json_string_value(json_key);
    snprintf(update->cidrs, strlen(view_name)+1, "%s", view_name);

    send_view_msg_to_master(update);
    
    json_decref(json_response);

    return post_ok;

 parse_err:   
   parseErr = strdup("parse data err\n");
    *len_response = strlen(parseErr);
    return (void* )parseErr;
}


static int do_view_msg_update(struct  view_tree *tree, struct view_info_update* update){
     if (update->action == ACTION_DEL){
         return view_delete(tree, update->cidrs);
     }else if (update->action == ACTION_ADD){
         return view_insert(tree, update->cidrs,update->view_name);   
     }
     return 0;
}


void* view_post(struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response){
    return view_parse(ACTION_ADD,con_info,len_response);
}


 void* view_del(struct connection_info_struct *con_info ,__attribute__((unused))char *url, int * len_response){   
    return view_parse(ACTION_DEL,con_info,len_response);
}

static void do_view_info_get(void * arg1,view_value_t * data){
     json_t * array  = (json_t *)arg1;
     json_t * value = json_pack("{s:s, s:s}", "viewName",data->view_name,"cidrs",data->cidrs );
     json_array_append_new(array, value);
    
}

void* view_get( __attribute__((unused)) struct connection_info_struct *con_info, char* url, int * len_response){

    log_msg(LOG_INFO,"view_get() in \n");
    char * outErr = NULL;

    json_t * array = json_array();

    if(!array){
        log_msg(LOG_ERR,"unable to create array\n");
        outErr = strdup("unable to create array");        
        goto err_out;
    }
    rte_rwlock_read_lock(&view_lock_master);
    view_tree_dump(view_tree_master->root, (void *) array, do_view_info_get);

    rte_rwlock_read_unlock(&view_lock_master);
    
    char *str_ret = json_dumps(array, JSON_COMPACT);
    json_decref(array);
    *len_response = strlen(str_ret);
    log_msg(LOG_INFO,"view_get() out \n");
    return (void* )str_ret;;

err_out:  
    *len_response = strlen(outErr);
     log_msg(LOG_INFO,"domain_get() err out \n");
    return (void* )outErr;

  
 
}

void view_msg_ring_create(void){

    char ring_name[64]={0};
    unsigned lcore_id = rte_lcore_id();
    // slave core
    if (dpdk_dns[lcore_id].db != NULL && (dpdk_dns[lcore_id].db->viewtree == NULL)) {
        dpdk_dns[lcore_id].db->viewtree = view_tree_create();
    }
    if (view_tree_master == NULL) {
        rte_rwlock_init(&view_lock_master); 
        view_tree_master = view_tree_create();
    }
    snprintf(ring_name, sizeof(ring_name), "view_ring_core%d", lcore_id);
    view_msg_ring[lcore_id] = rte_ring_create(ring_name, MSG_RING_SIZE,
            rte_socket_id(), 0);
    if (unlikely(NULL == view_msg_ring[lcore_id])) {
        log_msg(LOG_ERR, "Fail to create ring :%s  !\n",ring_name);
        exit(-1) ;
    }
}

static inline struct view_info_update * vmsg_copy(struct view_info_update *src){

    struct view_info_update * dst = calloc(1,sizeof(struct view_info_update )) ;
    assert(dst);
    dst->action = src->action;

    memcpy(dst->cidrs,src->cidrs,MAX_VIEW_NAME_LEN);
    memcpy(dst->view_name,src->view_name,MAX_VIEW_NAME_LEN);
    return dst;  
}


void view_msg_master_process(void){
    
    struct view_info_update *msg;   
    unsigned cid_master = rte_get_master_lcore();    
    
    unsigned idx =0;
    
    while (0 == rte_ring_dequeue(view_msg_ring[cid_master], (void **)&msg)) {
        
        //dispatch the msg
        for(idx =0; idx < MAX_CORES; idx ++){

            // skip the no bind core
            if ( view_msg_ring[idx] == NULL){
                continue;
            }
            // skip the no bind core

             if(idx == cid_master){
                struct view_info_update * new_msg = vmsg_copy(msg);
                rte_rwlock_write_lock(&view_lock_master);
                do_view_msg_update(view_tree_master,new_msg);
                rte_rwlock_write_unlock(&view_lock_master);
                free(new_msg);
                continue;
            }    
            struct view_info_update * new_msg = vmsg_copy(msg);
            int res = rte_ring_enqueue(view_msg_ring[idx], (void *)new_msg);

            if (unlikely(-EDQUOT == res)) {
                printf(" msg_ring of lcore %d quota exceeded\n", idx);
           } else if (unlikely(-ENOBUFS == res)) {
                log_msg(LOG_ERR," msg_ring of lcore %d is full\n", idx);
                free(new_msg);
           } else if (res) {
                log_msg(LOG_ERR,"unkown error %d for rte_ring_enqueue lcore %d\n", res,idx);
                free(new_msg);
           }
             
        }
        // tcp use view_tree_master    

    }   
}

void view_msg_slave_process(void){
    struct view_info_update *msg;   
    unsigned cid = rte_lcore_id();    
    while (0 == rte_ring_dequeue(view_msg_ring[cid], (void **)&msg)) {   
        do_view_msg_update(dpdk_dns[cid].db->viewtree,msg);
        free(msg); 
    }   
}



void view_query_tcp(struct  query *query_tcp){
    rte_rwlock_read_lock(&view_lock_master);
    view_value_t* data = view_find(view_tree_master, (uint8_t *)&query_tcp->sip,32);
        if (data != VIEW_NO_NODE){
           snprintf(query_tcp->view_name,MAX_VIEW_NAME_LEN,"%s",data->view_name);
   }
   rte_rwlock_read_unlock(&view_lock_master);          
}

