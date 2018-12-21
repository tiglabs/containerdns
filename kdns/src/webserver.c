#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <microhttpd.h>

#include "webserver.h"
#include "util.h"
#include "dns-conf.h"



#define POST_BUFFER_SIZE (32*1024)
#define REQUEST_BUFFER_SIZE (16*1024)

#define CONTENT_TYPE_JSON "Content-Type: application/json; charset=utf-8"



/**
 find the endpoint
*/
static struct web_endpoint * web_endpoint_match( const char * method, const char * url, struct web_instance * ins) {

    struct web_endpoint *ep = ins->endpoint_list;

    while(ep != NULL){
         if ((strcmp(ep->method, method) == 0) && (strcmp(ep->url, url) == 0)){
            break;
         }
         if ((strcmp("GET", method) == 0)&& (strcmp(ep->method, method) == 0) && (strncmp(ep->url, url,strlen(ep->url)) == 0)){
             break;
         }
         ep = ep->next;       
    }
    return ep;
}


/**
* Add a struct web_endpoint * to the specified web_instance with its values specified
not thread safe

*/
int web_endpoint_add(const char *  method, const char * url, struct web_instance * ins, 
          void* (* callback_function)(struct connection_info_struct *con_info, char *url,int * len_response)) {

    struct web_endpoint *ep = web_endpoint_match((const char *)method,(const char *)url, ins);
    if (ep != NULL){
        log_msg(LOG_ERR,"the ep existed --->  method:%s url:%s\n",method,url);
        return -1;
    }
    log_msg(LOG_INFO,"web_endpoint_add method:%s url:%s\n",method,url);
    ep = xalloc_zero(sizeof(struct web_endpoint));
    ep->method = strdup(method);
    ep->url    = strdup(url);
    ep->callback_function = callback_function;
    ep->next = ins->endpoint_list;
    ins->endpoint_list = ep;
    return 0;  
}


/*
 * Called after a connection , to clean up connection info.
 */
static void request_completed (void *cls, struct MHD_Connection *connection,
        void **con_cls, enum MHD_RequestTerminationCode toe)
{
    if (*con_cls == NULL) return;
    cls = cls;
    connection = connection;
    toe = toe;

    struct connection_info_struct *con_info = *con_cls;
    if (con_info->postprocessor != NULL) {
        MHD_destroy_post_processor(con_info->postprocessor);
    }
    if (con_info->request_buffer != NULL){
        free(con_info->request_buffer);     
    }
    if (con_info->uploaddata != NULL){
        free(con_info->uploaddata);     
    }
    free(con_info);
    *con_cls = NULL;
}


#define HTTP_NOT_FOUND_BODY "Resource not found"


static int send_bad_response( struct MHD_Connection *connection)  
{    

    int ret;                                                      
    struct MHD_Response *response; 
    void * response_buffer =  (void*) strdup(HTTP_NOT_FOUND_BODY);

    int response_buffer_len = strlen(HTTP_NOT_FOUND_BODY);
    response = MHD_create_response_from_buffer (response_buffer_len, response_buffer, MHD_RESPMEM_MUST_FREE );
    ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response (response);                              
    return ret;                                                     
}  

static int
send_page (struct MHD_Connection *connection,  void *data, int len)
{
	int ret;
	struct MHD_Response *response;
    if (data != NULL){
        response = MHD_create_response_from_data(len,(void*) data,	MHD_NO, MHD_YES);
		free(data);
        if (!response)
		    return MHD_NO;
        MHD_add_response_header(response, "Content-Type", CONTENT_TYPE_JSON);
		ret = MHD_queue_response(connection,MHD_HTTP_OK,response);
		MHD_destroy_response(response);
        return ret;
    }
    
    return send_bad_response(connection);
}

static int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
        const char *filename, const char *content_type, const char *transfer_encoding,
        const char *data, uint64_t off, size_t size)
{
    printf("post data: %p %d %s=%s %ld %s %s %s\n",coninfo_cls, kind,key, data, off,filename,content_type,transfer_encoding); 
    //Todo
    return MHD_YES;
}



/*
 * Callback to handle a new connection.
 */
static int webservice_dispatcher(void *cls, struct MHD_Connection *connection,
        const char *url, const char *method, __attribute__((unused)) const char *version,
        const char *uploaddata, size_t *uploaddata_size, void **con_cls)
{
      
    if (*con_cls == NULL) {
        struct connection_info_struct *con_info;
        con_info = xalloc_zero(sizeof(struct connection_info_struct));

        if (strcmp(method, "POST") == 0 || strcmp(method, "DELETE") == 0){
            con_info->request_buffer = xalloc_zero(REQUEST_BUFFER_SIZE);
            //con_info->uploaddata = xalloc_zero(*uploaddata_size + connection->remaining_upload_size);
            con_info->postprocessor = MHD_create_post_processor(connection,
                    POST_BUFFER_SIZE, iterate_post, con_info->request_buffer);
        }
        *con_cls = con_info;
        return MHD_YES;
    }
   

    struct connection_info_struct *con_info = *con_cls;

    /* get request data */
    if (strcmp(method, "POST") == 0 || strcmp(method, "DELETE") == 0){
        
        if (*uploaddata_size != 0) { /* continue to process the post data */
            if (con_info->uploaddata == NULL){
                con_info->uploaddata = xalloc_zero(POST_BUFFER_SIZE);
                con_info->data_block_idx = 1;
            }
            if (con_info->data_buffer_offset + *uploaddata_size > con_info->data_block_idx * POST_BUFFER_SIZE ){
                con_info->data_block_idx++;
                con_info->uploaddata = xrealloc(con_info->uploaddata , con_info->data_block_idx * POST_BUFFER_SIZE);  
                memset(con_info->uploaddata + con_info->data_buffer_offset ,0,
                    con_info->data_block_idx * POST_BUFFER_SIZE - con_info->data_buffer_offset);
            }
            
            memcpy(con_info->uploaddata + con_info->data_buffer_offset ,uploaddata,*uploaddata_size);
            con_info->data_buffer_offset += *uploaddata_size;
            MHD_post_process(con_info->postprocessor, uploaddata, *uploaddata_size);
           // con_info->uploaddata = strdup(uploaddata);
            *uploaddata_size = 0;
            return MHD_YES;
        }
    }

    int response_len =0 ;
   // int status =0;
    void *response_buf = NULL;
    struct web_instance * wen_ins = (struct web_instance *)cls;

    struct web_endpoint *ep =  web_endpoint_match(method,url,wen_ins);
    if (ep != NULL){
        response_buf = ep->callback_function(con_info, url,&response_len);      
    }
    return send_page(connection,response_buf,response_len);
}


struct web_instance * webserver_new(unsigned int port)
{
    struct web_instance * instance = (struct web_instance *)xalloc(sizeof(struct web_instance));
    instance->mhd_daemon = NULL;
    instance->port = port;
    instance->endpoint_list = NULL;
    return instance;
}


static char *get_ca_file(char *fname)  
{  
    FILE *fp;  
    char *buffer;  
    int filesize;  
    if ((fp=fopen(fname,"rb"))== NULL){  
       log_msg(LOG_ERR,"open file err:%s\n",fname);  
       exit(-1);  
    }  
  
    fseek(fp,0,SEEK_END);   
    filesize = ftell(fp);  
    rewind(fp);
    buffer =(char *)xalloc(filesize);  
    if (buffer == NULL)  
    {  
        log_msg(LOG_ERR, "no mem\n");   
        exit(-1);  
    }  
 
    /* ���ļ�������buffer�� */  
   int result = fread (buffer,1,filesize,fp);  
    if (result != filesize)  
    {  
        log_msg(LOG_ERR,"read file err:%s\n",fname);  
        exit(-1);  
    } 
    fclose(fp);  
    return buffer;  
} 


int webserver_run(struct web_instance * instance)
{
  //  int flags = MHD_USE_SELECT_INTERNALLY | MHD_USE_POLL | MHD_USE_DEBUG | MHD_USE_SSL ;
  int flags = MHD_USE_THREAD_PER_CONNECTION | MHD_USE_POLL | MHD_USE_DEBUG |MHD_USE_INTERNAL_POLLING_THREAD;
  if (g_dns_cfg->comm.ssl_enable == 1){
      flags |= MHD_USE_SSL ;

      char *key_pem =  get_ca_file(g_dns_cfg->comm.key_pem_file);
      char *cert_pem =  get_ca_file(g_dns_cfg->comm.cert_pem_file);
    

      instance->mhd_daemon = MHD_start_daemon(flags, instance->port,
            NULL, NULL, &webservice_dispatcher, (void *)instance,
            MHD_OPTION_NOTIFY_COMPLETED, request_completed,NULL, 
             MHD_OPTION_HTTPS_MEM_KEY, key_pem,
             MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
             MHD_OPTION_CONNECTION_MEMORY_LIMIT,REQUEST_BUFFER_SIZE,
            MHD_OPTION_END);
  }else{
        instance->mhd_daemon = MHD_start_daemon(flags, instance->port,
            NULL, NULL, &webservice_dispatcher, (void *)instance,
            MHD_OPTION_NOTIFY_COMPLETED, request_completed,NULL, 
            MHD_OPTION_END);

  }
    
    if (instance->mhd_daemon == NULL) {
        log_msg(LOG_ERR,"web server run faile\n");
        return -1;
    }
    
    log_msg(LOG_INFO,"web server running on port =%d\n",instance->port);
    return 0;
}


void webserver_stop(struct web_instance * instance)
{
    MHD_stop_daemon(instance->mhd_daemon);
}

//#define ENABLE_WEB_TEST 

#ifdef ENABLE_WEB_TEST


void* sample_post(struct connection_info_struct *con_info ,char *url, int * len_response)
{
    char * post_ok = strdup("POST OK\n");
    printf("data = %s\n",con_info->upload_data);
    *len_response = strlen(post_ok);
    return (void* )post_ok;
}

void* sample_get(struct connection_info_struct *con_info ,char *url, int * len_response)
{
    char * get_ok = strdup("GET OK\n");
//    printf("data = %s\n",con_info->uploaddata);
    *len_response = strlen(get_ok);
    return (void* )get_ok;
}


int main(){

  struct web_instance * ins =  webserver_new(5500);

  web_endpoint_add("POST","/webtest",ins,&sample_post);
  web_endpoint_add("GET","/webtest",ins,&sample_get);
  
  webserver_run(ins);

  while(1){
    sleep(3);
    printf(". ");
    
  }
    
}

#endif
