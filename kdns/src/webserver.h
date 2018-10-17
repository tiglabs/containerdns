#ifndef __WEBSERVER_H__
#define __WEBSERVER_H__

#include <microhttpd.h>

#define HTTP_NOT_FOUND 404

struct connection_info_struct
{
    struct MHD_PostProcessor *postprocessor;
    void *request_buffer;   // must be molloc(s)
    void *uploaddata;      // must be molloc(s)
};


typedef struct web_endpoint {
  char * method;
  char * url;
  struct web_endpoint *next;
  void* (* callback_function)(struct connection_info_struct *con_info , char* url, int * len_response);
}web_endpoint_st;

struct web_instance {
  struct MHD_Daemon           * mhd_daemon;
  unsigned int                  port;
  struct web_endpoint         * endpoint_list;
};

int web_endpoint_add(const char * method, const char * url, struct web_instance * ins, 
          void* (* callback_function)(struct connection_info_struct *con_info,char* url, int * len_response)) ;

struct web_instance * webserver_new(unsigned int port);
int webserver_run(struct web_instance * instance);
void webserver_stop(struct web_instance * instance);


#endif
