/*
 * tcp+process.c 
 */

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>

#include "netdev.h"
#include "util.h"
#include "dns-conf.h"
#include "kdns.h"
#include "forward.h"
#include "view_update.h"
#include "db_update.h"
#include "query.h"
#include "kdns-adap.h"



extern  struct dns_config *g_dns_cfg;
extern void domain_store_zones_check_create(struct kdns*  kdns, char *zones);

int tcp_domian_databd_update(struct domin_info_update* update);
static int dns_handle_tcp_remote(int respond_sock, char *snd_pkt, uint16_t old_id, int snd_len, char *domain);



char host_name[64]={0};

static struct	kdns kdns_tcp;
static struct  query *query_tcp = NULL;

int tcp_domian_databd_update(struct domin_info_update* update){
    
    return domaindata_update(kdns_tcp.db,update);
}


static int dns_do_remote_tcp_query(char *snd_buf, ssize_t snd_len, char *rvc_buf, ssize_t rcv_len, dns_addr_t *id_addr) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1){      
        log_msg(LOG_ERR,"dns_do_remote_tcp_query sock errno=%d, errinfo=%s\n", errno, strerror(errno));
        return -1;
    }
	
    struct timeval tv = {2, 0};
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {  
        log_msg(LOG_ERR,"dns_do_remote_tcp_query socket option SO_RCVTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;  
    } 
    if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {  
        log_msg(LOG_ERR,"dns_do_remote_tcp_query socket option SO_SNDTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;  
    } 

    int connResult = connect(sock_fd, (struct sockaddr *)id_addr->addr, id_addr->addrlen); 
    if (-1 == connResult) { 
        log_msg(LOG_ERR,"dns_do_remote_tcp_query connect errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(sock_fd);
        return -1;  
    } 

    int ret = send(sock_fd, snd_buf, snd_len, 0);
    if (ret <= 0){
        log_msg(LOG_ERR,"dns_do_remote_tcp_query send errno=%d, errinfo=%s\n",errno, strerror(errno));
        close(sock_fd);
        return -1;  
    }

    memset(rvc_buf, 0, rcv_len);
    ret = recv(sock_fd, rvc_buf, rcv_len - 1, 0);
    if (ret <=0){
        log_msg(LOG_ERR,"dns_do_remote_tcp_query recv errno=%d, errinfo=%s\n",errno, strerror(errno));
        close(sock_fd);
        return -1;  
    }
    close(sock_fd);
    return ret;
}


static int dns_handle_tcp_remote(int respond_sock, char *snd_pkt,uint16_t old_id,int snd_len,char *domain){
    int i = 0;
    int retfwd = 0;
    char recv_buf[16384] = {0};
    domain_fwd_addrs *fwd_addrs = find_zone_fwd_addrs(domain);
    for (;i < fwd_addrs->servers_len; i++){
		retfwd = dns_do_remote_tcp_query(snd_pkt, snd_len, recv_buf, 16384, &fwd_addrs->server_addrs[i]);
		if (retfwd > 0) {
			break;
		} else {
			log_msg(LOG_ERR, "Failed to requset %s form %s:%d, trycnt:%d\n", domain,
                    inet_ntoa(((struct sockaddr_in *)fwd_addrs->server_addrs[i].addr)->sin_addr),
                    ntohs(((struct sockaddr_in *)fwd_addrs->server_addrs[i].addr)->sin_port), i);
		}
    }
    if (retfwd > 0){
         uint16_t len = htons(retfwd);
         memcpy(recv_buf, &len, 2);
         if(send(respond_sock,recv_buf,retfwd +2,0) == -1){   
             log_msg(LOG_ERR,"last send error %s\n", domain);
             return -1;
         } 
    }  
    return 0;   
}


static void *dns_tcp_process(void *arg) {     
          
    struct sockaddr_in sin,pin;
    char *ip  = (char*)arg;
    int sock_descriptor,temp_sock_descriptor,address_size;  
    char buf[16384]; 

    query_tcp = query_create();
    
    sleep(30);

    sock_descriptor = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    bzero(&sin,sizeof(sin)); 
    sin.sin_family = AF_INET; 
    sin.sin_addr.s_addr = inet_addr(ip);;  
    sin.sin_port = htons(53);  
    if(bind(sock_descriptor,(struct sockaddr *)&sin,sizeof(sin)) == -1)
    {  
        log_msg(LOG_ERR,"call bind err \n");  
        exit(1);  
    }  
    if(listen(sock_descriptor,100) == -1)
    {  
        log_msg(LOG_ERR,"call listen err \n");  
        exit(1);  
    }  
    printf("Accpting connections...\n");  

    while(1)  
    {  
            address_size = sizeof(pin);  
            temp_sock_descriptor = accept(sock_descriptor,(struct sockaddr *)&pin,&address_size);
            if (temp_sock_descriptor == -1)
            {  
                log_msg(LOG_ERR,"call  accept error\n");  
                continue;  
            } 
            int recv_len = recv(temp_sock_descriptor,buf,16384,0);
            if(recv_len <= 0)
            {  
                 log_msg(LOG_ERR, "call  recv error, ret=%d, errno=%d, errinfo=%s\n", recv_len, errno, strerror(errno));
                 close(temp_sock_descriptor);
                 continue;  
            }  
            inet_ntop(AF_INET,&pin.sin_addr,host_name,sizeof(host_name));  
          //  printf("received from client(%s):%d\n",host_name,recv_len);  

            query_reset(query_tcp);
            query_tcp->maxMsgLen = TCP_MAX_MESSAGE_LEN;

            query_tcp->packet->data = (uint8_t *)(buf+2); // skip len

            uint16_t flags_old ;
            memcpy(&flags_old,query_tcp->packet->data +2 , 2);
            
            query_tcp->packet->position += recv_len;
            buffer_flip(query_tcp->packet);
            
            query_tcp->sip = *(uint32_t *)&pin.sin_addr;
            view_query_tcp(query_tcp);

            if(query_process(query_tcp, &kdns_tcp) != QUERY_FAIL) {
                buffer_flip(query_tcp->packet);
            }
            
            if(GET_RCODE(query_tcp->packet) == RCODE_REFUSE ) {
                   memcpy((buf+2) + 2, &flags_old, 2);  
                   dns_handle_tcp_remote(temp_sock_descriptor,buf,GET_ID(query_tcp->packet),recv_len,(char *)domain_name_to_string(query_tcp->qname, NULL));
                   close(temp_sock_descriptor); 
                  continue;
            }


             int retLen = buffer_remaining(query_tcp->packet);
             if (retLen > 0) {
                 uint16_t  len = htons(retLen);
                 memcpy(buf,&len,2);
                 if(send(temp_sock_descriptor,buf,retLen+2,0) == -1){   
                        log_msg(LOG_ERR," send error\n");
                 } 
                
             }
 
            close(temp_sock_descriptor);  
    }   
}  

int dns_tcp_process_init(char *ip){
    memset(&kdns_tcp,0,sizeof(kdns_tcp));
    if (dnsdata_prepare(&kdns_tcp) != 0) {
        log_msg(LOG_ERR,"server preparation failed,could not be started");
        return -1;
    }

    pthread_t *thread_cache_expired = (pthread_t *)  xalloc(sizeof(pthread_t));  
    pthread_create(thread_cache_expired, NULL, dns_tcp_process, (void*)ip);
    return 0;
}

