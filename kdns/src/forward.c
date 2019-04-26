/*
 * forward.c 
 */

#define _GNU_SOURCE
#include <pthread.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>

#include <rte_mbuf.h>
#include <rte_ether.h> 
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_rwlock.h>
#include <rte_udp.h>
#include <arpa/inet.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include "netdev.h"
#include "util.h"
#include "forward.h"
#include "dns-conf.h"
#include "hashMap.h"
#include "metrics.h"

struct fwd_pkt_input {
    struct rte_mbuf *pkt;
    uint16_t old_id;
    uint16_t qtype;
    uint32_t src_addr;
    char  domain_name[FWD_MAX_DOMAIN_NAME_LEN];
};


typedef struct {
   char *zone_name;
   char *fwd_addrs;
 } zone_fwd_input_tmp;


typedef struct domin_fwd_cache{
    char  domain_name[FWD_MAX_DOMAIN_NAME_LEN];
    char  data[EDNS_MAX_MESSAGE_LEN];
    int   data_len;
    uint16_t         qtype;
    time_t time_expired;
}domin_fwd_cache_st;


typedef struct domin_fwd_query_{
    char  *data;
    int   *data_len;
    int    status;
}domin_fwd_query;


#define FORWARD_HASH_SIZE                0x3FFFF
#define FORWARD_LOCK_SIZE                0xF

// 
#define FORWARD_CACHE_TIME_OUT_SCAN_NUM  0xFFFF

#define FORWARD_CACHE_NEED_DETECT   1
#define FORWARD_CACHE_FIND          0
#define FORWARD_CACHE_NOT_FIND      -1
#define FORWARD_CACHE_DATA_EXPIRED  -2

#define FWD_RING_SIZE   65536

static domain_fwd_addrs *default_fwd_addrs = NULL ;
static domain_fwd_addrs **zones_fwd_addrs = NULL ;
static int g_fwd_zone_num = 0;
pthread_rwlock_t __fwd_lock;

extern struct rte_mempool *pkt_mbuf_pool;
struct rte_ring *master_fwd_pkt_ex_ring;
struct rte_ring *fwd_pkt_to_process_ring;



static domain_fwd_addrs * resolve_dns_servers(const char * domain_suffix,char * dns_addrs);
static void *thread_fwd_pkt_process(void *arg);
static void *thread_fwd_cache_expired_cleanup(void *arg);


//static struct domin_fwd_cache *g_fwd_cache_hash_list[FORWARD_HASH_SIZE + 1 ] ;
//static rte_rwlock_t fwd_cache_list_lock;

static hashMap *g_fwd_cache_hash = NULL;

static rte_atomic64_t dns_fwd_rcv;	/* Total number of receive forward packets */
static rte_atomic64_t dns_fwd_snd;	/* Total number of send to client forward packets */

void fwd_statsdata_get(struct netif_queue_stats *sta)
{
	sta->dns_fwd_rcv_udp = rte_atomic64_read(&dns_fwd_rcv);
	sta->dns_fwd_snd_udp = rte_atomic64_read(&dns_fwd_snd);
    return;
}

void fwd_statsdata_reset(void)
{
	rte_atomic64_clear(&dns_fwd_rcv);
	rte_atomic64_clear(&dns_fwd_snd);
	return;
}

static domain_fwd_addrs** parse_dns_fwd_zones(char *addrs, int *fwd_zone_num) {
    int zone_idx = 1;
    char *zone_info = NULL;
    char buf[512];
    char zone_name[FWD_MAX_DOMAIN_NAME_LEN];
    char zone_addr[512];
    char fwd_addrs[512] = {0};
    zone_fwd_input_tmp * fwd_input_tmp = NULL;

    if (!addrs || strlen(addrs) == 0) {
        return NULL;
    }
    strncpy(fwd_addrs, addrs, MIN(sizeof(fwd_addrs), strlen(addrs)));

    log_msg(LOG_INFO, "parse_dns_fwd_zones fwd_addrs %s\n", fwd_addrs);
    char *pch = strchr(fwd_addrs, '%');
    while (pch != NULL) {
        zone_idx++;
        pch = strchr(pch + 1, '%');
    }

    domain_fwd_addrs** tmp_fwd_addrs = calloc(zone_idx, sizeof(domain_fwd_addrs*));
    // in order to use resolve_dns_servers(),use fwd_input_tmp instead of strtok_r
    fwd_input_tmp = calloc(zone_idx, sizeof(zone_fwd_input_tmp));
    *fwd_zone_num = zone_idx;
    zone_idx = 0;
    zone_info = strtok(fwd_addrs, "%");
    while (zone_info) {
        char *pos;
        memset(buf, 0, sizeof(buf));
        memset(zone_name, 0, FWD_MAX_DOMAIN_NAME_LEN);
        memset(zone_addr, 0, sizeof(zone_addr));
        strncpy(buf, zone_info, sizeof(buf) - 1);
        pos = (strrchr(buf, '@'));
        if (pos) {
            if (pos - buf >= FWD_MAX_DOMAIN_NAME_LEN) {
                log_msg(LOG_ERR, "domain name legth greater than %d\n", FWD_MAX_DOMAIN_NAME_LEN);
                exit(-1);
            }

            memcpy(zone_name, buf, pos - buf);
            memcpy(zone_addr, pos+1, strlen(buf)+ buf - pos -1 );
            fwd_input_tmp[zone_idx].zone_name = strdup(zone_name);
            fwd_input_tmp[zone_idx].fwd_addrs = strdup(zone_addr);
        }else{
            log_msg(LOG_ERR, "wrong fmt %s\n", zone_info);
            exit(-1);
        } 
        zone_idx++;
        zone_info = strtok(NULL, "%");    
    }
    for (zone_idx =0; zone_idx < *fwd_zone_num; zone_idx++ ){
        tmp_fwd_addrs[zone_idx] = resolve_dns_servers(fwd_input_tmp[zone_idx].zone_name,fwd_input_tmp[zone_idx].fwd_addrs);
        free(fwd_input_tmp[zone_idx].zone_name);
        free(fwd_input_tmp[zone_idx].fwd_addrs);
    }

    free(fwd_input_tmp);
    return tmp_fwd_addrs;
}

static int fwd_check_equal(char *key,void *data, hashNode *node){
    
    key = key;
    domin_fwd_cache_st *fwdNode = (domin_fwd_cache_st*) data;
    domin_fwd_cache_st *fwdNodeChk = (domin_fwd_cache_st*) node->data;

    if (fwdNode->qtype == fwdNodeChk->qtype &&
            strcmp(fwdNode->domain_name,fwdNodeChk->domain_name)==0){
            return 1;
    }
    return 0;
}

static int fwd_node_query(hashNode *node, void* output){

     domin_fwd_cache_st *fwdNode = (domin_fwd_cache_st*) node->data;

     domin_fwd_query *out = (domin_fwd_query*) output;

        memcpy(out->data, fwdNode->data, fwdNode->data_len);
        *out->data_len = fwdNode->data_len;
        if (fwdNode->time_expired > time(NULL)) {
            if (fwdNode->time_expired < time(NULL) + 10) {
                out->status = FORWARD_CACHE_NEED_DETECT;
            } else {
                 out->status = FORWARD_CACHE_FIND;
      }  
        } else {
            fwdNode->time_expired = time(NULL)+ 60;    //will be del or used next 60 second
   }  
        return 1;
}  

static int do_fwd_cache_expired_check(hashNode *node, void* arg){

    time_t *time_now = (time_t *)arg; 
    domin_fwd_cache_st *fwdNode = (domin_fwd_cache_st*) node->data;
    // 60S time_expired,we del it 600s later
    if (fwdNode->time_expired + 600 < *time_now){
        printf(" %s time_expired\n",fwdNode->domain_name);
        return 1;   
    }   
    return 0; 
}
 
    


static void fwd_cache_init(void){
    g_fwd_cache_hash = hashMap_create(FORWARD_HASH_SIZE, FORWARD_LOCK_SIZE, elfHashDomain, 
        fwd_check_equal, fwd_node_query, do_fwd_cache_expired_check, NULL); 
    }


static void fwd_cache_update(char *domain, uint16_t qtype, char *data, int data_len)
{
        domin_fwd_cache_st * newNode = xalloc_zero(sizeof(domin_fwd_cache_st));
        memcpy(newNode->domain_name,domain,strlen(domain));
        newNode->data_len = data_len;
        newNode->qtype = qtype;
        memcpy(newNode->data,data,data_len);
        newNode->time_expired = time(NULL)+ 60; //second
    hmap_update(g_fwd_cache_hash, domain, (void*)newNode);
}


static void fwd_cache_del(char *domain,uint16_t qtype){
    domin_fwd_cache_st  delNode;
    memset((void *)&delNode, 0, sizeof(domin_fwd_cache_st));
    memcpy(delNode.domain_name,domain,strlen(domain));
    delNode.qtype = qtype;       
    hmap_del(g_fwd_cache_hash, domain, (void*)&delNode);
}

static int fwd_cache_lookup(char *domain, uint16_t qtype, char *cache_data, int *cache_data_len)
{
    domin_fwd_cache_st  queNode ;
    memset((void *)&queNode, 0, sizeof(domin_fwd_cache_st));
    memcpy(queNode.domain_name,domain,strlen(domain));
    queNode.qtype = qtype;   

    domin_fwd_query out ;
    out.data = cache_data;
    out.data_len =  cache_data_len;
    out.status   =  FORWARD_CACHE_NOT_FIND;
    hmap_lookup(g_fwd_cache_hash, domain, (void*)&queNode, &out);    
    return out.status;
}

int remote_sock_init(char * fwd_addrs, char * fwd_def_addr,int fwd_threads){
    pthread_rwlockattr_t attr;
    (void)pthread_rwlockattr_init(&attr);
    (void)pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    (void)pthread_rwlock_init(&__fwd_lock, &attr);

    fwd_cache_init();

    default_fwd_addrs = resolve_dns_servers("defulat.zone",fwd_def_addr);
    zones_fwd_addrs = parse_dns_fwd_zones(fwd_addrs, &g_fwd_zone_num);
    
    master_fwd_pkt_ex_ring = rte_ring_create("master_fwd_pkt_ex_ring", FWD_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
    if (!master_fwd_pkt_ex_ring) {
        log_msg(LOG_ERR, "Cannot create ring master_fwd_pkt_ex_ring  %s\n", rte_strerror(rte_errno));
        exit(-1);
    }

    fwd_pkt_to_process_ring = rte_ring_create("fwd_pkt_to_process_ring", FWD_RING_SIZE, rte_socket_id(), 0); 
    if (!fwd_pkt_to_process_ring) {
        log_msg(LOG_ERR, "Cannot create ring fwd_pkt_to_process_ring  %s\n", rte_strerror(rte_errno));
        exit(-1);
    }

   #ifdef ENABLE_KDNS_FWD_METRICS
        fwd_metrics_init();
   #endif

    /* create a separate thread to send task status as quick as possible */
	rte_atomic64_init(&dns_fwd_rcv);
	rte_atomic64_init(&dns_fwd_snd);
    int i = 0;
    for( ;i< fwd_threads;i++){
        pthread_t *thread_id = (pthread_t *)xalloc(sizeof(pthread_t));
        pthread_create(thread_id, NULL, thread_fwd_pkt_process, NULL);

        char tname[16];
        snprintf(tname, sizeof(tname), "kdns_udp_fwd_%d", i);
        pthread_setname_np(*thread_id, tname);
    }

    // cache date expired clean up thread
    pthread_t *thread_cache_expired = (pthread_t *)  xalloc(sizeof(pthread_t));  
    pthread_create(thread_cache_expired, NULL, thread_fwd_cache_expired_cleanup, (void*)NULL);
    pthread_setname_np(*thread_cache_expired, "kdns_fcache_clr");
 
    return 0;
}

static domain_fwd_addrs * resolve_dns_servers(const char *domain_suffix, char *addrs) {
    
    char buf[512];
    struct addrinfo *addr_ip;
    struct addrinfo hints;
    char* token;
    char dns_addrs[512] = {0};

    int i=0,r = 0;

    strncpy(dns_addrs, addrs, MIN(sizeof(dns_addrs), strlen(addrs)));
    domain_fwd_addrs *fwd_addrs = calloc(1, sizeof(domain_fwd_addrs));
    fwd_addrs->servers_len =1;
    memcpy(fwd_addrs->domain_name,domain_suffix,strlen(domain_suffix));

    char *pch = strchr(dns_addrs, ',');
    while (pch != NULL) {
        fwd_addrs->servers_len++;
        pch = strchr(pch + 1, ',');
    }

    log_msg(LOG_INFO,"domain_suffix :%s remote addr :%s\n",domain_suffix,dns_addrs);
    fwd_addrs->server_addrs = calloc(fwd_addrs->servers_len, sizeof(dns_addr_t));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    token = strtok(dns_addrs, ",");
    while (token) {
        char *port;
        memset(buf, 0, sizeof(buf));
        strncpy(buf, token, sizeof(buf) - 1);
        port = (strrchr(buf, ':'));
        if (port) {
        *port = '\0';
        port++;
        } else {
            port = strdup("53");
        }
        if (0 != (r = getaddrinfo(buf, port, &hints, &addr_ip))) {
            log_msg(LOG_ERR,"err  getaddrinfo \n");
            exit(-1);
        }
        fwd_addrs->server_addrs[i].addr = addr_ip->ai_addr;
        fwd_addrs->server_addrs[i].addrlen = addr_ip->ai_addrlen;
        i++;
        token = strtok(0, ",");    
    }
    return fwd_addrs;
}

static int dns_do_remote_query(char *snd_buf, ssize_t snd_len, char *recv_buf, ssize_t recv_buf_len, dns_addr_t *id_addr) {
    int remote_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (remote_sock == -1) {
        log_msg(LOG_ERR,"dns_do_remote_query socket errno=%d, errinfo=%s\n", errno, strerror(errno));
        return -1;
    }

    struct timeval tv = {2, 0};
    if (setsockopt(remote_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        log_msg(LOG_ERR,"dns_do_remote_query setsockopt SO_RCVTIMEO errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(remote_sock);
        return -1;
    }

    if (-1 == sendto(remote_sock, snd_buf, snd_len, 0, id_addr->addr, id_addr->addrlen)) {
        log_msg(LOG_ERR,"dns_do_remote_query sendto errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(remote_sock);
        return -1;
    }

    struct sockaddr src_addr;
    socklen_t src_len = sizeof(struct sockaddr);
    int recv_len = recvfrom(remote_sock, recv_buf, recv_buf_len, 0, &src_addr, &src_len);
    if (recv_len < 0) {
        log_msg(LOG_ERR,"dns_do_remote_query recvfrom errno=%d, errinfo=%s\n", errno, strerror(errno));
        close(remote_sock);
        return -1;
    }
    
    close(remote_sock);
    return recv_len;
}

domain_fwd_addrs * find_zone_fwd_addrs(char * domain_name){
    int i =0;
    for(;i< g_fwd_zone_num; i++){
        int zone_len = strlen(zones_fwd_addrs[i]->domain_name);
        int domain_len = strlen(domain_name);
        if ((domain_len >= zone_len) && strncmp (domain_name + domain_len - zone_len ,zones_fwd_addrs[i]->domain_name,strlen(zones_fwd_addrs[i]->domain_name)) == 0 ){
            return zones_fwd_addrs[i];
        }
    }
    return default_fwd_addrs;  
}

static int dns_query_remote(char *domain, uint16_t qtype, char *query_data, ssize_t query_len,
                                char *recv_buf, ssize_t recv_buf_len, uint32_t src_addr)
{
    int i = 0;

    pthread_rwlock_rdlock(&__fwd_lock);
    domain_fwd_addrs *fwd_addrs = find_zone_fwd_addrs(domain);
    for (; i < fwd_addrs->servers_len; ++i) {
        dns_addr_t *server_addrs = &fwd_addrs->server_addrs[i];
        int recv_len = dns_do_remote_query(query_data, query_len, recv_buf, recv_buf_len, server_addrs);
        if (recv_len > 0) {
            fwd_cache_update(domain, qtype, recv_buf, recv_len);
            pthread_rwlock_unlock(&__fwd_lock);
            return recv_len;
        } else {
            char ip_src_str[INET_ADDRSTRLEN] = {0};
            char ip_dst_str[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, (struct in_addr *)&src_addr, ip_src_str, sizeof(ip_src_str));
            inet_ntop(AF_INET, &((struct sockaddr_in *)server_addrs->addr)->sin_addr, ip_dst_str, sizeof(ip_dst_str));
            log_msg(LOG_ERR, "Failed to requset %s, type %d, to %s:%d, from: %s, trycnt:%d\n", domain, qtype,
                ip_dst_str, ntohs(((struct sockaddr_in *)server_addrs->addr)->sin_port), ip_src_str, i);
        }
    }
    pthread_rwlock_unlock(&__fwd_lock);
    return -1;
}

static int do_dns_handle_remote_response(struct rte_mbuf *pkt, uint16_t old_id, uint16_t qtype, char *domain, char *response_data, int response_len)
{
    struct ether_hdr *eth_hdr = NULL;
    struct ipv4_hdr  *ip4_hdr = NULL;
    struct udp_hdr   *udp_hdr = NULL;
    char *query_data = NULL;
    struct ether_addr *src_mac, *dst_mac;
    uint32_t src_addr, dst_addr;
    uint16_t src_port, dst_port;
    struct ether_hdr pkt_eth_hdr;
    struct ipv4_hdr pkt_ipv4_hdr;
    struct udp_hdr pkt_udp_hdr;

    eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr*); 
    ip4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, sizeof(struct ether_hdr));
    udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    query_data = rte_pktmbuf_mtod_offset(pkt, char*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)+ sizeof(struct udp_hdr));

    src_mac = &(eth_hdr->d_addr);
    dst_mac = &(eth_hdr->s_addr);
    src_addr = ip4_hdr->dst_addr;
    dst_addr = ip4_hdr->src_addr;
    src_port = udp_hdr->dst_port;
    dst_port = udp_hdr->src_port;

    init_eth_header(&pkt_eth_hdr, src_mac, dst_mac, ETHER_TYPE_IPv4);
    init_ipv4_header(&pkt_ipv4_hdr, src_addr, dst_addr, sizeof(struct udp_hdr) + response_len);
    init_udp_header(&pkt_udp_hdr, src_port, dst_port, response_len);

    memcpy(eth_hdr,&pkt_eth_hdr, sizeof(struct ether_hdr));
    memcpy(ip4_hdr,&pkt_ipv4_hdr, sizeof(struct ipv4_hdr));
    memcpy(udp_hdr,&pkt_udp_hdr, sizeof(struct udp_hdr));
    pkt->pkt_len = response_len + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);
    pkt->data_len = pkt->pkt_len;
    pkt->l2_len = sizeof(struct ether_hdr);
    pkt->vlan_tci  = ETHER_TYPE_IPv4;
    pkt->l3_len = sizeof(struct ipv4_hdr);
    memcpy(query_data, response_data, response_len);

    // change the fag and queryId
    uint16_t ns_old_id = htons(old_id);
    memcpy(query_data, &ns_old_id, 2);

    int ret = rte_ring_mp_enqueue(master_fwd_pkt_ex_ring, (void*)pkt);
    if (ret != 0) {
        char ip_src_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &dst_addr, ip_src_str, sizeof(ip_src_str));
        log_msg(LOG_ERR, "Failed to response query: %s, type: %d, from: %s\n", domain, qtype, ip_src_str);
        rte_pktmbuf_free(pkt);
    }
    return ret;
}

static void do_dns_handle_remote(struct rte_mbuf *pkt, uint16_t old_id, uint16_t qtype, char *domain) {
    char recv_data[EDNS_MAX_MESSAGE_LEN] = {0};
    char detect_data[EDNS_MAX_MESSAGE_LEN] = {0};
    char cache_data[EDNS_MAX_MESSAGE_LEN] = {0};
    int cache_data_len = 0;

    struct ipv4_hdr *ip4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, sizeof(struct ether_hdr));
    struct udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
    char *query_data = rte_pktmbuf_mtod_offset(pkt, char*, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)+ sizeof(struct udp_hdr));
    int query_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct udp_hdr);
    uint32_t src_addr = ip4_hdr->src_addr;

    int status = fwd_cache_lookup(domain, qtype, cache_data, &cache_data_len);
    if (status == FORWARD_CACHE_FIND) {
        do_dns_handle_remote_response(pkt, old_id, qtype, domain, cache_data, cache_data_len);
    } else if (status == FORWARD_CACHE_NEED_DETECT) {
        memcpy(detect_data, query_data, query_len);
        do_dns_handle_remote_response(pkt, old_id, qtype, domain, cache_data, cache_data_len);
        dns_query_remote(domain, qtype, detect_data, query_len, recv_data, EDNS_MAX_MESSAGE_LEN, src_addr);
    } else {
        int recv_len = dns_query_remote(domain, qtype, query_data, query_len, recv_data, EDNS_MAX_MESSAGE_LEN, src_addr);
        if (recv_len > 0) {
            do_dns_handle_remote_response(pkt, old_id, qtype, domain, recv_data, recv_len);
        } else {
            if (status == FORWARD_CACHE_DATA_EXPIRED) {
                do_dns_handle_remote_response(pkt, old_id, qtype, domain, cache_data, cache_data_len);
            } else {
                char ip_src_str[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &src_addr, ip_src_str, sizeof(ip_src_str));
                log_msg(LOG_ERR, "Query failed and no cache, failed to response query: %s, type: %d, from: %s\n", domain, qtype, ip_src_str);
                rte_pktmbuf_free(pkt);
            }
        }
    }
}

int dns_handle_remote(struct rte_mbuf *pkt,uint16_t old_id,uint16_t qtype,uint32_t src_addr, char *domain){

    struct fwd_pkt_input *etm = calloc(sizeof(struct fwd_pkt_input),1);
    if (!etm){
        rte_pktmbuf_free(pkt);
        return -1;   
    }
    etm->pkt = pkt;
    etm->old_id = old_id;
    etm->qtype = qtype;
    etm->src_addr =  src_addr;
    memcpy(etm->domain_name,domain,strlen(domain));
    int ret = rte_ring_mp_enqueue(fwd_pkt_to_process_ring, (void*)etm);
    if (ret != 0) {
        rte_pktmbuf_free(pkt);
        free(etm);
        return -2;       
    }
    return 0;   
}

uint16_t fwd_pkts_dequeue(struct rte_mbuf **mbufs,uint16_t pkts_cnt)
{

    while (pkts_cnt > 0 && unlikely(rte_ring_dequeue_bulk(master_fwd_pkt_ex_ring, (void ** )mbufs, pkts_cnt) != 0)) {
        pkts_cnt = (uint16_t)RTE_MIN(rte_ring_count(master_fwd_pkt_ex_ring),pkts_cnt);
    }

	rte_atomic64_add(&dns_fwd_snd, pkts_cnt);
    return pkts_cnt;
}

static void *thread_fwd_pkt_process(void *arg){
	(void)arg;
    struct fwd_pkt_input *etm;
    
    log_msg(LOG_INFO,"Starting thread_fwd_pkt_process \n");
    while (1) {
        if (rte_ring_mc_dequeue(fwd_pkt_to_process_ring, (void **)&etm) != 0){
            usleep(10);
            continue;
        }
		rte_atomic64_inc(&dns_fwd_rcv);

        #ifdef ENABLE_KDNS_FWD_METRICS
        uint64_t  start_time = time_now_usec();
        #endif

        do_dns_handle_remote(etm->pkt, etm->old_id, etm->qtype, etm->domain_name);
        #ifdef ENABLE_KDNS_FWD_METRICS
        metrics_domain_update(etm->domain_name, start_time);
        metrics_domain_clientIp_update(etm->domain_name, start_time, etm->src_addr);
        #endif
        free(etm);
    }
    return NULL;
}

static void *thread_fwd_cache_expired_cleanup(void *arg){
	 (void)arg;
     while (1){
        sleep(600);
        time_t time_now = time(NULL);
        hmap_check_expired(g_fwd_cache_hash, (void*)&time_now);     
    }
     return NULL;

}

int fwd_def_addrs_reload(char *addrs)
{
    domain_fwd_addrs *new_def_fwd_addrs = NULL;
    domain_fwd_addrs *old_def_fwd_addrs = NULL;
    if (!addrs)
        return -1;

    new_def_fwd_addrs = resolve_dns_servers("defulat.zone", addrs);
    if (new_def_fwd_addrs) {
        pthread_rwlock_wrlock(&__fwd_lock);
        old_def_fwd_addrs = default_fwd_addrs;
        default_fwd_addrs = new_def_fwd_addrs;
        pthread_rwlock_unlock(&__fwd_lock);
    }

    if (old_def_fwd_addrs) {
        if (old_def_fwd_addrs->server_addrs)
            free(old_def_fwd_addrs->server_addrs);

        free(old_def_fwd_addrs);
    }

    return 0;
}

int fwd_addrs_reload(char *addrs)
{
    int index = 0;
    int new_zone_num = 0;
    int old_zone_num = 0;
    domain_fwd_addrs **new_fwd_addrs = NULL;
    domain_fwd_addrs **old_fwd_addrs = NULL;

    if (!addrs)
        return -1;

    new_fwd_addrs = parse_dns_fwd_zones(addrs, &new_zone_num);
    pthread_rwlock_wrlock(&__fwd_lock);
    old_fwd_addrs = zones_fwd_addrs;
    zones_fwd_addrs = new_fwd_addrs;
    old_zone_num = g_fwd_zone_num;
    g_fwd_zone_num = new_zone_num;
    pthread_rwlock_unlock(&__fwd_lock);

    if (old_fwd_addrs) {
        for (index = 0; index < old_zone_num; index++) {
            if (old_fwd_addrs[index]->server_addrs)
                free(old_fwd_addrs[index]->server_addrs);
            free(old_fwd_addrs[index]);
        }

        free(old_fwd_addrs);
    }

    return 0;
}
