#define _GNU_SOURCE
#include <pthread.h>
#include <rte_mbuf.h>
#include <rte_ether.h> 
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_udp.h>
#include <arpa/inet.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_arp.h>
#include <rte_icmp.h>

#include "rte_cycles.h"

#include "dns-conf.h"
#include "process.h"
#include "kdns-adap.h"
#include "query.h"
#include "buffer.h"
#include "netdev.h"

#include "forward.h"
#include "domain_update.h"
#include "view_update.h"
#include "dns-conf.h"
#include "rate_limit.h"

extern struct dns_config *g_dns_cfg;
extern struct rte_kni     *master_kni;
extern struct net_device  kdns_net_device;
static void packet_icmp_handle(struct rte_mbuf *pkt, struct netif_queue_conf *conf);

#if 0
static void print_ip(uint32_t sip, uint32_t dip) {

#define PRINT_IP_FORMAT         "%u.%u.%u.%u"  
#define  PRINT_HIP(x)\
       ((x >> 24) & 0xFF),\
       ((x >> 16) & 0xFF),\
       ((x >>  8) & 0xFF),\
       ((x >>  0) & 0xFF)

    char ip_str[64];  
    sprintf(ip_str, PRINT_IP_FORMAT, PRINT_HIP(ntohl(dip)));  
    printf("dist ip :%s   ", ip_str);  
    sprintf(ip_str, PRINT_IP_FORMAT, PRINT_HIP(ntohl(sip)));  
    printf("src_addr ip :%s \n", ip_str);  
}

#endif

int packet_l3_handle(struct rte_mbuf *pkt, struct netif_queue_conf *conf, unsigned lcore_id) {
    
    struct ether_hdr *eth_hdr_in = NULL;
    struct ipv4_hdr  *ip_hdr_in = NULL;
    struct udp_hdr   *udp_hdr_in = NULL; 
    
    struct ether_hdr tmp_eth_hdr;
    struct ipv4_hdr  tmp_ipv4_hdr;
    struct udp_hdr   tmp_udp_hdr;
    
    uint16_t ether_hdr_offset = sizeof(struct ether_hdr);
    uint16_t ip_hdr_offset    = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
    uint16_t udp_hdr_offset   = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);
   

    kdns_query_st *query;
    
    ip_hdr_in = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, ether_hdr_offset);

    int ip_headlen           = (ip_hdr_in->version_ihl & 0xF)<<2 ;
    uint16_t ip_total_length = rte_be_to_cpu_16(ip_hdr_in->total_length);
    
    //check the pkt
    if(ip_total_length  < ip_headlen) {
        conf->stats.pkt_len_err++;
        log_msg(LOG_ERR, "ip_total_length err: ip_total_length(%d), ip_headlen(%d)\n", ip_total_length, ip_headlen);
        goto cleanup; 
    }

    if(pkt->pkt_len < ip_total_length + ether_hdr_offset) {
        conf->stats.pkt_len_err++;
        log_msg(LOG_ERR, "pkt_len err: pkt->pkt_len(%d) < ip_total_length(%d) + ether_hdr(%d)\n", pkt->pkt_len, ip_total_length, ether_hdr_offset);
        goto cleanup;
    }

    if (rate_limit(ip_hdr_in->src_addr, RATE_LIMIT_TYPE_ALL, lcore_id) != 0) {
        goto cleanup;
    }

    switch(ip_hdr_in->next_proto_id) {
    case IPPROTO_UDP:
        eth_hdr_in = rte_pktmbuf_mtod(pkt, struct ether_hdr*);
        udp_hdr_in = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr*, ip_hdr_offset);
        if(ip_total_length != ip_headlen + ntohs(udp_hdr_in->dgram_len)) {
            conf->stats.pkt_len_err++;
            log_msg(LOG_ERR, "udp_hdr_in->dgram_len err: ip_total_length (%d) != ip_headlen(%d)+ dgram_len(%d)\n",ip_total_length , ip_headlen,ntohs(udp_hdr_in->dgram_len));
            goto cleanup;
        }
        
        if(udp_hdr_in->dst_port == UDP_PORT_53) { // port 53

            conf->stats.dns_pkts_rcv++;
           // printf("rvc len =%d\n",pkt->pkt_len);
            conf->stats.dns_lens_rcv += pkt->pkt_len;
            int received = rte_be_to_cpu_16(udp_hdr_in->dgram_len) - sizeof(struct udp_hdr);

            uint16_t flags_old ;
            char * bufdata = rte_pktmbuf_mtod_offset(pkt, char*, udp_hdr_offset);
            memcpy(&flags_old,bufdata+2 , 2);
              
            query = dns_packet_proess(pkt, ip_hdr_in->src_addr,udp_hdr_offset, received);
            int retLen = buffer_remaining(query->packet);

            if (GET_RCODE(query->packet) == RCODE_REFUSE) {
                if (rate_limit(ip_hdr_in->src_addr, RATE_LIMIT_TYPE_FWD, lcore_id) != 0) {
                    goto cleanup;
                }

                memcpy(bufdata + 2, &flags_old, 2);
                fwd_query_enqueue(pkt, ip_hdr_in->src_addr, GET_ID(query->packet), query->qtype, (char *)domain_name_to_string(query->qname, NULL));
                return 0;
            }
            if(query != NULL && retLen > 0) {
                init_eth_header(&tmp_eth_hdr, &eth_hdr_in->d_addr, &eth_hdr_in->s_addr, ETHER_TYPE_IPv4);
                init_ipv4_header(&tmp_ipv4_hdr, ip_hdr_in->dst_addr, ip_hdr_in->src_addr, sizeof(struct udp_hdr) + retLen);
                init_udp_header(&tmp_udp_hdr, udp_hdr_in->dst_port, udp_hdr_in->src_port, retLen);

                memcpy(eth_hdr_in,&tmp_eth_hdr, sizeof(struct ether_hdr));
                memcpy(ip_hdr_in,&tmp_ipv4_hdr, sizeof(struct ipv4_hdr));
                memcpy(udp_hdr_in,&tmp_udp_hdr, sizeof(struct udp_hdr));
                pkt->pkt_len = retLen + udp_hdr_offset;
                pkt->data_len = pkt->pkt_len;
                pkt->l2_len = sizeof(struct ether_hdr);
                pkt->vlan_tci  = ETHER_TYPE_IPv4;
                pkt->l3_len = sizeof(struct ipv4_hdr);  
                
                conf->tx_mbufs[conf->tx_len] = pkt;
                conf->tx_len++;
                conf->stats.dns_lens_snd += pkt->pkt_len;
               // printf("snd len =%d\n",pkt->pkt_len);
            }
            
        }else{
            conf->stats.pkt_dropped++;
             rte_pktmbuf_free(pkt);     
        }
        return 0;
    case IPPROTO_ICMP:
        packet_icmp_handle(pkt,conf);
        conf->tx_mbufs[conf->tx_len] = pkt;
        conf->tx_len++;
        return 0;
    default:
        conf->kni_mbufs[conf->kni_len]= pkt;
        conf->kni_len ++;
        return 0;

    }
cleanup:
    conf->stats.pkt_dropped++;
    rte_pktmbuf_free(pkt);
    return 0;
}

#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)


static uint16_t
ipv4_hdr_cksum(struct ipv4_hdr *ip_h)
{
	uint16_t *v16_h;
	uint32_t ip_cksum;

	/*
	 * Compute the sum of successive 16-bit words of the IPv4 header,
	 * skipping the checksum field of the header.
	 */
	v16_h = (unaligned_uint16_t *) ip_h;
	ip_cksum = v16_h[0] + v16_h[1] + v16_h[2] + v16_h[3] +
		v16_h[4] + v16_h[6] + v16_h[7] + v16_h[8] + v16_h[9];

	/* reduce 32 bit checksum to 16 bits and complement it */
	ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
	ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	return (ip_cksum == 0) ? 0xFFFF : (uint16_t) ip_cksum;
}


static void packet_icmp_handle(struct rte_mbuf *pkt, struct netif_queue_conf *conf) {

	struct ether_hdr *eth_h;
    struct arp_hdr  *arp_h;
    struct ipv4_hdr *ip_h;
    struct icmp_hdr *icmp_h;
    struct ether_addr eth_addr;
    uint32_t ip_addr;
    uint32_t cksum;
    conf->stats.pkts_icmp ++;
    
    eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    uint16_t eth_type = rte_be_to_cpu_16(eth_h->ether_type);
    /* Reply to ARP requests   // no use*/
	if (eth_type == ETHER_TYPE_ARP){

        arp_h = (struct arp_hdr *) ((char *)eth_h + sizeof(struct ether_hdr));

    	/* Use source MAC address as destination MAC address. */
    	ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
    	/* Set source MAC address with MAC address of TX port */
    	ether_addr_copy(&kdns_net_device.hwaddr,&eth_h->s_addr);

    	arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

        ether_addr_copy(&arp_h->arp_data.arp_tha, &eth_addr);
    	ether_addr_copy(&arp_h->arp_data.arp_sha, &arp_h->arp_data.arp_tha);
    	ether_addr_copy(&eth_h->s_addr, &arp_h->arp_data.arp_sha);

    	/* Swap IP addresses in ARP payload */
    	ip_addr = arp_h->arp_data.arp_sip;
    	arp_h->arp_data.arp_sip = arp_h->arp_data.arp_tip;
    	arp_h->arp_data.arp_tip = ip_addr;
        return ;
   }

    ip_h = (struct ipv4_hdr *) ((char *)eth_h + sizeof(struct ether_hdr));
    icmp_h = (struct icmp_hdr *) ((char *)ip_h + sizeof(struct ipv4_hdr));

	ether_addr_copy(&eth_h->s_addr, &eth_addr);
	ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
	ether_addr_copy(&eth_addr, &eth_h->d_addr);
	ip_addr = ip_h->src_addr;
	if (is_multicast_ipv4_addr(ip_h->dst_addr)) {
		uint32_t ip_src;

		ip_src = rte_be_to_cpu_32(ip_addr);
		if ((ip_src & 0x00000003) == 1)
			ip_src = (ip_src & 0xFFFFFFFC) | 0x00000002;
		else
			ip_src = (ip_src & 0xFFFFFFFC) | 0x00000001;
		ip_h->src_addr = rte_cpu_to_be_32(ip_src);
		ip_h->dst_addr = ip_addr;
		ip_h->hdr_checksum = ipv4_hdr_cksum(ip_h);
	} else {
		ip_h->src_addr = ip_h->dst_addr;
		ip_h->dst_addr = ip_addr;
	}
	icmp_h->icmp_type = IP_ICMP_ECHO_REPLY;
	cksum = ~icmp_h->icmp_cksum & 0xffff;
	cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
	cksum += htons(IP_ICMP_ECHO_REPLY << 8);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	icmp_h->icmp_cksum = ~cksum;   
}


int process_slave(__attribute__((unused)) void *arg) {
    int t,k;
    unsigned lcore_id = rte_lcore_id();

    kdns_init(lcore_id);
    domain_msg_ring_create(lcore_id);
    view_msg_ring_create(lcore_id);
    rate_limit_init(lcore_id);

    struct netif_queue_conf *conf = netif_queue_conf_get(lcore_id);
    log_msg(LOG_INFO, "Starting core %u conf: rx=%d, tx=%d\n", lcore_id, conf->rx_queue_id, conf->tx_queue_id);
    while (1){
        config_reload_pre_core(lcore_id);
        view_msg_slave_process();
        domain_msg_slave_process();
        struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST] ={0};
        uint16_t rx_count;
    
        rx_count = rte_eth_rx_burst(conf->port_id, conf->rx_queue_id, mbufs, NETIF_MAX_PKT_BURST);

        if (unlikely(rx_count == 0)) {
           continue;
        } 
        conf->tx_len = conf->kni_len =0;
        memset(conf->tx_mbufs,0,sizeof(conf->tx_mbufs));
        memset(conf->kni_mbufs,0,sizeof(conf->kni_mbufs));

        /* prefetch packets */
        for (t = 0; t < rx_count && t < 3; t++)
             rte_prefetch0(rte_pktmbuf_mtod(mbufs[t], void *));
        
        for (k = 0; k < rx_count; k++) {
                packet_l2_handle(mbufs[k], conf, lcore_id);
                if (t < rx_count) {
                    rte_prefetch0(rte_pktmbuf_mtod(mbufs[t], void *));
                    t++;
                } 
        }
        // send the pkts
        if (likely(conf->tx_len >0)){
               int ntx = rte_eth_tx_burst(conf->port_id,conf->tx_queue_id, conf->tx_mbufs, conf->tx_len);
               conf->stats.dns_pkts_snd += ntx;
               if (unlikely(ntx != conf->tx_len)){
                   log_msg(LOG_ERR, "rx=%d tx=%d real tx=%d\n",rx_count, conf->tx_len, ntx);
                   int i =0;
                   for (i = ntx; i < conf->tx_len; i++)
                       rte_pktmbuf_free(conf->tx_mbufs[i]);
                   conf->stats.pkt_dropped += ntx;
               }
        }
        // snd to master
        if (unlikely(conf->kni_len > 0)){
            dns_kni_enqueue(conf,conf->kni_mbufs,conf->kni_len);
        }       
    }
    return 0;
}

//set master's affinity to master core
static int reset_master_affinity(void)
{
    int s;
    pthread_t tid;
    cpu_set_t cpuset;

    tid = pthread_self();
    CPU_ZERO(&cpuset);
    CPU_SET(rte_get_master_lcore(), &cpuset);

    s = pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        log_msg(LOG_ERR, "fail to set thread affinty, errno=%d, errinfo=%s\n", errno, strerror(errno));
        return -1;
    }

    CPU_ZERO(&cpuset);
    s = pthread_getaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
    if (s != 0) {
        log_msg(LOG_ERR, "fail to get thread affinity, errno=%d, errinfo=%s\n", errno, strerror(errno));
        return -2;
    }
    log_msg(LOG_INFO, "master thread affinity is set to %u\n", CPU_COUNT(&cpuset));

    return 0;
}

void process_master(__attribute__((unused)) void *arg) {
    unsigned lcore_id = rte_lcore_id();

    domain_msg_ring_create(lcore_id);
    view_msg_ring_create(lcore_id);

    domian_info_exchange_run(g_dns_cfg->comm.web_port);

    reset_master_affinity();
    log_msg(LOG_INFO, "Starting master core %u\n", lcore_id);
    while(1) {
        struct rte_mbuf *pkts_kni_rx[NETIF_MAX_PKT_BURST];
        unsigned pkt_num;

        config_reload_pre_core(lcore_id);
        view_msg_master_process();
        domain_msg_master_process();
        uint16_t rx_count = dns_kni_dequeue(pkts_kni_rx,NETIF_MAX_PKT_BURST);
        if (rx_count == 0){
            rte_kni_tx_burst(master_kni,NULL , 0); 
           // rte_delay_ms(30);
        }else{
            pkt_num = rte_kni_tx_burst(master_kni, pkts_kni_rx, rx_count);          
            if (unlikely(pkt_num < rx_count)) {
                int i =0;
                for(i = pkt_num; i < rx_count; i ++  )
                    rte_pktmbuf_free(pkts_kni_rx[i]);
            }
        }

        // kni 
        rte_kni_handle_request(master_kni);

        struct rte_mbuf *kni_pkts_tx[NETIF_MAX_PKT_BURST];
        unsigned npkts = rte_kni_rx_burst(master_kni, kni_pkts_tx, NETIF_MAX_PKT_BURST);
        if(npkts > 0) {
            uint16_t nb_tx = rte_eth_tx_burst(0, 0, kni_pkts_tx, (uint16_t)npkts);
            if(nb_tx < npkts){
                uint16_t i =0;
                for(i = nb_tx; i < npkts; i++  )
                    rte_pktmbuf_free(kni_pkts_tx[i]);
           }
        }   

        //fwd
        struct rte_mbuf *fwd_pkts_tx[NETIF_MAX_PKT_BURST];
        unsigned fwd_count = fwd_response_dequeue(fwd_pkts_tx, NETIF_MAX_PKT_BURST);
        if (fwd_count != 0){
            uint16_t nb_tx = rte_eth_tx_burst(0, 0, fwd_pkts_tx, (uint16_t)fwd_count);
            if(nb_tx < fwd_count){
                uint16_t i =0;
                for(i = nb_tx; i < fwd_count; i++)
                    rte_pktmbuf_free(fwd_pkts_tx[i]);
           }
        }
    }
    
    return ;
}


