#include "rte_cycles.h"
#include "rte_memory.h"
#include "rte_memzone.h"
#include "rte_launch.h"
#include "rte_eal.h"
#include "rte_per_lcore.h"
#include "rte_lcore.h"
#include "rte_debug.h"
#include "rte_ring.h"
#include "rte_mempool.h"
#include "rte_mbuf.h"
#include "rte_ethdev.h"
#include "rte_kni.h"
#include <rte_ip.h>
#include <rte_udp.h>
#include "netdev.h"
#include "dns-conf.h"
#include "util.h"
#include "process.h"


#define KNI_ENET_HEADER_SIZE    14
/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_RING_SIZE     65536

#define KNI_DEF_MBUF_SIZE       2048

#define MBUF_CACHE_DEF    256

struct rte_kni  *master_kni;

struct rte_mempool *pkt_mbuf_pool;

struct rte_mempool *kni_mbuf_pool;

struct rte_ring *master_kni_pkt_ring;

struct net_device  kdns_net_device ={0};
static  int rss_enable = 0;


/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.header_split = 0,      /* Header Split disabled */
		.hw_ip_checksum = 0,    /* IP checksum offload disabled */
		.hw_vlan_filter = 0,    /* VLAN filtering disabled */
		.jumbo_frame = 0,       /* Jumbo Frame Support disabled */
		.hw_strip_crc = 0,      /* CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static struct rte_eth_conf port_conf_rss = {
	.rxmode = {
		.mq_mode	= ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload enabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf =  ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};


static int kni_config_network_interface(uint8_t port_id, uint8_t if_up)
{
	int ret = 0;
    return 0 ;

	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		log_msg(LOG_ERR,"Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	log_msg(LOG_INFO,"Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	if (ret < 0)
		log_msg(LOG_ERR,"Failed to start port %d\n", port_id);

	return ret;
}



/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	log_msg(LOG_INFO, "Checking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status) {
                    log_msg(LOG_INFO, "Port %d Link Up - speed %u Mbps - %s\n", (uint8_t)portid, (unsigned)link.link_speed,
                            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));
                } else {
                    log_msg(LOG_INFO, "Port %d Link Down\n", (uint8_t)portid);
                }
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1) {
            break;
        }

		if (all_ports_up == 0) {
            log_msg(LOG_INFO, ".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
            log_msg(LOG_INFO, "done\n");
		}
	}
}

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
	int ret;
	struct rte_eth_conf conf;
    return 0 ;

	if (port_id >= rte_eth_dev_count()) {
		log_msg(LOG_ERR, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	log_msg(LOG_INFO, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);
    if ( strcmp(g_dns_cfg->netdev.mode,"rss") == 0 ){
        rss_enable = 1;
        memcpy(&conf, &port_conf_rss, sizeof(conf));
    }else{
    	memcpy(&conf, &port_conf, sizeof(conf));
    }

	/* Set new MTU */
	if (new_mtu > ETHER_MAX_LEN)
		conf.rxmode.jumbo_frame = 1;
	else
		conf.rxmode.jumbo_frame = 0;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
							KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		log_msg(LOG_ERR, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		log_msg(LOG_ERR,"Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

static int kni_alloc(uint8_t port_id)
{
	struct rte_kni_conf conf;
    struct rte_kni_ops ops;
	struct rte_eth_dev_info dev_info;
	struct ether_addr eth_addr;

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));
    
	conf.core_id = 0;
    conf.force_bind = 1;
    conf.mbuf_size = KNI_DEF_MBUF_SIZE;
    conf.group_id = (uint16_t)0;
    snprintf(conf.name, sizeof(conf.name),"%s",g_dns_cfg->netdev.name_prefix);

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
	conf.addr = dev_info.pci_dev->addr;
	conf.id = dev_info.pci_dev->id;

	memset(&ops, 0, sizeof(ops));
	ops.port_id = port_id;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_config_network_interface;

	master_kni = rte_kni_alloc(kni_mbuf_pool, &conf, &ops);
	if (!master_kni){
        log_msg(LOG_ERR,"Fail to create kni for port: %d\n", port_id);
		exit(-1);
    }

	rte_eth_macaddr_get(port_id, &eth_addr);
	int ret = linux_set_if_mac(conf.name, (unsigned char *)&eth_addr);
	if (ret != 0) {
		char mac[ETHER_ADDR_FMT_SIZE];
		ether_format_addr(mac, ETHER_ADDR_FMT_SIZE, &eth_addr);
		log_msg(LOG_ERR, "Fail to set mac %s for %s: %s\n", mac, conf.name, strerror(errno));
		exit(-1);
	}

	return 0;
}

int kni_free_kni(uint8_t port_id)
{
    if (rte_kni_release(master_kni))
		log_msg(LOG_ERR,"Fail to release kni\n");	
	rte_eth_dev_stop(port_id);
	return 0;
}


/* Initialise a single port on an Ethernet device */
static void init_port(uint8_t port,uint16_t rx_rings, uint16_t tx_rings)
{
	int ret,q;

	/* Initialise device and RX/TX queues */
	log_msg(LOG_INFO, "Initialising port %u ...\n", (unsigned)port);
	fflush(stdout);
    struct rte_eth_conf conf;
    
    if ( strcmp(g_dns_cfg->netdev.mode,"rss") == 0 ){
        rss_enable = 1;
        memcpy(&conf, &port_conf_rss, sizeof(conf));
    }else{
    	memcpy(&conf, &port_conf, sizeof(conf));
    } 
	ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &conf);
	if (ret < 0){
		log_msg(LOG_ERR, "Could not configure port%u (%d)\n",
		            (unsigned)port, ret);
        exit(-1);
    }

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		ret = rte_eth_rx_queue_setup(port, q, g_dns_cfg->netdev.rxq_desc_num,
				rte_eth_dev_socket_id(port), NULL, pkt_mbuf_pool);
		if (ret < 0){
            log_msg(LOG_ERR,"rte_eth_rx_queue_setup err\n");
			 exit(-1);
        }
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		ret = rte_eth_tx_queue_setup(port, q,  g_dns_cfg->netdev.txq_desc_num,
				rte_eth_dev_socket_id(port), NULL);
		if (ret < 0){
            log_msg(LOG_ERR,"rte_eth_tx_queue_setup err\n");
			exit(-1);
        }
	}


	ret = rte_eth_dev_start(port);
	if (ret < 0){
		log_msg(LOG_ERR, "Could not start port%u (%d)\n",
						(unsigned)port, ret);
        exit(-1);
    }
	rte_eth_promiscuous_enable(port);
    
}

void dns_kni_enqueue(struct netif_queue_conf *conf,struct rte_mbuf **mbufs,uint16_t rx_len){
    int i =0;
    int res = rte_ring_enqueue_bulk(master_kni_pkt_ring, (void *const * )mbufs, rx_len);
    if (res) {
        if (res == -EDQUOT) {
            log_msg(LOG_ERR,"rte_ring_enqueue_bulk err\n ");
        } else {
             conf->stats.pkt_dropped += (uint64_t)rx_len;
            for (i = 0; i < rx_len; i++) {
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }else{
         conf->stats.pkts_2kni += (uint64_t)rx_len; 
    }
}

uint16_t dns_kni_dequeue(struct rte_mbuf **mbufs,uint16_t pkts_len){

   while (pkts_len > 0 &&
				unlikely(rte_ring_dequeue_bulk(master_kni_pkt_ring, (void ** )mbufs,
					pkts_len) != 0))
			pkts_len = (uint16_t)RTE_MIN(rte_ring_count(master_kni_pkt_ring),pkts_len);
   
   return pkts_len;
}



static char *
flowtype_to_str(uint16_t flow_type)
{
	struct flow_type_info {
		char str[32];
		uint16_t ftype;
	};

	uint8_t i;
	static struct flow_type_info flowtype_str_table[] = {
		{"raw", RTE_ETH_FLOW_RAW},
		{"ipv4", RTE_ETH_FLOW_IPV4},
		{"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
		{"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
		{"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
		{"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
		{"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
		{"ipv6", RTE_ETH_FLOW_IPV6},
		{"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
		{"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
		{"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
		{"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
		{"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
		{"l2_payload", RTE_ETH_FLOW_L2_PAYLOAD},
		{"port", RTE_ETH_FLOW_PORT},
		{"vxlan", RTE_ETH_FLOW_VXLAN},
		{"geneve", RTE_ETH_FLOW_GENEVE},
		{"nvgre", RTE_ETH_FLOW_NVGRE},
	};

	for (i = 0; i < RTE_DIM(flowtype_str_table); i++) {
		if (flowtype_str_table[i].ftype == flow_type)
			return flowtype_str_table[i].str;
	}

	return NULL;
}


void dns_dpdk_init(void){
    
    char *dpdk_argv[g_dns_cfg->dpdk.argc];
    int i;

    for (i = 0; i < g_dns_cfg->dpdk.argc; i++) {
        dpdk_argv[i] = strdup(g_dns_cfg->dpdk.argv[i]);
    }
    if (rte_eal_init(g_dns_cfg->dpdk.argc, dpdk_argv) < 0) {
        log_msg(LOG_ERR, "EAL init failed.\n");
        exit(-1);
    }
    uint8_t nb_sys_ports;

    pkt_mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", g_dns_cfg->netdev.mbuf_num,
                MBUF_CACHE_DEF, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (pkt_mbuf_pool == NULL) {
        log_msg(LOG_ERR, "Could not initialise mbuf pool\n");
        exit(-1);
    }

    kni_mbuf_pool = rte_pktmbuf_pool_create("kni_mbuf_pool", g_dns_cfg->netdev.kni_mbuf_num,
                MBUF_CACHE_DEF, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!kni_mbuf_pool){
        log_msg(LOG_ERR, "Fail to create pktmbuf_pool for kni.");
        exit(-1);
    }

    master_kni_pkt_ring = rte_ring_create("master_kni_pkt_ring", KNI_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);

    if (master_kni_pkt_ring == NULL){
        log_msg(LOG_ERR, "Could not initialise ring buf \n");
        exit(-1);
    }
    
        /* Get number of ports found in scan */
    nb_sys_ports = rte_eth_dev_count();
    if (nb_sys_ports == 0){
        log_msg(LOG_ERR, "No supported Ethernet device found\n");
        exit(-1);
    }
    
    if (nb_sys_ports != 1){
        log_msg(LOG_ERR, "now just one port supported\n");
        exit(-1);
    }

    rte_kni_init(nb_sys_ports);
    
    init_port(0,g_dns_cfg->netdev.rxq_num,g_dns_cfg->netdev.txq_num);
    kni_alloc(0);

    check_all_ports_link_status(nb_sys_ports, 1);

    struct rte_eth_dev_info dev_info;
 
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(0, &dev_info);
    
    log_msg(LOG_INFO,"flow_type_rss_offloads = %ld\n",dev_info.flow_type_rss_offloads);

	log_msg(LOG_INFO,"Supported flow types:\n");
	char *p;
	for (i = RTE_ETH_FLOW_UNKNOWN + 1; i < RTE_ETH_FLOW_MAX;i++) {
		if (!(dev_info.flow_type_rss_offloads & (1ULL << i)))
			continue;
		p = flowtype_to_str(i);
		log_msg(LOG_INFO,"  %s\n", (p ? p : "unknown"));
	}
                            
    rte_eth_macaddr_get(0, &kdns_net_device.hwaddr);

}


 int packet_l2_handle(struct rte_mbuf *pkt, struct netif_queue_conf *conf, unsigned lcore_id) {

#ifdef ENABLE_KDNS_METRICS
     uint64_t start_time = time_now_usec();
#endif

    struct ether_hdr *eth_hdr = NULL;
    conf->stats.pkts_rcv++;
    eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *); 

    switch(ntohs(eth_hdr->ether_type)) {
    case ETHER_TYPE_IPv4:
        packet_l3_handle(pkt, conf, lcore_id);
        break;
    case ETHER_TYPE_IPv6:
    default:
        conf->kni_mbufs[conf->kni_len++]= pkt;
        break;
    }

#ifdef ENABLE_KDNS_METRICS
     metrics_data_update( &conf->stats.metrics,  time_now_usec() - start_time);
#endif
    return 0;
 }
    
    
 static void netif_queue_conf_init(uint16_t lcore_id, uint16_t port_id,uint16_t rx_queue_id,uint16_t tx_queue_id)
 {
     log_msg(LOG_INFO,"core queue info: coreId(%d) portID(%d) rxQueueId(%d) txQueueId(%d)\n",
        lcore_id,port_id,rx_queue_id,tx_queue_id);
     memset(&kdns_net_device.l_netif_queue_conf[lcore_id],0,sizeof(struct netif_queue_conf));
     kdns_net_device.l_netif_queue_conf[lcore_id].port_id = port_id;
     kdns_net_device.l_netif_queue_conf[lcore_id].rx_queue_id = rx_queue_id;
     kdns_net_device.l_netif_queue_conf[lcore_id].tx_queue_id = tx_queue_id;
 }

void netif_queue_core_bind(void)
{
    int rx_id =0;
    int tx_id =0;
    if (rss_enable)
        tx_id = 1; 
    unsigned lcore_id;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {     
        netif_queue_conf_init(lcore_id,0,rx_id,tx_id);
        rx_id++;
        tx_id++;
    }
}

    
struct netif_queue_conf* netif_queue_conf_get(uint16_t lcore_id){
    return &kdns_net_device.l_netif_queue_conf[lcore_id];   
}

void netif_statsdata_get(struct netif_queue_stats *sta){
    unsigned lcore_id;
    struct netif_queue_stats *sta_lcore;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {  
        sta_lcore = &kdns_net_device.l_netif_queue_conf[lcore_id].stats;
        sta->pkts_rcv     +=  sta_lcore->pkts_rcv;
        sta->pkts_2kni    +=  sta_lcore->pkts_2kni;
        sta->pkts_icmp     +=  sta_lcore->pkts_icmp;
        sta->dns_pkts_rcv +=  sta_lcore->dns_pkts_rcv;
        sta->dns_pkts_snd +=  sta_lcore->dns_pkts_snd;
        sta->dns_lens_rcv +=  sta_lcore->dns_lens_rcv;
        sta->dns_lens_snd +=  sta_lcore->dns_lens_snd;
        sta->pkt_dropped      +=  sta_lcore->pkt_dropped;
        sta->pkt_len_err  +=  sta_lcore->pkt_len_err;

        #ifdef ENABLE_KDNS_METRICS
            sta->metrics.timeSum +=  sta_lcore->metrics.timeSum;
            sta->metrics.metrics[0] +=  sta_lcore->metrics.metrics[0];
            sta->metrics.metrics[1] +=  sta_lcore->metrics.metrics[1];
            sta->metrics.metrics[2] +=  sta_lcore->metrics.metrics[2];
            sta->metrics.metrics[3] +=  sta_lcore->metrics.metrics[3];
            if (sta->metrics.minTime > sta_lcore->metrics.minTime){
                sta->metrics.minTime = sta_lcore->metrics.minTime;
            }
            if (sta->metrics.maxTime < sta_lcore->metrics.maxTime){
                sta->metrics.maxTime = sta_lcore->metrics.maxTime;
            } 
        #endif
    }  
    return;
}

void netif_statsdata_reset(void){
    unsigned lcore_id;
    struct netif_queue_stats *sta_lcore;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {  
        sta_lcore = &kdns_net_device.l_netif_queue_conf[lcore_id].stats;
        sta_lcore->pkts_rcv     = 0;
        sta_lcore->pkts_2kni    = 0 ;
        sta_lcore->pkts_icmp     = 0 ;
        sta_lcore->dns_pkts_rcv = 0 ;
        sta_lcore->dns_pkts_snd = 0 ;
        sta_lcore->dns_lens_rcv = 0 ;
        sta_lcore->dns_lens_snd = 0 ;
        sta_lcore->pkt_dropped  = 0 ;
        sta_lcore->pkt_len_err  = 0 ;
    }  
    return;
}


void netif_statsdata_metrics_reset(void){
    unsigned lcore_id;
    struct netif_queue_stats *sta_lcore;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {  
        sta_lcore = &kdns_net_device.l_netif_queue_conf[lcore_id].stats;
        memset(&sta_lcore->metrics, 0 ,sizeof(metrics_metrics_st)) ;
        sta_lcore->metrics.minTime = 0xffff;
    }  
    return;
}


void init_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac, \
    struct ether_addr *dst_mac, uint16_t ether_type)
{
    ether_addr_copy(dst_mac, &eth_hdr->d_addr);
    ether_addr_copy(src_mac, &eth_hdr->s_addr);

    eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
}

uint16_t init_ipv4_header(struct ipv4_hdr *ip_hdr, uint32_t src_addr,
    uint32_t dst_addr, uint16_t pktdata_len)
{
    uint16_t pkt_len;
    unaligned_uint16_t *ptr16;
    uint32_t ip_cksum;

    pkt_len = (uint16_t) (pktdata_len + sizeof(struct ipv4_hdr));

    ip_hdr->version_ihl   = IP_VHL_DEF;
    ip_hdr->type_of_service   = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live   = IP_DEFTTL;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->packet_id = 0;
    ip_hdr->total_length   = rte_cpu_to_be_16(pkt_len);
    ip_hdr->src_addr = src_addr;
    ip_hdr->dst_addr = dst_addr;

    ptr16 = (unaligned_uint16_t *)ip_hdr;
    ip_cksum = 0;
    ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
    ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
    ip_cksum += ptr16[4];
    ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
    ip_cksum += ptr16[8]; ip_cksum += ptr16[9];


    ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
        (ip_cksum & 0x0000FFFF);
    ip_cksum %= 65536;
    ip_cksum = (~ip_cksum) & 0x0000FFFF;
    if (ip_cksum == 0)
        ip_cksum = 0xFFFF;
    ip_hdr->hdr_checksum = (uint16_t) ip_cksum;

    return pkt_len;
}


uint16_t init_udp_header(struct udp_hdr *udp_hdr, uint16_t src_port,
    uint16_t dst_port, uint16_t pktdata_len)
{
    uint16_t pkt_len;

    pkt_len = (uint16_t) (pktdata_len + sizeof(struct udp_hdr));

    udp_hdr->src_port = src_port;
    udp_hdr->dst_port = dst_port;
    udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_len);
    udp_hdr->dgram_cksum = 0; 

    return pkt_len;
}

