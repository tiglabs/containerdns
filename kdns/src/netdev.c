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
#include "ctrl_msg.h"

#define IP_DEFTTL               (64)    /* from RFC 1340. */
#define IP_VERSION              (0x40)
#define IP_HDRLEN               (0x05)  /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF              (IP_VERSION | IP_HDRLEN)

#define KNI_ENET_HEADER_SIZE    (14)

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       (4)

#define MBUF_CACHE_DEF          (256)

struct rte_kni *kdns_kni;

struct rte_mempool *pkt_mbuf_pool;

struct rte_mempool *kni_mbuf_pool;

struct net_device kdns_net_device;

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
        .mq_mode    = ETH_MQ_RX_RSS,
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

static char *flowtype_to_str(uint16_t flow_type) {
    struct flow_type_info {
        char str[32];
        uint16_t ftype;
    };

    static struct flow_type_info flowtype_str_table[] = {
        {"raw",             RTE_ETH_FLOW_RAW},
        {"ipv4",            RTE_ETH_FLOW_IPV4},
        {"ipv4-frag",       RTE_ETH_FLOW_FRAG_IPV4},
        {"ipv4-tcp",        RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
        {"ipv4-udp",        RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
        {"ipv4-sctp",       RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
        {"ipv4-other",      RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
        {"ipv6",            RTE_ETH_FLOW_IPV6},
        {"ipv6-frag",       RTE_ETH_FLOW_FRAG_IPV6},
        {"ipv6-tcp",        RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
        {"ipv6-udp",        RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
        {"ipv6-sctp",       RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
        {"ipv6-other",      RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
        {"l2_payload",      RTE_ETH_FLOW_L2_PAYLOAD},
        {"ipv6-ex",         RTE_ETH_FLOW_IPV6_EX},
        {"ipv6-tcp-ex",     RTE_ETH_FLOW_IPV6_TCP_EX},
        {"ipv6-udp-ex",     RTE_ETH_FLOW_IPV6_UDP_EX},
        {"port",            RTE_ETH_FLOW_PORT},
        {"vxlan",           RTE_ETH_FLOW_VXLAN},
        {"geneve",          RTE_ETH_FLOW_GENEVE},
        {"nvgre",           RTE_ETH_FLOW_NVGRE},
    };

    uint8_t i;
    for (i = 0; i < RTE_DIM(flowtype_str_table); i++) {
        if (flowtype_str_table[i].ftype == flow_type) {
            return flowtype_str_table[i].str;
        }
    }

    return NULL;
}

static void check_port_flow_type_rss_offloads(uint8_t port_id) {
    int i;
    char *p;
    struct rte_eth_dev_info dev_info;

    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);

    log_msg(LOG_INFO, "flow_type_rss_offloads = %lu\n", dev_info.flow_type_rss_offloads);
    log_msg(LOG_INFO, "Supported flow types:\n");
    for (i = RTE_ETH_FLOW_UNKNOWN + 1; i < RTE_ETH_FLOW_MAX; i++) {
        if ((dev_info.flow_type_rss_offloads & (1ULL << i))) {
            p = flowtype_to_str(i);
            log_msg(LOG_INFO, "  %s\n", (p ? p : "unknown"));
        }
    }
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    log_msg(LOG_INFO, "Checking link status");
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if ((port_mask & (1 << portid)) == 0) {
                continue;
            }
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
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            log_msg(LOG_INFO, "done\n");
        }
    }
}

struct netif_queue_conf *netif_queue_conf_get(uint16_t lcore_id) {
    return &kdns_net_device.l_netif_queue_conf[lcore_id];
}

static void netif_queue_core_bind(uint8_t port_id) {
    int rx_id = 0;
    int tx_id = 0;
    int port_socket_id = rte_eth_dev_socket_id(port_id);
    unsigned lcore_id;

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        log_msg(LOG_INFO, "core queue info: coreId(%d) coreSocketId(%u) portID(%d) portSocketId(%d) rxQueueId(%d) txQueueId(%d)\n",
                lcore_id, lcore_config[lcore_id].socket_id, port_id, port_socket_id, rx_id, tx_id);

        memset(&kdns_net_device.l_netif_queue_conf[lcore_id], 0, sizeof(struct netif_queue_conf));
        kdns_net_device.l_netif_queue_conf[lcore_id].port_id = port_id;
        kdns_net_device.l_netif_queue_conf[lcore_id].rx_queue_id = rx_id;
        kdns_net_device.l_netif_queue_conf[lcore_id].tx_queue_id = tx_id;
        ++rx_id;
        ++tx_id;
    }
}

static void kdns_port_init(uint8_t port_id) {
    int ret;
    uint16_t q;
    struct rte_eth_conf conf;

    uint16_t nb_rx_q = g_dns_cfg->netdev.rxq_num;
    uint16_t nb_tx_q = g_dns_cfg->netdev.txq_num;
    uint16_t nb_rx_desc = g_dns_cfg->netdev.rxq_desc_num;
    uint16_t nb_tx_desc = g_dns_cfg->netdev.txq_desc_num;
    unsigned nb_mbuf = g_dns_cfg->netdev.mbuf_num;

    pkt_mbuf_pool = rte_pktmbuf_pool_create("pkt_mbuf_pool", nb_mbuf, MBUF_CACHE_DEF, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (pkt_mbuf_pool == NULL) {
        log_msg(LOG_ERR, "Could not initialise pkt_mbuf_pool\n");
        exit(-1);
    }
    log_msg(LOG_INFO, "Initialising port(%u), rx queues(%u) desc(%u), tx queues(%u) desc(%u) ...\n", port_id, nb_rx_q, nb_rx_desc, nb_tx_q, nb_tx_desc);

    if (strcmp(g_dns_cfg->netdev.mode, "rss") == 0) {
        memcpy(&conf, &port_conf_rss, sizeof(conf));
    } else {
        memcpy(&conf, &port_conf, sizeof(conf));
    }
    ret = rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, &conf);
    if (ret < 0) {
        log_msg(LOG_ERR, "Could not configure port(%u) ret(%d)\n", port_id, ret);
        exit(-1);
    }
    for (q = 0; q < nb_rx_q; ++q) {
        ret = rte_eth_rx_queue_setup(port_id, q, nb_rx_desc, rte_eth_dev_socket_id(port_id), NULL, pkt_mbuf_pool);
        if (ret < 0) {
            log_msg(LOG_ERR, "Could not setup up RX queue for port(%u) queue(%u) ret(%d)\n", port_id, q, ret);
            exit(-1);
        }
    }
    for (q = 0; q < nb_tx_q; ++q) {
        ret = rte_eth_tx_queue_setup(port_id, q, nb_tx_desc, rte_eth_dev_socket_id(port_id), NULL);
        if (ret < 0) {
            log_msg(LOG_ERR, "Could not setup up X queue for port(%u) queue(%u) ret(%d)\n", port_id, q, ret);
            exit(-1);
        }
    }
    netif_queue_core_bind(port_id);

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        log_msg(LOG_ERR, "Could not start port %u (%d)\n", (unsigned)port_id, ret);
        exit(-1);
    }
    rte_eth_promiscuous_enable(port_id);
}

static int kni_config_network_interface(uint8_t port_id, uint8_t if_up) {
    int ret = 0;

    (void)port_id;
    (void)if_up;
#if 0
    if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
        log_msg(LOG_ERR, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }
    log_msg(LOG_INFO, "Configure network interface of %d %s\n", port_id, if_up ? "up" : "down");

    if (if_up != 0) {   /* Configure network interface up */
        rte_eth_dev_stop(port_id);
        ret = rte_eth_dev_start(port_id);
    } else {            /* Configure network interface down */
        rte_eth_dev_stop(port_id);
    }

    if (ret < 0) {
        log_msg(LOG_ERR, "Failed to start port %d\n", port_id);
    }
#endif

    return ret;
}

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu) {
    (void)port_id;
    (void)new_mtu;
#if 0
    int ret;
    struct rte_eth_conf conf;

    uint16_t nb_rx_q = g_dns_cfg->netdev.rxq_num;
    uint16_t nb_tx_q = g_dns_cfg->netdev.txq_num;

    if (port_id >= rte_eth_dev_count()) {
        log_msg(LOG_ERR, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }
    log_msg(LOG_INFO, "Change MTU of port %d to %u\n", port_id, new_mtu);

    /* Stop specific port */
    rte_eth_dev_stop(port_id);

    if (strcmp(g_dns_cfg->netdev.mode, "rss") == 0) {
        memcpy(&conf, &port_conf_rss, sizeof(conf));
    } else {
        memcpy(&conf, &port_conf, sizeof(conf));
    }

    /* Set new MTU */
    if (new_mtu > ETHER_MAX_LEN) {
        conf.rxmode.jumbo_frame = 1;
    } else {
        conf.rxmode.jumbo_frame = 0;
    }

    /* mtu + length of header + length of FCS = max pkt length */
    conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE + KNI_ENET_FCS_SIZE;
    ret = rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, &conf);
    if (ret < 0) {
        log_msg(LOG_ERR, "Fail to reconfigure port %d\n", port_id);
        return ret;
    }

    /* Restart specific port */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        log_msg(LOG_ERR, "Fail to restart port %d\n", port_id);
        return ret;
    }
#endif

    return 0;
}

__attribute__((unused)) static int kdns_kni_deinit(uint8_t port_id) {
    if (rte_kni_release(kdns_kni)) {
        log_msg(LOG_ERR, "Fail to release kni\n");
    }
    rte_eth_dev_stop(port_id);
    return 0;
}

static int kdns_kni_init(uint8_t port_id) {
    struct rte_kni_ops ops;
    struct rte_kni_conf conf;
    struct rte_eth_dev_info dev_info;

    unsigned nb_mbuf = g_dns_cfg->netdev.kni_mbuf_num;
    char *kni_name = g_dns_cfg->netdev.name_prefix;

    kni_mbuf_pool = rte_pktmbuf_pool_create("kni_mbuf_pool", nb_mbuf, MBUF_CACHE_DEF, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (kni_mbuf_pool == NULL) {
        log_msg(LOG_ERR, "Could not initialise kni_mbuf_pool\n");
        exit(-1);
    }

    rte_kni_init(1);

    memset(&conf, 0, sizeof(conf));
    conf.core_id = 0;
    conf.force_bind = 1;
    conf.group_id = (uint16_t)port_id;
    conf.mbuf_size = RTE_MBUF_DEFAULT_DATAROOM;
    snprintf(conf.name, sizeof(conf.name), "%s", kni_name);

    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    conf.addr = dev_info.pci_dev->addr;
    conf.id = dev_info.pci_dev->id;

    memset(&ops, 0, sizeof(ops));
    ops.port_id = port_id;
    ops.change_mtu = kni_change_mtu;
    ops.config_network_if = kni_config_network_interface;

    kdns_kni = rte_kni_alloc(kni_mbuf_pool, &conf, &ops);
    if (!kdns_kni) {
        log_msg(LOG_ERR, "Fail to create kni for port: %d\n", port_id);
        exit(-1);
    }

    rte_eth_macaddr_get(port_id, &kdns_net_device.hwaddr);
    if (linux_set_if_mac(conf.name, (unsigned char *)&kdns_net_device.hwaddr) != 0) {
        char str_mac[ETHER_ADDR_FMT_SIZE];
        ether_format_addr(str_mac, ETHER_ADDR_FMT_SIZE, &kdns_net_device.hwaddr);
        log_msg(LOG_ERR, "Fail to set mac %s for %s: %s\n", str_mac, conf.name, strerror(errno));
        exit(-1);
    }
    return 0;
}

int kdns_netdev_init(void) {
    uint8_t nb_sys_ports = rte_eth_dev_count();
    if (nb_sys_ports == 0) {
        log_msg(LOG_ERR, "No supported Ethernet device found\n");
        exit(-1);
    }
    if (nb_sys_ports != 1) {
        log_msg(LOG_ERR, "Now just one port supported\n");
        exit(-1);
    }

    uint8_t port_id = 0;
    kdns_port_init(port_id);
    kdns_kni_init(port_id);
    check_all_ports_link_status(nb_sys_ports, 1);
    check_port_flow_type_rss_offloads(port_id);

    return 0;
}

void kni_egress(struct rte_mbuf **mbufs, uint16_t nb_mbufs) {
    uint16_t nb_tx = rte_kni_tx_burst(kdns_kni, mbufs, nb_mbufs);
    if (unlikely(nb_tx < nb_mbufs)) {
        log_msg(LOG_ERR, "Failed to send %u pkt to kni\n", nb_mbufs - nb_tx);
        do {
            rte_pktmbuf_free(mbufs[nb_tx]);
        } while (++nb_tx < nb_mbufs);
    }
}

int kni_ingress(struct rte_mbuf **mbufs, uint16_t nb_mbufs) {
    rte_kni_handle_request(kdns_kni);

    return rte_kni_rx_burst(kdns_kni, mbufs, nb_mbufs);
}

void netif_statsdata_get(struct netif_queue_stats *sta) {
    unsigned lcore_id;
    struct netif_queue_stats *sta_lcore;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        sta_lcore = &kdns_net_device.l_netif_queue_conf[lcore_id].stats;
        sta->pkts_rcv += sta_lcore->pkts_rcv;
        sta->pkts_2kni += sta_lcore->pkts_2kni;
        sta->pkts_icmp += sta_lcore->pkts_icmp;
        sta->dns_pkts_rcv += sta_lcore->dns_pkts_rcv;
        sta->dns_pkts_snd += sta_lcore->dns_pkts_snd;
        sta->dns_lens_rcv += sta_lcore->dns_lens_rcv;
        sta->dns_lens_snd += sta_lcore->dns_lens_snd;
        sta->pkt_dropped += sta_lcore->pkt_dropped;
        sta->pkt_len_err += sta_lcore->pkt_len_err;

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

void netif_statsdata_reset(void) {
    unsigned lcore_id;
    struct netif_queue_stats *sta_lcore;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        sta_lcore = &kdns_net_device.l_netif_queue_conf[lcore_id].stats;
        sta_lcore->pkts_rcv = 0;
        sta_lcore->pkts_2kni = 0;
        sta_lcore->pkts_icmp = 0;
        sta_lcore->dns_pkts_rcv = 0;
        sta_lcore->dns_pkts_snd = 0;
        sta_lcore->dns_lens_rcv = 0;
        sta_lcore->dns_lens_snd = 0;
        sta_lcore->pkt_dropped = 0;
        sta_lcore->pkt_len_err = 0;
    }
    return;
}

void netif_statsdata_metrics_reset(void) {
    unsigned lcore_id;
    struct netif_queue_stats *sta_lcore;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        sta_lcore = &kdns_net_device.l_netif_queue_conf[lcore_id].stats;
        memset(&sta_lcore->metrics, 0, sizeof(metrics_metrics_st));
        sta_lcore->metrics.minTime = 0xffff;
    }
    return;
}

void init_dns_packet_header(struct ether_hdr *eth_hdr, struct ipv4_hdr *ipv4_hdr, struct udp_hdr *udp_hdr, uint16_t data_len) {
    uint16_t udp_data_len = sizeof(struct udp_hdr) + data_len;
    uint16_t ipv4_data_len = sizeof(struct ipv4_hdr) + udp_data_len;
    /*
     * Initialize ETHER header.
     */
    struct ether_addr tmp_mac;
    ether_addr_copy(&eth_hdr->d_addr, &tmp_mac);
    ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
    ether_addr_copy(&tmp_mac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    /*
     * Initialize IP header.
     */
    uint32_t src_addr = ipv4_hdr->src_addr;
    uint32_t dst_addr = ipv4_hdr->dst_addr;

    ipv4_hdr->version_ihl = IP_VHL_DEF;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = IP_DEFTTL;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->packet_id = 0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(ipv4_data_len);
    ipv4_hdr->src_addr = dst_addr;
    ipv4_hdr->dst_addr = src_addr;

    /*
     * Compute IP header checksum.
     */
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    /*
     * Initialize UDP header.
     */
    uint16_t src_port = udp_hdr->src_port;
    uint16_t dst_port = udp_hdr->dst_port;

    udp_hdr->src_port = dst_port;
    udp_hdr->dst_port = src_port;
    udp_hdr->dgram_len = rte_cpu_to_be_16(udp_data_len);
    udp_hdr->dgram_cksum = 0;   /* No UDP checksum. */
}
