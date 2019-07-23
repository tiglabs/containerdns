#ifndef _DNSNETDEV_H_
#define _DNSNETDEV_H_

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_mempool.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include "metrics.h"

#define NETIF_MAX_PKT_BURST     (32)

struct netif_queue_stats {
    uint64_t pkts_rcv;          /* Total number of receive packets */
    uint64_t pkts_2kni;         /* Total number of receive pkts to kni */
    uint64_t pkts_icmp;         /* Total number of receive pkts to kni */

    uint64_t dns_pkts_rcv;      /* Total number of successfully received packets. */
    uint64_t dns_pkts_snd;      /* Total number of successfully transmitted packets. */
    uint64_t pkt_dropped;       /* Total number of dropped packets by software. */
    uint64_t pkt_len_err;       /* pkt len err. */

    uint64_t dns_lens_rcv;      /* Total lens of  received packets. */
    uint64_t dns_lens_snd;      /* Total lens of  transmitted packets. */

    uint64_t dns_fwd_rcv_udp;   /* Total number of receive forward packets */
    uint64_t dns_fwd_snd_udp;   /* Total number of response forward packets */
    uint64_t dns_fwd_lost_udp;  /* Total number of lost response forward packets */

    uint64_t dns_fwd_rcv_tcp;
    uint64_t dns_fwd_snd_tcp;
    uint64_t dns_fwd_lost_tcp;
    uint64_t dns_pkts_rcv_tcp;
    uint64_t dns_pkts_snd_tcp;

    metrics_metrics_st metrics;
} __rte_cache_aligned;

/* RX/TX queue conf for lcore */
struct netif_queue_conf {
    uint16_t port_id;
    uint16_t rx_queue_id;
    uint16_t tx_queue_id;
    struct netif_queue_stats stats;
    uint16_t tx_len;
    struct rte_mbuf *tx_mbufs[NETIF_MAX_PKT_BURST];

    uint16_t kni_len;
    struct rte_mbuf *kni_mbufs[NETIF_MAX_PKT_BURST];
} __rte_cache_aligned;

struct net_device {
    uint16_t max_rx_queues;
    uint16_t max_tx_queues;
    uint16_t max_rx_desc;
    uint16_t max_tx_desc;
    struct ether_addr hwaddr;

    struct netif_queue_conf l_netif_queue_conf[RTE_MAX_LCORE];
};

int netdev_mode_parse(const char *entry);

struct netif_queue_conf *netif_queue_conf_get(uint16_t lcore_id);

int kdns_netdev_init(void);

void kni_egress(struct rte_mbuf **mbufs, uint16_t nb_mbufs);

int kni_ingress(struct rte_mbuf **mbufs, uint16_t nb_mbufs);

void netif_statsdata_get(struct netif_queue_stats *sta);

void netif_statsdata_reset(void);

void netif_statsdata_metrics_reset(void);

void init_dns_packet_header(struct ether_hdr *eth_hdr, struct ipv4_hdr *ipv4_hdr, struct udp_hdr *udp_hdr, uint16_t data_len);

#endif
