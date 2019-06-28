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
#include "ctrl_msg.h"

#define PREFETCH_OFFSET     (3)

extern struct dns_config *g_dns_cfg;
extern struct rte_kni *master_kni;

void kni_msg_slave_process(ctrl_msg *msg, unsigned slave_lcore) {
    ctrl_mbufs_msg *mmsg = (ctrl_mbufs_msg *)msg;

    struct netif_queue_conf *conf = netif_queue_conf_get(slave_lcore);
    uint16_t cnts = rte_eth_tx_burst(conf->port_id, conf->tx_queue_id, mmsg->mbufs, mmsg->mbufs_cnts);
    if (unlikely(cnts < mmsg->mbufs_cnts)) {
        log_msg(LOG_ERR, "Failed to send %u pkt to tx_queue %u on slave_lcore %u\n", mmsg->mbufs_cnts - cnts, conf->tx_queue_id, slave_lcore);
        do {
            rte_pktmbuf_free(mmsg->mbufs[cnts]);
        } while (++cnts < mmsg->mbufs_cnts);
    }
    free(mmsg);
}

static void kni_msg_slave_ingress(struct rte_mbuf **mbufs, uint16_t rx_len) {
    uint16_t i;
    static unsigned kni_slave_lcore = 0;

    ctrl_mbufs_msg *msg = xalloc_zero(sizeof(ctrl_mbufs_msg));
    msg->cmsg.type = CTRL_MSG_TYPE_TO_TX;
    msg->cmsg.len = sizeof(ctrl_mbufs_msg);
    msg->mbufs_cnts = rx_len;
    for (i = 0; i < rx_len; ++i) {
        msg->mbufs[i] = mbufs[i];
    }

    kni_slave_lcore = rte_get_next_lcore(kni_slave_lcore, 1, 1);
    int s_cnt = ctrl_msg_slave_ingress((void **)&msg, 1, kni_slave_lcore);
    if (s_cnt != 1) {
        log_msg(LOG_ERR, "Failed to send %u pkt to tx msg to slave_lcore %u\n", rx_len, kni_slave_lcore);
        for (i = 0; i < rx_len; i++) {
            rte_pktmbuf_free(mbufs[i]);
        }
        free(msg);
    }
}

void kni_msg_master_process(ctrl_msg *msg) {
    ctrl_mbufs_msg *mmsg = (ctrl_mbufs_msg *)msg;

    uint16_t cnts = rte_kni_tx_burst(master_kni, mmsg->mbufs, mmsg->mbufs_cnts);
    if (unlikely(cnts < mmsg->mbufs_cnts)) {
        log_msg(LOG_ERR, "Failed to send %u pkt to kni\n", mmsg->mbufs_cnts - cnts);
        do {
            rte_pktmbuf_free(mmsg->mbufs[cnts]);
        } while (++cnts < mmsg->mbufs_cnts);
    }
    free(mmsg);
}

static void kni_msg_master_ingress(struct rte_mbuf **mbufs, uint16_t rx_len, struct netif_queue_conf *conf) {
    uint16_t i;

    ctrl_mbufs_msg *msg = xalloc_zero(sizeof(ctrl_mbufs_msg));
    msg->cmsg.type = CTRL_MSG_TYPE_TO_KNI;
    msg->cmsg.len = sizeof(ctrl_mbufs_msg);
    msg->mbufs_cnts = rx_len;
    for (i = 0; i < rx_len; ++i) {
        msg->mbufs[i] = mbufs[i];
    }

    int s_cnt = ctrl_msg_master_ingress((void **)&msg, 1);
    if (s_cnt != 1) {
        log_msg(LOG_ERR, "Failed to send %u pkt to kni msg\n", rx_len);
        conf->stats.pkt_dropped += (uint64_t)rx_len;
        for (i = 0; i < rx_len; i++) {
            rte_pktmbuf_free(mbufs[i]);
        }
        free(msg);
    } else {
        conf->stats.pkts_2kni += (uint64_t)rx_len;
    }
}

static int packet_process(struct rte_mbuf *pkt, struct netif_queue_conf *conf, unsigned lcore_id) {
    uint16_t ether_hdr_offset = sizeof(struct ether_hdr);
    uint16_t ip_hdr_offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr);
    uint16_t udp_hdr_offset = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr);

    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    struct ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, ether_hdr_offset);
    struct udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct udp_hdr *, ip_hdr_offset);

#ifdef ENABLE_KDNS_METRICS
    uint64_t start_time = time_now_usec();
#endif

    conf->stats.pkts_rcv++;
    if (unlikely(eth_hdr->ether_type != rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
        conf->kni_mbufs[conf->kni_len++] = pkt;
        return 0;
    }
    if (unlikely(rate_limit(ipv4_hdr->src_addr, RATE_LIMIT_TYPE_ALL, lcore_id) != 0)) {
        conf->stats.pkt_dropped++;
        rte_pktmbuf_free(pkt);
        return 0;
    }
    uint16_t ip_hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
    uint16_t ip_total_length = rte_be_to_cpu_16(ipv4_hdr->total_length);
    if (unlikely(ip_hdr_len != sizeof(struct ipv4_hdr) || ip_total_length < ip_hdr_len || pkt->pkt_len < (sizeof(struct ether_hdr) + ip_total_length))) {
        log_msg(LOG_ERR, "illegal pkt: pkt_len(%d), ip_hdr_len(%d), ip_total_length(%d)\n", pkt->pkt_len, ip_hdr_len, ip_total_length);
        conf->stats.pkt_len_err++;
        conf->stats.pkt_dropped++;
        rte_pktmbuf_free(pkt);
        return 0;
    }
    if (unlikely(ipv4_hdr->next_proto_id != IPPROTO_UDP || udp_hdr->dst_port != UDP_PORT_53)) {
        conf->kni_mbufs[conf->kni_len++] = pkt;
        return 0;
    }

    conf->stats.dns_pkts_rcv++;
    conf->stats.dns_lens_rcv += pkt->pkt_len;

    uint16_t udp_dgram_len = rte_be_to_cpu_16(udp_hdr->dgram_len);
    int query_len = udp_dgram_len - sizeof(struct udp_hdr);
    if (unlikely((ip_total_length != (sizeof(struct ipv4_hdr) + udp_dgram_len) || query_len < DNS_HEAD_SIZE))) {
        log_msg(LOG_ERR, "illegal pkt: ip_total_length(%d), udp_dgram_len(%d), query_len(%d)\n", ip_total_length, udp_dgram_len, query_len);
        conf->stats.pkt_len_err++;
        conf->stats.pkt_dropped++;
        rte_pktmbuf_free(pkt);
        return 0;
    }

    uint8_t *query_data = rte_pktmbuf_mtod_offset(pkt, uint8_t *, udp_hdr_offset);
    uint16_t old_flag = *(((uint16_t *)query_data) + 1);

    kdns_query_st *query = dns_packet_proess(ipv4_hdr->src_addr, query_data, query_len, lcore_id);
    if (unlikely(GET_RCODE(query->packet) == RCODE_REFUSE)) {
        if (unlikely(rate_limit(ipv4_hdr->src_addr, RATE_LIMIT_TYPE_FWD, lcore_id) != 0)) {
            conf->stats.pkt_dropped++;
            rte_pktmbuf_free(pkt);
            return 0;
        }

        *(((uint16_t *)query_data) + 1) = old_flag;
        fwd_query_enqueue(pkt, ipv4_hdr->src_addr, GET_ID(query->packet), query->qtype, (char *)domain_name_to_string(query->qname, NULL));
        return 0;
    }

    int ret_len = buffer_remaining(query->packet);
    if (likely(ret_len > 0)) {
        init_dns_packet_header(eth_hdr, ipv4_hdr, udp_hdr, ret_len);
        pkt->pkt_len = ret_len + udp_hdr_offset;
        pkt->data_len = pkt->pkt_len;
        pkt->l2_len = sizeof(struct ether_hdr);
        pkt->vlan_tci = ETHER_TYPE_IPv4;
        pkt->l3_len = sizeof(struct ipv4_hdr);

        conf->tx_mbufs[conf->tx_len++] = pkt;
        conf->stats.dns_lens_snd += pkt->pkt_len;
    } else {
        log_msg(LOG_ERR, "failed deal dns packet, ret %d\n", ret_len);
        conf->stats.pkt_dropped++;
        rte_pktmbuf_free(pkt);
        return 0;
    }

#ifdef ENABLE_KDNS_METRICS
    metrics_data_update(&conf->stats.metrics, time_now_usec() - start_time);
#endif
    return 0;
}

int process_slave(__attribute__((unused)) void *arg) {
    int i;
    uint16_t rx_count, cp_count = 0;
    uint64_t now_tsc, prev_tsc, intvl_tsc;
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST];
    unsigned lcore_id = rte_lcore_id();

    now_tsc = rte_rdtsc();
    prev_tsc = now_tsc;
    intvl_tsc = rte_get_timer_hz() / 1000;  //1ms

    kdns_init(lcore_id);
    rate_limit_init(lcore_id);

    struct netif_queue_conf *conf = netif_queue_conf_get(lcore_id);
    log_msg(LOG_INFO, "Starting core %u conf: rx=%d, tx=%d\n", lcore_id, conf->rx_queue_id, conf->tx_queue_id);
    while (1) {
        now_tsc = rte_rdtsc();
        if (cp_count || now_tsc - prev_tsc > intvl_tsc) {
            prev_tsc = now_tsc;
            config_reload_pre_core(lcore_id);
            cp_count = ctrl_msg_slave_process(lcore_id);
        }

        rx_count = rte_eth_rx_burst(conf->port_id, conf->rx_queue_id, mbufs, NETIF_MAX_PKT_BURST);
        if (unlikely(rx_count == 0)) {
            continue;
        }

        conf->tx_len = 0;
        conf->kni_len = 0;

        /* Prefetch PREFETCH_OFFSET packets */
        for (i = 0; i < PREFETCH_OFFSET && i < rx_count; i++) {
            rte_prefetch0(rte_pktmbuf_mtod(mbufs[i], void *));
        }

        /* Prefetch and Deal already prefetched packets. */
        for (i = 0; i < (rx_count - PREFETCH_OFFSET); i++) {
            rte_prefetch0(rte_pktmbuf_mtod(mbufs[i + PREFETCH_OFFSET], void *));
            packet_process(mbufs[i], conf, lcore_id);
        }

        /* Deal remaining prefetched packets */
        for (; i < rx_count; i++) {
            packet_process(mbufs[i], conf, lcore_id);
        }

        // send the pkts
        if (likely(conf->tx_len > 0)) {
            int ntx = rte_eth_tx_burst(conf->port_id, conf->tx_queue_id, conf->tx_mbufs, conf->tx_len);
            conf->stats.dns_pkts_snd += ntx;
            if (unlikely(ntx != conf->tx_len)) {
                log_msg(LOG_ERR, "rx=%d tx=%d real tx=%d\n", rx_count, conf->tx_len, ntx);
                int i = 0;
                for (i = ntx; i < conf->tx_len; i++) {
                    rte_pktmbuf_free(conf->tx_mbufs[i]);
                }
                conf->stats.pkt_dropped += ntx;
            }
        }
        // snd to master
        if (unlikely(conf->kni_len > 0)) {
            kni_msg_master_ingress(conf->kni_mbufs, conf->kni_len, conf);
        }
    }
    return 0;
}

//set master's affinity to master core
static int reset_master_affinity(void) {
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

int process_master(__attribute__((unused)) void *arg) {
    unsigned lcore_id = rte_lcore_id();

    domain_info_master_init();
    view_master_init();

    domian_info_exchange_run(g_dns_cfg->comm.web_port);

    reset_master_affinity();
    log_msg(LOG_INFO, "Starting master on core %u\n", lcore_id);
    while (1) {
        config_reload_pre_core(lcore_id);
        ctrl_msg_master_process();

        rte_kni_handle_request(master_kni);

        struct rte_mbuf *kni_pkts_tx[NETIF_MAX_PKT_BURST];
        uint16_t npkts = rte_kni_rx_burst(master_kni, kni_pkts_tx, NETIF_MAX_PKT_BURST);
        if (npkts > 0) {
            kni_msg_slave_ingress(kni_pkts_tx, (uint16_t)npkts);
        }

        //fwd
        struct rte_mbuf *fwd_pkts_tx[NETIF_MAX_PKT_BURST];
        unsigned fwd_count = fwd_response_dequeue(fwd_pkts_tx, NETIF_MAX_PKT_BURST);
        if (fwd_count != 0) {
            uint16_t nb_tx = rte_eth_tx_burst(0, 0, fwd_pkts_tx, (uint16_t)fwd_count);
            if (unlikely(nb_tx < fwd_count)) {
                uint16_t i = 0;
                for (i = nb_tx; i < fwd_count; i++) {
                    rte_pktmbuf_free(fwd_pkts_tx[i]);
                }
            }
        }
    }

    return 0;
}


