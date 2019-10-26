#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <unistd.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_pdump.h>

#include <signal.h>

#include "process.h"
#include "netdev.h"
#include "kdns-adap.h"
#include "dns-conf.h"
#include "util.h"
#include "forward.h"
#include "tcp_process.h"
#include "local_udp_process.h"
#include "domain_update.h"
#include "ctrl_msg.h"

#define VERSION "0.2.1"
#define DEFAULT_CONF_FILEPATH "/etc/kdns/kdns.cfg"
#define PIDFILE "/var/run/kdns.pid"

int dns_reload;
char *dns_cfgfile;
char *dns_procname;

static char *parse_progname(char *arg) {
    char *p;
    if ((p = strrchr(arg, '/')) != NULL) {
        return strdup(p + 1);
    }
    return strdup(arg);
}

static void parse_args(int argc, char *argv[]) {
    int i;
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--conf=", 7) == 0) {
            dns_cfgfile = strdup(argv[i] + 7);
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("Version: %s\n", VERSION);
            exit(0);
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("usage: [--conf=%s] [--version] [--help]\n", DEFAULT_CONF_FILEPATH);
            exit(0);
        } else {
            printf("usage: [--conf=%s] [--version] [--help]\n", DEFAULT_CONF_FILEPATH);
            exit(0);
        }
    }
    if (!dns_cfgfile) {
        dns_cfgfile = strdup(DEFAULT_CONF_FILEPATH);
    }
}

static void signal_handler(int sig) {
    switch (sig) {
    case SIGQUIT:
        //log_msg(LOG_ERR, "QUIT signal @@@.");
        break;
    case SIGTERM:
        //log_msg(LOG_ERR, "TERM signal @@@.");
        break;
    case SIGINT:
        //log_msg(LOG_ERR, "INT signal @@@.");
        break;
    case SIGHUP:
        //log_msg(LOG_INFO, "Program hanged up @@@.");
        dns_reload = 1;
        return;
    case SIGPIPE:
        //log_msg(LOG_ERR, "SIGPIPE @@@.");
        break;
    case SIGCHLD:
        //log_msg(LOG_ERR, "SIGCHLD @@@.");
        break;
    case SIGUSR1:
        //log_msg(LOG_ERR, "SIGUSR1 @@@.");
        break;
    case SIGUSR2:
        //log_msg(LOG_ERR, "SIGUSR2 @@@.");
        break;
    case SIGURG:
        //log_msg(LOG_ERR, "SIGURG @@@.");
        break;
    default:
        //log_msg(LOG_ERR, "Unknown signal(%d) ended program!", sig);
        break;
    }
    rte_pdump_uninit();
}

static void init_signals(void) {
    struct sigaction sigact;
    sigact.sa_handler = signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGQUIT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGHUP, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
    sigaction(SIGCHLD, &sigact, NULL);
    sigaction(SIGURG, &sigact, NULL);
    sigaction(SIGUSR1, &sigact, NULL);
    sigaction(SIGUSR2, &sigact, NULL);
}

//set thread's affinity to cpus that are not used by dpdk
static int set_thread_affinity(void) {
    int s;
    uint8_t cid;
    pthread_t tid;
    cpu_set_t cpuset;
    unsigned long long cpumask = 0;

    tid = pthread_self();
    CPU_ZERO(&cpuset);
    for (cid = 0; cid < RTE_MAX_LCORE; ++cid) {
        if (!rte_lcore_is_enabled(cid)) {
            CPU_SET(cid, &cpuset);
        }
    }

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

    for (cid = 0; cid < RTE_MAX_LCORE; cid++) {
        if (CPU_ISSET(cid, &cpuset)) {
            cpumask |= (1LL << cid);
        }
    }
    log_msg(LOG_INFO, "current thread affinity is set to %llX\n", cpumask);

    return 0;
}

int main(int argc, char **argv) {
    int i;
    char *dpdk_argv[DPDK_MAX_ARG_NUM];

    if (check_pid(PIDFILE) < 0) {
        exit(0);
    }
    write_pid(PIDFILE);

    parse_args(argc, argv);
    dns_procname = parse_progname(argv[0]);
    dns_config_load(dns_cfgfile, dns_procname);

    for (i = 0; i < g_dns_cfg->eal.argc; i++) {
        dpdk_argv[i] = strdup(g_dns_cfg->eal.argv[i]);
    }
    if (rte_eal_init(g_dns_cfg->eal.argc, dpdk_argv) < 0) {
        log_msg(LOG_ERR, "EAL init failed.\n");
        exit(-1);
    }
    kdns_netdev_init();

    if (set_thread_affinity() != 0) {
        log_msg(LOG_ERR, "set_thread_affinity failed\n");
        exit(EXIT_FAILURE);
    }

    // struct sigaction action;
    /* Setup the signal handling... */
    init_signals();
    rte_pdump_init("/var/run/.dpdk");

    ctrl_msg_init();
    fwd_server_init();
    tcp_process_init();
    local_udp_process_init();

    unsigned lcore_id;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_remote_launch(process_slave, NULL, lcore_id);
    }

    process_master(NULL);

    rte_eal_mp_wait_lcore();
    return 0;
}
