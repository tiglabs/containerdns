#ifndef _DNS_PROCESS_
#define _DNS_PROCESS_

#include <rte_mbuf.h>
#include "netdev.h"
#include "ctrl_msg.h"

int process_slave(__attribute__((unused)) void *arg);

int process_master(__attribute__((unused)) void *arg);

#endif
