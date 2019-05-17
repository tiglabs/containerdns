#ifndef _LOCAL_UDP_PROCESS_H_
#define _LOCAL_UDP_PROCESS_H_

#include <arpa/inet.h>
#include "db_update.h"

int local_udp_process_init(char *ip);

int local_udp_domian_databd_update(struct domin_info_update *update);

#endif  /* _LOCAL_UDP_PROCESS_H_ */

