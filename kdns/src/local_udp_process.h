#ifndef _LOCAL_UDP_PROCESS_H_
#define _LOCAL_UDP_PROCESS_H_

#include <arpa/inet.h>
#include "db_update.h"

int local_udp_process_init(void);

int local_udp_domian_databd_update(struct domin_info_update *update);

int local_udp_zones_reload(char *del_zones, char *add_zones);

#endif  /* _LOCAL_UDP_PROCESS_H_ */

