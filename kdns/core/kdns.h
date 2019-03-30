/*
 *  kdns.h --  kdns(8) definitions and prototypes
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#ifndef	_NSD_H_
#define	_NSD_H_

#include "dns.h"

#define MAX_CORES 64

#define DEFAULT_VIEW_NAME "no_info"
#define MAX_VIEW_NAME_LEN 32
#define VIEW_MATCH_DEF   0
#define VIEW_MATCH_NAME  1
#define VIEW_MATCH_NONE  2
// max match 128 rrs
#define VIEW_MATCH_MAX_NUM  1024

/*  configuration and run-time variables */
typedef struct kdns kdns_type;
struct	kdns
{
	struct  domain_store	*db;
    /*
    uint16_t *compressed_domain_name_offsets ;
    uint32_t compression_tablecapacity ;
    uint32_t compression_table_size  ;
    */
};


/* extra domain numbers for temporary domains */
#define EXTRA_DOMAIN_NUMBERS 2048000  
#define EDNS_MAX_MESSAGE_LEN 4096
#define UDP_PORT "53"
#define UDP_MAX_MESSAGE_LEN 512
#define TCP_MAX_MESSAGE_LEN 65535


#endif	/* _NSD_H_ */
