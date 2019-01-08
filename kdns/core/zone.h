/*
 * zone.h -- zone compiler.
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#ifndef _ZONEC_H_
#define _ZONEC_H_

#include "domain_store.h"

#define	MAXTOKENSLEN	512		/* Maximum number of tokens per entry */
#define	B64BUFSIZE	65535		/* Buffer size for b64 conversion */
#define	ROOT		(const uint8_t *)"\001"

#define NSEC_WINDOW_COUNT     256
#define NSEC_WINDOW_BITS_COUNT 256
#define NSEC_WINDOW_BITS_SIZE  (NSEC_WINDOW_BITS_COUNT / 8)

#define IPSECKEY_NOGATEWAY      0       /* RFC 4025 */
#define IPSECKEY_IP4            1
#define IPSECKEY_IP6            2
#define IPSECKEY_DNAME          3

#define LINEBUFSZ 1024
#define ZONES_STR_LEN (1024)

struct lexdata {
    size_t   len;		/* holds the label length */
    char    *str;		/* holds the data */
};

#define DEFAULT_TTL 3600

 int
zrdatacmp(uint16_t type, rr_type *a, rr_type *b);



uint16_t *zparser_conv_serial( const char *periodstr);

uint16_t *zparser_conv_short( const char *text);

uint16_t *zparser_conv_a( const char *text);

uint16_t *alloc_rdata_init( const void *data, size_t size);

void domain_store_zones_check_delete(struct kdns* kdns, char* zones);
void domain_store_zones_check_create(struct kdns* kdns, char *zones);
#endif /* _ZONEC_H_ */
