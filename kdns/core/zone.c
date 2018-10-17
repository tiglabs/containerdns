/*
 * zone.c -- zone compiler.
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "zone.h"
#include "dns.h"
#include "kdns.h"
#include "domain_store.h"


uint16_t *
alloc_rdata_init( const void *data, size_t size)
{
	uint16_t *result = xalloc( sizeof(uint16_t) + size);
	*result = size;
	memcpy(result + 1, data, size);
	return result;
}


uint16_t *
zparser_conv_serial( const char *serialstr)
{
	uint16_t *r = NULL;
	uint32_t serial;
	const char *t;

	serial = strtoserial(serialstr, &t);
	if (*t != '\0') {
		log_msg(LOG_ERR,"serial is expected or serial too big");
	} else {
		serial = htonl(serial);
		r = alloc_rdata_init( &serial, sizeof(serial));
	}
	return r;
}

uint16_t *
zparser_conv_short( const char *text)
{
	uint16_t *r = NULL;
	uint16_t value;
	char *end;

	value = htons((uint16_t) strtol(text, &end, 10));
	if (*end != '\0') {
		log_msg(LOG_ERR,"integer value is expected");
	} else {
		r = alloc_rdata_init( &value, sizeof(value));
	}
	return r;
}

uint16_t *
zparser_conv_a( const char *text)
{
	in_addr_t address;
	uint16_t *r = NULL;

	if (inet_pton(AF_INET, text, &address) != 1) {
		log_msg(LOG_ERR,"invalid IPv4 address '%s'", text);
	} else {
		r = alloc_rdata_init( &address, sizeof(address));
	}
	return r;
}


 int
zrdatacmp(uint16_t type, rr_type *a, rr_type *b)
{
	int i = 0;

	assert(a);
	assert(b);

	/* One is shorter than another */
	if (a->rdata_count != b->rdata_count)
		return 1;

	/* Compare element by element */
	for (i = 0; i < a->rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			if (rdata_atom_domain(a->rdatas[i])
			    != rdata_atom_domain(b->rdatas[i]))
			{
				return 1;
			}
		} else if(rdata_atom_is_literal_domain(type, i)) {
			if (rdata_atom_size(a->rdatas[i])
			    != rdata_atom_size(b->rdatas[i]))
				return 1;
			if (!domain_name_equal_nocase(rdata_atomdata(a->rdatas[i]),
				   rdata_atomdata(b->rdatas[i]),
				   rdata_atom_size(a->rdatas[i])))
				return 1;
		} else {
			if (rdata_atom_size(a->rdatas[i])
			    != rdata_atom_size(b->rdatas[i]))
			{
				return 1;
			}
			if (memcmp(rdata_atomdata(a->rdatas[i]),
				   rdata_atomdata(b->rdatas[i]),
				   rdata_atom_size(a->rdatas[i])) != 0)
			{
				return 1;
			}
		}
	}

	/* Otherwise they are equal */
	return 0;
}


/** create a zone */
zone_type*
domain_store_zone_create(domain_store_type* db, const domain_name_st* dname)
{
	zone_type* zone = (zone_type *) xalloc(
		sizeof(zone_type));
	zone->node = radomain_name_insert(db->zonetree, domain_name_get(dname),
		dname->name_size, zone);
	assert(zone->node);
	zone->apex = domain_table_insert(db->domains, dname,0);
	zone->apex->usage++; 
	zone->apex->is_apex = 1;
	zone->soa_rrset = NULL;
	zone->soa_nx_rrset = NULL;
	zone->ns_rrset = NULL;
	zone->zonestatid = 0;
	zone->is_changed = 0;
	zone->is_ok = 1;
	return zone;
}

void
domain_store_zone_delete(domain_store_type* db, zone_type* zone)
{
	/* RRs and UDB and NSEC3 and so on must be already deleted */
	radix_delete(db->zonetree, zone->node);

	/* see if apex can be deleted */
	if(zone->apex) {
		zone->apex->usage --;
		zone->apex->is_apex = 0;
		if(zone->apex->usage == 0) {
			/* delete the apex, possibly */
			domain_table_deldomain(db, zone->apex);
		}
	}

	/* soa_rrset is freed when the SOA was deleted */
	if(zone->soa_nx_rrset) {
		free(zone->soa_nx_rrset->rrs);
		free( zone->soa_nx_rrset);
	}
	free(zone);
}


void domain_store_zones_check_create(struct kdns*  kdns, char* zones)
{
    char zoneTmp[1024] = {0};
    char* name ;
    memcpy(zoneTmp,zones, strlen(zones));
    log_msg(LOG_INFO,"zones: %s\n",zones);
    name = strtok(zoneTmp, ",");
    while (name)
    { 
        const domain_name_st* dname = (const domain_name_st*)domain_name_parse(name);
    	/* find zone to go with it, or create it */
    	zone_type*  zone = domain_store_find_zone( kdns->db, dname);
    	if(!zone) {
    		zone = domain_store_zone_create( kdns->db, dname);
    	}
        name = strtok(0, ","); 
    }
    return;
}


/** add an rdata (uncompressed) to the destination */
static size_t
add_rdata(rr_type* rr, unsigned i, uint8_t* buf, size_t buflen)
{
	switch(rdata_atom_wireformat_type(rr->type, i)) {
		case RDATA_WF_COMPRESSED_DNAME:
		case RDATA_WF_UNCOMPRESSED_DNAME:
		{
			const domain_name_st* dname = domain_dname(
				rdata_atom_domain(rr->rdatas[i]));
			if(dname->name_size > buflen)
				return 0;
			memmove(buf, domain_name_get(dname), dname->name_size);
			return dname->name_size;
		}
		default:
			break;
	}
	if(rdata_atom_size(rr->rdatas[i]) > buflen)
		return 0;
	memmove(buf, rdata_atomdata(rr->rdatas[i]),
		rdata_atom_size(rr->rdatas[i]));
	return rdata_atom_size(rr->rdatas[i]);
}

/* marshal rdata into buffer, must be MAX_RDLENGTH in size */
size_t
rr_marshal_rdata(rr_type* rr, uint8_t* rdata, size_t sz)
{
	size_t len = 0;
	unsigned i;
	assert(rr);
	for(i=0; i<rr->rdata_count; i++) {
		len += add_rdata(rr, i, rdata+len, sz-len);
	}
	return len;
}


