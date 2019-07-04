/*
 * domain_store.h -- internal namespace database definitions
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */
#ifndef _DOMAIN_STORE_H_
#define	_DOMAIN_STORE_H_

#include <stdio.h>
#include "dns.h"
#include "kdns.h"

#include "radtree.h"

struct kdns;

typedef struct domain
{

	struct radnode* rnode;
	domain_name_st* dname;
	struct domain* parent;
	struct domain* wildcard_child_closest_match;
	struct rrset * rrsets;
	size_t     usage;     
    uint16_t    compressed_offset;
    uint32_t maxAnswer;
	unsigned     is_existing : 1;
	unsigned     is_apex : 1;
}domain_type;

typedef struct zone
{
	struct radnode *node; 
	struct domain  * apex;
	struct rrset   * soa_rrset;
	struct rrset*  soa_nx_rrset; 
	struct rrset*  ns_rrset;

	unsigned     zonestatid; /* array index for zone stats */
	unsigned     is_ok : 1; /* zone has not expired. */
	unsigned     is_changed : 1; /* zone was changed by AXFR */
}zone_type;

/* a RR in DNS */
typedef struct rr {
	struct domain *     owner;
	union rdata_atom* rdatas;
	char  view_name[MAX_VIEW_NAME_LEN];
	uint32_t         ttl;
	uint16_t         type;
	uint16_t         klass;
	uint16_t         rdata_count;
	
	uint16_t         lb_mode;
	uint16_t         lb_weight;
	uint16_t         lb_weight_cur;
}rr_type;

/*
 * An RRset consists of at least one RR.  All RRs are from the same
 * zone.
 */
typedef struct rrset
{
	struct rrset* next;
	struct zone*  zone;
	struct rr*    rrs;
	uint16_t    rr_count;
}rrset_type;

typedef union rdata_atom
{
	domain_type* domain;

	/* Default. */
	uint16_t*    data;
}rdata_atom_type;

typedef struct domain_table
{
    struct radtree *nametree;
	struct domain* root;
    size_t     number_total; 
}domain_table_type;


typedef struct  domain_store
{
	struct domain_table* domains;
	struct radtree*    zonetree;
	struct view_tree* viewtree;
}domain_store_type;


/*
 * Create a new domain_table containing only the root domain.
 */
domain_table_type *domain_table_create(void);

/*
 * Search the domain table for a match and the closest encloser.
 */
int domain_table_search(domain_table_type* table,
			const domain_name_st* dname,
			domain_type      **closest_match,
			domain_type      **closest_encloser);

/*
 * The number of domains stored in the table (minimum is one for the
 * root domain).
 */
static inline uint32_t
domain_table_count(domain_table_type* table)
{
	return table->nametree->count;
}

void rrset_lower_usage(domain_store_type* db, rrset_type* rrset);
void rrset_delete(domain_store_type* db, domain_type* domain, rrset_type* rrset);
void rr_lower_usage(domain_store_type* db, rr_type* rr);
void add_rdata_to_recyclebin( rr_type* rr);
domain_type* rrset_zero_nonexist_check(domain_type* domain, domain_type* ce);


/*
 * Find the specified dname in the domain_table.  NULL is returned if
 * there is no exact match.
 */
domain_type* domain_table_find(domain_table_type* table,
			       const domain_name_st* dname);

/*
 * Insert a domain name in the domain table.  If the domain name is
 * not yet present in the table it is copied and a new domain_name_info node
 * is created (as well as for the missing parent domain names, if
 * any).  Otherwise the domain_type that is already in the
 * domain_table is returned.
 */
domain_type *domain_table_insert(domain_table_type *table,
				 const domain_name_st  *dname,uint32_t maxAnswer);

/*
 * Add an RRset to the specified domain.  Updates the is_existing flag
 * as required.
 */
void domain_add_rrset(domain_type* domain, rrset_type* rrset);

rrset_type* domain_find_rrset(domain_type* domain, zone_type* zone, uint16_t type);
rrset_type* domain_find_any_rrset(domain_type* domain, zone_type* zone);

zone_type* domain_find_zone(domain_store_type* db, domain_type* domain);

/* find DNAME rrset in domain->parent or higher and return that domain */
domain_type * find_domain_name_above(domain_type* domain, zone_type* zone);

domain_type* domain_wildcard_child(domain_type* domain);
domain_type *domain_previous_existing_child(domain_type* domain);


static inline domain_name_st *
domain_dname(domain_type* domain)
{
	return (domain_name_st *) domain->dname;
}


static inline domain_type *
domain_previous(domain_type* domain)
{
   struct radnode* prev = radix_prev(domain->rnode);
   return prev == NULL ? NULL : (domain_type*)prev->elem;
}

static inline domain_type *
domain_next(domain_type* domain)
{
    struct radnode* next = radix_next(domain->rnode);
    return next == NULL ? NULL : (domain_type*)next->elem;
}

/* easy comparison for subdomain, true if d1 is subdomain of d2. */
static inline int domain_is_subdomain(domain_type* d1, domain_type* d2)
{ return domain_name_is_subdomain(domain_dname(d1), domain_dname(d2)); }
/* easy printout, to static buffer of domain_name_to_string, fqdn. */
static inline const char* domain_to_string(domain_type* domain)
{ return domain_name_to_string(domain_dname(domain), NULL); }


static inline int rdata_atom_is_domain(uint16_t type, size_t index);
static inline int rdata_atom_is_literal_domain(uint16_t type, size_t index);

static inline domain_type *
rdata_atom_domain(rdata_atom_type atom)
{
	return atom.domain;
}

static inline uint16_t
rdata_atom_size(rdata_atom_type atom)
{
	return *atom.data;
}

static inline uint8_t *
rdata_atomdata(rdata_atom_type atom)
{
	return (uint8_t *) (atom.data + 1);
}


/* Find the zone for the specified dname in DB. */
zone_type *domain_store_find_zone(domain_store_type *db, const domain_name_st *dname);
/*
 * Delete a domain name from the domain table.  Removes domain_name_info node.
 * Only deletes if usage is 0, has no rrsets and no children.  Checks parents
 * for deletion as well.  Adjusts numberlist(domain.number), and 
 * wcard_child closest match.
 */
void domain_table_deldomain(domain_store_type* db, domain_type* domain);


/** marshal rdata into buffer, must be MAX_RDLENGTH in size */
size_t rr_marshal_rdata(rr_type* rr, uint8_t* rdata, size_t sz);
/* dbaccess.c */
int domain_store_lookup (struct  domain_store* db,
		   const domain_name_st* dname,
		   domain_type     **closest_match,
		   domain_type     **closest_encloser);
/* pass number of children (to alloc in dirty array */
struct  domain_store *domain_store_open(void);
void domain_store_close(struct  domain_store* db);

/** zone one zonefile into memory and revert on parse error, write to udb */
void domain_store_read_zonefile(struct kdns*  kdns, struct zone* zone);
void apex_rrset_checks(rrset_type* rrset,domain_type* domain);
zone_type* domain_store_zone_create(domain_store_type* db, const domain_name_st* dname);
void domain_store_zone_delete(domain_store_type* db, zone_type* zone);

static inline int
rdata_atom_is_domain(uint16_t type, size_t index)
{
	const rrtype_descriptor_st *descriptor
		= rrtype_descriptor_by_type(type);
	return (index < descriptor->maximum
		&& (descriptor->wireformat[index] == RDATA_WF_COMPRESSED_DNAME
		    || descriptor->wireformat[index] == RDATA_WF_UNCOMPRESSED_DNAME));
}

static inline int
rdata_atom_is_literal_domain(uint16_t type, size_t index)
{
	const rrtype_descriptor_st *descriptor
		= rrtype_descriptor_by_type(type);
	return (index < descriptor->maximum
		&& (descriptor->wireformat[index] == RDATA_WF_LITERAL_DNAME));
}

static inline rdata_wireformat_type
rdata_atom_wireformat_type(uint16_t type, size_t index)
{
	const rrtype_descriptor_st *descriptor
		= rrtype_descriptor_by_type(type);
	assert(index < descriptor->maximum);
	return (rdata_wireformat_type) descriptor->wireformat[index];
}

static inline uint16_t
rrset_rrtype(rrset_type* rrset)
{
	assert(rrset);
	assert(rrset->rr_count > 0);
	return rrset->rrs[0].type;
}

static inline uint16_t
rrset_rrclass(rrset_type* rrset)
{
	assert(rrset);
	assert(rrset->rr_count > 0);
	return rrset->rrs[0].klass;
}

#endif
