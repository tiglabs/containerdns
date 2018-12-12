/*
 * domain_store.c
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 * 
 */

#include <sys/types.h>
#include <netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "domain_store.h"

static domain_type *
allocate_domain_info(domain_table_type* table,
		     const domain_name_st* dname,
		     domain_type* parent)
{
	
	domain_type *d;

	d = (domain_type *) xalloc(sizeof(domain_type));
        d->dname = (domain_name_st*) domain_name_partial_copy(dname, domain_dname(parent)->label_count + 1);
	d->parent = parent;
	d->wildcard_child_closest_match = d;
	d->rrsets = NULL;
	d->usage = 0;
	d->is_existing = 0;
	d->is_apex = 0;
    d->compressed_offset =0;
    table->number_total++;
	return d;
}

/** see if a domain is eligible to be deleted, and thus is not used */
static int
domain_can_be_deleted(domain_type* domain)
{
	domain_type* n;
	/* it has data or it has usage, do not delete it */
	if(domain->rrsets) return 0;
	if(domain->usage) return 0;
	n = domain_next(domain);
	/* it has children domains, do not delete it */
	if(n && domain_is_subdomain(n, domain))
		return 0;
	return 1;
}


/** perform domain name deletion */
static void
do_deldomain(domain_store_type* db, domain_type* domain)
{
	assert(domain && domain->parent); /* exists and not root */

	/* see if this domain is someones wildcard-child-closest-match,
	 * which can only be the parent, and then it should use the
	 * one-smaller than this domain as closest-match. */
	if(domain->parent->wildcard_child_closest_match == domain)
		domain->parent->wildcard_child_closest_match =
			domain_previous_existing_child(domain);

    radix_delete(db->domains->nametree, domain->rnode);
    db->domains->number_total--;
    free(domain_dname(domain));
    free(domain);
}

void
domain_table_deldomain(domain_store_type* db, domain_type* domain)
{
    while(domain_can_be_deleted(domain)) {
		/* save parent */
		domain_type * domain_temp = domain->parent;
		/* delete it */
		do_deldomain(db, domain);
		/* test parent in next loop */
		domain = domain_temp;
	}
}


void
add_rdata_to_recyclebin(rr_type* rr)
{
	/* add rdatas to recycle bin. */
	size_t i;
	for(i=0; i<rr->rdata_count; i++)
	{
		if(!rdata_atom_is_domain(rr->type, i))
            free(rr->rdatas[i].data);
	}
	free(rr->rdatas);
}

/* this routine determines if below a domain there exist names with
 * data (is_existing) or no names below the domain have data.
 */
static int
hasdata_below(domain_type* top)
{
	domain_type* d = top;
	assert(d != NULL);
	/* in the canonical ordering subdomains are after this name */
	d = domain_next(d);
	while(d != NULL && domain_is_subdomain(d, top)) {
		if(d->is_existing)
			return 1;
		d = domain_next(d);
	}
	return 0;
}

void
apex_rrset_checks( rrset_type* rrset, domain_type* domain)
{
	uint32_t soa_minimum;
	zone_type* zone = rrset->zone;
	assert(domain == zone->apex);
	(void)domain;
	if (rrset_rrtype(rrset) == TYPE_SOA) {
		zone->soa_rrset = rrset;

		if(zone->soa_nx_rrset == 0) {
			zone->soa_nx_rrset = xalloc(
				sizeof(rrset_type));
			zone->soa_nx_rrset->rr_count = 1;
			zone->soa_nx_rrset->next = 0;
			zone->soa_nx_rrset->zone = zone;
			zone->soa_nx_rrset->rrs = xalloc(sizeof(rr_type));
		}
		memcpy(zone->soa_nx_rrset->rrs, rrset->rrs, sizeof(rr_type));

		memcpy(&soa_minimum, rdata_atomdata(rrset->rrs->rdatas[6]),
				rdata_atom_size(rrset->rrs->rdatas[6]));
		if (rrset->rrs->ttl > ntohl(soa_minimum)) {
			zone->soa_nx_rrset->rrs[0].ttl = ntohl(soa_minimum);
		}
	} 
}


/** check if domain with 0 rrsets has become empty (nonexist) */
domain_type*
rrset_zero_nonexist_check(domain_type* domain, domain_type* ce)
{
	/* is the node now an empty node (completely deleted) */
	if(domain->rrsets == 0) {
		/* if there is no data below it, it becomes non existing.
		   also empty nonterminals above it become nonexisting */
		/* check for data below this node. */
		if(!hasdata_below(domain)) {
			/* nonexist this domain and all parent empty nonterminals */
			domain_type* p = domain;
			while(p != NULL && p->rrsets == 0) {
				if(p == ce || hasdata_below(p))
					return p;
				p->is_existing = 0;
				/* fixup wildcard child of parent */
				if(p->parent &&
					p->parent->wildcard_child_closest_match == p)
					p->parent->wildcard_child_closest_match = domain_previous_existing_child(p);
				p = p->parent;
			}
		}
	}
	return NULL;
}

/** remove rrset.  Adjusts zone params.  Does not remove domain */
void
rrset_delete(domain_store_type* db, domain_type* domain, rrset_type* rrset)
{
	int i;
	/* find previous */
	rrset_type** pp = &domain->rrsets;
	while(*pp && *pp != rrset) {
		pp = &( (*pp)->next );
	}
	if(!*pp) {
		/* rrset does not exist for domain */
		return;
	}
	*pp = rrset->next;

	/* is this a SOA rrset ? */
	if(rrset->zone->soa_rrset == rrset) {
		rrset->zone->soa_rrset = 0;
	}
	if(rrset->zone->ns_rrset == rrset) {
		rrset->zone->ns_rrset = 0;
	}
	/* recycle the memory space of the rrset */
	for (i = 0; i < rrset->rr_count; ++i)
		add_rdata_to_recyclebin( &rrset->rrs[i]);
    free(rrset->rrs);
    free(rrset);
}


/* fixup usage lower for domain names in the rdata */
void
rr_lower_usage(domain_store_type* db, rr_type* rr)
{
	unsigned i;
	for(i=0; i<rr->rdata_count; i++) {
		if(rdata_atom_is_domain(rr->type, i)) {
			assert(rdata_atom_domain(rr->rdatas[i])->usage > 0);
			rdata_atom_domain(rr->rdatas[i])->usage --;
			if(rdata_atom_domain(rr->rdatas[i])->usage == 0)
				domain_table_deldomain(db,
					rdata_atom_domain(rr->rdatas[i]));
		}
	}
}

void
rrset_lower_usage(domain_store_type* db, rrset_type* rrset)
{
	unsigned i;
	for(i=0; i<rrset->rr_count; i++)
		rr_lower_usage(db, &rrset->rrs[i]);
}



domain_table_type *
domain_table_create(void)
{
	const domain_name_st* origin;
	domain_table_type* result;
	domain_type* root;

	origin = domain_name_make( (uint8_t *) "", 0);

	root = (domain_type *) xalloc_zero( sizeof(domain_type));
	root->dname = (domain_name_st*)origin;
	root->parent = NULL;
	root->wildcard_child_closest_match = root;
	root->rrsets = NULL;
	root->usage = 1; /* do not delete root, ever */
	root->is_existing = 0;
	root->is_apex = 0;

	result = (domain_table_type *) xalloc(
						    sizeof(domain_table_type));

    result->nametree = radix_tree_create();
    root->rnode = radomain_name_insert(result->nametree, domain_name_get(root->dname),
            root->dname->name_size, root);


    result->number_total = 1;

	result->root = root;

	return result;
}

int
domain_table_search(domain_table_type *table,
		   const domain_name_st   *dname,
		   domain_type       **closest_match,
		   domain_type       **closest_encloser)
{
	int exact;
	uint8_t label_match_count;

	assert(table);
	assert(dname);
	assert(closest_match);
	assert(closest_encloser);


    exact = radomain_name_find_less_equal(table->nametree, domain_name_get(dname),
            dname->name_size, (struct radnode**)closest_match);
        *closest_match = (domain_type*)((*(struct radnode**)closest_match)->elem);
	assert(*closest_match);

	*closest_encloser = *closest_match;

	if (!exact) {
		label_match_count = domain_name_label_match_count(
			domain_dname(*closest_encloser),
			dname);
		assert(label_match_count < dname->label_count);
		while (label_match_count < domain_dname(*closest_encloser)->label_count) {
			(*closest_encloser) = (*closest_encloser)->parent;
			assert(*closest_encloser);
		}
	}

	return exact;
}

domain_type *
domain_table_find(domain_table_type* table,
		  const domain_name_st* dname)
{
	domain_type* closest_match;
	domain_type* closest_encloser;
	int exact;

	exact = domain_table_search(
		table, dname, &closest_match, &closest_encloser);
	return exact ? closest_encloser : NULL;
}


domain_type *
domain_table_insert(domain_table_type* table,
		    const domain_name_st* dname,uint32_t maxAnswer)
{
	domain_type* closest_match;
	domain_type* closest_encloser;
	domain_type* result;
	int exact;

	assert(table);
	assert(dname);

	exact = domain_table_search(
		table, dname, &closest_match, &closest_encloser);
	if (exact) {
		result = closest_encloser;
	} else {
		assert(domain_dname(closest_encloser)->label_count < dname->label_count);

		/* Insert new node(s).  */
		do {
			result = allocate_domain_info(table,
						      dname,
						      closest_encloser);
                        result->maxAnswer = maxAnswer;

			result->rnode = radomain_name_insert(table->nametree,
				domain_name_get(result->dname),
				result->dname->name_size, result);

			/*
			 * If the newly added domain name is larger
			 * than the parent's current
			 * wildcard_child_closest_match but smaller or
			 * equal to the wildcard domain name, update
			 * the parent's wildcard_child_closest_match
			 * field.
			 */
			if (label_compare(domain_name_get(domain_dname(result)),
					  (const uint8_t *) "\001*") <= 0
			    && domain_name_compare(domain_dname(result),
					     domain_dname(closest_encloser->wildcard_child_closest_match)) > 0)
			{
				closest_encloser->wildcard_child_closest_match
					= result;
			}
			closest_encloser = result;
		} while (domain_dname(closest_encloser)->label_count < dname->label_count);
	}

	return result;
}

domain_type *domain_previous_existing_child(domain_type* domain)
{
	domain_type* parent = domain->parent;
	domain = domain_previous(domain);
	while(domain && !domain->is_existing) {
		if(domain == parent) /* do not walk back above parent */
			return parent;
		domain = domain_previous(domain);
	}
	return domain;
}

void
domain_add_rrset(domain_type* domain, rrset_type* rrset)
{
#if 0 	/* fast */
	rrset->next = domain->rrsets;
	domain->rrsets = rrset;
#else
	/* preserve ordering, add at end */
	rrset_type** p = &domain->rrsets;
	while(*p)
		p = &((*p)->next);
	*p = rrset;
	rrset->next = 0;
#endif

	while (domain && !domain->is_existing) {
		domain->is_existing = 1;
		/* does this name in existance update the parent's
		 * wildcard closest match? */
		if(domain->parent
		   && label_compare(domain_name_get(domain_dname(domain)),
			(const uint8_t *) "\001*") <= 0
		   && domain_name_compare(domain_dname(domain),
		   	domain_dname(domain->parent->wildcard_child_closest_match)) > 0) {
			domain->parent->wildcard_child_closest_match = domain;
		}
		domain = domain->parent;
	}
}


rrset_type *
domain_find_rrset(domain_type* domain, zone_type* zone, uint16_t type)
{
	rrset_type* result = domain->rrsets;

	while (result) {
		if (result->zone == zone && rrset_rrtype(result) == type) {
			return result;
		}
		result = result->next;
	}
	return NULL;
}

rrset_type *
domain_find_any_rrset(domain_type* domain, zone_type* zone)
{
	rrset_type* result = domain->rrsets;

	while (result) {
		if (result->zone == zone) {
			return result;
		}
		result = result->next;
	}
	return NULL;
}

domain_type *
domain_wildcard_child(domain_type* domain)
{
	domain_type* wildcard_child;

	assert(domain);
	assert(domain->wildcard_child_closest_match);

	wildcard_child = domain->wildcard_child_closest_match;
	if (wildcard_child != domain
	    && label_is_wildcard(domain_name_get(domain_dname(wildcard_child))))
	{
		return wildcard_child;
	} else {
		return NULL;
	}
}

zone_type *
domain_find_zone(domain_store_type* db, domain_type* domain)
{
	rrset_type* rrset;
	while (domain) {
		if(domain->is_apex) {
			for (rrset = domain->rrsets; rrset; rrset = rrset->next) {
				if (rrset_rrtype(rrset) == TYPE_SOA) {
					return rrset->zone;
				}
			}
			return domain_store_find_zone(db, domain_dname(domain));
		}
		domain = domain->parent;
	}
	return NULL;
}


zone_type *
domain_store_find_zone(domain_store_type* db, const domain_name_st* dname)
{
	struct radnode* n = radomain_name_search(db->zonetree, domain_name_get(dname),
		dname->name_size);
	if(n) return (zone_type*)n->elem;
	return NULL;
}


struct  domain_store *domain_store_open (void)
{
	domain_store_type* db;
	db = (domain_store_type *)xalloc_zero(sizeof(struct  domain_store));
	db->domains = domain_table_create();
	db->zonetree = radix_tree_create();
    return db;

}


int
domain_store_lookup(struct  domain_store* db,
	      const domain_name_st* dname,
	      domain_type     **closest_match,
	      domain_type     **closest_encloser)
{
	return domain_table_search(
		db->domains, dname, closest_match, closest_encloser);
}
