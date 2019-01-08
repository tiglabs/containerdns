/*
 * query.c  
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#include <stdlib.h>

#include "dns.h"
#include "kdns.h"
#include "domain_store.h"
#include "query.h"
#include "util.h"

struct additional_rr_types
{
	uint16_t        rr_type;
	rr_section_type rr_section;
};

struct additional_rr_types default_additional_rr_types[] = {
	{ TYPE_A, ADDITIONAL_SECTION },
	{ 0, (rr_section_type) 0 }
};

static int add_rrset(struct query  *query,
		     kdns_answer_st    *answer,
		     rr_section_type section,
		     domain_type    *owner,
		     rrset_type     *rrset);

static void answer_authoritative(struct kdns * kdns,
				 struct query     *q,
				 kdns_answer_st   *answer,
				 int               exact,
				 domain_type      *closest_match,
				 domain_type      *closest_encloser);

static void answer_lookup_zone(struct kdns * kdns, struct query *q,
			       kdns_answer_st *answer,
			       int exact, domain_type *closest_match,
			       domain_type *closest_encloser);
 
query_state_type query_error (struct query *q,  int rcode)
{
	if (rcode == -1) {
		return QUERY_FAIL;
	}

	buffer_clear(q->packet);

	SET_FLAG_QR(q->packet);	   /* This is an answer.  */
	RESET_FLAG_AD(q->packet);
	SET_RCODE(q->packet, (int) rcode); 
 	SET_QD_COUNT(q->packet, 0);
	SET_AN_COUNT(q->packet, 0);
	SET_NS_COUNT(q->packet, 0);
	SET_AR_COUNT(q->packet, 0);
	buffer_set_position(q->packet, DNS_HEAD_SIZE);
	return QUERY_SUCCESS;
}

static query_state_type
query_format_error (struct query *query)
{
	int opcode = GET_OPCODE(query->packet);
	SET_FLAGS(query->packet, GET_FLAGS(query->packet) & 0x0100U);
 	SET_OPCODE(query->packet, opcode);
	return query_error(query, RCODE_FORMAT);
}


kdns_query_st *
query_create(void)
{
	kdns_query_st *query = (kdns_query_st *) xalloc_zero( sizeof(kdns_query_st));
	query->packet = buffer_create( QIOBUFSZ);
    query->qname =(domain_name_st *) xalloc_zero(sizeof(domain_name_st)+ MAXDOMAINLEN * 2);
	return query;
}

void
query_reset(kdns_query_st *q )
{
    if (q->wildcard_match != NULL) {
        free(q->wildcard_match);
        q->wildcard_match = NULL;
    }
    if (q->qname != NULL){
        memset((void *)q->qname,0,sizeof(struct domain_name)+ MAXDOMAINLEN * 2);
    }   
    buffer_clear(q->packet);
    q->qtype = 0;
    q->qclass = 0;
    q->zone = NULL;
    q->opcode = 0;
    q->maxAnswer = 0;
    q->offset = 0;
    q->sip = 0 ;
    q->cname_count = 0;
    q->maxMsgLen= UDP_MAX_MESSAGE_LEN;
    memset(q->view_name,0,MAX_VIEW_NAME_LEN);
}

/*
 * Parse the question section of a query.  The normalized query name
 * is stored in QUERY->name, the class in QUERY->klass, and the type
 * in QUERY->type.
 */
static int
process_query_section(kdns_query_st *query)
{
	uint8_t qnamebuf[MAXDOMAINLEN];

	buffer_set_position(query->packet, DNS_HEAD_SIZE);
	/* Lets parse the query name and convert it to lower case.  */
	if(!packet_read_query_section(query->packet, qnamebuf,
		&query->qtype, &query->qclass))
		return 0;
	query->qname = domain_name_make_no_malloc( qnamebuf, 1,(domain_name_st *)query->qname);
	return 1;
}


static void
add_additional_rrsets(struct query *query, kdns_answer_st *answer,
		      rrset_type *master_rrset, size_t rdata_index,
		      struct additional_rr_types types[])
{
	int i;

	assert(query);
	assert(answer);
	assert(master_rrset);
	assert(rdata_atom_is_domain(rrset_rrtype(master_rrset), rdata_index));

	for (i = 0; i < master_rrset->rr_count; ++i) {
		int j;
		domain_type *additional = rdata_atom_domain(master_rrset->rrs[i].rdatas[rdata_index]);
		domain_type *match = additional;

		assert(additional);

		/*
		 * Check to see if we need to generate the dependent
		 * based on a wildcard domain.
		 */
		while (!match->is_existing) {
			match = match->parent;
		}
		if (additional != match && domain_wildcard_child(match)) {
			domain_type *wildcard_child = domain_wildcard_child(match);
			query->wildcard_match = (domain_type *) xalloc(sizeof(domain_type));
			domain_type *temp = query->wildcard_match;
			temp->rnode = NULL;
			temp->dname = additional->dname;
			temp->parent = match;
			temp->wildcard_child_closest_match = temp;
			temp->rrsets = wildcard_child->rrsets;
			temp->compressed_offset = DNS_HEAD_SIZE;
			temp->is_existing = wildcard_child->is_existing;
			additional = temp;
		}

		for (j = 0; types[j].rr_type != 0; ++j) {
			rrset_type *rrset = domain_find_rrset(
				additional, query->zone, types[j].rr_type);
			if (rrset) {
				answer_add_rrset(answer, types[j].rr_section,
						 additional, rrset);
			}
		}
	}
}


static int
add_rrset(struct query   *query,
	  kdns_answer_st    *answer,
	  rr_section_type section,
	  domain_type    *owner,
	  rrset_type     *rrset)
{
	int result = answer_add_rrset(answer, section, owner, rrset);
    if (rrset_rrtype(rrset) == TYPE_SRV){
        add_additional_rrsets(query, answer, rrset, 3, default_additional_rr_types);
    }

	return result;
}


/*
 * Answer SOA information.
 */
static void
answer_soa(struct query *query, kdns_answer_st *answer)
{
	if (query->qclass != CLASS_ANY) {
		add_rrset(query, answer,
			  AUTHORITY_SECTION,
			  query->zone->apex,
			  query->zone->soa_nx_rrset);
	}
}

 
static void
answer_nodata(struct query *query, kdns_answer_st *answer, domain_type *original)
{
	(void)original;
	if (query->cname_count == 0) {
		answer_soa(query, answer);
	}
}

static void
answer_nxdomain(kdns_query_st *query, kdns_answer_st *answer)
{
	SET_RCODE(query->packet, RCODE_NXDOMAIN);
	answer_soa(query, answer);
}


/*
 * Answer domain information (or SOA if we do not have an RRset for
 * the type specified by the query).
 */
static void
answer_domain(struct kdns*  kdns, struct query *q, kdns_answer_st *answer,
	      domain_type *domain, domain_type *original)
{
	rrset_type *rrset;

     if ((rrset = domain_find_rrset(domain, q->zone, q->qtype))) {
        q->maxAnswer = domain->maxAnswer;
		add_rrset(q, answer, ANSWER_SECTION, domain, rrset);
	} else if ((rrset = domain_find_rrset(domain, q->zone, TYPE_CNAME))) {
		int added;
		added = add_rrset(q, answer, ANSWER_SECTION, domain, rrset);
		assert(rrset->rr_count > 0);
		if (added) {
			/* only process first CNAME record */
			domain_type *closest_match = rdata_atom_domain(rrset->rrs[0].rdatas[0]);
			domain_type *closest_encloser = closest_match;
			zone_type* origzone = q->zone;
			++q->cname_count;

			answer_lookup_zone( kdns, q, answer,
					     closest_match == closest_encloser,
					     closest_match, closest_encloser);
			q->zone = origzone;
		}
		return;
	} else {
		answer_nodata(q, answer, original);
		return;
	}

	if (q->qclass != CLASS_ANY && q->zone->ns_rrset ) {
		add_rrset(q, answer, OPTIONAL_AUTHORITY_SECTION, q->zone->apex,
			  q->zone->ns_rrset);
	}
}

static void
answer_authoritative(struct kdns   * kdns,
		     struct query *q,
		     kdns_answer_st  *answer,
		     int           exact,
		     domain_type  *closest_match,
		     domain_type  *closest_encloser)
{
	domain_type *match;
	domain_type *original = closest_match;
	if (exact) {
		match = closest_match;
	} else if (domain_wildcard_child(closest_encloser)) {
		/* Generate the domain from the wildcard.  */
		domain_type *wildcard_child = domain_wildcard_child(closest_encloser);
		q->wildcard_match = (domain_type *) xalloc(sizeof(domain_type));
		match = q->wildcard_match;
		match->rnode = NULL;
		match->dname = wildcard_child->dname;
		match->parent = closest_encloser;
		match->wildcard_child_closest_match = match;
		match->rrsets = wildcard_child->rrsets;
		match->compressed_offset = DNS_HEAD_SIZE;
		match->is_existing = wildcard_child->is_existing;

		/*
		 * Remember the original domain in case a Wildcard No
		 * Data (3.1.3.4) response needs to be generated.  In
		 * this particular case the wildcard IS NOT
		 * expanded.
		 */
		original = wildcard_child;
	} else {
		match = NULL;
	}

	if (match) {
		answer_domain( kdns, q, answer, match, original);
	} else {
		answer_nxdomain(q, answer);
	}
}

/*
 * qname may be different after CNAMEs have been followed from query->qname.
 */
static void
answer_lookup_zone(struct kdns * kdns, struct query *q, kdns_answer_st *answer,
	 int exact, domain_type *closest_match,domain_type *closest_encloser)
{
	q->zone = domain_find_zone( kdns->db, closest_encloser);
	if (!q->zone) {
		/* no zone for this */
		if(q->cname_count == 0)
			SET_RCODE(q->packet, RCODE_REFUSE);
		return;
	}
    if(!q->zone->apex || !q->zone->soa_rrset) {
		/* zone is configured but not loaded */
		if(q->cname_count == 0)
			SET_RCODE(q->packet, RCODE_SERVFAIL);
		return;
	}
	/* now move up the closest encloser until it exists, previous
	 * (possibly empty) closest encloser was useful to finding the zone
	 * (for empty zones too), but now we want actual data nodes */
	if (closest_encloser && !closest_encloser->is_existing) {
		exact = 0;
		while (closest_encloser != NULL && !closest_encloser->is_existing)
			closest_encloser = closest_encloser->parent;
	}

	if (q->qclass == CLASS_ANY) {
		RESET_FLAG_AA(q->packet);
	} else {
		SET_FLAG_AA(q->packet);
	}
	answer_authoritative( kdns, q, answer, exact,
			     closest_match, closest_encloser);
	
}

static void query_compressed_table_clear(struct query *q){
    int i =0;
    for(;i < q->compressed_count; i++){
        if (q->compressed_dnames[i] != NULL) {
            q->compressed_dnames[i]->compressed_offset = 0;
        }      
    }
    q->compressed_count = 0;    
}

static void
query_compressed_table_add(struct query *q, domain_type *domain, uint16_t offset)
{
	while (domain->parent) {
		domain->compressed_offset = offset;
		q->compressed_dnames[q->compressed_count] = domain;
		q->compressed_count++;

		offset += label_length(domain_name_get(domain_dname(domain))) + 1;
		domain = domain->parent;
	}
}

static void
query_response(struct kdns * kdns, struct query *q)
{
	domain_type *closest_match;
	domain_type *closest_encloser;
	int exact;
	uint16_t offset;
	kdns_answer_st answer ={0};

	exact = domain_store_lookup( kdns->db, q->qname, &closest_match, &closest_encloser);
	answer_lookup_zone( kdns, q, &answer, exact, closest_match,closest_encloser);
	if (GET_RCODE(q->packet) != RCODE_REFUSE) {
		offset = domain_name_label_offsets(q->qname)[domain_dname(closest_encloser)->label_count - 1] + DNS_HEAD_SIZE;
		query_compressed_table_add(q, closest_encloser, offset);
		encode_answer(q, &answer);
		query_compressed_table_clear(q);
	}
}

void
query_prepare_response_data(kdns_query_st *q)
{
	uint16_t flags;
	buffer_set_position(q->packet, buffer_getlimit(q->packet));
	buffer_setlimit(q->packet, buffer_getcapacity(q->packet));

	/* Update the flags.  */
	flags = GET_FLAGS(q->packet);
	flags &= 0x0100U;	/* Preserve the RD flag.  */
	/* CD flag must be cleared for auth answers */
	flags |= 0x8000U;	/* Set the QR flag.  */
	SET_FLAGS(q->packet, flags);
}

/*
 * process one query.
 *
 */
query_state_type query_process(kdns_query_st *q, kdns_type * kdns)
{
	if ((buffer_getlimit(q->packet) < DNS_HEAD_SIZE) ||(GET_FLAG_QR(q->packet)) ){
		return QUERY_FAIL;
	}

	q->opcode = GET_OPCODE(q->packet);
	if(q->opcode != OPCODE_QUERY) {
		return query_error(q, RCODE_IMPL);
	}

	if (GET_RCODE(q->packet) != RCODE_OK || !process_query_section(q)) {
		return query_format_error(q);
	}
    // question count must be 1
	if (GET_QD_COUNT(q->packet) != 1) {
		SET_FLAGS(q->packet, 0);
		return query_format_error(q);
	}
	/* Ignore settings of flags */
 	if (GET_AN_COUNT(q->packet) != 0 || GET_NS_COUNT(q->packet) != 0 ||  GET_AR_COUNT(q->packet) >= 2) {
		return query_format_error(q);
	}

 	buffer_setlimit(q->packet, buffer_get_position(q->packet));

    //
	query_prepare_response_data(q);

	if (q->qclass != CLASS_IN ) {
		return query_error(q, RCODE_REFUSE);
	}
    
	query_response(kdns, q);
	return QUERY_SUCCESS;
}

int
answer_add_rrset(kdns_answer_st *answer, rr_section_type section,
		 domain_type *domain, rrset_type *rrset)
{
	size_t i;

	assert(section >= ANSWER_SECTION && section < RR_SECTION_COUNT);
	assert(domain);
	assert(rrset);

	/* Don't add an RRset multiple times.  */
	for (i = 0; i < answer->rrset_count; ++i) {
		if (answer->rrsets[i] == rrset &&
			answer->domains[i] == domain ) {
			if (section < answer->section[i]) {
				answer->section[i] = section;
				return 1;
			} else {
				return 0;
			}
		}
	}

	if (answer->rrset_count >= MAXRRSPP) {
 		return 0;
	}

	answer->section[answer->rrset_count] = section;
	answer->domains[answer->rrset_count] = domain;
	answer->rrsets[answer->rrset_count] = rrset;
	++answer->rrset_count;

	return 1;
}

void
encode_answer(kdns_query_st *q, const kdns_answer_st *answer)
{
	uint16_t counts[RR_SECTION_COUNT]={0};
	rr_section_type section;
	size_t i;
  
	for (section = ANSWER_SECTION;
	     !GET_FLAG_TC(q->packet) && section < RR_SECTION_COUNT;
	     ++section) {

		for (i = 0; !GET_FLAG_TC(q->packet) && i < answer->rrset_count; ++i) {
			if (answer->section[i] == section) {
				counts[section] += packet_encode_rrset( q, answer->domains[i],
					answer->rrsets[i], section );
			}
		}
	}

	SET_AN_COUNT(q->packet, counts[ANSWER_SECTION]);
	SET_NS_COUNT(q->packet,
		    counts[AUTHORITY_SECTION]
		    + counts[OPTIONAL_AUTHORITY_SECTION]);

   SET_AR_COUNT(q->packet, counts[ADDITIONAL_SECTION]);
}

