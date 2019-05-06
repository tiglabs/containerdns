/*
 * query.h -- manipulation with the queries
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#ifndef _QUERY_H_
#define _QUERY_H_

#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include "domain_store.h"
#include "kdns.h"
#include "packet.h"



typedef enum query_state {
	QUERY_SUCCESS,
	QUERY_FAIL,
}query_state_type;

/* Query as we pass it around */

typedef struct query {
	domain_type *wildcard_match;
	buffer_st *packet;
	const domain_name_st *qname;
	uint16_t qtype;
	uint16_t qclass;
    uint8_t opcode;

    uint32_t sip;
    char view_name[MAX_VIEW_NAME_LEN];
    
	zone_type *zone;
    
	int cname_count;
    uint16_t offset;
    uint32_t maxAnswer;
    uint32_t maxMsgLen;

    domain_type *compressed_dnames[MAXRRSPP];
    uint16_t    compressed_count;
    
    /*
	uint16_t     compressed_domain_name_count;
	domain_type *compressed_dnames[MAXRRSPP];
	uint16_t    *compressed_domain_name_offsets;
	size_t compressed_domain_name_offsets_size;
	*/
}kdns_query_st;

typedef struct answer {
	size_t rrset_count;
	rrset_type *rrsets[MAXRRSPP];
	domain_type *domains[MAXRRSPP];
	rr_section_type section[MAXRRSPP];
}kdns_answer_st;

static inline int check_view_info(kdns_query_st *query, rr_type *rr)
{
    // rr no view info 
    if (0 == strcmp(rr->view_name,DEFAULT_VIEW_NAME)){
        return VIEW_MATCH_DEF;
    }
    if (0 == strcmp(query->view_name,rr->view_name)){
        return VIEW_MATCH_NAME;
    }
    return VIEW_MATCH_NONE;
}

void encode_answer(kdns_query_st *q, const kdns_answer_st *answer);

/*
 * Add the specified RRset to the answer in the specified section.  If
 * the RRset is already present and in the same (or "higher") section
 * return 0, otherwise return 1.
 */
int answer_add_rrset(kdns_answer_st *answer, rr_section_type section,
		     domain_type *domain, rrset_type *rrset); 


/*
 * Create a new query structure.
 */
kdns_query_st *query_create(void);

/*
 * Reset a query structure so it is ready for receiving and processing
 * a new query.
 */
void query_reset(kdns_query_st *query );

int process_query_section(kdns_query_st *query);

/*
 * Process a query and write the response in the query I/O buffer.
 */
query_state_type query_process(kdns_query_st *q,  kdns_type * kdns);

/*
 * Prepare the query structure for writing the response. The packet
 * data up-to the current packet limit is preserved. This usually
 * includes the packet header and question section. Space is reserved
 * for the optional EDNS record, if required.
 */
void query_prepare_response_data(kdns_query_st *q);

/*
 * Write an error response into the query structure with the indicated
 * RCODE.
 */
query_state_type query_error(kdns_query_st *q,  int rcode);
void query_clear_dname_offsets(struct query *q, size_t max_offset);

 
#endif /* _QUERY_H_ */
