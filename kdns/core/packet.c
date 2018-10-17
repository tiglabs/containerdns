/*
 * packet.c -- low-level DNS packet encoding and decoding functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#include <string.h>
#include "packet.h"
#include "query.h"
#include "zone.h"

#define VIEW_MATCH_DEF   0
#define VIEW_MATCH_NAME  1
#define VIEW_MATCH_NONE  2

#define VIEW_MATCH_DEF   0
#define VIEW_MATCH_NAME  1
#define VIEW_MATCH_NONE  2

#define DOMAIN_LB_RR    1
#define DOMAIN_LB_WRR   2
#define DOMAIN_LB_HASH  3


// max match 128 rrs
#define VIEW_MATCH_MAX_NUM  1024



int round_robin = 1;



static void
do_dname_data_encode(kdns_query_st *q, domain_type *domain)
{
	while (domain->parent && domain->compressed_offset == 0) {
		domain->compressed_offset =  buffer_get_position(q->packet);
        q->compressed_dnames[q->compressed_count] = domain;
        q->compressed_count++;
        
		buffer_write(q->packet, domain_name_get(domain_dname(domain)),
			     label_length(domain_name_get(domain_dname(domain))) + 1U);
		domain = domain->parent;
	}
	if (domain->parent) {
		buffer_write_u16(q->packet,0xc000 | domain->compressed_offset);
	} else {
		buffer_write_u8(q->packet, 0);
	}
}



int
packet_encode_rr(kdns_query_st *q, domain_type *owner, rr_type *rr, uint32_t ttl)
{
	size_t truncation_mark;
	uint16_t rdlength = 0;
	size_t rdlength_pos;
	uint16_t j;
	/*
	 * If the record does not in fit in the packet the packet size
	 * will be restored to the mark.
	 */
	truncation_mark = buffer_get_position(q->packet);

    do_dname_data_encode(q,owner);

    
	buffer_write_u16(q->packet, rr->type);
	buffer_write_u16(q->packet, rr->klass);
	buffer_write_u32(q->packet, ttl);

	/* Reserve space for rdlength. */
	rdlength_pos = buffer_get_position(q->packet);
	buffer_skip(q->packet, sizeof(rdlength));

	for (j = 0; j < rr->rdata_count; ++j) {
		switch (rdata_atom_wireformat_type(rr->type, j)) {
		case RDATA_WF_COMPRESSED_DNAME:
			do_dname_data_encode(q, rdata_atom_domain(rr->rdatas[j]));
			break;
		case RDATA_WF_UNCOMPRESSED_DNAME:
		{
			const domain_name_st *dname = domain_dname(
				rdata_atom_domain(rr->rdatas[j]));
			buffer_write(q->packet,
				     domain_name_get(dname), dname->name_size);
			break;
		}
		default:
			buffer_write(q->packet,
				     rdata_atomdata(rr->rdatas[j]),
				     rdata_atom_size(rr->rdatas[j]));
			break;
		}
	}

	if (buffer_get_position(q->packet) <= q->maxMsgLen){
		rdlength = (buffer_get_position(q->packet) - rdlength_pos
			    - sizeof(rdlength));
		buffer_write_u16_at(q->packet, rdlength_pos, rdlength);
		return 1;
	} else {
		buffer_set_position(q->packet, truncation_mark);
       // query_clear_dname_offsets(q, truncation_mark);
		return 0;
	}
}



static int ckeck_view_info(kdns_query_st *query, rr_type *rr)
{
    // rr no view info 
    if (0 == strcmp(rr->view_name,DEFAULT_VIEW_NAME)){
        return VIEW_MATCH_DEF;
    }

    if (0 ==  strcmp(query->view_name,rr->view_name)){
        return VIEW_MATCH_NAME;
    }
    return VIEW_MATCH_NONE;
}

static int lb_filter(kdns_query_st *query,domain_type *owner,int16_t lb_mode, rrset_type *rrset,
                    int16_t *idx_array, int16_t size,uint16_t round_robin_off){

    rr_type *rr_to_encode = NULL;
    int16_t fit_rr_idx =0;

    if (lb_mode == DOMAIN_LB_RR){
        fit_rr_idx = idx_array[round_robin_off %size];       
    }else if (lb_mode == DOMAIN_LB_HASH){
        fit_rr_idx = idx_array[query->sip %size];       
    }else if (lb_mode == DOMAIN_LB_WRR){
        int16_t i;
        int16_t find =0;
        rr_type *rr;
wrr_retry:

        for( i =0; i<size; i++){
            rr = &rrset->rrs[idx_array[i]];  
            if (rr->lb_weight_cur >0){   
                fit_rr_idx =  idx_array[i];
                rr->lb_weight_cur--;
                find =1;
                break;
            }  
        }
        //no find rebuild lb_weight_cur
        if (!find){     
            for( i =0; i<size; i++){
              rr = &rrset->rrs[idx_array[i]];  
              rr->lb_weight_cur = rr->lb_weight;      
            }  
            goto wrr_retry;
        }
            
    }else{
        log_msg(LOG_ERR,"lb_filter() lb_mode = %d \n",lb_mode);
        return 0;
    }

    rr_to_encode = &rrset->rrs[fit_rr_idx];

    if (packet_encode_rr(query, owner,rr_to_encode,rr_to_encode->ttl)) {
	    return 1;
    }
   return 0;
}


int
packet_encode_rrset(kdns_query_st *query, domain_type *owner,
		    rrset_type *rrset, int section )

{
	uint16_t i;
	uint16_t added = 0;  
	static uint16_t round_robin_off = 0;
	int do_robin = (round_robin && section == ANSWER_SECTION);
	uint16_t start;
    uint16_t rr_match_max;
    uint32_t maxAnswer = 65535;
    // max 128 record per view
    int16_t rrs_view_idx[VIEW_MATCH_MAX_NUM];
    int16_t rrs_def_idx[VIEW_MATCH_MAX_NUM];
    int16_t view_match_idx  =0 ;
    int16_t def_match_idx  =0 ;
    memset(rrs_view_idx, -1, sizeof(int16_t)*VIEW_MATCH_MAX_NUM);
    memset(rrs_def_idx, -1, sizeof(int16_t)*VIEW_MATCH_MAX_NUM);

    rr_type *rr_to_encode = NULL;
    
    int truncate_rrset = (section == ANSWER_SECTION ||
				section == AUTHORITY_SECTION ||
				section == OPTIONAL_AUTHORITY_SECTION);
    int all_added =1; 
    if (query->maxAnswer > 0){
        maxAnswer = query->maxAnswer;
    }

	assert(rrset->rr_count > 0);
    size_t truncation_mark = buffer_get_position(query->packet);

    round_robin_off++;

    // filter the view info
    int ret_tmp;
    uint16_t lb_mode = 0;
    
	for (i = 0; i < rrset->rr_count; ++i) {
        ret_tmp = ckeck_view_info(query,&rrset->rrs[i]);
        if ((ret_tmp == VIEW_MATCH_NAME)&& (view_match_idx < VIEW_MATCH_MAX_NUM)){
            if (lb_mode ==0) {
                lb_mode = rrset->rrs[i].lb_mode;
            }
            rrs_view_idx[view_match_idx] = i;
            view_match_idx ++;      
        }else if ((ret_tmp == VIEW_MATCH_DEF)&& (def_match_idx < VIEW_MATCH_MAX_NUM)){
            if (lb_mode ==0) {
                lb_mode = rrset->rrs[i].lb_mode;
            }
            rrs_def_idx[def_match_idx] = i;
            def_match_idx ++;    
        }else{
            continue;
        }
	}
    // lb enable
    if (lb_mode != 0){
        if (view_match_idx >0){
            return lb_filter(query, owner, lb_mode, rrset, rrs_view_idx, view_match_idx, round_robin_off);
        }else if (def_match_idx >0){
            return lb_filter(query, owner, lb_mode, rrset, rrs_def_idx, def_match_idx, round_robin_off);
        }else{
            return 0;
        }
    }
    
    // lb_mode ==0 
	if(do_robin && view_match_idx){
		start = (uint16_t)(round_robin_off % view_match_idx);
        rr_match_max = view_match_idx;
    }else if (do_robin && def_match_idx){
        start = (uint16_t)(round_robin_off % def_match_idx);
        rr_match_max = def_match_idx;
    }else{
        start = 0;
        rr_match_max = def_match_idx;
    }
    

    for (i = start; i < rr_match_max && added < maxAnswer; ++i) {

        if (view_match_idx){
            rr_to_encode = &rrset->rrs[rrs_view_idx[i]];
        }else if (def_match_idx) {
            rr_to_encode = &rrset->rrs[rrs_def_idx[i]];
        }else{
            continue;
        }
        
		if (packet_encode_rr(query, owner,rr_to_encode,rr_to_encode->ttl)) {
			++added;
		} else {
		    all_added = 0;
			break;
		}
	}
	for (i = 0; i < start && added < maxAnswer; ++i) {
        
		if (view_match_idx){
            rr_to_encode = &rrset->rrs[rrs_view_idx[i]];
        }else if (def_match_idx) {
            rr_to_encode = &rrset->rrs[rrs_def_idx[i]];
        }else{
            continue;
        }
        
		if (packet_encode_rr(query, owner,rr_to_encode,rr_to_encode->ttl)) {
			++added;
		} else {
		    all_added = 0;
			break;
		}
	}

	if (!all_added && truncate_rrset) {
		/* Truncate entire RRset and set truncate flag. */
		buffer_set_position(query->packet, truncation_mark);
	//	query_clear_dname_offsets(query, truncation_mark);
		SET_FLAG_TC(query->packet);
		added = 0;
    }

	return added;
}

int packet_read_query_section(buffer_st *packet,
	uint8_t* dst, uint16_t* qtype, uint16_t* qclass)
{
	uint8_t *query_name = buffer_current(packet);
	uint8_t *src = query_name;
	size_t len;

	while (*src) {
		/*
		 * If we are out of buffer limits or we have a pointer
		 * in question dname or the domain name is longer than
		 * MAXDOMAINLEN ...
		 */
		if ((*src & 0xc0) ||
		    (src + *src + 2 > buffer_end(packet)) ||
		    (src + *src + 2 > query_name + MAXDOMAINLEN))
		{
			return 0;
		}
		memcpy(dst, src, *src + 1);
		dst += *src + 1;
		src += *src + 1;
	}
	*dst++ = *src++;

	/* Make sure name is not too long or we have stripped packet... */
	len = src - query_name;
	if (len > MAXDOMAINLEN ||
	    (src + 2*sizeof(uint16_t) > buffer_end(packet)))
	{
		return 0;
	}
	buffer_set_position(packet, src - buffer_begin(packet));

	*qtype = buffer_read_u16(packet);
	*qclass = buffer_read_u16(packet);
	return 1;
}
