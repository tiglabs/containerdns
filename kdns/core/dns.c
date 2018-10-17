/*
 * dns.c -- DNS definitions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. 
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 *
 */

#include  <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include "dns.h"
#include "zone.h"


static rrtype_descriptor_st rrtype_descriptors[TYPE_SUPPORT_MAX] = {
	/* 1 */
	{ TYPE_A, "A", 1, 1,
	  { RDATA_WF_A } },
	/* 5 */
	{ TYPE_CNAME, "CNAME", 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME } },
	/* 6 */
	{ TYPE_SOA, "SOA", 7, 7,
	  { RDATA_WF_COMPRESSED_DNAME, RDATA_WF_COMPRESSED_DNAME, RDATA_WF_LONG,
	    RDATA_WF_LONG, RDATA_WF_LONG, RDATA_WF_LONG, RDATA_WF_LONG } },
	/* 12 */
	{ TYPE_PTR, "PTR", 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME } },
	/* 33 */
	{ TYPE_SRV, "SRV", 4, 4,
	  { RDATA_WF_SHORT, RDATA_WF_SHORT, RDATA_WF_SHORT,
	    RDATA_WF_UNCOMPRESSED_DNAME }}
};

rrtype_descriptor_st *
rrtype_descriptor_by_type(uint16_t type)
{
   int i = 0;
   for(;i < TYPE_SUPPORT_MAX; i++){
        if (type == rrtype_descriptors[i].type){
            return &rrtype_descriptors[i];
        }
   }
   return NULL;
}



const domain_name_st *
domain_name_make( const uint8_t *name, int normalize)
{
	size_t name_size = 0;
	uint8_t label_offsets[MAXDOMAINLEN];
	uint8_t label_count = 0;
	const uint8_t *label = name;
	domain_name_st *result;
	ssize_t i;

	assert(name);

	while (1) {
		if (label_is_pointer(label))
			return NULL;

		label_offsets[label_count] = (uint8_t) (label - name);
		++label_count;
		name_size += label_length(label) + 1;

		if (label_is_root(label))
			break;

		label = label_next(label);
	}

	if (name_size > MAXDOMAINLEN)
		return NULL;

	assert(label_count <= MAXDOMAINLEN / 2 + 1);

	/* Reverse label offsets.  */
	for (i = 0; i < label_count / 2; ++i) {
		uint8_t tmp = label_offsets[i];
		label_offsets[i] = label_offsets[label_count - i - 1];
		label_offsets[label_count - i - 1] = tmp;
	}

	result = (domain_name_st *) xalloc((sizeof(domain_name_st)+ (((size_t)label_count) + ((size_t)name_size)) * sizeof(uint8_t)));
	result->name_size = name_size;
	result->label_count = label_count;
	memcpy((uint8_t *) domain_name_label_offsets(result),
	       label_offsets,
	       label_count * sizeof(uint8_t));
	if (normalize) {
		uint8_t *dst = (uint8_t *) domain_name_get(result);
		const uint8_t *src = name;
		while (!label_is_root(src)) {
			ssize_t len = label_length(src);
			*dst++ = *src++;
			for (i = 0; i < len; ++i) {
				*dst++ = tolower((unsigned char)*src++);
			}
		}
		*dst = *src;
	} else {
		memcpy((uint8_t *) domain_name_get(result),
		       name,
		       name_size * sizeof(uint8_t));
	}
	return result;
}



const domain_name_st *
domain_name_make_no_malloc( const uint8_t *name, int normalize,domain_name_st *result)
{
	size_t name_size = 0;
	uint8_t label_offsets[MAXDOMAINLEN];
	uint8_t label_count = 0;
	const uint8_t *label = name;
	
	ssize_t i;

	assert(name);

	while (1) {
		if (label_is_pointer(label))
			return NULL;

		label_offsets[label_count] = (uint8_t) (label - name);
		++label_count;
		name_size += label_length(label) + 1;

		if (label_is_root(label))
			break;

		label = label_next(label);
	}

	if (name_size > MAXDOMAINLEN)
		return NULL;

	assert(label_count <= MAXDOMAINLEN / 2 + 1);

	/* Reverse label offsets.  */
	for (i = 0; i < label_count / 2; ++i) {
		uint8_t tmp = label_offsets[i];
		label_offsets[i] = label_offsets[label_count - i - 1];
		label_offsets[label_count - i - 1] = tmp;
	}
	result->name_size = name_size;
	result->label_count = label_count;
	memcpy((uint8_t *) domain_name_label_offsets(result),
	       label_offsets,
	       label_count * sizeof(uint8_t));
	if (normalize) {
		uint8_t *dst = (uint8_t *) domain_name_get(result);
		const uint8_t *src = name;
		while (!label_is_root(src)) {
			ssize_t len = label_length(src);
			*dst++ = *src++;
			for (i = 0; i < len; ++i) {
				*dst++ = tolower((unsigned char)*src++);
			}
		}
		*dst = *src;
	} else {
		memcpy((uint8_t *) domain_name_get(result),
		       name,
		       name_size * sizeof(uint8_t));
	}
	return result;
}


const domain_name_st *
domain_name_parse( const char *name)
{
	uint8_t dname[MAXDOMAINLEN];
	if(!domain_name_parse_wire(dname, name))
		return 0;
	return domain_name_make( dname, 1);
}

int domain_name_parse_wire(uint8_t* dname, const char* name)
{
	const uint8_t *s = (const uint8_t *) name;
	uint8_t *h;
	uint8_t *p;
	uint8_t *d = dname;
	size_t label_length;

	if (strcmp(name, ".") == 0) {
		dname[0] = 0;
		return 1;
	}

	for (h = d, p = h + 1; *s; ++s, ++p) {
		if (p - dname >= MAXDOMAINLEN) {
			return 0;
		}

		switch (*s) {
		case '.':
			if (p == h + 1) {
				/* Empty label.  */
				return 0;
			} else {
				label_length = p - h - 1;
				if (label_length > MAXLABELLEN) {
					return 0;
				}
				*h = label_length;
				h = p;
			}
			break;
		case '\\':
			/* Handle escaped characters (RFC1035 5.1) */
			if (isdigit((unsigned char)s[1]) && isdigit((unsigned char)s[2]) && isdigit((unsigned char)s[3])) {
				int val = (hexdigit_to_int(s[1]) * 100 +
					   hexdigit_to_int(s[2]) * 10 +
					   hexdigit_to_int(s[3]));
				if (0 <= val && val <= 255) {
					s += 3;
					*p = val;
				} else {
					*p = *++s;
				}
			} else if (s[1] != '\0') {
				*p = *++s;
			}
			break;
		default:
			*p = *s;
			break;
		}
	}

	if (p != h + 1) {
		/* Terminate last label.  */
		label_length = p - h - 1;
		if (label_length > MAXLABELLEN) {
			return 0;
		}
		*h = label_length;
		h = p;
	}

	/* Add root label.  */
	if (h - dname >= MAXDOMAINLEN) {
		return 0;
	}
	*h = 0;

	return p-dname;
}



const domain_name_st *
domain_name_partial_copy( const domain_name_st *dname, uint8_t label_count)
{
	if (!dname)
		return NULL;

	if (label_count == 0) {
		/* Always copy the root label.  */
		label_count = 1;
	}

	assert(label_count <= dname->label_count);

	return domain_name_make( domain_name_label(dname, label_count - 1), 0);
}


const domain_name_st *
domain_name_origin( const domain_name_st *dname)
{
	return domain_name_partial_copy( dname, dname->label_count - 1);
}


int
domain_name_is_subdomain(const domain_name_st *left, const domain_name_st *right)
{
	uint8_t i;

	if (left->label_count < right->label_count)
		return 0;

	for (i = 1; i < right->label_count; ++i) {
		if (label_compare(domain_name_label(left, i),
				  domain_name_label(right, i)) != 0)
			return 0;
	}

	return 1;
}


int
domain_name_compare(const domain_name_st *left, const domain_name_st *right)
{
	int result;
	uint8_t label_count;
	uint8_t i;

	assert(left);
	assert(right);

	if (left == right) {
		return 0;
	}

	label_count = (left->label_count <= right->label_count
		       ? left->label_count
		       : right->label_count);

	/* Skip the root label by starting at label 1.  */
	for (i = 1; i < label_count; ++i) {
		result = label_compare(domain_name_label(left, i),
				       domain_name_label(right, i));
		if (result) {
			return result;
		}
	}

	/* Dname with the fewest labels is "first".  */
	/* the subtraction works because the size of int is much larger than
	 * the label count and the values won't wrap around */
	return (int) left->label_count - (int) right->label_count;
}


int
label_compare(const uint8_t *left, const uint8_t *right)
{
	int left_length;
	int right_length;
	size_t size;
	int result;

	assert(left);
	assert(right);

	assert(label_is_normal(left));
	assert(label_is_normal(right));

	left_length = label_length(left);
	right_length = label_length(right);
	size = left_length < right_length ? left_length : right_length;

	result = memcmp(labeldata(left), labeldata(right), size);
	if (result) {
		return result;
	} else {
		/* the subtraction works because the size of int is much
		 * larger than the lengths and the values won't wrap around */
		return (int) left_length - (int) right_length;
	}
}


uint8_t
domain_name_label_match_count(const domain_name_st *left, const domain_name_st *right)
{
	uint8_t i;

	assert(left);
	assert(right);

	for (i = 1; i < left->label_count && i < right->label_count; ++i) {
		if (label_compare(domain_name_label(left, i),
				  domain_name_label(right, i)) != 0)
		{
			return i;
		}
	}

	return i;
}

const char *
domain_name_to_string(const domain_name_st *dname, const domain_name_st *origin)
{
    char buf[MAXDOMAINLEN * 5] ={0};
	size_t i;
	size_t labels_to_convert = dname->label_count - 1;
	int absolute = 1;
	char *dst;
	const uint8_t *src;

	if (dname->label_count == 1) {
		strlcpy(buf, ".", sizeof(buf));
		return buf;
	}

	if (origin && domain_name_is_subdomain(dname, origin)) {
		int common_labels = domain_name_label_match_count(dname, origin);
		labels_to_convert = dname->label_count - common_labels;
		absolute = 0;
	}

	dst = buf;
	src = domain_name_get(dname);
	for (i = 0; i < labels_to_convert; ++i) {
		size_t len = label_length(src);
		size_t j;
		++src;
		for (j = 0; j < len; ++j) {
			uint8_t ch = *src++;
			if (isalnum((unsigned char)ch) || ch == '-' || ch == '_') {
				*dst++ = ch;
			} else if (ch == '.' || ch == '\\') {
				*dst++ = '\\';
				*dst++ = ch;
			} else {
				snprintf(dst, 5, "\\%03u", (unsigned int)ch);
				dst += 4;
			}
		}
		*dst++ = '.';
	}
	if (absolute) {
		*dst = '\0';
	} else {
		*--dst = '\0';
	}
	return buf;
}


const domain_name_st *
domain_name_make_from_label(
		      const uint8_t *label, const size_t length)
{
	uint8_t temp[MAXLABELLEN + 2];

	assert(length > 0 && length <= MAXLABELLEN);

	temp[0] = length;
	memcpy(temp + 1, label, length * sizeof(uint8_t));
	temp[length + 1] = '\000';

	return domain_name_make( temp, 1);
}


const domain_name_st *
domain_name_concatenate(
		  const domain_name_st *left,
		  const domain_name_st *right)
{
	uint8_t temp[MAXDOMAINLEN];

	assert(left->name_size + right->name_size - 1 <= MAXDOMAINLEN);

	memcpy(temp, domain_name_get(left), left->name_size - 1);
	memcpy(temp + left->name_size - 1, domain_name_get(right), right->name_size);

	return domain_name_make( temp, 0);
}


const domain_name_st *
domain_name_replace(
		const domain_name_st* name,
		const domain_name_st* src,
		const domain_name_st* dest)
{
	/* nomenclature: name is said to be <x>.<src>. x can be null. */
	domain_name_st* res;
	int x_labels = name->label_count - src->label_count;
	int x_len = name->name_size - src->name_size;
	int i;
	assert(domain_name_is_subdomain(name, src));

	/* check if final size is acceptable */
	if(x_len+dest->name_size > MAXDOMAINLEN)
		return NULL;

	res = (domain_name_st*)xalloc( sizeof(domain_name_st) +
		(x_labels+((int)dest->label_count) + x_len+((int)dest->name_size))
		*sizeof(uint8_t));
	res->name_size = x_len+dest->name_size;
	res->label_count = x_labels+dest->label_count;
	for(i=0; i<dest->label_count; i++)
		((uint8_t*)domain_name_label_offsets(res))[i] =
			domain_name_label_offsets(dest)[i] + x_len;
	for(i=dest->label_count; i<res->label_count; i++)
		((uint8_t*)domain_name_label_offsets(res))[i] =
			domain_name_label_offsets(name)[i - dest->label_count +
				src->label_count];
	memcpy((uint8_t*)domain_name_get(res), domain_name_get(name), x_len);
	memcpy((uint8_t*)domain_name_get(res)+x_len, domain_name_get(dest), dest->name_size);
	assert(domain_name_is_subdomain(res, dest));
	return res;
}

int domain_name_equal_nocase(uint8_t* a, uint8_t* b, uint16_t len)
{
	uint8_t i, lablen;
	while(len > 0) {
		/* check labellen */
		if(*a != *b)
			return 0;
		lablen = *a++;
		b++;
		len--;
		/* malformed or compression ptr; we stop scanning */
		if((lablen & 0xc0) || len < lablen)
			return (memcmp(a, b, len) == 0);
		/* check the label, lowercased */
		for(i=0; i<lablen; i++) {
			if(tolower((unsigned char)*a++) != tolower((unsigned char)*b++))
				return 0;
		}
		len -= lablen;
	}
	return 1;
}


