/*
 * dns.h -- DNS definitions.
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#ifndef _DNS_H_
#define _DNS_H_
#include <stdint.h>
#include <assert.h>
#include <stdio.h>

#include "buffer.h"


typedef enum rr_section {
	QUESTION_SECTION,
	ANSWER_SECTION,
	AUTHORITY_SECTION,
	OPTIONAL_AUTHORITY_SECTION,
	ADDITIONAL_SECTION,
	RR_SECTION_COUNT
}rr_section_type;

/* Possible OPCODE values */
#define OPCODE_QUERY		0 	/* a standard query (QUERY) */
#define OPCODE_IQUERY		1 	/* an inverse query (IQUERY) */
#define OPCODE_STATUS		2 	/* a server status request (STATUS) */
#define OPCODE_NOTIFY		4 	/* NOTIFY */
#define OPCODE_UPDATE		5 	/* Dynamic update */

/* Possible RCODE values */
#define RCODE_OK		    0 	/* No error condition */
#define RCODE_FORMAT		1 	/* Format error */
#define RCODE_SERVFAIL		2 	/* Server failure */
#define RCODE_NXDOMAIN		3 	/* Name Error */
#define RCODE_IMPL		    4 	/* Not implemented */
#define RCODE_REFUSE		5 	/* Refused */
#define RCODE_YXDOMAIN		6	/* name should not exist */
#define RCODE_YXRRSET		7	/* rrset should not exist */
#define RCODE_NXRRSET		8	/* rrset does not exist */
#define RCODE_NOTAUTH		9	/* server not authoritative */
#define RCODE_NOTZONE		10	/* name not inside zone */

/* RFC1035 */
#define CLASS_IN	1	/* Class IN */
#define CLASS_CS	2	/* Class CS */
#define CLASS_CH	3	/* Class CHAOS */
#define CLASS_HS	4	/* Class HS */
#define CLASS_NONE	254	/* Class NONE rfc2136 */
#define CLASS_ANY	255	/* Class ANY */

// type support
#define TYPE_A		1	/* a host address */
#define TYPE_CNAME	5	/* the canonical name for an alias */
#define TYPE_SOA	6	/* marks the start of a zone of authority */
#define TYPE_PTR	12	/* a domain name pointer */
#define TYPE_SRV	33	/* SRV record RFC2782 */


#define TYPE_SUPPORT_MAX  5


#define MAXLABELLEN	63
#define MAXDOMAINLEN	255

#define MAXRDATALEN	64      /* This is more than enough, think multiple TXT. */
#define MAX_RDLENGTH	65535

/* Maximum size of a single RR.  */
#define MAX_RR_SIZE \
	(MAXDOMAINLEN + sizeof(uint32_t) + 4*sizeof(uint16_t) + MAX_RDLENGTH)


/*
 * The different types of RDATA wireformat data.
 */
enum rdata_wireformat
{
	RDATA_WF_COMPRESSED_DNAME,   /* Possibly compressed domain name.  */
	RDATA_WF_UNCOMPRESSED_DNAME, /* Uncompressed domain name.  */
	RDATA_WF_LITERAL_DNAME,      /* Literal (not downcased) dname.  */
	RDATA_WF_BYTE,               /* 8-bit integer.  */
	RDATA_WF_SHORT,              /* 16-bit integer.  */
	RDATA_WF_LONG,               /* 32-bit integer.  */
	RDATA_WF_TEXT,               /* Text string.  */
	RDATA_WF_TEXTS,              /* Text string sequence.  */
	RDATA_WF_A,                  /* 32-bit IPv4 address.  */
	RDATA_WF_AAAA,               /* 128-bit IPv6 address.  */
	RDATA_WF_BINARY,             /* Binary data (unknown length).  */
	RDATA_WF_BINARYWITHLENGTH,   /* Binary data preceded by 1 byte length */
	RDATA_WF_APL,                /* APL data.  */
	RDATA_WF_IPSECGATEWAY,       /* IPSECKEY gateway ip4, ip6 or dname. */
	RDATA_WF_ILNP64,             /* 64-bit uncompressed IPv6 address.  */
	RDATA_WF_EUI48,	             /* 48-bit address.  */
	RDATA_WF_EUI64,              /* 64-bit address.  */
	RDATA_WF_LONG_TEXT           /* Long (>255) text string. */
};
typedef enum rdata_wireformat rdata_wireformat_type;


typedef struct rrtype_descriptor
{
	uint16_t    type;	/* RR type */
	const char *name;	/* Textual name.  */
	uint32_t    minimum;	/* Minimum number of RDATAs.  */
	uint32_t    maximum;	/* Maximum number of RDATAs.  */
	uint8_t     wireformat[MAXRDATALEN]; /* rdata_wireformat_type */
}rrtype_descriptor_st;


rrtype_descriptor_st *rrtype_descriptor_by_type(uint16_t type);


/*
 * Domain names stored in memory add some additional information to be
 * able to quickly index and compare by label.
 */
typedef struct domain_name domain_name_st;
struct domain_name
{
	uint8_t name_size;
	uint8_t label_count;
};

const domain_name_st *
domain_name_make_no_malloc( const uint8_t *name, int normalize,domain_name_st *result);

/*
 * Construct a new domain name based on NAME in wire format.  NAME
 * cannot contain compression pointers.
 *
 * Pre: NAME != NULL.
 */
const domain_name_st *domain_name_make( const uint8_t *name,
			     int normalize);


/*
 * Construct a new domain name based on the ASCII representation NAME.
 * If ORIGIN is not NULL and NAME is not terminated by a "." the
 * ORIGIN is appended to the result.  NAME can contain escape
 * sequences.
 *
 * Returns NULL on failure.  Otherwise a newly allocated domain name
 * is returned.
 *
 * Pre: name != NULL.
 */
const domain_name_st *domain_name_parse( const char *name);

/*
 * parse ascii string to wireformat domain name (without compression ptrs)
 * returns 0 on failure, the length of the wireformat on success.
 * the result is stored in the wirefmt which must be at least MAXDOMAINLEN
 * in size. On failure, the wirefmt can be altered.
 */
int domain_name_parse_wire(uint8_t* wirefmt, const char* name);



/*
 * Copy the most significant LABEL_COUNT labels from dname.
 */
const domain_name_st *domain_name_partial_copy(
				     const domain_name_st *dname,
				     uint8_t label_count);


/*
 * The origin of DNAME.
 */
const domain_name_st *domain_name_origin( const domain_name_st *dname);

/*
 * Return true if LEFT is a subdomain of RIGHT.
 */
int domain_name_is_subdomain(const domain_name_st *left, const domain_name_st *right);


/*
 * Offsets into NAME for each label starting with the most
 * significant label (the root label, followed by the TLD,
 * etc).
 */
static inline const uint8_t *
domain_name_label_offsets(const domain_name_st *dname)
{
	return (const uint8_t *) ((const char *) dname + sizeof(domain_name_st));
}


/*
 * The actual name in wire format (a sequence of label, each
 * prefixed by a length byte, terminated by a zero length
 * label).
 */
static inline const uint8_t *
domain_name_get(const domain_name_st *dname)
{
	return (const uint8_t *) ((const char *) dname
				  + sizeof(domain_name_st)
				  + dname->label_count * sizeof(uint8_t));
}


/*
 * Return the label for DNAME specified by LABEL_INDEX.  The first
 * label (LABEL_INDEX == 0) is the root label, the next label is the
 * TLD, etc.
 *
 * Pre: dname != NULL && label_index < dname->label_count.
 */
static inline const uint8_t *
domain_name_label(const domain_name_st *dname, uint8_t label)
{
	uint8_t label_index;

	assert(dname != NULL);
	assert(label < dname->label_count);

	label_index = domain_name_label_offsets(dname)[label];
	assert(label_index < dname->name_size);

	return domain_name_get(dname) + label_index;
}


/*
 * Compare two domain names.  The comparison defines a lexicographical
 * ordering based on the domain name's labels, starting with the most
 * significant label.
 *
 * Return < 0 if LEFT < RIGHT, 0 if LEFT == RIGHT, and > 0 if LEFT >
 * RIGHT.  The comparison is case sensitive.
 *
 * Pre: left != NULL && right != NULL
 */
int domain_name_compare(const domain_name_st *left, const domain_name_st *right);


/*
 * Compare two labels.  The comparison defines a lexicographical
 * ordering based on the characters in the labels.
 *
 * Return < 0 if LEFT < RIGHT, 0 if LEFT == RIGHT, and > 0 if LEFT >
 * RIGHT.  The comparison is case sensitive.
 *
 * Pre: left != NULL && right != NULL
 *      label_is_normal(left) && label_is_normal(right)
 */
int label_compare(const uint8_t *left, const uint8_t *right);


/*
 * Returns the number of labels that match in LEFT and RIGHT, starting
 * with the most significant label.  Because the root label always
 * matches, the result will always be >= 1.
 *
 * Pre: left != NULL && right != NULL
 */
uint8_t domain_name_label_match_count(const domain_name_st *left,
				const domain_name_st *right);


/*
 * The total size (in bytes) allocated to store DNAME.
 *
 * Pre: dname != NULL
 */
static inline size_t
domain_name_total_size(const domain_name_st *dname)
{
	return (sizeof(domain_name_st)
		+ ((((size_t)dname->label_count) + ((size_t)dname->name_size))
		   * sizeof(uint8_t)));
}


/*
 * Is LABEL a normal LABEL (not a pointer or reserved)?
 *
 * Pre: label != NULL;
 */
static inline int
label_is_normal(const uint8_t *label)
{
	assert(label);
	return (label[0] & 0xc0) == 0;
}


/*
 * Is LABEL a pointer?
 *
 * Pre: label != NULL;
 。若是真正的数据，会以0x00结尾；若是指针，指针占2个字节，第一个字节的高2位为11。
 */
static inline int
label_is_pointer(const uint8_t *label)
{
	assert(label);
	return (label[0] & 0xc0) == 0xc0;
}


/*
 * LABEL's pointer location.
 *
 * Pre: label != NULL && label_is_pointer(label)
 */
static inline uint16_t
label_pointer_location(const uint8_t *label)
{
	assert(label);
	assert(label_is_pointer(label));
	return ((uint16_t) (label[0] & ~0xc0) << 8) | (uint16_t) label[1];
}


/*
 * Length of LABEL.
 *
 * Pre: label != NULL && label_is_normal(label)
 */
static inline uint8_t
label_length(const uint8_t *label)
{
	assert(label);
	assert(label_is_normal(label));
	return label[0];
}


/*
 * The data of LABEL.
 *
 * Pre: label != NULL && label_is_normal(label)
 */
static inline const uint8_t *
labeldata(const uint8_t *label)
{
	assert(label);
	assert(label_is_normal(label));
	return label + 1;
}


/*
 * Is LABEL the root label?
 *
 * Pre: label != NULL
 */
static inline int
label_is_root(const uint8_t *label)
{
	assert(label);
	return label[0] == 0;
}


/*
 * Is LABEL the wildcard label?
 *
 * Pre: label != NULL
 */
static inline int
label_is_wildcard(const uint8_t *label)
{
	assert(label);
	return label[0] == 1 && label[1] == '*';
}


/*
 * The next label of LABEL.
 *
 * Pre: label != NULL
 *      label_is_normal(label)
 *      !label_is_root(label)
 */
static inline const uint8_t *
label_next(const uint8_t *label)
{
	assert(label);
	assert(label_is_normal(label));
	assert(!label_is_root(label));
	return label + label_length(label) + 1;
}


/*
 * Convert DNAME to its string representation.  The result points to a
 * static buffer that is overwritten the next time this function is
 * invoked.
 *
 * If ORIGIN is provided and DNAME is a subdomain of ORIGIN the dname
 * will be represented relative to ORIGIN.
 *
 * Pre: dname != NULL
 */
const char *domain_name_to_string(const domain_name_st *dname,
			    const domain_name_st *origin);


/*
 * Create a dname containing the single label specified by STR
 * followed by the root label.
 */
const domain_name_st *domain_name_make_from_label(
					const uint8_t *label,
					const size_t length);


/*
 * Concatenate two dnames.
 */
const domain_name_st *domain_name_concatenate(
				    const domain_name_st *left,
				    const domain_name_st *right);


/*
 * Perform DNAME substitution on a name, replace src with dest.
 * Name must be a subdomain of src. The returned name is a subdomain of dest.
 * Returns NULL if the result domain name is too long.
 */
const domain_name_st *domain_name_replace( 
				const domain_name_st* name,
				const domain_name_st* src,
				const domain_name_st* dest);

/** check if two uncompressed dnames of the same total length are equal */
int domain_name_equal_nocase(uint8_t* a, uint8_t* b, uint16_t len);


#endif /* _DNS_H_ */
