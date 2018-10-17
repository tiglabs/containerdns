/*
 * packet.h -- low-level DNS packet encoding and decoding functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#ifndef _PACKET_H_
#define _PACKET_H_

#include <sys/types.h>

#include "dns.h"
#include "domain_store.h"

struct query;


/*
 *
 *                                   
 *      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |QR|   OPCODE  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
 

/* The length of the header */
#define	DNS_HEAD_SIZE	12

/* First octet of flags */
#define	RD_MASK		0x01U
#define	GET_FLAG_RD(packet)      (*buffer_at((packet), 2) & RD_MASK)
#define	SET_FALG_RD(packet)	    (*buffer_at((packet), 2) |= RD_MASK)
#define	RESET_FLAG_RD(packet)	(*buffer_at((packet), 2) &= ~RD_MASK)

#define TC_MASK		0x02U
#define	GET_FLAG_TC(packet)	    (*buffer_at((packet), 2) & TC_MASK)
#define	SET_FLAG_TC(packet)	    (*buffer_at((packet), 2) |= TC_MASK)
#define	RESET_FLAG_TC(packet)	(*buffer_at((packet), 2) &= ~TC_MASK)

#define	AA_MASK		0x04U
#define	GET_FLAG_AA(packet)	    (*buffer_at((packet), 2) & AA_MASK)
#define	SET_FLAG_AA(packet)	    (*buffer_at((packet), 2) |= AA_MASK)
#define	RESET_FLAG_AA(packet)	(*buffer_at((packet), 2) &= ~AA_MASK)

#define	OPCODE_MASK	0x78U
#define	OPCODE_SHIFT	3
#define	GET_OPCODE(packet)	((*buffer_at((packet), 2) & OPCODE_MASK) >> OPCODE_SHIFT)
#define	SET_OPCODE(packet, OPCODE) \
	(*buffer_at((packet), 2) = (*buffer_at((packet), 2) & ~OPCODE_MASK) | ((OPCODE) << OPCODE_SHIFT))

#define	QR_MASK		0x80U
#define	GET_FLAG_QR(packet)	(*buffer_at((packet), 2) & QR_MASK)
#define	SET_FLAG_QR(packet)	(*buffer_at((packet), 2) |= QR_MASK)
#define	RESET_FLAG_QR(packet)	(*buffer_at((packet), 2) &= ~QR_MASK)

/* Second octet of flags */
#define	RCODE_MASK	0x0fU
#define	GET_RCODE(packet)	(*buffer_at((packet), 3) & RCODE_MASK)
#define	SET_RCODE(packet, rcode) \
	(*buffer_at((packet), 3) = (*buffer_at((packet), 3) & ~RCODE_MASK) | (rcode))

#define	CD_MASK		0x10U
#define	CD_SHIFT	4
#define	GET_FLAG_CD(packet)	(*buffer_at((packet), 3) & CD_MASK)
#define	SET_FLAG_CD(packet)	(*buffer_at((packet), 3) |= CD_MASK)
#define	RESET_FLAG_CD(packet)	(*buffer_at((packet), 3) &= ~CD_MASK)

#define	AD_MASK		0x20U
#define	AD_SHIFT	5
#define	GET_FLAG_AD(packet)	(*buffer_at((packet), 3) & AD_MASK)
#define	SET_FLAG_AD(packet)	(*buffer_at((packet), 3) |= AD_MASK)
#define	RESET_FLAG_AD(packet)	(*buffer_at((packet), 3) &= ~AD_MASK)

#define	Z_MASK		0x40U
#define	Z_SHIFT		6
#define	GET_FLAG_Z(packet)	(*buffer_at((packet), 3) & Z_MASK)
#define	SET_FLAG_Z(packet)	(*buffer_at((packet), 3) |= Z_MASK)
#define	RESET_FLAG_Z(packet)	(*buffer_at((packet), 3) &= ~Z_MASK)

#define	RA_MASK		0x80U
#define	RA_SHIFT	7
#define	GET_FLAG_RA(packet)	(*buffer_at((packet), 3) & RA_MASK)
#define	SET_FLAG_RA(packet)	(*buffer_at((packet), 3) |= RA_MASK)
#define	RESET_FLAG_RA(packet)	(*buffer_at((packet), 3) &= ~RA_MASK)

/* Query ID */
#define	GET_ID(packet)		(buffer_read_u16_at((packet), 0))
#define	SET_ID(packet, id)	(buffer_write_u16_at((packet), 0, (id)))

/* Flags, RCODE, and OPCODE. */
#define GET_FLAGS(packet)		(buffer_read_u16_at((packet), 2))
#define SET_FLAGS(packet, f)	(buffer_write_u16_at((packet), 2, (f)))

/* Counter of the question section */
#define	GET_QD_COUNT(packet)		(buffer_read_u16_at((packet), 4))
#define SET_QD_COUNT(packet, c)	(buffer_write_u16_at((packet), 4, (c)))

/* Counter of the answer section */
#define	GET_AN_COUNT(packet)		(buffer_read_u16_at((packet), 6))
#define SET_AN_COUNT(packet, c)	(buffer_write_u16_at((packet), 6, (c)))

/* Counter of the authority section */
#define	GET_NS_COUNT(packet)		(buffer_read_u16_at((packet), 8))
#define SET_NS_COUNT(packet, c)	(buffer_write_u16_at((packet), 8, (c)))

/* Counter of the additional section */
#define	GET_AR_COUNT(packet)		(buffer_read_u16_at((packet), 10))
#define SET_AR_COUNT(packet, c)	(buffer_write_u16_at((packet), 10, (c)))

/* Miscellaneous limits */
#define MAX_PACKET_SIZE         65535   /* Maximum supported size of DNS packets.  */

#define	QIOBUFSZ		(MAX_PACKET_SIZE + MAX_RR_SIZE)

#define	MAXRRSPP		1024    /* Maximum number of rr's per packet */
#define MAX_COMPRESSED_DNAMES	MAXRRSPP /* Maximum number of compressed domains. */
#define MAX_COMPRESSION_OFFSET  0x3fff	 ///the 2 higher bits set to 0
#define IPV4_MINIMAL_RESPONSE_SIZE 1480	 /* Recommended minimal edns size for IPv4 */
 
 
/*
 * Encode RR with OWNER as owner name into QUERY.  Returns the number
 * of RRs successfully encoded.
 */
int packet_encode_rr(struct query *query,
		     domain_type *owner,
		     rr_type *rr,
		     uint32_t ttl);

/*
 * Encode RRSET with OWNER as the owner name into QUERY.  Returns the
 * number of RRs successfully encoded.  If TRUNCATE_RRSET the entire
 * RRset is truncated in case an RR (or the RRsets signature) does not
 * fit.
 */
int packet_encode_rrset(struct query *query, domain_type *owner, rrset_type *rrset, int section);

/*
 * read a query entry from network packet given in buffer.
 * does not follow compression ptrs, checks for errors (returns 0).
 * Dest must be at least MAXDOMAINLEN long.
 */
int packet_read_query_section(buffer_st *packet,
			uint8_t* dest,
			uint16_t* qtype,
			uint16_t* qclass);

#endif /* _PACKET_H_ */
