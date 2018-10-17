/*
 * buffer.h -- generic memory buffer.
 *
 * Copyright (c) 2001-2006, NLnet Labs.
 *
 * Modified Work Copyright (c) 2018 The TIGLabs Authors.
 *
 */

#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <assert.h>
#include <stdarg.h>
#include <string.h> 
#include "util.h"


static inline uint16_t
do_read_uint16( void *src)
{
	uint8_t *d = (uint8_t *) src;
	return (d[0] << 8) | d[1];
}

static inline uint32_t
do_read_uint32( void *src)
{
	uint8_t *d = (uint8_t *) src;
	return (d[0] << 24) | (d[1] << 16) |
           (d[2] << 8) | d[3];
}

static inline uint64_t
do_read_uint64( void *src)
{
	uint8_t *d = (uint8_t *) src;
	return
	    ((uint64_t)d[0] << 56) |
	    ((uint64_t)d[1] << 48) |
	    ((uint64_t)d[2] << 40) |
	    ((uint64_t)d[3] << 32) |
	    ((uint64_t)d[4] << 24) |
	    ((uint64_t)d[5] << 16) |
	    ((uint64_t)d[6] <<  8) |
	    (uint64_t)d[7];
}


static inline void
do_write_uint16(void *dst, uint16_t data)
{
	uint8_t *d = (uint8_t *) dst;
	d[0] = (uint8_t) ((data >> 8) & 0xff);
	d[1] = (uint8_t) (data & 0xff);
}

static inline void
do_write_uint32(void *dst, uint32_t data)
{
	uint8_t *d = (uint8_t *) dst;
	d[0] = (uint8_t) ((data >> 24) & 0xff);
	d[1] = (uint8_t) ((data >> 16) & 0xff);
	d[2] = (uint8_t) ((data >> 8) & 0xff);
	d[3] = (uint8_t) (data & 0xff);
}

static inline void
do_write_uint64(void *dst, uint64_t data)
{
	uint8_t *d = (uint8_t *) dst;
	d[0] = (uint8_t) ((data >> 56) & 0xff);
	d[1] = (uint8_t) ((data >> 48) & 0xff);
	d[2] = (uint8_t) ((data >> 40) & 0xff);
	d[3] = (uint8_t) ((data >> 32) & 0xff);
	d[4] = (uint8_t) ((data >> 24) & 0xff);
	d[5] = (uint8_t) ((data >> 16) & 0xff);
	d[6] = (uint8_t) ((data >> 8) & 0xff);
	d[7] = (uint8_t) (data & 0xff);
}


typedef struct buffer
{
	size_t   position;
	size_t   limit;
	size_t   capacity;
	uint8_t *data;
}buffer_st;


static inline void
buffer_check(buffer_st *buffer)
{
	assert(buffer);
	assert(buffer->position <= buffer->limit);
	assert(buffer->limit <= buffer->capacity);
	assert(buffer->data);
}


/*
 * Create a new buffer with the specified capacity.
 */
static inline buffer_st *buffer_create( size_t capacity){
	buffer_st *buffer
		= (buffer_st *) xalloc( sizeof(buffer_st));
	if (!buffer)
		return NULL;

	buffer->data = (uint8_t *) xalloc(1);
	buffer->position = 0;
	buffer->limit = buffer->capacity = capacity;
	buffer_check(buffer);
	return buffer;
}


static inline void buffer_clear(buffer_st *buffer)
{
   	buffer_check(buffer);	
	buffer->position = 0;
	buffer->limit = buffer->capacity;
}


static inline void buffer_flip(buffer_st *buffer){
	buffer_check(buffer);	
	buffer->limit = buffer->position;
	buffer->position = 0;

}


static inline void buffer_rewind(buffer_st *buffer){
	buffer_check(buffer);	
	buffer->position = 0;
}

static inline size_t
buffer_get_position(buffer_st *buffer)
{
	return buffer->position;
}

static inline void
buffer_set_position(buffer_st *buffer, size_t mark)
{
	assert(mark <= buffer->limit);
	buffer->position = mark;
}

static inline void
buffer_skip(buffer_st *buffer, ssize_t count)
{
	assert(buffer->position + count <= buffer->limit);
	buffer->position += count;
}

static inline size_t
buffer_getlimit(buffer_st *buffer)
{
	return buffer->limit;
}


static inline void
buffer_setlimit(buffer_st *buffer, size_t limit)
{
	assert(limit <= buffer->capacity);
	buffer->limit = limit;
	if (buffer->position > buffer->limit)
		buffer->position = buffer->limit;
}


static inline size_t
buffer_getcapacity(buffer_st *buffer)
{
	return buffer->capacity;
}


static inline void buffer_setcapacity(buffer_st *buffer, size_t capacity){
	buffer_check(buffer);
	assert(buffer->position <= capacity);
	buffer->data = (uint8_t *) xrealloc(buffer->data, capacity);
	buffer->limit = buffer->capacity = capacity;
}


static inline uint8_t *
buffer_at(buffer_st *buffer, size_t at)
{
	assert(at <= buffer->limit);
	return buffer->data + at;
}


static inline uint8_t *
buffer_begin(buffer_st *buffer)
{
	return buffer_at(buffer, 0);
}


static inline uint8_t *
buffer_end(buffer_st *buffer)
{
	return buffer_at(buffer, buffer->limit);
}


static inline uint8_t *
buffer_current(buffer_st *buffer)
{
	return buffer_at(buffer, buffer->position);
}


static inline size_t
buffer_remaining_at(buffer_st *buffer, size_t at)
{
	buffer_check(buffer);
	assert(at <= buffer->limit);
	return buffer->limit - at;
}

static inline size_t
buffer_remaining(buffer_st *buffer)
{
	return buffer_remaining_at(buffer, buffer->position);
}


static inline int
buffer_available_at(buffer_st *buffer, size_t at, size_t count)
{
	return count <= buffer_remaining_at(buffer, at);
}

static inline int
buffer_available(buffer_st *buffer, size_t count)
{
	return buffer_available_at(buffer, buffer->position, count);
}

static inline void
buffer_write_at(buffer_st *buffer, size_t at, const void *data, size_t count)
{
	assert(buffer_available_at(buffer, at, count));
	memcpy(buffer->data + at, data, count);
}

static inline void
buffer_write(buffer_st *buffer, const void *data, size_t count)
{
	buffer_write_at(buffer, buffer->position, data, count);
	buffer->position += count;
}

static inline void
buffer_write_string_at(buffer_st *buffer, size_t at, const char *str)
{
	buffer_write_at(buffer, at, str, strlen(str));
}

static inline void
buffer_write_string(buffer_st *buffer, const char *str)
{
	buffer_write(buffer, str, strlen(str));
}

static inline void
buffer_write_u8_at(buffer_st *buffer, size_t at, uint8_t data)
{
	assert(buffer_available_at(buffer, at, sizeof(data)));
	buffer->data[at] = data;
}

static inline void
buffer_write_u8(buffer_st *buffer, uint8_t data)
{
	buffer_write_u8_at(buffer, buffer->position, data);
	buffer->position += sizeof(data);
}

static inline void
buffer_write_u16_at(buffer_st *buffer, size_t at, uint16_t data)
{
	assert(buffer_available_at(buffer, at, sizeof(data)));
	do_write_uint16(buffer->data + at, data);
}

static inline void
buffer_write_u16(buffer_st *buffer, uint16_t data)
{
	buffer_write_u16_at(buffer, buffer->position, data);
	buffer->position += sizeof(data);
}

static inline void
buffer_write_u32_at(buffer_st *buffer, size_t at, uint32_t data)
{
	assert(buffer_available_at(buffer, at, sizeof(data)));
	do_write_uint32(buffer->data + at, data);
}

static inline void
buffer_write_u32(buffer_st *buffer, uint32_t data)
{
	buffer_write_u32_at(buffer, buffer->position, data);
	buffer->position += sizeof(data);
}

static inline void
buffer_write_u64_at(buffer_st *buffer, size_t at, uint64_t data)
{
	assert(buffer_available_at(buffer, at, sizeof(data)));
	do_write_uint64(buffer->data + at, data);
}

static inline void
buffer_write_u64(buffer_st *buffer, uint64_t data)
{
	buffer_write_u64_at(buffer, buffer->position, data);
	buffer->position += sizeof(data);
}

static inline void
buffer_read_at(buffer_st *buffer, size_t at, void *data, size_t count)
{
	assert(buffer_available_at(buffer, at, count));
	memcpy(data, buffer->data + at, count);
}

static inline void
buffer_read(buffer_st *buffer, void *data, size_t count)
{
	buffer_read_at(buffer, buffer->position, data, count);
	buffer->position += count;
}

static inline uint8_t
buffer_read_u8_at(buffer_st *buffer, size_t at)
{
	assert(buffer_available_at(buffer, at, sizeof(uint8_t)));
	return buffer->data[at];
}

static inline uint8_t
buffer_read_u8(buffer_st *buffer)
{
	uint8_t result = buffer_read_u8_at(buffer, buffer->position);
	buffer->position += sizeof(uint8_t);
	return result;
}

static inline uint16_t
buffer_read_u16_at(buffer_st *buffer, size_t at)
{
	assert(buffer_available_at(buffer, at, sizeof(uint16_t)));
	return do_read_uint16(buffer->data + at);
}

static inline uint16_t
buffer_read_u16(buffer_st *buffer)
{
	uint16_t result = buffer_read_u16_at(buffer, buffer->position);
	buffer->position += sizeof(uint16_t);
	return result;
}

static inline uint32_t
buffer_read_u32_at(buffer_st *buffer, size_t at)
{
	assert(buffer_available_at(buffer, at, sizeof(uint32_t)));
	return do_read_uint32(buffer->data + at);
}

static inline uint32_t
buffer_read_u32(buffer_st *buffer)
{
	uint32_t result = buffer_read_u32_at(buffer, buffer->position);
	buffer->position += sizeof(uint32_t);
	return result;
}

static inline uint64_t
buffer_read_u64_at(buffer_st *buffer, size_t at)
{
	assert(buffer_available_at(buffer, at, sizeof(uint64_t)));
	return do_read_uint64(buffer->data + at);
}

static inline uint64_t
buffer_read_u64(buffer_st *buffer)
{
	uint64_t result = buffer_read_u64_at(buffer, buffer->position);
	buffer->position += sizeof(uint64_t);
	return result;
}

#endif /* _BUFFER_H_ */
