/*
 * bcl.h - Binary Combinatory Logic parsing and emission
 *
 * BCL encoding:
 *   00     = K
 *   01     = S  
 *   1 X Y  = App(X, Y)
 *
 * This is a prefix code - no delimiters needed, parse left-to-right.
 * BCL is isomorphic to SKI AST.
 */
#ifndef EEZO_BCL_H
#define EEZO_BCL_H

#include "types.h"
#include "term.h"

/*
 * BCL bit stream for parsing
 * Wraps a byte array, tracks current bit position
 */
typedef struct {
    const u8 *data;
    u64 len;        /* length in bits */
    u64 pos;        /* current position in bits */
} BclStream;

/* Initialize stream from byte array. nbits = number of valid bits */
void bcl_stream_init(BclStream *s, const u8 *data, u64 nbits);

/* Read next bit, returns -1 on EOF */
int bcl_stream_read(BclStream *s);

/* Peek next bit without advancing, returns -1 on EOF */
int bcl_stream_peek(BclStream *s);

/* Check if at end */
bool bcl_stream_eof(BclStream *s);

/* Get current position */
u64 bcl_stream_pos(BclStream *s);

/*
 * BCL bit buffer for emission
 */
typedef struct {
    u8 *data;
    u64 capacity;   /* capacity in bits */
    u64 len;        /* current length in bits */
} BclBuffer;

/* Initialize buffer */
void bcl_buffer_init(BclBuffer *b, u8 *data, u64 capacity_bits);

/* Write a bit, returns false if full */
bool bcl_buffer_write(BclBuffer *b, int bit);

/* Get length in bits */
u64 bcl_buffer_len(BclBuffer *b);

/*
 * Parsing: BCL bits → SKITerm
 */
SKITerm *bcl_parse(SKIPool *p, BclStream *s);

/*
 * Emission: SKITerm → BCL bits
 */
bool bcl_emit(SKITerm *t, BclBuffer *b);

/*
 * Size calculation (without emission)
 */
u64 bcl_size(SKITerm *t);

#endif /* EEZO_BCL_H */
