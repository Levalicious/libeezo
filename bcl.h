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
 * The extended-leaf codes of XBCL (five bits, after the 011 tag). A limb list follows the primitives:
 * the code, a 32-bit limb count, then the limbs, least significant first. The range is five bits wide,
 * so PRIM_COUNT must stay below 26.
 */
enum { XB_I = 0, XB_B, XB_C, XB_T, XB_R, XB_WORD, XB_PRIM0, XB_BIG = XB_PRIM0 + PRIM_COUNT,
       /* a denoted number follows the limb list: a limb list for the base, then one for the exponent */
       XB_DEN = XB_BIG + 1 };

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

/*
 * XBCL: BCL with the extended leaves (2026-09-13).
 *   1 X Y         App(X, Y)
 *   00            K
 *   010           S
 *   011 ccccc     a leaf by 5-bit code: 0 I, 1 B, 2 C, 3 T, 4 R,
 *                 5 a word (followed by its 64 bits, most significant first),
 *                 6 + op a primitive (op as in PrimOp)
 * Pure BCL has no free codepoint, so this is a format of its own; the pure
 * formats spell B C T R as their S K trees and cannot spell words at all.
 */
SKITerm *xbcl_parse(SKIPool *p, BclStream *s);
bool xbcl_emit(SKITerm *t, BclBuffer *b);
u64 xbcl_size(SKITerm *t);

#endif /* EEZO_BCL_H */
