/*
 * jomplement.h - Jomplement and Jot parsing
 *
 * Jomplement (Jot with bits flipped):
 *   [ε] → I
 *   [F1] → [F]SK     (apply to S, then K)  
 *   [F0] → S(K[F])   (compose/nest)
 *
 * Jot (original):
 *   [ε] → I
 *   [F0] → [F]SK
 *   [F1] → S(K[F])
 *
 * Both parse LSB-first (right-to-left in the bitstring).
 * Jomplement: leading 0s droppable. Enumeration 1,10,11,... = distinct programs.
 * Jot: leading 1s droppable.
 */
#ifndef EEZO_JOMPLEMENT_H
#define EEZO_JOMPLEMENT_H

#include "types.h"
#include "term.h"
#include "bcl.h"

/*
 * Parse Jomplement bitstring to term (stream-based, arbitrary length)
 * Uses BclStream for input - processes bits RTL (MSB to LSB)
 */
SKITerm *jomplement_parse(SKIPool *p, BclStream *s);

/*
 * Parse Jot bitstring to term (stream-based, arbitrary length)
 */
SKITerm *jot_parse(SKIPool *p, BclStream *s);

/*
 * Emit SKI term to Jot bitstring using Barker transform (SKI→Iota→Jot)
 * Returns bit count, writes bits to buffer (MSB first in each byte)
 * Barker transform: K=ι(ι(ιι)), S=ι(ι(ι(ιι))), I=SKK, App preserves structure
 * Iota→Jot: ι="0", App(X,Y)="1"+jot(X)+jot(Y) (tree encoding)
 */
i32 jot_emit(SKITerm *t, u8 *buf, u32 buf_size);

/*
 * Emit SKI term to Jomplement bitstring (bitwise NOT of Jot)
 * Same interface as jot_emit
 */
i32 jomplement_emit(SKITerm *t, u8 *buf, u32 buf_size);

/*
 * Size calculation for Jot encoding
 */
u64 jot_size(SKITerm *t);

#endif /* EEZO_JOMPLEMENT_H */
