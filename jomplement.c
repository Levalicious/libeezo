/*
 * jomplement.c - Jomplement and Jot parsing and emission
 *
 * Jot grammar (RTL parsing, MSB to LSB):
 *   [ε] → I
 *   [W0] → ([W]S)K
 *   [W1] → S(K[W])
 *
 * Verified encodings:
 *   K = 11100 (5 bits)
 *   S = 11111000 (8 bits)
 *   {AB} = 1{A}{B}
 *
 * Minimal standalone: 00→K, 000→S (leading 1s droppable, extensionally I)
 */
#include "jomplement.h"
#include "bcl.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "mem.h"

/*
 * ===========================================================================
 * SKI → JOT ENCODING
 * ===========================================================================
 *
 * Verified encoding rules (esolangs, confirmed with RTL parser):
 *   {K}  = 11100
 *   {S}  = 11111000
 *   {AB} = 1{A}{B}
 *   {I}  = (empty, or 1{S}{K}{K} for explicit SKK)
 * Written into the shared growable bit buffer (bcl.h).
 */

static void jot_write_str(BclBuffer *buf, const char *pattern) {
    for (const char *p = pattern; *p; p++) bcl_buffer_write(buf, *p == '1');
}

/* A leaf's pure S K spelling (ski_expansion) in Jot: '1' application, S = 11111000, K = 11100, other letters expand in
   turn (recursion only through the constant expansion strings) */
static u64 jot_expansion_size(const char *e) {
    u64 n = 0;
    for (; *e; e++) {
        switch (*e) {
            case '1': n += 1; break;
            case 'S': n += 8; break;
            case 'K': n += 5; break;
            case 'I': n += jot_expansion_size(ski_expansion(TERM_I)); break;
            case 'B': n += jot_expansion_size(ski_expansion(TERM_B)); break;
            case 'C': n += jot_expansion_size(ski_expansion(TERM_C)); break;
            default: break;
        }
    }
    return n;
}

static bool jot_emit_expansion(BclBuffer *buf, const char *e) {
    for (; *e; e++) {
        switch (*e) {
            case '1': bcl_buffer_write(buf, 1); break;
            case 'S': jot_write_str(buf, "11111000"); break;
            case 'K': jot_write_str(buf, "11100"); break;
            case 'I': if (!jot_emit_expansion(buf, ski_expansion(TERM_I))) return false; break;
            case 'B': if (!jot_emit_expansion(buf, ski_expansion(TERM_B))) return false; break;
            case 'C': if (!jot_emit_expansion(buf, ski_expansion(TERM_C))) return false; break;
            default: return false;
        }
    }
    return true;
}

/* {AB} = 1{A}{B}: a prefix-code walk on a heap stack, as bcl.c's */
static Stack jot_st = { NULL, 0, 0, sizeof(SKITerm *) };
static bool emit_ski_to_jot(SKITerm *t, BclBuffer *buf) {
    if (!t) return false;
    size_t base = jot_st.n;
    STACK_PUSH(&jot_st, SKITerm *, t);
    while (jot_st.n > base) {
        SKITerm *x = STACK_POP(&jot_st, SKITerm *);
        if (x->tag == TERM_APP) { bcl_buffer_write(buf, 1); STACK_PUSH(&jot_st, SKITerm *, x->app.right); STACK_PUSH(&jot_st, SKITerm *, x->app.left); continue; }
        if (x->tag == TERM_WORD || x->tag == TERM_PRIM || !jot_emit_expansion(buf, ski_expansion(x->tag))) { jot_st.n = base; return false; }   /* no pure spelling */
    }
    return true;
}
static u64 ski_jot_size(SKITerm *t) {
    if (!t) return 0;
    size_t base = jot_st.n; u64 n = 0;
    STACK_PUSH(&jot_st, SKITerm *, t);
    while (jot_st.n > base) {
        SKITerm *x = STACK_POP(&jot_st, SKITerm *);
        if (x->tag == TERM_APP) { n += 1; STACK_PUSH(&jot_st, SKITerm *, x->app.right); STACK_PUSH(&jot_st, SKITerm *, x->app.left); continue; }
        if (x->tag != TERM_WORD && x->tag != TERM_PRIM) n += jot_expansion_size(ski_expansion(x->tag));
    }
    return n;
}

/*
 * ===========================================================================
 * PUBLIC API
 * ===========================================================================
 */

/*
 * Jomplement parsing (RIGHT-TO-LEFT):
 *   [ε] → I
 *   [W0] → S(K[W])
 *   [W1] → ([W]S)K
 *
 * Jomplement is bit-flipped Jot: 0↔1 swapped in the rules.
 * Stream is read left-to-right, but we need RTL semantics.
 * So we buffer all bits first, then process from end to start.
 */
/* The bits, in the order received (bit 0 is the rightmost of the program): each wraps the term so far. ones is the
   bit whose rule is [W1] -> S(K[W]) (Jot: 1; Jomplement: 0); the other is [W] -> ([W]S)K. A truncated stream is NULL. */
static SKITerm *jot_like_parse(SKIPool *p, BclStream *s, int ones) {
    u64 nbits = s->len - s->pos;
    SKITerm *result = ski_i(p);
    for (u64 i = 0; i < nbits; i++) {
        int bit = bcl_stream_read(s);
        if (bit < 0) { ski_unref(p, result); return NULL; }
        if (bit == ones) result = ski_app(p, ski_s(p), ski_app(p, ski_k(p), result));   /* S(K[W]) */
        else result = ski_app(p, ski_app(p, result, ski_s(p)), ski_k(p));             /* ([W]S)K */
    }
    return result;
}
SKITerm *jomplement_parse(SKIPool *p, BclStream *s) { return jot_like_parse(p, s, 0); }
SKITerm *jot_parse(SKIPool *p, BclStream *s) { return jot_like_parse(p, s, 1); }

/*
 * ===========================================================================
 * EMISSION: SKI → Jot
 * ===========================================================================
 */

/*
 * Calculate size in bits for an SKI term
 */
u64 jot_size(SKITerm *t) {
    return ski_jot_size(t);
}

/*
 * Emit SKI term to Jot bits, appended to b (direct encoding, no Iota intermediate). False when the term has a word or
 * a primitive, which Jot cannot spell.
 */
bool jot_emit(SKITerm *t, BclBuffer *b) { return emit_ski_to_jot(t, b); }

/*
 * Emit SKI term to Jomplement bits (the bitwise NOT of Jot), appended to b
 */
bool jomplement_emit(SKITerm *t, BclBuffer *b) {
    u64 from = bcl_buffer_len(b);
    if (!jot_emit(t, b)) return false;
    for (u64 i = from; i < b->len; i++) STACK_AT(&b->bytes, u8, i / 8) ^= (u8)(1 << (7 - i % 8));
    return true;
}
