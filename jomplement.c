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

/* Bit buffer for emission */
typedef struct {
    u8 *data;
    u32 capacity;  /* in bits */
    u32 len;       /* current length in bits */
} JotBuffer;

static void jot_buf_init(JotBuffer *b, u8 *data, u32 capacity_bits) {
    b->data = data;
    b->capacity = capacity_bits;
    b->len = 0;
    if (data && capacity_bits > 0) {
        memset(data, 0, (capacity_bits + 7) / 8);
    }
}

static bool jot_buf_write(JotBuffer *b, int bit) {
    if (b->len >= b->capacity) return false;
    if (bit) {
        b->data[b->len / 8] |= (1 << (7 - (b->len % 8)));
    }
    b->len++;
    return true;
}

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
 */

/* Write a bit pattern from a string (leftmost char = first bit written) */
static bool jot_buf_write_str(JotBuffer *buf, const char *pattern) {
    for (const char *p = pattern; *p; p++) {
        if (!jot_buf_write(buf, *p == '1' ? 1 : 0)) return false;
    }
    return true;
}

/* Calculate size in bits for SKI → Jot encoding */
static u64 ski_jot_size(SKITerm *t) {
    if (!t) return 0;
    
    switch (t->tag) {
        case TERM_K:
            return 5;   /* "11100" */
        case TERM_S:
            return 8;   /* "11111000" */
        case TERM_I:
            /* I = SKK = 1{S}1{K}{K} = 1 + 8 + 1 + 5 + 5 = 20 bits */
            /* Or use 1{1{S}{K}}{K} = 1 + (1+8+5) + 5 = 20 bits */
            return 20;
        case TERM_APP:
            /* {AB} = 1{A}{B} */
            return 1 + ski_jot_size(t->app.left) + ski_jot_size(t->app.right);
        default:
            return 0;
    }
}

/* Emit SKI term to Jot */
static bool emit_ski_to_jot(SKITerm *t, JotBuffer *buf) {
    if (!t) return false;
    
    switch (t->tag) {
        case TERM_K:
            return jot_buf_write_str(buf, "11100");
        case TERM_S:
            return jot_buf_write_str(buf, "11111000");
        case TERM_I:
            /* I = ((S K) K) = 1{1{S}{K}}{K} */
            /* = 1 + 1 + 11111000 + 11100 + 11100 */
            return jot_buf_write(buf, 1) &&
                   jot_buf_write(buf, 1) &&
                   jot_buf_write_str(buf, "11111000") &&
                   jot_buf_write_str(buf, "11100") &&
                   jot_buf_write_str(buf, "11100");
        case TERM_APP:
            /* {AB} = 1{A}{B} */
            if (!jot_buf_write(buf, 1)) return false;
            if (!emit_ski_to_jot(t->app.left, buf)) return false;
            if (!emit_ski_to_jot(t->app.right, buf)) return false;
            return true;
        default:
            return false;
    }
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
SKITerm *jomplement_parse(SKIPool *p, BclStream *s) {
    /* Buffer all bits */
    u64 nbits = s->len - s->pos;
    if (nbits == 0) return ski_i(p);
    
    u8 *bits = malloc((nbits + 7) / 8);
    if (!bits) return NULL;
    
    for (u64 i = 0; i < nbits; i++) {
        int b = bcl_stream_read(s);
        if (b < 0) { free(bits); return NULL; }
        u64 byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        if (bit_idx == 7) bits[byte_idx] = 0;
        if (b) bits[byte_idx] |= (1 << bit_idx);
    }
    
    SKITerm *result = ski_i(p);
    if (!result) { free(bits); return NULL; }
    
    /* Process in order received: bit 0 is rightmost */
    for (u64 i = 0; i < nbits; i++) {
        u64 byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        u32 bit = (bits[byte_idx] >> bit_idx) & 1;
        
        if (bit == 1) {
            /* [W1] → ([W]S)K */
            SKITerm *sk = ski_s(p);
            SKITerm *k = ski_k(p);
            if (!sk || !k) goto fail;
            
            SKITerm *app1 = ski_app(p, result, sk);
            if (!app1) { ski_unref(p, sk); ski_unref(p, k); goto fail; }
            
            SKITerm *app2 = ski_app(p, app1, k);
            if (!app2) { ski_unref(p, app1); ski_unref(p, k); goto fail; }
            
            result = app2;
        } else {
            /* [W0] → S(K[W]) */
            SKITerm *sk = ski_s(p);
            SKITerm *k = ski_k(p);
            if (!sk || !k) goto fail;
            
            SKITerm *kw = ski_app(p, k, result);
            if (!kw) { ski_unref(p, sk); ski_unref(p, k); goto fail; }
            
            SKITerm *skw = ski_app(p, sk, kw);
            if (!skw) { ski_unref(p, sk); ski_unref(p, kw); goto fail; }
            
            result = skw;
        }
    }
    
    free(bits);
    return result;
    
fail:
    free(bits);
    ski_unref(p, result);
    return NULL;
}

/*
 * Jot parsing (RIGHT-TO-LEFT):
 *   [ε] → I
 *   [W0] → ([W]S)K
 *   [W1] → S(K[W])
 *
 * Stream-based version for arbitrary length.
 */
SKITerm *jot_parse(SKIPool *p, BclStream *s) {
    /* Buffer all bits */
    u64 nbits = s->len - s->pos;
    if (nbits == 0) return ski_i(p);
    
    u8 *bits = malloc((nbits + 7) / 8);
    if (!bits) return NULL;
    
    for (u64 i = 0; i < nbits; i++) {
        int b = bcl_stream_read(s);
        if (b < 0) { free(bits); return NULL; }
        u64 byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        if (bit_idx == 7) bits[byte_idx] = 0;
        if (b) bits[byte_idx] |= (1 << bit_idx);
    }
    
    SKITerm *result = ski_i(p);
    if (!result) { free(bits); return NULL; }
    
    /* Process in order received: bit 0 is rightmost */
    for (u64 i = 0; i < nbits; i++) {
        u64 byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        u32 bit = (bits[byte_idx] >> bit_idx) & 1;
        
        if (bit == 0) {
            /* [W0] → ([W]S)K */
            SKITerm *sk = ski_s(p);
            SKITerm *k = ski_k(p);
            if (!sk || !k) goto fail;
            
            SKITerm *app1 = ski_app(p, result, sk);
            if (!app1) { ski_unref(p, sk); ski_unref(p, k); goto fail; }
            
            SKITerm *app2 = ski_app(p, app1, k);
            if (!app2) { ski_unref(p, app1); ski_unref(p, k); goto fail; }
            
            result = app2;
        } else {
            /* [W1] → S(K[W]) */
            SKITerm *sk = ski_s(p);
            SKITerm *k = ski_k(p);
            if (!sk || !k) goto fail;
            
            SKITerm *kw = ski_app(p, k, result);
            if (!kw) { ski_unref(p, sk); ski_unref(p, k); goto fail; }
            
            SKITerm *skw = ski_app(p, sk, kw);
            if (!skw) { ski_unref(p, sk); ski_unref(p, kw); goto fail; }
            
            result = skw;
        }
    }
    
    free(bits);
    return result;
    
fail:
    free(bits);
    ski_unref(p, result);
    return NULL;
}

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
 * Emit SKI term to Jot bitstring (direct encoding, no Iota intermediate)
 */
i32 jot_emit(SKITerm *t, u8 *buf, u32 buf_size) {
    if (!t) return -1;
    
    JotBuffer jb;
    jot_buf_init(&jb, buf, buf_size * 8);
    
    bool ok = emit_ski_to_jot(t, &jb);
    
    if (!ok) return -1;
    return (i32)jb.len;
}

/*
 * Emit SKI term to Jomplement bitstring (bitwise NOT of Jot)
 */
i32 jomplement_emit(SKITerm *t, u8 *buf, u32 buf_size) {
    i32 bits = jot_emit(t, buf, buf_size);
    if (bits < 0) return bits;
    
    /* Flip all bits */
    u32 full_bytes = bits / 8;
    for (u32 i = 0; i < full_bytes; i++) {
        buf[i] = ~buf[i];
    }
    
    /* Flip partial byte bits */
    u32 remaining = bits % 8;
    if (remaining > 0) {
        u8 mask = (0xFF << (8 - remaining)) & 0xFF;
        buf[full_bytes] = (~buf[full_bytes]) & mask;
    }
    
    return bits;
}
