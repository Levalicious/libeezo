/*
 * bcl.c - Binary Combinatory Logic implementation
 */
#include "bcl.h"
#include <string.h>

/*
 * Bit stream operations
 */

void bcl_stream_init(BclStream *s, const u8 *data, u64 nbits) {
    s->data = data;
    s->len = nbits;
    s->pos = 0;
}

int bcl_stream_read(BclStream *s) {
    if (s->pos >= s->len) return -1;
    u64 byte_idx = s->pos / 8;
    u64 bit_idx = s->pos % 8;
    s->pos++;
    /* MSB first within each byte */
    return (s->data[byte_idx] >> (7 - bit_idx)) & 1;
}

int bcl_stream_peek(BclStream *s) {
    if (s->pos >= s->len) return -1;
    u64 byte_idx = s->pos / 8;
    u64 bit_idx = s->pos % 8;
    return (s->data[byte_idx] >> (7 - bit_idx)) & 1;
}

bool bcl_stream_eof(BclStream *s) {
    return s->pos >= s->len;
}

u64 bcl_stream_pos(BclStream *s) {
    return s->pos;
}

/*
 * Bit buffer operations
 */

void bcl_buffer_init(BclBuffer *b, u8 *data, u64 capacity_bits) {
    b->data = data;
    b->capacity = capacity_bits;
    b->len = 0;
    /* Zero the buffer */
    memset(data, 0, (capacity_bits + 7) / 8);
}

bool bcl_buffer_write(BclBuffer *b, int bit) {
    if (b->len >= b->capacity) return false;
    u64 byte_idx = b->len / 8;
    u64 bit_idx = b->len % 8;
    if (bit) {
        b->data[byte_idx] |= (1 << (7 - bit_idx));
    }
    b->len++;
    return true;
}

u64 bcl_buffer_len(BclBuffer *b) {
    return b->len;
}

/*
 * BCL Parsing
 *
 * Grammar:
 *   T ::= 00      (K)
 *       | 01      (S)
 *       | 1 T T   (App)
 */

SKITerm *bcl_parse(SKIPool *p, BclStream *s) {
    int bit = bcl_stream_read(s);
    if (bit < 0) return NULL;  /* unexpected EOF */
    
    if (bit == 0) {
        /* 00 = K, 01 = S */
        int bit2 = bcl_stream_read(s);
        if (bit2 < 0) return NULL;
        if (bit2 == 0) {
            return ski_k(p);
        } else {
            return ski_s(p);
        }
    } else {
        /* 1 X Y = App(X, Y) */
        SKITerm *left = bcl_parse(p, s);
        if (!left) return NULL;
        
        SKITerm *right = bcl_parse(p, s);
        if (!right) {
            ski_unref(p, left);
            return NULL;
        }
        
        SKITerm *app = ski_app(p, left, right);
        if (!app) {
            ski_unref(p, left);
            ski_unref(p, right);
            return NULL;
        }
        return app;
    }
}

/*
 * BCL Emission
 */

bool bcl_emit(SKITerm *t, BclBuffer *b) {
    if (!t) return false;
    
    switch (t->tag) {
    case TERM_K:
        return bcl_buffer_write(b, 0) && bcl_buffer_write(b, 0);
    case TERM_S:
        return bcl_buffer_write(b, 0) && bcl_buffer_write(b, 1);
    case TERM_I:
        /* I = SKK, emit as 1 01 1 00 00 = 1011 0000 */
        /* Actually: App(App(S,K),K) = 1 1 01 00 00 */
        return bcl_buffer_write(b, 1) &&
               bcl_buffer_write(b, 1) &&
               bcl_buffer_write(b, 0) &&
               bcl_buffer_write(b, 1) &&
               bcl_buffer_write(b, 0) &&
               bcl_buffer_write(b, 0) &&
               bcl_buffer_write(b, 0) &&
               bcl_buffer_write(b, 0);
    case TERM_APP:
        return bcl_buffer_write(b, 1) &&
               bcl_emit(t->app.left, b) &&
               bcl_emit(t->app.right, b);
    default:
        return false;
    }
}

/*
 * Size calculation
 */

u64 bcl_size(SKITerm *t) {
    if (!t) return 0;
    
    switch (t->tag) {
    case TERM_K: return 2;  /* 00 */
    case TERM_S: return 2;  /* 01 */
    case TERM_I: return 8;  /* 1 1 01 00 00 (SKK) */
    case TERM_APP:
        return 1 + bcl_size(t->app.left) + bcl_size(t->app.right);
    default:
        return 0;
    }
}
