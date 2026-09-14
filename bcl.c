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

/* A leaf's pure S K spelling (ski_expansion), written out: '1' application, S = 01, K = 00, other letters expand in turn */
static bool emit_expansion(BclBuffer *b, const char *e) {
    for (; *e; e++) {
        switch (*e) {
        case '1': if (!bcl_buffer_write(b, 1)) return false; break;
        case 'S': if (!bcl_buffer_write(b, 0) || !bcl_buffer_write(b, 1)) return false; break;
        case 'K': if (!bcl_buffer_write(b, 0) || !bcl_buffer_write(b, 0)) return false; break;
        case 'I': if (!emit_expansion(b, ski_expansion(TERM_I))) return false; break;
        case 'B': if (!emit_expansion(b, ski_expansion(TERM_B))) return false; break;
        case 'C': if (!emit_expansion(b, ski_expansion(TERM_C))) return false; break;
        default: return false;
        }
    }
    return true;
}

static u64 expansion_size(const char *e) {
    u64 n = 0;
    for (; *e; e++) {
        switch (*e) {
        case '1': n += 1; break;
        case 'S': case 'K': n += 2; break;
        case 'I': n += expansion_size(ski_expansion(TERM_I)); break;
        case 'B': n += expansion_size(ski_expansion(TERM_B)); break;
        case 'C': n += expansion_size(ski_expansion(TERM_C)); break;
        default: break;
        }
    }
    return n;
}

bool bcl_emit(SKITerm *t, BclBuffer *b) {
    if (!t) return false;
    
    switch (t->tag) {
    case TERM_APP:
        return bcl_buffer_write(b, 1) &&
               bcl_emit(t->app.left, b) &&
               bcl_emit(t->app.right, b);
    case TERM_WORD:
    case TERM_PRIM:
        return false;   /* no pure spelling: see xbcl_emit */
    default:
        return emit_expansion(b, ski_expansion(t->tag));
    }
}

/*
 * Size calculation
 */

u64 bcl_size(SKITerm *t) {
    if (!t) return 0;
    
    switch (t->tag) {
    case TERM_APP:
        return 1 + bcl_size(t->app.left) + bcl_size(t->app.right);
    case TERM_WORD:
    case TERM_PRIM:
        return 0;
    default:
        return expansion_size(ski_expansion(t->tag));
    }
}

/*
 * XBCL (see bcl.h)
 */

enum { XB_I = 0, XB_B, XB_C, XB_T, XB_R, XB_WORD, XB_PRIM0 };

static bool write_bits(BclBuffer *b, u64 v, int n) {
    for (int i = n - 1; i >= 0; i--)
        if (!bcl_buffer_write(b, (v >> i) & 1)) return false;
    return true;
}

static int read_bits(BclStream *s, int n, u64 *out) {
    u64 v = 0;
    for (int i = 0; i < n; i++) {
        int bit = bcl_stream_read(s);
        if (bit < 0) return -1;
        v = (v << 1) | (u64)bit;
    }
    *out = v;
    return 0;
}

SKITerm *xbcl_parse(SKIPool *p, BclStream *s) {
    int bit = bcl_stream_read(s);
    if (bit < 0) return NULL;
    if (bit == 1) {
        SKITerm *left = xbcl_parse(p, s);
        if (!left) return NULL;
        SKITerm *right = xbcl_parse(p, s);
        if (!right) { ski_unref(p, left); return NULL; }
        SKITerm *app = ski_app(p, left, right);
        if (!app) { ski_unref(p, left); ski_unref(p, right); return NULL; }
        return app;
    }
    int b2 = bcl_stream_read(s);
    if (b2 < 0) return NULL;
    if (b2 == 0) return ski_k(p);
    int b3 = bcl_stream_read(s);
    if (b3 < 0) return NULL;
    if (b3 == 0) return ski_s(p);
    u64 code;
    if (read_bits(s, 5, &code) < 0) return NULL;
    switch (code) {
    case XB_I: return ski_i(p);
    case XB_B: return ski_b(p);
    case XB_C: return ski_c(p);
    case XB_T: return ski_t(p);
    case XB_R: return ski_r(p);
    case XB_WORD: {
        u64 w;
        if (read_bits(s, 64, &w) < 0) return NULL;
        return ski_word(p, w);
    }
    default:
        if (code >= XB_PRIM0 && code < XB_PRIM0 + PRIM_COUNT) return ski_prim(p, (PrimOp)(code - XB_PRIM0));
        return NULL;
    }
}

static int xb_code(SKITag tag) {
    switch (tag) {
    case TERM_I: return XB_I;
    case TERM_B: return XB_B;
    case TERM_C: return XB_C;
    case TERM_T: return XB_T;
    case TERM_R: return XB_R;
    default: return -1;
    }
}

bool xbcl_emit(SKITerm *t, BclBuffer *b) {
    if (!t) return false;
    switch (t->tag) {
    case TERM_K: return write_bits(b, 0, 2);
    case TERM_S: return write_bits(b, 2, 3);
    case TERM_APP: return bcl_buffer_write(b, 1) && xbcl_emit(t->app.left, b) && xbcl_emit(t->app.right, b);
    case TERM_WORD: return write_bits(b, 3, 3) && write_bits(b, XB_WORD, 5) && write_bits(b, t->word, 64);
    case TERM_PRIM: return write_bits(b, 3, 3) && write_bits(b, XB_PRIM0 + t->op, 5);
    default: {
        int c = xb_code(t->tag);
        return c >= 0 && write_bits(b, 3, 3) && write_bits(b, (u64)c, 5);
    }
    }
}

u64 xbcl_size(SKITerm *t) {
    if (!t) return 0;
    switch (t->tag) {
    case TERM_K: return 2;
    case TERM_S: return 3;
    case TERM_APP: return 1 + xbcl_size(t->app.left) + xbcl_size(t->app.right);
    case TERM_WORD: return 3 + 5 + 64;
    default: return 3 + 5;
    }
}
