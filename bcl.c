/*
 * bcl.c - Binary Combinatory Logic implementation
 */
#include "bcl.h"
#include "mem.h"
#include <stdlib.h>
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

void bcl_buffer_init(BclBuffer *b) { stack_init(&b->bytes, 1); b->len = 0; }
void bcl_buffer_write(BclBuffer *b, int bit) {
    if (b->len % 8 == 0) stack_push(&b->bytes);   /* a fresh byte, zeroed */
    if (bit) STACK_AT(&b->bytes, u8, b->len / 8) |= (u8)(1 << (7 - b->len % 8));
    b->len++;
}
u64 bcl_buffer_len(const BclBuffer *b) { return b->len; }
const u8 *bcl_buffer_data(const BclBuffer *b) { return (const u8 *)b->bytes.p; }
void bcl_buffer_drop(BclBuffer *b) { stack_drop(&b->bytes); b->len = 0; }

/*
 * BCL Parsing
 *
 * Grammar:
 *   T ::= 00      (K)
 *       | 01      (S)
 *       | 1 T T   (App)
 */

/* A prefix code parsed by an explicit machine, not recursion: an application's frame waits for its left result, then
   its right. leaf_fn reads one non-application code (the first bit, 0, already read): NULL on a truncated or invalid
   code, and then the whole parse fails and what was built is released. */
typedef struct { SKITerm *l; int have_l; } PFrame;
static Stack parse_st = { NULL, 0, 0, sizeof(PFrame) };
static SKITerm *prefix_parse(SKIPool *p, BclStream *s, SKITerm *(*leaf_fn)(SKIPool *, BclStream *)) {
    size_t base = parse_st.n;
    for (;;) {
        int bit = bcl_stream_read(s);
        if (bit < 0) goto fail;   /* unexpected EOF */
        if (bit == 1) { PFrame f = { NULL, 0 }; STACK_PUSH(&parse_st, PFrame, f); continue; }
        SKITerm *t = leaf_fn(p, s);
        if (!t) goto fail;
        /* a complete term: it completes the frames it finishes, innermost first */
        for (;;) {
            if (parse_st.n == base) return t;
            PFrame *f = &STACK_TOP(&parse_st, PFrame);
            if (!f->have_l) { f->l = t; f->have_l = 1; break; }
            t = ski_app(p, f->l, t); parse_st.n--;
        }
    }
fail:
    while (parse_st.n > base) { PFrame f = STACK_POP(&parse_st, PFrame); if (f.have_l) ski_unref(p, f.l); }
    return NULL;
}

/* BCL: after the 0, one more bit: 00 K, 01 S */
static SKITerm *bcl_leaf(SKIPool *p, BclStream *s) {
    int bit2 = bcl_stream_read(s);
    if (bit2 < 0) return NULL;
    return bit2 == 0 ? ski_k(p) : ski_s(p);
}
SKITerm *bcl_parse(SKIPool *p, BclStream *s) { return prefix_parse(p, s, bcl_leaf); }

/*
 * BCL Emission
 */

/* A leaf's pure S K spelling (ski_expansion), written out: '1' application, S = 01, K = 00, other letters expand in
   turn (recursion only through the constant expansion strings) */
static bool emit_expansion(BclBuffer *b, const char *e) {
    for (; *e; e++) {
        switch (*e) {
        case '1': bcl_buffer_write(b, 1); break;
        case 'S': bcl_buffer_write(b, 0); bcl_buffer_write(b, 1); break;
        case 'K': bcl_buffer_write(b, 0); bcl_buffer_write(b, 0); break;
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

/* A prefix-code emission walk: an application writes its 1 and then its left and right subterms, in order - a
   depth-first walk on a heap stack (the right subterm pushed under the left). leaf_fn writes a leaf, false when the
   leaf has no spelling in the format. */
static Stack emit_st = { NULL, 0, 0, sizeof(SKITerm *) };
static bool prefix_emit(SKITerm *t, BclBuffer *b, bool (*leaf_fn)(SKITerm *, BclBuffer *)) {
    if (!t) return false;
    size_t base = emit_st.n;
    STACK_PUSH(&emit_st, SKITerm *, t);
    while (emit_st.n > base) {
        SKITerm *x = STACK_POP(&emit_st, SKITerm *);
        if (x->tag == TERM_APP) {
            bcl_buffer_write(b, 1);
            STACK_PUSH(&emit_st, SKITerm *, x->app.right); STACK_PUSH(&emit_st, SKITerm *, x->app.left);
            continue;
        }
        if (!leaf_fn(x, b)) { emit_st.n = base; return false; }
    }
    return true;
}
/* a term's size under a format: 1 per application plus its leaves' sizes, summed by a walk on a heap stack */
static u64 prefix_size(SKITerm *t, u64 (*leaf_fn)(SKITerm *)) {
    if (!t) return 0;
    size_t base = emit_st.n; u64 n = 0;
    STACK_PUSH(&emit_st, SKITerm *, t);
    while (emit_st.n > base) {
        SKITerm *x = STACK_POP(&emit_st, SKITerm *);
        if (x->tag == TERM_APP) { n += 1; STACK_PUSH(&emit_st, SKITerm *, x->app.right); STACK_PUSH(&emit_st, SKITerm *, x->app.left); continue; }
        n += leaf_fn(x);
    }
    return n;
}

static bool bcl_leaf_emit(SKITerm *t, BclBuffer *b) {
    if (t->tag == TERM_WORD || t->tag == TERM_PRIM) return false;   /* no pure spelling: see xbcl_emit */
    return emit_expansion(b, ski_expansion(t->tag));
}
static u64 bcl_leaf_size(SKITerm *t) { return t->tag == TERM_WORD || t->tag == TERM_PRIM ? 0 : expansion_size(ski_expansion(t->tag)); }
bool bcl_emit(SKITerm *t, BclBuffer *b) { return prefix_emit(t, b, bcl_leaf_emit); }
u64 bcl_size(SKITerm *t) { return prefix_size(t, bcl_leaf_size); }

/*
 * XBCL (see bcl.h)
 */

_Static_assert(XB_PRIM0 + PRIM_COUNT <= 32, "the extended-leaf codes must fit five bits");   /* the codes are bcl.h's */

static bool write_bits(BclBuffer *b, u64 v, int n) {
    for (int i = n - 1; i >= 0; i--) bcl_buffer_write(b, (v >> i) & 1);
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

/* XBCL: after the 0: 0 K, 10 S, 11 ccccc a leaf by code */
static SKITerm *xbcl_leaf(SKIPool *p, BclStream *s) {
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
SKITerm *xbcl_parse(SKIPool *p, BclStream *s) { return prefix_parse(p, s, xbcl_leaf); }

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

static bool xbcl_leaf_emit(SKITerm *t, BclBuffer *b) {
    switch (t->tag) {
    case TERM_K: return write_bits(b, 0, 2);
    case TERM_S: return write_bits(b, 2, 3);
    case TERM_WORD: return write_bits(b, 3, 3) && write_bits(b, XB_WORD, 5) && write_bits(b, t->word, 64);
    case TERM_PRIM: return write_bits(b, 3, 3) && write_bits(b, XB_PRIM0 + t->op, 5);
    default: {
        int c = xb_code(t->tag);
        return c >= 0 && write_bits(b, 3, 3) && write_bits(b, (u64)c, 5);
    }
    }
}
static u64 xbcl_leaf_size(SKITerm *t) {
    switch (t->tag) {
    case TERM_K: return 2;
    case TERM_S: return 3;
    case TERM_WORD: return 3 + 5 + 64;
    default: return 3 + 5;
    }
}
bool xbcl_emit(SKITerm *t, BclBuffer *b) { return prefix_emit(t, b, xbcl_leaf_emit); }
u64 xbcl_size(SKITerm *t) { return prefix_size(t, xbcl_leaf_size); }
