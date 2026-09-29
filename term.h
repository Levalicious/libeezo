/*
 * term.h - SKI combinator term representation
 *
 * Core data structure for Eezo. Terms are DAGs with reference counting.
 * Supports S, K, I combinators and application.
 */
#ifndef EEZO_TERM_H
#define EEZO_TERM_H

#include <stdio.h>
#include "types.h"
#include "mem.h"

typedef enum {
    TERM_S,
    TERM_K,
    TERM_I,
    TERM_APP,
    /* The extended leaves (2026-09-13). Kiselyov's combinators, native rather than S K trees:
     *   B f g x = f (g x)     C f g x = f x g     T x f = f x     R x f g = f g x
     * and machine words with their primitives. A word applied passes itself on (the
     * Reduceron's #):  #w f = f #w.  A primitive forces its arguments through that rule:
     *   op x y = x (B y op)   unless x is a word,
     *   op x y = y (op x)     unless y is a word,
     *   op #a #b = the value.
     * Every evaluator implements exactly these rules. */
    TERM_B,
    TERM_C,
    TERM_T,
    TERM_R,
    TERM_WORD,      /* a u64 */
    TERM_PRIM,      /* a primitive, of arity 2 on machine words */
} SKITag;

/*
 * Word primitives, all of arity 2 on u64 with wrap-around. The results:
 *   ADD SUB MUL AND OR XOR: a word.
 *   SHL SHR: (a * 2^b) mod 2^64 and floor(a / 2^b), so a count >= 64 gives 0.
 *   EQ LT: a Scott boolean, true = K, false = K I.
 *   ADDC (sum, carry)  SUBB (difference, borrow)  MULL (low, high: the 128-bit product)
 *   DIVMOD (quotient, remainder), with x / 0 = 0 and x % 0 = x so that division is total:
 *   these are Scott pairs \p. p x y, spelled with the native leaves as C (T x) y.
 */
typedef enum {
    PRIM_ADD, PRIM_SUB, PRIM_MUL, PRIM_AND, PRIM_OR, PRIM_XOR, PRIM_SHL, PRIM_SHR,
    PRIM_EQ, PRIM_LT, PRIM_ADDC, PRIM_SUBB, PRIM_MULL, PRIM_DIVMOD,
    PRIM_COUNT
} PrimOp;

typedef struct SKITerm SKITerm;

struct SKITerm {
    SKITag tag;
    u64 refs;       /* 64 bits: a term shared past 2^32 references is not an overflow */
    union {
        struct { SKITerm *left; SKITerm *right; } app;
        u64 word;       /* TERM_WORD */
        PrimOp op;      /* TERM_PRIM */
    };
};

/* The terms' pool: a pool of the memory layer (mem.h). It grows; running out of memory is the layer's resource abort,
 * so no constructor below returns NULL. */
typedef struct { Pool p; } SKIPool;

void ski_pool_init(SKIPool *p);
void ski_pool_drop(SKIPool *p);        /* every term, and the pages */
size_t ski_pool_live(SKIPool *p);      /* terms currently allocated */

/* SKITerm constructors */
SKITerm *ski_s(SKIPool *p);
SKITerm *ski_k(SKIPool *p);
SKITerm *ski_i(SKIPool *p);
SKITerm *ski_app(SKIPool *p, SKITerm *left, SKITerm *right);
SKITerm *ski_b(SKIPool *p);
SKITerm *ski_c(SKIPool *p);
SKITerm *ski_t(SKIPool *p);
SKITerm *ski_r(SKIPool *p);
SKITerm *ski_word(SKIPool *p, u64 w);
SKITerm *ski_prim(SKIPool *p, PrimOp op);

/* How many arguments a leaf takes before it reduces (a word: none, it is a value) */
int ski_arity(SKITag tag);
/* The primitive's name, without the leading '#' */
const char *prim_name(PrimOp op);
/* The pure S K spelling of a leaf, for the formats that have no extended leaves: a string over
 * '1' (application), 'S', 'K' and letters naming other leaves to expand in turn (I B C).
 * NULL for words and primitives, which have no such spelling. */
const char *ski_expansion(SKITag tag);
/* The term with B C T R replaced by their S K trees (one shared tree per leaf): what a pure format
 * carries. NULL if the term has words or primitives, which no pure spelling can carry. */
SKITerm *ski_expand_pure(SKIPool *p, SKITerm *t);
/* Does the term contain a word or a primitive anywhere? (then it needs XBCL or the ELF) */
bool ski_uses_words(SKITerm *t);
/* Does the term contain any extended leaf (B C T R, words, primitives)? */
bool ski_uses_extended(SKITerm *t);
/* The value of a saturated primitive on two words: a fresh term (NULL only for an unknown primitive) */
SKITerm *prim_apply(SKIPool *p, PrimOp op, u64 a, u64 b);

/* Reference counting */
SKITerm *ski_ref(SKITerm *t);
void ski_unref(SKIPool *p, SKITerm *t);

/* Deep copy */
SKITerm *ski_copy(SKIPool *p, SKITerm *t);

/* Reduction (normal order: leftmost-outermost).
 * ski_reduce: to full normal form (reduces inside arguments too).
 * ski_reduce_mode(..., whnf=true): head reduction only, stops at weak
 * head normal form. Returns steps taken, -1 on error. */
i64 ski_reduce(SKIPool *p, SKITerm **t, u64 max_steps);
i64 ski_reduce_mode(SKIPool *p, SKITerm **t, u64 max_steps, bool whnf);
bool ski_is_nf(SKITerm *t);     /* no redex anywhere */
bool ski_is_whnf(SKITerm *t);   /* no redex on the head spine */

/* Comparison */
bool ski_equal(SKITerm *a, SKITerm *b);

/* Type checks */
static inline bool ski_is_s(SKITerm *t) { return t && t->tag == TERM_S; }
static inline bool ski_is_k(SKITerm *t) { return t && t->tag == TERM_K; }
static inline bool ski_is_i(SKITerm *t) { return t && t->tag == TERM_I; }
static inline bool ski_is_app(SKITerm *t) { return t && t->tag == TERM_APP; }

/* Debug */
void ski_fprint(FILE *f, SKITerm *t);
void ski_print(SKITerm *t);
void ski_println(SKITerm *t);

#endif /* EEZO_TERM_H */
