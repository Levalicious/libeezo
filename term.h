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
#include "bn.h"     /* Bn: the limb list a TERM_BIG carries */

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
    TERM_PRIM,      /* a primitive, of arity 2: a machine word's, or a limb list's */
    /* The limb list (2026-09-16). A natural of the theory's limb layer is, at run time, the C list
     * of limbs itself: bn.h's Bn - little-endian u64 limbs, no leading zero - which is what a chain
     * of machine words evaluates to. Every limb primitive IS that list evaluating itself directly
     * (bn_add, bn_monus, bn_mul, Knuth D divmod: one pass of C per limb, not a fold unfolding), so
     * sub is something the actual list in C evaluates straight to its result. A limb list applied
     * passes itself on, as a word does:  b f = f b.  Its primitives force their arguments through
     * that rule, and a machine word is a one-limb list (2^64 - 1 is literally a machine word):
     *   op x y = x (B y op)   unless x is a limb list or a word,
     *   op x y = y (op x)     unless y is a limb list or a word,
     *   op a b = the C list's own answer. */
    TERM_BIG,       /* a limb list: bn.h's Bn */
    /* A denoted number (M17): a flat power a ^ b, both limb lists, for values no limb list can hold.
     * It is a Nat like the limb list is, passes itself the same way, and the limb primitives act on it
     * by the laws proved in stdlib/tt (pow_add, pow_mul) or materialize it when the result does fit. */
    TERM_DEN,
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
    PRIM_WORD_COUNT,        /* the machine words' primitives end here: ADD ... DIVMOD */
    /* Limb primitives (2026-09-16), arity 2 on the limb list, named for the word primitives they
     * lift. BADD BSUB BMUL are bn_add, bn_monus, bn_mul; BDIVMOD is the Scott pair (quotient,
     * remainder), with x / 0 = 0 and x % 0 = x; BLT BEQ are a Scott boolean on bn_cmp; BPOW is
     * bn_pow, the successor recursion x ^ s(y) = x * x ^ y in one pass; BMINV is the modular
     * inverse minv x y = x ^ (y - 2) mod y (Fermat: y's inverse is a divisor of it). The rest of
     * the arithmetic (truthy, select, min, max, truncated difference) is equations over these, not
     * primitives. A machine word is accepted where a list is, as its one limb. */
    PRIM_BADD = PRIM_WORD_COUNT, PRIM_BSUB, PRIM_BMUL, PRIM_BDIVMOD, PRIM_BLT, PRIM_BEQ,
    PRIM_BPOW, PRIM_BMINV,
    PRIM_COUNT
} PrimOp;

/* A limb primitive taking two limb lists (a word is one), rather than two machine words */
static inline bool prim_is_limb(PrimOp op) { return op >= PRIM_WORD_COUNT && op < PRIM_COUNT; }

typedef struct SKITerm SKITerm;

struct SKITerm {
    SKITag tag;
    u32 refs;
    union {
        struct { SKITerm *left; SKITerm *right; } app;
        u64 word;       /* TERM_WORD */
        PrimOp op;      /* TERM_PRIM */
        Bn *big;        /* TERM_BIG: the limb list, owned by the term */
        struct { Bn *base, *exp; } den;   /* TERM_DEN: base ^ exp, both owned by the term */
    };
};

/* Allocation pool for terms */
typedef struct {
    SKITerm *pool;
    u32 capacity;
    u32 next_free;
    SKITerm *freelist;
} SKIPool;

/* Pool management */
void pool_init(SKIPool *p, u32 capacity);
void pool_free(SKIPool *p);
void pool_reset(SKIPool *p);  /* Clear all terms, reuse memory */
u32  pool_used(SKIPool *p);   /* Count of allocated terms */

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
/* A limb list leaf, taking ownership of b (a fresh leaf on failure frees it and returns NULL) */
SKITerm *ski_big(SKIPool *p, Bn *b);
SKITerm *ski_den(SKIPool *p, Bn *base, Bn *exp);   /* base ^ exp, both taken over */

/* How many arguments a leaf takes before it reduces (a word: none, it is a value) */
int ski_arity(SKITag tag);
/* The primitive's name, without the leading '#' */
const char *prim_name(PrimOp op);
/* The pure S K spelling of a leaf, for the formats that have no extended leaves: a string over
 * '1' (application), 'S', 'K' and letters naming other leaves to expand in turn (I B C).
 * NULL for words, limb lists and primitives, which have no such spelling. */
const char *ski_expansion(SKITag tag);
/* The term with B C T R replaced by their S K trees (one shared tree per leaf): what a pure format
 * carries. NULL if the term has words or primitives, which no pure spelling can carry. */
SKITerm *ski_expand_pure(SKIPool *p, SKITerm *t);
/* Does the term contain a word or a primitive anywhere? (then it needs XBCL or the ELF) */
bool ski_uses_words(SKITerm *t);
/* Does the term contain a limb list, or a limb primitive, anywhere? (the simple interpreter runs
 * these: the limb primitives are the C list itself; the STG machine and the native JIT refuse them
 * for now, main.c asks this before either is entered) */
bool ski_uses_bigs(SKITerm *t);
/* Refuse a limb list where the evaluator has none: it runs on the simple interpreter (-s), whose
 * cells carry the C list (bn.h) directly. Never returns. */
void ski_refuse_limb(const char *who);
void ski_refuse_den(const char *who);
void ski_refuse_den_op(PrimOp op);   /* the operation wanted a number that no limb list holds */
/* Does the term contain any extended leaf (B C T R, words, primitives, limb lists)? */
bool ski_uses_extended(SKITerm *t);
/* The value of a saturated primitive on two words: a fresh term, NULL if the pool is exhausted */
SKITerm *prim_apply(SKIPool *p, PrimOp op, u64 a, u64 b);
/* The value of a saturated limb primitive on two limb lists, each a TERM_BIG or a TERM_WORD (a word
 * is its one limb): a fresh term, NULL if the pool is exhausted */
SKITerm *prim_big_apply(SKIPool *p, PrimOp op, SKITerm *x, SKITerm *y);

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
