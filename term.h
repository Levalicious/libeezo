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

typedef enum {
    TERM_S,
    TERM_K,
    TERM_I,
    TERM_APP,
} SKITag;

typedef struct SKITerm SKITerm;

struct SKITerm {
    SKITag tag;
    u32 refs;
    union {
        struct { SKITerm *left; SKITerm *right; } app;
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
