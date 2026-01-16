/*
 * term.c - SKI combinator term implementation
 */
#include "term.h"
#include <stdlib.h>
#include <stdio.h>

/*
 * Pool management
 */

void pool_init(SKIPool *p, u32 capacity) {
    p->pool = calloc(capacity, sizeof(SKITerm));
    p->capacity = capacity;
    p->next_free = 0;
    p->freelist = NULL;
}

void pool_free(SKIPool *p) {
    free(p->pool);
    p->pool = NULL;
    p->capacity = 0;
}

void pool_reset(SKIPool *p) {
    p->next_free = 0;
    p->freelist = NULL;
}

u32 pool_used(SKIPool *p) {
    /* Count freelist length */
    u32 free_count = 0;
    for (SKITerm *t = p->freelist; t; t = t->app.left)
        free_count++;
    return p->next_free - free_count;
}

static SKITerm *pool_alloc(SKIPool *p) {
    if (p->freelist) {
        SKITerm *t = p->freelist;
        p->freelist = t->app.left;
        return t;
    }
    if (p->next_free >= p->capacity) {
        return NULL;
    }
    return &p->pool[p->next_free++];
}

static void pool_release(SKIPool *p, SKITerm *t) {
    t->app.left = p->freelist;
    p->freelist = t;
}

/*
 * SKITerm constructors
 */

SKITerm *ski_s(SKIPool *p) {
    SKITerm *t = pool_alloc(p);
    if (!t) return NULL;
    t->tag = TERM_S;
    t->refs = 1;
    return t;
}

SKITerm *ski_k(SKIPool *p) {
    SKITerm *t = pool_alloc(p);
    if (!t) return NULL;
    t->tag = TERM_K;
    t->refs = 1;
    return t;
}

SKITerm *ski_i(SKIPool *p) {
    SKITerm *t = pool_alloc(p);
    if (!t) return NULL;
    t->tag = TERM_I;
    t->refs = 1;
    return t;
}

SKITerm *ski_app(SKIPool *p, SKITerm *left, SKITerm *right) {
    SKITerm *t = pool_alloc(p);
    if (!t) return NULL;
    t->tag = TERM_APP;
    t->refs = 1;
    t->app.left = left;
    t->app.right = right;
    return t;
}

/*
 * Reference counting
 */

SKITerm *ski_ref(SKITerm *t) {
    if (t) t->refs++;
    return t;
}

void ski_unref(SKIPool *p, SKITerm *t) {
    if (!t) return;
    if (--t->refs == 0) {
        if (t->tag == TERM_APP) {
            ski_unref(p, t->app.left);
            ski_unref(p, t->app.right);
        }
        pool_release(p, t);
    }
}

/*
 * Deep copy
 */

SKITerm *ski_copy(SKIPool *p, SKITerm *t) {
    if (!t) return NULL;
    
    switch (t->tag) {
    case TERM_S: return ski_s(p);
    case TERM_K: return ski_k(p);
    case TERM_I: return ski_i(p);
    case TERM_APP: {
        SKITerm *left = ski_copy(p, t->app.left);
        if (!left) return NULL;
        SKITerm *right = ski_copy(p, t->app.right);
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
    default:
        return NULL;
    }
}

/*
 * Reduction
 */

/* Check if node is a redex */
static bool is_redex(SKITerm *t) {
    if (!t || t->tag != TERM_APP) return false;
    SKITerm *left = t->app.left;
    
    /* I x → x */
    if (left->tag == TERM_I) return true;
    
    /* K x y → x */
    if (left->tag == TERM_APP && left->app.left->tag == TERM_K) return true;
    
    /* S x y z → xz(yz) */
    if (left->tag == TERM_APP && 
        left->app.left->tag == TERM_APP &&
        left->app.left->app.left->tag == TERM_S) {
        return true;
    }
    
    return false;
}

/* 
 * Find leftmost-outermost redex (iterative with explicit stack).
 * Returns pointer to the SKITerm* that holds the redex.
 * 
 * We traverse left-first (leftmost), and check for redex at each app node
 * before descending (outermost). Uses a stack to avoid recursion.
 */
#define REDEX_STACK_SIZE 4096

static SKITerm **find_redex(SKITerm **tp) {
    /* Stack of (pointer-to-pointer, phase) pairs */
    /* Phase 0: check this node, then push left */
    /* Phase 1: left done, push right */
    /* Phase 2: done with this node */
    struct { SKITerm **tp; int phase; } stack[REDEX_STACK_SIZE];
    int sp = 0;
    
    if (!*tp || (*tp)->tag != TERM_APP) return NULL;
    
    stack[sp].tp = tp;
    stack[sp].phase = 0;
    sp++;
    
    while (sp > 0) {
        int idx = sp - 1;
        SKITerm **cur = stack[idx].tp;
        SKITerm *t = *cur;
        int phase = stack[idx].phase;
        
        if (phase == 0) {
            /* Check if this is a redex (outermost check) */
            if (is_redex(t)) {
                return cur;
            }
            
            /* Not a redex, try left child first (leftmost) */
            stack[idx].phase = 1;
            
            if (t->tag == TERM_APP && t->app.left && t->app.left->tag == TERM_APP) {
                if (sp >= REDEX_STACK_SIZE) return NULL; /* Stack overflow */
                stack[sp].tp = &t->app.left;
                stack[sp].phase = 0;
                sp++;
            }
        } else if (phase == 1) {
            /* Left done, try right child */
            stack[idx].phase = 2;
            
            if (t->tag == TERM_APP && t->app.right && t->app.right->tag == TERM_APP) {
                if (sp >= REDEX_STACK_SIZE) return NULL; /* Stack overflow */
                stack[sp].tp = &t->app.right;
                stack[sp].phase = 0;
                sp++;
            }
        } else {
            /* Done with this node, pop */
            sp--;
        }
    }
    
    return NULL;
}

/* Perform one reduction step at *tp. Returns true if reduced. */
static bool reduce_step(SKIPool *p, SKITerm **tp) {
    SKITerm *t = *tp;
    
    if (t->tag != TERM_APP) return false;
    
    SKITerm *left = t->app.left;
    SKITerm *right = t->app.right;
    
    /* I x → x */
    if (left->tag == TERM_I) {
        ski_ref(right);
        ski_unref(p, t);
        *tp = right;
        return true;
    }
    
    /* K x y → x */
    if (left->tag == TERM_APP && left->app.left->tag == TERM_K) {
        SKITerm *x = left->app.right;
        ski_ref(x);
        ski_unref(p, t);
        *tp = x;
        return true;
    }
    
    /* S x y z → xz(yz) */
    if (left->tag == TERM_APP && 
        left->app.left->tag == TERM_APP &&
        left->app.left->app.left->tag == TERM_S) {
        SKITerm *x = left->app.left->app.right;
        SKITerm *y = left->app.right;
        SKITerm *z = right;
        
        /* Build xz */
        ski_ref(x);
        ski_ref(z);
        SKITerm *xz = ski_app(p, x, z);
        if (!xz) {
            ski_unref(p, x);
            ski_unref(p, z);
            return false;
        }
        
        /* Build yz */
        ski_ref(y);
        ski_ref(z);
        SKITerm *yz = ski_app(p, y, z);
        if (!yz) {
            ski_unref(p, xz);
            ski_unref(p, y);
            ski_unref(p, z);
            return false;
        }
        
        /* Build xz(yz) */
        SKITerm *result = ski_app(p, xz, yz);
        if (!result) {
            ski_unref(p, xz);
            ski_unref(p, yz);
            return false;
        }
        
        ski_unref(p, t);
        *tp = result;
        return true;
    }
    
    return false;
}

i64 ski_reduce(SKIPool *p, SKITerm **t, u64 max_steps) {
    i64 steps = 0;
    
    while (max_steps == 0 || (u64)steps < max_steps) {
        SKITerm **redex = find_redex(t);
        if (!redex) break;
        
        if (!reduce_step(p, redex)) {
            return -1;
        }
        steps++;
    }
    
    return steps;
}

bool ski_is_hnf(SKITerm *t) {
    return find_redex(&t) == NULL;
}

/*
 * Comparison
 */

bool ski_equal(SKITerm *a, SKITerm *b) {
    if (a == b) return true;
    if (!a || !b) return false;
    if (a->tag != b->tag) return false;
    
    if (a->tag == TERM_APP) {
        return ski_equal(a->app.left, b->app.left) &&
               ski_equal(a->app.right, b->app.right);
    }
    
    return true;
}

/*
 * Debug printing
 */

void ski_fprint(FILE *f, SKITerm *t) {
    if (!t) {
        fprintf(f, "NULL");
        return;
    }
    
    switch (t->tag) {
        case TERM_S: fprintf(f, "S"); break;
        case TERM_K: fprintf(f, "K"); break;
        case TERM_I: fprintf(f, "I"); break;
        case TERM_APP:
            fprintf(f, "(");
            ski_fprint(f, t->app.left);
            fprintf(f, " ");
            ski_fprint(f, t->app.right);
            fprintf(f, ")");
            break;
    }
}

void ski_print(SKITerm *t) {
    ski_fprint(stdout, t);
}

void ski_println(SKITerm *t) {
    ski_print(t);
    printf("\n");
}
