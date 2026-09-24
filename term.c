#include "res.h"
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
    p->pool = rcalloc(capacity, sizeof(SKITerm));
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

static SKITerm *leaf(SKIPool *p, SKITag tag) {
    SKITerm *t = pool_alloc(p);
    if (!t) return NULL;
    t->tag = tag;
    t->refs = 1;
    return t;
}
SKITerm *ski_b(SKIPool *p) { return leaf(p, TERM_B); }
SKITerm *ski_c(SKIPool *p) { return leaf(p, TERM_C); }
SKITerm *ski_t(SKIPool *p) { return leaf(p, TERM_T); }
SKITerm *ski_r(SKIPool *p) { return leaf(p, TERM_R); }
SKITerm *ski_word(SKIPool *p, u64 w) { SKITerm *t = leaf(p, TERM_WORD); if (t) t->word = w; return t; }
SKITerm *ski_prim(SKIPool *p, PrimOp op) { SKITerm *t = leaf(p, TERM_PRIM); if (t) t->op = op; return t; }
SKITerm *ski_big(SKIPool *p, Bn *b) {
    SKITerm *t = leaf(p, TERM_BIG);
    if (!t) { bn_free(b); return NULL; }   /* the leaf owns the list from here */
    t->big = b;
    return t;
}

SKITerm *ski_den(SKIPool *p, Bn *base, Bn *exp) {
    SKITerm *t = leaf(p, TERM_DEN);
    if (!t) { bn_free(base); bn_free(exp); return NULL; }
    t->den.base = base; t->den.exp = exp;
    return t;
}

int ski_arity(SKITag tag) {
    switch (tag) {
    case TERM_S: case TERM_B: case TERM_C: case TERM_R: return 3;
    case TERM_K: case TERM_T: case TERM_PRIM: return 2;
    case TERM_I: case TERM_WORD: case TERM_BIG: case TERM_DEN: return 1;
    default: return 0;
    }
}

const char *prim_name(PrimOp op) {
    static const char *names[PRIM_COUNT] = {
        "add", "sub", "mul", "and", "or", "xor", "shl", "shr",
        "eq", "lt", "addc", "subb", "mull", "divmod",
        "badd", "bsub", "bmul", "bdivmod", "blt", "beq",
        "bpow", "bminv"
    };
    return op < PRIM_COUNT ? names[op] : "?";
}

const char *ski_expansion(SKITag tag) {
    switch (tag) {
    case TERM_S: return "S";
    case TERM_K: return "K";
    case TERM_I: return "11SKK";             /* S K K */
    case TERM_B: return "11S1KSK";           /* S (K S) K */
    case TERM_C: return "11S11S1KBS1KK";     /* S (S (K B) S) (K K) */
    case TERM_T: return "1CI";               /* C I */
    case TERM_R: return "1CC";               /* C C */
    default: return NULL;
    }
}

/* A leaf's expansion string (ski_expansion) as a term */
static SKITerm *expansion_term(SKIPool *p, const char **e) {
    char c = *(*e)++;
    switch (c) {
    case 'S': return ski_s(p);
    case 'K': return ski_k(p);
    case 'I': { const char *x = ski_expansion(TERM_I); return expansion_term(p, &x); }
    case 'B': { const char *x = ski_expansion(TERM_B); return expansion_term(p, &x); }
    case 'C': { const char *x = ski_expansion(TERM_C); return expansion_term(p, &x); }
    case '1': {
        SKITerm *l = expansion_term(p, e);
        if (!l) return NULL;
        SKITerm *r = expansion_term(p, e);
        if (!r) { ski_unref(p, l); return NULL; }
        SKITerm *a = ski_app(p, l, r);
        if (!a) { ski_unref(p, l); ski_unref(p, r); }
        return a;
    }
    default: return NULL;
    }
}

typedef struct { SKITerm *leaf[4]; } PureLeaves;   /* B C T R, built once each */

static SKITerm *expand_pure(SKIPool *p, SKITerm *t, PureLeaves *pl) {
    switch (t->tag) {
    case TERM_S: return ski_s(p);
    case TERM_K: return ski_k(p);
    case TERM_I: return ski_i(p);
    case TERM_B: case TERM_C: case TERM_T: case TERM_R: {
        int i = t->tag - TERM_B;
        if (!pl->leaf[i]) { const char *x = ski_expansion(t->tag); pl->leaf[i] = expansion_term(p, &x); }
        return ski_ref(pl->leaf[i]);
    }
    case TERM_APP: {
        SKITerm *l = expand_pure(p, t->app.left, pl);
        if (!l) return NULL;
        SKITerm *r = expand_pure(p, t->app.right, pl);
        if (!r) { ski_unref(p, l); return NULL; }
        SKITerm *a = ski_app(p, l, r);
        if (!a) { ski_unref(p, l); ski_unref(p, r); }
        return a;
    }
    default: return NULL;   /* words, limb lists and primitives */
    }
}

SKITerm *ski_expand_pure(SKIPool *p, SKITerm *t) {
    PureLeaves pl = { { NULL, NULL, NULL, NULL } };
    SKITerm *r = expand_pure(p, t, &pl);
    for (int i = 0; i < 4; i++) ski_unref(p, pl.leaf[i]);   /* the result holds its own references */
    return r;
}

bool ski_uses_words(SKITerm *t) {
    if (!t) return false;
    if (t->tag == TERM_APP) return ski_uses_words(t->app.left) || ski_uses_words(t->app.right);
    return t->tag == TERM_WORD || t->tag == TERM_PRIM;
}

bool ski_uses_bigs(SKITerm *t) {
    if (!t) return false;
    if (t->tag == TERM_APP) return ski_uses_bigs(t->app.left) || ski_uses_bigs(t->app.right);
    return t->tag == TERM_BIG || (t->tag == TERM_PRIM && prim_is_limb(t->op));
}

void ski_refuse_limb(const char *who) {
    fprintf(stderr, "eezo: %s has no limb primitives yet: a limb list is the C list of limbs (bn.h),\n"
                    "      and it evaluates itself on the simple interpreter, so run this program with -s\n", who);
    exit(1);
}

void ski_refuse_den(const char *who) {
    fprintf(stderr, "eezo: %s has no denoted numbers yet: a power no limb list fits is a value the\n"
                    "      simple interpreter names, so run this program with -s\n", who);
    exit(1);
}

bool ski_uses_extended(SKITerm *t) {
    if (!t) return false;
    if (t->tag == TERM_APP) return ski_uses_extended(t->app.left) || ski_uses_extended(t->app.right);
    return t->tag != TERM_S && t->tag != TERM_K && t->tag != TERM_I;
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
        } else if (t->tag == TERM_BIG) {
            bn_free(t->big);
        } else if (t->tag == TERM_DEN) {
            bn_free(t->den.base); bn_free(t->den.exp);
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
    case TERM_B: return ski_b(p);
    case TERM_C: return ski_c(p);
    case TERM_T: return ski_t(p);
    case TERM_R: return ski_r(p);
    case TERM_WORD: return ski_word(p, t->word);
    case TERM_PRIM: return ski_prim(p, t->op);
    case TERM_BIG: return ski_big(p, bn_copy(t->big));
    case TERM_DEN: return ski_den(p, bn_copy(t->den.base), bn_copy(t->den.exp));
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

/*
 * A redex is a leaf applied to exactly its arity of arguments (a deeper spine
 * is not: the redex sits further in, on the left). The spine is read up to
 * three applications deep, which covers every arity.
 */
typedef struct { SKITerm *head; SKITerm *a[3]; int n; } Spine;

/* t's head leaf and its arguments, a[0] nearest the head; n = -1 if the head is not a leaf within three applications */
static void spine(SKITerm *t, Spine *s) {
    SKITerm *args[3];
    int n = 0;
    SKITerm *cur = t;
    while (cur->tag == TERM_APP && n < 3) { args[n++] = cur->app.right; cur = cur->app.left; }
    if (cur->tag == TERM_APP) { s->n = -1; return; }
    s->head = cur;
    s->n = n;
    for (int i = 0; i < n; i++) s->a[i] = args[n - 1 - i];
}

/* Check if node is a redex */
static bool is_redex(SKITerm *t) {
    if (!t || t->tag != TERM_APP) return false;
    Spine s;
    spine(t, &s);
    return s.n >= 0 && s.n == ski_arity(s.head->tag);
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

/* An application of two owned terms; on failure both are released and NULL returned */
static SKITerm *app2(SKIPool *p, SKITerm *l, SKITerm *r) {
    if (!l || !r) { ski_unref(p, l); ski_unref(p, r); return NULL; }
    SKITerm *t = ski_app(p, l, r);
    if (!t) { ski_unref(p, l); ski_unref(p, r); }
    return t;
}

/* pair x y = \p. p x y = C (T x) y */
static SKITerm *mk_pair(SKIPool *p, SKITerm *x, SKITerm *y) {
    return app2(p, app2(p, ski_c(p), app2(p, ski_t(p), x)), y);
}

/* true = K, false = K I */
static SKITerm *mk_bool(SKIPool *p, int b) {
    return b ? ski_k(p) : app2(p, ski_k(p), ski_i(p));
}

SKITerm *prim_apply(SKIPool *p, PrimOp op, u64 a, u64 b) {
    switch (op) {
    case PRIM_ADD: return ski_word(p, a + b);
    case PRIM_SUB: return ski_word(p, a - b);
    case PRIM_MUL: return ski_word(p, a * b);
    case PRIM_AND: return ski_word(p, a & b);
    case PRIM_OR:  return ski_word(p, a | b);
    case PRIM_XOR: return ski_word(p, a ^ b);
    case PRIM_SHL: return ski_word(p, b >= 64 ? 0 : a << b);
    case PRIM_SHR: return ski_word(p, b >= 64 ? 0 : a >> b);
    case PRIM_EQ:  return mk_bool(p, a == b);
    case PRIM_LT:  return mk_bool(p, a < b);
    case PRIM_ADDC: { u64 s = a + b; return mk_pair(p, ski_word(p, s), ski_word(p, s < a)); }
    case PRIM_SUBB: return mk_pair(p, ski_word(p, a - b), ski_word(p, a < b));
    case PRIM_MULL: {
        unsigned __int128 m = (unsigned __int128)a * b;
        return mk_pair(p, ski_word(p, (u64)m), ski_word(p, (u64)(m >> 64)));
    }
    case PRIM_DIVMOD:
        if (b == 0) return mk_pair(p, ski_word(p, 0), ski_word(p, a));
        return mk_pair(p, ski_word(p, a / b), ski_word(p, a % b));
    default: return NULL;
    }
}

/* A limb operand is a limb list or a machine word: the word is its one limb, and 2^64 - 1 is
 * literally a machine word. Its list: the leaf's own, or the word's single limb in tmp. */
static bool is_limb_operand(SKITerm *t) { return t->tag == TERM_BIG || t->tag == TERM_WORD || t->tag == TERM_DEN; }
static const Bn *limb_of(SKITerm *t, Bn *tmp) {
    if (t->tag == TERM_BIG) return t->big;
    tmp->limb = t->word ? &t->word : NULL;   /* zero is the empty list: no limb at all */
    tmp->n = t->word ? 1 : 0;
    return tmp;
}

/* a ^ e: materialized when a limb list can hold it, denoted when none can (M17) */
static SKITerm *den_make(SKIPool *p, Bn *base, Bn *exp) {
    if (!bn_fits_pow(base, exp)) return ski_den(p, base, exp);
    SKITerm *t = ski_big(p, bn_pow(base, exp));
    bn_free(base); bn_free(exp);
    return t;
}
/* the value itself, for a denoted number that has one: NULL when no limb list holds it */
static const Bn *den_value(SKITerm *t, Bn **owned, Bn *tmp) {
    if (t->tag != TERM_DEN) return limb_of(t, tmp);
    if (!bn_fits_pow(t->den.base, t->den.exp)) return NULL;
    *owned = bn_pow(t->den.base, t->den.exp);
    return *owned;
}
/* a number the machine can only denote reached an operation that wanted it held */
void ski_refuse_den_op(PrimOp op) {
    fprintf(stderr, "eezo: %s needs a number this machine can hold, and its argument is only denoted: "
                    "the value is a power no limb list fits (M17)\n", prim_name(op));
    exit(1);
}

/* The C list evaluating itself: one pass over the limbs, not a fold unfolding */
SKITerm *prim_big_apply(SKIPool *p, PrimOp op, SKITerm *x, SKITerm *y) {
    Bn tx, ty;
    const Bn *a = limb_of(x, &tx), *b = limb_of(y, &ty);
    /* A denoted number is a Nat the machine names instead of holding. The limb primitives act on it by
       the laws stdlib/tt proves (pow_add, pow_mul), or by building it when a limb list can hold it, and
       when neither is true they refuse by name - never a silent answer. */
    if (x->tag == TERM_DEN || y->tag == TERM_DEN) {
        if (op == PRIM_BPOW && x->tag == TERM_DEN && y->tag != TERM_DEN)
            return den_make(p, bn_copy(x->den.base), bn_mul(x->den.exp, limb_of(y, &ty)));   /* pow_mul */
        if (op == PRIM_BMUL && x->tag == TERM_DEN && y->tag == TERM_DEN && bn_cmp(x->den.base, y->den.base) == 0)
            return den_make(p, bn_copy(x->den.base), bn_add(x->den.exp, y->den.exp));        /* pow_add */
        /* everything else wants the number itself: build the operands, or say why not */
        Bn *ox = NULL, *oy = NULL;
        const Bn *vx = den_value(x, &ox, &tx), *vy = den_value(y, &oy, &ty);
        if (!vx || !vy) { bn_free(ox); bn_free(oy); ski_refuse_den_op(op); }
        SKITerm *mx = ski_big(p, bn_copy(vx)), *my = ski_big(p, bn_copy(vy));
        bn_free(ox); bn_free(oy);
        SKITerm *r = (mx && my) ? prim_big_apply(p, op, mx, my) : NULL;
        ski_unref(p, mx); ski_unref(p, my);
        return r;
    }
    switch (op) {
    case PRIM_BADD: return ski_big(p, bn_add(a, b));
    case PRIM_BSUB: return ski_big(p, bn_monus(a, b));
    case PRIM_BMUL: return ski_big(p, bn_mul(a, b));
    case PRIM_BDIVMOD: {
        Bn *q, *r;
        bn_divmod(a, b, &q, &r);
        SKITerm *qt = ski_big(p, q), *rt = ski_big(p, r);
        if (!qt || !rt) { ski_unref(p, qt); ski_unref(p, rt); return NULL; }
        return mk_pair(p, qt, rt);
    }
    case PRIM_BLT: return mk_bool(p, bn_cmp(a, b) < 0);
    case PRIM_BEQ: return mk_bool(p, bn_cmp(a, b) == 0);
    case PRIM_BPOW: return den_make(p, bn_copy(a), bn_copy(b));   /* built, or denoted when it cannot fit */
    case PRIM_BMINV: return ski_big(p, bn_minv(a, b));   /* minv x y = x ^ (y - 2) mod y, never the power */
    default: return NULL;
    }
}

/* Perform one reduction step at *tp. Returns true if reduced. */
static bool reduce_step(SKIPool *p, SKITerm **tp) {
    SKITerm *t = *tp;
    if (!is_redex(t)) return false;
    Spine s;
    spine(t, &s);
    SKITerm *x = s.a[0], *y = s.n > 1 ? s.a[1] : NULL, *z = s.n > 2 ? s.a[2] : NULL;
    SKITerm *r = NULL;
    switch (s.head->tag) {
    case TERM_I: r = ski_ref(x); break;                                                          /* I x -> x */
    case TERM_K: r = ski_ref(x); break;                                                          /* K x y -> x */
    case TERM_S: r = app2(p, app2(p, ski_ref(x), ski_ref(z)), app2(p, ski_ref(y), ski_ref(z))); break;  /* S x y z -> x z (y z) */
    case TERM_B: r = app2(p, ski_ref(x), app2(p, ski_ref(y), ski_ref(z))); break;                /* B x y z -> x (y z) */
    case TERM_C: r = app2(p, app2(p, ski_ref(x), ski_ref(z)), ski_ref(y)); break;                /* C x y z -> x z y */
    case TERM_T: r = app2(p, ski_ref(y), ski_ref(x)); break;                                     /* T x y -> y x */
    case TERM_R: r = app2(p, app2(p, ski_ref(y), ski_ref(z)), ski_ref(x)); break;                /* R x y z -> y z x */
    case TERM_WORD: r = app2(p, ski_ref(x), ski_ref(s.head)); break;                             /* #w f -> f #w */
    case TERM_BIG: r = app2(p, ski_ref(x), ski_ref(s.head)); break;                               /* b f -> f b */
    case TERM_DEN: r = app2(p, ski_ref(x), ski_ref(s.head)); break;                               /* d f -> f d */
    case TERM_PRIM:
        if (prim_is_limb(s.head->op)) {
            if (!is_limb_operand(x))                                                             /* op x y -> x (B y op) */
                r = app2(p, ski_ref(x), app2(p, app2(p, ski_b(p), ski_ref(y)), ski_ref(s.head)));
            else if (!is_limb_operand(y))                                                        /* op x y -> y (op x) */
                r = app2(p, ski_ref(y), app2(p, ski_ref(s.head), ski_ref(x)));
            else
                r = prim_big_apply(p, s.head->op, x, y);
        } else if (x->tag == TERM_BIG || y->tag == TERM_BIG) {   /* a word primitive on a limb list */
            fprintf(stderr, "eezo: the word primitive %s takes machine words, not a limb list: "
                            "the limb primitives (badd bsub bmul bdivmod blt beq) take limb lists\n",
                    prim_name(s.head->op));
            exit(1);
        } else if (x->tag != TERM_WORD)                                                          /* op x y -> x (B y op) */
            r = app2(p, ski_ref(x), app2(p, app2(p, ski_b(p), ski_ref(y)), ski_ref(s.head)));
        else if (y->tag != TERM_WORD)                                                            /* op x y -> y (op x) */
            r = app2(p, ski_ref(y), app2(p, ski_ref(s.head), ski_ref(x)));
        else
            r = prim_apply(p, s.head->op, x->word, y->word);
        break;
    default: return false;
    }
    if (!r) return false;
    ski_unref(p, t);
    *tp = r;
    return true;
}

/*
 * Find the head redex only: walk the left spine, outermost first.
 * Stops at weak head normal form (a combinator with too few args);
 * arguments are never entered.
 */
static SKITerm **find_head_redex(SKITerm **tp) {
    SKITerm **cur = tp;
    while (*cur && (*cur)->tag == TERM_APP) {
        if (is_redex(*cur)) return cur;
        cur = &(*cur)->app.left;
    }
    return NULL;
}

i64 ski_reduce_mode(SKIPool *p, SKITerm **t, u64 max_steps, bool whnf) {
    i64 steps = 0;
    
    while (max_steps == 0 || (u64)steps < max_steps) {
        SKITerm **redex = whnf ? find_head_redex(t) : find_redex(t);
        if (!redex) break;
        
        if (!reduce_step(p, redex)) {
            return -1;
        }
        steps++;
    }
    
    return steps;
}

i64 ski_reduce(SKIPool *p, SKITerm **t, u64 max_steps) {
    return ski_reduce_mode(p, t, max_steps, false);
}

bool ski_is_nf(SKITerm *t) {
    return find_redex(&t) == NULL;
}

bool ski_is_whnf(SKITerm *t) {
    return find_head_redex(&t) == NULL;
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
        case TERM_B: fprintf(f, "B"); break;
        case TERM_C: fprintf(f, "C"); break;
        case TERM_T: fprintf(f, "T"); break;
        case TERM_R: fprintf(f, "R"); break;
        case TERM_WORD: fprintf(f, "#%llu", (unsigned long long)t->word); break;
        case TERM_PRIM: fprintf(f, "#%s", prim_name(t->op)); break;
        case TERM_BIG: { char *d = bn_to_dec(t->big); fprintf(f, "#%sB", d); free(d); break; }
        case TERM_DEN: { char *b = bn_to_dec(t->den.base), *e = bn_to_dec(t->den.exp);
                         fprintf(f, "#%s^%s", b, e); free(b); free(e); break; }
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
