/*
 * term.c - SKI combinator term implementation
 *
 * The terms live in a pool of the memory layer (mem.h): it grows, and running out of memory is the layer's resource
 * abort, so no constructor returns NULL. Every walk over a term is an explicit machine on a heap stack (a static
 * Stack per walker, reused), not C recursion: a term's depth is bounded by memory alone.
 */
#include "mem.h"
#include "term.h"
#include <stdlib.h>
#include <stdio.h>

void ski_pool_init(SKIPool *p) { pool_setup(&p->p, sizeof(SKITerm), 0); }
void ski_pool_drop(SKIPool *p) { pool_drop(&p->p); }
size_t ski_pool_live(SKIPool *p) { return p->p.live; }

static SKITerm *leaf(SKIPool *p, SKITag tag) {
    SKITerm *t = pool_get(&p->p);
    t->tag = tag;
    t->refs = 1;
    return t;
}
SKITerm *ski_s(SKIPool *p) { return leaf(p, TERM_S); }
SKITerm *ski_k(SKIPool *p) { return leaf(p, TERM_K); }
SKITerm *ski_i(SKIPool *p) { return leaf(p, TERM_I); }
SKITerm *ski_b(SKIPool *p) { return leaf(p, TERM_B); }
SKITerm *ski_c(SKIPool *p) { return leaf(p, TERM_C); }
SKITerm *ski_t(SKIPool *p) { return leaf(p, TERM_T); }
SKITerm *ski_r(SKIPool *p) { return leaf(p, TERM_R); }
SKITerm *ski_word(SKIPool *p, u64 w) { SKITerm *t = leaf(p, TERM_WORD); t->word = w; return t; }
SKITerm *ski_prim(SKIPool *p, PrimOp op) { SKITerm *t = leaf(p, TERM_PRIM); t->op = op; return t; }
SKITerm *ski_app(SKIPool *p, SKITerm *left, SKITerm *right) {
    SKITerm *t = leaf(p, TERM_APP);
    t->app.left = left;
    t->app.right = right;
    return t;
}

int ski_arity(SKITag tag) {
    switch (tag) {
    case TERM_S: case TERM_B: case TERM_C: case TERM_R: return 3;
    case TERM_K: case TERM_T: case TERM_PRIM: return 2;
    case TERM_I: case TERM_WORD: return 1;
    default: return 0;
    }
}

const char *prim_name(PrimOp op) {
    static const char *names[PRIM_COUNT] = {
        "add", "sub", "mul", "and", "or", "xor", "shl", "shr",
        "eq", "lt", "addc", "subb", "mull", "divmod"
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

/* A leaf's expansion string (ski_expansion) as a term. It recurses, but only through the constant expansion strings
   (a few levels), never through a term's own depth. */
static SKITerm *expansion_term(SKIPool *p, const char **e) {
    char c = *(*e)++;
    switch (c) {
    case 'S': return ski_s(p);
    case 'K': return ski_k(p);
    case 'I': { const char *x = ski_expansion(TERM_I); return expansion_term(p, &x); }
    case 'B': { const char *x = ski_expansion(TERM_B); return expansion_term(p, &x); }
    case 'C': { const char *x = ski_expansion(TERM_C); return expansion_term(p, &x); }
    case '1': { SKITerm *l = expansion_term(p, e); SKITerm *r = expansion_term(p, e); return ski_app(p, l, r); }
    default: return NULL;
    }
}

/* Rebuilding a term bottom-up with each leaf replaced (leaf returns NULL: no replacement, the whole rebuild fails and
   the part built is released). Frames: the application, and its left result once built. */
typedef struct { SKITerm *t, *l; int st; } BFrame;
static Stack rebuild_st = { NULL, 0, 0, sizeof(BFrame) };
static SKITerm *rebuild(SKIPool *p, SKITerm *t, SKITerm *(*leaf_fn)(SKIPool *, SKITerm *, void *), void *d) {
    size_t base = rebuild_st.n;
    SKITerm *ret = NULL; int have = 0;
    BFrame f0 = { t, NULL, 0 }; STACK_PUSH(&rebuild_st, BFrame, f0);
    while (rebuild_st.n > base) {
        BFrame *f = &STACK_TOP(&rebuild_st, BFrame);
        if (!have) {
            if (f->t->tag != TERM_APP) {
                ret = leaf_fn(p, f->t, d); rebuild_st.n--;
                if (!ret) goto fail;
                have = 1; continue;
            }
            BFrame c = { f->st == 0 ? f->t->app.left : f->t->app.right, NULL, 0 };
            STACK_PUSH(&rebuild_st, BFrame, c);
            continue;
        }
        have = 0;
        if (f->st == 0) { f->l = ret; f->st = 1; continue; }
        ret = ski_app(p, f->l, ret); rebuild_st.n--; have = 1;
    }
    return ret;
fail:   /* the left results the open frames hold are released with them */
    while (rebuild_st.n > base) { BFrame f = STACK_POP(&rebuild_st, BFrame); if (f.st == 1) ski_unref(p, f.l); }
    return NULL;
}

typedef struct { SKITerm *leaf[4]; } PureLeaves;   /* B C T R, built once each */
static SKITerm *pure_leaf(SKIPool *p, SKITerm *t, void *d) {
    PureLeaves *pl = d;
    switch (t->tag) {
    case TERM_S: return ski_s(p);
    case TERM_K: return ski_k(p);
    case TERM_I: return ski_i(p);
    case TERM_B: case TERM_C: case TERM_T: case TERM_R: {
        int i = t->tag - TERM_B;
        if (!pl->leaf[i]) { const char *x = ski_expansion(t->tag); pl->leaf[i] = expansion_term(p, &x); }
        return ski_ref(pl->leaf[i]);
    }
    default: return NULL;   /* words and primitives: no pure spelling */
    }
}

SKITerm *ski_expand_pure(SKIPool *p, SKITerm *t) {
    PureLeaves pl = { { NULL, NULL, NULL, NULL } };
    SKITerm *r = rebuild(p, t, pure_leaf, &pl);
    for (int i = 0; i < 4; i++) ski_unref(p, pl.leaf[i]);   /* the result holds its own references */
    return r;
}

/* does any leaf of t satisfy the test? (a depth-first walk on a heap stack) */
static Stack any_st = { NULL, 0, 0, sizeof(SKITerm *) };
static bool any_leaf(SKITerm *t, bool (*test)(SKITerm *)) {
    if (!t) return false;
    size_t base = any_st.n;
    STACK_PUSH(&any_st, SKITerm *, t);
    while (any_st.n > base) {
        SKITerm *x = STACK_POP(&any_st, SKITerm *);
        if (x->tag == TERM_APP) { STACK_PUSH(&any_st, SKITerm *, x->app.right); STACK_PUSH(&any_st, SKITerm *, x->app.left); continue; }
        if (test(x)) { any_st.n = base; return true; }
    }
    return false;
}
static bool is_word_leaf(SKITerm *x) { return x->tag == TERM_WORD || x->tag == TERM_PRIM; }
static bool is_extended_leaf(SKITerm *x) { return x->tag != TERM_S && x->tag != TERM_K && x->tag != TERM_I; }
bool ski_uses_words(SKITerm *t) { return any_leaf(t, is_word_leaf); }
bool ski_uses_extended(SKITerm *t) { return any_leaf(t, is_extended_leaf); }

/*
 * Reference counting
 */

SKITerm *ski_ref(SKITerm *t) {
    if (t) t->refs++;
    return t;
}

/* a term whose last reference goes releases its children's references in turn: a worklist, not recursion */
static Stack unref_st = { NULL, 0, 0, sizeof(SKITerm *) };
void ski_unref(SKIPool *p, SKITerm *t) {
    if (!t || --t->refs) return;
    size_t base = unref_st.n;
    STACK_PUSH(&unref_st, SKITerm *, t);
    while (unref_st.n > base) {
        SKITerm *x = STACK_POP(&unref_st, SKITerm *);
        if (x->tag == TERM_APP) {
            SKITerm *l = x->app.left, *r = x->app.right;
            if (l && --l->refs == 0) STACK_PUSH(&unref_st, SKITerm *, l);
            if (r && --r->refs == 0) STACK_PUSH(&unref_st, SKITerm *, r);
        }
        pool_put(&p->p, x);
    }
}

/*
 * Deep copy
 */
static SKITerm *copy_leaf(SKIPool *p, SKITerm *t, void *d) {
    (void)d;
    SKITerm *c = leaf(p, t->tag);
    if (t->tag == TERM_WORD) c->word = t->word;
    else if (t->tag == TERM_PRIM) c->op = t->op;
    return c;
}
SKITerm *ski_copy(SKIPool *p, SKITerm *t) { return t ? rebuild(p, t, copy_leaf, NULL) : NULL; }

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
 * Find the leftmost-outermost redex: a depth-first walk on a heap stack, checking each application before its
 * children (outermost) and the left child before the right (leftmost). Returns the slot holding the redex, NULL when
 * there is none - only then: the walk has no depth limit (it had a fixed 4096-entry array that answered "no redex"
 * when a spine was deeper).
 */
static Stack redex_st = { NULL, 0, 0, sizeof(SKITerm **) };
static SKITerm **find_redex(SKITerm **tp) {
    if (!*tp || (*tp)->tag != TERM_APP) return NULL;
    redex_st.n = 0;
    STACK_PUSH(&redex_st, SKITerm **, tp);
    while (redex_st.n) {
        SKITerm **cur = STACK_POP(&redex_st, SKITerm **);
        SKITerm *t = *cur;
        if (is_redex(t)) { redex_st.n = 0; return cur; }
        if (t->app.right && t->app.right->tag == TERM_APP) STACK_PUSH(&redex_st, SKITerm **, &t->app.right);
        if (t->app.left && t->app.left->tag == TERM_APP) STACK_PUSH(&redex_st, SKITerm **, &t->app.left);
    }
    return NULL;
}

/* An application of two owned terms */
static SKITerm *app2(SKIPool *p, SKITerm *l, SKITerm *r) { return ski_app(p, l, r); }

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
    case TERM_PRIM:
        if (x->tag != TERM_WORD)                                                          /* op x y -> x (B y op) */
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

static Stack eq_st = { NULL, 0, 0, sizeof(SKITerm *) };
bool ski_equal(SKITerm *a, SKITerm *b) {
    size_t base = eq_st.n;
    STACK_PUSH(&eq_st, SKITerm *, a); STACK_PUSH(&eq_st, SKITerm *, b);
    while (eq_st.n > base) {
        SKITerm *y = STACK_POP(&eq_st, SKITerm *), *x = STACK_POP(&eq_st, SKITerm *);
        if (x == y) continue;
        if (!x || !y || x->tag != y->tag) { eq_st.n = base; return false; }
        if (x->tag == TERM_APP) {
            STACK_PUSH(&eq_st, SKITerm *, x->app.right); STACK_PUSH(&eq_st, SKITerm *, y->app.right);
            STACK_PUSH(&eq_st, SKITerm *, x->app.left); STACK_PUSH(&eq_st, SKITerm *, y->app.left);
        }
    }
    return true;
}

/*
 * Debug printing: the pieces still to print (a term, or a closing/separating string) on a heap stack
 */
typedef struct { SKITerm *t; const char *s; } PPiece;
static Stack print_st = { NULL, 0, 0, sizeof(PPiece) };
void ski_fprint(FILE *f, SKITerm *t0) {
    size_t base = print_st.n;
    PPiece p0 = { t0, NULL }; STACK_PUSH(&print_st, PPiece, p0);
    while (print_st.n > base) {
        PPiece pc = STACK_POP(&print_st, PPiece);
        if (pc.s) { fputs(pc.s, f); continue; }
        SKITerm *t = pc.t;
        if (!t) { fprintf(f, "NULL"); continue; }
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
            case TERM_APP: {
                fprintf(f, "(");
                PPiece close = { NULL, ")" }, sp = { NULL, " " }, r = { t->app.right, NULL }, l = { t->app.left, NULL };
                STACK_PUSH(&print_st, PPiece, close); STACK_PUSH(&print_st, PPiece, r);
                STACK_PUSH(&print_st, PPiece, sp); STACK_PUSH(&print_st, PPiece, l);
                break;
            }
        }
    }
}

void ski_print(SKITerm *t) {
    ski_fprint(stdout, t);
}

void ski_println(SKITerm *t) {
    ski_print(t);
    printf("\n");
}
