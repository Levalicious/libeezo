/*
 * mem.c - the toolchain's one memory layer (see mem.h)
 */
#include "mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

static const char *mem_tool;
static unsigned long long mem_total, mem_limit = ~0ULL;
static const char *mem_limit_env;

void mem_init(const char *tool, const char *budget_env) {
    mem_tool = tool;
    mem_limit_env = budget_env;
    const char *e = budget_env ? getenv(budget_env) : NULL;
    mem_limit = e ? strtoull(e, NULL, 0) : ~0ULL;
}

void resource_die(const char *fmt, ...) {
    va_list ap;
    fflush(stdout);
    if (mem_tool) fprintf(stderr, "%s: ", mem_tool);
    fputs("resource limit: ", stderr);
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
    exit(70);
}

void mem_account(size_t n) {
    mem_total += n ? n : 1;
    if (mem_total > mem_limit)
        resource_die("allocated over %llu bytes (%s)", mem_limit, mem_limit_env ? mem_limit_env : "the budget");
}

void *rmalloc(size_t n) { mem_account(n); void *p = malloc(n ? n : 1); if (!p) resource_die("out of memory (%zu bytes)", n); return p; }
void *rcalloc(size_t n, size_t m) {
    if (m && n > SIZE_MAX / m) resource_die("out of memory (%zu x %zu bytes)", n, m);
    mem_account(n * m);
    void *p = calloc(n ? n : 1, m ? m : 1); if (!p) resource_die("out of memory (%zu x %zu bytes)", n, m);
    return p;
}
void *rrealloc(void *p, size_t n) { mem_account(n); void *q = realloc(p, n ? n : 1); if (!q) resource_die("out of memory (%zu bytes)", n); return q; }
char *rstrdup(const char *s) { size_t n = strlen(s) + 1; char *p = rmalloc(n); memcpy(p, s, n); return p; }

/* ---- arenas ---- */
struct ArenaChunk { ArenaChunk *next; size_t size; };
#define ARENA_CHUNK ((size_t)1 << 20)
#define ALIGN16(x) (((x) + 15) & ~(size_t)15)
#define CHUNK_HDR ALIGN16(sizeof(ArenaChunk))
static ArenaChunk *arena_chunk(Arena *a, size_t size) {
    ArenaChunk *c = rcalloc(1, CHUNK_HDR + size);   /* calloc: fresh pages come zeroed from the system */
    c->size = size; c->next = a->head; a->head = c;
    return c;
}
void *arena_alloc(Arena *a, size_t n) {
    n = ALIGN16(n ? n : 1);
    if ((size_t)(a->end - a->cur) >= n) { void *p = a->cur; a->cur += n; return p; }
    if (n > ARENA_CHUNK / 4) {   /* a big object gets a chunk of its own; the current chunk keeps serving */
        ArenaChunk *c = rcalloc(1, CHUNK_HDR + n);
        c->size = n;
        if (a->head) { c->next = a->head->next; a->head->next = c; } else { c->next = NULL; a->head = c; a->cur = a->end = (char *)c + CHUNK_HDR + n; }
        return (char *)c + CHUNK_HDR;
    }
    ArenaChunk *c = arena_chunk(a, ARENA_CHUNK);
    a->cur = (char *)c + CHUNK_HDR; a->end = a->cur + ARENA_CHUNK;
    void *p = a->cur; a->cur += n; return p;
}
char *arena_strdup(Arena *a, const char *s) { size_t n = strlen(s) + 1; char *p = arena_alloc(a, n); memcpy(p, s, n); return p; }
void arena_drop(Arena *a) {
    for (ArenaChunk *c = a->head, *nx; c; c = nx) { nx = c->next; free(c); }
    a->head = NULL; a->cur = a->end = NULL;
}

/* ---- stacks ---- */
void stack_init(Stack *s, size_t esz) { s->p = NULL; s->n = s->cap = 0; s->esz = esz; }
void stack_reserve(Stack *s, size_t n) {
    if (n <= s->cap) return;
    size_t nc = s->cap ? s->cap : 64;
    while (nc < n) { if (nc > SIZE_MAX / 2 / s->esz) resource_die("a stack of %zu elements of %zu bytes", n, s->esz); nc *= 2; }
    s->p = rrealloc(s->p, nc * s->esz);
    s->cap = nc;
}
void *stack_push(Stack *s) {
    if (s->n == s->cap) stack_reserve(s, s->n + 1);
    void *e = s->p + s->n++ * s->esz;
    memset(e, 0, s->esz);
    return e;
}
void stack_drop(Stack *s) { free(s->p); s->p = NULL; s->n = s->cap = 0; }

/* ---- pools ---- */
struct PoolPage { PoolPage *next; };
#define PAGE_HDR ALIGN16(sizeof(PoolPage))
void pool_setup(Pool *p, size_t esz, size_t per_page) {
    p->esz = ALIGN16(esz < sizeof(void *) ? sizeof(void *) : esz);
    p->per_page = per_page ? per_page : (ARENA_CHUNK / p->esz ? ARENA_CHUNK / p->esz : 1);
    p->pages = NULL; p->cur = p->end = NULL; p->free = NULL; p->live = 0;
}
void *pool_get(Pool *p) {
    void *x;
    if (p->free) { x = p->free; p->free = *(void **)x; memset(x, 0, p->esz); }
    else {
        if (p->cur == p->end) {
            PoolPage *pg = rcalloc(1, PAGE_HDR + p->per_page * p->esz);
            pg->next = p->pages; p->pages = pg;
            p->cur = (char *)pg + PAGE_HDR; p->end = p->cur + p->per_page * p->esz;
        }
        x = p->cur; p->cur += p->esz;   /* fresh from a calloc'd page: zero */
    }
    p->live++;
    return x;
}
void pool_put(Pool *p, void *x) { *(void **)x = p->free; p->free = x; p->live--; }
void pool_clear(Pool *p) {
    /* every object back: the pages are kept and handed out again from the first */
    p->free = NULL; p->live = 0;
    if (!p->pages) return;
    for (PoolPage *pg = p->pages->next; pg; pg = pg->next) {   /* all pages but the current one onto the free list */
        char *b = (char *)pg + PAGE_HDR;
        for (size_t i = 0; i < p->per_page; i++) { void *x = b + i * p->esz; memset(x, 0, p->esz); *(void **)x = p->free; p->free = x; }
    }
    char *b = (char *)p->pages + PAGE_HDR;
    memset(b, 0, p->per_page * p->esz);
    p->cur = b; p->end = b + p->per_page * p->esz;
}
void pool_drop(Pool *p) {
    for (PoolPage *pg = p->pages, *nx; pg; pg = nx) { nx = pg->next; free(pg); }
    p->pages = NULL; p->cur = p->end = NULL; p->free = NULL; p->live = 0;
}
