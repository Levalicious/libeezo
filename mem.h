/*
 * mem.h - the toolchain's one memory layer (2026-09-29).
 *
 * Every C-side allocation in libeezo, eezott, eezoc and eezo goes through here, so there is one failure path and one
 * budget instead of one per component (Decision_Lev_SharedMemoryLayer_AllTools). Nothing here has a fixed capacity:
 * arenas, stacks and pools grow, and the only limit is memory - the machine's, or the budget a harness sets.
 *
 * Failure. Allocation failure is never a typing judgement and never a reason to continue: it reports
 * '<tool>: resource limit: ...' on stderr and exits 70, so callers and harnesses can tell reaching the memory budget
 * apart from a rejected program (Decision_ResourceAbortStandard_Toolchain_2026_09_14).
 *
 * Budget. Off unless the tool's environment variable names one (EEZOTT_MAX_ALLOC, ...): the budget is the harness's
 * cap, not the theory's. It counts the bytes requested from the system - arena chunks, pool pages, stack growth,
 * plain blocks - over the run.
 *
 * The three shapes:
 *   Arena  objects that live until the arena is dropped (the checker's values and terms, the compiler's AST):
 *          bump allocation in chunks, zeroed, 16-byte aligned.
 *   Stack  a growable array of fixed-size elements, addressed by index (an explicit machine's goals and frames, any
 *          vector): a push may move the storage, so hold indices across pushes, never pointers.
 *   Pool   fixed-size objects that are reclaimed one at a time (the runtime's terms): pages plus a free list; an
 *          object's address is stable for its life.
 * The code that native.c emits into generated programs manages its own heap (its collector runs without a C runtime)
 * and is outside this layer.
 */
#ifndef EEZO_MEM_H
#define EEZO_MEM_H

#include <stddef.h>

/* the tool's name (the failure message's prefix) and the environment variable that may set its budget */
void mem_init(const char *tool, const char *budget_env);
void resource_die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
void mem_on_die(void (*hook)(void));   /* a tool's diagnostics, printed before the abort's message */
void mem_account(size_t n);   /* bytes about to be requested from the system: dies past the budget */

/* plain blocks, for what has its own lifetime (a file's contents, a string handed to a caller) */
void *rmalloc(size_t n);
void *rcalloc(size_t n, size_t m);
void *rrealloc(void *p, size_t n);
char *rstrdup(const char *s);

typedef struct ArenaChunk ArenaChunk;
typedef struct { ArenaChunk *head; char *cur, *end; } Arena;
void *arena_alloc(Arena *a, size_t n);   /* zeroed, 16-byte aligned */
char *arena_strdup(Arena *a, const char *s);
void arena_drop(Arena *a);               /* everything it gave out, at once */

typedef struct { char *p; size_t n, cap, esz; } Stack;
#define STACK_INIT(T) ((Stack){ NULL, 0, 0, sizeof(T) })
void stack_init(Stack *s, size_t esz);
void *stack_push(Stack *s);              /* a new zeroed element on top; the pointer is good until the next push */
void stack_reserve(Stack *s, size_t n);
void stack_drop(Stack *s);
#define STACK_AT(s, T, i) (((T *)(s)->p)[i])
#define STACK_TOP(s, T) (((T *)(s)->p)[(s)->n - 1])
#define STACK_PUSH(s, T, v) (*(T *)stack_push(s) = (v))
#define STACK_POP(s, T) (((T *)(s)->p)[--(s)->n])

typedef struct PoolPage PoolPage;
typedef struct { size_t esz, per_page; PoolPage *pages; char *cur, *end; void *free; size_t live; } Pool;
void pool_setup(Pool *p, size_t esz, size_t per_page);   /* per_page: objects per page (0: a sensible default) */
void *pool_get(Pool *p);                 /* zeroed */
void pool_put(Pool *p, void *x);
void pool_clear(Pool *p);                /* every object back, pages kept */
void pool_drop(Pool *p);                 /* pages returned to the system */

#endif
