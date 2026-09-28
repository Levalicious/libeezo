/*
 * native.h - Native code generation for CPS SKI
 *
 * Generates SELF-CONTAINED x86_64 code for SKI combinator evaluation.
 * The emitted code includes EVERYTHING: combinators, GC, output, syscalls.
 * NO C runtime, NO trampolines, NO external dependencies.
 *
 * Output model: The emitted code writes results to stdout via syscall,
 * then exits. Both JIT and ELF use identical code - JIT just forks first.
 *
 * For JIT: fork, child mmaps+jumps in, writes output, exits. Parent waits.
 * For ELF: wrap emitted code in ELF headers -> standalone executable.
 */
#ifndef EEZO_NATIVE_H
#define EEZO_NATIVE_H

#include "types.h"
#include "term.h"
#include "bcl.h"     /* the XBCL leaf codes, which the emitted output writes */
#include "x86.h"

/*
 * Closure types - each has distinct entry code
 */
typedef enum {
    CLOS_S,         /* S combinator (singleton) */
    CLOS_K,         /* K combinator (singleton) */
    CLOS_I,         /* I combinator (singleton) */
    CLOS_S1,        /* S x - partial application */
    CLOS_S2,        /* S x y - partial application */
    CLOS_K1,        /* K x - partial application */
    CLOS_APP,       /* App[f, x] - application THUNK (not a value) */
    CLOS_IND,       /* Ind[v] - an updated thunk: enter v */
    CLOS_APPLYK,    /* ApplyK[x, k] - waiting for f_val; applies it to the UNEVALUATED x */
    CLOS_UPDK,      /* UpdK[thunk, k] - overwrite thunk with Ind[value], pass value to k */
    CLOS_NORM,      /* Norm[k] - receives a WHNF, normalizes its captured args, passes NF to k */
    CLOS_FIELD1,    /* Field1[v, k] - receives nf(v.x), stores it in place, continues */
    CLOS_FIELD2,    /* Field2[v, k] - receives nf(v.y), stores it in place, k(v) */
    CLOS_IOV,       /* IoV - stream I/O: receives the output cell (WHNF), asks for its head */
    CLOS_IOH,       /* IoH[v] - receives the head, applies it to the markers K and S */
    CLOS_ION,       /* IoN[v, count] - unfolds the K1 spine; on S emits the byte, moves to the tail */
    CLOS_HALT,      /* Halt continuation - jumps to output routine */
    CLOS_FWD,       /* Forwarding pointer (during GC) */
    /* The extended leaves (2026-09-13, term.h) */
    CLOS_B,         /* B combinator (singleton) */
    CLOS_C,         /* C combinator (singleton) */
    CLOS_T,         /* T combinator (singleton) */
    CLOS_R,         /* R combinator (singleton) */
    CLOS_B1,        /* B x */
    CLOS_B2,        /* B x y */
    CLOS_C1,        /* C x */
    CLOS_C2,        /* C x y */
    CLOS_T1,        /* T x */
    CLOS_R1,        /* R x */
    CLOS_R2,        /* R x y */
    CLOS_WORD,      /* Word[w] - a machine word (w is not a pointer) */
    CLOS_PRIM,      /* Prim[op] - a word primitive (one singleton per op; op is not a pointer) */
    CLOS_PRIM1,     /* Prim1[x, op] - the primitive applied to x */
    CLOS_MOT,       /* MoT - monadic I/O: receives the program's 4-tuple, asks for its tag */
    CLOS_MONUMH,    /* MoNumH[v, what] - receives a numeral, applies it to the markers K and S */
    CLOS_MONUMN,    /* MoNumN[v, what, count] - unfolds the K1 spine; on S acts on count as `what` says */
    CLOS_COUNT
} ClosureType;

/*
 * Output format - compile-time selection of serialization routine
 * All three are emitted under the same "output" label.
 */
typedef enum {
    OUTPUT_BCL,         /* Binary Combinatory Logic: S=01, K=00, App=1 */
    OUTPUT_JOT,         /* Jot encoding */
    OUTPUT_JOMPLEMENT,  /* Jomplement encoding */
    OUTPUT_XBCL         /* BCL with the extended leaves (bcl.h) */
} OutputFormat;

/*
 * Closure sizes in words (8 bytes each)
 */
static const int CLOS_SIZES[CLOS_COUNT] = {
    1,  /* S */
    1,  /* K */
    1,  /* I */
    2,  /* S1: entry + x */
    3,  /* S2: entry + x + y */
    2,  /* K1: entry + x */
    3,  /* APP: entry + f + x */
    3,  /* IND: entry + value + unused (same cell as the App it replaced, so static term areas stay linearly scannable) */
    3,  /* APPLYK: entry + x + k */
    3,  /* UPDK: entry + thunk + k */
    2,  /* NORM: entry + k */
    3,  /* FIELD1: entry + v + k */
    3,  /* FIELD2: entry + v + k */
    1,  /* IOV */
    2,  /* IOH: entry + v */
    3,  /* ION: entry + v + count (an unboxed small integer; the collector leaves it alone) */
    1,  /* HALT */
    2,  /* FWD: entry + target */
    1, 1, 1, 1,             /* B C T R */
    2, 3, 2, 3, 2, 2, 3,    /* B1 B2 C1 C2 T1 R1 R2 */
    2,  /* WORD: entry + the word */
    2,  /* PRIM: entry + op */
    3,  /* PRIM1: entry + x + op */
    1,  /* MOT */
    3,  /* MONUMH: entry + v + what (a small integer the collector leaves alone) */
    4,  /* MONUMN: entry + v + what + count */
};

/* Pointer counts for GC (excludes entry ptr itself) */
static const int CLOS_PTRS[CLOS_COUNT] = {
    0,  /* S */
    0,  /* K */
    0,  /* I */
    1,  /* S1 */
    2,  /* S2 */
    1,  /* K1 */
    2,  /* APP */
    1,  /* IND */
    2,  /* APPLYK */
    2,  /* UPDK */
    1,  /* NORM */
    2,  /* FIELD1 */
    2,  /* FIELD2 */
    0,  /* IOV */
    1,  /* IOH */
    2,  /* ION (count is outside every semispace, so copy_closure returns it unchanged) */
    0,  /* HALT */
    1,  /* FWD */
    0, 0, 0, 0,             /* B C T R */
    1, 2, 1, 2, 1, 1, 2,    /* B1 B2 C1 C2 T1 R1 R2 */
    0,  /* WORD */
    0,  /* PRIM */
    1,  /* PRIM1: x only; op is a datum */
    0,  /* MOT */
    2,  /* MONUMH (what is outside every semispace, so copy_closure returns it unchanged, as ION's count) */
    3,  /* MONUMN */
};

/*
 * Memory layout of emitted code/data
 *
 * The emitted binary contains:
 *   1. Data section (runtime state)
 *   2. Code section (combinators, GC, entry point)
 *
 * Data section layout (offsets from data base):
 */
#define DATA_SPACE0         0       /* void*: semispace 0 base */
#define DATA_SPACE1         8       /* void*: semispace 1 base */
#define DATA_ACTIVE         16      /* u64: which space is active (0 or 1) */
#define DATA_SPACE_SIZE     24      /* u64: size of each semispace */
#define DATA_HP             32      /* void*: heap pointer */
#define DATA_LIMIT          40      /* void*: heap limit */
#define DATA_ROOT           48      /* void*: saved continuation for GC */
#define DATA_SCAN           56      /* void*: Cheney scan pointer */
#define DATA_OUTBUF         64      /* void*: output buffer base */
#define DATA_OUTPOS         72      /* u64: current output position */
#define DATA_OUTLEN         80      /* u64: output buffer length */
#define DATA_MAX_SPACE_SIZE 88      /* u64: max size per semispace (heap limit) */
#define DATA_ALLOC_REQUEST  96      /* u64: bytes requested when GC triggered */
#define DATA_OUTPUT_XOR     104     /* u64: XOR mask for output bits (0=Jot, 1=Jomplement) */
#define DATA_NF_MODE        112     /* u64: 1 = normalize to full NF before output, 0 = WHNF */
#define DATA_SPACE0_SIZE    120     /* u64: size of semispace 0 (may differ while growing) */
#define DATA_SPACE1_SIZE    128     /* u64: size of semispace 1 */
#define DATA_GC_ROOT_K      136     /* void*: rbx (continuation) saved across a collection */
#define DATA_GC_ROOT_SELF   144     /* void*: rdi (closure being entered) saved across a collection */
#define DATA_GC_ROOT_VAL    152     /* void*: r14 (incoming value) saved across a collection */
#define DATA_FROM_BASE      160     /* void*: fromspace bounds during a collection */
#define DATA_FROM_END       168
#define DATA_STATIC_BEGIN   176     /* void*: static closure area (ELF: the embedded term) - scanned as roots */
#define DATA_STATIC_END     184
#define DATA_IO_MODE        192     /* u64: 1 = stream I/O mode (Lazy-K), 2 = monadic I/O, 0 = term output */
#define DATA_STATIC2_BEGIN  200     /* void*: second static root area: the input stream (io mode) */
#define DATA_STATIC2_END    208
#define DATA_IO_BUF         216     /* void*: raw stdin bytes (io mode) */
#define DATA_IO_LEN         224     /* u64: their count */
#define DATA_IO_CHAIN       232     /* void*: numeral chain base: num[k] = chain + (k-1)*24, num[0] = K I */
#define DATA_IOV            240     /* IoV continuation singleton (1 word) */
#define DATA_KI             248     /* K I as a static closure: [entry_K1, prim_I] (2 words) */
#define DATA_ENTRY_TABLE    264     /* void*[CLOS_COUNT]: entry addresses */
#define DATA_SIZE_TABLE     (264 + 8*CLOS_COUNT)  /* u8[CLOS_COUNT]: sizes */
#define DATA_PRIM_S         ((DATA_SIZE_TABLE + CLOS_COUNT + 7) & ~7)
#define DATA_PRIM_K         (DATA_PRIM_S + 8)
#define DATA_PRIM_I         (DATA_PRIM_K + 8)
#define DATA_HALT           (DATA_PRIM_I + 8)
#define DATA_PRIM_B         (DATA_HALT + 8)
#define DATA_PRIM_C         (DATA_PRIM_B + 8)
#define DATA_PRIM_T         (DATA_PRIM_C + 8)
#define DATA_PRIM_R         (DATA_PRIM_T + 8)
#define DATA_PRIM_OPS       (DATA_PRIM_R + 8)               /* PRIM_COUNT singletons [entry_Prim, op], 16 bytes each */
#define DATA_MOT            (DATA_PRIM_OPS + 16 * PRIM_COUNT)   /* MoT continuation singleton (1 word) */
#define DATA_MO_SEL         (DATA_MOT + 8)                      /* void*[4]: the 4-tuple's selectors, built at start (monadic I/O) */
#define DATA_MO_INBYTE      (DATA_MO_SEL + 32)                  /* u64: the byte getc reads (zeroed first) */
#define DATA_SECTION_SIZE   (DATA_MO_INBYTE + 8)

/*
 * Register convention (during CPS execution):
 *   rbx = current continuation (GC root)
 *   r12 = heap pointer
 *   r13 = heap limit  
 *   r14 = incoming value (from continuation call)
 *   r15 = data section base address
 *   rdi = self (closure being entered)
 *   rax, rcx, rdx, rsi, r8-r11 = scratch
 */

/*
 * Emitter state - used during code generation
 */
typedef struct {
    X86Buf code;            /* code buffer */
    
    /* Offsets of entry points (filled during emission) */
    u32 entry_offsets[CLOS_COUNT];
    u32 gc_offset;          /* GC routine */
    u32 gc_copy_offset;     /* copy_closure subroutine */
    u32 gc_classify_offset; /* classify subroutine (entry ptr -> size/ptr bytes) */
    u32 gc_scavenge_offset; /* scavenge subroutine (copy the fields of one closure) */
    u32 gc_call_patch[64];  /* rel32 sites of `call gc` emitted by emit_reserve */
    int n_gc_call;
    /* Normalization mode baked into the data section: 1 = NF (default), 0 = WHNF */
    int nf_mode;
    /* Stream I/O mode (Lazy-K): read stdin into an input stream, drive the
     * program as a stream transformer, write bytes. Replaces term output. */
    int io_mode;
    u32 output_offset;      /* output serialization routine */
    u32 start_offset;       /* program entry point */
    
    /* Output format (compile-time selected) */
    OutputFormat output_fmt;
    
    /* Patch location for Halt -> output jump */
    u32 halt_output_patch;
    
    /* ELF-specific patch locations */
    u32 elf_lea_patch;      /* offset of LEA r15 displacement */
    u32 elf_start_jmp_patch; /* offset of jump to _start */
    
    /* For JIT: data section is separate allocation */
    /* For ELF: data section is part of output */
    u8 *data;
    u32 data_size;
    
    /* The SKI term to compile (as initial heap contents) */
    SKITerm *term;
    
    /* Heap initialization data */
    u8 *init_heap;
    u32 init_heap_size;
} NativeEmit;

/*
 * Initialize emitter with output format selection
 */
void native_emit_init(NativeEmit *e, u8 *code_buf, u32 code_cap, OutputFormat fmt);

/*
 * Emit the complete runtime (combinators + GC + output + entry)
 * Output routine is selected based on format passed to native_emit_init.
 */
void native_emit_runtime(NativeEmit *e);

/*
 * Emit code to construct a term on the heap
 * Returns offset in init_heap where root closure is
 */
u32 native_emit_term(NativeEmit *e, SKITerm *term);

/*
 * Get emitted code
 */
u8  *native_get_code(NativeEmit *e, u32 *size);
u32  native_get_entry(NativeEmit *e);  /* offset of _start */

/*
 * For JIT execution
 */
typedef struct {
    void *code;             /* mmap'd executable code */
    void *data;             /* data section */
    void *heap0;            /* semispace 0 */
    void *heap1;            /* semispace 1 */
    u32 code_size;
    u32 heap_size;
    u32 start_offset;       /* offset of _start within code */
} NativeJIT;

/* Default initial semispace (bytes); -H overrides it in eezo and eezoc */
#define NATIVE_DEFAULT_HEAP_SIZE (16u * 1024 * 1024)
/* Growth ceiling of one semispace for an initial size of heap_size */
u64 native_max_space(u32 heap_size);
NativeJIT *native_jit_prepare(NativeEmit *e, u32 heap_size);
void native_jit_free(NativeJIT *jit);

/*
 * Load a term onto the JIT heap for execution.
 * Converts SKITerm tree to native closures.
 * Must be called after native_jit_prepare, before native_jit_run.
 * Returns 0 on success, -1 if term too large for heap.
 */
int native_jit_load_term(NativeJIT *jit, SKITerm *term);

/*
 * Execute the JIT'd code.
 * Forks, child jumps into emitted code which writes output and exits.
 * Parent waits. Returns child's exit status.
 * Output goes to stdout (or wherever fd 1 points).
 */
int native_jit_run(NativeJIT *jit);

/*
 * Emit ELF executable.
 * Creates a standalone executable that evaluates the given term.
 * Caller must free *out.
 */
void native_emit_elf(NativeEmit *e, u8 **out, u32 *out_size, SKITerm *term, u32 heap_size);

#endif /* EEZO_NATIVE_H */
