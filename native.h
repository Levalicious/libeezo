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
    CLOS_APP,       /* (f x) - application node (term) */
    CLOS_APPLYK1,   /* ApplyK1[x_term, k] - waiting for f_val */
    CLOS_APPLYK2,   /* ApplyK2[f_val, k] - waiting for x_val */
    CLOS_HALT,      /* Halt continuation - jumps to output routine */
    CLOS_FWD,       /* Forwarding pointer (during GC) */
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
    3,  /* APPLYK1: entry + x_term + k */
    3,  /* APPLYK2: entry + f_val + k */
    1,  /* HALT */
    2,  /* FWD: entry + target */
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
    2,  /* APPLYK1 */
    2,  /* APPLYK2 */
    0,  /* HALT */
    1,  /* FWD */
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
#define DATA_ENTRY_TABLE    104     /* void*[CLOS_COUNT]: entry addresses */
#define DATA_SIZE_TABLE     (104 + 8*CLOS_COUNT)  /* u8[CLOS_COUNT]: sizes */
#define DATA_PRIM_S         ((DATA_SIZE_TABLE + CLOS_COUNT + 7) & ~7)
#define DATA_PRIM_K         (DATA_PRIM_S + 8)
#define DATA_PRIM_I         (DATA_PRIM_K + 8)
#define DATA_HALT           (DATA_PRIM_I + 8)
#define DATA_SECTION_SIZE   (DATA_HALT + 8)

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
