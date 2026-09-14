/*
 * native.c - Native code generation for CPS SKI
 *
 * Emits SELF-CONTAINED x86_64 code including:
 * - Combinator entry points (S, K, I, S1, S2, K1)
 * - Thunks and continuations (App, Ind, ApplyK, UpdK, Norm, Field1, Field2, Halt)
 *   Evaluation is NORMAL ORDER with sharing (call-by-need): App is a thunk,
 *   arguments are captured unevaluated, results are written back as Ind.
 * - Cheney copying GC (entirely in assembly)
 * - Syscall wrappers (mmap for heap, write for output, exit)
 *
 * NO C RUNTIME. NO TRAMPOLINES. FULLY STANDALONE.
 */

#include "native.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Linux syscall numbers */
#define SYS_write   1
#define SYS_mmap    9
#define SYS_munmap  11
#define SYS_mremap  25
#define SYS_exit    60

/* mmap flags */
#define MMAP_PROT_RW    (0x1 | 0x2)  /* PROT_READ | PROT_WRITE */
#define MMAP_PRIVATE_ANON (0x02 | 0x20)  /* MAP_PRIVATE | MAP_ANONYMOUS */

/*
 * Helper: emit syscall instruction
 * Args in: rdi, rsi, rdx, r10, r8, r9
 * Result in: rax
 */
static void emit_syscall(X86Buf *b) {
    x86_byte(b, 0x0F);
    x86_byte(b, 0x05);
}

/*
 * Initialize emitter with output format
 */
void native_emit_init(NativeEmit *e, u8 *code_buf, u32 code_cap, OutputFormat fmt) {
    memset(e, 0, sizeof(*e));
    x86_init(&e->code, code_buf, code_cap);
    e->data_size = DATA_SECTION_SIZE;
    e->output_fmt = fmt;
    e->nf_mode = 1;
}

/*
 * Emit: load data section field into register
 * Uses r15 as data base
 */
static void emit_load_data(X86Buf *b, X86Reg dst, int offset) {
    x86_mov_rm(b, dst, R15, offset);
}

/*
 * Emit: store register to data section field
 */
static void emit_store_data(X86Buf *b, int offset, X86Reg src) {
    x86_mov_mr(b, R15, offset, src);
}

/*
 * Emit: get entry address for closure type from table
 * Result in dst register
 */
static void emit_get_entry(X86Buf *b, X86Reg dst, ClosureType type) {
    x86_mov_rm(b, dst, R15, DATA_ENTRY_TABLE + type * 8);
}

/*
 * Emit: get singleton closure address (S, K, I, or Halt)
 */
static void emit_get_singleton(X86Buf *b, X86Reg dst, ClosureType type) {
    int offset;
    switch (type) {
        case CLOS_S: offset = DATA_PRIM_S; break;
        case CLOS_K: offset = DATA_PRIM_K; break;
        case CLOS_I: offset = DATA_PRIM_I; break;
        case CLOS_HALT: offset = DATA_HALT; break;
        default: offset = DATA_PRIM_S; break;
    }
    x86_lea(b, dst, R15, offset);
}

/*
 * Conditional jump rel32 with a patchable displacement.
 * Returns the offset of the rel32 (pass to x86_patch_rel32).
 */
#define CC_B   0x82
#define CC_AE  0x83
#define CC_E   0x84
#define CC_NE  0x85
#define CC_BE  0x86
#define CC_A   0x87
#define CC_GE  0x8D
#define CC_L   0x8C
static u32 emit_jcc(X86Buf *b, u8 cc) {
    x86_byte(b, 0x0F); x86_byte(b, cc);
    u32 p = x86_len(b);
    x86_dword(b, 0);
    return p;
}

/* cmovne dst, src */
static void emit_cmovne(X86Buf *b, X86Reg dst, X86Reg src) {
    x86_byte(b, 0x48 | (((dst >> 3) & 1) << 2) | ((src >> 3) & 1));
    x86_byte(b, 0x0F); x86_byte(b, 0x45);
    x86_byte(b, 0xC0 | ((dst & 7) << 3) | (src & 7));
}

/* jmp to an already-emitted offset */
static void emit_jmp_back(X86Buf *b, u32 target) {
    x86_jmp_rel(b, (i32)target - (i32)(x86_len(b) + 5));
}

/*
 * ALLOCATION PROTOCOL
 *
 * Every entry code that allocates begins with emit_reserve(words, retry).
 * If fewer than `words` words remain, the live state (rbx = continuation,
 * rdi = self, r14 = incoming value) is saved to the data section, the
 * collector is CALLed, the three roots are reloaded (they moved), and
 * control jumps back to `retry` - the entry's first instruction - so the
 * entry re-executes from scratch against the compacted heap. Entries must
 * not write to the heap before their reserve. After a successful reserve
 * the allocations themselves are unchecked bumps (emit_bump).
 */
static void emit_reserve(NativeEmit *e, int words, u32 retry) {
    X86Buf *b = &e->code;
    x86_lea(b, RAX, R12, words * 8);
    x86_cmp_rr(b, RAX, R13);
    u32 ok = emit_jcc(b, CC_BE);
    x86_mov_mi(b, R15, DATA_ALLOC_REQUEST, words * 8);
    emit_store_data(b, DATA_GC_ROOT_K, RBX);
    emit_store_data(b, DATA_GC_ROOT_SELF, RDI);
    emit_store_data(b, DATA_GC_ROOT_VAL, R14);
    x86_call_rel(b, 0);
    e->gc_call_patch[e->n_gc_call++] = x86_len(b) - 4;
    emit_load_data(b, RBX, DATA_GC_ROOT_K);
    emit_load_data(b, RDI, DATA_GC_ROOT_SELF);
    emit_load_data(b, R14, DATA_GC_ROOT_VAL);
    emit_jmp_back(b, retry);
    x86_patch_rel32(b, ok, x86_len(b));
}

/* rax = hp; hp += words (space guaranteed by a preceding reserve) */
static void emit_bump(X86Buf *b, int words) {
    x86_mov_rr(b, RAX, R12);
    x86_add_ri(b, R12, words * 8);
}

/*
 * Emit: enter closure in rdi
 * jmp [rdi] - closure entry ptr is first word
 */
static void emit_enter(X86Buf *b) {
    x86_jmp_m(b, RDI, 0);
}

/*
 * Emit: call continuation in rbx with value in r14
 * mov rdi, rbx; jmp [rdi]
 */
static void emit_call_cont(X86Buf *b) {
    x86_mov_rr(b, RDI, RBX);
    emit_enter(b);
}

/* ========================================================================
 * COMBINATOR ENTRY POINTS
 * ======================================================================== */

/*
 * Entry for S combinator
 * S is a value - just call continuation with self
 */
static void emit_entry_S(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_S] = x86_len(b);
    
    /* r14 = self (the S singleton) */
    x86_mov_rr(b, R14, RDI);
    /* call continuation */
    emit_call_cont(b);
}

/*
 * Entry for K combinator - same pattern
 */
static void emit_entry_K(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_K] = x86_len(b);
    
    x86_mov_rr(b, R14, RDI);
    emit_call_cont(b);
}

/*
 * Entry for I combinator
 */
static void emit_entry_I(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_I] = x86_len(b);
    
    x86_mov_rr(b, R14, RDI);
    emit_call_cont(b);
}

/*
 * Entry for S1[x] - partial application, also a value
 */
static void emit_entry_S1(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_S1] = x86_len(b);
    
    x86_mov_rr(b, R14, RDI);
    emit_call_cont(b);
}

/*
 * Entry for S2[x,y] - partial application, also a value
 */
static void emit_entry_S2(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_S2] = x86_len(b);
    
    x86_mov_rr(b, R14, RDI);
    emit_call_cont(b);
}

/*
 * Entry for K1[x] - partial application, also a value
 */
static void emit_entry_K1(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_K1] = x86_len(b);
    
    x86_mov_rr(b, R14, RDI);
    emit_call_cont(b);
}

/*
 * Entry for App[f, x] - a THUNK (not a value)
 *
 *   eval(App[f,x], k) = eval(f, ApplyK[x, UpdK[self, k]])
 *
 * x is passed UNEVALUATED (normal order). When the value of the whole
 * application comes back through UpdK, self is overwritten with an
 * indirection to it, so every other reference to this thunk shares the
 * result (call-by-need).
 */
static void emit_entry_App(NativeEmit *e) {
    X86Buf *b = &e->code;
    u32 top = x86_len(b);
    e->entry_offsets[CLOS_APP] = top;
    emit_reserve(e, 6, top);
    x86_mov_rm(b, RCX, RDI, 8);    /* f */
    x86_mov_rm(b, RDX, RDI, 16);   /* x */
    /* UpdK[self, k] */
    emit_bump(b, 3);
    emit_get_entry(b, RSI, CLOS_UPDK);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, RDI);
    x86_mov_mr(b, RAX, 16, RBX);
    x86_mov_rr(b, R8, RAX);
    /* ApplyK[x, updk] */
    emit_bump(b, 3);
    emit_get_entry(b, RSI, CLOS_APPLYK);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, RDX);
    x86_mov_mr(b, RAX, 16, R8);
    x86_mov_rr(b, RBX, RAX);
    /* enter f */
    x86_mov_rr(b, RDI, RCX);
    emit_enter(b);
}

/*
 * Entry for Ind[v] - an updated thunk: enter its value
 */
static void emit_entry_Ind(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_IND] = x86_len(b);
    x86_mov_rm(b, RDI, RDI, 8);
    emit_enter(b);
}

/*
 * Entry for UpdK[thunk, k] - receives the thunk's value in r14.
 * Overwrites the thunk (3 words) with Ind[value] (2 words), passes value to k.
 */
static void emit_entry_UpdK(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_UPDK] = x86_len(b);
    x86_mov_rm(b, RCX, RDI, 8);    /* thunk */
    x86_mov_rm(b, RDX, RDI, 16);   /* k */
    emit_get_entry(b, RSI, CLOS_IND);
    x86_mov_mr(b, RCX, 0, RSI);
    x86_mov_mr(b, RCX, 8, R14);
    x86_mov_rr(b, RBX, RDX);
    emit_call_cont(b);
}

/*
 * Dispatch on the entry pointer in RSI against a list of closure types.
 * patch[i] receives the rel32 offset of the je for types[i]. Falls
 * through when none match. Clobbers R8.
 */
static void emit_dispatch(X86Buf *b, const ClosureType *types, int n, u32 *patch) {
    for (int i = 0; i < n; i++) {
        emit_get_entry(b, R8, types[i]);
        x86_cmp_rr(b, RSI, R8);
        patch[i] = emit_jcc(b, CC_E);
    }
}

/*
 * Entry for ApplyK[x, k] - receives f_val in r14; performs apply(f_val, x, k).
 * x is an arbitrary closure (usually an unevaluated thunk): it is captured,
 * never evaluated here, so evaluation stays normal-order.
 */
static void emit_entry_ApplyK(NativeEmit *e) {
    X86Buf *b = &e->code;
    u32 top = x86_len(b);
    e->entry_offsets[CLOS_APPLYK] = top;
    emit_reserve(e, 9, top);                /* worst case: the S2 rule */
    x86_mov_rm(b, RCX, RDI, 8);             /* x */
    x86_mov_rm(b, RDX, RDI, 16);            /* k */
    x86_mov_rm(b, RSI, R14, 0);             /* f_val entry */
    static const ClosureType cases[] = { CLOS_S, CLOS_K, CLOS_I, CLOS_S1, CLOS_S2, CLOS_K1 };
    u32 p[6];
    emit_dispatch(b, cases, 6, p);
    x86_int3(b);                            /* a non-value reached a continuation */
    /* S x -> k(S1[x]) */
    x86_patch_rel32(b, p[0], x86_len(b));
    emit_bump(b, 2);
    emit_get_entry(b, RSI, CLOS_S1);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, RCX);
    x86_mov_rr(b, R14, RAX);
    x86_mov_rr(b, RBX, RDX);
    emit_call_cont(b);
    /* K x -> k(K1[x]) */
    x86_patch_rel32(b, p[1], x86_len(b));
    emit_bump(b, 2);
    emit_get_entry(b, RSI, CLOS_K1);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, RCX);
    x86_mov_rr(b, R14, RAX);
    x86_mov_rr(b, RBX, RDX);
    emit_call_cont(b);
    /* I x -> eval(x, k) */
    x86_patch_rel32(b, p[2], x86_len(b));
    x86_mov_rr(b, RDI, RCX);
    x86_mov_rr(b, RBX, RDX);
    emit_enter(b);
    /* S1[a] x -> k(S2[a, x]) */
    x86_patch_rel32(b, p[3], x86_len(b));
    x86_mov_rm(b, R8, R14, 8);
    emit_bump(b, 3);
    emit_get_entry(b, RSI, CLOS_S2);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, R8);
    x86_mov_mr(b, RAX, 16, RCX);
    x86_mov_rr(b, R14, RAX);
    x86_mov_rr(b, RBX, RDX);
    emit_call_cont(b);
    /* S2[a,b] z -> eval(a, ApplyK[z, ApplyK[App[b,z], k]])   (= a z (b z)) */
    x86_patch_rel32(b, p[4], x86_len(b));
    x86_mov_rm(b, R8, R14, 8);              /* a */
    x86_mov_rm(b, R9, R14, 16);             /* b */
    emit_bump(b, 3);                        /* App[b, z]: a shared thunk */
    emit_get_entry(b, RSI, CLOS_APP);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, R9);
    x86_mov_mr(b, RAX, 16, RCX);
    x86_mov_rr(b, R10, RAX);
    emit_bump(b, 3);                        /* ApplyK[bz, k] */
    emit_get_entry(b, RSI, CLOS_APPLYK);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, R10);
    x86_mov_mr(b, RAX, 16, RDX);
    x86_mov_rr(b, R11, RAX);
    emit_bump(b, 3);                        /* ApplyK[z, that] */
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, RCX);
    x86_mov_mr(b, RAX, 16, R11);
    x86_mov_rr(b, RBX, RAX);
    x86_mov_rr(b, RDI, R8);
    emit_enter(b);
    /* K1[a] x -> eval(a, k) */
    x86_patch_rel32(b, p[5], x86_len(b));
    x86_mov_rm(b, RDI, R14, 8);
    x86_mov_rr(b, RBX, RDX);
    emit_enter(b);
}

/*
 * NORMAL-FORM PASS
 *
 * Norm[k] receives a value v (weak head normal form). Primitives are
 * already normal. A partial application S1[x] / K1[x] / S2[x,y] is normal
 * once its captured arguments are: each is evaluated under a fresh Norm
 * whose continuation Field1/Field2 stores the normal form back into v in
 * place (the argument is replaced by an equal term), then k receives v.
 * The initial continuation is Norm[Halt] in NF mode and Halt in WHNF mode.
 */
static void emit_entry_Norm(NativeEmit *e) {
    X86Buf *b = &e->code;
    u32 top = x86_len(b);
    e->entry_offsets[CLOS_NORM] = top;
    emit_reserve(e, 5, top);
    x86_mov_rm(b, RDX, RDI, 8);             /* k */
    x86_mov_rm(b, RSI, R14, 0);             /* v entry */
    static const ClosureType prims[] = { CLOS_S, CLOS_K, CLOS_I };
    static const ClosureType paps[]  = { CLOS_S1, CLOS_K1, CLOS_S2 };
    u32 pp[3], pq[3];
    emit_dispatch(b, prims, 3, pp);
    emit_dispatch(b, paps, 3, pq);
    x86_int3(b);
    /* primitive: already normal */
    for (int i = 0; i < 3; i++) x86_patch_rel32(b, pp[i], x86_len(b));
    x86_mov_rr(b, RBX, RDX);
    emit_call_cont(b);
    /* partial application: eval(v.x, Norm[Field1[v, k]]) */
    for (int i = 0; i < 3; i++) x86_patch_rel32(b, pq[i], x86_len(b));
    emit_bump(b, 3);
    emit_get_entry(b, RSI, CLOS_FIELD1);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, R14);
    x86_mov_mr(b, RAX, 16, RDX);
    x86_mov_rr(b, R8, RAX);
    emit_bump(b, 2);
    emit_get_entry(b, RSI, CLOS_NORM);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, R8);
    x86_mov_rr(b, RBX, RAX);
    x86_mov_rm(b, RDI, R14, 8);
    emit_enter(b);
}

/* Field1[v, k]: receives nf(v.x); stores it; S2 continues with y, others finish */
static void emit_entry_Field1(NativeEmit *e) {
    X86Buf *b = &e->code;
    u32 top = x86_len(b);
    e->entry_offsets[CLOS_FIELD1] = top;
    emit_reserve(e, 5, top);
    x86_mov_rm(b, RCX, RDI, 8);             /* v */
    x86_mov_rm(b, RDX, RDI, 16);            /* k */
    x86_mov_mr(b, RCX, 8, R14);             /* v.x := nf(v.x) */
    x86_mov_rm(b, RSI, RCX, 0);
    emit_get_entry(b, R8, CLOS_S2);
    x86_cmp_rr(b, RSI, R8);
    u32 is_s2 = emit_jcc(b, CC_E);
    /* S1 / K1: done -> k(v) */
    x86_mov_rr(b, R14, RCX);
    x86_mov_rr(b, RBX, RDX);
    emit_call_cont(b);
    /* S2: eval(v.y, Norm[Field2[v, k]]) */
    x86_patch_rel32(b, is_s2, x86_len(b));
    emit_bump(b, 3);
    emit_get_entry(b, RSI, CLOS_FIELD2);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, RCX);
    x86_mov_mr(b, RAX, 16, RDX);
    x86_mov_rr(b, R8, RAX);
    emit_bump(b, 2);
    emit_get_entry(b, RSI, CLOS_NORM);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, R8);
    x86_mov_rr(b, RBX, RAX);
    x86_mov_rm(b, RDI, RCX, 16);
    emit_enter(b);
}

/* Field2[v, k]: receives nf(v.y); stores it; k(v) */
static void emit_entry_Field2(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_FIELD2] = x86_len(b);
    x86_mov_rm(b, RCX, RDI, 8);
    x86_mov_rm(b, RDX, RDI, 16);
    x86_mov_mr(b, RCX, 16, R14);
    x86_mov_rr(b, R14, RCX);
    x86_mov_rr(b, RBX, RDX);
    emit_call_cont(b);
}

/*
 * Entry for Halt continuation
 * Receives final value in r14
 * Jumps to output routine (which is format-specific)
 */
static void emit_entry_Halt(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_HALT] = x86_len(b);
    
    /* r14 = final value, jump to output routine */
    /* output_offset will be patched after output routine is emitted */
    x86_jmp_rel(b, 0);  /* placeholder, patched by emit_output_* */
    e->halt_output_patch = x86_len(b) - 4;
}

/*
 * Entry for FWD (forwarding pointer) - should never be entered
 */
static void emit_entry_Fwd(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_FWD] = x86_len(b);
    x86_int3(b);  /* trap */
}

/* ========================================================================
 * GARBAGE COLLECTOR (in assembly)
 * ======================================================================== */

/*
 * classify: RSI = entry pointer -> RCX = pointer-field bytes, RDX = closure bytes.
 * Generated from CLOS_PTRS / CLOS_SIZES. Clobbers R8. Traps on an unknown entry.
 */
static void emit_classify(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->gc_classify_offset = x86_len(b);
    u32 p[CLOS_COUNT];
    for (int t = 0; t < CLOS_COUNT; t++) {
        emit_get_entry(b, R8, (ClosureType)t);
        x86_cmp_rr(b, RSI, R8);
        p[t] = emit_jcc(b, CC_E);
    }
    x86_int3(b);
    for (int t = 0; t < CLOS_COUNT; t++) {
        x86_patch_rel32(b, p[t], x86_len(b));
        x86_mov_ri(b, RCX, CLOS_PTRS[t] * 8);
        x86_mov_ri(b, RDX, CLOS_SIZES[t] * 8);
        x86_ret(b);
    }
}

/*
 * copy_closure: RDI = closure -> RAX = its tospace address.
 * Outside the fromspace (NULL, data-section singletons): returned unchanged.
 * Forwarded: the forwarding target. Otherwise copied, forwarded, returned.
 * Clobbers RCX, RDX, RSI, R8-R11. Bumps R12 (hp).
 */
static void emit_copy_closure(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->gc_copy_offset = x86_len(b);
    x86_mov_rr(b, RAX, RDI);
    x86_cmp_rm(b, RDI, R15, DATA_FROM_BASE);
    u32 out1 = emit_jcc(b, CC_B);
    x86_cmp_rm(b, RDI, R15, DATA_FROM_END);
    u32 out2 = emit_jcc(b, CC_AE);
    x86_mov_rm(b, RSI, RDI, 0);
    emit_get_entry(b, R8, CLOS_FWD);
    x86_cmp_rr(b, RSI, R8);
    u32 fwd = emit_jcc(b, CC_E);
    x86_call_rel(b, 0);
    u32 cls = x86_len(b) - 4;
    /* copy RDX bytes from RDI to hp */
    x86_mov_rr(b, RAX, R12);
    x86_mov_ri(b, R8, 0);
    u32 loop = x86_len(b);
    x86_cmp_rr(b, R8, RDX);
    u32 done = emit_jcc(b, CC_AE);
    x86_mov_rr(b, R9, RDI); x86_add_rr(b, R9, R8); x86_mov_rm(b, R9, R9, 0);
    x86_mov_rr(b, R10, RAX); x86_add_rr(b, R10, R8); x86_mov_mr(b, R10, 0, R9);
    x86_add_ri(b, R8, 8);
    emit_jmp_back(b, loop);
    x86_patch_rel32(b, done, x86_len(b));
    x86_add_rr(b, R12, RDX);
    /* forward the old copy */
    emit_get_entry(b, RCX, CLOS_FWD);
    x86_mov_mr(b, RDI, 0, RCX);
    x86_mov_mr(b, RDI, 8, RAX);
    x86_ret(b);
    x86_patch_rel32(b, fwd, x86_len(b));
    x86_mov_rm(b, RAX, RDI, 8);
    x86_ret(b);
    x86_patch_rel32(b, out1, x86_len(b));
    x86_patch_rel32(b, out2, x86_len(b));
    x86_ret(b);
    x86_patch_rel32(b, cls, e->gc_classify_offset);
}

/*
 * scavenge: RBX = closure -> copies each pointer field, RBX = next closure.
 * Uses RBP / R14 as loop state (the caller saves them). Clobbers the rest.
 */
static void emit_scavenge(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->gc_scavenge_offset = x86_len(b);
    x86_mov_rm(b, RSI, RBX, 0);
    x86_call_rel(b, 0); u32 cl = x86_len(b) - 4;         /* rcx = ptr bytes, rdx = size bytes */
    x86_push(b, RDX);
    x86_mov_rr(b, R14, RCX); x86_add_ri(b, R14, 8);      /* end offset of pointer fields */
    x86_mov_ri(b, RBP, 8);                                /* first field */
    u32 fld = x86_len(b);
    x86_cmp_rr(b, RBP, R14);
    u32 fld_done = emit_jcc(b, CC_AE);
    x86_mov_rr(b, RDI, RBX); x86_add_rr(b, RDI, RBP); x86_mov_rm(b, RDI, RDI, 0);
    x86_call_rel(b, 0); u32 cp = x86_len(b) - 4;
    x86_mov_rr(b, R8, RBX); x86_add_rr(b, R8, RBP); x86_mov_mr(b, R8, 0, RAX);
    x86_add_ri(b, RBP, 8);
    emit_jmp_back(b, fld);
    x86_patch_rel32(b, fld_done, x86_len(b));
    x86_pop(b, RDX);
    x86_add_rr(b, RBX, RDX);
    x86_ret(b);
    x86_patch_rel32(b, cl, e->gc_classify_offset);
    x86_patch_rel32(b, cp, e->gc_copy_offset);
}

/* Store RAX (base) / R8 (size) into the slots of the FROM space (1 - active) */
static void emit_store_from_space(X86Buf *b) {
    emit_load_data(b, RCX, DATA_ACTIVE);
    x86_cmp_ri(b, RCX, 0);
    u32 act1 = emit_jcc(b, CC_NE);
    emit_store_data(b, DATA_SPACE1, RAX);
    emit_store_data(b, DATA_SPACE1_SIZE, R8);
    x86_jmp_rel(b, 0);
    u32 join = x86_len(b) - 4;
    x86_patch_rel32(b, act1, x86_len(b));
    emit_store_data(b, DATA_SPACE0, RAX);
    emit_store_data(b, DATA_SPACE0_SIZE, R8);
    x86_patch_rel32(b, join, x86_len(b));
}

/* RCX = size of the TO (active) space, RDX = size of the FROM space */
static void emit_load_space_sizes(X86Buf *b) {
    emit_load_data(b, RAX, DATA_ACTIVE);
    emit_load_data(b, R10, DATA_SPACE0_SIZE);
    emit_load_data(b, R11, DATA_SPACE1_SIZE);
    x86_cmp_ri(b, RAX, 0);
    x86_mov_rr(b, RCX, R10); emit_cmovne(b, RCX, R11);
    x86_mov_rr(b, RDX, R11); emit_cmovne(b, RDX, R10);
}

/*
 * gc: CALLed from emit_reserve with the roots in DATA_GC_ROOT_{K,SELF,VAL}
 * and the request in DATA_ALLOC_REQUEST. Flips semispaces, copies the
 * roots, Cheney-scans, then guarantees hp + request <= limit - growing the
 * heap if necessary - before returning with R12/R13 = new hp/limit and
 * the root slots updated.
 *
 * Growing: only an EMPTY space is ever remapped (MREMAP_MAYMOVE may move
 * it, which is harmless when nothing points into it). If the live data
 * plus the request does not fit after a collection, the just-evacuated
 * fromspace is doubled and the collection is repeated into it; after a
 * successful collection the (empty) fromspace is brought up to the same
 * size, so both spaces are equal again on return.
 */
static void emit_gc(NativeEmit *e) {
    X86Buf *b = &e->code;
    emit_classify(e);
    emit_copy_closure(e);
    emit_scavenge(e);
    e->gc_offset = x86_len(b);
    u32 oom_patch[4]; int n_oom = 0;
    x86_push(b, RBX); x86_push(b, RBP); x86_push(b, R14);
    u32 flip = x86_len(b);
    /* active ^= 1 */
    emit_load_data(b, RAX, DATA_ACTIVE);
    x86_mov_ri(b, RCX, 1);
    x86_byte(b, 0x48); x86_byte(b, 0x31); x86_byte(b, 0xC8);  /* xor rax, rcx */
    emit_store_data(b, DATA_ACTIVE, RAX);
    /* to = space[active], from = space[1 - active] */
    emit_load_data(b, R8, DATA_SPACE0);
    emit_load_data(b, R9, DATA_SPACE1);
    emit_load_data(b, R10, DATA_SPACE0_SIZE);
    emit_load_data(b, R11, DATA_SPACE1_SIZE);
    x86_cmp_ri(b, RAX, 0);
    x86_mov_rr(b, RBX, R8);  emit_cmovne(b, RBX, R9);    /* to_base */
    x86_mov_rr(b, RCX, R10); emit_cmovne(b, RCX, R11);   /* to_size */
    x86_mov_rr(b, RBP, R9);  emit_cmovne(b, RBP, R8);    /* from_base */
    x86_mov_rr(b, RDX, R11); emit_cmovne(b, RDX, R10);   /* from_size */
    emit_store_data(b, DATA_FROM_BASE, RBP);
    x86_add_rr(b, RDX, RBP);
    emit_store_data(b, DATA_FROM_END, RDX);
    x86_mov_rr(b, R12, RBX);                              /* hp = to_base */
    x86_mov_rr(b, R13, RBX); x86_add_rr(b, R13, RCX);     /* limit = to_base + to_size */
    emit_store_data(b, DATA_SCAN, RBX);                   /* Cheney scan starts at to_base */
    /* roots */
    static const int roots[3] = { DATA_GC_ROOT_K, DATA_GC_ROOT_SELF, DATA_GC_ROOT_VAL };
    u32 rc[3];
    for (int i = 0; i < 3; i++) {
        emit_load_data(b, RDI, roots[i]);
        x86_call_rel(b, 0); rc[i] = x86_len(b) - 4;
        emit_store_data(b, roots[i], RAX);
    }
    /* Static area (ELF: the embedded term, whose thunks get updated to point
     * into the heap): its closures never move, but their fields are roots. */
    emit_load_data(b, RBX, DATA_STATIC_BEGIN);
    u32 sscan = x86_len(b);
    x86_cmp_rm(b, RBX, R15, DATA_STATIC_END);
    u32 sscan_done = emit_jcc(b, CC_AE);
    x86_call_rel(b, 0); u32 sv1 = x86_len(b) - 4;
    emit_jmp_back(b, sscan);
    x86_patch_rel32(b, sscan_done, x86_len(b));
    emit_load_data(b, RBX, DATA_STATIC2_BEGIN);
    u32 s2 = x86_len(b);
    x86_cmp_rm(b, RBX, R15, DATA_STATIC2_END);
    u32 s2_done = emit_jcc(b, CC_AE);
    x86_call_rel(b, 0); u32 sv3 = x86_len(b) - 4;
    emit_jmp_back(b, s2);
    x86_patch_rel32(b, s2_done, x86_len(b));
    /* Cheney scan: rbx = scan pointer, chases hp */
    emit_load_data(b, RBX, DATA_SCAN);
    u32 scan = x86_len(b);
    x86_cmp_rr(b, RBX, R12);
    u32 scan_done = emit_jcc(b, CC_AE);
    x86_call_rel(b, 0); u32 sv2 = x86_len(b) - 4;
    emit_jmp_back(b, scan);
    x86_patch_rel32(b, scan_done, x86_len(b));
    /* enough room for the pending request? */
    emit_load_data(b, RAX, DATA_ALLOC_REQUEST);
    x86_add_rr(b, RAX, R12);
    x86_cmp_rr(b, RAX, R13);
    u32 fits = emit_jcc(b, CC_BE);
    /* grow: double the (empty) fromspace, then collect again into it */
    emit_load_space_sizes(b);                             /* rcx = to_size, rdx = from_size */
    x86_mov_rr(b, R8, RCX); x86_add_rr(b, R8, RCX);       /* new = 2 * to_size */
    x86_cmp_rm(b, R8, R15, DATA_MAX_SPACE_SIZE);
    oom_patch[n_oom++] = emit_jcc(b, CC_A);
    emit_load_data(b, RDI, DATA_FROM_BASE);
    x86_mov_rr(b, RSI, RDX);
    x86_mov_rr(b, RDX, R8);
    x86_mov_ri(b, R10, 1);                                /* MREMAP_MAYMOVE */
    x86_push(b, R8);
    x86_mov_ri(b, RAX, SYS_mremap);
    emit_syscall(b);
    x86_pop(b, R8);
    x86_cmp_ri(b, RAX, 0);
    u32 grow_ok = emit_jcc(b, CC_GE);
    oom_patch[n_oom++] = x86_len(b) + 1; x86_jmp_rel(b, 0);
    x86_patch_rel32(b, grow_ok, x86_len(b));
    emit_store_from_space(b);
    emit_jmp_back(b, flip);
    /* fits: bring the (empty) fromspace up to the tospace size if a grow left them unequal */
    x86_patch_rel32(b, fits, x86_len(b));
    emit_load_space_sizes(b);                             /* rcx = to_size, rdx = from_size */
    x86_cmp_rr(b, RDX, RCX);
    u32 equal = emit_jcc(b, CC_AE);
    emit_load_data(b, RDI, DATA_FROM_BASE);
    x86_mov_rr(b, RSI, RDX);
    x86_mov_rr(b, RDX, RCX);
    x86_mov_ri(b, R10, 1);
    x86_push(b, RCX);
    x86_mov_ri(b, RAX, SYS_mremap);
    emit_syscall(b);
    x86_pop(b, R8);
    x86_cmp_ri(b, RAX, 0);
    u32 eq_ok = emit_jcc(b, CC_GE);
    oom_patch[n_oom++] = x86_len(b) + 1; x86_jmp_rel(b, 0);
    x86_patch_rel32(b, eq_ok, x86_len(b));
    emit_store_from_space(b);
    x86_patch_rel32(b, equal, x86_len(b));
    /* done */
    emit_store_data(b, DATA_HP, R12);
    emit_store_data(b, DATA_LIMIT, R13);
    x86_pop(b, R14); x86_pop(b, RBP); x86_pop(b, RBX);
    x86_ret(b);
    /* OOM: write "OOM\n" to stderr, exit 137 */
    for (int i = 0; i < n_oom; i++) x86_patch_rel32(b, oom_patch[i], x86_len(b));
    x86_push(b, RAX);
    x86_mov_ri(b, RAX, 0x0A4D4F4F);
    x86_mov_mr(b, RSP, 0, RAX);
    x86_mov_ri(b, RAX, SYS_write);
    x86_mov_ri(b, RDI, 2);
    x86_mov_rr(b, RSI, RSP);
    x86_mov_ri(b, RDX, 4);
    emit_syscall(b);
    x86_mov_ri(b, RAX, SYS_exit);
    x86_mov_ri(b, RDI, 137);
    emit_syscall(b);
    /* subroutine calls */
    for (int i = 0; i < 3; i++) x86_patch_rel32(b, rc[i], e->gc_copy_offset);
    x86_patch_rel32(b, sv1, e->gc_scavenge_offset);
    x86_patch_rel32(b, sv2, e->gc_scavenge_offset);
    x86_patch_rel32(b, sv3, e->gc_scavenge_offset);
}


/* ========================================================================
 * STREAM I/O - the Lazy-K / WHNF model (see eezo/io.h)
 *
 * The program is a function from the input stream to the output stream.
 * Streams are pairs  f -> f x rest  = S (S I (K x)) (K rest), elements are
 * Church numerals, the input ends in an infinite stream of 256, an output
 * element n >= 256 exits with status n - 256.
 *
 * The driver is three continuations, all pure:
 *   IoV        receives the output cell v (WHNF)  -> apply v to K       (head)
 *   IoH[v]     receives the head h                -> apply h to K, then S
 *   IoN[v, c]  receives t: K1[u] -> c+1, unfold u; S -> the numeral is c:
 *              emit the byte (or exit), then apply v to K I for the tail,
 *              whose value goes back to IoV.
 * Reading a numeral never needs a normal form: n K S = K (K (... S)) and
 * each step is one weak head reduction.
 *
 * The input stream is built by emitted code at start-up (both JIT and
 * ELF) into a separate mmap'd region that the collector scans as a second
 * static root area; its cells are thunks and get updated like any other.
 * ======================================================================== */

/* write(1, OUTBUF, OUTPOS); OUTPOS = 0. Clobbers RAX, RCX, RDX, RSI, RDI, R11. */
static void emit_io_flush(X86Buf *b) {
    emit_load_data(b, RDX, DATA_OUTPOS);
    x86_cmp_ri(b, RDX, 0);
    u32 skip = emit_jcc(b, CC_E);
    x86_mov_ri(b, RAX, SYS_write);
    x86_mov_ri(b, RDI, 1);
    emit_load_data(b, RSI, DATA_OUTBUF);
    emit_syscall(b);
    x86_mov_ri(b, RCX, 0);
    emit_store_data(b, DATA_OUTPOS, RCX);
    x86_patch_rel32(b, skip, x86_len(b));
}

/* Byte in RDI -> output buffer, flushing when full. Preserves RBX, R14. */
static void emit_output_byte(X86Buf *b) {
    emit_load_data(b, RAX, DATA_OUTBUF);
    emit_load_data(b, RCX, DATA_OUTPOS);
    x86_mov_rr(b, RDX, RDI);
    x86_byte(b, 0x88); x86_byte(b, 0x14); x86_byte(b, 0x08);   /* mov [rax+rcx], dl */
    x86_add_ri(b, RCX, 1);
    emit_store_data(b, DATA_OUTPOS, RCX);
    emit_load_data(b, RDX, DATA_OUTLEN);
    x86_cmp_rr(b, RCX, RDX);
    u32 skip = emit_jcc(b, CC_B);
    emit_io_flush(b);
    x86_patch_rel32(b, skip, x86_len(b));
}

/* Write a 16-byte message (two little-endian qwords) to stderr, exit(code) */
static void emit_die(X86Buf *b, u64 w0, u64 w1, int code) {
    x86_mov_ri(b, RAX, w1); x86_push(b, RAX);
    x86_mov_ri(b, RAX, w0); x86_push(b, RAX);
    x86_mov_ri(b, RAX, SYS_write);
    x86_mov_ri(b, RDI, 2);
    x86_mov_rr(b, RSI, RSP);
    x86_mov_ri(b, RDX, 16);
    emit_syscall(b);
    x86_mov_ri(b, RAX, SYS_exit);
    x86_mov_ri(b, RDI, code);
    emit_syscall(b);
}
#define MSG_NOT_NUMERAL_0 0x20746f6e203a6f69ULL
#define MSG_NOT_NUMERAL_1 0x0a6c6172656d756eULL
#define MSG_READ_FAILED_0 0x64616572203a6f69ULL
#define MSG_READ_FAILED_1 0x0a64656c69616620ULL

/* IoV: receives the output cell v -> eval(v K, IoH[v]) */
static void emit_entry_IoV(NativeEmit *e) {
    X86Buf *b = &e->code;
    u32 top = x86_len(b);
    e->entry_offsets[CLOS_IOV] = top;
    emit_reserve(e, 5, top);
    emit_bump(b, 2);                                   /* IoH[v] */
    emit_get_entry(b, RSI, CLOS_IOH);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, R14);
    x86_mov_rr(b, R8, RAX);
    emit_bump(b, 3);                                   /* ApplyK[K, IoH] */
    emit_get_entry(b, RSI, CLOS_APPLYK);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_lea(b, RCX, R15, DATA_PRIM_K);
    x86_mov_mr(b, RAX, 8, RCX);
    x86_mov_mr(b, RAX, 16, R8);
    x86_mov_rr(b, RBX, RAX);
    emit_call_cont(b);                                 /* f_val = v (r14) */
}

/* IoH[v]: receives the head h -> eval(h K S, IoN[v, 0]) */
static void emit_entry_IoH(NativeEmit *e) {
    X86Buf *b = &e->code;
    u32 top = x86_len(b);
    e->entry_offsets[CLOS_IOH] = top;
    emit_reserve(e, 9, top);
    x86_mov_rm(b, RCX, RDI, 8);                        /* v */
    emit_bump(b, 3);                                   /* IoN[v, 0] */
    emit_get_entry(b, RSI, CLOS_ION);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, RCX);
    x86_mov_mi(b, RAX, 16, 0);
    x86_mov_rr(b, R8, RAX);
    emit_bump(b, 3);                                   /* ApplyK[S, IoN] */
    emit_get_entry(b, RSI, CLOS_APPLYK);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_lea(b, RCX, R15, DATA_PRIM_S);
    x86_mov_mr(b, RAX, 8, RCX);
    x86_mov_mr(b, RAX, 16, R8);
    x86_mov_rr(b, R9, RAX);
    emit_bump(b, 3);                                   /* ApplyK[K, that] */
    x86_mov_mr(b, RAX, 0, RSI);
    x86_lea(b, RCX, R15, DATA_PRIM_K);
    x86_mov_mr(b, RAX, 8, RCX);
    x86_mov_mr(b, RAX, 16, R9);
    x86_mov_rr(b, RBX, RAX);
    emit_call_cont(b);                                 /* f_val = h (r14) */
}

/* IoN[v, count]: receives t */
static void emit_entry_IoN(NativeEmit *e) {
    X86Buf *b = &e->code;
    u32 top = x86_len(b);
    e->entry_offsets[CLOS_ION] = top;
    emit_reserve(e, 3, top);
    x86_mov_rm(b, RSI, R14, 0);
    emit_get_entry(b, R8, CLOS_K1);
    x86_cmp_rr(b, RSI, R8);
    u32 more = emit_jcc(b, CC_E);
    emit_get_entry(b, R8, CLOS_S);
    x86_cmp_rr(b, RSI, R8);
    u32 done = emit_jcc(b, CC_E);
    emit_io_flush(b);
    emit_die(b, MSG_NOT_NUMERAL_0, MSG_NOT_NUMERAL_1, 1);
    /* K1[u]: count++, unfold u under the same continuation */
    x86_patch_rel32(b, more, x86_len(b));
    x86_mov_rm(b, RAX, RDI, 16);
    x86_add_ri(b, RAX, 1);
    x86_mov_mr(b, RDI, 16, RAX);
    x86_mov_rr(b, RBX, RDI);
    x86_mov_rm(b, RDI, R14, 8);
    emit_enter(b);
    /* S: the numeral is count */
    x86_patch_rel32(b, done, x86_len(b));
    x86_mov_rr(b, RBX, RDI);                           /* self, safe across syscalls */
    x86_mov_rm(b, RCX, RDI, 16);
    x86_cmp_ri(b, RCX, 256);
    u32 fin = emit_jcc(b, CC_AE);
    x86_mov_rr(b, RDI, RCX);
    emit_output_byte(b);
    x86_mov_rm(b, RCX, RBX, 8);                        /* v */
    emit_bump(b, 3);                                   /* ApplyK[K I, IoV]: the tail's value returns to IoV */
    emit_get_entry(b, RSI, CLOS_APPLYK);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_lea(b, RDX, R15, DATA_KI);
    x86_mov_mr(b, RAX, 8, RDX);
    x86_lea(b, RDX, R15, DATA_IOV);
    x86_mov_mr(b, RAX, 16, RDX);
    x86_mov_rr(b, RBX, RAX);
    x86_mov_rr(b, R14, RCX);
    emit_call_cont(b);
    /* count >= 256: flush, exit(count - 256) */
    x86_patch_rel32(b, fin, x86_len(b));
    x86_push(b, RCX);
    emit_io_flush(b);
    x86_pop(b, RDI);
    x86_sub_ri(b, RDI, 256);
    x86_mov_ri(b, RAX, SYS_exit);
    emit_syscall(b);
}

/* mmap(NULL, RSI bytes, RW, private|anon) -> RAX. Clobbers RDI, RDX, R8-R11. */
static void emit_mmap_rsi(X86Buf *b) {
    x86_mov_ri(b, RAX, SYS_mmap);
    x86_mov_ri(b, RDI, 0);
    x86_mov_ri(b, RDX, MMAP_PROT_RW);
    x86_mov_ri(b, R10, MMAP_PRIVATE_ANON);
    x86_mov_ri(b, R8, (u64)-1);
    x86_mov_ri(b, R9, 0);
    emit_syscall(b);
}

/* Write an App cell [entry_App, f, x] at the bump pointer R9; RAX = its address. Clobbers RSI. */
static void emit_io_cell(X86Buf *b, X86Reg f, X86Reg x) {
    x86_mov_rr(b, RAX, R9);
    emit_get_entry(b, RSI, CLOS_APP);
    x86_mov_mr(b, R9, 0, RSI);
    x86_mov_mr(b, R9, 8, f);
    x86_mov_mr(b, R9, 16, x);
    x86_add_ri(b, R9, 24);
}

/*
 * io start: entered from _start with r12/r13/r15 set up.
 *   1. output buffer
 *   2. read all of stdin (rbx = buf, rbp = len, r14 = cap)
 *   3. mmap the input region: (15*len + 801) words
 *   4. build: succ, the numeral chain, S I, the EOF cycle, the cells, App(P, s)
 *   5. enter App(P, s) with continuation IoV
 */
static void emit_io_start(NativeEmit *e) {
    X86Buf *b = &e->code;
    /* 1 */
    x86_mov_ri(b, RSI, 4096);
    emit_mmap_rsi(b);
    emit_store_data(b, DATA_OUTBUF, RAX);
    x86_mov_ri(b, RAX, 4096);
    emit_store_data(b, DATA_OUTLEN, RAX);
    x86_mov_ri(b, RAX, 0);
    emit_store_data(b, DATA_OUTPOS, RAX);
    /* 2 */
    x86_mov_ri(b, R14, 65536);
    x86_mov_rr(b, RSI, R14);
    emit_mmap_rsi(b);
    x86_mov_rr(b, RBX, RAX);
    x86_mov_ri(b, RBP, 0);
    u32 rd = x86_len(b);
    x86_mov_ri(b, RAX, 0);                             /* SYS_read */
    x86_mov_ri(b, RDI, 0);
    x86_mov_rr(b, RSI, RBX); x86_add_rr(b, RSI, RBP);
    x86_mov_rr(b, RDX, R14); x86_byte(b, 0x48); x86_byte(b, 0x29); x86_byte(b, 0xEA);   /* sub rdx, rbp */
    emit_syscall(b);
    x86_cmp_ri(b, RAX, 0);
    u32 rd_err = emit_jcc(b, CC_L);
    u32 rd_done = emit_jcc(b, CC_E);
    x86_add_rr(b, RBP, RAX);
    x86_cmp_rr(b, RBP, R14);
    u32 rd_again = emit_jcc(b, CC_B);
    /* buffer full: double it (bytes only, moving is fine) */
    x86_mov_rr(b, RDI, RBX);
    x86_mov_rr(b, RSI, R14);
    x86_mov_rr(b, RDX, R14); x86_add_rr(b, RDX, R14);
    x86_mov_ri(b, R10, 1);
    x86_mov_ri(b, RAX, SYS_mremap);
    emit_syscall(b);
    x86_cmp_ri(b, RAX, 0);
    u32 rd_err2 = emit_jcc(b, CC_L);
    x86_mov_rr(b, RBX, RAX);
    x86_mov_rr(b, R14, RDX);
    x86_patch_rel32(b, rd_again, x86_len(b));
    emit_jmp_back(b, rd);
    x86_patch_rel32(b, rd_err, x86_len(b));
    x86_patch_rel32(b, rd_err2, x86_len(b));
    emit_die(b, MSG_READ_FAILED_0, MSG_READ_FAILED_1, 1);
    x86_patch_rel32(b, rd_done, x86_len(b));
    emit_store_data(b, DATA_IO_BUF, RBX);
    emit_store_data(b, DATA_IO_LEN, RBP);
    /* 3: bytes = (15*len + 801) * 8 */
    x86_mov_rr(b, RAX, RBP);
    x86_byte(b, 0x48); x86_byte(b, 0xC1); x86_byte(b, 0xE0); x86_byte(b, 4);       /* shl rax, 4 */
    x86_byte(b, 0x48); x86_byte(b, 0x29); x86_byte(b, 0xE8);                        /* sub rax, rbp */
    x86_add_ri(b, RAX, 801);
    x86_byte(b, 0x48); x86_byte(b, 0xC1); x86_byte(b, 0xE0); x86_byte(b, 3);       /* shl rax, 3 */
    x86_mov_rr(b, RSI, RAX);
    emit_mmap_rsi(b);
    emit_store_data(b, DATA_STATIC2_BEGIN, RAX);
    x86_mov_rr(b, R9, RAX);                            /* bump pointer */
    /* the cons subroutine: r10 = x, r11 = y -> rax = S (S I (K x)) (K y); r14 = S I.
     * Uses rax, rcx, rdx, rsi, r8; preserves rdi, r10, r11. */
    x86_jmp_rel(b, 0);
    u32 over = x86_len(b) - 4;
    u32 cons = x86_len(b);
    x86_mov_rr(b, RDX, R11);
    x86_lea(b, RCX, R15, DATA_PRIM_K); emit_io_cell(b, RCX, R10); x86_mov_rr(b, R8, RAX);   /* K x */
    emit_io_cell(b, R14, R8);          x86_mov_rr(b, R8, RAX);                              /* S I (K x) */
    x86_lea(b, RCX, R15, DATA_PRIM_S); emit_io_cell(b, RCX, R8);  x86_mov_rr(b, R8, RAX);   /* S (..) */
    x86_lea(b, RCX, R15, DATA_PRIM_K); emit_io_cell(b, RCX, RDX); x86_mov_rr(b, RCX, RAX);  /* K y */
    emit_io_cell(b, R8, RCX);                                                               /* the cell */
    x86_ret(b);
    x86_patch_rel32(b, over, x86_len(b));
    /* 4: succ = S (S (K S) K) */
    x86_lea(b, R10, R15, DATA_PRIM_K); x86_lea(b, R11, R15, DATA_PRIM_S); emit_io_cell(b, R10, R11);
    x86_lea(b, R10, R15, DATA_PRIM_S); x86_mov_rr(b, R11, RAX);           emit_io_cell(b, R10, R11);
    x86_mov_rr(b, R10, RAX);           x86_lea(b, R11, R15, DATA_PRIM_K); emit_io_cell(b, R10, R11);
    x86_lea(b, R10, R15, DATA_PRIM_S); x86_mov_rr(b, R11, RAX);           emit_io_cell(b, R10, R11);
    x86_mov_rr(b, R14, RAX);                           /* succ */
    /* chain: num[k] = succ num[k-1], k = 1..256, contiguous */
    emit_store_data(b, DATA_IO_CHAIN, R9);
    x86_lea(b, R11, R15, DATA_KI);
    x86_mov_ri(b, RCX, 256);
    u32 ch = x86_len(b);
    x86_push(b, RCX);
    emit_io_cell(b, R14, R11);
    x86_pop(b, RCX);
    x86_mov_rr(b, R11, RAX);
    x86_sub_ri(b, RCX, 1);
    x86_cmp_ri(b, RCX, 0);
    u32 ch_done = emit_jcc(b, CC_E);
    emit_jmp_back(b, ch);
    x86_patch_rel32(b, ch_done, x86_len(b));
    /* S I */
    x86_lea(b, R10, R15, DATA_PRIM_S); x86_lea(b, R11, R15, DATA_PRIM_I); emit_io_cell(b, R10, R11);
    x86_mov_rr(b, R14, RAX);
    /* EOF cycle: cons(num[256], itself); the cell is the 5th one written */
    emit_load_data(b, R10, DATA_IO_CHAIN); x86_add_ri(b, R10, 255 * 24);
    x86_lea(b, R11, R9, 96);
    x86_call_rel(b, 0); u32 c1 = x86_len(b) - 4;
    x86_mov_rr(b, RDI, RAX);                           /* s */
    /* the bytes, back to front: rbp counts down */
    u32 bl = x86_len(b);
    x86_cmp_ri(b, RBP, 0);
    u32 bl_done = emit_jcc(b, CC_E);
    x86_sub_ri(b, RBP, 1);
    x86_byte(b, 0x48); x86_byte(b, 0x0F); x86_byte(b, 0xB6); x86_byte(b, 0x04); x86_byte(b, 0x2B);   /* movzx rax, byte [rbx+rbp] */
    x86_cmp_ri(b, RAX, 0);
    u32 nz = emit_jcc(b, CC_NE);
    x86_lea(b, R10, R15, DATA_KI);
    x86_jmp_rel(b, 0); u32 have = x86_len(b) - 4;
    x86_patch_rel32(b, nz, x86_len(b));
    x86_sub_ri(b, RAX, 1);
    x86_byte(b, 0x48); x86_byte(b, 0xC1); x86_byte(b, 0xE0); x86_byte(b, 3);       /* shl rax, 3 */
    x86_byte(b, 0x48); x86_byte(b, 0x8D); x86_byte(b, 0x0C); x86_byte(b, 0x40);    /* lea rcx, [rax+rax*2] */
    emit_load_data(b, R10, DATA_IO_CHAIN);
    x86_add_rr(b, R10, RCX);
    x86_patch_rel32(b, have, x86_len(b));
    x86_mov_rr(b, R11, RDI);
    x86_call_rel(b, 0); u32 c2 = x86_len(b) - 4;
    x86_mov_rr(b, RDI, RAX);
    emit_jmp_back(b, bl);
    x86_patch_rel32(b, bl_done, x86_len(b));
    x86_patch_rel32(b, c1, cons);
    x86_patch_rel32(b, c2, cons);
    /* App(P, s) */
    emit_load_data(b, R10, DATA_ROOT);
    emit_io_cell(b, R10, RDI);
    emit_store_data(b, DATA_STATIC2_END, R9);
    /* 5 */
    x86_lea(b, RBX, R15, DATA_IOV);
    x86_mov_rr(b, RDI, RAX);
    x86_mov_ri(b, R14, 0);
    emit_enter(b);
}

/* ========================================================================
 * PROGRAM ENTRY POINT
 * ======================================================================== */

static void emit_start(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->start_offset = x86_len(b);
    
    /*
     * Entry point:
     * 1. r15 already set to data section by caller
     * 2. Heap already mmap'd, pointers in data section
     * 3. Root term already built on heap, address in DATA_ROOT
     *
     * We just:
     * - Load hp/limit into registers
     * - Set continuation to Halt
     * - Load root term and enter it
     */
    
    /* Load runtime state into registers */
    emit_load_data(b, R12, DATA_HP);
    emit_load_data(b, R13, DATA_LIMIT);
    emit_load_data(b, RAX, DATA_IO_MODE);
    x86_cmp_ri(b, RAX, 0);
    u32 io = emit_jcc(b, CC_NE);
    x86_mov_ri(b, R14, 0);                      /* no value yet: the GC root must be clean */
    x86_lea(b, RBX, R15, DATA_HALT);            /* k = Halt */
    emit_load_data(b, RDI, DATA_ROOT);          /* the program */
    /* NF mode: k = Norm[Halt]; WHNF mode: k = Halt */
    u32 retry = x86_len(b);
    emit_reserve(e, 2, retry);
    emit_load_data(b, RAX, DATA_NF_MODE);
    x86_cmp_ri(b, RAX, 0);
    u32 whnf = emit_jcc(b, CC_E);
    emit_bump(b, 2);
    emit_get_entry(b, RSI, CLOS_NORM);
    x86_mov_mr(b, RAX, 0, RSI);
    x86_mov_mr(b, RAX, 8, RBX);
    x86_mov_rr(b, RBX, RAX);
    x86_patch_rel32(b, whnf, x86_len(b));
    emit_enter(b);
    /* stream I/O mode */
    x86_patch_rel32(b, io, x86_len(b));
    emit_io_start(e);
}

/* ========================================================================
 * OUTPUT SERIALIZATION ROUTINES
 *
 * These walk the result closure and write encoding to stdout.
 * Entry: r14 = final value (closure pointer)
 * All three routines end with syscall exit(0).
 *
 * The walk is done iteratively with an explicit stack (stored in heap).
 * Format: BCL uses 00=K, 01=S, 1=App prefix
 *         Jot uses unary encoding
 *         Jomplement uses complement of Jot
 * ======================================================================== */

/*
 * Helper: emit a bit to output buffer
 * Clobbers rax, rcx
 * bit value in lowest bit of rdi
 */
static void emit_output_bit(X86Buf *b) {
    /* 
     * Output buffer stores ASCII '0'/'1' characters.
     * DATA_OUTBUF = buffer base, DATA_OUTPOS = current write position
     *
     * buf[pos] = '0' + (rdi & 1)
     * pos++
     * if pos >= OUTLEN, flush
     */
    
    /* rax = outbuf base */
    emit_load_data(b, RAX, DATA_OUTBUF);
    /* rcx = outpos */
    emit_load_data(b, RCX, DATA_OUTPOS);
    
    /* Calculate character: '0' + (rdi & 1) */
    x86_mov_rr(b, RDX, RDI);
    x86_byte(b, 0x48); x86_byte(b, 0x83); x86_byte(b, 0xE2); x86_byte(b, 0x01);  /* and rdx, 1 */
    x86_add_ri(b, RDX, '0');
    
    /* Store byte: [rax + rcx] = dl */
    x86_byte(b, 0x88); x86_byte(b, 0x14); x86_byte(b, 0x08);  /* mov [rax+rcx], dl */
    
    /* Increment position */
    x86_add_ri(b, RCX, 1);
    emit_store_data(b, DATA_OUTPOS, RCX);
    
    /* Check if flush needed (pos >= outlen) */
    emit_load_data(b, RDX, DATA_OUTLEN);
    x86_cmp_rr(b, RCX, RDX);
    /* jb skip_flush */
    u32 skip_flush = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x82); x86_dword(b, 0);
    
    /* Flush: write(1, buf, pos) */
    x86_push(b, R14);  /* save r14 */
    x86_mov_ri(b, RAX, SYS_write);
    x86_mov_ri(b, RDI, 1);  /* fd = stdout */
    emit_load_data(b, RSI, DATA_OUTBUF);
    emit_load_data(b, RDX, DATA_OUTPOS);
    emit_syscall(b);
    x86_pop(b, R14);
    
    /* Reset position to 0 */
    x86_mov_ri(b, RCX, 0);
    emit_store_data(b, DATA_OUTPOS, RCX);
    
    /* skip_flush: */
    x86_patch_rel32(b, skip_flush, x86_len(b));
}

/*
 * Helper: output a single bit with XOR against DATA_OUTPUT_XOR
 * Input: rdi = bit value (0 or 1)
 * Used for Jot/Jomplement: XOR mask is 0 for Jot, 1 for Jomplement
 */
static void emit_output_bit_xor(X86Buf *b) {
    /* XOR rdi with DATA_OUTPUT_XOR */
    emit_load_data(b, RAX, DATA_OUTPUT_XOR);
    x86_byte(b, 0x48); x86_byte(b, 0x31); x86_byte(b, 0xC7);  /* xor rdi, rax */
    
    /* Then do normal output */
    emit_load_data(b, RAX, DATA_OUTBUF);
    emit_load_data(b, RCX, DATA_OUTPOS);
    
    x86_mov_rr(b, RDX, RDI);
    x86_byte(b, 0x48); x86_byte(b, 0x83); x86_byte(b, 0xE2); x86_byte(b, 0x01);  /* and rdx, 1 */
    x86_add_ri(b, RDX, '0');
    
    x86_byte(b, 0x88); x86_byte(b, 0x14); x86_byte(b, 0x08);  /* mov [rax+rcx], dl */
    
    x86_add_ri(b, RCX, 1);
    emit_store_data(b, DATA_OUTPOS, RCX);
    
    emit_load_data(b, RDX, DATA_OUTLEN);
    x86_cmp_rr(b, RCX, RDX);
    u32 skip_flush = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x82); x86_dword(b, 0);
    
    x86_push(b, R14);
    x86_mov_ri(b, RAX, SYS_write);
    x86_mov_ri(b, RDI, 1);
    emit_load_data(b, RSI, DATA_OUTBUF);
    emit_load_data(b, RDX, DATA_OUTPOS);
    emit_syscall(b);
    x86_pop(b, R14);
    
    x86_mov_ri(b, RCX, 0);
    emit_store_data(b, DATA_OUTPOS, RCX);
    
    x86_patch_rel32(b, skip_flush, x86_len(b));
}

/*
 * Helper: flush remaining output buffer and exit
 */
static void emit_flush_and_exit(X86Buf *b) {
    /* Write any remaining data */
    emit_load_data(b, RDX, DATA_OUTPOS);
    x86_cmp_ri(b, RDX, 0);
    u32 skip_write = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je skip */
    
    x86_mov_ri(b, RAX, SYS_write);
    x86_mov_ri(b, RDI, 1);
    emit_load_data(b, RSI, DATA_OUTBUF);
    /* rdx already has outpos */
    emit_syscall(b);
    
    x86_patch_rel32(b, skip_write, x86_len(b));
    
    /* Write newline */
    /* Use a byte on the stack */
    x86_push(b, RAX);
    x86_mov_ri(b, RAX, '\n');
    x86_mov_mr(b, RSP, 0, RAX);
    x86_mov_ri(b, RAX, SYS_write);
    x86_mov_ri(b, RDI, 1);
    x86_mov_rr(b, RSI, RSP);
    x86_mov_ri(b, RDX, 1);
    emit_syscall(b);
    x86_pop(b, RAX);
    
    /* exit(0) */
    x86_mov_ri(b, RAX, SYS_exit);
    x86_mov_ri(b, RDI, 0);
    emit_syscall(b);
}

/*
 * Output helper: r10 = closure, rcx = closure, rdx = its entry pointer.
 * Follow indirections (updated thunks) to the value they stand for.
 */
static void emit_follow_ind(X86Buf *b) {
    u32 top = x86_len(b);
    emit_get_entry(b, RAX, CLOS_IND);
    x86_cmp_rr(b, RDX, RAX);
    u32 skip = emit_jcc(b, CC_NE);
    x86_mov_rm(b, R10, R10, 8);
    x86_mov_rr(b, RCX, R10);
    x86_mov_rm(b, RDX, RCX, 0);
    emit_jmp_back(b, top);
    x86_patch_rel32(b, skip, x86_len(b));
}

/*
 * BCL Output Routine
 *
 * BCL encoding: K=00, S=01, App(f,x)=1 + encode(f) + encode(x)
 *
 * We use an iterative approach with a stack:
 * - Push closures to process
 * - Pop, emit bits based on type, push children if App
 */
static void emit_output_bcl(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->output_offset = x86_len(b);
    
    /*
     * r14 = root closure to serialize
     * Use r8 as stack pointer (grows down from heap limit area)
     * r9 = stack base (for underflow check)
     */
    
    /* Allocate output buffer (4KB) via mmap */
    x86_mov_ri(b, RAX, SYS_mmap);
    x86_mov_ri(b, RDI, 0);
    x86_mov_ri(b, RSI, 4096);
    x86_mov_ri(b, RDX, MMAP_PROT_RW);
    x86_mov_ri(b, R10, MMAP_PRIVATE_ANON);
    x86_mov_ri(b, R8, (u64)-1);
    x86_mov_ri(b, R9, 0);
    emit_syscall(b);
    emit_store_data(b, DATA_OUTBUF, RAX);
    x86_mov_ri(b, RCX, 0);
    emit_store_data(b, DATA_OUTPOS, RCX);
    x86_mov_ri(b, RCX, 4096);
    emit_store_data(b, DATA_OUTLEN, RCX);
    
    /* Allocate traversal stack (64KB) */
    x86_mov_ri(b, RAX, SYS_mmap);
    x86_mov_ri(b, RDI, 0);
    x86_mov_ri(b, RSI, 65536);
    x86_mov_ri(b, RDX, MMAP_PROT_RW);
    x86_mov_ri(b, R10, MMAP_PRIVATE_ANON);
    x86_mov_ri(b, R8, (u64)-1);
    x86_mov_ri(b, R9, 0);
    emit_syscall(b);
    
    /* r8 = stack top (starts at end, grows down) */
    x86_mov_rr(b, R8, RAX);
    x86_add_ri(b, R8, 65536);
    /* r9 = stack base */
    x86_mov_rr(b, R9, RAX);
    
    /* Push root onto stack */
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, R14);
    
    /* Main loop: while stack not empty */
    u32 loop_start = x86_len(b);
    
    /* Check stack empty (r8 >= r9 + 65536) */
    x86_mov_rr(b, RAX, R9);
    x86_add_ri(b, RAX, 65536);
    x86_cmp_rr(b, R8, RAX);
    u32 loop_done_patch = x86_len(b) + 2;
    x86_jae_rel(b, 0);  /* stack empty -> done */
    
    /* Pop closure into rcx, save to r10 for field access after emit_output_bit */
    x86_mov_rm(b, RCX, R8, 0);
    x86_add_ri(b, R8, 8);
    x86_mov_rr(b, R10, RCX);  /* r10 = closure (preserved across emit_output_bit) */
    
    /* Get entry pointer to determine type */
    x86_mov_rm(b, RDX, RCX, 0);  /* rdx = entry ptr */
    emit_follow_ind(b);
    
    /* Check for S */
    emit_get_entry(b, RAX, CLOS_S);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_s_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for K */
    emit_get_entry(b, RAX, CLOS_K);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_k_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for I - emit as SKK */
    emit_get_entry(b, RAX, CLOS_I);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_i_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for S1[x] - emit as App(S, x) */
    emit_get_entry(b, RAX, CLOS_S1);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_s1_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for S2[x,y] - emit as App(App(S, x), y) */
    emit_get_entry(b, RAX, CLOS_S2);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_s2_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for K1[x] - emit as App(K, x) */
    emit_get_entry(b, RAX, CLOS_K1);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_k1_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for App[f,x] */
    emit_get_entry(b, RAX, CLOS_APP);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_app_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Unknown type - trap */
    x86_int3(b);
    
    /* is_s: emit 01 */
    u32 is_s_target = x86_len(b);
    x86_patch_rel32(b, is_s_patch, is_s_target);
    x86_mov_ri(b, RDI, 0);
    emit_output_bit(b);
    x86_mov_ri(b, RDI, 1);
    emit_output_bit(b);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_k: emit 00 */
    u32 is_k_target = x86_len(b);
    x86_patch_rel32(b, is_k_patch, is_k_target);
    x86_mov_ri(b, RDI, 0);
    emit_output_bit(b);
    x86_mov_ri(b, RDI, 0);
    emit_output_bit(b);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_i: I = S K K, so emit 1 1 01 00 00 (App(App(S,K),K)) */
    u32 is_i_target = x86_len(b);
    x86_patch_rel32(b, is_i_patch, is_i_target);
    /* 1 (outer app) */
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);
    /* 1 (inner app) */
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);
    /* 01 (S) */
    x86_mov_ri(b, RDI, 0); emit_output_bit(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);
    /* 00 (K) */
    x86_mov_ri(b, RDI, 0); emit_output_bit(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit(b);
    /* 00 (K) */
    x86_mov_ri(b, RDI, 0); emit_output_bit(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit(b);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_s1: S1[x] = App(S, x), emit 1, push x, push S-singleton */
    u32 is_s1_target = x86_len(b);
    x86_patch_rel32(b, is_s1_patch, is_s1_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);
    /* Push x = [r10+8] (r10 preserved across emit_output_bit) */
    x86_mov_rm(b, RAX, R10, 8);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    /* Push S singleton address */
    x86_lea(b, RAX, R15, DATA_PRIM_S);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_s2: S2[x,y] = App(App(S,x), y), emit 1, push y, push App(S,x) as S1[x] */
    u32 is_s2_target = x86_len(b);
    x86_patch_rel32(b, is_s2_patch, is_s2_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);
    /* Push y = [r10+16] (r10 preserved across emit_output_bit) */
    x86_mov_rm(b, RAX, R10, 16);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    /* For App(S,x), we need to emit 1 + S + x */
    /* Push x */
    x86_mov_rm(b, RAX, R10, 8);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    /* Push marker for "emit 1 then S" - use S singleton, handle specially */
    /* Actually simpler: just emit 1, S inline, then push x */
    /* Let me redo: emit 1 1, push x, push S, push y - wait that's wrong order */
    /* Need: 1 (outer) then 1 (inner) then 01 (S) then encode(x) then encode(y) */
    /* So emit: 1, then push y (to do last), then handle App(S,x) */
    /* Actually let's just emit the bits inline for the S part */
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);  /* inner app bit */
    x86_mov_ri(b, RDI, 0); emit_output_bit(b);  /* S = 01 */
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);
    /* Now stack has [y, x], which is correct order for BCL (x first, then y) */
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_k1: K1[x] = App(K, x), emit 1, push x, push K-singleton */
    u32 is_k1_target = x86_len(b);
    x86_patch_rel32(b, is_k1_patch, is_k1_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);
    x86_mov_rm(b, RAX, R10, 8);  /* r10 preserved across emit_output_bit */
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    x86_lea(b, RAX, R15, DATA_PRIM_K);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_app: App[f,x], emit 1, push x, push f */
    u32 is_app_target = x86_len(b);
    x86_patch_rel32(b, is_app_patch, is_app_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit(b);
    /* Push x = [r10+16] first (will be popped second) - r10 preserved */
    x86_mov_rm(b, RAX, R10, 16);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    /* Push f = [r10+8] (will be popped first) */
    x86_mov_rm(b, RAX, R10, 8);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* loop_done: flush and exit */
    u32 loop_done_target = x86_len(b);
    x86_patch_rel32(b, loop_done_patch, loop_done_target);
    emit_flush_and_exit(b);
}

/*
 * Jot/Jomplement Output Routine
 * 
 * Jot encoding (verified from esolangs):
 *   K = 11100 (5 bits)
 *   S = 11111000 (8 bits)
 *   I = SKK = 1 + 1 + 11111000 + 11100 + 11100 = 20 bits
 *   App(a,b) = 1 + encode(a) + encode(b)
 *
 * Same traversal structure as BCL, just different bit patterns.
 * Uses DATA_OUTPUT_XOR: 0 for Jot, 1 for Jomplement (all bits inverted).
 */
static void emit_output_jot_impl(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->output_offset = x86_len(b);
    
    /* Allocate output buffer (4KB) via mmap */
    x86_mov_ri(b, RAX, SYS_mmap);
    x86_mov_ri(b, RDI, 0);
    x86_mov_ri(b, RSI, 4096);
    x86_mov_ri(b, RDX, MMAP_PROT_RW);
    x86_mov_ri(b, R10, MMAP_PRIVATE_ANON);
    x86_mov_ri(b, R8, (u64)-1);
    x86_mov_ri(b, R9, 0);
    emit_syscall(b);
    emit_store_data(b, DATA_OUTBUF, RAX);
    x86_mov_ri(b, RCX, 0);
    emit_store_data(b, DATA_OUTPOS, RCX);
    x86_mov_ri(b, RCX, 4096);
    emit_store_data(b, DATA_OUTLEN, RCX);
    
    /* Allocate traversal stack (64KB) */
    x86_mov_ri(b, RAX, SYS_mmap);
    x86_mov_ri(b, RDI, 0);
    x86_mov_ri(b, RSI, 65536);
    x86_mov_ri(b, RDX, MMAP_PROT_RW);
    x86_mov_ri(b, R10, MMAP_PRIVATE_ANON);
    x86_mov_ri(b, R8, (u64)-1);
    x86_mov_ri(b, R9, 0);
    emit_syscall(b);
    
    /* r8 = stack top (starts at end, grows down) */
    x86_mov_rr(b, R8, RAX);
    x86_add_ri(b, R8, 65536);
    /* r9 = stack base */
    x86_mov_rr(b, R9, RAX);
    
    /* Push root onto stack */
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, R14);
    
    /* Main loop: while stack not empty */
    u32 loop_start = x86_len(b);
    
    /* Check stack empty (r8 >= r9 + 65536) */
    x86_mov_rr(b, RAX, R9);
    x86_add_ri(b, RAX, 65536);
    x86_cmp_rr(b, R8, RAX);
    u32 loop_done_patch = x86_len(b) + 2;
    x86_jae_rel(b, 0);  /* stack empty -> done */
    
    /* Pop closure into rcx, save to r10 */
    x86_mov_rm(b, RCX, R8, 0);
    x86_add_ri(b, R8, 8);
    x86_mov_rr(b, R10, RCX);
    
    /* Get entry pointer to determine type */
    x86_mov_rm(b, RDX, RCX, 0);
    emit_follow_ind(b);
    
    /* Check for S */
    emit_get_entry(b, RAX, CLOS_S);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_s_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for K */
    emit_get_entry(b, RAX, CLOS_K);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_k_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for I */
    emit_get_entry(b, RAX, CLOS_I);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_i_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for S1[x] */
    emit_get_entry(b, RAX, CLOS_S1);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_s1_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for S2[x,y] */
    emit_get_entry(b, RAX, CLOS_S2);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_s2_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for K1[x] */
    emit_get_entry(b, RAX, CLOS_K1);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_k1_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for App[f,x] */
    emit_get_entry(b, RAX, CLOS_APP);
    x86_cmp_rr(b, RDX, RAX);
    u32 is_app_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Unknown type - trap */
    x86_int3(b);
    
    /* is_s: emit 11111000 */
    u32 is_s_target = x86_len(b);
    x86_patch_rel32(b, is_s_patch, is_s_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_k: emit 11100 */
    u32 is_k_target = x86_len(b);
    x86_patch_rel32(b, is_k_patch, is_k_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_i: I = SKK = 1 + 1 + S + K + K = 1 + 1 + 11111000 + 11100 + 11100 */
    u32 is_i_target = x86_len(b);
    x86_patch_rel32(b, is_i_patch, is_i_target);
    /* 1 (outer app) */
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    /* 1 (inner app) */
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    /* S = 11111000 */
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    /* K = 11100 */
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    /* K = 11100 */
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_s1: S1[x] = App(S, x), emit 1, push x, push S-singleton */
    u32 is_s1_target = x86_len(b);
    x86_patch_rel32(b, is_s1_patch, is_s1_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    /* Push x = [r10+8] */
    x86_mov_rm(b, RAX, R10, 8);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    /* Push S singleton */
    x86_lea(b, RAX, R15, DATA_PRIM_S);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_s2: S2[x,y] = App(App(S,x), y), emit 1, push y, then emit 1, S inline, push x */
    u32 is_s2_target = x86_len(b);
    x86_patch_rel32(b, is_s2_patch, is_s2_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    /* Push y = [r10+16] */
    x86_mov_rm(b, RAX, R10, 16);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    /* Push x */
    x86_mov_rm(b, RAX, R10, 8);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    /* Emit 1 for inner app, then S inline */
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    /* S = 11111000 */
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_mov_ri(b, RDI, 0); emit_output_bit_xor(b);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_k1: K1[x] = App(K, x), emit 1, push x, push K-singleton */
    u32 is_k1_target = x86_len(b);
    x86_patch_rel32(b, is_k1_patch, is_k1_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    x86_mov_rm(b, RAX, R10, 8);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    x86_lea(b, RAX, R15, DATA_PRIM_K);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* is_app: App[f,x], emit 1, push x, push f */
    u32 is_app_target = x86_len(b);
    x86_patch_rel32(b, is_app_patch, is_app_target);
    x86_mov_ri(b, RDI, 1); emit_output_bit_xor(b);
    /* Push x = [r10+16] first (will be popped second) */
    x86_mov_rm(b, RAX, R10, 16);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    /* Push f = [r10+8] (will be popped first) */
    x86_mov_rm(b, RAX, R10, 8);
    x86_sub_ri(b, R8, 8);
    x86_mov_mr(b, R8, 0, RAX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* loop_done: flush and exit */
    u32 loop_done_target = x86_len(b);
    x86_patch_rel32(b, loop_done_patch, loop_done_target);
    emit_flush_and_exit(b);
}

/*
 * Jot Output - calls shared impl with XOR=0
 */
static void emit_output_jot(NativeEmit *e) {
    emit_output_jot_impl(e);
}

/*
 * Jomplement Output - calls shared impl with XOR=1 (set at init time)
 */
static void emit_output_jomplement(NativeEmit *e) {
    emit_output_jot_impl(e);
}

/*
 * Emit output routine based on format and patch Halt jump
 */
static void emit_output(NativeEmit *e) {
    switch (e->output_fmt) {
        case OUTPUT_BCL:
            emit_output_bcl(e);
            break;
        case OUTPUT_JOT:
            emit_output_jot(e);
            break;
        case OUTPUT_JOMPLEMENT:
            emit_output_jomplement(e);
            break;
    }
    
    /* Patch Halt's jump to point to output routine */
    i32 rel = e->output_offset - (e->halt_output_patch + 4);
    memcpy(e->code.buf + e->halt_output_patch, &rel, 4);
}

/*
 * Emit the complete runtime
 */
void native_emit_runtime(NativeEmit *e) {
    /* Values */
    emit_entry_S(e);
    emit_entry_K(e);
    emit_entry_I(e);
    emit_entry_S1(e);
    emit_entry_S2(e);
    emit_entry_K1(e);
    /* Thunks and continuations */
    emit_entry_App(e);
    emit_entry_Ind(e);
    emit_entry_ApplyK(e);
    emit_entry_UpdK(e);
    emit_entry_Norm(e);
    emit_entry_Field1(e);
    emit_entry_Field2(e);
    emit_entry_IoV(e);
    emit_entry_IoH(e);
    emit_entry_IoN(e);
    emit_entry_Halt(e);
    emit_entry_Fwd(e);
    /* Collector (classify + copy_closure + gc) */
    emit_gc(e);
    /* Program entry */
    emit_start(e);
    /* Output serialization; patches Halt's jump */
    emit_output(e);
    /* Wire every reserve's `call gc` */
    for (int i = 0; i < e->n_gc_call; i++)
        x86_patch_rel32(&e->code, e->gc_call_patch[i], e->gc_offset);
}

/*
 * Get emitted code
 */
u8 *native_get_code(NativeEmit *e, u32 *size) {
    *size = x86_len(&e->code);
    return e->code.buf;
}

u32 native_get_entry(NativeEmit *e) {
    return e->start_offset;
}

/* ========================================================================
 * JIT EXECUTION
 * ======================================================================== */

static u32 calc_term_size(SKITerm *term);

/*
 * The growth ceiling of one semispace. -H sets the INITIAL size only: a
 * small initial heap (chosen to exercise the grow path) must not lower the
 * ceiling below what a default run gets, so the ceiling is 16x the larger
 * of the two.
 */
u64 native_max_space(u32 heap_size) {
    u64 m = (u64)heap_size * 16;
    u64 d = (u64)NATIVE_DEFAULT_HEAP_SIZE * 16;
    return m > d ? m : d;
}

NativeJIT *native_jit_prepare(NativeEmit *e, u32 heap_size) {
    NativeJIT *jit = calloc(1, sizeof(NativeJIT));
    if (!jit) return NULL;
    
    u32 code_size = x86_len(&e->code);
    
    /* Allocate executable memory for code */
    jit->code = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (jit->code == MAP_FAILED) {
        free(jit);
        return NULL;
    }
    memcpy(jit->code, e->code.buf, code_size);
    jit->code_size = code_size;
    
    /* Allocate data section */
    jit->data = calloc(1, DATA_SECTION_SIZE);
    if (!jit->data) {
        munmap(jit->code, code_size);
        free(jit);
        return NULL;
    }
    
    /* Allocate heaps */
    jit->heap_size = heap_size;
    jit->heap0 = mmap(NULL, heap_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    jit->heap1 = mmap(NULL, heap_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (jit->heap0 == MAP_FAILED || jit->heap1 == MAP_FAILED) {
        if (jit->heap0 != MAP_FAILED) munmap(jit->heap0, heap_size);
        if (jit->heap1 != MAP_FAILED) munmap(jit->heap1, heap_size);
        free(jit->data);
        munmap(jit->code, code_size);
        free(jit);
        return NULL;
    }
    
    /* Initialize data section */
    u64 *data = (u64*)jit->data;
    data[DATA_SPACE0 / 8] = (u64)jit->heap0;
    data[DATA_SPACE1 / 8] = (u64)jit->heap1;
    data[DATA_ACTIVE / 8] = 0;
    data[DATA_SPACE_SIZE / 8] = heap_size;
    data[DATA_SPACE0_SIZE / 8] = heap_size;
    data[DATA_SPACE1_SIZE / 8] = heap_size;
    data[DATA_NF_MODE / 8] = e->nf_mode ? 1 : 0;
    data[DATA_STATIC_BEGIN / 8] = 0;
    data[DATA_STATIC_END / 8] = 0;
    data[DATA_IO_MODE / 8] = e->io_mode ? 1 : 0;
    data[DATA_STATIC2_BEGIN / 8] = 0;
    data[DATA_STATIC2_END / 8] = 0;
    data[DATA_IOV / 8] = (u64)jit->code + e->entry_offsets[CLOS_IOV];
    data[DATA_KI / 8] = (u64)jit->code + e->entry_offsets[CLOS_K1];
    data[DATA_KI / 8 + 1] = (u64)jit->data + DATA_PRIM_I;
    data[DATA_HP / 8] = (u64)jit->heap0;
    data[DATA_LIMIT / 8] = (u64)jit->heap0 + heap_size;
    data[DATA_MAX_SPACE_SIZE / 8] = native_max_space(heap_size);
    data[DATA_ALLOC_REQUEST / 8] = 0;
    data[DATA_OUTPUT_XOR / 8] = (e->output_fmt == OUTPUT_JOMPLEMENT) ? 1 : 0;
    
    /* Set entry addresses in data section */
    for (int i = 0; i < CLOS_COUNT; i++) {
        data[(DATA_ENTRY_TABLE / 8) + i] = (u64)jit->code + e->entry_offsets[i];
    }
    
    /* Set up singleton closures in data section */
    /* These point to themselves (entry ptr = their own entry code) */
    u64 *prim_s = (u64*)((u8*)jit->data + DATA_PRIM_S);
    u64 *prim_k = (u64*)((u8*)jit->data + DATA_PRIM_K);
    u64 *prim_i = (u64*)((u8*)jit->data + DATA_PRIM_I);
    u64 *halt = (u64*)((u8*)jit->data + DATA_HALT);
    
    *prim_s = (u64)jit->code + e->entry_offsets[CLOS_S];
    *prim_k = (u64)jit->code + e->entry_offsets[CLOS_K];
    *prim_i = (u64)jit->code + e->entry_offsets[CLOS_I];
    *halt = (u64)jit->code + e->entry_offsets[CLOS_HALT];
    
    /* Store start offset for native_jit_run */
    jit->start_offset = e->start_offset;
    
    return jit;
}

void native_jit_free(NativeJIT *jit) {
    if (!jit) return;
    munmap(jit->code, jit->code_size);
    munmap(jit->heap0, jit->heap_size);
    munmap(jit->heap1, jit->heap_size);
    free(jit->data);
    free(jit);
}

/*
 * Build a term on the heap.
 *
 * Recursively converts SKITerm tree to native closures.
 * Returns pointer to root closure (absolute address).
 * Updates *hp_ptr to new heap position.
 *
 * S, K, I return pointers to singletons in data section.
 * App allocates a 3-word closure on heap.
 */
static u64 build_term_recursive(NativeJIT *jit, SKITerm *term, u8 **hp_ptr) {
    u64 *data = (u64*)jit->data;
    
    switch (term->tag) {
        case TERM_S:
            /* Return address of singleton S in data section */
            return (u64)((u8*)jit->data + DATA_PRIM_S);
            
        case TERM_K:
            return (u64)((u8*)jit->data + DATA_PRIM_K);
            
        case TERM_I:
            return (u64)((u8*)jit->data + DATA_PRIM_I);
            
        case TERM_APP: {
            /* Build children first (depth-first) */
            u64 f_ptr = build_term_recursive(jit, term->app.left, hp_ptr);
            u64 x_ptr = build_term_recursive(jit, term->app.right, hp_ptr);
            
            /* Allocate App[f, x] - 3 words */
            u64 *app = (u64*)*hp_ptr;
            *hp_ptr += 24;
            
            app[0] = data[(DATA_ENTRY_TABLE / 8) + CLOS_APP];
            app[1] = f_ptr;
            app[2] = x_ptr;
            
            return (u64)app;
        }
    }
    
    /* Fallback - shouldn't happen */
    return (u64)((u8*)jit->data + DATA_PRIM_I);
}

/*
 * Build term on heap and set up for execution.
 * Returns 0 on success, -1 on failure (e.g., term too large).
 */
/*
 * The heaps must hold the initial program before anything runs. Size them
 * to the term - a power of two with as much again to work in - remapping
 * the spaces native_jit_prepare made if they are too small.
 */
static int jit_size_heaps(NativeJIT *jit, u32 need) {
    u64 want = jit->heap_size;
    while (want < (u64)need * 2) want *= 2;
    if (want > 0xFFFFFFFFull) return -1;
    if (want == jit->heap_size) return 0;
    void *h0 = mmap(NULL, want, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *h1 = mmap(NULL, want, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (h0 == MAP_FAILED || h1 == MAP_FAILED) {
        if (h0 != MAP_FAILED) munmap(h0, want);
        if (h1 != MAP_FAILED) munmap(h1, want);
        return -1;
    }
    munmap(jit->heap0, jit->heap_size);
    munmap(jit->heap1, jit->heap_size);
    jit->heap0 = h0;
    jit->heap1 = h1;
    jit->heap_size = (u32)want;
    u64 *data = (u64*)jit->data;
    data[DATA_SPACE0 / 8] = (u64)h0;
    data[DATA_SPACE1 / 8] = (u64)h1;
    data[DATA_SPACE_SIZE / 8] = want;
    data[DATA_SPACE0_SIZE / 8] = want;
    data[DATA_SPACE1_SIZE / 8] = want;
    data[DATA_HP / 8] = (u64)h0;
    data[DATA_LIMIT / 8] = (u64)h0 + want;
    data[DATA_MAX_SPACE_SIZE / 8] = native_max_space((u32)want);
    return 0;
}

int native_jit_load_term(NativeJIT *jit, SKITerm *term) {
    /* Never write past the space: size it first, then build */
    u32 need = calc_term_size(term);
    if (jit_size_heaps(jit, need) != 0 || need > jit->heap_size) return -1;
    u8 *hp = (u8*)jit->heap0;
    u64 root = build_term_recursive(jit, term, &hp);
    
    /* Update heap pointer in data section */
    u64 *data = (u64*)jit->data;
    data[DATA_HP / 8] = (u64)hp;
    
    /* Store root as the initial term to evaluate */
    /* The start code will load this and enter it */
    data[DATA_ROOT / 8] = root;
    
    return 0;
}

/*
 * Execute JIT'd code.
 *
 * Forks a child process. Child sets up r15 and jumps into emitted code.
 * Emitted code writes output to stdout via syscall write, then exits.
 * Parent waits for child and returns exit status.
 *
 * This ensures JIT and ELF execute IDENTICAL code paths.
 */
int native_jit_run(NativeJIT *jit) {
    pid_t pid = fork();
    
    if (pid < 0) {
        /* Fork failed */
        return -1;
    }
    
    if (pid == 0) {
        /* Child process - jump into generated code */
        void *entry = (u8*)jit->code + jit->start_offset;
        void *data = jit->data;
        
        /*
         * Set up r15 = data section base, then jump to _start.
         * The generated code will:
         *   1. Run CPS evaluation
         *   2. Write output via syscall write
         *   3. syscall exit
         *
         * This never returns.
         */
        __asm__ volatile (
            "mov %0, %%r15\n\t"
            "jmp *%1\n\t"
            :
            : "r"(data), "r"(entry)
            : /* doesn't matter, we never return */
        );
        
        /* Should never reach here */
        _exit(127);
    }
    
    /* Parent process - wait for child */
    int status;
    waitpid(pid, &status, 0);
    
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    
    /* Child terminated abnormally */
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);   /* the shell convention, as the ELF would show */
    }
    return -1;
}

/* ========================================================================
 * ELF EMISSION
 * ======================================================================== */

/*
 * ELF64 header structures (matching Linux ABI)
 */
#define ELF_MAGIC       "\x7f""ELF"
#define ELFCLASS64      2
#define ELFDATA2LSB     1
#define EV_CURRENT      1
#define ELFOSABI_NONE   0
#define ET_EXEC         2
#define EM_X86_64       62
#define PT_LOAD         1
#define PF_X            1
#define PF_W            2
#define PF_R            4

typedef struct {
    u8  e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u64 e_entry;
    u64 e_phoff;
    u64 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    u32 p_type;
    u32 p_flags;
    u64 p_offset;
    u64 p_vaddr;
    u64 p_paddr;
    u64 p_filesz;
    u64 p_memsz;
    u64 p_align;
} Elf64_Phdr;

/*
 * Emit ELF startup code.
 * This runs before the regular _start:
 *   1. mmap two heap semispaces
 *   2. Initialize data section
 *   3. Jump to regular _start
 *
 * Returns offset of ELF entry point.
 */
static u32 emit_elf_start(NativeEmit *e, u32 heap_size) {
    X86Buf *b = &e->code;
    u32 entry = x86_len(b);
    
    /*
     * At ELF entry:
     *   - Stack is set up by kernel
     *   - No registers are meaningful
     *   - We need to set up everything
     *
     * Layout:
     *   Code section at 0x400000 (typical)
     *   Data section immediately after code in file, at known offset
     *   r15 will point to data section in memory
     *
     * We use RIP-relative addressing to find data section.
     */
    
    /* First, calculate where data section is (after code) */
    /* We'll use a lea with RIP-relative addressing */
    /* For now, we'll patch this after we know code size */
    
    /* lea r15, [rip + data_offset] -- placeholder, will patch */
    u32 lea_patch = x86_len(b);
    x86_byte(b, 0x4C);  /* REX.WR */
    x86_byte(b, 0x8D);  /* LEA */
    x86_byte(b, 0x3D);  /* r15, [rip+disp32] */
    x86_dword(b, 0);    /* placeholder for displacement */
    
    /* Save data base in a callee-saved register for now */
    /* r15 is our data base, will stay there */
    
    /* mmap heap0: mmap(NULL, heap_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0) */
    /* syscall args: rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=offset */
    x86_mov_ri(b, RAX, SYS_mmap);
    x86_mov_ri(b, RDI, 0);                    /* addr = NULL */
    x86_mov_ri(b, RSI, heap_size);            /* len */
    x86_mov_ri(b, RDX, MMAP_PROT_RW);         /* prot = RW */
    x86_mov_ri(b, R10, MMAP_PRIVATE_ANON);    /* flags */
    x86_mov_ri(b, R8, (u64)-1);               /* fd = -1 */
    x86_mov_ri(b, R9, 0);                     /* offset = 0 */
    emit_syscall(b);
    
    /* Store heap0 base in data section */
    x86_mov_mr(b, R15, DATA_SPACE0, RAX);
    /* Also set as initial HP */
    x86_mov_mr(b, R15, DATA_HP, RAX);
    /* Calculate and store limit */
    x86_add_ri(b, RAX, heap_size);
    x86_mov_mr(b, R15, DATA_LIMIT, RAX);
    
    /* mmap heap1 */
    x86_mov_ri(b, RAX, SYS_mmap);
    x86_mov_ri(b, RDI, 0);
    x86_mov_ri(b, RSI, heap_size);
    x86_mov_ri(b, RDX, MMAP_PROT_RW);
    x86_mov_ri(b, R10, MMAP_PRIVATE_ANON);
    x86_mov_ri(b, R8, (u64)-1);
    x86_mov_ri(b, R9, 0);
    emit_syscall(b);
    
    /* Store heap1 base */
    x86_mov_mr(b, R15, DATA_SPACE1, RAX);
    
    /* Initialize other data fields */
    x86_mov_ri(b, RAX, 0);
    x86_mov_mr(b, R15, DATA_ACTIVE, RAX);
    x86_mov_mr(b, R15, DATA_ALLOC_REQUEST, RAX);
    /* DATA_OUTPUT_XOR: 0 for BCL/Jot, 1 for Jomplement */
    x86_mov_ri(b, RAX, (e->output_fmt == OUTPUT_JOMPLEMENT) ? 1 : 0);
    x86_mov_mr(b, R15, DATA_OUTPUT_XOR, RAX);
    x86_mov_ri(b, RAX, heap_size);
    x86_mov_mr(b, R15, DATA_SPACE_SIZE, RAX);
    x86_mov_mr(b, R15, DATA_SPACE0_SIZE, RAX);
    x86_mov_mr(b, R15, DATA_SPACE1_SIZE, RAX);
    x86_mov_ri(b, RAX, e->nf_mode ? 1 : 0);
    x86_mov_mr(b, R15, DATA_NF_MODE, RAX);
    x86_mov_ri(b, RAX, e->io_mode ? 1 : 0);
    x86_mov_mr(b, R15, DATA_IO_MODE, RAX);
    x86_mov_ri(b, RAX, native_max_space(heap_size));
    x86_mov_mr(b, R15, DATA_MAX_SPACE_SIZE, RAX);
    
    /* Entry table is already in data section (baked in) */
    /* Singletons are already in data section (baked in) */
    
    /* Jump to regular _start */
    x86_jmp_rel(b, 0);  /* placeholder */
    u32 start_jmp_patch = x86_len(b) - 4;
    
    /* Store patch locations for later */
    e->elf_lea_patch = lea_patch + 3;  /* offset of the disp32 */
    e->elf_start_jmp_patch = start_jmp_patch;
    
    return entry;
}

/*
 * Calculate term size in bytes (for heap allocation).
 * S, K, I are singletons (0 bytes on heap).
 * App costs 24 bytes (3 words).
 */
static u32 calc_term_size(SKITerm *term) {
    switch (term->tag) {
        case TERM_S:
        case TERM_K:
        case TERM_I:
            return 0;  /* singletons, no heap allocation */
        case TERM_APP:
            return 24 + calc_term_size(term->app.left) + calc_term_size(term->app.right);
    }
    return 0;
}

/*
 * Build term for ELF embedding.
 *
 * Similar to build_term_recursive, but uses virtual addresses instead of
 * runtime pointers. The term is built into a buffer that will be embedded
 * in the ELF data section.
 *
 * Parameters:
 *   buf      - buffer to write term closures into
 *   buf_vaddr - virtual address where buf will be loaded at runtime
 *   hp       - current write position in buf (updated)
 *   code_vaddr - virtual address of code section (for entry pointers)
 *   data_vaddr - virtual address of data section (for singletons)
 *   entry_offsets - array of entry point offsets
 *
 * Returns virtual address of the built term.
 */
static u64 build_term_for_elf(SKITerm *term, u8 *buf, u64 buf_vaddr, u32 *hp,
                               u64 code_vaddr, u64 data_vaddr, u32 *entry_offsets) {
    switch (term->tag) {
        case TERM_S:
            return data_vaddr + DATA_PRIM_S;
        case TERM_K:
            return data_vaddr + DATA_PRIM_K;
        case TERM_I:
            return data_vaddr + DATA_PRIM_I;
        case TERM_APP: {
            /* Build children first */
            u64 f_vaddr = build_term_for_elf(term->app.left, buf, buf_vaddr, hp,
                                              code_vaddr, data_vaddr, entry_offsets);
            u64 x_vaddr = build_term_for_elf(term->app.right, buf, buf_vaddr, hp,
                                              code_vaddr, data_vaddr, entry_offsets);
            
            /* Allocate App closure */
            u32 offset = *hp;
            *hp += 24;
            
            u64 *app = (u64*)(buf + offset);
            app[0] = code_vaddr + entry_offsets[CLOS_APP];  /* entry pointer */
            app[1] = f_vaddr;
            app[2] = x_vaddr;
            
            return buf_vaddr + offset;
        }
    }
    return data_vaddr + DATA_PRIM_I;  /* fallback */
}

/*
 * Emit ELF executable.
 *
 * The ELF contains:
 *   - ELF header
 *   - Program header (one PT_LOAD segment)
 *   - Code (including ELF startup + runtime + GC)
 *   - Data section (pre-initialized with entry table, singletons, initial term)
 *
 * The initial term is embedded in the data section after the fixed fields.
 * At runtime, _start loads DATA_ROOT which points to the embedded term.
 *
 * Caller must free *out.
 */
void native_emit_elf(NativeEmit *e, u8 **out, u32 *out_size, SKITerm *term, u32 heap_size) {
    /*
     * Memory layout at runtime:
     *   0x400000: ELF header + phdr
     *   0x400000 + header_size: code
     *   0x400000 + header_size + code_size: data section (RW)
     *     - Fixed fields (entry table, heap pointers, singletons)
     *     - Embedded initial term
     *   Heap is mmap'd separately at runtime
     */
    
    const u64 base_addr = 0x400000;
    const u32 header_size = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
    
    /* Emit ELF startup code first (it needs to come before regular start) */
    u32 elf_entry_offset = emit_elf_start(e, heap_size);
    
    /* The regular runtime was already emitted by native_emit_runtime */
    /* We need to patch the ELF startup to jump to start_offset */
    
    u32 code_size = x86_len(&e->code);
    
    /* Patch the jump to _start */
    i32 start_rel = e->start_offset - (e->elf_start_jmp_patch + 4);
    memcpy(e->code.buf + e->elf_start_jmp_patch, &start_rel, 4);
    
    /* Calculate term size and total data section size */
    u32 term_size = calc_term_size(term);
    u32 data_size = DATA_SECTION_SIZE + term_size;
    /* Align to 8 bytes */
    data_size = (data_size + 7) & ~7;
    
    u8 *data = calloc(1, data_size);
    if (!data) {
        *out = NULL;
        *out_size = 0;
        return;
    }
    
    u64 code_vaddr = base_addr + header_size;
    u64 data_vaddr = code_vaddr + code_size;
    
    /* Patch the LEA r15 instruction to point to data section */
    /* LEA uses RIP-relative: disp = target - (rip after instruction) */
    /* RIP after LEA = code_vaddr + elf_lea_patch + 4 */
    i32 lea_disp = data_vaddr - (code_vaddr + e->elf_lea_patch + 4);
    memcpy(e->code.buf + e->elf_lea_patch, &lea_disp, 4);
    
    /* Fill in data section */
    u64 *d = (u64*)data;
    
    /* Entry addresses - these are code_vaddr + offset */
    for (int i = 0; i < CLOS_COUNT; i++) {
        d[(DATA_ENTRY_TABLE / 8) + i] = code_vaddr + e->entry_offsets[i];
    }
    
    /* Singletons - their entry ptr points to their entry code */
    u64 *prim_s = (u64*)(data + DATA_PRIM_S);
    u64 *prim_k = (u64*)(data + DATA_PRIM_K);
    u64 *prim_i = (u64*)(data + DATA_PRIM_I);
    u64 *halt = (u64*)(data + DATA_HALT);
    
    *prim_s = code_vaddr + e->entry_offsets[CLOS_S];
    *prim_k = code_vaddr + e->entry_offsets[CLOS_K];
    *prim_i = code_vaddr + e->entry_offsets[CLOS_I];
    *halt = code_vaddr + e->entry_offsets[CLOS_HALT];
    
    /* Build initial term in data section after fixed fields */
    u64 term_buf_vaddr = data_vaddr + DATA_SECTION_SIZE;
    u32 term_hp = 0;
    u64 root_vaddr = build_term_for_elf(term, data + DATA_SECTION_SIZE, term_buf_vaddr,
                                         &term_hp, code_vaddr, data_vaddr, e->entry_offsets);
    
    /* Set DATA_ROOT to point to the embedded term */
    d[DATA_ROOT / 8] = root_vaddr;
    d[DATA_STATIC_BEGIN / 8] = term_buf_vaddr;
    d[DATA_STATIC_END / 8] = term_buf_vaddr + term_hp;
    d[DATA_IOV / 8] = code_vaddr + e->entry_offsets[CLOS_IOV];
    d[DATA_KI / 8] = code_vaddr + e->entry_offsets[CLOS_K1];
    d[DATA_KI / 8 + 1] = data_vaddr + DATA_PRIM_I;
    
    /* Calculate total file size */
    u32 total_size = header_size + code_size + data_size;
    
    /* Allocate output buffer */
    u8 *elf = malloc(total_size);
    if (!elf) {
        free(data);
        *out = NULL;
        *out_size = 0;
        return;
    }
    
    /* Fill ELF header */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
    memset(ehdr, 0, sizeof(*ehdr));
    memcpy(ehdr->e_ident, ELF_MAGIC, 4);
    ehdr->e_ident[4] = ELFCLASS64;
    ehdr->e_ident[5] = ELFDATA2LSB;
    ehdr->e_ident[6] = EV_CURRENT;
    ehdr->e_ident[7] = ELFOSABI_NONE;
    ehdr->e_type = ET_EXEC;
    ehdr->e_machine = EM_X86_64;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_entry = code_vaddr + elf_entry_offset;
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_shoff = 0;  /* no section headers */
    ehdr->e_flags = 0;
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = 1;
    ehdr->e_shentsize = 0;
    ehdr->e_shnum = 0;
    ehdr->e_shstrndx = 0;
    
    /* Fill program header - single RWX segment for simplicity */
    Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + sizeof(Elf64_Ehdr));
    phdr->p_type = PT_LOAD;
    phdr->p_flags = PF_R | PF_W | PF_X;
    phdr->p_offset = 0;
    phdr->p_vaddr = base_addr;
    phdr->p_paddr = base_addr;
    phdr->p_filesz = total_size;
    phdr->p_memsz = total_size;
    phdr->p_align = 0x1000;
    
    /* Copy code */
    memcpy(elf + header_size, e->code.buf, code_size);
    
    /* Copy data */
    memcpy(elf + header_size + code_size, data, data_size);
    
    free(data);
    
    *out = elf;
    *out_size = total_size;
}
