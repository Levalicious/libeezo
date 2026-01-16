/*
 * native.c - Native code generation for CPS SKI
 *
 * Emits SELF-CONTAINED x86_64 code including:
 * - Combinator entry points (S, K, I, S1, S2, K1)
 * - Continuation types (App, ApplyK1, ApplyK2, Halt)
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
 * Emit: allocate n words on heap
 * Result (old hp) in RAX. Updates r12.
 * If allocation would overflow, stores request size and jumps to gc_needed label.
 * Caller must patch the gc_needed jump target.
 * Returns offset of the rel32 to patch.
 */
static u32 emit_alloc(X86Buf *b, int words) {
    int bytes = words * 8;
    
    /* rax = r12 (old hp, will be return value) */
    x86_mov_rr(b, RAX, R12);
    
    /* r12 += words * 8 */
    x86_add_ri(b, R12, bytes);
    
    /* if r12 >= r13, need GC */
    x86_cmp_rr(b, R12, R13);
    
    /* jb alloc_ok (skip GC path) */
    u32 ok_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x82); x86_dword(b, 0);
    
    /* GC needed - restore r12 and store allocation request */
    x86_mov_rr(b, R12, RAX);  /* restore hp */
    /* Store request size in DATA_ALLOC_REQUEST */
    x86_push(b, RCX);
    x86_mov_ri(b, RCX, bytes);
    emit_store_data(b, DATA_ALLOC_REQUEST, RCX);
    x86_pop(b, RCX);
    
    /* jmp gc_needed (patch later) */
    u32 patch_offset = x86_len(b) + 1;  /* after opcode byte */
    x86_jmp_rel(b, 0);  /* placeholder */
    
    /* alloc_ok: */
    u32 ok_target = x86_len(b);
    x86_patch_rel32(b, ok_patch, ok_target);
    
    return patch_offset;
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
 * Entry for App[f, x] - application node (NOT a value)
 * eval(App[f,x], k) = eval(f, ApplyK1[x, k])
 */
static void emit_entry_App(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_APP] = x86_len(b);
    
    /* Load f and x from self */
    /* rcx = f = [rdi + 8] */
    x86_mov_rm(b, RCX, RDI, 8);
    /* rdx = x = [rdi + 16] */
    x86_mov_rm(b, RDX, RDI, 16);
    
    /* Allocate ApplyK1[x, k] - 3 words */
    u32 gc_patch = emit_alloc(b, 3);
    
    /* rax = new closure address */
    /* [rax] = entry_ApplyK1 */
    emit_get_entry(b, RSI, CLOS_APPLYK1);
    x86_mov_mr(b, RAX, 0, RSI);
    /* [rax + 8] = x (rdx) */
    x86_mov_mr(b, RAX, 8, RDX);
    /* [rax + 16] = k (rbx) */
    x86_mov_mr(b, RAX, 16, RBX);
    
    /* New continuation is the ApplyK1 */
    x86_mov_rr(b, RBX, RAX);
    
    /* Enter f */
    x86_mov_rr(b, RDI, RCX);
    emit_enter(b);
    
    /* GC needed path - patch jump */
    u32 gc_target = x86_len(b);
    x86_patch_rel32(b, gc_patch, gc_target);
    
    /* Save state and call GC */
    emit_store_data(b, DATA_ROOT, RBX);
    /* Save rdi (self) and rcx, rdx for retry */
    x86_push(b, RDI);
    x86_push(b, RCX);
    x86_push(b, RDX);
    
    /* Jump to GC */
    x86_jmp_rel(b, 0);  /* Will patch to gc_offset */
    u32 gc_jmp_patch = x86_len(b) - 4;
    
    /* After GC, we need to retry - but this is complex.
     * For now, let's use a simpler approach: GC is a subroutine
     * that returns here. We'll emit a proper solution later.
     */
    (void)gc_jmp_patch;  /* TODO: proper GC integration */
}

/*
 * Entry for ApplyK1[x_term, k] - continuation waiting for f_val
 * Receives f_val in r14
 * Then: eval(x_term, ApplyK2[f_val, k])
 */
static void emit_entry_ApplyK1(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_APPLYK1] = x86_len(b);
    
    /* f_val in r14 */
    /* x_term = [rdi + 8] */
    x86_mov_rm(b, RCX, RDI, 8);
    /* k = [rdi + 16] */
    x86_mov_rm(b, RDX, RDI, 16);
    
    /* Allocate ApplyK2[f_val, k] - 3 words */
    u32 gc_patch = emit_alloc(b, 3);
    
    /* [rax] = entry_ApplyK2 */
    emit_get_entry(b, RSI, CLOS_APPLYK2);
    x86_mov_mr(b, RAX, 0, RSI);
    /* [rax + 8] = f_val (r14) */
    x86_mov_mr(b, RAX, 8, R14);
    /* [rax + 16] = k (rdx) */
    x86_mov_mr(b, RAX, 16, RDX);
    
    /* New continuation is ApplyK2 */
    x86_mov_rr(b, RBX, RAX);
    
    /* Enter x_term */
    x86_mov_rr(b, RDI, RCX);
    emit_enter(b);
    
    /* GC path */
    u32 gc_target = x86_len(b);
    x86_patch_rel32(b, gc_patch, gc_target);
    emit_store_data(b, DATA_ROOT, RBX);
    /* TODO: proper GC call */
    x86_int3(b);  /* trap for now */
}

/*
 * Entry for ApplyK2[f_val, k] - continuation waiting for x_val
 * Receives x_val in r14
 * Then: apply(f_val, x_val, k)
 */
static void emit_entry_ApplyK2(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->entry_offsets[CLOS_APPLYK2] = x86_len(b);
    
    /* x_val in r14 */
    /* f_val = [rdi + 8] */
    x86_mov_rm(b, RCX, RDI, 8);
    /* k = [rdi + 16] */
    x86_mov_rm(b, RDX, RDI, 16);
    
    /* Now dispatch on f_val type to do apply(f_val, x_val, k) */
    /* f_val entry ptr is [rcx] */
    x86_mov_rm(b, RSI, RCX, 0);
    
    /* Compare against each entry type */
    /* if f_val.entry == entry_S: apply_S */
    emit_get_entry(b, R8, CLOS_S);
    x86_cmp_rr(b, RSI, R8);
    u32 apply_s_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je apply_S */
    
    /* if f_val.entry == entry_K: apply_K */
    emit_get_entry(b, R8, CLOS_K);
    x86_cmp_rr(b, RSI, R8);
    u32 apply_k_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je apply_K */
    
    /* if f_val.entry == entry_I: apply_I */
    emit_get_entry(b, R8, CLOS_I);
    x86_cmp_rr(b, RSI, R8);
    u32 apply_i_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je apply_I */
    
    /* if f_val.entry == entry_S1: apply_S1 */
    emit_get_entry(b, R8, CLOS_S1);
    x86_cmp_rr(b, RSI, R8);
    u32 apply_s1_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je apply_S1 */
    
    /* if f_val.entry == entry_S2: apply_S2 */
    emit_get_entry(b, R8, CLOS_S2);
    x86_cmp_rr(b, RSI, R8);
    u32 apply_s2_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je apply_S2 */
    
    /* if f_val.entry == entry_K1: apply_K1 */
    emit_get_entry(b, R8, CLOS_K1);
    x86_cmp_rr(b, RSI, R8);
    u32 apply_k1_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je apply_K1 */
    
    /* Unknown - shouldn't happen, trap */
    x86_int3(b);
    
    /* apply_S: S x_val k -> k(S1[x_val]) */
    u32 apply_s_target = x86_len(b);
    x86_patch_rel32(b, apply_s_patch, apply_s_target);
    {
        /* Allocate S1[x_val] - 2 words */
        u32 gc_patch = emit_alloc(b, 2);
        emit_get_entry(b, RSI, CLOS_S1);
        x86_mov_mr(b, RAX, 0, RSI);
        x86_mov_mr(b, RAX, 8, R14);  /* x_val */
        /* k(S1) */
        x86_mov_rr(b, R14, RAX);
        x86_mov_rr(b, RBX, RDX);  /* k */
        emit_call_cont(b);
        /* GC path */
        x86_patch_rel32(b, gc_patch, x86_len(b));
        x86_int3(b);
    }
    
    /* apply_K: K x_val k -> k(K1[x_val]) */
    u32 apply_k_target = x86_len(b);
    x86_patch_rel32(b, apply_k_patch, apply_k_target);
    {
        u32 gc_patch = emit_alloc(b, 2);
        emit_get_entry(b, RSI, CLOS_K1);
        x86_mov_mr(b, RAX, 0, RSI);
        x86_mov_mr(b, RAX, 8, R14);
        x86_mov_rr(b, R14, RAX);
        x86_mov_rr(b, RBX, RDX);
        emit_call_cont(b);
        x86_patch_rel32(b, gc_patch, x86_len(b));
        x86_int3(b);
    }
    
    /* apply_I: I x_val k -> k(x_val) */
    u32 apply_i_target = x86_len(b);
    x86_patch_rel32(b, apply_i_patch, apply_i_target);
    {
        /* r14 already has x_val */
        x86_mov_rr(b, RBX, RDX);  /* k */
        emit_call_cont(b);
    }
    
    /* apply_S1: S1[a] x_val k -> k(S2[a, x_val]) */
    u32 apply_s1_target = x86_len(b);
    x86_patch_rel32(b, apply_s1_patch, apply_s1_target);
    {
        /* a = [rcx + 8] */
        x86_mov_rm(b, R8, RCX, 8);
        u32 gc_patch = emit_alloc(b, 3);
        emit_get_entry(b, RSI, CLOS_S2);
        x86_mov_mr(b, RAX, 0, RSI);
        x86_mov_mr(b, RAX, 8, R8);   /* a */
        x86_mov_mr(b, RAX, 16, R14); /* x_val */
        x86_mov_rr(b, R14, RAX);
        x86_mov_rr(b, RBX, RDX);
        emit_call_cont(b);
        x86_patch_rel32(b, gc_patch, x86_len(b));
        x86_int3(b);
    }
    
    /* apply_S2: S2[a,b] z k -> eval(App(App(a,z), App(b,z)), k) */
    u32 apply_s2_target = x86_len(b);
    x86_patch_rel32(b, apply_s2_patch, apply_s2_target);
    {
        /* a = [rcx + 8], b = [rcx + 16], z = r14 */
        x86_mov_rm(b, R8, RCX, 8);   /* a */
        x86_mov_rm(b, R9, RCX, 16);  /* b */
        /* z is in r14 */
        
        /* Need to build: App(App(a,z), App(b,z)) */
        /* That's 3 App nodes: App(a,z), App(b,z), App(first, second) */
        
        /* Allocate 3 * 3 = 9 words */
        u32 gc_patch = emit_alloc(b, 9);
        
        /* rax points to first of 3 consecutive App closures */
        /* App(a,z) at rax */
        emit_get_entry(b, RSI, CLOS_APP);
        x86_mov_mr(b, RAX, 0, RSI);
        x86_mov_mr(b, RAX, 8, R8);   /* a */
        x86_mov_mr(b, RAX, 16, R14); /* z */
        
        /* App(b,z) at rax+24 */
        x86_mov_mr(b, RAX, 24, RSI);
        x86_mov_mr(b, RAX, 32, R9);  /* b */
        x86_mov_mr(b, RAX, 40, R14); /* z */
        
        /* App(App(a,z), App(b,z)) at rax+48 */
        x86_mov_mr(b, RAX, 48, RSI);
        /* [rax+56] = rax (App(a,z)) */
        x86_mov_mr(b, RAX, 56, RAX);
        /* [rax+64] = rax+24 (App(b,z)) */
        x86_lea(b, R10, RAX, 24);
        x86_mov_mr(b, RAX, 64, R10);
        
        /* Enter the outer App with continuation k */
        x86_mov_rr(b, RBX, RDX);  /* k */
        x86_lea(b, RDI, RAX, 48);
        emit_enter(b);
        
        x86_patch_rel32(b, gc_patch, x86_len(b));
        x86_int3(b);
    }
    
    /* apply_K1: K1[a] x_val k -> k(a) */
    u32 apply_k1_target = x86_len(b);
    x86_patch_rel32(b, apply_k1_patch, apply_k1_target);
    {
        /* a = [rcx + 8] */
        x86_mov_rm(b, R14, RCX, 8);
        x86_mov_rr(b, RBX, RDX);
        emit_call_cont(b);
    }
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

static void emit_gc(NativeEmit *e) {
    X86Buf *b = &e->code;
    e->gc_offset = x86_len(b);
    
    /*
     * Cheney copying GC
     *
     * On entry: root saved in DATA_ROOT
     * 
     * Algorithm:
     *   1. Swap spaces
     *   2. Set hp = scan = tospace base
     *   3. Copy root
     *   4. While scan < hp: scavenge closure at scan, advance scan
     *   5. Update DATA_ROOT with new root location
     *   6. Return (caller retries allocation)
     */
    
    /* Save callee-saved registers we'll use */
    x86_push(b, RBX);
    x86_push(b, R12);
    x86_push(b, R13);
    x86_push(b, R14);
    x86_push(b, R15);
    
    /* r15 = data base (already set, but reload to be safe) */
    /* TODO: need to establish r15 if not already set */
    
    /* Swap active space: active = 1 - active */
    emit_load_data(b, RAX, DATA_ACTIVE);
    x86_mov_ri(b, RCX, 1);
    x86_sub_ri(b, RCX, 0);  /* This doesn't work - need xor */
    /* Actually: new_active = 1 ^ old_active */
    x86_byte(b, 0x48); x86_byte(b, 0x31); x86_byte(b, 0xC1);  /* xor rcx, rax (but we want 1 xor rax) */
    /* Let me redo this properly */
    
    /* rcx = 1 */
    x86_mov_ri(b, RCX, 1);
    /* rcx ^= rax (old active) */
    x86_byte(b, 0x48); x86_byte(b, 0x31); x86_byte(b, 0xC1);  /* xor rcx, rax */
    /* Now rcx = new active */
    emit_store_data(b, DATA_ACTIVE, RCX);
    
    /* Get tospace base: if new_active==0, tospace=space0, else space1 */
    /* r8 = space0, r9 = space1 */
    emit_load_data(b, R8, DATA_SPACE0);
    emit_load_data(b, R9, DATA_SPACE1);
    
    /* tospace = (new_active == 0) ? space0 : space1 */
    /* Use cmov: r10 = space0, then if rcx!=0, r10 = space1 */
    x86_mov_rr(b, R10, R8);
    x86_cmp_ri(b, RCX, 0);
    /* cmovne r10, r9 */
    x86_byte(b, 0x4D); x86_byte(b, 0x0F); x86_byte(b, 0x45); x86_byte(b, 0xD1);
    
    /* r10 = tospace base */
    /* Set hp = scan = tospace */
    x86_mov_rr(b, R12, R10);  /* hp */
    emit_store_data(b, DATA_HP, R12);
    emit_store_data(b, DATA_SCAN, R10);
    
    /* Set limit = tospace + space_size */
    emit_load_data(b, R13, DATA_SPACE_SIZE);
    x86_add_rr(b, R13, R10);
    emit_store_data(b, DATA_LIMIT, R13);
    
    /* Copy root */
    emit_load_data(b, RDI, DATA_ROOT);  /* rdi = root to copy */
    /* Call copy_closure subroutine */
    x86_call_rel(b, 0);  /* Will patch */
    u32 copy_root_patch = x86_len(b) - 4;
    /* rax = new root location */
    emit_store_data(b, DATA_ROOT, RAX);
    
    /* Cheney loop: while scan < hp */
    u32 loop_start = x86_len(b);
    emit_load_data(b, RCX, DATA_SCAN);
    x86_cmp_rr(b, RCX, R12);  /* scan vs hp */
    /* jae loop_done */
    u32 loop_done_patch = x86_len(b) + 2;
    x86_jae_rel(b, 0);
    
    /* Scavenge closure at scan */
    /* Get closure type from entry ptr */
    x86_mov_rm(b, RSI, RCX, 0);  /* entry ptr */
    
    /* For each pointer field, copy it */
    /* This is type-dependent. We need to check entry against each type. */
    /* For simplicity, let's handle the common cases inline */
    
    /* Check if it's S, K, I, or Halt (0 pointers) */
    emit_get_entry(b, R8, CLOS_S);
    x86_cmp_rr(b, RSI, R8);
    u32 skip_s = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je no_ptrs */
    
    emit_get_entry(b, R8, CLOS_K);
    x86_cmp_rr(b, RSI, R8);
    u32 skip_k = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_I);
    x86_cmp_rr(b, RSI, R8);
    u32 skip_i = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_HALT);
    x86_cmp_rr(b, RSI, R8);
    u32 skip_halt = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Check for 1-pointer types: S1, K1, FWD */
    emit_get_entry(b, R8, CLOS_S1);
    x86_cmp_rr(b, RSI, R8);
    u32 one_ptr_s1 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_K1);
    x86_cmp_rr(b, RSI, R8);
    u32 one_ptr_k1 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Everything else has 2 pointers */
    /* Copy [rcx+8] */
    x86_push(b, RCX);
    x86_mov_rm(b, RDI, RCX, 8);
    x86_call_rel(b, 0);
    u32 copy1_patch = x86_len(b) - 4;
    x86_pop(b, RCX);
    x86_mov_mr(b, RCX, 8, RAX);
    
    /* Copy [rcx+16] */
    x86_push(b, RCX);
    x86_mov_rm(b, RDI, RCX, 16);
    x86_call_rel(b, 0);
    u32 copy2_patch = x86_len(b) - 4;
    x86_pop(b, RCX);
    x86_mov_mr(b, RCX, 16, RAX);
    
    /* Advance scan by 3 words */
    x86_add_ri(b, RCX, 24);
    emit_store_data(b, DATA_SCAN, RCX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* 1-pointer path */
    u32 one_ptr_target = x86_len(b);
    x86_patch_rel32(b, one_ptr_s1, one_ptr_target);
    x86_patch_rel32(b, one_ptr_k1, one_ptr_target);
    
    x86_push(b, RCX);
    x86_mov_rm(b, RDI, RCX, 8);
    x86_call_rel(b, 0);
    u32 copy_one_patch = x86_len(b) - 4;
    x86_pop(b, RCX);
    x86_mov_mr(b, RCX, 8, RAX);
    
    x86_add_ri(b, RCX, 16);
    emit_store_data(b, DATA_SCAN, RCX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* No pointers path */
    u32 no_ptrs_target = x86_len(b);
    x86_patch_rel32(b, skip_s, no_ptrs_target);
    x86_patch_rel32(b, skip_k, no_ptrs_target);
    x86_patch_rel32(b, skip_i, no_ptrs_target);
    x86_patch_rel32(b, skip_halt, no_ptrs_target);
    
    x86_add_ri(b, RCX, 8);
    emit_store_data(b, DATA_SCAN, RCX);
    x86_jmp_rel(b, loop_start - (x86_len(b) + 5));
    
    /* Loop done */
    u32 loop_done_target = x86_len(b);
    x86_patch_rel32(b, loop_done_patch, loop_done_target);
    
    /*
     * GC complete. Check if we have enough space for pending allocation.
     * DATA_ALLOC_REQUEST holds the bytes requested when GC was triggered.
     * If hp + request > limit, need to grow heap.
     */
    emit_load_data(b, RAX, DATA_ALLOC_REQUEST);
    x86_add_rr(b, RAX, R12);  /* rax = hp + request */
    x86_cmp_rr(b, RAX, R13);  /* compare with limit */
    u32 space_ok_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x86); x86_dword(b, 0);  /* jbe space_ok */
    
    /*
     * Not enough space after GC - try to grow heap.
     * New size = current_size * 2 (double it)
     * Check against max_space_size
     */
    emit_load_data(b, RAX, DATA_SPACE_SIZE);
    x86_byte(b, 0x48); x86_byte(b, 0xD1); x86_byte(b, 0xE0);  /* shl rax, 1 (double) */
    
    emit_load_data(b, RCX, DATA_MAX_SPACE_SIZE);
    x86_cmp_rr(b, RAX, RCX);
    u32 can_grow_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x86); x86_dword(b, 0);  /* jbe can_grow */
    
    /* Can't grow - OOM. Exit with code 137 (128 + SIGKILL-ish) */
    x86_mov_ri(b, RAX, SYS_write);
    x86_mov_ri(b, RDI, 2);  /* stderr */
    /* We need an error message - use immediate bytes on stack */
    /* Push "OOM\n" backwards */
    x86_push(b, RAX);  /* make space */
    x86_mov_ri(b, RAX, 0x0A4D4F4F);  /* "OOM\n" little-endian */
    x86_mov_mr(b, RSP, 0, RAX);
    x86_mov_rr(b, RSI, RSP);
    x86_mov_ri(b, RDX, 4);
    x86_mov_ri(b, RAX, SYS_write);
    emit_syscall(b);
    x86_mov_ri(b, RAX, SYS_exit);
    x86_mov_ri(b, RDI, 137);
    emit_syscall(b);
    
    /* can_grow: rax = new_size, allocate new spaces via mremap */
    u32 can_grow_target = x86_len(b);
    x86_patch_rel32(b, can_grow_patch, can_grow_target);
    
    /* Save new size in r8 */
    x86_mov_rr(b, R8, RAX);
    
    /* mremap space0: mremap(old_addr, old_size, new_size, MREMAP_MAYMOVE) */
    emit_load_data(b, RDI, DATA_SPACE0);
    emit_load_data(b, RSI, DATA_SPACE_SIZE);
    x86_mov_rr(b, RDX, R8);  /* new size */
    x86_mov_ri(b, R10, 1);   /* MREMAP_MAYMOVE */
    x86_mov_ri(b, RAX, 25);  /* SYS_mremap */
    emit_syscall(b);
    
    /* Check for error (rax < 0 or MAP_FAILED) */
    x86_cmp_ri(b, RAX, 0);
    u32 mremap0_ok_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x8D); x86_dword(b, 0);  /* jge ok */
    /* mremap failed - treat as OOM */
    x86_mov_ri(b, RAX, SYS_exit);
    x86_mov_ri(b, RDI, 137);
    emit_syscall(b);
    
    u32 mremap0_ok_target = x86_len(b);
    x86_patch_rel32(b, mremap0_ok_patch, mremap0_ok_target);
    emit_store_data(b, DATA_SPACE0, RAX);
    
    /* mremap space1 */
    emit_load_data(b, RDI, DATA_SPACE1);
    emit_load_data(b, RSI, DATA_SPACE_SIZE);
    x86_mov_rr(b, RDX, R8);
    x86_mov_ri(b, R10, 1);
    x86_mov_ri(b, RAX, 25);
    emit_syscall(b);
    
    x86_cmp_ri(b, RAX, 0);
    u32 mremap1_ok_patch = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x8D); x86_dword(b, 0);
    x86_mov_ri(b, RAX, SYS_exit);
    x86_mov_ri(b, RDI, 137);
    emit_syscall(b);
    
    u32 mremap1_ok_target = x86_len(b);
    x86_patch_rel32(b, mremap1_ok_patch, mremap1_ok_target);
    emit_store_data(b, DATA_SPACE1, RAX);
    
    /* Update space_size */
    emit_store_data(b, DATA_SPACE_SIZE, R8);
    
    /* Update limit based on new active space */
    emit_load_data(b, RAX, DATA_ACTIVE);
    emit_load_data(b, RCX, DATA_SPACE0);
    emit_load_data(b, RDX, DATA_SPACE1);
    x86_cmp_ri(b, RAX, 0);
    x86_mov_rr(b, R13, RCX);  /* assume active=0, use space0 */
    /* cmovne r13, rdx */
    x86_byte(b, 0x4C); x86_byte(b, 0x0F); x86_byte(b, 0x45); x86_byte(b, 0xEA);
    x86_add_rr(b, R13, R8);  /* limit = base + new_size */
    emit_store_data(b, DATA_LIMIT, R13);
    
    /* space_ok: */
    u32 space_ok_target = x86_len(b);
    x86_patch_rel32(b, space_ok_patch, space_ok_target);
    
    /* Restore registers */
    x86_pop(b, R15);
    x86_pop(b, R14);
    x86_pop(b, R13);
    x86_pop(b, R12);
    x86_pop(b, RBX);
    
    /* Reload r12, r13 from data section */
    emit_load_data(b, R12, DATA_HP);
    emit_load_data(b, R13, DATA_LIMIT);
    
    x86_ret(b);
    
    /* Now emit copy_closure subroutine */
    e->gc_copy_offset = x86_len(b);
    
    /* Patch the calls to copy_closure */
    x86_patch_rel32(b, copy_root_patch, e->gc_copy_offset);
    x86_patch_rel32(b, copy1_patch, e->gc_copy_offset);
    x86_patch_rel32(b, copy2_patch, e->gc_copy_offset);
    x86_patch_rel32(b, copy_one_patch, e->gc_copy_offset);
    
    /*
     * copy_closure(rdi = from) -> rax = to
     * If from is NULL or not in fromspace, return from unchanged.
     * If from is forwarding ptr, return target.
     * Otherwise, copy to tospace, install forwarding ptr, return new addr.
     */
    
    /* Check NULL */
    x86_mov_rr(b, RAX, RDI);
    x86_cmp_ri(b, RDI, 0);
    u32 null_ret = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je return */
    
    /* Check if in fromspace */
    /* fromspace = (active==0) ? space1 : space0 (opposite of tospace) */
    emit_load_data(b, RAX, DATA_ACTIVE);
    emit_load_data(b, R8, DATA_SPACE0);
    emit_load_data(b, R9, DATA_SPACE1);
    /* fromspace = (active==0) ? space1 : space0 */
    x86_cmp_ri(b, RAX, 0);
    x86_mov_rr(b, R10, R9);  /* assume active==0, so from=space1 */
    /* cmovne r10, r8 */
    x86_byte(b, 0x4D); x86_byte(b, 0x0F); x86_byte(b, 0x45); x86_byte(b, 0xD0);
    
    /* Check: from_base <= rdi < from_base + space_size */
    x86_cmp_rr(b, RDI, R10);
    u32 not_in_from1 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x82); x86_dword(b, 0);  /* jb return (below fromspace) */
    
    emit_load_data(b, R11, DATA_SPACE_SIZE);
    x86_add_rr(b, R11, R10);  /* r11 = from_end */
    x86_cmp_rr(b, RDI, R11);
    u32 not_in_from2 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x83); x86_dword(b, 0);  /* jae return (above fromspace) */
    
    /* Check for forwarding pointer */
    x86_mov_rm(b, RSI, RDI, 0);  /* entry ptr */
    emit_get_entry(b, R8, CLOS_FWD);
    x86_cmp_rr(b, RSI, R8);
    u32 is_fwd = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);  /* je is_fwd */
    
    /* Not forwarded - need to copy */
    /* Determine size based on entry type */
    /* For now, use a simple approach: lookup in size table */
    /* size_table is at DATA_SIZE_TABLE, indexed by type */
    /* But we have entry ptr, not type. Need entry->type mapping. */
    /* Simpler: just check each entry and hardcode size */
    
    /* This is getting complex. Let's use a size lookup table. */
    /* Actually, let's just hardcode the checks */
    
    x86_mov_ri(b, RCX, 8);  /* default size = 1 word */
    
    emit_get_entry(b, R8, CLOS_S1);
    x86_cmp_rr(b, RSI, R8);
    u32 size_s1 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_K1);
    x86_cmp_rr(b, RSI, R8);
    u32 size_k1 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_S2);
    x86_cmp_rr(b, RSI, R8);
    u32 size_s2 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_APP);
    x86_cmp_rr(b, RSI, R8);
    u32 size_app = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_APPLYK1);
    x86_cmp_rr(b, RSI, R8);
    u32 size_ak1 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_APPLYK2);
    x86_cmp_rr(b, RSI, R8);
    u32 size_ak2 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    emit_get_entry(b, R8, CLOS_FWD);
    x86_cmp_rr(b, RSI, R8);
    u32 size_fwd = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x84); x86_dword(b, 0);
    
    /* Default: 1 word (S, K, I, Halt) */
    x86_mov_ri(b, RCX, 8);
    x86_jmp_rel(b, 0);
    u32 do_copy_jmp = x86_len(b) - 4;
    
    /* Size = 2 words */
    u32 size_2_target = x86_len(b);
    x86_patch_rel32(b, size_s1, size_2_target);
    x86_patch_rel32(b, size_k1, size_2_target);
    x86_patch_rel32(b, size_fwd, size_2_target);
    x86_mov_ri(b, RCX, 16);
    x86_jmp_rel(b, 0);
    u32 size_2_jmp = x86_len(b) - 4;
    
    /* Size = 3 words */
    u32 size_3_target = x86_len(b);
    x86_patch_rel32(b, size_s2, size_3_target);
    x86_patch_rel32(b, size_app, size_3_target);
    x86_patch_rel32(b, size_ak1, size_3_target);
    x86_patch_rel32(b, size_ak2, size_3_target);
    x86_mov_ri(b, RCX, 24);
    
    /* Do the copy - rcx = size in bytes, rdi = source */
    u32 do_copy_target = x86_len(b);
    x86_patch_rel32(b, do_copy_jmp, do_copy_target);
    x86_patch_rel32(b, size_2_jmp, do_copy_target);
    
    /* Save size in r11 (caller-saved, safe to use here) */
    x86_mov_rr(b, R11, RCX);
    
    /* rax = hp (destination, also return value) */
    x86_mov_rr(b, RAX, R12);
    
    /* Copy based on size: always copy word 0 */
    x86_mov_rm(b, RCX, RDI, 0);
    x86_mov_mr(b, RAX, 0, RCX);
    
    /* If size >= 16, copy word 1 */
    x86_cmp_ri(b, R11, 16);
    u32 skip_word1 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x82); x86_dword(b, 0);  /* jb skip */
    x86_mov_rm(b, RCX, RDI, 8);
    x86_mov_mr(b, RAX, 8, RCX);
    u32 skip_word1_target = x86_len(b);
    x86_patch_rel32(b, skip_word1, skip_word1_target);
    
    /* If size >= 24, copy word 2 */
    x86_cmp_ri(b, R11, 24);
    u32 skip_word2 = x86_len(b) + 2;
    x86_byte(b, 0x0F); x86_byte(b, 0x82); x86_dword(b, 0);  /* jb skip */
    x86_mov_rm(b, RCX, RDI, 16);
    x86_mov_mr(b, RAX, 16, RCX);
    u32 skip_word2_target = x86_len(b);
    x86_patch_rel32(b, skip_word2, skip_word2_target);
    
    /* Bump hp by actual size (r11) */
    x86_add_rr(b, R12, R11);
    emit_store_data(b, DATA_HP, R12);
    
    /* Install forwarding pointer in old location */
    emit_get_entry(b, RCX, CLOS_FWD);
    x86_mov_mr(b, RDI, 0, RCX);
    x86_mov_mr(b, RDI, 8, RAX);
    
    /* Return new address in rax */
    x86_ret(b);
    
    /* Is forwarding pointer - return target */
    u32 is_fwd_target = x86_len(b);
    x86_patch_rel32(b, is_fwd, is_fwd_target);
    x86_mov_rm(b, RAX, RDI, 8);
    x86_ret(b);
    
    /* Return unchanged (null or not in fromspace) */
    u32 return_target = x86_len(b);
    x86_patch_rel32(b, null_ret, return_target);
    x86_patch_rel32(b, not_in_from1, return_target);
    x86_patch_rel32(b, not_in_from2, return_target);
    x86_mov_rr(b, RAX, RDI);
    x86_ret(b);
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
    
    /* Set continuation to Halt singleton */
    x86_lea(b, RBX, R15, DATA_HALT);
    
    /* Load root term from DATA_ROOT and enter it */
    emit_load_data(b, RDI, DATA_ROOT);
    emit_enter(b);
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
    /* Emit all entry points */
    emit_entry_S(e);
    emit_entry_K(e);
    emit_entry_I(e);
    emit_entry_S1(e);
    emit_entry_S2(e);
    emit_entry_K1(e);
    emit_entry_App(e);
    emit_entry_ApplyK1(e);
    emit_entry_ApplyK2(e);
    emit_entry_Halt(e);
    emit_entry_Fwd(e);
    
    /* Emit GC */
    emit_gc(e);
    
    /* Emit start */
    emit_start(e);
    
    /* Emit output serialization and patch Halt */
    emit_output(e);
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
    data[DATA_HP / 8] = (u64)jit->heap0;
    data[DATA_LIMIT / 8] = (u64)jit->heap0 + heap_size;
    data[DATA_MAX_SPACE_SIZE / 8] = heap_size * 16;  /* Allow 16x growth */
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
int native_jit_load_term(NativeJIT *jit, SKITerm *term) {
    u8 *hp = (u8*)jit->heap0;
    u8 *limit = hp + jit->heap_size;
    
    /* Build the term */
    u64 root = build_term_recursive(jit, term, &hp);
    
    /* Check we didn't overflow */
    if (hp > limit) {
        return -1;
    }
    
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
    /* Max space size = heap_size * 16 (allow 16x growth) */
    x86_mov_ri(b, RAX, (u64)heap_size * 16);
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
