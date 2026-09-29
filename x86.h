/*
 * x86.h - x86_64 instruction encoding
 *
 * Low-level byte emission for x86_64 machine code.
 * Used by native.c to generate SKI combinator code.
 */
#ifndef EEZO_X86_H
#define EEZO_X86_H

#include "types.h"
#include "mem.h"

/*
 * Code buffer for emission: a growable Stack of the memory layer (mem.h). Offsets into it are u32 - the reach of the
 * rel32 jumps the code is made of - so it may not pass 2 GB (a resource abort, never a silent truncation).
 */
typedef struct { Stack bytes; } X86Buf;
#define X86_BUF(b) ((u8 *)(b)->bytes.p)

void x86_init(X86Buf *b);
void x86_drop(X86Buf *b);
u32  x86_len(X86Buf *b);

/*
 * Register encoding
 */
typedef enum {
    RAX = 0, RCX = 1, RDX = 2, RBX = 3,
    RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    R8  = 8, R9  = 9, R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
} X86Reg;

/*
 * Our register convention:
 *   rbx = current continuation (GC root)
 *   r12 = heap pointer
 *   r13 = heap limit
 *   r14 = temp / argument passing
 *   r15 = temp
 *   rdi = closure being entered (self)
 *   rax = scratch / return value
 */
#define REG_CONT    RBX
#define REG_HP      R12
#define REG_LIMIT   R13
#define REG_ARG     R14
#define REG_TMP     R15
#define REG_SELF    RDI

/*
 * Emit raw bytes
 */
void x86_byte(X86Buf *b, u8 v);
void x86_word(X86Buf *b, u16 v);
void x86_dword(X86Buf *b, u32 v);
void x86_qword(X86Buf *b, u64 v);

/*
 * MOV instructions
 */
void x86_mov_rr(X86Buf *b, X86Reg dst, X86Reg src);           /* mov dst, src */
void x86_mov_ri(X86Buf *b, X86Reg dst, u64 imm);              /* mov dst, imm64 */
void x86_mov_rm(X86Buf *b, X86Reg dst, X86Reg base, i32 off); /* mov dst, [base+off] */
void x86_mov_mr(X86Buf *b, X86Reg base, i32 off, X86Reg src); /* mov [base+off], src */
void x86_mov_mi(X86Buf *b, X86Reg base, i32 off, u32 imm);    /* mov qword [base+off], imm32 (sign-ext) */

/*
 * LEA instruction
 */
void x86_lea(X86Buf *b, X86Reg dst, X86Reg base, i32 off);    /* lea dst, [base+off] */

/*
 * Arithmetic
 */
void x86_add_ri(X86Buf *b, X86Reg dst, i32 imm);              /* add dst, imm */
void x86_add_rr(X86Buf *b, X86Reg dst, X86Reg src);           /* add dst, src */
void x86_sub_ri(X86Buf *b, X86Reg dst, i32 imm);              /* sub dst, imm */
void x86_cmp_rr(X86Buf *b, X86Reg a, X86Reg b_);              /* cmp a, b */
void x86_cmp_ri(X86Buf *b, X86Reg a, i32 imm);                /* cmp a, imm */
void x86_cmp_rm(X86Buf *b, X86Reg a, X86Reg base, i32 off);   /* cmp a, [base+off] */

/*
 * Jumps and calls
 */
void x86_jmp_r(X86Buf *b, X86Reg target);                     /* jmp target (register) */
void x86_jmp_m(X86Buf *b, X86Reg base, i32 off);              /* jmp [base+off] */
void x86_jmp_rel(X86Buf *b, i32 offset);                      /* jmp rel32 */
void x86_jae_rel(X86Buf *b, i32 offset);                      /* jae rel32 (unsigned >=) */
void x86_call_r(X86Buf *b, X86Reg target);                    /* call target */
void x86_call_rel(X86Buf *b, i32 offset);                     /* call rel32 */
void x86_ret(X86Buf *b);                                      /* ret */

/*
 * Stack operations (for C interop)
 */
void x86_push(X86Buf *b, X86Reg r);
void x86_pop(X86Buf *b, X86Reg r);

/*
 * Misc
 */
void x86_nop(X86Buf *b);
void x86_int3(X86Buf *b);                                     /* breakpoint */

/*
 * Patch a relative jump/call at a given offset
 * (used for forward references)
 */
void x86_patch_rel32(X86Buf *b, u32 patch_offset, u32 target_offset);

#endif /* EEZO_X86_H */
