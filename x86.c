/*
 * x86.c - x86_64 instruction encoding
 *
 * Reference: Intel SDM Vol 2, AMD64 APM Vol 3
 *
 * x86_64 encoding basics:
 *   - REX prefix (0x40-0x4F) for 64-bit operands and extended registers
 *   - REX.W (bit 3): 64-bit operand size
 *   - REX.R (bit 2): extends ModRM.reg
 *   - REX.X (bit 1): extends SIB.index
 *   - REX.B (bit 0): extends ModRM.rm or SIB.base
 *   - ModRM byte: mod (2 bits) | reg (3 bits) | rm (3 bits)
 */

#include "x86.h"
#include <string.h>

void x86_init(X86Buf *b, u8 *buf, u32 cap) {
    b->buf = buf;
    b->cap = cap;
    b->len = 0;
}

u32 x86_len(X86Buf *b) {
    return b->len;
}

u8 *x86_ptr(X86Buf *b) {
    return b->buf + b->len;
}

/*
 * Raw byte emission
 */
void x86_byte(X86Buf *b, u8 v) {
    if (b->len < b->cap) {
        b->buf[b->len++] = v;
    }
}

void x86_word(X86Buf *b, u16 v) {
    x86_byte(b, v & 0xFF);
    x86_byte(b, (v >> 8) & 0xFF);
}

void x86_dword(X86Buf *b, u32 v) {
    x86_byte(b, v & 0xFF);
    x86_byte(b, (v >> 8) & 0xFF);
    x86_byte(b, (v >> 16) & 0xFF);
    x86_byte(b, (v >> 24) & 0xFF);
}

void x86_qword(X86Buf *b, u64 v) {
    x86_dword(b, v & 0xFFFFFFFF);
    x86_dword(b, (v >> 32) & 0xFFFFFFFF);
}

/*
 * REX prefix helpers
 */
static u8 rex(int w, int r, int x, int b_) {
    return 0x40 | (w << 3) | (r << 2) | (x << 1) | b_;
}

static int reg_ext(X86Reg r) {
    return (r >= R8) ? 1 : 0;
}

static int reg_lo(X86Reg r) {
    return r & 7;
}

/*
 * ModRM byte: mod=11 (register direct)
 */
static u8 modrm_rr(X86Reg reg, X86Reg rm) {
    return 0xC0 | (reg_lo(reg) << 3) | reg_lo(rm);
}

/*
 * ModRM byte with displacement
 */
static u8 modrm_disp(int mod, X86Reg reg, X86Reg rm) {
    return (mod << 6) | (reg_lo(reg) << 3) | reg_lo(rm);
}

/*
 * MOV r64, r64
 * REX.W + 89 /r (mov r/m64, r64) or 8B /r (mov r64, r/m64)
 */
void x86_mov_rr(X86Buf *b, X86Reg dst, X86Reg src) {
    x86_byte(b, rex(1, reg_ext(src), 0, reg_ext(dst)));
    x86_byte(b, 0x89);
    x86_byte(b, modrm_rr(src, dst));
}

/*
 * MOV r64, imm64
 * REX.W + B8+rd io
 */
void x86_mov_ri(X86Buf *b, X86Reg dst, u64 imm) {
    /* If imm fits in 32 bits and is positive, use shorter encoding */
    if (imm <= 0xFFFFFFFF) {
        /* MOV r32, imm32 (zero-extends to 64 bits) */
        if (reg_ext(dst)) {
            x86_byte(b, rex(0, 0, 0, 1));
        }
        x86_byte(b, 0xB8 + reg_lo(dst));
        x86_dword(b, (u32)imm);
    } else {
        /* Full 64-bit immediate */
        x86_byte(b, rex(1, 0, 0, reg_ext(dst)));
        x86_byte(b, 0xB8 + reg_lo(dst));
        x86_qword(b, imm);
    }
}

/*
 * MOV r64, [base+disp]
 * REX.W + 8B /r
 */
void x86_mov_rm(X86Buf *b, X86Reg dst, X86Reg base, i32 off) {
    x86_byte(b, rex(1, reg_ext(dst), 0, reg_ext(base)));
    x86_byte(b, 0x8B);
    
    /* Handle RSP/R12 specially - needs SIB byte */
    if (reg_lo(base) == 4) {
        if (off == 0) {
            x86_byte(b, modrm_disp(0, dst, base));
            x86_byte(b, 0x24);  /* SIB: scale=0, index=RSP (none), base=RSP */
        } else if (off >= -128 && off <= 127) {
            x86_byte(b, modrm_disp(1, dst, base));
            x86_byte(b, 0x24);
            x86_byte(b, (i8)off);
        } else {
            x86_byte(b, modrm_disp(2, dst, base));
            x86_byte(b, 0x24);
            x86_dword(b, off);
        }
    }
    /* Handle RBP/R13 specially - no disp8=0 encoding */
    else if (reg_lo(base) == 5 && off == 0) {
        x86_byte(b, modrm_disp(1, dst, base));
        x86_byte(b, 0);
    }
    else if (off == 0) {
        x86_byte(b, modrm_disp(0, dst, base));
    } else if (off >= -128 && off <= 127) {
        x86_byte(b, modrm_disp(1, dst, base));
        x86_byte(b, (i8)off);
    } else {
        x86_byte(b, modrm_disp(2, dst, base));
        x86_dword(b, off);
    }
}

/*
 * MOV [base+disp], r64
 * REX.W + 89 /r
 */
void x86_mov_mr(X86Buf *b, X86Reg base, i32 off, X86Reg src) {
    x86_byte(b, rex(1, reg_ext(src), 0, reg_ext(base)));
    x86_byte(b, 0x89);
    
    if (reg_lo(base) == 4) {
        if (off == 0) {
            x86_byte(b, modrm_disp(0, src, base));
            x86_byte(b, 0x24);
        } else if (off >= -128 && off <= 127) {
            x86_byte(b, modrm_disp(1, src, base));
            x86_byte(b, 0x24);
            x86_byte(b, (i8)off);
        } else {
            x86_byte(b, modrm_disp(2, src, base));
            x86_byte(b, 0x24);
            x86_dword(b, off);
        }
    }
    else if (reg_lo(base) == 5 && off == 0) {
        x86_byte(b, modrm_disp(1, src, base));
        x86_byte(b, 0);
    }
    else if (off == 0) {
        x86_byte(b, modrm_disp(0, src, base));
    } else if (off >= -128 && off <= 127) {
        x86_byte(b, modrm_disp(1, src, base));
        x86_byte(b, (i8)off);
    } else {
        x86_byte(b, modrm_disp(2, src, base));
        x86_dword(b, off);
    }
}

/*
 * MOV qword [base+disp], imm32 (sign-extended)
 * REX.W + C7 /0 id
 */
void x86_mov_mi(X86Buf *b, X86Reg base, i32 off, u32 imm) {
    x86_byte(b, rex(1, 0, 0, reg_ext(base)));
    x86_byte(b, 0xC7);
    
    X86Reg reg = RAX;  /* /0 in ModRM */
    
    if (reg_lo(base) == 4) {
        if (off == 0) {
            x86_byte(b, modrm_disp(0, reg, base));
            x86_byte(b, 0x24);
        } else if (off >= -128 && off <= 127) {
            x86_byte(b, modrm_disp(1, reg, base));
            x86_byte(b, 0x24);
            x86_byte(b, (i8)off);
        } else {
            x86_byte(b, modrm_disp(2, reg, base));
            x86_byte(b, 0x24);
            x86_dword(b, off);
        }
    }
    else if (reg_lo(base) == 5 && off == 0) {
        x86_byte(b, modrm_disp(1, reg, base));
        x86_byte(b, 0);
    }
    else if (off == 0) {
        x86_byte(b, modrm_disp(0, reg, base));
    } else if (off >= -128 && off <= 127) {
        x86_byte(b, modrm_disp(1, reg, base));
        x86_byte(b, (i8)off);
    } else {
        x86_byte(b, modrm_disp(2, reg, base));
        x86_dword(b, off);
    }
    
    x86_dword(b, imm);
}

/*
 * LEA r64, [base+disp]
 * REX.W + 8D /r
 */
void x86_lea(X86Buf *b, X86Reg dst, X86Reg base, i32 off) {
    x86_byte(b, rex(1, reg_ext(dst), 0, reg_ext(base)));
    x86_byte(b, 0x8D);
    
    if (reg_lo(base) == 4) {
        if (off >= -128 && off <= 127) {
            x86_byte(b, modrm_disp(1, dst, base));
            x86_byte(b, 0x24);
            x86_byte(b, (i8)off);
        } else {
            x86_byte(b, modrm_disp(2, dst, base));
            x86_byte(b, 0x24);
            x86_dword(b, off);
        }
    }
    else if (off >= -128 && off <= 127) {
        x86_byte(b, modrm_disp(1, dst, base));
        x86_byte(b, (i8)off);
    } else {
        x86_byte(b, modrm_disp(2, dst, base));
        x86_dword(b, off);
    }
}

/*
 * ADD r64, imm32
 * REX.W + 81 /0 id  or  REX.W + 83 /0 ib
 */
void x86_add_ri(X86Buf *b, X86Reg dst, i32 imm) {
    x86_byte(b, rex(1, 0, 0, reg_ext(dst)));
    if (imm >= -128 && imm <= 127) {
        x86_byte(b, 0x83);
        x86_byte(b, modrm_rr(RAX, dst));  /* /0 */
        x86_byte(b, (i8)imm);
    } else {
        x86_byte(b, 0x81);
        x86_byte(b, modrm_rr(RAX, dst));  /* /0 */
        x86_dword(b, imm);
    }
}

/*
 * ADD r64, r64
 * REX.W + 01 /r
 */
void x86_add_rr(X86Buf *b, X86Reg dst, X86Reg src) {
    x86_byte(b, rex(1, reg_ext(src), 0, reg_ext(dst)));
    x86_byte(b, 0x01);
    x86_byte(b, modrm_rr(src, dst));
}

/*
 * SUB r64, imm32
 * REX.W + 81 /5 id  or  REX.W + 83 /5 ib
 */
void x86_sub_ri(X86Buf *b, X86Reg dst, i32 imm) {
    x86_byte(b, rex(1, 0, 0, reg_ext(dst)));
    if (imm >= -128 && imm <= 127) {
        x86_byte(b, 0x83);
        x86_byte(b, modrm_rr(RBP, dst));  /* /5 = RBP */
        x86_byte(b, (i8)imm);
    } else {
        x86_byte(b, 0x81);
        x86_byte(b, modrm_rr(RBP, dst));  /* /5 = RBP */
        x86_dword(b, imm);
    }
}

/*
 * CMP r64, r64
 * REX.W + 39 /r
 */
void x86_cmp_rr(X86Buf *b, X86Reg a, X86Reg b_) {
    x86_byte(b, rex(1, reg_ext(b_), 0, reg_ext(a)));
    x86_byte(b, 0x39);
    x86_byte(b, modrm_rr(b_, a));
}

/*
 * CMP r64, imm32
 * REX.W + 81 /7 id  or  REX.W + 83 /7 ib
 */
void x86_cmp_ri(X86Buf *b, X86Reg a, i32 imm) {
    x86_byte(b, rex(1, 0, 0, reg_ext(a)));
    if (imm >= -128 && imm <= 127) {
        x86_byte(b, 0x83);
        x86_byte(b, modrm_rr(RDI, a));  /* /7 = RDI */
        x86_byte(b, (i8)imm);
    } else {
        x86_byte(b, 0x81);
        x86_byte(b, modrm_rr(RDI, a));  /* /7 = RDI */
        x86_dword(b, imm);
    }
}

/*
 * CMP r64, [base+off]
 * REX.W + 3B /r
 */
void x86_cmp_rm(X86Buf *b, X86Reg a, X86Reg base, i32 off) {
    x86_byte(b, rex(1, reg_ext(a), 0, reg_ext(base)));
    x86_byte(b, 0x3B);
    
    if (reg_lo(base) == 4) {
        if (off == 0) {
            x86_byte(b, modrm_disp(0, a, base));
            x86_byte(b, 0x24);
        } else if (off >= -128 && off <= 127) {
            x86_byte(b, modrm_disp(1, a, base));
            x86_byte(b, 0x24);
            x86_byte(b, (i8)off);
        } else {
            x86_byte(b, modrm_disp(2, a, base));
            x86_byte(b, 0x24);
            x86_dword(b, off);
        }
    }
    else if (reg_lo(base) == 5 && off == 0) {
        x86_byte(b, modrm_disp(1, a, base));
        x86_byte(b, 0);
    }
    else if (off == 0) {
        x86_byte(b, modrm_disp(0, a, base));
    } else if (off >= -128 && off <= 127) {
        x86_byte(b, modrm_disp(1, a, base));
        x86_byte(b, (i8)off);
    } else {
        x86_byte(b, modrm_disp(2, a, base));
        x86_dword(b, off);
    }
}

/*
 * JMP r64
 * FF /4
 */
void x86_jmp_r(X86Buf *b, X86Reg target) {
    if (reg_ext(target)) {
        x86_byte(b, rex(0, 0, 0, 1));
    }
    x86_byte(b, 0xFF);
    x86_byte(b, modrm_rr(RSP, target));  /* /4 = RSP */
}

/*
 * JMP [base+off]
 * FF /4
 */
void x86_jmp_m(X86Buf *b, X86Reg base, i32 off) {
    if (reg_ext(base)) {
        x86_byte(b, rex(0, 0, 0, 1));
    }
    x86_byte(b, 0xFF);
    
    X86Reg reg = RSP;  /* /4 */
    
    if (reg_lo(base) == 4) {
        if (off == 0) {
            x86_byte(b, modrm_disp(0, reg, base));
            x86_byte(b, 0x24);
        } else if (off >= -128 && off <= 127) {
            x86_byte(b, modrm_disp(1, reg, base));
            x86_byte(b, 0x24);
            x86_byte(b, (i8)off);
        } else {
            x86_byte(b, modrm_disp(2, reg, base));
            x86_byte(b, 0x24);
            x86_dword(b, off);
        }
    }
    else if (reg_lo(base) == 5 && off == 0) {
        x86_byte(b, modrm_disp(1, reg, base));
        x86_byte(b, 0);
    }
    else if (off == 0) {
        x86_byte(b, modrm_disp(0, reg, base));
    } else if (off >= -128 && off <= 127) {
        x86_byte(b, modrm_disp(1, reg, base));
        x86_byte(b, (i8)off);
    } else {
        x86_byte(b, modrm_disp(2, reg, base));
        x86_dword(b, off);
    }
}

/*
 * JMP rel32
 * E9 cd
 */
void x86_jmp_rel(X86Buf *b, i32 offset) {
    x86_byte(b, 0xE9);
    x86_dword(b, offset);
}

/*
 * JAE rel32 (unsigned >=)
 * 0F 83 cd
 */
void x86_jae_rel(X86Buf *b, i32 offset) {
    x86_byte(b, 0x0F);
    x86_byte(b, 0x83);
    x86_dword(b, offset);
}

/*
 * CALL r64
 * FF /2
 */
void x86_call_r(X86Buf *b, X86Reg target) {
    if (reg_ext(target)) {
        x86_byte(b, rex(0, 0, 0, 1));
    }
    x86_byte(b, 0xFF);
    x86_byte(b, modrm_rr(RDX, target));  /* /2 = RDX */
}

/*
 * CALL rel32
 * E8 cd
 */
void x86_call_rel(X86Buf *b, i32 offset) {
    x86_byte(b, 0xE8);
    x86_dword(b, offset);
}

/*
 * RET
 * C3
 */
void x86_ret(X86Buf *b) {
    x86_byte(b, 0xC3);
}

/*
 * PUSH r64
 * 50+rd (with REX.B if extended)
 */
void x86_push(X86Buf *b, X86Reg r) {
    if (reg_ext(r)) {
        x86_byte(b, rex(0, 0, 0, 1));
    }
    x86_byte(b, 0x50 + reg_lo(r));
}

/*
 * POP r64
 * 58+rd (with REX.B if extended)
 */
void x86_pop(X86Buf *b, X86Reg r) {
    if (reg_ext(r)) {
        x86_byte(b, rex(0, 0, 0, 1));
    }
    x86_byte(b, 0x58 + reg_lo(r));
}

/*
 * NOP
 * 90
 */
void x86_nop(X86Buf *b) {
    x86_byte(b, 0x90);
}

/*
 * INT3 (breakpoint)
 * CC
 */
void x86_int3(X86Buf *b) {
    x86_byte(b, 0xCC);
}

/*
 * Patch a rel32 at patch_offset to jump to target_offset
 * The rel32 is relative to the END of the instruction (patch_offset + 4)
 */
void x86_patch_rel32(X86Buf *b, u32 patch_offset, u32 target_offset) {
    i32 rel = (i32)target_offset - (i32)(patch_offset + 4);
    b->buf[patch_offset + 0] = rel & 0xFF;
    b->buf[patch_offset + 1] = (rel >> 8) & 0xFF;
    b->buf[patch_offset + 2] = (rel >> 16) & 0xFF;
    b->buf[patch_offset + 3] = (rel >> 24) & 0xFF;
}
