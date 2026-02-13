/*
 * arm64_relocator.c - ARM64 Instruction Relocator Implementation
 *
 * Provides an API for relocating ARM64 instructions from one address to another,
 * handling PC-relative instructions that need adjustment.
 */

#include "arm64_relocator.h"
#include <string.h>

/* ============================================================================
 * Helper Macros and Functions
 * ============================================================================ */

#define GET_BITS(x, hi, lo) (((x) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))
#define SET_BITS(orig, hi, lo, v) \
    (((orig) & ~(((1u << ((hi) - (lo) + 1)) - 1) << (lo))) | \
     (((v) & ((1u << ((hi) - (lo) + 1)) - 1)) << (lo)))

static inline int64_t sign_extend(uint64_t value, int bits) {
    int shift = 64 - bits;
    return ((int64_t)(value << shift)) >> shift;
}

static inline int fits_signed(int64_t v, int bits) {
    int64_t min_val = -(1LL << (bits - 1));
    int64_t max_val = (1LL << (bits - 1)) - 1;
    return v >= min_val && v <= max_val;
}

/* ============================================================================
 * Initialization / Cleanup
 * ============================================================================ */

void arm64_relocator_init(Arm64Relocator* r, const void* input, uint64_t input_pc, Arm64Writer* output) {
    r->input_start = (const uint8_t*)input;
    r->input_cur = (const uint8_t*)input;
    r->input_pc = input_pc;
    r->output = output;
    r->current_insn = 0;
    memset(&r->current_info, 0, sizeof(r->current_info));
    r->eoi = 0;
    r->eob = 0;
}

void arm64_relocator_reset(Arm64Relocator* r, const void* input, uint64_t input_pc) {
    r->input_start = (const uint8_t*)input;
    r->input_cur = (const uint8_t*)input;
    r->input_pc = input_pc;
    r->current_insn = 0;
    memset(&r->current_info, 0, sizeof(r->current_info));
    r->eoi = 0;
    r->eob = 0;
}

void arm64_relocator_clear(Arm64Relocator* r) {
    /* No dynamic memory to free */
    (void)r;
}

/* ============================================================================
 * Instruction Analysis
 * ============================================================================ */

Arm64InsnInfo arm64_relocator_analyze_insn(uint64_t pc, uint32_t insn) {
    Arm64InsnInfo info;
    memset(&info, 0, sizeof(info));
    info.type = ARM64_INSN_OTHER;
    info.is_pc_relative = 0;

    /* B / BL: op0=00101 (B) or op0=10010 (BL)
     * Format: op 00101 imm26
     * B:  0 00101 imm26 (0x14000000)
     * BL: 1 00101 imm26 (0x94000000)
     */
    if ((insn & 0x7C000000) == 0x14000000) {
        info.is_pc_relative = 1;
        uint32_t imm26 = GET_BITS(insn, 25, 0);
        int64_t offset = sign_extend(imm26, 26) << 2;
        info.target = pc + offset;

        if (insn & 0x80000000) {
            info.type = ARM64_INSN_BL;
        } else {
            info.type = ARM64_INSN_B;
        }
        return info;
    }

    /* B.cond: 01010100 imm19 0 cond */
    if ((insn & 0xFF000010) == 0x54000000) {
        info.type = ARM64_INSN_B_COND;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.cond = (Arm64Cond)(insn & 0xF);
        return info;
    }

    /* CBZ / CBNZ: sf 011010 op imm19 Rt
     * CBZ:  sf 0110100 imm19 Rt (0x34000000)
     * CBNZ: sf 0110101 imm19 Rt (0x35000000)
     */
    if ((insn & 0x7E000000) == 0x34000000) {
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.reg = (Arm64Reg)(insn & 0x1F);
        if (insn & 0x80000000) {
            info.reg = (Arm64Reg)(info.reg); /* 64-bit */
        } else {
            info.reg = (Arm64Reg)(info.reg + 32); /* 32-bit W register */
        }

        if (insn & 0x01000000) {
            info.type = ARM64_INSN_CBNZ;
        } else {
            info.type = ARM64_INSN_CBZ;
        }
        return info;
    }

    /* TBZ / TBNZ: b5 011011 op b40 imm14 Rt
     * TBZ:  b5 0110110 b40 imm14 Rt (0x36000000)
     * TBNZ: b5 0110111 b40 imm14 Rt (0x37000000)
     */
    if ((insn & 0x7E000000) == 0x36000000) {
        info.is_pc_relative = 1;
        uint32_t imm14 = GET_BITS(insn, 18, 5);
        int64_t offset = sign_extend(imm14, 14) << 2;
        info.target = pc + offset;
        info.reg = (Arm64Reg)(insn & 0x1F);
        info.bit = (GET_BITS(insn, 31, 31) << 5) | GET_BITS(insn, 23, 19);

        if (insn & 0x01000000) {
            info.type = ARM64_INSN_TBNZ;
        } else {
            info.type = ARM64_INSN_TBZ;
        }
        return info;
    }

    /* ADR: 0 immlo 10000 immhi Rd */
    if ((insn & 0x9F000000) == 0x10000000) {
        info.type = ARM64_INSN_ADR;
        info.is_pc_relative = 1;
        uint32_t immlo = GET_BITS(insn, 30, 29);
        uint32_t immhi = GET_BITS(insn, 23, 5);
        uint32_t imm21 = (immhi << 2) | immlo;
        int64_t offset = sign_extend(imm21, 21);
        info.target = pc + offset;
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        return info;
    }

    /* ADRP: 1 immlo 10000 immhi Rd */
    if ((insn & 0x9F000000) == 0x90000000) {
        info.type = ARM64_INSN_ADRP;
        info.is_pc_relative = 1;
        uint32_t immlo = GET_BITS(insn, 30, 29);
        uint32_t immhi = GET_BITS(insn, 23, 5);
        uint32_t imm21 = (immhi << 2) | immlo;
        int64_t offset_pages = sign_extend(imm21, 21);
        info.target = (pc & ~0xFFFULL) + (offset_pages << 12);
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        return info;
    }

    /* LDR literal (GPR): opc 011 0 00 imm19 Rt
     * opc=00: 32-bit (0x18000000)
     * opc=01: 64-bit (0x58000000)
     */
    if ((insn & 0xBF000000) == 0x18000000) {
        info.type = ARM64_INSN_LDR_LITERAL;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        info.is_signed = 0;
        return info;
    }

    /* LDRSW literal: 10 011 0 00 imm19 Rt (0x98000000) */
    if ((insn & 0xFF000000) == 0x98000000) {
        info.type = ARM64_INSN_LDRSW_LITERAL;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        info.is_signed = 1;
        return info;
    }

    /* LDR literal (FP/SIMD): opc 011 1 00 imm19 Rt
     * opc=00: 32-bit S register (0x1C000000)
     * opc=01: 64-bit D register (0x5C000000)
     * opc=10: 128-bit Q register (0x9C000000)
     */
    if ((insn & 0x3F000000) == 0x1C000000) {
        info.type = ARM64_INSN_LDR_LITERAL_FP;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        info.dst_reg = (Arm64Reg)(insn & 0x1F);
        uint32_t opc = GET_BITS(insn, 31, 30);
        info.fp_size = (opc == 0) ? 4 : (opc == 1) ? 8 : 16;
        return info;
    }

    /* PRFM literal: 11 011 0 00 imm19 Rt (0xD8000000) */
    if ((insn & 0xFF000000) == 0xD8000000) {
        info.type = ARM64_INSN_PRFM_LITERAL;
        info.is_pc_relative = 1;
        uint32_t imm19 = GET_BITS(insn, 23, 5);
        int64_t offset = sign_extend(imm19, 19) << 2;
        info.target = pc + offset;
        return info;
    }

    /* BR: 1101011 0000 11111 000000 Rn 00000 (0xD61F0000) */
    if ((insn & 0xFFFFFC1F) == 0xD61F0000) {
        info.type = ARM64_INSN_BR;
        info.reg = (Arm64Reg)GET_BITS(insn, 9, 5);
        return info;
    }

    /* BLR: 1101011 0001 11111 000000 Rn 00000 (0xD63F0000) */
    if ((insn & 0xFFFFFC1F) == 0xD63F0000) {
        info.type = ARM64_INSN_BLR;
        info.reg = (Arm64Reg)GET_BITS(insn, 9, 5);
        return info;
    }

    /* RET: 1101011 0010 11111 000000 Rn 00000 (0xD65F0000) */
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        info.type = ARM64_INSN_RET;
        info.reg = (Arm64Reg)GET_BITS(insn, 9, 5);
        return info;
    }

    return info;
}

/* ============================================================================
 * Reading Instructions
 * ============================================================================ */

int arm64_relocator_read_one(Arm64Relocator* r) {
    if (r->eoi) return 0;

    r->current_insn = *(const uint32_t*)r->input_cur;
    uint64_t current_pc = r->input_pc + (uint64_t)(r->input_cur - r->input_start);
    r->current_info = arm64_relocator_analyze_insn(current_pc, r->current_insn);

    r->input_cur += 4;

    /* Check for end-of-block (unconditional branch without link) */
    if (r->current_info.type == ARM64_INSN_B ||
        r->current_info.type == ARM64_INSN_BR ||
        r->current_info.type == ARM64_INSN_RET) {
        r->eob = 1;
    }

    return 4;
}

/* ============================================================================
 * Instruction Relocation
 * ============================================================================ */

/* Try to relocate B/BL */
static Arm64RelocResult try_relocate_b_bl(uint64_t src_pc, uint64_t dst_pc,
                                           uint32_t insn, uint32_t* out) {
    if ((insn & 0x7C000000) != 0x14000000) {
        return ARM64_RELOC_ERROR; /* Not a B/BL */
    }

    uint32_t imm26 = GET_BITS(insn, 25, 0);
    int64_t offset = sign_extend(imm26, 26) << 2;
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if ((new_offset & 0x3) != 0) return ARM64_RELOC_OUT_OF_RANGE;
    int64_t new_imm26 = new_offset >> 2;
    if (!fits_signed(new_imm26, 26)) return ARM64_RELOC_OUT_OF_RANGE;

    *out = SET_BITS(insn, 25, 0, (uint32_t)new_imm26 & 0x03FFFFFF);
    return ARM64_RELOC_OK;
}

/* Try to relocate B.cond */
static Arm64RelocResult try_relocate_b_cond(uint64_t src_pc, uint64_t dst_pc,
                                             uint32_t insn, uint32_t* out) {
    if ((insn & 0xFF000010) != 0x54000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t imm19 = GET_BITS(insn, 23, 5);
    int64_t offset = sign_extend(imm19, 19) << 2;
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if ((new_offset & 0x3) != 0) return ARM64_RELOC_OUT_OF_RANGE;
    int64_t new_imm19 = new_offset >> 2;
    if (!fits_signed(new_imm19, 19)) return ARM64_RELOC_OUT_OF_RANGE;

    *out = SET_BITS(insn, 23, 5, (uint32_t)new_imm19 & 0x7FFFF);
    return ARM64_RELOC_OK;
}

/* Try to relocate CBZ/CBNZ */
static Arm64RelocResult try_relocate_cbz_cbnz(uint64_t src_pc, uint64_t dst_pc,
                                               uint32_t insn, uint32_t* out) {
    if ((insn & 0x7E000000) != 0x34000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t imm19 = GET_BITS(insn, 23, 5);
    int64_t offset = sign_extend(imm19, 19) << 2;
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if ((new_offset & 0x3) != 0) return ARM64_RELOC_OUT_OF_RANGE;
    int64_t new_imm19 = new_offset >> 2;
    if (!fits_signed(new_imm19, 19)) return ARM64_RELOC_OUT_OF_RANGE;

    *out = SET_BITS(insn, 23, 5, (uint32_t)new_imm19 & 0x7FFFF);
    return ARM64_RELOC_OK;
}

/* Try to relocate TBZ/TBNZ */
static Arm64RelocResult try_relocate_tbz_tbnz(uint64_t src_pc, uint64_t dst_pc,
                                               uint32_t insn, uint32_t* out) {
    if ((insn & 0x7E000000) != 0x36000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t imm14 = GET_BITS(insn, 18, 5);
    int64_t offset = sign_extend(imm14, 14) << 2;
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if ((new_offset & 0x3) != 0) return ARM64_RELOC_OUT_OF_RANGE;
    int64_t new_imm14 = new_offset >> 2;
    if (!fits_signed(new_imm14, 14)) return ARM64_RELOC_OUT_OF_RANGE;

    *out = SET_BITS(insn, 18, 5, (uint32_t)new_imm14 & 0x3FFF);
    return ARM64_RELOC_OK;
}

/* Try to relocate ADR */
static Arm64RelocResult try_relocate_adr(uint64_t src_pc, uint64_t dst_pc,
                                          uint32_t insn, uint32_t* out) {
    if ((insn & 0x9F000000) != 0x10000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t immlo = GET_BITS(insn, 30, 29);
    uint32_t immhi = GET_BITS(insn, 23, 5);
    uint32_t imm21 = (immhi << 2) | immlo;
    int64_t offset = sign_extend(imm21, 21);
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if (!fits_signed(new_offset, 21)) return ARM64_RELOC_OUT_OF_RANGE;

    uint32_t u = (uint32_t)new_offset;
    uint32_t new_immlo = u & 0x3;
    uint32_t new_immhi = (u >> 2) & 0x7FFFF;

    *out = SET_BITS(SET_BITS(insn, 30, 29, new_immlo), 23, 5, new_immhi);
    return ARM64_RELOC_OK;
}

/* Try to relocate ADRP */
static Arm64RelocResult try_relocate_adrp(uint64_t src_pc, uint64_t dst_pc,
                                           uint32_t insn, uint32_t* out) {
    if ((insn & 0x9F000000) != 0x90000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t immlo = GET_BITS(insn, 30, 29);
    uint32_t immhi = GET_BITS(insn, 23, 5);
    uint32_t imm21 = (immhi << 2) | immlo;
    int64_t offset_pages = sign_extend(imm21, 21);

    int64_t src_page = (int64_t)src_pc & ~0xFFFLL;
    int64_t target = src_page + (offset_pages << 12);

    int64_t dst_page = (int64_t)dst_pc & ~0xFFFLL;
    int64_t new_offset_pages = (target - dst_page) >> 12;

    if (!fits_signed(new_offset_pages, 21)) return ARM64_RELOC_OUT_OF_RANGE;

    uint32_t u = (uint32_t)new_offset_pages;
    uint32_t new_immlo = u & 0x3;
    uint32_t new_immhi = (u >> 2) & 0x7FFFF;

    *out = SET_BITS(SET_BITS(insn, 30, 29, new_immlo), 23, 5, new_immhi);
    return ARM64_RELOC_OK;
}

/* Try to relocate LDR literal (GPR) / LDRSW literal */
static Arm64RelocResult try_relocate_ldr_literal(uint64_t src_pc, uint64_t dst_pc,
                                                  uint32_t insn, uint32_t* out) {
    int is_gpr = (insn & 0xBF000000) == 0x18000000;
    int is_ldrsw = (insn & 0xFF000000) == 0x98000000;
    if (!is_gpr && !is_ldrsw) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t imm19 = GET_BITS(insn, 23, 5);
    int64_t offset = sign_extend(imm19, 19) << 2;
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if ((new_offset & 0x3) != 0) return ARM64_RELOC_OUT_OF_RANGE;
    int64_t new_imm19 = new_offset >> 2;
    if (!fits_signed(new_imm19, 19)) return ARM64_RELOC_OUT_OF_RANGE;

    *out = SET_BITS(insn, 23, 5, (uint32_t)new_imm19 & 0x7FFFF);
    return ARM64_RELOC_OK;
}

/* Try to relocate LDR literal (FP/SIMD) */
static Arm64RelocResult try_relocate_ldr_literal_fp(uint64_t src_pc, uint64_t dst_pc,
                                                     uint32_t insn, uint32_t* out) {
    if ((insn & 0x3F000000) != 0x1C000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t imm19 = GET_BITS(insn, 23, 5);
    int64_t offset = sign_extend(imm19, 19) << 2;
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if ((new_offset & 0x3) != 0) return ARM64_RELOC_OUT_OF_RANGE;
    int64_t new_imm19 = new_offset >> 2;
    if (!fits_signed(new_imm19, 19)) return ARM64_RELOC_OUT_OF_RANGE;

    *out = SET_BITS(insn, 23, 5, (uint32_t)new_imm19 & 0x7FFFF);
    return ARM64_RELOC_OK;
}

/* Try to relocate PRFM literal */
static Arm64RelocResult try_relocate_prfm_literal(uint64_t src_pc, uint64_t dst_pc,
                                                   uint32_t insn, uint32_t* out) {
    if ((insn & 0xFF000000) != 0xD8000000) {
        return ARM64_RELOC_ERROR;
    }

    uint32_t imm19 = GET_BITS(insn, 23, 5);
    int64_t offset = sign_extend(imm19, 19) << 2;
    int64_t target = (int64_t)src_pc + offset;
    int64_t new_offset = target - (int64_t)dst_pc;

    if ((new_offset & 0x3) != 0) return ARM64_RELOC_OUT_OF_RANGE;
    int64_t new_imm19 = new_offset >> 2;
    if (!fits_signed(new_imm19, 19)) return ARM64_RELOC_OUT_OF_RANGE;

    *out = SET_BITS(insn, 23, 5, (uint32_t)new_imm19 & 0x7FFFF);
    return ARM64_RELOC_OK;
}

Arm64RelocResult arm64_relocator_relocate_insn(uint64_t src_pc, uint64_t dst_pc,
                                                uint32_t insn, uint32_t* out) {
    Arm64RelocResult result;

    /* Try each PC-relative instruction type */
    result = try_relocate_b_bl(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_b_cond(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_cbz_cbnz(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_tbz_tbnz(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_adr(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_adrp(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_ldr_literal(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_ldr_literal_fp(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    result = try_relocate_prfm_literal(src_pc, dst_pc, insn, out);
    if (result != ARM64_RELOC_ERROR) return result;

    /* Not a PC-relative instruction, copy as-is */
    *out = insn;
    return ARM64_RELOC_OK;
}

/* ============================================================================
 * Writing Instructions
 * ============================================================================ */

Arm64RelocResult arm64_relocator_write_one(Arm64Relocator* r) {
    uint64_t src_pc = r->input_pc + (uint64_t)(r->input_cur - r->input_start - 4);
    uint64_t dst_pc = arm64_writer_pc(r->output);

    if (!r->current_info.is_pc_relative) {
        /* Non-PC-relative instruction, just copy it */
        arm64_writer_put_insn(r->output, r->current_insn);
        return ARM64_RELOC_OK;
    }

    /* Try direct relocation first */
    uint32_t relocated_insn;
    Arm64RelocResult result = arm64_relocator_relocate_insn(
        src_pc, dst_pc, r->current_insn, &relocated_insn);

    if (result == ARM64_RELOC_OK) {
        arm64_writer_put_insn(r->output, relocated_insn);
        return ARM64_RELOC_OK;
    }

    /* Direct relocation failed, need to generate multi-instruction sequence */
    switch (r->current_info.type) {
        case ARM64_INSN_B:
        case ARM64_INSN_BL: {
            /* Generate: LDR X16, [PC, #8]; BR/BLR X16; .quad target */
            if (r->current_info.type == ARM64_INSN_BL) {
                arm64_writer_put_call_address(r->output, r->current_info.target);
            } else {
                arm64_writer_put_branch_address(r->output, r->current_info.target);
            }
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_B_COND: {
            /* Generate: B.!cond skip; LDR X16, [PC, #8]; BR X16; .quad target; skip: */
            uint64_t skip_label = arm64_writer_new_label_id(r->output);
            Arm64Cond inv_cond = (Arm64Cond)(r->current_info.cond ^ 1); /* Invert condition */
            arm64_writer_put_b_cond_label(r->output, inv_cond, skip_label);
            arm64_writer_put_branch_address(r->output, r->current_info.target);
            arm64_writer_put_label(r->output, skip_label);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_CBZ:
        case ARM64_INSN_CBNZ: {
            /* Generate: CB(N)Z reg, skip_near; B far_target; skip_near: */
            /* Or if even that's not enough: CBZ reg, +8; B skip; LDR X16; BR X16; skip: */
            uint64_t skip_label = arm64_writer_new_label_id(r->output);

            /* Invert the condition */
            if (r->current_info.type == ARM64_INSN_CBZ) {
                arm64_writer_put_cbnz_reg_label(r->output, r->current_info.reg, skip_label);
            } else {
                arm64_writer_put_cbz_reg_label(r->output, r->current_info.reg, skip_label);
            }
            arm64_writer_put_branch_address(r->output, r->current_info.target);
            arm64_writer_put_label(r->output, skip_label);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_TBZ:
        case ARM64_INSN_TBNZ: {
            /* Similar to CBZ/CBNZ */
            uint64_t skip_label = arm64_writer_new_label_id(r->output);

            if (r->current_info.type == ARM64_INSN_TBZ) {
                arm64_writer_put_tbnz_reg_imm_label(r->output, r->current_info.reg,
                                                     r->current_info.bit, skip_label);
            } else {
                arm64_writer_put_tbz_reg_imm_label(r->output, r->current_info.reg,
                                                    r->current_info.bit, skip_label);
            }
            arm64_writer_put_branch_address(r->output, r->current_info.target);
            arm64_writer_put_label(r->output, skip_label);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_ADR: {
            /* Generate: MOVZ/MOVK sequence to load target address */
            arm64_writer_put_mov_reg_imm(r->output, r->current_info.dst_reg,
                                          r->current_info.target);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_ADRP: {
            /* Generate: MOVZ/MOVK sequence to load page address */
            arm64_writer_put_mov_reg_imm(r->output, r->current_info.dst_reg,
                                          r->current_info.target);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_LDR_LITERAL:
        case ARM64_INSN_LDRSW_LITERAL: {
            /* Load target address into register, then load from there */
            /* Use X16 as scratch, then load into destination */
            arm64_writer_put_ldr_reg_address(r->output, ARM64_REG_X16,
                                              r->current_info.target);
            arm64_writer_put_ldr_reg_reg_offset(r->output, r->current_info.dst_reg,
                                                 ARM64_REG_X16, 0);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_LDR_LITERAL_FP: {
            /* For FP literal loads, load address into X16, then use LDR [X16] */
            arm64_writer_put_ldr_reg_address(r->output, ARM64_REG_X16,
                                              r->current_info.target);
            /* Use appropriate FP load based on size */
            arm64_writer_put_ldr_fp_reg_reg(r->output,
                                             (uint32_t)r->current_info.dst_reg,
                                             ARM64_REG_X16,
                                             r->current_info.fp_size);
            return ARM64_RELOC_OK;
        }

        case ARM64_INSN_PRFM_LITERAL: {
            /* Prefetch - can be dropped or converted to NOP for simplicity */
            arm64_writer_put_nop(r->output);
            return ARM64_RELOC_OK;
        }

        default:
            /* Should not reach here, but copy as-is */
            arm64_writer_put_insn(r->output, r->current_insn);
            return ARM64_RELOC_OUT_OF_RANGE;
    }
}

void arm64_relocator_write_all(Arm64Relocator* r) {
    while (!r->eoi) {
        if (arm64_relocator_read_one(r) == 0) break;
        arm64_relocator_write_one(r);
    }
}

void arm64_relocator_skip_one(Arm64Relocator* r) {
    /* Just advance without writing */
    /* The instruction has already been read */
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

int arm64_relocator_can_relocate_directly(uint64_t src_pc, uint64_t dst_pc, uint32_t insn) {
    uint32_t out;
    return arm64_relocator_relocate_insn(src_pc, dst_pc, insn, &out) == ARM64_RELOC_OK;
}

size_t arm64_relocator_get_safe_boundary(const void* addr, size_t min_bytes) {
    const uint32_t* code = (const uint32_t*)addr;
    size_t offset = 0;

    while (offset < min_bytes) {
        uint32_t insn = code[offset / 4];
        Arm64InsnInfo info = arm64_relocator_analyze_insn((uint64_t)addr + offset, insn);

        offset += 4;

        /* Check for ADRP + ADD/LDR sequence that shouldn't be split */
        if (info.type == ARM64_INSN_ADRP && offset < min_bytes) {
            /* ADRP is often followed by ADD or LDR that uses the result */
            /* Include the next instruction as well */
            offset += 4;
        }
    }

    return offset;
}
