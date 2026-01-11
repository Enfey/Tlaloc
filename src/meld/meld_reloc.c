/*
 * meld_reloc.c - ARM32 relocation processing implementation
 *
 * Worked examples: https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/Semester%201%20Y3/Linkers%20and%20Loaders/Chapters/Chapter%207.md#arm7tdmi-relocation-in-elf
 * Reference:       https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_reloc.h"
#include "meld_symbol.h"
#include "meld_section.h"
#include "meld_output.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const char *reloc_type_name(uint8_t type) {
    switch (type) {
        case R_ARM_NONE:        return "R_ARM_NONE";         case R_ARM_ABS32:       return "R_ARM_ABS32";        
        case R_ARM_REL32:       return "R_ARM_REL32";        case R_ARM_ABS16:       return "R_ARM_ABS16";        
        case R_ARM_ABS12:       return "R_ARM_ABS12";        case R_ARM_ABS8:        return "R_ARM_ABS8";         
        case R_ARM_GOTOFF:      return "R_ARM_GOTOFF";       case R_ARM_GOTPC:       return "R_ARM_GOTPC";        
        case R_ARM_GOT32:       return "R_ARM_GOT32";   
        case R_ARM_CALL:        return "R_ARM_CALL";         case R_ARM_JUMP24:      return "R_ARM_JUMP24";       
        case R_ARM_TARGET1:     return "R_ARM_TARGET1";      case R_ARM_TARGET2:     return "R_ARM_TARGET2";      
        case R_ARM_MOVW_ABS_NC: return "R_ARM_MOVW_ABS_NC";  case R_ARM_MOVT_ABS:    return "R_ARM_MOVT_ABS";
        case R_ARM_MOVW_PREL_NC:return "R_ARM_MOVW_PREL_NC"; case R_ARM_MOVT_PREL:   return "R_ARM_MOVT_PREL";
        case R_ARM_MOVW_BREL_NC:return "R_ARM_MOVW_BREL_NC"; case R_ARM_MOVT_BREL:   return "R_ARM_MOVT_BREL";
        case R_ARM_MOVW_BREL:   return "R_ARM_MOVW_BREL";    case R_ARM_GOT_PREL:    return "R_ARM_GOT_PREL";
        case R_ARM_PREL31:      return "R_ARM_PREL31";       default:                return "R_ARM_UNKNOWN";
    }
}

/* For data-type relocations: sign-extend the initial 32-bit value.
 *
 * For instruction relocations, extract imm according to type:
 *
 * BL/B (R_ARM_CALL, R_ARM_JUMP24, R_ARM_PC24):
 *     Encoding: cond[31:28] 101L[27:24] imm24[23:0]
 *
 * MOVW/MOVT:
 *     Encoding: cond[31:28] 0011 0x00 imm4[19:16] Rd[15:12] imm12[11:0]
 *
 * LDR/STR with immediate offset:
 *     If U bit (bit 23) is clear, negate the offset.
 *
 * PREL31: 
 *     bits [30:0] sign-extended
 */
int32_t reloc_decode_addend(uint8_t type, const void *loc) {
    const uint32_t *word = (const uint32_t *)loc;
    uint32_t insn = *word;  /* P */

    /* Addend formed from sign-extended(the larger cast guarantees this) initial word value */
    if (reloc_is_data_type(type)) return (int32_t)(int64_t)insn;

    switch (type) {
        case R_ARM_NONE:
            return 0;

        case R_ARM_PC24:
        case R_ARM_CALL:
        case R_ARM_JUMP24: {
            uint32_t imm24 = insn & 0x00FFFFFF;  /* Mask to acquire insn[23:0] */
            /* Sign-extension; check highest bit, if set, fill upper bits with 1's */
            if (imm24 & 0x00800000) {
                imm24 |= (int32_t)0xFF000000;
            }
            return imm24 << 2;
        }

        /* MOVW/T*: initial addend formed via 16-bit imm split across [19:16] and [11:0] */
        case R_ARM_MOVW_ABS_NC:
        case R_ARM_MOVT_ABS:
        case R_ARM_MOVW_PREL_NC:
        case R_ARM_MOVT_PREL:
        case R_ARM_MOVW_BREL_NC:
        case R_ARM_MOVT_BREL:
        case R_ARM_MOVW_BREL: {
            uint32_t imm4 = (insn >> 16) & 0xF;
            uint32_t imm12 = insn & 0xFFF;
            return (int32_t)((imm4 << 12) | imm12);
        }

        /* PREL31: 31-bit: initial added formed via bits [30:0] sign extended  */
        case R_ARM_PREL31: {
            uint32_t val = insn & 0x7FFFFFFF;
            if (val & 0x40000000) {
                val |= (int32_t)0x80000000;
            }
            return val;
        }

        /* ABS12: initial addend formed via 12-bit imm (in LDR/STR)
         * Check U bit (bit 23): if clear, offset is negative
         */
        case R_ARM_ABS12: {
            uint32_t imm12 = insn & 0xFFF;
            if (!(insn & (1 << 23))) {  /* U bit */
                imm12 = -imm12;
            }
            return imm12;
        }

        case R_ARM_ABS16:
            return (int16_t)(insn & 0xFFFF);

        case R_ARM_ABS8:
            return (int8_t)(insn & 0xFF);

        default:
            return 0;
    }
}

/*
 * Compute V = f(S, A, P, GOT...) and patch at loc.
 *
 * For branch instructions, V is divided by 4 to yield a word displacement; must fit in 24 bits signed as per instruction format
 * got_entry is signed; we just check positive before using it as part of a reloc, a negative value implies the got does not exist. 
 */
meld_reloc_err_t reloc_apply(void *loc, uint8_t type,
                             uint32_t S, int32_t A, uint32_t P,
                             uint32_t got_base, int32_t got_entry) {
    uint32_t *word = (uint32_t *)loc;
    int32_t V;
    uint32_t val;

    switch (type) {
        case R_ARM_NONE:
            return RELOC_OK;

        case R_ARM_ABS32:
        case R_ARM_TARGET1:
            *word = S + A;
            return RELOC_OK;

        case R_ARM_REL32:
        case R_ARM_TARGET2:
            *word = S + A - P;
            return RELOC_OK;

        case R_ARM_ABS16:
            val = S + A;
            if (val > 0xFFFF) return RELOC_ERR_OVERFLOW;
            *(uint16_t *)loc = (uint16_t)val;
            return RELOC_OK;

        case R_ARM_ABS8:
            val = S + A;
            if (val > 0xFF) return RELOC_ERR_OVERFLOW;
            *(uint8_t *)loc = (uint8_t)val;
            return RELOC_OK;

        case R_ARM_PREL31:
            V = (int32_t)(S + A - P);
            if (V < (int32_t)0xC0000000 || V > (int32_t)0x3FFFFFFF) {
                return RELOC_ERR_OVERFLOW;
            }
            *word = (*word & 0x80000000) | ((uint32_t)V & 0x7FFFFFFF);  /* Preserve bit 31 & set bits [30:0] */
            return RELOC_OK;

        case R_ARM_CALL:
        case R_ARM_JUMP24: {
            V = (int32_t)(S + A - P);

            if (!reloc_branch_in_range(V)) {
                return RELOC_NEEDS_VENEER;
            }

            uint32_t imm24 = ((uint32_t)V >> 2) & 0x00FFFFFF;
            *word = (*word & 0xFF000000) | imm24;  /* Preserve cond + opcode */
            return RELOC_OK;
        }

        case R_ARM_MOVW_ABS_NC: {
            /* no overflow check (_NC) */
            val = (S + A) & 0xFFFF;
            goto encode_movw;  /* This is the first time ive ever used this keyword and its been useful it feels liberating */
        }

        case R_ARM_MOVT_ABS: {
            val = ((S + A) >> 16) & 0xFFFF;
            goto encode_movw;
        }

        case R_ARM_MOVW_PREL_NC: {
            /* no overflow check */
            val = (S + A - P) & 0xFFFF;
            goto encode_movw;
        }

        case R_ARM_MOVT_PREL: {
            val = ((S + A - P) >> 16) & 0xFFFF;
            goto encode_movw;
        }

        case R_ARM_MOVW_BREL_NC: {
            /* Segment-base relative, lower 16 bits, no check */
            val = (S + A) & 0xFFFF;
            goto encode_movw;
        }

        case R_ARM_MOVW_BREL: {
            /* Segment-base relative, lower 16 bits, w/ overflow check */
            int32_t full = (int32_t)(S + A);
            if (full < -32768 || full > 65535) return RELOC_ERR_OVERFLOW;
            val = (uint32_t)full & 0xFFFF;
            goto encode_movw;
        }

        case R_ARM_MOVT_BREL: {
            val = ((S + A) >> 16) & 0xFFFF;
            goto encode_movw;
        }

        encode_movw: {
            uint32_t imm4 = (val >> 12) & 0xF;
            uint32_t imm12 = val & 0xFFF;
            *word = (*word & 0xFFF0F000) | (imm4 << 16) | imm12;
            return RELOC_OK;
        }

        case R_ARM_GOT32:
        case R_ARM_GOT_ABS:
            if (got_entry < 0) return RELOC_ERR_NO_GOT;
            *word = (uint32_t)got_entry + A;
            return RELOC_OK;
        case R_ARM_GOT_PREL:
            if (got_entry < 0) return RELOC_ERR_NO_GOT;
            *word = (uint32_t)got_entry + A - P;
            return RELOC_OK;

        case R_ARM_GOTOFF:
            if (!got_base) return RELOC_ERR_NO_GOT;
            *word = S + A - got_base;
            return RELOC_OK;

        case R_ARM_GOTPC:
            if (!got_base) return RELOC_ERR_NO_GOT;
            *word = got_base + A - P;
            return RELOC_OK;

        case R_ARM_ABS12: {
            V = (int32_t)(S + A);
            uint32_t abs_v = (V < 0) ? (uint32_t)(-V) : (uint32_t)V;
            if (abs_v > 0xFFF) return RELOC_ERR_OVERFLOW;

            /* Clear U bit and imm12; set appropriately */
            *word = *word & ~((1 << 23) | 0xFFF);
            if (V >= 0) {
                *word |= (1 << 23);
            }
            *word |= (abs_v & 0xFFF);
            return RELOC_OK;
        }

        default:
            return RELOC_ERR_UNKNOWN_TYPE;
    }
}

/* MOVT-to-NOP: When the upper 16 bits of the target value are zero,
 * the MOVT instruction is unnecessary and can be replaced with NOP.
 * 
 * Example sequence we could relax:
 *   Before: MOVW Rd, #lo16    ; sets low 16 bits, clears high 16
 *           MOVT Rd, #0       ; sets high 16 bits to 0 , redundant
 *   After:  MOVW Rd, #lo16
 *           NOP
 *
 * GOT relaxation is handled separately via reloc_scan_relax() converting reloc
 * type to support PC relative access without GOT indirection for local, non-preemptible 
 * symbols.
 */

/* MOV R0, R0, AL */
#define ARM_NOP  0xE1A00000

meld_reloc_err_t reloc_try_relax(void *loc, uint8_t type,
                                  uint32_t S, int32_t A, uint32_t P,
                                  const meld_symbol_t *sym) {
    uint32_t *word = (uint32_t *)loc;
    (void)sym;  /* Unused, void as reserved for future relocs if I get round to them */

    switch (type) {
        /* MOVW instruction clears the upper 16 bits prior to writing the lower 16,
         * if the upper 16 bits are known to be zero, a following MOVT is redundant.
         */
        case R_ARM_MOVT_BREL:
        case R_ARM_MOVT_ABS: {
            uint32_t hi16 = ((S + A) >> 16) & 0xFFFF;
            if (hi16 == 0) {
                /* Preserve cond (bits 31:28), replace rest with NOP */
                uint32_t cond = *word & 0xF0000000;
                *word = cond | (ARM_NOP & 0x0FFFFFFF);
                return RELOC_RELAXED;
            }
            return RELOC_OK;
        }

        case R_ARM_MOVT_PREL: {
            int32_t val = (int32_t)(S + A - P);
            uint32_t hi16 = ((uint32_t)val >> 16) & 0xFFFF;
            /* Relax if upper bits are positive small/negative small */
            if (hi16 == 0 || hi16 == 0xFFFF) {
                uint32_t cond = *word & 0xF0000000;
                *word = cond | (ARM_NOP & 0x0FFFFFFF);
                return RELOC_RELAXED;
            }
            return RELOC_OK;
        }

        default:
            return RELOC_OK;
    }
}

int reloc_parse_input(meld_input_t *input) {
    if (!input) return MELD_ERR_INTERNAL;

    const elf_t *elf = &input->elf;
    uint32_t shnum = elf_shnum(elf);

    for (uint32_t i = 1; i < shnum; i++) {
        uint32_t sh_type = elf_sh_type(elf, i);

        if (sh_type != SHT_REL && sh_type != SHT_RELA) continue;

        uint32_t sh_info = elf_sh_info(elf, i);  /* For SHT_REL/A, interpreted as the section header index to which the relocs apply */
        uint64_t sh_size = elf_sh_size(elf, i);

        const void *rel_data = elf_sh_data(elf, i);
        if (!rel_data) continue;

        /* Get target section data for addend formulation (REL only) */
        const void *target_sec_data = elf_sh_data(elf, sh_info);

        if (sh_type == SHT_REL) {
            const Elf32_Rel *rels = (const Elf32_Rel *)rel_data;
            uint32_t rel_count = sh_size / sizeof(Elf32_Rel);

            for (uint32_t j = 0; j < rel_count; j++) {
                const Elf32_Rel *rel = &rels[j];

                uint32_t r_type = ELF32_R_TYPE(rel->r_info);
                uint32_t r_sym = ELF32_R_SYM(rel->r_info);

                if (r_type == R_ARM_NONE) continue;

                int32_t addend = 0;
                if (target_sec_data) {
                    const void *loc = (const uint8_t *)target_sec_data + rel->r_offset;
                    addend = reloc_decode_addend(r_type, loc);
                }

                if (input->reloc_count >= input->reloc_cap) {
                    uint32_t new_cap = input->reloc_cap ? input->reloc_cap * 2 : 64;
                    meld_reloc_t *new_relocs = realloc(input->relocs,
                                                       new_cap * sizeof(meld_reloc_t));
                    if (!new_relocs) return MELD_ERR_NOMEM;
                    input->relocs = new_relocs;
                    input->reloc_cap = new_cap;
                }

                meld_reloc_t *r = &input->relocs[input->reloc_count++];
                r->offset = rel->r_offset;
                r->type = r_type;
                r->orig_type = r_type;
                r->sym_idx = r_sym;
                r->addend = addend;
                r->sec_ndx = sh_info;
            }
        } else {
            const Elf32_Rela *relas = (const Elf32_Rela *)rel_data;
            uint32_t rela_count = sh_size / sizeof(Elf32_Rela);

            for (uint32_t j = 0; j < rela_count; j++) {
                const Elf32_Rela *rela = &relas[j];

                uint32_t r_type = ELF32_R_TYPE(rela->r_info);
                uint32_t r_sym = ELF32_R_SYM(rela->r_info);

                if (r_type == R_ARM_NONE) continue;

                if (input->reloc_count >= input->reloc_cap) {
                    uint32_t new_cap = input->reloc_cap ? input->reloc_cap * 2 : 64;
                    meld_reloc_t *new_relocs = realloc(input->relocs,
                                                       new_cap * sizeof(meld_reloc_t));
                    if (!new_relocs) return MELD_ERR_NOMEM;
                    input->relocs = new_relocs;
                    input->reloc_cap = new_cap;
                }

                meld_reloc_t *r = &input->relocs[input->reloc_count++];
                r->offset = rela->r_offset;
                r->type = r_type;
                r->orig_type = r_type;
                r->sym_idx = r_sym;
                r->addend = rela->r_addend;
                r->sec_ndx = sh_info;
            }
        }
    }

    return MELD_OK;
}
static uint8_t veneer_template[ARM_VENEER_SIZE] = {
    0x04, 0xF0, 0x1F, 0xE5,  /* LDR PC, [PC, #-4] - we do not provide padding */
    0x00, 0x00, 0x00, 0x00   /* .word target (patched) */
};

/* Generate long-branch veneer at veneer_loc for target_addr */
static void veneer_generate(uint8_t *veneer_loc, uint32_t target_addr) {
    memcpy(veneer_loc, veneer_template, ARM_VENEER_SIZE);
    veneer_loc[4] = (target_addr >>  0) & 0xFF;
    veneer_loc[5] = (target_addr >>  8) & 0xFF;
    veneer_loc[6] = (target_addr >> 16) & 0xFF;
    veneer_loc[7] = (target_addr >> 24) & 0xFF;
}
int veneer_mgr_init(meld_veneer_mgr_t *mgr) {
    memset(mgr, 0, sizeof(*mgr));
    return MELD_OK;
}

void veneer_mgr_destroy(meld_veneer_mgr_t *mgr) {
    if (!mgr) return;

    meld_veneer_entry_t *e = mgr->entries;
    while (e) {
        meld_veneer_entry_t *next = e->next;
        free(e);
        e = next;
    }
    free(mgr->data);
    memset(mgr, 0, sizeof(*mgr));
}

uint32_t veneer_mgr_add(meld_veneer_mgr_t *mgr, meld_symbol_t *sym) {
    if (!mgr || !sym) return 0;

    if (sym->veneer_addr != 0) {
        return sym->veneer_addr;
    }

    meld_veneer_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return 0;

    e->target = sym;
    e->offset = mgr->count * ARM_VENEER_SIZE;

    uint32_t needed = (mgr->count + 1) * ARM_VENEER_SIZE;
    if (needed > mgr->data_cap) {
        uint32_t new_cap = mgr->data_cap ? mgr->data_cap * 2 : 256;
        while (new_cap < needed) new_cap *= 2;
        uint8_t *new_data = realloc(mgr->data, new_cap);
        if (!new_data) {
            free(e);
            return 0;
        }
        mgr->data = new_data;
        mgr->data_cap = new_cap;
    }

    veneer_generate(mgr->data + e->offset, sym->st_value);

    if (mgr->tail) {
        mgr->tail->next = e;
    } else {
        mgr->entries = e;
    }
    mgr->tail = e;
    mgr->count++;

    return e->offset;
}

uint32_t veneer_addr_lookup(meld_symbol_t *sym) {
    if (!sym) return 0;
    return sym->veneer_addr;
}

int veneer_mgr_layout(meld_veneer_mgr_t *mgr, uint32_t section_addr) {
    mgr->section_addr = section_addr;

    for (meld_veneer_entry_t *e = mgr->entries; e; e = e->next) {
        e->veneer_addr = section_addr + e->offset;
        e->target->veneer_addr = e->veneer_addr;

        /* Re-generate with final target addresses */
        veneer_generate(mgr->data + e->offset, e->target->st_value);
    }

    return MELD_OK;
}

size_t veneer_mgr_size(const meld_veneer_mgr_t *mgr) {
    return mgr ? mgr->count * ARM_VENEER_SIZE : 0;
}

const uint8_t *veneer_mgr_data(const meld_veneer_mgr_t *mgr) {
    return mgr ? mgr->data : NULL;
}

int reloc_apply_input(meld_input_t *input, meld_ctx_t *ctx,
                      meld_got_t *got, uint32_t plt_addr,
                      meld_veneer_mgr_t *veneers,
                      void *out_buf) {
    if (!input || !ctx || !out_buf) return MELD_ERR_INTERNAL;

    const elf_t *elf = &input->elf;
    (void)elf;  /* Suppress the unused warning - only used in some paths */

    for (uint32_t i = 0; i < input->reloc_count; i++) {
        meld_reloc_t *r = &input->relocs[i];

        /* Skip relocations for sections not included in output (e.g., debug sections) */
        if (!input->sec_state || !input->sec_state[r->sec_ndx].out) {
            continue;
        }

        /* Get symbol (S) that the relocation refers to */
        meld_symbol_t *sym = NULL;
        if (input->sym_map) {
            sym = input->sym_map[r->sym_idx];
        }

        if (!sym) {
            /* Try to retrieve symbol name for better error message */
            const char *sym_name = elf_sym_name(&input->elf, r->sym_idx, false);
            SET_ERR(ctx, MELD_ERR_UNDEF, "reloc %s: unresolved symbol '%s' (idx %u) in %s",
                    reloc_type_name(r->type), 
                    sym_name ? sym_name : "<unknown>",
                    r->sym_idx,
                    input->elf.path ? input->elf.path : "<input>");
            return MELD_ERR_UNDEF;
        }

        /* For section symbols (STT_SECTION), their value is 0 in the input. We compute S as the output address
         * of the referenced section. st_shndx tells us which input section it refers to.
         */
        uint32_t S;
        if (sym->flags & SYM_FLAG_SECTION) {
            uint16_t target_shndx = sym->st_shndx;
            if (!input->sec_state || !input->sec_state[target_shndx].out) {
                const char *sec_name = elf_sh_name(&input->elf, target_shndx);
                SET_ERR(ctx, MELD_ERR_RELOC, "section symbol references section %u (%s) not in output",
                        target_shndx, sec_name ? sec_name : "<null>");
                return MELD_ERR_RELOC;
            }
            meld_sec_state_t *target_state = &input->sec_state[target_shndx];  /* Get output mapping */
            S = target_state->out->addr + target_state->output_offset;
        } else {
            S = sym->st_value;  /* Address already known */
        }

        /* plt_offset >= 0 indicates symbol has a PLT entry (this was hardcoded and caused segfaults lol) */
        bool use_plt = (sym->plt_offset >= 0) && 
                       (r->type == R_ARM_CALL || r->type == R_ARM_JUMP24 || r->type == R_ARM_PLT32);
        if (use_plt) {
            S = plt_addr + (uint32_t)sym->plt_offset;
        }

        /* Compute P */
        meld_sec_state_t *sec_state = &input->sec_state[r->sec_ndx];
        meld_osec_t *osec = sec_state->out;
        uint32_t P = osec->addr + sec_state->output_offset + r->offset;

        /* Compute location in output buffer */
        uint32_t file_off = osec->file_off + sec_state->output_offset + r->offset;
        void *loc = (uint8_t *)out_buf + file_off;

        uint32_t got_base = got ? got->got_addr : 0;
        int32_t got_entry = got ? got_lookup(got, sym) : -1;

        if (reloc_can_relax(r->type)) {
            meld_reloc_err_t relax_err = reloc_try_relax(loc, r->type, S, r->addend, P, sym);
            if (relax_err == RELOC_RELAXED) {
                continue;
            }
        }

        meld_reloc_err_t err = reloc_apply(loc, r->type, S, r->addend, P,
                                           got_base, got_entry);

        if (err == RELOC_NEEDS_VENEER) {
            if (!reloc_can_veneer(r->type)) {
                SET_ERR(ctx, MELD_ERR_RELOC,
                        "reloc %s at 0x%x: overflow, veneer not supported for this type",
                        reloc_type_name(r->type), r->offset);
                return MELD_ERR_RELOC;
            }

            bool eligible = (sym_type(sym) == STT_FUNC);
            if (!eligible) {
                SET_ERR(ctx, MELD_ERR_RELOC,
                        "reloc %s at 0x%x: overflow, target '%s' not veneer-eligible",
                        reloc_type_name(r->type), r->offset, sym->name);
                return MELD_ERR_RELOC;
            }

            /* Get/create veneer for this symbol */
            uint32_t veneer_addr = veneer_addr_lookup(sym);
            if (veneer_addr == 0) {
                veneer_mgr_add(veneers, sym);
                veneer_addr = veneers->section_addr + (veneers->count - 1) * ARM_VENEER_SIZE;
                sym->veneer_addr = veneer_addr;
            }

            /* Retarget */
            err = reloc_apply(loc, r->type, veneer_addr, 0, P, 0, 0);
            if (err != RELOC_OK) {
                SET_ERR(ctx, MELD_ERR_RELOC,
                        "reloc %s at 0x%x: veneer still out of range",
                        reloc_type_name(r->type), r->offset);
                return MELD_ERR_RELOC;
            }
            continue;
        }

        if (err == RELOC_ERR_NO_GOT) {
            SET_ERR(ctx, MELD_ERR_RELOC,
                    "reloc %s for '%s': requires GOT entry",
                    reloc_type_name(r->type), sym->name);
            return MELD_ERR_RELOC;
        }

        if (err != RELOC_OK) {
            SET_ERR(ctx, MELD_ERR_RELOC, "reloc %s at 0x%x: %s",
                    reloc_type_name(r->type), r->offset,
                    err == RELOC_ERR_OVERFLOW ? "overflow" :
                    err == RELOC_ERR_UNKNOWN_TYPE ? "unknown type" :
                    "error");
            return MELD_ERR_RELOC;
        }
    }

    return MELD_OK;
}
