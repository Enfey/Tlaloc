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