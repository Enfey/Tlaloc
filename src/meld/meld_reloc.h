/* meld_reloc.h - ARM32 relocation processing
 *
 * Handles relocations for ARM32 (EM_ARM) objects following the ARM ELF ABI.
 *
 * High-Level flow regarding relocs:
 *   1. Parse .rel/a sections(typically the former for EM_ARM), extract P, compute A as per instruction class rules. 
 *   2. Compute V = f(S, A, P) where f is implied by the relocation type.
 *   3. For instruction relocations, check overflow; generate long-branch veneer if eligble or report error.
 *   4. Patch the instruction/data with computed value V
 *
 * Reference: https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/Semester%201%20Y3/Linkers%20and%20Loaders/Chapters/Chapter%207.md#high-level-flow-for-every-relocation

 * Key symbols in relocation expressions:
 *
 * Supported relocations:
 *     Data:
 *       R_ARM_ABS32       - S + A
 *       R_ARM_REL32       - S + A - P
 *       R_ARM_PREL31      - (S + A - P) & 0x7FFFFFFF
 *       R_ARM_TARGET1     - Platform: ABS32 or REL32 (we use ABS32)
 *       R_ARM_TARGET2     - Platform: REL32, GOT_REL, or ABS32 (we use REL32)
 *
 *     Branch:
 *       R_ARM_CALL        - ((S + A) | T) - P  (BL/BLX, ±32MB)
 *       R_ARM_JUMP24      - ((S + A) | T) - P  (B/BL<cond>, ±32MB)
 *
 *     MOVW/MOVT:
 *       R_ARM_MOVW_ABS_NC - (S + A) & 0xFFFF
 *       R_ARM_MOVT_ABS    - ((S + A) >> 16) & 0xFFFF
 *       R_ARM_MOVW_PREL_NC- (S + A - P) & 0xFFFF
 *       R_ARM_MOVT_PREL   - ((S + A - P) >> 16) & 0xFFFF
 *
 *     GOT-related:
 *       R_ARM_GOT32       - GOT(S) + A
 *       R_ARM_GOT_PREL    - GOT(S) + A - P
 *       R_ARM_GOT_BREL    - GOT(S) + A - GOT_ORG
 *       R_ARM_GOTOFF      - S + A - GOT_ORG
 *       R_ARM_GOTPC       - GOT_ORG + A - P
 * 
 * Reference: https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_RELOC_H
#define MELD_RELOC_H

#include "meld.h"
#include "meld_input.h"
#include <stdint.h>
#include <stdbool.h>
#include <elf.h>

typedef enum {
    RELOC_OK = 0,
    RELOC_ERR_OVERFLOW,
    RELOC_ERR_UNKNOWN_TYPE,
    RELOC_ERR_UNDEF_SYM,
    RELOC_ERR_BAD_SECTION,
    RELOC_ERR_NO_GOT,
    RELOC_NEEDS_VENEER,
    RELOC_RELAXED,
} meld_reloc_err_t;

struct meld_reloc {
    uint32_t        offset;
    uint8_t         type;           /* Current type (may be relaxed via type conversion - currently only applies to GOT relocs) */
    uint8_t         orig_type;
    uint32_t        sym_idx;
    int32_t         addend;
    uint32_t        sec_ndx;
};

/* When a branch target exceeds range ±32MB, we opt for the generation of a long-branch veneer(zero clue how I'm going to test this works):
 *
 *     Original:    BL far_target     ; out of range
 *     Becomes:     BL __veneer_X     ; within range
 *     ...
 *     __veneer_X:  LDR PC, [PC, #0] ; PC+8-4 = veneer+4 = &target_addr (no padding, 0 if there is)
 *                  .word far_target  ; absolute address
 *
 * Long-branch veneer eligible relocations we support are R_ARM_CALL and R_ARM_JUMP24
 */

typedef struct meld_veneer_entry {
    meld_symbol_t   *target;        /* Target symbol */
    uint32_t         veneer_addr;   /* Final address of veneer */
    uint32_t         offset;        /* Offset within veneer section */
    struct meld_veneer_entry *next;
} meld_veneer_entry_t;

typedef struct meld_veneer_mgr {
    meld_veneer_entry_t *entries;
    meld_veneer_entry_t *tail;
    uint32_t             count;

    uint8_t             *data;          /* Veneer synthetic section buffer */
    uint32_t             data_cap;
    uint32_t             section_addr;
} meld_veneer_mgr_t;

int       veneer_mgr_init(meld_veneer_mgr_t *mgr);
void      veneer_mgr_destroy(meld_veneer_mgr_t *mgr);
uint32_t  veneer_mgr_add(meld_veneer_mgr_t *mgr, meld_symbol_t *sym);
uint32_t  veneer_addr_lookup(meld_symbol_t *sym);
int       veneer_mgr_layout(meld_veneer_mgr_t *mgr, uint32_t section_addr);
size_t    veneer_mgr_size(const meld_veneer_mgr_t *mgr);
const uint8_t *veneer_mgr_data(const meld_veneer_mgr_t *mgr);

/* Forward declaration (meld_output.h) */
struct meld_got;
typedef struct meld_got meld_got_t;

int32_t reloc_decode_addend(uint8_t type, const void *loc);
meld_reloc_err_t reloc_apply(void *loc, uint8_t type,
                             uint32_t S, int32_t A, uint32_t P,
                             uint32_t got_base, int32_t got_entry);
int reloc_parse_input(meld_input_t *input);

/* Relaxation transforms expensive instruction sequences yielded by relocation types that 'overreach' into cheaper ones:
 * Currently only handles MOVT-to-NOP relaxation when upper 16 bits are zero.
 */
meld_reloc_err_t reloc_try_relax(void *loc, uint8_t type,
                                  uint32_t S, int32_t A, uint32_t P,
                                  const meld_symbol_t *sym);

int reloc_apply_input(meld_input_t *input, meld_ctx_t *ctx,
                      meld_got_t *got, uint32_t plt_addr,
                      meld_veneer_mgr_t *veneers,
                      void *out_buf);

const char *reloc_type_name(uint8_t type);

static inline bool reloc_can_veneer(uint8_t type) {
    switch (type) {
        case R_ARM_PC24:
        case R_ARM_CALL:
        case R_ARM_JUMP24:
            return true;
        default:
            return false;
    }
}

static inline bool reloc_can_relax(uint8_t type) {
    switch (type) {
        case R_ARM_MOVT_ABS:
        case R_ARM_MOVT_PREL:
        case R_ARM_MOVT_BREL:
            return true;
        default:
            return false;
    }
}

/* Data-type relocs - initial value at P is sign-extended to 32 bits */
static inline bool reloc_is_data_type(uint8_t type) {
    switch (type) {
        case R_ARM_ABS32:
        case R_ARM_REL32:
        case R_ARM_GOT_ABS:
        case R_ARM_GOT32:
        case R_ARM_GOTOFF:
        case R_ARM_GOTPC:
        case R_ARM_GOT_PREL:
        case R_ARM_TARGET1:
        case R_ARM_TARGET2:
        case R_ARM_SBREL31:
            return true;
        default:
            return false;
    }
}

#define ARM_BRANCH_RANGE_MAX    ((int32_t)0x01FFFFFC)   /* +32MB - 4 */
#define ARM_BRANCH_RANGE_MIN    ((int32_t)-0x02000000)  /* -32MB */

static inline bool reloc_branch_in_range(int32_t offset) {
    return offset >= ARM_BRANCH_RANGE_MIN && offset <= ARM_BRANCH_RANGE_MAX;
}

/* Long-branch veneer code size: LDR PC, [PC, #-4] + .word target = 8 bytes */
#define ARM_VENEER_SIZE  8

#endif /* MELD_RELOC_H */
