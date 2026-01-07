/* meld_input.h - Lean input file tracking header
 *
 * lens stays open; store only linker-specific state
 * Section data, names, attributes, etc are accessed via lens at runtime.
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_INPUT_H
#define MELD_INPUT_H

#include "meld.h"
#include <stdint.h>
#include <stdbool.h>

/* Per-section linker state providing only what lens doesn't provide */
typedef struct meld_sec_state {
    struct meld_osec *out;              /* Output section this coalesces into - partially implemented to support input_update_symbol_values */
    uint32_t output_offset;             /* Offset within that output section */
} meld_sec_state_t;

struct meld_input {
    /* lens handle - kept open, all ELF queries go through here */
    elf_t            elf;
    bool             elf_opened;

    uint32_t         idx;             /* Index in ctx->inputs */

    meld_sec_state_t *sec_state;        /* array[elf.shnum] */

    /*ELF symbol index -> meld_symbol_t*
     *
     * For GLOBAL/WEAK: points to GST entry
     * For LOCAL: points to locally-owned symbol
    */
    meld_symbol_t  **sym_map;           /* array[elf.symtab_count] */

    meld_symbol_t  **locals;
    uint32_t         local_count;
    uint32_t         local_cap;

    meld_reloc_t     *relocs;           /* TODO */
    uint32_t         reloc_count;
    uint32_t         reloc_cap;

    meld_archive_t  *parent_archive;    /* I could make this structure hold a union to save some bytes, but I think its fairly negligble in the grand scheme of things */
    uint32_t         ar_member_off;
};

__attribute__((nonnull(1)))
meld_input_t *input_create(const char *path);

__attribute__((nonnull(1, 3)))
meld_input_t *input_create_from_archive(meld_archive_t *ar, uint32_t member_off,
                                        const void *data, size_t size);
__attribute__((nonnull(1, 2)))
int input_parse_symbols(meld_input_t *input, struct meld_gst *gst);

/* Update symbol st_value to final output addresses after section layout.
 * Must be called after section addresses are assigned.
 */
void input_update_symbol_values(meld_input_t *input);
void input_destroy(meld_input_t *input);

static inline elf_t *input_elf(meld_input_t *inp) { return &inp->elf; }

#endif /* MELD_INPUT_H */
