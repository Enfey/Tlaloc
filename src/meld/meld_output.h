/* meld_output.h - ELF symbol table and hash generation
 *
 * Handling of emission of sections which the static linker is responsible for construction:
 *     .symtab / .strtab
 *     .dynsym / .dynstr
 *     .gnu.hash
 *     .gnu.version
 *     .gnu.version_d 
 *     .gnu.version_r
 *     .dynamic
 *     .plt
 *     .got
 *     Amongst others
 *
 * References:
 *     GNU hash:     https://flapenguin.me/elf-dt-gnu-hash & https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/Semester%201%20Y3/Linkers%20and%20Loaders/Advanced/GNU%20Hash.md
 *     Versioning:   https://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/symversion.html
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_OUTPUT_H
#define MELD_OUTPUT_H

#include "meld.h"
#include "meld_symbol.h"
#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* GOT related structures.
 *
 * Auxiliary info: 
 *     .got.plt layout for ARM32:
 *       [0] &_DYNAMIC
 *       [1] link_map* (filled by dynamic linker and is internal)
 *       [2] &_dl_runtime_resolve (filled by dynamic linker, the related GOT slot will be initialised by the dynamic linker/loader to point to &_dl_runtime_resolve)
 *       [3..] function entries
 */
typedef struct meld_got_entry {
    meld_symbol_t       *sym;
    uint32_t             got_offset;
    bool                 is_plt;        /* Entry in .got.plt */
    struct meld_got_entry *next;
} meld_got_entry_t;

typedef struct meld_got {
    meld_got_entry_t    *entries;
    meld_got_entry_t    *tail;
    uint32_t             count;

    uint32_t             got_addr;
    uint32_t             got_size;

    uint32_t             gotplt_addr;
    uint32_t             gotplt_size;
} meld_got_t;

int         got_init(meld_got_t *got);
void        got_destroy(meld_got_t *got);
uint32_t    got_add(meld_got_t *got, meld_symbol_t *sym, bool is_plt);
int32_t     got_lookup(meld_got_t *got, meld_symbol_t *sym);
int         got_layout(meld_got_t *got, uint32_t got_addr, uint32_t gotplt_addr);
size_t      got_size(const meld_got_t *got);
size_t      got_write(const meld_got_t *got, void *buf, size_t len);

#endif /* MELD_OUTPUT_H */
