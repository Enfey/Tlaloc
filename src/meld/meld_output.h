/* meld_output.h - ELF symbol table and hash generation
 *
 * Handles emission of sections which the static linker is responsible for construction:
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

/* .strtab
 * Concatenated NUL-terminated strings. The first byte, index 0, holds NUL terminator, and so does the last.
 */
typedef struct {
    char    *data;
    size_t   size;
    size_t   cap;
} meld_strtab_t;

int      strtab_init(meld_strtab_t *st);
void     strtab_destroy(meld_strtab_t *st);
uint32_t strtab_add(meld_strtab_t *st, const char *s);

static inline const char *strtab_data(const meld_strtab_t *st) { return st ? st->data : NULL; }
static inline size_t strtab_size(const meld_strtab_t *st) { return st ? st->size : 0; }

/* .symtab
 *   [0]       STN_UNDEF.
 *   sh_info = N (first non-local index)
 *
 * .dynsym: same structure, filtered for exportable symbols only, that is: STV_DEFAULT, relevant runtime type, STB_GLOAL || STB_WEAK.
 */
typedef struct {
    Elf32_Sym      *syms;
    uint32_t        count;
    uint32_t        cap;
    uint32_t        first_global;   /* sh_info value (though i think i've decided this will just be 1, not propagating locals). */
    meld_strtab_t   strtab;
} meld_symtab_t;

int      symtab_init(meld_symtab_t *st);
void     symtab_destroy(meld_symtab_t *st);
uint32_t symtab_add(meld_symtab_t *st, const meld_symbol_t *sym);
void     symtab_end_locals(meld_symtab_t *st);

#endif /* MELD_OUTPUT_H */