/* meld_output.c - ELF static linker structure instantiation implementation file
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_output.h"
#include "meld.h"
#include "meld_symbol.h"
#include "meld_input.h"    /* For inp->locals iteration */
#include "meld_section.h"  /* For meld_osec_t in symtab_add */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* String Table (.strtab / .dynstr)
 * ELF string tables are simple: a sequence of NUL-terminated strings.
 * Symbols reference strings by byte offset into this blob.
 * 
 * Index 0 is always the empty string (just a NUL byte).
 */
#define STRTAB_INIT_CAP 4096
#define ELFCLASS_BITS   32

int strtab_init(meld_strtab_t *st) {
    st->data = malloc(STRTAB_INIT_CAP);
    if (!st->data) return MELD_ERR_NOMEM;

    st->cap = STRTAB_INIT_CAP;
    st->data[0] = '\0';  /* Index 0 = empty string */
    st->size = 1;

    return MELD_OK;
}

void strtab_destroy(meld_strtab_t *st) {
    if (!st) return;
    free(st->data);
    memset(st, 0, sizeof(*st));
}

uint32_t strtab_add(meld_strtab_t *st, const char *s) {
    if (!st || !s) return 0;
    if (!*s) return 0;  /* offset 0 */

    size_t len = strlen(s);
    size_t need = st->size + len + 1;

    if (need > st->cap) {
        size_t newcap = st->cap * 2;
        while (newcap < need) newcap *= 2;
        char *p = realloc(st->data, newcap);
        if (!p) return 0;
        st->data = p;
        st->cap = newcap;
    }

    uint32_t off = (uint32_t)st->size;
    memcpy(st->data + st->size, s, len + 1);
    st->size += len + 1;

    return off;
}

/* Symbol Table (.symtab / .dynsym)
 *
 * Array of Elf32_Sym structures. Index 0 is always STN_UNDEF (all zeros).
 *
 * sh_info typically divides the table into locals (indices 0..sh_info-1)
 * and globals (indices sh_info..count-1). We track with first_global.
 *
 * For .dynsym, locals are omitted, so naturally first_global will remain = 1.
 */
#define SYMTAB_INIT_CAP 256

int symtab_init(meld_symtab_t *st) {
    memset(st, 0, sizeof(*st));

    st->syms = calloc(SYMTAB_INIT_CAP, sizeof(Elf32_Sym));
    if (!st->syms) return MELD_ERR_NOMEM;

    st->cap = SYMTAB_INIT_CAP;

    int rc = strtab_init(&st->strtab);
    if (rc != MELD_OK) {
        free(st->syms);
        return rc;
    }

    /* Index 0: STN_UNDEF, already zeroed. */
    st->count = 1;
    st->first_global = 1;

    return MELD_OK;
}

void symtab_destroy(meld_symtab_t *st) {
    if (!st) return;
    free(st->syms);
    strtab_destroy(&st->strtab);
    memset(st, 0, sizeof(*st));
}

uint32_t symtab_add(meld_symtab_t *st, const meld_symbol_t *sym) {
    if (!st || !sym) return 0;

    if (st->count >= st->cap) {
        uint32_t newcap = st->cap * 2;
        Elf32_Sym *p = realloc(st->syms, newcap * sizeof(Elf32_Sym));
        if (!p) return 0;
        st->syms = p;
        memset(st->syms + st->count, 0, (newcap - st->count) * sizeof(Elf32_Sym));  /* Zeroing the new memory */
        st->cap = newcap;
    }

    /* Map input section index to output section index */
    uint16_t out_shndx = sym->st_shndx;
    if (out_shndx != SHN_UNDEF && out_shndx < SHN_LORESERVE) {
        if (sym->input && sym->input->sec_state && 
            out_shndx < elf_shnum(&sym->input->elf)) {
            meld_osec_t *osec = sym->input->sec_state[out_shndx].out;
            out_shndx = osec ? osec->idx : SHN_UNDEF;
        }
    }

    Elf32_Sym *out = &st->syms[st->count];
    out->st_name  = strtab_add(&st->strtab, sym->name ? sym->name : "");
    out->st_value = sym->st_value;
    out->st_size  = sym->st_size;
    out->st_info  = sym->st_info;
    out->st_other = sym->st_other;
    out->st_shndx = out_shndx;

    return st->count++;
}

void symtab_end_locals(meld_symtab_t *st) {
    if (st) st->first_global = st->count;
}