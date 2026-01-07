/* meld_input.c - Input file management
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_input.h"
#include "meld_symbol.h"
#include "meld_section.h"
#include "../lens/lens.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

meld_input_t *input_create(const char *path) {
    meld_input_t *inp = calloc(1, sizeof(*inp));
    if (!inp) return NULL;

    if (elf_open(&inp->elf, path) != 0) {
        free(inp);
        return NULL;
    }
    inp->elf_opened = true;

    /* Validation, lens happily accepts AArch64 + ET_DYN/ET_EXEC; must be ARM32 ET_REL */
    if (!ELF_IS_ARM32(&inp->elf)) {
        elf_close(&inp->elf);
        free(inp);
        return NULL;
    }
    if (inp->elf.elf_type != ET_REL) {
        elf_close(&inp->elf);
        free(inp);
        return NULL;
    }

    /* Alloc per-section state (shnum includes NULL section at 0) */
    uint32_t shnum = elf_shnum(&inp->elf);
    if (shnum > 0) {
        inp->sec_state = calloc(shnum, sizeof(meld_sec_state_t));
        if (!inp->sec_state) {
            elf_close(&inp->elf);
            free(inp);
            return NULL;
        }
    }

    /* Alloc sym map (symtab_count includes STN_UNDEF at 0) */
    uint32_t sym_count = elf_sym_count(&inp->elf, false);
    if (sym_count > 0) {
        inp->sym_map = calloc(sym_count, sizeof(meld_symbol_t *));
        if (!inp->sym_map) {
            free(inp->sec_state);
            elf_close(&inp->elf);
            free(inp);
            return NULL;
        }
    }

    return inp;
}

meld_input_t *input_create_from_archive(meld_archive_t *ar, uint32_t member_off,
                                        const void *data, size_t size) {
    meld_input_t *inp = calloc(1, sizeof(*inp));
    if (!inp) return NULL;

    /* Open from memory via lens - data points into mmap'd archive */
    if (elf_open_mem(&inp->elf, data, size) != 0) {
        free(inp);
        return NULL;
    }
    inp->elf_opened = true;
    inp->parent_archive = ar;
    inp->ar_member_off = member_off;

    /* Validate: must be ARM32 ET_REL */
    if (!ELF_IS_ARM32(&inp->elf) || inp->elf.elf_type != ET_REL) {
        /* Don't call elf_close for memory - just clear */
        memset(&inp->elf, 0, sizeof(inp->elf));
        free(inp);
        return NULL;
    }

    uint32_t shnum = elf_shnum(&inp->elf);
    if (shnum > 0) {
        inp->sec_state = calloc(shnum, sizeof(meld_sec_state_t));
        if (!inp->sec_state) {
            memset(&inp->elf, 0, sizeof(inp->elf));
            free(inp);
            return NULL;
        }
    }

    uint32_t sym_count = elf_sym_count(&inp->elf, false);
    if (sym_count > 0) {
        inp->sym_map = calloc(sym_count, sizeof(meld_symbol_t *));
        if (!inp->sym_map) {
            free(inp->sec_state);
            memset(&inp->elf, 0, sizeof(inp->elf));
            free(inp);
            return NULL;
        }
    }

    return inp;
}

void input_destroy(meld_input_t *inp) {
    if (!inp) return;

    /* Freeing locally-owned symbols only */
    for (uint32_t i = 0; i < inp->local_count; i++) {
        symbol_destroy(inp->locals[i]);
    }

    free(inp->locals);
    free(inp->sym_map);
    free(inp->sec_state);
    free(inp->relocs);

    if (inp->elf_opened) {
        elf_close(&inp->elf);
    }

    free(inp);
}

/* Helper: add local symbol to input's local array */
static int input_add_local(meld_input_t *inp, meld_symbol_t *sym) {
    if (inp->local_count >= inp->local_cap) {
        uint32_t new_cap = inp->local_cap ? inp->local_cap * 2 : 32;
        meld_symbol_t **new_arr = realloc(inp->locals, new_cap * sizeof(*new_arr));
        if (!new_arr) return MELD_ERR_NOMEM;
        inp->locals = new_arr;
        inp->local_cap = new_cap;
    }
    inp->locals[inp->local_count++] = sym;
    return MELD_OK;
}

/* Iterates over .symtab for an input object, instantiating meld_symbol_t entries. 
 * Local symbols stored in inp->locals, referenced by sym_map.
 * Globals are inserted into GST, sym_map points to GST entry.
 */
__attribute__((hot)) 
int input_parse_symbols(meld_input_t *inp, struct meld_gst *gst) {
    const elf_t *elf = &inp->elf;
    uint32_t sym_count = elf->symtab_count;

    /* STN_UNDEF skipped */
    for (uint32_t i = 1; i < sym_count; i++) {
        uint8_t info = elf_sym_info(elf, i, false);
        uint8_t bind = ELF32_ST_BIND(info);
        uint8_t type = ELF32_ST_TYPE(info);

        /* Skip! */
        if (__builtin_expect(type == STT_FILE, 0)) {
            continue;
        }

        if (type == STT_SECTION) {
            uint16_t shndx = elf_sym_shndx(elf, i, false);
            if (shndx == SHN_UNDEF || shndx >= SHN_LORESERVE) {
                continue;
            }
            
            /* Instantiate local symbol to represent this section
             * The st_value will be updated to the output section address later
             * Store shndx so we can look up the output address later
             */
            meld_symbol_t *sym = calloc(1, sizeof(*sym));
            if (!sym) return MELD_ERR_NOMEM;
            
            sym->state = SYM_DEFINED;
            sym->st_info = info;
            sym->st_other = 0;
            sym->st_shndx = shndx;
            sym->st_value = 0;              /* Will eventually be set to output section addr */
            sym->st_size = 0;
            sym->input = inp;
            sym->name = NULL;               /* STT_SECTION have no name in symtab */
            sym->name_hash = 0;
            sym->flags = SYM_FLAG_SECTION;  /* Mark as section symbol */
            sym->got_offset = -1;
            sym->plt_offset = -1;
            
            int rc = input_add_local(inp, sym);
            if (rc != MELD_OK) {
                symbol_destroy(sym);
                return rc;
            }
            inp->sym_map[i] = sym;
            continue;
        }

        meld_symbol_t *sym = symbol_from_elf(elf, i, inp);
        if (__builtin_expect(!sym, 0)) {
            continue;  /* Unnamed/invalid symbols are skipped */
        }

        if (bind == STB_LOCAL) {
            int rc = input_add_local(inp, sym);
            if (__builtin_expect(rc != MELD_OK, 0)) {
                symbol_destroy(sym);
                return rc;
            }
            inp->sym_map[i] = sym;
        } else {
            meld_symbol_t *gst_entry;
            int rc = gst_insert(gst, sym, &gst_entry);
            if (__builtin_expect(rc != MELD_OK, 0)) {
                /* Multi def error, report symbol name */
                symbol_destroy(sym);
                return rc;
            }

            /* If merged into existing, free incoming symbol */
            if (gst_entry != sym) {
                symbol_destroy(sym);
            }
            inp->sym_map[i] = gst_entry;
        }
    }

    return MELD_OK;
}

void input_update_symbol_values(meld_input_t *input) {
    const elf_t *elf = &input->elf;
    uint32_t sym_count = elf->symtab_count;

    for (uint32_t i = 1; i < sym_count; i++) {
        meld_symbol_t *sym = input->sym_map[i];
        if (!sym) continue;

        /* Skip undef/shared */
        if (sym->state != SYM_DEFINED) continue;
        
        /* Skip unsupported (defensive, may be extended/removed) */
        uint16_t shndx = sym->st_shndx;
        if (shndx == SHN_ABS || shndx == SHN_COMMON || shndx >= SHN_LORESERVE) {
            continue;
        }

        /* Skip symbols from other inputs */
        if (sym->input != input) continue;

        if (shndx >= elf_shnum(elf)) continue;
        
        meld_sec_state_t *sec_state = &input->sec_state[shndx];
        if (!sec_state->out) continue;

        uint32_t final_addr = sec_state->out->addr + sec_state->output_offset + sym->st_value;
        sym->st_value = final_addr;
    }
}
