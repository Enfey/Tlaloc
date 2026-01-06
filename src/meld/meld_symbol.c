/* meld_symbol.c - GST manipulation & symbol resolution
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_symbol.h"
#include "meld.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int gst_init(struct meld_gst *gst) {
    memset(gst, 0, sizeof(*gst));
    gst->bucket_count = GST_INITIAL_BUCKETS;
    gst->buckets = calloc(gst->bucket_count, sizeof(meld_symbol_t *));
    if (!gst->buckets) return MELD_ERR_NOMEM;

    return MELD_OK;
}

void gst_destroy(struct meld_gst *gst) {
    if (!gst) return;

    for (uint32_t i = 0; i < gst->bucket_count; i++) {
        meld_symbol_t *sym = gst->buckets[i];
        while (sym) {
            meld_symbol_t *next = sym->next;
            symbol_destroy(sym);
            sym = next;
        }
    }

    free(gst->buckets);
    memset(gst, 0, sizeof(*gst));
}

static int gst_rehash(struct meld_gst *gst) {
    uint32_t new_count = gst->bucket_count * 2;
    meld_symbol_t **new_buckets = calloc(new_count, sizeof(meld_symbol_t *));
    if (!new_buckets) return MELD_ERR_NOMEM;

    for (uint32_t i = 0; i < gst->bucket_count; i++) {
        meld_symbol_t *sym = gst->buckets[i];
        while (sym) {
            meld_symbol_t *next = sym->next;
            uint32_t idx = sym->name_hash & (new_count - 1); /* Mod, yields new bucket */
            /* Head insertion */
            sym->next = new_buckets[idx];
            new_buckets[idx] = sym;
            sym = next;
        }
    }

    free(gst->buckets);
    gst->buckets = new_buckets;
    gst->bucket_count = new_count;
    return MELD_OK;
}

/* Behold! The ordained rules!:
 *     UNDEFINED & DEFINED:   Replace
 *     UNDEFINED & SHARED:    Replace
 *     UNDEFINED & UNDEFINED: NOP
 *
 *     DEFINED   & *:         Keep existing (strongest state)
 *     DEFINED   & DEFINED:   Standard weak/strong rules govern this outcome
 *
 *     SHARED    & DEFINED:   Replace, prefer local defs
 *     SHARED    & *:         Keep existing
 */
int resolve_conflict(meld_symbol_t *existing, meld_symbol_t *incoming,
                     meld_symbol_t **winner) {
    if (!existing || !incoming || !winner) return MELD_ERR_INTERNAL;

    *winner = existing;
    
    /* For our processor, (and for the AArch supplement, for future reference perhaps), no additional symbol bindings are 
     * specified. We take OS specific, that is STB_LOOS & STB_HIOS, to be undefined in meld. Meld will forbid such
     * symbols from ever reaching this function, so we can currently trust sym_is_weak.
     */
    bool ex_weak = sym_is_weak(existing);
    bool in_weak = sym_is_weak(incoming);

    switch (existing->state) {
    case SYM_DEFINED:
        if (incoming->state == SYM_DEFINED) {
            if (ex_weak && !in_weak) {
                *winner = incoming;
                return MELD_OK;
            }
            if (!ex_weak && in_weak) {
                return MELD_OK;
            }
            if (!ex_weak && !in_weak) {
                return MELD_ERR_MULTI_DEF;
            }
            return MELD_OK;
        }
        /* Existing wins if incoming is Undefined, Lazy, or Shared */
        return MELD_OK;

    case SYM_UNDEFINED:
        if (incoming->state == SYM_DEFINED) {
            *winner = incoming;
            return MELD_OK;
        }
        if (incoming->state == SYM_SHARED) {
            *winner = incoming;
            return MELD_OK;
        }
        return MELD_OK;

    case SYM_SHARED:
        /* Local definition takes precedence over DSO symbol */
        if (incoming->state == SYM_DEFINED) {
            *winner = incoming;
            return MELD_OK;
        }
        return MELD_OK;
    }

    return MELD_ERR_INTERNAL;
}

__attribute__((hot))
int gst_insert(struct meld_gst *gst, meld_symbol_t *sym, meld_symbol_t **out) {
    if (out) *out = NULL;

    if (sym_is_local(sym)) {
        if (out) *out = sym;
        return MELD_OK;
    }
    
    if (sym->name_hash == 0 && sym->name) {
        sym->name_hash = fnv1a_hash(sym->name);
    }

    if (gst->symbol_count >= (uint32_t)(gst->bucket_count * GST_LOAD_FACTOR)) {
        int rc = gst_rehash(gst);
        if (rc != MELD_OK) return rc;
    }

    uint32_t idx = sym->name_hash & (gst->bucket_count - 1);

    meld_symbol_t **pp = &gst->buckets[idx]; /* Remember that subscript binds tighter - we use p-to-p to modify the chain itself */
    while (*pp) {
        meld_symbol_t *existing = *pp;
        if (existing->name_hash == sym->name_hash &&
            strcmp(existing->name, sym->name) == 0) {
            /* Collision resolution via resolve_conflict */
            meld_symbol_t *winner;
            int rc = resolve_conflict(existing, sym, &winner);
            if (rc != MELD_OK) return rc;

            if (winner == sym) {
                /* Preserve chain pointer */
                meld_symbol_t *next_save = existing->next;
                bool was_undef = (existing->state == SYM_UNDEFINED);

                if (!sym_name_borrowed(existing)) free((void *)existing->name);
                free((void *)existing->shared_lib);  /* Free before overwrite */
                memcpy(existing, sym, sizeof(*sym));
                existing->next = next_save;

                if (was_undef && existing->state != SYM_UNDEFINED) {
                    gst->undef_count--;
                } else if (!was_undef && existing->state == SYM_UNDEFINED) {
                    gst->undef_count++;
                }

                /* Ownership transferred to existing; prevent double-free */
                sym->flags |= SYM_FLAG_NAME_BORROWED;
                sym->shared_lib = NULL;
            }
            /* If winner is existing sym, don't insert, sym can also be freed */
            if (out) *out = existing;
            return MELD_OK;
        }
        pp = &(*pp)->next;
    }
    /* No collision - head insertion therefore motivated */
    sym->next = gst->buckets[idx];
    gst->buckets[idx] = sym;
    gst->symbol_count++;

    if (sym->state == SYM_UNDEFINED) {
        gst->undef_count++;
    }

    if (out) *out = sym;
    return MELD_OK;
}

__attribute__((hot))
meld_symbol_t *gst_lookup(struct meld_gst *gst, const char *name) {
    return gst_lookup_hash(gst, name, fnv1a_hash(name));
}

__attribute__((hot))
meld_symbol_t *gst_lookup_hash(struct meld_gst *gst, const char *name, uint32_t hash) {
    uint32_t idx = hash & (gst->bucket_count - 1);
    meld_symbol_t *sym = gst->buckets[idx];

    while (sym) {
        if (sym->name_hash == hash && 
            strcmp(sym->name, name) == 0) {
            return sym;
        }
        sym = sym->next;
    }
    return NULL;
}

int gst_iterate(struct meld_gst *gst, gst_iter_fn fn, void *user) {
    if (!gst || !fn) return MELD_ERR_INTERNAL;

    for (uint32_t i = 0; i < gst->bucket_count; i++) {
        meld_symbol_t *sym = gst->buckets[i];
        while (sym) {
            int rc = fn(sym, user);
            if (rc != 0) return rc;
            sym = sym->next;
        }
    }
    return MELD_OK;
}

meld_symbol_t *symbol_from_elf(const elf_t *elf, uint32_t sym_idx,
                               meld_input_t *input) {
    if (!elf) return NULL;

    const char *name = elf_sym_name(elf, sym_idx, false);
    if (!name || name[0] == '\0') return NULL;

    meld_symbol_t *sym = calloc(1, sizeof(*sym));
    if (!sym) return NULL;

    sym->name = strdup(name);
    if (!sym->name) {
        free(sym);
        return NULL;
    }
    sym->name_hash = fnv1a_hash(sym->name);

    /* Extract & pack symbol attributes via lens */
    sym->st_info  = elf_sym_info(elf, sym_idx, false);
    sym->st_other = elf_sym_other(elf, sym_idx, false);  /* Visibility in low 2 bits */
    sym->st_shndx = elf_sym_shndx(elf, sym_idx, false);
    sym->st_value = (uint32_t)elf_sym_value(elf, sym_idx, false);
    sym->st_size  = (uint32_t)elf_sym_size(elf, sym_idx, false);

    sym->got_offset = -1;
    sym->plt_offset = -1;
    sym->veneer_addr = 0;

    sym->input = input;

    if (sym->st_shndx == SHN_UNDEF) {
        sym->state = SYM_UNDEFINED;
    } else {
        sym->state = SYM_DEFINED;
    }

    return sym;
}

meld_symbol_t *symbol_create_shared(const char *name, uint8_t st_info, uint8_t st_other,
                                    uint32_t st_size, const char *soname) {
    if (!name) return NULL;

    meld_symbol_t *sym = calloc(1, sizeof(*sym));
    if (!sym) return NULL;

    sym->name = strdup(name);
    if (!sym->name) {
        free(sym);
        return NULL;
    }
    sym->name_hash = fnv1a_hash(sym->name);
    sym->state = SYM_SHARED;
    sym->st_info = st_info;
    sym->st_other = st_other;
    sym->st_size = st_size;
    sym->st_shndx = SHN_UNDEF;  /* No local section */
    sym->got_offset = -1;
    sym->plt_offset = -1;
    sym->shared_lib = soname ? strdup(soname) : NULL;

    return sym;
}

void symbol_destroy(meld_symbol_t *sym) {
    if (!sym) return;
    if (!sym_name_borrowed(sym)) {
        free((void *)sym->name);
    }
    if (sym->shared_lib) {
        free((void *)sym->shared_lib);
    }
    free(sym);
}

void symbol_dump(const meld_symbol_t *sym) {
    if (!sym) {
        printf("(null symbol)\n");
        return;
    }

    const char *state_str;
    switch (sym->state) {
        case SYM_UNDEFINED: state_str = "UNDEF";  break;
        case SYM_DEFINED:   state_str = "DEF";    break;
        case SYM_SHARED:    state_str = "SHARED"; break;
        default:            state_str = "???";    break;
    }

    const char *bind_str;
    switch (sym_bind(sym)) {
        case STB_LOCAL:  bind_str = "LOCAL";  break;
        case STB_GLOBAL: bind_str = "GLOBAL"; break;
        case STB_WEAK:   bind_str = "WEAK";   break;
        default:         bind_str = "???";    break;
    }

    /* Just deal with the magic nums for now */
    printf("%-24s %08x %6s %6s shndx=%04x val=%08x sz=%u\n",
           sym->name ? sym->name : "(null)",
           sym->name_hash,
           state_str,
           bind_str,
           sym->st_shndx,
           sym->st_value,
           sym->st_size);
}

void gst_dump(const struct meld_gst *gst) {
    if (!gst) {
        printf("(null GST)\n");
        return;
    }

    printf("=== GST: %u symbols, %u undefined ===\n",
           gst->symbol_count, gst->undef_count);

    for (uint32_t i = 0; i < gst->bucket_count; i++) {
        meld_symbol_t *sym = gst->buckets[i];
        while (sym) {
            symbol_dump(sym);
            sym = sym->next;
        }
    }
}
