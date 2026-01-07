/* meld_symbol.h - Global Symbol Table and symbol resolution
 *
 * The GST is a hash table (https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#FNV-1a_hash) 
 * mapping symbol names to meld_symbol_t entries.
 *
 * Resolution as expected follows traditional semantics; references seek defs, weak yield to strong, multiple strong
 * defs result in errors, local definitions are preferred over shared libraries that would supply one.
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_SYMBOL_H
#define MELD_SYMBOL_H

#include "meld.h"
#include <stdint.h>
#include <stdbool.h>
#include <elf.h>

typedef enum {
    SYM_UNDEFINED = 0,  
    SYM_DEFINED   = 1,  
    SYM_SHARED    = 3,   /* Defined in shared library, needs runtime resolution */
} meld_sym_state_t;

#define SYM_FLAG_NAME_BORROWED  0x01
#define SYM_FLAG_SECTION        0x02  /* Symbol represents a section (STT_SECTION) */

/* Visibility is currently stored in st_other, accessed via ELF32_ST_VISIBILITY() which masks the lower 2 bits of (o):
 *     STV_DEFAULT   (0) - fully exported, interposable
 *     STV_INTERNAL  (1) - processor-reserved, treat as hidden
 *     STV_HIDDEN    (2) - not exported
 *     STV_PROTECTED (3) - exported but non-interposable, binding solely within the consumer object
 */

/*
 * GST symbol representation. LOCAL symbols stay in their input file's
 * local table and are NOT inserted into the GST. `name` is owned (strdup'd) unless 
 * SYM_FLAG_NAME_BORROWED is set.
 * 
 * Some symbol properties are not stored here. See further below for more details.
 */
struct meld_symbol {
    /* 16 bytes on 64-bit */
    const char       *name;
    uint32_t          name_hash;

    uint8_t           st_info;
    uint8_t           st_other;     /* Visibility in low 2 bits */
    uint8_t           flags;
    uint16_t          st_shndx;

    uint32_t          st_value;
    uint32_t          st_size;

    uint8_t           state;          /* meld_sym_state_t */
    uint16_t          version_ndx;    /* Version index for .gnu.version - TODO*/

    /* -1/0 = no entry */
    int32_t           got_offset;
    int32_t           plt_offset;
    uint32_t          veneer_addr;    /* Incredibly speculative - TODO */
    uint32_t          dynsym_idx;     /* Index in .dynsym (0 = not in dynsym) */

    meld_input_t     *input;          /* Defining input file */

    meld_archive_t   *archive;        /* Archive containing this symbol */
    uint32_t          ar_member_off;  /* Offset of member in archive */

    const char       *shared_lib;     /* SONAME if from shared library */

    meld_symbol_t    *resolved;

    meld_symbol_t    *next;           
};

/* Accessors for Derived Properties. We compute from packed st_info rather than 
 * storing bools to reduce memory footprint. 
 */
static inline uint8_t sym_bind(const meld_symbol_t *s) {
    return ELF32_ST_BIND(s->st_info);
}

static inline uint8_t sym_type(const meld_symbol_t *s) {
    return ELF32_ST_TYPE(s->st_info);
}

static inline bool sym_is_weak(const meld_symbol_t *s) {
    return ELF32_ST_BIND(s->st_info) == STB_WEAK;
}

static inline bool sym_is_local(const meld_symbol_t *s) {
    return ELF32_ST_BIND(s->st_info) == STB_LOCAL;
}

static inline uint8_t sym_visibility(const meld_symbol_t *s) {
    return ELF32_ST_VISIBILITY(s->st_other);
}

/* Returns true if symbol should not be exported to .dynsym */
static inline bool sym_is_local_binding(const meld_symbol_t *s) {
    uint8_t vis = sym_visibility(s);
    return vis == STV_HIDDEN || vis == STV_INTERNAL;
}

static inline bool sym_name_borrowed(const meld_symbol_t *s) {
    return (s->flags & SYM_FLAG_NAME_BORROWED) != 0;
}

#define GST_INITIAL_BUCKETS  1024
#define GST_LOAD_FACTOR      0.75

struct meld_gst {
    meld_symbol_t  **buckets;
    uint32_t         bucket_count;
    uint32_t         symbol_count;
    uint32_t         undef_count;
};

/* FNV-1a; a fast non-cryptographic hash function suited to use in hash tables with good avalanche characteristics.
 * XORs 8 bits per incremented pointer into the low 8 bits of h, and multiplies by prime to make the effect of the byte propagate.
 */
#define FNV_OFFSET_BASIS  2166136261u
#define FNV_PRIME         16777619u

static inline uint32_t fnv1a_hash(const char *s) {
    uint32_t h = FNV_OFFSET_BASIS;
    for (; *s; s++) {
        h ^= (uint8_t)*s;
        h *= FNV_PRIME;
    }
    return h;
}

int  gst_init(struct meld_gst *gst);
void gst_destroy(struct meld_gst *gst);

/*
 * If a symbol with the same name exists then we:
 *     Apply resolution rules (see resolve_conflict)
 *     May update existing entry or reject with MELD_ERR_MULTI_DEF
 *
 * On success, returns MELD_OK and sets *out to the GST entry (may
 * differ from sym if merged). If sym->st_bind == STB_LOCAL, returns MELD_OK with 
 * no insertion
 */
__attribute__((nonnull(1, 2)))
int gst_insert(struct meld_gst *gst, meld_symbol_t *sym, meld_symbol_t **out);

/* Returns NULL if not found. */
__attribute__((nonnull(1, 2)))
meld_symbol_t *gst_lookup(struct meld_gst *gst, const char *name);

__attribute__((nonnull(1, 2)))
meld_symbol_t *gst_lookup_hash(struct meld_gst *gst, const char *name, uint32_t hash);

typedef int (*gst_iter_fn)(meld_symbol_t *sym, void *user);
int gst_iterate(struct meld_gst *gst, gst_iter_fn fn, void *user);

static inline uint32_t gst_undef_count(const struct meld_gst *gst) {
    return gst ? gst->undef_count : 0;
}

meld_symbol_t *symbol_from_elf(const elf_t *elf, uint32_t sym_idx,
                               meld_input_t *input);
meld_symbol_t *symbol_create_shared(const char *name, uint8_t st_info, uint8_t st_other,
                                    uint32_t st_size, const char *soname);
void symbol_destroy(meld_symbol_t *sym);

int resolve_conflict(meld_symbol_t *existing, meld_symbol_t *incoming,
                     meld_symbol_t **winner);

void symbol_dump(const meld_symbol_t *sym);
void gst_dump(const struct meld_gst *gst);

#endif /* MELD_SYMBOL_H */
