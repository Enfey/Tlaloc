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

/* .gnu.hash
 *
 * The following is all uint32_t for ELFCLASS32    :
 *   [0] nbuckets   Number of hash buckets
 *   [1] symndx     First .dynsym index covered by hash, implies there are dynsymcount - symndx symbols the hash table can 'touch'.
 *   [2] maskwords  Bloom filter word count (power of 2)
 *   [3] shift2     Secondary shift used by bloom filter
 *   [4..4+maskwords-1]           Bloom filter
 *   [4+maskwords..4+maskwords+nbuckets-1]  Bucket array
 *   [4+maskwords+nbuckets..]     Chain array (dynsymcount - symndx)
 */
typedef struct {
    /* Header */
    uint32_t  nbuckets;
    uint32_t  symndx;
    uint32_t  maskwords;
    uint32_t  shift2;

    uint32_t *bloom;
    uint32_t *buckets;
    uint32_t *chains;
    uint32_t  nchains;
} meld_gnu_hash_t;

/* GNU hash function - DJB2 variant as appears in .gnu.hash specification */
__attribute__((const))
static inline uint32_t gnu_hash(const char *s) {
    uint32_t h = 5381;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        h = (h << 5) + h + *p;  /* Historically it mattered that this was a shift and an add rather than integer multiplication, apparently the difference is marginal, if existent at all, on modern machines. */
    return h;
}

int    gnu_hash_init(meld_gnu_hash_t *gh);
void   gnu_hash_destroy(meld_gnu_hash_t *gh);
int    gnu_hash_build(meld_symtab_t *dynsym, uint32_t symndx, meld_gnu_hash_t *gh);
size_t gnu_hash_size(const meld_gnu_hash_t *gh);
size_t gnu_hash_write(const meld_gnu_hash_t *gh, void *buf, size_t len);

/* Symbol Versioning (this was so confusing it makes you wonder why they settled on this design)
 *
 *   .gnu.version
 *       Elf32_Versym[dynsym_count] - one uint16_t per .dynsym entry
 *       Values: 0 = VER_NDX_LOCAL, 1 = VER_NDX_GLOBAL, >=2 = version index; diambiguating which structure we refer to comes from the symbols definition status in .dynsym.
 *
 *   .gnu.version_d
 *       Elf32_Verdef + Elf32_Verdaux pairs - versions we define/export
 *       vd_ndx provides the index used in .gnu.version
 *
 *       Layout per def:
 *         Elf32_Verdef   { vd_version=1, vd_flags, vd_ndx, vd_cnt, vd_hash, vd_aux, vd_next }
 *         Elf32_Verdaux  { vda_name, vda_next }     // version name
 *         [Elf32_Verdaux { vda_name, vda_next }]*   // ancestor names (up to 3 levels)
 *
 *       Example inheritance chain (GLIBC_2.2 → GLIBC_2.1 → GLIBC_2.0):
 *         Verdef: vd_cnt=3
 *         Verdaux[0]: "GLIBC_2.2" (self)
 *         Verdaux[1]: "GLIBC_2.1" (parent)
 *         Verdaux[2]: "GLIBC_2.0" (grandparent, vda_next=0)
 *
 *   .gnu.version_r (SHT_GNU_verneed)
 *       Elf32_Verneed + Elf32_Vernaux pairs - versions required from shared libs
 *       vna_other in Elf32_Vernaux provides index used in .gnu.version
 *
 *       Layout per dependency:
 *         Elf32_Verneed  { vn_version=1, vn_cnt, vn_file, vn_aux, vn_next }
 *         Elf32_Vernaux  { vna_hash, vna_flags, vna_other, vna_name, vna_next }*
 *
 * IR holds data during link and serialises to expected ELF structures on output.
 * Reference: https://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/symversion.html
 */

/* Serialises to Elf32_Verdef + Elf32_Verdaux chain
 * Supports up to 3 levels of inheritance (self + 2 ancestors)
 * vd_cnt = 1 + depth of inheritance chain when serialising
 */
typedef struct meld_verdef {
    const char          *name;        /* Elf32_Verdaux.vda_name (strtab offset) */
    uint32_t             hash;
    uint32_t             name_strtab_off; /* Offset into .dynstr */
    uint16_t             ndx;
    uint16_t             flags;
    uint16_t             parent_ndx;  /* Parent version index (0 = no parent) */
    struct meld_verdef  *next;        /* Preferred as pointer for simplicity over byte offset, can be calculated easily regardless */
} meld_verdef_t;

/* Serialises to Elf32_Vernaux */
typedef struct meld_verneed_aux {
    const char               *name;     /* Elf32_Vernaux.vna_name (via .dynstr) */
    uint32_t                  hash;
    uint32_t                  name_strtab_off;
    uint16_t                  flags;
    uint16_t                  other;
    struct meld_verneed_aux  *next;
} meld_verneed_aux_t;

/* Version requirement - becomes Elf32_Verneed on output */
typedef struct meld_verneed {
    const char           *filename;     /* Elf32_Verneed.vn_file (via .dynstr) */
    uint32_t              filename_strtab_off;
    meld_verneed_aux_t   *aux;
    uint16_t              cnt;
    struct meld_verneed  *next;
} meld_verneed_t;

typedef struct {
    Elf32_Versym   *versym;         /* .gnu.version */
    uint32_t        versym_count;

    meld_verdef_t  *verdefs;
    uint16_t        verdef_count;   /* DT_VERDEFNUM */

    meld_verneed_t *verneeds;
    uint16_t        verneed_count;  /* DT_VERNEEDNUM */

    uint16_t        next_ndx;
} meld_version_t;

int  version_init(meld_version_t *v);
void version_destroy(meld_version_t *v);

uint16_t version_add_def(meld_version_t *v, const char *name, bool is_base);
uint16_t version_add_need(meld_version_t *v, const char *soname, const char *version);

void version_set_sym(meld_version_t *v, uint32_t sym_idx, uint16_t ver_ndx);
int version_alloc_versym(meld_version_t *v, uint32_t dynsym_count);

size_t version_versym_size(const meld_version_t *v);
size_t version_versym_write(const meld_version_t *v, void *buf, size_t len);

size_t version_verdef_size(const meld_version_t *v);
size_t version_verneed_size(const meld_version_t *v);

/* Add all version names to the string table before sizing .dynstr
 * Need this to be called before version_verdef_write/version_verneed_write
 */
void version_add_strings_to_strtab(const meld_version_t *v, meld_strtab_t *strtab);

size_t version_verdef_write(const meld_version_t *v, void *buf, size_t len);
size_t version_verneed_write(const meld_version_t *v, void *buf, size_t len);

/* Version script parsing
 * Parses primitive GNU-style version scripts for symbol versioning (no support for @ and @@ syntax).
 */
int version_script_load(meld_ctx_t *ctx, meld_version_t *v, const char *path);
int version_script_parse(meld_ctx_t *ctx, meld_version_t *v, const char *script);

#endif /* MELD_OUTPUT_H */