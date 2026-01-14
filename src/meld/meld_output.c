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

/* GNU Hash Table (.gnu.hash)
 * 
 * A section with the name `.gnu.hash` of type `SHT_GNU_HASH` contains a hash table augmented with a 
 * bloom filter, some auxiliary data, and provides .dynsym ordering whereby ordering is via hash-values,
 * such that memory access tends to be adjacent and monotonically increasing to exploit memory locality
 * for improved cache behaviour. 
 *
 * Reference: https://blogs.oracle.com/solaris/gnu-hash-elf-sections
 *            https://flapenguin.me/elf-dt-gnu-hash
 */
int gnu_hash_init(meld_gnu_hash_t *gh) {
    memset(gh, 0, sizeof(*gh));
    return MELD_OK;
}

void gnu_hash_destroy(meld_gnu_hash_t *gh) {
    if (!gh) return;
    free(gh->bloom);
    free(gh->buckets);
    free(gh->chains);
    memset(gh, 0, sizeof(*gh));
}

typedef struct {
    uint32_t idx;       /* .dynsym */
    uint32_t hash;
    uint32_t bucket; 
} gnu_sort_t;

static int cmp_gnu_sort(const void *a, const void *b) {
    const gnu_sort_t *sa = a, *sb = b;
    if (sa->bucket != sb->bucket) return (int)sa->bucket - (int)sb->bucket;
    return (int)sa->idx - (int)sb->idx;  /* Stable within bucket */
}

__attribute__((const))
static uint32_t next_pow2(uint32_t n) {
    if (n == 0) return 1;
    n--;
    n |= n >> 1; n |= n >> 2; n |= n >> 4; n |= n >> 8; n |= n >> 16;   /* Spread highest 1 bit downward, doubling distance each time, until all lower bits filled */
    return n + 1;                                                       /* Next power of 2 */
}

/* Computes floor(log2(n)) by counting number of right shifts */
__attribute__((const))
static uint32_t log2_floor(uint32_t n) {
    if (n == 0) return 0;
    uint32_t r = 0;
    while (n >>= 1) r++;
    return r;
}

int gnu_hash_build(meld_symtab_t *dynsym, uint32_t symndx, meld_gnu_hash_t *gh) {
    if (!dynsym || !gh) return MELD_ERR_INTERNAL;

    uint32_t nsyms = dynsym->count;
    uint32_t nhash = nsyms - symndx;     /* Symbols covered by hash */

    if (nhash == 0) {
        /* Still valid per spec? */
        gh->nbuckets  = 1;
        gh->symndx    = symndx;
        gh->maskwords = 1;
        gh->shift2    = 5;
        gh->bloom     = calloc(1, sizeof(uint32_t));
        gh->buckets   = calloc(1, sizeof(uint32_t));
        gh->chains    = NULL;
        gh->nchains   = 0;
        return (gh->bloom && gh->buckets) ? MELD_OK : MELD_ERR_NOMEM;
    }

    gh->nbuckets  = next_pow2(nhash > 4 ? nhash / 2 : 1);  /* Permits fast modulo as we'll see */
    gh->symndx    = symndx;
    gh->maskwords = next_pow2((nhash + 31) / 32);          /* Roughly 1 bit per symbol, rounded up to a power of 2, get 2 :D */

    uint32_t log2_nsyms = log2_floor(nhash);
    gh->shift2 = (log2_nsyms < 5) ? 5 : log2_nsyms;          /* [5..31] min 5 for ELF32 */

    gnu_sort_t *sorted = malloc(nhash * sizeof(gnu_sort_t));
    if (!sorted) return MELD_ERR_NOMEM;

    for (uint32_t i = 0; i < nhash; i++) {
        uint32_t idx = symndx + i;
        const char *name = dynsym->strtab.data + dynsym->syms[idx].st_name;  /* st_name is offset into the string table, add it to base pointer */
        sorted[i].idx    = idx;
        sorted[i].hash   = gnu_hash(name);
        sorted[i].bucket = sorted[i].hash & (gh->nbuckets - 1);              /* Fast modulo permitted ! */
    }

    qsort(sorted, nhash, sizeof(gnu_sort_t), cmp_gnu_sort);

    Elf32_Sym *tmp = malloc(nhash * sizeof(Elf32_Sym));
    if (!tmp) { free(sorted); return MELD_ERR_NOMEM; }

    for (uint32_t i = 0; i < nhash; i++)
        tmp[i] = dynsym->syms[sorted[i].idx];
    memcpy(&dynsym->syms[symndx], tmp, nhash * sizeof(Elf32_Sym));
    free(tmp);

    gh->bloom   = calloc(gh->maskwords, sizeof(uint32_t));
    gh->buckets = calloc(gh->nbuckets, sizeof(uint32_t));
    gh->chains  = calloc(nhash, sizeof(uint32_t));
    gh->nchains = nhash;

    if (!gh->bloom || !gh->buckets || !gh->chains) {
        free(sorted);
        gnu_hash_destroy(gh);
        return MELD_ERR_NOMEM;
    }

    /* Bloom filter */
    for (uint32_t i = 0; i < nhash; i++) {
        uint32_t h1 = sorted[i].hash;
        uint32_t h2 = h1 >> gh->shift2;

        uint32_t word = (h1 / ELFCLASS_BITS ) & (gh->maskwords - 1);
        uint32_t bit1 = h1 & 31;
        uint32_t bit2 = h2 & 31;

        gh->bloom[word] |= (1UL << bit1) | (1UL << bit2);
    }

    uint32_t prev_bucket = UINT32_MAX;
    for (uint32_t i = 0; i < nhash; i++) {
        uint32_t bucket = sorted[i].bucket;
        uint32_t h = sorted[i].hash;

        /* First sym in bucket */
        if (bucket != prev_bucket) {
            gh->buckets[bucket] = symndx + i;
            prev_bucket = bucket;
        }

        /* Chain entry, hash with LSB cleared, set if last in bucket */
        bool is_last = (i + 1 >= nhash) || (sorted[i + 1].bucket != bucket);
        gh->chains[i] = (h & ~1u) | (is_last ? 1u : 0u);
    }

    free(sorted);
    return MELD_OK;
}

size_t gnu_hash_size(const meld_gnu_hash_t *gh) {
    if (!gh) return 0;
    return sizeof(uint32_t) * (4 + gh->maskwords + gh->nbuckets + gh->nchains);
}

size_t gnu_hash_write(const meld_gnu_hash_t *gh, void *buf, size_t len) {
    if (!gh || !buf) return 0;

    size_t need = gnu_hash_size(gh);
    if (len < need) return 0;

    uint32_t *p = buf;

    *p++ = gh->nbuckets;
    *p++ = gh->symndx;
    *p++ = gh->maskwords;
    *p++ = gh->shift2;

    memcpy(p, gh->bloom, gh->maskwords * sizeof(uint32_t));
    p += gh->maskwords;

    memcpy(p, gh->buckets, gh->nbuckets * sizeof(uint32_t));
    p += gh->nbuckets;

    if (gh->nchains > 0)
        memcpy(p, gh->chains, gh->nchains * sizeof(uint32_t));

    return need;
}

/* Symbol Versioning
 * Reference: https://refspecs.linuxbase.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/symversion.html
 *            https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/Semester%201%20Y3/Linkers%20and%20Loaders/Chapters/Chapter%209.md#library-and-symbol-versioning
 */

/* https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html#hash */
__attribute__((const))
static uint32_t elf_hash(const char *s) {
    uint32_t h = 0, g;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = (h << 4) + *p;
        if ((g = h & 0xf0000000) != 0) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

int version_init(meld_version_t *v) {
    memset(v, 0, sizeof(*v));
    v->next_ndx = 2;
    return MELD_OK;
}

void version_destroy(meld_version_t *v) {
    if (!v) return;

    free(v->versym);

    for (meld_verdef_t *vd = v->verdefs; vd; ) {
        meld_verdef_t *next = vd->next;
        free((void *)vd->name);
        free(vd);
        vd = next;
    }

    for (meld_verneed_t *vn = v->verneeds; vn; ) {
        meld_verneed_t *next = vn->next;
        for (meld_verneed_aux_t *aux = vn->aux; aux; ) {
            meld_verneed_aux_t *anext = aux->next;
            free((void *)aux->name);
            free(aux);
            aux = anext;
        }
        free((void *)vn->filename);
        free(vn);
        vn = next;
    }

    memset(v, 0, sizeof(*v));
}

uint16_t version_add_def(meld_version_t *v, const char *name, bool is_base) {
    if (!v || !name) return 0;

    meld_verdef_t *vd = calloc(1, sizeof(*vd));
    if (!vd) return 0;

    vd->name  = strdup(name);
    vd->hash  = elf_hash(name);
    vd->ndx   = v->next_ndx++;
    vd->flags = is_base ? VER_FLG_BASE : 0;  /* VER_FLG_WEAK rarely used, left out for now  */

    /* Prepend */
    vd->next = v->verdefs;
    v->verdefs = vd;
    v->verdef_count++;

    return vd->ndx;
}

/**/
uint16_t version_add_need(meld_version_t *v, const char *soname, const char *version) {
    if (!v || !soname || !version) return 0;

    /* Find potential existing verneed entry for soname */
    meld_verneed_t *vn = NULL;
    for (meld_verneed_t *p = v->verneeds; p; p = p->next) {
        if (strcmp(p->filename, soname) == 0) {
            vn = p;
            break;
        }
    }

    /* If not pre-existing, instantiate */
    if (!vn) {
        vn = calloc(1, sizeof(*vn));
        if (!vn) return 0;
        vn->filename = strdup(soname);
        if (!vn->filename) { free(vn); return 0; }
        vn->next = v->verneeds;
        v->verneeds = vn;
        v->verneed_count++;
    }

    /* Add aux entry for provided version */
    meld_verneed_aux_t *aux = calloc(1, sizeof(*aux));
    if (!aux) return 0;

    aux->name  = strdup(version);
    aux->hash  = elf_hash(version);
    aux->other = v->next_ndx++;
    aux->flags = 0;

    aux->next = vn->aux;
    vn->aux = aux;
    vn->cnt++;

    return aux->other;
}

int version_alloc_versym(meld_version_t *v, uint32_t count) {
    free(v->versym);
    v->versym = calloc(count, sizeof(Elf32_Versym));
    if (!v->versym && count > 0) return MELD_ERR_NOMEM;

    v->versym_count = count;  /* == dynsym_count */

    for (uint32_t i = 0; i < count; i++)
        v->versym[i] = VER_NDX_GLOBAL;  /* Default */

    return MELD_OK;
}

void version_set_sym(meld_version_t *v, uint32_t idx, uint16_t ndx) {
    if (v && v->versym && idx < v->versym_count)
        v->versym[idx] = ndx;
}

size_t version_versym_size(const meld_version_t *v) {
    return v->versym_count * sizeof(Elf32_Versym);
}

size_t version_versym_write(const meld_version_t *v, void *buf, size_t len) {
    if (!v || !buf) return 0;

    size_t need = version_versym_size(v);
    if (len < need) return 0;

    memcpy(buf, v->versym, need);
    return need;
}

static meld_verdef_t *verdef_find_by_ndx(const meld_version_t *v, uint16_t ndx) {
    for (meld_verdef_t *vd = v->verdefs; vd; vd = vd->next)
        if (vd->ndx == ndx) return vd;
    return NULL;
}

/* This could be significantly more efficient if I redesigned the internal IR to graph inheritance relationships with 
 * verdaux structures as vd_cnt - 1 would immediately yield the depth of the inheritance chain, but I'm in quite the hurry currently!  
 */
static uint16_t verdef_chain_depth(const meld_version_t *v, const meld_verdef_t *vd) {
    uint16_t depth = 1;
    uint16_t parent_ndx = vd->parent_ndx;
    
    for (int i = 0; i < 2 && parent_ndx != 0; i++) {  /* Max 2 ancestors */
        meld_verdef_t *parent = verdef_find_by_ndx(v, parent_ndx);
        if (!parent) break;
        depth++;
        parent_ndx = parent->parent_ndx;
    }
    return depth;
}

size_t version_verdef_size(const meld_version_t *v) {
    size_t sz = 0;
    for (meld_verdef_t *vd = v->verdefs; vd; vd = vd->next) {
        uint16_t depth = verdef_chain_depth(v, vd);
        sz += sizeof(Elf32_Verdef) + depth * sizeof(Elf32_Verdaux);
    }
    return sz;
}

void version_add_strings_to_strtab(const meld_version_t *v, meld_strtab_t *strtab) {
    if (!v || !strtab) return;

    /* verdef */
    for (meld_verdef_t *vd = v->verdefs; vd; vd = vd->next) {
        vd->name_strtab_off = strtab_add(strtab, vd->name);
    }

    /* verneed */
    for (meld_verneed_t *vn = v->verneeds; vn; vn = vn->next) {
        vn->filename_strtab_off = strtab_add(strtab, vn->filename);
        for (meld_verneed_aux_t *aux = vn->aux; aux; aux = aux->next) {
            aux->name_strtab_off = strtab_add(strtab, aux->name);
        }
    }
}

size_t version_verdef_write(const meld_version_t *v, void *buf, size_t len) {
    if (!v || !buf) return 0;

    size_t need = version_verdef_size(v);
    if (len < need) return 0;

    uint8_t *p = buf;

    for (meld_verdef_t *vd = v->verdefs; vd; vd = vd->next) {
        uint16_t depth = verdef_chain_depth(v, vd);
        size_t entry_size = sizeof(Elf32_Verdef) + depth * sizeof(Elf32_Verdaux);

        Elf32_Verdef *out = (Elf32_Verdef *)p;
        out->vd_version = VER_DEF_CURRENT;       /* Always 1 */
        out->vd_flags   = vd->flags;
        out->vd_ndx     = vd->ndx;
        out->vd_cnt     = depth;
        out->vd_hash    = vd->hash;
        out->vd_aux     = sizeof(Elf32_Verdef);  /* First aux immediately follows */
        out->vd_next    = vd->next ? entry_size : 0;
        p += sizeof(Elf32_Verdef);

        /* Walk inheritance chain writing the Verdaux entries; first aux is the version
         * name itself, subsequent are parents.
         */
        const meld_verdef_t *cur = vd;
        for (uint16_t i = 0; i < depth && cur; i++) {
            Elf32_Verdaux *aux = (Elf32_Verdaux *)p;
            aux->vda_name = cur->name_strtab_off;
            aux->vda_next = (i + 1 < depth) ? sizeof(Elf32_Verdaux) : 0;
            p += sizeof(Elf32_Verdaux);

            /* Move to parent if exists, otherwise, iterate outer outermost loop*/
            if (cur->parent_ndx != 0) {
                cur = verdef_find_by_ndx(v, cur->parent_ndx);
            } else {
                cur = NULL;
            }
        }
    }

    return need;
}

size_t version_verneed_size(const meld_version_t *v) {
    size_t sz = 0;
    for (meld_verneed_t *vn = v->verneeds; vn; vn = vn->next)
        sz += sizeof(Elf32_Verneed) + vn->cnt * sizeof(Elf32_Vernaux);

    return sz;
}

size_t version_verneed_write(const meld_version_t *v, void *buf, size_t len) {
    if (!v || !buf) return 0;

    size_t need = version_verneed_size(v);
    if (len < need) return 0;

    uint8_t *p = buf;

    for (meld_verneed_t *vn = v->verneeds; vn; vn = vn->next) {
        Elf32_Verneed *out = (Elf32_Verneed *)p;
        out->vn_version = VER_NEED_CURRENT;
        out->vn_cnt     = vn->cnt;
        out->vn_file    = vn->filename_strtab_off;
        out->vn_aux     = sizeof(Elf32_Verneed);  /* Follows immediately */

        size_t entry_size = sizeof(Elf32_Verneed) + vn->cnt * sizeof(Elf32_Vernaux);
        out->vn_next = vn->next ? entry_size : 0;

        p += sizeof(Elf32_Verneed);

        uint32_t aux_idx = 0;
        for (meld_verneed_aux_t *aux = vn->aux; aux; aux = aux->next, aux_idx++) {
            Elf32_Vernaux *aout = (Elf32_Vernaux *)p;
            aout->vna_hash  = aux->hash;
            aout->vna_flags = aux->flags;
            aout->vna_other = aux->other;
            aout->vna_name  = aux->name_strtab_off;
            aout->vna_next  = aux->next ? sizeof(Elf32_Vernaux) : 0;

            p += sizeof(Elf32_Vernaux);
        }
    }

    return need;
}

/* Version Script Parsing 
 *
 * Generic format:
 *   VERSION_TAG {
 *       global:
 *           symbol1;
 *           symbol2;
 *       local:
 *           *;
 *   } [PARENT_TAG];
 *
 * This minimal subset is supported currently.
 */
static const char *skip_ws(const char *p) {
    while (*p) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
            p++;
        } else if (*p == '/' && p[1] == '*') {
            p += 2;
            while (*p && !(*p == '*' && p[1] == '/')) p++;  /* Scan until closing */
            if (*p) p += 2;
        } else {
            break;
        }
    }
    return p;
}

static const char *parse_ident(const char *p, char *buf, size_t bufsz) {
    size_t i = 0;
    while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                  (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' || *p == '*')) {
        if (i < bufsz - 1) buf[i++] = *p;
        p++;
    }
    buf[i] = '\0';
    return p;  /* End pos */
}

int version_script_parse(meld_ctx_t *ctx, meld_version_t *ver, const char *script) {
    if (!ctx || !ver || !script) return MELD_ERR_INTERNAL;

    const char *p = script;
    char name[128], sym[128];
    uint16_t current_ndx = 0;
    bool in_global = true;
    bool has_local_wildcard = false;

    while (*p) {
        p = skip_ws(p);
        if (!*p) break;

        p = parse_ident(p, name, sizeof(name));
        if (!name[0]) break;

        p = skip_ws(p);
        if (*p != '{') return MELD_ERR_INTERNAL;
        p++;

        /* Add verdef for specified version tag */
        current_ndx = version_add_def(ver, name, ver->verdef_count == 0);
        in_global = false;

        /* Parse block contents */
        while (*p && *p != '}') {
            p = skip_ws(p);
            if (!*p || *p == '}') break;

            p = parse_ident(p, sym, sizeof(sym));

            if (strcmp(sym, "global") == 0) {
                p = skip_ws(p);
                if (*p == ':') p++;
                in_global = true;
            } else if (strcmp(sym, "local") == 0) {
                p = skip_ws(p);
                if (*p == ':') p++;
                in_global = false;
            } else if (strcmp(sym, "*") == 0) {
                /* * means hide all non-exported symbols */
                if (!in_global) {
                    has_local_wildcard = true;
                }
                p = skip_ws(p);
                if (*p == ';') p++;
            } else if (sym[0]) {
                /* Symbol name - tag with current version if global */
                if (in_global) {
                    meld_symbol_t *s = gst_lookup(ctx->gst, sym);
                    if (s) {
                         /* Store version association, symbol → ver idx, for use in .gnu.version */
                        s->version_ndx = current_ndx;
                    }
                }
                p = skip_ws(p);
                if (*p == ';') p++;
            }
        }

        if (*p == '}') p++;
        p = skip_ws(p);

        /* Optional parent reference */
        if (*p && *p != ';' && *p != '{') {
            p = parse_ident(p, sym, sizeof(sym));
            if (sym[0]) {
                /* Find parent verdef by name, store its ndx in current verdef's 
                 * parent_ndx to enables version inheritance (e.g., GLIBC_2.1 inherits GLIBC_2.0).
                */
                for (meld_verdef_t *vd = ver->verdefs; vd; vd = vd->next) {
                    if (vd->ndx == current_ndx) {
                        /* Find parent by name */
                        for (meld_verdef_t *parent = ver->verdefs; parent; parent = parent->next) {
                            if (strcmp(parent->name, sym) == 0) {
                                vd->parent_ndx = parent->ndx;
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
        if (*p == ';') p++;
    }

    /* Apply local: * visibility - hide all symbols not explicitly exported */
    if (has_local_wildcard) {
        for (uint32_t i = 0; i < ctx->gst->bucket_count; i++) {
            for (meld_symbol_t *s = ctx->gst->buckets[i]; s; s = s->next) {
                if (s->version_ndx == 0 && s->state == SYM_DEFINED) {
                    s->st_other = (s->st_other & ~0x3) | STV_HIDDEN;
                }
            }
        }
    }

    return MELD_OK;
}

/* Load and parse version script from file */
int version_script_load(meld_ctx_t *ctx, meld_version_t *ver, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return MELD_ERR_IO;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);  /* Acquire size from SEEK_END fseek() */
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return MELD_ERR_NOMEM; }

    size_t n = fread(buf, 1, sz, f);
    buf[n] = '\0';
    fclose(f);

    int rc = version_script_parse(ctx, ver, buf);
    free(buf);
    return rc;
}

int got_init(meld_got_t *got) {
    if (!got) return MELD_ERR_INTERNAL;
    memset(got, 0, sizeof(*got));
    return MELD_OK;
}

void got_destroy(meld_got_t *got) {
    if (!got) return;

    meld_got_entry_t *e = got->entries;
    while (e) {
        meld_got_entry_t *next = e->next;
        free(e);
        e = next;
    }

    memset(got, 0, sizeof(*got));
}

uint32_t got_add(meld_got_t *got, meld_symbol_t *sym, bool is_plt) {
    if (!got || !sym) return MELD_ERR_INTERNAL;

    for (meld_got_entry_t *e = got->entries; e; e = e->next) {
        if (e->sym == sym) return MELD_OK;  /* Already has entry */
    }

    meld_got_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return MELD_ERR_NOMEM;

    e->sym = sym;
    e->is_plt = is_plt;

    if (got->tail) {
        got->tail->next = e;
    } else {
        got->entries = e;
    }
    got->tail = e;
    got->count++;

    return MELD_OK;
}

/* Returns offset of the symbol's GOT entry from GOT base
 * Useful for relocs like R_ARM_BREL; GOT(S) + A – GOT_ORG
 */
int32_t got_lookup(meld_got_t *got, meld_symbol_t *sym) {
    if (!got || !sym) return -1;
    return sym->got_offset;  /* Already -1 if no GOT entry */
}

int got_layout(meld_got_t *got, uint32_t got_addr, uint32_t gotplt_addr) {
    if (!got) return MELD_ERR_INTERNAL;

    got->got_addr = got_addr;
    got->gotplt_addr = gotplt_addr;

    uint32_t got_entries = 0;
    uint32_t gotplt_entries = 3;  /* Reserved: _DYNAMIC, link_map, resolver stub */

    for (meld_got_entry_t *e = got->entries; e; e = e->next) {
        if (e->is_plt) {
            e->got_offset = gotplt_entries * 4;
            gotplt_entries++;
        } else {
            e->got_offset = got_entries * 4;
            got_entries++;
        }
        if (e->sym) {
            e->sym->got_offset = (int32_t)e->got_offset;
        }
    }

    got->got_size = got_entries * 4;
    got->gotplt_size = gotplt_entries * 4;

    return MELD_OK;
}

size_t got_size(const meld_got_t *got) {
    return got ? got->got_size : 0;
}

size_t got_write(const meld_got_t *got, void *buf, size_t len) {
    if (!got || !buf) return 0;
    if (len < got->got_size) return 0;  /* Maybe placing too much pressure on caller? */

    uint32_t *data = (uint32_t *)buf;
    memset(data, 0, got->got_size);

    /* Static linking, maybe add support for fixing up dynamic ones here if it doesn't fit anywhere else better */
    for (meld_got_entry_t *e = got->entries; e; e = e->next) {
        if (!e->is_plt && e->sym) {
            data[e->got_offset / 4] = e->sym->st_value;  /* Yield index and write final address into GOT slot */
        }
    }

    return got->got_size;
}

int plt_init(meld_plt_t *plt) {
    if (!plt) return MELD_ERR_INTERNAL;
    memset(plt, 0, sizeof(*plt));
    return MELD_OK;
}

void plt_destroy(meld_plt_t *plt) {
    if (!plt) return;

    meld_plt_entry_t *e = plt->entries;
    while (e) {
        meld_plt_entry_t *next = e->next;
        free(e);
        e = next;
    }

    memset(plt, 0, sizeof(*plt));
}

/* Duplicates handled at callsite */
uint32_t plt_add(meld_plt_t *plt, meld_symbol_t *sym, meld_got_t *got) {
    if (!plt || !sym) return 0;

    meld_plt_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return 0;

    e->sym = sym;
    e->plt_offset = ARM_PLT0_SIZE + (plt->count * ARM_PLTN_SIZE);

    sym->plt_offset = (int32_t)e->plt_offset;

    /* Add corresponding .got.plt entry if doesn't already exist */
    if (got) {
        got_add(got, sym, true);
    }

    if (plt->tail) {
        plt->tail->next = e;
    } else {
        plt->entries = e;
    }
    plt->tail = e;
    plt->count++;

    return plt->plt_addr + e->plt_offset;
}

int plt_layout(meld_plt_t *plt, uint32_t plt_addr) {
    if (!plt) return MELD_ERR_INTERNAL;
    plt->plt_addr = plt_addr;
    plt->plt_size = ARM_PLT0_SIZE + (plt->count * ARM_PLTN_SIZE);
    return MELD_OK;
}

size_t plt_size(const meld_plt_t *plt) {
    return plt ? plt->plt_size : 0;
}

size_t plt_write(const meld_plt_t *plt, const meld_got_t *got, void *buf, size_t len) {
    if (!plt || !buf || !got) return 0;
    if (len < plt->plt_size) return 0;

    uint32_t *code = (uint32_t *)buf;

    /* PLT[0]: Lazy binding resolver stub
     * Reference: https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=bfd/elf32-arm.c#l2409
     *
     * Note: musl uses eager binding by default, so PLT[0] is rarely executed (should hopefully get round to testing this)
     */
    code[0] = 0xE52DE004;  /* STR LR, [SP, #-4]!   ; Push return address            */
    code[1] = 0xE59FE004;  /* LDR LR, [PC, #4]     ; LR = literal offset            */
    code[2] = 0xE08FE00E;  /* ADD LR, PC, LR       ; LR = &.got.plt[0]              */
    code[3] = 0xE5BEF008;  /* LDR PC, [LR, #8]!    ; PC = .got.plt[2], LR += 8      */

    
    int32_t plt0_offset = (int32_t)got->gotplt_addr - (int32_t)(plt->plt_addr + 16);
    code[4] = (uint32_t)plt0_offset;

    /* PLT[n]:
     *
     * Fast !
     *     +0:  LDR IP, [PC, #12]     ; IP = offset
     *     +4:  ADD IP, PC, IP        ; IP = &.got.plt[n]
     *     +8:  LDR PC, [IP]          ; PC = *.got.plt[n] (resolved address)
     *
     * Lazy stub (.got.plt[n] initially points to here):
     *     +12: PUSH {LR}             ; Save return address
     *     +16: B PLT[0]              ; Jump to resolver (IP still = &.got.plt[n])
     *
     * Literal pool:
     *     +20: .word offset          ; PC-relative offset to .got.plt[n]
     *
     * First call: .got.plt[n] contains PLT[n]+12, so LDR PC,[IP] lands at +12.
     * Resolver uses IP (= &.got.plt[n]) to find R_ARM_JUMP_SLOT, resolves symbol,
     * patches .got.plt[n] with actual address. Subsequent calls jump directly.
     */
    uint32_t idx = 5;  /* Start after PLT[0]'s 5 words */
    for (meld_plt_entry_t *e = plt->entries; e; e = e->next) {
        /* GOT slot address set by got_layout() */
        uint32_t got_slot_addr = got->gotplt_addr + (uint32_t)e->sym->got_offset;
        uint32_t plt_entry_addr = plt->plt_addr + e->plt_offset;
        int32_t offset = (int32_t)got_slot_addr - (int32_t)(plt_entry_addr + 12);
        
        /* Branch offset for B PLT[0]: at B (+16), PC = plt_entry_addr + 24 */
        int32_t b_offset = ((int32_t)plt->plt_addr - (int32_t)(plt_entry_addr + 24)) >> 2;
        
        code[idx++] = 0xE59FC00C;  /* LDR IP, [PC, #12]  ; Load offset from +20      */
        code[idx++] = 0xE08FC00C;  /* ADD IP, PC, IP     ; IP = &.got.plt[n]         */
        code[idx++] = 0xE59CF000;  /* LDR PC, [IP]       ; Jump through GOT          */
        code[idx++] = 0xE52DE004;  /* PUSH {LR}          ; Save return addr          */
        code[idx++] = 0xEA000000 | (b_offset & 0x00FFFFFF);  /* B PLT[0]             */
        code[idx++] = (uint32_t)offset;  /* Literal: offset to GOT slot              */
    }

    return plt->plt_size;
}

int dynrel_init(meld_dynrel_mgr_t *mgr) {
    if (!mgr) return MELD_ERR_INTERNAL;
    memset(mgr, 0, sizeof(*mgr));
    return MELD_OK;
}

void dynrel_destroy(meld_dynrel_mgr_t *mgr) {
    if (!mgr) return;

    meld_dynrel_t *r = mgr->rel_dyn;
    while (r) {
        meld_dynrel_t *next = r->next;
        free(r);
        r = next;
    }

    r = mgr->rel_plt;
    while (r) {
        meld_dynrel_t *next = r->next;
        free(r);
        r = next;
    }

    memset(mgr, 0, sizeof(*mgr));
}

int dynrel_add_dyn(meld_dynrel_mgr_t *mgr, uint32_t offset, uint32_t type, uint32_t sym_idx) {
    if (!mgr) return MELD_ERR_INTERNAL;

    meld_dynrel_t *r = calloc(1, sizeof(*r));
    if (!r) return MELD_ERR_NOMEM;

    r->r_offset = offset;
    r->r_type = type;
    r->sym_idx = sym_idx;

    if (mgr->rel_dyn_tail) {
        mgr->rel_dyn_tail->next = r;
    } else {
        mgr->rel_dyn = r;
    }
    mgr->rel_dyn_tail = r;
    mgr->rel_dyn_count++;

    return MELD_OK;
}

int dynrel_add_plt(meld_dynrel_mgr_t *mgr, uint32_t offset, uint32_t sym_idx) {
    if (!mgr) return MELD_ERR_INTERNAL;

    meld_dynrel_t *r = calloc(1, sizeof(*r));
    if (!r) return MELD_ERR_NOMEM;

    r->r_offset = offset;
    r->r_type = R_ARM_JUMP_SLOT;
    r->sym_idx = sym_idx;

    if (mgr->rel_plt_tail) {
        mgr->rel_plt_tail->next = r;
    } else {
        mgr->rel_plt = r;
    }
    mgr->rel_plt_tail = r;
    mgr->rel_plt_count++;

    return MELD_OK;
}

size_t dynrel_dyn_size(const meld_dynrel_mgr_t *mgr) {
    return mgr ? mgr->rel_dyn_count * sizeof(Elf32_Rel) : 0;
}

size_t dynrel_plt_size(const meld_dynrel_mgr_t *mgr) {
    return mgr ? mgr->rel_plt_count * sizeof(Elf32_Rel) : 0;
}

size_t dynrel_dyn_write(const meld_dynrel_mgr_t *mgr, void *buf, size_t len) {
    if (!mgr || !buf) return 0;

    size_t need = dynrel_dyn_size(mgr);
    if (len < need) return 0;

    Elf32_Rel *rels = (Elf32_Rel *)buf;
    uint32_t i = 0;

    for (meld_dynrel_t *r = mgr->rel_dyn; r; r = r->next) {
        rels[i].r_offset = r->r_offset;
        rels[i].r_info = ELF32_R_INFO(r->sym_idx, r->r_type);
        i++;
    }

    return need;
}

size_t dynrel_plt_write(const meld_dynrel_mgr_t *mgr, void *buf, size_t len) {
    if (!mgr || !buf) return 0;

    size_t need = dynrel_plt_size(mgr);
    if (len < need) return 0;

    Elf32_Rel *rels = (Elf32_Rel *)buf;
    uint32_t i = 0;

    for (meld_dynrel_t *r = mgr->rel_plt; r; r = r->next) {
        rels[i].r_offset = r->r_offset;
        rels[i].r_info = ELF32_R_INFO(r->sym_idx, r->r_type);
        i++;
    }

    return need;
}

int meld_output_ext_init(meld_output_ext_t *out) {
    if (!out) return MELD_ERR_INTERNAL;

    memset(out, 0, sizeof(*out));

    int rc;
    if ((rc = symtab_init(&out->symtab)) != MELD_OK) return rc;
    if ((rc = symtab_init(&out->dynsym)) != MELD_OK) return rc;
    if ((rc = gnu_hash_init(&out->gnu_hash)) != MELD_OK) return rc;
    if ((rc = version_init(&out->version)) != MELD_OK) return rc;
    if ((rc = got_init(&out->got)) != MELD_OK) return rc;
    if ((rc = plt_init(&out->plt)) != MELD_OK) return rc;
    if ((rc = dynrel_init(&out->dynrels)) != MELD_OK) return rc;

    return MELD_OK;
}

void meld_output_ext_destroy(meld_output_ext_t *out) {
    if (!out) return;

    symtab_destroy(&out->symtab);
    symtab_destroy(&out->dynsym);
    gnu_hash_destroy(&out->gnu_hash);
    version_destroy(&out->version);
    got_destroy(&out->got);
    plt_destroy(&out->plt);
    dynrel_destroy(&out->dynrels);

    memset(out, 0, sizeof(*out));
}

/* Determines which symbols are exported to .dynsym

 * Interesting article/reference: https://maskray.me/blog/2021-05-16-elf-interposition-and-bsymbolic
 *   STV_DEFAULT   - fully exported, interposable
 *   STV_PROTECTED - exported but not interposable
 *   STV_HIDDEN    - not exported to .dynsym
 *   STV_INTERNAL  - processor-reserved, treat as hidden
 */
static bool sym_is_dynamic(const meld_symbol_t *sym) {
    if (!sym) return false;
    uint8_t bind = sym_bind(sym);
    if (bind != STB_GLOBAL && bind != STB_WEAK) return false;
    if (sym_is_local_binding(sym)) return false;
    return sym->state == SYM_DEFINED || sym->state == SYM_UNDEFINED || sym->state == SYM_SHARED;
}

static int add_global(meld_symbol_t *sym, void *user) {
    if (!sym_is_local(sym)) symtab_add(user, sym);
    return 0;
}

static int add_dynamic(meld_symbol_t *sym, void *user) {
    if (!sym_is_dynamic(sym)) return 0;
    symtab_add(user, sym);
    return 0;
}

int meld_output_ext_build(meld_ctx_t *ctx, meld_output_ext_t *out, bool dynamic) {
    if (!ctx || !out || !ctx->gst) return MELD_ERR_INTERNAL;

    /* Build .symtab: locals first (from each input), then globals (from GST)
     * 
     * STB_LOCAL stored per-input in inp->locals[] because they don't participate in cross-file resolution(unsurprisingly).
     * We must iterate each input to collect them for the output .symtab.
     */
    for (uint32_t i = 0; i < ctx->input_count; i++) {
        meld_input_t *inp = ctx->inputs[i];
        for (uint32_t j = 0; j < inp->local_count; j++) {
            symtab_add(&out->symtab, inp->locals[j]);
        }
    }
    symtab_end_locals(&out->symtab);
    
    /* Add globals/weak from GST */
    gst_iterate(ctx->gst, add_global, &out->symtab);

    if (!dynamic) return MELD_OK;

    /* Build .dynsym (names go into embedded .dynstr via strtab_add) */
    int rc = gst_iterate(ctx->gst, add_dynamic, &out->dynsym);
    if (rc != MELD_OK) return rc;

    /* Build .gnu.hash, reordering .dynsym symbols by bucket for cache locality */
    rc = gnu_hash_build(&out->dynsym, 1, &out->gnu_hash);
    if (rc != MELD_OK) return rc;

    /* Allocate .gnu.version */
    rc = version_alloc_versym(&out->version, out->dynsym.count);
    if (rc != MELD_OK) return rc;

    /* Populate .gnu.version from symbol version_ndx.
     * After gnu_hash_build reorders .dynsym, look up each symbol by name
     * in the GST to retrieve corresponding version_ndx. .dynstr offsets survive
     * reordering since the string table itself hasn't been modified.
     * We store dynsym_idx on the symbol for relocation generation
     */
    for (uint32_t i = 1; i < out->dynsym.count; i++) {
        const char *name = out->dynsym.strtab.data + out->dynsym.syms[i].st_name;
        meld_symbol_t *sym = gst_lookup(ctx->gst, name);
        if (sym) {
            sym->dynsym_idx = i;
            if (sym->version_ndx >= 2) {
                version_set_sym(&out->version, i, sym->version_ndx);
            }
        }
        /* Otherwise keeps default VER_NDX_GLOBAL from version_alloc_versym */
    }

    return MELD_OK;
}

void meld_output_ext_update_symtab_values(meld_ctx_t *ctx, meld_output_ext_t *out) {
    if (!ctx || !out) return;

    /* Update symtab entries with final symbol addresses.
     * Will be called after input_update_symbol_values().
     */
    uint32_t idx = 1;

    /* Locals; same order as meld_output_ext_build to update naturally */
    for (uint32_t i = 0; i < ctx->input_count; i++) {
        meld_input_t *inp = ctx->inputs[i];
        for (uint32_t j = 0; j < inp->local_count; j++) {
            if (idx < out->symtab.count) {
                out->symtab.syms[idx].st_value = inp->locals[j]->st_value;
            }
            idx++;
        }
    }

    if (ctx->gst) {
        for (uint32_t b = 0; b < ctx->gst->bucket_count; b++) {
            for (meld_symbol_t *sym = ctx->gst->buckets[b]; sym; sym = sym->next) {
                if (!sym_is_local(sym) && idx < out->symtab.count) {
                    out->symtab.syms[idx].st_value = sym->st_value;
                    idx++;
                }
            }
        }
    }
}

void meld_output_ext_update_dynsym_values(meld_ctx_t *ctx, meld_output_ext_t *out) {
    if (!ctx || !out || !ctx->gst) return;
    for (uint32_t i = 1; i < out->dynsym.count; i++) {
        const char *name = out->dynsym.strtab.data + out->dynsym.syms[i].st_name;
        meld_symbol_t *sym = gst_lookup(ctx->gst, name);
        if (sym) {
            out->dynsym.syms[i].st_value = sym->st_value;
        }
    }
}