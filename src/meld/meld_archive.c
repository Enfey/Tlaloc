/* meld_archive.c - Implementation of static archive (.a) parsing for non-thin archives.
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_archive.h"
#include "meld.h"
#include "meld_symbol.h"
#include "meld_input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Parse a decimal number from an ASCII field (space-padded) */
static uint64_t parse_decimal(const char *s, size_t len) {
    uint64_t val = 0;
    for (size_t i = 0; i < len && s[i] != ' '; i++) {
        if (s[i] >= '0' && s[i] <= '9') {
            val = val * 10 + (s[i] - '0');    /* Left shift one dp, use -'0' to get normalise ASCII values to proper digit range */
        }
    }
    return val;
}

static const char *get_member_name(const ar_hdr_t *hdr, const meld_archive_t *ar,
                                   char *buf, size_t buf_size) {
    if (hdr->ar_name[0] == '/') {
        if (hdr->ar_name[1] >= '0' && hdr->ar_name[1] <= '9') {
            /* /offset */
            uint64_t off = parse_decimal(&hdr->ar_name[1], 15);
            if (ar->long_names && off < ar->long_names_size) {
                /* Name ends at '/\n' in long names table */
                return ar->long_names + off;
            }
        }
    }

    /* Otherwise space or '/' terminated */
    size_t i;
    for (i = 0; i < 16 && hdr->ar_name[i] != ' ' && hdr->ar_name[i] != '/'; i++) {
        if (i < buf_size - 1) buf[i] = hdr->ar_name[i];
    }
    buf[i < buf_size ? i : buf_size - 1] = '\0';    /* Avoid OOB write to buf[16] with another -1 */
    return buf;
}

/* `/` = (bigend) */
static int parse_gnu_symtab(meld_archive_t *ar, const uint8_t *data, size_t size) {
    if (size < 4) return MELD_ERR_BAD_ARCHIVE;  /* Member must hold at least count */ 

    /* Ensure intepretable as native integer */
    uint32_t count = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                     ((uint32_t)data[2] << 8)  | (uint32_t)data[3];

    if (size < 4 + count * 4) return MELD_ERR_BAD_ARCHIVE;  /* 4 byte member offset per symbol */

    ar->symbols = calloc(count, sizeof(meld_ar_index_entry_t));
    if (!ar->symbols) return MELD_ERR_NOMEM;
    ar->symbol_count = count;

    const uint8_t *offsets = data + 4;
    const char *strings = (const char *)(data + 4 + count * 4);  /* One per symbol */
    size_t strings_size = size - (4 + count * 4);

    const char *s = strings;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t off = ((uint32_t)offsets[0] << 24) | ((uint32_t)offsets[1] << 16) |
                       ((uint32_t)offsets[2] << 8)  | (uint32_t)offsets[3];
        offsets += 4;

        /* Ensure not pointing beyond string table */
        if ((s - strings) >= strings_size) {
            free(ar->symbols);
            ar->symbols = NULL;
            ar->symbol_count = 0;
            return MELD_ERR_BAD_ARCHIVE;
        }

        ar->symbols[i].name = s;
        ar->symbols[i].name_hash = fnv1a_hash(s);
        ar->symbols[i].member_off = off;

        /* Advance! */
        while ((s - strings) < strings_size && *s) s++;
        s++;  /* Skip the nul terminator explicitly */
    }

    return MELD_OK;
}

bool archive_is_archive(const void *data, size_t size) {
    return size >= AR_MAGIC_LEN && memcmp(data, AR_MAGIC, AR_MAGIC_LEN) == 0;
}

/* Archive equivalent of elf_open() for archives*/
meld_archive_t *archive_open(const char *path) {
    if (!path) return NULL;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }

    void *base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return NULL;

    /* Ensure valid format */
    if (!archive_is_archive(base, st.st_size)) {
        munmap(base, st.st_size);
        return NULL;
    }

    meld_archive_t *ar = calloc(1, sizeof(*ar));
    if (!ar) {
        munmap(base, st.st_size);
        return NULL;
    }

    ar->path = strdup(path);
    ar->base = base;
    ar->size = st.st_size;
    ar->format = AR_FORMAT_GNU;  /* Assume GNU for now, add preprocessor conditionals if get chance? */

    /* First pass; count members to allocate tracking arrays */
    size_t pos = AR_MAGIC_LEN;
    uint32_t member_count = 0;
    while (pos + AR_HDR_SIZE <= ar->size) {
        const ar_hdr_t *hdr = (const ar_hdr_t *)((uint8_t *)ar->base + pos);  /* Give parith elem size */
        if (memcmp(hdr->ar_fmag, AR_FMAG, AR_FMAG_LEN) != 0) break;  /* Not terminated correctly */
        uint64_t member_size = parse_decimal(hdr->ar_size, 10);
        /* Skip `/` and `//` */
        if (!(hdr->ar_name[0] == '/' && (hdr->ar_name[1] == ' ' || hdr->ar_name[1] == '/'))) {
            member_count++;
        }
        pos += AR_HDR_SIZE + member_size;  /* Skip to next header */
        if (pos & 1) pos++;                /* ar members requires even-byte alignment, skip the padding byte for odd-sized members */
    }

    /* Alloc tracking arrays for archive members */
    if (member_count > 0) {
        ar->member_offsets = malloc(member_count * sizeof(uint32_t));
        ar->extracted = calloc(member_count, sizeof(bool));
        if (!ar->member_offsets || !ar->extracted) {
            archive_close(ar);
            return NULL;
        }
        ar->member_cap = member_count;
    }

    /* Second pass; parse and record member offsets */
    pos = AR_MAGIC_LEN;
    while (pos + AR_HDR_SIZE <= ar->size) {
        const ar_hdr_t *hdr = (const ar_hdr_t *)((uint8_t *)ar->base + pos);
        if (memcmp(hdr->ar_fmag, AR_FMAG, AR_FMAG_LEN) != 0) break;

        uint64_t member_size = parse_decimal(hdr->ar_size, 10);
        const uint8_t *member_data = (const uint8_t *)ar->base + pos + AR_HDR_SIZE;

        if (hdr->ar_name[0] == '/' && hdr->ar_name[1] == ' ') {
            int rc = parse_gnu_symtab(ar, member_data, member_size);
            if (rc != MELD_OK) {
                archive_close(ar);
                return NULL;
            }
        } else if (memcmp(hdr->ar_name, "//", 2) == 0) {
            ar->long_names = (const char *)member_data;
            ar->long_names_size = member_size;
        } else {
            /* Record this member's offset for extraction tracking */
            ar->member_offsets[ar->member_count++] = (uint32_t)pos;
        }

        pos += AR_HDR_SIZE + member_size;
        if (pos & 1) pos++;
    }

    return ar;
}

void archive_close(meld_archive_t *ar) {
    if (!ar) return;

    free((void *)ar->path);
    free(ar->symbols);
    free(ar->member_offsets);
    free(ar->extracted);

    if (ar->base && ar->size > 0) {
        munmap(ar->base, ar->size);
    }

    free(ar);
}

__attribute__((hot))
uint32_t archive_lookup_symbol_hash(meld_archive_t *ar, const char *name, uint32_t hash) {
    if (!ar->symbols) return 0;

    for (uint32_t i = 0; i < ar->symbol_count; i++) {
        if (__builtin_expect(ar->symbols[i].name_hash == hash, 0)) {
            if (strcmp(ar->symbols[i].name, name) == 0) {
                return ar->symbols[i].member_off;
            }
        }
    }
    return 0;
}

int archive_extract_member(meld_archive_t *ar, uint32_t member_off,
                           const void **data_out, size_t *size_out,
                           const char **name_out) {
    if (!ar || member_off == 0) return MELD_ERR_INTERNAL;

    if (member_off + AR_HDR_SIZE > ar->size) {
        return MELD_ERR_BAD_ARCHIVE;
    }

    const ar_hdr_t *hdr = (const ar_hdr_t *)((uint8_t *)ar->base + member_off);

    if (memcmp(hdr->ar_fmag, AR_FMAG, AR_FMAG_LEN) != 0) {
        return MELD_ERR_BAD_ARCHIVE;
    }

    uint64_t size = parse_decimal(hdr->ar_size, 10);
    const uint8_t *data = (const uint8_t *)ar->base + member_off + AR_HDR_SIZE;

    if (member_off + AR_HDR_SIZE + size > ar->size) {
        return MELD_ERR_BAD_ARCHIVE;
    }

    if (data_out) *data_out = data;
    if (size_out) *size_out = size;

    if (name_out) {
        static char name_buf[64];
        *name_out = get_member_name(hdr, ar, name_buf, sizeof(name_buf));
    }

    return MELD_OK;
}

/* Binary search to compute member index given a corresponding member offset.
 * member_offsets, inherently sorted as the archive is parsed sequentially in archive_open()
 */
static uint32_t find_member_index(const meld_archive_t *ar, uint32_t member_off) {
    if (ar->member_count == 0) return UINT32_MAX;  /* Should probably make an enum for these idx lookup errors */
    
    uint32_t lo = 0, hi = ar->member_count;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (ar->member_offsets[mid] < member_off) {
            lo = mid + 1;
        } else if (ar->member_offsets[mid] > member_off) {
            hi = mid;
        } else {
            return mid;
        }
    }
    return UINT32_MAX;
}

void archive_mark_extracted(meld_archive_t *ar, uint32_t member_off) {
    if (!ar || !ar->extracted) return;
    uint32_t idx = find_member_index(ar, member_off);
    if (idx != UINT32_MAX) {
        ar->extracted[idx] = true;
    }
}

bool archive_is_extracted(meld_archive_t *ar, uint32_t member_off) {
    if (!ar || !ar->extracted || member_off == 0) return false;
    uint32_t idx = find_member_index(ar, member_off);
    return (idx != UINT32_MAX) ? ar->extracted[idx] : false;
}

__attribute__((hot))
static int extract_and_process_member(meld_ctx_t *ctx, meld_archive_t *ar,
                                      uint32_t member_off) {
    if (archive_is_extracted(ar, member_off)) return MELD_OK;

    const void *data;
    size_t size;
    const char *name;
    int rc = archive_extract_member(ar, member_off, &data, &size, &name);
    if (rc != MELD_OK) return rc;

    archive_mark_extracted(ar, member_off);

    meld_input_t *inp = input_create_from_archive(ar, member_off, data, size);
    if (!inp) {
        /* Not ARM32 object - skip ! */
        return MELD_OK;
    }

    inp->idx = ctx->input_count;

    if (ctx->input_count >= ctx->input_cap) {
        uint32_t new_cap = ctx->input_cap ? ctx->input_cap * 2 : 16;
        meld_input_t **new_arr = realloc(ctx->inputs, new_cap * sizeof(*new_arr));
        if (!new_arr) {
            input_destroy(inp);
            return MELD_ERR_NOMEM;
        }
        ctx->inputs = new_arr;
        ctx->input_cap = new_cap;
    }
    ctx->inputs[ctx->input_count++] = inp;

    rc = input_parse_symbols(inp, ctx->gst);
    if (rc != MELD_OK) return rc;

    return MELD_OK;
}

typedef struct {
    meld_symbol_t **undefs;
    uint32_t count;
    uint32_t cap;
} undef_collector_t;

static int collect_undefs(meld_symbol_t *sym, void *user) {
    undef_collector_t *col = user;

    if (sym->state == SYM_UNDEFINED) {
        if (col->count >= col->cap) {
            uint32_t new_cap = col->cap ? col->cap * 2 : 256;
            meld_symbol_t **new_arr = realloc(col->undefs, new_cap * sizeof(*new_arr));
            if (!new_arr) return MELD_ERR_NOMEM;
            col->undefs = new_arr;
            col->cap = new_cap;
        }
        col->undefs[col->count++] = sym;
    }
    return 0;
}

/*
 * Search a range of archives [start, end) for symbols that resolve undefs.
 * Returns the number of new inputs extracted.
 */
static int search_archive_range(meld_ctx_t *ctx, uint32_t start, uint32_t end, 
                                uint32_t *extracted_count) {
    *extracted_count = 0;
    uint32_t prev_input_count = ctx->input_count;

    undef_collector_t col = {0};
    int rc = gst_iterate(ctx->gst, collect_undefs, &col);
    if (rc != MELD_OK) {
        free(col.undefs);
        return rc;
    }

    for (uint32_t i = 0; i < col.count; i++) {
        meld_symbol_t *sym = col.undefs[i];

        /* UNDEF: search archives in [start, end) range, respecting order */
        for (uint32_t j = start; j < end; j++) {
            meld_archive_t *ar = ctx->archives[j];
            uint32_t member_off = archive_lookup_symbol_hash(ar, sym->name, sym->name_hash);
            if (member_off != 0 && !archive_is_extracted(ar, member_off)) {
                rc = extract_and_process_member(ctx, ar, member_off);
                if (rc != MELD_OK) {
                    free(col.undefs);
                    return rc;
                }
                /* Don't break here for grouped archives - continue checking
                 * in case newly extracted member introduces new undefs
                 * that could be satisfied by earlier archives in the group.
                 * For non-grouped, stop at first match.
                 */
                if (ar->group_id == 0) {
                    break;
                }
            }
        }
    }

    free(col.undefs);
    *extracted_count = ctx->input_count - prev_input_count;
    return MELD_OK;
}

/* Archive resolution with --start-group / --end-group support.
 *
 * Traditional behaviour:
 *     Archives are processed left-to-right. Each archive is visited once.
 *     Extraction only if supplies a needed definition
 *
 * With groups (--start-group -lN -lM ... --end-group):
 *     Archives within a group are searched repeatedly until no new symbols
 *     are extracted, handling cyclic dependencies effectively.
 
 * Reference: https://sourceware.org/binutils/docs/ld/Options.html
              https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/Semester%201%20Y3/Linkers%20and%20Loaders/Chapters/Chapter%206.md#searching-libraries
 */
__attribute__((hot))
int archive_resolve_lazy(meld_ctx_t *ctx) {
    if (!ctx || !ctx->gst) return MELD_ERR_INTERNAL;
    if (ctx->archive_count == 0) return MELD_OK;

    uint32_t i = 0;
    while (i < ctx->archive_count) {
        meld_archive_t *ar = ctx->archives[i];

        if (ar->group_id == 0) {
            /* No group therefore L-R singular pass */
            uint32_t extracted;
            int rc = search_archive_range(ctx, i, i + 1, &extracted);
            if (rc != MELD_OK) return rc;
            i++;
        } else {
            /* Grouped archives: find extent of this group */
            uint32_t group_id = ar->group_id;
            uint32_t group_start = i;
            uint32_t group_end = i + 1;

            while (group_end < ctx->archive_count && 
                   ctx->archives[group_end]->group_id == group_id) {
                group_end++;  /* Find where consecutive group id equivalent archives end */
            }

            /* Iterate over identified group until fixpoint */
            bool made_progress;
            do {
                uint32_t extracted;
                int rc = search_archive_range(ctx, group_start, group_end, &extracted);
                if (rc != MELD_OK) return rc;
                made_progress = (extracted > 0);
            } while (made_progress);

            i = group_end;
        }
    }

    return MELD_OK;
}

/* Everytime I try and space something nicely it's utterly woeful */
inline void archive_start_group(meld_ctx_t *ctx)        { ctx->current_group_id++;   }
inline void archive_end_group(meld_ctx_t *ctx)          { ctx->current_group_id = 0; }

