/* meld_archive.h - Header file for static archive (.a) parsing and library search with group semantics support
 * 
 * Special members:
 *   /         - Directory maintaining symbol to member offset mapping
 *   //        - Long filename table (GNU & others)
 *   __.SYMDEF - `/` Equivalent (BSD) (most bsd code here is speculative, and its implementation is a stretch goal, so will be kept in for the time being)
 *
 * Reference: https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/Semester%201%20Y3/Linkers%20and%20Loaders/Chapters/Chapter%206.md
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_ARCHIVE_H
#define MELD_ARCHIVE_H

#include "meld.h"
#include <stdint.h>
#include <stdbool.h>

#define AR_MAGIC      "!<arch>\n" /* 21 3C 61 72 63 68 3E 0A */
#define AR_MAGIC_LEN  8
#define AR_FMAG       "`\n"       /* ar_hdr_t terminator */
#define AR_FMAG_LEN   2

typedef struct {
    char ar_name[16];    /* Member name (space-padded or '/' offset into `//` member) */
    char ar_date[12];    /* Unused by meld */
    char ar_uid[6];      /* Unused by meld */
    char ar_gid[6];      /* Unused by meld */
    char ar_mode[8];     /* Unused by meld */
    char ar_size[10];
    char ar_fmag[2];
} ar_hdr_t;

#define AR_HDR_SIZE  60

typedef struct {
    const char *name;
    uint32_t    name_hash;
    uint32_t    member_off;
} meld_ar_index_entry_t;

typedef enum {
    AR_FORMAT_GNU,
    AR_FORMAT_BSD,
} meld_ar_format_t;

struct meld_archive {
    const char          *path;
    uint32_t             index;       /* Idx in ctx->archives */

    void                *base;
    size_t               size;

    meld_ar_format_t     format;

    /* Group membership for group semantics semantics.
     * Archives in same group (group_id > 0) are searched repeatedly
     * until no new symbols are extracted. 0 = not in any group.
     */
    uint32_t             group_id;

    /* `/` */
    meld_ar_index_entry_t *symbols;
    uint32_t              symbol_count;

    /* // :  Stores all long filenames concatenated, separated by `/\n` */
    const char          *long_names;
    size_t               long_names_size;

    /* Extraction tracking: member_offsets[i] = file offset of member i.
     * extracted[i] = true if member i has been extracted (this could be significantly more space
     * space efficient if I opt for a bitmap, but I'd rather just keep it straightforward for now)
     * Inspired by the `/` structure.
     */
    uint32_t            *member_offsets;
    bool                *extracted;
    uint32_t             member_count;
    uint32_t             member_cap;
};

meld_archive_t *archive_open(const char *path);
void archive_close(meld_archive_t *ar);

bool is_archive(const void *data, size_t size);

__attribute__((nonnull(1, 2)))
uint32_t archive_lookup_symbol_hash(meld_archive_t *ar, const char *name, uint32_t hash);

/* Returns member data & size
 * Member name is returned in *name_out if non-NULL.
 */
int archive_extract_member(meld_archive_t *ar, uint32_t member_off,
                           const void **data_out, size_t *size_out,
                           const char **name_out);

void archive_mark_extracted(meld_archive_t *ar, uint32_t member_off);
bool archive_is_extracted(meld_archive_t *ar, uint32_t member_off);

/* For each undefined symbol S in the GST:
 *    Check the library index for S.name
 *    If found, extract corresponding member, parse as .o
 *    Add its symbols to GST
 *    Iterate until stable
 * Returns MELD_OK on sucess, error otherwise.
 * Remaining undefined symbols are not an error here (checked later).
 * Reference: https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/Semester%201%20Y3/Linkers%20and%20Loaders/Chapters/Chapter%206.md#searching-libraries
 */
int archive_resolve_lazy(meld_ctx_t *ctx);

/* With: meld ... --start-group -lN ... --end-group
 *
 * Implementation:
 *     archive_start_group() marks the beginning of a new group
 *     Archives added via meld_add_archive() inherit current group_id
 *     archive_end_group() closes the group
 *     archive_resolve_lazy() handles grouped archives specially
 *
 * Reference: https://sourceware.org/binutils/docs/ld/Options.html
 */
void archive_start_group(meld_ctx_t *ctx);
void archive_end_group(meld_ctx_t *ctx);

#endif /* MELD_ARCHIVE_H */
