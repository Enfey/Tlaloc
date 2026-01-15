/* meld_dynlink.h - Dynamic linking section generation
 *
 * Orchestrates generation of the following runtime linking sections:
 *   .got
 *   .got.plt
 *   .plt
 *   .rel.dyn      Dynamic data relocations
 *   .rel.plt      Dynamic relocations for PLT via .got.plt (R_ARM_JUMP_SLOT)
 *   .dynamic 
 *   .interp 
 *
 * Absolute address emission is disabled by default for PIC/PIE outputs(the meld default).
 * MELD_ALLOW_TEXTREL should be set to permit R_ARM_ABS32 in .text.
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_DYNLINK_H
#define MELD_DYNLINK_H

#include "meld.h"
#include "meld_output.h"
#include "meld_reloc.h"
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    DYNLINK_OK = 0,
    DYNLINK_ERR_TEXTREL,
    DYNLINK_ERR_NOMEM,
    DYNLINK_ERR_INTERNAL,
} meld_dynlink_err_t;

typedef struct meld_dyn_tag {
    uint32_t             tag;
    uint32_t             val;
    struct meld_dyn_tag *next;
} meld_dyn_tag_t;

typedef struct meld_dynamic {
    meld_dyn_tag_t      *tags;
    meld_dyn_tag_t      *tail;
    uint32_t             count;
} meld_dynamic_t;

/* IR to help yield DT_NEEDED .dynamic entries*/
typedef struct meld_needed {
    const char          *soname;
    char                *path;          /* Full path to .so file */
    uint32_t             strtab_offset; /* Offset into .dynstr for DT_NEEDED d_val */
    struct meld_needed  *next;
} meld_needed_t;

typedef struct meld_dynlink {
    meld_got_t           got;
    meld_plt_t           plt;
    meld_dynrel_mgr_t    dynrels;
    meld_veneer_mgr_t    veneers;
    meld_dynamic_t       dynamic;

    struct meld_gst     *gst;           /* For synthetic symbol lookup */

    meld_needed_t       *needed;        /* DT_NEEDED list */
    meld_needed_t       *needed_tail;
    uint32_t             needed_count;

    const char          *interp;        /* NULL for static */

    uint32_t             got_addr;
    uint32_t             gotplt_addr;
    uint32_t             plt_addr;
    uint32_t             dynamic_addr;
    uint32_t             interp_addr;
    uint32_t             rel_dyn_addr;
    uint32_t             rel_plt_addr;
    uint32_t             veneer_addr;

    bool                 has_textrel;
    bool                 allow_textrel;
    bool                 is_pie;
    bool                 is_static;
    bool                 needs_got;

    uint32_t             abs_data_reloc_count;  /* Count of absolute relocs in writable sections needing R_ARM_RELATIVE */
} meld_dynlink_t;

int dynlink_init(meld_dynlink_t *dl, struct meld_gst *gst);
void dynlink_destroy(meld_dynlink_t *dl);
int dynamic_init(meld_dynamic_t *d);
void dynamic_destroy(meld_dynamic_t *d);
size_t dynamic_size(const meld_dynamic_t *d);
size_t dynlink_dynamic_size(const meld_dynlink_t *dl);
size_t dynlink_interp_size(const meld_dynlink_t *dl);

#endif /* MELD_DYNLINK_H */
