/* meld_dynlink.c - Dynamic linking section generation implementation
 *
 * Reference: https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/Semester%201%20Y3/Linkers%20and%20Loaders/Chapters/Chapter%209.md
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_dynlink.h"
#include "meld_symbol.h"
#include "meld_output.h"
#include "meld_section.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define ARM_INTERP_PATH "/lib/ld-musl-arm.so.1"  /* Shame I won't have chance to implement glue :( */

int dynlink_init(meld_dynlink_t *dl, struct meld_gst *gst) {
    memset(dl, 0, sizeof(*dl));

    int rc;
    if ((rc = got_init(&dl->got)) != MELD_OK) return rc;
    if ((rc = plt_init(&dl->plt)) != MELD_OK) goto fail_plt;
    if ((rc = dynrel_init(&dl->dynrels)) != MELD_OK) goto fail_dynrel;
    if ((rc = veneer_mgr_init(&dl->veneers)) != MELD_OK) goto fail_veneer;
    if ((rc = dynamic_init(&dl->dynamic)) != MELD_OK) goto fail_dynamic;

    dl->gst = gst;
    dl->allow_textrel = false;
    dl->interp = NULL;
    return DYNLINK_OK;

fail_dynamic:
    veneer_mgr_destroy(&dl->veneers);
fail_veneer:
    dynrel_destroy(&dl->dynrels);
fail_dynrel:
    plt_destroy(&dl->plt);
fail_plt:
    got_destroy(&dl->got);
    return DYNLINK_ERR_NOMEM;
}

void dynlink_destroy(meld_dynlink_t *dl) {
    if (!dl) return;
    got_destroy(&dl->got);
    plt_destroy(&dl->plt);
    dynrel_destroy(&dl->dynrels);
    veneer_mgr_destroy(&dl->veneers);
    dynamic_destroy(&dl->dynamic);

    meld_needed_t *n = dl->needed;
    while (n) {
        meld_needed_t *next = n->next;
        free((void *)n->soname);
        free(n);
        n = next;
    }

    memset(dl, 0, sizeof(*dl));
}

int dynlink_configure(meld_dynlink_t *dl, meld_ctx_t *ctx) {
    if (!dl || !ctx) return DYNLINK_ERR_INTERNAL;

    dl->is_static = ctx->is_static;
    dl->is_pie = (ctx->output_type == ET_DYN && ctx->base_addr == 0);

    if (!dl->is_static) {
        dl->interp = ARM_INTERP_PATH;
    }

    return DYNLINK_OK;
}

int dynamic_init(meld_dynamic_t *d) {
    memset(d, 0, sizeof(*d));
    return MELD_OK;
}

void dynamic_destroy(meld_dynamic_t *d) {
    if (!d) return;
    meld_dyn_tag_t *t = d->tags;
    while (t) {
        meld_dyn_tag_t *next = t->next;
        free(t);
        t = next;
    }
    memset(d, 0, sizeof(*d));
}

size_t dynamic_size(const meld_dynamic_t *d) {
    return (d->count + 1) * sizeof(Elf32_Dyn);
}

size_t dynlink_dynamic_size(const meld_dynlink_t *dl) {
    return dl ? dynamic_size(&dl->dynamic) : 0;
}

size_t dynlink_interp_size(const meld_dynlink_t *dl) {
    if (!dl->interp) return 0;
    return strlen(dl->interp) + 1;
}