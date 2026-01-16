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

size_t dynlink_rel_plt_size(const meld_dynlink_t *dl) {
    if (dl->dynrels.rel_plt_count > 0)
        return dynrel_plt_size(&dl->dynrels);
    /* Calculate based on PLT entries, excluding PLT0 */
    return dl->plt.count * sizeof(Elf32_Rel);
}

size_t dynlink_veneer_size(const meld_dynlink_t *dl) {
    return dl ? veneer_mgr_size(&dl->veneers) : 0;
}

/* If relocation target is not in a writable section
 * Relevant for PIE; absolute relocations e.g., R_ARM_ABS32 require TEXTREL
 * which we should aim to avoid as this prevents text sharing between processes
 * and makes an executable section writable at load-time.
 */
static bool reloc_in_writable_section(meld_input_t *input, meld_reloc_t *rel) {
    if (!input || !rel) return false;
    elf_t *e = &input->elf;
    if (!ELF_IS_32(e) || rel->sec_ndx >= e->shnum) return false;
    return (elf_sh_flags(e, rel->sec_ndx) & SHF_WRITE) != 0;
}

/* Determines whether a reference to sym requires a dynamic relocation.
 * Can be avoided in the following cases:
 *     Static only linking
 *     Hidden/internal visibility: symbol is not exported
 *     Protected visibility: exported but non-interposable
 *
 * Resolution is needed where:
 *     The symbol is undefined within current object
 *     The symbol is eligible for interposition
 */
static bool symbol_needs_runtime_resolution(const meld_symbol_t *sym, bool is_static) {
    if (!sym) return false;
    if (is_static) return false;

    if (sym->state == SYM_UNDEFINED) return true;              /* Always require runtime resolution at this point */

    uint8_t vis = ELF32_ST_VISIBILITY(sym->st_other);
    if (vis == STV_HIDDEN || vis == STV_INTERNAL) return false;

    if (vis == STV_PROTECTED) return false;                    /* Condition comes after we've determined this is defined locally */

    uint8_t bind = ELF32_ST_BIND(sym->st_info);
    return (bind == STB_GLOBAL || bind == STB_WEAK);
}

/* Initial pass over all relocations to determine what dynamic structures are needed:
 *
 * R_ARM_GOT32, R_ARM_GOT_PREL, R_ARM_GOT_ABS request a GOT slot for the denoted symbol.
 *
 * R_ARM_CALL, R_ARM_JUMP24, R_ARM_PLT32 to external functions
 * need PLT[n] stub.
 *
 * Absolute relocations in read-only sections require the
 * text segment to be writable at load time. Error by default unless 
 * allow_textrel(default=False) is set.
 *
 * Final section sizes are computed during layout e.g., when we add reserved entries.
 */
int dynlink_scan_relocs(meld_dynlink_t *dl, meld_ctx_t *ctx) {
    if (!dl || !ctx) return DYNLINK_ERR_INTERNAL;

    for (uint32_t i = 0; i < ctx->input_count; i++) {
        meld_input_t *input = ctx->inputs[i];
        if (!input) continue;

        for (uint32_t j = 0; j < input->reloc_count; j++) {
            meld_reloc_t *rel = &input->relocs[j];
            uint8_t type = rel->type;

            meld_symbol_t *sym = NULL;
            if (rel->sym_idx > 0 && rel->sym_idx < input->elf.symtab_count) {
                sym = input->sym_map[rel->sym_idx];
            }

            /* Add GOT entries for purely GOT-related relocations */
            if (dynlink_needs_got_entry(type) && sym) {
                dl->needs_got = true;
                got_add(&dl->got, sym, false);
            }

            if (dynlink_needs_got_base(type)) {
                dl->needs_got = true;
            }

            bool is_undef = sym && (sym->state == SYM_UNDEFINED);
            bool is_shared = sym && (sym->state == SYM_SHARED);

            /* Accept both STT_FUNC and STT_NOTYPE (undefined symbols
             * in object files often have this type; promoted to STT_FUNC at runtime).
             */
            uint8_t sym_type = sym ? ELF32_ST_TYPE(sym->st_info) : STT_NOTYPE;
            bool is_func_or_notype = (sym_type == STT_FUNC || sym_type == STT_NOTYPE);
            bool needs_plt = dynlink_needs_plt_entry(type, is_undef, is_shared);

            if (needs_plt && is_func_or_notype) {
                if (sym->plt_offset < 0) {
                    plt_add(&dl->plt, sym, &dl->got);
                }
            }

            if (!dl->is_static && dl->is_pie && dynlink_is_abs_reloc(type)) {
                if (!reloc_in_writable_section(input, rel)) {
                    if (!dl->allow_textrel) {
                        SET_ERR(ctx, MELD_ERR_RELOC,
                                "TEXTREL: absolute relocation %s in non-writable section",
                                reloc_type_name(type));
                        return DYNLINK_ERR_TEXTREL;
                    }
                    dl->has_textrel = true;
                } else {
                    /* Absolute reloc in writable section; need R_ARM_RELATIVE */
                    dl->abs_data_reloc_count++;
                }
            }
        }
    }

    return DYNLINK_OK;
}

int dynlink_layout(meld_dynlink_t *dl,
                   uint32_t got_addr,
                   uint32_t gotplt_addr,
                   uint32_t plt_addr,
                   uint32_t dynamic_addr,
                   uint32_t text_end_addr) {
    if (!dl) return DYNLINK_ERR_INTERNAL;

    dl->got_addr = got_addr;
    dl->gotplt_addr = gotplt_addr;
    dl->plt_addr = plt_addr;
    dl->dynamic_addr = dynamic_addr;
    dl->veneer_addr = text_end_addr;
    
    /* Delegate ! */
    got_layout(&dl->got, got_addr, gotplt_addr);
    plt_layout(&dl->plt, plt_addr);
    veneer_mgr_layout(&dl->veneers, text_end_addr);

    /* Set synthetic symbol values now they can be computed */
    meld_symbol_t *sym;
    if ((sym = gst_lookup(dl->gst, "_DYNAMIC")) != NULL)
        sym->st_value = dynamic_addr;
    if ((sym = gst_lookup(dl->gst, "_GLOBAL_OFFSET_TABLE_")) != NULL)
        sym->st_value = gotplt_addr;

    return DYNLINK_OK;
}

/* Second pass: Generate dynamic relocations for the .rel.dyn and .rel.plt sections.
 *
 * For each GOT entry:
 *     PLT entries (.got.plt): R_ARM_JUMP_SLOT
 *     Global symbols: R_ARM_GLOB_DAT
 *
 * Defined symbols that don't need interposition are relaxed to R_ARM_RELATIVE
 * instead of R_ARM_GLOB_DAT. Works even if the symbol isn't exported to .dynsym as 
 * R_ARM_RELATIVE does not refer to a symbol.
 *     GOT[n] = foo_offset
 *     *(GOT[n]) += runtime_base_vaddr;
 *
 * For PIE, Absolute relocations in writable sections need R_ARM_RELATIVE to fix up the base address
 */
int dynlink_finalise_relocs(meld_dynlink_t *dl, meld_ctx_t *ctx) {
    if (!dl || !ctx) return DYNLINK_ERR_INTERNAL;
    if (dl->is_static) return DYNLINK_OK;

    /* GOT */
    for (meld_got_entry_t *e = dl->got.entries; e; e = e->next) {
        if (!e->sym) continue;

        /* Determine section membership */
        uint32_t offset = e->is_plt ? dl->gotplt_addr + e->got_offset
                                    : dl->got_addr + e->got_offset;

        bool needs_runtime = symbol_needs_runtime_resolution(e->sym, dl->is_static);

        if (e->is_plt) {
            uint32_t sym_idx = e->sym->dynsym_idx;
            dynrel_add_plt(&dl->dynrels, offset, sym_idx);
        } else if (!needs_runtime && e->sym->state == SYM_DEFINED) {
            dynrel_add_dyn(&dl->dynrels, offset, R_ARM_RELATIVE, 0);  /* Relax to cheaper relative relocation */
        } else {
            uint32_t sym_idx = e->sym->dynsym_idx;
            dynrel_add_dyn(&dl->dynrels, offset, R_ARM_GLOB_DAT, sym_idx);    /* Otherwise, select the default for .got entries */
        }
    }

    /* Scan for absolute relocations in writable sections; emit R_ARM_RELATIVE correspondingly */
    if (dl->is_pie) {
        for (uint32_t i = 0; i < ctx->input_count; i++) {
            meld_input_t *input = ctx->inputs[i];
            if (!input) continue;

            for (uint32_t j = 0; j < input->reloc_count; j++) {
                meld_reloc_t *rel = &input->relocs[j];
                uint8_t type = rel->type;

                
                if (!dynlink_is_abs_reloc(type)) continue;

                /* Refers to writable section(no support for textrel) */
                if (!reloc_in_writable_section(input, rel)) continue;

                /* Compute output address of referred place */
                meld_sec_state_t *sec_state = &input->sec_state[rel->sec_ndx];
                if (!sec_state || !sec_state->out) continue;

                uint32_t reloc_addr = sec_state->out->addr + sec_state->output_offset + rel->offset;
                dynrel_add_dyn(&dl->dynrels, reloc_addr, R_ARM_RELATIVE, 0);
            }
        }
    }

    return DYNLINK_OK;
}

size_t dynlink_got_size(const meld_dynlink_t *dl) {
    /* If layout hasn't been called yet then we compute size based on estimate */
    if (dl->got.got_size > 0) return dl->got.got_size;
    uint32_t got_entries = 0;
    for (meld_got_entry_t *e = dl->got.entries; e; e = e->next) {
        if (!e->is_plt) got_entries++;
    }
    return got_entries * 4;
}

size_t dynlink_gotplt_size(const meld_dynlink_t *dl) {
    if (dl->got.gotplt_size > 0) return dl->got.gotplt_size;
    uint32_t gotplt_entries = 3;  /* Reserved: _DYNAMIC, link_map, resolver stub */
    for (meld_got_entry_t *e = dl->got.entries; e; e = e->next) {
        if (e->is_plt) gotplt_entries++;
    }
    return gotplt_entries * 4;
}

size_t dynlink_plt_size(const meld_dynlink_t *dl) {
    if (dl->plt.plt_size > 0) return dl->plt.plt_size;
    if (dl->plt.count == 0) return 0;
    return ARM_PLT0_SIZE + (dl->plt.count * ARM_PLTN_SIZE);
}

size_t dynlink_rel_dyn_size(const meld_dynlink_t *dl) {
    /* If relocs haven't been finalised then we calculate size based on GOT entries
     * plus absolute data relocations that need R_ARM_RELATIVE 
     */
    if (dl->dynrels.rel_dyn_count > 0) 
        return dynrel_dyn_size(&dl->dynrels);
    
    uint32_t count = 0;
    for (meld_got_entry_t *e = dl->got.entries; e; e = e->next) {
        if (!e->is_plt) count++;
    }
    /* Add count of absolute data relocations needing R_ARM_RELATIVE */
    count += dl->abs_data_reloc_count;
    return count * sizeof(Elf32_Rel);
}

size_t dynlink_got_write(const meld_dynlink_t *dl, void *buf, size_t len) {
    if (!dl || !buf) return 0;

    size_t need = dl->got.got_size;
    if (len < need || need == 0) return 0;

    memset(buf, 0, need);
    uint32_t *words = (uint32_t *)buf;

    for (meld_got_entry_t *e = dl->got.entries; e; e = e->next) {
        if (e->is_plt) continue;
        uint32_t idx = e->got_offset / 4;
        if (e->sym && e->sym->state == SYM_DEFINED) {
            words[idx] = e->sym->st_value;
        }
    }

    return need;
}

size_t dynlink_gotplt_write(const meld_dynlink_t *dl, void *buf, size_t len) {
    if (!dl || !buf) return 0;

    size_t need = dl->got.gotplt_size;
    if (len < need || need == 0) return 0;

    memset(buf, 0, need);
    uint32_t *words = (uint32_t *)buf;

    words[0] = dl->dynamic_addr;
    words[1] = 0;  /* link_map* */
    words[2] = 0;  /* _dl_runtime_resolve */

    /* We init .got.plt[n] to point to each PLT[n]'s lazy binding portion at +12
     * See the auxiliary information regarding the plt instantiation in output.c
     */
    for (meld_got_entry_t *e = dl->got.entries; e; e = e->next) {
        if (!e->is_plt) continue;
        uint32_t idx = e->got_offset / 4;
        /* Find corresponding PLT entry to acquire offset */
        for (meld_plt_entry_t *pe = dl->plt.entries; pe; pe = pe->next) {
            if (pe->sym == e->sym) {
                words[idx] = dl->plt_addr + pe->plt_offset + 12;
                break;
            }
        }
    }

    return need;
}

size_t dynlink_plt_write(const meld_dynlink_t *dl, void *buf, size_t len) {
    return dl ? plt_write(&dl->plt, &dl->got, buf, len) : 0;
}

size_t dynlink_rel_dyn_write(const meld_dynlink_t *dl, void *buf, size_t len) {
    return dl ? dynrel_dyn_write(&dl->dynrels, buf, len) : 0;
}

size_t dynlink_rel_plt_write(const meld_dynlink_t *dl, void *buf, size_t len) {
    return dl ? dynrel_plt_write(&dl->dynrels, buf, len) : 0;
}

size_t dynlink_dynamic_write(const meld_dynlink_t *dl, void *buf, size_t len) {
    return dl ? dynamic_write(&dl->dynamic, buf, len) : 0;
}

size_t dynlink_veneer_write(const meld_dynlink_t *dl, void *buf, size_t len) {
    if (!dl || !buf) return 0;
    size_t sz = veneer_mgr_size(&dl->veneers);
    if (len < sz) return 0;

    const uint8_t *data = veneer_mgr_data(&dl->veneers);
    if (data && sz > 0) {
        memcpy(buf, data, sz);
    }
    return sz;
}

size_t dynlink_interp_write(const meld_dynlink_t *dl, void *buf, size_t len) {
    if (!buf || !dl->interp) return 0;

    size_t need = strlen(dl->interp) + 1;
    if (len < need) return 0;

    memcpy(buf, dl->interp, need);
    return need;
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

int dynamic_add(meld_dynamic_t *d, uint32_t tag, uint32_t val) {
    meld_dyn_tag_t *t = calloc(1, sizeof(*t));
    if (!t) return MELD_ERR_NOMEM;

    t->tag = tag;
    t->val = val;
    t->next = NULL;

    if (!d->tags) {
        d->tags = d->tail = t;
    } else {
        d->tail->next = t;
        d->tail = t;
    }
    d->count++;

    return MELD_OK;
}

size_t dynamic_write(const meld_dynamic_t *d, void *buf, size_t len) {
    if (!d || !buf) return 0;

    size_t need = dynamic_size(d);
    if (len < need) return 0;

    Elf32_Dyn *dyn = (Elf32_Dyn *)buf;
    uint32_t i = 0;

    for (meld_dyn_tag_t *t = d->tags; t; t = t->next, i++) {
        dyn[i].d_tag = t->tag;
        dyn[i].d_un.d_val = t->val;
    }

    dyn[i].d_tag = DT_NULL;  /* Mandatory */
    dyn[i].d_un.d_val = 0;

    return need;
}

int dynlink_build_dynamic(meld_dynlink_t *dl, meld_ctx_t *ctx,
                          uint32_t hash_addr, uint32_t strtab_addr, uint32_t strtab_size,
                          uint32_t symtab_addr, uint32_t init_addr, uint32_t fini_addr,
                          uint32_t init_array_addr, uint32_t init_array_size,
                          uint32_t fini_array_addr, uint32_t fini_array_size,
                          uint32_t preinit_array_addr, uint32_t preinit_array_size) {
    if (!dl || !ctx) return DYNLINK_ERR_INTERNAL;

    meld_dynamic_t *d = &dl->dynamic;

    /* DT_NEEDED entries first (convention) */
    for (meld_needed_t *n = dl->needed; n; n = n->next) {
        dynamic_add(d, DT_NEEDED, n->strtab_offset);
    }
    
    if (hash_addr)   dynamic_add(d, DT_GNU_HASH, hash_addr);
    if (strtab_addr) dynamic_add(d, DT_STRTAB, strtab_addr);
    if (strtab_size) dynamic_add(d, DT_STRSZ, strtab_size);
    if (symtab_addr) dynamic_add(d, DT_SYMTAB, symtab_addr);

    dynamic_add(d, DT_SYMENT, sizeof(Elf32_Sym));

    if (dl->plt.count > 0) {
        dynamic_add(d, DT_PLTGOT, dl->gotplt_addr);
        dynamic_add(d, DT_PLTRELSZ, dynlink_rel_plt_size(dl));
        dynamic_add(d, DT_PLTREL, DT_REL);
        dynamic_add(d, DT_JMPREL, dl->rel_plt_addr);
    }

    /* Check for non-PLT GOT entries that need .rel.dyn */
    size_t rel_dyn_sz = dynlink_rel_dyn_size(dl);
    if (rel_dyn_sz > 0) {
        dynamic_add(d, DT_REL, dl->rel_dyn_addr);
        dynamic_add(d, DT_RELSZ, rel_dyn_sz);
        dynamic_add(d, DT_RELENT, sizeof(Elf32_Rel));
    }

    /* Legacy */
    if (init_addr) dynamic_add(d, DT_INIT, init_addr);
    if (fini_addr) dynamic_add(d, DT_FINI, fini_addr);

    /* Modern init/fini arrays */
    if (preinit_array_addr && preinit_array_size > 0) {
        dynamic_add(d, DT_PREINIT_ARRAY, preinit_array_addr);
        dynamic_add(d, DT_PREINIT_ARRAYSZ, preinit_array_size);
    }
    if (init_array_addr && init_array_size > 0) {
        dynamic_add(d, DT_INIT_ARRAY, init_array_addr);
        dynamic_add(d, DT_INIT_ARRAYSZ, init_array_size);
    }
    if (fini_array_addr && fini_array_size > 0) {
        dynamic_add(d, DT_FINI_ARRAY, fini_array_addr);
        dynamic_add(d, DT_FINI_ARRAYSZ, fini_array_size);
    }

    if (dl->has_textrel) {
        dynamic_add(d, DT_TEXTREL, 0);
    }

    /* DT_FLAGS and DT_FLAGS_1 for bind-now / RELRO */
    uint32_t flags = 0;
    uint32_t flags1 = 0;
    if (ctx->bind_now) {
        flags |= DF_BIND_NOW;
        flags1 |= DF_1_NOW;
    }
    if (flags) dynamic_add(d, DT_FLAGS, flags);
    if (flags1) dynamic_add(d, DT_FLAGS_1, flags1);

    return DYNLINK_OK;
}

int dynlink_add_needed(meld_dynlink_t *dl, const char *soname) {
    if (!dl || !soname) return DYNLINK_ERR_INTERNAL;

    meld_needed_t *n = calloc(1, sizeof(*n));
    if (!n) return DYNLINK_ERR_NOMEM;

    n->soname = strdup(soname);
    if (!n->soname) {
        free(n);
        return DYNLINK_ERR_NOMEM;
    }

    if (dl->needed_tail) {
        dl->needed_tail->next = n;
    } else {
        dl->needed = n;
    }
    dl->needed_tail = n;
    dl->needed_count++;

    return DYNLINK_OK;
}
