/* 
     #####   ##    ##       ##### ##       ##### /           ##### ##    
  ######  /#### #####    ######  /### / ######  /         /#####  /##    
 /#   /  /  ##### ##### /#   /  / ###/ /#   /  /        //    /  / ###   
/    /  /   # ##  # ## /    /  /   ## /    /  /        /     /  /   ###  
    /  /    #     #        /  /           /  /              /  /     ### 
   ## ##    #     #       ## ##          ## ##             ## ##      ## 
   ## ##    #     #       ## ##          ## ##             ## ##      ## 
   ## ##    #     #       ## ######      ## ##             ## ##      ## 
   ## ##    #     #       ## #####       ## ##             ## ##      ## 
   ## ##    #     ##      ## ##          ## ##             ## ##      ## 
   #  ##    #     ##      #  ##          #  ##             #  ##      ## 
      /     #      ##        /              /                 /       /  
  /##/      #      ##    /##/         / /##/           / /###/       /   
 /  #####           ##  /  ##########/ /  ############/ /   ########/    
/     ##               /     ######   /     #########  /       ####      
#                      #              #                #                 
 ##                     ##             ##               ## 
 
 * meld.c - Static linker for ARM32 (EM_ARM) objects.
 * 
 * It should be noted, the majority of the ideas and background for symbol resolution, reloc processing, etc, come from my personal notes.
 * Please feel free to have a read. They are often cited where relevant algorithms and ideas have been derived from them.
 * https://github.com/Enfey/UoN-CS-MSci-Notes/tree/main/Semester%201%20Y3/Linkers%20and%20Loaders/Chapters
 * 
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld.h"
#include "meld_archive.h"
#include "meld_symbol.h"
#include "meld_input.h"
#include "meld_section.h"
#include "meld_dynlink.h"
#include "meld_layout.h"
#include "meld_output.h"
#include "meld_synthetic.h"
#include "meld_reloc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>  /* access() */

/* Should probably move to meld_ctx_t */
static meld_needed_t *g_shared_libs = NULL;
static meld_needed_t *g_shared_libs_tail = NULL;

int meld_init(meld_ctx_t *ctx) {
    if (!ctx) return MELD_ERR_INTERNAL;
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->gst = calloc(1, sizeof(struct meld_gst));
    if (!ctx->gst) return MELD_ERR_NOMEM;
    
    int rc = gst_init(ctx->gst);
    if (rc != MELD_OK) {
        free(ctx->gst);
        ctx->gst = NULL;
        return rc;
    }
    
    /* Do immediately, prior to adding input objects */
    rc = synth_predefine_linker_symbols(ctx->gst);
    if (rc != MELD_OK) {
        gst_destroy(ctx->gst);
        free(ctx->gst);
        ctx->gst = NULL;
        return rc;
    }
    
    /* Default to PIE, Partial RELRO, and lazy .got.plt binding (though like is mentioned in
     * other comments, musl(our stdlib target) doesn't actually support lazy binding like glibc
     * and does its absolute best to avoid lazy resolution).
     */
    ctx->output_type = ET_DYN;
    ctx->base_addr = 0;
    ctx->is_static = false;
    ctx->relro = true;
    ctx->bind_now = false;
    
    return MELD_OK;
}

void meld_destroy(meld_ctx_t *ctx) {
    if (!ctx) return;
    
    for (uint32_t i = 0; i < ctx->input_count; i++) {
        input_destroy(ctx->inputs[i]);
    }
    free(ctx->inputs);
    
    for (uint32_t i = 0; i < ctx->archive_count; i++) {
        archive_close(ctx->archives[i]);
    }
    free(ctx->archives);
    
    for (uint32_t i = 0; i < ctx->lib_path_count; i++) {
        free(ctx->lib_paths[i]);
    }
    free(ctx->lib_paths);
    
    if (ctx->gst) {
        gst_destroy(ctx->gst);
        free(ctx->gst);
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

int meld_add_input(meld_ctx_t *ctx, const char *path) {
    if (!ctx || !path) return MELD_ERR_INTERNAL;
    
    meld_input_t *inp = input_create(path);
    if (!inp) {
        SET_ERR(ctx, MELD_ERR_IO, "failed to open input: %s", path);
        return MELD_ERR_IO;
    }
    
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
    
    inp->idx = ctx->input_count;
    ctx->inputs[ctx->input_count++] = inp;
    
    int rc = input_parse_symbols(inp, ctx->gst);
    if (rc != MELD_OK) {
        SET_ERR(ctx, rc, "symbol parse error in %s", path);
        return rc;
    }
    
    return MELD_OK;
}

int meld_add_archive(meld_ctx_t *ctx, const char *path) {
    if (!ctx || !path) return MELD_ERR_INTERNAL;
    
    meld_archive_t *ar = archive_open(path);
    if (!ar) {
        SET_ERR(ctx, MELD_ERR_IO, "failed to open archive: %s", path);
        return MELD_ERR_IO;
    }
    
    if (ctx->archive_count >= ctx->archive_cap) {
        uint32_t new_cap = ctx->archive_cap ? ctx->archive_cap * 2 : 8;
        meld_archive_t **new_arr = realloc(ctx->archives, new_cap * sizeof(*new_arr));
        if (!new_arr) {
            archive_close(ar);
            return MELD_ERR_NOMEM;
        }
        ctx->archives = new_arr;
        ctx->archive_cap = new_cap;
    }
    
    ar->index = ctx->archive_count;
    ar->group_id = ctx->current_group_id;  /* Inherited */
    ctx->archives[ctx->archive_count++] = ar;
    
    return MELD_OK;
}

/* Add a shared lib dependency, recording library for DT_NEEDED and imports its symbols
 * as requiring runtime resolution as defined in symbol.c/h
 */
int meld_add_shared_lib(meld_ctx_t *ctx, const char *path) {
    if (!ctx || !path) return MELD_ERR_INTERNAL;
    
    /* Open .so */
    elf_t elf;
    int rc = elf_open(&elf, path);
    if (rc != 0) {
        SET_ERR(ctx, MELD_ERR_IO, "failed to open shared library: %s", path);
        return MELD_ERR_IO;
    }
    
    if (!ELF_IS_32(&elf) || elf.elf_type != ET_DYN) {
        SET_ERR(ctx, MELD_ERR_NOT_OBJECT, "not a 32-bit shared object: %s", path);
        elf_close(&elf);
        return MELD_ERR_NOT_OBJECT;
    }
    
    /* Acquire SONAME from .dynamic */
    const char *soname = NULL;
    if (elf.e32.dynamic && elf.dynstr) {
        for (uint32_t i = 0; i < elf.dynamic_count; i++) {
            if (elf.e32.dynamic[i].d_tag == DT_SONAME) {
                uint32_t str_off = elf.e32.dynamic[i].d_un.d_val;
                if (str_off < elf.dynstr_size) {
                    soname = elf.dynstr + str_off;
                }
                break;
            }
            if (elf.e32.dynamic[i].d_tag == DT_NULL) break;
        }
    }
    
    /* Otherwise, fall back to basename if no SONAME */
    if (!soname) {
        soname = strrchr(path, '/');
        soname = soname ? soname + 1 : path;
    }
    
    /* Register symbols from .dynsym as shared library symbols; import only those symbols that are 
     * actually needed (already undef in GST)
     */
    if (elf.e32.dynsym && elf.dynstr) {
        for (uint32_t i = 1; i < elf.dynsym_count; i++) {  /* STN_UNDEF skipped */
            Elf32_Sym *sym = &elf.e32.dynsym[i];
            uint8_t bind = ELF32_ST_BIND(sym->st_info);
            
            /* Only global/weak defined symbols */
            if ((bind == STB_GLOBAL || bind == STB_WEAK) && sym->st_shndx != SHN_UNDEF) {
                if (sym->st_name >= elf.dynstr_size) continue;
                const char *name = elf.dynstr + sym->st_name;
                if (name[0] == '\0') continue;
                
                meld_symbol_t *existing = gst_lookup(ctx->gst, name);
                if (!existing || existing->state != SYM_UNDEFINED) continue;
                
                /* Marked for runtime resolution  */
                meld_symbol_t *shared = symbol_create_shared(name, sym->st_info, sym->st_other,
                                                              sym->st_size, soname);
                if (shared) {
                    meld_symbol_t *out;
                    if (gst_insert(ctx->gst, shared, &out) != MELD_OK || out != shared) {
                        symbol_destroy(shared);
                    }
                }
            }
        }
    }
    
    /* Add to dynlink later */
    meld_needed_t *needed = calloc(1, sizeof(*needed));
    if (!needed) {
        elf_close(&elf);
        return MELD_ERR_NOMEM;
    }
    needed->soname = strdup(soname);
    needed->path = strdup(path);
    needed->next = NULL;
    
    elf_close(&elf);
    
    fprintf(stderr, "meld: added shared library %s (soname: %s)\n", path, needed->soname);
    
    /* Transfer to dynlink during link-step */
    if (!g_shared_libs) {
        g_shared_libs = needed;
        g_shared_libs_tail = needed;
    } else {
        g_shared_libs_tail->next = needed;
        g_shared_libs_tail = needed;
    }
    
    return MELD_OK;
}

void meld_set_output_type(meld_ctx_t *ctx, uint16_t type) {
    if (!ctx) return;
    ctx->output_type = type;
    ctx->base_addr = (type == ET_EXEC) ? 0x10000 : 0;
}

/* BEHOLD! */
int meld_link(meld_ctx_t *ctx) {
    if (!ctx) return MELD_ERR_INTERNAL;

    meld_section_mgr_t sections;
    meld_dynlink_t dynlink;
    meld_layout_t layout;
    int rc;

    rc = section_mgr_init(&sections);
    if (rc != 0) {
        SET_ERR(ctx, rc, "section manager init failed");
        return MELD_ERR_NOMEM;
    }

    rc = section_collect_all(ctx, &sections);
    if (rc != MELD_OK) {
        SET_ERR(ctx, rc,  "section collection failed");
        section_mgr_destroy(&sections);
        return MELD_ERR_INTERNAL;
    }

    /* Assign section indices immmediately so symtab_add can compute st_shndx */
    section_assign_indices(&sections);

    /* Parse ALL relocations*/
    for (uint32_t i = 0; i < ctx->input_count; i++) {
        rc = reloc_parse_input(ctx->inputs[i]);
        if (rc != MELD_OK) {
            SET_ERR(ctx, rc, "reloc parse failed for input %u", i);
            section_mgr_destroy(&sections);
            return rc;
        }
    }

    rc = section_layout(&sections);
    if (rc != 0) {
        SET_ERR(ctx, rc, "section layout failed");
        section_mgr_destroy(&sections);
        return MELD_ERR_NOMEM;
    }

    rc = dynlink_init(&dynlink, ctx->gst);
    if (rc != 0) {
        SET_ERR(ctx, rc, "dynlink init failed");
        section_mgr_destroy(&sections);
        return MELD_ERR_NOMEM;
    }
    dynlink_configure(&dynlink, ctx);

    /* Transfer shared lib needed entries */
    for (meld_needed_t *n = g_shared_libs; n; n = n->next) {
        dynlink_add_needed(&dynlink, n->soname);
    }

    rc = dynlink_scan_relocs(&dynlink, ctx);
    if (rc != DYNLINK_OK) {
        SET_ERR(ctx, rc, "reloc scan failed");
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_RELOC;
    }

    meld_output_ext_t output_ext;
    rc = meld_output_ext_init(&output_ext);
    if (rc != MELD_OK) {
        SET_ERR(ctx, rc, "output ext init failed");
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_NOMEM;
    }

    /* Parse version script if provided - sets sym->version_ndx on GST symbols
     * Done before meld_output_ext_build which populates .gnu.version
     */
    if (ctx->version_script) {
        rc = version_script_load(ctx, &output_ext.version, ctx->version_script);
        if (rc != MELD_OK) {
            fprintf(stderr, "meld: warning: failed to load version script '%s'\n", ctx->version_script);
        }
    }

    rc = meld_output_ext_build(ctx, &output_ext, !ctx->is_static);
    if (rc != MELD_OK) {
        SET_ERR(ctx, rc, "output ext build failed");
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_INTERNAL;
    }

    /* Add DT_NEEDED sonames to .dynstr and store offsets in dynlink */
    if (!ctx->is_static) {
        for (meld_needed_t *n = dynlink.needed; n; n = n->next) {
            n->strtab_offset = strtab_add(&output_ext.dynsym.strtab, n->soname);
        }
        
        /* Add version strings to .dynstr */
        version_add_strings_to_strtab(&output_ext.version, &output_ext.dynsym.strtab);
    }
    
    /* Static executables with GOT-oriented relocs still need .got section, 
     * such entries are filled at link time
     */
    if (ctx->is_static && dynlink.needs_got) {
        size_t got_sz = dynlink.got.count * 4;
        if (got_sz < 4) got_sz = 4;
        section_add_synthetic(&sections, ".got", OSEC_ALLOC | OSEC_WRITE, SHT_PROGBITS, 4, got_sz);
    }

    /* Always emit*/
    size_t symtab_sz = output_ext.symtab.count * sizeof(Elf32_Sym);
    size_t strtab_sz = strtab_size(&output_ext.symtab.strtab);
    if (symtab_sz > 0)
        section_add_synthetic(&sections, ".symtab", 0, SHT_SYMTAB, 4, symtab_sz);
    if (strtab_sz > 0)
        section_add_synthetic(&sections, ".strtab", 0, SHT_STRTAB, 1, strtab_sz);

    /* Add dynamic linking specific sections */
    if (!ctx->is_static) {
        size_t got_sz = dynlink_got_size(&dynlink);
        size_t gotplt_sz = dynlink_gotplt_size(&dynlink);
        size_t plt_sz = dynlink_plt_size(&dynlink);
        size_t reldyn_sz = dynlink_rel_dyn_size(&dynlink);
        size_t relplt_sz = dynlink_rel_plt_size(&dynlink);
        size_t interp_sz = dynlink_interp_size(&dynlink);
        /* Dynamic section size determined later after build */
        size_t dynamic_sz = 256;  /* Initial estimate to be updated */

        size_t dynsym_sz = output_ext.dynsym.count * sizeof(Elf32_Sym);
        size_t dynstr_sz = strtab_size(&output_ext.dynsym.strtab);
        size_t gnuhash_sz = gnu_hash_size(&output_ext.gnu_hash);

        /* Create .got if we have entries OR if need a GOT base for GOTPC/GOTOFF */
        if (got_sz > 0 || dynlink.needs_got)
            section_add_synthetic(&sections, ".got", OSEC_ALLOC | OSEC_WRITE, SHT_PROGBITS, 4, got_sz > 0 ? got_sz : 4);
        if (gotplt_sz > 0)
            section_add_synthetic(&sections, ".got.plt", OSEC_ALLOC | OSEC_WRITE, SHT_PROGBITS, 4, gotplt_sz);
        if (plt_sz > 0)
            section_add_synthetic(&sections, ".plt", OSEC_ALLOC | OSEC_EXEC, SHT_PROGBITS, 4, plt_sz);
        if (reldyn_sz > 0)
            section_add_synthetic(&sections, ".rel.dyn", OSEC_ALLOC, SHT_REL, 4, reldyn_sz);
        if (relplt_sz > 0)
            section_add_synthetic(&sections, ".rel.plt", OSEC_ALLOC, SHT_REL, 4, relplt_sz);
        if (interp_sz > 0)
            section_add_synthetic(&sections, ".interp", OSEC_ALLOC, SHT_PROGBITS, 1, interp_sz);
        if (ctx->output_type == ET_DYN || dynlink.needs_got)
            section_add_synthetic(&sections, ".dynamic", OSEC_ALLOC | OSEC_WRITE, SHT_DYNAMIC, 4, dynamic_sz);
        
        /* Add symbol table related sections */
        if (dynsym_sz > 0)
            section_add_synthetic(&sections, ".dynsym", OSEC_ALLOC, SHT_DYNSYM, 4, dynsym_sz);
        if (dynstr_sz > 0)
            section_add_synthetic(&sections, ".dynstr", OSEC_ALLOC, SHT_STRTAB, 1, dynstr_sz);
        if (gnuhash_sz > 0)
            section_add_synthetic(&sections, ".gnu.hash", OSEC_ALLOC, SHT_GNU_HASH, 4, gnuhash_sz);

        /* Add versioning sections if we have version definitions */
        size_t versym_sz = version_versym_size(&output_ext.version);
        size_t verdef_sz = version_verdef_size(&output_ext.version);
        size_t verneed_sz = version_verneed_size(&output_ext.version);

        if (versym_sz > 0)
            section_add_synthetic(&sections, ".gnu.version", OSEC_ALLOC, SHT_GNU_versym, 2, versym_sz);
        if (verdef_sz > 0)
            section_add_synthetic(&sections, ".gnu.version_d", OSEC_ALLOC, SHT_GNU_verdef, 4, verdef_sz);
        if (verneed_sz > 0)
            section_add_synthetic(&sections, ".gnu.version_r", OSEC_ALLOC, SHT_GNU_verneed, 4, verneed_sz);
    }

    /* Re-assign indices after adding synthetic */
    section_assign_indices(&sections);

    /* Re-layout */
    rc = section_layout(&sections);
    if (rc != 0) {
        SET_ERR(ctx, rc, "section layout failed (with synthetics)");
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_NOMEM;
    }

    /* Finalising header fields*/
    section_finalise_structure(&sections,
                               output_ext.symtab.first_global,
                               output_ext.version.verdef_count,
                               output_ext.version.verneed_count);

    rc = layout_init(&layout, &sections, &dynlink);
    if (rc != 0) {
        SET_ERR(ctx, rc, "layout init failed");
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_NOMEM;
    }
    layout_configure(&layout, ctx);

    rc = layout_assign_addresses(&layout, ctx->base_addr);
    if (rc != 0) {
        SET_ERR(ctx, rc, "address assignment failed");
        layout_destroy(&layout);
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_INTERNAL;
    }

    /* Find section addresses for dynlink configuration */
    meld_osec_t *got_sec = section_find(&sections, ".got");
    meld_osec_t *gotplt_sec = section_find(&sections, ".got.plt");
    meld_osec_t *plt_sec = section_find(&sections, ".plt");
    meld_osec_t *dynamic_sec = section_find(&sections, ".dynamic");
    meld_osec_t *text_sec = section_find(&sections, ".text");
    meld_osec_t *interp_sec = section_find(&sections, ".interp");
    
    meld_osec_t *dynsym_sec = section_find(&sections, ".dynsym");
    meld_osec_t *dynstr_sec = section_find(&sections, ".dynstr");
    meld_osec_t *gnuhash_sec = section_find(&sections, ".gnu.hash");
    
    meld_osec_t *init_array_sec = section_find(&sections, ".init_array");
    meld_osec_t *fini_array_sec = section_find(&sections, ".fini_array");
    meld_osec_t *preinit_array_sec = section_find(&sections, ".preinit_array");

    uint32_t text_end = text_sec ? (text_sec->addr + text_sec->size) : ctx->base_addr;
    
    /* Set interpreter address for PT_INTERP */
    if (interp_sec)
        dynlink.interp_addr = interp_sec->addr;
    
    /* Layout dynlink structures and set synthetic symbol values (_DYNAMIC, _GOT_, etc.) */
    dynlink_layout(&dynlink,
                   got_sec ? got_sec->addr : 0,
                   gotplt_sec ? gotplt_sec->addr : 0,
                   plt_sec ? plt_sec->addr : 0,
                   dynamic_sec ? dynamic_sec->addr : 0,
                   text_end);

    /* Update symbol st_value to final output addresses */
    for (uint32_t i = 0; i < ctx->input_count; i++) {
        input_update_symbol_values(ctx->inputs[i]);
    }

    /* Update symtab/dynsym entries with final symbol addresses (after dynlink_layout) */
    meld_output_ext_update_symtab_values(ctx, &output_ext);
    if (!ctx->is_static) {
        meld_output_ext_update_dynsym_values(ctx, &output_ext);
    }

    /* Construct .dynamic/DT_* entries */
    if (!ctx->is_static && dynamic_sec) {
        meld_osec_t *reldyn_sec = section_find(&sections, ".rel.dyn");
        meld_osec_t *relplt_sec = section_find(&sections, ".rel.plt");
        
        /* DT_REL/DT_JMPREL entries */
        if (reldyn_sec) dynlink.rel_dyn_addr = reldyn_sec->addr;
        if (relplt_sec) dynlink.rel_plt_addr = relplt_sec->addr;
        
        rc = dynlink_build_dynamic(&dynlink, ctx,
                                   gnuhash_sec ? gnuhash_sec->addr : 0,
                                   dynstr_sec ? dynstr_sec->addr : 0,
                                   dynstr_sec ? dynstr_sec->size : 0,
                                   dynsym_sec ? dynsym_sec->addr : 0,
                                   0,  /* init_addr */
                                   0,  /* fini_addr */
                                   init_array_sec ? init_array_sec->addr : 0,
                                   init_array_sec ? init_array_sec->size : 0,
                                   fini_array_sec ? fini_array_sec->addr : 0,
                                   fini_array_sec ? fini_array_sec->size : 0,
                                   preinit_array_sec ? preinit_array_sec->addr : 0,
                                   preinit_array_sec ? preinit_array_sec->size : 0);
        if (rc != 0) {
            SET_ERR(ctx, rc, "dynamic section build failed");
            layout_destroy(&layout);
            meld_output_ext_destroy(&output_ext);
            dynlink_destroy(&dynlink);
            section_mgr_destroy(&sections);
            return MELD_ERR_INTERNAL;
        }

        /* Add versioning DT_* entries, if we have need for them */
        meld_osec_t *versym_sec = section_find(&sections, ".gnu.version");
        meld_osec_t *verdef_sec = section_find(&sections, ".gnu.version_d");
        meld_osec_t *verneed_sec = section_find(&sections, ".gnu.version_r");
        
        if (versym_sec) {
            dynamic_add(&dynlink.dynamic, DT_VERSYM, versym_sec->addr);
        }
        if (verdef_sec) {
            dynamic_add(&dynlink.dynamic, DT_VERDEF, verdef_sec->addr);
            dynamic_add(&dynlink.dynamic, DT_VERDEFNUM, output_ext.version.verdef_count);
        }
        if (verneed_sec) {
            dynamic_add(&dynlink.dynamic, DT_VERNEED, verneed_sec->addr);
            dynamic_add(&dynlink.dynamic, DT_VERNEEDNUM, output_ext.version.verneed_count);
        }

        /* Section size updated */
        dynamic_sec->size = dynlink_dynamic_size(&dynlink);
    }

    rc = dynlink_finalise_relocs(&dynlink, ctx);
    if (rc != DYNLINK_OK) {
        SET_ERR(ctx, rc, "reloc finalisation failed");
        layout_destroy(&layout);
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_RELOC;
    }

    rc = layout_build_shstrtab(&layout);
    if (rc != 0) {
        SET_ERR(ctx, rc, "shstrtab build failed");
        layout_destroy(&layout);
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_INTERNAL;
    }

    rc = layout_generate_phdrs(&layout);
    if (rc != 0) {
        SET_ERR(ctx, rc, "program header generation failed");
        layout_destroy(&layout);
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_INTERNAL;
    }

    /* Resolve _start full address (could maybe just attach to structure/ctx to save this lookup but 
     * relatively minor performance gain at this point) 
     */
    meld_symbol_t *start_sym = gst_lookup(ctx->gst, "_start");
    if (start_sym && start_sym->state == SYM_DEFINED) {
        layout.entry_addr = start_sym->st_value;
    }
    ctx->entry_addr = layout.entry_addr;

    layout.shdr_off = ALIGN_UP(layout.file_size, 4);
    layout.shdr_count = sections.count + 2; /* NULL + .shstrtab */
    layout.shstrtab_off = layout.shdr_off + layout.shdr_count * sizeof(Elf32_Shdr);
    layout.file_size = layout.shstrtab_off + layout.shstrtab_size;

    int fd = open(ctx->output_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        SET_ERR(ctx, MELD_ERR_IO, "cannot create %s", ctx->output_path);
        layout_destroy(&layout);
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_IO;
    }

    void *buf = calloc(1, layout.file_size);
    if (!buf) {
        close(fd);
        layout_destroy(&layout);
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_NOMEM;
    }

    layout_ehdr_write(&layout, buf, sizeof(Elf32_Ehdr), ctx->output_type);
    layout_phdrs_write(&layout, (char *)buf + layout.phdr_off, layout.phdr_count * sizeof(Elf32_Phdr));

    /* Write section data - both input sections and synthetic sections */
    for (meld_osec_t *osec = sections.sections; osec; osec = osec->next) {
        if (osec->flags & OSEC_NOBITS) continue;
        
        /* Synthetic */
        if (osec->flags & OSEC_SYNTHETIC) {
            char *dest = (char *)buf + osec->file_off;
            const char *name = osec->name;
            
            if (strcmp(name, ".got") == 0) {
                dynlink_got_write(&dynlink, dest, osec->size);
            } else if (strcmp(name, ".got.plt") == 0) {
                dynlink_gotplt_write(&dynlink, dest, osec->size);
            } else if (strcmp(name, ".plt") == 0) {
                dynlink_plt_write(&dynlink, dest, osec->size);
            } else if (strcmp(name, ".dynamic") == 0) {
                dynlink_dynamic_write(&dynlink, dest, osec->size);
            } else if (strcmp(name, ".rel.dyn") == 0) {
                dynlink_rel_dyn_write(&dynlink, dest, osec->size);
            } else if (strcmp(name, ".rel.plt") == 0) {
                dynlink_rel_plt_write(&dynlink, dest, osec->size);
            } else if (strcmp(name, ".interp") == 0) {
                dynlink_interp_write(&dynlink, dest, osec->size);
            } else if (strcmp(name, ".dynsym") == 0) {
                memcpy(dest, output_ext.dynsym.syms, output_ext.dynsym.count * sizeof(Elf32_Sym));
            } else if (strcmp(name, ".dynstr") == 0) {
                memcpy(dest, strtab_data(&output_ext.dynsym.strtab), strtab_size(&output_ext.dynsym.strtab));
            } else if (strcmp(name, ".gnu.hash") == 0) {
                gnu_hash_write(&output_ext.gnu_hash, dest, osec->size);
            } else if (strcmp(name, ".gnu.version") == 0) {
                version_versym_write(&output_ext.version, dest, osec->size);
            } else if (strcmp(name, ".gnu.version_d") == 0) {
                version_verdef_write(&output_ext.version, dest, osec->size);
            } else if (strcmp(name, ".gnu.version_r") == 0) {
                version_verneed_write(&output_ext.version, dest, osec->size);
            } else if (strcmp(name, ".symtab") == 0) {
                memcpy(dest, output_ext.symtab.syms, output_ext.symtab.count * sizeof(Elf32_Sym));
            } else if (strcmp(name, ".strtab") == 0) {
                memcpy(dest, strtab_data(&output_ext.symtab.strtab), strtab_size(&output_ext.symtab.strtab));
            }
            continue;
        }
        
        /* Handle general input object sections */
        for (meld_isec_t *isec = osec->isecs; isec; isec = isec->next) {
            elf_t *elf = input_elf(isec->input);
            uint32_t sh_type = elf_sh_type(elf, isec->shndx);
            if (sh_type == SHT_NOBITS) continue;

            const void *data = elf_sh_data(elf, isec->shndx);
            uint64_t size = elf_sh_size(elf, isec->shndx);
            if (data && size > 0) {
                memcpy((char *)buf + osec->file_off + isec->output_off, data, size);
            }
        }
    }

    /* Apply relocs to final output buffer */
    for (uint32_t i = 0; i < ctx->input_count; i++) {
        meld_input_t *inp = ctx->inputs[i];
        rc = reloc_apply_input(inp, ctx, &dynlink.got, dynlink.plt.plt_addr, NULL, buf);
        if (rc != MELD_OK) {
            /* reloc_apply_input() sets error on ctx */
            fprintf(stderr, "meld: %s\n", meld_strerror(ctx));
            free(buf);
            close(fd);
            layout_destroy(&layout);
            meld_output_ext_destroy(&output_ext);
            dynlink_destroy(&dynlink);
            section_mgr_destroy(&sections);
            return rc;
        }
    }

    layout_shdrs_write(&layout, (char *)buf + layout.shdr_off, layout.shdr_count * sizeof(Elf32_Shdr));
    layout_shstrtab_write(&layout, (char *)buf + layout.shstrtab_off, layout.shstrtab_size);

    ssize_t written = write(fd, buf, layout.file_size);
    free(buf);
    close(fd);

    if (written != (ssize_t)layout.file_size) {
        SET_ERR(ctx, MELD_ERR_IO, "write failed: wrote %zd of %u bytes", written, layout.file_size);
        layout_destroy(&layout);
        meld_output_ext_destroy(&output_ext);
        dynlink_destroy(&dynlink);
        section_mgr_destroy(&sections);
        return MELD_ERR_IO;
    }

    printf("meld: wrote %s (%u bytes, %u sections, %u phdrs)\n",
           ctx->output_path, layout.file_size, sections.count, layout.phdr_count);

    layout_destroy(&layout);
    meld_output_ext_destroy(&output_ext);
    dynlink_destroy(&dynlink);
    section_mgr_destroy(&sections);
    return MELD_OK;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] file...\n"
        "Options:\n"
        "  -h, --help         Show this help message\n"
        "  -o <file>          Output file (default: a.out)\n"
        "  -static            Create fully static executable\n"
        "  -shared            Create shared object (ET_DYN)\n"
        "  -pie               Create position-independent executable (default)\n"
        "  -no-pie            Create traditional executable (ET_EXEC @ 0x10000)\n"
        "  -z relro           Enable partial RELRO (default)\n"
        "  -z norelro         Disable RELRO\n"
        "  -z now             Full RELRO - eager bind PLT\n"
        "  -z lazy            Lazy PLT binding\n"
        "  --start-group      Begin archive group (for cyclic deps)\n"
        "  --end-group        End archive group\n"
        "  --version-script=<file>  Symbol versioning script\n"
        "  -l<lib>            Link against lib<lib>.a\n"
        "  -L<dir>            Add library search path\n",
        prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return MELD_ERR_INTERNAL;
    }

    meld_ctx_t ctx;
    int rc = meld_init(&ctx);
    if (rc != MELD_OK) {
        fprintf(stderr, "meld: failed to initialise context\n");
        return MELD_ERR_INTERNAL;
    }

    ctx.output_path = "a.out";

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            meld_destroy(&ctx);
            return MELD_OK;
        } else if (strcmp(arg, "-o") == 0 && i + 1 < argc) {
            ctx.output_path = argv[++i];
        } else if (strcmp(arg, "-static") == 0) {
            ctx.is_static = true;
            meld_set_output_type(&ctx, ET_EXEC);  /* Static executables use ET_EXEC */
        } else if (strcmp(arg, "-shared") == 0) {
            /* Potentially add support for .so if I get the time */
            meld_set_output_type(&ctx, ET_DYN);
        } else if (strcmp(arg, "-pie") == 0) {
            meld_set_output_type(&ctx, ET_DYN);  /* PIE is ET_DYN with entry */
        } else if (strcmp(arg, "-no-pie") == 0) {
            meld_set_output_type(&ctx, ET_EXEC); /* Traditional fixed-address executable */
        } else if (strcmp(arg, "-z") == 0 && i + 1 < argc) {
            const char *zopt = argv[++i];
            if (strcmp(zopt, "relro") == 0) ctx.relro = true;
            else if (strcmp(zopt, "norelro") == 0) ctx.relro = false;
            else if (strcmp(zopt, "now") == 0) ctx.bind_now = true;
            else if (strcmp(zopt, "lazy") == 0) ctx.bind_now = false;
            else fprintf(stderr, "meld: unknown -z option: %s\n", zopt);
        } else if (strcmp(arg, "--start-group") == 0) {
            archive_start_group(&ctx);
        } else if (strcmp(arg, "--end-group") == 0) {
            archive_end_group(&ctx);
        } else if (strncmp(arg, "--version-script=", 17) == 0) {
            ctx.version_script = arg + 17;
        } else if (arg[0] == '-' && arg[1] == 'l') {
            /* Search -L paths for lib<name>.a or lib<name>.so */
            const char *libname = arg + 2;
            char path[512];
            bool found = false;
            
            /* Search in order: -L paths, then current directory
             * For dynamic linking, prefer .so; for static, prefer .a
             */
            const char *first_ext = ctx.is_static ? ".a" : ".so";
            const char *second_ext = ctx.is_static ? ".so" : ".a";
            
            for (uint32_t j = 0; j < ctx.lib_path_count && !found; j++) {
                /* Try preferred extension */
                snprintf(path, sizeof(path), "%s/lib%s%s", ctx.lib_paths[j], libname, first_ext);
                if (access(path, R_OK) == 0) {
                    if (first_ext[1] == 'a') {
                        rc = meld_add_archive(&ctx, path);
                    } else {
                        rc = meld_add_shared_lib(&ctx, path);
                    }
                    found = true;
                } else {
                    snprintf(path, sizeof(path), "%s/lib%s%s", ctx.lib_paths[j], libname, second_ext);
                    if (access(path, R_OK) == 0) {
                        if (second_ext[1] == 'a') {
                            rc = meld_add_archive(&ctx, path);
                        } else {
                            rc = meld_add_shared_lib(&ctx, path);
                        }
                        found = true;
                    }
                }
            }
            
            /* Try current directory (only .a though) */
            if (!found) {
                snprintf(path, sizeof(path), "lib%s.a", libname);
                if (access(path, R_OK) == 0) {
                    rc = meld_add_archive(&ctx, path);
                    found = true;
                }
            }
            
            if (!found) {
                fprintf(stderr, "meld: cannot find -l%s\n", libname);
            } else if (rc != MELD_OK) {
                fprintf(stderr, "meld: %s\n", meld_strerror(&ctx));
            }
        } else if (arg[0] == '-' && arg[1] == 'L') {
            /* Add to library search path list */
            const char *dir = arg + 2;
            if (ctx.lib_path_count >= ctx.lib_path_cap) {
                uint32_t new_cap = ctx.lib_path_cap ? ctx.lib_path_cap * 2 : 8;
                char **new_arr = realloc(ctx.lib_paths, new_cap * sizeof(*new_arr));
                if (!new_arr) {
                    fprintf(stderr, "meld: out of memory\n");
                    meld_destroy(&ctx);
                    return MELD_ERR_NOMEM;
                }
                ctx.lib_paths = new_arr;
                ctx.lib_path_cap = new_cap;
            }
            ctx.lib_paths[ctx.lib_path_count++] = strdup(dir);
        } else if (arg[0] != '-') {
            /* Positional: .o, .a archive, or .so shared library */
            size_t len = strlen(arg);
            if (len > 2 && strcmp(arg + len - 2, ".a") == 0) {
                rc = meld_add_archive(&ctx, arg);
            } else if (len > 3 && strcmp(arg + len - 3, ".so") == 0) {
                rc = meld_add_shared_lib(&ctx, arg);
            } else {
                rc = meld_add_input(&ctx, arg);
            }
            if (rc != MELD_OK) {
                fprintf(stderr, "meld: %s\n", meld_strerror(&ctx));
                meld_destroy(&ctx);
                return MELD_ERR_INTERNAL;
            }
        } else {
            fprintf(stderr, "meld: unknown option: %s\n", arg);
        }
    }

    /* Resolve archive symbols */
    rc = archive_resolve_lazy(&ctx);
    if (rc != MELD_OK) {
        fprintf(stderr, "meld: archive resolution failed: %s\n", meld_strerror(&ctx));
        meld_destroy(&ctx);
        return MELD_ERR_INTERNAL;
    }

    /* Check for remaining undefined non-weak symbols via gst_undef_count */
    if (ctx.output_type == ET_EXEC && gst_undef_count(ctx.gst) > 0) {
        fprintf(stderr, "meld: %u undefined symbols remain\n", gst_undef_count(ctx.gst));
        gst_dump(ctx.gst); /* Debug */
        meld_destroy(&ctx);
        return MELD_ERR_INTERNAL;
    }

    printf("meld: %u inputs, %u archives, output_type=%s, base=0x%x\n",
           ctx.input_count, ctx.archive_count,
           ctx.output_type == ET_EXEC ? "ET_EXEC" : "ET_DYN",
           ctx.base_addr);

    rc = meld_link(&ctx);
    if (rc != MELD_OK) {
        fprintf(stderr, "meld: link failed: %s\n", meld_strerror(&ctx));
        meld_destroy(&ctx);
        return MELD_ERR_INTERNAL;
    }

    meld_destroy(&ctx);
    return 0;
}
