/* meld_layout.c - Section layout and program header generation for ARM32
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_layout.h"
#include "../tlaloc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int layout_init(meld_layout_t *layout, meld_section_mgr_t *sections, meld_dynlink_t *dynlink) {
    memset(layout, 0, sizeof(*layout));
    layout->sections = sections;
    layout->dynlink = dynlink;
    layout->ehdr_size = sizeof(Elf32_Ehdr);
    return LAYOUT_OK;
}

void layout_destroy(meld_layout_t *layout) {
    meld_phdr_t *p = layout->phdrs;
    while (p) {
        meld_phdr_t *next = p->next;
        free(p);
        p = next;
    }
    free(layout->shstrtab);
    memset(layout, 0, sizeof(*layout));
}

int layout_configure(meld_layout_t *layout, meld_ctx_t *ctx) {
    layout->base_addr = ctx->base_addr;
    layout->is_pie = (ctx->output_type == ET_DYN);
    layout->is_static = ctx->is_static;
    layout->relro = ctx->relro;
    layout->bind_now = ctx->bind_now;
    return LAYOUT_OK;
}

int layout_add_phdr(meld_layout_t *layout, uint32_t type, uint32_t flags,
                    uint32_t offset, uint32_t vaddr, uint32_t filesz,
                    uint32_t memsz, uint32_t align)
{
    meld_phdr_t *p = calloc(1, sizeof(*p));
    if (!p) return LAYOUT_ERR_NOMEM;

    p->phdr.p_type   = type;
    p->phdr.p_flags  = flags;
    p->phdr.p_offset = offset;
    p->phdr.p_vaddr  = vaddr;
    p->phdr.p_paddr  = vaddr;
    p->phdr.p_filesz = filesz;
    p->phdr.p_memsz  = memsz;
    p->phdr.p_align  = align;

    if (layout->phdrs_tail) {
        layout->phdrs_tail->next = p;
        layout->phdrs_tail = p;
    } else {
        layout->phdrs = layout->phdrs_tail = p;
    }
    layout->phdr_count++;
    return LAYOUT_OK;
}

uint32_t layout_shstrtab_add(meld_layout_t *layout, const char *name) {
    size_t len = strlen(name) + 1;
    if (layout->shstrtab_size + len > layout->shstrtab_cap) {
        uint32_t new_cap = layout->shstrtab_cap ? layout->shstrtab_cap * 2 : 512;
        while (new_cap < layout->shstrtab_size + len) new_cap *= 2;
        char *new_buf = realloc(layout->shstrtab, new_cap);
        if (!new_buf) return 0;
        layout->shstrtab = new_buf;
        layout->shstrtab_cap = new_cap;
    }
    uint32_t off = layout->shstrtab_size;
    memcpy(layout->shstrtab + off, name, len);
    layout->shstrtab_size += len;
    return off;
}

int layout_build_shstrtab(meld_layout_t *layout) {
    /* First byte must be NUL */
    if (layout->shstrtab_size == 0) {
        layout_shstrtab_add(layout, "");
    }

    for (meld_osec_t *osec = layout->sections->sections; osec; osec = osec->next) {
        osec->name_off = layout_shstrtab_add(layout, osec->name);
    }

    layout->shstrtab_name_off = layout_shstrtab_add(layout, ".shstrtab");   /* Add self */

    return LAYOUT_OK;
}

int layout_assign_addresses(meld_layout_t *layout, uint32_t base_addr) {
    layout->base_addr = base_addr;

    /* Iterate sections once to count non-empty segments */
    bool has_seg[SEG_COUNT] = {false};
    for (meld_osec_t *osec = layout->sections->sections; osec; osec = osec->next) {
        if (!(osec->flags & OSEC_ALLOC)) continue;
        if (osec->size == 0 && !(osec->flags & OSEC_NOBITS)) continue; /* Skip empty non-BSS */
        meld_seg_type_t seg = osec_segment_relro(osec, layout->relro, layout->bind_now);
        has_seg[seg] = true;
    }

    /* Get exact count(in order):
     * + 1 PT_PHDR
     * + 1 PT_INTERP if dynamic with interpreter
     * + some number of non-empty PT_LOADs
     * + 1 PT_DYNAMIC if dynamic
     * + 1 PT_GNU_RELRO if enabled and has content
     * + 1 PT_GNU_STACK
     */
    uint32_t phdr_count = 1; /* PT_PHDR */
    if (layout->dynlink && layout->dynlink->interp)
        phdr_count++;
    for (meld_seg_type_t seg = SEG_RO; seg < SEG_COUNT; seg++) {
        if (has_seg[seg]) phdr_count++;
    }
    if (layout->dynlink && !layout->is_static)
        phdr_count++; /* PT_DYNAMIC */
    if (layout->relro && has_seg[SEG_RELRO])
        phdr_count++;
    phdr_count++; /* PT_GNU_STACK */

    layout->phdr_off = layout->ehdr_size;
    layout->phdr_size = phdr_count * sizeof(Elf32_Phdr);

    /* Align first loadable segment to 16 bytes to satisfy ABI alignment
     * requirements and maintain p_offset % p_align == p_vaddr % p_align. 
     */
    uint32_t file_off = ALIGN_UP(layout->ehdr_size + layout->phdr_size, 16);
    uint32_t vaddr = base_addr + file_off;

    meld_osec_t **arr_osec = NULL;  /* We need array form because we will iterate multiple times according to segment type */
    uint32_t count = layout->sections->count;
    if (count > 0) {
        arr_osec = calloc(count, sizeof(*arr_osec));
        if (!arr_osec) return LAYOUT_ERR_NOMEM;

        uint32_t i = 0;
        for (meld_osec_t *osec = layout->sections->sections; osec; osec = osec->next) {
            arr_osec[i++] = osec;
        }
    }

    for (meld_seg_type_t seg = SEG_RO; seg < SEG_COUNT; seg++) {
        bool seg_started = false;  /* Per-segment */

        for (uint32_t i = 0; i < count; i++) {
            meld_osec_t *osec = arr_osec[i];
            meld_seg_type_t osec_seg = osec_segment_relro(osec, layout->relro, layout->bind_now);
            if (osec_seg != seg) continue;
            if (!(osec->flags & OSEC_ALLOC)) continue;

            if (!seg_started) {
                /* New segment; establish section boundaries, page-align start according to previous values */
                if (seg != SEG_RO) {
                    file_off = ALIGN_UP(file_off, PAGE_SIZE);
                    vaddr = ALIGN_UP(vaddr, PAGE_SIZE);
                }
                layout->seg_addr[seg] = vaddr;
                layout->seg_off[seg] = file_off;

                if (seg == SEG_RELRO) {
                    layout->relro_addr = vaddr;  /* Start RELRO region */
                    layout->relro_off = file_off;
                }
                seg_started = true;
            }

            /* Section address assignment within segment according to assigned values */
            uint32_t align = osec->align ? osec->align : 1;
            file_off = ALIGN_UP(file_off, align); 
            vaddr = ALIGN_UP(vaddr, align);

            osec->addr = vaddr;
            osec->file_off = file_off;

            if (osec->flags & OSEC_NOBITS) {
                /* BSS; increase memsz only */
                vaddr += osec->size;
            } else {
                file_off += osec->size;
                vaddr += osec->size;
            }
        }

        /* Update segment sizes */
        if (seg_started) {
            layout->seg_size[seg] = vaddr - layout->seg_addr[seg];
            if (seg == SEG_BSS) {
                layout->seg_filesz[seg] = 0;
            } else {
                layout->seg_filesz[seg] = file_off - layout->seg_off[seg];
            }

            /* Must be page aligned for mprotect() */
            if (seg == SEG_RELRO) {
                layout->relro_size = ALIGN_UP(vaddr - layout->relro_addr, PAGE_SIZE);
            }
        }
    }

    /* Place non-loadable sections e.g., .symtab, .strtab */
    for (uint32_t i = 0; i < count; i++) {
        meld_osec_t *osec = arr_osec[i];
        if (osec->flags & OSEC_ALLOC) continue;

        uint32_t align = osec->align ? osec->align : 1;
        file_off = ALIGN_UP(file_off, align);
        osec->file_off = file_off;
        osec->addr = 0;
        file_off += osec->size;
    }

    layout->file_size = file_off;
    free(arr_osec);
    return LAYOUT_OK;
}

int layout_generate_phdrs(meld_layout_t *layout) {
    /* Final phdr count;
     *   1 (PT_PHDR)
     * + 1 (PT_INTERP) if dynamic with interpreter
     * + some number of non-empty PT_LOAD segments
     * + 1 (PT_DYNAMIC) if dynamic
     * + 1 (PT_GNU_RELRO) if enabled
     * + 1 (PT_GNU_STACK)
     */
    uint32_t final_phdr_count = 1; /* PT_PHDR */
    if (layout->dynlink && layout->dynlink->interp)
        final_phdr_count++;
    for (meld_seg_type_t seg = SEG_RO; seg < SEG_COUNT; seg++) {
        if (layout->seg_size[seg] > 0) final_phdr_count++;  /* Distinct PT_LOADs have unique permissions */
    }
    if (layout->dynlink && layout->dynlink->dynamic_addr)
        final_phdr_count++;
    if (layout->relro && layout->relro_size > 0)
        final_phdr_count++;
    final_phdr_count++; /* PT_GNU_STACK */

    layout_add_phdr(layout, PT_PHDR, PF_R,
                    layout->phdr_off, layout->base_addr + layout->phdr_off,
                    final_phdr_count * sizeof(Elf32_Phdr),
                    final_phdr_count * sizeof(Elf32_Phdr),
                    4);

    /* PT_INTERP if dynamic */
    if (layout->dynlink && layout->dynlink->interp) {
        layout_add_phdr(layout, PT_INTERP, PF_R,
                        layout->dynlink->interp_addr - layout->base_addr,
                        layout->dynlink->interp_addr,
                        dynlink_interp_size(layout->dynlink),
                        dynlink_interp_size(layout->dynlink),
                        1);
    }

    /* The first PT_LOAD segment must start at offset 0 to cover
     * the ELF header and program headers to avoid the warning of PT_PHDR
     * not being covered by a PT_LOAD segment
     */
    for (meld_seg_type_t seg = SEG_RO; seg < SEG_COUNT; seg++) {
        if (layout->seg_size[seg] == 0) continue;

        uint32_t off = layout->seg_off[seg];
        uint32_t addr = layout->seg_addr[seg];
        uint32_t filesz = layout->seg_filesz[seg];
        uint32_t memsz = layout->seg_size[seg];

        /* First; start at offset 0 to include ELF header + phdrs */
        if (seg == SEG_RO) {
            uint32_t delta = off;  /* Distance from offset 0 to segment start */
            off = 0;               /* Move segment start to offset 0 */
            addr -= delta;         /* Adjust vaddr to maintain p_offset % p_align == p_vaddr % p_align */
            filesz += delta;
            memsz += delta;
        }

        layout_add_phdr(layout, PT_LOAD, seg_pflags(seg),
                        off, addr, filesz, memsz, PAGE_SIZE);
    }

    /* PT_DYNAMIC if dynamic */
    if (layout->dynlink && layout->dynlink->dynamic_addr) {
        size_t dyn_size = dynlink_dynamic_size(layout->dynlink);
        layout_add_phdr(layout, PT_DYNAMIC, PF_R | PF_W,
                        layout->dynlink->dynamic_addr - layout->base_addr,
                        layout->dynlink->dynamic_addr,
                        dyn_size, dyn_size, 4);
    }

    /* PT_GNU_RELRO if enabled */
    if (layout->relro && layout->relro_size > 0) {
        layout_add_phdr(layout, PT_GNU_RELRO, PF_R,  /* It's flags are largely ignored */
                        layout->relro_off, layout->relro_addr,
                        layout->relro_size, layout->relro_size, 1);
    }

    /* PT_GNU_STACK; does not map any file data. It's p_flags will tell the loader whether the
     * process stack should be executable (PF_X); it is a good hardening practice to omit PF_X to
     * enforce an NX stack, preventing stack-based code injection.
     */
    layout_add_phdr(layout, PT_GNU_STACK, PF_R | PF_W,
                    0, 0, 0, 0, 16);

    return LAYOUT_OK;
}

size_t layout_ehdr_write(const meld_layout_t *layout, void *buf, size_t len, uint16_t e_type) {
    if (len < sizeof(Elf32_Ehdr)) return 0;

    Elf32_Ehdr *ehdr = buf;
    memset(ehdr, 0, sizeof(*ehdr));

    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS32;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_NONE;
    /* Padding */

    ehdr->e_type = e_type;
    ehdr->e_machine = EM_ARM;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_entry = layout->entry_addr;
    ehdr->e_phoff = layout->phdr_off;
    ehdr->e_shoff = layout->shdr_off;
    ehdr->e_flags = 0x5000400;  /* EABI5 */
    ehdr->e_ehsize = sizeof(Elf32_Ehdr);
    ehdr->e_phentsize = sizeof(Elf32_Phdr);
    ehdr->e_phnum = layout->phdr_count;
    ehdr->e_shentsize = sizeof(Elf32_Shdr);
    ehdr->e_shnum = layout->shdr_count;
    ehdr->e_shstrndx = layout->shdr_count - 1; /* .shstrtab comes last */

    return sizeof(Elf32_Ehdr);
}

size_t layout_phdrs_write(const meld_layout_t *layout, void *buf, size_t len) {
    size_t needed = layout->phdr_count * sizeof(Elf32_Phdr);
    if (len < needed) return 0;

    Elf32_Phdr *out = buf;
    for (meld_phdr_t *p = layout->phdrs; p; p = p->next) {
        *out++ = p->phdr;
    }

    return needed;
}

size_t layout_shdrs_write(const meld_layout_t *layout, void *buf, size_t len) {
    uint32_t count = layout->sections->count + 2; /* NULL + .shstrtab */
    size_t needed = count * sizeof(Elf32_Shdr);
    if (len < needed) return 0;

    Elf32_Shdr *out = buf;
    memset(out, 0, needed);

    /* SHN_UNDEF */
    out++;

    /* Output sections */
    for (meld_osec_t *osec = layout->sections->sections; osec; osec = osec->next) {
        out->sh_name = osec->name_off;
        out->sh_type = osec->sh_type;
        out->sh_flags = 0;
        if (osec->flags & OSEC_ALLOC) out->sh_flags |= SHF_ALLOC;
        if (osec->flags & OSEC_WRITE) out->sh_flags |= SHF_WRITE;
        if (osec->flags & OSEC_EXEC)  out->sh_flags |= SHF_EXECINSTR;
        if (osec->flags & OSEC_TLS)   out->sh_flags |= SHF_TLS;
        out->sh_addr = osec->addr;
        out->sh_offset = osec->file_off;
        out->sh_size = osec->size;
        out->sh_link = osec->sh_link;
        out->sh_info = osec->sh_info;
        out->sh_addralign = osec->align;
        out->sh_entsize = osec->sh_entsize;
        out++;
    }

    /* .shstrtab appended - name offset from layout_build_shstrtab */
    out->sh_name = layout->shstrtab_name_off;
    out->sh_type = SHT_STRTAB;
    out->sh_flags = 0;
    out->sh_addr = 0;
    out->sh_offset = layout->shstrtab_off;
    out->sh_size = layout->shstrtab_size;
    out->sh_link = 0;
    out->sh_info = 0;
    out->sh_addralign = 1;
    out->sh_entsize = 0;

    return needed;
}

size_t layout_shstrtab_write(const meld_layout_t *layout, void *buf, size_t len) {
    if (len < layout->shstrtab_size) return 0;
    memcpy(buf, layout->shstrtab, layout->shstrtab_size);
    return layout->shstrtab_size;
}
