/* meld_layout.h - Section layout and program header generation for ARM32 ET_EXEC and ET_DYN object
 *
 * Assigns virtual addresses to output sections and generates program headers.
 * Supports ET_EXEC with base 0x10000 (historically, this was 0x8000(i had a source for this but can no longer find it unfortuately), 
 * but the choice of the former leaves more unmapped guard space and thereforre catches more wild pointers)
 * and ET_DYN (base 0x0, randomised at load-time according to ASLR entropy).
 *
 * Ordering:
 *   1. ELF header + program headers
 *   2. .interp (if e_type == ET_DYN)
 *   3. RO sections
 *   4. Executable sections
 *   5. RW sections
 *   6. .bss (NOBITS)
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_LAYOUT_H
#define MELD_LAYOUT_H

#include "meld.h"
#include <string.h>
#include "meld_section.h"
#include "meld_dynlink.h"
#include <elf.h>
#include <stdint.h>
#include <stdbool.h>

#define ARM32_EXEC_BASE     0x10000
#define ARM32_DYN_BASE      0

typedef enum {
    SEG_RO,
    SEG_RX,
    SEG_RW,
    SEG_BSS,
    SEG_RELRO,  /* RELRO - relocation read-only, a hardening technique that prevents memory corruption/injection attacks into writable runtime areas,
                 * preventing GOT overwrite attacks, DYNAMIC section modification, etc. Targets sections writable during relocation, 
                 * then marked read-only.
                 * Reference: https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro
                 */
    SEG_COUNT
} meld_seg_type_t;

typedef enum {
    LAYOUT_OK = 0,
    LAYOUT_ERR_NOMEM,
    LAYOUT_ERR_INTERNAL,
} meld_layout_err_t;

typedef struct meld_phdr {
    Elf32_Phdr           phdr;
    struct meld_phdr    *next;
} meld_phdr_t;

/* Virtual addresses are assigned linearly, with page-aligned boundaries between
 * segments of different permissions, ensures the kernel can map each segment
 * with appropriate protections (r--, r-x, rw-) without the danger of producing an -WX section.
 *
 * The program headers immediately follow the ELF header so PT_PHDR can point
 * to them. Section headers are placed at the end by convention (not-required for ET_EXEC if i'm not mistaken, 
 * could add an option to strip to reduce binary size).
 */
typedef struct meld_layout {
    meld_section_mgr_t  *sections;
    meld_dynlink_t      *dynlink;  /* TODO */

    meld_phdr_t         *phdrs;
    meld_phdr_t         *phdrs_tail;
    uint32_t             phdr_count;

    uint32_t             ehdr_size;     /* sizeof(Elf32_Ehdr) = 52 bytes */
    uint32_t             phdr_off;      /* File offset of program header table */
    uint32_t             phdr_size;

    /* Per-segment tracking arrays indexed by meld_seg_type_t */
    uint32_t             seg_addr[SEG_COUNT];
    uint32_t             seg_size[SEG_COUNT];
    uint32_t             seg_off[SEG_COUNT];
    uint32_t             seg_filesz[SEG_COUNT];

    uint32_t             shdr_off;      /* File offset of section header table */
    uint32_t             shdr_count;

    uint32_t             shstrtab_off;
    uint32_t             shstrtab_size;
    uint32_t             shstrtab_name_off;  /* Self offset */
    char                *shstrtab;
    uint32_t             shstrtab_cap;

    uint32_t             base_addr;     /* As mentioned prior, 0x10000 for ET_EXEC, 0 for ET_DYN */
    uint32_t             entry_addr;    /* vaddr of _start */
    uint32_t             file_size;

    /* After the dynamic linker processes relocations, sections in this region
     * are marked read-only via calls to mprotect().
     * 
     * This region must be page-aligned and contiguous. It is described by PT_GNU_RELRO.
     */
    uint32_t             relro_addr;
    uint32_t             relro_off;
    uint32_t             relro_size;    /* Size (rounded up to pg boundary) */

    bool                 is_pie;        /* Default behaviour */
    bool                 is_static;
    bool                 relro;         /* Partial RELRO, default behaviour*/
    bool                 bind_now;      /* DF_BIND_NOW: resolve all PLT at load (full RELRO enabled) */
} meld_layout_t;

int  layout_init(meld_layout_t *lay, meld_section_mgr_t *sections, meld_dynlink_t *dynlink);
void layout_destroy(meld_layout_t *lay);

int layout_configure(meld_layout_t *lay, meld_ctx_t *ctx);

int layout_assign_addresses(meld_layout_t *lay, uint32_t base_addr);

int layout_add_phdr(meld_layout_t *lay, uint32_t type, uint32_t flags,
                    uint32_t offset, uint32_t vaddr, uint32_t filesz,
                    uint32_t memsz, uint32_t align);

int layout_generate_phdrs(meld_layout_t *lay);

int layout_build_shstrtab(meld_layout_t *lay);

uint32_t layout_shstrtab_add(meld_layout_t *lay, const char *name);

size_t layout_ehdr_write(const meld_layout_t *lay, void *buf, size_t len, uint16_t e_type);
size_t layout_phdrs_write(const meld_layout_t *lay, void *buf, size_t len);
size_t layout_shdrs_write(const meld_layout_t *lay, void *buf, size_t len);
size_t layout_shstrtab_write(const meld_layout_t *lay, void *buf, size_t len);

/* Partial RELRO; -z relro:
 *   .dynamic
 *   .got
 *   .init_array
 *   .fini_array
 *   .preinit_array
 *
 * Full RELRO; -z relro -z now:
 *   Those above, plus:
 *   .got.plt      - PLT[n]'s corresponding GOT entries
 */
static bool osec_is_relro(const meld_osec_t *osec, bool full_relro) {
    const char *n = osec->name;
    if (strcmp(n, ".dynamic") == 0) return true;
    if (strcmp(n, ".got") == 0) return true;
    if (strcmp(n, ".init_array") == 0) return true;
    if (strcmp(n, ".fini_array") == 0) return true;
    if (strcmp(n, ".preinit_array") == 0) return true;
    if (full_relro && strcmp(n, ".got.plt") == 0) return true;
    return false;
}

/* Segment ordering in output file:
 *     SEG_RO
 *     SEG_RX
 *     SEG_RW
 *     SEG_RELRO
 *     SEG_BSS
 */
static meld_seg_type_t osec_segment_relro(const meld_osec_t *osec, bool relro, bool full_relro) {
    if (osec->flags & OSEC_NOBITS) return SEG_BSS;
    if (osec->flags & OSEC_EXEC)   return SEG_RX;
    if (osec->flags & OSEC_WRITE) {
        if (relro && osec_is_relro(osec, full_relro)) return SEG_RELRO;
        return SEG_RW;
    }
    return SEG_RO;
}

/* Maps segment type to ELF p_flags for PT_LOAD headers.
 * These correspond to mmap() flags:
 *     PF_R = PROT_READ
 *     PF_W = PROT_WRITE  
 *     PF_X = PROT_EXEC
 */
__attribute__((unused))
static uint32_t seg_pflags(meld_seg_type_t seg) {
    switch (seg) {
        case SEG_RO:    return PF_R;
        case SEG_RX:    return PF_R | PF_X;
        case SEG_RW:    return PF_R | PF_W;
        case SEG_RELRO: return PF_R | PF_W;  /* mprotect() marks as PROT_READ at load-time */
        case SEG_BSS:   return PF_R | PF_W;
        default:        return 0;
    }
}

#endif /* MELD_LAYOUT_H */
