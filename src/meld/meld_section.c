/* meld_section.c - Input section management and output section coalescing
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_section.h"
#include "meld_input.h"
#include "../tlaloc.h"
#include <elf.h>
#include <stdlib.h>
#include <string.h>

/* Known section name bases for coalescing.
 * Sections like ".text.foo" coalesce into ".text". Checked in order, first match wins.
 * is_prefix=true matches ".name.*" patterns.
 */
static const struct {
    const char *name;
    size_t      len;
    bool        is_prefix;
} known_bases[] = {
    { ".text",           5, true  },
    { ".rodata",         7, true  },
    { ".data.rel.ro",   12, true  },  /* Higher specificity must come before where is_prefix is true */
    { ".data",           5, true  },
    { ".bss",            4, true  },
    { ".init_array",    11, false },
    { ".fini_array",    11, false },
    { ".tdata",          6, true  },
    { ".tbss",           5, true  },
    { ".got",            4, false },
    { ".got.plt",        8, false },
    { ".plt",            4, false },
    { ".rel.dyn",        8, false },
    { ".rel.plt",        8, false },
    { ".rela.dyn",       9, false },
    { ".rela.plt",       9, false },
    { ".dynamic",        8, false },
    { ".interp",         7, false },
    { ".note",           5, true  },
    { ".eh_frame",       9, false },
    { ".eh_frame_hdr",  13, false },
    { ".ARM.exidx",       10, false },
    { ".ARM.extab",       10, false },
    { ".ARM.attributes",  15, false },
};

const char *section_name_base(const char *name) {
    if (!name) return NULL;

    /* Self maintaining loop condition */
    for (size_t i = 0; i < ARRAY_LEN(known_bases); i++) {
        if (known_bases[i].is_prefix) {
            if (strncmp(name, known_bases[i].name, known_bases[i].len) == 0) {
                char next = name[known_bases[i].len];
                if (next == '\0' || next == '.') {
                    return known_bases[i].name;  /* If . , then subsection, otherwise exact match */
                }
            }
        } else {
            if (strcmp(name, known_bases[i].name) == 0) {
                return known_bases[i].name;
            }
        }
    }

    /* Use original name otherwise, no coalescing */
    return name;
}

int section_mgr_init(meld_section_mgr_t *mgr) {
    if (!mgr) return MELD_ERR_INTERNAL;
    memset(mgr, 0, sizeof(*mgr));
    return MELD_OK;
}

void section_mgr_destroy(meld_section_mgr_t *mgr) {
    if (!mgr) return;

    meld_osec_t *osec = mgr->sections;
    while (osec) {
        meld_osec_t *next = osec->next;

        meld_isec_t *isec = osec->isecs;
        while (isec) {
            meld_isec_t *inext = isec->next;
            free(isec);
            isec = inext;
        }

        free(osec);
        osec = next;
    }

    memset(mgr, 0, sizeof(*mgr));
}

#define OSEC_CORE_FLAGS (OSEC_WRITE | OSEC_EXEC | OSEC_NOBITS | OSEC_TLS | OSEC_LINK_ORDER)

static meld_osec_t *find_or_create_osec(meld_section_mgr_t *mgr,
                                        const char *base_name,
                                        uint8_t flags,
                                        uint32_t sh_type) {
    for (meld_osec_t *osec = mgr->sections; osec; osec = osec->next) {
        if (strcmp(osec->name, base_name) == 0 &&
            (osec->flags & OSEC_CORE_FLAGS) == (flags & OSEC_CORE_FLAGS)) {
            return osec;
        }
    }

    meld_osec_t *osec = calloc(1, sizeof(*osec));
    if (!osec) return NULL;

    osec->name = base_name;
    osec->flags = flags;
    osec->sh_type = sh_type;
    osec->align = 1;  /* Can only raise alignment, so set to minimum value to be adjusted later (should we need to) */

    if (mgr->tail) {
        mgr->tail->next = osec;
    } else {
        mgr->sections = osec;
    }
    mgr->tail = osec;
    mgr->count++;

    return osec;
}

meld_osec_t *section_add_input(meld_section_mgr_t *mgr, meld_input_t *input, uint32_t shndx) {
    if (!mgr || !input) return NULL;

    const elf_t *elf = &input->elf;
    const char *name = elf_sh_name(elf, shndx);
    uint32_t sh_flags = (uint32_t)elf_sh_flags(elf, shndx);
    uint32_t sh_type = elf_sh_type(elf, shndx);

    const char *base_name = section_name_base(name);
    uint8_t flags = flags_from_elf(sh_flags, sh_type);

    meld_osec_t *osec = find_or_create_osec(mgr, base_name, flags, sh_type);
    if (!osec) return NULL;

    meld_isec_t *isec = calloc(1, sizeof(*isec));
    if (!isec) return NULL;

    /* UID */
    isec->input = input;
    isec->shndx = shndx;

    if (osec->isecs_tail) {
        osec->isecs_tail->next = isec;
    } else {
        osec->isecs = isec;
    }
    osec->isecs_tail = isec;
    osec->isec_count++;

    /* Update alignment for osec to largest seen */
    uint32_t align = (uint32_t)elf_sh_addralign(elf, shndx);
    if (align > osec->align) {
        osec->align = align;
    }

    /* Store ref in input section state array (obvious its just the chain of structs is really hard to follow so the comment is just easier) */
    if (input->sec_state) {
        input->sec_state[shndx].out = osec;
    }

    return osec;
}

meld_osec_t *section_find(meld_section_mgr_t *mgr, const char *name) {
    if (!mgr || !name) return NULL;

    for (meld_osec_t *osec = mgr->sections; osec; osec = osec->next) {
        if (strcmp(osec->name, name) == 0) {
            return osec;
        }
    }
    return NULL;
}

/* Returns the index of a named section, or 0 if not found */
uint32_t section_index(meld_section_mgr_t *mgr, const char *name) {
    meld_osec_t *osec = section_find(mgr, name);
    return osec ? osec->idx : 0;
}

void section_assign_indices(meld_section_mgr_t *mgr) {
    if (!mgr) return;
    uint32_t idx = 1;  /* 0 = SHN_UNDEF */
    for (meld_osec_t *osec = mgr->sections; osec; osec = osec->next) {
        osec->idx = idx++;
    }
}

/* Finalise ELF section header fields (sh_link, sh_info, sh_entsize) */
void section_finalise_structure(meld_section_mgr_t *mgr,
                                uint32_t symtab_first_global,
                                uint32_t verdef_count,
                                uint32_t verneed_count) {
    if (!mgr) return;

    uint32_t dynstr_idx = section_index(mgr, ".dynstr");
    uint32_t dynsym_idx = section_index(mgr, ".dynsym");
    uint32_t strtab_idx = section_index(mgr, ".strtab");

    for (meld_osec_t *osec = mgr->sections; osec; osec = osec->next) {
        if (strcmp(osec->name, ".dynsym") == 0) {
            osec->sh_link = dynstr_idx;
            osec->sh_entsize = sizeof(Elf32_Sym);
            osec->sh_info = 1;  /* First global symbol index (after locals) */
        } else if (strcmp(osec->name, ".symtab") == 0) {
            osec->sh_link = strtab_idx;
            osec->sh_entsize = sizeof(Elf32_Sym);
            osec->sh_info = symtab_first_global;
        } else if (strcmp(osec->name, ".dynamic") == 0) {
            osec->sh_link = dynstr_idx;
            osec->sh_entsize = sizeof(Elf32_Dyn);
        } else if (strcmp(osec->name, ".gnu.hash") == 0) {
            osec->sh_link = dynsym_idx;
            osec->sh_entsize = 4;
        } else if (strcmp(osec->name, ".rel.dyn") == 0) {
            osec->sh_link = dynsym_idx;
            osec->sh_entsize = sizeof(Elf32_Rel);
        } else if (strcmp(osec->name, ".rel.plt") == 0) {
            osec->sh_link = dynsym_idx;
            osec->sh_entsize = sizeof(Elf32_Rel);
            /* sh_info points to .got.plt */
            osec->sh_info = section_index(mgr, ".got.plt");
        } else if (strcmp(osec->name, ".hash") == 0) {
            osec->sh_link = dynsym_idx;
            osec->sh_entsize = 4;
        } else if (strcmp(osec->name, ".gnu.version") == 0) {
            /* .gnu.version links to .dynsym */
            osec->sh_link = dynsym_idx;
            osec->sh_entsize = sizeof(Elf32_Versym);  /* 2 bytes */
        } else if (strcmp(osec->name, ".gnu.version_d") == 0) {
            osec->sh_link = dynstr_idx;
            osec->sh_info = verdef_count;
        } else if (strcmp(osec->name, ".gnu.version_r") == 0) {
            osec->sh_link = dynstr_idx;
            osec->sh_info = verneed_count;
        }
    }
}

meld_osec_t *section_add_synthetic(meld_section_mgr_t *mgr, const char *name,
                                   uint8_t flags, uint32_t sh_type,
                                   uint32_t align, uint32_t size) {
    if (!name) return NULL;

    meld_osec_t *osec = calloc(1, sizeof(*osec));
    if (!osec) return NULL;

    osec->name = name;  /* Assume static string or strdup'd */
    osec->flags = flags | OSEC_SYNTHETIC;
    osec->sh_type = sh_type;
    osec->align = align;
    osec->size = size;
    osec->isecs = NULL;  /* Purely synthetic */
    osec->isec_count = 0;

    if (mgr->tail) {
        mgr->tail->next = osec;
    } else {
        mgr->sections = osec;
    }
    mgr->tail = osec;
    mgr->count++;

    return osec;
}

/* For each output section, iterate input sections and assign offsets.
 * Alignment padding inserted as necessitated.
 */
int section_layout(meld_section_mgr_t *mgr) {
    if (!mgr) return MELD_ERR_INTERNAL;

    for (meld_osec_t *osec = mgr->sections; osec; osec = osec->next) {
        uint32_t offset = 0;

        for (meld_isec_t *isec = osec->isecs; isec; isec = isec->next) {
            const elf_t *elf = &isec->input->elf;
            uint32_t align = (uint32_t)elf_sh_addralign(elf, isec->shndx); /* Between sections */
            uint32_t size = (uint32_t)elf_sh_size(elf, isec->shndx);

            /* Example: offset=29 (0x1D), align=8 (0x10)
             *   8-1 = 7 = 0x7 = 00000111
             *   ~0x7 = 11111000
             *   11111000 & (0x1D + 0x7)
             *   11111000 & (00011101 + 00000111) = 
             *   11111000 & 0x24 = 00100100 = 00100000 = 32
             */
            if (align > 1) {
                ALIGN_UP(offset, align);
            }

            isec->output_off = offset;

            if (isec->input->sec_state) {
                isec->input->sec_state[isec->shndx].output_offset = offset;  /* Statements like this make me question my ability to design programs exceeding more than 50 lines of code */
            }

            offset += size;
        }
        /* Only update size if we have input sections, otherwise preserve
         * the size set for synthetic sections (e.g., .got, .plt) */
        if (osec->isecs) {
            osec->size = offset;
        }
    }

    return MELD_OK;
}

int section_collect_all(meld_ctx_t *ctx, meld_section_mgr_t *mgr) {
    if (!ctx || !mgr) return MELD_ERR_INTERNAL;

    for (uint32_t i = 0; i < ctx->input_count; i++) {
        meld_input_t *inp = ctx->inputs[i];
        uint32_t shnum = elf_shnum(&inp->elf);

        for (uint32_t j = 1; j < shnum; j++) { 
            uint32_t sh_type = elf_sh_type(&inp->elf, j);
            uint64_t sh_flags = elf_sh_flags(&inp->elf, j);

            if (!(sh_flags & SHF_ALLOC)) continue;

            if (sh_type == SHT_SYMTAB || sh_type == SHT_STRTAB ||
                sh_type == SHT_REL || sh_type == SHT_RELA) {
                continue;
            }

            meld_osec_t *osec = section_add_input(mgr, inp, j);
            if (!osec) return MELD_ERR_NOMEM;
        }
    }

    return MELD_OK;
}
