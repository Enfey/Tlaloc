/*
     ##### /          ##### ##       ##### #     ##      #######    
  ######  /        ######  /### / ######  /#    #### / /       ###  
 /#   /  /        /#   /  / ###/ /#   /  / ##    ###/ /         ##  
/    /  /        /    /  /   ## /    /  /  ##    # #  ##        #   
    /  /             /  /           /  /    ##   #     ###          
   ## ##            ## ##          ## ##    ##   #    ## ###        
   ## ##            ## ##          ## ##     ##  #     ### ###      
   ## ##            ## ######      ## ##     ##  #       ### ###    
   ## ##            ## #####       ## ##      ## #         ### /##  
   ## ##            ## ##          ## ##      ## #           #/ /## 
   #  ##            #  ##          #  ##       ###            #/ ## 
      /                /              /        ###             # /  
  /##/           / /##/         / /##/          ##   /##        /   
 /  ############/ /  ##########/ /  #####           /  ########/    
/     #########  /     ######   /     ##           /     #####      
#                #              #                  |                
 ##               ##             ##                 \)              
                                                     
 * lens.c - implementation of an mmap-based ELF parser for EM_ARM and EM_AARCH64 objects with E_TYPE
 * ∈ {ET_REL, ET_EXEC, ET_DYN}
 *
 * Copyright (c) 2025 Felix Riley-Kay @ github.com/enfey
 */

#define _GNU_SOURCE
#include <elf.h>
#include "lens.h"
#include "../tlaloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

/* Not present in older glibc distributions - must provide ourselves */
#ifndef NT_ARM_SSVE
#define NT_ARM_SSVE 0x40b
#endif
#ifndef NT_ARM_ZA
#define NT_ARM_ZA 0x40c
#endif
#ifndef NT_ARM_ZT
#define NT_ARM_ZT 0x40d
#endif
#ifndef NT_ARM_FPMR
#define NT_ARM_FPMR 0x40e
#endif
#ifndef NT_ARM_POE
#define NT_ARM_POE 0x40f
#endif
#ifndef NT_ARM_GCS
#define NT_ARM_GCS 0x410
#endif

/* Check if [off, off+len] is within the mmap'd file. Second check catches overflow wraparound */
static inline bool in_bounds(const elf_t *e, size_t off, size_t len) { return (off + len <= e->size) && (off + len >= off); }

/* Parse ELF from already-mapped memory.
 * If owns_base is true, munmap on error; otherwise caller owns memory e.g., archive_open().
 */
static int elf_parse_internal(elf_t *e, void *base, size_t size, bool owns_base) {
    e->base = base;
    e->size = size;

    if (size < EI_NIDENT) {
        if (owns_base) { munmap(base, size); e->base = NULL; }
        SET_ERR(e, E_TRUNCATED, "file too small"); return E_TRUNCATED;
    }

    const unsigned char *ident = (const unsigned char *)base;
    if (memcmp(ident, ELFMAG, SELFMAG) != 0) {
        if (owns_base) { munmap(base, size); e->base = NULL; }
        SET_ERR(e, E_NOT_ELF, "not an ELF file"); return E_NOT_ELF;
    }

    e->elf_class = ident[EI_CLASS];

    if (ELF_IS_32(e)) {
        if (size < sizeof(Elf32_Ehdr)) {
            if (owns_base) { munmap(base, size); e->base = NULL; }
            SET_ERR(e, E_TRUNCATED, "truncated ELF32 header"); return E_TRUNCATED;
        }
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)base;
        e->e32.ehdr = ehdr;
        e->elf_type = ehdr->e_type;
        e->elf_machine = ehdr->e_machine;
        e->shnum = ehdr->e_shnum;
        e->phnum = ehdr->e_phnum;

        if (ehdr->e_machine != EM_ARM) {
            if (owns_base) { munmap(base, size); e->base = NULL; }
            SET_ERR(e, E_NOT_ARM, "not ARM (machine=0x%x)", e->elf_machine); return E_NOT_ARM;
        }
        if (ehdr->e_type != ET_REL && ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
            if (owns_base) { munmap(base, size); e->base = NULL; }
            SET_ERR(e, E_BAD_TYPE, "unsupported ELF type %d", e->elf_type); return E_BAD_TYPE;
        }

        if (ehdr->e_shnum > 0 && ehdr->e_shoff > 0) {
            size_t shdrs_size;
            if (__builtin_mul_overflow(ehdr->e_shnum, sizeof(Elf32_Shdr), &shdrs_size)) {
                if (owns_base) { munmap(base, size); e->base = NULL; }
                SET_ERR(e, E_TRUNCATED, "section header count overflow"); return E_TRUNCATED;
            }
            if (!in_bounds(e, ehdr->e_shoff, shdrs_size)) {
                if (owns_base) { munmap(base, size); e->base = NULL; }
                SET_ERR(e, E_TRUNCATED, "section headers past EOF"); return E_TRUNCATED;
            }

            e->e32.shdrs = (Elf32_Shdr *)((char *)base + ehdr->e_shoff);

            if (ehdr->e_shstrndx < ehdr->e_shnum) {
                Elf32_Shdr *shstr = &e->e32.shdrs[ehdr->e_shstrndx];
                if (in_bounds(e, shstr->sh_offset, shstr->sh_size)) {
                    e->shstrtab = (const char *)base + shstr->sh_offset;
                    e->shstrtab_size = shstr->sh_size;
                }
            }
        }

        if (ehdr->e_phnum > 0 && ehdr->e_phoff > 0) {
            size_t phdrs_size;
            if (__builtin_mul_overflow(ehdr->e_phnum, sizeof(Elf32_Phdr), &phdrs_size)) {
                if (owns_base) { munmap(base, size); e->base = NULL; }
                SET_ERR(e, E_TRUNCATED, "program header count overflow"); return E_TRUNCATED;
            }
            if (!in_bounds(e, ehdr->e_phoff, phdrs_size)) {
                if (owns_base) { munmap(base, size); e->base = NULL; }
                SET_ERR(e, E_TRUNCATED, "program headers past EOF"); return E_TRUNCATED;
            }
            e->e32.phdrs = (Elf32_Phdr *)((char *)base + ehdr->e_phoff);
        }

        if (e->e32.shdrs) {
            for (uint32_t i = 0; i < ehdr->e_shnum; i++) {
                Elf32_Shdr *sh = &e->e32.shdrs[i];
                if (sh->sh_type == SHT_SYMTAB && !e->e32.symtab) {
                    if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                        e->e32.symtab = (Elf32_Sym *)((char *)base + sh->sh_offset);
                        e->symtab_count = sh->sh_size / sizeof(Elf32_Sym);
                        if (sh->sh_link < ehdr->e_shnum) {
                            Elf32_Shdr *strtab = &e->e32.shdrs[sh->sh_link];
                            if (in_bounds(e, strtab->sh_offset, strtab->sh_size)) {
                                e->strtab = (const char *)base + strtab->sh_offset;
                                e->strtab_size = strtab->sh_size;
                            }
                        }
                    }
                } else if (sh->sh_type == SHT_DYNSYM && !e->e32.dynsym) {
                    if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                        e->e32.dynsym = (Elf32_Sym *)((char *)base + sh->sh_offset);
                        e->dynsym_count = sh->sh_size / sizeof(Elf32_Sym);
                        if (sh->sh_link < ehdr->e_shnum) {
                            Elf32_Shdr *dynstr = &e->e32.shdrs[sh->sh_link];
                            if (in_bounds(e, dynstr->sh_offset, dynstr->sh_size)) {
                                e->dynstr = (const char *)base + dynstr->sh_offset;
                                e->dynstr_size = dynstr->sh_size;
                            }
                        }
                    }
                } else if (sh->sh_type == SHT_DYNAMIC && !e->e32.dynamic) {
                    if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                        e->e32.dynamic = (Elf32_Dyn *)((char *)base + sh->sh_offset);
                        e->dynamic_count = sh->sh_size / sizeof(Elf32_Dyn);
                    }
                }
            }
        }
    } else if (ELF_IS_64(e)) {
        if (size < sizeof(Elf64_Ehdr)) {
            if (owns_base) { munmap(base, size); e->base = NULL; }
            SET_ERR(e, E_TRUNCATED, "truncated ELF64 header"); return E_TRUNCATED;
        }
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;
        e->e64.ehdr = ehdr;
        e->elf_type = ehdr->e_type;
        e->elf_machine = ehdr->e_machine;
        e->shnum = ehdr->e_shnum;
        e->phnum = ehdr->e_phnum;

        if (ehdr->e_machine != EM_AARCH64) {
            if (owns_base) { munmap(base, size); e->base = NULL; }
            SET_ERR(e, E_NOT_ARM, "not AArch64 (machine=0x%x)", e->elf_machine); return E_NOT_ARM;
        }
        if (ehdr->e_type != ET_REL && ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
            if (owns_base) { munmap(base, size); e->base = NULL; }
            SET_ERR(e, E_BAD_TYPE, "unsupported ELF type %d", e->elf_type); return E_BAD_TYPE;
        }

        if (ehdr->e_shnum > 0 && ehdr->e_shoff > 0) {
            size_t shdrs_size;
            if (__builtin_mul_overflow(ehdr->e_shnum, sizeof(Elf64_Shdr), &shdrs_size)) {
                if (owns_base) { munmap(base, size); e->base = NULL; }
                SET_ERR(e, E_TRUNCATED, "section header count overflow"); return E_TRUNCATED;
            }
            if (!in_bounds(e, ehdr->e_shoff, shdrs_size)) {
                if (owns_base) { munmap(base, size); e->base = NULL; }
                SET_ERR(e, E_TRUNCATED, "section headers past EOF"); return E_TRUNCATED;
            }
            e->e64.shdrs = (Elf64_Shdr *)((char *)base + ehdr->e_shoff);

            if (ehdr->e_shstrndx < ehdr->e_shnum) {
                Elf64_Shdr *shstr = &e->e64.shdrs[ehdr->e_shstrndx];
                if (in_bounds(e, shstr->sh_offset, shstr->sh_size)) {
                    e->shstrtab = (const char *)base + shstr->sh_offset;
                    e->shstrtab_size = shstr->sh_size;
                }
            }
        }

        if (ehdr->e_phnum > 0 && ehdr->e_phoff > 0) {
            size_t phdrs_size;
            if (__builtin_mul_overflow(ehdr->e_phnum, sizeof(Elf64_Phdr), &phdrs_size)) {
                if (owns_base) { munmap(base, size); e->base = NULL; }
                SET_ERR(e, E_TRUNCATED, "program header count overflow"); return E_TRUNCATED;
            }
            if (!in_bounds(e, ehdr->e_phoff, phdrs_size)) {
                if (owns_base) { munmap(base, size); e->base = NULL; }
                SET_ERR(e, E_TRUNCATED, "program headers past EOF"); return E_TRUNCATED;
            }
            e->e64.phdrs = (Elf64_Phdr *)((char *)base + ehdr->e_phoff);
        }

        if (e->e64.shdrs) {
            for (uint32_t i = 0; i < ehdr->e_shnum; i++) {
                Elf64_Shdr *sh = &e->e64.shdrs[i];
                if (sh->sh_type == SHT_SYMTAB && !e->e64.symtab) {
                    if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                        e->e64.symtab = (Elf64_Sym *)((char *)base + sh->sh_offset);
                        e->symtab_count = sh->sh_size / sizeof(Elf64_Sym);
                        if (sh->sh_link < ehdr->e_shnum) {
                            Elf64_Shdr *strtab = &e->e64.shdrs[sh->sh_link];
                            if (in_bounds(e, strtab->sh_offset, strtab->sh_size)) {
                                e->strtab = (const char *)base + strtab->sh_offset;
                                e->strtab_size = strtab->sh_size;
                            }
                        }
                    }
                } else if (sh->sh_type == SHT_DYNSYM && !e->e64.dynsym) {
                    if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                        e->e64.dynsym = (Elf64_Sym *)((char *)base + sh->sh_offset);
                        e->dynsym_count = sh->sh_size / sizeof(Elf64_Sym);
                        if (sh->sh_link < ehdr->e_shnum) {
                            Elf64_Shdr *dynstr = &e->e64.shdrs[sh->sh_link];
                            if (in_bounds(e, dynstr->sh_offset, dynstr->sh_size)) {
                                e->dynstr = (const char *)base + dynstr->sh_offset;
                                e->dynstr_size = dynstr->sh_size;
                            }
                        }
                    }
                } else if (sh->sh_type == SHT_DYNAMIC && !e->e64.dynamic) {
                    if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                        e->e64.dynamic = (Elf64_Dyn *)((char *)base + sh->sh_offset);
                        e->dynamic_count = sh->sh_size / sizeof(Elf64_Dyn);
                    }
                }
            }
        }
    } else {
        if (owns_base) { munmap(base, size); e->base = NULL; }
        SET_ERR(e, E_BAD_CLASS, "unsupported ELF class %d", e->elf_class); return E_BAD_CLASS;
    }

    return E_OK;
}

int elf_open(elf_t *e, const char *path) {
    if (!e) return E_NULLPTR;
    if (!path) { SET_ERR(e, E_NULLPTR, "path is NULL"); return E_NULLPTR; }

    memset(e, 0, sizeof(*e));
    e->path = path;

    int fd = open(path, O_RDONLY);
    if (fd < 0) { SET_ERR(e, E_MMAP, "open '%s': %s", path, strerror(errno)); return E_MMAP; }

    struct stat st;
    if (fstat(fd, &st) < 0) { SET_ERR(e, E_MMAP, "fstat: %s", strerror(errno)); close(fd); return E_MMAP; }

    void *base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { SET_ERR(e, E_MMAP, "mmap: %s", strerror(errno)); return E_MMAP; }

    return elf_parse_internal(e, base, st.st_size, true);
}

int elf_open_mem(elf_t *e, const void *data, size_t size) {
    if (!e) return E_NULLPTR;
    if (!data) { SET_ERR(e, E_NULLPTR, "data is NULL"); return E_NULLPTR; }
    if (size == 0) { SET_ERR(e, E_TRUNCATED, "size is 0"); return E_TRUNCATED; }

    memset(e, 0, sizeof(*e));
    e->path = "(memory)";

    /* For memory buffers, caller owns memory */
    return elf_parse_internal(e, (void *)data, size, false);
}

void elf_close(elf_t *e) {
    if (!e) return;
    /* Only unmap if we own the memory (path != "(memory)") */
    if (e->base && e->base != MAP_FAILED && e->path && strcmp(e->path, "(memory)") != 0) {
        munmap(e->base, e->size);
    }
    memset(e, 0, sizeof(*e));
}

/*
 * Index-based accessors - all return widest type (uint64_t) to unify the API.
 * These are marked hot because they're all called frequently during linking. 
 * https://gcc.gnu.org/onlinedocs/gcc-15.2.0/gcc/Common-Function-Attributes.html#index-hot-function-attribute:~:text=its%20special%20behavior.-,hot,-%C2%B6
 * The branch predictor will learn elf_class very quickly, as it remains the
 * same for a given elf_t.
 */

__attribute__((hot))
uint64_t elf_sh_addr(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return 0;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_addr : e->e32.shdrs[i].sh_addr;
}

__attribute__((hot))
uint64_t elf_sh_size(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return 0;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_size : e->e32.shdrs[i].sh_size;
}

__attribute__((hot))
uint64_t elf_sh_offset(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return 0;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_offset : e->e32.shdrs[i].sh_offset;
}

uint32_t elf_sh_type(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return SHT_NULL;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_type : e->e32.shdrs[i].sh_type;
}

uint64_t elf_sh_flags(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return 0;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_flags : e->e32.shdrs[i].sh_flags;
}

uint32_t elf_sh_link(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return 0;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_link : e->e32.shdrs[i].sh_link;
}

uint32_t elf_sh_info(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return 0;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_info : e->e32.shdrs[i].sh_info;
}

uint64_t elf_sh_addralign(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return 0;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_addralign : e->e32.shdrs[i].sh_addralign;
}

uint64_t elf_sh_entsize(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return 0;
    return ELF_IS_64(e) ? e->e64.shdrs[i].sh_entsize : e->e32.shdrs[i].sh_entsize;
}

/*
 * Safe string accessor - checks offset is within table bounds.
 * Returns empty string for invalid offsets, "<corrupt>" for non-terminated strings.
 */
static const char *safe_string(const char *strtab, size_t strtab_size, uint32_t offset) {
    if (!strtab || offset >= strtab_size) return "";
    /* Check string terminates within the table */
    size_t max_len = strtab_size - offset;
    if (strnlen(strtab + offset, max_len) == max_len) return "<corrupt>";
    return strtab + offset;
}

const char *elf_sh_name(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum || !e->shstrtab) return "";
    uint32_t name_off = ELF_IS_64(e) ? e->e64.shdrs[i].sh_name : e->e32.shdrs[i].sh_name;
    return safe_string(e->shstrtab, e->shstrtab_size, name_off);
}

void *elf_sh_data(const elf_t *e, uint32_t i) {
    if (!e || i >= e->shnum) return NULL;
    uint32_t type = elf_sh_type(e, i);
    if (type == SHT_NOBITS) return NULL;
    uint64_t off = elf_sh_offset(e, i);
    uint64_t sz = elf_sh_size(e, i);
    if (!in_bounds(e, off, sz)) return NULL;
    return (char *)e->base + off;
}

ssize_t elf_sh_find(const elf_t *e, const char *name) {
    if (!e || !name || !e->shstrtab) return -1;
    for (uint32_t i = 0; i < e->shnum; i++) {
        if (strcmp(elf_sh_name(e, i), name) == 0) return (ssize_t)i;
    }
    return -1;
}

ssize_t elf_sh_find_type(const elf_t *e, uint32_t type) {
    if (!e) return -1;
    for (uint32_t i = 0; i < e->shnum; i++) {
        if (elf_sh_type(e, i) == type) return (ssize_t)i;
    }
    return -1;
}

uint32_t elf_ph_type(const elf_t *e, uint32_t i) {
    if (!e || i >= e->phnum) return PT_NULL;
    return ELF_IS_64(e) ? e->e64.phdrs[i].p_type : e->e32.phdrs[i].p_type;
}

uint32_t elf_ph_flags(const elf_t *e, uint32_t i) {
    if (!e || i >= e->phnum) return 0;
    return ELF_IS_64(e) ? e->e64.phdrs[i].p_flags : e->e32.phdrs[i].p_flags;
}

__attribute__((hot))
uint64_t elf_ph_offset(const elf_t *e, uint32_t i) {
    if (!e || i >= e->phnum) return 0;
    return ELF_IS_64(e) ? e->e64.phdrs[i].p_offset : e->e32.phdrs[i].p_offset;
}

__attribute__((hot))
uint64_t elf_ph_vaddr(const elf_t *e, uint32_t i) {
    if (!e || i >= e->phnum) return 0;
    return ELF_IS_64(e) ? e->e64.phdrs[i].p_vaddr : e->e32.phdrs[i].p_vaddr;
}

uint64_t elf_ph_paddr(const elf_t *e, uint32_t i) {
    if (!e || i >= e->phnum) return 0;
    return ELF_IS_64(e) ? e->e64.phdrs[i].p_paddr : e->e32.phdrs[i].p_paddr;
}

__attribute__((hot))
uint64_t elf_ph_filesz(const elf_t *e, uint32_t i) {
    if (!e || i >= e->phnum) return 0;
    return ELF_IS_64(e) ? e->e64.phdrs[i].p_filesz : e->e32.phdrs[i].p_filesz;
}

__attribute__((hot))
uint64_t elf_ph_memsz(const elf_t *e, uint32_t i) {
    if (!e || i >= e->phnum) return 0;
    return ELF_IS_64(e) ? e->e64.phdrs[i].p_memsz : e->e32.phdrs[i].p_memsz;
}

uint64_t elf_ph_align(const elf_t *e, uint32_t i) {
    if (!e || i >= e->phnum) return 0;
    return ELF_IS_64(e) ? e->e64.phdrs[i].p_align : e->e32.phdrs[i].p_align;
}

__attribute__((hot))
uint64_t elf_sym_value(const elf_t *e, uint32_t i, bool dyn) {
    if (!e) return 0;
    uint32_t count = dyn ? e->dynsym_count : e->symtab_count;
    if (i >= count) return 0;
    if (ELF_IS_64(e)) {
        Elf64_Sym *tab = dyn ? e->e64.dynsym : e->e64.symtab;
        return tab ? tab[i].st_value : 0;
    } else {
        Elf32_Sym *tab = dyn ? e->e32.dynsym : e->e32.symtab;
        return tab ? tab[i].st_value : 0;
    }
}

uint64_t elf_sym_size(const elf_t *e, uint32_t i, bool dyn) {
    if (!e) return 0;
    uint32_t count = dyn ? e->dynsym_count : e->symtab_count;
    if (i >= count) return 0;
    if (ELF_IS_64(e)) {
        Elf64_Sym *tab = dyn ? e->e64.dynsym : e->e64.symtab;
        return tab ? tab[i].st_size : 0;
    } else {
        Elf32_Sym *tab = dyn ? e->e32.dynsym : e->e32.symtab;
        return tab ? tab[i].st_size : 0;
    }
}

uint8_t elf_sym_info(const elf_t *e, uint32_t i, bool dyn) {
    if (!e) return 0;
    uint32_t count = dyn ? e->dynsym_count : e->symtab_count;
    if (i >= count) return 0;
    if (ELF_IS_64(e)) {
        Elf64_Sym *tab = dyn ? e->e64.dynsym : e->e64.symtab;
        return tab ? tab[i].st_info : 0;
    } else {
        Elf32_Sym *tab = dyn ? e->e32.dynsym : e->e32.symtab;
        return tab ? tab[i].st_info : 0;
    }
}

uint8_t elf_sym_other(const elf_t *e, uint32_t i, bool dyn) {
    if (!e) return 0;
    uint32_t count = dyn ? e->dynsym_count : e->symtab_count;
    if (i >= count) return 0;
    if (ELF_IS_64(e)) {
        Elf64_Sym *tab = dyn ? e->e64.dynsym : e->e64.symtab;
        return tab ? tab[i].st_other : 0;
    } else {
        Elf32_Sym *tab = dyn ? e->e32.dynsym : e->e32.symtab;
        return tab ? tab[i].st_other : 0;
    }
}

__attribute__((hot))
uint16_t elf_sym_shndx(const elf_t *e, uint32_t i, bool dyn) {
    if (!e) return SHN_UNDEF;
    uint32_t count = dyn ? e->dynsym_count : e->symtab_count;
    if (i >= count) return SHN_UNDEF;
    if (ELF_IS_64(e)) {
        Elf64_Sym *tab = dyn ? e->e64.dynsym : e->e64.symtab;
        return tab ? tab[i].st_shndx : SHN_UNDEF;
    } else {
        Elf32_Sym *tab = dyn ? e->e32.dynsym : e->e32.symtab;
        return tab ? tab[i].st_shndx : SHN_UNDEF;
    }
}

const char *elf_sym_name(const elf_t *e, uint32_t i, bool dyn) {
    if (!e) return "";
    uint32_t count = dyn ? e->dynsym_count : e->symtab_count;
    if (i >= count) return "";
    const char *strtab = dyn ? e->dynstr : e->strtab;
    size_t strtab_size = dyn ? e->dynstr_size : e->strtab_size;
    if (!strtab) return "";
    uint32_t name_off;
    if (ELF_IS_64(e)) {
        Elf64_Sym *tab = dyn ? e->e64.dynsym : e->e64.symtab;
        if (!tab) return "";
        name_off = tab[i].st_name;
    } else {
        Elf32_Sym *tab = dyn ? e->e32.dynsym : e->e32.symtab;
        if (!tab) return "";
        name_off = tab[i].st_name;
    }
    return safe_string(strtab, strtab_size, name_off);
}

ssize_t elf_sym_find(const elf_t *e, const char *name, bool dyn) {
    if (!e || !name) return -1;
    uint32_t count = dyn ? e->dynsym_count : e->symtab_count;
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(elf_sym_name(e, i, dyn), name) == 0) return (ssize_t)i;
    }
    return -1;
}

bool elf_is_mapping_sym(const char *name) {
    if (!name || name[0] != '$') return false;
    /* ARM/AArch64 mapping symbols: $a, $t, $d, $x (and variants like $a.0) */
    if (name[1] == 'a' || name[1] == 't' || name[1] == 'd' || name[1] == 'x')
        return (name[2] == '\0' || name[2] == '.');
    return false;
}

int64_t elf_dyn_tag(const elf_t *e, uint32_t i) {
    if (!e || i >= e->dynamic_count) return DT_NULL;
    if (ELF_IS_64(e)) {
        return e->e64.dynamic ? e->e64.dynamic[i].d_tag : DT_NULL;
    } else {
        return e->e32.dynamic ? e->e32.dynamic[i].d_tag : DT_NULL;
    }
}

uint64_t elf_dyn_val(const elf_t *e, uint32_t i) {
    if (!e || i >= e->dynamic_count) return 0;
    if (ELF_IS_64(e)) {
        return e->e64.dynamic ? e->e64.dynamic[i].d_un.d_val : 0;
    } else {
        return e->e32.dynamic ? e->e32.dynamic[i].d_un.d_val : 0;
    }
}

const char *elf_type_str(uint16_t type) {
    switch (type) {
        case ET_NONE: return "NONE"; case ET_REL: return "REL (Relocatable)";
        case ET_EXEC: return "EXEC (Executable)"; case ET_DYN: return "DYN (Shared object)";
        case ET_CORE: return "CORE"; default: return "UNKNOWN";
    }
}

const char *elf_machine_str(uint16_t machine) {
    switch (machine) {
        case EM_ARM: return "ARM";
        case EM_AARCH64: return "AArch64";
        default: return "Unknown";
    }
}

const char *elf_shtype_str(uint32_t type, uint16_t machine) {
    /* Has duplicate with ARM32 */
    if(machine == EM_AARCH64)
        if (type == SHT_AARCH64_ATTRIBUTES) return "AARCH64_ATTRIBUTES";
    
    switch (type) {
        case SHT_NULL: return "NULL"; case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB"; case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA"; case SHT_HASH: return "HASH";
        case SHT_DYNAMIC: return "DYNAMIC"; case SHT_NOTE: return "NOTE";
        case SHT_NOBITS: return "NOBITS"; case SHT_REL: return "REL";
        case SHT_DYNSYM: return "DYNSYM"; case SHT_INIT_ARRAY: return "INIT_ARRAY";
        case SHT_FINI_ARRAY: return "FINI_ARRAY"; case SHT_GNU_HASH: return "GNU_HASH";
        case SHT_GNU_verdef: return "VERDEF"; case SHT_GNU_verneed: return "VERNEED";
        case SHT_GNU_versym: return "VERSYM"; case SHT_ARM_EXIDX: return "ARM_EXIDX";
        case SHT_ARM_ATTRIBUTES: return "ARM_ATTRIBUTES";
        default: return (type >= SHT_LOPROC && type <= SHT_HIPROC) ? "PROC" : "UNKNOWN";
    }
}

const char *elf_phtype_str(uint32_t type, uint16_t machine) {
    /* Has duplicate with ARM32 */
    if (machine == EM_AARCH64) 
        if (type == PT_AARCH64_UNWIND) return "AARCH64_UNWIND"; 
    
    switch (type) {
        case PT_NULL: return "NULL"; case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC"; case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE"; case PT_PHDR: return "PHDR"; case PT_TLS: return "TLS";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME"; case PT_GNU_STACK: return "GNU_STACK";
        case PT_GNU_RELRO: return "GNU_RELRO"; case PT_GNU_PROPERTY: return "GNU_PROPERTY";
        case PT_ARM_EXIDX: return "ARM_EXIDX"; case PT_ARM_ARCHEXT: return "ARM_ARCHEXT";
        default: return "UNKNOWN";
    }
}

const char *elf_sym_bind_str(uint8_t info) {
    switch (ELF32_ST_BIND(info)) {
        case STB_LOCAL: return "LOCAL"; case STB_GLOBAL: return "GLOBAL";
        case STB_WEAK: return "WEAK"; default: return "UNKNOWN";
    }
}

const char *elf_sym_type_str(uint8_t info) {
    switch (ELF32_ST_TYPE(info)) {
        case STT_NOTYPE: return "NOTYPE"; case STT_OBJECT: return "OBJECT";
        case STT_FUNC: return "FUNC"; case STT_SECTION: return "SECTION";
        case STT_FILE: return "FILE"; case STT_COMMON: return "COMMON";
        case STT_TLS: return "TLS"; case STT_GNU_IFUNC: return "GNU_IFUNC";
        case STT_ARM_TFUNC: return "ARM_TFUNC";
        default: return "UNKNOWN";
    }
}

const char *elf_sym_vis_str(uint8_t other) {
    switch (ELF32_ST_VISIBILITY(other)) { /* Same macro works for 64-bit */
        case STV_DEFAULT: return "DEFAULT"; case STV_INTERNAL: return "INTERNAL";
        case STV_HIDDEN: return "HIDDEN"; case STV_PROTECTED: return "PROTECTED";
        default: return "UNKNOWN";
    }
}

const char *elf_reloc_type_str(uint16_t machine, uint32_t type) {
    if (machine == EM_AARCH64) {
        switch (type) {
            case R_AARCH64_NONE: return "R_AARCH64_NONE";case R_AARCH64_ABS64: return "R_AARCH64_ABS64";
            case R_AARCH64_ABS32: return "R_AARCH64_ABS32";case R_AARCH64_COPY: return "R_AARCH64_COPY";
            case R_AARCH64_GLOB_DAT: return "R_AARCH64_GLOB_DAT"; case R_AARCH64_JUMP_SLOT: return "R_AARCH64_JUMP_SLOT";
            case R_AARCH64_RELATIVE: return "R_AARCH64_RELATIVE"; case R_AARCH64_TLS_DTPMOD: return "R_AARCH64_TLS_DTPMOD";
            case R_AARCH64_TLS_DTPREL: return "R_AARCH64_TLS_DTPREL"; case R_AARCH64_TLS_TPREL: return "R_AARCH64_TLS_TPREL";
            case R_AARCH64_TLSDESC: return "R_AARCH64_TLSDESC"; case R_AARCH64_CALL26: return "R_AARCH64_CALL26";
            case R_AARCH64_JUMP26: return "R_AARCH64_JUMP26"; case R_AARCH64_ADR_PREL_PG_HI21: return "R_AARCH64_ADR_PREL_PG_HI21";
            case R_AARCH64_ADD_ABS_LO12_NC: return "R_AARCH64_ADD_ABS_LO12_NC"; default: return "R_AARCH64_UNKNOWN";
        }
    }
    switch (type) {
        case R_ARM_NONE: return "R_ARM_NONE";   case R_ARM_ABS32: return "R_ARM_ABS32";
        case R_ARM_REL32: return "R_ARM_REL32"; case R_ARM_CALL: return "R_ARM_CALL";
        case R_ARM_GLOB_DAT: return "R_ARM_GLOB_DAT"; case R_ARM_JUMP_SLOT: return "R_ARM_JUMP_SLOT"; 
        case R_ARM_RELATIVE: return "R_ARM_RELATIVE"; case R_ARM_COPY: return "R_ARM_COPY"; 
        case R_ARM_TLS_DTPMOD32: return "R_ARM_TLS_DTPMOD32"; case R_ARM_TLS_TPOFF32: 
        case R_ARM_JUMP24: return "R_ARM_JUMP24"; case R_ARM_ABS12: return "R_ARM_ABS12";
        case R_ARM_PREL31: return "R_ARM_PREREL31"; default: return "R_ARM_UNKNOWN";
    }
}

const char *elf_dyn_tag_str(int64_t tag) {
    switch (tag) {
        case DT_NULL: return "NULL"; case DT_NEEDED: return "NEEDED";
        case DT_PLTRELSZ: return "PLTRELSZ"; case DT_PLTGOT: return "PLTGOT";
        case DT_HASH: return "HASH"; case DT_STRTAB: return "STRTAB";
        case DT_SYMTAB: return "SYMTAB"; case DT_RELA: return "RELA";
        case DT_RELASZ: return "RELASZ"; case DT_RELAENT: return "RELAENT";
        case DT_STRSZ: return "STRSZ"; case DT_SYMENT: return "SYMENT";
        case DT_INIT: return "INIT"; case DT_FINI: return "FINI";
        case DT_SONAME: return "SONAME"; case DT_RPATH: return "RPATH";
        case DT_REL: return "REL"; case DT_RELSZ: return "RELSZ";
        case DT_RELENT : return "RELENT"; case DT_PLTREL: return "PLTREL";
        case DT_DEBUG  : return "DEBUG"; case DT_TEXTREL: return "TEXTREL";
        case DT_JMPREL: return "JMPREL"; case DT_BIND_NOW: return "BIND_NOW";
        case DT_INIT_ARRAY: return "INIT_ARRAY"; case DT_FINI_ARRAY: return "FINI_ARRAY";
        case DT_INIT_ARRAYSZ: return "INIT_ARRAYSZ"; case DT_FINI_ARRAYSZ: return "FINI_ARRAYSZ";
        case DT_RUNPATH: return "RUNPATH"; case DT_FLAGS: return "FLAGS";
        case DT_PREINIT_ARRAY: return "PREINIT_ARRAY"; case DT_PREINIT_ARRAYSZ: return "PREINIT_ARRAYSZ"; 
        case DT_NUM: return "NUM"; case DT_GNU_HASH: return "GNU_HASH"; 
        case DT_VERNEED : return "VERNEED"; case DT_VERNEEDNUM: return "VERNEEDNUM";
        case DT_VERSYM: return "VERSYM"; case DT_VERDEF: return "VERDEF";
        case DT_VERDEFNUM: return "VERDEFNUM"; case DT_RELACOUNT: return "RELACOUNT"; 
        case DT_RELCOUNT: return "RELCOUNT"; case DT_FLAGS_1: return "FLAGS_1";
        case DT_AUXILIARY: return "AUXILIARY"; case DT_FILTER: return "FILTER";
        case DT_POSFLAG_1: return "POSFLAG_1"; case DT_ARM_SYMTABSZ: return "ARM_SYMTABSZ";
        case DT_AARCH64_VARIANT_PCS: return "DT_AARCH64_VARIANT_PCS"; default: return "UNKNOWN";
    }
}

#define ADDR_WIDTH(e)   ELF_IS_64(e) ? 16 : 8

#define FMT_NAME_W      17
#define FMT_TYPE_W      15      
#define FMT_OFFSET_W    6      
#define FMT_SIZE_W      6    
#define FMT_ENTSIZE_W   2       
#define FMT_SHNDX_W     2       
#define FMT_SYMSIZE_W   5      
#define FMT_RELTYPE_W   20     
#define FMT_DYNTAG_W    28      

static void print_arm_flags(uint32_t flags) {
    printf("  ARM flags: 0x%08x\n", flags);
    printf("    EABI version: %u\n", arm_eabi_ver(flags));
    if (arm_be8(flags)) printf("    BE-8\n");
    if (arm_hard_float(flags)) printf("    Hard float\n");
    if (arm_soft_float(flags)) printf("    Soft float\n");
}

static void print_ehdr(const elf_t *e) {
    if (!e) return;
    const unsigned char *ident = (const unsigned char *)e->base;
    printf("ELF Header:\n  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) printf("%02x ", ident[i]);
    printf("\n  Class:                             %s\n", ELF_IS_64(e) ? "ELF64" : "ELF32");
    printf("  Data:                              %s\n",
           ident[EI_DATA] == ELFDATA2LSB ? "little endian" : "big endian");
    printf("  Type:                              %s\n", elf_type_str(e->elf_type));
    printf("  Machine:                           %s\n", elf_machine_str(e->elf_machine));
    printf("  Entry point address:               0x%lx\n", (unsigned long)elf_entry(e));
    if (ELF_IS_64(e)) {
        printf("  Start of program headers:          %lu (bytes)\n", (unsigned long)e->e64.ehdr->e_phoff);
        printf("  Start of section headers:          %lu (bytes)\n", (unsigned long)e->e64.ehdr->e_shoff);
    } else {
        printf("  Start of program headers:          %u (bytes)\n", e->e32.ehdr->e_phoff);
        printf("  Start of section headers:          %u (bytes)\n", e->e32.ehdr->e_shoff);
    }
    printf("  Flags:                             0x%x\n", elf_flags(e));
    printf("  Number of program headers:         %u\n", e->phnum);
    printf("  Number of section headers:         %u\n", e->shnum);
    if (e->elf_machine == EM_ARM && elf_flags(e)) print_arm_flags(elf_flags(e));
}

static void print_shflags(uint64_t flags) {
    char buf[16] = {0}; int i = 0;
    if (flags & SHF_WRITE) buf[i++] = 'W';
    if (flags & SHF_ALLOC) buf[i++] = 'A';
    if (flags & SHF_EXECINSTR) buf[i++] = 'X';
    if (flags & SHF_MERGE) buf[i++] = 'M';
    if (flags & SHF_STRINGS) buf[i++] = 'S';
    if (flags & SHF_TLS) buf[i++] = 'T';
    printf("%s", buf);
}

static void print_shdrs(const elf_t *e) {
    if (!e || e->shnum == 0) { printf("No section headers.\n"); return; }
    int w = ADDR_WIDTH(e);
    printf("\nSection Headers:\n");
    printf("  [Nr] %-*s %-*s %-*s %-*s %-*s ES Flg Lk Inf Al\n",
           FMT_NAME_W, "Name", FMT_TYPE_W, "Type", w, "Address",
           FMT_OFFSET_W, "Off", FMT_SIZE_W, "Size");
    for (uint32_t i = 0; i < e->shnum; i++) {
        printf("  [%2u] %-*.*s %-*s %0*lx %0*lx %0*lx %0*lx ",
               i, FMT_NAME_W, FMT_NAME_W, elf_sh_name(e, i),
               FMT_TYPE_W, elf_shtype_str(elf_sh_type(e, i), e->elf_machine),
               w, (unsigned long)elf_sh_addr(e, i),
               FMT_OFFSET_W, (unsigned long)elf_sh_offset(e, i),
               FMT_SIZE_W, (unsigned long)elf_sh_size(e, i),
               FMT_ENTSIZE_W, (unsigned long)elf_sh_entsize(e, i));
        print_shflags(elf_sh_flags(e, i));
        printf(" %*u %3u %2lu\n", FMT_SHNDX_W, elf_sh_link(e, i), elf_sh_info(e, i),
               (unsigned long)elf_sh_addralign(e, i));
    }
}

static void print_phdrs(const elf_t *e) {
    if (!e || e->phnum == 0) {
        printf("\nNo program headers.\n"); return;
    }
    int w = ADDR_WIDTH(e);
    printf("\nProgram Headers:\n");
    printf("  %-14s %-8s %-*s %-*s %-7s %-7s Flg Align\n",
           "Type", "Offset", w, "VirtAddr", w, "PhysAddr", "FileSiz", "MemSiz");
    for (uint32_t i = 0; i < e->phnum; i++) {
        uint32_t flags = elf_ph_flags(e, i);
        printf("  %-14s 0x%0*lx 0x%0*lx 0x%0*lx 0x%05lx 0x%05lx %c%c%c 0x%lx\n",
               elf_phtype_str(elf_ph_type(e, i), e->elf_machine),
               FMT_OFFSET_W, (unsigned long)elf_ph_offset(e, i),
               w, (unsigned long)elf_ph_vaddr(e, i),
               w, (unsigned long)elf_ph_paddr(e, i),
               (unsigned long)elf_ph_filesz(e, i),
               (unsigned long)elf_ph_memsz(e, i),
               (flags & PF_R) ? 'R' : ' ', (flags & PF_W) ? 'W' : ' ',
               (flags & PF_X) ? 'X' : ' ', (unsigned long)elf_ph_align(e, i));
        if (elf_ph_type(e, i) == PT_INTERP && elf_ph_filesz(e, i) > 0)
            printf("      [Interpreter: %s]\n", (const char *)e->base + elf_ph_offset(e, i));
    }
}

/*
 * A section is in a segment if: sh_addr >= p_vaddr && sh_addr + sh_size <= p_vaddr + p_memsz
 * Or:  S ∈ P  ⇔  [ S.sh_addr, S.sh_addr + S.sh_size )  ⊆  [ P.p_vaddr, P.p_vaddr + P.p_memsz )
 * For SHT_NULL or sections with sh_addr == 0, we use file offset comparison.
 */
static void print_section_to_segment(const elf_t *e) {
    if (!e || e->phnum == 0 || e->shnum == 0) return;

    printf("\n Section to Segment mapping:\n");
    printf("  Segment Sections...\n");

    for (uint32_t i = 0; i < e->phnum; i++) {
        printf("   %02u     ", i);
        uint64_t ph_vaddr = elf_ph_vaddr(e, i);
        uint64_t ph_memsz = elf_ph_memsz(e, i);
        uint64_t ph_offset = elf_ph_offset(e, i);
        uint64_t ph_filesz = elf_ph_filesz(e, i);

        for (uint32_t j = 0; j < e->shnum; j++) {
            uint32_t sh_type = elf_sh_type(e, j);
            if (sh_type == SHT_NULL) continue;

            bool in_segment = false;
            uint64_t sh_flags = elf_sh_flags(e, j);
            uint64_t sh_addr = elf_sh_addr(e, j);
            uint64_t sh_size = elf_sh_size(e, j);
            uint64_t sh_offset = elf_sh_offset(e, j);

            if (sh_flags & SHF_ALLOC) {
                /* Allocated sections: use sh_addr */
                uint64_t sh_end = sh_addr + sh_size;
                uint64_t ph_end = ph_vaddr + ph_memsz;
                in_segment = (sh_addr >= ph_vaddr && sh_end <= ph_end);
            } else if (sh_size > 0 && ph_filesz > 0) {
                /* Non-allocated sections (debug, etc): use sh_offset */
                uint64_t sh_end = sh_offset + sh_size;
                uint64_t ph_end = ph_offset + ph_filesz;
                in_segment = (sh_offset >= ph_offset && sh_end <= ph_end);
            }

            if (in_segment)
                printf("%s ", elf_sh_name(e, j));
        }
        printf("\n");
    }
}

static void print_symtab(const elf_t *e, bool dynamic) {
    if (!e) return;
    uint32_t count = dynamic ? e->dynsym_count : e->symtab_count;
    const char *tabname = dynamic ? ".dynsym" : ".symtab";
    
    /* Check if table exists */
    bool has_table = ELF_IS_64(e) 
        ? (dynamic ? e->e64.dynsym != NULL : e->e64.symtab != NULL)
        : (dynamic ? e->e32.dynsym != NULL : e->e32.symtab != NULL);
    
    if (!has_table || count == 0) { printf("\nNo %s.\n", tabname); return; }

    int w = ADDR_WIDTH(e);
    printf("\nSymbol table '%s' contains %u entries:\n", tabname, count);
    printf("   Num:    %-*s  Size Type    Bind   Vis      Ndx Name\n", w, "Value");
    for (uint32_t i = 0; i < count; i++) {
        char ndx[8];
        uint16_t shndx = elf_sym_shndx(e, i, dynamic);
        switch (shndx) {
            case SHN_UNDEF: strcpy(ndx, "UND"); break;
            case SHN_ABS: strcpy(ndx, "ABS"); break;
            case SHN_COMMON: strcpy(ndx, "COM"); break;
            default: snprintf(ndx, sizeof(ndx), "%3u", shndx);
        }
        uint8_t info = elf_sym_info(e, i, dynamic);
        uint64_t value = elf_sym_value(e, i, dynamic);
        printf("  %4u: %0*lx %*lu %-7s %-6s %-8s %s %s",
               i, w, (unsigned long)value,
               FMT_SYMSIZE_W, (unsigned long)elf_sym_size(e, i, dynamic),
               elf_sym_type_str(info), elf_sym_bind_str(info), 
               elf_sym_vis_str(elf_sym_other(e, i, dynamic)),
               ndx, elf_sym_name(e, i, dynamic));
        /* THUMB indicator for ARM32 only */
        if (e->elf_machine == EM_ARM && ELF32_ST_TYPE(info) == STT_FUNC && (value & 1))
            printf(" [THUMB]");
        printf("\n");
    }
}

static void print_relocs(const elf_t *e, uint32_t reloc_idx) {
    if (!e || reloc_idx >= e->shnum) return;
    uint32_t sh_type = elf_sh_type(e, reloc_idx);
    if (sh_type != SHT_REL && sh_type != SHT_RELA) return;

    bool is_rela = (sh_type == SHT_RELA);
    uint32_t sym_sh_idx = elf_sh_link(e, reloc_idx);
    bool use_dynsym = (sym_sh_idx < e->shnum && elf_sh_type(e, sym_sh_idx) == SHT_DYNSYM);
    uint64_t entsize = elf_sh_entsize(e, reloc_idx);
    if (entsize == 0) return;
    uint32_t count = elf_sh_size(e, reloc_idx) / entsize;
    int w = ADDR_WIDTH(e);

    printf("\nRelocation section '%s' at offset 0x%lx contains %u entries:\n",
           elf_sh_name(e, reloc_idx), (unsigned long)elf_sh_offset(e, reloc_idx), count);
    printf(" %-*s  %-*s %-*s %-*s  Sym.Name%s\n",
           w, "Offset", w, "Info", FMT_RELTYPE_W, "Type", w, "Sym.Value",
           is_rela ? " + Addend" : "");

    void *data = elf_sh_data(e, reloc_idx);
    if (!data) return;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t offset, info, sym_val;
        uint32_t sym_idx, type;
        int64_t addend = 0;
        const char *sym_name;

        if (ELF_IS_64(e)) {
            if (is_rela) {
                Elf64_Rela *r = &((Elf64_Rela *)data)[i];
                offset = r->r_offset;
                info = r->r_info;
                sym_idx = ELF64_R_SYM(info);
                type = ELF64_R_TYPE(info);
                addend = r->r_addend;
            } else {
                Elf64_Rel *r = &((Elf64_Rel *)data)[i];
                offset = r->r_offset;
                info = r->r_info;
                sym_idx = ELF64_R_SYM(info);
                type = ELF64_R_TYPE(info);
            }
        } else {
            if (is_rela) {
                Elf32_Rela *r = &((Elf32_Rela *)data)[i];
                offset = r->r_offset;
                info = r->r_info;
                sym_idx = ELF32_R_SYM(info);
                type = ELF32_R_TYPE(info);
                addend = r->r_addend;
            } else {
                Elf32_Rel *r = &((Elf32_Rel *)data)[i];
                offset = r->r_offset;
                info = r->r_info;
                sym_idx = ELF32_R_SYM(info);
                type = ELF32_R_TYPE(info);
            }
        }

        sym_val = elf_sym_value(e, sym_idx, use_dynsym);
        sym_name = elf_sym_name(e, sym_idx, use_dynsym);

        if (is_rela)
            printf("%0*lx  %0*lx %-*s %0*lx   %s + %lx\n",
                   w, (unsigned long)offset, w, (unsigned long)info,
                   FMT_RELTYPE_W, elf_reloc_type_str(e->elf_machine, type),
                   w, (unsigned long)sym_val, sym_name, (unsigned long)addend);
        else
            printf("%0*lx  %0*lx %-*s %0*lx   %s\n",
                   w, (unsigned long)offset, w, (unsigned long)info,
                   FMT_RELTYPE_W, elf_reloc_type_str(e->elf_machine, type),
                   w, (unsigned long)sym_val, sym_name);
    }
}

static void print_all_relocs(const elf_t *e) {
    if (!e || e->shnum == 0) return;
    bool found = false;
    for (uint32_t i = 0; i < e->shnum; i++) {
        uint32_t type = elf_sh_type(e, i);
        if (type == SHT_REL || type == SHT_RELA) {
            print_relocs(e, i); found = true;
        }
    }
    if (!found) printf("\nNo relocations.\n");
}

static void print_dynamic(const elf_t *e) {
    if (!e || e->dynamic_count == 0) {
        printf("\nNo dynamic section.\n"); return;
    }
    int w = ADDR_WIDTH(e);
    printf("\nDynamic section contains %u entries:\n", e->dynamic_count);
    printf("  %-*s %-*s Name/Value\n", w + 2, "Tag", FMT_DYNTAG_W, "Type");
    for (uint32_t i = 0; i < e->dynamic_count; i++) {
        int64_t tag = elf_dyn_tag(e, i);
        if (tag == DT_NULL) break;
        uint64_t val = elf_dyn_val(e, i);
        printf(" 0x%0*lx %-*s ", w, (unsigned long)tag, FMT_DYNTAG_W, elf_dyn_tag_str(tag));
        switch (tag) {
            case DT_NEEDED: case DT_SONAME: case DT_RPATH: case DT_RUNPATH:
                printf("%s\n", e->dynstr ? e->dynstr + val : "(null)"); break;
            case DT_PLTREL:
                printf("%s\n", val == DT_REL ? "REL" : "RELA"); break;
            default: printf("0x%lx\n", (unsigned long)val);
        }
    }
}

#define NOTE_ALIGN(x)   ALIGN_UP((x), 4)

static const char *note_type_str(const char *owner, uint32_t type) {
    if (!owner) owner = "";

    if (strcmp(owner, "GNU") == 0) {
        switch (type) {
            case NT_GNU_ABI_TAG: return "NT_GNU_ABI_TAG";
            case NT_GNU_HWCAP: return "NT_GNU_HWCAP";
            case NT_GNU_BUILD_ID: return "NT_GNU_BUILD_ID";
            case NT_GNU_GOLD_VERSION: return "NT_GNU_GOLD_VERSION";
            case NT_GNU_PROPERTY_TYPE_0: return "NT_GNU_PROPERTY_TYPE_0";
            default: return "NT_GNU_<unknown>";
        }
    }

    /* Linux/CORE notes (including ARM-specific) */
    if (strcmp(owner, "LINUX") == 0 || strcmp(owner, "CORE") == 0) {
        switch (type) {
            case NT_PRSTATUS: return "NT_PRSTATUS"; case NT_PRFPREG: return "NT_PRFPREG";
            case NT_PRPSINFO: return "NT_PRPSINFO"; case NT_TASKSTRUCT: return "NT_TASKSTRUCT";
            case NT_AUXV: return "NT_AUXV"; case NT_SIGINFO: return "NT_SIGINFO";
            case NT_FILE: return "NT_FILE";
            /* ARM-specific - Exhaustive, I couldn't find much info on these when I looked so I just included all of them */
            case NT_ARM_VFP: return "NT_ARM_VFP"; case NT_ARM_TLS: return "NT_ARM_TLS";
            case NT_ARM_HW_BREAK: return "NT_ARM_HW_BREAK"; case NT_ARM_HW_WATCH: return "NT_ARM_HW_WATCH";
            case NT_ARM_SYSTEM_CALL: return "NT_ARM_SYSTEM_CALL"; case NT_ARM_SVE: return "NT_ARM_SVE";
            case NT_ARM_PAC_MASK: return "NT_ARM_PAC_MASK"; case NT_ARM_PACA_KEYS: return "NT_ARM_PACA_KEYS";
            case NT_ARM_PACG_KEYS: return "NT_ARM_PACG_KEYS"; case NT_ARM_TAGGED_ADDR_CTRL: return "NT_ARM_TAGGED_ADDR_CTRL";
            case NT_ARM_PAC_ENABLED_KEYS: return "NT_ARM_PAC_ENABLED_KEYS"; case NT_ARM_SSVE: return "NT_ARM_SSVE";
            case NT_ARM_ZA: return "NT_ARM_ZA"; case NT_ARM_ZT: return "NT_ARM_ZT";
            case NT_ARM_FPMR: return "NT_ARM_FPMR"; case NT_ARM_POE: return "NT_ARM_POE";
            case NT_ARM_GCS: return "NT_ARM_GCS"; default: return "NT_<unknown>";
        }
    }

    return "NT_<unknown>";
}

static void print_note(const char *name, uint32_t descsz, uint32_t type,
                       const void *desc) {
    printf("  %-16s 0x%08x  %s\n", name, descsz, note_type_str(name, type));

    if (!desc || descsz == 0) return;

    /* Print descriptor content for known GNU types */
    if (strcmp(name, "GNU") == 0) {
        switch (type) {
            case NT_GNU_BUILD_ID: {
                printf("    Build ID: ");
                const uint8_t *id = (const uint8_t *)desc;
                for (uint32_t i = 0; i < descsz; i++) printf("%02x", id[i]);
                printf("\n");
                break;
            }
            case NT_GNU_ABI_TAG: {
                if (descsz >= 16) {
                    const uint32_t *d = (const uint32_t *)desc;
                    const char *os;
                    switch (d[0]) {
                        case 0: os = "Linux"; break; case 1: os = "GNU"; break;
                        case 2: os = "Solaris2"; break; case 3: os = "FreeBSD"; break;
                        default: os = "Unknown"; break;
                    }
                    printf("    OS: %s, ABI: %u.%u.%u\n", os, d[1], d[2], d[3]);
                }
                break;
            }
            case NT_GNU_GOLD_VERSION:
                printf("    Version: %.*s\n", descsz, (const char *)desc);
                break;
            case NT_GNU_PROPERTY_TYPE_0: {
                printf("    Properties:\n");
                const uint8_t *p = (const uint8_t *)desc;
                const uint8_t *pend = p + descsz;
                while (p + 8 <= pend) {
                    uint32_t pr_type = *(const uint32_t *)p;
                    uint32_t pr_datasz = *(const uint32_t *)(p + 4);
                    printf("      type=0x%x, datasz=%u\n", pr_type, pr_datasz);
                    p += 8 + NOTE_ALIGN(pr_datasz);
                }
                break;
            }
        }
    }
}

/* Note: Elf32_Nhdr and Elf64_Nhdr are identical - both use 32-bit fields */
static void print_notes(const elf_t *e) {
    if (!e || e->shnum == 0) return;

    bool found = false;
    for (uint32_t i = 0; i < e->shnum; i++) {
        if (elf_sh_type(e, i) != SHT_NOTE) continue;
        uint64_t sh_offset = elf_sh_offset(e, i);
        uint64_t sh_size = elf_sh_size(e, i);
        if (!in_bounds(e, sh_offset, sh_size)) continue;

        if (!found) {
            printf("\nDisplaying notes found in: %s\n", e->path);
            printf("  %-16s %-11s Type\n", "Owner", "Data size");
            found = true;
        }
        printf(" Section '%s':\n", elf_sh_name(e, i));

        const uint8_t *ptr = (const uint8_t *)e->base + sh_offset;
        const uint8_t *end = ptr + sh_size;

        while (ptr + sizeof(Elf32_Nhdr) <= end) {
            const Elf32_Nhdr *nhdr = (const Elf32_Nhdr *)ptr;
            ptr += sizeof(Elf32_Nhdr);

            size_t name_aligned = NOTE_ALIGN(nhdr->n_namesz);
            size_t desc_aligned = NOTE_ALIGN(nhdr->n_descsz);
            if (ptr + name_aligned + desc_aligned > end) break;

            const char *name = nhdr->n_namesz > 0 ? (const char *)ptr : "";
            const void *desc = nhdr->n_descsz > 0 ? ptr + name_aligned : NULL;

            print_note(name, nhdr->n_descsz, nhdr->n_type, desc);
            ptr += name_aligned + desc_aligned;
        }
    }
    if (!found) printf("\nNo notes.\n");
}

void elf_dump(const elf_t *e) {
    if (!e) return;
    print_ehdr(e);
    print_shdrs(e);
    print_phdrs(e);
    print_section_to_segment(e);
    print_symtab(e, false);
    print_symtab(e, true);
    print_all_relocs(e);
    print_dynamic(e);
    print_notes(e);
}
