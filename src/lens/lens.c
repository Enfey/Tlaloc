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
                                                     
 * lens.c - mmap-based ELF parser for 32/64-bit ARM binaries
 * Supports ET_REL, ET_EXEC, ET_DYN.
 *
 * Copyright (c) 2025 Felix Riley-Kay @ github.com/enfey
 */

#define _GNU_SOURCE
#include "lens.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>

/* Variadic, do while(0) expands the macro to a single statement syntactically so it can be used in if/else. Defensively programmed, but we assume the caller will not exceed sizeof(e->errmsg) */
#define SET_ERR(e, code, fmt, ...) do {                                 \
    (e)->last_err = (code);                                             \
    snprintf((e)->errmsg, sizeof((e)->errmsg), fmt, ##__VA_ARGS__);     \
} while (0)

/* Check if [off, off+len] is within the mmap'd file. Second check catches overflow wraparound */
static inline bool in_bounds(const elf_t *e, size_t off, size_t len) { return (off + len <= e->size) && (off + len >= off); }

int elf_open(elf_t *e, const char *path) {
    if (!e) return E_NULLPTR;
    if (!path) { SET_ERR(e, E_NULLPTR, "path is NULL"); return E_NULLPTR; }

    memset(e, 0, sizeof(*e)); 
    e->path = path;

    int fd = open(path, O_RDONLY);
    if (fd < 0) { SET_ERR(e, E_MMAP, "open '%s': %s", path, strerror(errno)); return E_MMAP; }

    struct stat st;
    if (fstat(fd, &st) < 0) { SET_ERR(e, E_MMAP, "fstat: %s", strerror(errno)); close(fd); return E_MMAP; }
    e->size = st.st_size;

    if (e->size < sizeof(Elf32_Ehdr)) {
        SET_ERR(e, E_TRUNCATED, "file too small"); close(fd); return E_TRUNCATED;
    }

    void *base = mmap(NULL, e->size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { SET_ERR(e, E_MMAP, "mmap: %s", strerror(errno)); return E_MMAP; }
    e->base = base;
    e->ehdr = (Elf32_Ehdr *)base; /*Take first bytes as ELF header*/

    /*Endianness agnostic, everything is 1 byte each in e_ident[EI_NIDENT] - should be noted that ARMv7-A is biendian*/
    if (memcmp(e->ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        munmap(e->base, e->size); e->base = NULL;
        SET_ERR(e, E_NOT_ELF, "not an ELF file"); return E_NOT_ELF;
    }
    if (e->ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        munmap(e->base, e->size); e->base = NULL;
        SET_ERR(e, E_NOT_32BIT, "not 32-bit ELF"); return E_NOT_32BIT;
    }
    if (e->ehdr->e_machine != EM_ARM) {
        munmap(e->base, e->size); e->base = NULL;
        SET_ERR(e, E_NOT_ARM, "not ARM (machine=0x%x)", e->ehdr->e_machine); return E_NOT_ARM;
    }
    uint16_t type = e->ehdr->e_type;
    if (type != ET_REL && type != ET_EXEC && type != ET_DYN) {
        munmap(e->base, e->size); e->base = NULL;
        SET_ERR(e, E_BAD_TYPE, "unsupported ELF type %d", type); return E_BAD_TYPE;
    }

    if (e->ehdr->e_shnum > 0 && e->ehdr->e_shoff > 0) {
        size_t shdrs_size = e->ehdr->e_shnum * sizeof(Elf32_Shdr);
        if (!in_bounds(e, e->ehdr->e_shoff, shdrs_size)) {
            munmap(e->base, e->size); e->base = NULL;
            SET_ERR(e, E_TRUNCATED, "section headers past EOF"); return E_TRUNCATED;
        }
        e->shdrs = (Elf32_Shdr *)((char *)base + e->ehdr->e_shoff);

        if (e->ehdr->e_shstrndx < e->ehdr->e_shnum) {
            Elf32_Shdr *shstr = &e->shdrs[e->ehdr->e_shstrndx];
            if (in_bounds(e, shstr->sh_offset, shstr->sh_size))
                e->shstrtab = (const char *)base + shstr->sh_offset;
        }
    }

    if (e->ehdr->e_phnum > 0 && e->ehdr->e_phoff > 0) {
        size_t phdrs_size = e->ehdr->e_phnum * sizeof(Elf32_Phdr);
        if (!in_bounds(e, e->ehdr->e_phoff, phdrs_size)) {
            munmap(e->base, e->size); e->base = NULL;
            SET_ERR(e, E_TRUNCATED, "program headers past EOF"); return E_TRUNCATED;
        }
        e->phdrs = (Elf32_Phdr *)((char *)base + e->ehdr->e_phoff);
    }

    if (e->shdrs) {
        for (uint32_t i = 0; i < e->ehdr->e_shnum; i++) {
            Elf32_Shdr *sh = &e->shdrs[i];
            if (sh->sh_type == SHT_SYMTAB && !e->symtab) {
                if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                    e->symtab = (Elf32_Sym *)((char *)base + sh->sh_offset);
                    e->symtab_count = sh->sh_size / sizeof(Elf32_Sym);
                    if (sh->sh_link < e->ehdr->e_shnum) {
                        Elf32_Shdr *strtab = &e->shdrs[sh->sh_link];
                        if (in_bounds(e, strtab->sh_offset, strtab->sh_size))
                            e->strtab = (const char *)base + strtab->sh_offset;
                    }
                }
            } else if (sh->sh_type == SHT_DYNSYM && !e->dynsym) {
                if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                    e->dynsym = (Elf32_Sym *)((char *)base + sh->sh_offset);
                    e->dynsym_count = sh->sh_size / sizeof(Elf32_Sym);
                    if (sh->sh_link < e->ehdr->e_shnum) {
                        Elf32_Shdr *dynstr = &e->shdrs[sh->sh_link];
                        if (in_bounds(e, dynstr->sh_offset, dynstr->sh_size))
                            e->dynstr = (const char *)base + dynstr->sh_offset;
                    }
                }
            } else if (sh->sh_type == SHT_DYNAMIC && !e->dynamic) {
                if (in_bounds(e, sh->sh_offset, sh->sh_size)) {
                    e->dynamic = (Elf32_Dyn *)((char *)base + sh->sh_offset);
                    e->dynamic_count = sh->sh_size / sizeof(Elf32_Dyn);
                }
            }
        }
    }
    return E_OK;
}

void elf_close(elf_t *e) {
    if (!e) return;
    if (e->base && e->base != MAP_FAILED) munmap(e->base, e->size);
    memset(e, 0, sizeof(*e));
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
        case EM_ARM: return "ARM"; default: return "Unknown";
    }
}

const char *elf_shtype_str(uint32_t type) {
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

const char *elf_phtype_str(uint32_t type) {
    switch (type) {
        case PT_NULL: return "NULL"; case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC"; case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE"; case PT_PHDR: return "PHDR"; case PT_TLS: return "TLS";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME"; case PT_GNU_STACK: return "GNU_STACK";
        case PT_GNU_RELRO: return "GNU_RELRO"; case PT_ARM_EXIDX: return "ARM_EXIDX";
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

static const char *sym_vis_str(uint8_t other) {
    switch (ELF32_ST_VISIBILITY(other)) {
        case STV_DEFAULT: return "DEFAULT"; case STV_INTERNAL: return "INTERNAL";
        case STV_HIDDEN: return "HIDDEN"; case STV_PROTECTED: return "PROTECTED";
        default: return "UNKNOWN";
    }
}

const char *elf_reloc_type_str(uint8_t type) {
    switch (type) {
        case R_ARM_NONE: return "R_ARM_NONE"; case R_ARM_ABS32: return "R_ARM_ABS32";
        case R_ARM_REL32: return "R_ARM_REL32"; case R_ARM_CALL: return "R_ARM_CALL";
        case R_ARM_JUMP24: return "R_ARM_JUMP24"; case R_ARM_GLOB_DAT: return "R_ARM_GLOB_DAT";
        case R_ARM_JUMP_SLOT: return "R_ARM_JUMP_SLOT"; case R_ARM_RELATIVE: return "R_ARM_RELATIVE";
        case R_ARM_COPY: return "R_ARM_COPY"; case R_ARM_TLS_DTPMOD32: return "R_ARM_TLS_DTPMOD32";
        case R_ARM_TLS_TPOFF32: return "R_ARM_TLS_TPOFF32"; default: return "R_ARM_UNKNOWN";
    }
}

const char *elf_dyn_tag_str(int32_t tag) {
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
        default: return "UNKNOWN";
    }
}

Elf32_Shdr *elf_get_shdr(elf_t *e, uint32_t idx) {
    if (!e || !e->shdrs || idx >= e->ehdr->e_shnum) return NULL;
    return &e->shdrs[idx];
}

const char *elf_section_name(elf_t *e, Elf32_Shdr *sh) {
    if (!e || !sh || !e->shstrtab) return "";
    return e->shstrtab + sh->sh_name;
}

void *elf_section_data(elf_t *e, Elf32_Shdr *sh) {
    if (!e || !sh || sh->sh_type == SHT_NOBITS) return NULL;
    if (!in_bounds(e, sh->sh_offset, sh->sh_size)) return NULL;
    return (char *)e->base + sh->sh_offset;
}

Elf32_Shdr *elf_find_section(elf_t *e, const char *name) {
    if (!e || !name || !e->shdrs || !e->shstrtab) return NULL;
    for (uint32_t i = 0; i < e->ehdr->e_shnum; i++) {
        if (strcmp(elf_section_name(e, &e->shdrs[i]), name) == 0)
            return &e->shdrs[i];
    }
    return NULL;
}

Elf32_Shdr *elf_find_section_by_type(elf_t *e, uint32_t type) {
    if (!e || !e->shdrs) return NULL;
    for (uint32_t i = 0; i < e->ehdr->e_shnum; i++) {
        if (e->shdrs[i].sh_type == type) return &e->shdrs[i];
    }
    return NULL;
}

Elf32_Phdr *elf_get_phdr(elf_t *e, uint32_t idx) {
    if (!e || !e->phdrs || idx >= e->ehdr->e_phnum) return NULL;
    return &e->phdrs[idx];
}

Elf32_Sym *elf_get_sym(elf_t *e, uint32_t idx, bool dynamic) {
    if (!e) return NULL;
    if (dynamic) {
        if (!e->dynsym || idx >= e->dynsym_count) return NULL;
        return &e->dynsym[idx];
    }
    if (!e->symtab || idx >= e->symtab_count) return NULL;
    return &e->symtab[idx];
}

const char *elf_sym_name(elf_t *e, Elf32_Sym *sym, bool dynamic) {
    if (!e || !sym) return "";
    const char *strtab = dynamic ? e->dynstr : e->strtab;
    return strtab ? strtab + sym->st_name : "";
}

Elf32_Sym *elf_find_sym(elf_t *e, const char *name, bool dynamic) {
    if (!e || !name) return NULL;
    Elf32_Sym *tab = dynamic ? e->dynsym : e->symtab;
    uint32_t count = dynamic ? e->dynsym_count : e->symtab_count;
    if (!tab) return NULL;
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(elf_sym_name(e, &tab[i], dynamic), name) == 0)
            return &tab[i];
    }
    return NULL;
}

bool elf_is_mapping_sym(const char *name) {
    if (!name || name[0] != '$') return false;
    if (name[1] == 'a' || name[1] == 't' || name[1] == 'd')
        return (name[2] == '\0' || name[2] == '.');
    return false;
}

void elf_print_arm_flags(uint32_t flags) {
    printf("  ARM flags: 0x%08x\n", flags);
    printf("    EABI version: %u\n", arm_eabi_ver(flags));
    if (arm_be8(flags)) printf("    BE-8\n");
    if (arm_hard_float(flags)) printf("    Hard float\n");
    if (arm_soft_float(flags)) printf("    Soft float\n");
}

void elf_print_ehdr(elf_t *e) {
    if (!e || !e->ehdr) return;
    Elf32_Ehdr *h = e->ehdr;
    printf("ELF Header:\n  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) printf("%02x ", h->e_ident[i]);
    printf("\n  Class:                             ELF32\n");
    printf("  Data:                              %s\n",
           h->e_ident[EI_DATA] == ELFDATA2LSB ? "little endian" : "big endian");
    printf("  Type:                              %s\n", elf_type_str(h->e_type));
    printf("  Machine:                           %s\n", elf_machine_str(h->e_machine));
    printf("  Entry point address:               0x%x\n", h->e_entry);
    printf("  Start of program headers:          %u (bytes)\n", h->e_phoff);
    printf("  Start of section headers:          %u (bytes)\n", h->e_shoff);
    printf("  Flags:                             0x%x\n", h->e_flags);
    printf("  Number of program headers:         %u\n", h->e_phnum);
    printf("  Number of section headers:         %u\n", h->e_shnum);
    if (h->e_machine == EM_ARM && h->e_flags) elf_print_arm_flags(h->e_flags);
}

static void print_shflags(uint32_t flags) {
    char buf[16] = {0}; int i = 0;
    if (flags & SHF_WRITE) buf[i++] = 'W';
    if (flags & SHF_ALLOC) buf[i++] = 'A';
    if (flags & SHF_EXECINSTR) buf[i++] = 'X';
    if (flags & SHF_MERGE) buf[i++] = 'M';
    if (flags & SHF_STRINGS) buf[i++] = 'S';
    if (flags & SHF_TLS) buf[i++] = 'T';
    printf("%s", buf);
}

void elf_print_shdrs(elf_t *e) {
    if (!e || !e->shdrs) { printf("No section headers.\n"); return; }
    printf("\nSection Headers:\n");
    printf("  [Nr] %-17s %-15s %-8s %-6s %-6s ES Flg Lk Inf Al\n",
           "Name", "Type", "Addr", "Off", "Size");
    for (uint32_t i = 0; i < e->ehdr->e_shnum; i++) {
        Elf32_Shdr *sh = &e->shdrs[i];
        printf("  [%2u] %-17.17s %-15s %08x %06x %06x %02x ",
               i, elf_section_name(e, sh), elf_shtype_str(sh->sh_type),
               sh->sh_addr, sh->sh_offset, sh->sh_size, sh->sh_entsize);
        print_shflags(sh->sh_flags);
        printf(" %2u %3u %2u\n", sh->sh_link, sh->sh_info, sh->sh_addralign);
    }
}

void elf_print_phdrs(elf_t *e) {
    if (!e || !e->phdrs || e->ehdr->e_phnum == 0) {
        printf("\nNo program headers.\n"); return;
    }
    printf("\nProgram Headers:\n");
    printf("  %-14s %-8s %-8s %-8s %-7s %-7s Flg Align\n",
           "Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz");
    for (uint32_t i = 0; i < e->ehdr->e_phnum; i++) {
        Elf32_Phdr *ph = &e->phdrs[i];
        printf("  %-14s 0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %c%c%c 0x%x\n",
               elf_phtype_str(ph->p_type), ph->p_offset, ph->p_vaddr, ph->p_paddr,
               ph->p_filesz, ph->p_memsz,
               (ph->p_flags & PF_R) ? 'R' : ' ', (ph->p_flags & PF_W) ? 'W' : ' ',
               (ph->p_flags & PF_X) ? 'X' : ' ', ph->p_align);
        if (ph->p_type == PT_INTERP && ph->p_filesz > 0)
            printf("      [Interpreter: %s]\n", (const char *)e->base + ph->p_offset);
    }
}

void elf_print_symtab(elf_t *e, bool dynamic) {
    if (!e) return;
    Elf32_Sym *tab = dynamic ? e->dynsym : e->symtab;
    uint32_t count = dynamic ? e->dynsym_count : e->symtab_count;
    const char *tabname = dynamic ? ".dynsym" : ".symtab";
    if (!tab || count == 0) { printf("\nNo %s.\n", tabname); return; }

    printf("\nSymbol table '%s' contains %u entries:\n", tabname, count);
    printf("   Num:    Value  Size Type    Bind   Vis      Ndx Name\n");
    for (uint32_t i = 0; i < count; i++) {
        Elf32_Sym *sym = &tab[i];
        char ndx[8];
        switch (sym->st_shndx) {
            case SHN_UNDEF: strcpy(ndx, "UND"); break;
            case SHN_ABS: strcpy(ndx, "ABS"); break;
            case SHN_COMMON: strcpy(ndx, "COM"); break;
            default: snprintf(ndx, sizeof(ndx), "%3u", sym->st_shndx);
        }
        printf("  %4u: %08x %5u %-7s %-6s %-8s %s %s",
               i, sym->st_value, sym->st_size, elf_sym_type_str(sym->st_info),
               elf_sym_bind_str(sym->st_info), sym_vis_str(sym->st_other),
               ndx, elf_sym_name(e, sym, dynamic));
        if (ELF32_ST_TYPE(sym->st_info) == STT_FUNC && (sym->st_value & 1))
            printf(" [THUMB]");
        printf("\n");
    }
}

void elf_print_relocs(elf_t *e, Elf32_Shdr *reloc_sh) {
    if (!e || !reloc_sh) return;
    if (reloc_sh->sh_type != SHT_REL && reloc_sh->sh_type != SHT_RELA) return;

    bool is_rela = (reloc_sh->sh_type == SHT_RELA);
    Elf32_Shdr *sym_sh = elf_get_shdr(e, reloc_sh->sh_link);
    bool use_dynsym = (sym_sh && sym_sh->sh_type == SHT_DYNSYM);
    uint32_t count = reloc_sh->sh_size / reloc_sh->sh_entsize;

    printf("\nRelocation section '%s' at offset 0x%x contains %u entries:\n",
           elf_section_name(e, reloc_sh), reloc_sh->sh_offset, count);
    printf(" Offset     Info    Type                Sym.Value  Sym.Name%s\n",
           is_rela ? " + Addend" : "");

    void *data = elf_section_data(e, reloc_sh);
    if (!data) return;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t offset, info; int32_t addend = 0;
        if (is_rela) {
            Elf32_Rela *r = &((Elf32_Rela *)data)[i];
            offset = r->r_offset; info = r->r_info; addend = r->r_addend;
        } else {
            Elf32_Rel *r = &((Elf32_Rel *)data)[i];
            offset = r->r_offset; info = r->r_info;
        }
        uint32_t sym_idx = ELF32_R_SYM(info);
        uint8_t type = ELF32_R_TYPE(info);
        Elf32_Sym *sym = elf_get_sym(e, sym_idx, use_dynsym);
        const char *sym_name = sym ? elf_sym_name(e, sym, use_dynsym) : "";
        uint32_t sym_val = sym ? sym->st_value : 0;

        if (is_rela)
            printf("%08x  %08x %-20s %08x   %s + %x\n",
                   offset, info, elf_reloc_type_str(type), sym_val, sym_name, addend);
        else
            printf("%08x  %08x %-20s %08x   %s\n",
                   offset, info, elf_reloc_type_str(type), sym_val, sym_name);
    }
}

void elf_print_all_relocs(elf_t *e) {
    if (!e || !e->shdrs) return;
    bool found = false;
    for (uint32_t i = 0; i < e->ehdr->e_shnum; i++) {
        Elf32_Shdr *sh = &e->shdrs[i];
        if (sh->sh_type == SHT_REL || sh->sh_type == SHT_RELA) {
            elf_print_relocs(e, sh); found = true;
        }
    }
    if (!found) printf("\nNo relocations.\n");
}

void elf_print_dynamic(elf_t *e) {
    if (!e || !e->dynamic || e->dynamic_count == 0) {
        printf("\nNo dynamic section.\n"); return;
    }
    printf("\nDynamic section contains %u entries:\n", e->dynamic_count);
    printf("  Tag        Type                         Name/Value\n");
    for (uint32_t i = 0; i < e->dynamic_count; i++) {
        Elf32_Dyn *d = &e->dynamic[i];
        if (d->d_tag == DT_NULL) break;
        printf(" 0x%08x %-28s ", d->d_tag, elf_dyn_tag_str(d->d_tag));
        switch (d->d_tag) {
            case DT_NEEDED: case DT_SONAME: case DT_RPATH: case DT_RUNPATH:
                printf("%s\n", e->dynstr ? e->dynstr + d->d_un.d_val : "(null)"); break;
            case DT_PLTREL:
                printf("%s\n", d->d_un.d_val == DT_REL ? "REL" : "RELA"); break;
            default: printf("0x%x\n", d->d_un.d_val);
        }
    }
}

void elf_dump(elf_t *e) {
    if (!e) return;
    elf_print_ehdr(e);
    elf_print_shdrs(e);
    elf_print_phdrs(e);
    elf_print_symtab(e, false);
    elf_print_symtab(e, true);
    elf_print_all_relocs(e);
    elf_print_dynamic(e);
}

static void usage(const char *prog) {
    fprintf(stderr, "usage: %s [-q] <elf-file>\n", prog);
    fprintf(stderr, "  -q  quiet mode (summary only)\n");
}

int main(int argc, char **argv) {
    int quiet = 0, opt;
    while ((opt = getopt(argc, argv, "qh")) != -1) {
        switch (opt) {
            case 'q': quiet = 1; break;
            default: usage(argv[0]); return (opt == 'h') ? 0 : 1;
        }
    }
    if (optind >= argc) { usage(argv[0]); return 1; }

    elf_t elf;
    int err = elf_open(&elf, argv[optind]);
    if (err != E_OK) { fprintf(stderr, "error: %s\n", elf.errmsg); return 1; }

    if (quiet) {
        printf("File: %s\nType: %s\nMachine: %s\nEntry: 0x%x\n",
               argv[optind], elf_type_str(elf.ehdr->e_type),
               elf_machine_str(elf.ehdr->e_machine), elf.ehdr->e_entry);
        printf("Sections: %u, Symbols: %u + %u\n",
               elf.ehdr->e_shnum, elf.symtab_count, elf.dynsym_count);
    } else {
        elf_dump(&elf);
    }
    elf_close(&elf);
    return 0;
}
