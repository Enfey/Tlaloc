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
                                                                                                                                     
 * lens.h - header file for mmap-based multithreaded ELF parser for ARM 32/64 bit binaries, supporting ET_REL, ET_EXEC, ET_DYN.
 * 
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef LENS_H
#define LENS_H

#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

enum {
    E_OK = 0,
    E_NULLPTR,
    E_MMAP,
    E_NOT_ELF,
    E_NOT_ARM,
    E_NOT_32BIT,
    E_BAD_TYPE,
    E_TRUNCATED,
    E_CORRUPT,
    E_NO_SECTION,
    E_NO_SYMBOL,
};

static inline uint32_t arm_eabi_ver(uint32_t flags) { return (flags & EF_ARM_EABIMASK) >> 24; }
static inline bool arm_be8(uint32_t flags) { return (flags & EF_ARM_BE8) != 0; }
static inline bool arm_hard_float(uint32_t flags) { return (flags & EF_ARM_ABI_FLOAT_HARD) != 0; }
static inline bool arm_soft_float(uint32_t flags) { return (flags & EF_ARM_ABI_FLOAT_SOFT) != 0; }

/* https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst */
#define PT_ARM_ARCHEXT      0x70000000 

#define DT_ARM_RESERVED1    0x70000000UL
#define DT_ARM_SYMTABSZ     0x70000001UL 
#define DT_ARM_PREEMPTMAP   0x70000002UL 
#define DT_ARM_RESERVED2    0x70000003UL

typedef struct {
    void        *base;          /* mmap base */
    size_t       size;          /* file size */
    const char  *path;          /* file path (for error msgs) */
    
    /* direct pointers into mmap'd region */
    Elf32_Ehdr  *ehdr;
    Elf32_Shdr  *shdrs;         /* section header table */
    Elf32_Phdr  *phdrs;         /* program header table (NULL for ET_REL) */
    const char  *shstrtab;      /* section name strings */
    
    /* symbol tables - point directly into mmap */
    Elf32_Sym   *symtab;
    uint32_t     symtab_count;
    const char  *strtab;        /* .strtab */
    
    Elf32_Sym   *dynsym;
    uint32_t     dynsym_count;
    const char  *dynstr;        /* .dynstr */
    
    /* dynamic section */
    Elf32_Dyn   *dynamic;
    uint32_t     dynamic_count;
    
    int          last_err;
    char         errmsg[128];
} elf_t;

int elf_open(elf_t *e, const char *path);
void elf_close(elf_t *e);

const char *elf_type_str(uint16_t type);
const char *elf_machine_str(uint16_t machine);
void elf_print_ehdr(elf_t *e);
void elf_print_arm_flags(uint32_t flags);

Elf32_Shdr *elf_get_shdr(elf_t *e, uint32_t idx);
Elf32_Shdr *elf_find_section(elf_t *e, const char *name);
Elf32_Shdr *elf_find_section_by_type(elf_t *e, uint32_t type);
const char *elf_section_name(elf_t *e, Elf32_Shdr *sh);
void *elf_section_data(elf_t *e, Elf32_Shdr *sh);
const char *elf_shtype_str(uint32_t type);
void elf_print_shdrs(elf_t *e);

Elf32_Phdr *elf_get_phdr(elf_t *e, uint32_t idx);
const char *elf_phtype_str(uint32_t type);
void elf_print_phdrs(elf_t *e);
void elf_print_section_to_segment(elf_t *e);

Elf32_Sym *elf_get_sym(elf_t *e, uint32_t idx, bool dynamic);
const char *elf_sym_name(elf_t *e, Elf32_Sym *sym, bool dynamic);
Elf32_Sym *elf_find_sym(elf_t *e, const char *name, bool dynamic);
const char *elf_sym_bind_str(uint8_t info);
const char *elf_sym_type_str(uint8_t info);
void elf_print_symtab(elf_t *e, bool dynamic);

bool elf_is_mapping_sym(const char *name);

void elf_print_relocs(elf_t *e, Elf32_Shdr *reloc_sh);
void elf_print_all_relocs(elf_t *e);
const char *elf_reloc_type_str(uint8_t type);

void elf_print_dynamic(elf_t *e);
const char *elf_dyn_tag_str(int32_t tag);

void elf_print_notes(elf_t *e);

/* Analogous to readelf -a */
void elf_dump(elf_t *e);

#endif /* LENS_H */
