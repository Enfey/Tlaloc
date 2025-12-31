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
                                                                                                                                     
 * lens.h - mmap-based ELF parser for ARM32 (EM_ARM) and AArch64 (EM_AARCH64).
 * Supports ET_REL, ET_EXEC, ET_DYN. Zero-copy: pointers reference mmap directly.
 * There is a uniform API for ARM32 and AArch64. C has no function overloading, 
 * and providing dual functions places more responsibility on the caller. Dispatching was 
 * moved inside lens, and an index is passed to indicate the object we are concerned with (object
 * here is a general term for section, program header, symbol, etc.).
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef LENS_H
#define LENS_H

#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

/* Error codes */
enum {
    E_OK = 0,
    E_NULLPTR,
    E_MMAP,
    E_NOT_ELF,
    E_NOT_ARM,
    E_BAD_CLASS,
    E_BAD_TYPE,
    E_TRUNCATED,
    E_CORRUPT,
    E_NO_SECTION,
    E_NO_SYMBOL,
};

/* ARM32 flag helpers */
static inline uint32_t arm_eabi_ver(uint32_t f)   { return (f & EF_ARM_EABIMASK) >> 24; }
static inline bool     arm_be8(uint32_t f)        { return (f & EF_ARM_BE8) != 0; }
static inline bool     arm_hard_float(uint32_t f) { return (f & EF_ARM_ABI_FLOAT_HARD) != 0; }
static inline bool     arm_soft_float(uint32_t f) { return (f & EF_ARM_ABI_FLOAT_SOFT) != 0; }

/* ARM-specific ELF constants */
#define PT_ARM_ARCHEXT         0x70000000UL
#define PT_AARCH64_UNWIND      0x70000001UL
#define DT_ARM_SYMTABSZ        0x70000001UL
#define SHT_AARCH64_ATTRIBUTES 0x70000003UL
#define SHF_AARCH64_PURECODE   0x20000000UL

/*
 * Main ELF handle. All pointers reference the mmap'd file directly.
 * Union discriminated by elf_class; only e32 OR e64 is valid.
 * INVARIANT: All pointers become invalid after elf_close().
 */
typedef struct {
    void       *base;
    size_t      size;
    const char *path;

    uint8_t     elf_class;
    uint16_t    elf_type;    
    uint16_t    elf_machine; 

    union {
        struct {
            Elf32_Ehdr *ehdr;
            Elf32_Shdr *shdrs;
            Elf32_Phdr *phdrs;
            Elf32_Sym  *symtab;
            Elf32_Sym  *dynsym;
            Elf32_Dyn  *dynamic;
        } e32;
        struct {
            Elf64_Ehdr *ehdr;
            Elf64_Shdr *shdrs;
            Elf64_Phdr *phdrs;
            Elf64_Sym  *symtab;
            Elf64_Sym  *dynsym;
            Elf64_Dyn  *dynamic;
        } e64;
    };

    const char *shstrtab;
    const char *strtab;
    const char *dynstr;

    size_t      shstrtab_size;   /* For bounds-checking string offsets */
    size_t      strtab_size;
    size_t      dynstr_size;

    uint32_t    shnum;
    uint32_t    phnum;
    uint32_t    symtab_count;
    uint32_t    dynsym_count;
    uint32_t    dynamic_count;

    int         last_err;
    char        errmsg[128];
} elf_t;

#define ELF_IS_32(e)      ((e)->elf_class == ELFCLASS32)
#define ELF_IS_64(e)      ((e)->elf_class == ELFCLASS64)
#define ELF_IS_ARM32(e)   ((e)->elf_machine == EM_ARM)
#define ELF_IS_AARCH64(e) ((e)->elf_machine == EM_AARCH64)

/* Lifecycle */
int  elf_open(elf_t *e, const char *path);
void elf_close(elf_t *e);

/* Header accessors */
static inline uint64_t elf_entry(const elf_t *e) {
    return ELF_IS_64(e) ? e->e64.ehdr->e_entry : e->e32.ehdr->e_entry;
}
static inline uint32_t elf_flags(const elf_t *e) {
    return ELF_IS_64(e) ? e->e64.ehdr->e_flags : e->e32.ehdr->e_flags;
}

/* Section accessors */
static inline uint32_t elf_shnum(const elf_t *e) { return e ? e->shnum : 0; }
uint64_t    elf_sh_addr(const elf_t *e, uint32_t i);
uint64_t    elf_sh_size(const elf_t *e, uint32_t i);
uint64_t    elf_sh_offset(const elf_t *e, uint32_t i);
uint32_t    elf_sh_type(const elf_t *e, uint32_t i);
uint64_t    elf_sh_flags(const elf_t *e, uint32_t i);
uint32_t    elf_sh_link(const elf_t *e, uint32_t i);
uint32_t    elf_sh_info(const elf_t *e, uint32_t i);
uint64_t    elf_sh_addralign(const elf_t *e, uint32_t i);
uint64_t    elf_sh_entsize(const elf_t *e, uint32_t i);
const char *elf_sh_name(const elf_t *e, uint32_t i);
void       *elf_sh_data(const elf_t *e, uint32_t i);
ssize_t     elf_sh_find(const elf_t *e, const char *name);
ssize_t     elf_sh_find_type(const elf_t *e, uint32_t type);

/* Program header accessors */
static inline uint32_t elf_phnum(const elf_t *e) { return e ? e->phnum : 0; }
uint32_t    elf_ph_type(const elf_t *e, uint32_t i);
uint32_t    elf_ph_flags(const elf_t *e, uint32_t i);
uint64_t    elf_ph_offset(const elf_t *e, uint32_t i);
uint64_t    elf_ph_vaddr(const elf_t *e, uint32_t i);
uint64_t    elf_ph_paddr(const elf_t *e, uint32_t i);
uint64_t    elf_ph_filesz(const elf_t *e, uint32_t i);
uint64_t    elf_ph_memsz(const elf_t *e, uint32_t i);
uint64_t    elf_ph_align(const elf_t *e, uint32_t i);

/* Symbol accessors */
static inline uint32_t elf_sym_count(const elf_t *e, bool dyn) {
    return e ? (dyn ? e->dynsym_count : e->symtab_count) : 0;
}
uint64_t    elf_sym_value(const elf_t *e, uint32_t i, bool dyn);
uint64_t    elf_sym_size(const elf_t *e, uint32_t i, bool dyn);
uint8_t     elf_sym_info(const elf_t *e, uint32_t i, bool dyn);
uint8_t     elf_sym_other(const elf_t *e, uint32_t i, bool dyn);
uint16_t    elf_sym_shndx(const elf_t *e, uint32_t i, bool dyn);
const char *elf_sym_name(const elf_t *e, uint32_t i, bool dyn);
ssize_t     elf_sym_find(const elf_t *e, const char *name, bool dyn);
bool        elf_is_mapping_sym(const char *name);

/* Dynamic section accessors */
static inline uint32_t elf_dyn_count(const elf_t *e) {
    return e ? e->dynamic_count : 0;
}
int64_t     elf_dyn_tag(const elf_t *e, uint32_t i);
uint64_t    elf_dyn_val(const elf_t *e, uint32_t i);

/* String converters (for diagnostics) */
const char *elf_type_str(uint16_t type);
const char *elf_machine_str(uint16_t machine);
const char *elf_shtype_str(uint32_t type, uint16_t machine);
const char *elf_phtype_str(uint32_t type, uint16_t machine);
const char *elf_sym_bind_str(uint8_t info);
const char *elf_sym_type_str(uint8_t info);
const char *elf_sym_vis_str(uint8_t other);
const char *elf_dyn_tag_str(int64_t tag);
const char *elf_reloc_type_str(uint16_t machine, uint32_t type);

/* Analogous to readelf -a */
void elf_dump(const elf_t *e);

#endif /* LENS_H */
