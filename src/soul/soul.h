#ifndef SOUL_H
#define SOUL_H

#include "../tlaloc.h"
#include <elf.h>
#include <sys/mman.h>

/*──────────────────────────────────────────────────────────────────────────────
 * ELF Segment Loading Formulas
 *
 * When mapping PT_LOAD segments, mmap() requires page-aligned addresses and
 * offsets. These macros compute the correct values for a given program header.
 *
 * Memory layout:
 *
 *   page boundary →   ┌─────────────────────────────┐  ← RUNTIME_MAP_ADDR
 *                     │      padding (DELTA_V)      │
 *        p_vaddr →    ├─────────────────────────────┤  ← RUNTIME_SEG_CONTENT
 *                     │     file content (p_filesz) │
 *  p_vaddr+filesz →   ├─────────────────────────────┤
 *                     │     zero-fill (BSS)         │
 *   p_vaddr+memsz →   └─────────────────────────────┘
 *
 * Reference(my own notes): https://github.com/Enfey/UoN-CS-MSci-Notes/blob/main/
 *                          Semester%201%20Y3/Linkers%20and%20Loaders/Chapters/Chapter%209.md
 *────────────────────────────────────────────────────────────────────────────*/

#define FILE_MAP_OFFSET(phdr)   PAGE_ALIGN_DOWN((phdr)->p_offset)

#define SEG_PAGE_VADDR(phdr)    PAGE_ALIGN_DOWN((phdr)->p_vaddr)

#define DELTA_V(phdr)           ((phdr)->p_vaddr  & (PAGE_SIZE - 1))
#define DELTA_O(phdr)           ((phdr)->p_offset & (PAGE_SIZE - 1))

#define MAP_FILESZ(phdr)        PAGE_ALIGN(DELTA_O(phdr) + (phdr)->p_filesz)

#define MAP_MEMSZ(phdr)         PAGE_ALIGN(DELTA_V(phdr) + (phdr)->p_memsz)

#define RUNTIME_MAP_ADDR(phdr, bias)    ((bias) + SEG_PAGE_VADDR(phdr))

#define RUNTIME_SEG_CONTENT(phdr, bias) ((bias) + (phdr)->p_vaddr)

#define ZERO_FILL_START(phdr, bias)     (RUNTIME_SEG_CONTENT(phdr, bias) + (phdr)->p_filesz)
#define ZERO_FILL_LEN(phdr)             ((phdr)->p_memsz - (phdr)->p_filesz)

/* If >1 PT_LOAD ∈ page, take the union of their flags. */
static inline int seg_to_prot(uint32_t p_flags)
{
    return ((p_flags & PF_R) ? PROT_READ  : 0) |
           ((p_flags & PF_W) ? PROT_WRITE : 0) |
           ((p_flags & PF_X) ? PROT_EXEC  : 0);
}

#endif /* SOUL_H */
