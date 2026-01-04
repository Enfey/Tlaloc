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

 * meld.h - Static linker for ARM32 (EM_ARM) objects.
 *
 * Meld accepts relocatable ELF objects (.o with e_type == ET_REL) and static archives (.a) and produces
 * a statically linked executable. Utilises lens for ELF interrogation.
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_H
#define MELD_H

#include "../tlaloc.h"
#include "../lens/lens.h"
#include <elf.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

enum {
    MELD_OK = 0,
    MELD_ERR_NOMEM,
    MELD_ERR_IO,
    MELD_ERR_NOT_OBJECT,      /* Expected ET_REL, got something else */
    MELD_ERR_MULTI_DEF,       /* Multiple strong definitions */
    MELD_ERR_UNDEF,           /* Non-weak unresolved symbol */
    MELD_ERR_BAD_ARCHIVE,   
    MELD_ERR_RELOC,           /* Relocation error (overflow, unknown type) */
    MELD_ERR_INTERNAL,      
};

typedef struct meld_ctx      meld_ctx_t;       /* Main linker context instantiated once and passed to all operations.*/
typedef struct meld_input    meld_input_t;     /* Input file (.o or .a member) */
typedef struct meld_symbol   meld_symbol_t;    
typedef struct meld_section  meld_section_t;   
typedef struct meld_reloc    meld_reloc_t;    
typedef struct meld_archive  meld_archive_t; 

struct meld_ctx {
    meld_input_t   **inputs;         
    uint32_t         input_count;
    uint32_t         input_cap;

    meld_archive_t **archives;
    uint32_t         archive_count;
    uint32_t         archive_cap;

    uint32_t         current_group_id;  /* Group semantics - See archive.h */

    struct meld_gst *gst;               /* GST - TODO!*/

    /* Library search paths (-L) */
    char           **lib_paths;
    uint32_t         lib_path_count;
    uint32_t         lib_path_cap;

    /* Output config */
    const char      *output_path;
    const char      *version_script; /* Version script path (.map file) */
    uint16_t         output_type;
    bool             is_static;
    bool             relro;
    bool             bind_now;
    uint32_t         entry_addr;     /* default: _start */
    uint32_t         base_addr;      /* 0x10000 for ET_EXEC, 0x0 for ET_DYN */

    int              last_err;
    char             errmsg[256];    /* More space than elf_t to support more complex error messages */
};

int  meld_init(meld_ctx_t *ctx);
void meld_destroy(meld_ctx_t *ctx);
void meld_set_output_type(meld_ctx_t *ctx, uint16_t type);

int meld_add_input(meld_ctx_t *ctx, const char *path);
int meld_add_archive(meld_ctx_t *ctx, const char *path);
int meld_add_shared_lib(meld_ctx_t *ctx, const char *path);

/* Unfortunately, it appears we cannot implement protected functions in C. GCC/Clang is full of wizardy;
 * the solution I initially thought of was restricting some functions including a public header, such that they pass their
 * execution context e.g., their own function pointer, and this could be somehow reverse engineered to acquire a symbol; you could 
 * then match on that and determine whether the file is permitted to call that function. Unfortunately symbol tables are optional, and 
 * there's the issue of what something like dladdr() returns, may yield shared-object path, not source. Furthermore the 
 * compiler is happy to inline, eliminate, and fold functions. Everything you try here is UB. Even __builtin_return_address() maintains 
 * that the result is undefined oftentimes.
 */
int meld_link(meld_ctx_t *ctx);

static inline const char *meld_strerror(const meld_ctx_t *ctx) {
    return ctx ? ctx->errmsg : "NULL context";
}

#endif /* MELD_H */
