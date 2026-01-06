/* meld_synthetic.c - Synthetic symbol pre-definition
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "meld_synthetic.h"
#include "meld_symbol.h"
#include <string.h>
#include <stdlib.h>
#include <elf.h>

typedef struct {
    const char *name;
    uint8_t     bind;       /* STB_WEAK, STB_GLOBAL */
    uint8_t     type;       /* STT_NOTYPE, STT_OBJECT */
    bool        hidden;     /* STV_HIDDEN if true */
    bool        absolute;   /* SHN_ABS if true */
} synth_def_t;

static const synth_def_t SYNTH_DEFS[] = {
    { "_DYNAMIC",              STB_WEAK, STT_OBJECT, true, false },
    { "_GLOBAL_OFFSET_TABLE_", STB_WEAK, STT_OBJECT, true, false },
    { "__executable_start",    STB_WEAK, STT_NOTYPE, true, false },
    { "__bss_start",           STB_WEAK, STT_NOTYPE, true, false },
    { "_end",                  STB_WEAK, STT_NOTYPE, true, false },
    { "_edata",                STB_WEAK, STT_NOTYPE, true, false },
    { "_etext",                STB_WEAK, STT_NOTYPE, true, false },
    { "__init_array_start",    STB_WEAK, STT_NOTYPE, true, false },
    { "__init_array_end",      STB_WEAK, STT_NOTYPE, true, false },
    { "__fini_array_start",    STB_WEAK, STT_NOTYPE, true, false },
    { "__fini_array_end",      STB_WEAK, STT_NOTYPE, true, false },
    { "__preinit_array_start", STB_WEAK, STT_NOTYPE, true, false },
    { "__preinit_array_end",   STB_WEAK, STT_NOTYPE, true, false },
};

/* Pre-define linker symbols as WEAK HIDDEN so they don't cause undefined symbol
 * errors if unused, and don't trigger archive extraction. Values are set to 0
 * initially; actual values are to be assigned during layout via GST lookup.
 */
int synth_predefine_linker_symbols(struct meld_gst *gst) {
    for (size_t i = 0; i < ARRAY_LEN(SYNTH_DEFS); i++) {
        const synth_def_t *def = &SYNTH_DEFS[i];
        
        meld_symbol_t *sym = calloc(1, sizeof(*sym));
        if (!sym) return MELD_ERR_NOMEM;
        
        sym->name = strdup(def->name);
        if (!sym->name) { free(sym); return MELD_ERR_NOMEM; }
        
        sym->name_hash = fnv1a_hash(def->name);
        sym->st_info = ELF32_ST_INFO(def->bind, def->type);
        sym->st_other = def->hidden ? STV_HIDDEN : STV_DEFAULT;
        sym->st_shndx = def->absolute ? SHN_ABS : 1;
        sym->st_value = 0;
        sym->st_size = 0;
        sym->state = SYM_DEFINED;
        sym->flags = 0;
        sym->got_offset = -1;
        sym->plt_offset = -1;
        sym->input = NULL;  /* Linker defined */
        
        meld_symbol_t *out = NULL;
        int rc = gst_insert(gst, sym, &out);
        if (rc != MELD_OK) {
            free((void *)sym->name);
            free(sym);
            return rc;
        }
    }
    return MELD_OK;
}
