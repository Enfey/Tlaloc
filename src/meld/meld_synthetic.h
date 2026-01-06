/* meld_synthetic.h - Synthetic symbol pre-definition
 *
 * Synthetic symbols are those that are linker-defined and are not present in any input object.
 * As nice as the word 'synthetic' is to say, i dislike long identifiers. So we prefer synth for 
 * declarations and definitions in synthetic.h and synthetic.c.
 *
 * Currently supported synthetic symbols include:
 *   _DYNAMIC
 *   _GLOBAL_OFFSET_TABLE_
 *   __executable_start    - Start of executable load segment
 *   _start
 *   __bss_start
 *   _end / _edata / _etext
 * 
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#ifndef MELD_SYNTH_H
#define MELD_SYNTH_H

struct meld_gst;

int synth_predefine_linker_symbols(struct meld_gst *gst);

#endif /* MELD_SYNTH_H */
