/* main.c - Lens CLI tool entry point
 *
 * Copyright (c) 2025-2026 Felix Riley-Kay @ github.com/enfey
 */

#include "lens.h"
#include <stdio.h>
#include <getopt.h>

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
        printf("File: %s\nType: %s\nMachine: %s\nEntry: 0x%lx\n",
               argv[optind], elf_type_str(elf.elf_type),
               elf_machine_str(elf.elf_machine), (unsigned long)elf_entry(&elf));
        printf("Sections: %u, Symbols: %u + %u\n",
               elf.shnum, elf.symtab_count, elf.dynsym_count);
    } else {
        elf_dump(&elf);
    }
    elf_close(&elf);
    return 0;
}
