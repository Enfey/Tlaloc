#!/bin/bash
# Test: lens rejects non-ELF files
. $(dirname $0)/common.inc

echo "not an elf file" > $t/notelf

# Should fail with error
not run_lens $t/notelf 2>&1 | grep -qi "elf\|magic\|invalid"
