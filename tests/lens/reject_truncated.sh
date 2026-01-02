#!/bin/bash
# Test: lens rejects truncated ELF files
. $(dirname $0)/common.inc

# Create valid ELF then truncate it
make_arm_obj $t/obj.o
head -c 32 $t/obj.o > $t/truncated

# Should fail
not run_lens $t/truncated 2>&1
