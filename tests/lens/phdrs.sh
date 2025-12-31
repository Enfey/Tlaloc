#!/bin/bash
# Test: lens displays program headers
. $(dirname $0)/common.inc

make_arm_exec $t/exe

run_lens $t/exe > $t/out

# Should show program headers
grep -q "LOAD\|INTERP\|PHDR" $t/out || \
  grep -q "Program Headers\|Segments" $t/out
