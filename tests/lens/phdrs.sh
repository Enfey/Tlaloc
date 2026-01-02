#!/bin/bash
# Test: lens displays program headers
. $(dirname $0)/common.inc

make_arm_so $t/lib.so

run_lens $t/lib.so > $t/out

grep -q "LOAD\|INTERP\|PHDR" $t/out || \
  grep -q "Program Headers\|Segments" $t/out
