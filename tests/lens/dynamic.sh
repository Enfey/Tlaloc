#!/bin/bash
# Test: lens displays dynamic section for shared objects
. $(dirname $0)/common.inc

make_arm_so $t/lib.so

run_lens $t/lib.so > $t/out

grep -q "NEEDED\|SONAME\|SYMTAB\|STRTAB" $t/out || \
  grep -q "Dynamic\|\.dynamic" $t/out
