#!/bin/bash
# Test: lens can parse an ARM ET_DYN shared object
. $(dirname $0)/common.inc

make_arm_so $t/lib.so

run_lens $t/lib.so > $t/out

grep -q "Type:.*DYN" $t/out
grep -q "Machine:.*ARM" $t/out
