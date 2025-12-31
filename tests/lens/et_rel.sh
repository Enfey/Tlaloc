#!/bin/bash
# Test: lens can parse an ARM ET_REL relocatable object
. $(dirname $0)/common.inc

make_arm_obj $t/obj.o

run_lens $t/obj.o > $t/out

grep -q "Type:.*REL" $t/out
grep -q "Machine:.*ARM" $t/out
