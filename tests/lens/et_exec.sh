#!/bin/bash
# Test: lens can parse an ARM ET_EXEC executable
. $(dirname $0)/common.inc

make_arm_exec $t/exe

run_lens $t/exe > $t/out

grep -q "Type:.*EXEC" $t/out
grep -q "Machine:.*ARM" $t/out
