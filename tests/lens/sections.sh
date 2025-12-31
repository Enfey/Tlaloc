#!/bin/bash
# Test: lens displays section headers
. $(dirname $0)/common.inc

make_arm_exec $t/exe

run_lens $t/exe > $t/out

# Should show common sections
grep -q "\.text" $t/out
