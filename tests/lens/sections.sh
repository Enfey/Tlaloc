#!/bin/bash
# Test: lens displays section headers
. $(dirname $0)/common.inc

make_arm_obj $t/obj.o

run_lens $t/obj.o > $t/out

# Should show common sections - very minimal as we're making no assumptions about the resultant object - just want to ensure
# that lens runs without crashing and can parse at least one section.
grep -q "\.text" $t/out
