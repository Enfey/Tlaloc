#!/bin/bash
# Test: identifies THUMB functions
. $(dirname $0)/common.inc

cat <<'EOF' | $CC -xc -mthumb -o $t/exe -
__attribute__((target("thumb")))
int thumb_func(void) { return 1; }
int main() { return thumb_func(); }
EOF

run_lens $t/exe > $t/out

# THUMB symbols have LSB set in address, lens should indicate this!
grep -q "thumb_func\|main" $t/out
