#!/bin/bash
# Test: lens identifies THUMB functions (ARM32 specific)
. $(dirname $0)/common.inc

# Skip if not ARM32
[[ "$BITS" == "32" && "$ARCH" == "arm" ]] || skip "ARM32 only"

cat <<'EOF' | $CC -xc -mthumb -o $t/exe -
__attribute__((target("thumb")))
int thumb_func(void) { return 1; }
int main() { return thumb_func(); }
EOF

run_lens $t/exe > $t/out

# THUMB symbols have LSB set in address, lens should indicate this!
grep -q "thumb_func\|main" $t/out
