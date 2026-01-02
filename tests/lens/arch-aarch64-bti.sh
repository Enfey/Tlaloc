#!/bin/bash
# Test: identification of BTI (Branch Target Identification) in AArch64 binaries
# BTI is an ARMv8.5-A security feature that marks valid branch targets.
# When enabled, the GNU property note contains GNU_PROPERTY_AARCH64_FEATURE_1_BTI.
# https://maskray.me/blog/2023-03-05-linker-notes-on-aarch64
. $(dirname $0)/common.inc

# Compile with BTI - skip if compiler lacks support
cat <<'EOF' | $CC -xc -mbranch-protection=bti -o $t/exe - 2>/dev/null || skip "Compiler lacks BTI support."
int main() { return 0; }
EOF

$READELF -n $t/exe 2>/dev/null | grep -qF ".note.gnu.property" || skip "Toolchain doesn't emit BTI property note despite accepting flag."

run_lens $t/exe > $t/out

grep -q "Machine:.*AArch64" $t/out || { echo "Machine type not detected"; cat $t/out; exit 1; }

grep -qF ".note.gnu.property" $t/out || { echo "GNU property section not shown"; cat $t/out; exit 1; }
grep -qE "(BTI|AARCH64_FEATURE_1_BTI|Branch Target)" $t/out || { echo "BTI not detected"; cat $t/out; exit 1; }
