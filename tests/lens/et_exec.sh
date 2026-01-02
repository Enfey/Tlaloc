#!/bin/bash
# Test: lens can parse an ARM ET_EXEC executable (non-PIE)
. $(dirname $0)/common.inc

# Force non-PIE to get actual ET_EXEC (modern toolchains default to PIE)
cat <<'EOF' | $CC -xc -no-pie -o $t/exe - 2>/dev/null || skip "Compiler doesn't support -no-pie"
int main() { return 0; }
EOF

run_lens $t/exe > $t/out

grep -q "Type:.*EXEC" $t/out
grep -q "Machine:.*ARM\|AArch64" $t/out
