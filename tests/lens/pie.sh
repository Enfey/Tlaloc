#!/bin/bash
# Test: lens parses PIE binary happily
. $(dirname $0)/common.inc

cat <<'EOF' | $CC -xc -fPIE -pie -o $t/exe -
#include <stdio.h>

int data = 42;

int main() {
    printf("data @ %p = %d\n", &data, data);
    return 0;
}
EOF

run_lens $t/exe > $t/out

# PIE is type DYN but has entry point and INTERP (unlike regular .so)
grep -q "Type:.*DYN" $t/out
grep -q "Machine:.*ARM\|AArch64" $t/out
grep -q "INTERP\|Interpreter:" $t/out
grep -q "Entry point address:.*0x[1-9]" $t/out
