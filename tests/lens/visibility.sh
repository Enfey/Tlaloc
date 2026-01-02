#!/bin/bash
# Test: lens is aware of symbol visibilities.
. $(dirname $0)/common.inc

cat <<'EOF' | $CC -xc -shared -fPIC -o $t/lib.so -
__attribute__((visibility("default")))
int default_func(void) { return 1; }

// not exported from DSO
__attribute__((visibility("hidden")))
int hidden_func(void) { return 2; }

// Cannot be preempted
__attribute__((visibility("protected")))
int protected_func(void) { return 3; }

__attribute__((visibility("internal")))
int internal_func(void) { return 4; }

__attribute__((weak))
int weak_func(void) { return 5; }

int global_func(void) { return 6; }
EOF

run_lens $t/lib.so > $t/out

grep -q "Type:.*DYN" $t/out
grep -q "Machine:.*ARM\|AArch64" $t/out
grep -q "DEFAULT" $t/out
grep -q "GLOBAL" $t/out
grep -q "WEAK" $t/out
grep -q "default_func\|global_func" $t/out
