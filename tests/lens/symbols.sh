#!/bin/bash
# Test: lens displays symbol table
. $(dirname $0)/common.inc

cat <<'EOF' | $CC -xc -o $t/exe -
int my_global_var = 42;
int my_function(void) { return my_global_var; }
int main() { return my_function(); }
EOF

run_lens $t/exe > $t/out

# Should find our symbols
grep -q "my_function\|my_global_var\|main" $t/out
