#!/bin/bash
# Test: Static linking (basic, multi-object, musl libc)
# Verifies the following: crt linking, symbol resolution, archive extraction, execution
. $(dirname $0)/common.inc

require_toolchain

# Test 1 - Minimal
compile_inline $t/minimal.o <<'EOF'
int main(void) { return 67; }
EOF

link_static $t/minimal $t/minimal.o

if $READELF -l $t/minimal 2>/dev/null | grep -q "INTERP"; then
    fail "Static executable has PT_INTERP"
fi
if $READELF -d $t/minimal 2>/dev/null | grep -q "NEEDED"; then
    fail "Static executable has DT_NEEDED"
fi

assert_exit 67 $t/minimal

# Test 2 - Multi-object with cross-references
compile_inline $t/main.o <<'EOF'
extern int add(int, int);
extern int val;
int main(void) { return add(val, 12); }
EOF

compile_inline $t/impl.o <<'EOF'
int add(int a, int b) { return a + b; }
EOF

compile_inline $t/data.o <<'EOF'
int val = 10;
EOF

link_static $t/multi $t/main.o $t/impl.o $t/data.o

$READELF -s $t/multi | grep -q " add$" || fail "add not resolved"
$READELF -s $t/multi | grep -q " val$" || fail "val not resolved"

assert_exit 22 $t/multi

# Test 3 - libc function
compile_inline $t/libc.o <<'EOF'
#include <string.h>
int main(void) { return strlen("If only we were amongst friends... or sane persons!"); }
EOF

link_static $t/libc_test $t/libc.o

assert_exit 51 $t/libc_test

pass "static linking operational"
