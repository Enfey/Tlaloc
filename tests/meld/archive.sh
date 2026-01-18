#!/bin/bash
# Test: Archive handling (lazy extraction, cyclic deps)
# Verifies the following: Only needed objects extracted, --start-group resolves cycles
. $(dirname $0)/common.inc

require_toolchain

# Test 1 -  Extraction
compile_inline $t/needed.o <<'EOF'
int needed(void) { return 67; }
EOF

compile_inline $t/unneeded.o <<'EOF'
int unneeded(void) { return 99; }
EOF

compile_inline $t/main1.o <<'EOF'
extern int needed(void);
int main(void) { return needed(); }
EOF

$AR rcs $t/libtest.a $t/needed.o $t/unneeded.o

link_static $t/lazy $t/main1.o $t/libtest.a

# needed must be present, unneeded must NOT
$READELF -s $t/lazy | grep -q " needed$" || fail "needed not extracted"
if $READELF -s $t/lazy | grep -q " unneeded$"; then
    fail "unneeded incorrectly extracted"
fi

assert_exit 67 $t/lazy

# Test 2 - Cyclic dependencies resolved w/ group semantics
compile_inline $t/a.o <<'EOF'
extern int func_b(int);
int func_a(int x) { return x <= 0 ? 0 : x + func_b(x-1); }
EOF

compile_inline $t/b.o <<'EOF'
extern int func_a(int);
int func_b(int x) { return x <= 0 ? 0 : x + func_a(x-1); }
EOF

compile_inline $t/main2.o <<'EOF'
extern int func_a(int);
int main(void) { return func_a(5); }
EOF

$AR rcs $t/liba.a $t/a.o
$AR rcs $t/libb.a $t/b.o

run_meld -static \
    -o $t/cycle \
    "$CRT_PATH/crt1.o" "$CRT_PATH/crti.o" \
    $t/main2.o \
    --start-group $t/liba.a $t/libb.a --end-group \
    -L"$MUSL_SYSROOT/lib" -lc \
    "$CRT_PATH/crtn.o"

$READELF -s $t/cycle | grep -q " func_a$" || fail "func_a not resolved"
$READELF -s $t/cycle | grep -q " func_b$" || fail "func_b not resolved"

assert_exit 15 $t/cycle  # 5+4+3+2+1

pass "archive handling operational"
