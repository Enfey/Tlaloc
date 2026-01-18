#!/bin/bash
# Test: Symbol versioning (version script parsing, verdef generation)
# Verifies: --version-script parsing, .gnu.version_d, .gnu.version, visibility (though there is some partial structural 
# support for .gnu.version_r, there is not full support, and I don't have time to implement it)
. $(dirname $0)/common.inc

require_toolchain

TESTDIR="$(cd "$(dirname "$0")" && pwd)"

# Test 1 - --version-script parsing - PIE can have verdef; use to test this without -shared being supported by meld
compile_inline $t/versioned.o -fPIC <<'EOF'
int foo(int x) { return x + 1; }
int bar(int x) { return x * 2; }
int baz(int x) { return foo(x) + bar(x); }

int internal(int x) { return x; }

int main(void) {
    return baz(5) - 16;  /* (5+1) + (5*2) = 16, so returns 0 */
}
EOF

run_meld -pie \
    --version-script="$TESTDIR/libver.map" \
    -o "$t/versioned" \
    "$CRT_PATH/Scrt1.o" \
    "$CRT_PATH/crti.o" \
    "$t/versioned.o" \
    -L"$MUSL_SYSROOT/lib" \
    --start-group -lc --end-group \
    "$CRT_PATH/crtn.o"

# Verify .gnu.version_d generated 
verdef_sec=$(section_addr "$t/versioned" ".gnu.version_d")
if [[ -z "$verdef_sec" ]]; then
    fail "Missing .gnu.version_d section - version script not processed"
fi

verdef_dt=$(dynamic_value "$t/versioned" "VERDEF")
[[ $((verdef_dt)) -eq $((verdef_sec)) ]] || fail "DT_VERDEF != .gnu.version_d addr"

# DT_VERDEFNUM >= 2
verdefnum=$($READELF -d "$t/versioned" 2>/dev/null | grep "VERDEFNUM" | awk '{print $3}')
if [[ -z "$verdefnum" ]] || [[ "$verdefnum" -lt 2 ]]; then
    fail "DT_VERDEFNUM missing or too small (got: ${verdefnum:-empty})"
fi

versym_sec=$(section_addr "$t/versioned" ".gnu.version")
if [[ -z "$versym_sec" ]]; then
    fail "Missing .gnu.version section"
fi

versym_dt=$(dynamic_value "$t/versioned" "VERSYM")
[[ $((versym_dt)) -eq $((versym_sec)) ]] || fail "DT_VERSYM != .gnu.version addr"

if ! $READELF -V "$t/versioned" 2>/dev/null | grep -q "LIBVER_1.0"; then
    fail "LIBVER_1.0 version tag not found in output"
fi

if ! $READELF -V "$t/versioned" 2>/dev/null | grep -q "LIBVER_2.0"; then
    fail "LIBVER_2.0 version tag not found in output"
fi

# Appear as sym@@VERSION in readelf output
$READELF --dyn-syms "$t/versioned" 2>/dev/null | grep -q " foo@@LIBVER_1.0$" || fail "foo not exported"
$READELF --dyn-syms "$t/versioned" 2>/dev/null | grep -q " bar@@LIBVER_1.0$" || fail "bar not exported"
$READELF --dyn-syms "$t/versioned" 2>/dev/null | grep -q " baz@@LIBVER_2.0$" || fail "baz not exported"

if $READELF --dyn-syms "$t/versioned" 2>/dev/null | grep -q " internal"; then
    fail "internal should be hidden by 'local: *' but is exported"
fi

assert_exit 0 "$t/versioned"

pass "symbol versioning operational"
