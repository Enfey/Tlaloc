#!/bin/bash
# Test: PIE linking with full structural validation
# Verifies the following: ET_DYN, segments, .dynamic structure, PLT/GOT, data relocs
. $(dirname $0)/common.inc

require_toolchain

# Enforce PLT calls and data pointers
compile_inline $t/main.o -fPIC <<'EOF'
#include <string.h>
#include <stdlib.h>

const char rodata[] = "constant";
int data = 67;
static const char *ptr = "pointer";

int main(void) {
    void *p = malloc(strlen(ptr));
    if (p) free(p);
    return data + (int)strlen(rodata);
}
EOF

link_pie $t/a.out $t/main.o

$READELF -h $t/a.out | grep -q "DYN" || fail "Not ET_DYN"
$READELF -l $t/a.out | grep -q "INTERP" || fail "Missing PT_INTERP"

assert_segments_valid $t/a.out
assert_section_order $t/a.out ".text" ".data"
assert_dynamic_structure $t/a.out

# Sanity
jmprel=$(dynamic_value $t/a.out "JMPREL")
relplt=$(section_addr $t/a.out ".rel.plt")
[[ -z "$jmprel" ]] || [[ $((jmprel)) -eq $((relplt)) ]] || fail "DT_JMPREL mismatch"

strsz=$(dynamic_value $t/a.out "STRSZ")
dynstr_sz=$(section_size $t/a.out ".dynstr")
[[ -z "$strsz" ]] || [[ $((strsz)) -eq $((dynstr_sz)) ]] || fail "DT_STRSZ mismatch"

assert_plt_reloc_match $t/a.out
assert_gotplt_reserved $t/a.out

plt_sz=$(($(section_size $t/a.out ".plt")))
[[ $(( (plt_sz - 20) % 24 )) -eq 0 ]] || fail "PLT size not 20+N*24"

# R_ARM_RELATIVE emitted for pointer
rel_count=$($READELF -r $t/a.out | grep -c "R_ARM_RELATIVE" || echo 0)
[[ $rel_count -ge 1 ]] || fail "Expected R_ARM_RELATIVE for data pointer"

entry=$($READELF -h $t/a.out | grep "Entry" | awk '{print $4}')
start=$(symbol_value $t/a.out "_start")
[[ $((entry)) -eq $((start)) ]] || fail "Entry != _start"

assert_exit 75 $t/a.out  # 67 + 8

pass "PIE linking operational"
