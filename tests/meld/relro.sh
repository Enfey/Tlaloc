#!/bin/bash
# Test: RELRO (partial and full)
# Verifies the following: PT_GNU_RELRO structure, BIND_NOW flag, .got coverage
. $(dirname $0)/common.inc

require_toolchain

compile_inline $t/main.o -fPIC <<'EOF'
#include <string.h>
int main(void) { return strlen("test"); }
EOF

# Partial RELRO (default)
link_pie $t/partial $t/main.o

# Full RELRO
run_meld -pie -z now \
    -o $t/full \
    "$CRT_PATH/Scrt1.o" "$CRT_PATH/crti.o" \
    $t/main.o \
    -L"$MUSL_SYSROOT/lib" --start-group -lc --end-group \
    "$CRT_PATH/crtn.o"

# PT_GNU_RELRO
$READELF -l $t/partial | grep -q "GNU_RELRO" || fail "Partial missing RELRO"
$READELF -l $t/full | grep -q "GNU_RELRO" || fail "Full missing RELRO"

# Full RELRO; BIND_NOW
$READELF -d $t/full | grep -q "BIND_NOW" || fail "Full missing BIND_NOW"

# Partial RELRO; BIND_NOW should not be set
if $READELF -d $t/partial | grep -q "BIND_NOW"; then
    fail "Partial should not have BIND_NOW"
fi

# PT_GNU_RELRO must cover .got
relro_info=$($READELF -l $t/partial | grep "GNU_RELRO")
relro_addr=$(echo "$relro_info" | awk '{print $3}')
relro_memsz=$(echo "$relro_info" | awk '{print $6}')

got_addr=$(section_addr $t/partial ".got")
if [[ -n "$got_addr" ]] && [[ -n "$relro_addr" ]]; then
    got=$((got_addr))
    relro=$((relro_addr))
    relro_end=$((relro + relro_memsz))
    
    if [[ $got -lt $relro ]] || [[ $got -ge $relro_end ]]; then
        fail ".got not covered by RELRO"
    fi
fi

assert_exit 4 $t/partial
assert_exit 4 $t/full

pass "RELRO operational"
