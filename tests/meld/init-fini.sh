#!/bin/bash
# Test: .init_array
# Verifies the following: DT_INIT_ARRAY points to section, constructor runs
. $(dirname $0)/common.inc

require_toolchain

compile_inline $t/main.o -fPIC <<'EOF'
static int init_ran = 0;

__attribute__((constructor))
static void my_init(void) { init_ran = 1; }

int main(void) { return init_ran ? 0 : 1; }
EOF

link_pie $t/a.out $t/main.o

# DT_INIT_ARRAY must equal .init_array address
init_dt=$(dynamic_value $t/a.out "INIT_ARRAY")
init_sec=$(section_addr $t/a.out ".init_array")
[[ -z "$init_dt" ]] || [[ $((init_dt)) -eq $((init_sec)) ]] || fail "DT_INIT_ARRAY mismatch"

# DT_INIT_ARRAYSZ must equal .init_array size
sz_dt=$(dynamic_value $t/a.out "INIT_ARRAYSZ")
sz_sec=$(section_size $t/a.out ".init_array")
[[ -z "$sz_dt" ]] || [[ $((sz_dt)) -eq $((sz_sec)) ]] || fail "DT_INIT_ARRAYSZ mismatch"

# Size must be multiple of 4 (pointer size)
[[ -z "$sz_sec" ]] || [[ $(($sz_sec % 4)) -eq 0 ]] || fail "Size not aligned"

# Constructor must actually run
assert_exit 0 $t/a.out

pass ".init_array works as expected"
