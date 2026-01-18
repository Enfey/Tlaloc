#!/bin/bash
# Test: Symbol handling (resolution, weak, synthetic)
# Verifies the following: Symbols in correct sections, weak override, linker-provided symbols
. $(dirname $0)/common.inc

require_toolchain

# Test 1 - Symbol-to-section mapping
compile_inline $t/main.o -fPIC <<'EOF'
const char rodata[] = "ro";
int data = 1;
int bss;
int func(void) { return 67; }
int main(void) { bss = data; return func(); }
EOF

link_pie $t/sym $t/main.o

# Each symbol must be within its section's address range
for pair in "func .text" "data .data" "bss .bss" "rodata .rodata"; do
    sym=$(echo $pair | cut -d' ' -f1)
    sec=$(echo $pair | cut -d' ' -f2)
    
    sym_val=$(($(symbol_value $t/sym "$sym")))
    sec_addr=$(($(section_addr $t/sym "$sec")))
    sec_size=$(($(section_size $t/sym "$sec")))
    
    if [[ $sym_val -lt $sec_addr ]] || [[ $sym_val -ge $((sec_addr + sec_size)) ]]; then
        fail "$sym ($sym_val) not in $sec [$sec_addr, +$sec_size)"
    fi
done

assert_exit 67 $t/sym

# Test 2 - Weak symbol override
compile_inline $t/weak.o <<'EOF'
__attribute__((weak)) int value(void) { return 1; }
int main(void) { return value(); }
EOF

compile_inline $t/strong.o <<'EOF'
int value(void) { return 99; }
EOF

link_static $t/weak_only $t/weak.o
link_static $t/with_strong $t/weak.o $t/strong.o

assert_exit 1 $t/weak_only
assert_exit 99 $t/with_strong

# Test 3 - Synthetic symbols
compile_inline $t/synth.o -fPIC <<'EOF'
extern char _DYNAMIC[];
extern char _GLOBAL_OFFSET_TABLE_[];
int main(void) {
    return (_DYNAMIC != 0 && _GLOBAL_OFFSET_TABLE_ != 0) ? 0 : 1;
}
EOF

link_pie $t/synth $t/synth.o

dyn_sym=$(symbol_value $t/synth "_DYNAMIC")
dyn_sec=$(section_addr $t/synth ".dynamic")
[[ $((dyn_sym)) -eq $((dyn_sec)) ]] || fail "_DYNAMIC != .dynamic addr"

got_sym=$(symbol_value $t/synth "_GLOBAL_OFFSET_TABLE_")
gotplt_sec=$(section_addr $t/synth ".got.plt")
[[ $((got_sym)) -eq $((gotplt_sec)) ]] || fail "_GOT_ != .got.plt addr"

assert_exit 0 $t/synth

pass "symbol handling operational"
