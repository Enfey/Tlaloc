# Source this at the start of each meld test: . $(dirname $0)/common.inc

set -e
set -x

t=$(mktemp -d)
trap "rm -rf $t" EXIT

# Env
# Meld tests require the ARM32 musl toolchain specifically
CC="arm-linux-musleabi-gcc"
READELF="arm-linux-musleabi-readelf"
OBJDUMP="arm-linux-musleabi-objdump"
AR="arm-linux-musleabi-ar"
MELD="${MELD:-$(dirname $0)/../../build/bin/meld}"

QEMU="${QEMU:-qemu-arm}"
# Set manually if cross-compiling meld itself
QEMU_MELD="${QEMU_MELD:-}"

MUSL_SYSROOT="${MUSL_SYSROOT:-/tmp/arm-linux-musleabi-cross/arm-linux-musleabi}"
CRT_PATH="${CRT_PATH:-${MUSL_SYSROOT}/lib}"

skip() {
    echo "SKIP: $1"
    exit 0
}

fail() {
    echo "FAIL: $1"
    exit 1
}

pass() {
    echo "PASS: $1"
    exit 0
}

has_cmd() {
    command -v "$1" &>/dev/null
}

# Currently running through the docker so no need for qemu for meld
run_meld() {
    if [[ -n "$QEMU_MELD" ]]; then
        $QEMU_MELD "$MELD" "$@"
    else
        "$MELD" "$@"
    fi
}

run_binary() {
    local bin="$1"
    shift # Skip, acquire extra flags
    $QEMU -L "$MUSL_SYSROOT" "$bin" "$@"
}

# Check toolchain-related envs are sane
require_toolchain() {
    has_cmd "$CC" || skip "Cross compiler $CC not found"
    [[ -d "$MUSL_SYSROOT" ]] || skip "musl sysroot not found at $MUSL_SYSROOT"
    [[ -f "$MELD" ]] || skip "meld not found at $MELD"
}

# Compile inline C to ET_REL object
# Usage: compile_inline output.o <<'EOF' ... EOF
compile_inline() {
    local out="$1"
    shift
    $CC -c -xc -o "$out" "$@" -
}

# Link with meld (static executable)
# Usage: link_static output obj1.o obj2.o ...
link_static() {
    local out="$1"
    shift
    run_meld -static \
        -o "$out" \
        "$CRT_PATH/crt1.o" \
        "$CRT_PATH/crti.o" \
        "$@" \
        -L"$MUSL_SYSROOT/lib" \
        --start-group -lc --end-group \
        "$CRT_PATH/crtn.o"
}

# Usage: link_pie output obj1.o obj2.o ...
link_pie() {
    local out="$1"
    shift
    run_meld -pie \
        -o "$out" \
        "$CRT_PATH/Scrt1.o" \
        "$CRT_PATH/crti.o" \
        "$@" \
        -L"$MUSL_SYSROOT/lib" \
        --start-group -lc --end-group \
        "$CRT_PATH/crtn.o"
}

# Assert binary runs+ returns expected exit code
# Usage: assert_exit expected_code binary [args...]
assert_exit() {
    local expected="$1"
    local bin="$2"
    shift 2
    
    local actual
    set +e     # Disable temporarily; a non-zero exit would kill test script otherwise
    run_binary "$bin" "$@"
    actual=$?  # Capture exit status 
    set -e
    
    if [[ "$actual" -ne "$expected" ]]; then
        fail "Expected exit code $expected, got $actual"
    fi
}

# Usage: section_addr binary section_name
section_addr() {
    local bin="$1"
    local sec="$2"
    $READELF -S "$bin" | grep " $sec " | awk '{print "0x"$(NF-7)}'
}

section_size() {
    local bin="$1"
    local sec="$2"
    # Size is NF-5 from the end
    $READELF -S "$bin" | grep " $sec " | awk '{print "0x"$(NF-5)}'
}

# Usage: symbol_value binary symbol_name
symbol_value() {
    local bin="$1"
    local sym="$2"
    $READELF -s "$bin" | grep " $sym$" | head -1 | awk '{print "0x"$2}'
}

# Usage: dynamic_value binary tag
dynamic_value() {
    local bin="$1"
    local tag="$2"
    local line=$($READELF -d "$bin" | grep "($tag)")
    # Extract everything after "(TAG)" - use the first word after the tag
    local value=$(echo "$line" | sed "s/.*(${tag}) *//" | awk '{print $1}')
    echo "$value"
}

# Assert PT_LOADs don't overlap + are page-aligned
# Usage: assert_segments_valid binary
assert_segments_valid() {
    local bin="$1"
    local prev_end=0
    
    while read -r line; do
        local vaddr=$(echo "$line" | awk '{print $3}')
        local memsz=$(echo "$line" | awk '{print $6}')
        local align=$(echo "$line" | awk '{print $8}')
        
        # Parse bases and reassign
        vaddr=$((vaddr))
        memsz=$((memsz))
        align=$((align))
        
        # Check minimum
        if [[ $align -ge 4096 ]] && [[ $((vaddr % 4096)) -ne 0 ]]; then
            fail "Segment at $vaddr not page-aligned"
        fi
        
        if [[ $vaddr -lt $prev_end ]]; then
            fail "Segment at $vaddr overlaps with previous (ended at $prev_end)"
        fi
        
        prev_end=$((vaddr + memsz))
    done < <($READELF -l "$bin" 2>/dev/null | grep "LOAD")
}

# Assert .got.plt reserved entries are correct
# Usage: assert_gotplt_reserved binary
assert_gotplt_reserved() {
    local bin="$1"
    
    local gotplt_addr=$(section_addr "$bin" ".got.plt")
    local dynamic_addr=$(section_addr "$bin" ".dynamic")
    
    if [[ -z "$gotplt_addr" ]] || [[ -z "$dynamic_addr" ]]; then
        skip
    fi
    
    # First word of .got.plt should be address of .dynamic
    local first_word=$($OBJDUMP -s -j .got.plt "$bin" 2>/dev/null | grep -A1 "Contents" | tail -1 | awk '{print $2}')
    
    if [[ -n "$first_word" ]]; then
        local reversed=$(echo "$first_word" | sed 's/\(..\)\(..\)\(..\)\(..\)/\4\3\2\1/') # Break 32 bytes into 4 distinct groups, 
                                                                                          # then replace in reverse to acquire little-endian variant
        local got_val=$((16#$reversed)) # Interpret with 0x so arithmetic expansion can parse base; objdump does not have 0x
        local dyn_val=$((dynamic_addr))
        
        if [[ $got_val -ne $dyn_val ]]; then
            fail ".got.plt[0] ($got_val) != .dynamic addr ($dyn_val)"
        fi
    fi
}

# Usage: assert_plt_reloc_match binary
assert_plt_reloc_match() {
    local bin="$1"
    
    local plt_size=$(section_size "$bin" ".plt")
    local jmprel_count=$($READELF -r "$bin" 2>/dev/null | grep -c "R_ARM_JUMP_SLOT" || echo 0)
    
    if [[ -z "$plt_size" ]] || [[ "$jmprel_count" -eq 0 ]]; then
        skip
    fi
    
    # PLT size = PLT[0] (20) + N * PLT[n] (24)
    # Therefore, size - 20 / 24 should equal jmprel_count
    local plt_sz=$((plt_size))
    local expected_count=$(( (plt_sz - 20) / 24 ))
    
    if [[ $expected_count -ne $jmprel_count ]]; then
        fail "PLT entries ($expected_count) != JUMP_SLOT relocs ($jmprel_count)"
    fi
}

# Assert DT_PLTGOT points to .got.plt
# Usage: assert_pltgot_correct binary
assert_pltgot_correct() {
    local bin="$1"
    
    local pltgot=$(dynamic_value "$bin" "PLTGOT")
    local gotplt_addr=$(section_addr "$bin" ".got.plt")
    
    if [[ -z "$pltgot" ]] || [[ -z "$gotplt_addr" ]]; then
        skip
    fi
    
    # Avoid format differences
    if [[ $((pltgot)) -ne $((gotplt_addr)) ]]; then
        fail "DT_PLTGOT ($pltgot) != .got.plt addr ($gotplt_addr)"
    fi
}

# Assert DT_STRTAB points to .dynstr
# Usage: assert_strtab_correct binary
assert_strtab_correct() {
    local bin="$1"
    
    local strtab=$(dynamic_value "$bin" "STRTAB")
    local dynstr_addr=$(section_addr "$bin" ".dynstr")
    
    if [[ -z "$strtab" ]] || [[ -z "$dynstr_addr" ]]; then
        return 0
    fi
    
    if [[ $((strtab)) -ne $((dynstr_addr)) ]]; then
        fail "DT_STRTAB ($strtab) != .dynstr addr ($dynstr_addr)"
    fi
}

# Assert DT_SYMTAB points to .dynsym
# Usage: assert_symtab_correct binary
assert_symtab_correct() {
    local bin="$1"
    
    local symtab=$(dynamic_value "$bin" "SYMTAB")
    local dynsym_addr=$(section_addr "$bin" ".dynsym")
    
    if [[ -z "$symtab" ]] || [[ -z "$dynsym_addr" ]]; then
        return 0
    fi
    
    if [[ $((symtab)) -ne $((dynsym_addr)) ]]; then
        fail "DT_SYMTAB ($symtab) != .dynsym addr ($dynsym_addr)"
    fi
}

# Assert portion of .dynamic section pointers are valid
# The pattern is replicated in meld; I have little doubt
# this will break so it would be meaningless to test this for arbitrary tags
# Usage: assert_dynamic_structure binary
assert_dynamic_structure() {
    local bin="$1"
    
    assert_pltgot_correct "$bin"
    assert_strtab_correct "$bin"
    assert_symtab_correct "$bin"
}

# Assert section ordering (text before data, etc.)
# Usage: assert_section_order binary sec1 sec2
assert_section_order() {
    local bin="$1"
    local sec1="$2"
    local sec2="$3"
    
    local addr1=$(section_addr "$bin" "$sec1")
    local addr2=$(section_addr "$bin" "$sec2")
    
    if [[ -z "$addr1" ]] || [[ -z "$addr2" ]]; then
        skip
    fi
    
    if [[ $((addr1)) -ge $((addr2)) ]]; then
        fail "Section $sec1 ($addr1) should come before $sec2 ($addr2)"
    fi
}
