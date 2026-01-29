#!/bin/bash
# Comprehensive meld test - single main.c + archive
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

CC="${CC:-arm-linux-musleabi-gcc}"
AR="${AR:-arm-linux-musleabi-ar}"
READELF="${READELF:-arm-linux-musleabi-readelf}"
MELD="${MELD:-../../../build-docker/bin/meld}"
QEMU="${QEMU:-qemu-arm}"
MUSL_SYSROOT="${MUSL_SYSROOT:-/tmp/arm-linux-musleabi-cross/arm-linux-musleabi}"
CRT_PATH="${CRT_PATH:-${MUSL_SYSROOT}/lib}"

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

MODE="${1:-pie}"

echo "Compiling"
[[ "$MODE" == "static" ]] && CFLAGS="" || CFLAGS="-fPIC"
$CC -c $CFLAGS -o "$TMPDIR/main.o" main.c
$CC -c $CFLAGS -o "$TMPDIR/archive_func.o" archive_func.c

echo "Creating archive"
$AR rcs "$TMPDIR/libtest.a" "$TMPDIR/archive_func.o"

echo "Linking with meld ($MODE)"
OUTPUT="$TMPDIR/test"

if [[ "$MODE" == "static" ]]; then
    "$MELD" -static -o "$OUTPUT" \
        "$CRT_PATH/crt1.o" "$CRT_PATH/crti.o" \
        "$TMPDIR/main.o" "$TMPDIR/libtest.a" \
        -L"$MUSL_SYSROOT/lib" --start-group -lc --end-group \
        "$CRT_PATH/crtn.o"
else
    "$MELD" -pie -o "$OUTPUT" \
        "$CRT_PATH/Scrt1.o" "$CRT_PATH/crti.o" \
        "$TMPDIR/main.o" "$TMPDIR/libtest.a" \
        -L"$MUSL_SYSROOT/lib" --start-group -lc --end-group \
        "$CRT_PATH/crtn.o"
fi

echo "ELF Header"
$READELF -h "$OUTPUT" | grep -E "Type:|Entry"

echo ""
echo "Program Headers"
$READELF -l "$OUTPUT" | grep -E "LOAD|INTERP|DYNAMIC|RELRO" || true

echo ""
echo "Dynamic Section"
$READELF -d "$OUTPUT" | grep -E "NEEDED|INIT|FINI|SYMTAB|STRTAB|REL|PLT|GOT|BIND" || true

echo ""
echo "Key Symbols"
$READELF -s "$OUTPUT" | grep -E "_start|_DYNAMIC|_GLOBAL_OFFSET|main|archive_func|weak_value" || true

echo ""
echo "Relocations"
$READELF -r "$OUTPUT" | head -20

echo ""
echo "Running Test"
$QEMU -L "$MUSL_SYSROOT" "$OUTPUT"
