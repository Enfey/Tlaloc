# Source this at the start of each test: . $(dirname $0)/common.inc

set -e
set -x

t=$(mktemp -d)
trap "rm -rf $t" EXIT

CC="${CC:-cc}"
READELF="${READELF:-readelf}"
OBJDUMP="${OBJDUMP:-objdump}"

QEMU_LENS="${QEMU_LENS:-}"

LENS="${LENS:-$(dirname $0)/../../build/bin/lens}"

skip() {
  echo "skipped: $1"
  exit 0
}

has_cmd() {
  command -v "$1" &>/dev/null
}

# via QEMU if cross-compiled
run_lens() {
  if [[ -n "$QEMU_LENS" ]]; then
    $QEMU_LENS "$LENS" "$@"
  else
    "$LENS" "$@"
  fi
}

is_cross() {
  [[ -n "$TRIPLE" ]]
}

make_arm_exec() {
  local output="$1"
  cat <<'EOF' | $CC -xc -no-pie -o "$output" -
int main() { return 0; }
EOF
}

make_arm_so() {
  local output="$1"
  cat <<'EOF' | $CC -xc -shared -fPIC -o "$output" -
int foo() { return 42; }
EOF
}

make_arm_obj() {
  local output="$1"
  cat <<'EOF' | $CC -xc -c -o "$output" -
int foo() { return 42; }
EOF
}

not() {
  ! "$@"
}
