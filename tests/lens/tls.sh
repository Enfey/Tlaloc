#!/bin/bash
# Test: lens parses TLS .tdata, .tbss, PT_TLS
. $(dirname $0)/common.inc

cat <<'EOF' | $CC -xc -o $t/exe -lpthread -
#include <stdio.h>

__thread int tls_var = 123;
__thread int tls_bss;

int get_tls(void) { return tls_var + tls_bss; }
void set_tls(int v) { tls_var = v; }

int main() {
    set_tls(456);
    return get_tls();
}
EOF

run_lens $t/exe > $t/out

grep -q "Machine:.*ARM\|AArch64" $t/out
grep -q -E "\.tdata|\.tbss" $t/out
grep -q "TLS" $t/out
