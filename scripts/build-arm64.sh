#!/bin/bash
# Build Tlaloc for ARM64 (AArch64)
set -e

cd /workspace

cmake -B build-arm64 -G Ninja \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DCMAKE_BUILD_TYPE=Release

cmake --build build-arm64

echo "ARM64 build complete. Binaries in build-arm64/bin/"
file build-arm64/bin/*
