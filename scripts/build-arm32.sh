#!/bin/bash
set -e

cd /workspace

cmake -B build-arm32 -G Ninja \
    -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_SYSTEM_PROCESSOR=arm \
    -DCMAKE_C_COMPILER=arm-linux-gnueabi-gcc \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="-march=armv7-a -marm"

cmake --build build-arm32

echo "ARM32 build complete. Binaries in build-arm32/bin/"
file build-arm32/bin/*
