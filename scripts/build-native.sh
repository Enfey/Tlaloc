#!/bin/bash
# Native build with sanitisers and no optimisations enabled.
set -e

cd /workspace

cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-fsanitize=undefined,address -fno-omit-frame-pointer"

cmake --build build

echo "Native build complete. Binaries in build/bin/"
file build/bin/*
