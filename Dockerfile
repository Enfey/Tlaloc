# Tlaloc Development Container
# Multi-architecture build env for ARM32/ARM64 cross-compilation
#
# Build:
#   docker build -t tlaloc-dev .
#
# Run interactive shell:
#   docker run -it --rm -v $(pwd):/workspace tlaloc-dev
#
# Build ARM32:
#   docker run --rm -v $(pwd):/workspace tlaloc-dev ./scripts/build-arm32.sh
#
# Build ARM64:
#   docker run --rm -v $(pwd):/workspace tlaloc-dev ./scripts/build-arm64.sh

FROM debian:bookworm-slim

LABEL maintainer="Felix Riley-Kay <github.com/enfey>"
LABEL description="Tlaloc ELF toolchain development environment"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    gcc-arm-linux-gnueabi \
    g++-arm-linux-gnueabi \
    libc6-dev-armel-cross \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    qemu-user \
    qemu-user-static \
    cppcheck \
    clang-format \
    valgrind \
    gdb-multiarch \
    file \
    binutils \
    binutils-arm-linux-gnueabi \
    binutils-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Default to bash
CMD ["/bin/bash"]
