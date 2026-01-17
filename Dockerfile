# Tlaloc Development Container
# Multi-arch build env
#
# Build:
#     docker build -t tlaloc-dev .
#
# Run interactive shell:
#     docker run -it --rm -v $(pwd):/workspace tlaloc-dev
#

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
    clang-format \
    valgrind \
    gdb-multiarch \
    file \
    binutils \
    binutils-arm-linux-gnueabi \
    binutils-aarch64-linux-gnu \
    curl \
    ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

ENV MUSL_VERSION=arm-linux-musleabi-cross
ENV MUSL_URL=https://musl.cc/${MUSL_VERSION}.tgz
ENV MUSL_SYSROOT=/opt/musl-arm

RUN curl -fsSL ${MUSL_URL} | tar -xz -C /opt \
    && mv /opt/${MUSL_VERSION} ${MUSL_SYSROOT} \
    && ln -s ${MUSL_SYSROOT}/bin/* /usr/local/bin/ \
    && rm -f ${MUSL_SYSROOT}/arm-linux-musleabi/lib/ld-musl-arm.so.1 \
    && ln -s libc.so ${MUSL_SYSROOT}/arm-linux-musleabi/lib/ld-musl-arm.so.1

ENV PATH="${MUSL_SYSROOT}/bin:${PATH}"
ENV MUSL_SYSROOT="${MUSL_SYSROOT}/arm-linux-musleabi"

WORKDIR /workspace

CMD ["/bin/bash"]
