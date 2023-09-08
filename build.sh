#!/bin/sh -eux

# Ref. https://wiki.qemu.org/Hosts/Linux

export CC=/usr/lib/ccache/gcc-12 # fails with gcc-10

if [ -d build ]; then
    cd build && make -j
else
    mkdir -p build
    (
        cd build
        ../configure \
            --target-list=riscv32-linux-user,riscv64-linux-user \
            --enable-tcg \
            --enable-plugins \
            --enable-debug
        make -j
    )
fi
