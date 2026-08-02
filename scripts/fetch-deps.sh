#!/bin/sh
# Fetch + build libntfs-3g (static) into refs/ — needed once before building.
set -e
cd "$(dirname "$0")/.."
mkdir -p refs && cd refs
[ -d ntfs-3g ] || git clone --depth 1 --branch 2026.7.7 https://github.com/tuxera/ntfs-3g.git
cd ntfs-3g
[ -f config.h ] || ./autogen.sh && ./configure --disable-shared --enable-static --disable-ntfsprogs-static
make -j8 -C libntfs-3g
echo "libntfs-3g ready: libntfs-3g/.libs/libntfs-3g.a"
