#!/bin/sh
# Rebuilds the bundled mkntfs from the ntfs-3g tree (GPL-2.0).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)   # absolute: we cd away before writing -o
cd "$HERE/../refs/ntfs-3g/ntfsprogs"
clang -O2 -DHAVE_CONFIG_H -I.. -I../include -I../include/ntfs-3g -I. \
  mkntfs.c utils.c sd.c boot.c attrdef.c \
  ../libntfs-3g/.libs/libntfs-3g.a -framework CoreFoundation \
  -o "$HERE/ntfskit.fs/Contents/Resources/mkntfs"
echo "mkntfs rebuilt"
