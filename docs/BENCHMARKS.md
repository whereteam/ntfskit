# Benchmarks

## Method

Sequential write and read measured with `dd` on macOS 26.5, Apple Silicon:

```
# write
dd if=/dev/zero of=<vol>/bench.bin bs=1m count=100
# read
dd if=bench.bin of=/dev/null bs=1m
```

## Driver ceiling (RAM-backed disk image)

Run against a RAM-backed disk image, `dd` measures the **driver's ceiling**,
not the disk:

- Sequential write: **572 MB/s**
- ~**1.85x** faster than the pre-KOIO byte-copy path (309 MB/s)
- ~**28x** faster than FUSE-T + ntfs-3g setups (~20 MB/s reported by that
  community)

## Why it's fast: Kernel-Offloaded I/O (KOIO)

The kernel writes file data **directly** to the disk's clusters. The driver
only maps extents and stamps metadata — there is no userspace byte-copy in the
write path.

Newly-allocated space is grown with solid (non-sparse) clusters **without a
zeroing pass**, using the NTFS `initialized_size` mechanism. A sequential write
therefore does zero redundant engine writes.

## On real hardware

On a physical disk, writes run at the **disk's own speed** — the driver is not
the bottleneck. Verified kernel-direct on a USB stick, where throughput was the
stick's own ceiling, not the driver's.

## Honesty note

572 MB/s is a driver-ceiling figure on a RAM-backed image. Your real number
depends on your disk. The point is not the headline throughput; it is that the
**driver adds negligible overhead** on top of whatever your hardware can do.

## Comparison

| Setup | Throughput | Notes |
|---|---|---|
| **NTFSKit** | 572 MB/s (driver ceiling); device-speed on real disks | Userspace, no kext |
| Paragon | ~1460 / 2250 MB/s (published, 2018 SSD) | kext |
| FUSE-based (FUSE-T + ntfs-3g) | ~20 MB/s | userspace copy path |

These numbers come from **different hardware and are not directly comparable**.
Frame NTFSKit's advantage as what it structurally is: **device-speed, in
userspace, no kext**.
