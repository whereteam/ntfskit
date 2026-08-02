# NTFSKit

**Full read/write NTFS for macOS — the world's first pure-FSKit NTFS driver
with Kernel-Offloaded I/O.**

Plug in an NTFS disk and it just mounts, read/write, at device speed.
No kext. No Reduced Security. No macFUSE. No terminal ceremony.

## Why it's different

| | NTFSKit | Paragon / Tuxera | Mounty / ntfs-3g+FUSE |
|---|---|---|---|
| Architecture | **FSKit (userspace, macOS 26)** | kext | macFUSE kext / FUSE-T |
| Reduced Security required | **No** | Yes (Apple Silicon) | Yes (macFUSE) |
| Auto-mount read/write | **Yes** | Yes | No (remount dance) |
| Write path | **Kernel-Offloaded I/O** — the kernel writes file data directly to disk; the driver only maps extents | kernel driver | userspace copy (~1–20 MB/s) |
| Survives macOS updates | **By design** (no kernel code) | Historically breaks | Historically breaks |
| Price | **Free & open source** (driver) | $15–30, re-paid per macOS era | Free |

Measured: **572 MB/s sequential writes** on a RAM-backed test volume
(driver ceiling — real disks run at their own device speed, verified
kernel-direct on USB hardware). ~28× faster than FUSE-T-based setups.

## Features

- Automatic read/write mounting of NTFS volumes (USB, external SSD/HDD, images)
- Kernel-Offloaded I/O: `blockmapFile` extent mapping, allocate-without-zeroing
  writes (`initialized_size`-correct, no stale-data exposure)
- Real fsck: verifies + replays the NTFS `$LogFile` journal, clears dirty flag
- Format as NTFS from Disk Utility / `diskutil eraseVolume NTFSKit Name diskN`
- Extended attributes stored as NTFS Alternate Data Streams — no `._` files,
  round-trips to Windows
- Windows hibernation / Fast Startup detected → safe read-only fallback with
  a clear in-app explanation
- Symlinks, Unicode names, volume label read at probe (mounts as
  `/Volumes/<YourLabel>`), stable volume UUIDs from the NTFS serial

## Requirements

- macOS 15.4+ (Apple Silicon)
- One-time enable: System Settings → General → Login Items & Extensions →
  File System Extensions → **NTFSKit**

## Building

```sh
# 1. libntfs-3g (static) — see refs/ntfs-3g (configure && make)
# 2. Generate the Xcode project and build
xcodegen generate
xcodebuild -scheme NTFSKit -configuration Release -allowProvisioningUpdates build
# 3. Engine tests (no FSKit needed)
cd NTFSModule/bridge && clang -Wall -DTEST_FORMAT -DHAVE_CONFIG_H \
  -I../../refs/ntfs-3g -I../../refs/ntfs-3g/include -I../../refs/ntfs-3g/include/ntfs-3g \
  -Imkntfs -I. test_bridge.c ntfs_bridge.c mkntfs/*.c \
  ../../refs/ntfs-3g/libntfs-3g/.libs/libntfs-3g.a -framework CoreFoundation -o test_bridge
```

## Architecture notes (for FSKit implementers)

Hard-won lessons, free to a good home:

- **FSKit tracks items by object identity.** Return one live `FSItem` per
  path or unlinks are silently deferred forever.
- **The kernel buffer cache (`metadataRead/Write`) attaches at kernel mount** —
  during `activate` it returns EIO. Start on plain `read/write`, upgrade on
  first success. Post-mount, buffer-cache I/O is what lets the engine touch
  metadata inside `blockmapFile` without deadlocking.
- **KOIO is all-or-nothing per volume**: advertising
  `FSSupportsKernelOffloadedIO` while inhibiting every item wedges kernel
  writeback (unkillable state-U writers).
- `startCheck` must complete its `Progress` *and* call `task.didComplete`
  asynchronously — a pre-completed Progress deadlocks fskitd and
  diskarbitrationd system-wide.
- Purge (`metadataPurge`) engine-primed buffer-cache ranges before the kernel
  writes those sectors directly, or later cache reads return stale data.

## Licensing

- **Driver (`NTFSModule/`, `fsbundle/`)**: GPL-2.0 — see `NTFSModule/LICENSE.GPL2`.
  Built on [libntfs-3g / ntfsprogs](https://github.com/tuxera/ntfs-3g)
  (© their authors; commercially dual-licensed by Tuxera Inc.).
- **App UI (`App/`)**: proprietary (see `LICENSE`). The driver is free
  forever; the app's Pro conveniences fund development.
