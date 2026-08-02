# Security & Code Review

## Foundational property: userspace, not the kernel

NTFSKit's driver runs in userspace via Apple's FSKit. It **cannot panic the
kernel or corrupt other volumes**. A bug in the driver takes down the driver,
not the machine. This is a structural difference from kext-based NTFS drivers
(Paragon, Tuxera) and from macFUSE, all of which run code in kernel space where
a fault can bring down the whole system or damage unrelated disks. Everything
below is defense in depth on top of that base property.

## Review process

Before release, the driver went through **4 independent code-review rounds**.
Each round combined:

- Claude (Anthropic)
- Codex (OpenAI GPT)
- Grok (xAI)
- A dedicated macOS-kernel / IO expert review

Roughly **50 defects** were found and fixed across the four rounds.

## Security-relevant fixes

- **Untrusted boot-sector / MFT volume-label parser** (runs at PROBE time on
  every disk inserted): bounded all shift exponents before shifting (a crafted
  NTFS boot sector could otherwise trap the module), guarded integer overflow
  in offset math, added power-of-two geometry validation, added
  update-sequence-array (USA) sector-trailer validation, and confined attribute
  values to their bounds. Fuzzed **20,000 random boot sectors** with no trap.
- **Runlist validation** on untrusted on-disk extent maps: overflow,
  out-of-volume clusters, and VCN contiguity are all checked, so corrupt
  runlists fail cleanly instead of reaching memcpy / alloc / loops.
- **xattr size cap before allocation**: a malicious huge Alternate Data Stream
  could otherwise drive an out-of-memory kill; the size is capped first.
- **Admin-privilege shell-quoting fix** in the app's format-support installer:
  POSIX single-quote escaping, closing a command-injection vector via the app
  bundle path.
- **Concurrency**: data races closed with locks (namespace cache, read-only
  state, device I/O mode); TOCTOU in xattr create/replace closed by single-hold
  operations.
- **Buffer-cache aliasing** for Kernel-Offloaded I/O: metadataPurge of
  kernel-written ranges so stale cached bytes never shadow direct kernel writes.

## Reproducibility

The driver is **GPL-2.0 open source**. Anyone can read, audit, and rebuild it.
That transparency is itself a security property closed-source competitors
cannot offer: you do not have to trust a claim, you can verify the code.

## Scope

These rounds reviewed, hardened, and fuzzed the driver. That is not a claim of
being bug-free or unhackable. It is a claim that the code has been examined by
multiple independent reviewers, that the untrusted-input paths are bounded and
fuzzed, and that you can check all of it yourself.

## Reporting

Security issues: **prathan@whereteam.com**
