# NTFS-for-Mac market research (mid-2026)

Two research passes: competitor feature matrix + real-user pain points.
Full source links at bottom of each section.

## Strategic finding

**The pure-FSKit slot is open.** Paragon and Tuxera still ship kexts that
require Reduced Security on Apple Silicon; iBoysoft advertises FSKit but as a
dual FSKit/kext path; Apple's own Tahoe NTFS driver is FSKit but read-only;
free options (Mounty, macFUSE+ntfs-3g) are slow or fragile. Nobody ships a
pure-FSKit read/write NTFS driver. NTFSKit's architecture kills the top-3
user complaints by construction: breaks-every-macOS-update, Reduced-Security
hassle, pay-again-per-macOS-version.

## Competitor matrix (condensed)

| Feature | Paragon | Tuxera | iBoysoft | EaseUS | Hasleo | Omi | Mounty |
|---|---|---|---|---|---|---|---|
| Price | $29.95 | $15 | $19.95/yr, $49.95 life | $14.95/mo, $49.95 life | Free | Freemium | Free |
| Tahoe 26 shipped | ✓ | ✓ (7 mo late) | ✓ | ✗ | ✗ | ? | ⚠️ manual deps |
| FSKit vs kext | kext | kext | FSKit+kext dual | kext | kext | AS helper | macFUSE |
| Auto-mount RW | ✓ | ✓ | ✓ | ✗ manual | ✓ | ✓ | ✗ prompt |
| Menu bar | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| RO toggle/volume | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | n/a |
| Format NTFS | ✓ | ✓ | ✓ | ✓ | ✗ | ✓ | ✗ |
| Check/repair | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ | ✗ |
| Boot Camp | ✓ +reboot-to-Win | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Published MB/s | ✓ 1460/2250 | ✗ | ✓ 970/1100 TB4 | ✗ | ✗ | ✗ | ✗ |
| xattr | ✓ | ✓ ("only driver") | ? | ✗ | ✗ | ✗ | via ntfs-3g |
| CLI | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Spotlight on NTFS | ✓ | ✓ | ? | ✗ | ✗ | ✗ | ✗ |

Features in 2+ competitors, by universality: menu bar (8/8), Apple Silicon
(8/8), auto-mount rw (6/8), Tahoe support (4-5/8), format (5/8),
check/repair (4/8), trial (5/8), RO toggle (3/8), Boot Camp (3/8),
CLI (3/8), published benchmarks (2/8), Spotlight (2/8).

## Top user pain points (ranked, 2024-2026)

1. Breaks after every macOS update (all vendors; Paragon not installable on
   Tahoe at launch; Tuxera 7 months late)
2. Kext / Reduced Security hassle on Apple Silicon ("turning off low-level
   protection just to mount a disk")
3. Pay-again-per-macOS-version resentment; licenses invalidated (Paragon
   post-Sonoma), subscription anger (iBoysoft)
4. "Ridiculous macOS can't do this natively" — want plug-in → read+write,
   zero setup
5. FUSE write speeds terrible (<1 MB/s macFUSE reports, ~20 MB/s FUSE-T)
6. Corruption / data-loss fear; "run chkdsk on Windows after Mac writes"
7. Mounty dies with each new macOS (piggybacks Apple's fragile write path)
8. The remount dance (Homebrew + macFUSE + ntfs-3g + sudo per plug-in)
9. **Windows Fast Startup / hibernation makes drives read-only — users blame
   the driver; nobody explains it well** ← cheap differentiator
10. Boot Camp partition read-only from macOS
11. Mac-written files need "take ownership" on Windows (permission mismatch)
12. No FSKit NTFS write driver ships yet (the open niche)
13. Apple's read-only FSKit mount races third-party write tools
14. FSKit expectation: userspace = can't panic kernel, Full Security intact
15. "Just use exFAT" resented when the drive isn't yours to reformat
    (friend's disk, dashcam/camera SD, shared game drives)

## NTFSKit roadmap derived from this research

- P0: publish real benchmarks (KOIO); hibernation-aware mount + in-app
  explanation; reliability story ($LogFile replay + real fsck); per-volume
  read-only toggle
- P1: mkntfs → startFormat (UI already built); full check/repair; verify
  Boot Camp partition; CLI; verify Spotlight indexing
- P2: xattr via NTFS ADS (kills ._ AppleDouble, matches Tuxera's brag);
  Thai + Chinese localization; day-one macOS support messaging; volume
  label editing; reboot-to-Windows menu item

## Sources

Competitors: paragon-software.com/home/ntfs-mac, ntfsformac.tuxera.com,
iboysoft.com/ntfs-for-mac, toolbox.easeus.com/ntfs-for-mac,
easyuefi.com/ntfs-for-mac, apps.apple.com (Omi id1585757563), mounty.app,
sysgeeker.com/ntfs-for-mac, eclecticlight.co (macOS 26 filesystems),
download.paragon-software.com/doc/ntfs4mac_performance.pdf

Pain points: news.ycombinator.com/item?id=44259974 & 43540157,
drbuho.com/review/paragon-ntfs-for-mac-review, trustpilot.com/review/iboysoft.com,
github.com/macfuse issues #265/#1025, github.com/macos-fuse-t/fuse-t#89,
discussions.apple.com threads 256036953/3549290/253707407,
forums.macrumors.com/threads/2447591, paragon-software.zendesk.com,
macsupport.tuxera.com, github.com/YangsonHung/macos-ntfs-smart-mount,
github.com/khr898/ntfsmac
