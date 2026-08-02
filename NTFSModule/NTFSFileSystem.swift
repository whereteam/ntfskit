import Foundation
import FSKit
import os

/// Unary file system delegate: probe a block resource, and load it as an
/// NTFS volume when the boot sector says so.
final class NTFSFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations {

    private let log = Logger(subsystem: "com.whereteam.ntfskit.NTFSModule", category: "fs")
    private var lastResource: FSBlockDeviceResource?
    /// Check and format must never run concurrently — both do raw RMW on the
    /// same device.
    static let maintenanceQueue = DispatchQueue(label: "com.whereteam.ntfskit.maintenance")

    /// Deterministic UUID from the NTFS volume serial (boot sector 0x48) —
    /// random ones would give DiskArbitration a new identity every probe,
    /// breaking persistent mount records for the same disk.
    private static func volumeUUID(bootSector boot: [UInt8]) -> UUID {
        var b = [UInt8](repeating: 0, count: 16)
        for i in 0..<8 { b[i] = boot[0x48 + i] }
        // Fixed suffix marks these as NTFSKit-derived, RFC4122 v5-style bits.
        b[8] = 0x4E; b[9] = 0x54; b[10] = 0x46; b[11] = 0x53   // "NTFS"
        b[12] = 0x4B; b[13] = 0x49; b[14] = 0x54; b[15] = 0x00 // "KIT"
        b[6] = (b[6] & 0x0F) | 0x50
        b[8] = (b[8] & 0x3F) | 0x80
        return UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                           b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }

    func probeResource(resource: FSResource) async throws -> FSProbeResult {
        guard let block = resource as? FSBlockDeviceResource else {
            return .notRecognized
        }
        var boot = [UInt8](repeating: 0, count: 512)
        let read = try boot.withUnsafeMutableBytes { raw in
            try block.read(into: raw, startingAt: 0, length: 512)
        }
        // Boot sector bytes 3..6 spell "NTFS".
        guard read >= 8,
              boot[3] == 0x4E, boot[4] == 0x54, boot[5] == 0x46, boot[6] == 0x53 else {
            return .notRecognized
        }
        let uuid = Self.volumeUUID(bootSector: boot)
        // DiskArbitration names the mountpoint after the PROBE name — read the
        // real label ($Volume's VOLUME_NAME) so disks mount as /Volumes/<label>.
        let label = Self.readVolumeLabel(block: block, boot: boot) ?? "NTFS"
        return .usable(name: label, containerID: FSContainerIdentifier(uuid: uuid))
    }

    /// Minimal on-disk walk: boot sector → $MFT → record 3 ($Volume) →
    /// attribute 0x60 (VOLUME_NAME, resident UTF-16LE). Untrusted input:
    /// every offset is bounds-checked; any oddity returns nil.
    private static func readVolumeLabel(block: FSBlockDeviceResource,
                                        boot: [UInt8]) -> String? {
        func le16(_ b: [UInt8], _ o: Int) -> Int { Int(b[o]) | Int(b[o + 1]) << 8 }
        func le64(_ b: [UInt8], _ o: Int) -> Int64 {
            var v: Int64 = 0
            for i in (0..<8).reversed() { v = v << 8 | Int64(b[o + i]) }
            return v
        }
        let bytesPerSector = le16(boot, 0x0B)
        guard bytesPerSector >= 256, bytesPerSector <= 4096 else { return nil }
        let spc = Int(boot[0x0D])
        let clusterSize = spc > 0x80 ? (1 << (256 - spc)) : spc * bytesPerSector
        guard clusterSize > 0, clusterSize <= 2 << 20 else { return nil }
        let mftLCN = le64(boot, 0x30)
        guard mftLCN > 0 else { return nil }
        let cpr = Int(Int8(bitPattern: boot[0x40]))
        let recordSize = cpr < 0 ? (1 << -cpr) : cpr * clusterSize
        guard recordSize >= 512, recordSize <= 65536 else { return nil }

        // $Volume = MFT record 3 (within the MFT's first, always-contiguous run)
        let offset = mftLCN * Int64(clusterSize) + Int64(3 * recordSize)
        var rec = [UInt8](repeating: 0, count: recordSize)
        let got = (try? rec.withUnsafeMutableBytes { raw in
            try block.read(into: raw, startingAt: off_t(offset), length: recordSize)
        }) ?? 0
        guard got == recordSize,
              rec[0] == 0x46, rec[1] == 0x49, rec[2] == 0x4C, rec[3] == 0x45 else {
            return nil   // "FILE"
        }
        // Apply update-sequence fixups (last 2 bytes of each sector).
        let usaOfs = le16(rec, 4), usaCount = le16(rec, 6)
        guard usaCount > 1, usaOfs + usaCount * 2 <= recordSize,
              recordSize >= usaCount &* bytesPerSector - bytesPerSector else { return nil }
        for i in 1..<usaCount {
            let pos = i * bytesPerSector - 2
            guard pos + 1 < recordSize else { return nil }
            rec[pos] = rec[usaOfs + i * 2]
            rec[pos + 1] = rec[usaOfs + i * 2 + 1]
        }
        // Walk resident attributes for type 0x60 VOLUME_NAME.
        var a = le16(rec, 0x14)
        while a + 8 <= recordSize {
            let type = le16(rec, a) | le16(rec, a + 2) << 16
            if type == 0xFFFF_FFFF || type == 0xFFFF { break }
            let alen = le16(rec, a + 4) | le16(rec, a + 6) << 16
            guard alen >= 24, a + alen <= recordSize else { return nil }
            if type == 0x60, rec[a + 8] == 0 {   // resident
                let vlen = le16(rec, a + 0x10) | le16(rec, a + 0x12) << 16
                let vofs = le16(rec, a + 0x14)
                guard vlen > 0, vlen <= 256, vlen % 2 == 0,
                      a + vofs + vlen <= recordSize else { return nil }
                let data = Data(rec[(a + vofs)..<(a + vofs + vlen)])
                let s = String(data: data, encoding: .utf16LittleEndian)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                return (s?.isEmpty ?? true) ? nil : s
            }
            a += alen
        }
        return nil
    }

    func loadResource(resource: FSResource, options: FSTaskOptions) async throws -> FSVolume {
        guard let block = resource as? FSBlockDeviceResource else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
        }
        // Read-only when the device is, or when mount asked for it
        // (`mount -o rdonly` arrives as argv-style task options).
        let opts = options.taskOptions
        let readOnly = !block.isWritable || opts.contains("--rdonly") ||
                       opts.contains("rdonly") || opts.contains("ro")
        log.info("load NTFS on \(block.bsdName, privacy: .public) readOnly=\(readOnly)")
        lastResource = block
        containerStatus = .ready
        // Same serial-derived UUID as probe: DA keeps one identity per disk.
        var boot = [UInt8](repeating: 0, count: 512)
        _ = try? boot.withUnsafeMutableBytes { raw in
            try block.read(into: raw, startingAt: 0, length: 512)
        }
        let uuid = Self.volumeUUID(bootSector: boot)
        return NTFSVolume(resource: block,
                          volumeName: FSFileName(string: "NTFS"),
                          volumeID: FSVolume.Identifier(uuid: uuid),
                          readOnly: readOnly)
    }

    func unloadResource(resource: FSResource, options: FSTaskOptions) async throws {
        // Volume closes its engine handle in deactivate().
    }
}

// MARK: - fsck / newfs (required for DiskArbitration auto-mount)

extension NTFSFileSystem: FSManageableResourceMaintenanceOperations {

    func startCheck(task: FSTask, options: FSTaskOptions) throws -> Progress {
        // Real fsck (ntfsfix-level): mount the engine over the resource.
        // Check mode verifies mountability + dirty flag; repair mode replays
        // the $LogFile journal and clears the dirty flag — the same log pass
        // Windows chkdsk does. Full MFT/bitmap cross-check is a later phase.
        //
        // The Progress MUST finish *after* this method returns — FSKit
        // registers for completion on the returned object, and a
        // pre-completed Progress never fires, deadlocking fskitd (and with
        // it diskarbitrationd, i.e. the whole disk subsystem).
        let progress = Progress(totalUnitCount: 1)
        let block = lastResource
        let log = self.log
        let checkOnly = options.taskOptions.contains("-n")
        Self.maintenanceQueue.async {
            var checkError: NSError? = nil
            defer {
                progress.completedUnitCount = 1
                // fskitd's check connector blocks on this signal — without it
                // the whole disk subsystem (diskarbitrationd) wedges.
                task.didComplete(error: checkError)
            }
            guard let block else {
                // The check connector can run before any resource is loaded —
                // report clean rather than blocking every mount.
                log.info("startCheck: no resource — reporting clean")
                return
            }
            let fsckIO = FsckIO(resource: block)
            let repair = !checkOnly && block.isWritable
            var io = nk_io(ctx: Unmanaged.passUnretained(fsckIO).toOpaque(),
                           pread: fsckPreadTrampoline,
                           pwrite: fsckPwriteTrampoline,
                           size: fsckIO.deviceSize,
                           readonly: repair ? 0 : 1)
            var errbuf = [CChar](repeating: 0, count: 256)
            let rc = withExtendedLifetime(fsckIO) {
                nk_fsck(&io, repair ? 1 : 0, &errbuf, 256)
            }
            switch rc {
            case 0:
                log.info("startCheck: clean")
            case 1:
                log.info("startCheck: volume dirty\(repair ? " — journal replayed, flag cleared" : "")")
            case -2:
                // Hibernated Windows: mount falls back to read-only with the
                // reason in the log; blocking the mount here would help nobody.
                log.error("startCheck: Windows is hibernated — volume will mount read-only")
            default:
                log.error("startCheck: unmountable: \(String(cString: errbuf), privacy: .public)")
                checkError = NSError(domain: NSPOSIXErrorDomain, code: Int(EIO))
            }
        }
        return progress
    }

    func startFormat(task: FSTask, options: FSTaskOptions) throws -> Progress {
        // Real newfs: mkntfs (quick format) over the resource callbacks.
        // Same async completion contract as startCheck.
        let progress = Progress(totalUnitCount: 1)
        let block = lastResource
        let log = self.log
        // `newfs -v <label>` style: label follows -v in the option syntax.
        var label = "NTFS"
        let opts = options.taskOptions
        if let i = opts.firstIndex(of: "-v"), i + 1 < opts.count {
            label = opts[i + 1]
        }
        Self.maintenanceQueue.async {
            var formatError: NSError? = nil
            defer {
                progress.completedUnitCount = 1
                task.didComplete(error: formatError)
            }
            guard let block, block.isWritable else {
                formatError = NSError(domain: NSPOSIXErrorDomain, code: Int(EROFS))
                return
            }
            let io = FsckIO(resource: block)
            var nio = nk_io(ctx: Unmanaged.passUnretained(io).toOpaque(),
                            pread: fsckPreadTrampoline,
                            pwrite: fsckPwriteTrampoline,
                            size: io.deviceSize,
                            readonly: 0)
            var errbuf = [CChar](repeating: 0, count: 256)
            let rc = withExtendedLifetime(io) {
                label.withCString { nk_format(&nio, $0, &errbuf, 256) }
            }
            if rc == 0 {
                log.info("startFormat: mkntfs ok label=\(label, privacy: .public)")
            } else {
                log.error("startFormat failed: \(String(cString: errbuf), privacy: .public)")
                formatError = NSError(domain: NSPOSIXErrorDomain, code: Int(EIO))
            }
        }
        return progress
    }
}

// MARK: - fsck device I/O
// Sector-aligned RMW over the plain resource API — safe here because fsck
// runs with no kernel I/O in flight (volume not mounted).

final class FsckIO {
    let resource: FSBlockDeviceResource
    let blockSize: Int64
    let deviceSize: Int64

    init(resource: FSBlockDeviceResource) {
        self.resource = resource
        self.blockSize = Int64(resource.blockSize)
        self.deviceSize = Int64(resource.blockCount) * Int64(resource.blockSize)
    }

    func pread(_ buf: UnsafeMutableRawPointer, _ count: Int64, _ offset: Int64) -> Int64 {
        if offset < 0 || count < 0 || offset > Int64.max - count { return -1 }
        let end = min(offset + count, deviceSize)
        if offset >= deviceSize || end <= offset { return 0 }
        let start = (offset / blockSize) * blockSize
        let alignedEnd = min(((end + blockSize - 1) / blockSize) * blockSize, deviceSize)
        let len = Int(alignedEnd - start)
        let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: len,
                                                             alignment: Int(blockSize))
        defer { scratch.deallocate() }
        do {
            let n = try resource.read(into: scratch, startingAt: off_t(start), length: len)
            guard n == len else { return -1 }   // short read = failed sector
            let skip = Int(offset - start)
            let avail = min(Int(end - offset), n - skip)
            if avail > 0 { memcpy(buf, scratch.baseAddress!.advanced(by: skip), avail) }
            return Int64(avail)
        } catch { return -1 }
    }

    func pwrite(_ buf: UnsafeRawPointer, _ count: Int64, _ offset: Int64) -> Int64 {
        if offset < 0 || count < 0 || offset > Int64.max - count { return -1 }
        let end = min(offset + count, deviceSize)
        if offset >= deviceSize || end <= offset { return 0 }
        let start = (offset / blockSize) * blockSize
        let alignedEnd = min(((end + blockSize - 1) / blockSize) * blockSize, deviceSize)
        let len = Int(alignedEnd - start)
        let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: len,
                                                             alignment: Int(blockSize))
        defer { scratch.deallocate() }
        do {
            if offset != start || end != alignedEnd {
                let n = try resource.read(into: scratch, startingAt: off_t(start), length: len)
                guard n == len else { return -1 }
            }
            memcpy(scratch.baseAddress!.advanced(by: Int(offset - start)), buf, Int(end - offset))
            let w = try resource.write(from: UnsafeRawBufferPointer(scratch),
                                       startingAt: off_t(start), length: len)
            guard w == len else { return -1 }   // partial write = corrupt format
            return end - offset
        } catch { return -1 }
    }
}

let fsckPreadTrampoline: nk_pread_cb = { ctx, buf, count, offset in
    guard let ctx, let buf else { return -1 }
    return Unmanaged<FsckIO>.fromOpaque(ctx).takeUnretainedValue()
        .pread(buf, count, offset)
}

let fsckPwriteTrampoline: nk_pwrite_cb = { ctx, buf, count, offset in
    guard let ctx, let buf else { return -1 }
    return Unmanaged<FsckIO>.fromOpaque(ctx).takeUnretainedValue()
        .pwrite(buf, count, offset)
}
