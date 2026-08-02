import Foundation
import FSKit
import os

/// NTFS volume backed by libntfs-3g through the nk_* C bridge.
/// libntfs-3g is not thread-safe → every engine call goes through one serial queue.
final class NTFSVolume: FSVolume, FSVolume.Operations, FSVolume.ReadWriteOperations {

    private let log = Logger(subsystem: "com.whereteam.ntfskit.NTFSModule", category: "volume")
    private let engineQueue = DispatchQueue(label: "com.whereteam.ntfskit.engine")

    private let resource: FSBlockDeviceResource
    /// Becomes true if a read-write engine mount fails (hibernated Windows,
    /// unrecoverable journal) and we fall back to read-only. Lock-guarded:
    /// written during mount, read from concurrent upcall threads.
    private let roLock = NSLock()
    private var _readOnly: Bool
    private var readOnly: Bool {
        get { roLock.lock(); defer { roLock.unlock() }; return _readOnly }
        set { roLock.lock(); defer { roLock.unlock() }; _readOnly = newValue }
    }

    private var vol: OpaquePointer?              // nk_volume*
    private var nextID: UInt64 = 100
    private var idByPath: [String: FSItem.Identifier] = ["/": .rootDirectory]
    /// Bumped on every namespace mutation so cached kernel dirents invalidate.
    private var dirGeneration: UInt64 = 1
    /// One live NTFSItem instance per path — FSKit tracks items by object
    /// identity; handing out fresh instances per lookup leaks phantom vnodes
    /// (files stay "open" forever and unlink is deferred indefinitely).
    private var itemByPath: [String: NTFSItem] = [:]
    /// FSKit doesn't promise upcalls arrive serialized — all namespace-cache
    /// state above is guarded by this lock (recursive: item() calls id()).
    private let stateLock = NSRecursiveLock()

    private func item(path: String, kind: FSItem.ItemType) -> NTFSItem {
        stateLock.lock(); defer { stateLock.unlock() }
        if let existing = itemByPath[path] { return existing }
        let fresh = NTFSItem(path: path, kind: kind, identifier: id(for: path))
        itemByPath[path] = fresh
        return fresh
    }

    // Sector-aligned scratch state for the nk_io callbacks. The sandbox forbids
    // opening /dev, so all engine I/O goes through FSBlockDeviceResource.
    //
    // TWO device paths, switched automatically:
    // - The kernel buffer cache (metadataRead/metadataWrite) only comes alive
    //   once the KERNEL MOUNT exists — during activate it returns EIO. So
    //   engine I/O starts on the plain read/write API (safe: no kernel I/O is
    //   in flight before the mount) and flips to buffer-cache I/O the moment
    //   a metadataRead succeeds. Post-mount, buffer-cache I/O is what makes
    //   engine metadata updates inside blockmapFile deadlock-free (msdos-style).
    /// Device I/O mode; only touched from engineQueue (all device callbacks
    /// originate from engine calls serialized there).
    fileprivate enum IOMode { case probing, metadata }
    fileprivate var ioMode: IOMode = .probing

    fileprivate var deviceBlockSize: Int {
        // Use the LOGICAL block size: it's the unit blockCount is measured in,
        // so deviceSize stays an exact multiple and tail I/O stays aligned.
        // (max with physicalBlockSize breaks on 512e disks whose blockCount
        // isn't a multiple of 8.)
        Int(resource.blockSize)
    }
    fileprivate var deviceSize: Int64 {
        // blockCount is in units of blockSize (NOT deviceBlockSize) — using
        // the wrong unit inflated the size 8x and pushed end-of-volume reads
        // (NTFS backup boot sector) past the device, which EIOs.
        Int64(resource.blockCount) * Int64(resource.blockSize)
    }

    /// Aligned pread through the kernel buffer cache: read whole sectors
    /// covering [offset, offset+count) and copy out the window. -1 on error.
    fileprivate func devicePread(_ buf: UnsafeMutableRawPointer, _ count: Int64, _ offset: Int64) -> Int64 {
        let bs = Int64(deviceBlockSize)
        if offset < 0 || count < 0 || offset > Int64.max - count { return -1 }
        let end = min(offset + count, deviceSize)
        if offset >= deviceSize || end <= offset { return 0 }
        let alignedStart = (offset / bs) * bs
        let alignedEnd = min(((end + bs - 1) / bs) * bs, deviceSize)
        let alignedLen = Int(alignedEnd - alignedStart)
        let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: alignedLen,
                                                             alignment: Int(bs))
        defer { scratch.deallocate() }
        do {
            try readAligned(into: scratch, at: alignedStart, length: alignedLen)
            let skip = Int(offset - alignedStart)
            let avail = max(0, min(Int(end - offset), alignedLen - skip))
            if avail > 0 {
                memcpy(buf, scratch.baseAddress!.advanced(by: skip), avail)
            }
            return Int64(avail)
        } catch {
            log.error("devicePread(\(offset), \(count)) failed: \(error, privacy: .public)")
            return -1
        }
    }

    /// Aligned whole-block read through the current mode, upgrading to
    /// buffer-cache I/O as soon as the kernel accepts it.
    private func readAligned(into scratch: UnsafeMutableRawBufferPointer,
                             at start: Int64, length: Int) throws {
        dispatchPrecondition(condition: .onQueue(engineQueue))
        if ioMode == .metadata {
            try resource.metadataRead(into: scratch, startingAt: off_t(start),
                                      length: length)
            return
        }
        do {
            try resource.metadataRead(into: scratch, startingAt: off_t(start),
                                      length: length)
            ioMode = .metadata
            log.info("device I/O upgraded to kernel buffer cache")
        } catch {
            let n = try resource.read(into: scratch, startingAt: off_t(start),
                                      length: length)
            guard n == length else { throw posix(EIO) }
        }
    }

    /// Aligned whole-block write. Upgrades to buffer-cache I/O the same way
    /// reads do — critical: once the kernel mount exists, plain resource.write
    /// races the kernel's direct KOIO writes (torn MFT/$Bitmap sectors), so we
    /// must move onto metadataWrite as soon as the cache accepts it.
    private func writeAligned(_ scratch: UnsafeMutableRawBufferPointer,
                              at start: Int64, length: Int) throws {
        dispatchPrecondition(condition: .onQueue(engineQueue))
        if ioMode == .metadata {
            try resource.metadataWrite(from: UnsafeRawBufferPointer(scratch),
                                       startingAt: off_t(start), length: length)
            return
        }
        do {
            try resource.metadataWrite(from: UnsafeRawBufferPointer(scratch),
                                       startingAt: off_t(start), length: length)
            ioMode = .metadata
            log.info("device I/O upgraded to kernel buffer cache (write)")
        } catch {
            // Pre-mount only: buffer cache not attached yet, no kernel I/O in
            // flight, plain write is safe.
            let n = try resource.write(from: UnsafeRawBufferPointer(scratch),
                                       startingAt: off_t(start), length: length)
            guard n == length else { throw posix(EIO) }
        }
    }

    /// Aligned pwrite through the kernel buffer cache, with read-modify-write
    /// on partial edge sectors.
    fileprivate func devicePwrite(_ buf: UnsafeRawPointer, _ count: Int64, _ offset: Int64) -> Int64 {
        let bs = Int64(deviceBlockSize)
        if offset < 0 || count < 0 || offset > Int64.max - count { return -1 }
        let end = min(offset + count, deviceSize)
        if offset >= deviceSize || end <= offset { return 0 }
        let alignedStart = (offset / bs) * bs
        let alignedEnd = min(((end + bs - 1) / bs) * bs, deviceSize)
        let alignedLen = Int(alignedEnd - alignedStart)
        let scratch = UnsafeMutableRawBufferPointer.allocate(byteCount: alignedLen,
                                                             alignment: Int(bs))
        defer { scratch.deallocate() }
        do {
            // RMW: preload edge sectors when the write is not perfectly aligned.
            if offset != alignedStart || end != alignedEnd {
                try readAligned(into: scratch, at: alignedStart, length: alignedLen)
            }
            let skip = Int(offset - alignedStart)
            memcpy(scratch.baseAddress!.advanced(by: skip), buf, Int(end - offset))
            // INVARIANT: engine writes MUST stay synchronous while
            // blockmapFile purges data ranges from the buffer cache. With
            // delayedMetadataWrite, purging would drop dirty buffers (lossy)
            // and an unflushed engine write could later flush stale bytes
            // OVER data the kernel wrote directly. Do not "optimize" this
            // without redesigning the purge protocol.
            try writeAligned(scratch, at: alignedStart, length: alignedLen)
            return end - offset
        } catch {
            log.error("devicePwrite(\(offset), \(count)) failed: \(error, privacy: .public)")
            return -1
        }
    }

    init(resource: FSBlockDeviceResource, volumeName: FSFileName,
         volumeID: FSVolume.Identifier, readOnly: Bool) {
        self.resource = resource
        self._readOnly = readOnly
        super.init(volumeID: volumeID, volumeName: volumeName)
        wantReadOnlyMount = readOnly
    }

    // MARK: engine

    private func openEngine() throws {
        try engineQueue.sync {
            guard vol == nil else { return }
            var io = nk_io(ctx: Unmanaged.passUnretained(self).toOpaque(),
                           pread: nkPreadTrampoline,
                           pwrite: nkPwriteTrampoline,
                           size: deviceSize,
                           readonly: readOnly ? 1 : 0)
            var errbuf = [CChar](repeating: 0, count: 256)
            if let handle = nk_mount_io(&io, &errbuf, 256) {
                vol = handle
                return
            }
            let reason = String(cString: errbuf)
            log.error("nk_mount_io failed: \(reason, privacy: .public)")
            // Hibernated Windows / unrecoverable journal refuse read-write —
            // fall back to read-only instead of failing the whole mount, so
            // the user can still get at their files (the app explains why).
            if !readOnly {
                io.readonly = 1
                if let handle = nk_mount_io(&io, &errbuf, 256) {
                    log.info("falling back to READ-ONLY mount: \(reason, privacy: .public)")
                    readOnly = true
                    wantReadOnlyMount = true
                    vol = handle
                    return
                }
            }
            throw self.posix(EIO)
        }
    }

    @discardableResult
    private func closeEngine() -> Int32 {
        engineQueue.sync {
            let rc: Int32 = vol.map { nk_umount($0) } ?? 0
            vol = nil
            // If FSKit reactivates this instance, the next engine open happens
            // pre-mount again — the buffer cache won't be attached, so start
            // back in probing mode.
            ioMode = .probing
            return rc
        }
    }

    private func id(for path: String) -> FSItem.Identifier {
        stateLock.lock(); defer { stateLock.unlock() }
        if let existing = idByPath[path] { return existing }
        nextID += 1
        let newID = FSItem.Identifier(rawValue: nextID) ?? .invalid
        idByPath[path] = newID
        return newID
    }

    /// Namespace mutation bookkeeping under one lock.
    private func mutateNamespace(_ body: () -> Void) {
        stateLock.lock(); defer { stateLock.unlock() }
        dirGeneration += 1
        body()
    }

    private func posix(_ code: Int32) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(code))
    }

    // MARK: FSVolume.Operations

    /// Version-independent intent (Bool, no 26-only type) — the actual
    /// `requestedMountOptions` witness below is gated to macOS 26.4 where
    /// FSMountOptions exists. On 15.4–26.3 the kernel mount mode just follows
    /// the block device's own writability; the volume still works read-only.
    fileprivate var wantReadOnlyMount = false

    /// FSKit reads this after mount() replies — if the engine fell back to
    /// read-only (hibernated Windows, bad journal), the KERNEL mount goes
    /// read-only too, so Finder/statfs agree with reality. Only on 26.4+
    /// (FSMountOptions is a V2.4 API).
    @available(macOS 26.4, *)
    var requestedMountOptions: FSVolume.MountOptions {
        wantReadOnlyMount ? [.readOnly] : []
    }

    /// POSIX open-unlink semantics (delete an open file, keep using it) —
    /// FSKit emulates it via rename + deferred delete. V2 API (macOS 26+);
    /// on 15.4 the kernel simply doesn't offer the emulation.
    @available(macOS 26.0, *)
    var enableOpenUnlinkEmulation: Bool { true }

    var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let caps = FSVolume.SupportedCapabilities()
        // Honest advertising: createLink is ENOTSUP and our IDs are per-mount
        // path counters, not stable MFT references (flip both when those land).
        caps.supportsHardLinks = false
        caps.supportsSymbolicLinks = true
        caps.supportsPersistentObjectIDs = false
        caps.doesNotSupportImmutableFiles = true
        caps.supports64BitObjectIDs = true
        return caps
    }

    var volumeStatistics: FSStatFSResult {
        let stats = FSStatFSResult(fileSystemTypeName: "ntfskit")
        var total: Int64 = 0, free: Int64 = 0
        var cluster: Int32 = 0
        engineQueue.sync { _ = nk_statvfs(vol, &total, &free, &cluster) }
        let bs = cluster > 0 ? Int(cluster) : 4096
        stats.blockSize = bs
        stats.ioSize = 1 << 20
        stats.totalBlocks = UInt64(max(0, total)) / UInt64(bs)
        stats.availableBlocks = UInt64(max(0, free)) / UInt64(bs)
        stats.freeBlocks = stats.availableBlocks
        return stats
    }

    // MARK: PathConf

    var maximumLinkCount: Int { 1023 }
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { false }
    var truncatesLongNames: Bool { false }

    // MARK: lifecycle

    func activate(options: FSTaskOptions) async throws -> FSItem {
        try openEngine()
        var label = [CChar](repeating: 0, count: 256)
        engineQueue.sync { _ = nk_label(vol, &label, 256) }
        let name = String(cString: label)
        if !name.isEmpty { self.name = FSFileName(string: name) }
        return item(path: "/", kind: .directory)
    }

    func deactivate(options: FSDeactivateOptions) async throws {
        // An unmount-time engine write failure must not be silent data loss,
        // and flushing the buffer cache at teardown is on us, not fskitd.
        let rc = closeEngine()
        try? resource.metadataFlush()
        guard rc == 0 else { throw posix(EIO) }
    }
    func mount(options: FSTaskOptions) async throws { try openEngine() }
    func unmount() async { closeEngine() }

    func synchronize(flags: FSSyncFlags) async throws {
        let rc = engineQueue.sync { nk_sync(vol) }
        guard rc == 0 else { throw posix(EIO) }
        try resource.metadataFlush()
    }

    // MARK: attributes

    private func makeAttributes(path: String, st: nk_stat,
                                identifier: FSItem.Identifier) -> FSItem.Attributes {
        let attrs = FSItem.Attributes()
        if st.is_symlink != 0 {
            attrs.type = .symlink
            attrs.mode = 0o120755
        } else if st.is_dir != 0 {
            attrs.type = .directory
            attrs.mode = 0o040755
        } else {
            attrs.type = .file
            attrs.mode = 0o0100644
        }
        attrs.size = UInt64(max(0, st.size))
        attrs.allocSize = UInt64(max(0, st.alloc_size))
        attrs.linkCount = 1
        attrs.fileID = identifier
        attrs.parentID = path == "/" ? .parentOfRoot : id(for: (path as NSString).deletingLastPathComponent)
        attrs.uid = getuid()
        attrs.gid = getgid()
        attrs.flags = 0
        // Compressed/encrypted data can't be extent-mapped — those files use
        // the byte-copy upcall path. Everything else (incl. resident files,
        // which nk_blockmap converts on first map) rides KOIO at device speed.
        // Converting resident data is a write, so on read-only mounts resident
        // files must stay on the byte-copy path too.
        attrs.inhibitKernelOffloadedIO = st.koio_ok == 0 ||
                                         (readOnly && st.is_resident != 0)
        attrs.modifyTime = timespec(tv_sec: Int(st.mtime), tv_nsec: 0)
        attrs.accessTime = timespec(tv_sec: Int(st.atime), tv_nsec: 0)
        attrs.changeTime = timespec(tv_sec: Int(st.ctime), tv_nsec: 0)
        attrs.birthTime = timespec(tv_sec: Int(st.btime), tv_nsec: 0)
        return attrs
    }

    func attributes(_ request: FSItem.GetAttributesRequest, of item: FSItem) async throws -> FSItem.Attributes {
        guard let item = item as? NTFSItem else { throw posix(EINVAL) }
        var st = nk_stat()
        let rc = engineQueue.sync { item.path.withCString { nk_stat_path(vol, $0, &st) } }
        guard rc == 0 else { throw posix(ENOENT) }
        return makeAttributes(path: item.path, st: st, identifier: item.identifier)
    }

    func setAttributes(_ request: FSItem.SetAttributesRequest, on item: FSItem) async throws -> FSItem.Attributes {
        guard let item = item as? NTFSItem else { throw posix(EINVAL) }
        if request.isValid(.size) {
            if readOnly { throw posix(EROFS) }
            let rc = engineQueue.sync {
                item.path.withCString { nk_truncate(vol, $0, Int64(request.size)) }
            }
            guard rc == 0 else { throw posix(EIO) }
        }
        let atime = request.isValid(.accessTime) ? Int64(request.accessTime.tv_sec) : Int64(-1)
        let mtime = request.isValid(.modifyTime) ? Int64(request.modifyTime.tv_sec) : Int64(-1)
        let btime = request.isValid(.birthTime) ? Int64(request.birthTime.tv_sec) : Int64(-1)
        if atime >= 0 || mtime >= 0 || btime >= 0 {
            _ = engineQueue.sync {
                item.path.withCString { nk_set_times(vol, $0, atime, mtime, btime) }
            }
        }
        // Ownership/mode changes: accepted silently for now (NTFS ACL mapping
        // is a later phase); report back the real on-disk attributes.
        return try await attributes(FSItem.GetAttributesRequest(), of: item)
    }

    // MARK: lookup / enumerate

    func lookupItem(named name: FSFileName, inDirectory directory: FSItem) async throws -> (FSItem, FSFileName) {
        guard let dir = directory as? NTFSItem, let childName = name.string else { throw posix(EINVAL) }
        let childPath = dir.childPath(childName)
        var st = nk_stat()
        let rc = engineQueue.sync { childPath.withCString { nk_stat_path(vol, $0, &st) } }
        guard rc == 0 else { throw posix(ENOENT) }
        let kind: FSItem.ItemType = st.is_symlink != 0 ? .symlink
                                  : st.is_dir != 0 ? .directory : .file
        return (item(path: childPath, kind: kind), name)
    }

    func enumerateDirectory(_ directory: FSItem,
                            startingAt cookie: FSDirectoryCookie,
                            verifier: FSDirectoryVerifier,
                            attributes: FSItem.GetAttributesRequest?,
                            packer: FSDirectoryEntryPacker) async throws -> FSDirectoryVerifier {
        guard let dir = directory as? NTFSItem else { throw posix(EINVAL) }

        // Sample the generation BEFORE listing: if a mutation lands during or
        // after the list, the verifier we hand back is already stale and the
        // next resume gets told to restart — never a fresh verifier on a
        // stale entry vector.
        let generation = stateLock.withLock { dirGeneration }
        if cookie.rawValue != 0 && verifier.rawValue != generation {
            throw FSError(.invalidDirectoryCookie)
        }

        let collector = DirCollector()
        let rc = engineQueue.sync {
            dir.path.withCString { path in
                nk_list(vol, path, dirCollectCallback, Unmanaged.passUnretained(collector).toOpaque())
            }
        }
        guard rc == 0 else { throw posix(EIO) }

        var entries: [(name: String, type: FSItem.ItemType, path: String)] = []
        if attributes == nil {
            let parentPath = dir.path == "/" ? "/"
                : (dir.path as NSString).deletingLastPathComponent
            entries.append((".", .directory, dir.path))
            entries.append(("..", .directory, parentPath))
        }
        for e in collector.items {
            entries.append((e.name, e.isDir ? .directory : .file, dir.childPath(e.name)))
        }

        guard var index = Int(exactly: cookie.rawValue) else {
            throw FSError(.invalidDirectoryCookie)
        }
        while index < entries.count {
            let entry = entries[index]
            // FSKit drops entries packed without attributes when it asked for
            // them — fetch per entry (path-addressed engine, one stat each).
            var entryAttrs: FSItem.Attributes? = nil
            if attributes != nil {
                var st = nk_stat()
                let rc = engineQueue.sync { entry.path.withCString { nk_stat_path(vol, $0, &st) } }
                if rc == 0 {
                    entryAttrs = makeAttributes(path: entry.path, st: st,
                                                identifier: id(for: entry.path))
                }
            }
            let ok = packer.packEntry(name: FSFileName(string: entry.name),
                                      itemType: entry.type,
                                      itemID: id(for: entry.path),
                                      nextCookie: FSDirectoryCookie(rawValue: UInt64(index + 1)),
                                      attributes: entryAttrs)
            if !ok { break }
            index += 1
        }
        return FSDirectoryVerifier(rawValue: generation)
    }

    // MARK: create / remove / rename

    func createItem(named name: FSFileName,
                    type: FSItem.ItemType,
                    inDirectory directory: FSItem,
                    attributes newAttributes: FSItem.SetAttributesRequest) async throws -> (FSItem, FSFileName) {
        guard let dir = directory as? NTFSItem, let childName = name.string else { throw posix(EINVAL) }
        if readOnly { throw posix(EROFS) }
        let rc = engineQueue.sync {
            dir.path.withCString { dp in
                childName.withCString { np in
                    type == .directory ? nk_mkdir(vol, dp, np) : nk_create(vol, dp, np)
                }
            }
        }
        guard rc == 0 else { throw posix(EIO) }
        mutateNamespace {}
        let childPath = dir.childPath(childName)
        return (item(path: childPath, kind: type), name)
    }

    func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
        guard let item = item as? NTFSItem else { throw posix(EINVAL) }
        if readOnly { throw posix(EROFS) }
        let rc = engineQueue.sync { item.path.withCString { nk_delete(vol, $0) } }
        log.info("removeItem \(item.path, privacy: .public) rc=\(rc)")
        guard rc == 0 else { throw posix(EIO) }
        mutateNamespace {
            idByPath[item.path] = nil
            itemByPath[item.path] = nil
        }
    }

    func renameItem(_ item: FSItem,
                    inDirectory sourceDirectory: FSItem,
                    named sourceName: FSFileName,
                    to destinationName: FSFileName,
                    inDirectory destinationDirectory: FSItem,
                    overItem: FSItem?) async throws -> FSFileName {
        guard let item = item as? NTFSItem,
              let destDir = destinationDirectory as? NTFSItem,
              let newName = destinationName.string else { throw posix(EINVAL) }
        if readOnly { throw posix(EROFS) }

        // A directory must never move into itself or its own subtree — the
        // engine's link-then-delete would happily create a cycle.
        if destDir.path == item.path || destDir.path.hasPrefix(item.path + "/") {
            throw posix(EINVAL)
        }

        // Replace semantics: remove the target first if it exists — and evict
        // its cache entries (and any cached descendants), or the next lookup
        // of the destination path would resurrect the dead item object.
        if let overItem = overItem as? NTFSItem {
            let drc = engineQueue.sync { overItem.path.withCString { nk_delete(vol, $0) } }
            guard drc == 0 else { throw posix(EIO) }
            mutateNamespace {
                let overPrefix = overItem.path + "/"
                itemByPath[overItem.path] = nil
                idByPath[overItem.path] = nil
                for p in itemByPath.keys where p.hasPrefix(overPrefix) {
                    itemByPath[p] = nil
                }
                for p in idByPath.keys where p.hasPrefix(overPrefix) {
                    idByPath[p] = nil
                }
            }
        }
        let rc = engineQueue.sync {
            item.path.withCString { op in
                destDir.path.withCString { dp in
                    newName.withCString { np in nk_rename(vol, op, dp, np) }
                }
            }
        }
        guard rc == 0 else { throw posix(EIO) }

        // The kernel keeps using the SAME item object after rename (it may be
        // open) — rewrite its path in place and re-key the caches, including
        // every cached descendant when a directory moves. idByPath is walked
        // independently: enumeration seeds ids for paths with no live item.
        mutateNamespace {
            let oldPath = item.path
            let newPath = destDir.childPath(newName)
            let oldPrefix = oldPath + "/"
            itemByPath[oldPath] = nil
            item.path = newPath
            itemByPath[newPath] = item
            for p in itemByPath.keys.filter({ $0.hasPrefix(oldPrefix) }) {
                let np = newPath + "/" + p.dropFirst(oldPrefix.count)
                let child = itemByPath.removeValue(forKey: p)!
                child.path = np
                itemByPath[np] = child
            }
            let movedID = idByPath.removeValue(forKey: oldPath) ?? item.identifier
            idByPath[newPath] = movedID
            for p in idByPath.keys.filter({ $0.hasPrefix(oldPrefix) }) {
                let np = newPath + "/" + p.dropFirst(oldPrefix.count)
                idByPath[np] = idByPath.removeValue(forKey: p)
            }
        }
        return destinationName
    }

    func reclaimItem(_ item: FSItem) async throws {
        guard let item = item as? NTFSItem else { return }
        // Only evict if this object is still the cached one — a late reclaim
        // of a replaced item (rename-over) must not evict its successor.
        evictIfCurrent(item)
    }

    private func evictIfCurrent(_ item: NTFSItem) {
        stateLock.lock(); defer { stateLock.unlock() }
        if itemByPath[item.path] === item {
            itemByPath[item.path] = nil
        }
    }

    // MARK: read / write

    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
        guard let item = item as? NTFSItem else { throw posix(EINVAL) }
        let n = engineQueue.sync {
            buffer.withUnsafeMutableBytes { raw -> Int64 in
                item.path.withCString { path in
                    nk_read(vol, path, Int64(offset), Int64(min(length, raw.count)), raw.baseAddress)
                }
            }
        }
        guard n >= 0 else { throw posix(EIO) }
        return Int(n)
    }

    func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
        guard let item = item as? NTFSItem else { throw posix(EINVAL) }
        if readOnly { throw posix(EROFS) }
        let n = engineQueue.sync {
            contents.withUnsafeBytes { raw -> Int64 in
                item.path.withCString { path in
                    nk_write(vol, path, Int64(offset), Int64(raw.count), raw.baseAddress)
                }
            }
        }
        guard n >= 0 else { throw posix(EIO) }
        return Int(n)
    }

    // MARK: symlinks

    func readSymbolicLink(_ item: FSItem) async throws -> FSFileName {
        guard let item = item as? NTFSItem else { throw posix(EINVAL) }
        var buf = [CChar](repeating: 0, count: 4096)
        let rc = engineQueue.sync { item.path.withCString { nk_readlink(vol, $0, &buf, 4096) } }
        guard rc == 0 else { throw posix(EINVAL) }
        return FSFileName(string: String(cString: buf))
    }

    func createSymbolicLink(named name: FSFileName,
                            inDirectory directory: FSItem,
                            attributes: FSItem.SetAttributesRequest,
                            linkContents contents: FSFileName) async throws -> (FSItem, FSFileName) {
        guard let dir = directory as? NTFSItem,
              let linkName = name.string,
              let target = contents.string else { throw posix(EINVAL) }
        if readOnly { throw posix(EROFS) }
        let rc = engineQueue.sync {
            dir.path.withCString { dp in
                linkName.withCString { np in
                    target.withCString { tp in nk_create_symlink(vol, dp, np, tp) }
                }
            }
        }
        guard rc == 0 else { throw posix(EIO) }
        mutateNamespace {}
        let childPath = dir.childPath(linkName)
        return (item(path: childPath, kind: .symlink), name)
    }

    // MARK: not yet supported

    func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem) async throws -> FSFileName {
        throw posix(ENOTSUP)
    }
}

// MARK: - Volume rename

extension NTFSVolume: FSVolume.RenameOperations {

    func setVolumeName(_ name: FSFileName) async throws -> FSFileName {
        guard let label = name.string else { throw posix(EINVAL) }
        if readOnly { throw posix(EROFS) }
        let rc = engineQueue.sync { label.withCString { nk_set_label(vol, $0) } }
        guard rc == 0 else { throw posix(EIO) }
        self.name = name
        return name
    }
}

// MARK: - Extended attributes (stored as NTFS alternate data streams)
// Real xattrs on NTFS: no ._ AppleDouble litter, and they round-trip to
// Windows as named streams.

extension NTFSVolume: FSVolume.XattrOperations {

    func xattrs(of item: FSItem) async throws -> [FSFileName] {
        guard let item = item as? NTFSItem else { throw posix(EINVAL) }
        final class NameBox { var names: [String] = [] }
        let box = NameBox()
        let cb: nk_name_cb = { ctx, name in
            guard let ctx, let name else { return 0 }
            Unmanaged<NameBox>.fromOpaque(ctx).takeUnretainedValue()
                .names.append(String(cString: name))
            return 0
        }
        let rc = engineQueue.sync {
            item.path.withCString {
                nk_xattr_list(vol, $0, cb, Unmanaged.passUnretained(box).toOpaque())
            }
        }
        guard rc == 0 else { throw posix(EIO) }
        return box.names.map { FSFileName(string: $0) }
    }

    func xattr(named name: FSFileName, of item: FSItem) async throws -> Data {
        guard let item = item as? NTFSItem, let xname = name.string else {
            throw posix(EINVAL)
        }
        // Size query + read under ONE engine hold — a concurrent setXattr
        // between two holds could truncate the read.
        let result: Data? = engineQueue.sync {
            item.path.withCString { p -> Data? in
                xname.withCString { n -> Data? in
                    let size = nk_xattr_get(vol, p, n, nil, 0)
                    guard size >= 0 else { return nil }
                    // macOS caps xattrs at ~64 KB; a corrupt/huge ADS size must
                    // not drive a giant Data(count:) that kills the extension.
                    guard size <= 4 << 20 else { return nil }
                    if size == 0 { return Data() }
                    var data = Data(count: Int(size))
                    let got = data.withUnsafeMutableBytes {
                        nk_xattr_get(vol, p, n, $0.baseAddress, Int64($0.count))
                    }
                    guard got >= 0 else { return nil }
                    data.removeSubrange(Int(got)..<data.count)
                    return data
                }
            }
        }
        guard let result else { throw posix(ENOATTR) }
        return result
    }

    func setXattr(named name: FSFileName, to value: Data?, on item: FSItem,
                  policy: FSVolume.SetXattrPolicy) async throws {
        guard let item = item as? NTFSItem, let xname = name.string else {
            throw posix(EINVAL)
        }
        if readOnly { throw posix(EROFS) }

        // Existence check + mutation in ONE engine hold — otherwise a
        // concurrent upcall between the two could violate .mustCreate /
        // .mustReplace. `errno`-style POSIX result mapped after the hold.
        let rc: Int32 = value.withUnsafeBytesOrNil { raw in
            engineQueue.sync {
                item.path.withCString { p in
                    xname.withCString { n -> Int32 in
                        let present = nk_xattr_get(vol, p, n, nil, 0) >= 0
                        switch policy {
                        case .mustCreate where present: return EEXIST
                        case .mustReplace where !present: return ENOATTR
                        case .delete:
                            return nk_xattr_remove(vol, p, n) == 0 ? 0 : ENOATTR
                        default: break
                        }
                        guard let raw else {   // nil value = delete
                            return nk_xattr_remove(vol, p, n) == 0 ? 0 : ENOATTR
                        }
                        return nk_xattr_set(vol, p, n, raw.baseAddress,
                                            Int64(raw.count)) == 0 ? 0 : EIO
                    }
                }
            }
        }
        guard rc == 0 else { throw posix(rc) }
    }
}

// MARK: - Open/Close lifecycle
// The kernel defers parts of the unlink flow (open-unlink semantics) to
// volumes that receive open/close calls; without this conformance deletes on
// KOIO volumes never reach removeItem.

extension NTFSVolume: FSVolume.OpenCloseOperations {

    func openItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        // Path-addressed engine: nothing to hold open. But block write-opens
        // of files that must use byte-copy I/O (compressed/encrypted):
        // streaming writeback to an inhibited item on a KOIO volume wedged the
        // kernel in testing (state-U, no upcalls). Until a fix or a passing
        // test on this macOS build, refusing the open beats wedging the disk.
        guard modes.contains(.write), let item = item as? NTFSItem,
              item.kind == .file else { return }
        var st = nk_stat()
        let rc = engineQueue.sync { item.path.withCString { nk_stat_path(vol, $0, &st) } }
        if rc == 0 && st.koio_ok == 0 && st.is_symlink == 0 {
            throw posix(EROFS)
        }
    }

    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        // Nothing retained per open; engine flushes on every operation.
    }
}

// MARK: - Kernel-Offloaded I/O (Phase 2)
// Lesson learned: KOIO is all-or-nothing per volume. Advertising
// FSSupportsKernelOffloadedIO while inhibiting every item wedges kernel
// writeback on streaming writes (state-U, zero upcalls). With the engine on
// buffer-cache I/O and resident conversion in nk_blockmap, only
// compressed/encrypted files stay inhibited.
extension NTFSVolume: FSVolumeKernelOffloadedIOOperations {

    private final class ExtentBox {
        let packer: FSExtentPacker
        let resource: FSBlockDeviceResource
        var packedAll = true
        /// Physical byte ranges handed to the kernel for direct WRITE — these
        /// must be purged from the buffer cache afterwards (the engine's
        /// zero-fill primed the cache; the kernel then writes the sectors
        /// directly, so any cached copy goes stale).
        var writeRanges: [(phys: Int64, len: Int64)] = []
        init(packer: FSExtentPacker, resource: FSBlockDeviceResource) {
            self.packer = packer
            self.resource = resource
        }
    }

    func blockmapFile(_ file: FSItem, offset: off_t, length: Int,
                      flags: FSBlockmapFlags, operationID: FSOperationID,
                      packer: FSExtentPacker) async throws {
        guard let item = file as? NTFSItem else { throw posix(EINVAL) }
        let forWrite = flags.contains(.write)
        if forWrite && readOnly { throw posix(EROFS) }

        let box = ExtentBox(packer: packer, resource: resource)
        let cb: nk_extent_cb = { ctx, logical, physical, length in
            let box = Unmanaged<ExtentBox>.fromOpaque(ctx!).takeUnretainedValue()
            let ok = box.packer.packExtent(resource: box.resource,
                                           type: physical < 0 ? .zeroFill : .data,
                                           logicalOffset: off_t(logical),
                                           physicalOffset: off_t(physical < 0 ? 0 : physical),
                                           length: Int(length))
            if !ok { box.packedAll = false; return 1 }
            if physical >= 0 { box.writeRanges.append((physical, length)) }
            return 0
        }
        let rc = engineQueue.sync {
            item.path.withCString {
                nk_blockmap(vol, $0, Int64(offset), Int64(length),
                            forWrite ? 1 : 0, Int32(deviceBlockSize), cb,
                            Unmanaged.passUnretained(box).toOpaque())
            }
        }
        log.info("blockmap \(item.path, privacy: .public) off=\(offset) len=\(length) write=\(forWrite) rc=\(rc)")
        guard rc == 0 else { throw posix(rc == -2 ? ENOTSUP : EIO) }

        // The kernel is about to write these sectors directly; drop any copy
        // the engine left in the buffer cache so later cache reads can't see
        // stale data. A failed purge means possible silent corruption — fail
        // the whole blockmap rather than continue.
        if forWrite && !box.writeRanges.isEmpty {
            let bs = Int64(deviceBlockSize)
            let ranges = box.writeRanges.map { r -> FSMetadataRange in
                let start = (r.phys / bs) * bs
                let end = ((r.phys + r.len + bs - 1) / bs) * bs
                return FSMetadataRange(offset: off_t(start),
                                       segmentLength: UInt64(bs),
                                       segmentCount: UInt64((end - start) / bs))
            }
            do { try resource.metadataPurge(ranges) } catch {
                log.error("metadataPurge failed: \(error, privacy: .public)")
                throw posix(EIO)
            }
        }
    }

    func completeIO(for file: FSItem, offset: off_t, length: Int,
                    status: (any Error)?, flags: FSCompleteIOFlags,
                    operationID: FSOperationID) async throws {
        guard let item = file as? NTFSItem else { throw posix(EINVAL) }
        if flags.contains(.write) && status == nil {
            // Data landed on disk via the kernel: mark the range initialized
            // (blockmapFile allocated it solid, without writing) and stamp
            // mtime. Failing to record initialized_size would make the bytes
            // read back as zeros — that's data loss, so propagate.
            let rc = engineQueue.sync {
                item.path.withCString {
                    nk_complete_write(vol, $0, Int64(offset), Int64(length))
                }
            }
            guard rc == 0 else { throw posix(EIO) }
            _ = engineQueue.sync {
                item.path.withCString { nk_set_times(vol, $0, -1, Int64(time(nil)), -1) }
            }
        }
    }

    func createFile(name: FSFileName, in directory: FSItem,
                    attributes: FSItem.SetAttributesRequest,
                    packer: FSExtentPacker) async throws -> (FSItem, FSFileName) {
        // Extent packing here is an optional optimization — delegate to the
        // regular create path and let blockmapFile supply extents on demand.
        try await createItem(named: name, type: .file, inDirectory: directory,
                             attributes: attributes)
    }

    func lookupItem(name: FSFileName, in directory: FSItem,
                    packer: FSExtentPacker) async throws -> (FSItem, FSFileName) {
        try await lookupItem(named: name, inDirectory: directory)
    }
}

private extension Optional where Wrapped == Data {
    /// Run `body` with the bytes (or nil when self is nil) — lets the xattr
    /// set/delete path do everything inside one closure.
    func withUnsafeBytesOrNil<R>(_ body: (UnsafeRawBufferPointer?) -> R) -> R {
        switch self {
        case .some(let d): return d.withUnsafeBytes { body($0) }
        case .none: return body(nil)
        }
    }
}

/// Box that collects directory entries out of the C callback.
final class DirCollector {
    var items: [(name: String, isDir: Bool, size: Int64)] = []
}

private let nkPreadTrampoline: nk_pread_cb = { ctx, buf, count, offset in
    guard let ctx, let buf else { return -1 }
    let vol = Unmanaged<NTFSVolume>.fromOpaque(ctx).takeUnretainedValue()
    return vol.devicePread(buf, count, offset)
}

private let nkPwriteTrampoline: nk_pwrite_cb = { ctx, buf, count, offset in
    guard let ctx, let buf else { return -1 }
    let vol = Unmanaged<NTFSVolume>.fromOpaque(ctx).takeUnretainedValue()
    return vol.devicePwrite(buf, count, offset)
}

private let dirCollectCallback: nk_dirent_cb = { ctx, entryPtr in
    guard let ctx, let entryPtr else { return 0 }
    let collector = Unmanaged<DirCollector>.fromOpaque(ctx).takeUnretainedValue()
    let entry = entryPtr.pointee
    if let namePtr = entry.name {
        collector.items.append((String(cString: namePtr), entry.is_dir != 0, entry.size))
    }
    return 0
}
