import FSKit

/// A file or directory in the NTFS volume, identified by its POSIX path.
/// The path is the only state needed to address the item through libntfs-3g.
final class NTFSItem: FSItem {
    // "/" for root; rewritten in-place on rename (FSKit tracks by object
    // identity — the same instance must follow the file to its new name).
    // Lock-guarded: I/O upcalls read the path concurrently with rename.
    private let pathLock = NSLock()
    private var _path: String
    var path: String {
        get { pathLock.lock(); defer { pathLock.unlock() }; return _path }
        set { pathLock.lock(); defer { pathLock.unlock() }; _path = newValue }
    }
    let kind: FSItem.ItemType
    let identifier: FSItem.Identifier

    init(path: String, kind: FSItem.ItemType, identifier: FSItem.Identifier) {
        self._path = path
        self.kind = kind
        self.identifier = identifier
        super.init()
    }

    func childPath(_ name: String) -> String {
        path == "/" ? "/\(name)" : "\(path)/\(name)"
    }
}
