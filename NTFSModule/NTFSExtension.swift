import FSKit
import ExtensionFoundation

/// FSKit module entry point — FSKit instantiates the file system in-process.
@main
struct NTFSKitExtension: UnaryFileSystemExtension {
    let fileSystem = NTFSFileSystem()
}
