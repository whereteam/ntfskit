// SPDX-License-Identifier: GPL-2.0-or-later
// Minimal open-source host app for the NTFSKit FSKit module.
// (The full-featured NTFSKit Pro app lives in a separate repository.)
import SwiftUI
import AppKit

@main
struct NTFSKitApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
    }
}

struct VolumeInfo: Identifiable {
    let id: String, device: String, readOnly: Bool
}

func scanVolumes() -> [VolumeInfo] {
    var mounts: UnsafeMutablePointer<statfs>?
    let count = getmntinfo(&mounts, MNT_NOWAIT)
    guard count > 0, let mounts else { return [] }
    return (0..<Int(count)).compactMap { i in
        var fs = mounts[i]
        let type = withUnsafeBytes(of: &fs.f_fstypename) {
            String(cString: $0.bindMemory(to: CChar.self).baseAddress!)
        }
        guard type == "ntfskit" else { return nil }
        let path = withUnsafeBytes(of: &fs.f_mntonname) {
            String(cString: $0.bindMemory(to: CChar.self).baseAddress!)
        }
        let dev = withUnsafeBytes(of: &fs.f_mntfromname) {
            String(cString: $0.bindMemory(to: CChar.self).baseAddress!)
        }
        return VolumeInfo(id: path, device: dev,
                          readOnly: fs.f_flags & UInt32(MNT_RDONLY) != 0)
    }
}

struct ContentView: View {
    @State private var volumes = scanVolumes()
    private let timer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "externaldrive.fill.badge.checkmark")
                .font(.system(size: 44))
                .foregroundStyle(.blue)
            Text("NTFSKit").font(.largeTitle.bold())
            Text("Open-source NTFS read/write for macOS — FSKit native, no kext.")
                .foregroundStyle(.secondary)

            if volumes.isEmpty {
                Text("Plug in an NTFS disk — it mounts automatically once the extension is enabled.")
                    .font(.callout)
                Button("Open File System Extensions…") {
                    NSWorkspace.shared.open(
                        URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences")!)
                }
                .buttonStyle(.borderedProminent)
            } else {
                ForEach(volumes) { vol in
                    HStack {
                        Image(systemName: "internaldrive.fill").foregroundStyle(.blue)
                        Text(vol.id)
                        if vol.readOnly { Text("read-only").foregroundStyle(.orange) }
                        Spacer()
                        Button("Eject") {
                            _ = NSWorkspace.shared.unmountAndEjectDevice(atPath: vol.id)
                        }
                    }
                    .padding(8)
                    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                }
            }
            Text("GPL-2.0 · powered by libntfs-3g")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(28)
        .frame(width: 480)
        .onReceive(timer) { _ in volumes = scanVolumes() }
    }
}
