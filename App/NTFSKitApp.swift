import SwiftUI
import AppKit
import ServiceManagement
import UserNotifications

@main
enum Entry {
    static func main() {
        // `NTFSKit.app/Contents/MacOS/NTFSKit list|eject|check` — the CLI
        // competitors charge for. Symlink the binary as `ntfskit` and go.
        let args = Array(CommandLine.arguments.dropFirst())
        if let cmd = args.first,
           ["list", "eject", "check", "version", "snapshot"].contains(cmd) {
            CLI.run(cmd, Array(args.dropFirst()))
            return
        }
        NTFSKitApp.main()
    }
}

enum CLI {
    static func run(_ cmd: String, _ args: [String]) {
        switch cmd {
        case "version":
            let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] ?? "?"
            print("ntfskit \(v)")
        case "list":
            let vols = scanNTFSVolumes()
            if vols.isEmpty { print("no NTFS volumes mounted") }
            for v in vols {
                let mode = v.readOnly ? "ro" : "rw"
                print("\(v.device)\t\(v.id)\t\(mode)\t\(v.free)/\(v.total) free")
            }
        case "eject":
            guard let target = args.first else { die("usage: ntfskit eject <mount-point|name>") }
            let vols = scanNTFSVolumes()
            guard let vol = vols.first(where: { $0.id == target || $0.name == target }) else {
                die("no mounted NTFS volume matches \(target)")
            }
            let ok = NSWorkspace.shared.unmountAndEjectDevice(atPath: vol.id)
            print(ok ? "ejected \(vol.name)" : "eject failed (busy?)")
            if !ok { exit(1) }
        case "check":
            guard let dev = args.first else { die("usage: ntfskit check /dev/diskNsM") }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
            p.arguments = ["repairVolume", dev]
            try? p.run()
            p.waitUntilExit()
            exit(p.terminationStatus)
        case "snapshot":
            // Offscreen UI render (no screen-recording permission needed) —
            // for docs/screenshots from headless/remote sessions.
            let dir = args.first ?? "/tmp"
            Task { @MainActor in
                let monitor = VolumeMonitor()
                monitor.volumes = [
                    NTFSVolumeInfo(id: "/Volumes/WORKDISK", name: "WORKDISK",
                                   device: "/dev/disk4s1",
                                   total: 512_000_000_000, free: 198_000_000_000,
                                   readOnly: false),
                    NTFSVolumeInfo(id: "/Volumes/WINDOWS", name: "WINDOWS",
                                   device: "/dev/disk5s2",
                                   total: 1_000_000_000_000, free: 310_000_000_000,
                                   readOnly: true),
                ]
                monitor.hibernatedIDs = ["/Volumes/WINDOWS"]
                @MainActor func save(_ view: some View, _ name: String) {
                    let renderer = ImageRenderer(content: view)
                    renderer.scale = 2
                    if let img = renderer.nsImage, let tiff = img.tiffRepresentation,
                       let rep = NSBitmapImageRep(data: tiff),
                       let png = rep.representation(using: .png, properties: [:]) {
                        try? png.write(to: URL(fileURLWithPath: "\(dir)/\(name).png"))
                        print("\(dir)/\(name).png")
                    }
                }
                save(ContentView().environmentObject(monitor).frame(width: 560), "ntfskit-main")
                save(SettingsView(), "ntfskit-settings")
                exit(0)
            }
            RunLoop.main.run()
        default:
            break
        }
    }

    private static func die(_ msg: String) -> Never {
        FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
        exit(2)
    }
}

struct NTFSKitApp: App {
    @StateObject private var monitor = VolumeMonitor()

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environmentObject(monitor)
                .environmentObject(LicenseManager.shared)
        }
        .windowResizability(.contentSize)

        Settings {
            SettingsView()
                .environmentObject(LicenseManager.shared)
        }

        // Competitors' hallmark feature: always-there menu bar access.
        MenuBarExtra {
            MenuBarContent()
                .environmentObject(monitor)
        } label: {
            Image(systemName: monitor.volumes.isEmpty
                  ? "externaldrive" : "externaldrive.fill.badge.checkmark")
        }
    }
}

// MARK: - Mounted-volume model

struct NTFSVolumeInfo: Identifiable, Equatable {
    let id: String          // mount point path
    let name: String
    let device: String      // /dev/diskNsM
    let total: Int64
    let free: Int64
    let readOnly: Bool

    var used: Int64 { max(0, total - free) }
    var usedFraction: Double { total > 0 ? Double(used) / Double(total) : 0 }
}

/// Scans the mount table for volumes served by our fs module.
func scanNTFSVolumes() -> [NTFSVolumeInfo] {
    var mounts: UnsafeMutablePointer<statfs>?
    let count = getmntinfo(&mounts, MNT_NOWAIT)
    guard count > 0, let mounts else { return [] }
    var found: [NTFSVolumeInfo] = []
    for i in 0..<Int(count) {
        var fs = mounts[i]
        let type = withUnsafeBytes(of: &fs.f_fstypename) {
            String(cString: $0.bindMemory(to: CChar.self).baseAddress!)
        }
        guard type == "ntfskit" else { continue }
        let path = withUnsafeBytes(of: &fs.f_mntonname) {
            String(cString: $0.bindMemory(to: CChar.self).baseAddress!)
        }
        let dev = withUnsafeBytes(of: &fs.f_mntfromname) {
            String(cString: $0.bindMemory(to: CChar.self).baseAddress!)
        }
        let bsize = Int64(fs.f_bsize)
        found.append(NTFSVolumeInfo(
            id: path,
            name: FileManager.default.displayName(atPath: path),
            device: dev,
            total: Int64(fs.f_blocks) * bsize,
            free: Int64(fs.f_bavail) * bsize,
            readOnly: fs.f_flags & UInt32(MNT_RDONLY) != 0))
    }
    return found
}

/// Watches the mount table for volumes served by our fs module.
@MainActor
final class VolumeMonitor: ObservableObject {
    @Published var volumes: [NTFSVolumeInfo] = []
    /// Mount paths of read-only volumes with a Windows hiberfil.sys —
    /// detected OFF the main thread (a stat on a wedged volume can hang).
    @Published var hibernatedIDs: Set<String> = []
    private var timer: Timer?
    /// Volumes we already applied the read-only policy to this session
    /// (guards against remount loops).
    private var policyApplied: Set<String> = []

    init() {
        refresh()
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didMountNotification,
                     NSWorkspace.didUnmountNotification,
                     NSWorkspace.didRenameVolumeNotification] {
            center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.refresh() }
            }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func refresh() {
        let found = scanNTFSVolumes()
        guard found != volumes else { return }
        notifyNewMounts(old: volumes, new: found)
        volumes = found
        // Volumes that vanished are eligible for policy enforcement again
        // on their next plug-in.
        policyApplied.formIntersection(Set(found.map(\.id)))
        enforceReadOnlyPolicy()
        detectHibernation(found)
    }

    private func detectHibernation(_ vols: [NTFSVolumeInfo]) {
        let candidates = vols.filter(\.readOnly).map(\.id)
        Task.detached(priority: .utility) { [weak self] in
            var hits: Set<String> = []
            for path in candidates
            where FileManager.default.fileExists(atPath: path + "/hiberfil.sys") {
                hits.insert(path)
            }
            let found = hits
            await MainActor.run { self?.hibernatedIDs = found }
        }
    }

    /// If the user asked for a volume to be read-only, remount it that way
    /// whenever it shows up read-write (competitor "RO toggle" parity).
    private func enforceReadOnlyPolicy() {
        guard LicenseManager.shared.isEntitled else { return }
        for vol in volumes where !vol.readOnly && !policyApplied.contains(vol.id) {
            policyApplied.insert(vol.id)
            Task {
                if await ReadOnlyPolicy.wantsReadOnly(vol) {
                    _ = await ReadOnlyPolicy.remount(vol, readOnly: true)
                }
            }
        }
    }

    private func notifyNewMounts(old: [NTFSVolumeInfo], new: [NTFSVolumeInfo]) {
        guard UserDefaults.standard.bool(forKey: "notifyOnMount") else { return }
        let oldIDs = Set(old.map(\.id))
        for vol in new where !oldIDs.contains(vol.id) {
            let content = UNMutableNotificationContent()
            content.title = "\(vol.name) mounted"
            content.body = "NTFS volume ready — read & write at full speed."
            content.sound = nil
            UNUserNotificationCenter.current().add(
                UNNotificationRequest(identifier: vol.id + UUID().uuidString,
                                      content: content, trigger: nil))
        }
    }
}

// MARK: - Per-volume read-only policy (persisted by volume UUID)

enum ReadOnlyPolicy {
    private static let key = "readOnlyVolumeUUIDs"

    static func volumeUUID(device: String) async -> String? {
        var out = ""
        let rc = await DiskTool.run(["info", "-plist", device]) { out += $0 }
        guard rc == 0, let data = out.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = plist as? [String: Any] else { return nil }
        return dict["VolumeUUID"] as? String
    }

    static func wantsReadOnly(_ vol: NTFSVolumeInfo) async -> Bool {
        guard let uuid = await volumeUUID(device: vol.device) else { return false }
        let set = UserDefaults.standard.stringArray(forKey: key) ?? []
        return set.contains(uuid)
    }

    static func setWantsReadOnly(_ want: Bool, for vol: NTFSVolumeInfo) async {
        guard let uuid = await volumeUUID(device: vol.device) else { return }
        var set = Set(UserDefaults.standard.stringArray(forKey: key) ?? [])
        if want { set.insert(uuid) } else { set.remove(uuid) }
        UserDefaults.standard.set(Array(set), forKey: key)
    }

    /// Unmount + remount through DiskArbitration in the requested mode.
    /// If the target mode fails, remounts the old way — never leave the
    /// user's disk unmounted.
    static func remount(_ vol: NTFSVolumeInfo, readOnly: Bool) async -> Bool {
        var log = ""
        guard await DiskTool.run(["unmount", vol.id], onOutput: { log += $0 }) == 0
        else { return false }
        let args = readOnly ? ["mount", "readOnly", vol.device]
                            : ["mount", vol.device]
        if await DiskTool.run(args, onOutput: { log += $0 }) == 0 { return true }
        _ = await DiskTool.run(["mount", vol.device], onOutput: { log += $0 })
        return false
    }
}

// MARK: - diskutil runner (First Aid / Format / Eject)

enum DiskTool {
    /// Runs diskutil with the given arguments, streaming combined output.
    static func run(_ args: [String],
                    onOutput: @escaping @Sendable (String) -> Void) async -> Int32 {
        await withCheckedContinuation { cont in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
            p.arguments = args
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe
            pipe.fileHandleForReading.readabilityHandler = { h in
                let d = h.availableData
                if !d.isEmpty, let s = String(data: d, encoding: .utf8) {
                    onOutput(s)
                }
            }
            p.terminationHandler = { proc in
                // Drain what's left before tearing down — the readability
                // handler can miss the final chunk (plist output truncation).
                pipe.fileHandleForReading.readabilityHandler = nil
                let rest = pipe.fileHandleForReading.readDataToEndOfFile()
                if !rest.isEmpty, let s = String(data: rest, encoding: .utf8) {
                    onOutput(s)
                }
                cont.resume(returning: proc.terminationStatus)
            }
            do { try p.run() } catch {
                onOutput("failed to launch diskutil: \(error.localizedDescription)\n")
                cont.resume(returning: -1)
            }
        }
    }
}

// MARK: - Root view

struct ContentView: View {
    @EnvironmentObject private var monitor: VolumeMonitor

    var body: some View {
        ZStack {
            BackgroundGradient()
            VStack(spacing: 20) {
                HeroHeader()
                if monitor.volumes.isEmpty {
                    SetupCard()
                } else {
                    VolumeList(volumes: monitor.volumes)
                }
                StepsCard(active: !monitor.volumes.isEmpty)
                FooterBar()
            }
            .padding(28)
        }
        .frame(width: 560)
        .fixedSize(horizontal: false, vertical: true)
    }
}

// MARK: - Pieces

private struct BackgroundGradient: View {
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        LinearGradient(
            colors: scheme == .dark
                ? [Color(red: 0.09, green: 0.11, blue: 0.16), Color(red: 0.05, green: 0.06, blue: 0.09)]
                : [Color(red: 0.94, green: 0.96, blue: 1.0), Color(red: 0.88, green: 0.91, blue: 0.97)],
            startPoint: .topLeading, endPoint: .bottomTrailing)
            .ignoresSafeArea()
    }
}

private struct HeroHeader: View {
    var body: some View {
        VStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(LinearGradient(colors: [.teal, .blue],
                                         startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 88, height: 88)
                    .shadow(color: .blue.opacity(0.35), radius: 14, y: 6)
                Image(systemName: "externaldrive.fill")
                    .font(.system(size: 42, weight: .medium))
                    .foregroundStyle(.white)
                Image(systemName: "bolt.fill")
                    .font(.system(size: 17, weight: .bold))
                    .foregroundStyle(.yellow)
                    .offset(x: 26, y: -26)
            }
            Text("NTFSKit")
                .font(.system(size: 34, weight: .bold, design: .rounded))
            Text("NTFS read & write for macOS — no kext, no compromise.")
                .font(.title3)
                .foregroundStyle(.secondary)
            HStack(spacing: 6) {
                Badge(text: "FSKit native", icon: "checkmark.seal.fill", tint: .green)
                Badge(text: "Kernel-offloaded I/O", icon: "bolt.fill", tint: .orange)
                Badge(text: "Open source", icon: "chevron.left.forwardslash.chevron.right", tint: .blue)
            }
        }
    }
}

struct Badge: View {
    let text: String, icon: String, tint: Color
    var body: some View {
        // LocalizedStringKey: Label(String) would bypass Localizable.strings.
        Label(LocalizedStringKey(text), systemImage: icon)
            .fixedSize()
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(tint.opacity(0.14), in: Capsule())
            .foregroundStyle(tint)
    }
}

private struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background.opacity(0.6), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(.separator.opacity(0.5), lineWidth: 1))
    }
}

private struct SetupCard: View {
    var body: some View {
        Card {
            Label("No NTFS volume mounted", systemImage: "externaldrive.badge.questionmark")
                .font(.headline)
            Text("Plug in an NTFS disk and it mounts automatically. First time here? Enable the extension once:")
                .foregroundStyle(.secondary)
            Button {
                let url = URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences")!
                NSWorkspace.shared.open(url)
            } label: {
                Label("Open File System Extensions…", systemImage: "gearshape")
            }
            .buttonStyle(.borderedProminent)
            .tint(.blue)
        }
    }
}

// MARK: - Volume list + maintenance sheets

private struct VolumeList: View {
    let volumes: [NTFSVolumeInfo]
    var body: some View {
        Card {
            Label("Mounted NTFS volumes", systemImage: "externaldrive.connected.to.line.below.fill")
                .font(.headline)
            ForEach(volumes) { vol in
                VolumeRow(volume: vol)
                if vol != volumes.last { Divider() }
            }
        }
    }
}

private struct VolumeRow: View {
    let volume: NTFSVolumeInfo
    @EnvironmentObject private var monitor: VolumeMonitor
    @EnvironmentObject private var license: LicenseManager
    @State private var ejectFailed = false
    @State private var maintenance: MaintenanceKind?
    @State private var busy = false
    @State private var showUnlock = false

    private static let fmt: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f
    }()

    /// Windows Fast Startup / hibernation leaves hiberfil.sys — the #1 cause
    /// of "why is my disk read-only" confusion, which users blame on drivers.
    /// Detected asynchronously by VolumeMonitor (never stat a volume from the
    /// view body — a wedged disk would hang the UI).
    private var hibernated: Bool {
        monitor.hibernatedIDs.contains(volume.id)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
        HStack(spacing: 14) {
            Image(systemName: "internaldrive.fill")
                .font(.system(size: 26))
                .foregroundStyle(LinearGradient(colors: [.teal, .blue],
                                                startPoint: .top, endPoint: .bottom))
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(volume.name).font(.body.weight(.semibold))
                    if volume.readOnly {
                        Badge(text: "read-only", icon: "lock.fill", tint: .orange)
                    }
                }
                Text("\(volume.device)  ·  \(Self.fmt.string(fromByteCount: volume.free)) free of \(Self.fmt.string(fromByteCount: volume.total))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                ProgressView(value: volume.usedFraction)
                    .tint(volume.usedFraction > 0.9 ? .red : .blue)
                    .controlSize(.small)
            }
            Spacer()
            Button {
                guard license.isEntitled else { showUnlock = true; return }
                busy = true
                let vol = volume
                let makeRO = !vol.readOnly
                Task {
                    await ReadOnlyPolicy.setWantsReadOnly(makeRO, for: vol)
                    _ = await ReadOnlyPolicy.remount(vol, readOnly: makeRO)
                    await MainActor.run { busy = false }
                }
            } label: {
                Image(systemName: volume.readOnly ? "lock.open" : "lock")
            }
            .buttonStyle(.bordered)
            .disabled(busy || hibernated)
            .overlay(alignment: .topTrailing) {
                if !license.isPro { ProChip().offset(x: 6, y: -6) }
            }
            .help(volume.readOnly ? "Remount read-write" : "Remount read-only")
            Button {
                NSWorkspace.shared.open(URL(fileURLWithPath: volume.id))
            } label: {
                Image(systemName: "folder")
            }
            .buttonStyle(.bordered)
            .help("Show in Finder")
            Menu {
                Button {
                    if license.isEntitled { maintenance = .firstAid } else { showUnlock = true }
                } label: {
                    Label("First Aid…", systemImage: "stethoscope")
                }
                Button {
                    if license.isEntitled { maintenance = .format } else { showUnlock = true }
                } label: {
                    Label("Erase (Format NTFS)…", systemImage: "trash")
                }
            } label: {
                Image(systemName: "wrench.and.screwdriver")
            }
            .menuStyle(.borderlessButton)
            .frame(width: 40)
            .help("Maintenance")
            Button {
                ejectFailed = !NSWorkspace.shared.unmountAndEjectDevice(atPath: volume.id)
            } label: {
                Image(systemName: "eject.fill")
            }
            .buttonStyle(.bordered)
            .help("Eject \(volume.name)")
        }
        if hibernated {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "zzz")
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Windows is hibernating on this disk")
                        .font(.caption.weight(.semibold))
                    Text("Mounted read-only to protect your files. On Windows: shut down fully (not Fast Startup) — Shift-click Shut Down, or disable Fast Startup in power settings — then reconnect.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(10)
            .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
        }
        }
        .alert("Couldn't eject — the volume is busy.", isPresented: $ejectFailed) {
            Button("OK", role: .cancel) {}
        }
        .sheet(item: $maintenance) { kind in
            MaintenanceSheet(volume: volume, kind: kind)
        }
        .sheet(isPresented: $showUnlock) {
            UnlockProSheet().environmentObject(license)
        }
    }
}

enum MaintenanceKind: String, Identifiable {
    case firstAid, format
    var id: String { rawValue }
}

/// Runs diskutil verify/repair/erase against a volume with live output —
/// the same First Aid / Erase experience as Disk Utility, in-app.
private struct MaintenanceSheet: View {
    let volume: NTFSVolumeInfo
    let kind: MaintenanceKind
    @Environment(\.dismiss) private var dismiss

    @State private var output = ""
    @State private var running = false
    @State private var exitCode: Int32?
    @State private var confirmText = ""
    @State private var newName = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(kind == .firstAid ? "First Aid — \(volume.name)"
                                    : "Erase \(volume.name) as NTFS",
                  systemImage: kind == .firstAid ? "stethoscope" : "trash")
                .font(.title3.weight(.semibold))

            if kind == .format {
                Text("This erases every file on \(volume.device). This cannot be undone.")
                    .foregroundStyle(.red)
                TextField("New volume name", text: $newName)
                    .textFieldStyle(.roundedBorder)
                TextField("Type \(volume.name) to confirm", text: $confirmText)
                    .textFieldStyle(.roundedBorder)
            } else {
                Text("Checks the NTFS structures on \(volume.device) and repairs what it can.")
                    .foregroundStyle(.secondary)
            }

            if !output.isEmpty || running {
                ScrollView {
                    Text(output.isEmpty ? "…" : output)
                        .font(.caption.monospaced())
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(height: 160)
                .padding(8)
                .background(.black.opacity(0.85), in: RoundedRectangle(cornerRadius: 8))
                .foregroundStyle(.green)
            }

            HStack {
                if let code = exitCode {
                    Label {
                        code == 0 ? Text("Done") : Text("Failed (\(Int(code)))")
                    } icon: {
                        Image(systemName: code == 0 ? "checkmark.circle.fill" : "xmark.octagon.fill")
                    }
                    .foregroundStyle(code == 0 ? .green : .red)
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(kind == .firstAid ? "Run First Aid" : "Erase") {
                    Task { await run() }
                }
                .buttonStyle(.borderedProminent)
                .tint(kind == .format ? .red : .blue)
                .disabled(running ||
                          (kind == .format && (confirmText != volume.name || newName.isEmpty)))
            }
        }
        .padding(22)
        .frame(width: 460)
    }

    private func run() async {
        running = true
        exitCode = nil
        output = ""
        let args = kind == .firstAid
            ? ["repairVolume", volume.device]
            : ["eraseVolume", "NTFSKit", newName, volume.device]
        let code = await DiskTool.run(args) { chunk in
            Task { @MainActor in output += chunk }
        }
        await MainActor.run {
            exitCode = code
            running = false
            if kind == .format && code != 0 {
                output += "\nIf the volume was busy, eject other apps' windows "
                    + "using it and try again.\n"
            }
        }
    }
}

private struct StepsCard: View {
    let active: Bool
    var body: some View {
        Card {
            Label("How it works", systemImage: "sparkles")
                .font(.headline)
            HStack(alignment: .top, spacing: 0) {
                Step(number: 1, icon: "gearshape.fill", title: "Enable once",
                     detail: "File System Extensions → NTFSKit")
                Step(number: 2, icon: "cable.connector", title: "Plug in",
                     detail: "Any NTFS disk auto-mounts")
                Step(number: 3, icon: "bolt.fill", title: "Full speed",
                     detail: active ? "Reading & writing now" : "Read & write, kernel-fast")
            }
        }
    }
}

private struct Step: View {
    let number: Int, icon: String, title: String, detail: String
    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(.blue)
                .frame(height: 24)
            // Text(String) skips localization — go through the key type.
            (Text(verbatim: "\(number). ") + Text(LocalizedStringKey(title)))
                .font(.callout.weight(.semibold))
            Text(LocalizedStringKey(detail))
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
    }
}

private struct FooterBar: View {
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        HStack {
            Text("GPL-2.0 · powered by libntfs-3g")
            Spacer()
            Button("Settings…") { openSettings() }
                .buttonStyle(.link)
                .font(.caption)
            Spacer()
            Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"].flatMap { "v\($0)" } ?? "")
        }
        .font(.caption)
        .foregroundStyle(.tertiary)
    }
}

// MARK: - Settings

struct SettingsView: View {
    @EnvironmentObject private var license: LicenseManager
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var showUnlock = false
    @AppStorage("notifyOnMount") private var notifyOnMount = false

    var body: some View {
        Form {
            Section("NTFSKit Pro") {
                if license.isPro {
                    LabeledContent("License") {
                        Label(license.licensedEmail ?? "", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                    }
                } else {
                    LabeledContent("License") {
                        Text(license.trialDaysLeft > 0
                             ? "Trial — เหลือ \(license.trialDaysLeft) วัน"
                             : "Trial หมดอายุ")
                    }
                    Button("Unlock Pro…") { showUnlock = true }
                }
            }
            Section("General") {
                Toggle("Start NTFSKit at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, on in
                        do {
                            if on { try SMAppService.mainApp.register() }
                            else { try SMAppService.mainApp.unregister() }
                        } catch {
                            launchAtLogin = SMAppService.mainApp.status == .enabled
                        }
                    }
                Toggle("Notify when an NTFS volume mounts", isOn: $notifyOnMount)
                    .disabled(!license.isEntitled)
                    .onChange(of: notifyOnMount) { _, on in
                        guard on else { return }
                        guard license.isEntitled else { notifyOnMount = false; return }
                        UNUserNotificationCenter.current()
                            .requestAuthorization(options: [.alert]) { granted, _ in
                                if !granted {
                                    DispatchQueue.main.async { notifyOnMount = false }
                                }
                            }
                    }
            }
            Section("Mounting") {
                LabeledContent("Auto-mount") {
                    Text("Managed by macOS — plug in and go")
                }
                if !FileManager.default.fileExists(atPath: "/Library/Filesystems/ntfskit.fs") {
                    LabeledContent("Format support") {
                        Button("Install…") { installFormatSupport() }
                    }
                } else {
                    LabeledContent("Format support") {
                        Label("Installed — Disk Utility can erase to NTFS", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                }
                LabeledContent("Read-only per volume") {
                    Text("Use the lock button next to a mounted volume. NTFSKit remembers each disk's setting.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 420)
        .fixedSize(horizontal: false, vertical: true)
        .sheet(isPresented: $showUnlock) {
            UnlockProSheet().environmentObject(license)
        }
    }

    /// Copies the bundled ntfskit.fs into /Library/Filesystems (admin prompt)
    /// so diskutil/Disk Utility can format volumes as NTFS.
    private func installFormatSupport() {
        guard let src = Bundle.main.url(forResource: "ntfskit", withExtension: "fs")
        else { return }
        let script = "rm -rf /Library/Filesystems/ntfskit.fs && " +
            "cp -R '\(src.path)' /Library/Filesystems/ && " +
            "chown -R root:wheel /Library/Filesystems/ntfskit.fs && " +
            "chmod -R 755 /Library/Filesystems/ntfskit.fs"
        let osa = "do shell script \"\(script.replacingOccurrences(of: "\"", with: "\\\""))\" " +
            "with administrator privileges with prompt \"NTFSKit: install Disk Utility format support\""
        DispatchQueue.global().async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = ["-e", osa]
            try? p.run()
            p.waitUntilExit()
        }
    }
}

// MARK: - Menu bar

private struct MenuBarContent: View {
    @EnvironmentObject private var monitor: VolumeMonitor
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    private static let fmt: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f
    }()

    var body: some View {
        if monitor.volumes.isEmpty {
            Text("No NTFS volume mounted")
        } else {
            ForEach(monitor.volumes) { vol in
                Menu {
                    Button("Open in Finder") {
                        NSWorkspace.shared.open(URL(fileURLWithPath: vol.id))
                    }
                    Button("Eject") {
                        _ = NSWorkspace.shared.unmountAndEjectDevice(atPath: vol.id)
                    }
                } label: {
                    Text("\(vol.name) — \(Self.fmt.string(fromByteCount: vol.free)) free")
                }
            }
        }
        Divider()
        Button("Open NTFSKit…") {
            NSApp.activate(ignoringOtherApps: true)
            openWindow(id: "main")
        }
        Button("Settings…") { openSettings() }
        Divider()
        Button("Quit NTFSKit") { NSApp.terminate(nil) }
    }
}
