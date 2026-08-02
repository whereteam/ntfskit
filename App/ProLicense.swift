import Foundation
import CryptoKit
import SwiftUI

/// NTFSKit Pro entitlement: offline ed25519-signed license keys + 14-day
/// full-feature trial. The driver itself is free — Pro gates convenience
/// features only (RO policy, First Aid/Erase UI, notifications).
@MainActor
final class LicenseManager: ObservableObject {
    static let shared = LicenseManager()

    /// ed25519 public key — the matching private key lives offline.
    private static let publicKeyB64 = "lsSYLY0eTQULKisISpWgrVIoY61h9AOrd24aeT+P0Ic="
    private static let trialDays = 14

    @AppStorage("proLicenseKey") private var storedKey = ""
    @Published private(set) var licensedEmail: String?

    struct Payload: Codable {
        let e: String   // email
        let p: String   // product
        let d: String   // issue date
    }

    private init() {
        licensedEmail = Self.verify(storedKey)?.e
        if UserDefaults.standard.object(forKey: "firstLaunch") == nil {
            UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: "firstLaunch")
        }
    }

    var isPro: Bool { licensedEmail != nil }

    var trialDaysLeft: Int {
        let first = UserDefaults.standard.double(forKey: "firstLaunch")
        let used = Int(Date().timeIntervalSince1970 - first) / 86400
        return max(0, Self.trialDays - used)
    }

    /// Pro OR still in trial → features available.
    var isEntitled: Bool { isPro || trialDaysLeft > 0 }

    /// Try to activate a key. Returns false when invalid.
    func activate(_ key: String) -> Bool {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let payload = Self.verify(trimmed) else { return false }
        storedKey = trimmed
        licensedEmail = payload.e
        return true
    }

    static func verify(_ key: String) -> Payload? {
        let parts = key.split(separator: ".")
        guard parts.count == 3, parts[0] == "NTFSKITPRO",
              let payloadData = Data(base64Encoded: String(parts[1])),
              let sig = Data(base64Encoded: String(parts[2])),
              let pub = Data(base64Encoded: publicKeyB64),
              let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pub),
              pubKey.isValidSignature(sig, for: payloadData),
              let payload = try? JSONDecoder().decode(Payload.self, from: payloadData),
              payload.p == "pro" else { return nil }
        return payload
    }
}

// MARK: - Unlock UI

struct UnlockProSheet: View {
    @EnvironmentObject private var license: LicenseManager
    @Environment(\.dismiss) private var dismiss
    @State private var keyInput = ""
    @State private var failed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("NTFSKit Pro", systemImage: "bolt.badge.checkmark.fill")
                .font(.title3.weight(.semibold))
            Text("Driver ฟรีตลอดไป — Pro ปลดล็อกเครื่องมือ: read-only ต่อดิสก์, First Aid, Erase, การแจ้งเตือน")
                .foregroundStyle(.secondary)
            if license.trialDaysLeft > 0 && !license.isPro {
                Label("ทดลองใช้ครบทุกฟีเจอร์ได้อีก \(license.trialDaysLeft) วัน",
                      systemImage: "clock")
                    .foregroundStyle(.blue)
            }
            TextField("วาง license key (NTFSKITPRO.…)", text: $keyInput)
                .textFieldStyle(.roundedBorder)
                .font(.caption.monospaced())
            if failed {
                Label("Key ไม่ถูกต้อง", systemImage: "xmark.octagon.fill")
                    .foregroundStyle(.red)
                    .font(.caption)
            }
            HStack {
                Link("ซื้อ License…",
                     destination: URL(string: "https://ntfskit.whereteam.dev/buy")!)
                Spacer()
                Button("ปิด") { dismiss() }
                Button("Activate") {
                    failed = !license.activate(keyInput)
                    if !failed { dismiss() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(keyInput.isEmpty)
            }
        }
        .padding(22)
        .frame(width: 440)
    }
}

/// Small "PRO" chip for gated controls.
struct ProChip: View {
    var body: some View {
        Text("PRO")
            .font(.system(size: 9, weight: .bold))
            .padding(.horizontal, 4).padding(.vertical, 1)
            .background(.orange.opacity(0.2), in: Capsule())
            .foregroundStyle(.orange)
    }
}
