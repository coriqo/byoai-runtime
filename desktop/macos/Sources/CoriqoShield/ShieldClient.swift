import AppKit
import Foundation

/// Reads the local Shield (byoai-shield) API. GET only: the app never changes
/// settings itself; that happens in the Shield window, which Shield already guards.
struct FeedItem: Decodable, Identifiable {
    let id: String
    let surface: String?
    let verb: String?
    let ts: String?
    let date: String?
    let verdict: String?
    let tier: String?
}

struct Feed: Decodable {
    /// Today's figures (summary_since=<today>), over every row Shield holds.
    struct Summary: Decodable { let checked: Int; let flagged: Int; let high_risk: Int }
    let summary: Summary
    let items: [FeedItem]
}

struct Verify: Decodable {
    let tamper_evident: Bool?
}

struct CoriqoStatus: Decodable {
    struct Sync: Decodable {
        let level: String?
        let pending: Int?
        let last_sent_at: Double?
        let next_attempt_at: Double?
        let failures: Int?
        let last_error: String?
    }
    let connected: Bool?
    let has_new: Bool?
    let last_sent_at: Double?
    let next_attempt_at: Double?
    let every_hours: Double?
    let sync: Sync?
    let tenant: String?
    let base_url: String?
    let last_error: String?
    let needs_attention: Bool?
}

enum ShieldState: Equatable {
    case starting, protecting, attention(String), stopped
}

@MainActor
final class ShieldModel: ObservableObject {
    /// The port Shield listens on. An app opened from Finder or at login gets
    /// no shell environment, so the login item's own --port is read first.
    static let port: Int = {
        let valid = { (p: Int?) -> Int? in p.flatMap { (1...65535).contains($0) ? $0 : nil } }
        let plist = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.coriqo.shield.plist")
        if let data = try? Data(contentsOf: plist),
           let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            if let args = dict["ProgramArguments"] as? [String], let i = args.firstIndex(of: "--port"),
               i + 1 < args.count, let p = valid(Int(args[i + 1])) { return p }
            if let env = dict["EnvironmentVariables"] as? [String: String],
               let p = valid(env["BYOAI_SHIELD_PORT"].flatMap(Int.init)) { return p }
        }
        if let p = valid(ProcessInfo.processInfo.environment["BYOAI_SHIELD_PORT"].flatMap(Int.init)) { return p }
        return 17831
    }()
    static let base = URL(string: "http://127.0.0.1:\(port)")!

    @Published var state: ShieldState = .starting {
        didSet {
            // A "!" on the Dock icon (seen while the window is open) whenever something is wrong.
            switch state {
            case .attention, .stopped: NSApp?.dockTile.badgeLabel = "!"
            default: NSApp?.dockTile.badgeLabel = nil
            }
        }
    }
    @Published var feed: Feed?
    @Published var coriqo: CoriqoStatus?
    @Published var updated: Date?

    private var timer: Timer?

    init() {
        Task { await refresh() }
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            Task { await self?.refresh() }
        }
    }

    func refresh() async {
        let today = Self.dayFormat.string(from: Date())
        async let fReq: Feed = get("/api/feed?limit=5&summary_since=\(today)")
        async let vReq: Verify = get("/api/verify")
        async let cReq: CoriqoStatus = get("/api/coriqo")
        do {
            let f = try await fReq
            let v = try? await vReq
            let c = try? await cReq
            feed = f; coriqo = c; updated = Date()
            if v?.tamper_evident == false {
                state = .attention("The record on this Mac was changed outside Shield. Open Shield to see what changed.")
            } else if c?.needs_attention == true {
                state = .attention(c?.last_error ?? "Coriqo needs attention.")
            } else {
                state = .protecting
            }
        } catch {
            _ = try? await vReq; _ = try? await cReq
            feed = nil; coriqo = nil
            // Only "nothing is listening" means stopped. A slow or erroring
            // Shield is still running and must not be offered a restart.
            let code = (error as? URLError)?.code
            state = (code == .cannotConnectToHost || code == .cannotFindHost)
                ? .stopped
                : .attention("Shield is running but slow to answer. This usually clears on its own.")
        }
    }

    private static let dayFormat: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    /// Start Shield's login item (com.coriqo.shield) if it is installed. No -k:
    /// a Shield that is already running is left alone.
    func startShield() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["kickstart", "gui/\(getuid())/com.coriqo.shield"]
        try? p.run()
        state = .starting
        Task { try? await Task.sleep(for: .seconds(3)); await refresh() }
    }

    private func get<T: Decodable>(_ path: String) async throws -> T {
        var req = URLRequest(url: URL(string: path, relativeTo: Self.base)!)
        req.timeoutInterval = 3
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
        return try JSONDecoder().decode(T.self, from: data)
    }
}
