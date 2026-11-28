import Foundation
import ServiceManagement

/// Open at login: on by default, and an organisation can set it.
///
/// An MDM profile for the domain `com.coriqo.shield.app` with the key
/// `OpenAtLogin` (true/false) is a managed preference: it wins, and the
/// switch is shown locked. Without one, the app turns itself on at first
/// launch and the person can change it.
@MainActor
final class LoginItem: ObservableObject {
    static let key = "OpenAtLogin"
    private let defaults = UserDefaults.standard

    @Published private(set) var enabled = SMAppService.mainApp.status == .enabled
    var managed: Bool { defaults.objectIsForced(forKey: Self.key) }

    init() { refresh() }

    /// Re-read the system and the managed preference: run at launch and each
    /// time the menu opens, so a profile pushed while running, or a change in
    /// System Settings, shows up.
    func refresh() {
        if managed {
            apply(defaults.bool(forKey: Self.key))
        } else if !defaults.bool(forKey: "OpenAtLoginDecided") {
            // The default is "on" until it has actually taken effect once;
            // a failed or not-yet-approved registration is tried again.
            apply(true)
            if SMAppService.mainApp.status == .enabled { defaults.set(true, forKey: "OpenAtLoginDecided") }
        }
        enabled = SMAppService.mainApp.status == .enabled
    }

    func set(_ on: Bool) {
        guard !managed else { return }
        defaults.set(true, forKey: "OpenAtLoginDecided")   // the person chose
        apply(on)
    }

    private func apply(_ on: Bool) {
        let svc = SMAppService.mainApp
        do {
            if on, svc.status != .enabled { try svc.register() }
            if !on, svc.status == .enabled { try svc.unregister() }
        } catch {
            NSLog("Coriqo Shield: open at login: \(error.localizedDescription)")
        }
        enabled = svc.status == .enabled
    }
}
