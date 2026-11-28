import AppKit
import SwiftUI

@main
struct CoriqoShieldApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = ShieldModel()

    var body: some Scene {
        MenuBarExtra {
            MenuView(model: model)
        } label: {
            Image(systemName: model.menuSymbol)
                .accessibilityLabel("Coriqo Shield")
        }
        .menuBarExtraStyle(.window)
    }
}

/// Double-clicking the app (from Finder, Launchpad or Spotlight) opens the
/// Shield window, so the app is never only a small icon you have to find.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ note: Notification) {
        // A start at login stays quiet in the menu bar; any other start shows the window.
        let event = NSAppleEventManager.shared().currentAppleEvent
        let atLogin = event?.paramDescriptor(forKeyword: keyAELaunchedAsLogInItem) != nil
        if !atLogin { ConsoleWindow.show() }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        ConsoleWindow.show()
        return true
    }
}

extension ShieldModel {
    var menuSymbol: String {
        switch state {
        case .protecting: return "checkmark.shield"
        case .attention: return "exclamationmark.shield"
        case .stopped: return "shield.slash"
        case .starting: return "shield"
        }
    }
}
