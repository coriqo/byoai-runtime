import AppKit
import SwiftUI

@main
struct CoriqoShieldApp: App {
    @StateObject private var model = ShieldModel()

    var body: some Scene {
        MenuBarExtra {
            MenuView(model: model)
        } label: {
            Image(systemName: model.menuSymbol)
        }
        .menuBarExtraStyle(.window)

        Window("Coriqo Shield", id: "console") {
            ConsoleView()
                .frame(minWidth: 900, minHeight: 600)
                .background(Brand.paper)
        }
        .defaultSize(width: 1180, height: 780)
    }
}

extension ShieldModel {
    var menuSymbol: String {
        switch state {
        case .protecting: return "checkmark.shield.fill"
        case .attention: return "exclamationmark.shield.fill"
        case .stopped: return "xmark.shield"
        case .starting: return "shield"
        }
    }
}
