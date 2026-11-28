import SwiftUI

/// The menu-bar dropdown, a "mini player": one status you can read at a
/// glance, today's line, and a footer naming where records go. Everything
/// else is one click away in the Shield window.
struct MenuView: View {
    @ObservedObject var model: ShieldModel
    @ObservedObject var login: LoginItem

    var body: some View {
        VStack(spacing: 0) {
            header
            VStack(alignment: .leading, spacing: Size.spaceMd) {
                statusButton
                Text(look.detail)
                    .font(.system(size: Size.textSm)).foregroundStyle(Brand.inkSoft)
                    .fixedSize(horizontal: false, vertical: true)
                if let today { Text(today).font(.system(size: Size.textSm)).foregroundStyle(Brand.ink) }
                if model.coriqo != nil && model.coriqo?.connected != true && model.state != .stopped {
                    SecondaryButton(title: "Connect to Coriqo") { ConsoleWindow.show(page: "shield?tab=settings") }
                }
            }
            .padding(.horizontal, Size.spaceLg).padding(.bottom, Size.spaceLg)
            footer
        }
        .frame(width: 300)
        .background(Brand.paper)
        .onAppear { login.refresh() }
    }

    // MARK: header: brand on the left, the window on the right

    private var header: some View {
        HStack(spacing: Size.spaceSm) {
            SealMark(size: Size.iconPanel)
            Text("Coriqo Shield").font(.system(size: Size.textSm, weight: .semibold)).foregroundStyle(Brand.ink)
            Spacer()
            IconButton(symbol: "macwindow", label: "Open Shield window") { ConsoleWindow.show() }
        }
        .padding(.leading, Size.spaceLg).padding(.trailing, Size.spaceSm)
        .frame(minHeight: Size.target)
    }

    // MARK: the one status

    /// A large, state-coloured control: the main thing to read, and the main
    /// thing to click (open the window, or start Shield when it is off).
    private var statusButton: some View {
        Button {
            if model.state == .stopped { model.startShield() } else { ConsoleWindow.show() }
        } label: {
            HStack(spacing: Size.spaceMd) {
                Image(systemName: look.symbol).font(.system(size: Size.iconPanel, weight: .semibold))
                VStack(alignment: .leading, spacing: 2) {
                    Text(look.title).font(.system(size: Size.textMd, weight: .semibold))
                    Text(look.action).font(.system(size: Size.textXs)).opacity(0.85)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: Size.iconStatus, weight: .semibold)).opacity(0.7)
            }
            .foregroundStyle(look.ink)
            .padding(.horizontal, Size.spaceLg)
            .frame(maxWidth: .infinity, minHeight: 56, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: Size.radius).fill(look.fill))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(look.title). \(look.action)")
    }

    private var look: (symbol: String, title: String, action: String, detail: String, fill: Color, ink: Color) {
        switch model.state {
        case .protecting:
            return ("checkmark.shield.fill", "Protected", "Open Shield",
                    "Messages to AI apps are checked on this Mac before they leave. Your words are not stored or sent.",
                    Brand.action, Brand.onAction)
        case .attention(let why):
            return ("exclamationmark.triangle.fill", "Needs a look", "Open Shield to see why", why,
                    Brand.pending, Brand.onStatus)
        case .stopped:
            return ("shield.slash.fill", "Shield is off", "Start Shield",
                    "Messages are not being checked or recorded.", Brand.offScope, Brand.onStatus)
        case .starting:
            return ("circle.dashed", "Checking", "One moment", "Looking for Shield on this Mac.",
                    Brand.paper2, Brand.ink)
        }
    }

    private var today: String? {
        guard model.state != .stopped, let s = model.feed?.summary else { return nil }
        let needs = s.flagged + s.high_risk
        if s.checked == 0 { return "No messages checked today." }
        return "\(s.checked) checked today · " + (needs == 0 ? "none flagged" : "\(needs) to review")
    }

    // MARK: footer: where records go, and the overflow menu

    private var footer: some View {
        HStack(spacing: Size.spaceSm) {
            Circle().fill(syncTint).frame(width: 6, height: 6)
            Text(syncWords).font(.system(size: Size.textXs)).foregroundStyle(Brand.inkSoft).lineLimit(1)
            Spacer()
            Menu {
                Toggle("Open at login", isOn: Binding(get: { login.enabled }, set: { login.set($0) }))
                    .disabled(login.managed)
                if login.managed { Text("Open at login is set by your organisation") }
                Divider()
                Button("Shield settings…") { ConsoleWindow.show(page: "shield?tab=settings") }
                Button("Check again") { Task { await model.refresh() } }
                Divider()
                Button("Quit Coriqo Shield") { NSApp.terminate(nil) }
            } label: {
                Image(systemName: "ellipsis.circle").font(.system(size: Size.iconRow)).foregroundStyle(Brand.inkSoft)
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .frame(width: Size.target, height: Size.target)
            .accessibilityLabel("More")
        }
        .padding(.leading, Size.spaceLg).padding(.trailing, Size.spaceXs)
        .frame(minHeight: Size.target)
        .background(Brand.paper2)
        .overlay(alignment: .top) { Rectangle().fill(Brand.line).frame(height: 1) }
    }

    /// Both sync jobs folded into one ranked state: the worst thing wins, and
    /// the dot and the words always come from the same case.
    private enum Sync {
        case off(String), sealAttention, sealRetrying, activityRetrying, activityUnknown
        case activityWaiting(Int), sealWaiting(String), upToDate(String)
    }

    private var sync: Sync {
        guard let c = model.coriqo, c.connected == true else {
            return .off(model.state == .stopped ? "Not running" : "Records stay on this Mac")
        }
        if c.needs_attention == true { return .sealAttention }
        if c.last_error != nil { return .sealRetrying }
        let level = c.sync?.level
        if level != "seal" {
            if c.sync?.last_error != nil || (c.sync?.failures ?? 0) > 0 { return .activityRetrying }
            if level == nil { return .activityUnknown }
            if let n = c.sync?.pending, n > 0 { return .activityWaiting(n) }
        }
        if c.has_new == true { return .sealWaiting(Self.when(c.next_attempt_at)) }
        return .upToDate(level == "events" ? "live, up to date" : level == "daily" ? "daily totals, up to date" : "seal up to date")
    }

    private var syncWords: String {
        let to = model.coriqo?.tenant ?? "Coriqo"
        switch sync {
        case .off(let w): return w
        case .sealAttention: return "\(to) · needs attention"
        case .sealRetrying: return "\(to) · seal send retrying"
        case .activityRetrying: return "\(to) · activity sync retrying"
        case .activityUnknown: return "\(to) · activity sync unknown"
        case .activityWaiting(let n): return "\(to) · \(n) waiting to sync"
        case .sealWaiting(let when): return "\(to) · seal sends \(when)"
        case .upToDate(let w): return "\(to) · \(w)"
        }
    }

    private var syncTint: Color {
        switch sync {
        case .off: return Brand.inkSoft
        case .sealAttention: return Brand.offScope
        case .sealRetrying, .activityRetrying, .activityUnknown: return Brand.pending
        case .activityWaiting, .sealWaiting: return Brand.azure
        case .upToDate: return Brand.validated
        }
    }

    private static func when(_ at: Double?) -> String {
        guard let at else { return "within a minute" }
        let mins = Int(((at - Date().timeIntervalSince1970) / 60).rounded())
        return mins <= 1 ? "within a minute" : mins < 60 ? "in \(mins) min" : "in \(mins / 60) h"
    }
}

/// Outlined control for a second action: hairline edge, ink text, 44px tall.
struct SecondaryButton: View {
    let title: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(size: Size.textSm, weight: .medium))
                .frame(maxWidth: .infinity, minHeight: Size.target)
                .foregroundStyle(Brand.ink)
                .background(RoundedRectangle(cornerRadius: Size.radiusSm).fill(hover ? Brand.paper2 : Brand.field))
                .overlay(RoundedRectangle(cornerRadius: Size.radiusSm).stroke(Brand.line))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

/// A 44px square icon control with a hover surface.
struct IconButton: View {
    let symbol: String
    let label: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Image(systemName: symbol).font(.system(size: Size.iconRow)).foregroundStyle(Brand.inkSoft)
                .frame(width: Size.target, height: Size.target)
                .background(RoundedRectangle(cornerRadius: Size.radiusSm).fill(hover ? Brand.paper2 : .clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .help(label)
        .accessibilityLabel(label)
    }
}
