import ServiceManagement
import SwiftUI

/// The menu-bar dropdown. One status, one sentence about what it means, one
/// main action. Detail lives in the Shield window, not here.
struct MenuView: View {
    @ObservedObject var model: ShieldModel
    @State private var openAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        VStack(alignment: .leading, spacing: Size.spaceLg) {
            brand
            status
            if model.state != .stopped && model.state != .starting { activity }
            primary
            promise
            Divider().overlay(Brand.line)
            VStack(spacing: 0) {
                Toggle("Open at login", isOn: $openAtLogin)
                    .toggleStyle(.switch).tint(Brand.action)
                    .font(.system(size: Size.textSm)).foregroundStyle(Brand.ink)
                    .frame(minHeight: Size.target)
                    .onChange(of: openAtLogin) { _, on in
                        do { if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() } }
                        catch { openAtLogin = SMAppService.mainApp.status == .enabled }
                    }
                QuietRow(title: "Check again") { Task { await model.refresh() } }
                QuietRow(title: "Quit Coriqo Shield") { NSApp.terminate(nil) }
            }
        }
        .padding(Size.spaceLg)
        .frame(width: 320)
        .background(Brand.paper)
    }

    private var brand: some View {
        HStack(spacing: Size.spaceSm) {
            SealMark(size: Size.iconPanel)
            Text("Coriqo Shield").font(.system(size: Size.textSm, weight: .semibold)).foregroundStyle(Brand.ink)
        }
    }

    // MARK: status: the one thing to read

    private var status: some View {
        HStack(alignment: .top, spacing: Size.spaceMd) {
            Image(systemName: look.symbol)
                .font(.system(size: Size.iconPanel)).foregroundStyle(look.tint)
                .frame(width: Size.iconNav)
            VStack(alignment: .leading, spacing: Size.spaceXs) {
                Text(look.title).font(Brand.title(Size.textXl)).foregroundStyle(Brand.ink)
                Text(look.detail).font(.system(size: Size.textSm)).foregroundStyle(Brand.inkSoft)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(Size.spaceMd)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: Size.radius).fill(Brand.field))
        .overlay(RoundedRectangle(cornerRadius: Size.radius).stroke(look.edge))
        .accessibilityElement(children: .combine)
    }

    private var look: (symbol: String, tint: Color, edge: Color, title: String, detail: String) {
        switch model.state {
        case .protecting:
            return ("checkmark.shield", Brand.validated, Brand.line, "Protecting this Mac",
                    "Messages to AI apps are checked before they leave, and each check is sealed in a signed record.")
        case .attention(let why):
            return ("exclamationmark.triangle", Brand.pending, Brand.pending.opacity(0.45), "Needs a look", why)
        case .stopped:
            return ("pause.circle", Brand.offScope, Brand.offScope.opacity(0.45), "Shield is off",
                    "Messages are not being checked or recorded until Shield starts.")
        case .starting:
            return ("circle.dashed", Brand.inkSoft, Brand.line, "Checking Shield", "One moment.")
        }
    }

    // MARK: activity: one quiet line

    private var activity: some View {
        let s = model.feed?.summary
        let checked = s?.checked ?? 0, needs = (s?.flagged ?? 0) + (s?.high_risk ?? 0)
        let today = checked == 0 ? "No messages checked today."
            : "\(checked) \(checked == 1 ? "message" : "messages") checked today"
              + (needs == 0 ? ", none flagged." : ", \(needs) to review.")
        return VStack(alignment: .leading, spacing: Size.spaceSm) {
            Text(today).font(.system(size: Size.textSm)).foregroundStyle(Brand.ink)
            if model.coriqo?.connected == true { syncLine }
        }
    }

    /// The two sync jobs in one line each: what is shared, and where the job is.
    private var syncLine: some View {
        let c = model.coriqo
        let to = c?.tenant.map { "Coriqo (\($0))" } ?? "Coriqo"
        let seal: (String, Color) = c?.needs_attention == true ? ("needs attention", Brand.offScope)
            : c?.last_error != nil ? ("retrying", Brand.pending)
            : c?.has_new == true ? ("sending \(Self.when(c?.next_attempt_at))", Brand.inkSoft)
            : ("up to date", Brand.validated)
        // Off only when Shield says so; an older Shield or an unreadable policy is unknown.
        let level = c?.sync?.level ?? "unknown"
        let pending = c?.sync?.pending ?? 0
        let act: (String, Color)? = level == "seal" ? nil
            : (c?.sync?.failures ?? 0) > 0 || c?.sync?.last_error != nil ? ("retrying", Brand.pending)
            : pending > 0 ? ("\(pending) waiting, sending \(Self.when(c?.sync?.next_attempt_at))", Brand.inkSoft)
            : ("up to date", Brand.validated)
        return VStack(alignment: .leading, spacing: Size.spaceXs) {
            Text("Syncing with \(to)").font(.system(size: Size.textXs, weight: .semibold)).foregroundStyle(Brand.inkSoft)
            jobRow("Seal, every \(Int(c?.every_hours ?? 6)) h", seal)
            if let act {
                jobRow(level == "events" ? "Activity, live" : level == "daily" ? "Daily totals, hourly" : "Activity, mode unknown", act)
            } else {
                Text("No activity is shared, only the seal.").font(.system(size: Size.textXs)).foregroundStyle(Brand.inkSoft)
            }
        }
    }

    private func jobRow(_ name: String, _ state: (String, Color)) -> some View {
        HStack(spacing: Size.spaceSm) {
            Circle().fill(state.1).frame(width: Size.iconStatus / 2, height: Size.iconStatus / 2)
            Text(name).foregroundStyle(Brand.ink)
            Spacer(minLength: Size.spaceSm)
            Text(state.0).foregroundStyle(Brand.inkSoft).lineLimit(1)
        }
        .font(.system(size: Size.textXs))
        .accessibilityElement(children: .combine)
    }

    private static func when(_ at: Double?) -> String {
        guard let at else { return "within a minute" }
        let mins = Int(((at - Date().timeIntervalSince1970) / 60).rounded())
        return mins <= 1 ? "within a minute" : mins < 60 ? "in \(mins) min" : "in \(mins / 60) h"
    }

    // MARK: actions

    @ViewBuilder private var primary: some View {
        if model.state == .stopped {
            PrimaryButton(title: "Start Shield") { model.startShield() }
            SecondaryButton(title: "Open Shield") { ConsoleWindow.show() }
        } else {
            PrimaryButton(title: "Open Shield") { ConsoleWindow.show() }
            if model.coriqo != nil && model.coriqo?.connected != true {
                SecondaryButton(title: "Connect to Coriqo") { ConsoleWindow.show(page: "shield?tab=settings") }
            }
        }
    }

    private var promise: some View {
        Text("Your words are checked on this Mac. By default they are not stored or sent.")
            .font(.system(size: Size.textXs)).foregroundStyle(Brand.inkSoft)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// Filled control: the seal's navy, 44px tall.
struct PrimaryButton: View {
    let title: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(size: Size.textSm, weight: .semibold))
                .frame(maxWidth: .infinity, minHeight: Size.target)
                .foregroundStyle(Brand.onAction)
                .background(RoundedRectangle(cornerRadius: Size.radiusSm).fill(hover ? Brand.actionHover : Brand.action))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

/// Outlined control for the second action: azure edge, ink text, 44px tall.
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

/// Plain text row, 44px tall, hover on the raised surface.
struct QuietRow: View {
    let title: String
    let action: () -> Void
    @State private var hover = false
    var body: some View {
        Button(action: action) {
            Text(title).font(.system(size: Size.textSm)).foregroundStyle(Brand.ink)
                .padding(.horizontal, Size.spaceSm)
                .frame(maxWidth: .infinity, minHeight: Size.target, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: Size.radiusSm).fill(hover ? Brand.paper2 : .clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, -Size.spaceSm)
        .onHover { hover = $0 }
    }
}
