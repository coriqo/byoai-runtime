import ServiceManagement
import SwiftUI

/// The menu-bar dropdown, in the spirit of Tailscale's: state first, then the
/// few things you check often, then actions.
struct MenuView: View {
    @ObservedObject var model: ShieldModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider().overlay(Brand.line)
            if let feed = model.feed {
                counts(feed.summary).padding(14)
                Divider().overlay(Brand.line)
                recent(feed.items)
                Divider().overlay(Brand.line)
                coriqoRow.padding(.horizontal, 14).padding(.vertical, 10)
                Divider().overlay(Brand.line)
            }
            actions.padding(8)
        }
        .frame(width: 320)
        .background(Brand.paper)
        .foregroundStyle(Brand.ink)
    }

    // MARK: header

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 8).fill(Color(hex: 0x0A1834))
                Image(systemName: "shield.lefthalf.filled").foregroundStyle(Brand.seal)
            }
            .frame(width: 32, height: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text("Coriqo Shield").font(Brand.title(17))
                HStack(spacing: 6) {
                    Circle().fill(stateColor).frame(width: 8, height: 8)
                    Text(stateWords).font(.system(size: 12)).foregroundStyle(Brand.inkSoft)
                }
            }
            Spacer()
        }
        .padding(14)
    }

    private var stateWords: String {
        switch model.state {
        case .protecting: return "Protecting this Mac"
        case .attention: return "Needs attention"
        case .stopped: return "Not running"
        case .starting: return "Starting…"
        }
    }

    private var stateColor: Color {
        switch model.state {
        case .protecting: return Brand.validated
        case .attention: return Brand.pending
        case .stopped: return Brand.offScope
        case .starting: return Brand.inkSoft
        }
    }

    // MARK: body

    private func counts(_ c: Feed.Summary) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if case .attention(let why) = model.state {
                Text(why).font(.system(size: 12)).foregroundStyle(Brand.pending)
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Brand.pending.opacity(0.10)))
            }
            HStack(spacing: 8) {
                stat("Checked today", c.checked, Brand.ink)
                stat("Flagged", c.flagged, Brand.pending)
                stat("High risk", c.high_risk, Brand.offScope)
            }
        }
    }

    private func stat(_ label: String, _ n: Int, _ tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(n)").font(.system(size: 20, weight: .semibold)).foregroundStyle(tint).monospacedDigit()
            Text(label).font(.system(size: 12)).foregroundStyle(Brand.inkSoft)
        }
        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Brand.field))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Brand.line))
    }

    private func recent(_ items: [FeedItem]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("RECENT").font(.system(size: 11, weight: .semibold)).foregroundStyle(Brand.inkSoft)
            if items.isEmpty {
                Text("Nothing yet.").font(.system(size: 13)).foregroundStyle(Brand.inkSoft)
            }
            ForEach(items.prefix(4)) { item in
                HStack(spacing: 8) {
                    Image(systemName: icon(item)).foregroundStyle(tint(item)).frame(width: 16)
                    Text(item.verb ?? item.surface ?? "Activity").font(.system(size: 13)).lineLimit(1)
                    Spacer()
                    Text(item.ts ?? "").font(.system(size: 12)).foregroundStyle(Brand.inkSoft).monospacedDigit()
                }
            }
        }
        .padding(14)
    }

    private func icon(_ i: FeedItem) -> String {
        switch i.verdict {
        case "block": return "hand.raised.fill"
        case "redact": return "eye.slash"
        case "warn", "flag": return "exclamationmark.triangle"
        default: return "checkmark.circle"
        }
    }

    private func tint(_ i: FeedItem) -> Color {
        switch i.verdict {
        case "block": return Brand.offScope
        case "warn", "flag": return Brand.pending
        default: return Brand.validated
        }
    }

    private var coriqoRow: some View {
        HStack(spacing: 8) {
            Image(systemName: model.coriqo?.connected == true ? "link" : "link.badge.plus")
                .foregroundStyle(Brand.azure)
            if model.coriqo?.connected == true {
                Text("Connected to Coriqo").font(.system(size: 13))
                if let t = model.coriqo?.tenant { Text(t).font(.system(size: 12)).foregroundStyle(Brand.inkSoft) }
            } else {
                Text("Not connected to Coriqo").font(.system(size: 13)).foregroundStyle(Brand.inkSoft)
            }
            Spacer()
        }
    }

    // MARK: actions

    private var actions: some View {
        VStack(spacing: 2) {
            if model.state == .stopped {
                Button { model.startShield() } label: {
                    Text("Start Shield").font(.system(size: 13, weight: .medium))
                        .frame(maxWidth: .infinity).padding(.vertical, 7)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Brand.action))
                        .foregroundStyle(Brand.onAction)
                }
                .buttonStyle(.plain).padding(.bottom, 4)
            }
            row("Open Shield", "macwindow") {
                openWindow(id: "console")
                NSApp.activate(ignoringOtherApps: true)
            }
            Toggle(isOn: Binding(
                get: { SMAppService.mainApp.status == .enabled },
                set: { on in
                    do { if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() } }
                    catch { NSLog("Open at login: \(error)") }
                    model.objectWillChange.send()
                })) {
                Text("Open at login").font(.system(size: 13))
            }
            .toggleStyle(.switch).controlSize(.mini).tint(Brand.action)
            .padding(.horizontal, 6).padding(.vertical, 5)
            row("Refresh", "arrow.clockwise") { Task { await model.refresh() } }
            row("Quit", "power") { NSApp.terminate(nil) }
        }
    }

    private func row(_ title: String, _ symbol: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Image(systemName: symbol).frame(width: 16).foregroundStyle(Brand.inkSoft)
                Text(title).font(.system(size: 13))
                Spacer()
            }
            .padding(.horizontal, 6).padding(.vertical, 5).contentShape(Rectangle())
        }
        .buttonStyle(MenuRowStyle())
    }
}

struct MenuRowStyle: ButtonStyle {
    @State private var hover = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(RoundedRectangle(cornerRadius: 6).fill(hover || configuration.isPressed ? Brand.paper2 : .clear))
            .onHover { hover = $0 }
    }
}
