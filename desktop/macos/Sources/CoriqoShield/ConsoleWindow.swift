import SwiftUI
import WebKit

/// The desktop window: one shared NSWindow, opened from the menu or a relaunch.
enum ConsoleWindow {
    private static var window: NSWindow?

    /// Open the window, optionally on one Shield page (e.g. "shield?tab=settings").
    @MainActor static func show(page: String? = nil) {
        if let page, let web = findWeb(window?.contentView) {
            web.load(URLRequest(url: URL(string: page, relativeTo: ShieldModel.base)!))
        }
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 780),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                             backing: .buffered, defer: false)
            w.title = "Coriqo Shield"
            w.titlebarAppearsTransparent = true
            w.backgroundColor = NSColor(Brand.paper)
            w.minSize = NSSize(width: 900, height: 600)
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: ConsoleView(page: page ?? "shield"))
            w.delegate = closer
            // A remembered place if there is one, else centred on the screen in use.
            if !w.setFrameUsingName("CoriqoShieldConsole") { w.center() }
            w.setFrameAutosaveName("CoriqoShieldConsole")
            window = w
        }
        // While the window is open the app sits in the Dock and the app switcher,
        // like any app; closing it returns Shield to the menu bar only.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    private static let closer = Closer()
    private final class Closer: NSObject, NSWindowDelegate {
        func windowWillClose(_ notification: Notification) {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    private static func findWeb(_ view: NSView?) -> WKWebView? {
        guard let view else { return nil }
        if let web = view as? WKWebView { return web }
        for sub in view.subviews { if let web = findWeb(sub) { return web } }
        return nil
    }
}

/// The desktop view: Shield's own console, served by byoai-shield on this Mac.
struct ConsoleView: View {
    var page = "shield"
    var body: some View {
        WebView(url: URL(string: page, relativeTo: ShieldModel.base)!)
    }
}

struct WebView: NSViewRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> WKWebView {
        let view = WKWebView(frame: .zero, configuration: WKWebViewConfiguration())
        view.navigationDelegate = context.coordinator
        view.setValue(false, forKey: "drawsBackground")
        view.load(URLRequest(url: url))
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {}

    /// Keep only Shield's own pages in the window; links elsewhere open in the browser.
    final class Coordinator: NSObject, WKNavigationDelegate {
        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = action.request.url, let scheme = url.scheme?.lowercased() else {
                return decisionHandler(.cancel)
            }
            // Shield's own pages (and the blank/error page) stay in the window.
            if (scheme == "http" && url.host == "127.0.0.1" && url.port == ShieldModel.port)
                || url.absoluteString == "about:blank" {
                return decisionHandler(.allow)
            }
            // Anything else opens in the browser only when the person clicked a
            // web or mail link; scripts, redirects and frames never launch apps.
            if action.navigationType == .linkActivated, action.targetFrame?.isMainFrame != false,
               ["http", "https", "mailto"].contains(scheme) {
                NSWorkspace.shared.open(url)
            }
            decisionHandler(.cancel)
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation _: WKNavigation!, withError _: Error) {
            webView.loadHTMLString("""
            <body style="font:14px -apple-system;background:#F9F8F4;color:#1D1D1F;padding:48px">
            <h2 style="font-family:Newsreader,Georgia,serif;font-weight:500">Shield isn't running</h2>
            <p>Start it from the menu bar, or run <code>byoai-shield</code>.</p></body>
            """, baseURL: nil)
        }
    }
}
