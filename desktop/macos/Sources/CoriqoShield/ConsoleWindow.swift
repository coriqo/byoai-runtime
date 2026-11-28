import SwiftUI
import WebKit

/// The desktop view: Shield's own console, served by byoai-shield on this Mac.
struct ConsoleView: View {
    var body: some View {
        WebView(url: ShieldModel.base.appendingPathComponent("shield"))
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
