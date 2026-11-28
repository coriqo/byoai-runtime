import AppKit
import SwiftUI

/// Coriqo brand colours, copied from web/src/styles/tokens.css (light, dark).
enum Brand {
    static let paper     = dyn(0xF9F8F4, 0x0C0D10)
    static let field     = dyn(0xFFFFFF, 0x141519)
    static let paper2    = dyn(0xF3F1EB, 0x1C1E23)
    static let line      = dyn(0xE8E5DD, 0x2A2D34)
    static let ink       = dyn(0x1D1D1F, 0xF2F3F5)
    static let inkSoft   = dyn(0x5F5F64, 0x9A9FAB)
    static let action    = dyn(0x0A1834, 0x3D7EFF)
    static let onAction  = dyn(0xFFFFFF, 0x0B1220)
    static let azure     = dyn(0x2447A6, 0x709FFF)
    static let seal      = Color(hex: 0x3F7BFF)
    static let validated = dyn(0x1B6A48, 0x4AD6A0)
    static let pending   = dyn(0x815411, 0xE0B15A)
    static let offScope  = dyn(0x70221C, 0xE8857B)

    static func title(_ size: CGFloat) -> Font { .custom("Newsreader", size: size).weight(.medium) }

    private static func dyn(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { app in
            app.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? NSColor(hex: dark) : NSColor(hex: light)
        })
    }
}

extension NSColor {
    convenience init(hex: UInt32) {
        self.init(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
}

extension Color {
    init(hex: UInt32) { self.init(nsColor: NSColor(hex: hex)) }
}
