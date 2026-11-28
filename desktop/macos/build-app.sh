#!/bin/sh
# Build "Coriqo Shield.app" (menu bar + window) into desktop/macos/build/.
set -eu
cd "$(dirname "$0")"
swift build -c release
APP="build/Coriqo Shield.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
# App icon from the extension's Coriqo seal icon.
ICON_SRC=../../src/byoai/browser_extension/icons/icon128.png
ISET=build/AppIcon.iconset; rm -rf "$ISET"; mkdir -p "$ISET"
for s in 16 32 64 128 256 512; do
  sips -z $s $s "$ICON_SRC" --out "$ISET/icon_${s}x${s}.png" >/dev/null
done
for s in 16 32 128 256; do cp "$ISET/icon_$((s*2))x$((s*2)).png" "$ISET/icon_${s}x${s}@2x.png"; done
rm -f "$ISET/icon_64x64.png"
iconutil -c icns "$ISET" -o "$APP/Contents/Resources/AppIcon.icns"
cp .build/release/CoriqoShield "$APP/Contents/MacOS/CoriqoShield"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Coriqo Shield</string>
  <key>CFBundleIdentifier</key><string>com.coriqo.shield.app</string>
  <key>CFBundleExecutable</key><string>CoriqoShield</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSAppTransportSecurity</key><dict>
    <key>NSAllowsLocalNetworking</key><true/>
  </dict>
</dict></plist>
PLIST
codesign --force --sign - "$APP"
echo "Built $APP"
