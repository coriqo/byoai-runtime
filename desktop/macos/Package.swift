// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "CoriqoShield",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "CoriqoShield", path: "Sources/CoriqoShield")
    ]
)
