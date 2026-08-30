// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SideSign",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8),
        .visionOS(.v1)
    ],

    products: [
        .library(
            name: "SideSign",
            type: .static,
            targets: ["SideSign"]
        ),
        .library(
            name: "SideSign-Dynamic",
            type: .dynamic,
            targets: ["SideSign"]
        ),
        .executable(
            name: "sidesign",
            targets: ["SideSignCLI"]
        ),
    ],

    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git",    "4.0.0" ..< "5.0.0"),

        .package(url: "https://github.com/mahee96/CodeSignKit.git",   branch: "main"),
        .package(url: "https://github.com/mahee96/GSACryptoKit.git",  branch: "main"),
        .package(url: "https://github.com/SideStore/minizip-ng",      branch: "develop"),
        .package(url: "https://github.com/mahee96/AnisetteKit.git",   branch: "main"),

//        .package(name: "CodeSignKit",  path: "../../local/CodeSignKit"),
//        .package(name: "GSACryptoKit", path: "../../local/GSACryptoKit"),
//        .package(name: "minizip-ng",    path: "../../local/minizip-ng")
//        .package(name: "AnisetteKit",   path: "../../local/AnisetteKit")
    ],

    targets: [
        .target(
            name: "SideSign",
            dependencies: [
                .product(name: "minizip-ng", package: "minizip-ng"),
                .product(name: "Crypto", package: "swift-crypto"),
                "AnisetteKit",
                "CodeSignKit",
                "GSACryptoKit"
            ],
            path: "Sources"
        ),
        .executableTarget(
            name: "SideSignCLI",
            dependencies: [
                "SideSign",
                "CodeSignKit",
                "GSACryptoKit",
                "AnisetteKit"
            ],
            path: "CLI"
        ),
        .testTarget(
            name: "SideSignTests",
            dependencies: [
                "SideSign",
                "CodeSignKit",
                "GSACryptoKit"
            ],
            path: "Tests/SideSignTests"
        )
    ],

    swiftLanguageModes: [.v6],
    cLanguageStandard: .gnu11
)
