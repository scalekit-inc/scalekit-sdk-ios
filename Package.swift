// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ScalekitAuth",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "ScalekitAuth",
            targets: ["ScalekitAuth"]
        )
    ],
    dependencies: [
        .package(
            url: "https://github.com/openid/AppAuth-iOS",
            from: "1.7.0"
        )
    ],
    targets: [
        .target(
            name: "ScalekitAuth",
            dependencies: [
                .product(name: "AppAuth", package: "AppAuth-iOS")
            ]
        )
    ]
)
