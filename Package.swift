// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "pam-companion",
  platforms: [.macOS(.v14)],
  products: [
    .executable(
      name: "pam-companion",
      targets: ["PAMCompanionCLI"]
    )
  ],
  targets: [
    .target(
      name: "PAMCompanionCore",
      path: "Sources/PAMCompanionCore"
    ),
    .executableTarget(
      name: "PAMCompanionCLI",
      dependencies: ["PAMCompanionCore"],
      path: "Sources/PAMCompanionCLI"
    ),
    .testTarget(
      name: "PAMCompanionTests",
      dependencies: ["PAMCompanionCore"],
      path: "Tests/PAMCompanionTests"
    ),
  ],
  swiftLanguageModes: [.v6]
)
