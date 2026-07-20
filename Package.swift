// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "pam-companion",
  platforms: [.macOS(.v14)],
  products: [
    .library(
      name: "pam-companion",
      type: .dynamic,
      targets: ["PAMCompanion"]
    )
  ],
  targets: [
    .target(
      name: "CPAM",
      path: "Sources/CPAM",
      publicHeadersPath: "include"
    ),
    .target(
      name: "PAMCompanionCore",
      path: "Sources/PAMCompanionCore"
    ),
    .target(
      name: "PAMCompanion",
      dependencies: ["CPAM", "PAMCompanionCore"],
      path: "Sources/PAMCompanion"
    ),
    .testTarget(
      name: "PAMCompanionTests",
      dependencies: ["CPAM", "PAMCompanion", "PAMCompanionCore"],
      path: "Tests/PAMCompanionTests"
    ),
  ],
  swiftLanguageModes: [.v6]
)
