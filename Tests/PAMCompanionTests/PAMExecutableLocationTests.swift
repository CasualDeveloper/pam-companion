import Darwin
import Foundation
import XCTest

@testable import PAMCompanionCore

final class PAMExecutableLocationTests: XCTestCase {
  func testModuleLocationUsesActualExecutableInsteadOfInvocationSpelling() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let executable = root.appendingPathComponent("Cellar/pam-companion/0.1.0/bin/pam-companion")
    try FileManager.default.createDirectory(
      at: executable.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    try Data().write(to: executable)
    let symlink = root.appendingPathComponent("bin/pam-companion")
    try FileManager.default.createDirectory(
      at: symlink.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: executable)
    let canonicalPath = try XCTUnwrap(realpath(executable.path, nil))
    defer { free(canonicalPath) }
    let canonicalExecutable = URL(
      fileURLWithFileSystemRepresentation: canonicalPath,
      isDirectory: false,
      relativeTo: nil
    )
    let expected = canonicalExecutable.deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("libexec/pam_companion.so")

    let invocations = ["pam-companion", "./pam-companion", executable.path, symlink.path]
    for invocation in invocations {
      XCTAssertEqual(
        try PAMExecutableLocation.installedModuleURL(
          arguments: [invocation],
          executablePath: { symlink.path }
        ),
        expected
      )
    }
  }
}
