import XCTest

@testable import PAMCompanionCore

final class PAMCommandLineParserTests: XCTestCase {
  func testInspectionCommandsParse() throws {
    XCTAssertEqual(try PAMCommandLineParser.parse(["pam-companion", "status"]), .status)
    XCTAssertEqual(try PAMCommandLineParser.parse(["pam-companion", "doctor"]), .doctor)
    XCTAssertEqual(try PAMCommandLineParser.parse(["pam-companion", "--version"]), .version)
  }

  func testLifecycleCommandsExposeDryRunExplicitly() throws {
    XCTAssertEqual(try PAMCommandLineParser.parse(["pam-companion", "setup"]), .setup(dryRun: false))
    XCTAssertEqual(
      try PAMCommandLineParser.parse(["pam-companion", "setup", "--dry-run"]),
      .setup(dryRun: true)
    )
    XCTAssertEqual(try PAMCommandLineParser.parse(["pam-companion", "restore"]), .restore(dryRun: false))
    XCTAssertEqual(
      try PAMCommandLineParser.parse(["pam-companion", "uninstall", "--prepare"]),
      .uninstallPrepare(dryRun: false)
    )
  }

  func testUnknownOrImplicitlyElevatedFormsAreRejected() {
    let invalid = [
      ["pam-companion"],
      ["pam-companion", "setup", "--sudo"],
      ["pam-companion", "uninstall"],
      ["pam-companion", "restore", "unexpected"],
      ["pam-companion", "unknown"],
    ]

    for arguments in invalid {
      XCTAssertThrowsError(try PAMCommandLineParser.parse(arguments))
    }
  }

  func testSystemInspectionAndMutationCommandsRequireRoot() throws {
    XCTAssertTrue(try PAMCommandLineParser.parse(["pam-companion", "status"]).requiresRoot)
    XCTAssertTrue(try PAMCommandLineParser.parse(["pam-companion", "doctor"]).requiresRoot)
    XCTAssertTrue(try PAMCommandLineParser.parse(["pam-companion", "setup"]).requiresRoot)
    XCTAssertTrue(try PAMCommandLineParser.parse(["pam-companion", "restore"]).requiresRoot)
    XCTAssertTrue(
      try PAMCommandLineParser.parse(["pam-companion", "uninstall", "--prepare"]).requiresRoot
    )
  }
}
