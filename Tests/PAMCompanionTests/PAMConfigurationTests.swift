import Foundation
import XCTest

@testable import PAMCompanionCore

final class PAMConfigurationPlannerTests: XCTestCase {
  func testMigrationEnablesNativeModuleAndRemovesLegacyModule() throws {
    let original = """
      # sudo_local survives system updates
      # keep this comment
      #auth       sufficient     pam_tid.so
      auth       sufficient     pam_watchid.so

      """

    let plan = try PAMConfigurationPlanner.plan(original)

    XCTAssertEqual(
      plan.updated,
      """
      # sudo_local survives system updates
      # keep this comment
      auth       sufficient     pam_tid.so

      """
    )
    XCTAssertEqual(plan.removedModules, ["pam_watchid.so"])
  }

  func testMigrationRemovesCurrentCustomModuleFromNativeStack() throws {
    let original = """
      #auth       sufficient     pam_tid.so
      auth sufficient /usr/local/lib/pam/pam_companion.so reason=Approve timeout=45
      """

    let plan = try PAMConfigurationPlanner.plan(original)

    XCTAssertEqual(
      plan.updated,
      "auth       sufficient     pam_tid.so"
    )
    XCTAssertEqual(plan.removedModules, ["pam_companion.so"])
  }

  func testExistingNativeConfigurationIsByteForByteUnchanged() throws {
    let original = "# custom spacing\nauth  sufficient  pam_tid.so\n"

    let plan = try PAMConfigurationPlanner.plan(original)

    XCTAssertFalse(plan.changed)
    XCTAssertEqual(plan.updated, original)
    XCTAssertTrue(plan.removedModules.isEmpty)
  }

  func testNativeTemplateAnchorIsRequired() {
    let configurations = ["# comments only\n", "auth sufficient pam_companion.so\n"]

    for configuration in configurations {
      XCTAssertThrowsError(try PAMConfigurationPlanner.plan(configuration), configuration)
    }
  }

  func testDuplicateCompanionFamilyEntriesAreRejected() {
    let configurations = [
      "auth sufficient pam_tid.so\nauth sufficient pam_watchid.so\nauth sufficient pam_watchid.so.2\n",
      "auth sufficient pam_tid.so\nauth sufficient pam_companion.so\nauth sufficient pam_watchid.so\n",
      "auth sufficient pam_tid.so\nauth sufficient pam_companion.so\nauth sufficient pam_companion.so\n",
    ]

    for configuration in configurations {
      XCTAssertThrowsError(try PAMConfigurationPlanner.plan(configuration)) { error in
        XCTAssertEqual(error as? PAMConfigurationError, .duplicateModuleEntries)
      }
    }
  }

  func testUnsafeControlFlagsFunctionsAndArgumentsAreRejected() {
    let configurations: [(String, PAMConfigurationError)] = [
      ("auth sufficient pam_tid.so\nauth required pam_watchid.so\n", .unsupportedModuleEntry),
      ("auth sufficient pam_tid.so\naccount sufficient pam_watchid.so\n", .unsupportedModuleEntry),
      ("auth sufficient pam_tid.so debug\n", .unsupportedLocalPolicy),
    ]

    for (configuration, expected) in configurations {
      XCTAssertThrowsError(try PAMConfigurationPlanner.plan(configuration)) { error in
        XCTAssertEqual(error as? PAMConfigurationError, expected)
      }
    }
  }

  func testInvalidUTF8AndNulBytesAreRejected() {
    XCTAssertThrowsError(try PAMConfigurationPlanner.plan(Data([0xff])))
    XCTAssertThrowsError(
      try PAMConfigurationPlanner.plan(Data("auth sufficient pam_tid.so\0\n".utf8)))
  }

  func testOnlyKnownSafeSudoLocalShapesAreAccepted() throws {
    let accepted = [
      "auth sufficient pam_tid.so\n",
      "#auth sufficient pam_tid.so\n",
      "auth sufficient pam_tid.so\nauth sufficient pam_watchid.so reason=Approve\n",
      "# auth sufficient pam_tid.so\nauth sufficient pam_companion.so timeout=45\n",
    ]
    for configuration in accepted {
      XCTAssertNoThrow(try PAMConfigurationPlanner.plan(configuration), configuration)
    }

    let rejected = [
      "auth required pam_opendirectory.so\n",
      "auth requisite pam_smartcard.so\n",
      "auth include another_policy\n",
      "auth sufficient pam_tid.so debug\n",
      "# comments only\n",
      "auth sufficient pam_tid.so\nauth sufficient pam_tid.so\n",
      "account required pam_permit.so\n",
    ]
    for configuration in rejected {
      XCTAssertThrowsError(try PAMConfigurationPlanner.plan(configuration), configuration)
    }
  }
}

final class PAMReferenceScannerTests: XCTestCase {
  func testScannerFindsActiveRemovableReferencesIndependentlyOfFileNames() throws {
    let policies = [
      "/etc/pam.d/custom-companion": Data(
        "auth required /usr/local/lib/pam/pam_companion.so\n".utf8),
      "/etc/pam.d/custom-watch": Data(
        "auth required /usr/local/lib/pam/pam_watchid.so.2\n".utf8),
      "/etc/pam.d/commented": Data("# auth sufficient pam_watchid.so\n".utf8),
    ]

    XCTAssertEqual(
      try PAMReferenceScanner.removableReferences(in: policies),
      [
        PAMLegacyReference(
          policyPath: "/etc/pam.d/custom-companion", module: "pam_companion.so"),
        PAMLegacyReference(policyPath: "/etc/pam.d/custom-watch", module: "pam_watchid.so.2"),
      ]
    )
  }

  func testScannerRejectsUnparseablePolicies() {
    XCTAssertThrowsError(
      try PAMReferenceScanner.removableReferences(in: ["/etc/pam.d/unknown": Data([0xff])])
    )
  }

  func testPamConfScannerAccountsForLeadingServiceField() throws {
    let policies = [
      "/etc/pam.conf": Data(
        "sudo auth required pam_companion.so\nlogin auth required pam_opendirectory.so\n".utf8)
    ]

    XCTAssertEqual(
      try PAMReferenceScanner.pamConfReferences(in: policies),
      [PAMLegacyReference(policyPath: "/etc/pam.conf", module: "pam_companion.so")]
    )
  }
}
