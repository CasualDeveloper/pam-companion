import Foundation
import XCTest

@testable import PAMCompanionCore

final class PAMConfigurationPlannerTests: XCTestCase {
  func testMigrationMovesCanonicalModuleBeforeExistingAuthenticationModules() throws {
    let original = """
      # sudo_local survives system updates
      # keep this comment
      auth       sufficient     pam_tid.so
      auth       sufficient     pam_watchid.so

      """

    let plan = try PAMConfigurationPlanner.plan(original)

    XCTAssertEqual(
      plan.updated,
      """
      # sudo_local survives system updates
      # keep this comment
      auth       sufficient     pam_companion.so
      auth       sufficient     pam_tid.so

      """
    )
    XCTAssertEqual(plan.replacedLegacyModules, ["pam_watchid.so"])
  }

  func testMigrationPreservesSupportedArgumentsFromVersionedLegacyModule() throws {
    let original = "auth sufficient /usr/local/lib/pam/pam_watchid.so.2 reason=Approve timeout=45\n"

    let plan = try PAMConfigurationPlanner.plan(original)

    XCTAssertEqual(
      plan.updated,
      "auth       sufficient     pam_companion.so reason=Approve timeout=45\n"
    )
    XCTAssertEqual(plan.replacedLegacyModules, ["pam_watchid.so.2"])
  }

  func testExistingCanonicalConfigurationIsByteForByteUnchanged() throws {
    let original = "# custom spacing\nauth  sufficient  pam_companion.so  timeout=45\n"

    let plan = try PAMConfigurationPlanner.plan(original)

    XCTAssertFalse(plan.changed)
    XCTAssertEqual(plan.updated, original)
    XCTAssertTrue(plan.replacedLegacyModules.isEmpty)
  }

  func testCommentsAndSimilarNamesAreNotTreatedAsInstalledModules() throws {
    let original = """
      # auth sufficient pam_watchid.so
      auth optional pam_watchid.so.backup

      """

    let plan = try PAMConfigurationPlanner.plan(original)

    XCTAssertEqual(
      plan.updated,
      """
      # auth sufficient pam_watchid.so
      auth       sufficient     pam_companion.so
      auth optional pam_watchid.so.backup

      """
    )
    XCTAssertTrue(plan.replacedLegacyModules.isEmpty)
  }

  func testDuplicateCompanionFamilyEntriesAreRejected() {
    let configurations = [
      "auth sufficient pam_watchid.so\nauth sufficient pam_watchid.so.2\n",
      "auth sufficient pam_companion.so\nauth sufficient pam_watchid.so\n",
      "auth sufficient pam_companion.so\nauth sufficient pam_companion.so\n",
    ]

    for configuration in configurations {
      XCTAssertThrowsError(try PAMConfigurationPlanner.plan(configuration)) { error in
        XCTAssertEqual(error as? PAMConfigurationError, .duplicateModuleEntries)
      }
    }
  }

  func testInvalidUTF8AndNulBytesAreRejected() {
    XCTAssertThrowsError(try PAMConfigurationPlanner.plan(Data([0xff])))
    XCTAssertThrowsError(try PAMConfigurationPlanner.plan(Data("auth sufficient pam_tid.so\0\n".utf8)))
  }
}

final class PAMReferenceScannerTests: XCTestCase {
  func testScannerFindsActiveLegacyReferencesIndependentlyOfFileNames() {
    let policies = [
      "/etc/pam.d/sudo_local": Data("auth sufficient pam_companion.so\n".utf8),
      "/etc/pam.d/custom": Data("auth required /usr/local/lib/pam/pam_watchid.so.2\n".utf8),
      "/etc/pam.d/commented": Data("# auth sufficient pam_watchid.so\n".utf8),
    ]

    XCTAssertEqual(
      PAMReferenceScanner.legacyReferences(in: policies),
      [PAMLegacyReference(policyPath: "/etc/pam.d/custom", module: "pam_watchid.so.2")]
    )
  }
}
