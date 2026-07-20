import Darwin
import XCTest

@testable import PAMCompanionCore

final class PAMCommandLineRunnerTests: XCTestCase {
  func testStatusIsReadOnlyAndReportsLegacyInstallation() {
    let lifecycle = StubLifecycle(status: .legacy)
    let output = RecordingOutput()
    let runner = PAMCommandLineRunner(
      lifecycle: lifecycle,
      effectiveUserID: 501,
      standardOutput: output.writeStandardOutput,
      standardError: output.writeStandardError
    )

    XCTAssertEqual(runner.run(["pam-companion", "status"]), 0)
    XCTAssertEqual(output.standardOutput, ["legacy: pam_watchid installation detected"])
    XCTAssertEqual(lifecycle.mutationCount, 0)
  }

  func testDoctorReturnsNonzeroUntilManagedConfigurationIsHealthy() {
    for status in [
      PAMLifecycleStatus.notConfigured, .legacy, .unmanaged, .recoveryRequired, .drifted,
    ] {
      let output = RecordingOutput()
      let runner = PAMCommandLineRunner(
        lifecycle: StubLifecycle(status: status),
        effectiveUserID: 501,
        standardOutput: output.writeStandardOutput,
        standardError: output.writeStandardError
      )

      XCTAssertEqual(runner.run(["pam-companion", "doctor"]), 1)
      XCTAssertTrue(output.standardError.first?.hasPrefix("error:") == true)
    }

    let output = RecordingOutput()
    let runner = PAMCommandLineRunner(
      lifecycle: StubLifecycle(status: .configured),
      effectiveUserID: 501,
      standardOutput: output.writeStandardOutput,
      standardError: output.writeStandardError
    )
    XCTAssertEqual(runner.run(["pam-companion", "doctor"]), 0)
    XCTAssertEqual(output.standardOutput, ["ok: pam_companion.so is installed and sudo_local is managed"])
  }

  func testMutationRefusesNonRootWithoutCallingLifecycleManager() {
    let lifecycle = StubLifecycle(status: .legacy)
    let output = RecordingOutput()
    let runner = PAMCommandLineRunner(
      lifecycle: lifecycle,
      effectiveUserID: 501,
      standardOutput: output.writeStandardOutput,
      standardError: output.writeStandardError
    )

    XCTAssertEqual(runner.run(["pam-companion", "setup"]), 1)
    XCTAssertEqual(output.standardError, ["pam-companion: this command must be run explicitly with sudo"])
    XCTAssertEqual(lifecycle.mutationCount, 0)
  }

  func testRootLifecycleCommandsDelegateWithoutSelfEscalation() {
    let lifecycle = StubLifecycle(status: .legacy)
    let output = RecordingOutput()
    let runner = PAMCommandLineRunner(
      lifecycle: lifecycle,
      effectiveUserID: 0,
      standardOutput: output.writeStandardOutput,
      standardError: output.writeStandardError
    )

    XCTAssertEqual(runner.run(["pam-companion", "setup", "--dry-run"]), 0)
    XCTAssertEqual(runner.run(["pam-companion", "restore"]), 0)
    XCTAssertEqual(runner.run(["pam-companion", "uninstall", "--prepare"]), 0)
    XCTAssertEqual(lifecycle.setupDryRuns, [true])
    XCTAssertEqual(lifecycle.restoreDryRuns, [false, false])
  }

  func testVersionAndUsageDoNotInspectSystemState() {
    let lifecycle = StubLifecycle(status: .drifted)
    let output = RecordingOutput()
    let runner = PAMCommandLineRunner(
      lifecycle: lifecycle,
      effectiveUserID: 501,
      standardOutput: output.writeStandardOutput,
      standardError: output.writeStandardError
    )

    XCTAssertEqual(runner.run(["pam-companion", "--version"]), 0)
    XCTAssertEqual(output.standardOutput, ["pam-companion 0.1.0"])
    XCTAssertEqual(runner.run(["pam-companion", "unknown"]), 2)
    XCTAssertEqual(lifecycle.statusCount, 0)
  }
}

private final class StubLifecycle: PAMLifecycleManaging {
  let currentStatus: PAMLifecycleStatus
  private(set) var statusCount = 0
  private(set) var setupDryRuns: [Bool] = []
  private(set) var restoreDryRuns: [Bool] = []

  var mutationCount: Int { setupDryRuns.count + restoreDryRuns.count }

  init(status: PAMLifecycleStatus) { currentStatus = status }

  func status() throws -> PAMLifecycleStatus {
    statusCount += 1
    return currentStatus
  }

  func setup(dryRun: Bool) throws -> PAMLifecycleResult {
    setupDryRuns.append(dryRun)
    return PAMLifecycleResult(changed: true, summary: "setup result")
  }

  func restore(dryRun: Bool) throws -> PAMLifecycleResult {
    restoreDryRuns.append(dryRun)
    return PAMLifecycleResult(changed: true, summary: "restore result")
  }
}

private final class RecordingOutput {
  private(set) var standardOutput: [String] = []
  private(set) var standardError: [String] = []

  func writeStandardOutput(_ value: String) { standardOutput.append(value) }
  func writeStandardError(_ value: String) { standardError.append(value) }
}
