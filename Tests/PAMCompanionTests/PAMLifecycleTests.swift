import Darwin
import Foundation
import XCTest

@testable import PAMCompanionCore

final class PAMLifecycleManagerTests: XCTestCase {
  func testSetupMigratesLegacyInstallationAndRestoreReconstructsItExactly() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let originalPolicy = try system.read(system.paths.sudoLocal)
    let originalMode = try system.mode(system.paths.sudoLocal)
    let attribute = Data("preserve me".utf8)
    try system.setExtendedAttribute(attribute, name: "dev.authcompanion.test", on: system.paths.sudoLocal)
    let manager = system.manager()

    let setup = try manager.setup(dryRun: false)

    XCTAssertTrue(setup.changed)
    XCTAssertEqual(
      try system.string(system.paths.sudoLocal),
      "# local policy\nauth       sufficient     pam_companion.so\nauth       sufficient     pam_tid.so\n"
    )
    XCTAssertEqual(try system.read(system.paths.canonicalModule), system.moduleBytes)
    XCTAssertFalse(system.exists(system.paths.legacyVersionedModule))
    XCTAssertEqual(try system.mode(system.paths.sudoLocal), originalMode)
    XCTAssertEqual(
      try system.extendedAttribute(name: "dev.authcompanion.test", on: system.paths.sudoLocal),
      attribute
    )
    XCTAssertEqual(try manager.status(), .configured)

    let restore = try manager.restore(dryRun: false)

    XCTAssertTrue(restore.changed)
    XCTAssertEqual(try system.read(system.paths.sudoLocal), originalPolicy)
    XCTAssertEqual(try system.read(system.paths.legacyVersionedModule), system.legacyBytes)
    XCTAssertEqual(
      try system.extendedAttribute(name: "dev.authcompanion.test", on: system.paths.sudoLocal),
      attribute
    )
    XCTAssertFalse(system.exists(system.paths.canonicalModule))
    XCTAssertFalse(system.exists(system.paths.stateDirectory))
    XCTAssertEqual(try manager.status(), .legacy)
  }

  func testDryRunDescribesChangeWithoutWritingAnything() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let before = try system.snapshot()

    let result = try system.manager().setup(dryRun: true)

    XCTAssertTrue(result.changed)
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testSetupRequiresExplicitRootExecution() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let before = try system.snapshot()

    XCTAssertThrowsError(try system.manager(effectiveUserID: 501).setup(dryRun: false)) { error in
      XCTAssertEqual(error as? PAMLifecycleError, .rootRequired)
    }
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testSetupRefusesWhenSudoPasswordFallbackCannotBeProven() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    try system.write("auth include sudo_local\n", to: system.paths.sudoPolicy)
    let before = try system.snapshot()

    XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
      XCTAssertEqual(error as? PAMLifecycleError, .passwordFallbackUnavailable)
    }
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testSetupRefusesToRemoveLegacyModuleReferencedByAnotherPolicy() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    try system.write(
      "auth required /usr/local/lib/pam/pam_watchid.so.2\n",
      to: system.paths.policyDirectory.appendingPathComponent("custom")
    )
    let before = try system.snapshot()

    XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
      XCTAssertEqual(
        error as? PAMLifecycleError,
        .legacyModuleStillReferenced("pam_watchid.so.2", policy: "custom")
      )
    }
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testEveryInjectedSetupFailureRollsBackExactly() throws {
    for point in PAMLifecycleFailurePoint.allCases {
      let system = try TemporaryPAMSystem()
      defer { system.remove() }
      let before = try system.snapshot()

      XCTAssertThrowsError(try system.manager(failurePoint: point).setup(dryRun: false))
      XCTAssertEqual(try system.snapshot(), before, "rollback mismatch after \(point)")
    }
  }

  func testRestoreRefusesToOverwriteManagedPolicyDrift() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let manager = system.manager()
    _ = try manager.setup(dryRun: false)
    try system.write("# user changed this after setup\n", to: system.paths.sudoLocal)

    XCTAssertThrowsError(try manager.restore(dryRun: false)) { error in
      XCTAssertEqual(error as? PAMLifecycleError, .managedStateDrift(system.paths.sudoLocal.path))
    }
  }

  func testSetupIsIdempotentWhenManagedStateIsIntact() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let manager = system.manager()
    _ = try manager.setup(dryRun: false)
    let before = try system.snapshot()

    let second = try manager.setup(dryRun: false)

    XCTAssertFalse(second.changed)
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testPreparedStateIsReportedAndCanBeRestoredAfterInterruption() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let before = try system.snapshot()
    let fileSystem = PAMLifecycleFileSystem(
      expectedOwnerUserID: getuid(),
      expectedOwnerGroupID: getgid()
    )
    let plan = try PAMConfigurationPlanner.plan(try system.read(system.paths.sudoLocal))
    try fileSystem.createStateDirectory(system.paths.stateDirectory)
    let targets = [
      (system.paths.sudoLocal, "sudo_local.original"),
      (system.paths.canonicalModule, "pam_companion.so.original"),
      (system.paths.legacyModule, "pam_watchid.so.original"),
      (system.paths.legacyVersionedModule, "pam_watchid.so.2.original"),
    ]
    let snapshots = try targets.map {
      try fileSystem.snapshot(
        $0.0,
        backupName: $0.1,
        stateDirectory: system.paths.stateDirectory
      )
    }
    let record = PAMLifecycleRecord(
      schemaVersion: 1,
      phase: .prepared,
      snapshots: snapshots,
      installedPolicySHA256: fileSystem.sha256(Data(plan.updated.utf8)),
      installedModuleSHA256: fileSystem.sha256(system.moduleBytes)
    )
    try fileSystem.writeRecord(
      record,
      to: system.paths.stateDirectory.appendingPathComponent("record.json")
    )
    try fileSystem.installModule(from: system.paths.moduleSource, to: system.paths.canonicalModule)
    try fileSystem.replacePolicy(system.paths.sudoLocal, with: Data(plan.updated.utf8))

    let manager = system.manager()
    XCTAssertEqual(try manager.status(), .recoveryRequired)
    XCTAssertTrue(try manager.restore(dryRun: false).changed)
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testSymlinkedModuleAndStateTargetsAreRejected() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let sentinel = system.root.appendingPathComponent("sentinel")
    try Data("do not touch".utf8).write(to: sentinel)
    try system.replaceWithSymbolicLink(system.paths.legacyVersionedModule, destination: sentinel)

    XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
      XCTAssertEqual(error as? PAMLifecycleError, .unsafePath(system.paths.legacyVersionedModule.path))
    }
    XCTAssertEqual(try system.read(sentinel), Data("do not touch".utf8))

    try system.replaceWithSymbolicLink(
      system.paths.stateDirectory,
      destination: system.paths.moduleDirectory
    )
    XCTAssertThrowsError(try system.manager().status()) { error in
      XCTAssertEqual(error as? PAMLifecycleError, .unsafePath(system.paths.stateDirectory.path))
    }
  }
}

private final class TemporaryPAMSystem {
  let root: URL
  let paths: PAMLifecyclePaths
  let moduleBytes = Data("new universal module".utf8)
  let legacyBytes = Data("old legacy module".utf8)
  private let fileManager = FileManager.default

  init() throws {
    root = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    paths = PAMLifecyclePaths(
      policyDirectory: root.appendingPathComponent("etc/pam.d"),
      sudoPolicy: root.appendingPathComponent("etc/pam.d/sudo"),
      sudoLocal: root.appendingPathComponent("etc/pam.d/sudo_local"),
      moduleSource: root.appendingPathComponent("cellar/libexec/pam_companion.so"),
      moduleDirectory: root.appendingPathComponent("usr/local/lib/pam"),
      stateDirectory: root.appendingPathComponent("var/db/pam-companion")
    )
    try fileManager.createDirectory(at: paths.policyDirectory, withIntermediateDirectories: true)
    try fileManager.createDirectory(at: paths.moduleDirectory, withIntermediateDirectories: true)
    try fileManager.createDirectory(
      at: paths.moduleSource.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    try fileManager.createDirectory(
      at: paths.stateDirectory.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    try write(
      "auth include sudo_local\nauth required pam_opendirectory.so\n",
      to: paths.sudoPolicy
    )
    try write(
      "# local policy\nauth       sufficient     pam_tid.so\nauth       sufficient     pam_watchid.so\n",
      to: paths.sudoLocal
    )
    try moduleBytes.write(to: paths.moduleSource)
    try legacyBytes.write(to: paths.legacyVersionedModule)
    XCTAssertEqual(chmod(paths.sudoPolicy.path, 0o444), 0)
    XCTAssertEqual(chmod(paths.sudoLocal.path, 0o444), 0)
    XCTAssertEqual(chmod(paths.moduleSource.path, 0o444), 0)
    XCTAssertEqual(chmod(paths.legacyVersionedModule.path, 0o444), 0)
  }

  func manager(
    effectiveUserID: uid_t = 0,
    failurePoint: PAMLifecycleFailurePoint? = nil
  ) -> PAMLifecycleManager {
    PAMLifecycleManager(
      paths: paths,
      effectiveUserID: effectiveUserID,
      expectedOwnerUserID: getuid(),
      expectedOwnerGroupID: getgid(),
      moduleValidator: { _ in },
      failurePoint: failurePoint
    )
  }

  func exists(_ url: URL) -> Bool { fileManager.fileExists(atPath: url.path) }

  func read(_ url: URL) throws -> Data { try Data(contentsOf: url) }

  func string(_ url: URL) throws -> String {
    try XCTUnwrap(String(data: read(url), encoding: .utf8))
  }

  func write(_ value: String, to url: URL) throws {
    let wasPresent = exists(url)
    if wasPresent { XCTAssertEqual(chmod(url.path, 0o600), 0) }
    try Data(value.utf8).write(to: url)
    if wasPresent { XCTAssertEqual(chmod(url.path, 0o444), 0) }
  }

  func mode(_ url: URL) throws -> mode_t {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    return info.st_mode & 0o777
  }

  func setExtendedAttribute(_ data: Data, name: String, on url: URL) throws {
    let originalMode = try mode(url)
    guard chmod(url.path, 0o600) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    defer { _ = chmod(url.path, originalMode) }
    let result = data.withUnsafeBytes { bytes in
      url.path.withCString { path in
        name.withCString { attribute in
          setxattr(path, attribute, bytes.baseAddress, bytes.count, 0, 0)
        }
      }
    }
    guard result == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
  }

  func extendedAttribute(name: String, on url: URL) throws -> Data {
    let size = url.path.withCString { path in
      name.withCString { attribute in getxattr(path, attribute, nil, 0, 0, 0) }
    }
    guard size >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
    var data = Data(count: size)
    let read = data.withUnsafeMutableBytes { bytes in
      url.path.withCString { path in
        name.withCString { attribute in
          getxattr(path, attribute, bytes.baseAddress, bytes.count, 0, 0)
        }
      }
    }
    guard read == size else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
    return data
  }

  func snapshot() throws -> [String: Data] {
    guard exists(root) else { return [:] }
    let enumerator = try XCTUnwrap(fileManager.enumerator(at: root, includingPropertiesForKeys: nil))
    var result: [String: Data] = [:]
    for case let url as URL in enumerator where !url.hasDirectoryPath {
      result[String(url.path.dropFirst(root.path.count))] = try Data(contentsOf: url)
    }
    return result
  }

  func remove() { try? fileManager.removeItem(at: root) }

  func replaceWithSymbolicLink(_ url: URL, destination: URL) throws {
    if exists(url) { try fileManager.removeItem(at: url) }
    try fileManager.createSymbolicLink(at: url, withDestinationURL: destination)
  }
}
