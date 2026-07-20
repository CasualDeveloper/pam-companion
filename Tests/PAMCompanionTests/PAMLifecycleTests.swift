import Darwin
import Foundation
import XCTest

@testable import PAMCompanionCore

final class PAMLifecycleManagerTests: XCTestCase {
  func testTransactionalMetadataExcludesOnlyPathManagedAppleProvenance() {
    let provenance = Data([0x01, 0x02, 0x00])
    let custom = Data("preserve me".utf8)

    XCTAssertEqual(
      PAMFileMetadata.trackedExtendedAttributes([
        "com.apple.provenance": provenance,
        "dev.authcompanion.test": custom,
      ]),
      ["dev.authcompanion.test": custom]
    )
  }

  func testPreparedSchemaTwoJournalContainingProvenanceCanBeRestored() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let before = try system.snapshot()
    let prepared = try system.makePreparedRecord()
    let provenance = Data([0x01, 0x02, 0x00, 0x94])
    func addingProvenance(_ metadata: PAMFileMetadata?) -> PAMFileMetadata? {
      guard let metadata else { return nil }
      var attributes = metadata.extendedAttributes
      attributes["com.apple.provenance"] = provenance
      return PAMFileMetadata(
        mode: metadata.mode,
        ownerUserID: metadata.ownerUserID,
        ownerGroupID: metadata.ownerGroupID,
        flags: metadata.flags,
        extendedAttributes: attributes
      )
    }
    let legacyRecord = PAMLifecycleRecord(
      schemaVersion: prepared.schemaVersion,
      phase: prepared.phase,
      snapshots: prepared.snapshots.map { snapshot in
        PAMLifecycleSnapshot(
          path: snapshot.path,
          backupName: snapshot.backupName,
          existed: snapshot.existed,
          originalSHA256: snapshot.originalSHA256,
          metadata: addingProvenance(snapshot.metadata)
        )
      },
      installedPolicySHA256: prepared.installedPolicySHA256,
      installedModuleSHA256: prepared.installedModuleSHA256,
      installedPolicyMetadata: addingProvenance(prepared.installedPolicyMetadata),
      installedModuleMetadata: addingProvenance(prepared.installedModuleMetadata)
    )
    try system.fileSystem.writeRecord(
      legacyRecord,
      to: system.paths.stateDirectory.appendingPathComponent("record.json")
    )

    XCTAssertTrue(try system.manager().restore(dryRun: false).changed)
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testSetupMigratesLegacyInstallationAndRestoresTrackedStateAndOriginalInodes() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let originalPolicy = try system.read(system.paths.sudoLocal)
    let originalMode = try system.mode(system.paths.sudoLocal)
    let originalIdentity = try system.fileIdentity(system.paths.sudoLocal)
    let attribute = Data("preserve me".utf8)
    try system.setExtendedAttribute(
      attribute, name: "dev.authcompanion.test", on: system.paths.sudoLocal)
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
      try system.fileIdentity(
        system.backupURL(for: system.paths.sudoLocal)),
      originalIdentity
    )
    XCTAssertEqual(
      try system.extendedAttribute(name: "dev.authcompanion.test", on: system.paths.sudoLocal),
      attribute
    )
    XCTAssertEqual(try manager.status(), .configured)

    let restore = try manager.restore(dryRun: false)

    XCTAssertTrue(restore.changed)
    XCTAssertEqual(try system.read(system.paths.sudoLocal), originalPolicy)
    XCTAssertEqual(try system.fileIdentity(system.paths.sudoLocal), originalIdentity)
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

  func testSetupInstallsTheExactModuleBytesValidatedFromOneDescriptor() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let replacement = Data("path was replaced after validation began".utf8)
    let manager = system.manager(moduleValidator: { _ in
      try system.replaceModuleSource(with: replacement)
    })

    _ = try manager.setup(dryRun: false)

    XCTAssertEqual(try system.read(system.paths.canonicalModule), system.moduleBytes)
    XCTAssertEqual(try system.read(system.paths.moduleSource), replacement)
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
    let unsupportedPolicies = [
      "auth include sudo_local\n",
      "auth include sudo_local\nauth required pam_deny.so\n",
      "auth include sudo_local\nauth required pam_permit.so\n",
      "auth include sudo_local\nauth sufficient pam_smartcard.so\n",
      "auth include nested\nauth required pam_opendirectory.so\n",
      "auth required pam_opendirectory.so\nauth include sudo_local\n",
      "auth include sudo_local\nauth requisite pam_opendirectory.so\n",
      "auth include sudo_local\nauth required pam_opendirectory.so\nauth required pam_deny.so\n",
    ]
    for policy in unsupportedPolicies {
      let system = try TemporaryPAMSystem()
      defer { system.remove() }
      try system.write(policy, to: system.paths.sudoPolicy)
      let before = try system.snapshot()

      XCTAssertThrowsError(try system.manager().setup(dryRun: false), policy) { error in
        XCTAssertEqual(error as? PAMLifecycleError, .passwordFallbackUnavailable)
      }
      XCTAssertEqual(try system.snapshot(), before)
    }
  }

  func testSetupAcceptsCurrentMacOSSudoPasswordFallbackShape() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    try system.write(
      """
      # sudo: auth account password session
      auth       include        sudo_local
      auth       sufficient     pam_smartcard.so
      auth       required       pam_opendirectory.so
      account    required       pam_permit.so
      password   required       pam_deny.so
      session    required       pam_permit.so

      """,
      to: system.paths.sudoPolicy
    )

    XCTAssertTrue(try system.manager().setup(dryRun: true).changed)
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

  func testEveryInjectedSetupFailureRollsBackTrackedState() throws {
    for point in PAMLifecycleFailurePoint.setupCases {
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
    let record = try system.makePreparedRecord()
    try system.installPreparedCanonicalAndPolicy(record)

    let manager = system.manager()
    XCTAssertEqual(try manager.status(), .recoveryRequired)
    XCTAssertTrue(try manager.restore(dryRun: false).changed)
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testPreparingStateCanBeRestoredBeforeAnyPAMMutation() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let before = try system.snapshot()
    let fileSystem = system.fileSystem
    try fileSystem.createStateDirectory(system.paths.stateDirectory)
    let targets = [
      (system.paths.sudoLocal, system.backupName(for: system.paths.sudoLocal)),
      (system.paths.canonicalModule, system.backupName(for: system.paths.canonicalModule)),
      (system.paths.legacyModule, system.backupName(for: system.paths.legacyModule)),
      (
        system.paths.legacyVersionedModule,
        system.backupName(for: system.paths.legacyVersionedModule)
      ),
    ]
    let snapshots = try targets.map {
      try fileSystem.snapshot($0.0, backupName: $0.1)
    }
    let plan = try PAMConfigurationPlanner.plan(try system.read(system.paths.sudoLocal))
    let record = PAMLifecycleRecord(
      schemaVersion: 2,
      phase: .preparing,
      snapshots: snapshots,
      installedPolicySHA256: fileSystem.sha256(Data(plan.updated.utf8)),
      installedModuleSHA256: fileSystem.sha256(system.moduleBytes),
      installedPolicyMetadata: nil,
      installedModuleMetadata: nil
    )
    try fileSystem.writeRecord(
      record,
      to: system.paths.stateDirectory.appendingPathComponent("record.json")
    )
    try fileSystem.stageModule(
      system.moduleBytes,
      at: system.stagedURL(for: system.paths.canonicalModule)
    )

    let manager = system.manager()
    XCTAssertEqual(try manager.status(), .recoveryRequired)
    XCTAssertTrue(try manager.restore(dryRun: false).changed)
    XCTAssertEqual(try system.snapshot(), before)
  }

  func testRestoreResumesAfterEveryDurableRestoreFailurePoint() throws {
    for point in PAMLifecycleFailurePoint.restoreCases {
      let system = try TemporaryPAMSystem()
      defer { system.remove() }
      let before = try system.snapshot()
      _ = try system.manager().setup(dryRun: false)

      XCTAssertThrowsError(
        try system.manager(failurePoint: point).restore(dryRun: false), "\(point)")
      XCTAssertEqual(try system.manager().status(), .recoveryRequired, "\(point)")
      XCTAssertTrue(try system.manager().restore(dryRun: false).changed, "\(point)")
      XCTAssertEqual(try system.snapshot(), before, "restore mismatch after \(point)")
    }
  }

  func testPreparedRecoveryRefusesInterveningAdministratorChanges() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    try system.makePreparedRecord()
    try system.write("# administrator repair\n", to: system.paths.sudoLocal)

    XCTAssertThrowsError(try system.manager().restore(dryRun: false)) { error in
      XCTAssertEqual(error as? PAMLifecycleError, .managedStateDrift(system.paths.sudoLocal.path))
    }
  }

  func testPreparedRecoveryRefusesInterveningExtendedAttributeChanges() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    try system.makePreparedRecord()
    try system.setExtendedAttribute(
      Data("administrator changed metadata".utf8),
      name: "dev.authcompanion.drift",
      on: system.paths.sudoLocal
    )

    XCTAssertThrowsError(try system.manager().restore(dryRun: false)) { error in
      XCTAssertEqual(error as? PAMLifecycleError, .managedStateDrift(system.paths.sudoLocal.path))
    }
  }

  func testInterruptedRecoveryRefusesTransactionalExtendedAttributeChanges() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let record = try system.makePreparedRecord()
    try system.installPreparedCanonicalAndPolicy(record)
    try system.setExtendedAttribute(
      Data("administrator changed managed metadata".utf8),
      name: "dev.authcompanion.managed-drift",
      on: system.paths.sudoLocal
    )

    XCTAssertThrowsError(try system.manager().restore(dryRun: false)) { error in
      XCTAssertEqual(error as? PAMLifecycleError, .managedStateDrift(system.paths.sudoLocal.path))
    }
  }

  func testCompletedSetupRejectsADeletedOriginalBackup() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let manager = system.manager()
    _ = try manager.setup(dryRun: false)
    try FileManager.default.removeItem(
      at: system.backupURL(for: system.paths.sudoLocal))

    XCTAssertThrowsError(try manager.status()) { error in
      XCTAssertEqual(
        error as? PAMLifecycleError,
        .invalidState("missing backup: .sudo_local.pam-companion.original")
      )
    }
  }

  func testOrphanedLifecycleSiblingIsRejectedWithoutAJournal() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let orphan = system.stagedURL(for: system.paths.canonicalModule)
    try system.moduleBytes.write(to: orphan)

    XCTAssertThrowsError(try system.manager().status()) { error in
      XCTAssertEqual(
        error as? PAMLifecycleError,
        .invalidState("unexpected lifecycle file without a transaction: \(orphan.path)")
      )
    }
    XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
      XCTAssertEqual(
        error as? PAMLifecycleError,
        .invalidState("unexpected lifecycle file without a transaction: \(orphan.path)")
      )
    }
  }

  func testSymlinkedModuleAndStateTargetsAreRejected() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let sentinel = system.root.appendingPathComponent("sentinel")
    try Data("do not touch".utf8).write(to: sentinel)
    try system.replaceWithSymbolicLink(system.paths.legacyVersionedModule, destination: sentinel)

    XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
      XCTAssertEqual(
        error as? PAMLifecycleError, .unsafePath(system.paths.legacyVersionedModule.path))
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

  func testACLsImmutableFlagsAndHardLinksAreRejected() throws {
    do {
      let system = try TemporaryPAMSystem()
      defer { system.remove() }
      try system.addWriteACL(to: system.paths.sudoLocal)
      XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
        XCTAssertEqual(error as? PAMLifecycleError, .unsafePath(system.paths.sudoLocal.path))
      }
    }

    do {
      let system = try TemporaryPAMSystem()
      defer {
        try? system.clearFlags(on: system.paths.sudoLocal)
        system.remove()
      }
      try system.makeImmutable(system.paths.sudoLocal)
      XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
        XCTAssertEqual(error as? PAMLifecycleError, .unsafePath(system.paths.sudoLocal.path))
      }
    }

    do {
      let system = try TemporaryPAMSystem()
      defer { system.remove() }
      let alias = system.root.appendingPathComponent("legacy-hard-link")
      try FileManager.default.linkItem(at: system.paths.legacyVersionedModule, to: alias)
      XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
        XCTAssertEqual(
          error as? PAMLifecycleError, .unsafePath(system.paths.legacyVersionedModule.path))
      }
    }
  }

  func testWritablePrivilegedAncestorIsRejected() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    XCTAssertEqual(chmod(system.root.path, 0o777), 0)

    XCTAssertThrowsError(try system.manager().setup(dryRun: false)) { error in
      guard let lifecycleError = error as? PAMLifecycleError,
        case .unsafePath = lifecycleError
      else {
        return XCTFail("expected unsafePath, received \(error)")
      }
    }
  }

  func testFailedLockContenderCannotUnlinkTheActiveLock() throws {
    let system = try TemporaryPAMSystem()
    defer { system.remove() }
    let fileSystem = system.fileSystem

    try fileSystem.withLock(system.paths.lock) {
      XCTAssertThrowsError(try fileSystem.withLock(system.paths.lock) {})
      XCTAssertTrue(system.exists(system.paths.lock))
      XCTAssertThrowsError(try fileSystem.withLock(system.paths.lock) {})
    }
    XCTAssertTrue(system.exists(system.paths.lock))
  }
}

final class SystemPAMModuleValidatorTests: XCTestCase {
  func testRequiresAdHocHardenedRuntimeSignatureDetails() throws {
    XCTAssertNoThrow(
      try SystemPAMModuleValidator.validateSignatureDetails(
        "Signature=adhoc\nCodeDirectory v=20500 flags=0x10002(adhoc,runtime)\n"
      )
    )
    let rejected = [
      "Signature=adhoc\nCodeDirectory v=20500 flags=0x2(adhoc)\n",
      "Authority=Developer ID Application: Example\nCodeDirectory flags=0x10000(runtime)\n",
    ]
    for details in rejected {
      XCTAssertThrowsError(try SystemPAMModuleValidator.validateSignatureDetails(details))
    }
  }
}

private final class TemporaryPAMSystem {
  let root: URL
  let paths: PAMLifecyclePaths
  let moduleBytes = Data("new universal module".utf8)
  let legacyBytes = Data("old legacy module".utf8)
  private let fileManager = FileManager.default

  var fileSystem: PAMLifecycleFileSystem {
    PAMLifecycleFileSystem(expectedOwnerUserID: getuid(), expectedOwnerGroupID: getgid())
  }

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
    failurePoint: PAMLifecycleFailurePoint? = nil,
    moduleValidator: ((URL) throws -> Void)? = nil
  ) -> PAMLifecycleManager {
    PAMLifecycleManager(
      paths: paths,
      effectiveUserID: effectiveUserID,
      expectedOwnerUserID: getuid(),
      expectedOwnerGroupID: getgid(),
      moduleValidator: moduleValidator ?? { _ in },
      failurePoint: failurePoint
    )
  }

  @discardableResult
  func makePreparedRecord() throws -> PAMLifecycleRecord {
    let plan = try PAMConfigurationPlanner.plan(try read(paths.sudoLocal))
    try fileSystem.createStateDirectory(paths.stateDirectory)
    let targets = [
      (paths.sudoLocal, backupName(for: paths.sudoLocal)),
      (paths.canonicalModule, backupName(for: paths.canonicalModule)),
      (paths.legacyModule, backupName(for: paths.legacyModule)),
      (paths.legacyVersionedModule, backupName(for: paths.legacyVersionedModule)),
    ]
    let snapshots = try targets.map {
      try fileSystem.snapshot($0.0, backupName: $0.1)
    }
    let stagedModule = stagedURL(for: paths.canonicalModule)
    let stagedPolicy = stagedURL(for: paths.sudoLocal)
    try fileSystem.stageModule(moduleBytes, at: stagedModule)
    try fileSystem.stagePolicy(
      Data(plan.updated.utf8),
      at: stagedPolicy,
      preserving: paths.sudoLocal
    )
    let record = PAMLifecycleRecord(
      schemaVersion: 2,
      phase: .prepared,
      snapshots: snapshots,
      installedPolicySHA256: fileSystem.sha256(Data(plan.updated.utf8)),
      installedModuleSHA256: fileSystem.sha256(moduleBytes),
      installedPolicyMetadata: try fileSystem.metadata(stagedPolicy),
      installedModuleMetadata: try fileSystem.metadata(stagedModule)
    )
    try fileSystem.writeRecord(
      record, to: paths.stateDirectory.appendingPathComponent("record.json"))
    return record
  }

  func installPreparedCanonicalAndPolicy(_ record: PAMLifecycleRecord) throws {
    let canonical = try XCTUnwrap(
      record.snapshots.first(where: { $0.path == paths.canonicalModule.path }))
    let policy = try XCTUnwrap(
      record.snapshots.first(where: { $0.path == paths.sudoLocal.path }))
    let moduleMetadata = try XCTUnwrap(record.installedModuleMetadata)
    let policyMetadata = try XCTUnwrap(record.installedPolicyMetadata)
    let stagedModule = stagedURL(for: paths.canonicalModule)
    let stagedPolicy = stagedURL(for: paths.sudoLocal)
    try fileSystem.moveOriginalToBackup(canonical, in: paths.stateDirectory)
    try fileSystem.moveStagedFile(
      stagedModule,
      to: paths.canonicalModule,
      sha256: record.installedModuleSHA256,
      metadata: moduleMetadata
    )
    try fileSystem.moveOriginalToBackup(policy, in: paths.stateDirectory)
    try fileSystem.moveStagedFile(
      stagedPolicy,
      to: paths.sudoLocal,
      sha256: record.installedPolicySHA256,
      metadata: policyMetadata
    )
  }

  func replaceModuleSource(with data: Data) throws {
    try fileManager.removeItem(at: paths.moduleSource)
    try data.write(to: paths.moduleSource)
    XCTAssertEqual(chmod(paths.moduleSource.path, 0o444), 0)
  }

  func backupName(for target: URL) -> String {
    ".\(target.lastPathComponent).pam-companion.original"
  }

  func backupURL(for target: URL) -> URL {
    target.deletingLastPathComponent().appendingPathComponent(backupName(for: target))
  }

  func stagedURL(for target: URL) -> URL {
    target.deletingLastPathComponent()
      .appendingPathComponent(".\(target.lastPathComponent).pam-companion.pending")
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

  func fileIdentity(_ url: URL) throws -> String {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    return "\(info.st_dev):\(info.st_ino)"
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
    let enumerator = try XCTUnwrap(
      fileManager.enumerator(at: root, includingPropertiesForKeys: nil))
    var result: [String: Data] = [:]
    for case let url as URL in enumerator
    where !url.hasDirectoryPath && url.lastPathComponent != "pam-companion.lock" {
      result[String(url.path.dropFirst(root.path.count))] = try Data(contentsOf: url)
    }
    return result
  }

  func remove() { try? fileManager.removeItem(at: root) }

  func replaceWithSymbolicLink(_ url: URL, destination: URL) throws {
    if exists(url) { try fileManager.removeItem(at: url) }
    try fileManager.createSymbolicLink(at: url, withDestinationURL: destination)
  }
  func addWriteACL(to url: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", "everyone allow write", url.path]
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(process.terminationStatus))
    }
  }

  func makeImmutable(_ url: URL) throws {
    guard chflags(url.path, UInt32(UF_IMMUTABLE)) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
  }

  func clearFlags(on url: URL) throws {
    guard chflags(url.path, 0) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
  }
}
