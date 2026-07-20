import Darwin
import Foundation

public final class PAMLifecycleManager: PAMLifecycleManaging {
  private let paths: PAMLifecyclePaths
  private let effectiveUserID: uid_t
  private let fileSystem: PAMLifecycleFileSystem
  private let failurePoint: PAMLifecycleFailurePoint?

  public convenience init(paths: PAMLifecyclePaths) {
    self.init(
      paths: paths,
      effectiveUserID: geteuid(),
      expectedOwnerUserID: 0,
      expectedOwnerGroupID: 0,
      failurePoint: nil
    )
  }

  init(
    paths: PAMLifecyclePaths,
    effectiveUserID: uid_t,
    expectedOwnerUserID: uid_t,
    expectedOwnerGroupID: gid_t,
    failurePoint: PAMLifecycleFailurePoint?
  ) {
    self.paths = paths
    self.effectiveUserID = effectiveUserID
    fileSystem = PAMLifecycleFileSystem(
      expectedOwnerUserID: expectedOwnerUserID,
      expectedOwnerGroupID: expectedOwnerGroupID
    )
    self.failurePoint = failurePoint
  }

  public func status() throws -> PAMLifecycleStatus {
    if fileSystem.exists(paths.stateDirectory) {
      if try recoverablePreJournalStateDirectoryExists() { return .recoveryRequired }
      let record = try loadRecord()
      guard record.phase == .complete else { return .recoveryRequired }
      guard try managedStateMatches(record) else { return .drifted }
      try fileSystem.validateRegularRootTarget(paths.sudoPolicy)
      do {
        try verifyPasswordFallback(fileSystem.read(paths.sudoPolicy))
      } catch PAMLifecycleError.passwordFallbackUnavailable {
        return .drifted
      }
      return record.schemaVersion == 3 ? .configured : .legacy
    }
    try validateNoOrphanedLifecycleFiles()

    let policy = fileSystem.exists(paths.sudoLocal) ? try fileSystem.read(paths.sudoLocal) : Data()
    let names = activeModuleNames(in: policy)
    if names.contains(where: PAMConfigurationPlanner.removableModules.contains)
      || fileSystem.exists(paths.customModule)
      || fileSystem.exists(paths.legacyModule)
      || fileSystem.exists(paths.legacyVersionedModule)
    {
      return .legacy
    }
    if names.contains(PAMConfigurationPlanner.nativeModule) {
      return .unmanaged
    }
    return .notConfigured
  }

  public func setup(dryRun: Bool) throws -> PAMLifecycleResult {
    try requireRoot()
    if dryRun {
      let preparation = try prepareSetup()
      if preparation.alreadyConfigured {
        return PAMLifecycleResult(changed: false, summary: "pam-companion is already configured")
      }
      return PAMLifecycleResult(
        changed: true, summary: "would enable the native pam_tid.so sudo integration")
    }
    return try fileSystem.withLock(paths.lock) {
      let preparation = try prepareSetup()
      guard !preparation.alreadyConfigured else {
        return PAMLifecycleResult(changed: false, summary: "pam-companion is already configured")
      }
      if let record = preparation.recordToReplace {
        try replaceManagedSetup(record)
      }
      return try performSetup(try prepareSetup())
    }
  }

  public func restore(dryRun: Bool) throws -> PAMLifecycleResult {
    try requireRoot()
    guard fileSystem.exists(paths.stateDirectory) else {
      return PAMLifecycleResult(
        changed: false, summary: "pam-companion has no managed setup to restore")
    }
    if try recoverablePreJournalStateDirectoryExists() {
      if dryRun {
        return PAMLifecycleResult(
          changed: true,
          summary: "would remove an incomplete pre-mutation lifecycle state"
        )
      }
      return try fileSystem.withLock(paths.lock) {
        guard try recoverablePreJournalStateDirectoryExists() else {
          throw PAMLifecycleError.recoveryRequired
        }
        try fileSystem.removeTree(paths.stateDirectory)
        return PAMLifecycleResult(
          changed: true,
          summary: "removed an incomplete pre-mutation lifecycle state; PAM was unchanged"
        )
      }
    }
    let record = try loadRecord()
    try verifyRecoverableState(record)
    if dryRun {
      return PAMLifecycleResult(
        changed: true, summary: "would restore the pre-setup PAM configuration")
    }
    return try fileSystem.withLock(paths.lock) {
      var lockedRecord = try loadRecord()
      try verifyRecoverableState(lockedRecord)
      if lockedRecord.phase != .restoring {
        lockedRecord.phase = .restoring
        try fileSystem.writeRecord(lockedRecord, to: recordURL)
      }
      try failIfRequested(.afterRestoreStarted)
      try restoreSnapshots(lockedRecord, injectingFailures: true)
      try failIfRequested(.beforeStateCleanup)
      try fileSystem.removeTree(paths.stateDirectory)
      return PAMLifecycleResult(changed: true, summary: "restored the pre-setup PAM configuration")
    }
  }

  private var recordURL: URL { paths.stateDirectory.appendingPathComponent("record.json") }
  private var stagedModuleURL: URL { stagedURL(for: paths.customModule) }
  private var stagedPolicyURL: URL { stagedURL(for: paths.sudoLocal) }

  private struct SetupPreparation {
    let policyPlan: PAMConfigurationPlan
    let alreadyConfigured: Bool
    let recordToReplace: PAMLifecycleRecord?
  }

  private func prepareSetup() throws -> SetupPreparation {
    try fileSystem.validateDirectory(paths.policyDirectory)
    try fileSystem.validateDirectory(paths.stateDirectory.deletingLastPathComponent())
    try fileSystem.validateRegularRootTarget(paths.sudoPolicy)
    try fileSystem.validateRegularRootTarget(paths.sudoLocal)
    if fileSystem.exists(paths.stateDirectory) {
      if try recoverablePreJournalStateDirectoryExists() {
        throw PAMLifecycleError.recoveryRequired
      }
      let record = try loadRecord()
      guard record.phase == .complete else { throw PAMLifecycleError.recoveryRequired }
      guard try managedStateMatches(record) else {
        throw PAMLifecycleError.managedStateDrift(paths.sudoLocal.path)
      }
      let plan = try PAMConfigurationPlanner.plan(fileSystem.read(paths.sudoLocal))
      let currentContract = record.schemaVersion == 3 && !plan.changed
      try verifyPasswordFallback(fileSystem.read(paths.sudoPolicy))
      if !currentContract {
        try verifyNoExternalReferences(removingWith: plan.updated)
      }
      return SetupPreparation(
        policyPlan: plan,
        alreadyConfigured: currentContract,
        recordToReplace: currentContract ? nil : record
      )
    }

    try validateNoOrphanedLifecycleFiles()
    try verifyPasswordFallback(fileSystem.read(paths.sudoPolicy))
    for module in [paths.customModule, paths.legacyModule, paths.legacyVersionedModule]
    where fileSystem.exists(module) {
      try fileSystem.validateRegularRootTarget(module)
    }
    let plan = try PAMConfigurationPlanner.plan(fileSystem.read(paths.sudoLocal))
    try verifyNoExternalReferences(removingWith: plan.updated)
    return SetupPreparation(
      policyPlan: plan,
      alreadyConfigured: false,
      recordToReplace: nil
    )
  }

  private func verifyNoExternalReferences(removingWith updatedPolicy: String) throws {
    var policies = try fileSystem.policyFiles(in: paths.policyDirectory)
    let lifecyclePolicyNames = [
      paths.sudoLocal.lastPathComponent,
      backupName(for: paths.sudoLocal),
      stagedPolicyURL.lastPathComponent,
    ]
    for path in policies.keys
    where lifecyclePolicyNames.contains(URL(fileURLWithPath: path).lastPathComponent) {
      policies.removeValue(forKey: path)
    }
    policies[paths.sudoLocal.path] = Data(updatedPolicy.utf8)
    var references = try PAMReferenceScanner.removableReferences(in: policies)
    if fileSystem.exists(paths.localPolicyDirectory) {
      try fileSystem.validateDirectory(paths.localPolicyDirectory)
      references += try PAMReferenceScanner.removableReferences(
        in: fileSystem.policyFiles(in: paths.localPolicyDirectory))
    }
    var globalPolicies: [String: Data] = [:]
    for pamConf in [paths.pamConf, paths.localPamConf] where fileSystem.exists(pamConf) {
      try fileSystem.validateRegularRootTarget(pamConf)
      globalPolicies[pamConf.path] = try fileSystem.read(pamConf)
    }
    references += try PAMReferenceScanner.pamConfReferences(in: globalPolicies)
    if let reference = references.sorted().first {
      throw PAMLifecycleError.legacyModuleStillReferenced(
        reference.module,
        policy: URL(fileURLWithPath: reference.policyPath).lastPathComponent
      )
    }
  }

  private func replaceManagedSetup(_ record: PAMLifecycleRecord) throws {
    var restoring = record
    restoring.phase = .restoring
    try fileSystem.writeRecord(restoring, to: recordURL)
    try failIfRequested(.afterRestoreStarted)
    try restoreSnapshots(restoring, injectingFailures: true)
    try failIfRequested(.beforeStateCleanup)
    try fileSystem.removeTree(paths.stateDirectory)
  }

  private func performSetup(_ preparation: SetupPreparation) throws -> PAMLifecycleResult {
    var record: PAMLifecycleRecord?
    do {
      try fileSystem.createStateDirectory(paths.stateDirectory)
      let policySnapshot = try fileSystem.snapshot(
        paths.sudoLocal,
        backupName: backupName(for: paths.sudoLocal)
      )
      let canonicalSnapshot = try fileSystem.snapshot(
        paths.customModule,
        backupName: backupName(for: paths.customModule)
      )
      let legacySnapshot = try fileSystem.snapshot(
        paths.legacyModule,
        backupName: backupName(for: paths.legacyModule)
      )
      let versionedLegacySnapshot = try fileSystem.snapshot(
        paths.legacyVersionedModule,
        backupName: backupName(for: paths.legacyVersionedModule)
      )
      let snapshots = [
        policySnapshot,
        canonicalSnapshot,
        legacySnapshot,
        versionedLegacySnapshot,
      ]
      var preparedRecord = PAMLifecycleRecord(
        schemaVersion: 3,
        phase: .preparing,
        snapshots: snapshots,
        installedPolicySHA256: fileSystem.sha256(Data(preparation.policyPlan.updated.utf8)),
        installedModuleSHA256: nil,
        installedPolicyMetadata: nil,
        installedModuleMetadata: nil
      )
      try fileSystem.writeRecord(preparedRecord, to: recordURL)
      record = preparedRecord

      try fileSystem.stagePolicy(
        Data(preparation.policyPlan.updated.utf8),
        at: stagedPolicyURL,
        preserving: paths.sudoLocal
      )
      let stagedPolicyMetadata = try fileSystem.metadata(stagedPolicyURL)
      preparedRecord.installedPolicyMetadata = stagedPolicyMetadata
      preparedRecord.phase = .prepared
      try fileSystem.writeRecord(preparedRecord, to: recordURL)
      record = preparedRecord
      try failIfRequested(.afterStatePrepared)

      try fileSystem.moveOriginalToBackup(policySnapshot, in: paths.stateDirectory)
      try failIfRequested(.afterPolicyBackedUp)
      try fileSystem.moveStagedFile(
        stagedPolicyURL,
        to: paths.sudoLocal,
        sha256: preparedRecord.installedPolicySHA256,
        metadata: stagedPolicyMetadata
      )
      try failIfRequested(.afterPolicyInstalled)

      try fileSystem.moveOriginalToBackup(canonicalSnapshot, in: paths.stateDirectory)
      try failIfRequested(.afterCanonicalBackedUp)
      try fileSystem.moveOriginalToBackup(legacySnapshot, in: paths.stateDirectory)
      try failIfRequested(.afterLegacyBackedUp)
      try fileSystem.moveOriginalToBackup(versionedLegacySnapshot, in: paths.stateDirectory)
      try failIfRequested(.afterVersionedLegacyBackedUp)
      try failIfRequested(.afterLegacyRemoved)

      preparedRecord.phase = .complete
      try fileSystem.writeRecord(preparedRecord, to: recordURL)
      return PAMLifecycleResult(
        changed: true, summary: "enabled the native pam_tid.so sudo integration")
    } catch {
      guard let record else {
        try? fileSystem.removeTree(paths.stateDirectory)
        throw error
      }
      do {
        try restoreSnapshots(record, injectingFailures: false)
        try fileSystem.removeTree(paths.stateDirectory)
      } catch {
        throw PAMLifecycleError.rollbackFailed(String(describing: error))
      }
      throw error
    }
  }

  private func restoreSnapshots(
    _ record: PAMLifecycleRecord,
    injectingFailures: Bool
  ) throws {
    try verifyRecoverableState(record)
    let policyPath = paths.sudoLocal.path
    for snapshot in record.snapshots where snapshot.path != policyPath {
      try verifyRecoverableSnapshot(snapshot, record: record)
      try fileSystem.restore(snapshot, from: paths.stateDirectory)
      if injectingFailures {
        try failIfRequested(restoreFailurePoint(for: snapshot.path))
      }
    }
    if let policy = record.snapshots.first(where: { $0.path == policyPath }) {
      try verifyRecoverableSnapshot(policy, record: record)
      try fileSystem.restore(policy, from: paths.stateDirectory)
      if injectingFailures { try failIfRequested(.afterPolicyRestored) }
    }
    try cleanupStagedFiles(record)
  }

  private func restoreFailurePoint(for path: String) -> PAMLifecycleFailurePoint {
    switch path {
    case paths.customModule.path: .afterCanonicalRestored
    case paths.legacyModule.path: .afterLegacyRestored
    case paths.legacyVersionedModule.path: .afterVersionedLegacyRestored
    default: .afterPolicyRestored
    }
  }

  private func loadRecord() throws -> PAMLifecycleRecord {
    try fileSystem.validateStateDirectory(paths.stateDirectory)
    try fileSystem.validateRecordFile(recordURL)
    let record = try fileSystem.readRecord(from: recordURL)
    let expected = [
      (paths.sudoLocal.path, backupName(for: paths.sudoLocal)),
      (paths.customModule.path, backupName(for: paths.customModule)),
      (paths.legacyModule.path, backupName(for: paths.legacyModule)),
      (paths.legacyVersionedModule.path, backupName(for: paths.legacyVersionedModule)),
    ]
    let supportedSchema = record.schemaVersion == 2 || record.schemaVersion == 3
    let validModuleHash =
      record.schemaVersion == 2
      ? record.installedModuleSHA256.map(isSHA256) == true
      : record.installedModuleSHA256 == nil
    guard supportedSchema,
      record.snapshots.count == expected.count,
      zip(record.snapshots, expected).allSatisfy({ snapshot, value in
        snapshot.path == value.0 && snapshot.backupName == value.1
      }),
      isSHA256(record.installedPolicySHA256),
      validModuleHash
    else {
      throw PAMLifecycleError.invalidState("record does not match the supported lifecycle paths")
    }
    for snapshot in record.snapshots {
      let backup = fileSystem.backupURL(for: snapshot)
      let hasOriginalSHA256 = snapshot.originalSHA256 != nil
      let hasMetadata = snapshot.metadata != nil
      guard snapshot.existed == hasOriginalSHA256,
        snapshot.existed == hasMetadata,
        snapshot.originalSHA256.map(isSHA256) ?? true
      else {
        throw PAMLifecycleError.invalidState("invalid snapshot: \(snapshot.path)")
      }
      if fileSystem.exists(backup) {
        guard snapshot.existed, record.phase != .preparing else {
          throw PAMLifecycleError.invalidState("unexpected backup: \(snapshot.backupName)")
        }
        try fileSystem.validateOriginal(snapshot, at: backup)
      } else if record.phase == .complete, snapshot.existed {
        throw PAMLifecycleError.invalidState("missing backup: \(snapshot.backupName)")
      }
    }
    let hasPolicyMetadata = record.installedPolicyMetadata != nil
    let hasModuleMetadata = record.installedModuleMetadata != nil
    guard record.schemaVersion == 2 || !hasModuleMetadata else {
      throw PAMLifecycleError.invalidState("transactional metadata is incomplete")
    }
    switch record.phase {
    case .preparing:
      guard !hasPolicyMetadata else {
        throw PAMLifecycleError.invalidState("preparing state contains transactional metadata")
      }
    case .prepared, .complete:
      guard hasPolicyMetadata, record.schemaVersion == 3 || hasModuleMetadata else {
        throw PAMLifecycleError.invalidState("transactional metadata is missing")
      }
    case .restoring:
      break
    }
    try validateStagedFiles(record)
    return record
  }

  private func isSHA256(_ value: String) -> Bool {
    value.count == 64
      && value.utf8.allSatisfy { byte in
        (48...57).contains(byte) || (97...102).contains(byte)
      }
  }

  private func managedStateMatches(_ record: PAMLifecycleRecord) throws -> Bool {
    guard fileSystem.exists(paths.sudoLocal),
      let policyMetadata = record.installedPolicyMetadata
    else {
      return false
    }
    let policyMatches = try fileSystem.managedFileMatches(
      at: paths.sudoLocal,
      sha256: record.installedPolicySHA256,
      metadata: policyMetadata
    )
    let moduleMatches: Bool
    if record.schemaVersion == 2,
      let moduleSHA256 = record.installedModuleSHA256,
      let moduleMetadata = record.installedModuleMetadata
    {
      moduleMatches =
        try fileSystem.exists(paths.customModule)
        && fileSystem.managedFileMatches(
          at: paths.customModule,
          sha256: moduleSHA256,
          metadata: moduleMetadata
        )
    } else {
      moduleMatches = !fileSystem.exists(paths.customModule)
    }
    return policyMatches && moduleMatches && !fileSystem.exists(paths.legacyModule)
      && !fileSystem.exists(paths.legacyVersionedModule)
  }

  private func verifyRecoverableState(_ record: PAMLifecycleRecord) throws {
    for snapshot in record.snapshots {
      try verifyRecoverableSnapshot(snapshot, record: record)
    }
  }

  private func verifyRecoverableSnapshot(
    _ snapshot: PAMLifecycleSnapshot,
    record: PAMLifecycleRecord
  ) throws {
    let target = URL(fileURLWithPath: snapshot.path)
    let backup = fileSystem.backupURL(for: snapshot)
    if snapshot.existed {
      if fileSystem.exists(backup) {
        try fileSystem.validateOriginal(snapshot, at: backup)
        guard fileSystem.exists(target) else { return }
        if let expectedSHA256 = transactionalHash(for: snapshot.path, record: record),
          let expectedMetadata = transactionalMetadata(for: snapshot.path, record: record),
          try fileSystem.managedFileMatches(
            at: target,
            sha256: expectedSHA256,
            metadata: expectedMetadata
          )
        {
          return
        }
        try fileSystem.validateOriginal(snapshot, at: target)
        return
      }
      guard fileSystem.exists(target) else {
        throw PAMLifecycleError.managedStateDrift(snapshot.path)
      }
      try fileSystem.validateOriginal(snapshot, at: target)
      return
    }
    guard !fileSystem.exists(backup) else {
      throw PAMLifecycleError.invalidState("unexpected backup: \(snapshot.backupName)")
    }
    guard fileSystem.exists(target) else { return }
    guard let expectedSHA256 = transactionalHash(for: snapshot.path, record: record),
      let expectedMetadata = transactionalMetadata(for: snapshot.path, record: record),
      try fileSystem.managedFileMatches(
        at: target,
        sha256: expectedSHA256,
        metadata: expectedMetadata
      )
    else {
      throw PAMLifecycleError.managedStateDrift(snapshot.path)
    }
  }

  private func transactionalHash(for path: String, record: PAMLifecycleRecord) -> String? {
    switch path {
    case paths.sudoLocal.path: record.installedPolicySHA256
    case paths.customModule.path: record.installedModuleSHA256
    case paths.legacyModule.path, paths.legacyVersionedModule.path: nil
    default: nil
    }
  }

  private func transactionalMetadata(
    for path: String,
    record: PAMLifecycleRecord
  ) -> PAMFileMetadata? {
    switch path {
    case paths.sudoLocal.path: record.installedPolicyMetadata
    case paths.customModule.path: record.installedModuleMetadata
    default: nil
    }
  }

  private func backupName(for target: URL) -> String {
    ".\(target.lastPathComponent).pam-companion.original"
  }

  private func stagedURL(for target: URL) -> URL {
    target.deletingLastPathComponent()
      .appendingPathComponent(".\(target.lastPathComponent).pam-companion.pending")
  }

  private var lifecycleURLs: [URL] {
    let targets = [
      paths.sudoLocal,
      paths.customModule,
      paths.legacyModule,
      paths.legacyVersionedModule,
    ]
    return targets.map {
      $0.deletingLastPathComponent().appendingPathComponent(backupName(for: $0))
    } + [stagedPolicyURL, stagedModuleURL]
  }

  private func validateNoOrphanedLifecycleFiles() throws {
    if let orphan = lifecycleURLs.first(where: fileSystem.exists) {
      throw PAMLifecycleError.invalidState(
        "unexpected lifecycle file without a transaction: \(orphan.path)")
    }
  }

  private func recoverablePreJournalStateDirectoryExists() throws -> Bool {
    guard fileSystem.exists(paths.stateDirectory) else { return false }
    guard try fileSystem.isRecoverablePreJournalStateDirectory(paths.stateDirectory) else {
      return false
    }
    try validateNoOrphanedLifecycleFiles()
    return true
  }

  private func validateStagedFiles(_ record: PAMLifecycleRecord) throws {
    let stagedFiles = [
      (
        stagedPolicyURL,
        record.installedPolicySHA256,
        record.installedPolicyMetadata
      ),
      (
        stagedModuleURL,
        record.installedModuleSHA256,
        record.installedModuleMetadata
      ),
    ]
    for (url, expectedSHA256, expectedMetadata) in stagedFiles where fileSystem.exists(url) {
      guard record.phase != .complete else {
        throw PAMLifecycleError.invalidState("unexpected staged file: \(url.lastPathComponent)")
      }
      if let expectedMetadata, let expectedSHA256 {
        guard
          try fileSystem.managedFileMatches(
            at: url,
            sha256: expectedSHA256,
            metadata: expectedMetadata
          )
        else {
          throw PAMLifecycleError.invalidState("staged file changed: \(url.lastPathComponent)")
        }
      } else {
        try fileSystem.validateRegularRootTarget(url)
      }
    }
  }

  private func cleanupStagedFiles(_ record: PAMLifecycleRecord) throws {
    try fileSystem.removeStagedFile(
      stagedPolicyURL,
      sha256: record.installedPolicyMetadata == nil ? nil : record.installedPolicySHA256,
      metadata: record.installedPolicyMetadata
    )
    try fileSystem.removeStagedFile(
      stagedModuleURL,
      sha256: record.installedModuleMetadata == nil ? nil : record.installedModuleSHA256,
      metadata: record.installedModuleMetadata
    )
  }

  private func verifyPasswordFallback(_ data: Data) throws {
    guard let policy = String(data: data, encoding: .utf8), !data.contains(0) else {
      throw PAMLifecycleError.passwordFallbackUnavailable
    }
    let authenticationLines = policy.components(separatedBy: "\n")
      .map(activeTokens)
      .filter { $0.first == "auth" }
    let allowedWithoutSmartcard = [
      ["auth", "include", "sudo_local"],
      ["auth", "required", "pam_opendirectory.so"],
    ]
    let allowedWithSmartcard = [
      ["auth", "include", "sudo_local"],
      ["auth", "sufficient", "pam_smartcard.so"],
      ["auth", "required", "pam_opendirectory.so"],
    ]
    guard
      authenticationLines == allowedWithoutSmartcard
        || authenticationLines == allowedWithSmartcard
    else {
      throw PAMLifecycleError.passwordFallbackUnavailable
    }
  }

  private func activeTokens(_ line: String) -> [String] {
    line.prefix { $0 != "#" }.split(whereSeparator: { $0.isWhitespace }).map(String.init)
  }

  private func activeModuleNames(in data: Data) -> [String] {
    guard let policy = String(data: data, encoding: .utf8), !data.contains(0) else { return [] }
    return policy.components(separatedBy: "\n").compactMap { line in
      let tokens = activeTokens(line)
      guard tokens.count >= 3 else { return nil }
      return tokens[2].split(separator: "/").last.map(String.init)
    }
  }

  private func requireRoot() throws {
    guard effectiveUserID == 0 else { throw PAMLifecycleError.rootRequired }
  }

  private func failIfRequested(_ point: PAMLifecycleFailurePoint) throws {
    if failurePoint == point { throw PAMLifecycleError.injectedFailure(point.rawValue) }
  }
}
