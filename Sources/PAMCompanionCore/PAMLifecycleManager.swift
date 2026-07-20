import Darwin
import Foundation

public final class PAMLifecycleManager: PAMLifecycleManaging {
  private let paths: PAMLifecyclePaths
  private let effectiveUserID: uid_t
  private let fileSystem: PAMLifecycleFileSystem
  private let moduleValidator: (URL) throws -> Void
  private let failurePoint: PAMLifecycleFailurePoint?

  public convenience init(paths: PAMLifecyclePaths) {
    self.init(
      paths: paths,
      effectiveUserID: geteuid(),
      expectedOwnerUserID: 0,
      expectedOwnerGroupID: 0,
      moduleValidator: SystemPAMModuleValidator.validate,
      failurePoint: nil
    )
  }

  init(
    paths: PAMLifecyclePaths,
    effectiveUserID: uid_t,
    expectedOwnerUserID: uid_t,
    expectedOwnerGroupID: gid_t,
    moduleValidator: @escaping (URL) throws -> Void,
    failurePoint: PAMLifecycleFailurePoint?
  ) {
    self.paths = paths
    self.effectiveUserID = effectiveUserID
    fileSystem = PAMLifecycleFileSystem(
      expectedOwnerUserID: expectedOwnerUserID,
      expectedOwnerGroupID: expectedOwnerGroupID
    )
    self.moduleValidator = moduleValidator
    self.failurePoint = failurePoint
  }

  public func status() throws -> PAMLifecycleStatus {
    if fileSystem.exists(paths.stateDirectory) {
      let record = try loadRecord()
      guard record.phase == .complete else { return .recoveryRequired }
      return (try managedStateMatches(record)) ? .configured : .drifted
    }

    let policy = fileSystem.exists(paths.sudoLocal) ? try fileSystem.read(paths.sudoLocal) : Data()
    let names = activeModuleNames(in: policy)
    if names.contains(where: PAMConfigurationPlanner.legacyModules.contains)
      || fileSystem.exists(paths.legacyModule)
      || fileSystem.exists(paths.legacyVersionedModule)
    {
      return .legacy
    }
    if names.contains(PAMConfigurationPlanner.canonicalModule)
      || fileSystem.exists(paths.canonicalModule)
    {
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
        changed: true, summary: "would install pam_companion.so and update sudo_local")
    }
    return try fileSystem.withLock(paths.lock) {
      let preparation = try prepareSetup()
      guard !preparation.alreadyConfigured else {
        return PAMLifecycleResult(changed: false, summary: "pam-companion is already configured")
      }
      return try performSetup(preparation)
    }
  }

  public func restore(dryRun: Bool) throws -> PAMLifecycleResult {
    try requireRoot()
    guard fileSystem.exists(paths.stateDirectory) else {
      return PAMLifecycleResult(
        changed: false, summary: "pam-companion has no managed setup to restore")
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
  private var stagedModuleURL: URL {
    paths.stateDirectory.appendingPathComponent("pam_companion.so.pending")
  }
  private var stagedPolicyURL: URL {
    paths.stateDirectory.appendingPathComponent("sudo_local.pending")
  }

  private struct SetupPreparation {
    let policyPlan: PAMConfigurationPlan
    let moduleData: Data
    let alreadyConfigured: Bool
  }

  private func prepareSetup() throws -> SetupPreparation {
    try fileSystem.validateDirectory(paths.policyDirectory)
    try fileSystem.validateDirectory(paths.moduleDirectory)
    try fileSystem.validateDirectory(paths.stateDirectory.deletingLastPathComponent())
    try fileSystem.validateRegularRootTarget(paths.sudoPolicy)
    try fileSystem.validateRegularRootTarget(paths.sudoLocal)
    let moduleData = try fileSystem.readSourceModule(paths.moduleSource)
    try fileSystem.withTemporaryModule(moduleData) { try moduleValidator($0) }

    if fileSystem.exists(paths.stateDirectory) {
      let record = try loadRecord()
      guard record.phase == .complete else { throw PAMLifecycleError.recoveryRequired }
      guard try managedStateMatches(record) else {
        throw PAMLifecycleError.managedStateDrift(paths.sudoLocal.path)
      }
      return SetupPreparation(
        policyPlan: try PAMConfigurationPlanner.plan(fileSystem.read(paths.sudoLocal)),
        moduleData: moduleData,
        alreadyConfigured: true
      )
    }

    try verifyPasswordFallback(fileSystem.read(paths.sudoPolicy))
    for module in [paths.canonicalModule, paths.legacyModule, paths.legacyVersionedModule]
    where fileSystem.exists(module) {
      try fileSystem.validateRegularRootTarget(module)
    }
    let plan = try PAMConfigurationPlanner.plan(fileSystem.read(paths.sudoLocal))
    var policies = try fileSystem.policyFiles(in: paths.policyDirectory)
    for path in policies.keys
    where URL(fileURLWithPath: path).lastPathComponent == paths.sudoLocal.lastPathComponent {
      policies.removeValue(forKey: path)
    }
    policies[paths.sudoLocal.path] = Data(plan.updated.utf8)
    if let reference = try PAMReferenceScanner.legacyReferences(in: policies).first {
      throw PAMLifecycleError.legacyModuleStillReferenced(
        reference.module,
        policy: URL(fileURLWithPath: reference.policyPath).lastPathComponent
      )
    }
    return SetupPreparation(policyPlan: plan, moduleData: moduleData, alreadyConfigured: false)
  }

  private func performSetup(_ preparation: SetupPreparation) throws -> PAMLifecycleResult {
    var record: PAMLifecycleRecord?
    do {
      try fileSystem.createStateDirectory(paths.stateDirectory)
      let policySnapshot = try fileSystem.snapshot(
        paths.sudoLocal,
        backupName: "sudo_local.original"
      )
      let canonicalSnapshot = try fileSystem.snapshot(
        paths.canonicalModule,
        backupName: "pam_companion.so.original"
      )
      let legacySnapshot = try fileSystem.snapshot(
        paths.legacyModule,
        backupName: "pam_watchid.so.original"
      )
      let versionedLegacySnapshot = try fileSystem.snapshot(
        paths.legacyVersionedModule,
        backupName: "pam_watchid.so.2.original"
      )
      let snapshots = [
        policySnapshot,
        canonicalSnapshot,
        legacySnapshot,
        versionedLegacySnapshot,
      ]
      var preparedRecord = PAMLifecycleRecord(
        schemaVersion: 2,
        phase: .preparing,
        snapshots: snapshots,
        installedPolicySHA256: fileSystem.sha256(Data(preparation.policyPlan.updated.utf8)),
        installedModuleSHA256: fileSystem.sha256(preparation.moduleData),
        installedPolicyMetadata: nil,
        installedModuleMetadata: nil
      )
      try fileSystem.writeRecord(preparedRecord, to: recordURL)
      record = preparedRecord

      try fileSystem.installModule(preparation.moduleData, to: stagedModuleURL)
      try fileSystem.replacePolicy(
        stagedPolicyURL,
        with: Data(preparation.policyPlan.updated.utf8),
        template: paths.sudoLocal
      )
      let stagedModuleMetadata = try fileSystem.metadata(stagedModuleURL)
      let stagedPolicyMetadata = try fileSystem.metadata(stagedPolicyURL)
      preparedRecord.installedModuleMetadata = stagedModuleMetadata
      preparedRecord.installedPolicyMetadata = stagedPolicyMetadata
      preparedRecord.phase = .prepared
      try fileSystem.writeRecord(preparedRecord, to: recordURL)
      record = preparedRecord
      try failIfRequested(.afterStatePrepared)

      try fileSystem.moveOriginalToBackup(canonicalSnapshot, in: paths.stateDirectory)
      try failIfRequested(.afterCanonicalBackedUp)
      try fileSystem.moveStagedFile(
        stagedModuleURL,
        to: paths.canonicalModule,
        sha256: preparedRecord.installedModuleSHA256,
        metadata: stagedModuleMetadata
      )
      try failIfRequested(.afterModuleInstalled)

      try fileSystem.moveOriginalToBackup(policySnapshot, in: paths.stateDirectory)
      try failIfRequested(.afterPolicyBackedUp)
      try fileSystem.moveStagedFile(
        stagedPolicyURL,
        to: paths.sudoLocal,
        sha256: preparedRecord.installedPolicySHA256,
        metadata: stagedPolicyMetadata
      )
      try failIfRequested(.afterPolicyInstalled)

      try fileSystem.moveOriginalToBackup(legacySnapshot, in: paths.stateDirectory)
      try failIfRequested(.afterLegacyBackedUp)
      try fileSystem.moveOriginalToBackup(versionedLegacySnapshot, in: paths.stateDirectory)
      try failIfRequested(.afterVersionedLegacyBackedUp)
      try failIfRequested(.afterLegacyRemoved)

      preparedRecord.phase = .complete
      try fileSystem.writeRecord(preparedRecord, to: recordURL)
      return PAMLifecycleResult(
        changed: true, summary: "installed pam_companion.so and updated sudo_local")
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
  }

  private func restoreFailurePoint(for path: String) -> PAMLifecycleFailurePoint {
    switch path {
    case paths.canonicalModule.path: .afterCanonicalRestored
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
      (paths.sudoLocal.path, "sudo_local.original"),
      (paths.canonicalModule.path, "pam_companion.so.original"),
      (paths.legacyModule.path, "pam_watchid.so.original"),
      (paths.legacyVersionedModule.path, "pam_watchid.so.2.original"),
    ]
    guard record.snapshots.count == expected.count,
      zip(record.snapshots, expected).allSatisfy({ snapshot, value in
        snapshot.path == value.0 && snapshot.backupName == value.1
      }),
      isSHA256(record.installedPolicySHA256),
      isSHA256(record.installedModuleSHA256)
    else {
      throw PAMLifecycleError.invalidState("record does not match the supported lifecycle paths")
    }
    for snapshot in record.snapshots {
      let backup = paths.stateDirectory.appendingPathComponent(snapshot.backupName)
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
    guard hasPolicyMetadata == hasModuleMetadata else {
      throw PAMLifecycleError.invalidState("transactional metadata is incomplete")
    }
    switch record.phase {
    case .preparing:
      guard !hasPolicyMetadata else {
        throw PAMLifecycleError.invalidState("preparing state contains transactional metadata")
      }
    case .prepared, .complete:
      guard hasPolicyMetadata else {
        throw PAMLifecycleError.invalidState("transactional metadata is missing")
      }
    case .restoring:
      break
    }
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
      fileSystem.exists(paths.canonicalModule),
      let policyMetadata = record.installedPolicyMetadata,
      let moduleMetadata = record.installedModuleMetadata
    else {
      return false
    }
    return try fileSystem.managedFileMatches(
      at: paths.sudoLocal,
      sha256: record.installedPolicySHA256,
      metadata: policyMetadata
    )
      && fileSystem.managedFileMatches(
        at: paths.canonicalModule,
        sha256: record.installedModuleSHA256,
        metadata: moduleMetadata
      )
      && !fileSystem.exists(paths.legacyModule)
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
    let backup = backupURL(snapshot.backupName)
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
    case paths.canonicalModule.path: record.installedModuleSHA256
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
    case paths.canonicalModule.path: record.installedModuleMetadata
    default: nil
    }
  }

  private func backupURL(_ name: String) -> URL {
    paths.stateDirectory.appendingPathComponent(name)
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

enum SystemPAMModuleValidator {
  static func validate(_ url: URL) throws {
    let codesign = try run("/usr/bin/codesign", ["--verify", "--strict", url.path])
    guard codesign.status == 0 else {
      throw PAMLifecycleError.moduleValidation(codesign.error)
    }
    let signature = try run("/usr/bin/codesign", ["-d", "--verbose=4", url.path])
    guard signature.status == 0 else {
      throw PAMLifecycleError.moduleValidation(signature.error)
    }
    try validateSignatureDetails(signature.output + signature.error)
    let architectures = try run("/usr/bin/lipo", ["-archs", url.path])
    guard architectures.status == 0 else {
      throw PAMLifecycleError.moduleValidation(architectures.error)
    }
    let values = Set(
      architectures.output.split(whereSeparator: { $0.isWhitespace }).map(String.init))
    guard values == ["arm64", "x86_64"] else {
      throw PAMLifecycleError.moduleValidation("expected universal arm64 and x86_64 architectures")
    }
  }

  static func validateSignatureDetails(_ details: String) throws {
    let lines = details.components(separatedBy: "\n")
    guard lines.contains("Signature=adhoc"),
      lines.contains(where: { line in
        line.hasPrefix("CodeDirectory ") && line.contains("(adhoc,runtime)")
      })
    else {
      throw PAMLifecycleError.moduleValidation(
        "expected an ad hoc signature with the hardened runtime"
      )
    }
  }

  private static func run(_ executable: String, _ arguments: [String]) throws
    -> (status: Int32, output: String, error: String)
  {
    let process = Process()
    let output = Pipe()
    let error = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = error
    do {
      try process.run()
    } catch {
      throw PAMLifecycleError.moduleValidation("could not run \(executable)")
    }
    process.waitUntilExit()
    return (
      process.terminationStatus,
      String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
      String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    )
  }
}
