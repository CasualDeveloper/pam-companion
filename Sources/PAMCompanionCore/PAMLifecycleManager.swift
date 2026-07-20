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
    let preparation = try prepareSetup()
    if preparation.alreadyConfigured {
      return PAMLifecycleResult(changed: false, summary: "pam-companion is already configured")
    }
    if dryRun {
      return PAMLifecycleResult(changed: true, summary: "would install pam_companion.so and update sudo_local")
    }
    return try fileSystem.withLock(paths.lock) {
      let lockedPreparation = try prepareSetup()
      guard !lockedPreparation.alreadyConfigured else {
        return PAMLifecycleResult(changed: false, summary: "pam-companion is already configured")
      }
      return try performSetup(lockedPreparation)
    }
  }

  public func restore(dryRun: Bool) throws -> PAMLifecycleResult {
    try requireRoot()
    guard fileSystem.exists(paths.stateDirectory) else {
      return PAMLifecycleResult(changed: false, summary: "pam-companion has no managed setup to restore")
    }
    let record = try loadRecord()
    if record.phase == .complete { try verifyManagedState(record) }
    if dryRun {
      return PAMLifecycleResult(changed: true, summary: "would restore the pre-setup PAM configuration")
    }
    return try fileSystem.withLock(paths.lock) {
      let lockedRecord = try loadRecord()
      if lockedRecord.phase == .complete { try verifyManagedState(lockedRecord) }
      try restoreSnapshots(lockedRecord)
      try fileSystem.removeTree(paths.stateDirectory)
      return PAMLifecycleResult(changed: true, summary: "restored the pre-setup PAM configuration")
    }
  }

  private var recordURL: URL { paths.stateDirectory.appendingPathComponent("record.json") }

  private struct SetupPreparation {
    let policyPlan: PAMConfigurationPlan
    let alreadyConfigured: Bool
  }

  private func prepareSetup() throws -> SetupPreparation {
    try fileSystem.validateDirectory(paths.policyDirectory)
    try fileSystem.validateDirectory(paths.moduleDirectory)
    try fileSystem.validateDirectory(paths.stateDirectory.deletingLastPathComponent())
    try fileSystem.validateRegularRootTarget(paths.sudoPolicy)
    try fileSystem.validateRegularRootTarget(paths.sudoLocal)
    try fileSystem.validateSourceModule(paths.moduleSource)
    try moduleValidator(paths.moduleSource)

    if fileSystem.exists(paths.stateDirectory) {
      let record = try loadRecord()
      guard record.phase == .complete else { throw PAMLifecycleError.recoveryRequired }
      guard try managedStateMatches(record) else {
        throw PAMLifecycleError.managedStateDrift(paths.sudoLocal.path)
      }
      return SetupPreparation(
        policyPlan: try PAMConfigurationPlanner.plan(fileSystem.read(paths.sudoLocal)),
        alreadyConfigured: true
      )
    }

    try verifyPasswordFallback(fileSystem.read(paths.sudoPolicy))
    for module in [paths.canonicalModule, paths.legacyModule, paths.legacyVersionedModule]
      where fileSystem.exists(module)
    {
      try fileSystem.validateRegularRootTarget(module)
    }
    let plan = try PAMConfigurationPlanner.plan(fileSystem.read(paths.sudoLocal))
    var policies = try fileSystem.policyFiles(in: paths.policyDirectory)
    for path in policies.keys
      where URL(fileURLWithPath: path).lastPathComponent == paths.sudoLocal.lastPathComponent
    {
      policies.removeValue(forKey: path)
    }
    policies[paths.sudoLocal.path] = Data(plan.updated.utf8)
    if let reference = try PAMReferenceScanner.legacyReferences(in: policies).first {
      throw PAMLifecycleError.legacyModuleStillReferenced(
        reference.module,
        policy: URL(fileURLWithPath: reference.policyPath).lastPathComponent
      )
    }
    return SetupPreparation(policyPlan: plan, alreadyConfigured: false)
  }

  private func performSetup(_ preparation: SetupPreparation) throws -> PAMLifecycleResult {
    var record: PAMLifecycleRecord?
    do {
      try fileSystem.createStateDirectory(paths.stateDirectory)
      let targets = [
        (paths.sudoLocal, "sudo_local.original"),
        (paths.canonicalModule, "pam_companion.so.original"),
        (paths.legacyModule, "pam_watchid.so.original"),
        (paths.legacyVersionedModule, "pam_watchid.so.2.original"),
      ]
      let snapshots = try targets.map {
        try fileSystem.snapshot($0.0, backupName: $0.1, stateDirectory: paths.stateDirectory)
      }
      var preparedRecord = PAMLifecycleRecord(
        schemaVersion: 1,
        phase: .prepared,
        snapshots: snapshots,
        installedPolicySHA256: fileSystem.sha256(Data(preparation.policyPlan.updated.utf8)),
        installedModuleSHA256: try fileSystem.sha256(paths.moduleSource)
      )
      record = preparedRecord
      try fileSystem.writeRecord(preparedRecord, to: recordURL)
      try failIfRequested(.afterStatePrepared)

      try fileSystem.installModule(from: paths.moduleSource, to: paths.canonicalModule)
      try failIfRequested(.afterModuleInstalled)

      try fileSystem.replacePolicy(paths.sudoLocal, with: Data(preparation.policyPlan.updated.utf8))
      try failIfRequested(.afterPolicyInstalled)

      try fileSystem.removeIfPresent(paths.legacyModule)
      try fileSystem.removeIfPresent(paths.legacyVersionedModule)
      try failIfRequested(.afterLegacyRemoved)

      preparedRecord.phase = .complete
      try fileSystem.writeRecord(preparedRecord, to: recordURL)
      return PAMLifecycleResult(changed: true, summary: "installed pam_companion.so and updated sudo_local")
    } catch {
      guard let record else {
        try? fileSystem.removeTree(paths.stateDirectory)
        throw error
      }
      do {
        try restoreSnapshots(record)
        try fileSystem.removeTree(paths.stateDirectory)
      } catch {
        throw PAMLifecycleError.rollbackFailed(String(describing: error))
      }
      throw error
    }
  }

  private func restoreSnapshots(_ record: PAMLifecycleRecord) throws {
    let policyPath = paths.sudoLocal.path
    for snapshot in record.snapshots where snapshot.path != policyPath {
      try fileSystem.restore(snapshot, from: paths.stateDirectory)
    }
    if let policy = record.snapshots.first(where: { $0.path == policyPath }) {
      try fileSystem.restore(policy, from: paths.stateDirectory)
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
      if snapshot.existed {
        try fileSystem.validateRegularRootTarget(backup)
      } else if fileSystem.exists(backup) {
        throw PAMLifecycleError.invalidState("unexpected backup: \(snapshot.backupName)")
      }
    }
    return record
  }

  private func isSHA256(_ value: String) -> Bool {
    value.count == 64 && value.utf8.allSatisfy { byte in
      (48...57).contains(byte) || (97...102).contains(byte)
    }
  }

  private func managedStateMatches(_ record: PAMLifecycleRecord) throws -> Bool {
    guard fileSystem.exists(paths.sudoLocal), fileSystem.exists(paths.canonicalModule) else {
      return false
    }
    return try fileSystem.sha256(paths.sudoLocal) == record.installedPolicySHA256
      && fileSystem.sha256(paths.canonicalModule) == record.installedModuleSHA256
      && !fileSystem.exists(paths.legacyModule)
      && !fileSystem.exists(paths.legacyVersionedModule)
  }

  private func verifyManagedState(_ record: PAMLifecycleRecord) throws {
    guard fileSystem.exists(paths.sudoLocal),
      try fileSystem.sha256(paths.sudoLocal) == record.installedPolicySHA256
    else {
      throw PAMLifecycleError.managedStateDrift(paths.sudoLocal.path)
    }
    guard fileSystem.exists(paths.canonicalModule),
      try fileSystem.sha256(paths.canonicalModule) == record.installedModuleSHA256
    else {
      throw PAMLifecycleError.managedStateDrift(paths.canonicalModule.path)
    }
    for legacy in [paths.legacyModule, paths.legacyVersionedModule] where fileSystem.exists(legacy) {
      throw PAMLifecycleError.managedStateDrift(legacy.path)
    }
  }

  private func verifyPasswordFallback(_ data: Data) throws {
    guard let policy = String(data: data, encoding: .utf8), !data.contains(0) else {
      throw PAMLifecycleError.passwordFallbackUnavailable
    }
    let lines = policy.components(separatedBy: "\n").map(activeTokens)
    guard let includeIndex = lines.firstIndex(where: { tokens in
      tokens.count >= 3 && tokens[0] == "auth" && tokens[1] == "include" && tokens[2] == "sudo_local"
    }) else {
      throw PAMLifecycleError.passwordFallbackUnavailable
    }
    let hasFallback = lines.dropFirst(includeIndex + 1).contains { tokens in
      tokens.count >= 3 && tokens[0] == "auth" && ["required", "requisite"].contains(tokens[1])
    }
    guard hasFallback else { throw PAMLifecycleError.passwordFallbackUnavailable }
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
    let architectures = try run("/usr/bin/lipo", ["-archs", url.path])
    guard architectures.status == 0 else {
      throw PAMLifecycleError.moduleValidation(architectures.error)
    }
    let values = Set(architectures.output.split(whereSeparator: { $0.isWhitespace }).map(String.init))
    guard values == ["arm64", "x86_64"] else {
      throw PAMLifecycleError.moduleValidation("expected universal arm64 and x86_64 architectures")
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
