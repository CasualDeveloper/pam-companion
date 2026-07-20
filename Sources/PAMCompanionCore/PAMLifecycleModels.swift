import Darwin
import Foundation

public struct PAMLifecyclePaths: Equatable, Sendable {
  public let policyDirectory: URL
  public let sudoPolicy: URL
  public let sudoLocal: URL
  public let moduleSource: URL
  public let moduleDirectory: URL
  public let stateDirectory: URL

  public init(
    policyDirectory: URL,
    sudoPolicy: URL,
    sudoLocal: URL,
    moduleSource: URL,
    moduleDirectory: URL,
    stateDirectory: URL
  ) {
    self.policyDirectory = policyDirectory
    self.sudoPolicy = sudoPolicy
    self.sudoLocal = sudoLocal
    self.moduleSource = moduleSource
    self.moduleDirectory = moduleDirectory
    self.stateDirectory = stateDirectory
  }

  public static func system(moduleSource: URL) -> PAMLifecyclePaths {
    PAMLifecyclePaths(
      policyDirectory: URL(fileURLWithPath: "/etc/pam.d"),
      sudoPolicy: URL(fileURLWithPath: "/etc/pam.d/sudo"),
      sudoLocal: URL(fileURLWithPath: "/etc/pam.d/sudo_local"),
      moduleSource: moduleSource,
      moduleDirectory: URL(fileURLWithPath: "/usr/local/lib/pam"),
      stateDirectory: URL(fileURLWithPath: "/var/db/pam-companion")
    )
  }

  public var canonicalModule: URL {
    moduleDirectory.appendingPathComponent(PAMConfigurationPlanner.canonicalModule)
  }

  public var legacyModule: URL {
    moduleDirectory.appendingPathComponent("pam_watchid.so")
  }

  public var legacyVersionedModule: URL {
    moduleDirectory.appendingPathComponent("pam_watchid.so.2")
  }

  var lock: URL {
    stateDirectory.deletingLastPathComponent().appendingPathComponent("pam-companion.lock")
  }
}

public enum PAMLifecycleStatus: Equatable, Sendable {
  case notConfigured
  case legacy
  case configured
  case unmanaged
  case recoveryRequired
  case drifted
}

public struct PAMLifecycleResult: Equatable, Sendable {
  public let changed: Bool
  public let summary: String

  public init(changed: Bool, summary: String) {
    self.changed = changed
    self.summary = summary
  }
}

public protocol PAMLifecycleManaging: AnyObject {
  func status() throws -> PAMLifecycleStatus
  func setup(dryRun: Bool) throws -> PAMLifecycleResult
  func restore(dryRun: Bool) throws -> PAMLifecycleResult
}

enum PAMLifecycleFailurePoint: String, CaseIterable, Codable, Sendable {
  case afterStatePrepared
  case afterCanonicalBackedUp
  case afterModuleInstalled
  case afterPolicyBackedUp
  case afterPolicyInstalled
  case afterLegacyBackedUp
  case afterVersionedLegacyBackedUp
  case afterLegacyRemoved
  case afterRestoreStarted
  case afterCanonicalRestored
  case afterLegacyRestored
  case afterVersionedLegacyRestored
  case afterPolicyRestored
  case beforeStateCleanup

  static let setupCases: [Self] = [
    .afterStatePrepared,
    .afterCanonicalBackedUp,
    .afterModuleInstalled,
    .afterPolicyBackedUp,
    .afterPolicyInstalled,
    .afterLegacyBackedUp,
    .afterVersionedLegacyBackedUp,
    .afterLegacyRemoved,
  ]

  static let restoreCases: [Self] = [
    .afterRestoreStarted,
    .afterCanonicalRestored,
    .afterLegacyRestored,
    .afterVersionedLegacyRestored,
    .afterPolicyRestored,
    .beforeStateCleanup,
  ]
}

public enum PAMLifecycleError: Error, Equatable, CustomStringConvertible {
  case rootRequired
  case passwordFallbackUnavailable
  case legacyModuleStillReferenced(String, policy: String)
  case managedStateDrift(String)
  case recoveryRequired
  case unsafePath(String)
  case invalidState(String)
  case moduleValidation(String)
  case fileSystem(path: String, message: String)
  case rollbackFailed(String)
  case injectedFailure(String)

  public var description: String {
    switch self {
    case .rootRequired:
      return "this command must be run explicitly with sudo"
    case .passwordFallbackUnavailable:
      return "refusing setup because the sudo password fallback could not be proven"
    case .legacyModuleStillReferenced(let module, let policy):
      return "refusing to remove \(module) because it is still referenced by \(policy)"
    case .managedStateDrift(let path):
      return "refusing to overwrite a managed file that changed after setup: \(path)"
    case .recoveryRequired:
      return "an incomplete setup exists; run sudo pam-companion restore"
    case .unsafePath(let path):
      return "refusing an unsafe filesystem target: \(path)"
    case .invalidState(let detail):
      return "invalid lifecycle state: \(detail)"
    case .moduleValidation(let detail):
      return "invalid pam_companion.so release module: \(detail)"
    case .fileSystem(let path, let message):
      return "filesystem operation failed at \(path): \(message)"
    case .rollbackFailed(let detail):
      return "setup failed and rollback also failed: \(detail)"
    case .injectedFailure(let point):
      return "injected lifecycle failure after \(point)"
    }
  }
}

enum PAMLifecyclePhase: String, Codable {
  case preparing
  case prepared
  case complete
  case restoring
}

struct PAMFileMetadata: Codable, Equatable {
  let mode: UInt32
  let ownerUserID: UInt32
  let ownerGroupID: UInt32
  let flags: UInt32
  let extendedAttributes: [String: Data]

  static func trackedExtendedAttributes(_ attributes: [String: Data]) -> [String: Data] {
    attributes.filter { name, _ in
      // macOS rewrites this opaque, path-managed value during otherwise
      // metadata-preserving renames. It cannot be treated as rollback state.
      name != "com.apple.provenance"
    }
  }

  func normalizingTrackedExtendedAttributes() -> PAMFileMetadata {
    PAMFileMetadata(
      mode: mode,
      ownerUserID: ownerUserID,
      ownerGroupID: ownerGroupID,
      flags: flags,
      extendedAttributes: Self.trackedExtendedAttributes(extendedAttributes)
    )
  }
}

struct PAMLifecycleSnapshot: Codable, Equatable {
  let path: String
  let backupName: String
  let existed: Bool
  let originalSHA256: String?
  let metadata: PAMFileMetadata?

  func normalizingTrackedExtendedAttributes() -> PAMLifecycleSnapshot {
    PAMLifecycleSnapshot(
      path: path,
      backupName: backupName,
      existed: existed,
      originalSHA256: originalSHA256,
      metadata: metadata?.normalizingTrackedExtendedAttributes()
    )
  }
}

struct PAMLifecycleRecord: Codable, Equatable {
  let schemaVersion: Int
  var phase: PAMLifecyclePhase
  let snapshots: [PAMLifecycleSnapshot]
  let installedPolicySHA256: String
  let installedModuleSHA256: String
  var installedPolicyMetadata: PAMFileMetadata?
  var installedModuleMetadata: PAMFileMetadata?

  func normalizingTrackedExtendedAttributes() -> PAMLifecycleRecord {
    PAMLifecycleRecord(
      schemaVersion: schemaVersion,
      phase: phase,
      snapshots: snapshots.map { $0.normalizingTrackedExtendedAttributes() },
      installedPolicySHA256: installedPolicySHA256,
      installedModuleSHA256: installedModuleSHA256,
      installedPolicyMetadata: installedPolicyMetadata?.normalizingTrackedExtendedAttributes(),
      installedModuleMetadata: installedModuleMetadata?.normalizingTrackedExtendedAttributes()
    )
  }
}
