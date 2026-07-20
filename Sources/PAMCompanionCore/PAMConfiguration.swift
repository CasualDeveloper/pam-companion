import Foundation

public enum PAMConfigurationError: Error, Equatable, CustomStringConvertible {
  case invalidEncoding
  case duplicateModuleEntries
  case unsupportedModuleEntry
  case nativeModuleAnchorMissing
  case unsupportedLocalPolicy

  public var description: String {
    switch self {
    case .invalidEncoding:
      return "PAM configuration must be NUL-free UTF-8"
    case .duplicateModuleEntries:
      return "PAM configuration contains multiple companion module entries"
    case .unsupportedModuleEntry:
      return "companion module entries must use 'auth sufficient'"
    case .nativeModuleAnchorMissing:
      return "sudo_local does not contain the system pam_tid.so template entry"
    case .unsupportedLocalPolicy:
      return
        "sudo_local contains an active entry outside the supported companion and Touch ID policy"
    }
  }
}

public struct PAMConfigurationPlan: Equatable, Sendable {
  public let original: String
  public let updated: String
  public let removedModules: [String]

  public var changed: Bool { original != updated }
}

public enum PAMConfigurationPlanner {
  public static let nativeModule = "pam_tid.so"
  public static let customModule = "pam_companion.so"
  public static let legacyModules = ["pam_watchid.so", "pam_watchid.so.2"]
  public static let nativeLine = "auth       sufficient     pam_tid.so"
  public static let removableModules = [customModule] + legacyModules

  public static func plan(_ data: Data) throws -> PAMConfigurationPlan {
    guard let configuration = String(data: data, encoding: .utf8), !data.contains(0) else {
      throw PAMConfigurationError.invalidEncoding
    }
    return try plan(configuration)
  }

  public static func plan(_ configuration: String) throws -> PAMConfigurationPlan {
    guard !configuration.utf8.contains(0) else {
      throw PAMConfigurationError.invalidEncoding
    }

    var lines = configuration.components(separatedBy: "\n")
    var nativeIndices: [Int] = []
    var commentedNativeIndices: [Int] = []
    for (index, line) in lines.enumerated()
    where commentedPolicyTokens(line) == ["auth", "sufficient", nativeModule] {
      commentedNativeIndices.append(index)
    }
    let matches = try lines.enumerated().compactMap { index, line -> ModuleEntry? in
      guard let tokens = policyTokens(line) else { return nil }
      guard tokens.count >= 3 else { throw PAMConfigurationError.unsupportedLocalPolicy }
      let module = moduleName(tokens[2])
      if module == nativeModule {
        guard tokens == ["auth", "sufficient", nativeModule] else {
          throw PAMConfigurationError.unsupportedLocalPolicy
        }
        nativeIndices.append(index)
        return nil
      }
      guard removableModules.contains(module) else {
        throw PAMConfigurationError.unsupportedLocalPolicy
      }
      guard tokens[0] == "auth", tokens[1] == "sufficient" else {
        throw PAMConfigurationError.unsupportedModuleEntry
      }
      return ModuleEntry(index: index, module: module)
    }

    guard matches.count <= 1 else {
      throw PAMConfigurationError.duplicateModuleEntries
    }
    guard nativeIndices.count + commentedNativeIndices.count == 1 else {
      if nativeIndices.isEmpty, commentedNativeIndices.isEmpty {
        throw PAMConfigurationError.nativeModuleAnchorMissing
      }
      throw PAMConfigurationError.unsupportedLocalPolicy
    }
    if let commentedIndex = commentedNativeIndices.first {
      lines[commentedIndex] = nativeLine
    }
    let removedModules = matches.map(\.module)
    for entry in matches.sorted(by: { $0.index > $1.index }) {
      lines.remove(at: entry.index)
    }

    return PAMConfigurationPlan(
      original: configuration,
      updated: lines.joined(separator: "\n"),
      removedModules: removedModules
    )
  }
}

public struct PAMLegacyReference: Equatable, Comparable, Sendable {
  public let policyPath: String
  public let module: String

  public init(policyPath: String, module: String) {
    self.policyPath = policyPath
    self.module = module
  }

  public static func < (lhs: PAMLegacyReference, rhs: PAMLegacyReference) -> Bool {
    (lhs.policyPath, lhs.module) < (rhs.policyPath, rhs.module)
  }
}

public enum PAMReferenceScanner {
  public static func removableReferences(in policies: [String: Data]) throws
    -> [PAMLegacyReference]
  {
    try references(in: policies, moduleIndex: 2)
  }

  public static func pamConfReferences(in policies: [String: Data]) throws
    -> [PAMLegacyReference]
  {
    try references(in: policies, moduleIndex: 3)
  }

  private static func references(in policies: [String: Data], moduleIndex: Int) throws
    -> [PAMLegacyReference]
  {
    try policies.flatMap { path, data -> [PAMLegacyReference] in
      guard let content = String(data: data, encoding: .utf8), !data.contains(0) else {
        throw PAMConfigurationError.invalidEncoding
      }
      return content.components(separatedBy: "\n").compactMap { line in
        guard let tokens = policyTokens(line), tokens.count > moduleIndex else { return nil }
        let module = moduleName(tokens[moduleIndex])
        guard PAMConfigurationPlanner.removableModules.contains(module) else { return nil }
        return PAMLegacyReference(policyPath: path, module: module)
      }
    }.sorted()
  }
}

private struct ModuleEntry {
  let index: Int
  let module: String
}

private func policyTokens(_ line: String) -> [String]? {
  let active = line.prefix { $0 != "#" }
  let tokens = active.split(whereSeparator: { $0.isWhitespace }).map(String.init)
  return tokens.isEmpty ? nil : tokens
}

private func commentedPolicyTokens(_ line: String) -> [String]? {
  let trimmed = line.drop(while: { $0.isWhitespace })
  guard trimmed.first == "#" else { return nil }
  let comment = trimmed.dropFirst().drop(while: { $0.isWhitespace })
  let tokens = comment.split(whereSeparator: { $0.isWhitespace }).map(String.init)
  return tokens.isEmpty ? nil : tokens
}

private func moduleName(_ token: String) -> String {
  token.split(separator: "/").last.map(String.init) ?? token
}
