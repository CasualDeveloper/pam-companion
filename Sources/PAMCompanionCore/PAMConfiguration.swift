import Foundation

public enum PAMConfigurationError: Error, Equatable, CustomStringConvertible {
  case invalidEncoding
  case duplicateModuleEntries
  case unsupportedModuleEntry
  case invalidModuleArguments
  case unsupportedLocalPolicy

  public var description: String {
    switch self {
    case .invalidEncoding:
      return "PAM configuration must be NUL-free UTF-8"
    case .duplicateModuleEntries:
      return "PAM configuration contains multiple companion module entries"
    case .unsupportedModuleEntry:
      return "companion module entries must use 'auth sufficient'"
    case .invalidModuleArguments:
      return "companion module entry contains unsupported arguments"
    case .unsupportedLocalPolicy:
      return
        "sudo_local contains an active entry outside the supported companion and Touch ID policy"
    }
  }
}

public struct PAMConfigurationPlan: Equatable, Sendable {
  public let original: String
  public let updated: String
  public let replacedLegacyModules: [String]

  public var changed: Bool { original != updated }
}

public enum PAMConfigurationPlanner {
  public static let canonicalModule = "pam_companion.so"
  public static let legacyModules = ["pam_watchid.so", "pam_watchid.so.2"]
  public static let canonicalLine = "auth       sufficient     pam_companion.so"

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
    var touchIDIndices: [Int] = []
    let matches = try lines.enumerated().compactMap { index, line -> ModuleEntry? in
      guard let tokens = policyTokens(line) else { return nil }
      guard tokens.count >= 3 else { throw PAMConfigurationError.unsupportedLocalPolicy }
      let module = moduleName(tokens[2])
      if module == "pam_tid.so" {
        guard tokens == ["auth", "sufficient", "pam_tid.so"] else {
          throw PAMConfigurationError.unsupportedLocalPolicy
        }
        touchIDIndices.append(index)
        return nil
      }
      guard module == canonicalModule || legacyModules.contains(module) else {
        throw PAMConfigurationError.unsupportedLocalPolicy
      }
      guard tokens[0] == "auth", tokens[1] == "sufficient" else {
        throw PAMConfigurationError.unsupportedModuleEntry
      }
      let arguments = Array(tokens.dropFirst(3))
      guard (try? PAMModuleOptionParser.parse(arguments)) != nil else {
        throw PAMConfigurationError.invalidModuleArguments
      }
      return ModuleEntry(index: index, module: module, arguments: arguments)
    }

    guard matches.count <= 1 else {
      throw PAMConfigurationError.duplicateModuleEntries
    }
    guard touchIDIndices.count <= 1 else {
      throw PAMConfigurationError.unsupportedLocalPolicy
    }
    if matches.first?.module == canonicalModule {
      return PAMConfigurationPlan(
        original: configuration,
        updated: configuration,
        replacedLegacyModules: []
      )
    }

    var arguments: [String] = []
    var replacedLegacyModules: [String] = []
    if let legacy = matches.first {
      arguments = legacy.arguments
      replacedLegacyModules = [legacy.module]
      lines.remove(at: legacy.index)
    }

    let insertionIndex =
      lines.firstIndex(where: { line in
        guard let tokens = policyTokens(line), tokens.count == 3 else { return false }
        return tokens == ["auth", "sufficient", "pam_tid.so"]
      }) ?? (lines.last == "" ? lines.count - 1 : lines.count)
    let suffix = arguments.isEmpty ? "" : " " + arguments.joined(separator: " ")
    lines.insert(canonicalLine + suffix, at: insertionIndex)

    return PAMConfigurationPlan(
      original: configuration,
      updated: lines.joined(separator: "\n"),
      replacedLegacyModules: replacedLegacyModules
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
  public static func legacyReferences(in policies: [String: Data]) throws -> [PAMLegacyReference] {
    try policies.flatMap { path, data -> [PAMLegacyReference] in
      guard let content = String(data: data, encoding: .utf8), !data.contains(0) else {
        throw PAMConfigurationError.invalidEncoding
      }
      return content.components(separatedBy: "\n").compactMap { line in
        guard let tokens = policyTokens(line), tokens.count >= 3 else { return nil }
        let module = moduleName(tokens[2])
        guard PAMConfigurationPlanner.legacyModules.contains(module) else { return nil }
        return PAMLegacyReference(policyPath: path, module: module)
      }
    }.sorted()
  }
}

private struct ModuleEntry {
  let index: Int
  let module: String
  let arguments: [String]
}

private func policyTokens(_ line: String) -> [String]? {
  let active = line.prefix { $0 != "#" }
  let tokens = active.split(whereSeparator: { $0.isWhitespace }).map(String.init)
  return tokens.isEmpty ? nil : tokens
}

private func moduleName(_ token: String) -> String {
  token.split(separator: "/").last.map(String.init) ?? token
}
