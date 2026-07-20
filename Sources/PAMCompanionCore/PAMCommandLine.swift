public enum PAMCommand: Equatable, Sendable {
  case help
  case version
  case status
  case doctor
  case setup(dryRun: Bool)
  case restore(dryRun: Bool)
  case uninstallPrepare(dryRun: Bool)

  public var requiresRoot: Bool {
    switch self {
    case .status, .doctor, .setup, .restore, .uninstallPrepare: true
    case .help, .version: false
    }
  }
}

public enum PAMCommandLineError: Error, Equatable, CustomStringConvertible {
  case usage

  public var description: String {
    "usage: pam-companion <status|doctor|setup|restore|uninstall --prepare> [--dry-run]"
  }
}

public enum PAMCommandLineParser {
  public static func parse(_ arguments: [String]) throws -> PAMCommand {
    let values = Array(arguments.dropFirst())
    switch values {
    case ["help"], ["--help"], ["-h"]:
      return .help
    case ["--version"], ["version"]:
      return .version
    case ["status"]:
      return .status
    case ["doctor"]:
      return .doctor
    case ["setup"]:
      return .setup(dryRun: false)
    case ["setup", "--dry-run"]:
      return .setup(dryRun: true)
    case ["restore"]:
      return .restore(dryRun: false)
    case ["restore", "--dry-run"]:
      return .restore(dryRun: true)
    case ["uninstall", "--prepare"]:
      return .uninstallPrepare(dryRun: false)
    case ["uninstall", "--prepare", "--dry-run"]:
      return .uninstallPrepare(dryRun: true)
    default:
      throw PAMCommandLineError.usage
    }
  }
}
