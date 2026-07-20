import Darwin

public enum PAMCompanionVersion {
  public static let current = "0.1.0"
}

public struct PAMCommandLineRunner {
  private let lifecycle: any PAMLifecycleManaging
  private let effectiveUserID: uid_t
  private let standardOutput: (String) -> Void
  private let standardError: (String) -> Void

  public init(
    lifecycle: any PAMLifecycleManaging,
    effectiveUserID: uid_t = geteuid(),
    standardOutput: @escaping (String) -> Void,
    standardError: @escaping (String) -> Void
  ) {
    self.lifecycle = lifecycle
    self.effectiveUserID = effectiveUserID
    self.standardOutput = standardOutput
    self.standardError = standardError
  }

  public func run(_ arguments: [String]) -> Int32 {
    let command: PAMCommand
    do {
      command = try PAMCommandLineParser.parse(arguments)
    } catch {
      standardError(String(describing: error))
      return 2
    }

    if command.requiresRoot, effectiveUserID != 0 {
      standardError("pam-companion: \(PAMLifecycleError.rootRequired)")
      return 1
    }

    do {
      switch command {
      case .help:
        standardOutput(Self.help)
      case .version:
        standardOutput("pam-companion \(PAMCompanionVersion.current)")
      case .status:
        standardOutput(statusLine(try lifecycle.status()))
      case .doctor:
        return doctor(try lifecycle.status())
      case .setup(let dryRun):
        standardOutput(try lifecycle.setup(dryRun: dryRun).summary)
      case .restore(let dryRun), .uninstallPrepare(let dryRun):
        standardOutput(try lifecycle.restore(dryRun: dryRun).summary)
      }
      return 0
    } catch {
      standardError("pam-companion: \(error)")
      return 1
    }
  }

  private func doctor(_ status: PAMLifecycleStatus) -> Int32 {
    if status == .configured {
      standardOutput("ok: pam_companion.so is installed and sudo_local is managed")
      return 0
    }
    standardError("error: \(statusLine(status))")
    return 1
  }

  private func statusLine(_ status: PAMLifecycleStatus) -> String {
    switch status {
    case .notConfigured: "not configured: run sudo pam-companion setup"
    case .legacy: "legacy: pam_watchid installation detected"
    case .configured: "configured: pam_companion.so is managed"
    case .unmanaged: "unmanaged: companion files exist without lifecycle state"
    case .recoveryRequired: "recovery required: run sudo pam-companion restore"
    case .drifted: "drifted: managed PAM files changed after setup"
    }
  }

  private static let help = """
    Usage: pam-companion <command>

      status                  Show the current PAM integration state
      doctor                  Check whether the managed integration is healthy
      setup [--dry-run]       Install and enable pam_companion.so (requires sudo)
      restore [--dry-run]     Restore the pre-setup PAM state (requires sudo)
      uninstall --prepare     Restore PAM before Homebrew removal (requires sudo)
      --version               Print the version
    """
}
