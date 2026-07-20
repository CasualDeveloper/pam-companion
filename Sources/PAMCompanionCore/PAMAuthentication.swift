import Foundation

public struct PAMResultCodes: Equatable, Sendable {
  public let success: CInt
  public let authenticationError: CInt
  public let ignore: CInt
  public let silent: CInt

  public init(
    success: CInt,
    authenticationError: CInt,
    ignore: CInt,
    silent: CInt
  ) {
    self.success = success
    self.authenticationError = authenticationError
    self.ignore = ignore
    self.silent = silent
  }
}

public struct PAMModuleOptions: Equatable, Sendable {
  public let reason: String
  public let timeoutSeconds: TimeInterval
}

public enum PAMModuleOptionError: Error, Equatable, CustomStringConvertible {
  case tooManyArguments
  case unknownArgument(String)
  case duplicateArgument(String)
  case invalidReason
  case invalidTimeout

  public var description: String {
    switch self {
    case .tooManyArguments: return "at most 64 module arguments are accepted"
    case .unknownArgument(let name): return "unknown module argument: \(name)"
    case .duplicateArgument(let name): return "duplicate module argument: \(name)"
    case .invalidReason:
      return "reason must be a single control-free UTF-8 value of at most 512 bytes"
    case .invalidTimeout: return "timeout must be an integer from 1 through 120 seconds"
    }
  }
}

public enum PAMModuleOptionParser {
  public static let defaultReason = "perform an action that requires authentication"
  public static let defaultTimeoutSeconds: TimeInterval = 30

  public static func parse(_ arguments: [String]) throws -> PAMModuleOptions {
    guard arguments.count <= 64 else { throw PAMModuleOptionError.tooManyArguments }
    var reason: String?
    var timeout: TimeInterval?

    for argument in arguments {
      guard let separator = argument.firstIndex(of: "=") else {
        throw PAMModuleOptionError.unknownArgument(argument)
      }
      let name = String(argument[..<separator])
      let value = String(argument[argument.index(after: separator)...])
      switch name {
      case "reason":
        guard reason == nil else {
          throw PAMModuleOptionError.duplicateArgument(name)
        }
        guard value.utf8.count <= 512,
          value.rangeOfCharacter(from: .controlCharacters) == nil
        else {
          throw PAMModuleOptionError.invalidReason
        }
        reason = value
      case "timeout":
        guard timeout == nil else {
          throw PAMModuleOptionError.duplicateArgument(name)
        }
        guard !value.isEmpty,
          value.unicodeScalars.allSatisfy({ (48...57).contains($0.value) }),
          let seconds = Int(value),
          (1...120).contains(seconds)
        else {
          throw PAMModuleOptionError.invalidTimeout
        }
        timeout = TimeInterval(seconds)
      default:
        throw PAMModuleOptionError.unknownArgument(name)
      }
    }

    let resolvedReason = reason.flatMap { $0.isEmpty ? nil : $0 } ?? defaultReason
    return PAMModuleOptions(
      reason: resolvedReason,
      timeoutSeconds: timeout ?? defaultTimeoutSeconds
    )
  }
}

public enum SudoAskpassDetector {
  private static let shortOptionsWithValues: Set<Character> = [
    "C", "D", "g", "h", "p", "R", "T", "U", "u",
  ]
  private static let longOptionsWithValues: Set<String> = [
    "chdir", "chroot", "close-from", "command-timeout", "group", "host",
    "other-user", "prompt", "user",
  ]

  public static func usesAskpass(_ arguments: [String]) -> Bool {
    guard let executable = arguments.first,
      URL(fileURLWithPath: executable).lastPathComponent == "sudo"
    else {
      return false
    }

    var index = 1
    while index < arguments.count {
      let argument = arguments[index]
      if argument == "--" || argument == "-" || !argument.hasPrefix("-") {
        return false
      }
      if argument == "--askpass" { return true }
      if argument.hasPrefix("--") {
        let option = String(argument.dropFirst(2))
        let name = option.split(separator: "=", maxSplits: 1).first.map(String.init) ?? ""
        if longOptionsWithValues.contains(name), !option.contains("=") {
          index += 1
        }
        index += 1
        continue
      }

      let cluster = Array(argument.dropFirst())
      var clusterIndex = 0
      while clusterIndex < cluster.count {
        let option = cluster[clusterIndex]
        if option == "A" { return true }
        if shortOptionsWithValues.contains(option) {
          if clusterIndex == cluster.count - 1 { index += 1 }
          break
        }
        clusterIndex += 1
      }
      index += 1
    }
    return false
  }
}

public protocol PAMLocalAuthenticating: AnyObject {
  func canEvaluate() -> Bool
  func evaluate(
    reason: String,
    completion: @escaping @Sendable (Bool, Error?) -> Void
  )
  func cancel()
}

public protocol PAMAuthenticationWaiting {
  func wait(on semaphore: DispatchSemaphore, timeoutSeconds: TimeInterval) -> Bool
}

public protocol PAMAuthenticationErrorReporting: AnyObject {
  func report(_ error: Error)
}

public struct DispatchPAMAuthenticationWaiter: PAMAuthenticationWaiting {
  public init() {}

  public func wait(on semaphore: DispatchSemaphore, timeoutSeconds: TimeInterval) -> Bool {
    semaphore.wait(timeout: .now() + timeoutSeconds) == .success
  }
}

public final class PAMAuthenticationEngine {
  private let codes: PAMResultCodes
  private let processArguments: [String]
  private let makeAuthenticator: () -> any PAMLocalAuthenticating
  private let waiter: any PAMAuthenticationWaiting
  private let errorReporter: any PAMAuthenticationErrorReporting

  public init(
    codes: PAMResultCodes,
    processArguments: [String],
    makeAuthenticator: @escaping () -> any PAMLocalAuthenticating,
    waiter: any PAMAuthenticationWaiting,
    errorReporter: any PAMAuthenticationErrorReporting
  ) {
    self.codes = codes
    self.processArguments = processArguments
    self.makeAuthenticator = makeAuthenticator
    self.waiter = waiter
    self.errorReporter = errorReporter
  }

  public func authenticate(flags: CInt, moduleArguments: [String]) -> CInt {
    if SudoAskpassDetector.usesAskpass(processArguments) { return codes.ignore }
    guard let options = try? PAMModuleOptionParser.parse(moduleArguments) else {
      return codes.ignore
    }

    let authenticator = makeAuthenticator()
    guard authenticator.canEvaluate() else { return codes.ignore }

    let latch = AuthenticationResultLatch()
    let isSilent = flags & codes.silent != 0
    authenticator.evaluate(reason: options.reason) { [codes] success, error in
      let result: CInt
      if error != nil {
        result = codes.ignore
      } else {
        result = success ? codes.success : codes.authenticationError
      }

      _ = latch.resolve(result, error: error)
    }

    let signaled = waiter.wait(
      on: latch.semaphore,
      timeoutSeconds: options.timeoutSeconds
    )
    let outcome = latch.finishWait(
      timeoutValue: codes.ignore,
      waiterTimedOut: !signaled
    )
    if outcome.didTimeOut { authenticator.cancel() }
    if let error = outcome.error, !isSilent {
      errorReporter.report(error)
    }
    return outcome.value
  }
}

private final class AuthenticationResultLatch: @unchecked Sendable {
  private enum State {
    case pending
    case completed(CInt, Error?)
    case timedOut
  }

  let semaphore = DispatchSemaphore(value: 0)
  private let lock = NSLock()
  private var state = State.pending

  func resolve(_ value: CInt, error: Error?) -> Bool {
    lock.lock()
    guard case .pending = state else {
      lock.unlock()
      return false
    }
    state = .completed(value, error)
    lock.unlock()
    semaphore.signal()
    return true
  }

  func finishWait(
    timeoutValue: CInt,
    waiterTimedOut: Bool
  ) -> (value: CInt, didTimeOut: Bool, error: Error?) {
    lock.lock()
    defer { lock.unlock() }
    if waiterTimedOut {
      state = .timedOut
      return (timeoutValue, true, nil)
    }
    if case .completed(let value, let error) = state {
      return (value, false, error)
    }
    state = .timedOut
    return (timeoutValue, true, nil)
  }
}
