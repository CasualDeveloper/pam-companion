import CPAM
import Darwin
import Foundation
import LocalAuthentication
import PAMCompanionCore

private let systemCodes = PAMResultCodes(
  success: pam_companion_pam_success(),
  authenticationError: pam_companion_pam_auth_err(),
  ignore: pam_companion_pam_ignore(),
  silent: pam_companion_pam_silent()
)

@_cdecl("pam_sm_authenticate")
public func pamModuleAuthenticate(
  _ pamh: UnsafeMutableRawPointer?,
  _ flags: CInt,
  _ argc: CInt,
  _ argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> CInt {
  _ = pamh
  guard let moduleArguments = decodeModuleArguments(argc: argc, argv: argv) else {
    return systemCodes.ignore
  }
  let engine = PAMAuthenticationEngine(
    codes: systemCodes,
    processArguments: ProcessInfo.processInfo.arguments,
    makeAuthenticator: { LocalAuthenticationAdapter() },
    waiter: DispatchPAMAuthenticationWaiter(),
    errorReporter: StandardErrorReporter()
  )
  return engine.authenticate(flags: flags, moduleArguments: moduleArguments)
}

@_cdecl("pam_sm_setcred")
public func pamModuleSetCredentials(
  _ pamh: UnsafeMutableRawPointer?,
  _ flags: CInt,
  _ argc: CInt,
  _ argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> CInt {
  systemCodes.ignore
}

@_cdecl("pam_sm_acct_mgmt")
public func pamModuleAccountManagement(
  _ pamh: UnsafeMutableRawPointer?,
  _ flags: CInt,
  _ argc: CInt,
  _ argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> CInt {
  systemCodes.ignore
}

@_cdecl("pam_sm_chauthtok")
public func pamModuleChangeAuthenticationToken(
  _ pamh: UnsafeMutableRawPointer?,
  _ flags: CInt,
  _ argc: CInt,
  _ argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> CInt {
  systemCodes.ignore
}

private func decodeModuleArguments(
  argc: CInt,
  argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> [String]? {
  let maximumArgumentCount = 64
  let maximumArgumentBytes = 4_096
  guard argc >= 0, argc <= maximumArgumentCount else { return nil }
  if argc == 0 { return [] }
  guard let argv else { return nil }

  var result: [String] = []
  result.reserveCapacity(Int(argc))
  for index in 0..<Int(argc) {
    guard let pointer = argv[index] else { return nil }
    let length = strnlen(pointer, maximumArgumentBytes + 1)
    guard length <= maximumArgumentBytes,
      let value = String(
        bytes: UnsafeRawBufferPointer(start: pointer, count: length),
        encoding: .utf8
      )
    else {
      return nil
    }
    result.append(value)
  }
  return result
}

private final class LocalAuthenticationAdapter: PAMLocalAuthenticating {
  private let context = LAContext()
  private let policy: LAPolicy

  init() {
    #if canImport(CoreHID)  // CoreHID is present in SDKs that declare the macOS 15 policy.
      if #available(macOS 15.0, *) {
        policy = .deviceOwnerAuthenticationWithBiometricsOrCompanion
      } else {
        policy = .deviceOwnerAuthenticationWithBiometricsOrWatch
      }
    #else
      policy = .deviceOwnerAuthenticationWithBiometricsOrWatch
    #endif
  }

  func canEvaluate() -> Bool {
    var error: NSError?
    return context.canEvaluatePolicy(policy, error: &error)
  }

  func evaluate(
    reason: String,
    completion: @escaping @Sendable (Bool, Error?) -> Void
  ) {
    context.evaluatePolicy(policy, localizedReason: reason, reply: completion)
  }

  func cancel() {
    context.invalidate()
  }
}

private final class StandardErrorReporter: PAMAuthenticationErrorReporting {
  func report(_ error: Error) {
    fputs("\(error.localizedDescription)\n", stderr)
  }
}
