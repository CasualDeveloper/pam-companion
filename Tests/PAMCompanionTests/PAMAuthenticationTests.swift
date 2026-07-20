import Foundation
import XCTest

@testable import PAMCompanionCore

final class PAMModuleOptionParserTests: XCTestCase {
  func testDefaultsApplyWhenNoArgumentsArePresent() throws {
    let options = try PAMModuleOptionParser.parse([])

    XCTAssertEqual(options.reason, "perform an action that requires authentication")
    XCTAssertEqual(options.timeoutSeconds, 30)
  }

  func testReasonPreservesTokenizedUnicodeAndEqualsCharacters() throws {
    let options = try PAMModuleOptionParser.parse([
      "reason=Approve café 🔐 for project=companion"
    ])

    XCTAssertEqual(options.reason, "Approve café 🔐 for project=companion")
  }

  func testEmptyReasonUsesTheDefault() throws {
    let options = try PAMModuleOptionParser.parse(["reason="])

    XCTAssertEqual(options.reason, "perform an action that requires authentication")
  }

  func testTimeoutAcceptsOnlyTheDocumentedRange() throws {
    XCTAssertEqual(
      try PAMModuleOptionParser.parse(["timeout=1"]).timeoutSeconds,
      1
    )
    XCTAssertEqual(
      try PAMModuleOptionParser.parse(["timeout=120"]).timeoutSeconds,
      120
    )

    for argument in ["timeout=0", "timeout=121", "timeout=-1", "timeout=1.5"] {
      XCTAssertThrowsError(try PAMModuleOptionParser.parse([argument]))
    }
  }

  func testUnknownDuplicateAndUnsafeArgumentsAreRejected() {
    let invalidArguments = [
      ["debug"],
      ["unknown=value"],
      ["reason=one", "reason=two"],
      ["timeout=10", "timeout=20"],
      ["reason=line\nbreak"],
      ["reason=" + String(repeating: "a", count: 513)],
    ]

    for arguments in invalidArguments {
      XCTAssertThrowsError(try PAMModuleOptionParser.parse(arguments))
    }
  }

  func testArgumentCountAndReasonUTF8ByteLimitAreEnforced() throws {
    let maximumMultibyteReason = String(repeating: "🔐", count: 128)
    XCTAssertEqual(
      try PAMModuleOptionParser.parse(["reason=" + maximumMultibyteReason]).reason,
      maximumMultibyteReason
    )
    XCTAssertThrowsError(
      try PAMModuleOptionParser.parse(["reason=" + String(repeating: "🔐", count: 129)])
    )
    XCTAssertThrowsError(
      try PAMModuleOptionParser.parse(Array(repeating: "timeout=30", count: 65))
    )
  }
}

final class SudoAskpassDetectorTests: XCTestCase {
  func testDetectsShortLongAndClusteredAskpassOptions() {
    XCTAssertTrue(SudoAskpassDetector.usesAskpass(["sudo", "-A", "true"]))
    XCTAssertTrue(SudoAskpassDetector.usesAskpass(["sudo", "--askpass", "true"]))
    XCTAssertTrue(SudoAskpassDetector.usesAskpass(["sudo", "-ABk", "true"]))
    XCTAssertTrue(SudoAskpassDetector.usesAskpass(["sudo", "-u", "root", "-A", "true"]))
  }

  func testDoesNotInterpretCommandArgumentsAsSudoOptions() {
    XCTAssertFalse(SudoAskpassDetector.usesAskpass(["sudo", "echo", "-A"]))
    XCTAssertFalse(SudoAskpassDetector.usesAskpass(["sudo", "--", "echo", "--askpass"]))
    XCTAssertFalse(SudoAskpassDetector.usesAskpass(["not-sudo", "-A"]))
    XCTAssertFalse(SudoAskpassDetector.usesAskpass(["sudo", "-uA", "true"]))
    XCTAssertFalse(
      SudoAskpassDetector.usesAskpass(["sudo", "--prompt", "--askpass", "true"])
    )
  }
}

final class PAMAuthenticationEngineTests: XCTestCase {
  private let codes = PAMResultCodes(
    success: 100,
    authenticationError: 109,
    ignore: 125,
    silent: CInt(bitPattern: 0x8000_0000)
  )

  func testAskpassReturnsIgnoreWithoutCreatingAnAuthenticator() {
    let factory = RecordingAuthenticatorFactory()
    let engine = makeEngine(
      processArguments: ["sudo", "-A", "true"],
      factory: factory
    )

    XCTAssertEqual(engine.authenticate(flags: 0, moduleArguments: []), codes.ignore)
    XCTAssertEqual(factory.makeCount, 0)
  }

  func testMalformedArgumentsReturnIgnoreWithoutCreatingAnAuthenticator() {
    let factory = RecordingAuthenticatorFactory()
    let engine = makeEngine(factory: factory)

    XCTAssertEqual(
      engine.authenticate(flags: 0, moduleArguments: ["timeout=invalid"]),
      codes.ignore
    )
    XCTAssertEqual(factory.makeCount, 0)
  }

  func testUnavailablePolicyReturnsIgnoreWithoutStartingEvaluation() {
    let authenticator = ControlledAuthenticator(canEvaluate: false)
    let engine = makeEngine(authenticator: authenticator)

    XCTAssertEqual(engine.authenticate(flags: 0, moduleArguments: []), codes.ignore)
    XCTAssertEqual(authenticator.evaluateCount, 0)
  }

  func testSuccessfulAuthenticationReturnsSuccess() {
    let authenticator = ControlledAuthenticator(outcome: .success)
    let engine = makeEngine(authenticator: authenticator)

    XCTAssertEqual(engine.authenticate(flags: 0, moduleArguments: []), codes.success)
    XCTAssertEqual(authenticator.reasons, ["perform an action that requires authentication"])
  }

  func testFalseCallbackWithoutErrorReturnsAuthenticationError() {
    let authenticator = ControlledAuthenticator(outcome: .rejected)
    let engine = makeEngine(authenticator: authenticator)

    XCTAssertEqual(
      engine.authenticate(flags: 0, moduleArguments: []),
      codes.authenticationError
    )
  }

  func testAuthenticationErrorReturnsIgnoreAndReportsWhenNotSilent() {
    let authenticator = ControlledAuthenticator(outcome: .error(TestAuthenticationError.denied))
    let reporter = RecordingErrorReporter()
    let engine = makeEngine(authenticator: authenticator, reporter: reporter)

    XCTAssertEqual(engine.authenticate(flags: 0, moduleArguments: []), codes.ignore)
    XCTAssertEqual(reporter.messages, [TestAuthenticationError.denied.localizedDescription])
  }

  func testPAMSilentSuppressesAuthenticationErrorOutput() {
    let authenticator = ControlledAuthenticator(outcome: .error(TestAuthenticationError.denied))
    let reporter = RecordingErrorReporter()
    let engine = makeEngine(authenticator: authenticator, reporter: reporter)

    XCTAssertEqual(
      engine.authenticate(flags: codes.silent, moduleArguments: []),
      codes.ignore
    )
    XCTAssertTrue(reporter.messages.isEmpty)
  }

  func testTimeoutCancelsEvaluationAndReturnsIgnore() {
    let authenticator = ControlledAuthenticator(outcome: .deferred)
    let waiter = StubWaiter(signaled: false)
    let engine = makeEngine(authenticator: authenticator, waiter: waiter)

    XCTAssertEqual(
      engine.authenticate(flags: 0, moduleArguments: ["timeout=7"]),
      codes.ignore
    )
    XCTAssertEqual(waiter.timeouts, [7])
    XCTAssertEqual(authenticator.cancelCount, 1)
  }

  func testTimeoutWinsAgainstCallbackArrivingAfterDeadline() {
    let authenticator = ControlledAuthenticator(outcome: .deferred)
    let reporter = RecordingErrorReporter()
    let waiter = StubWaiter(signaled: false) {
      authenticator.complete(.error(TestAuthenticationError.denied))
    }
    let engine = makeEngine(
      authenticator: authenticator,
      waiter: waiter,
      reporter: reporter
    )

    XCTAssertEqual(engine.authenticate(flags: 0, moduleArguments: []), codes.ignore)
    XCTAssertEqual(authenticator.cancelCount, 1)
    XCTAssertTrue(reporter.messages.isEmpty)
  }

  func testCallbackAfterTimeoutIsIgnoredWithoutLateOutput() {
    let authenticator = ControlledAuthenticator(outcome: .deferred)
    let reporter = RecordingErrorReporter()
    let engine = makeEngine(
      authenticator: authenticator,
      waiter: StubWaiter(signaled: false),
      reporter: reporter
    )

    XCTAssertEqual(engine.authenticate(flags: 0, moduleArguments: []), codes.ignore)
    authenticator.complete(.error(TestAuthenticationError.denied))
    XCTAssertTrue(reporter.messages.isEmpty)
  }

  func testOnlyTheFirstCallbackControlsTheResultAndOutput() {
    let authenticator = ControlledAuthenticator(outcome: .deferred)
    let reporter = RecordingErrorReporter()
    let waiter = StubWaiter(signaled: true) {
      authenticator.complete(.success)
      authenticator.complete(.error(TestAuthenticationError.denied))
    }
    let engine = makeEngine(
      authenticator: authenticator,
      waiter: waiter,
      reporter: reporter
    )

    XCTAssertEqual(engine.authenticate(flags: 0, moduleArguments: []), codes.success)
    XCTAssertTrue(reporter.messages.isEmpty)
  }

  private func makeEngine(
    processArguments: [String] = ["sudo", "true"],
    authenticator: ControlledAuthenticator = ControlledAuthenticator(outcome: .success),
    factory: RecordingAuthenticatorFactory? = nil,
    waiter: StubWaiter = StubWaiter(signaled: true),
    reporter: RecordingErrorReporter = RecordingErrorReporter()
  ) -> PAMAuthenticationEngine {
    let factory = factory ?? RecordingAuthenticatorFactory(authenticator: authenticator)
    return PAMAuthenticationEngine(
      codes: codes,
      processArguments: processArguments,
      makeAuthenticator: factory.make,
      waiter: waiter,
      errorReporter: reporter
    )
  }
}

private enum ControlledOutcome {
  case success
  case rejected
  case error(Error)
  case deferred
}

private final class ControlledAuthenticator: PAMLocalAuthenticating {
  private let canEvaluateResult: Bool
  private let outcome: ControlledOutcome
  private var completion: (@Sendable (Bool, Error?) -> Void)?
  private(set) var evaluateCount = 0
  private(set) var cancelCount = 0
  private(set) var reasons: [String] = []

  init(canEvaluate: Bool = true, outcome: ControlledOutcome = .deferred) {
    canEvaluateResult = canEvaluate
    self.outcome = outcome
  }

  func canEvaluate() -> Bool { canEvaluateResult }

  func evaluate(
    reason: String,
    completion: @escaping @Sendable (Bool, Error?) -> Void
  ) {
    evaluateCount += 1
    reasons.append(reason)
    self.completion = completion
    complete(outcome)
  }

  func cancel() { cancelCount += 1 }

  func complete(_ outcome: ControlledOutcome) {
    switch outcome {
    case .success: completion?(true, nil)
    case .rejected: completion?(false, nil)
    case .error(let error): completion?(false, error)
    case .deferred: break
    }
  }
}

private final class RecordingAuthenticatorFactory {
  private let authenticator: ControlledAuthenticator
  private(set) var makeCount = 0

  init(authenticator: ControlledAuthenticator = ControlledAuthenticator(outcome: .success)) {
    self.authenticator = authenticator
  }

  func make() -> any PAMLocalAuthenticating {
    makeCount += 1
    return authenticator
  }
}

private final class StubWaiter: PAMAuthenticationWaiting {
  private let signaled: Bool
  private let beforeReturn: () -> Void
  private(set) var timeouts: [TimeInterval] = []

  init(signaled: Bool, beforeReturn: @escaping () -> Void = {}) {
    self.signaled = signaled
    self.beforeReturn = beforeReturn
  }

  func wait(on semaphore: DispatchSemaphore, timeoutSeconds: TimeInterval) -> Bool {
    timeouts.append(timeoutSeconds)
    beforeReturn()
    return signaled
  }
}

private final class RecordingErrorReporter: PAMAuthenticationErrorReporting {
  private(set) var messages: [String] = []

  func report(_ error: Error) {
    messages.append(error.localizedDescription)
  }
}

private enum TestAuthenticationError: LocalizedError {
  case denied

  var errorDescription: String? { "authentication denied" }
}
