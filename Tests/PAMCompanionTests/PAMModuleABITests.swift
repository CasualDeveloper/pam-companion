import CPAM
import XCTest

@testable import PAMCompanion

final class PAMModuleABITests: XCTestCase {
  func testCShimUsesSystemPAMConstants() {
    XCTAssertEqual(pam_companion_pam_success(), 0)
    XCTAssertEqual(pam_companion_pam_auth_err(), 9)
    XCTAssertEqual(pam_companion_pam_ignore(), 25)
    XCTAssertEqual(pam_companion_pam_silent(), CInt.min)
  }

  func testUnhandledModuleFunctionsReturnSystemPAMIgnore() {
    let expected = pam_companion_pam_ignore()

    XCTAssertEqual(pamModuleSetCredentials(nil, 0, 0, nil), expected)
    XCTAssertEqual(pamModuleAccountManagement(nil, 0, 0, nil), expected)
    XCTAssertEqual(pamModuleChangeAuthenticationToken(nil, 0, 0, nil), expected)
  }

  func testAuthenticateRejectsInvalidCArgumentBoundariesWithoutEvaluation() {
    let expected = pam_companion_pam_ignore()

    XCTAssertEqual(pamModuleAuthenticate(nil, 0, -1, nil), expected)
    XCTAssertEqual(pamModuleAuthenticate(nil, 0, 1, nil), expected)
    XCTAssertEqual(pamModuleAuthenticate(nil, 0, 65, nil), expected)
  }

  func testAuthenticateRejectsNullInvalidUTF8AndOverlongCArguments() {
    let expected = pam_companion_pam_ignore()

    var nullArgument: UnsafePointer<CChar>? = nil
    XCTAssertEqual(
      withUnsafePointer(to: &nullArgument) {
        pamModuleAuthenticate(nil, 0, 1, $0)
      },
      expected
    )

    let invalidUTF8: [CChar] = [CChar(bitPattern: 0xff), 0]
    invalidUTF8.withUnsafeBufferPointer { buffer in
      var argument = buffer.baseAddress.map(UnsafePointer.init)
      XCTAssertEqual(
        withUnsafePointer(to: &argument) {
          pamModuleAuthenticate(nil, 0, 1, $0)
        },
        expected
      )
    }

    var overlong = [CChar](repeating: 65, count: 4_097)
    overlong.append(0)
    overlong.withUnsafeBufferPointer { buffer in
      var argument = buffer.baseAddress.map(UnsafePointer.init)
      XCTAssertEqual(
        withUnsafePointer(to: &argument) {
          pamModuleAuthenticate(nil, 0, 1, $0)
        },
        expected
      )
    }
  }
}
