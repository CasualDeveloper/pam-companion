import Darwin
import Foundation
import MachO

public enum PAMExecutableLocationError: Error, CustomStringConvertible {
  case unavailable

  public var description: String {
    "could not resolve the installed pam-companion executable"
  }
}

public enum PAMExecutableLocation {
  public static func installedModuleURL() throws -> URL {
    try installedModuleURL(arguments: CommandLine.arguments, executablePath: actualExecutablePath)
  }

  static func installedModuleURL(
    arguments _: [String],
    executablePath: () throws -> String
  ) throws -> URL {
    let invoked = try executablePath()
    guard let canonical = realpath(invoked, nil) else {
      throw PAMExecutableLocationError.unavailable
    }
    defer { free(canonical) }
    let executable = URL(
      fileURLWithFileSystemRepresentation: canonical,
      isDirectory: false,
      relativeTo: nil
    )
    return executable.deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("libexec/pam_companion.so")
  }

  private static func actualExecutablePath() throws -> String {
    var size: UInt32 = 0
    guard _NSGetExecutablePath(nil, &size) == -1, size > 0 else {
      throw PAMExecutableLocationError.unavailable
    }
    var buffer = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buffer, &size) == 0 else {
      throw PAMExecutableLocationError.unavailable
    }
    return String(decoding: buffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
  }
}
