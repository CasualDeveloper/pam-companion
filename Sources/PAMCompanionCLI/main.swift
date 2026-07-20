import Darwin
import Foundation
import PAMCompanionCore

private func writeLine(_ value: String, to handle: FileHandle) {
  handle.write(Data((value + "\n").utf8))
}

let arguments = CommandLine.arguments
let moduleURL: URL
do {
  moduleURL = try PAMExecutableLocation.installedModuleURL()
} catch {
  writeLine("pam-companion: \(error)", to: .standardError)
  exit(1)
}
let lifecycle = PAMLifecycleManager(
  paths: .system(moduleSource: moduleURL)
)
let runner = PAMCommandLineRunner(
  lifecycle: lifecycle,
  standardOutput: { writeLine($0, to: .standardOutput) },
  standardError: { writeLine($0, to: .standardError) }
)
exit(runner.run(arguments))
