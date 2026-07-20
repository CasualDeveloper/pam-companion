import Darwin
import Foundation
import PAMCompanionCore

private func writeLine(_ value: String, to handle: FileHandle) {
  handle.write(Data((value + "\n").utf8))
}

let arguments = CommandLine.arguments
let lifecycle = PAMLifecycleManager(
  paths: .system()
)
let runner = PAMCommandLineRunner(
  lifecycle: lifecycle,
  standardOutput: { writeLine($0, to: .standardOutput) },
  standardError: { writeLine($0, to: .standardError) }
)
exit(runner.run(arguments))
