import Darwin
import Foundation
import PAMCompanionCore

private func writeLine(_ value: String, to handle: FileHandle) {
  handle.write(Data((value + "\n").utf8))
}

private func installedModuleURL(arguments: [String]) -> URL {
  let invoked = arguments.first ?? "pam-companion"
  let executable = URL(
    fileURLWithPath: invoked,
    relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
  ).standardizedFileURL.resolvingSymlinksInPath()
  return executable.deletingLastPathComponent()
    .deletingLastPathComponent()
    .appendingPathComponent("libexec/pam_companion.so")
}

let arguments = CommandLine.arguments
let lifecycle = PAMLifecycleManager(
  paths: .system(moduleSource: installedModuleURL(arguments: arguments))
)
let runner = PAMCommandLineRunner(
  lifecycle: lifecycle,
  standardOutput: { writeLine($0, to: .standardOutput) },
  standardError: { writeLine($0, to: .standardError) }
)
exit(runner.run(arguments))
