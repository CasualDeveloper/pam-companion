import CryptoKit
import Darwin
import Foundation

struct PAMLifecycleFileSystem {
  let expectedOwnerUserID: uid_t
  let expectedOwnerGroupID: gid_t
  private let fileManager = FileManager.default
  private let maximumModuleSize = 64 * 1024 * 1024

  func exists(_ url: URL) -> Bool {
    var info = stat()
    return lstat(url.path, &info) == 0
  }

  func read(_ url: URL) throws -> Data {
    do {
      return try Data(contentsOf: url, options: .mappedIfSafe)
    } catch {
      throw fileSystemError(url.path)
    }
  }

  func validateRegularRootTarget(_ url: URL) throws {
    try validateAncestors(of: url)
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw fileSystemError(url.path) }
    guard info.st_mode & S_IFMT == S_IFREG,
      info.st_uid == expectedOwnerUserID,
      info.st_gid == expectedOwnerGroupID,
      info.st_mode & 0o022 == 0,
      info.st_nlink == 1,
      !hasUnsafeFlags(info),
      try !hasExtendedACL(url.path)
    else {
      throw PAMLifecycleError.unsafePath(url.path)
    }
  }

  func validateDirectory(_ url: URL) throws {
    try validateAncestors(of: url)
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw fileSystemError(url.path) }
    guard info.st_mode & S_IFMT == S_IFDIR,
      info.st_uid == expectedOwnerUserID,
      info.st_gid == expectedOwnerGroupID,
      info.st_mode & 0o022 == 0,
      !hasUnsafeFlags(info),
      try !hasExtendedACL(url.path)
    else {
      throw PAMLifecycleError.unsafePath(url.path)
    }
  }

  func validateStateDirectory(_ url: URL) throws {
    try validateAncestors(of: url)
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw fileSystemError(url.path) }
    guard info.st_mode & S_IFMT == S_IFDIR,
      info.st_uid == expectedOwnerUserID,
      info.st_gid == expectedOwnerGroupID,
      info.st_mode & 0o777 == 0o700,
      !hasUnsafeFlags(info),
      try !hasExtendedACL(url.path)
    else {
      throw PAMLifecycleError.unsafePath(url.path)
    }
  }

  func validateRecordFile(_ url: URL) throws {
    try validateAncestors(of: url)
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw fileSystemError(url.path) }
    guard info.st_mode & S_IFMT == S_IFREG,
      info.st_uid == expectedOwnerUserID,
      info.st_gid == expectedOwnerGroupID,
      info.st_mode & 0o777 == 0o600,
      info.st_nlink == 1,
      !hasUnsafeFlags(info),
      try !hasExtendedACL(url.path)
    else {
      throw PAMLifecycleError.unsafePath(url.path)
    }
  }

  func readSourceModule(_ url: URL) throws -> Data {
    try validateAncestors(of: url)
    let descriptor = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw fileSystemError(url.path) }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0 else { throw fileSystemError(url.path) }
    guard info.st_mode & S_IFMT == S_IFREG,
      info.st_mode & 0o022 == 0,
      info.st_nlink == 1,
      info.st_size > 0,
      info.st_size <= maximumModuleSize,
      !hasUnsafeFlags(info),
      try !hasExtendedACL(descriptor)
    else {
      throw PAMLifecycleError.unsafePath(url.path)
    }
    var data = Data(count: Int(info.st_size))
    let total = data.count
    var offset = 0
    while offset < total {
      let count = data.withUnsafeMutableBytes { bytes in
        Darwin.pread(
          descriptor,
          bytes.baseAddress?.advanced(by: offset),
          total - offset,
          off_t(offset)
        )
      }
      guard count > 0 else { throw fileSystemError(url.path) }
      offset += count
    }
    return data
  }

  func withTemporaryModule<T>(_ data: Data, operation: (URL) throws -> T) throws -> T {
    var template = Array("/var/tmp/pam-companion.validate.XXXXXX".utf8CString)
    let descriptor = mkstemp(&template)
    guard descriptor >= 0 else { throw fileSystemError("/var/tmp") }
    let path = String(
      decoding: template.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
    let url = URL(fileURLWithPath: path)
    defer {
      close(descriptor)
      _ = unlink(url.path)
    }
    guard fchmod(descriptor, 0o400) == 0,
      fchown(descriptor, expectedOwnerUserID, expectedOwnerGroupID) == 0
    else {
      throw fileSystemError(url.path)
    }
    try write(data, to: descriptor, path: url.path)
    guard fsync(descriptor) == 0 else { throw fileSystemError(url.path) }
    return try operation(url)
  }

  func policyFiles(in directory: URL) throws -> [String: Data] {
    let urls: [URL]
    do {
      urls = try fileManager.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
        options: [.skipsHiddenFiles]
      )
    } catch {
      throw fileSystemError(directory.path)
    }
    var policies: [String: Data] = [:]
    for url in urls {
      let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
      guard values.isSymbolicLink != true else { throw PAMLifecycleError.unsafePath(url.path) }
      guard values.isRegularFile == true else { continue }
      try validateRegularRootTarget(url)
      policies[url.path] = try read(url)
    }
    return policies
  }

  func createStateDirectory(_ url: URL) throws {
    guard !exists(url) else { throw PAMLifecycleError.recoveryRequired }
    do {
      try fileManager.createDirectory(at: url, withIntermediateDirectories: false)
    } catch {
      throw fileSystemError(url.path)
    }
    guard chmod(url.path, 0o700) == 0,
      chown(url.path, expectedOwnerUserID, expectedOwnerGroupID) == 0
    else {
      throw fileSystemError(url.path)
    }
    try syncDirectory(url.deletingLastPathComponent())
    try validateStateDirectory(url)
  }

  func snapshot(_ target: URL, backupName: String, stateDirectory: URL) throws
    -> PAMLifecycleSnapshot
  {
    let descriptor = PAMLifecycleSnapshot(
      path: target.path,
      backupName: backupName,
      existed: exists(target)
    )
    guard descriptor.existed else { return descriptor }
    try validateRegularRootTarget(target)
    let backup = stateDirectory.appendingPathComponent(backupName)
    try copy(target, to: backup)
    try syncFile(backup)
    try validateRegularRootTarget(backup)
    return descriptor
  }

  func installModule(_ data: Data, to target: URL) throws {
    let temporary = temporarySibling(of: target)
    do {
      try data.write(to: temporary, options: [.withoutOverwriting])
      guard chmod(temporary.path, 0o444) == 0,
        chown(temporary.path, expectedOwnerUserID, expectedOwnerGroupID) == 0
      else {
        throw fileSystemError(temporary.path)
      }
      try syncFile(temporary)
      try replace(temporary, target: target)
    } catch {
      try? fileManager.removeItem(at: temporary)
      throw error
    }
  }

  func replacePolicy(_ target: URL, with data: Data) throws {
    try validateRegularRootTarget(target)
    let temporary = temporarySibling(of: target)
    var info = stat()
    guard lstat(target.path, &info) == 0 else { throw fileSystemError(target.path) }
    do {
      try copy(target, to: temporary)
      guard chmod(temporary.path, 0o600) == 0 else { throw fileSystemError(temporary.path) }
      do {
        try data.write(to: temporary, options: [])
      } catch {
        throw fileSystemError(temporary.path)
      }
      guard chmod(temporary.path, info.st_mode & 0o7777) == 0,
        chown(temporary.path, info.st_uid, info.st_gid) == 0
      else {
        throw fileSystemError(temporary.path)
      }
      try syncFile(temporary)
      try replace(temporary, target: target)
    } catch {
      try? fileManager.removeItem(at: temporary)
      throw error
    }
  }

  func restore(_ snapshot: PAMLifecycleSnapshot, from stateDirectory: URL) throws {
    let target = URL(fileURLWithPath: snapshot.path)
    if snapshot.existed {
      let backup = stateDirectory.appendingPathComponent(snapshot.backupName)
      let temporary = temporarySibling(of: target)
      do {
        try copy(backup, to: temporary)
        try syncFile(temporary)
        try replace(temporary, target: target)
      } catch {
        try? fileManager.removeItem(at: temporary)
        throw error
      }
    } else if exists(target) {
      do {
        try fileManager.removeItem(at: target)
        try syncDirectory(target.deletingLastPathComponent())
      } catch {
        throw fileSystemError(target.path)
      }
    }
  }

  func removeIfPresent(_ url: URL) throws {
    guard exists(url) else { return }
    try validateRegularRootTarget(url)
    do {
      try fileManager.removeItem(at: url)
      try syncDirectory(url.deletingLastPathComponent())
    } catch {
      throw fileSystemError(url.path)
    }
  }

  func removeTree(_ url: URL) throws {
    guard exists(url) else { return }
    try validateStateDirectory(url)
    do {
      try fileManager.removeItem(at: url)
      try syncDirectory(url.deletingLastPathComponent())
    } catch {
      throw fileSystemError(url.path)
    }
  }

  func writeRecord(_ record: PAMLifecycleRecord, to url: URL) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    let data: Data
    do {
      data = try encoder.encode(record)
    } catch {
      throw PAMLifecycleError.invalidState("record could not be encoded")
    }
    let temporary = temporarySibling(of: url)
    do {
      if exists(url) { try validateRecordFile(url) }
      try data.write(to: temporary, options: [.withoutOverwriting])
      guard chmod(temporary.path, 0o600) == 0,
        chown(temporary.path, expectedOwnerUserID, expectedOwnerGroupID) == 0
      else {
        throw fileSystemError(temporary.path)
      }
      try syncFile(temporary)
      try replace(temporary, target: url)
    } catch {
      try? fileManager.removeItem(at: temporary)
      throw error
    }
  }

  func readRecord(from url: URL) throws -> PAMLifecycleRecord {
    let record: PAMLifecycleRecord
    do {
      record = try JSONDecoder().decode(PAMLifecycleRecord.self, from: read(url))
    } catch let error as PAMLifecycleError {
      throw error
    } catch {
      throw PAMLifecycleError.invalidState("record could not be decoded")
    }
    guard record.schemaVersion == 1 else {
      throw PAMLifecycleError.invalidState("unsupported schema version")
    }
    return record
  }

  func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  func sha256(_ url: URL) throws -> String { sha256(try read(url)) }

  func withLock<T>(_ url: URL, operation: () throws -> T) throws -> T {
    try validateDirectory(url.deletingLastPathComponent())
    let descriptor = open(url.path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else { throw fileSystemError(url.path) }
    defer {
      _ = flock(descriptor, LOCK_UN)
      _ = close(descriptor)
    }
    var info = stat()
    guard fstat(descriptor, &info) == 0,
      info.st_mode & S_IFMT == S_IFREG,
      info.st_uid == expectedOwnerUserID,
      info.st_gid == expectedOwnerGroupID,
      info.st_mode & 0o777 == 0o600,
      info.st_nlink == 1,
      !hasUnsafeFlags(info),
      try !hasExtendedACL(descriptor)
    else {
      throw PAMLifecycleError.unsafePath(url.path)
    }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
      throw PAMLifecycleError.fileSystem(
        path: url.path, message: "another lifecycle operation is active")
    }
    guard fsync(descriptor) == 0 else { throw fileSystemError(url.path) }
    try syncDirectory(url.deletingLastPathComponent())
    return try operation()
  }

  private func copy(_ source: URL, to destination: URL) throws {
    do {
      try fileManager.copyItem(at: source, to: destination)
    } catch {
      throw fileSystemError(destination.path)
    }
  }

  private func replace(_ temporary: URL, target: URL) throws {
    guard rename(temporary.path, target.path) == 0 else { throw fileSystemError(target.path) }
    try syncDirectory(target.deletingLastPathComponent())
  }

  private func temporarySibling(of url: URL) -> URL {
    url.deletingLastPathComponent().appendingPathComponent(".pam-companion.\(UUID().uuidString)")
  }

  private func syncFile(_ url: URL) throws {
    let descriptor = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw fileSystemError(url.path) }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw fileSystemError(url.path) }
  }

  private func syncDirectory(_ url: URL) throws {
    let descriptor = open(url.path, O_RDONLY | O_CLOEXEC)
    guard descriptor >= 0 else { throw fileSystemError(url.path) }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw fileSystemError(url.path) }
  }

  private func validateAncestors(of url: URL) throws {
    let parentPath = url.deletingLastPathComponent().path
    guard let resolved = realpath(parentPath, nil) else { throw fileSystemError(parentPath) }
    defer { free(resolved) }
    let parent = URL(
      fileURLWithFileSystemRepresentation: resolved,
      isDirectory: true,
      relativeTo: nil
    )
    var current = URL(fileURLWithPath: "/", isDirectory: true)
    try validateAncestor(current)
    for component in parent.pathComponents.dropFirst() {
      current.appendPathComponent(component, isDirectory: true)
      try validateAncestor(current)
    }
  }

  private func validateAncestor(_ url: URL) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw fileSystemError(url.path) }
    guard info.st_mode & S_IFMT == S_IFDIR,
      !hasUnsafeFlags(info),
      try !hasExtendedACL(url.path)
    else {
      throw PAMLifecycleError.unsafePath(url.path)
    }
  }

  private func hasUnsafeFlags(_ info: stat) -> Bool {
    let unsafe = UInt32(UF_IMMUTABLE | UF_APPEND | SF_IMMUTABLE | SF_APPEND)
    return info.st_flags & unsafe != 0
  }

  private func hasExtendedACL(_ path: String) throws -> Bool {
    errno = 0
    guard let accessControlList = path.withCString({ acl_get_link_np($0, ACL_TYPE_EXTENDED) })
    else {
      if errno == ENOENT { return false }
      throw fileSystemError(path)
    }
    defer { acl_free(UnsafeMutableRawPointer(accessControlList)) }
    return try hasEntries(accessControlList, path: path)
  }

  private func hasExtendedACL(_ descriptor: Int32) throws -> Bool {
    errno = 0
    guard let accessControlList = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
      if errno == ENOENT { return false }
      throw fileSystemError("file descriptor")
    }
    defer { acl_free(UnsafeMutableRawPointer(accessControlList)) }
    return try hasEntries(accessControlList, path: "file descriptor")
  }

  private func hasEntries(_ accessControlList: acl_t, path: String) throws -> Bool {
    var entry: acl_entry_t?
    let result = acl_get_entry(accessControlList, ACL_FIRST_ENTRY.rawValue, &entry)
    guard result != -1 else { throw fileSystemError(path) }
    return result == 0
  }

  private func write(_ data: Data, to descriptor: Int32, path: String) throws {
    var offset = 0
    while offset < data.count {
      let count = data.withUnsafeBytes { bytes in
        Darwin.write(descriptor, bytes.baseAddress?.advanced(by: offset), data.count - offset)
      }
      guard count > 0 else { throw fileSystemError(path) }
      offset += count
    }
  }

  private func fileSystemError(_ path: String) -> PAMLifecycleError {
    PAMLifecycleError.fileSystem(path: path, message: String(cString: strerror(errno)))
  }
}
