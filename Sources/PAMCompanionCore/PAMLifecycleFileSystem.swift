import CryptoKit
import Darwin
import Foundation

struct PAMLifecycleFileSystem {
  let expectedOwnerUserID: uid_t
  let expectedOwnerGroupID: gid_t
  private let fileManager = FileManager.default

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

  func isRecoverablePreJournalStateDirectory(_ url: URL) throws -> Bool {
    try validateStateDirectory(url)
    let children: [URL]
    do {
      children = try fileManager.contentsOfDirectory(
        at: url,
        includingPropertiesForKeys: nil,
        options: []
      )
    } catch {
      throw fileSystemError(url.path)
    }
    for child in children {
      let prefix = ".pam-companion."
      guard child.lastPathComponent.hasPrefix(prefix),
        UUID(uuidString: String(child.lastPathComponent.dropFirst(prefix.count))) != nil
      else {
        return false
      }
      var info = stat()
      guard lstat(child.path, &info) == 0 else { throw fileSystemError(child.path) }
      guard info.st_mode & S_IFMT == S_IFREG,
        info.st_uid == expectedOwnerUserID,
        info.st_gid == expectedOwnerGroupID,
        info.st_mode & 0o022 == 0,
        info.st_nlink == 1,
        info.st_size <= 1024 * 1024,
        !hasUnsafeFlags(info),
        try !hasExtendedACL(child.path)
      else {
        throw PAMLifecycleError.unsafePath(child.path)
      }
    }
    return true
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

  func policyFiles(in directory: URL) throws -> [String: Data] {
    let urls: [URL]
    do {
      urls = try fileManager.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
        options: []
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

  func snapshot(_ target: URL, backupName: String) throws -> PAMLifecycleSnapshot {
    guard exists(target) else {
      return PAMLifecycleSnapshot(
        path: target.path,
        backupName: backupName,
        existed: false,
        originalSHA256: nil,
        metadata: nil
      )
    }
    try validateRegularRootTarget(target)
    return PAMLifecycleSnapshot(
      path: target.path,
      backupName: backupName,
      existed: true,
      originalSHA256: try sha256(target),
      metadata: try metadata(target)
    )
  }

  func moveOriginalToBackup(_ snapshot: PAMLifecycleSnapshot, in stateDirectory: URL) throws {
    let target = URL(fileURLWithPath: snapshot.path)
    let backup = backupURL(for: snapshot)
    try validateStateDirectory(stateDirectory)
    if !snapshot.existed {
      guard !exists(backup) else {
        throw PAMLifecycleError.invalidState("unexpected backup: \(snapshot.backupName)")
      }
      guard !exists(target) else { throw PAMLifecycleError.managedStateDrift(snapshot.path) }
      return
    }
    try validateAncestors(of: target)
    if exists(backup) {
      try validateOriginal(snapshot, at: backup)
      return
    }
    try validateOriginal(snapshot, at: target)
    guard rename(target.path, backup.path) == 0 else { throw fileSystemError(target.path) }
    try syncDirectory(target.deletingLastPathComponent())
    try syncDirectory(stateDirectory)
    try validateOriginal(snapshot, at: backup)
  }

  func backupURL(for snapshot: PAMLifecycleSnapshot) -> URL {
    URL(fileURLWithPath: snapshot.path)
      .deletingLastPathComponent()
      .appendingPathComponent(snapshot.backupName)
  }

  func stageModule(_ data: Data, at target: URL) throws {
    try validateAncestors(of: target)
    guard !exists(target) else { throw PAMLifecycleError.managedStateDrift(target.path) }
    let descriptor = open(
      target.path,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      0o400
    )
    guard descriptor >= 0 else { throw fileSystemError(target.path) }
    var completed = false
    defer {
      close(descriptor)
      if !completed { _ = unlink(target.path) }
    }
    do {
      guard fchown(descriptor, expectedOwnerUserID, expectedOwnerGroupID) == 0 else {
        throw fileSystemError(target.path)
      }
      try write(data, to: descriptor, path: target.path)
      guard fchmod(descriptor, 0o444) == 0,
        fsync(descriptor) == 0
      else {
        throw fileSystemError(target.path)
      }
      try syncDirectory(target.deletingLastPathComponent())
      completed = true
    } catch {
      throw error
    }
  }

  func moveStagedFile(
    _ staged: URL,
    to target: URL,
    sha256 expectedSHA256: String,
    metadata expectedMetadata: PAMFileMetadata
  ) throws {
    try validateAncestors(of: target)
    guard !exists(target) else { throw PAMLifecycleError.managedStateDrift(target.path) }
    guard
      try managedFileMatches(
        at: staged,
        sha256: expectedSHA256,
        metadata: expectedMetadata
      )
    else {
      throw PAMLifecycleError.invalidState("staged file changed: \(staged.lastPathComponent)")
    }
    guard rename(staged.path, target.path) == 0 else { throw fileSystemError(target.path) }
    try syncDirectory(staged.deletingLastPathComponent())
    try syncDirectory(target.deletingLastPathComponent())
    guard
      try managedFileMatches(
        at: target,
        sha256: expectedSHA256,
        metadata: expectedMetadata
      )
    else {
      throw PAMLifecycleError.managedStateDrift(target.path)
    }
  }

  func stagePolicy(_ data: Data, at target: URL, preserving template: URL) throws {
    try validateAncestors(of: target)
    guard !exists(target) else { throw PAMLifecycleError.managedStateDrift(target.path) }
    try validateRegularRootTarget(template)
    var info = stat()
    guard lstat(template.path, &info) == 0 else { throw fileSystemError(template.path) }
    do {
      // The deterministic sibling is intentional: if power is lost while staging,
      // the preparing journal can find and remove the partial file. Moving a staged
      // file across directories would also let macOS rewrite provenance metadata.
      try copy(template, to: target)
      guard chmod(target.path, 0o600) == 0 else { throw fileSystemError(target.path) }
      do {
        try data.write(to: target, options: [])
      } catch {
        throw fileSystemError(target.path)
      }
      guard chown(target.path, info.st_uid, info.st_gid) == 0,
        chmod(target.path, info.st_mode & 0o7777) == 0
      else {
        throw fileSystemError(target.path)
      }
      try syncFile(target)
      try syncDirectory(target.deletingLastPathComponent())
    } catch {
      try? fileManager.removeItem(at: target)
      throw error
    }
  }

  func restore(_ snapshot: PAMLifecycleSnapshot, from stateDirectory: URL) throws {
    let target = URL(fileURLWithPath: snapshot.path)
    let backup = backupURL(for: snapshot)
    try validateStateDirectory(stateDirectory)
    if snapshot.existed {
      try validateAncestors(of: target)
      if exists(backup) {
        try validateOriginal(snapshot, at: backup)
        guard rename(backup.path, target.path) == 0 else { throw fileSystemError(target.path) }
        try syncDirectory(target.deletingLastPathComponent())
        try syncDirectory(stateDirectory)
        try validateOriginal(snapshot, at: target)
      } else {
        try validateOriginal(snapshot, at: target)
      }
    } else {
      guard !exists(backup) else {
        throw PAMLifecycleError.invalidState("unexpected backup: \(snapshot.backupName)")
      }
      guard exists(target) else { return }
      try validateAncestors(of: target)
      try validateRegularRootTarget(target)
      do {
        try fileManager.removeItem(at: target)
        try syncDirectory(target.deletingLastPathComponent())
      } catch {
        throw fileSystemError(target.path)
      }
    }
  }

  func removeStagedFile(
    _ url: URL,
    sha256 expectedSHA256: String?,
    metadata expectedMetadata: PAMFileMetadata?
  ) throws {
    guard exists(url) else { return }
    if let expectedSHA256, let expectedMetadata {
      guard
        try managedFileMatches(
          at: url,
          sha256: expectedSHA256,
          metadata: expectedMetadata
        )
      else {
        throw PAMLifecycleError.managedStateDrift(url.path)
      }
    } else {
      try validateRegularRootTarget(url)
    }
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
    guard record.schemaVersion == 2 || record.schemaVersion == 3 else {
      throw PAMLifecycleError.invalidState("unsupported schema version")
    }
    return record.normalizingTrackedExtendedAttributes()
  }

  func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  func sha256(_ url: URL) throws -> String { sha256(try read(url)) }

  func metadata(_ url: URL) throws -> PAMFileMetadata {
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw fileSystemError(url.path) }
    guard info.st_mode & S_IFMT == S_IFREG else {
      throw PAMLifecycleError.unsafePath(url.path)
    }
    return PAMFileMetadata(
      mode: UInt32(info.st_mode & 0o7777),
      ownerUserID: UInt32(info.st_uid),
      ownerGroupID: UInt32(info.st_gid),
      flags: UInt32(info.st_flags),
      extendedAttributes: PAMFileMetadata.trackedExtendedAttributes(try extendedAttributes(url))
    )
  }

  func validateOriginal(_ snapshot: PAMLifecycleSnapshot, at url: URL) throws {
    guard snapshot.existed,
      let originalSHA256 = snapshot.originalSHA256,
      let originalMetadata = snapshot.metadata
    else {
      throw PAMLifecycleError.invalidState("snapshot has no original: \(snapshot.path)")
    }
    try validateRegularRootTarget(url)
    guard try sha256(url) == originalSHA256,
      try metadata(url) == originalMetadata
    else {
      throw PAMLifecycleError.managedStateDrift(snapshot.path)
    }
  }

  func managedFileMatches(
    at url: URL,
    sha256 expectedSHA256: String,
    metadata expectedMetadata: PAMFileMetadata
  ) throws -> Bool {
    try validateRegularRootTarget(url)
    return try sha256(url) == expectedSHA256 && metadata(url) == expectedMetadata
  }

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
    let hasTrustedOwnership =
      (info.st_uid == 0 && info.st_gid == 0)
      || (info.st_uid == expectedOwnerUserID && info.st_gid == expectedOwnerGroupID)
    guard info.st_mode & S_IFMT == S_IFDIR,
      !hasUnsafeFlags(info),
      try !hasExtendedACL(url.path),
      hasTrustedOwnership,
      info.st_mode & 0o022 == 0
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

  private func extendedAttributes(_ url: URL) throws -> [String: Data] {
    let size = url.path.withCString { listxattr($0, nil, 0, XATTR_NOFOLLOW) }
    guard size >= 0 else { throw fileSystemError(url.path) }
    guard size > 0 else { return [:] }
    var buffer = [CChar](repeating: 0, count: size)
    let readCount = url.path.withCString { path in
      listxattr(path, &buffer, buffer.count, XATTR_NOFOLLOW)
    }
    guard readCount == size else { throw fileSystemError(url.path) }
    let names = Data(buffer.map { UInt8(bitPattern: $0) })
      .split(separator: 0)
      .map { String(decoding: $0, as: UTF8.self) }
    var result: [String: Data] = [:]
    for name in names {
      let valueSize = url.path.withCString { path in
        name.withCString { attribute in
          getxattr(path, attribute, nil, 0, 0, XATTR_NOFOLLOW)
        }
      }
      guard valueSize >= 0 else { throw fileSystemError(url.path) }
      var value = Data(count: valueSize)
      let valueRead = value.withUnsafeMutableBytes { bytes in
        url.path.withCString { path in
          name.withCString { attribute in
            getxattr(path, attribute, bytes.baseAddress, bytes.count, 0, XATTR_NOFOLLOW)
          }
        }
      }
      guard valueRead == valueSize else { throw fileSystemError(url.path) }
      result[name] = value
    }
    return result
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
