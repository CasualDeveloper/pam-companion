# Changelog

## 0.1.0 - 2026-07-20

### Added

- Greenfield Swift 6 PAM module with system-header constants and exactly four OpenPAM exports.
- Touch ID and companion-device authentication through Apple’s current LocalAuthentication policy.
- Standalone `pam-companion` CLI with status, doctor, setup, restore, and uninstall preparation.
- Explicit root boundary for system inspection and lifecycle commands; the CLI never attempts to elevate itself.
- Transactional `sudo_local` configuration, rollback snapshots for all tracked state, crash-resumable restore, and per-target drift protection. Apple's path-managed `com.apple.provenance` xattr is intentionally excluded.
- Automatic migration and removal of unreferenced `pam_watchid.so` and `pam_watchid.so.2` installations.
- Universal arm64/x86_64 ad hoc hardened-runtime release archives for macOS 14 or newer.
- Deterministic tests for authentication, PAM ABI boundaries, configuration parsing, CLI behavior, rollback failures, recovery, metadata preservation, and unsafe targets.

### Security

- Preserve a required password authentication path after `PAM_IGNORE` or `PAM_AUTH_ERR`.
- Refuse mutation for duplicate or unsupported PAM entries, unparseable policy files, external legacy references, ACLs, dangerous flags, hard links, symlinks, writable root targets, malformed state, and post-setup drift.
- Resolve the installed module from the actual executable path and eliminate path-based source-validation races by validating and installing one descriptor-captured byte sequence.
- Bound LocalAuthentication waits and make timeout completion authoritative over late callbacks.
