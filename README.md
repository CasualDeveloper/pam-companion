# pam-companion

`pam-companion` safely enables Touch ID and companion-device authentication, including Apple Watch, for macOS `sudo`. It is a standalone Swift command-line tool that manages Apple’s built-in `pam_tid.so` integration.

The project has no custom PAM module, daemon, network service, telemetry, or credential storage. Once setup is complete, `pam-companion` is not in the authentication path: `sudo` talks directly to Apple’s operating-system module.

## Install

```sh
brew install CasualDeveloper/tap/pam-companion
sudo pam-companion status
sudo pam-companion setup --dry-run
sudo pam-companion setup
```

Homebrew installs files only inside its prefix. The explicit `sudo pam-companion setup` command performs the privileged work:

- enables the system-provided `auth sufficient pam_tid.so` template in a known-safe `/etc/pam.d/sudo_local` shape;
- migrates supported `pam_companion.so`, `pam_watchid.so`, and `pam_watchid.so.2` configuration;
- removes custom and legacy module files only when no policy in macOS’s four PAM search locations still references them;
- journals the transaction under `/var/db/pam-companion` and preserves rollback files as hidden sibling inodes beside their PAM targets.

Setup is idempotent. It stops before mutation unless the system `sudo` policy has the supported `sudo_local`, optional smart-card, and required `pam_opendirectory.so` authentication sequence. It also refuses ACLs, dangerous file flags, hard links, symlinks, writable root targets, unknown active `sudo_local` controls, and removable modules still used by another PAM service.

Rollback validation covers bytes, ownership, permissions, flags, and every recorded extended attribute. The sole exception is Apple's opaque `com.apple.provenance` attribute: macOS rewrites that path-managed value during otherwise metadata-preserving renames, so it is neither recorded nor compared.

The rollback journal is root-owned and accessible only to root. Inspection commands require explicit `sudo` so they can verify every supported policy mode without exposing saved metadata.

## Check, restore, and uninstall

```sh
sudo pam-companion status
sudo pam-companion doctor
sudo pam-companion restore --dry-run
sudo pam-companion restore
```

Restore refuses to overwrite files outside their recorded original or transactional states. If setup or restore was interrupted, `status` reports that recovery is required and `restore` resumes idempotently from the durable pre-mutation snapshots. Interruptions before the first journal record are also recoverable without touching PAM state.

Prepare Homebrew removal with one explicit restore:

```sh
sudo pam-companion uninstall --prepare
brew uninstall pam-companion
```

## Authentication behavior

`pam_tid.so` is part of macOS and owns the privileged authentication flow, including binding approval to the user requested by PAM. `pam-companion` only enables its existing `sudo_local` template.

The configured PAM stack keeps password authentication after the optional native approval:

- successful Touch ID or Apple Watch approval satisfies `sudo` authentication;
- cancellation or an unavailable device continues to macOS’s required password path.

[AuthenticationServices](https://developer.apple.com/documentation/authenticationservices) is not used here: Apple documents it for app and service sign-in, credentials, passkeys, and SSO. This project delegates terminal authentication to the native PAM module shipped by macOS.

## Requirements and build

- macOS 14 or newer
- Swift 6.3.3 for release archives
- macOS Command Line Tools for builds and packaging
- Xcode, or another toolchain containing XCTest, only for the test suite

```sh
swift build -c release --product pam-companion
swift test
```

The Swiftly toolchain can build the release product but does not include XCTest. On this project, tests can be run with an installed Xcode explicitly:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcrun swift test
```

## Release integrity

The project does not currently have an Apple Developer Program membership. Release binaries are ad hoc signed with the hardened runtime and are not notarized. The Homebrew formula pins the archive SHA-256 digest, releases include checksums and GitHub build-provenance attestations, and the exact archive is verified on supported macOS versions before publication.

Create and verify a local candidate without touching live PAM state:

```sh
swiftly run ./Scripts/package-release.sh --allow-dirty
./Scripts/verify-release.sh dist/pam-companion-0.1.1.tar.gz
```

See [RELEASING.md](RELEASING.md) for the controlled live-authentication and publication gates.

## Acknowledgements

This project descends from the open-source `pam-watchid` and `pam-touchID` projects and their contributors. The current implementation is a greenfield Swift 6 lifecycle manager for Apple’s native module.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
