# pam-companion

`pam-companion` adds Touch ID and companion-device authentication, including Apple Watch, to macOS `sudo`. It is a standalone Swift command-line tool and PAM module.

The project has no daemon, network service, telemetry, or credential storage. macOS performs authentication through LocalAuthentication; the module receives only the success or failure result.

## Install

```sh
brew install CasualDeveloper/tap/pam-companion
pam-companion status
sudo pam-companion setup --dry-run
sudo pam-companion setup
```

Homebrew installs files only inside its prefix. The explicit `sudo pam-companion setup` command performs the privileged work:

- installs the canonical module at `/usr/local/lib/pam/pam_companion.so`;
- adds `auth sufficient pam_companion.so` before the optional `pam_tid.so` line in a known-safe `/etc/pam.d/sudo_local` shape;
- replaces supported `pam_watchid.so` or `pam_watchid.so.2` configuration;
- removes legacy module files only when no other PAM policy still references them;
- records an exact rollback snapshot under `/var/db/pam-companion`.

Setup is idempotent. It stops before mutation unless the system `sudo` policy has the supported `sudo_local`, optional smart-card, and required `pam_opendirectory.so` authentication sequence. It also refuses ACLs, dangerous file flags, hard links, symlinks, writable root targets, unknown active `sudo_local` controls, and legacy modules still used by another PAM service. The release module is read once through a no-follow descriptor, validated from those captured bytes, and only then installed.

## Check, restore, and uninstall

```sh
pam-companion status
pam-companion doctor
sudo pam-companion restore --dry-run
sudo pam-companion restore
```

Restore refuses to overwrite files outside their recorded original or transactional states. If setup or restore was interrupted, `status` reports that recovery is required and `restore` resumes idempotently from the durable pre-mutation snapshots.

Prepare Homebrew removal with one explicit restore:

```sh
sudo pam-companion uninstall --prepare
brew uninstall pam-companion
```

## Authentication behavior

On macOS 15 and later, the module uses Apple’s current [`deviceOwnerAuthenticationWithBiometricsOrCompanion`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometricsorcompanion) policy. On macOS 14 it uses Apple’s earlier Watch spelling of the same Touch ID-or-companion policy.

Authentication outcomes compose with the rest of the PAM stack:

- successful LocalAuthentication returns `PAM_SUCCESS`;
- an explicit rejected result returns `PAM_AUTH_ERR`;
- unavailable authentication, cancellation, errors, timeout, invalid arguments, and `sudo --askpass` return `PAM_IGNORE` so the configured password path can continue.

The optional module arguments are `reason=<text>` and `timeout=<1...120>`. The default timeout is 30 seconds.

[AuthenticationServices](https://developer.apple.com/documentation/authenticationservices) is not used here: Apple documents that framework for app and service sign-in, credentials, passkeys, and SSO. Direct device-owner approval remains part of [LocalAuthentication](https://developer.apple.com/documentation/localauthentication).

## Requirements and build

- macOS 14 or newer
- Swift 6.3.3 for release archives
- macOS Command Line Tools for builds and packaging
- Xcode, or another toolchain containing XCTest, only for the test suite

```sh
swift build -c release --product pam-companion
swift build -c release --product PAMCompanionModule
swift test
```

The Swiftly toolchain can build both products but does not include XCTest. On this project, tests can be run with an installed Xcode explicitly:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcrun swift test
```

## Release integrity

The project does not currently have an Apple Developer Program membership. Release binaries are ad hoc signed with the hardened runtime and are not notarized. The Homebrew formula pins the archive SHA-256 digest, releases include checksums and GitHub build-provenance attestations, and the exact archive is verified on supported macOS versions before publication.

Create and verify a local candidate without touching live PAM state:

```sh
swiftly run ./Scripts/package-release.sh --allow-dirty
./Scripts/verify-release.sh dist/pam-companion-0.1.0.tar.gz
```

See [RELEASING.md](RELEASING.md) for the controlled live-authentication and publication gates.

## Acknowledgements

This project descends from the open-source `pam-watchid` and `pam-touchID` projects and their contributors. The current implementation is a greenfield Swift 6 rewrite.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
