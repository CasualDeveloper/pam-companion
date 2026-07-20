# Releasing pam-companion

Release archives contain one universal `pam-companion` CLI and one universal `pam_companion.so` module in a Homebrew-shaped directory. Both are built with Swift 6.3.3 for macOS 14 or newer and ad hoc signed with the hardened runtime.

The project has no Apple Developer Program membership. Do not claim Developer ID identity, notarization, or Gatekeeper approval. Distribution integrity comes from the Homebrew formula digest, release checksums, GitHub provenance attestations, and verification of the exact archive.

Release binaries are always compiled in the macOS 26 packaging job with Swiftly's asserted Swift 6.3.3 toolchain. The compatibility matrix builds and tests with each runner's recorded native Xcode Swift toolchain on macOS 14, 15, and 26, then all three systems verify and load-smoke that one exact release archive. This is an intentional two-toolchain design: declared-compiler release packaging plus native-Xcode compatibility checks.

## Prepare a candidate

1. Update `PAMCompanionVersion.current` and `CHANGELOG.md` together.
2. Run the full XCTest suite with Xcode and build both release products with Swiftly 6.3.3.
3. Confirm `git diff --check` is clean and commit the release source.
4. From a clean tree, package and verify the candidate:

   ```sh
   swiftly run ./Scripts/package-release.sh
   ./Scripts/verify-release.sh dist/pam-companion-<version>.tar.gz
   ```

The verifier checks the exact archive layout and inner checksums, universal architectures, macOS 14 deployment target, ad hoc hardened-runtime signatures, module install name, exact four-symbol PAM export set, system-only linked dependencies, CLI version, and safe C `dlopen`/`dlsym` behavior.

## Draft release

Push the reviewed source to `main`, wait for all hosted macOS checks, then create and push the matching annotated tag, such as `v0.1.0`. The tag workflow rebuilds from that tag, verifies intrinsic version equality, attests the archive and checksum file, and creates a draft GitHub release. It does not publish automatically.

Manual workflow runs only create a seven-day candidate artifact. They do not create a tag or release.

## Live gate

PAM mutations and authentication prompts are intentionally excluded from hosted CI. Test the exact draft archive or a formula pointing to it on a Mac with a known administrator password and an already-open recovery shell.

1. Record the current bytes, mode, owner, flags, and extended attributes of `/etc/pam.d/sudo_local` and any files under `/usr/local/lib/pam` named `pam_companion.so`, `pam_watchid.so`, or `pam_watchid.so.2`. Compare every xattr except `com.apple.provenance`, which macOS rewrites as a path-managed value during renames.
2. Install the candidate through a temporary Homebrew formula whose URL and SHA-256 digest match the draft archive.
3. Run `pam-companion status`, then `sudo pam-companion setup --dry-run`.
4. Run `sudo pam-companion setup`; verify that legacy entries/files were migrated and `pam-companion doctor` passes.
5. In a new terminal, run `sudo -k; sudo true` and complete Touch ID or Apple Watch authentication.
6. Run `sudo -k; sudo true`, cancel companion authentication, and verify the administrator password fallback still succeeds.
7. Run `sudo pam-companion restore`; prove the captured tracked state was reconstructed, with only the documented `com.apple.provenance` exception.
8. Run setup again, verify idempotence and authentication once more, and leave the desired canonical installation active.

Keep the recovery shell open until password fallback and tracked-state restore have both passed. Stop on any unexpected PAM shape, missing fallback, lifecycle drift, or rollback error.

## Publish and update Homebrew

After the live gate succeeds, publish the existing draft without rebuilding it:

```sh
gh release edit v<version> --draft=false --repo CasualDeveloper/pam-companion
```

Update `CasualDeveloper/homebrew-tap` with the published archive URL and SHA-256 digest. The formula must only install `bin/pam-companion` and `libexec/pam_companion.so`; it must not edit `/etc`, write `/usr/local/lib/pam`, invoke `sudo`, or run setup automatically.

Run strict formula audit, install, version, status, setup/restore, upgrade, and uninstall-preparation checks before pushing the tap commit.
