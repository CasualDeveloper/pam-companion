#!/bin/sh

set -eu

[ "$#" -eq 1 ] || {
    echo "usage: test-release-verifier.sh <pam-companion-version.tar.gz>" >&2
    exit 2
}

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
archive=$1
archive_name=$(basename "$archive")
package_name=${archive_name%.tar.gz}
scratch_root=$(mktemp -d "${TMPDIR:-/tmp}/pam-companion-verifier-test.XXXXXX")
cleanup() {
    [ ! -d "$scratch_root" ] || rm -rf -- "$scratch_root"
}
trap cleanup EXIT

tar -xzf "$archive" -C "$scratch_root"
chmod 0755 "$scratch_root/$package_name/bin/pam-companion"
chmod 0644 "$scratch_root/$package_name/libexec/pam_companion.so"
COPYFILE_DISABLE=1 tar \
    --uid 0 \
    --gid 0 \
    --uname root \
    --gname wheel \
    -C "$scratch_root" \
    -czf "$scratch_root/$archive_name" \
    "$package_name"

if "$script_directory/verify-release.sh" "$scratch_root/$archive_name" \
    > "$scratch_root/output" 2>&1; then
    echo "release verifier accepted an archive with writable executable modes" >&2
    exit 1
fi
grep -Eq 'CLI mode must be 0555|PAM module mode must be 0444' "$scratch_root/output"
echo "PASS: release verifier rejects tampered executable modes"
