#!/bin/sh

set -eu

[ "$#" -eq 1 ] || {
    echo "usage: verify-release.sh <pam-companion-version.tar.gz>" >&2
    exit 2
}

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(dirname "$script_directory")
archive=$1
[ -f "$archive" ] && [ ! -L "$archive" ] || {
    echo "release archive is missing or unsafe: $archive" >&2
    exit 1
}
archive_size=$(stat -f '%z' "$archive")
[ "$archive_size" -le 67108864 ] || {
    echo "release archive exceeds the 64 MiB compressed-size limit" >&2
    exit 1
}

archive_name=$(basename "$archive")
package_name=${archive_name%.tar.gz}
version=${package_name#pam-companion-}
[ "$package_name" = "pam-companion-$version" ] && \
    printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
    echo "archive name does not contain a semantic version" >&2
    exit 1
}

scratch_root=$(mktemp -d "${TMPDIR:-/tmp}/pam-companion-verify.XXXXXX")
cleanup() {
    [ ! -d "$scratch_root" ] || rm -rf -- "$scratch_root"
}
trap cleanup EXIT

tar -tzf "$archive" > "$scratch_root/entries"
tar -tvzf "$archive" > "$scratch_root/listing"
awk '
    /^\// { exit 1 }
    /(^|\/)\.\.($|\/)/ { exit 1 }
' "$scratch_root/entries" || {
    echo "archive contains an unsafe path" >&2
    exit 1
}
awk 'substr($1, 1, 1) != "-" && substr($1, 1, 1) != "d" { exit 1 }' \
    "$scratch_root/listing" || {
    echo "archive contains a non-regular entry" >&2
    exit 1
}
awk '
    $5 > 67108864 { exit 1 }
    { total += $5 }
    END { if (total > 134217728) exit 1 }
' "$scratch_root/listing" || {
    echo "archive exceeds the uncompressed size limits" >&2
    exit 1
}

cat > "$scratch_root/expected" <<EOF
$package_name/
$package_name/LICENSE
$package_name/README.md
$package_name/SECURITY.md
$package_name/SHA256SUMS
$package_name/bin/
$package_name/bin/pam-companion
$package_name/libexec/
$package_name/libexec/pam_companion.so
EOF
LC_ALL=C sort "$scratch_root/entries" > "$scratch_root/entries.sorted"
LC_ALL=C sort "$scratch_root/expected" > "$scratch_root/expected.sorted"
diff -u "$scratch_root/expected.sorted" "$scratch_root/entries.sorted"

tar -xzf "$archive" -C "$scratch_root"
package="$scratch_root/$package_name"
find "$package" -type l -exec false {} +
(
    cd "$package"
    shasum -a 256 -c SHA256SUMS
)

cli="$package/bin/pam-companion"
module="$package/libexec/pam_companion.so"
[ "$(stat -f '%Lp' "$cli")" = "555" ] || {
    echo "CLI mode must be 0555" >&2
    exit 1
}
[ "$(stat -f '%Lp' "$module")" = "444" ] || {
    echo "PAM module mode must be 0444" >&2
    exit 1
}
[ "$($cli --version)" = "pam-companion $version" ]

verify_binary() {
    binary=$1
    lipo "$binary" -verify_arch arm64
    lipo "$binary" -verify_arch x86_64
    [ "$(lipo -archs "$binary" | wc -w | tr -d ' ')" -eq 2 ]
    codesign --verify --strict "$binary"
    signature=$(codesign -d --verbose=4 "$binary" 2>&1)
    printf '%s\n' "$signature" | grep -Fq 'Signature=adhoc'
    printf '%s\n' "$signature" | grep -Eq '^CodeDirectory .*flags=.*\(adhoc,runtime\)'
    for architecture in arm64 x86_64; do
        minos=$(vtool -arch "$architecture" -show-build "$binary" | \
            awk '/^[[:space:]]*minos / { print $2 }')
        [ "$minos" = "14.0" ]
    done
}

verify_binary "$cli"
verify_binary "$module"

for architecture in arm64 x86_64; do
    install_name=$(otool -arch "$architecture" -D "$module" | sed -n '2p')
    [ "$install_name" = "pam_companion.so" ]
    nm -arch "$architecture" -gjU "$module" | LC_ALL=C sort > "$scratch_root/exports"
    LC_ALL=C sort "$repository_root/Support/pam_companion.exports" > "$scratch_root/expected.exports"
    diff -u "$scratch_root/expected.exports" "$scratch_root/exports"
    otool -arch "$architecture" -L "$module" | sed -n '3,$p' | \
        awk '{ print $1 }' | while IFS= read -r dependency; do
            case "$dependency" in
                /usr/lib/*|/System/Library/*) ;;
                *) echo "unexpected linked dependency: $dependency" >&2; exit 1 ;;
            esac
        done
done

xcrun clang \
    -std=c17 \
    -Wall \
    -Wextra \
    -Werror \
    "$repository_root/Tests/ArtifactSmoke/pam_companion_smoke.c" \
    -o "$scratch_root/pam_companion_smoke"
"$scratch_root/pam_companion_smoke" "$module"

echo "PASS: verified pam-companion $version release archive"
