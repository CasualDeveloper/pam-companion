#!/bin/sh

set -eu

allow_dirty=false
if [ "${1:-}" = "--allow-dirty" ]; then
    allow_dirty=true
    shift
fi
[ "$#" -eq 0 ] || {
    echo "usage: package-release.sh [--allow-dirty]" >&2
    exit 2
}

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(dirname "$script_directory")
swift_executable=${SWIFT:-swift}

swift_version=$($swift_executable --version | sed -n '1p')
case "$swift_version" in
    *"Swift version 6.3.3"*) ;;
    *)
        echo "release archives require Swift 6.3.3, got: $swift_version" >&2
        exit 1
        ;;
esac

source_commit=$(git -C "$repository_root" rev-parse HEAD)
source_status=$(git -C "$repository_root" status --porcelain --untracked-files=normal)
if [ -n "$source_status" ] && [ "$allow_dirty" = false ]; then
    echo "refusing to package a dirty source tree; use --allow-dirty for local verification" >&2
    exit 1
fi

scratch_root=$(mktemp -d "${TMPDIR:-/tmp}/pam-companion-release.XXXXXX")
cleanup() {
    [ ! -d "$scratch_root" ] || rm -rf -- "$scratch_root"
}
trap cleanup EXIT

for architecture in arm64 x86_64; do
    scratch="$scratch_root/$architecture"
    $swift_executable build \
        --package-path "$repository_root" \
        --scratch-path "$scratch" \
        -c release \
        --arch "$architecture" \
        --product pam-companion \
        -Xswiftc -warnings-as-errors
    bin_path=$($swift_executable build \
        --package-path "$repository_root" \
        --scratch-path "$scratch" \
        -c release \
        --arch "$architecture" \
        --show-bin-path)
    cp "$bin_path/pam-companion" "$scratch_root/pam-companion-$architecture"
done

post_commit=$(git -C "$repository_root" rev-parse HEAD)
post_status=$(git -C "$repository_root" status --porcelain --untracked-files=normal)
[ "$post_commit" = "$source_commit" ] && [ "$post_status" = "$source_status" ] || {
    echo "source changed while packaging; refusing the archive" >&2
    exit 1
}

lipo -create \
    "$scratch_root/pam-companion-arm64" \
    "$scratch_root/pam-companion-x86_64" \
    -output "$scratch_root/pam-companion"
chmod 0555 "$scratch_root/pam-companion"
codesign --force --sign - --options runtime --timestamp=none "$scratch_root/pam-companion"
codesign --verify --strict "$scratch_root/pam-companion"

version_output=$($scratch_root/pam-companion --version)
version=${version_output#pam-companion }
[ "$version_output" = "pam-companion $version" ] && \
    printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
    echo "built CLI returned an invalid version: $version_output" >&2
    exit 1
}

package_name="pam-companion-$version"
package_root="$scratch_root/package/$package_name"
mkdir -p "$package_root/bin"
cp "$scratch_root/pam-companion" "$package_root/bin/"
chmod 0555 "$package_root/bin/pam-companion"
cp "$repository_root/LICENSE" "$repository_root/README.md" \
    "$repository_root/SECURITY.md" "$package_root/"
(
    cd "$package_root"
    shasum -a 256 bin/pam-companion > SHA256SUMS
)

mkdir -p "$repository_root/dist"
archive="$repository_root/dist/$package_name.tar.gz"
[ ! -e "$archive" ] || {
    echo "release archive already exists: $archive" >&2
    exit 1
}
COPYFILE_DISABLE=1 tar \
    --uid 0 \
    --gid 0 \
    --uname root \
    --gname wheel \
    -C "$scratch_root/package" \
    -czf "$archive" \
    "$package_name"
(
    cd "$repository_root/dist"
    shasum -a 256 "$package_name.tar.gz" > SHA256SUMS
)
printf 'packaged: %s\n' "$archive"
