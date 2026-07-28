#!/bin/sh
# LaunchGuard installer.
#
# Downloads a prebuilt binary, verifies its published SHA-256, and installs it.
# Read this script before piping it to a shell; it is deliberately short enough
# to audit in one screen.
#
#   curl -fsSL https://raw.githubusercontent.com/bananatruck/launchguard/main/install.sh | sh
#
# Environment:
#   LAUNCHGUARD_VERSION   tag to install, default: latest release
#   LAUNCHGUARD_BIN_DIR   install directory, default: $HOME/.local/bin
#
# Binaries are unsigned. macOS and Windows may warn on first run.

set -eu

REPO="bananatruck/launchguard"
BIN_DIR="${LAUNCHGUARD_BIN_DIR:-$HOME/.local/bin}"

fail() {
    printf 'launchguard: %s\n' "$1" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required but not installed"
}

need uname
need mktemp
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 ||
    fail "curl or wget is required"

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    else
        wget -qO "$2" "$1"
    fi
}

# Resolve the target triple from the running host.
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
    # Linux binaries are statically linked against musl, so they run on any
    # distribution regardless of its glibc version.
    Linux) os_part="unknown-linux-musl" ;;
    Darwin) os_part="apple-darwin" ;;
    *) fail "unsupported operating system: $os (Windows users: download the zip from the releases page)" ;;
esac
case "$arch" in
    x86_64 | amd64) arch_part="x86_64" ;;
    aarch64 | arm64) arch_part="aarch64" ;;
    *) fail "unsupported architecture: $arch" ;;
esac
target="${arch_part}-${os_part}"

version="${LAUNCHGUARD_VERSION:-}"
if [ -z "$version" ]; then
    tmp_tag="$(mktemp)"
    fetch "https://api.github.com/repos/${REPO}/releases/latest" "$tmp_tag" ||
        fail "could not reach the GitHub releases API"
    version="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp_tag" | head -n 1)"
    rm -f "$tmp_tag"
    [ -n "$version" ] || fail "no published release found"
fi

archive="launchguard-${target}.tar.gz"
base="https://github.com/${REPO}/releases/download/${version}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

printf 'launchguard: installing %s for %s\n' "$version" "$target"

fetch "${base}/${archive}" "${work}/${archive}" ||
    fail "could not download ${archive} for ${version}"
fetch "${base}/SHA256SUMS" "${work}/SHA256SUMS" ||
    fail "could not download SHA256SUMS; refusing to install an unverified binary"

# Verify before anything is made executable. A mismatch is fatal.
expected="$(grep " ${archive}\$" "${work}/SHA256SUMS" | awk '{print $1}' | head -n 1)"
[ -n "$expected" ] || fail "no published checksum for ${archive}"

if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${work}/${archive}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${work}/${archive}" | awk '{print $1}')"
else
    fail "sha256sum or shasum is required to verify the download"
fi

if [ "$expected" != "$actual" ]; then
    fail "checksum mismatch for ${archive}
  expected ${expected}
  actual   ${actual}
Refusing to install."
fi
printf 'launchguard: checksum verified\n'

tar -xzf "${work}/${archive}" -C "$work" ||
    fail "could not extract ${archive}"

mkdir -p "$BIN_DIR"
install -m 0755 "${work}/launchguard-${target}/launchguard" "${BIN_DIR}/launchguard" 2>/dev/null ||
    {
        cp "${work}/launchguard-${target}/launchguard" "${BIN_DIR}/launchguard"
        chmod 0755 "${BIN_DIR}/launchguard"
    }

printf 'launchguard: installed to %s/launchguard\n' "$BIN_DIR"

case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *) printf 'launchguard: add %s to your PATH to run it by name\n' "$BIN_DIR" ;;
esac

printf '\nNext: run "launchguard doctor" to see what this host can do.\n'
