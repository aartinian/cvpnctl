#!/usr/bin/env bash
# Installs an cvpnctl release from GitHub and verifies its checksum.
#
#   curl -fsSL https://raw.githubusercontent.com/aartinian/cvpnctl/master/scripts/install.sh | bash
#
# Environment:
#   VERSION      release tag to install, e.g. v1.0.0 (default: latest)
#   INSTALL_DIR  where to put the binary (default: /usr/local/bin)
set -euo pipefail

REPO="aartinian/cvpnctl"
BINARY="cvpnctl"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux | darwin) ;;
  *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

if [ -z "${VERSION:-}" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
    grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
fi
if [ -z "$VERSION" ]; then
  echo "could not determine the latest release" >&2
  exit 1
fi

ARCHIVE="${BINARY}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "downloading ${BINARY} ${VERSION} (${OS}/${ARCH})..."
curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMP}/${ARCHIVE}"
curl -fsSL "${BASE_URL}/checksums.txt" -o "${TMP}/checksums.txt"

echo "verifying checksum..."
(
  cd "$TMP"
  if ! grep " ${ARCHIVE}\$" checksums.txt >expected.txt; then
    echo "${ARCHIVE} is not listed in checksums.txt" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null; then
    sha256sum -c expected.txt >/dev/null
  else
    shasum -a 256 -c expected.txt >/dev/null
  fi
)

tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP" "$BINARY"

SUDO=""
if [ ! -w "$INSTALL_DIR" ]; then
  echo "${INSTALL_DIR} is not writable, using sudo"
  SUDO="sudo"
fi
$SUDO install -m 755 "${TMP}/${BINARY}" "${INSTALL_DIR}/${BINARY}"

echo "installed $("${INSTALL_DIR}/${BINARY}" --version) to ${INSTALL_DIR}/${BINARY}"
