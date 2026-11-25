#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOWNLOAD_DIR="$SCRIPT_DIR/download"
SRC_DIR="$DOWNLOAD_DIR/openssl-3.6.0-beta1"
INSTALL_DIR="$SCRIPT_DIR/openssl-3.6.0-beta1-install"
TARBALL="$DOWNLOAD_DIR/openssl-3.6.0-beta1.tar.gz"
PATCH_FILE="$SCRIPT_DIR/openssl-3.6.0-beta1.patch"
OPENSSL_URL="https://www.openssl.org/source/openssl-3.6.0-beta1.tar.gz"

usage() {
  cat <<EOF
Usage: $0 [--install-dir DIR] [--source-dir DIR] [--download-dir DIR] [--patch-file FILE]

Downloads upstream OpenSSL 3.6.0-beta1, applies the local repo patch, builds, and installs it.

Options:
  --download-dir DIR   Download base tarball and extracted source tree (default: $DOWNLOAD_DIR)
  --source-dir DIR     Extracted source tree root (default: $SRC_DIR)
  --install-dir DIR    OpenSSL install prefix (default: $INSTALL_DIR)
  --patch-file FILE    Patch file to apply (default: $PATCH_FILE)
  --help               Show this message.
EOF
}

ensure_tool() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required tool '$cmd' is missing." >&2
    exit 1
  fi
}

ensure_tools() {
  ensure_tool patch
  ensure_tool tar
  ensure_tool perl
  if command -v wget >/dev/null 2>&1; then
    :
  elif command -v curl >/dev/null 2>&1; then
    :
  else
    echo "Require wget or curl to download OpenSSL." >&2
    exit 1
  fi
  ensure_tool make
  ensure_tool gcc
}

download_tarball() {
  mkdir -p "$DOWNLOAD_DIR"
  if [[ -f "$TARBALL" ]]; then
    echo "Using existing tarball: $TARBALL"
    return
  fi
  echo "Downloading OpenSSL 3.6.0-beta1..."
  if command -v wget >/dev/null 2>&1; then
    wget -O "$TARBALL" "$OPENSSL_URL"
  else
    curl -L -o "$TARBALL" "$OPENSSL_URL"
  fi
}

extract_source() {
  rm -rf "$SRC_DIR"
  mkdir -p "$DOWNLOAD_DIR"
  tar -xzf "$TARBALL" -C "$DOWNLOAD_DIR"
}

apply_patch() {
  if [[ ! -f "$PATCH_FILE" ]]; then
    echo "Patch file not found: $PATCH_FILE" >&2
    exit 1
  fi
  pushd "$SRC_DIR" >/dev/null
  echo "Verifying patch applies cleanly..."
  patch -p2 --dry-run < "$PATCH_FILE"
  echo "Applying patch..."
  patch -p2 < "$PATCH_FILE"
  popd >/dev/null
}

configure_and_build() {
  mkdir -p "$INSTALL_DIR"
  pushd "$SRC_DIR" >/dev/null
  echo "Configuring OpenSSL..."
  ./config --prefix="$INSTALL_DIR"
  echo "Building OpenSSL..."
  make -j"$(nproc)"
  echo "Installing OpenSSL into $INSTALL_DIR..."
  make install_sw
  popd >/dev/null
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --download-dir)
        DOWNLOAD_DIR="$2"
        shift 2
        ;;
      --source-dir)
        SRC_DIR="$2"
        shift 2
        ;;
      --install-dir)
        INSTALL_DIR="$2"
        shift 2
        ;;
      --patch-file)
        PATCH_FILE="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage
        exit 1
        ;;
    esac
  done
}

main() {
  parse_args "$@"
  ensure_tools
  download_tarball
  extract_source
  apply_patch
  configure_and_build
  echo "Done. Installed OpenSSL at: $INSTALL_DIR"
}

main "$@"
