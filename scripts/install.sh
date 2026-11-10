#!/usr/bin/env bash
# Install rsbx from a signed Rheic GitHub release without manual approval.
#
# The binary is checked against SHA256SUMS, its SLSA provenance is verified
# when the GitHub CLI is available, it is ad-hoc signed on macOS and the
# quarantine attribute is removed, so Gatekeeper does not prompt for a
# Terminal-launched CLI. Set RSBX_NO_VERIFY=1 with --file only for offline testing.
set -euo pipefail

repo="rheic/sandboxes-cli"
version="${RSBX_VERSION:-}"
dir="${RSBX_INSTALL_DIR:-$HOME/.local/bin}"
file=""

usage() {
  echo "usage: $0 [--version vX.Y.Z] [--dir DIR] [--file PATH]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="${2:?}"; shift 2 ;;
    --dir) dir="${2:?}"; shift 2 ;;
    --file) file="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

no_verify="${RSBX_NO_VERIFY:-0}"
case "$no_verify" in
  0|1) ;;
  *) echo "RSBX_NO_VERIFY must be 0 or 1" >&2; exit 2 ;;
esac
if [ "$no_verify" = "1" ] && [ -z "$file" ]; then
  echo "RSBX_NO_VERIFY=1 requires --file for offline testing" >&2
  exit 2
fi

os="$(uname -s)"
case "$os" in
  Darwin) goos="darwin" ;;
  Linux) goos="linux" ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac
arch="$(uname -m)"
case "$arch" in
  arm64|aarch64) goarch="arm64" ;;
  x86_64|amd64) goarch="amd64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

asset="rsbx-${goos}-${goarch}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/rsbx-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ -z "$file" ]; then
  if [ -z "$version" ]; then
    if command -v gh >/dev/null 2>&1; then
      version="$(gh release view --repo "$repo" --json tagName --jq .tagName)"
    else
      version="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    fi
  fi
  [ -n "$version" ] || { echo "could not determine release version" >&2; exit 1; }
  if [[ ! "$version" =~ ^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "invalid release version: use stable major.minor.patch" >&2
    exit 2
  fi
  echo "downloading ${asset} from ${repo} ${version}"
  if command -v gh >/dev/null 2>&1; then
    gh release download "$version" --repo "$repo" --pattern "$asset" --pattern SHA256SUMS --dir "$tmp"
  else
    base="https://github.com/${repo}/releases/download/${version}"
    curl -fsSL "$base/$asset" -o "$tmp/$asset"
    curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
  fi
  file="$tmp/$asset"
else
  cp "$file" "$tmp/$asset"
  file="$tmp/$asset"
fi

if [ "$no_verify" != "1" ]; then
  if [ -f "$tmp/SHA256SUMS" ]; then
    expected="$(awk -v name="$(basename "$asset")" '$2 == name {print $1}' "$tmp/SHA256SUMS")"
    [ -n "$expected" ] || { echo "asset is missing from SHA256SUMS" >&2; exit 1; }
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || { echo "checksum mismatch for ${asset}" >&2; exit 1; }
    echo "checksum ok: ${actual}"
  else
    echo "SHA256SUMS not found; refusing to install unverified asset" >&2
    exit 1
  fi
  if command -v gh >/dev/null 2>&1 && [ -n "$version" ]; then
    gh attestation verify "$file" --repo "$repo" >/dev/null
    echo "SLSA provenance verified"
  fi
fi

chmod 0755 "$file"
if [ "$goos" = "darwin" ]; then
  if ! codesign --force --sign - "$file" >/dev/null 2>&1; then
    echo "could not ad-hoc sign the installed binary" >&2
    exit 1
  fi
  if ! codesign --verify --strict "$file" >/dev/null 2>&1; then
    echo "could not verify the ad-hoc signature" >&2
    exit 1
  fi
  if ! xattr -dr com.apple.quarantine "$file" 2>/dev/null; then
    echo "could not remove the macOS quarantine attribute" >&2
    exit 1
  fi
fi
mkdir -p "$dir"
install -m 0755 "$file" "$dir/rsbx"
echo "installed $dir/rsbx"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "add $dir to PATH, for example: export PATH=\"$dir:\$PATH\"" ;;
esac
