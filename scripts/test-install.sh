#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
installer="$root/scripts/install.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rsbx-install-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

if RSBX_NO_VERIFY=1 "$installer" --dir "$tmp/should-not-exist" >"$tmp/out" 2>"$tmp/err"; then
  printf 'installer allowed unverified remote installation\n' >&2
  exit 1
fi
if ! grep -Fq 'RSBX_NO_VERIFY=1 requires --file for offline testing' "$tmp/err"; then
  printf 'installer rejected remote verification bypass for the wrong reason\n' >&2
  cat "$tmp/err" >&2
  exit 1
fi
if [ -e "$tmp/should-not-exist" ]; then
  printf 'installer created the destination before rejecting the remote bypass\n' >&2
  exit 1
fi

if RSBX_NO_VERIFY=maybe "$installer" --dir "$tmp/invalid" >"$tmp/out" 2>"$tmp/err"; then
  printf 'installer accepted an invalid verification override\n' >&2
  exit 1
fi
if ! grep -Fq 'RSBX_NO_VERIFY must be 0 or 1' "$tmp/err"; then
  printf 'installer rejected the invalid override for the wrong reason\n' >&2
  cat "$tmp/err" >&2
  exit 1
fi
if [ -e "$tmp/invalid" ]; then
  printf 'installer created the destination before rejecting the invalid override\n' >&2
  exit 1
fi

mkdir -p "$tmp/mock-block-network"
for tool in gh curl; do
  cat > "$tmp/mock-block-network/$tool" <<'MOCK'
#!/bin/sh
printf 'unexpected downloader call\n' >> "$RSBX_TEST_NETWORK_LOG"
exit 99
MOCK
  chmod 0755 "$tmp/mock-block-network/$tool"
done

for invalid_version in 'v0.0.042' '../../other/repo' '--repo'; do
  destination="$tmp/invalid-version-${invalid_version//\//_}"
  if PATH="$tmp/mock-block-network:$PATH" RSBX_TEST_NETWORK_LOG="$tmp/network-called.log" RSBX_VERSION="$invalid_version" "$installer" --dir "$destination" >"$tmp/out" 2>"$tmp/err"; then
    printf 'installer accepted invalid release version: %s\n' "$invalid_version" >&2
    exit 1
  fi
  if ! grep -Fq 'invalid release version: use stable major.minor.patch' "$tmp/err"; then
    printf 'installer rejected invalid release version for the wrong reason\n' >&2
    cat "$tmp/err" >&2
    exit 1
  fi
  if [ -e "$destination" ]; then
    printf 'installer created the destination before rejecting release version\n' >&2
    exit 1
  fi
  if [ -e "$tmp/network-called.log" ]; then
    printf 'installer invoked a downloader before rejecting release version\n' >&2
    cat "$tmp/network-called.log" >&2
    exit 1
  fi
done

cat > "$tmp/rsbx-fixture" <<'FIXTURE'
#!/bin/sh
printf 'RSBX_INSTALL_FIXTURE_OK\n'
FIXTURE
chmod 0755 "$tmp/rsbx-fixture"

if [ "$(uname -s)" = Darwin ]; then
  mkdir -p "$tmp/mock-sign-fail" "$tmp/mock-verify-fail" "$tmp/mock-xattr-fail"
  cat > "$tmp/mock-sign-fail/codesign" <<'MOCK'
#!/bin/sh
exit 1
MOCK
  cat > "$tmp/mock-verify-fail/codesign" <<'MOCK'
#!/bin/sh
if [ "${1:-}" = --verify ]; then exit 1; fi
exit 0
MOCK
  cat > "$tmp/mock-xattr-fail/codesign" <<'MOCK'
#!/bin/sh
exit 0
MOCK
  cat > "$tmp/mock-xattr-fail/xattr" <<'MOCK'
#!/bin/sh
exit 1
MOCK
  chmod 0755 "$tmp"/mock-*/codesign "$tmp/mock-xattr-fail/xattr"

  for control in sign verify xattr; do
    mock="$tmp/mock-$control-fail"
    destination="$tmp/$control-failure-bin"
    case "$control" in
      sign) expected='could not ad-hoc sign the installed binary' ;;
      verify) expected='could not verify the ad-hoc signature' ;;
      xattr) expected='could not remove the macOS quarantine attribute' ;;
    esac
    if PATH="$mock:$PATH" RSBX_NO_VERIFY=1 "$installer" --file "$tmp/rsbx-fixture" --dir "$destination" >"$tmp/out" 2>"$tmp/err"; then
      printf 'installer ignored macOS %s failure\n' "$control" >&2
      exit 1
    fi
    if ! grep -Fq "$expected" "$tmp/err"; then
      printf 'installer rejected macOS %s failure for the wrong reason\n' "$control" >&2
      cat "$tmp/err" >&2
      exit 1
    fi
    if [ -e "$destination/rsbx" ]; then
      printf 'installer wrote a binary after macOS %s failure\n' "$control" >&2
      exit 1
    fi
  done
fi

RSBX_NO_VERIFY=1 "$installer" --file "$tmp/rsbx-fixture" --dir "$tmp/offline-bin" >"$tmp/out"
if [ "$("$tmp/offline-bin/rsbx")" != 'RSBX_INSTALL_FIXTURE_OK' ]; then
  printf 'offline local-file install did not preserve the executable\n' >&2
  exit 1
fi

printf 'PASS: remote bypass denied; invalid override denied; explicit offline file install succeeded\n'
