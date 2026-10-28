#!/bin/sh
# #18178: fail if dpkg-parsechangelog warns on debian/changelog.
# Usage: check-changelog-18178.sh [changelog-path]
# Exits 0 only on exit-0 parse with zero stderr and >=1 parsed entry.
set -u
changelog=${1:-debian/changelog}
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT INT TERM
out=$(dpkg-parsechangelog -l "$changelog" --all 2>"$tmp"); rc=$?
if [ "$rc" -ne 0 ]; then
  echo "FATAL: dpkg-parsechangelog --all failed (rc=$rc) on $changelog" >&2
  cat "$tmp" >&2
  exit 1
fi
if [ -s "$tmp" ]; then
  echo "FATAL: dpkg-parsechangelog --all emitted warnings on $changelog (#18178):" >&2
  cat "$tmp" >&2
  exit 1
fi
versions=$(printf '%s\n' "$out" | grep -c '^Version:' || true)
if [ "$versions" -lt 1 ]; then
  echo "FATAL: dpkg-parsechangelog --all parsed no entries in $changelog" >&2
  exit 1
fi
echo "==> changelog OK: $versions entr(ies), zero warnings ($changelog)"
