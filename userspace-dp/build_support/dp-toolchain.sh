#!/bin/sh
# #9920 F-148: print the userspace-dp toolchain pin, failing loudly on
# anything else. The Makefile's helper recipes resolve the pin through this
# script and invoke `$(CARGO) +<pin>` explicitly (cargo is run from the repo
# root with --manifest-path, so it never discovers rust-toolchain.toml by
# CWD — a bare pin file without explicit enforcement would pin nothing).
#
# Usage: dp-toolchain.sh TOML_PATH [CARGO_BIN]
#   TOML_PATH is userspace-dp/rust-toolchain.toml (explicit so tests can
#   drive fixtures; no env override — an override would defeat the pin).
#   When CARGO_BIN is given, the pin is additionally verified usable via
#   `CARGO_BIN +<pin> --version`, so a missing toolchain AND a non-rustup
#   cargo both fail here with the install hint instead of cryptically
#   mid-build. Prints ONLY the pin on stdout, on success.
set -eu

fail() {
    echo "dp-toolchain.sh (#9920): $*" >&2
    exit 1
}

[ "$#" -ge 1 ] || fail "usage: dp-toolchain.sh TOML_PATH [CARGO_BIN]"
toml=$1
cargo=${2:-}
[ -f "$toml" ] || fail "missing $toml (helper toolchain pin SSOT)"

# Tolerant of quote style (single/double), surrounding spacing, and trailing
# comments on the section AND value lines; scoped to the [toolchain] table;
# requires EXACTLY ONE channel key; strict shape check afterwards. The value
# must be exactly one quoted token with no interior whitespace — stripping is
# NOT validation (`channel = "1.98 .1"` must fail, not normalize to 1.98.1),
# so a non-conforming value passes through raw and fails the X.Y.Z check
# below, loudly. A garbled, missing, duplicated, or wrong-table parse fails
# loudly and can never fall back to an unpinned toolchain. (awk program only
# is shared with the bash pin block in pkg/dataplane/build-userspace-xdp.sh;
# the surrounding checks below are POSIX sh.)
channels=$(awk '
/^[[:space:]]*\[/ { in_tc = ($0 ~ /^[[:space:]]*\[toolchain\][[:space:]]*(#.*)?$/) }
in_tc && /^[[:space:]]*channel[[:space:]]*=/ {
	v=$0; sub(/^[^=]*=/, "", v); sub(/#.*/, "", v)
	if (v ~ /^[[:space:]]*"[^"[:space:]]+"[[:space:]]*$/ || v ~ /^[[:space:]]*'"'"'[^'"'"'[:space:]]+'"'"'[[:space:]]*$/) {
		gsub(/[[:space:]"'"'"']/, "", v); print v
	} else {
		print v
	}
}' "$toml")
[ -n "$channels" ] || fail "expected exactly one 'channel' key in the [toolchain] table of $toml; got none"
nl='
'
case "$channels" in
    *"$nl"*) fail "expected exactly one 'channel' key in the [toolchain] table of $toml; got: '$channels'" ;;
esac
if ! expr "$channels" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; then
    fail "could not parse an X.Y.Z channel pin from $toml (got '$channels')"
fi

if [ -n "$cargo" ]; then
    if ! "$cargo" "+$channels" --version >/dev/null 2>&1; then
        fail "toolchain pin '$channels' from $toml is not usable via $cargo (need the rustup shim + 'rustup toolchain install $channels')"
    fi
fi

printf '%s\n' "$channels"
