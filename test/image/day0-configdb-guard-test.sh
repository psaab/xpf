#!/usr/bin/env bash
# Regression test for the day-0 config-drive "already configured" guard
# (fable-review-165 H-1, issue #4175).
#
# The loader (scripts/image/xpf-day0-config) must skip the day-0 probe only
# when the box holds a COMMITTED configstore DB — i.e. .configdb/active.json
# exists — NOT merely when the bare .configdb DIRECTORY exists. xpfd creates
# .configdb on EVERY start (pkg/configstore NewDB -> MkdirAllDurable, before
# any commit), so guarding on the directory permanently defeated the
# fix-and-reboot retry contract: after the very first boot the empty
# .configdb dir existed and a rejected/absent drive could never be retried.
#
# RED-on-revert: change have_committed_config back to `[ -e "$XPF_DIR/.configdb" ]`
# and scenarios A and D fail (an empty .configdb dir wrongly reports
# "already configured" / suppresses the re-probe).
#
#   bash test/image/day0-configdb-guard-test.sh
#
# shellcheck disable=SC1007  # `CDPATH= cd` is an env-prefix, not an assignment
# shellcheck disable=SC1090  # the sourced loader path is a runtime argument
# shellcheck disable=SC2034  # REJECT_MARKER/STAMP/XPFD are consumed by main()
# shellcheck disable=SC2329  # probe/regen stubs are invoked indirectly by main()
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SCRIPT="${1:-$HERE/../../scripts/image/xpf-day0-config}"
[ -f "$SCRIPT" ] || { echo "loader not found: $SCRIPT" >&2; exit 1; }

# Source the loader as a library (do not run main).
XPF_DAY0_SOURCE_ONLY=1 . "$SCRIPT"
set +u  # keep the harness relaxed; the sourced script re-enables -u

fail() { echo "FAIL: $*" >&2; exit 1; }

# make_stub_xpfd <path> — an executable stand-in so main()'s `[ ! -x "$XPFD" ]`
# gate passes and the probe path is reached.
make_stub_xpfd() {
	cat >"$1" <<'STUB'
#!/bin/sh
exit 0
STUB
	chmod +x "$1"
}

# ── unit: the have_committed_config predicate ─────────────────────────────

# A: an empty .configdb directory (no active.json) must NOT count as
# configured — this is the exact state xpfd leaves after every start, and the
# state the retry contract depends on re-probing.
scenario_empty_dir_reprobes() (
	XPF_DIR=$(mktemp -d)
	mkdir -p "$XPF_DIR/.configdb"
	if have_committed_config; then
		fail "A: empty .configdb dir wrongly reported as committed (retry would be dead)"
	fi
	rm -rf "$XPF_DIR"
	echo "PASS A: empty .configdb dir -> re-probe (not configured)"
)

# B: a committed DB (active.json present) must count as configured.
scenario_active_json_skips() (
	XPF_DIR=$(mktemp -d)
	mkdir -p "$XPF_DIR/.configdb"
	: >"$XPF_DIR/.configdb/active.json"
	if ! have_committed_config; then
		fail "B: active.json present but not reported as committed (would clobber a real config)"
	fi
	rm -rf "$XPF_DIR"
	echo "PASS B: .configdb/active.json present -> skip (configured)"
)

# C: no .configdb at all must NOT count as configured.
scenario_no_configdb_reprobes() (
	XPF_DIR=$(mktemp -d)
	if have_committed_config; then
		fail "C: absent .configdb reported as committed"
	fi
	rm -rf "$XPF_DIR"
	echo "PASS C: no .configdb -> re-probe (not configured)"
)

# ── integration: main()'s skip/probe decision ────────────────────────────
# Stub the side-effecting helpers so main() exercises only the guard chain.

# D: empty .configdb + a valid xpfd + no media -> main must fall through the
# guard chain and REACH the probe (logs the no-medium fallback), proving the
# retry path is alive. It must NOT log "already configured".
scenario_main_empty_dir_probes() (
	XPF_DIR=$(mktemp -d)
	STAMP="$XPF_DIR/.day0-config-applied"
	REJECT_MARKER="$XPF_DIR/.day0-config-rejected"
	XPFD="$XPF_DIR/xpfd"; make_stub_xpfd "$XPFD"
	mkdir -p "$XPF_DIR/.configdb"          # empty dir as xpfd leaves it
	regen_ssh_host_keys() { :; }           # no ssh-keygen
	probe_devices() { :; }                 # no media -> empty
	out=$(main 2>&1)
	echo "$out" | grep -q "already configured" && \
		fail "D: main logged 'already configured' on an empty .configdb dir (retry dead)"
	echo "$out" | grep -q "no config medium found" || \
		fail "D: main did not reach the probe path on an empty .configdb dir"
	rm -rf "$XPF_DIR"
	echo "PASS D: empty .configdb dir -> main re-probes the medium"
)

# E: a committed DB (active.json) -> main must short-circuit at the guard and
# never reach the probe.
scenario_main_active_json_skips() (
	XPF_DIR=$(mktemp -d)
	STAMP="$XPF_DIR/.day0-config-applied"
	REJECT_MARKER="$XPF_DIR/.day0-config-rejected"
	XPFD="$XPF_DIR/xpfd"; make_stub_xpfd "$XPFD"
	mkdir -p "$XPF_DIR/.configdb"
	: >"$XPF_DIR/.configdb/active.json"
	regen_ssh_host_keys() { :; }
	probe_devices() { fail "E: main probed media despite a committed active.json"; }
	out=$(main 2>&1)
	echo "$out" | grep -q "already configured" || \
		fail "E: main did not skip on a committed active.json"
	rm -rf "$XPF_DIR"
	echo "PASS E: committed active.json -> main skips the day-0 probe"
)

# Each scenario runs in a subshell; `fail` exits that subshell non-zero, so
# propagate it to the overall exit status (a swallowed subshell exit would
# let CI see a green run despite FAIL lines).
scenario_empty_dir_reprobes      || exit 1
scenario_active_json_skips       || exit 1
scenario_no_configdb_reprobes    || exit 1
scenario_main_empty_dir_probes   || exit 1
scenario_main_active_json_skips  || exit 1
echo "ALL DAY-0 CONFIGDB GUARD SCENARIOS PASSED"
