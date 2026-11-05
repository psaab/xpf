#!/usr/bin/env bash
# Hermetic regression test for compare-gate identity ordering and attestation.
# Builds a tiny real .deb whose staged executable bytes provide the manifest
# SHA source of truth; all cell data and ledger output live under a temp dir.
# It never invokes Incus or mutates a cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PR_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPARE_GATE_SCRIPT="${COMPARE_GATE_SCRIPT:-$SCRIPT_DIR/compare-gate.sh}"
if [[ "$COMPARE_GATE_SCRIPT" != /* ]]; then
	COMPARE_GATE_SCRIPT="$PR_ROOT/$COMPARE_GATE_SCRIPT"
fi
OLD_COMPARE_GATE_SCRIPT="${XPF_OLD_COMPARE_GATE_SCRIPT:-/var/worktrees/.cache/gate-docs-loss/compare-gate.sh}"
MODE="${1:-all}"
T="$(mktemp -d "${TMPDIR:-/tmp}/xpf-compare-gate-selftest.XXXXXX")"
trap 'rm -rf "$T"' EXIT

PASS=0
ok() { PASS=$((PASS + 1)); printf 'PASS (%d): %s\n' "$PASS" "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

BUILD_SHA=1111111111111111111111111111111111111111
VERSION="9.9.0+g${BUILD_SHA:0:12}"
RUNTIME_VERSION="working-${VERSION}"
CLI_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Build a proper Debian package with the same staged-member layout consumed by
# deploy_manifest_sha_from_deb. The hashes are from the bytes dpkg-deb packs.
mkdir -p "$T/pkg/DEBIAN" "$T/pkg/usr/local/share/xpf/staged"
cat >"$T/pkg/DEBIAN/control" <<EOF
Package: xpf
Version: $VERSION
Architecture: amd64
Maintainer: selftest <noreply@example.invalid>
Description: compare-gate hermetic selftest fixture
EOF
printf 'selftest xpfd payload\n' >"$T/pkg/usr/local/share/xpf/staged/xpfd"
printf 'selftest userspace helper payload\n' >"$T/pkg/usr/local/share/xpf/staged/xpf-userspace-dp"
XPFD_SHA="$(sha256sum "$T/pkg/usr/local/share/xpf/staged/xpfd" | cut -d' ' -f1)"
HELPER_SHA="$(sha256sum "$T/pkg/usr/local/share/xpf/staged/xpf-userspace-dp" | cut -d' ' -f1)"
dpkg-deb --build "$T/pkg" "$T/fixture.deb" >/dev/null

write_valid_identity() {
	local out="$1" prefix="${2:-}"
	{
		if [[ -n "$prefix" ]]; then
			printf '%s\n' \
				'cell_mode=pr' \
				'cell_start_epoch=1793788547' \
				'cell_start_utc=2026-11-04T10:35:47+00:00' \
				'source_root=/fixture/source' \
				"source_sha=$BUILD_SHA" \
				"package=$T/fixture.deb" \
				"package_version=$VERSION" \
				"runtime_VERSION=$RUNTIME_VERSION"
		fi
		printf 'node0=loss:xpf-userspace-fw0 source_sha=%s manifest_sha=%s running_sha=%s cli_sha=%s helper_sha=%s deb_version=%s xpfd_version=%s\n' \
			"$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$CLI_SHA" "$HELPER_SHA" "$VERSION" "$RUNTIME_VERSION"
		printf 'node1=loss:xpf-userspace-fw1 source_sha=%s manifest_sha=%s running_sha=%s cli_sha=%s helper_sha=%s deb_version=%s xpfd_version=%s\n' \
			"$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$CLI_SHA" "$HELPER_SHA" "$VERSION" "$RUNTIME_VERSION"
	} >"$out"
}

write_identity_variant() {
	local out="$1" kind="$2"
	case "$kind" in
	valid) write_valid_identity "$out" ;;
	header) write_valid_identity "$out" header ;;
	incident)
		# Exact incident shape: eight cell-identity headers followed by two
		# node-prefixed records without running_sha or manifest_sha.
		{
			printf '%s\n' \
				'cell_mode=pr' \
				'cell_start_epoch=1793788547' \
				'cell_start_utc=2026-11-04T10:35:47+00:00' \
				'source_root=/fixture/source' \
				"source_sha=$BUILD_SHA" \
				"package=$T/fixture.deb" \
				"package_version=$VERSION" \
				"runtime_VERSION=$RUNTIME_VERSION"
			printf 'node0=loss:xpf-userspace-fw0 source_sha=%s helper_sha=%s deb_version=%s xpfd_version=%s\n' "$BUILD_SHA" "$HELPER_SHA" "$VERSION" "$RUNTIME_VERSION"
			printf 'node1=loss:xpf-userspace-fw1 source_sha=%s helper_sha=%s deb_version=%s xpfd_version=%s\n' "$BUILD_SHA" "$HELPER_SHA" "$VERSION" "$RUNTIME_VERSION"
		} >"$out"
		;;
	missing-node)
		printf 'node0=loss:xpf-userspace-fw0 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$HELPER_SHA" "$VERSION" >"$out"
		;;
	duplicate-node)
		{
			printf 'node0=loss:xpf-userspace-fw0 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$HELPER_SHA" "$VERSION"
			printf 'node0=loss:xpf-userspace-fw0 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$HELPER_SHA" "$VERSION"
			printf 'node1=loss:xpf-userspace-fw1 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$HELPER_SHA" "$VERSION"
		} >"$out"
		;;
	missing-key)
		{
			printf 'node0=loss:xpf-userspace-fw0 source_sha=%s manifest_sha=%s running_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$VERSION"
			printf 'node1=loss:xpf-userspace-fw1 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$HELPER_SHA" "$VERSION"
		} >"$out"
		;;
	bad-running-sha)
		{
			printf 'node0=loss:xpf-userspace-fw0 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' "$HELPER_SHA" "$VERSION"
			printf 'node1=loss:xpf-userspace-fw1 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' "$HELPER_SHA" "$VERSION"
		} >"$out"
		;;
	bad-helper-sha)
		{
			printf 'node0=loss:xpf-userspace-fw0 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' "$VERSION"
			printf 'node1=loss:xpf-userspace-fw1 source_sha=%s manifest_sha=%s running_sha=%s helper_sha=%s deb_version=%s\n' "$BUILD_SHA" "$XPFD_SHA" "$XPFD_SHA" "$HELPER_SHA" "$VERSION"
		} >"$out"
		;;
	empty) : >"$out" ;;
	*) fail "unknown identity fixture $kind" ;;
	esac
}

write_summary() {
	local path="$1" mode="$2"
	mkdir -p "$(dirname "$path")"
	printf 'cell\tcommand_rc\treceiver_bps\treceiver_bytes\tretransmits\n' >"$path"
	[[ "$mode" == empty ]] && return 0
	local name retr
	for name in single-v4-push single-v4-reverse single-v6-push single-v6-reverse \
		multi-v4-r1 multi-v4-r2 multi-v4-r3 multi-v4-r4 multi-v4-r5 \
		multi-v6-r1 multi-v6-r2 multi-v6-r3 multi-v6-r4 multi-v6-r5; do
		retr=1
		if [[ "$mode" == fail && "$name" == single-v6-reverse ]]; then retr=2; fi
		printf '%s\t0\t1000\t1000\t%s\n' "$name" "$retr" >>"$path"
	done
}

setup_window() {
	local name="$1" identity_kind="$2" measurement="$3"
	RUN="$T/$name"
	BASE="$RUN/baseline"
	PR="$RUN/pr"
	CONTROL="$RUN/control"
	OUT="$RUN/comparison"
	LEDGER="$RUN/ledger"
	mkdir -p "$BASE/throughput" "$BASE/connectivity" "$PR/throughput" "$PR/connectivity" "$CONTROL/throughput" "$CONTROL/connectivity" "$OUT" "$LEDGER"
	write_summary "$BASE/throughput/summary.tsv" full
	write_summary "$PR/throughput/summary.tsv" "$measurement"
	write_summary "$CONTROL/throughput/summary.tsv" full
	printf 'throughput_rc=0\n' >"$BASE/throughput-result.txt"
	printf 'throughput_rc=0\n' >"$PR/throughput-result.txt"
	printf 'throughput_rc=0\n' >"$CONTROL/throughput-result.txt"
	printf 'post_health_rc=0\n' >"$BASE/post-health-result.txt"
	printf 'post_health_rc=0\n' >"$PR/post-health-result.txt"
	: >"$BASE/connectivity/connectivity.log"
	: >"$PR/connectivity/connectivity.log"
	: >"$CONTROL/connectivity/connectivity.log"
	printf 'verdict=PASS\n' >"$PR/connectivity-comparison.txt"
	write_identity_variant "$PR/deployed-identity.txt" "$identity_kind"
}

run_gate() {
	if XPF_LEDGER="$LEDGER" XPF_GATE_ID=xpf-compare-gate-selftest \
		bash "$COMPARE_GATE_SCRIPT" "$PR_ROOT" "$T/fixture.deb" "$VERSION" "$BUILD_SHA" \
		"$RUNTIME_VERSION" "$BASE" "$PR" "$CONTROL" "$OUT" >"$RUN/stdout" 2>"$RUN/stderr"; then
		GATE_RC=0
	else
		GATE_RC=$?
	fi
}

ledger_count() {
	find "$LEDGER" -maxdepth 1 -type f -name '*.json' -print | wc -l
}

assert_judged() {
	local expected="$1" label="$2"
	[[ "$GATE_RC" -eq 0 ]] || fail "$label exited $GATE_RC: $(cat "$RUN/stderr")"
	[[ "$(grep -c '^verdict=' "$RUN/stdout")" -eq 1 ]] || fail "$label did not print exactly one verdict"
	grep -qx "verdict=$expected" "$RUN/stdout" || fail "$label printed the wrong verdict"
	[[ "$(ledger_count)" -eq 1 ]] || fail "$label wrote $(ledger_count) ledger shards, expected exactly one"
	python3 - "$LEDGER" "$expected" <<'PY'
import json, pathlib, sys
paths = list(pathlib.Path(sys.argv[1]).glob("*.json"))
assert len(paths) == 1, paths
row = json.loads(paths[0].read_text())
assert row["verdict"] == sys.argv[2], row
assert row["gate"] == "xpf-compare-gate-selftest", row
assert row["exe_check"] == "MATCH", row
assert row["helper_exe_check"] == "MATCH", row
assert row["running_exe_sha256"] == row["build_exe_sha256"], row
assert row["running_exe_sha256_peer"] == row["build_exe_sha256"], row
assert row["running_helper_exe_sha256"] == row["build_helper_exe_sha256"], row
assert row["running_helper_exe_sha256_peer"] == row["build_helper_exe_sha256"], row
PY
}

assert_rejected_before_verdict() {
	local label="$1"
	[[ "$GATE_RC" -ne 0 ]] || fail "$label unexpectedly succeeded"
	if grep -q '^verdict=' "$RUN/stdout"; then
		fail "$label printed a verdict before rejecting identity: $(grep '^verdict=' "$RUN/stdout")"
	fi
	[[ "$(ledger_count)" -eq 0 ]] || fail "$label wrote a judged shard"
	ok "$label is rejected pre-verdict with no ledger shard"
}

case_incident() {
	setup_window incident incident fail
	run_gate
	assert_rejected_before_verdict 'incident 8-header/missing-running-sha fixture'
}

if [[ "$MODE" != all && "$MODE" != incident-only ]]; then
	fail "usage: $0 [all|incident-only]"
fi

case_incident
if [[ "$MODE" == incident-only ]]; then
	printf 'ALL %d INCIDENT CASE PASS\n' "$PASS"
	exit 0
fi

setup_window valid-fail valid fail
run_gate
assert_judged FAIL 'valid identity plus FAIL summaries'
ok 'FAIL shard carries fully matched executable and helper attestations'

setup_window header-valid header fail
run_gate
assert_judged FAIL 'header-prefixed fully attested identity'
ok 'header-prefixed identity selected by node record prefixes'

for malformed in missing-node duplicate-node missing-key empty; do
	setup_window "malformed-$malformed" "$malformed" fail
	run_gate
	assert_rejected_before_verdict "malformed identity ($malformed)"
done

for mismatch in bad-running-sha bad-helper-sha; do
	setup_window "mismatch-$mismatch" "$mismatch" fail
	run_gate
	assert_rejected_before_verdict "manifest mismatch ($mismatch)"
	if grep -q 'MATCH' "$RUN/stdout" "$RUN/stderr"; then
		fail "manifest mismatch ($mismatch) emitted MATCH attestation"
	fi
	ok "manifest mismatch ($mismatch) emits no MATCH attestation"
done

setup_window valid-pass valid full
run_gate
assert_judged PASS 'valid identity plus PASS summaries'
ok 'PASS shard emitted'

setup_window valid-void valid empty
run_gate
assert_judged VOID 'valid identity plus VOID measurement window'
ok 'VOID measurement shard emitted'

# Prove case 3 is RED against the pre-fix ephemeral comparator when it is
# available: the old implementation computes/prints verdict=FAIL from this
# same incident-shaped identity, then aborts when it indexes empty ids[0].
# That is precisely the behavior the incident assertion above forbids.
if [[ -f "$OLD_COMPARE_GATE_SCRIPT" ]]; then
	OLD_COMPARE_GATE_SCRIPT="$(readlink -f "$OLD_COMPARE_GATE_SCRIPT")"
	COMPARE_GATE_SCRIPT="$OLD_COMPARE_GATE_SCRIPT"
	setup_window revert-red incident fail
	run_gate
	[[ "$GATE_RC" -ne 0 ]] || fail 'old comparator unexpectedly emitted a successful judgment for incident fixture'
	grep -qx 'verdict=FAIL' "$RUN/stdout" || fail 'old comparator did not reproduce verdict-before-abort behavior'
	[[ "$(ledger_count)" -eq 0 ]] || fail 'old comparator unexpectedly wrote an incident shard'
	ok 'RED-on-revert: old comparator prints verdict=FAIL before aborting without a shard'
else
	printf 'SKIP: RED-on-revert proof unavailable; old comparator copy not present at %s\n' "$OLD_COMPARE_GATE_SCRIPT"
fi

printf 'ALL %d CASES PASS\n' "$PASS"
