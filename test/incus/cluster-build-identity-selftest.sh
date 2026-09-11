#!/usr/bin/env bash
#
# Hermetic self-test for the shared-cluster BUILD IDENTITY check.
# Mocks `incus` and `cluster-env.sh`; never touches a cluster, never
# touches the real /tmp/xpf-cluster.lock. Safe to run anywhere.
#
#   ./test/incus/cluster-build-identity-selftest.sh
#
# Exits 0 with "ALL n CASES PASS" or non-zero naming the failed case.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T=$(mktemp -d /tmp/xpf-build-id-selftest.XXXXXX)
trap 'rm -rf "$T"' EXIT

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# --- mock incus: reports the sha named by the per-node files in $T/state
mkdir -p "$T/bin" "$T/state"
cat >"$T/bin/incus" <<'MOCK'
#!/usr/bin/env bash
# incus exec [-n] <ref> -- sha256sum <path>
# Like the real client, `incus exec` without -n reads its stdin (#9683): inside
# a stdin-fed loop it drains the loop's input. Emulated so a probe that forgets
# -n fails case 2b instead of passing it. The drain reads only input that is
# already there, so it never blocks.
[[ "$1" == "exec" ]] || exit 1
shift
drain=1 ref=""
for a in "$@"; do
	case "$a" in
	--) break ;;
	-n|--disable-stdin) drain=0 ;;
	-*) ;;
	*) [[ -n "$ref" ]] || ref="$a" ;;
	esac
done
if (( drain )) && [[ ! -t 0 ]]; then
	while read -r -t 0 _ && IFS= read -r _; do :; done
fi
f="${XPF_SELFTEST_STATE}/${ref//[^A-Za-z0-9_.-]/_}"
[[ -f "$f" ]] || exit 1          # node unreachable
printf '%s  /usr/local/sbin/xpfd\n' "$(cat "$f")"
MOCK
chmod +x "$T/bin/incus"
export PATH="$T/bin:$PATH"
export XPF_SELFTEST_STATE="$T/state"

# --- mock cluster-env.sh so the probe resolves two known refs
mkdir -p "$T/lib"
cp "$SCRIPT_DIR/cluster-build-identity.sh" "$T/lib/"
cat >"$T/lib/cluster-env.sh" <<'ENV'
FW0="node0"; FW1="node1"
ENV

# shellcheck source=cluster-build-identity.sh
source "$T/lib/cluster-build-identity.sh"

set_sha() { printf '%s' "$2" >"$T/state/$1"; }
drop_node() { rm -f "$T/state/$1"; }

A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

export XPF_CLUSTER_BUILD_BASELINE="$T/baseline"

# 1: unchanged build -> diff says 0, assert passes
set_sha node0 "$A"; set_sha node1 "$A"
xpf_cluster_build_record "$XPF_CLUSTER_BUILD_BASELINE"
xpf_cluster_build_diff >/dev/null 2>&1 || fail "unchanged build must diff clean"
xpf_assert_cluster_build_unchanged 2>/dev/null || fail "assert must pass on an unchanged build"
ok "unchanged build: diff clean and assert passes"

# 2: THE INCIDENT — one node's binary replaced under the cell
set_sha node0 "$B"
rc=0; xpf_cluster_build_diff >/dev/null 2>&1 || rc=$?
[[ "$rc" == 1 ]] || fail "a changed build must diff as CHANGED (rc=$rc)"
rc=0; xpf_assert_cluster_build_unchanged 2>/dev/null || rc=$?
[[ "$rc" == 1 ]] || fail "assert must FAIL on a changed build (rc=$rc)"
ok "changed build: diff reports CHANGED and the measurement assert fails"

# 2b: #9683 -- the SECOND node's binary replaced. Case 2 changes node0, which
#    a probe that samples only its first node still sees. The probe runs
#    `incus exec` inside a loop fed the node list on stdin; without -n the
#    first call drains that list, so only FW0 is ever sampled and a swap on FW1
#    diffs clean. The mock drains stdin like the real client, so this case
#    fails on exactly that build.
set_sha node0 "$A"; set_sha node1 "$A"
xpf_cluster_build_record "$XPF_CLUSTER_BUILD_BASELINE"
probed=$(xpf_cluster_build_probe | wc -l)
[[ "$probed" == 2 ]] \
	|| fail "the probe must sample EVERY node; it sampled $probed of 2 (#9683)"
set_sha node1 "$B"
rc=0; xpf_cluster_build_diff >/dev/null 2>&1 || rc=$?
[[ "$rc" == 1 ]] || fail "a binary changed on the SECOND node must diff as CHANGED (rc=$rc, #9683)"
ok "changed build on the second node: every node is sampled and the diff reports CHANGED"

# 3: the report names BOTH shas -- knowing WHICH build was measured is
#    what made the originating incident traceable
out=$(xpf_cluster_build_diff 2>&1 >/dev/null || true)
[[ "$out" == *"$A"* && "$out" == *"$B"* ]] \
	|| fail "the report must name the old AND new sha; got: $out"
ok "report names both shas"

# 4: re-baseline (a deliberate deploy) clears the change
xpf_cluster_rebaseline_build
xpf_cluster_build_diff >/dev/null 2>&1 || fail "re-baseline must clear a deliberate change"
ok "re-baseline after a deliberate deploy clears the change"

# 5: FAILURE-TO-UNKNOWN, the shape this whole file exists to close. An
#    unreachable node must NOT read as "unchanged" -- an unattributable
#    measurement is not evidence.
drop_node node0; drop_node node1
rc=0; xpf_cluster_build_diff >/dev/null 2>&1 || rc=$?
[[ "$rc" == 2 ]] || fail "an unsampleable cluster must report UNKNOWN (2), got rc=$rc"
rc=0; xpf_assert_cluster_build_unchanged 2>/dev/null || rc=$?
[[ "$rc" == 1 ]] || fail "assert must FAIL when the build cannot be established (rc=$rc)"
ok "unsampleable cluster reports UNKNOWN and the assert refuses to measure"

# 6: a PARTIAL sample is not a clean bill either -- one node known and
#    unchanged, the other unreachable, must not pass the assert silently.
set_sha node0 "$B"; set_sha node1 "$B"
xpf_cluster_build_record "$XPF_CLUSTER_BUILD_BASELINE"
drop_node node1
out=$(xpf_cluster_build_diff 2>&1 >/dev/null || true)
[[ "$out" == *"UNKNOWN"* ]] || fail "a partial sample must SAY it is partial; got: $out"
ok "partial sample is reported as unknown rather than passed over"

# 7: boundary report is ADVISORY by default and FATAL under STRICT --
#    the deliberate severity split, so a deploy path nobody wired cannot
#    break a working target for a diagnostic.
set_sha node0 "$A"; set_sha node1 "$A"
xpf_cluster_build_record "$XPF_CLUSTER_BUILD_BASELINE"
set_sha node0 "$B"
xpf_cluster_build_report cell >/dev/null 2>&1 || fail "advisory report must not fail the cell"
rc=0
XPF_CLUSTER_BUILD_STRICT=1 xpf_cluster_build_report cell >/dev/null 2>&1 || rc=$?
[[ "$rc" == 1 ]] || fail "STRICT must promote the boundary report to fatal (rc=$rc)"
ok "boundary report: advisory by default, fatal under XPF_CLUSTER_BUILD_STRICT"

# 8: no baseline at all (helper used outside a cell) is a no-op, never a
#    crash -- rebaseline and record must tolerate an unset path.
( unset XPF_CLUSTER_BUILD_BASELINE
  xpf_cluster_rebaseline_build || fail "rebaseline outside a cell must be a no-op"
  xpf_cluster_build_record     || fail "record outside a cell must be a no-op" ) \
	|| fail "helpers must tolerate being used outside a cell"
ok "outside a cell the helpers are no-ops rather than errors"

# 9: WIRING. Cases 1-8 exercise the helpers directly, so every one of them
#    stays green if the call in cluster-setup.sh's deploy path is deleted --
#    and that call is what stops a deliberate deploy reporting itself as an
#    intrusion. Bind the call SITE, with a positive control that the search
#    can actually fail, so this is a check rather than a formality.
deploy_body() {
	awk '/^cmd_deploy\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$SCRIPT_DIR/cluster-setup.sh"
}
[[ -n "$(deploy_body)" ]] \
	|| fail "control: could not extract cmd_deploy from cluster-setup.sh -- the \
search below would vacuously find nothing"
deploy_body | grep -q 'xpf_cluster_rebaseline_build' \
	|| fail "cmd_deploy must re-baseline after a deliberate deploy, or every \
deploy cell reports a build change it made itself"
deploy_body | grep -q 'xpf_cluster_build_report' \
	&& fail "control: cmd_deploy must NOT contain the boundary report -- if this \
matches, the search above is matching something other than the call site"
ok "the deploy path's re-baseline call site is wired (with a negative control)"

echo "ALL $PASS CASES PASS"
