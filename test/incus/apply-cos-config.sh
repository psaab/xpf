#!/usr/bin/env bash
#
# Re-apply a CoS iperf test config to a cluster VM after a deploy
# that wiped it. Usage:
#
#   ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
#   ./test/incus/apply-cos-config.sh --symmetric loss:xpf-userspace-fw0
#   ./test/incus/apply-cos-config.sh                     # defaults to xpf-userspace-fw0
#
# Only the RG0 primary needs the config applied — it replicates to the
# secondary via config sync. Run against the primary.
#
# Atomic design (round-3 finding #3 HIGH):
#
# Earlier revisions ran the destructive `delete class-of-service` etc.
# in a SEPARATE commit transaction from the reapply `set` lines. If the
# second commit failed (syntax drift, validation error, daemon unhappy)
# the cluster was left in a post-delete "no-CoS" state with no rollback,
# which silently contaminated the subsequent capture cells.
#
# The fix: merge deletes and sets into ONE candidate config, run
# `commit check` first, and only if check passes do we `commit`. Either
# ALL changes apply (delete + set atomic) or NONE apply (candidate
# discarded on `rollback`, live config unchanged). Post-commit we run
# `show class-of-service interface` and verify that shaper output is
# present; if verification fails we fall back to `rollback 1 | commit`
# which restores the previous good config.
#
set -euo pipefail

# #929: --same-class selects the same-class iperf-b fixture
# (cos-iperf-same-class.set), which adds term 4 mapping
# destination-port 7 → iperf-b. #1250: --symmetric selects
# cos-iperf-symmetric.set, which also shapes reverse iperf3 -R
# traffic on ge-0-0-1 using source-port terms. Flags must be
# parsed BEFORE the positional TARGET argument so they are not
# silently treated as hostnames.
SAME_CLASS=0
SYMMETRIC=0
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --same-class) SAME_CLASS=1; shift ;;
        --symmetric) SYMMETRIC=1; shift ;;
        --) shift; break ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

if [[ "$SAME_CLASS" -eq 1 && "$SYMMETRIC" -eq 1 ]]; then
	echo "error: --same-class and --symmetric select different fixtures; use one at a time" >&2
	exit 2
fi

TARGET="${1:-loss:xpf-userspace-fw0}"
# Copilot D.2: shift past TARGET and reject extra positional
# arguments so a typo or duplicated argument fails loudly
# instead of being silently ignored.
[[ $# -le 1 ]] || {
    shift
    echo "unexpected extra arguments: $*" >&2
    exit 2
}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$SAME_CLASS" -eq 1 ]]; then
    CONFIG_FILE="${SCRIPT_DIR}/cos-iperf-same-class.set"
elif [[ "$SYMMETRIC" -eq 1 ]]; then
    CONFIG_FILE="${SCRIPT_DIR}/cos-iperf-symmetric.set"
else
    CONFIG_FILE="${SCRIPT_DIR}/cos-iperf-config.set"
fi
REMOTE_SETS="/tmp/cos-iperf-sets.set"

if [[ ! -f "$CONFIG_FILE" ]]; then
	echo "error: cannot find $CONFIG_FILE" >&2
	exit 1
fi

# Strip `delete` / blank / comment lines from the fixture: we inject
# our own curated delete list (below) so the candidate config is
# idempotent against both fresh-post-deploy and already-applied states.
SETS_TMP="$(mktemp)"
trap "rm -f '$SETS_TMP'" EXIT
grep -E '^set ' "$CONFIG_FILE" > "$SETS_TMP"

incus file push --mode 0644 "$SETS_TMP" "${TARGET}/${REMOTE_SETS}" >/dev/null

# Deletes that may or may not exist depending on whether this is a
# fresh apply or a re-apply. Swallowed individually inside the single
# candidate session so "nothing to delete" is not a hard error, while
# a true commit failure still aborts the session.
#
# The `|| true` after each `delete` is bash-side — it suppresses the
# NON-zero exit heredocs leak when the CLI warns, not the commit itself.
# Because this whole block runs inside ONE `configure ... commit`
# session, the commit is still atomic: if `commit` fails, the
# candidate is discarded intact.
#
# IMPORTANT: this script speaks the Junos-style local CLI. `commit
# check` validates the candidate before apply; we invoke it first so a
# syntactically-bad candidate is caught before anything live changes.

# ---- Phase 1: commit check (dry-run validate) ----
CHECK_OUT=$(mktemp)
trap "rm -f '$SETS_TMP' '$CHECK_OUT'" EXIT
if ! incus exec "$TARGET" -- /usr/local/sbin/cli > "$CHECK_OUT" 2>&1 <<EOF
configure
delete class-of-service
delete firewall family inet filter bandwidth-output
delete interfaces reth0 unit 80 family inet filter output
delete firewall family inet6 filter bandwidth-output
delete interfaces reth0 unit 80 family inet6 filter output
delete firewall family inet filter bandwidth-output-reverse
delete interfaces ge-0-0-1 unit 0 family inet filter output
delete firewall family inet6 filter bandwidth-output-reverse
delete interfaces ge-0-0-1 unit 0 family inet6 filter output
load merge ${REMOTE_SETS}
commit check
exit
quit
EOF
then
	echo "error: commit check failed on $TARGET (candidate config is invalid)" >&2
	echo "---- cli output ----" >&2
	cat "$CHECK_OUT" >&2
	echo "---- end cli output ----" >&2
	echo "no live state changed (commit check runs on the candidate only)" >&2
	exit 4
fi

# ---- Phase 2: atomic commit ----
# Delete + set are in ONE transaction. If `commit` fails, the
# candidate config is discarded and live state is unchanged —
# specifically the destructive deletes are NOT committed without the
# compensating sets.
APPLY_OUT=$(mktemp)
trap "rm -f '$SETS_TMP' '$CHECK_OUT' '$APPLY_OUT'" EXIT
if ! incus exec "$TARGET" -- /usr/local/sbin/cli > "$APPLY_OUT" 2>&1 <<EOF
configure
delete class-of-service
delete firewall family inet filter bandwidth-output
delete interfaces reth0 unit 80 family inet filter output
delete firewall family inet6 filter bandwidth-output
delete interfaces reth0 unit 80 family inet6 filter output
delete firewall family inet filter bandwidth-output-reverse
delete interfaces ge-0-0-1 unit 0 family inet filter output
delete firewall family inet6 filter bandwidth-output-reverse
delete interfaces ge-0-0-1 unit 0 family inet6 filter output
load merge ${REMOTE_SETS}
commit
exit
quit
EOF
then
	echo "error: commit failed on $TARGET AFTER commit-check passed" >&2
	echo "---- cli output ----" >&2
	cat "$APPLY_OUT" >&2
	echo "---- end cli output ----" >&2
	# commit-check passed but commit itself failed: this is rare
	# (usually a transient daemon / commit-hook issue). The candidate
	# is already discarded by the failed commit, so live state is
	# the pre-apply state. For extra safety try `rollback 1 | commit`
	# to roll forward onto the last good committed config — if the
	# pre-apply state itself was wedged, this will repair it.
	echo "attempting rollback 1 | commit to restore last-good state..." >&2
	incus exec "$TARGET" -- /usr/local/sbin/cli <<'EOF' >&2 || true
configure
rollback 1
commit
exit
quit
EOF
	exit 5
fi

# ---- Phase 3: post-commit verification ----
# The atomic commit succeeded per the CLI. Now verify CoS is actually
# live via `show class-of-service interface`: we expect at least one
# interface block to show up (reth0 / reth0.80) with a shaper output
# setting. If the output is empty, the commit "succeeded" but CoS is
# not runtime-live — roll back to the previous good state.
VERIFY_OUT=$(mktemp)
trap "rm -f '$SETS_TMP' '$CHECK_OUT' '$APPLY_OUT' '$VERIFY_OUT'" EXIT
incus exec "$TARGET" -- /usr/local/sbin/cli -c "show class-of-service interface" \
	> "$VERIFY_OUT" 2>&1 || true
cat "$VERIFY_OUT"

# Look for ANY shaper/scheduler signal. If the show output does not
# mention a shaper/scheduler/output-traffic-control-profile, CoS is
# not effectively applied and we must roll back.
if ! grep -iqE 'shaper|scheduler|traffic-control-profile|output.*traffic' "$VERIFY_OUT"; then
	echo "error: post-commit verification FAILED — 'show class-of-service interface' output shows no shaper/scheduler binding" >&2
	echo "rolling forward with 'rollback 1 | commit' to restore the last good state..." >&2
	ROLLBACK_OUT=$(mktemp)
	trap "rm -f '$SETS_TMP' '$CHECK_OUT' '$APPLY_OUT' '$VERIFY_OUT' '$ROLLBACK_OUT'" EXIT
	if incus exec "$TARGET" -- /usr/local/sbin/cli > "$ROLLBACK_OUT" 2>&1 <<'EOF'
configure
rollback 1
commit
exit
quit
EOF
	then
		echo "rollback 1 committed — live state reverted" >&2
	else
		echo "WARN: rollback commit also failed — MANUAL INTERVENTION REQUIRED" >&2
		cat "$ROLLBACK_OUT" >&2
	fi
	exit 6
fi

echo "apply-cos-config: atomic commit + verification OK"
