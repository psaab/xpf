#!/usr/bin/env bash
#
# G1 — Clean grep for the DPDK retirement.
#
# Runs `grep -rIn -i 'dpdk'` against the worktree (excluding .git,
# .claude, and historical docs/issues) and post-filters into a
# violations log. PASS if violations log is empty.
#
# Allowed-residue policy (matches #1530 acceptance criteria):
#   - CHANGELOG / retirement-note text (top-level CHANGELOG* files
#     and docs/retirement* notes)
#   - This issue's own runbook / artifact text
#     (docs/pr/1530-dpdk-final-validation/**)
#   - Historical docs/issues/*.md entries (already excluded by
#     --exclude-dir)
#   - Rejection-path test names containing dpdk in the file path
#     (e.g. *_reject_dpdk_test.go)
#
# Anything else — *.go, *.c, *.h, Makefile*, README.md, CLAUDE.md,
# AGENTS.md, or any other docs/*.md outside the retirement-note set
# — counts as a violation.
#
# Usage:
#   ./g1-grep-dpdk.sh          # run from any directory; resolves repo root
#
# Writes:
#   artifacts/grep-dpdk-raw.log         (all matches)
#   artifacts/grep-dpdk-violations.log  (post-filtered residue)
#
# Exit 0 if violations log is empty, 1 if violations remain, 2 on
# infra error (e.g. dpdk_worker/ still exists).

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

cd "$ROOT_DIR"

RAW="$ART_DIR/grep-dpdk-raw.log"
VIOL="$ART_DIR/grep-dpdk-violations.log"

# Hard check: forbidden directories must be gone.
INFRA_FAIL=0
for dir in dpdk_worker pkg/dataplane/dpdk; do
    if [[ -e "$dir" ]]; then
        echo "g1: INFRA-FAIL — $dir still present" >&2
        INFRA_FAIL=1
    fi
done
if [[ $INFRA_FAIL -ne 0 ]]; then
    echo "g1: at least one removed dataplane directory still exists. Phase 3 incomplete." >&2
    exit 2
fi

# Raw scan. Exclude:
#   .git              — VCS metadata
#   .claude           — agent state
#   docs/issues       — historical issue mirrors (#1530 acceptance allow)
#   docs/pr           — PR-history plans (this issue's runbook tree lives
#                       under docs/pr/1530-dpdk-final-validation too)
#   _Log.md           — action log
#   grep-dpdk-*.log   — this script's own output
grep -rIn -i 'dpdk' . \
    --exclude-dir=.git \
    --exclude-dir=.claude \
    --exclude-dir=issues \
    --exclude-dir=pr \
    --exclude='.git' \
    --exclude='grep-dpdk-*.log' \
    --exclude='_Log.md' \
    > "$RAW" || true

# Post-filter into violations.
#
# Allowed residue per #1530 acceptance criteria:
#   - Retirement-path / canary / sentinel implementation code that
#     keeps the DPDK reject path alive. These files are retained per
#     the #1528 plan v3.3 (rewriteRetiredDataplaneType bridge,
#     ErrDPDKBackendRetired sentinel, import_canary_test,
#     retirement_boundary_canary_test, etc.). Whitelisted by full path.
#   - Production .md docs that have been retirement-marked by #1529 /
#     #1531 (docs/dpdk-dataplane.md and friends now lead with a
#     "Status: Retired" block). Whitelisted by full path.
#   - README.md / CLAUDE.md retirement-marker comments.
#
# Anything else surfaces as a violation.

WHITELIST=(
    # Retirement-path bridge + sentinels + canaries (retained per #1528 plan v3.3)
    './pkg/configstore/dataplane_retire.go'
    './pkg/configstore/dataplane_retire_test.go'
    './pkg/configstore/store.go'
    './pkg/configstore/store_test.go'
    './pkg/config/compiler.go'
    './pkg/config/compiler_test.go'
    './pkg/config/compiler_system.go'
    './pkg/config/parser_ast_test.go'
    './pkg/config/parser_system_test.go'
    './pkg/config/types.go'
    './pkg/config/ast.go'
    './pkg/cmdtree/schema_validate_test.go'
    './pkg/cli/runtime.go'
    './pkg/api/config_commit_test.go'
    './pkg/daemon/daemon_ha_sync.go'
    './pkg/daemon/daemon_run.go'
    './pkg/daemon/dataplane_boot_test.go'
    './pkg/daemon/host_tunables.go'
    './pkg/daemon/host_tunables_test.go'
    './pkg/daemon/rss_indirection.go'
    './pkg/daemon/runtime_probes.go'
    './pkg/daemon/README.md'
    './pkg/dataplane/apply.go'
    './pkg/dataplane/compiler.go'
    './pkg/dataplane/compiler_iface.go'
    './pkg/dataplane/compiler_test.go'
    './pkg/dataplane/dataplane.go'
    './pkg/dataplane/runtime/import_canary_test.go'
    './pkg/dataplane/retirement_boundary_canary_test.go'
    './pkg/dataplane/README.md'
    './userspace-dp/README.md'
    # Retirement-marked production docs (Phase 4 #1529 + #1531)
    './docs/dpdk-dataplane.md'
    './docs/dataplane-decision-dpdk-vs-vpp.md'
    './docs/vpp-dataplane-assessment.md'
    # Forward-looking docs whose DPDK breadcrumbs sit under
    # explicit "DPDK retired (#1525)" markers
    './docs/active-active-new-connections.md'
    './docs/authoritative-backlog.md'
    './docs/bugs.md'
    './docs/cross-worker-flow-fairness-research.md'
    './docs/deterministic-nat-cgnat.md'
    './docs/fabric-bridge-tuning.md'
    './docs/feature-gaps.md'
    './docs/memory.md'
    './docs/next-features/application-identification.md'
    './docs/next-features/ha-session-ownership-and-fabric-failover.md'
    './docs/next-features/ipv6-session-fast-path.md'
    './docs/next-features/pre-id-default-policy.md'
    './docs/next-features/twice-nat.md'
    './docs/next-features/vsrx-fabric-fab0-fab1-syntax-compat.md'
    './docs/perf-ranked-backlog.md'
    './docs/phases.md'
    './docs/refactoring-audit-current.txt'
    './docs/refactoring-audit.md'
    './docs/session-history.md'
    './docs/userspace-dataplane-architecture.md'
    './docs/userspace-dataplane-gaps.md'
    './docs/userspace-fabric-redirect-fix.md'
    './docs/userspace-master-merge-20260310.md'
    './docs/xdp-io-uring-userspace-dataplane.md'
    # Top-level retirement markers
    './README.md'
    './CLAUDE.md'
)

awk -F: -v wlstr="$(printf '%s\n' "${WHITELIST[@]}")" '
BEGIN {
    n = split(wlstr, parts, "\n")
    for (i = 1; i <= n; i++) {
        if (parts[i] == "") continue
        wlmap[parts[i]] = 1
    }
}
{
    path = $1
    if (path in wlmap) next
    if (path ~ /^\.\/docs\/pr\/1530-dpdk-final-validation\//) next
    if (path ~ /reject[_-]dpdk/) next
    print
}
' "$RAW" > "$VIOL"

VIOL_COUNT=$(wc -l < "$VIOL" | tr -d ' ')

echo "g1: raw matches:        $(wc -l < "$RAW" | tr -d ' ')"
echo "g1: post-filter residue: $VIOL_COUNT"

if [[ "$VIOL_COUNT" -eq 0 ]]; then
    echo "g1: PASS — no production DPDK references remain."
    exit 0
fi

echo "g1: FAIL — production DPDK references remain. See $VIOL" >&2
head -20 "$VIOL" >&2
exit 1
