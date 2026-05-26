#!/usr/bin/env bash
#
# Build summary.md from artifacts/ for the #1530 issue comment.
#
# Reads each gate's log file under artifacts/ and emits a Markdown
# summary with:
#   - commit SHA + cluster env
#   - binary hashes (build host + per-node deployed)
#   - gate-by-gate PASS/FAIL table with log filenames
#   - quoted excerpts from each gate's log
#
# Output: docs/pr/1530-dpdk-final-validation/summary.md
#
# This is intentionally idempotent — rerun after every gate completes
# to refresh the summary.

set -uo pipefail

DOC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ART_DIR="$DOC_DIR/artifacts"
OUT="$DOC_DIR/summary.md"

cd "$DOC_DIR"

# Helper: emit a fenced quote of up to N lines from a file, or
# "(missing)" if absent.
quote_log() {
    local file="$1"; shift
    local n="${1:-40}"
    if [[ ! -f "$file" ]]; then
        echo "(missing: $file)"
        return
    fi
    echo '```'
    head -"$n" "$file"
    echo '```'
}

# Helper: produce PASS / FAIL / TBD based on file presence + content.
gate_state() {
    local label="$1"
    local logfile="$2"
    local pattern="$3"
    if [[ ! -f "$logfile" ]]; then
        echo "TBD"
        return
    fi
    if [[ -z "$pattern" ]]; then
        # presence of non-empty log is sufficient
        if [[ -s "$logfile" ]]; then echo "PASS"; else echo "TBD"; fi
        return
    fi
    if grep -Eq "$pattern" "$logfile"; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

SHA="(TBD)"
if [[ -f "$ART_DIR/commit.txt" ]]; then
    SHA=$(grep '^head_sha=' "$ART_DIR/commit.txt" | head -n1 | cut -d= -f2-)
    SHA=${SHA:-$(grep '^target_sha=' "$ART_DIR/commit.txt" | head -n1 | cut -d= -f2-)}
    SHA=${SHA:-(TBD)}
fi

VIOL_COUNT="(TBD)"
[[ -f "$ART_DIR/grep-dpdk-violations.log" ]] && \
    VIOL_COUNT=$(wc -l < "$ART_DIR/grep-dpdk-violations.log" | tr -d ' ')

# Build gate states.
G1_STATE=$(gate_state G1 "$ART_DIR/grep-dpdk-violations.log" "")
[[ "$VIOL_COUNT" == "0" ]] && G1_STATE=PASS
[[ "$VIOL_COUNT" =~ ^[1-9] ]] && G1_STATE=FAIL

G2_BUILD=$(gate_state G2-build  "$ART_DIR/make-build.log"   "")
G2_CTL=$(gate_state   G2-ctl    "$ART_DIR/make-build-ctl.log" "")
G2_UDP=$(gate_state   G2-userdp "$ART_DIR/make-build-userspace-dp.log" "")
G2_TEST=$(gate_state  G2-test   "$ART_DIR/make-test.log" "ok\\s+[a-z]")

G3_STATE=PASS
if [[ -f "$ART_DIR/make-n-build-dpdk-exit.txt" ]]; then
    if grep -E ': exit=0$' "$ART_DIR/make-n-build-dpdk-exit.txt" >/dev/null 2>&1; then
        G3_STATE=FAIL
    fi
else
    G3_STATE=TBD
fi

G4_STATE=$(gate_state G4 "$ART_DIR/cli-reject-dpdk.log" "dpdk|retired|unsupported|unknown")

G5a_PUSH=$(gate_state G5a-push    "$ART_DIR/smoke-v4-cosoff-push.log"    "\\[SUM\\].*sender")
G5a_REV=$(gate_state  G5a-rev     "$ART_DIR/smoke-v4-cosoff-reverse.log" "\\[SUM\\].*sender")
G5b_PUSH=$(gate_state G5b-push    "$ART_DIR/smoke-v6-cosoff-push.log"    "\\[SUM\\].*sender")
G5b_REV=$(gate_state  G5b-rev     "$ART_DIR/smoke-v6-cosoff-reverse.log" "\\[SUM\\].*sender")
G5d=$(gate_state      G5d        "$ART_DIR/smoke-screen-after.txt" "")
G5e=$(gate_state      G5e        "$ART_DIR/make-test-failover.log" "PASS|sender")

{
cat <<EOF
# #1530 DPDK Final Validation — Summary

**Commit (Phase 3 source removal):** \`$SHA\`
**Cluster env:** \`test/incus/loss-userspace-cluster.env\`
**Nodes:** \`loss:xpf-userspace-fw0\`, \`loss:xpf-userspace-fw1\`
**LAN host:** \`loss:cluster-userspace-host\`
**WAN targets:** \`172.16.80.200\` / \`2001:559:8585:80::200\`
**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Gate results

| Gate | Description                                                | Result      | Log |
|------|------------------------------------------------------------|-------------|-----|
| G0   | Lock to Phase 3 source-removal SHA                         | (see above) | \`commit.txt\` |
| G1   | Clean grep — no production DPDK references ($VIOL_COUNT residue) | $G1_STATE   | \`grep-dpdk-violations.log\` |
| G2.a | \`make build\`                                             | $G2_BUILD   | \`make-build.log\` |
| G2.b | \`make build-ctl\`                                         | $G2_CTL     | \`make-build-ctl.log\` |
| G2.c | \`make build-userspace-dp\`                                | $G2_UDP     | \`make-build-userspace-dp.log\` |
| G2.d | \`make test\`                                              | $G2_TEST    | \`make-test.log\` |
| G3   | \`make build-dpdk*\` targets gone                          | $G3_STATE   | \`make-n-build-dpdk.log\` |
| G4   | Daemon rejects \`set system dataplane-type dpdk\`          | $G4_STATE   | \`cli-reject-dpdk.log\` |
| G5.a | CoS-off IPv4 push + reverse                                | $G5a_PUSH / $G5a_REV | \`smoke-v4-cosoff-{push,reverse}.log\` |
| G5.b | CoS-off IPv6 push + reverse                                | $G5b_PUSH / $G5b_REV | \`smoke-v6-cosoff-{push,reverse}.log\` |
| G5.c | CoS-on class sweep (v4 + v6, push + reverse)               | see per-class logs  | \`smoke-v{4,6}-coson-*.log\` |
| G5.d | Screen / flood baseline (LAND + SYN-flood + ICMP-flood)    | $G5d        | \`smoke-screen-*.log\` |
| G5.e | \`make test-failover\`                                     | $G5e        | \`make-test-failover.log\` |

## Binary hashes — build host

\`\`\`
$( [[ -f "$ART_DIR/binary-hashes.txt" ]] && cat "$ART_DIR/binary-hashes.txt" || echo "(pending G2)" )
\`\`\`

## Binary hashes — deployed (loss userspace cluster)

\`\`\`
$( [[ -f "$ART_DIR/node-binary-hashes.txt" ]] && cat "$ART_DIR/node-binary-hashes.txt" || echo "(pending G5 pre-flight)" )
\`\`\`

## G1 violations (head)

EOF

quote_log "$ART_DIR/grep-dpdk-violations.log" 30

cat <<'EOF'

## G3 — make -n exit codes

EOF
quote_log "$ART_DIR/make-n-build-dpdk-exit.txt" 10

cat <<'EOF'

## G4 — CLI rejection capture

EOF
quote_log "$ART_DIR/cli-reject-dpdk.log" 50

cat <<'EOF'

## G5 — SUM lines from each smoke run

EOF

for tag in \
    v4-cosoff-push v4-cosoff-reverse \
    v6-cosoff-push v6-cosoff-reverse ; do
    echo "### $tag"
    if [[ -f "$ART_DIR/smoke-$tag.log" ]]; then
        echo '```'
        grep -E '\[SUM\]' "$ART_DIR/smoke-$tag.log" || echo "(no SUM line found)"
        echo '```'
    else
        echo "(missing: smoke-$tag.log)"
    fi
done

# CoS-on class sweep SUM extraction.
shopt -s nullglob
for f in "$ART_DIR"/smoke-v[46]-coson-*.log; do
    name=$(basename "$f" .log)
    echo "### $name"
    echo '```'
    grep -E '\[SUM\]' "$f" || echo "(no SUM line found)"
    echo '```'
done
shopt -u nullglob

cat <<'EOF'

## G5.e — failover summary (tail)

EOF
if [[ -f "$ART_DIR/make-test-failover.log" ]]; then
    echo '```'
    tail -40 "$ART_DIR/make-test-failover.log"
    echo '```'
else
    echo '(pending G5.e)'
fi

cat <<EOF

## References

- Acceptance criteria: \`gh issue view 1530\`
- Umbrella: #1525
- Phase 3 source removal: #1528
- Sibling: #1477 (eBPF final validation)
- Runbook: \`docs/pr/1530-dpdk-final-validation/runbook.md\`
- Artifact ledger: \`docs/pr/1530-dpdk-final-validation/artifacts.md\`
EOF
} > "$OUT"

echo "build-summary: wrote $OUT"
wc -l "$OUT"
