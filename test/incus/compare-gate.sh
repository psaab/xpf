#!/usr/bin/env bash
# Compare a PR throughput window against its fresh baseline and control
# cells and emit exactly one ledger row for the judged window.
#
#   compare-gate.sh <pr_root> <pr_deb> <pr_deb_version> <pr_source_sha> \
#       <pr_runtime_version> <baseline_out> <pr_out> <control_out> <out>
#
# The PR identity evidence (<pr_out>/deployed-identity.txt) is validated
# BEFORE any verdict is computed or printed, and before any ledger shard
# is emitted (#18977). Identity records are selected by their ^node0= /
# ^node1= line prefix (never by position: the producer file may carry
# unrelated header lines), there must be exactly one record per node,
# and every record must carry running_sha, helper_sha, deb_version and
# source_sha. Both nodes' running/helper SHAs must equal the pinned
# deb's staged manifest SHAs (deploy_manifest_sha_from_deb), so the
# --exe-check/--helper-exe-check MATCH attestation written to the ledger
# is earned by comparison here, never asserted unconditionally.
#
# On any missing, unparsable or mismatched identity evidence this script
# fails non-zero BEFORE a verdict exists: nothing matching `verdict=`
# reaches stdout and no ledger shard is written. A window whose identity
# cannot be attested is not judged at all.
set -euo pipefail
PR_ROOT=${1:?PR worktree required}
PR_DEB=${2:?PR deb required}
PR_DEB_VERSION=${3:?PR deb version required}
PR_SHA=${4:?PR source SHA required}
PR_RUNTIME_VERSION=${5:?PR runtime VERSION required}
BASELINE_OUT=${6:?fresh baseline artifacts required}
PR_OUT=${7:?PR artifacts required}
CONTROL_OUT=${8:?fresh control artifacts required}
OUT=${9:?comparison artifacts required}
mkdir -p "$OUT"
GATE_ID=${XPF_GATE_ID:-pr18900-loss-throughput}

export BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
source "$PR_ROOT/test/incus/cluster-env.sh"
source "$PR_ROOT/test/incus/deploy-lib.sh"
source "$PR_ROOT/test/incus/harness-result.sh"

# ── Identity first ────────────────────────────────────────────────────
# Gather the PR identity captured during its own locked cell. The node
# is now on master after the follow-up control, so never query runtime
# binaries here. Every failure below exits before the verdict section
# runs, so no `verdict=` line and no ledger shard can escape ahead of
# the attestation they would claim.
identity="$PR_OUT/deployed-identity.txt"
if [[ ! -s "$identity" ]]; then
	echo "missing PR deployed identity evidence: $identity" >&2
	exit 77
fi

# Parse into a checked variable: a failing parser must abort the gate,
# never dissolve into an empty array that set -u detonates later
# (#18977: `readarray < <(...)` masked exactly that failure).
parsed_identity=""
if ! parsed_identity=$(python3 -I - "$identity" <<'PY'
import pathlib, sys

required = ("running_sha", "helper_sha", "deb_version", "source_sha")
records = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    node = None
    if line.startswith("node0="):
        node = 0
    elif line.startswith("node1="):
        node = 1
    else:
        continue
    if node in records:
        raise SystemExit(f"duplicate identity record for node{node}")
    records[node] = dict(
        tok.split("=", 1) for tok in line.split() if "=" in tok
    )
for node in (0, 1):
    if node not in records:
        raise SystemExit(f"missing identity record for node{node}")
    for key in required:
        if not records[node].get(key):
            raise SystemExit(f"missing {key} in node{node} identity record")
for node in (0, 1):
    print("\t".join(records[node][k] for k in required))
PY
); then
	echo "unparsable PR deployed identity evidence: $identity" >&2
	exit 77
fi
mapfile -t ids <<<"$parsed_identity"
if [[ ${#ids[@]} -ne 2 ]]; then
	echo "PR deployed identity evidence must yield exactly two node records" >&2
	exit 77
fi
IFS=$'\t' read -r pr_run_sha0 pr_run_helper0 pr_running_version0 pr_runtime_sha0 <<<"${ids[0]}"
IFS=$'\t' read -r pr_run_sha1 pr_run_helper1 pr_running_version1 pr_runtime_sha1 <<<"${ids[1]}"

# The pinned deb is the ground truth for what should be running: both
# nodes' running and helper SHAs must equal the staged bytes inside it,
# not merely agree with each other (a pair of nodes running the same
# wrong build attests nothing).
if ! pr_xpfd_sha=$(deploy_manifest_sha_from_deb "$PR_DEB" xpfd); then
	echo "cannot read xpfd manifest SHA from pinned deb: $PR_DEB" >&2
	exit 77
fi
if ! pr_helper_sha=$(deploy_manifest_sha_from_deb "$PR_DEB" xpf-userspace-dp); then
	echo "cannot read xpf-userspace-dp manifest SHA from pinned deb: $PR_DEB" >&2
	exit 77
fi
if [[ "$pr_run_sha0" != "$pr_xpfd_sha" || "$pr_run_sha1" != "$pr_xpfd_sha" ||
	"$pr_run_helper0" != "$pr_helper_sha" || "$pr_run_helper1" != "$pr_helper_sha" ||
	"$pr_running_version0" != "$PR_DEB_VERSION" || "$pr_running_version1" != "$PR_DEB_VERSION" ||
	"$pr_runtime_sha0" != "$PR_SHA" || "$pr_runtime_sha1" != "$PR_SHA" ]]; then
	echo "PR identity evidence does not match the pinned deb" >&2
	exit 77
fi

# ── Verdict ───────────────────────────────────────────────────────────
# Only now, with the identity attested, may a verdict be computed,
# printed, or written to the ledger.
if python3 -I - "$BASELINE_OUT" "$PR_OUT" "$CONTROL_OUT" "$OUT/gate-decision.txt" <<'PY'
import csv,pathlib,statistics,sys
baseline,pr,control,out=map(pathlib.Path,sys.argv[1:])
issues=[]
voids=[]
expected={*(f'single-v{v}-{direction}' for v in (4,6) for direction in ('push','reverse')),
          *(f'multi-v{v}-r{i}' for v in (4,6) for i in range(1,6))}
def failures(path):
    return {line.strip()[5:] for line in path.read_text(errors='replace').splitlines() if line.lstrip().startswith('FAIL ')}
def read_summary(cell,name):
    path=cell/'throughput'/'summary.tsv'
    if not path.is_file():
        voids.append(f'{name}: missing {path}')
        return {}
    try:
        rows=list(csv.DictReader(path.open(),delimiter='\t'))
        d={r['cell']:r for r in rows}
        missing=expected-d.keys()
        if missing:
            voids.append(f'{name}: missing iperf cells {sorted(missing)}')
        for n in expected & d.keys():
            r=d[n]
            if int(r['command_rc'])!=0 or int(r['receiver_bps'])<=0 or int(r['receiver_bytes'])<=0:
                voids.append(f'{name}: invalid/no-flow {n} rc={r["command_rc"]} receiver_bps={r["receiver_bps"]} bytes={r["receiver_bytes"]}')
        return d
    except Exception as e:
        voids.append(f'{name}: cannot parse {path}: {e}')
        return {}

def rc_file(cell,path):
    p=cell/path
    if not p.is_file():
        voids.append(f'missing result record {p}')
        return None
    try:
        return int(p.read_text().strip().split('=',1)[1])
    except Exception as e:
        voids.append(f'invalid result record {p}: {e}')
        return None

b=read_summary(baseline,'baseline')
p=read_summary(pr,'PR')
c=read_summary(control,'fresh master control')
master_conn=baseline/'connectivity'/'connectivity.log'
pr_conn=pr/'connectivity'/'connectivity.log'
control_conn=control/'connectivity'/'connectivity.log'
for f in (master_conn,pr_conn,control_conn):
    if not f.is_file(): voids.append(f'missing connectivity record {f}')
if not voids:
    bf,pf,cf=map(failures,(master_conn,pr_conn,control_conn))
    if pf-bf: issues.append(f'connectivity failures worsened vs baseline: {sorted(pf-bf)}')
    if cf-bf: issues.append(f'fresh control has new connectivity failures vs baseline: {sorted(cf-bf)}')
    pcmp=pr/'connectivity-comparison.txt'
    if pcmp.is_file() and 'verdict=PASS' not in pcmp.read_text():
        issues.append('PR cell connectivity comparison was not PASS')

# A complete measured set is a precondition; an absent/invalid sample is VOID,
# not a passing zero and not a product regression.
if not voids:
    for cell in (baseline,pr):
        if rc_file(cell,'throughput-result.txt')!=0:
            voids.append(f'{cell.name}: throughput runner did not complete successfully')
    if rc_file(control,'throughput-result.txt')!=0:
        voids.append('fresh master control throughput runner did not complete successfully')
    if rc_file(pr,'post-health-result.txt')!=0:
        issues.append('post-throughput PR forwarding health failed')
    if rc_file(baseline,'post-health-result.txt')!=0:
        voids.append('baseline post-throughput forwarding health did not pass')

lines=[]
if not voids:
    lines.extend((f'connectivity_baseline_failures={sorted(bf)}',f'connectivity_pr_failures={sorted(pf)}',
                  f'connectivity_control_failures={sorted(cf)}'))
    for name in sorted(n for n in expected if n.startswith('single-')):
        base_retr=int(b[name]['retransmits']); pr_retr=int(p[name]['retransmits'])
        lines.append(f'{name}: baseline_retransmits={base_retr} pr_retransmits={pr_retr} fresh_control_retransmits={int(c[name]["retransmits"])}')
        if pr_retr>base_retr:
            issues.append(f'{name}: PR retransmits {pr_retr} exceed master baseline {base_retr}')
    for v in (4,6):
        names=[f'multi-v{v}-r{i}' for i in range(1,6)]
        bm=[int(b[n]['receiver_bps']) for n in names]
        pm=[int(p[n]['receiver_bps']) for n in names]
        cm=[int(c[n]['receiver_bps']) for n in names]
        bmed,pmed,cmed=map(int,(statistics.median(bm),statistics.median(pm),statistics.median(cm)))
        prr=sum(int(p[n]['retransmits']) for n in names)
        crr=sum(int(c[n]['retransmits']) for n in names)
        pct=100*pmed/bmed
        lines.append(f'multi-v{v}: baseline_receiver_median_bps={bmed} pr_receiver_median_bps={pmed} pr_percent_of_baseline={pct:.2f} fresh_control_receiver_median_bps={cmed} pr_retransmit_sum={prr} fresh_control_retransmit_sum={crr}')
        # Only the below-baseline side blocks. Higher PR throughput is not a failure.
        if pmed*100 < bmed*90:
            issues.append(f'multi-v{v}: PR median {pmed} is more than 10% below baseline {bmed}')
        if prr>crr:
            issues.append(f'multi-v{v}: PR retransmit sum {prr} exceeds fresh master control {crr}')
lines.extend(f'VOID: {e}' for e in voids)
lines.extend(f'FAIL: {e}' for e in issues)
verdict='VOID' if voids else ('FAIL' if issues else 'PASS')
lines.append(f'verdict={verdict}')
out.write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
PY
then compare_rc=0; else compare_rc=$?; fi

if [[ "$compare_rc" -eq 0 ]]; then
	case "$(python3 -I -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text().splitlines()[-1].split("=",1)[1])' "$OUT/gate-decision.txt")" in
	PASS) verdict=PASS; void_reason= ;; FAIL) verdict=FAIL; void_reason= ;; VOID) verdict=VOID; void_reason='one or more required measurement/control records were absent or invalid';; esac
else
	verdict=VOID
	void_reason='comparison failed before a complete decision could be made'
fi
if [[ "$verdict" == VOID ]]; then
	harness_result_emit --gate "$GATE_ID" --env loss-userspace-cluster \
		--verdict VOID --void-reason "$void_reason" --build-git-sha "$PR_SHA" \
		--build-exe-sha256 "$pr_xpfd_sha" --running-exe-sha256 "$pr_run_sha0" \
		--running-exe-sha256-peer "$pr_run_sha1" --exe-check MATCH \
		--build-helper-exe-sha256 "$pr_helper_sha" --running-helper-exe-sha256 "$pr_run_helper0" \
		--running-helper-exe-sha256-peer "$pr_run_helper1" --helper-exe-check MATCH \
		--helper-exe-scope cluster --duration-s 120 --artifacts "$OUT" \
		--measurement-scope cluster --deb-version "$PR_DEB_VERSION" --node "$FW0" --node-peer "$FW1"
else
	metrics=$(python3 -I - "$BASELINE_OUT/throughput/summary.tsv" "$PR_OUT/throughput/summary.tsv" "$CONTROL_OUT/throughput/summary.tsv" <<'PY'
import csv,statistics,sys
read=lambda p:{r['cell']:r for r in csv.DictReader(open(p),delimiter='\t')}
b,p,c=map(read,sys.argv[1:])
items=[]
for v in (4,6):
 ns=[f'multi-v{v}-r{i}' for i in range(1,6)]
 items.extend(((f'multi_v{v}_baseline_receiver_median_bps',int(statistics.median(int(b[n]['receiver_bps']) for n in ns))),
               (f'multi_v{v}_pr_receiver_median_bps',int(statistics.median(int(p[n]['receiver_bps']) for n in ns))),
               (f'multi_v{v}_control_receiver_median_bps',int(statistics.median(int(c[n]['receiver_bps']) for n in ns))),
               (f'multi_v{v}_pr_retransmits',sum(int(p[n]['retransmits']) for n in ns)),
               (f'multi_v{v}_control_retransmits',sum(int(c[n]['retransmits']) for n in ns))))
print(' '.join(f'{k}={v}' for k,v in items))
PY
)
	harness_result_emit --gate "$GATE_ID" --env loss-userspace-cluster \
		--verdict "$verdict" --headline-metric multi_v4_pr_receiver_median_bps \
		--headline-direction higher-better --metrics "$metrics" \
		--build-git-sha "$PR_SHA" --build-exe-sha256 "$pr_xpfd_sha" \
		--running-exe-sha256 "$pr_run_sha0" --running-exe-sha256-peer "$pr_run_sha1" \
		--exe-check MATCH --build-helper-exe-sha256 "$pr_helper_sha" \
		--running-helper-exe-sha256 "$pr_run_helper0" --running-helper-exe-sha256-peer "$pr_run_helper1" \
		--helper-exe-check MATCH --helper-exe-scope cluster --duration-s 120 \
		--artifacts "$OUT" --measurement-scope cluster --deb-version "$PR_DEB_VERSION" \
		--node "$FW0" --node-peer "$FW1"
fi
