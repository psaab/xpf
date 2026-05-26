# #1530 DPDK Final Validation — Runbook

Capstone validation artifact for umbrella **#1525** (Retire the DPDK
dataplane). Runs against the exact merge SHA of **#1528** (Phase 3 —
Mechanical source removal). This is the DPDK sibling of #1477 (eBPF
final validation).

This file is the Phase A draft. Phase B execution fills in
`artifacts.md` with quoted output and the issue comment is composed
from the gate outputs collected here.

## Status of dependencies (at draft time)

- #1525 umbrella OPEN
- #1526 Phase 1 (reject path) CLOSED
- #1527 Phase 2 (boot decouple) CLOSED
- #1528 Phase 3 (source removal) OPEN — capstone blocker
- #1529 Phase 4 (docs sweep) CLOSED
- #1531 Phase 1 docs predecessor CLOSED
- Sibling: #1477 eBPF final validation OPEN (separate runner)

Phase B starts when **#1528 PR** merges and the issue closes.

## Environment contract

- Loss userspace cluster only: `loss:xpf-userspace-fw0` and
  `loss:xpf-userspace-fw1`, via
  `test/incus/loss-userspace-cluster.env`.
- LAN host: `loss:cluster-userspace-host`.
- Cluster targets: `172.16.80.200` (IPv4) and
  `2001:559:8585:80::200` (IPv6).
- All `incus` commands go through `sg incus-admin -c "..."`.
- Coordinate cluster access with smoke-runner singleton
  `ab1c7bcf4d14b36b6` via SendMessage before any cluster operation.
- Sibling agent for #1477 may also need the cluster. Only one
  validation runs at a time.

## Phase B — exact command set per gate

Run from the worktree, in order. Save each command's stdout+stderr
into `docs/pr/1530-dpdk-final-validation/artifacts/<gate>.log`. Use
`tee` and `script(1)` where indicated so CLI/journal output is
preserved verbatim.

### One-shot driver

The entire matrix is wrapped by `scripts/run-all.sh`, which runs each
gate, regenerates `summary.md` after every step, and aborts on the
first failure (unless `STOP_ON_FAIL=0`). Use it once the smoke-runner
singleton grants cluster access:

```bash
./docs/pr/1530-dpdk-final-validation/scripts/run-all.sh
# or with explicit override
./docs/pr/1530-dpdk-final-validation/scripts/run-all.sh <phase3-merge-sha>
```

Individual gate scripts (described below) live under
`docs/pr/1530-dpdk-final-validation/scripts/` and can be invoked
directly if a single gate needs to be rerun:

| Gate     | Script                          |
|----------|---------------------------------|
| G0       | `g0-lock-commit.sh`             |
| G1       | `g1-grep-dpdk.sh`               |
| G2       | `g2-build-test.sh`              |
| G3       | `g3-make-dpdk-gone.sh`          |
| G4       | `g4-cli-reject-dpdk.sh`         |
| G5 prep  | `g5-cluster-deploy.sh`          |
| G5 prep  | `g5-capture-cos-map.sh`         |
| G5.a/b   | `g5-smoke-cos-off.sh`           |
| G5.c     | `g5-smoke-cos-on.sh`            |
| G5.d     | `g5-screen-baseline.sh`         |
| G5.e     | `g5-failover.sh`                |
| summary  | `build-summary.sh`              |

### G0: Lock to the source-removal commit

```bash
cd /home/ps/git/bpfrx/.claude/worktrees/1530-dpdk-final-validation
git fetch origin master
# PHASE-3-SHA = merge SHA of the #1528 PR on master. Captured into
# artifacts/commit.txt by Phase B step 0.
PHASE3_SHA=$(gh pr list --state merged --search "1528 in:title" \
  --json mergeCommit --jq '.[0].mergeCommit.oid')
echo "$PHASE3_SHA" | tee artifacts/commit.txt
git checkout "$PHASE3_SHA"
git rev-parse HEAD | tee -a artifacts/commit.txt
git log -1 --stat | tee artifacts/commit-show.txt
```

**Pass criteria**: `PHASE3_SHA` resolves to a real merge commit on
master and HEAD matches.

### G1: Clean grep — no `dpdk` references in production surfaces

```bash
grep -rIn -i 'dpdk' . \
  --exclude-dir=.git \
  --exclude-dir=docs/issues \
  --exclude-dir=.claude \
  | tee artifacts/grep-dpdk-raw.log
```

Then post-filter into `artifacts/grep-dpdk-violations.log`:

```bash
grep -rIn -i 'dpdk' . \
  --exclude-dir=.git \
  --exclude-dir=docs/issues \
  --exclude-dir=.claude \
  | grep -Ev '^(CHANGELOG|RETIREMENT|docs/retirement|docs/dpdk-retirement)' \
  | grep -Ev '\.md:' \
  | grep -Ev 'rejection|reject_dpdk|reject-dpdk' \
  | tee artifacts/grep-dpdk-violations.log
```

**Pass criteria**: `grep-dpdk-violations.log` is empty OR contains
only:

- CHANGELOG / retirement-note text
- Historical `docs/issues/*.md`
- This issue's runbook / artifact text
- Rejection-path test names (`*_reject_dpdk_test.go`,
  `reject-dpdk-*`)

No matches in `*.go`, `*.c`, `*.h`, `Makefile`, `Makefile.*`,
`README.md`, `CLAUDE.md`, `AGENTS.md`, or any `docs/*.md` outside
the retirement-note set.

If `dpdk_worker/` or `pkg/dataplane/dpdk/` directories still exist,
this gate **fails** regardless of grep results — they must be
deleted by #1528.

### G2: Clean build — Go daemon, CLI, userspace dataplane, tests

```bash
make build 2>&1 | tee artifacts/make-build.log
make build-ctl 2>&1 | tee artifacts/make-build-ctl.log
make build-userspace-dp 2>&1 | tee artifacts/make-build-userspace-dp.log
make test 2>&1 | tee artifacts/make-test.log
```

**Pass criteria** (all four):

- Exit 0
- `make test` reports all packages PASS (no FAIL, no panic, no
  build error)
- No DPDK cgo / linker errors
- Binaries `xpfd`, `cli`, `userspace-dp/target/release/xpf-userspace-dp`
  produced

Capture binary hashes:

```bash
sha256sum xpfd cli userspace-dp/target/release/xpf-userspace-dp \
  | tee artifacts/binary-hashes.txt
```

### G3: `make build-dpdk*` is gone

```bash
make -n build-dpdk 2>&1 | tee artifacts/make-n-build-dpdk.log
make -n build-dpdk-worker 2>&1 | tee -a artifacts/make-n-build-dpdk.log
make -n clean-dpdk 2>&1 | tee -a artifacts/make-n-build-dpdk.log
```

**Pass criteria**: each invocation prints
`make: *** No rule to make target '<target>'.  Stop.` and exits
non-zero. Capture exit codes:

```bash
for t in build-dpdk build-dpdk-worker clean-dpdk; do
  make -n "$t" >/dev/null 2>&1
  echo "$t: exit=$?"
done | tee artifacts/make-n-build-dpdk-exit.txt
```

All three exit codes must be non-zero.

### G4: Commit rejection — daemon refuses `set system dataplane-type dpdk`

The Phase 1 (#1526) hard rejection landed at config commit. After
Phase 3 the schema is gone, so the rejection may come from the
generic parser unknown-token path or the Phase 1 retirement message
if still wired. Either is acceptable.

```bash
# Pick FW0 for the CLI session (RG0 primary at the time of capture).
NODE=loss:xpf-userspace-fw0
script -q -c "sg incus-admin -c \"incus exec $NODE -- /usr/local/sbin/cli\"" \
  artifacts/cli-reject-dpdk.script <<'EOF'
configure private
set system dataplane-type dpdk
commit check
rollback
exit
EOF
```

Manual variant if `script` is awkward:

```bash
sg incus-admin -c "incus exec $NODE -- /usr/local/sbin/cli -c \
  'configure private; set system dataplane-type dpdk; commit check'" \
  2>&1 | tee artifacts/cli-reject-dpdk.log
```

**Pass criteria**:

- The `commit check` (or `commit`) command **fails** with a clear
  error message.
- Error mentions either "dpdk" / "retired" / "unsupported
  dataplane-type" / "unknown value 'dpdk'" — any explicit rejection
  is acceptable.
- The daemon does **not** accept the config (no successful commit).

### G5: HA smoke matrix on the exact commit

Pre-flight: build + deploy + readiness gate (from
`/failover-test` SKILL.md):

```bash
make build
cd userspace-dp && cargo build --release && cd ..
cp userspace-dp/target/release/xpf-userspace-dp .

ENV_FILE=test/incus/loss-userspace-cluster.env \
  sg incus-admin -c "./test/incus/cluster-setup.sh deploy all" \
  2>&1 | tee artifacts/cluster-deploy.log

# CoS gets wiped by deploy — re-apply per CLAUDE.md
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0 \
  2>&1 | tee artifacts/cos-apply-fw0.log
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw1 \
  2>&1 | tee artifacts/cos-apply-fw1.log

# Wait for both takeover ready (60s timeout)
for i in $(seq 1 12); do
  fw0=$(sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'show chassis cluster status'" 2>&1 | grep -c "Takeover ready: yes")
  fw1=$(sg incus-admin -c "incus exec loss:xpf-userspace-fw1 -- cli -c 'show chassis cluster status'" 2>&1 | grep -c "Takeover ready: yes")
  [ "$fw0" -ge 3 ] && [ "$fw1" -ge 3 ] && break
  sleep 5
done

# Capture cluster status snapshot
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'show chassis cluster status'" \
  | tee artifacts/cluster-status-fw0.txt
sg incus-admin -c "incus exec loss:xpf-userspace-fw1 -- cli -c 'show chassis cluster status'" \
  | tee artifacts/cluster-status-fw1.txt

# Binary checksums on each node
for node in xpf-userspace-fw0 xpf-userspace-fw1; do
  sg incus-admin -c "incus exec loss:$node -- sha256sum /usr/local/sbin/xpfd /usr/local/sbin/xpf-userspace-dp"
done | tee artifacts/node-binary-hashes.txt
```

#### G5.a — CoS-off IPv4 push + reverse

```bash
HOST=loss:cluster-userspace-host
sg incus-admin -c "incus exec $HOST -- iperf3 -c 172.16.80.200 -P 4 -t 10" \
  2>&1 | tee artifacts/smoke-v4-cosoff-push.log
sg incus-admin -c "incus exec $HOST -- iperf3 -c 172.16.80.200 -P 4 -t 10 -R" \
  2>&1 | tee artifacts/smoke-v4-cosoff-reverse.log
```

**Pass criteria**: `[SUM] ... sender` line present, sender bitrate
> 5 Gbps in both directions, retransmits low (< 1% of segments).

#### G5.b — CoS-off IPv6 push + reverse

```bash
sg incus-admin -c "incus exec $HOST -- iperf3 -6 -c 2001:559:8585:80::200 -P 4 -t 10" \
  2>&1 | tee artifacts/smoke-v6-cosoff-push.log
sg incus-admin -c "incus exec $HOST -- iperf3 -6 -c 2001:559:8585:80::200 -P 4 -t 10 -R" \
  2>&1 | tee artifacts/smoke-v6-cosoff-reverse.log
```

**Pass criteria**: same as G5.a but on v6.

#### G5.c — CoS-on class sweep (both directions)

Drives traffic with DSCP markers across the configured CoS classes
on the cluster. Class set per
`test/incus/loss-userspace-cluster.env` and the deployed CoS
config (`docs/ha-cluster-userspace.conf` + the apply script
output captured in G5 pre-flight).

For each class label `c` in {best-effort, assured, voice, network-control}
(adjust to the actual class names emitted by
`show class-of-service classifier`):

```bash
CLASS=$c
# Set traffic-class via --tos DSCP marking for the iperf3 stream.
# DSCP→class map captured from cluster CoS show output.
DSCP=$(get_dscp_for_class "$CLASS")  # documented per-class in artifacts/cos-dscp-map.txt
sg incus-admin -c "incus exec $HOST -- iperf3 -c 172.16.80.200 -P 4 -t 10 --tos $DSCP" \
  2>&1 | tee "artifacts/smoke-v4-coson-${CLASS}-push.log"
sg incus-admin -c "incus exec $HOST -- iperf3 -c 172.16.80.200 -P 4 -t 10 -R --tos $DSCP" \
  2>&1 | tee "artifacts/smoke-v4-coson-${CLASS}-reverse.log"
sg incus-admin -c "incus exec $HOST -- iperf3 -6 -c 2001:559:8585:80::200 -P 4 -t 10 --tos $DSCP" \
  2>&1 | tee "artifacts/smoke-v6-coson-${CLASS}-push.log"
sg incus-admin -c "incus exec $HOST -- iperf3 -6 -c 2001:559:8585:80::200 -P 4 -t 10 -R --tos $DSCP" \
  2>&1 | tee "artifacts/smoke-v6-coson-${CLASS}-reverse.log"
```

After the sweep, capture queue stats from both nodes:

```bash
for node in xpf-userspace-fw0 xpf-userspace-fw1; do
  sg incus-admin -c "incus exec loss:$node -- cli -c 'show class-of-service interface'" \
    | tee "artifacts/cos-interfaces-${node}.txt"
  sg incus-admin -c "incus exec loss:$node -- cli -c 'show interfaces queue'" \
    | tee "artifacts/cos-queues-${node}.txt"
done
```

**Pass criteria**: each class push/reverse run finishes with sender
SUM > 0, no `connection refused`, no `connect failed`. Per-class
absolute floor depends on configured weights — record the result;
the hard gate is non-zero throughput on each class with bandwidth
roughly matching the configured class weight.

#### G5.d — Screen / flood baseline

LAND attack rejection:

```bash
sg incus-admin -c "incus exec $HOST -- hping3 --syn -a 172.16.80.200 -s 80 -p 80 -c 20 172.16.80.200" \
  2>&1 | tee artifacts/smoke-screen-land.log
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'show security flow screen statistics'" \
  | tee artifacts/smoke-screen-land-stats.log
```

**Pass criteria**: LAND counter increments in screen statistics;
host receives no responses (or all RST).

SYN-flood rejection:

```bash
sg incus-admin -c "incus exec $HOST -- hping3 -S -p 80 --flood -c 50000 172.16.80.200" \
  2>&1 | tee artifacts/smoke-screen-synflood.log &
SYN_PID=$!
sleep 5
kill $SYN_PID 2>/dev/null
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'show security flow screen statistics'" \
  | tee artifacts/smoke-screen-synflood-stats.log
```

**Pass criteria**: `syn-flood` counter increments; no daemon
crash; cluster status remains primary/secondary post-attack.

ICMP-flood rejection:

```bash
sg incus-admin -c "incus exec $HOST -- hping3 --icmp --flood -c 50000 172.16.80.200" \
  2>&1 | tee artifacts/smoke-screen-icmpflood.log &
ICMP_PID=$!
sleep 5
kill $ICMP_PID 2>/dev/null
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cli -c 'show security flow screen statistics'" \
  | tee artifacts/smoke-screen-icmpflood-stats.log
```

**Pass criteria**: `icmp-flood` counter increments; daemon stays
up.

#### G5.e — `make test-failover` — two-direction iperf3 across RG failover

```bash
make test-failover 2>&1 | tee artifacts/make-test-failover.log
```

**Pass criteria** (from `failover-test` skill):

- All 1-second intervals throughput > 3 Gbps
- Zero intervals at 0 Gbps
- Cluster ends in primary/secondary with RGs reset to original
  owners
- No daemon crash on either node

### G6: Artifact summary file

After all gates pass, populate `artifacts.md` with the structured
summary. Schema (see template below):

- commit SHA (G0)
- cluster env file path + node-id snapshot
- binary hashes (G2 + per-node G5 pre-flight)
- pass/fail row per gate G1..G5.e
- links to per-gate log files

## Phase B — issue comment composition

Final comment posted on #1530 contains:

1. Top-line: `VALIDATION ARTIFACT POSTED on <commit-SHA>`
2. Table of gates G1..G5.e with PASS marker and log filename
3. Quoted excerpts:
   - `grep-dpdk-violations.log` head (empty or filtered)
   - `make-test.log` final OK / PASS lines
   - `make-n-build-dpdk-exit.txt`
   - `cli-reject-dpdk.log` rejection message
   - SUM lines from each smoke iperf3 run
   - Final `make test-failover` summary
4. Binary hashes
5. Cluster status snapshot

After posting:

1. Close #1530 with reference to the comment.
2. Verify all other #1525 sub-issues closed:
   - #1526 CLOSED (verified at draft time)
   - #1527 CLOSED (verified at draft time)
   - #1528 — must be closed at Phase B start
   - #1529 CLOSED (verified at draft time)
3. Close umbrella #1525 with reference to #1530's comment as the
   final retirement evidence.

## Smoke-runner coordination protocol

Phase B steps that touch the cluster:

- G5 pre-flight (build + deploy + readiness)
- G5.a..G5.e

For each block:

1. SendMessage to `ab1c7bcf4d14b36b6` requesting cluster access
   with a target window and a job tag (e.g. `1530-G5d-screen`).
2. Wait for ACK or for the singleton to publish a green marker.
3. Execute the block.
4. SendMessage release notice when complete.

If the #1477 sibling is also queued, alternate runs. Never run G5
gates concurrently with another agent's cluster activity.

## Pass / fail decision

PASS only if every gate G1..G5.e records PASS in `artifacts.md`.
Any FAIL or partial → do not post the artifact, do not close
#1530, return blocker text instead. A blocker on #1530 may also
require reopening #1528 if the source-removal commit is the cause.

## Open items the runbook leaves to Phase B

- Exact DSCP→class map for the cluster CoS config. Captured live
  in G5 pre-flight from `cli -c 'show class-of-service classifier'`.
- Whether Phase 1 retirement message text is still in tree at the
  source-removal commit, or whether the rejection comes from the
  generic schema. G4 accepts either.
- Whether `hping3` is installed on `cluster-userspace-host`. If
  absent, install via `apt-get install -y hping3` before G5.d or
  substitute equivalent `nping` invocations.

## References

- Acceptance criteria: `gh issue view 1530`
- Sibling: #1477 (eBPF final validation artifact)
- Umbrella: #1525
- Phase 3 source removal: #1528
- Cluster env: `test/incus/loss-userspace-cluster.env`
- Skills: `/perf-test`, `/failover-test`
- Project rules: `CLAUDE.md`, `docs/engineering-style.md`
