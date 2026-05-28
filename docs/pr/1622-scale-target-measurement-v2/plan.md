# #1622 Scale Target measurement — synthetic-policy-gen + harness + table population

> Closes #1622. Closes #1612 (Tables populated under TSC gate).
> Refs #1609 v2 (empirical-grounding gap), #1607 (Scale Target row deferred).
>
> **Deliverable is the populated Scale Target table in
> `docs/userspace-jit-design.md`.** The Python + Bash artifacts are
> means, not ends. If reviewers find the harness design produces
> untrustworthy numbers (e.g. histogram bucket resolution too coarse,
> cross-worker first_key validation can't be satisfied under the
> 4-zone loss-cluster topology, or TSC drift on the Incus VM is
> larger than the bucket grain), PLAN-KILL is acceptable.

## 1. Scope (what this PR adds)

| Path | New/Mod | Purpose |
|---|---|---|
| `test/incus/synthetic-policy-gen.py` | NEW | Generate synthetic Junos `.set` policy at 10/100/1K/10K rule counts; SNAT-free default (AGY r4 axis 1); manifest header with `--rules`/`--zone-pairs`/`--seed`. |
| `test/incus/synthetic_policy_gen_test.py` | NEW | Python unittest suite — determinism (seed → byte-identical), realized-count manifest, zone-pair domain matches loss cluster (4 zones: lan/wan/sfmix/control), SNAT clauses absent by default. |
| `test/incus/cold-path-microbench.sh` | NEW | Driver: pre-flight snapshot → push synthetic config → flooder run → pre/post Prometheus + control-socket scrape → cross-worker `first_key` validation → percentile compute → TSV row. |
| `test/incus/cold_path_microbench_lib.py` | NEW | Helper Python module the bash driver shells out to: scrapes `/run/xpf/userspace-dp.sock` for the *full* `WorkerRuntimeStatus` (including `first_key` not exposed via Prometheus), runs the cross-worker collision check from plan v3.2 §3.4, computes p50/p99/p999 via the bucket midpoint method, emits the TSV row. |
| `docs/userspace-jit-design.md` | MOD | Add `## Scale Target` section with Tables A1/A2/B1/B2 populated with measured numbers. |
| `docs/pr/1622-scale-target-measurement-v2/plan.md` | NEW | this file. |
| `docs/pr/1622-scale-target-measurement-v2/reviewer-ids.md` | NEW | Codex + AGY + Copilot task-IDs per round. |
| `docs/pr/1622-scale-target-measurement-v2/claude-smr-plan-r*.md` | NEW | Claude SMR plan-review verdicts. |
| `docs/pr/1622-scale-target-measurement-v2/claude-smr-code-r*.md` | NEW | Claude SMR code-review verdicts. |
| `docs/pr/1622-scale-target-measurement-v2/measurement.tsv` | NEW | Raw TSV (one row per cell). |

### 1.1 Out of scope — do not touch

- `userspace-dp/src/afxdp/cos/queue_service/` — #1630 sub-agent (`adb4c2b75f6815e4c`) is in flight on the CoS equalize bug; file-zone disjoint.
- `userspace-dp/src/policy/` — #1632 just shipped Path B narrow; treat as foundation.
- `userspace-dp/src/afxdp/poll_descriptor/` — #1620 just shipped; treat as foundation.
- `userspace-dp/src/afxdp/cold_path_hist.rs` — #1619 just shipped; treat as foundation.
- `userspace-dp/src/protocol/` — #1621 just shipped wire-protocol fields; treat as foundation.
- `pkg/cluster/` HA paths — out of scope.
- 100K + 1M rule-count rows — gated on #1606 wire-protocol ceiling; record as `N/A blocked on #1606`.
- Lab CPU isolation fixture — #739 still open; rows ship with `isolation_warning=true`.

## 2. Wire-surface assumptions verified

Confirmed live on master via `/run/xpf/userspace-dp.sock` (loss userspace cluster, both nodes up at plan-write time):

- `workers: 6`, every worker reports `cold_path_clock_source = "tsc"` after the wrapper-baseline calibration completes at startup.
- `cold_path_first_key`: 16-element `Vec<u64>` per worker — present in the JSON wire payload; **NOT** exposed in the public Prometheus surface (intentional per #1621 plan — `first_key` is internal slot-safety metadata, not a public metric). The harness therefore scrapes the control socket directly for cross-worker `first_key` consistency, not Prometheus.
- Prometheus families exposed (10 confirmed live): `cold_path_alias_seen`, `cold_path_clock_source`, `cold_path_ns_bucket` (cumulative `le`), `cold_path_ns_per_tsc_q32`, `cold_path_sample_phase_total`, `cold_path_samples_total`, `cold_path_snapshot_failed_total`, `cold_path_sum_ns_total`, `cold_path_wrapper_ns_baseline`, `cold_path_wrapper_underflow_count_total`.
- `cold_path_hist[slot][b]` is a non-cumulative count in the wire JSON; Prometheus emission cumulates per slot before emit (verified at `pkg/api/metrics_userspace.go:570-580`). Harness percentile compute uses the **raw non-cumulative** form from the JSON to avoid double-cumulating.
- Bucket layout (confirmed at `userspace-dp/src/afxdp/cold_path_hist.rs` and `pkg/api/metrics_userspace.go:553-563`):
  - Bucket 0: `[0, 1024)` ns (`le=1023`).
  - Bucket i ∈ [1, 22]: `[2^(9+i), 2^(10+i))` ns (`le=2^(10+i) - 1`).
  - Bucket 23: `[2^32, ∞)` ns (`le="+Inf"`).
- `cold_path_sample_phase` is monotonic across the run; harness computes `actual_sampling_rate = sum(samples[slot]) / sample_phase` to detect sampling drift.

## 3. Synthetic policy generator design (`synthetic-policy-gen.py`)

### 3.1 CLI surface

```
synthetic-policy-gen.py
    --rules N                  # 10 / 100 / 1000 / 10000 (required)
    --zone-pairs K             # default: derived from cluster zone set
                               # default = 4 (lan-wan, lan-sfmix,
                               #              wan-lan, sfmix-lan)
                               # caller may override.
    --address-books B          # default 10 (small) | 100 (1K rules)
    --cidrs-per-book C         # default 100 | 1000 for 10K rules
    --apps-per-rule A          # default 5
    --permit-ratio P           # default 0.7
    --seed S                   # required for determinism
    --with-snat                # opt-in; off by default per AGY r4
    --out PATH                 # default stdout
    --manifest PATH            # write JSON manifest (counts realized).
```

### 3.2 Zone-pair domain

Cluster zone set (confirmed via `docs/ha-cluster-userspace.conf`):
**`lan / wan / sfmix / control`**. Four zones → at most 12 ordered pairs (excluding loopback `from == to` which Junos rejects). The default `--zone-pairs 4` matches the 4 policy rule-sets already present in the loss cluster baseline (`lan→wan`, `lan→sfmix`, plus their reverses needed for return traffic). Zone-pair selection is deterministic from the seed.

Why 4 zone-pairs by default: the 16-slot `splitmix64` `first_key` bookkeeping aliases at 5+ active zone-pairs on the loss cluster (Codex r1 finding 4, plan v3.2 §3.4 reproduced — `trust→dmz` and `untrust→trust` both map to slot 3, etc.). Staying at 4 active zone-pairs keeps the alias_seen surface clean. The generator CAN exceed 4 (the publication gate excludes aliased slots), but the *default* avoids aliasing entirely.

### 3.3 Rule body

```
set security policies from-zone <FROM> to-zone <TO> policy P-<i> \
    match source-address SRC-<i>
set security policies from-zone <FROM> to-zone <TO> policy P-<i> \
    match destination-address DST-<i>
set security policies from-zone <FROM> to-zone <TO> policy P-<i> \
    match application APP-<i>
set security policies from-zone <FROM> to-zone <TO> policy P-<i> \
    then { permit | deny }
```

`SRC-i` / `DST-i` reference `address-book global address <name> <CIDR>` entries from a global pool. **The pool is generated in deterministic seed order so that the 100-rule output is a strict prefix of the 1000-rule output, and the 1000-rule output is a strict prefix of the 10000-rule output.** This is the "superset" property from plan v3.2 §1.7 and is required so that differential analysis between rule-count cells is meaningful.

### 3.4 CIDR distribution

Within the address-book pool, CIDR prefix lengths follow this fixed mix (derived from common production firewall rule-sets):
- 50% `/24` (LANs / subnets).
- 30% `/28` (small site blocks).
- 20% `/32` (host pinholes).

Source/destination CIDRs are seeded from disjoint /8 blocks: SRC from `10.<book_id>.0.0/16`, DST from `192.<book_id>.0.0/16`. This avoids accidental SRC-DST overlap that would collapse policy match semantics.

### 3.5 Application pool

Apps are synthesised as `junos-tcp-port-<port>` clones referencing `set applications application <name> { protocol tcp; destination-port <port>; }`. Default pool of 64 apps (apps-per-rule × max realized rule count / 64-app reuse factor). Apps are reused round-robin across rules.

### 3.6 Manifest

JSON manifest at `--manifest PATH`:

```json
{
    "schema": 1,
    "rules_target": 10000,
    "rules_realized": 10000,
    "zone_pairs": ["lan→wan", "lan→sfmix", "wan→lan", "sfmix→lan"],
    "address_books": 100,
    "cidrs_per_book": 1000,
    "total_unique_cidrs": 100000,
    "apps_per_rule": 5,
    "apps_pool": 64,
    "permit_ratio": 0.7,
    "seed": 42,
    "with_snat": false,
    "git_sha": "<HEAD>",
    "generated_at": "<ISO8601 UTC>"
}
```

### 3.7 Unit tests (`synthetic_policy_gen_test.py`)

1. `test_determinism_same_seed` — two invocations with identical args produce byte-identical output.
2. `test_superset_property` — 10-rule output is a strict prefix of 100-rule output (after manifest header). Same for 100 ⊂ 1000 ⊂ 10000.
3. `test_realized_count_matches_target` — manifest.rules_realized == rules_target for each of 10/100/1000/10000.
4. `test_zone_pair_domain_is_cluster_set` — default zone-pair selection only uses the 4 cluster zones.
5. `test_snat_clauses_absent_by_default` — `--with-snat` omitted ⇒ no `set security nat source` lines.
6. `test_cidr_distribution_within_5pct` — empirical /24:/28:/32 ratio within ±5% of target across 10K-CIDR pool.
7. `test_apps_per_rule_exact` — every emitted policy references exactly `--apps-per-rule` distinct applications.
8. `test_manifest_round_trip_valid_json` — manifest is valid JSON parseable by `json.load`.
9. `test_permit_deny_ratio_within_2pct` — empirical permit ratio within ±2% of `--permit-ratio` over 10K-rule output.
10. `test_set_syntax_parseable` — output is parseable by `cli -c "configure; load merge ..."` (invoked via mock).

5× loop per `feedback_no_test_dismissal`.

## 4. Harness driver (`cold-path-microbench.sh` + `cold_path_microbench_lib.py`)

### 4.1 CLI surface

```
cold-path-microbench.sh
    --rules N                  # required: 10/100/1000/10000
    --cohort bounded|unbounded # default unbounded
    --duration SECS            # default 30
    --threads N                # default 4 (#1615 multi-thread)
    --cos on|off               # default off
    --out-tsv PATH             # required
    --seed S                   # synthetic-policy-gen seed; default 42
    --skip-deploy              # skip policy push (when iterating rule
                               # counts without rebuilding)
```

### 4.2 Pre-flight isolation snapshot

Captured into a header in the TSV. Fields:
- `host_kernel = $(uname -r)`
- `host_clocksource = $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource)`
- `host_isolcpus = $(grep -o 'isolcpus=[^ ]*' /proc/cmdline || echo "none")`
- `host_nproc = $(nproc)` — emit `FLOODER-PIN-WARNING` if `< 4`.
- `vm_clocksource` via `incus exec loss:xpf-userspace-fw0 -- cat /sys/devices/system/clocksource/clocksource0/current_clocksource` — emit `CLOCKSOURCE-WARNING: vm tsc not active` if `!= "tsc"`. (Per worker `cold_path_clock_source` is the real gate.)
- `vm_cpus_allowed` per worker via `taskset -pc $(pgrep -f userspace-dp)` (only the first worker; all 6 share affinity).
- `nic_irq_cpus` — `/proc/interrupts` grep for `mlx5_comp@pci`.

If `host_isolcpus == none` AND `host_nproc < 8`, set `isolation_warning=true` in every TSV row (default expectation per parent §4.5).

### 4.3 Steps (per cell)

1. Generate synthetic policy: `python3 synthetic-policy-gen.py --rules N --seed 42 --out /tmp/policy.set --manifest /tmp/policy.manifest.json`.
2. Push to VM (unless `--skip-deploy`): `incus file push /tmp/policy.set loss:xpf-userspace-fw0/tmp/`; then `incus exec ... -- /usr/local/sbin/cli -c "configure; load merge /tmp/policy.set; commit"`. Verify `/metrics` returns 200 OK and `workers == 6`.
3. **Sample-phase reset window:** wait 5 s for `cold_path_sample_phase` to stabilise. The wire-protocol has no explicit "clear histogram" RPC, so the harness does **delta arithmetic** between pre/post snapshots rather than absolute-value reads.
4. Pre-snapshot: `python3 cold_path_microbench_lib.py scrape --sock /run/xpf/userspace-dp.sock --out /tmp/pre.json`.
5. Invoke flooder on `cluster-userspace-host`:
   ```
   incus exec loss:cluster-userspace-host -- \
     taskset -c 1-3 /usr/local/bin/cold-path-flooder \
       --iface ge-0-0-1 \
       --dst-mac <RETH1-mac-from-VM-arp> \
       --dst-ip 10.0.61.1 \
       --threads 4 --cohort unbounded \
       --duration 30 --warmup 2 \
       --seed 1234
   ```
6. Post-snapshot: `python3 cold_path_microbench_lib.py scrape --sock ... --out /tmp/post.json`.
7. Verify per-worker TSC gate: every worker must report `cold_path_clock_source == "tsc"`. If any worker reports `clock_gettime`, set `tsc_gated_publish=false` and emit a TSV row footnote — the row is NOT copied into the published tables.
8. Cross-worker `first_key` validation (plan v3.2 §3.4 + AGY r3 finding 2):
   ```python
   def slot_safe_to_publish(slot, snapshots):
       keys = {s.first_key[slot] for s in snapshots
               if s.samples[slot] > 0 and s.first_key[slot] != 0}
       any_alias = any(s.alias_seen[slot] for s in snapshots)
       return len(keys) <= 1 and not any_alias
   ```
9. Percentile compute (per slot, then aggregated):
   - Decumulate the bucket histogram: `bucket_count[b] = bucket_cumulative[b]` (the wire JSON is already non-cumulative).
   - Reconstruct CDF: `cdf[b] = sum(bucket_count[0..=b])`.
   - For quantile q: find first b where `cdf[b] >= q * total`; sample value = bucket midpoint = `(bucket_lo[b] + bucket_hi[b]) / 2`. For bucket 0 (`[0, 1024)`), midpoint = 512. For bucket 23 (`[2^32, ∞)`), midpoint = `2^32` (saturating).
   - Aggregate: union all slot bucket counts that pass the cross-worker gate, then re-compute percentiles on the union histogram.
10. Compute per-worker Mpps from flooder JSON output (flooder reports `tx_pps` total + per-thread breakdown). Aggregate Mpps = sum across all flooder threads.
11. Append TSV row.

### 4.4 TSV schema

One row per (rule_count × cohort × cos × run_id). Columns:

```
rule_count cohort cos run_id duration_secs
host_clocksource vm_clocksource isolation_warning flooder_pin_warning
tsc_gated_publish wrapper_ns_baseline_median ns_per_tsc_q32_median
clock_source_per_worker actual_sampling_rate
aggregate_mpps per_worker_mpps_avg per_worker_mpps_stddev
slots_published slots_excluded_alias slots_excluded_cross_worker
p50_ns p99_ns p999_ns p9999_ns
samples_total snapshot_failed_total wrapper_underflow_total
git_sha measurement_iso8601
```

`p9999_ns` is populated **only** for unbounded cohort rows where `samples_total >= 58_586` (per AGY r3 axis 3 — p9999 requires ≥10× the bucket count to be statistically meaningful, and the 24-bucket histogram needs ~58K samples to populate the 99.99th percentile bucket).

### 4.5 Sample-size policy

For **Tables A1 / A2** (cold-saturated flood, 30 s, unbounded cohort, 2.96 M aggregate pps → ~889 M packets / 30 s → ~3.5 M sampled-policy-eval events at 1-in-256), N=3 runs per cell. Cell value is median across N=3 runs. CoV across runs reported in the TSV (`per_worker_mpps_stddev`).

For **Tables B1 / B2** (bounded cohort, smaller sample space) N=3 same.

### 4.6 Cluster serialization

Per `feedback_smoke_serialized_single_agent` + parent-plan §3.6, the measurement sweep (4 rule counts × 2 cohorts × 3 runs ≈ 30 min wall-clock, plus deploy time) IS a long smoke. Coordinate via PR comment marker `<!-- AWAITING-MEASUREMENT-WINDOW -->` if `#1630` sub-agent has the cluster.

## 5. Doc-coherency contract (load-bearing)

`docs/userspace-jit-design.md` gets a new **`## Scale Target`** section immediately before the existing `## Measurement plan` section. Section layout:

```markdown
## Scale Target

Measured on the loss userspace cluster (`loss:xpf-userspace-fw0/fw1`,
mlx5 VF passthrough, native XDP, 6 workers, TSC-calibrated cold-path
sampler at 1-in-256 sampling rate).

Methodology: see `test/incus/cold-path-microbench.sh`. Raw TSV:
`docs/pr/1622-scale-target-measurement-v2/measurement.tsv`.

### Table A1: Unbounded cohort, CoS-off, TSC-gated

| Rule count | Aggregate Mpps | Per-worker Mpps | p50 (ns) | p99 (ns) | p999 (ns) | p9999 (ns) |
|---|---|---|---|---|---|---|
| 10 | <X> | <X> | <X> | <X> | <X> | <X> |
| 100 | <X> | <X> | <X> | <X> | <X> | <X> |
| 1000 | <X> | <X> | <X> | <X> | <X> | <X> |
| 10000 | <X> | <X> | <X> | <X> | <X> | <X> |
| 100000 | N/A blocked on #1606 | | | | | |
| 1000000 | N/A blocked on #1606 | | | | | |

### Table A2: Bounded cohort, CoS-off, TSC-gated

(same schema; p9999 omitted per AGY r3 axis 3)

### Table B1: Unbounded cohort, CoS-on, TSC-gated
### Table B2: Bounded cohort, CoS-on, TSC-gated

### Footnotes

- All rows TSC-gated: every worker reported `cold_path_clock_source = "tsc"`.
- Slots aliased per the cross-worker `first_key` check are excluded
  from published percentiles. Excluded-slot count per row is in the
  raw TSV.
- `isolation_warning = <true|false>` row-by-row (per #739).
- Sampling rate: 1-in-256 (`--cold-path-sample-mask 0xff` default).
```

If the measurement run fails the TSC gate or cluster serialization can't be obtained, the section ships with **`MEASUREMENT-DEFERRED`** placeholders and an explicit disclaimer — but the PR is then **STAGED**, not FULL.

The existing `## Measurement plan` (lines 613-620) is left intact; the new `## Scale Target` section sits above it.

## 6. Test plan

### 6.1 Python tests

- `python3 -m unittest test/incus/synthetic_policy_gen_test.py` — full suite + 5× loop.
- `python3 -m unittest test/incus/cold_path_microbench_lib_test.py` — percentile-compute unit tests against a hand-crafted histogram with known p50/p99/p999.

### 6.2 Bash tests

- `shellcheck test/incus/cold-path-microbench.sh` clean.
- `bash -n test/incus/cold-path-microbench.sh` syntax-check.

### 6.3 No Rust / Go changes expected

This PR adds NO Rust or Go code. `cargo test` and `go test ./...` are run as smoke-only (verify master baseline didn't regress). If reviewers find a wire-protocol field that needs to land here too, that's a scope creep that should be its own PR.

### 6.4 Smoke matrix (loss userspace cluster)

Pass A (CoS-off) + Pass B (CoS-on) over v4/v6 × push/`-R` per `feedback_smoke_v4_and_v6` + `feedback_smoke_push_and_reverse`. Smoke runs as part of the measurement sweep — the cold-saturated flood IS the regression probe; the iperf3 smoke is the steady-state probe. Both must pass.

### 6.5 `make test-failover` — not required

This PR touches no HA code, no `pkg/cluster/`, no `pkg/vrrp/`. Per CLAUDE.md HA gate, `make test-failover` is only required for HA-touching changes. Explicit note in PR description.

### 6.6 Build clean

`cargo build --release` + `make build` + `make build-userspace-dp` + `make build-ctl` — clean baseline check; no expected changes.

## 7. Open questions for reviewers (≥5)

1. **Synthetic policy CIDR distribution** — is the fixed 50/30/20 (/24, /28, /32) mix sufficient for the JIT scale target, or do we need to sweep distribution as an axis? Plan picks fixed mix for v1; rationale: the cold-path latency we're measuring is dominated by the *rule count* (linear scan) not the prefix-match depth (which is a future LPM-DAG concern for #1609 v2). Reviewer may challenge.

2. **Rule-count ceiling per wire-protocol** — 10K rules is the highest cell we'll publish. 100K + 1M are recorded as `N/A blocked on #1606`. Should we attempt 100K as a best-effort row with a footnote? Plan picks NO (hard ceiling at 10K) — but reviewer may argue YES if the wire protocol's actual ceiling is north of 50K and a best-effort 100K row would inform #1606.

3. **Harness run duration per cell** — 30 s warmup-2 + duration-30 = 32 s flooder window. Long enough to escape warmup (≥10 s of flood at 2.96 M pps → ~30 M packets → ~117 K sampled events at 1-in-256, well above the 58.6 K p9999 floor). Bound jitter via N=3 runs + reported CoV. Reviewer may challenge: should we use 60 s for the p9999 tail?

4. **Sample size N=3 vs single-run** — N=3 keeps wall-clock at ~30 min for the full sweep (4 rule × 2 cohort × 3 N × ~75 s/cell). Reviewer may challenge for N=5.

5. **Per-zone-pair latency derivation from the 16-slot histogram** — the 16 splitmix64 slots are a *hash* of `(from_zone, to_zone)`, not a direct map. The harness publishes **per-slot percentiles only after cross-worker first_key validation passes**, with the `first_key` value identifying which zone-pair the slot covers. If the published row claims "Table A1 / 1000 rules / p50 = X ns", that's the *aggregate across all safe-to-publish slots*. Per-zone-pair detail is in the raw TSV. Reviewer may challenge: should the published table break out per-zone-pair rows, or is aggregate sufficient?

6. **Bucket midpoint vs lower-edge for percentile compute** — Plan picks **midpoint** (per Prometheus `histogram_quantile()` convention). Bucket 0 midpoint = 512 ns; bucket 23 (sat) midpoint = 2^32 ns. For tight cold-path samples (~100-1000 ns, all in bucket 0), this means **the reported p50 is dominated by bucket-0 midpoint resolution** — i.e. we report `p50 ≈ 512 ns` for the 10-rule cell unless bucket 1+ get populated. This is a HARD LIMIT of the 24-bucket layout. If reviewers want finer resolution at the low end, that requires changing #1619 — out of scope here. Reviewer may PLAN-KILL if the limit is judged unacceptable.

7. **TSC drift on the Incus VM** — `__rdtscp` is invariant on the host (KVM passes through `constant_tsc + nonstop_tsc`). The per-worker calibration runs once at startup; `ns_per_tsc_q32 = 1871680070` (≈ 0.436 ns/tsc) was confirmed live. The harness computes `ns_per_tsc_q32_median` across all 6 workers and emits the value; deviation > 5% between any two workers sets `tsc_gated_publish=false`. Reviewer may challenge — is 5% the right threshold?

8. **STAGED ship if measurement window can't be obtained** — if `#1630` sub-agent or some other smoke contender holds the cluster for >2 hours, do we STAGED-ship with `MEASUREMENT-DEFERRED` placeholders? Plan picks: yes, file a follow-up issue and merge harness only. Reviewer may challenge.

9. **PR auto-merge gate** — clean 4-of-4 reviewers (Codex + AGY + Copilot + Claude SMR) + populated table + smoke pass. Per `feedback_auto_merge_on_clean_triple`.

## 8. Acceptance criteria

- `synthetic-policy-gen.py` + tests pass + 5× loop.
- `cold_path_microbench_lib.py` percentile-compute tests pass + 5× loop.
- `cold-path-microbench.sh` shellcheck/syntax clean.
- Measurement sweep produces Tables A1/A2/B1/B2 populated with non-`TBD` numbers (FULL form).
- All published rows have `tsc_gated_publish=true`.
- `docs/userspace-jit-design.md` Scale Target section is added.
- Smoke matrix Pass A + Pass B succeed.
- PR body uses `Closes #1622` keyword.
- Either:
  - **FULL**: Tables populated, `#1609 v2 acceptance criterion UNBLOCKED` noted in PR body.
  - **STAGED**: Tables ship `MEASUREMENT-DEFERRED`, follow-up issue filed, `#1609 v2 acceptance REMAINS UNMET` noted.

## 9. Reviewer dispatch & framing

- **Round 1**: Codex (`expert,kernel-perf-measurement`) + AGY + Copilot (auto on PR push) + Claude SMR (this driver).
- Codex sandbox infra: per session-wide pattern, embed plan v1 + live wire surface evidence inline.
- Reviewer prompt frames:
  - HPC perf measurement methodology (warmup + N-run jitter + CoV reporting).
  - Synthetic workload design (CIDR mix, zone-pair domain, application pool).
  - Prometheus histogram percentile extraction (bucket midpoint vs lower-edge; `histogram_quantile()` convention).
  - Per-zone-pair latency interpretation from a 16-slot splitmix64 hash (NOT a direct map).
  - Junos config-deploy contention on the loss userspace cluster.

Per `feedback_gemini_model_3_1_pro_preview` Gemini is NOT in this rotation; AGY is the third reviewer (Codex + AGY + Copilot + Claude SMR = 4 seats).

## 10. Risk model (≥3 surfaced risks)

| Risk | Manifestation | Mitigation |
|---|---|---|
| HIGH: 24-bucket histogram resolution insufficient at low end | 10/100-rule cells all collapse to bucket 0 → reported p50/p99 are all 512 ns | Acknowledge as floor in the published table footnote; reviewer may PLAN-KILL if unacceptable; remedy is a finer-grain histogram in a future #1619 follow-up. |
| HIGH: Cross-worker `first_key` collisions exclude too many slots | 4 zone-pair default keeps it clean; but if reviewers push for 8+ zone-pairs the alias rate climbs | Plan picks 4 zone-pair default; the publication gate transparently excludes aliased slots and the count is in the TSV. |
| MED: Cluster serialization conflict with #1630 sub-agent | Measurement sweep takes ~30 min; #1630 may want the cluster during that window | Coordinate via `AWAITING-MEASUREMENT-WINDOW` marker; STAGED ship is the fallback. |
| MED: Synthetic policy commit time at 10K rules dominates wall-clock | Junos parser is O(n) so 10K rules commits in ~5-10 s; verified via inspection (no measurement yet) | Pre-flight a 10K commit dry-run; if commit > 60 s, downscope the 10K cell to a STAGED row. |
| LOW: Flooder pin contention with userspace-dp workers on the host | host `nproc=8`; 4 flooder threads + 6 worker threads = 10 contended threads | `taskset -c 1-3` pins flooder; emit `FLOODER-PIN-WARNING` row flag; STAGED if host has < 8 cores. |

## 11. Estimated wall-clock

- Plan-review round-trip (4 reviewers): 30-60 min.
- Implement (synthetic-gen + harness + tests): 2-3 hr.
- Measurement sweep on cluster: 30-40 min (gated on serialization).
- Code-review round-trip: 30-60 min.
- Auto-merge + final smoke: 15 min.
- **Total**: ~5-7 hr if no PLAN-KILL and cluster window opens promptly.
