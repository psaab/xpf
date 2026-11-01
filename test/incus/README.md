# test/incus — Incus cluster harnesses

Index for the 207 tracked files here (206 pre-existing + this README): cluster/measurement harnesses,
sourced libraries, hermetic self-tests, Python modules and their tests,
cluster definitions, and fixtures. Nothing in this directory moves when
this index changes; every census below keys on the paths listed here.

## Start here

| Question | Run / read |
|---|---|
| Hermetic checks (no cluster) | `make selftest` — `scripts/run-selftests.sh`, which also runs the self-test and harness censuses (`scripts/README.md`) |
| Is harness X reached by a gate? | `sh scripts/harness-census.sh` (`CENSUS_VERBOSE=1` lists the reached set); unreached harnesses are declared, with a reason, in `HARNESSES.unreached` |
| Canonical live-cluster gate | `make cluster-deploy-and-gate CLUSTER_GATE=<make-target>` under `with-cluster.sh`; gate rows are recorded through `harness-result.sh` into `test/results/ledger.d/` and compared by `ledger_compare.py` |
| Standalone single VM | `make test-env-init`, `test-vm`, `test-ct`, `test-deploy`, `test-ssh` (drives `setup.sh`) |
| Which single gate | The layer map and table below, then that harness's own header |

## Layer map

One direction only: gates call libraries and the result envelope;
libraries do not call gates. A file is in exactly one layer.

1. **Cluster definitions** (data, §5): `*.env` cluster files,
   `xpf-*.conf`, `*.set`, `xpfd.service`, and the shared-umem JSON.
   Sourced or copied; never executed.
2. **Cluster foundation** (sourced libraries, §3): `cluster-env.sh`
   (addressing defaults), `cluster-lock.sh` (the #1875 lock protocol),
   `cluster-cell.sh`, `cluster-build-identity.sh`, `deploy-lib.sh`,
   `target-services.sh`, `active-fw.sh`.
3. **Cluster lifecycle** (runnable, §2): `setup.sh` (standalone VM/CT),
   `cluster-setup.sh` (cluster nodes), `with-cluster.sh` (run a command
   inside the exclusive lock cell), `mouse-target-setup.sh`.
4. **Gate harnesses** (runnable, §2): `test-*.sh`, `wire-*.sh`, and the
   named live gates (`wg-interop.sh`, `dhcp-lease-failover.sh`,
   `persistent-nat-failover.sh`, `ipsec-content-change-10878.sh`,
   `cc-rollback-functional.sh`, `t12-g2-9506.sh`,
   `test-v6-na-recovery-12495.sh`, `screen-probe.sh`). A gate asserts a
   property and can fail; it is owed a Makefile recipe, or a
   `GATE:` line in `HARNESSES.unreached` until it gets one.
5. **Measurement harnesses** (runnable, §2): CoS/fairness, mouse-latency,
   new-flow-ceiling, step1/2/3 capture pipelines. They produce numbers
   first and verdicts through their Python layer (§4).
6. **Result envelope + ledger** (§3/§4): `harness-result.sh` wraps a gate
   run and appends exactly one `PASS`/`FAIL`/`VOID` row; `ledger_compare.py`
   compares rows across runs, gates coverage (`LEDGER_COVERAGE.unreached`),
   and lints the ledger. See "Exit codes are not verdicts" below.
7. **Hermetic self-tests** (`*-selftest.sh`, `*_test.py`, `test_*.py`,
   §3/§4): fixture-only tests of layers 2–6. Registered in
   `scripts/run-selftests.sh` and counted by `scripts/selftest-census.sh`;
   `wire-routing-separation-temporal-selftest.py` is the one Python
   self-test whose name matches neither Python glob; it is run by
   `wire-routing-separation.sh` itself (its `--selftest` path), not by discovery.
8. **Diagnostics** (§2): one-shot operator tools with no verdict
   (`analyze-userspace-traces.sh`, `capture-cold-stall.sh`, the
   `pnat-*-8341/8447.sh` bisect probes, step1/step2 evidence drivers).
   Declared `DIAGNOSTIC:` in `HARNESSES.unreached`; never give one a
   `make` target that implies "run to check the tree".

`cold-path-flooder/` and `newflow-gen/` are standalone Rust crates
(outside both cargo workspaces); build via `make test-cold-path-flooder`
and `make test-newflow-ceiling-lib` respectively.

## Inventory

Counts are on `origin/master` when this index landed. The censuses in
§6 are the live count; if a number here disagrees with them, the census
is right and this table needs an edit in the same change.

| Layer | Files |
|---|---|
| Shell, total | 115 `*.sh` = 59 runnable + 23 libraries + 33 self-tests (next rows; the harness census's own arithmetic is 61 + 21 + 33 — see the note under the reached/declared lists, where two semantic libraries sit in its runnable set by design) |
| Runnable shell | 59 = 58 harnesses + `harness-result.sh` (the envelope) |
| Sourced shell libraries | 23 = the 21 named in `scripts/harness-census.sh` (`cluster-cell.sh`, `cluster-env.sh`, `cluster-lock.sh`, `cos-apply-lib.sh`, `deploy-lib.sh`, `fbf-steering-lib.sh`, `failover-client-lib.sh`, `failover-clock-lib.sh`, `failover-journal-lib.sh`, `ha-assurance-lib.sh`, `ha-smoke-iperf-lib.sh`, `host-inbound-lib.sh`, `iperf-throughput-lib.sh`, `mouse-elephant-lib.sh`, `newflow-ceiling-lib.sh`, `private-rg-lib.sh`, `screen-probe-lib.sh`, `stress-failover-lib.sh`, `target-services.sh`, `wire-config-snapshot-lib.sh`, `wire-gate-lib.sh`) + `active-fw.sh` + `v6-na-recovery-lib-12495.sh` (both declared in `HARNESSES.unreached` as `LIBRARY`) |
| Hermetic shell self-tests | 33 `*-selftest.sh`, listed below |
| Python | 59 = 27 tests (`*_test.py`, `test_*.py`) + 32 modules/helpers (incl. `unittest_shim.py`, `wire-routing-separation-temporal-selftest.py`) |
| Cluster defs & fixtures | 26 tracked files that are neither `*.sh` nor `*.py` outside the Rust crates (listed under Non-code files) |
| Rust crates | `cold-path-flooder/` (`Cargo.toml`, `Cargo.lock`, `src/main.rs`, `.gitignore`), `newflow-gen/` (same four) |
| Declarations | `GO_BUILDTAG_REVIEWED`, `HARNESSES.unreached`, `LEDGER_COVERAGE.unreached`, `ledger-expected-red.txt` (counted in Non-code files above) |

### Runnable shell (58 harnesses + the envelope)

Reached by a Makefile recipe today (35, per `harness-census.sh`,
which also counts the 5 `scripts/userspace-*.sh`): `cc-rollback-functional.sh`,
`cluster-build-identity.sh`, `cluster-setup.sh`, `dhcp-lease-failover.sh`,
`harness-result.sh`, `ipsec-9506-fixture.sh`,
`ipsec-content-change-10878.sh`, `mouse-target-setup.sh`,
`persistent-nat-failover.sh`, `setup.sh`, `t12-g2-9506.sh`,
`test-active-active.sh`, `test-chained-crash.sh`,
`test-connectivity.sh`, `test-double-failover.sh`, `test-failover.sh`,
`test-fbf-steering.sh`, `test-ha-crash.sh`, `test-host-inbound.sh`,
`test-private-rg.sh`, `test-restart-connectivity.sh`, `rg-move-soak.sh`,
`test-rolling-upgrade.sh`, `test-stress-failover.sh`,
`test-wire-properties.sh`, `wg-interop.sh`, `wire-appmatch-twins.sh`,
`wire-conntrack-lifecycle.sh`, `wire-hostinbound-deny.sh`,
`wire-nat-frag-needed.sh`, `wire-policy-deny.sh`,
`wire-routing-separation.sh`, `wire-zone-matrix.sh`, `with-cluster.sh`.

Declared unreached in `HARNESSES.unreached` (28 here; +5 in `scripts/`):
GATE — `cos-be-contention-harness.sh`, `cos-gate1-small-four-alone.sh`,
`cos-simul-load-smoke.sh`, `fairness-cos-class-sweep.sh`,
`fairness-cos-throughput-headroom.sh`, `newflow-ceiling-harness.sh`,
`reverse-key-collision-probe.sh`, `test-mouse-latency-matrix.sh`,
`test-mouse-latency-same-class.sh`, `test-mouse-latency.sh`;
COMPOSED — `apply-cos-config.sh`, `fairness-harness.sh`,
`step1-capture.sh`;
DIAGNOSTIC — `analyze-userspace-traces.sh`, `capture-cold-stall.sh`,
`pnat-catchall-outage-check-8341.sh`, `pnat-counter-read-8447.sh`,
`pnat-mint-observability-8341.sh`, `pnat-rule-shape-8447.sh`,
`pnat-upstream-stage-8447.sh`, `pnat-wedge-recovery-8447.sh`,
`screen-probe.sh`, `step1-baseline-and-matrix.sh`, `step1-classify.sh`,
`step2-sched-switch-capture.sh`, `test-v6-na-recovery-12495.sh`;
LIBRARY — `active-fw.sh`, `v6-na-recovery-lib-12495.sh`.

That is every `*.sh` here, in the census's arithmetic: 33 reached +
28 declared + 21 census libraries + 33 self-tests = 115. The two
`LIBRARY` declarations are semantic libraries that the census
deliberately keeps in its runnable set (they are not in its named
`LIBRARIES` list), so the semantic split at the top of this section is
59 runnable / 23 libraries; both add to 115.

### Hermetic shell self-tests (33)

`cluster-build-identity-selftest.sh`, `cluster-cell-selftest.sh`,
`cluster-env-selftest.sh`, `cos-apply-lib-selftest.sh`,
`deploy-lib-selftest.sh`, `failover-client-selftest.sh`,
`failover-clock-selftest.sh`, `failover-journal-selftest.sh`,
`fbf-steering-harness-selftest.sh`, `fbf-steering-selftest.sh`,
`go-buildtag-census-selftest.sh`, `go-skip-census-selftest.sh`,
`ha-assurance-selftest.sh`, `harness-census-selftest.sh`,
`harness-ledger-mutation-selftest.sh`, `harness-result-selftest.sh`,
`host-inbound-selftest.sh`, `ignored-cell-census-selftest.sh`,
`iperf-throughput-selftest.sh`, `make-guard-probes-selftest.sh`,
`miri-census-selftest.sh`, `mouse-elephant-selftest.sh`,
`newflow-ceiling-selftest.sh`, `private-rg-fullcycle-selftest.sh`,
`private-rg-selftest.sh`, `screen-probe-selftest.sh`,
`selftest-census-selftest.sh`, `stress-failover-selftest.sh`,
`target-services-selftest.sh`, `v6-na-recovery-12495-selftest.sh`,
`wire-config-snapshot-selftest.sh`, `wire-gate-hermetic-selftest.sh`,
`with-cluster-selftest.sh`. Registered in `scripts/run-selftests.sh`;
a new one with no registration fails `scripts/selftest-census.sh` by name.

### Python modules vs tests

Modules/helpers (32): `cluster_status_parse.py`,
`cos_be_contention_validate.py`, `cos_fixture_spec.py`, `fairness_cov.py`,
`fairness_equal_flow_capture.py`, `fairness_multi_sample.py`,
`fairness_surplus_giveback_validate.py`, `host_inbound_probe.py`,
`iperf3_sum_parse.py`, `ledger_compare.py`, `mouse-target-echo.py`,
`mouse_latency_aggregate.py`, `mouse_latency_orchestrate.py`,
`mouse_latency_probe.py`, `newflow_ceiling_analyze.py`,
`policy_scheduler_validate.py`, `retire_ebpf_artifact_schema.py`,
`step1-histogram-classify.py`, `step1-rate-spread-analysis.py`,
`step1-rss-multinomial.py`, `step2-sched-switch-classify.py`,
`step2-sched-switch-reduce.py`, `step3-tx-kick-classify.py`,
`unittest_shim.py`, `v6-na-parse-12495.py`,
`rg_move_soak.py` (the #18583 RG-move soak; `rg-move-soak.sh` runs it),
`wire-routing-separation-temporal-selftest.py`, `wire_probe_burst.py`,
`wire_raw_tcp_burst.py`, `wire_routing_probe.py`, `wire_tcp_accept.py`,
`wire_tcp_hold.py`.

Tests (27, run by `run-selftests.sh` §3b via `unittest discover` over
`*_test.py`/`test_*.py`): `cluster_status_parse_test.py`,
`cos_be_contention_validate_test.py`, `cos_port_grid_test.py`,
`fairness_cos_active_fw_test.py`, `fairness_cov_test.py`,
`fairness_multi_sample_test.py`,
`fairness_surplus_giveback_validate_test.py`,
`harness_discovery_test.py`, `host_inbound_probe_test.py`,
`iperf3_sum_parse_test.py`, `ledger_compare_test.py`,
`mouse_latency_aggregate_test.py`, `mouse_latency_orchestrate_test.py`,
`mouse_latency_probe_test.py`, `newflow_ceiling_analyze_test.py`,
`policy_scheduler_validate_test.py`,
`retire_ebpf_artifact_schema_test.py`, `rg_move_soak_test.py`,
`rolling_upgrade_oracle_test.py`,
`step1_histogram_classify_test.py`, `step1_rate_spread_analysis_test.py`,
`step1_rss_multinomial_test.py`, `step2_sched_switch_classify_test.py`,
`step2_sched_switch_reduce_test.py`, `step3_tx_kick_classify_test.py`,
`test_cos_apply_lib.py`, `test_mouse_latency_shell_test.py`.

### Non-code files

Cluster envs: `loss-cluster.env`, `loss-userspace-cluster.env` (the
canonical default), `tcp-userspace-cluster.env`,
`udp-userspace-cluster.env`, `wg-interop.env`.
Configs/fixtures: `cos-iperf-config.set`, `cos-iperf-same-class.set`,
`cos-iperf-symmetric.set`, `fbf-two-upstream-config.set`,
`sqm-cookbook-config.set`, `failover-client-connect-error.jsonl`,
`failover-crash-straggler-2s91.jsonl` and
`failover-crash-straggler-4s05.jsonl` (real loss crash-run iperf3 logs,
cut; #18692 rows in `iperf3_sum_parse_test.py`),
`loss-userspace-shared-umem-phase0-node0.json`,
`loss-userspace-shared-umem-phase0-node1.json`, `xpf-cluster-fw0.conf`,
`xpf-cluster-fw1.conf`, `xpf-internet-test.conf`, `xpf-test.conf`,
`xpf-vlan-test.conf`, `xpfd.service`, `requirements-step1.txt`,
`requirements-step2.txt`, `.gitignore`.

## Exit codes are not verdicts

`harness-result.sh:12-39` is the canonical statement; summary:

| Tool | `exit 1` means |
|---|---|
| `newflow_ceiling_analyze.py` | INVALID — the run did not measure what it claims (2 = INCONCLUSIVE) |
| `mouse_latency_aggregate.py` | measured FAIL — a regression (2 = insufficient evidence) |
| `iperf-throughput-lib.sh` | FAIL only; it has no VOID state — "no measurement" arrives as FAIL text |
| `scripts/run-selftests.sh` | FAIL; 77 from a leg = SKIP |

So no caller may read a harness exit code as a verdict. `harness-result.sh`
adapts each named source (`--adapter` ∈ `ha-smoke`, `smoke-cells`,
`newflow-ceiling`, `mouse-latency`, `selftest`, `iperf-throughput`,
`wire-gate`; an unlisted source is refused, never defaulted) to one string
— `PASS`, `FAIL`, or `VOID` (VOID requires a non-empty reason; PASS/FAIL
refuse one) — and writes one JSON row per run. Makefile gates invoke it as
`./test/incus/harness-result.sh run --gate <name> --adapter <a> --env <e>
--cluster --node <inst> -- ./test/incus/<gate>.sh`.

## Env contract

Cluster selection (highest precedence first):

| Var | Contract |
|---|---|
| `BPFRX_CLUSTER_ENV` | Path to a `*.env` above (relative paths resolve against the repo root; empty = `cluster-setup.sh` local defaults). `cluster-env.sh` fails if the named file does not exist. Makefile: `CLUSTER_ENV` defaults to `loss-userspace-cluster.env`, to `$BPFRX_CLUSTER_ENV` when that is set |
| `CLUSTER_ENV` (make) | Same file, set on the `make` command line |
| `XPF_CLUSTER_LOCK` / `XPF_CLUSTER_LOCK_TIMEOUT` | Lock file (default under `/var/worktrees/.cache/tmpdir/`) / wait timeout in seconds for `with-cluster.sh`; `XPF_CLUSTER_LOCK_HELD` is set inside a live cell and makes nested cells reentrant |
| `XPF_LEDGER`, `XPF_REPO_ROOT` | Ledger directory override / repo-root override for `harness-result.sh`; defaults `test/results/ledger.d/` and the git toplevel |
| `TMPDIR`, `GOCACHE`, `GOTMPDIR`, `CARGO_TARGET_DIR` | Scratch pins for self-tests; `run-selftests.sh` defaults them under `/var/worktrees/.cache` and an explicit caller value wins |
| Sourced env files | Set `INCUS_REMOTE`, `VM0`/`VM1` or `FW0`/`FW1`, `LAN_HOST`, `PROFILE`, `CLUSTER_CONF`, `LAN_*`, `WAN_*`, `IPERF_TARGET4/6`, `MOUSE_TARGET_*`, `DMZ_*`, and loss's `TARGET_ALIAS_V4_DEPRECATED` (`.200`; `mouse-target-setup.sh` keeps that pin only while held, and the expiry is in the env file). `cluster-env.sh` derives the rest. An explicit caller override of any derived name wins. Exception, the #18576 leak guard: loading a DIFFERENT env first unsets every name still equal to the value the previous env resolved, and the census in `cluster-env-selftest.sh` keeps that guard list complete. Run knob, not set by env files: `MOUSE_TARGET_CLAIM_PROBE=skip` skips `mouse-target-setup.sh up`'s claim probe of a new address. The skip is recorded in `mouse-addr.service` and shown by `status` |

Never hardcode a node: source `cluster-env.sh` (directly or via
`deploy-lib.sh`) and use `$FW0`, `$FW1`, `$CLUSTER_LAN_HOST`. For live
measurement, resolve the active node with `active_fw_detect` from
`active-fw.sh`; it returns 1 when no candidate is primary, and callers
must fail closed rather than fall back to a hardcoded node.

## How to add a harness

1. Name it: `test-*.sh` / `wire-*.sh` for a gate, `*-lib.sh` for a sourced
   library (then add it to the named `LIBRARIES` list in
   `scripts/harness-census.sh` — a wildcard would let a runnable harness
   be exempted by renaming), `*-selftest.sh` for the hermetic test,
   `*_test.py` for a Python test.
2. Header first: what it asserts, the falsifiability shape (what it prints
   when the property is false / when the measurement did not happen /
   on an empty set), and its env inputs. Follow any sibling.
3. Source `cluster-env.sh` for addressing; never hardcode instance names,
   IPs, or the iperf target. Live runs take the lock:
   `./test/incus/with-cluster.sh "<purpose>" -- <cmd>`.
4. Wire it: a Makefile recipe that runs it through `harness-result.sh run
   --gate … --adapter …` (add an adapter row + a self-test cell if it is a
   new source), plus a hermetic `*-selftest.sh` registered in
   `scripts/run-selftests.sh`. Until it has a recipe, declare it in
   `HARNESSES.unreached` with a `GATE:`/`COMPOSED:`/`DIAGNOSTIC:` reason —
   that list only shrinks.
5. If it is a new `--gate`, either record a run or declare it in
   `LEDGER_COVERAGE.unreached` (VOID-only counts as unreached; shrink-only).
6. Prove reachability before pushing: `make harness-census`,
   `make selftest`, and the new self-test by name. A gate that cannot say
   which of PASS/FAIL/VOID it is writes no ledger row, and an absent row
   is visible to `ledger_compare.py` — that is the intended failure.

## Cross-checks (decisive)

```
sh scripts/harness-census.sh     # every runnable harness reached or declared
sh scripts/selftest-census.sh    # every self-test invoked by run-selftests.sh
make selftest                    # both censuses + all hermetic legs + ledger lint
CENSUS_VERBOSE=1 sh scripts/harness-census.sh   # the reached set, by name
```
