# CI gate contract: what ordinary green CI examines (and what it does not)

> Scope note (#12228): this is a verification-coverage record only. No
> shipped production regression is alleged, and the Go tests / Rust check
> below are not claimed worthless. The gap this file closes is that a
> Rust-test-only regression in policy/NAT/HA packet behavior could pass
> the ordinary green gate unobserved, with no contract saying so.

`.github/workflows/test.yml` (`CI tests`) runs on every PR. Its three
status contexts—`CI tests / Harness census and self-test`, `CI tests / Go
build and affected tests`, and `CI tests / Rust workspace compile
check`—do not block merges until required in master branch rulesets. This
contract lists every job command in that workflow and the issue-relevant
manual policy/NAT/HA dataplane gates it does not run, plus where results
are recorded.

## What ordinary green CI runs

| Job | Command | Source of truth |
|---|---|---|
| Harness census and self-test | `sh scripts/harness-census.sh`, then `bash ./test/incus/harness-census-selftest.sh` (runnable-harness reachability census and mutation self-test; examines no packets) | `test.yml` job `census` |
| Go build and affected tests | `go build ./...`, then `bash scripts/ci_affected_go_tests.sh "$BASE_SHA" "$HEAD_SHA"` (changed packages + reverse dependents) | `test.yml` job `go` (`Go build and affected tests`) |
| Rust workspace compile check | `cargo check --manifest-path userspace-dp/Cargo.toml --workspace --all-targets` | `test.yml` job `rust`, step `Check Rust workspace and all targets` |

That is the whole `CI tests` workflow gate. In particular:

- CI compiles the Rust workspace; it does **not** run the Rust
  dataplane test suite. The suite is red on master (tracked by #11649; the
  policy-revocation slice is #12262). The workflow header's
  `cargo test --workspace` command is a future CI promotion goal once green;
  it is not the current manual suite command. That gate is `make test-rust`
  as detailed below.

## Manual policy/NAT/HA dataplane gates (out of scope of the green gate)

A green CI run says nothing about the issue-relevant packet-level gates
below; these tables are not a census of every Makefile integration target.
The Rust suite is developer-invoked, runs without a cluster, and reports to
terminal output. The `harness-result.sh run`-wrapped gates record one JSON
row per invocation in `test/results/ledger.d/<run_id>.json` (the tracked
record; see the one-row-per-run contract in `test/incus/harness-result.sh`).

### Rust dataplane test suite

| Gate | Command | Results |
|---|---|---|
| `make test-rust` | Pinned-toolchain `cargo check --benches` (leg 0), full release `cargo test --bins --tests` with `--test-threads=1` (leg 1), debug-leg oracle census + one debug argv (leg 2); see the `test-rust` recipe and its `check-userspace-dt-needed` prerequisite (#10204 release relink + DT_NEEDED check) in `Makefile` | Terminal output; no wire-ledger row. Durable result location is described below. |

Record each manual Rust run durably in the associated `docs/log/<issue>.md`
entry: include the commit SHA, exact command, PASS/FAIL, and a concise result
summary. `make test-rust` does not write to `test/results/ledger.d/`; that
ledger is for the harness-wrapped wire/cluster gates below. Do not treat
terminal output alone as a durable result record.

`query_strategy` in `userspace-dp/src/policy_prop_tests/strategy.rs`
generates synthetic packet tuples, and `generated_config_strategy` in that
file constructs synthetic policy configurations, rather than observed
forwarding, so the prop-test leg cannot substitute for the wire gates below.

### Wire dataplane gates

These loss-cluster gates need `loss:xpf-userspace-fw0/fw1` and the #1875
lock cell (unless their Makefile wrapper already owns it). Their sibling
`-lib` targets are hermetic self-tests (no cluster, no lock), proving the
harness rather than observed wire behavior. For the three gates with zero
ledger rows (#11056: `wire_policy_deny`, `wire_hostinbound_deny`,
`wire_appmatch_twins`), `make test-wire-gate-hermetic-lib` additionally
drives the capture reductions against real tcpdump transcripts
(`test/fixtures/wire/`), the gates' `--fixture` modes over measured
transcripts, and — when run privileged — the full probe→drop→capture→
reduction→verdict pipeline in an isolated netns; the fixture-narrowing leg
is bound in-process by the `pkg/policymatch` `#11056` tests against the
committed cluster baseline. None of that substitutes for the live rows: the
three gates stay declared unreached in
`test/incus/LEDGER_COVERAGE.unreached` until the operator records them.

`make test-wire-properties` is different: it uses local Incus instances
`xpf-fw`, `trust-host`, and `untrust-host`, not the shared loss cluster,
and does not take the #1875 lock. Despite the wrapper's `--hermetic` flag,
it still needs those instances; see `test/incus/test-wire-properties.sh`.

| Gate | Makefile target | Wire proof |
|---|---|---|
| Host-inbound smoke (matrix) | `make test-host-inbound` (the `test-host-inbound` recipe in `Makefile`) | On-wire host-inbound probes against committed config; separate gate from the failover leg |
| Host-inbound smoke (failover) | `make test-host-inbound-failover` (the `test-host-inbound-failover` recipe in `Makefile`) | Same smoke with the HA leg: RG1+RG2 move to the peer and back under the #1875 lock |
| Wire policy-deny | `make test-wire-policy-deny` (the `test-wire-policy-deny` recipe in `Makefile`) | Offered probes leak 0 across deny policy; `WIRE_GATE wire_policy_deny` line per invocation |
| Wire appmatch twins | `make test-wire-appmatch-twins` (the `test-wire-appmatch-twins` recipe in `Makefile`) | Twin-flow application-match agreement on the wire |
| Wire zone matrix | `make test-wire-zone-matrix` (the `test-wire-zone-matrix` recipe in `Makefile`) | Zone-pair matrix verdicts observed on the wire |
| Wire hostinbound-deny | `make test-wire-hostinbound-deny` (the `test-wire-hostinbound-deny` recipe in `Makefile`) | Host-inbound deny verdicts observed on the wire |
| Wire conntrack lifecycle | `make test-wire-conntrack-lifecycle` (the `test-wire-conntrack-lifecycle` recipe in `Makefile`) | Create/witness/evict lifecycle observed on the wire |
| Wire routing separation | `make test-wire-routing-separation` (the `test-wire-routing-separation` recipe in `Makefile`) | Routing-separation probes observed on the wire |
| Wire properties | `make test-wire-properties` (the `test-wire-properties` recipe in `Makefile`) | IPv6 transit plus a DF/1500-byte probe that accepts either PMTUD feedback or ordinary delivery (a passing run does not necessarily exercise reflection), through the local Incus hosts (see the PMTUD Reflection and Dual-Stack IPv6 Transit sections in `test/incus/test-wire-properties.sh`) |
| Connectivity smoke | `make test-connectivity` (the `test-connectivity` recipe in `Makefile`) | Cross-zone policy permit + SNAT (IPv4/IPv6) and cluster session sync |

### HA continuity and NAT failover gates

These cluster smokes also run outside ordinary green CI and write ledger
rows through `harness-result.sh`:

| Gate | Makefile target | Packet-level scope |
|---|---|---|
| Single failover | `make test-failover` (the `test-failover` recipe in `Makefile`) | Connectivity through a node reboot and HA handoff |
| Double failover | `make test-double-failover` (the `test-double-failover` recipe in `Makefile`) | Connectivity through sequential node failures and handoffs |
| Active/active failover | `make test-active-active` (the `test-active-active` recipe in `Makefile`) | Per-RG forwarding while RG ownership is split |
| Stress failover | `make test-stress-failover` (the `test-stress-failover` recipe in `Makefile`) | Repeated failover cycles with traffic |
| HA crash | `make test-ha-crash` (the `test-ha-crash` recipe in `Makefile`) | Traffic behavior across a hard-crash/hung-node recovery |
| Persistent NAT failover | `make test-persistent-nat-failover` (the `test-persistent-nat-failover` recipe in `Makefile`) | Persistent NAT behavior across RG failover |
| Chained crash | `make test-chained-crash` (the `test-chained-crash` recipe in `Makefile`) | Traffic behavior across chained hard resets and recoveries |
| Rolling upgrade | `make test-rolling-upgrade` (the `test-rolling-upgrade` recipe in `Makefile`, #12200) | Version-asserted traffic through two rolling upgrade cuts |

Results for every wrapped run in the tables above live in
`test/results/ledger.d/` (one `<run_id>.json` per run, #8346);
`make harness-ledger-lint` fails on a zero-row or unparseable ledger, and
`make harness-coverage` reports the per-gate census. A claimed wrapped
packet-level run with no ledger row was not measured.

## The contract, in one paragraph

If it is not in the "What ordinary green CI runs" table, a green `CI tests`
run did not examine it; `.github/workflows/close-keyword-lint.yml` also runs
on every PR, but checks only PR text and commit messages. In particular: **a
Rust-test-only policy/NAT/HA regression is explicitly out of scope of the
ordinary green gate** until the workflow header's promotion note ("Keep the
all-targets compile check until `cargo test --workspace` is green") is
satisfied. Gates that can catch it include `make test-rust` (suite output)
and the cluster wire gates above (`test/results/ledger.d/` rows). Silence was
the defect (#9052); a green run whose contract names what it did not examine
is not a clean board.
