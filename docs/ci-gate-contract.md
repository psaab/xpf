# CI gate contract: what ordinary green CI examines (and what it does not)

> Scope note (#12228): this is a verification-coverage record only. No
> shipped production regression is alleged, and the Go tests / Rust check
> below are not claimed worthless. The gap this file closes is that a
> Rust-test-only regression in policy/NAT/HA packet behavior could pass
> the ordinary green gate unobserved, with no contract saying so.

`.github/workflows/test.yml` is the ordinary green gate: it reports on
every PR but does not block merges until its status contexts are required
in master branch rulesets. This contract records the complete list of
commands a green run examined, the issue-relevant manual policy/NAT/HA
dataplane gates it does not run, and where their results are recorded.

## What ordinary green CI runs

| Job | Command | Source of truth |
|---|---|---|
| Go build and affected tests | `go build ./...`, then `bash scripts/ci_affected_go_tests.sh "$BASE_SHA" "$HEAD_SHA"` (changed packages + reverse dependents; the full Go suite is red on master) | `test.yml:22-40` |
| Rust workspace compile check | `cargo check --manifest-path userspace-dp/Cargo.toml --workspace --all-targets` | `test.yml:42-59` |

That is the whole gate. In particular:

- CI compiles the Rust workspace; it does **not** run the Rust
  dataplane test suite. The suite is red on master. The workflow header's
  `cargo test --workspace` command is a future CI promotion goal once green;
  it is not the current manual suite command. That gate is `make test-rust`
  as detailed below.

## Manual policy/NAT/HA dataplane gates (out of scope of the green gate)

A green CI run says nothing about the issue-relevant gates below; these
tables are not a census of every Makefile integration target. The Rust
suite is developer-invoked, runs without a cluster, and reports to
terminal output. The `harness-result.sh run`-wrapped gates record one JSON
row per invocation in `test/results/ledger.d/<run_id>.json` (the tracked
record; see `test/incus/harness-result.sh:2-10`).

### Rust dataplane test suite

| Gate | Command | Results |
|---|---|---|
| `make test-rust` | Pinned-toolchain `cargo check --benches` (leg 0), full release `cargo test --bins --tests` with `--test-threads=1` (leg 1), debug-leg oracle census + one debug argv (leg 2); see `Makefile:397-406` | Terminal output; no wire-ledger row. Durable result location is described below. |

Record each manual Rust run durably in the associated `docs/log/<issue>.md`
entry: include the commit SHA, exact command, PASS/FAIL, and a concise result
summary. `make test-rust` does not write to `test/results/ledger.d/`; that
ledger is for the harness-wrapped wire/cluster gates below. Do not treat
terminal output alone as a durable result record. The suite was not run for
#12228, so this issue log does not claim a Rust result.


`userspace-dp/src/policy_prop_tests/strategy.rs:48-73` additionally
builds synthetic policy configurations rather than observed forwarding,
so the prop-test leg cannot substitute for the wire gates below.

### Wire dataplane gates

These loss-cluster gates need `loss:xpf-userspace-fw0/fw1` and the #1875
lock cell (unless their Makefile wrapper already owns it). Their sibling
`-lib` targets are hermetic self-tests (no cluster, no lock), proving the
harness rather than observed wire behavior.

`make test-wire-properties` is different: it uses local Incus instances
`xpf-fw`, `trust-host`, and `untrust-host`, not the shared loss cluster,
and does not take the #1875 lock. Despite the wrapper's `--hermetic` flag,
it still needs those instances; see `test/incus/test-wire-properties.sh:25-31`.

| Gate | Makefile target | Wire proof |
|---|---|---|
| Host-inbound smoke (matrix) | `make test-host-inbound` (`Makefile:1017-1021`) | On-wire host-inbound probes against committed config; separate gate from the failover leg |
| Host-inbound smoke (failover) | `make test-host-inbound-failover` (`Makefile:1022-1026`) | Same smoke with the HA leg: RG1+RG2 move to the peer and back under the #1875 lock |
| Wire policy-deny | `make test-wire-policy-deny` (`Makefile:1030-1034`) | Offered probes leak 0 across deny policy; `WIRE_GATE wire_policy_deny` line per invocation |
| Wire appmatch twins | `make test-wire-appmatch-twins` (`Makefile:1038-1042`) | Twin-flow application-match agreement on the wire |
| Wire zone matrix | `make test-wire-zone-matrix` (`Makefile:1046-1050`) | Zone-pair matrix verdicts observed on the wire |
| Wire hostinbound-deny | `make test-wire-hostinbound-deny` (`Makefile:1054-1058`) | Host-inbound deny verdicts observed on the wire |
| Wire conntrack lifecycle | `make test-wire-conntrack-lifecycle` (`Makefile:1062-1067`) | Create/witness/evict lifecycle observed on the wire |
| Wire routing separation | `make test-wire-routing-separation` (`Makefile:1074-1080`) | Routing-separation probes observed on the wire |
| Wire properties | `make test-wire-properties` (`Makefile:1300-1304`) | PMTUD reflection and IPv6 transit, exercised through the local Incus hosts (see `test/incus/test-wire-properties.sh:80-98`) |

### HA continuity and NAT failover gates

These cluster smokes also run outside ordinary green CI and write ledger
rows through `harness-result.sh`:

| Gate | Makefile target | Packet-level scope |
|---|---|---|
| Single failover | `make test-failover` (`Makefile:1306-1309`) | Connectivity through a node reboot and HA handoff |
| Double failover | `make test-double-failover` (`Makefile:1312-1315`) | Connectivity through sequential node failures and handoffs |
| Active/active failover | `make test-active-active` (`Makefile:1318-1321`) | Per-RG forwarding while RG ownership is split |
| Stress failover | `make test-stress-failover` (`Makefile:1324-1327`) | Repeated failover cycles with traffic |
| HA crash | `make test-ha-crash` (`Makefile:1330-1333`) | Traffic behavior across a hard-crash/hung-node recovery |
| Persistent NAT failover | `make test-persistent-nat-failover` (`Makefile:1350-1353`) | Persistent NAT behavior across RG failover |
| Chained crash | `make test-chained-crash` (`Makefile:1387-1390`) | Traffic behavior across chained hard resets and recoveries |

Results for every wrapped run in the tables above live in
`test/results/ledger.d/` (one `<run_id>.json` per run, #8346);
`make harness-ledger-lint` fails on a zero-row or unparseable ledger, and
`make harness-coverage` reports the per-gate census. A claimed wrapped
packet-level run with no ledger row was not measured.

## The contract, in one paragraph

If it is not in the "What ordinary green CI runs" table, a green CI run
did not examine it. In particular: **a Rust-test-only policy/NAT/HA
regression is explicitly out of scope of the ordinary green gate** until
the `test.yml:10-12` promotion lands. The gates that would catch it are
`make test-rust` (suite output) and the cluster wire gates above
(`test/results/ledger.d/` rows). Silence was the defect (#9052); a green
run whose contract names what it did not examine is not a clean board.
