# Plan: Rolling-upgrade cluster control must target the selected unit (#1983)

## 1. Problem

`xpfd upgrade --rolling --unit <name>` applies systemd actions to the
SELECTED unit but drives the rolling cluster control RPCs against the
hard-coded default daemon address:

- `cmd/xpfd/upgrade.go` — `--unit` flows into `Config{Unit}` AND
  `Sys: upgrade.NewSystem(*unit)` (systemd actions DO honor the unit).
- `pkg/upgrade/rolling.go:96` — `cl := NewCLICluster(cfg.Unit)`.
- `pkg/upgrade/cluster_cli.go:43-45` —
  `func NewCLICluster(unit string) RollingCluster {
   return &grpcCluster{addr: "127.0.0.1:50051", ...} }`
  — the `unit` parameter is silently DISCARDED; `addr` is hard-coded.

So with `--unit xpfd-test`: stop/start/flip hit `xpfd-test`, but
PeerAlive / SyncEstablished / DrainComplete / ForceSecondary /
ResetFailover all hit the DEFAULT daemon on `127.0.0.1:50051`. The drain
predicate evaluates the wrong daemon's RG state and ForceSecondary demotes
the wrong daemon while the cut tears down the other.

## 2. Hypothesis

Production ships exactly one unit (`upgrade.DefaultUnit`), so today no
operator hits the mismatch — but the CLI advertises a contract it does not
enforce, and `--unit xpfd-test` is exactly what an integration test would
use. The minimum sound fix is to REFUSE `--rolling --unit != default`
(fail fast, clear error) so the CLI never silently controls the wrong
daemon. The fuller fix is a unit→endpoint mapping behind an explicit
target object.

## 3. Goal / acceptance criteria

- `--rolling --unit <non-default>` cannot silently drive cluster RPCs
  against `127.0.0.1:50051`.
- Either (A) it is REJECTED with a clear error naming the limitation, or
  (B) the gRPC address is derived from the selected unit.
- Regression test proving the non-default-unit path does NOT reach the
  default address.
- Default-unit rolling behavior is byte-for-byte unchanged.

## 4. Approach

### 4.1 Minimum viable (recommended for engineer-now): REJECT — AT THE CONSTRUCTOR, not just RunRolling

**AGY plan review (NEEDS-MAJOR, FOLDED):** the guard must NOT live only in
`RunRolling`. `NewCLICluster(*unit)` is called from THREE sites, and the
other two also discard `unit`:

- `pkg/upgrade/rolling.go:96` — `RunRolling`
- `cmd/xpfd/upgrade_kernel.go:155` — `xpfd upgrade kernel drain`
  (`DrainAndConfirm`)
- `cmd/xpfd/upgrade_kernel.go:167` — `xpfd upgrade kernel rejoin`
  (`RejoinAndConfirm`)

A guard placed only in `RunRolling` leaves `kernel drain`/`kernel rejoin`
silently targeting `127.0.0.1:50051` under a non-default `--unit`
(VERIFIED: both kernel sub-verbs parse `--unit` at
`upgrade_kernel.go:48` and pass it into `NewCLICluster`). The kernel
sub-verbs ALSO take systemd/host actions keyed to the unit, so the same
wrong-daemon mismatch applies.

**Fix: change `NewCLICluster` to validate the unit and return an error**,
so EVERY call site is covered at one chokepoint:

```go
// NewCLICluster returns a RollingCluster driving the selected unit's xpfd.
// Until a unit->endpoint mapping exists, only the default unit is
// supported; a non-default unit is rejected so cluster RPCs can never
// silently target the wrong daemon while systemd actions hit another.
func NewCLICluster(unit string) (RollingCluster, error) {
    if unit != "" && unit != DefaultUnit {
        return nil, fmt.Errorf("cluster control for systemd unit %q is "+
            "unsupported (rolling/kernel-drain RPCs target the default "+
            "daemon at 127.0.0.1:50051; a non-default unit's control "+
            "endpoint is not yet mapped)", unit)
    }
    return &grpcCluster{addr: "127.0.0.1:50051", dialTimeout: 5 * time.Second}, nil
}
```

All three call sites propagate the error (RunRolling already returns
error; the two kernel sub-verbs print + `os.Exit(1)` like their siblings).
This is the single-chokepoint fix AGY recommends and is strictly safer than
three separate CLI-boundary guards (a future fourth caller is covered
automatically).

This closes the correctness hole immediately and is fully testable. The
systemd-action side already honors the unit, so a reject is the only safe
posture until the endpoint mapping exists.

### 4.2 Fuller fix (needs-research half): explicit target object

Introduce `pkg/upgrade/clusterclient` with:

```go
type Target struct {
    Unit        string
    GRPCAddr    string        // default "127.0.0.1:50051"
    DialTimeout time.Duration
    // future: TLS/auth material
}
func New(t Target) RollingCluster { ... }
```

`NewCLICluster(unit)` is replaced by `clusterclient.New(targetForUnit(unit))`
where `targetForUnit` maps a unit name to its control endpoint. For now the
only known mapping is `DefaultUnit -> 127.0.0.1:50051`; an unknown unit
either errors or accepts an explicit `--grpc-addr` override (added for
integration tests so address selection is not hidden inside a
constructor).

**Decision deferred to plan review:** ship 4.1 (reject) as the bug fix and
file 4.2 (target object + mapping) as a follow-up enhancement, OR do both
in one PR. The engineering-style "narrow scope" principle favors shipping
the reject as the bug fix and tracking the mapping separately, UNLESS the
mapping is trivial enough to land together. Given there is only one real
unit today, 4.1 alone fully closes the correctness defect; 4.2 is a
forward-looking modularity improvement.

## 5. Alternatives rejected

- **Leave the parameter discarded.** Silent wrong-daemon control — a
  latent foot-gun the moment any tooling passes `--unit`. Rejected.
- **Map unit→addr by string heuristic (e.g. append unit to a port).**
  No stable mapping exists; guessing is worse than rejecting. Rejected.
- **Make `NewCLICluster` panic on non-default unit.** A panic in a CLI
  path is hostile UX; a returned error with guidance is correct.

## 6. Files touched

- `pkg/upgrade/cluster_cli.go` (`NewCLICluster` returns `(RollingCluster,
  error)`; rejects non-default unit at the single chokepoint)
- `pkg/upgrade/rolling.go:96` (handle the new error from `NewCLICluster`)
- `cmd/xpfd/upgrade_kernel.go:155,167` (handle the new error in `drain`
  and `rejoin`)
- `pkg/upgrade/cluster_cli_test.go` / new test (non-default-unit reject for
  all three callers; dial-attempt recorder)
- NEW `pkg/upgrade/clusterclient/` (only if 4.2 is in scope)
- `cmd/xpfd/upgrade.go` (optional `--grpc-addr` if 4.2)
- `docs/in-place-upgrade.md` (document the unit/endpoint contract)

## 7. Test strategy

- Reject path: `RunRolling` with `cfg.Unit = "xpfd-test"` returns the
  refusal error WITHOUT dialing — assert via a `RollingCluster` factory
  seam that records whether a dial was attempted (strong: the test fails
  if the code reaches the gRPC client). The existing rolling tests already
  inject a fake cluster, so the seam exists.
- Default path: `cfg.Unit = DefaultUnit` (and empty) proceeds exactly as
  today (regression).
- If 4.2: a table test mapping unit→addr, plus `--grpc-addr` override.

## 8. Invariants

- Default-unit rolling is unchanged.
- No code path constructs a cluster client that controls a different
  daemon than the systemd actions target (the core invariant the bug
  violated).

## 9. Risk

LOW for 4.1 (reject) — it only adds a guard on a path that is broken
today. MEDIUM-LOW for 4.2 (new package + ctor wiring), behavior-preserving
for the default unit.

## 10. Rollout / validation

- Unit tests (above).
- `make test-failover` is the HA gate per CLAUDE.md — but note this change
  touches the rolling DRIVER's target selection, not VRRP/session-sync.
  Run `make test-failover` to confirm no regression in the default-unit
  rolling path if 4.2 rewires the constructor; for 4.1 (pure guard) a unit
  test suffices, state the reasoning in the PR body.

## 11. Disposition

engineer-now for 4.1 (reject) — trivial, safe, closes the defect. 4.2
(endpoint mapping / clusterclient package) as a tracked follow-up unless
review judges it small enough to ride along.

## Reviewer verdicts

- Claude SMR: PLAN READY (4.1; 4.2 follow-up).
- AGY companion: PLAN NEEDS-MAJOR (r1) — guard only in RunRolling leaves
  `kernel drain`/`kernel rejoin` (`upgrade_kernel.go:155,167`) silently
  targeting the default endpoint. FOLDED: moved the guard into
  `NewCLICluster` (returns error) so all three call sites are covered.
  Re-verdict on the folded plan: expected PLAN YES.
- Codex companion: _pending_
