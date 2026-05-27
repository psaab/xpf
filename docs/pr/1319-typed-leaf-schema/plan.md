# #1319 Phase 3a — typed leaf-value schema for chassis cluster numeric knobs

**Status:** DRAFT v1 — pending adversarial plan review (Codex + AGY hostile)

## Issue framing

#1319 tracks a multi-phase rollout of typed leaf-value schema for
CLI completion (`?` help) + commit-check validation. The infrastructure
(`pkg/cmdtree/schema_validate.go`, `pkg/config/schema_validators.go`)
and Phase 1 + Phase 2 (class-of-service schedulers — `transmit-rate`,
`priority`, `buffer-size`) already shipped on master via PR #1320 and
follow-ons. Issue is still open because Phase 3 (firewall filters,
interface addresses, chassis cluster knobs) is unstarted.

This PR is **Phase 3a — chassis cluster numeric/enum knobs**. The
schedulers subtree validates the typed-leaf design under a high-blast-
radius surface; chassis cluster knobs are the next-most-impactful
target because silent garbage on an HA timing parameter is operator-
visible after a real failover, not at commit time.

The other Phase 3 targets in the issue body (firewall filter
forwarding-class cross-reference, interface IPv4/IPv6 CIDR validation)
have richer semantics — cross-reference resolution and address parsing
— and are deliberately scoped out of this PR. They're separate Phase 3
increments because their validators need different infrastructure
(`Config`-aware lookups, IP parsing) and each PR should land
independently smoke-testable.

## Honest scope/value framing

The chassis-cluster numeric knobs are HA-critical timing parameters:
`heartbeat-interval` (ms), `heartbeat-threshold` (count),
`reth-advertise-interval` (ms), `takeover-hold-time` (ms),
`reth-count` (count), `cluster-id` (int), and the per-redundancy-group
`priority`, `hold-down-interval`, `gratuitous-arp-count`. Today the
compiler in `pkg/config/compiler_system.go:855-955` runs
`strconv.Atoi(v); if err == nil { store }` for every one of these and
silently leaves the struct field at zero on garbage input, which is
worse than the schedulers case: many of these fields treat 0 as
"use default", so `set chassis cluster heartbeat-interval abc;
commit` silently rolls the operator back to the default 100ms
heartbeat instead of the intended override, with no diagnostic.

**Operator impact**: a typo on `reth-advertise-interval` or
`heartbeat-interval` does not show up at commit time and does not
show up at boot — it shows up the first time the cluster fails over,
when the operator wonders why takeover is slow or why the cluster is
flapping. This is the exact failure mode #1319 was filed to eliminate.

**Code impact**: ~150 LOC of new typed-node declarations in
`pkg/cmdtree/tree.go` (chassis-cluster subtree), ~80 LOC of walker
code in `schema_validate.go` (analogous to `walkSchedulers`), zero
changes to the existing compiler (the silently-coerce-to-zero parsers
stay — SchemaValidate runs first; any invalid value is rejected before
the compiler ever sees it).

If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict. (No perf claim attached — this is
correctness-only.) Likewise if reviewers conclude the typed-walker
pattern doesn't scale beyond the schedulers case, PLAN-KILL is the
right outcome.

## What's already shipped / partially batched

- `pkg/cmdtree/schema_validate.go`: `SchemaValidate(tree, cfg)` entry
  point + `walkSchedulers` + `walkSchedulerInstance` + `validateSchedulerLeaf`.
  The entry function currently early-returns unless the AST has a
  `class-of-service` child. Phase 3a adds a `chassis` early-return
  branch in parallel.
- `pkg/cmdtree/tree.go`: `ValueType` enum (`ValueAny`, `ValueRate`,
  `ValueByteSizeOrPercent`, `ValueInteger`, `ValueEnumOf`),
  `Node.{ValueType, ValueDesc, ValueExamples, Validator}` fields,
  `Node.IsTypedLeaf()`, `Node.ValueType.Placeholder()`, plus the
  schedulers-only `ConfigClassOfServiceSchedulers` subtree.
- `pkg/config/schema_validators.go`: `ValidateRate`,
  `ValidateByteSize`, `ValidateByteSizeOrPercent`, `ValidateInteger(min,max)`,
  `ValidateEnum(allowed)`, `ValidatePercent(min,max)`.
- `pkg/configstore/store.go:182,194`: `cmdtree.SchemaValidate(expanded, nil)`
  is called from both `commitCheck` paths before compile, so any new
  typed leaf is enforced at commit-check without further wiring.
- `pkg/cmdtree/schema_validate_test.go:TestSchemaValidate_AcceptsLegacyDPDKSubStanza`:
  regression gate from Codex r6 v3.3 for #1528. **Any new walker must
  tolerate orphaned legacy DPDK sub-stanzas alongside chassis nodes.**
  Phase 3a's chassis walker must not trip on legacy/unknown chassis
  children.

## Concrete design

### 1. New cmdtree typed node — `ConfigChassisCluster`

Add to `pkg/cmdtree/tree.go`, alongside `ConfigClassOfServiceSchedulers`:

```go
// ConfigChassisCluster is the typed-leaf schema for
// `set chassis cluster ...` (#1319 Phase 3a). Numeric knobs are typed
// as ValueInteger with explicit (min,max) ranges; the cluster-id and
// reth-count have hard upper bounds that the compiler already
// enforces silently (cluster-id > 255 wraps, reth-count > N truncates).
//
// Like ConfigClassOfServiceSchedulers, this is opt-in per leaf — the
// SchemaValidate walker rejects only leaves with non-ValueAny
// ValueType. Unknown chassis-cluster children (legacy / future) are
// ignored, preserving rolling-upgrade tolerance.
var ConfigChassisCluster = &Node{
    Desc: "Chassis cluster (HA) configuration",
    Children: map[string]*Node{
        "cluster-id": {
            Desc:          "Cluster identity (used to derive RETH virtual MAC)",
            ValueType:     ValueInteger,
            ValueDesc:     "Integer 1..255",
            ValueExamples: []string{"1", "42"},
            Validator:     config.ValidateInteger(1, 255),
        },
        "reth-count": {
            Desc:          "Number of redundant Ethernet interfaces",
            ValueType:     ValueInteger,
            ValueDesc:     "Integer 0..128",
            ValueExamples: []string{"2", "4"},
            Validator:     config.ValidateInteger(0, 128),
        },
        "heartbeat-interval": {
            Desc:          "Heartbeat send interval (milliseconds)",
            ValueType:     ValueInteger,
            ValueDesc:     "Integer 50..2000 ms (typical: 100-200)",
            ValueExamples: []string{"100", "200", "500"},
            Validator:     config.ValidateInteger(50, 2000),
        },
        "heartbeat-threshold": {
            Desc:          "Missed-heartbeat threshold before peer is lost",
            ValueType:     ValueInteger,
            ValueDesc:     "Integer 3..255 (typical: 5)",
            ValueExamples: []string{"3", "5", "10"},
            Validator:     config.ValidateInteger(3, 255),
        },
        "reth-advertise-interval": {
            Desc:          "RETH VRRP advertisement interval (milliseconds)",
            ValueType:     ValueInteger,
            ValueDesc:     "Integer 10..1000 ms (default 30; <30 ms is sub-RFC and risks flap)",
            ValueExamples: []string{"30", "100", "200"},
            Validator:     config.ValidateInteger(10, 1000),
        },
        "takeover-hold-time": {
            Desc:          "Additional delay after RG becomes primary (milliseconds)",
            ValueType:     ValueInteger,
            ValueDesc:     "Integer 0..60000 ms (0 = immediate)",
            ValueExamples: []string{"0", "500", "1500"},
            Validator:     config.ValidateInteger(0, 60_000),
        },
        // Per-RG numeric knobs live under redundancy-group <id> — those
        // are an inner walker concern, see walkRedundancyGroup below.
        "redundancy-group": ConfigChassisClusterRedundancyGroup,
        // Presence-only knobs (no value) are listed for ?-help.
        "control-link-recovery":         {Desc: "Auto-recover control-link breakage"},
        "configuration-synchronize":     {Desc: "Forward config sync from primary to secondary"},
        "nat-state-synchronization":     {Desc: "Sync NAT bindings across nodes"},
        "ipsec-session-synchronization": {Desc: "Sync IPsec SAs across nodes"},
        "hitless-restart":               {Desc: "Preserve sessions across daemon restart"},
        "no-reth-vrrp":                  {Desc: "Disable RETH VRRP (control-link only)"},
        "no-private-rg-election":        {Desc: "Disable private RG election (legacy VRRP)"},
    },
}

// Per-RG typed subtree for `redundancy-group <id> { ... }`.
var ConfigChassisClusterRedundancyGroup = &Node{
    Desc: "Redundancy group configuration",
    Children: map[string]*Node{
        "<rg-id>": {
            Desc: "Redundancy group instance",
            Children: map[string]*Node{
                "node": {
                    Desc: "Per-node configuration",
                    Children: map[string]*Node{
                        "<node-id>": {
                            Desc: "Node identifier (0 or 1)",
                            Children: map[string]*Node{
                                "priority": {
                                    Desc:          "Election priority (higher wins)",
                                    ValueType:     ValueInteger,
                                    ValueDesc:     "Integer 1..255",
                                    ValueExamples: []string{"100", "200"},
                                    Validator:     config.ValidateInteger(1, 255),
                                },
                            },
                        },
                    },
                },
                "hold-down-interval": {
                    Desc:          "Failback hold-down (seconds)",
                    ValueType:     ValueInteger,
                    ValueDesc:     "Integer 0..1800 s",
                    ValueExamples: []string{"0", "60", "300"},
                    Validator:     config.ValidateInteger(0, 1800),
                },
                "gratuitous-arp-count": {
                    Desc:          "GARPs to send after RG becomes primary",
                    ValueType:     ValueInteger,
                    ValueDesc:     "Integer 1..16",
                    ValueExamples: []string{"4", "8"},
                    Validator:     config.ValidateInteger(1, 16),
                },
                "preempt": {Desc: "Allow higher-priority node to preempt"},
            },
        },
    },
}
```

Then wire `ConfigChassisCluster` into `ConfigTopLevel["set"].Children`
under a new `"chassis"` entry. (`chassis cluster <knob>` is the only
`set chassis ...` subtree this PR types; other chassis knobs stay
untyped.)

### 2. New walker — `walkChassisCluster`

Add to `pkg/cmdtree/schema_validate.go`, parallel to `walkSchedulers`:

```go
// In SchemaValidate, after the schedulers walk:
chassisNode := tree.FindChild("chassis")
if chassisNode != nil {
    for _, clusterNode := range chassisNode.FindChildren("cluster") {
        if err := walkChassisCluster(clusterNode, ConfigChassisCluster, cfg); err != nil {
            return err
        }
    }
}
```

`walkChassisCluster` handles both flat-set and hierarchical shape the
same way `walkSchedulers` does:

- **Flat set**: `set chassis cluster heartbeat-interval 100` →
  `Keys=["cluster","heartbeat-interval"]` with child `Keys=["100"]`.
- **Hierarchical**: `chassis cluster { heartbeat-interval 100; }` →
  `Keys=["cluster"]` with children where each leaf is
  `Keys=["heartbeat-interval"]` + child `Keys=["100"]`.

The walker descends one level into `redundancy-group <id> node <id>
priority <value>` to validate per-RG/per-node integer leaves.

### 3. Unchanged: existing compiler

`pkg/config/compiler_system.go:855-955` keeps its silent-zero-on-error
contract. SchemaValidate runs before compile (per
`configstore/store.go:182,194`), so any invalid value is rejected
before the compiler ever sees it. Existing behaviour for `0` (use
default) is preserved because `0` is a valid integer in every range
above except `cluster-id` (which has min=1, correctly disallowing
the silent-zero case for cluster-id; the others permit 0).

## Public API preservation

- `cmdtree.SchemaValidate(tree, cfg)` — signature unchanged.
- `cmdtree.Node` — no field additions or removals.
- `pkg/config` ValidateInteger/ValidateEnum — unchanged.
- `ConfigClassOfServiceSchedulers` — unchanged.
- `ConfigTopLevel` — adds one child key `"chassis"`. The set-mode
  completer already walks unknown subtrees through the legacy
  `ast.go` schemaNode fallback; this addition only adds typed value
  semantics for the new chassis leaves and does not remove anything.

## Hidden invariants the change must preserve

1. **Rolling-upgrade tolerance.** Stored configs that include legacy
   `chassis cluster <unknown-child>` (e.g. removed in future, or from a
   future version we haven't shipped yet) must not be rejected. The
   walker must ignore unknown children, same as `walkSchedulers` does
   for unknown leaves.

2. **Both AST shapes.** Both `set chassis cluster heartbeat-interval
   100` (flat) and `chassis { cluster { heartbeat-interval 100; } }`
   (hierarchical) must validate. Test fixtures must cover both.

3. **${node} variable expansion** — `pkg/configstore/store.go` calls
   `cmdtree.SchemaValidate(expanded, nil)` AFTER `ExpandGroupsWithVars`,
   so `${node}` in a chassis-cluster leaf would already be expanded to
   the node ID before the validator sees it. **No new ${node} handling
   needed.** Test fixture must use a non-cluster fixture (cluster
   compilation requires `/etc/xpf/node-id`) or `commit check` on the
   already-expanded form.

4. **Zero-on-error semantics for fields not yet typed.** Per-RG
   `<node-id>` is the loop variable, not a value to validate. Walker
   must NOT validate node-id as a numeric range (Junos accepts
   `local`/`peer` aliases for `node 0`/`node 1` in some versions; the
   compiler maps both). Leave node-id as ValueAny; only the
   `priority` integer leaf gets validated.

5. **Empty `set chassis cluster` clause must not trigger validation.**
   The Phase 2 schedulers walker correctly returns nil for an empty
   schedulers child; the chassis walker must do the same.

6. **Legacy DPDK regression gate** (`TestSchemaValidate_AcceptsLegacyDPDKSubStanza`)
   must still pass — it sets `chassis`-unrelated DPDK fixtures, but
   the walker must not over-grow and start rejecting DPDK shape if a
   future fixture adds chassis + DPDK together.

## Risk assessment

| Risk class                  | Level | Notes                                                              |
| --------------------------- | ----- | ------------------------------------------------------------------ |
| Behavioral regression       | LOW   | Validator opt-in per leaf; legacy leaves stay ValueAny.            |
| Lifetime / borrow shape     | N/A   | Pure Go.                                                            |
| Performance regression      | LOW   | Walker runs once at commit-check; tens of nodes; sub-microsecond. |
| Architectural mismatch      | MED   | Subtree-specific walker pattern. If reviewers conclude this    |
|                             |       | doesn't scale to firewall filters (cross-reference), PLAN-KILL  |
|                             |       | the per-subtree walker approach in favour of a generic         |
|                             |       | tree-walk-against-cmdtree algorithm.                                |

## Test plan

- `cargo build` not in scope (Go-only change).
- `go test ./pkg/cmdtree/... ./pkg/config/... ./pkg/configstore/...`
  — full pass, including `TestSchemaValidate_AcceptsLegacyDPDKSubStanza`.
- New tests in `pkg/cmdtree/schema_validate_test.go`:
  - `TestSchemaValidate_ChassisCluster_FlatSetRejectsGarbage`
    — `set chassis cluster heartbeat-interval abc` returns descriptive error.
  - `TestSchemaValidate_ChassisCluster_HierarchicalRejectsGarbage`
    — same via parsed hierarchical block.
  - `TestSchemaValidate_ChassisCluster_AcceptsValidIntegers`
    — every typed leaf accepts a value in the documented range.
  - `TestSchemaValidate_ChassisCluster_RangeBoundsRejected`
    — out-of-range integer fails (e.g. `heartbeat-interval 3000`
    when max=2000).
  - `TestSchemaValidate_ChassisCluster_PerRGPriorityRejected`
    — `set chassis cluster redundancy-group 0 node 0 priority abc`.
  - `TestSchemaValidate_ChassisCluster_IgnoresUnknownLeaves`
    — `set chassis cluster fictional-knob whatever` does NOT fail.
  - `TestSchemaValidate_ChassisCluster_EmptyClause`
    — `set chassis cluster` with no children does NOT fail.
- Smoke on the loss userspace cluster:
  - **Pass A — CoS disabled, v4+v6 × push+reverse + `-P 12 -R`** for
    line-rate regression detection. The chassis-cluster change is a
    pure commit-time validator; the runtime config of the smoke
    cluster is unaffected. Smoke confirms the cluster still comes up
    cleanly with the new validator gated on.
  - **Pass B — CoS enabled, per-class 5201-5206 × v4+v6 × push+reverse**.
    Same rationale; CoS smoke continues to exercise the Phase 2
    schedulers walker.

## Out of scope (explicitly)

- **Firewall filter typed leaves** — `forwarding-class <name>` cross-
  reference against defined forwarding classes, `dscp <name|number>`
  enum + numeric. Distinct PR; needs `Config`-aware cross-reference
  validator infrastructure.
- **Interface address typed leaves** — `family inet address <CIDR>` /
  `family inet6 address <CIDR>` requires IPv4/IPv6 CIDR parser
  validators. Distinct PR; closely tied to IP parsing in
  `pkg/config/compiler_interfaces.go`.
- **Schema-aware diff/show formatters** — listed out-of-scope in #1319
  itself.
- **`peer-fencing` / `control-interface` / `fabric-interface` typed
  leaves** — these are string interface-name leaves whose validator
  would cross-reference the configured interface list. Same
  cross-reference-validator-infrastructure prerequisite as firewall
  filter; defer to a separate PR.
- **`cluster-id` enforcement of the documented vSRX range.** Different
  vendors and on-prem deployments have different practical bounds.
  We pick the documented 1..255 (cluster ID encodes into the lower
  byte of the RETH virtual MAC; values >255 would collide), which
  matches the silent-truncation behavior of the current compiler.

## Open questions for adversarial review

1. **Is the per-subtree walker pattern (one walkFoo for each typed
   subtree) the right abstraction, or should this PR instead
   introduce a generic "walk-AST-against-cmdtree" algorithm that
   handles every typed-leaf path uniformly?** If the answer is
   "generic walker", that's a Phase 3a refactor scope expansion and
   probably justifies PLAN-KILL on this incremental design.

2. **Should `cluster-id` accept 0?** The compiler's `Atoi(v)` accepts
   `0` and the resulting MAC has `cluster-id` byte = 0. Junos
   reserves `cluster-id 0` for "disabled" (no cluster). If the
   intent is to forbid `0` at commit time, the validator should be
   `ValidateInteger(1, 255)`; if the intent is to allow `0` as
   "disabled", validator should be `ValidateInteger(0, 255)`.
   Current plan picks 1..255 — matches Junos vSRX docs. Reviewers
   may disagree.

3. **Is rejecting `heartbeat-interval < 50` ms too aggressive?**
   The userspace heartbeat code in `pkg/cluster/heartbeat.go` runs
   at 100 ms default; the lab cluster sometimes uses 30 ms in stress
   tests. If reviewers think the operator should be allowed to set
   `heartbeat-interval 10` for testing, the validator should drop
   the lower bound to ValidateInteger(1, 2000) — at the cost of
   losing the "obviously wrong" rejection.

4. **`takeover-hold-time` max = 60 s.** The compiler accepts any
   positive integer (Atoi). Is 60 s too restrictive (some HA
   operators want minutes-long hold-down for maintenance windows)?
   Or is the typed-leaf bound the right place to document the
   sensible max?

5. **Should `walkChassisCluster` recurse into all chassis sub-stanzas
   or only `chassis cluster`?** Plan v1 only walks `chassis cluster`
   children because that's where the immediate symptom is.
   `set chassis ...` has other subtrees (`chassis fpc <id> pic ...`)
   that have their own typed leaves; this PR ignores them. If a
   future operator sets `set chassis fpc 0 pic 0 garbage`, today's
   compiler ignores it, and tomorrow's walker will continue to
   ignore it because the walker only descends into `cluster` for
   now. Is that acceptable scope discipline, or should the chassis
   walker be designed up-front to handle every `chassis ...`
   subtree?

6. **Test fixture for the empty-cluster regression case.** Currently
   the schedulers walker has explicit empty-clause coverage. We
   should mirror that for chassis — but a `set chassis cluster` with
   no children parses to a `cluster` node with empty `Children`,
   and the walker must not panic. Are there other "almost-empty"
   shapes the test plan should cover (e.g. `set chassis cluster
   redundancy-group 0` with no node/priority children below it)?

7. **Walker fan-out vs. compiler validation.** The compiler already
   has `validateClassOfServiceStrict` (cross-references between
   schedulers / class-maps / forwarding-classes) that runs at
   commit time. The chassis-cluster compiler has no equivalent.
   Should this PR add `validateChassisClusterStrict` for
   cross-references (e.g. RG IDs must match the per-RG node
   priorities), or is that out of scope (and a separate follow-up
   issue)? Current plan: out of scope — Phase 3a is value-level
   schema, not cross-reference schema.
