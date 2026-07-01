# #3630 — Canonical structured representation of the implicit default policy

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).

Terminal target: PLAN-READY that is consciously **PLAN-DEFERRED** (low value,
leave open, label `plan-deferred-research`) unless the reviewers conclude the
current representation is unambiguous-enough → **PLAN-KILL** (works-as-intended).

## 2. Issue framing

The structured policy surfaces encode the *implicit default policy* (the
catch-all every flow matching no configured rule rides) inconsistently across
transports:

- The **inventory** surfaces (`GetPolicies` REST + gRPC) represent the default
  as a **synthetic row**: a `PolicyInfo` with `from_zone="-"`/`to_zone="-"`
  wrapping one `PolicyRule` whose match arrays are **empty**
  (`src_addresses`/`dst_addresses`/`applications` = `[]`), with
  `name="default-policy"`, `policy_id=0xFFFFFFFF`, `rule_id="default-policy"`.
- The **match-policies** surfaces (`MatchPolicies` REST + gRPC) represent the
  same concept as **typed fields**: `matched=false` + `default_used=true` +
  `action=<effective>`.

Two problems flow from this:

1. **Ambiguity of the synthetic row.** An empty match array reads, in many API
   conventions, as *match-NONE* rather than *match-ANY* (the true meaning of
   the default). A schema-only client (reads the proto/JSON, not the Go/Rust
   source) has no self-describing signal that this row is the implicit default:
   it must infer it from the `-`/`-` zone strings, the magic `policy_id`
   constant `0xFFFFFFFF`, or the name string `"default-policy"` — all brittle.
2. **Two encodings of one concept.** Inventory uses a synthetic row;
   match-policies uses `default_used`. A client normalizing both surfaces
   branches differently for each.

Fix direction (from the issue): add a **typed marker** (an `is_default` bool /
scope flag) to the inventory row so clients distinguish "the implicit default"
from a real rule with an empty match, and so the concept is self-describing and
consistent with the already-typed match-policies encoding. Additive wire only
(new fields, no renumber). Severity: **Low** (API representation / clarity;
no enforcement or security-behavior impact).

## 3. Honest scope/value framing

This is an **API-clarity / observability** change. There is **no** dataplane,
no performance, and no enforcement impact — the effective default action is
already correct on every surface today (`show`/CLI/REST/gRPC/Prometheus all
render `action=deny|permit|reject` for the default). The win is purely that a
structured client can identify the default row **without** knowing a magic
constant or matching on `-`/`-` strings, and without misreading empty match
arrays as match-none.

Absolute-scale value: small. The current representation already carries a
**machine-unambiguous** discriminator — `policy_id == DefaultPolicySentinelID
(0xFFFFFFFF)` — and since #3623 `policy_id` has explicit proto3 presence, so it
is **always emitted** on the default row. A disciplined client that keys on the
sentinel is already unambiguous. The residual gap is that the sentinel is a
Go/Rust constant **not published in the proto/JSON schema**, so a client author
reading only the wire contract has no documented signal, and the empty arrays
remain genuinely misleadable.

**If reviewers conclude the clarity gain is too small to justify the churn (a
schema-only client can be told to key on `policy_id==0xFFFFFFFF`), PLAN-KILL is
an acceptable verdict.** This plan's own recommendation is PLAN-DEFERRED: the
design is sound and cheap, but it is low-priority and should not pre-empt
higher-value work — it lands as a ready-to-execute plan behind the
`plan-deferred-research` gate.

## 4. What's already shipped / partially batched (must compose with)

- **#3363** (`ead084098`) added the synthetic default row to structured
  `GetPolicies` (REST `pkg/api/security.go:314-337`; gRPC
  `pkg/grpcapi/server_show_zones.go:283-306`) with the reserved
  `DefaultPolicySentinelID` hit counter. Contract test:
  `pkg/grpcapi/server_show_zones_default_policy_3363_test.go`.
- **#3375** added `default_used` (+ the explanatory `action` string) to
  match-policies REST (`pkg/api/types.go:480`) and gRPC
  (`proto/xpf/v1/xpf.proto:758`, field 12). This is the *typed encoding this
  plan wants to mirror onto inventory.*
- **#3623** (`02b3c0f29`) gave `policy_id` explicit proto3 presence
  (`optional uint32 policy_id = 17`, REST `*uint32`) so the sentinel is always
  present on the default row — the existing machine discriminator.
- **#3624** (`6f56df7c1`) added `scheduler_name`/`inactive` (proto fields 19/20)
  — the last additive fields on `PolicyRule`; **next free field number is 21**.
- **#3627** (`30f997685`) added `queried_from_zone`/`queried_to_zone` (proto
  fields 13/14) to match-policies.
- Sentinel SSOT: `pkg/dataplane/types.go:438` (`DefaultPolicySentinelID uint32
  = 0xFFFFFFFF`), `:444` (`DefaultPolicyName = "default-policy"`), kept in
  lockstep with `userspace-dp/src/policy.rs` (verified by
  `pkg/logging/default_policy_sentinel_3057_test.go`).

## 5. Concrete design

### 5.1 Confirmed inconsistent representations (file:line, base 84b6533e7)

| Surface | Default encoding | Location |
|---|---|---|
| REST inventory `GetPolicies` | synthetic `PolicyInfo{FromZone:"-",ToZone:"-"}` + `PolicyRule{Name:"default-policy", SrcAddresses:[], DstAddresses:[], Applications:[], PolicyID:0xFFFFFFFF, RuleID:"default-policy"}` | `pkg/api/security.go:314-337` (empty arrays L318-320; sentinel L321; `-`/`-` L333-334) |
| gRPC inventory `GetPolicies` | same synthetic row (proto) | `pkg/grpcapi/server_show_zones.go:283-306` (empty arrays L287-289; sentinel L291; `-`/`-` L303-304) |
| REST match-policies | **typed**: `Matched:false` + `DefaultUsed:true` + `Action` | `pkg/api/types.go:441-491` (`DefaultUsed` L480); handler `pkg/api/security.go:433-604` |
| gRPC match-policies | **typed**: `matched=false` + `default_used=true` (field 12) + `action` | `proto/xpf/v1/xpf.proto:712-770` (L758) |
| gRPC text `show security policies hit-count` | `"-" "-" default-policy <action>` | `pkg/grpcapi/server_show_policies_text.go:243-244` |
| CLI text `show security policies` | `"-" "-" "-" default-policy <count> <action>` | `pkg/cli/cli_show_security.go:166-167` |
| Prometheus `xpf_policy_hits_total` | labels `from_zone="-",to_zone="-",policy="default-policy"` | `pkg/api/metrics_counters.go:286-287` |

The `policymatch.Result` source of the typed encoding: `DefaultUsed`
(`pkg/policymatch/policymatch.go:287`), `Action` (`:324`), returned at `:378`,
`:406`, `:484`.

### 5.2 Canonical representation

Add ONE self-describing typed marker to the inventory `PolicyRule` on BOTH
transports. Set it true **only** on the synthetic default row; false/omitted on
every real rule. Do **not** remove or renumber anything.

**gRPC** — `proto/xpf/v1/xpf.proto`, `message PolicyRule` (append at field 21):

```proto
  // #3630: is_default is true ONLY for the synthetic row representing the
  // IMPLICIT default policy (the catch-all every flow matching no configured
  // rule rides). It is the self-describing, schema-visible discriminator for
  // that row — a client no longer needs the magic policy_id sentinel
  // (0xFFFFFFFF) or the "-"/"-" from/to-zone strings to identify it. When
  // is_default is true, the empty src_addresses/dst_addresses/applications mean
  // match-ANY (the default catch-all), NOT match-none; `action` is the
  // effective default-policy verdict. This is the inventory-row analogue of the
  // match-policies `default_used` field. Additive; false (omitted) for every
  // real zone-pair or global rule — no change for existing consumers.
  bool is_default = 21;
```

**REST** — `pkg/api/types.go`, `PolicyRule` struct:

```go
  // IsDefault marks the synthetic implicit-default row (#3630). See the proto
  // is_default doc: self-describing discriminator; empty match arrays mean
  // match-ANY when true. omitempty: absent for every real rule.
  IsDefault bool `json:"is_default,omitempty"`
```

**Set sites** (the only two producers): set `IsDefault: true` /
`IsDefault: proto.Bool(true)` — no, plain `bool`, so `IsDefault: true` — on the
synthetic `defRule` in:
- `pkg/api/security.go:315` (REST `defRule := PolicyRule{...}`)
- `pkg/grpcapi/server_show_zones.go:284` (gRPC `defRule := &pb.PolicyRule{...}`)

No other `PolicyRule` construction sets it (defaults to false/omitted).

### 5.3 Empty-match-array ambiguity — decision

**Keep the arrays empty; disambiguate via the flag; document the semantics.**
Do NOT rewrite the default row's arrays to a literal `["any"]`:

- Rewriting to `["any"]` is a **breaking output change** for existing #3363
  consumers and collides with a real address book legally named `any`.
- With `is_default=true` present, empty arrays are no longer ambiguous: the
  proto/JSON doc states that under `is_default` the empty arrays denote
  match-ANY. The client keys on the flag, not the arrays.

### 5.4 Cross-surface normalization (issue L05)

The two encodings stay **structurally** different (inventory is a list of rows;
match-policies is a single verdict) — that is inherent, not a defect. What this
plan makes consistent is that **both are now self-describing and
cross-mappable**:

- inventory: the `is_default=true` row carries `action` = effective default.
- match-policies: `default_used=true` carries `action` = effective default.

A client maps `inventory.rule(is_default).action == matchPolicies(default_used).action`
without magic constants. The plan will NOT rename `default_used` →
`is_default` (or vice-versa): they are semantically distinct (a row that *is*
the default vs a query that *fell through to* the default) and renaming a
shipped field breaks the #3375 contract. The naming divergence is documented as
intentional in both field docs.

### 5.5 Text / Prometheus surfaces — out of design (unchanged)

The CLI/gRPC text tables and the Prometheus `from_zone="-"` label are
**human/label** surfaces where `-`/`-` is an established display convention and
a typed bool has no natural home (a Prometheus label cannot carry a bool
cleanly; adding a label churns every existing series). They are left as-is; the
typed marker targets the **structured JSON/proto** surfaces the issue names.
This is stated explicitly so a reviewer does not read it as an omission.

### 5.6 Optional (deferred within this plan): publish the sentinel in-schema

We could also add a proto/JSON doc-comment (or a `// const` note) naming
`0xFFFFFFFF` as the default sentinel. With `is_default` shipped this is
redundant for identification; leave it as a doc line in the field comment
(already in 5.2) rather than a new symbol. No new proto enum/const.

## 6. Public API preservation

- No field removed, renamed, or renumbered. `is_default` is a NEW proto field
  (21) and a NEW REST JSON key (`is_default`, omitempty).
- `default_used` (match-policies, field 12) unchanged.
- `policy_id=0xFFFFFFFF` sentinel, `rule_id="default-policy"`, `-`/`-` zones on
  the inventory default row all PRESERVED (existing #3363 clients keep working;
  `is_default` is purely additive alongside them).
- All existing method signatures (`GetPolicies`, `MatchPolicies`, REST handlers)
  unchanged. `.pb.go` regenerated (`make proto` / buf) — a code-gen artifact,
  not a hand edit.

## 7. Hidden invariants the change must preserve

- **Exactly-one default row.** Both producers append the synthetic row
  unconditionally (once). `is_default` must be true on that row and nowhere
  else — a client relying on "exactly one is_default row" must hold. A real
  policy legally named `"default-policy"` must NOT get `is_default=true` (this
  is precisely why the name string is not a valid discriminator, and why the
  flag is set structurally at the two synthetic-row sites, never by name).
- **Sentinel lockstep untouched.** No change to `DefaultPolicySentinelID` /
  `DefaultPolicyName` or the Rust `policy.rs` mirror; the #3057 lockstep test
  stays green.
- **Counter gating preserved.** `is_default` is orthogonal to the
  `statsEnabled`/`IsLoaded` hit-counter gating already on the default row.
- **omitempty parity.** REST `is_default` omitempty ⇒ real rules emit no new
  key (byte-identical JSON for non-default rows). gRPC bool defaults false ⇒
  same on the wire.
- **N/A (Go + proto only):** no Rust hot-path, no allocation-rule, no
  borrow-checker/lifetime, no HA-sync-portability surface is touched by this
  change (it is control-plane read-only rendering).

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | **LOW** | Additive read-only field on two rendering paths; existing fields untouched; omitempty/false keeps non-default output byte-identical. |
| Lifetime / borrow-checker | **N/A** | Go + proto; no Rust, no ownership surface. |
| Performance regression | **NONE** | One extra bool set on a single synthetic row per `GetPolicies` call (a control-plane 1/s-class RPC), no hot path. |
| Architectural mismatch | **LOW** | Mirrors the already-accepted #3375 `default_used` typed pattern; no new concept, no new SSOT. The only fork risk is over-scoping (rewriting arrays / renaming `default_used` / churning text+Prometheus) — explicitly rejected in §5.3/§5.4/§5.5. |

## 9. Test plan

- `go build ./...` clean; `make proto` (or buf generate) regenerates
  `xpf.pb.go` with no unrelated diff.
- `go test ./...` — 30+ Go packages green. Specifically:
  - Extend `pkg/grpcapi/server_show_zones_default_policy_3363_test.go`: assert
    the default row has `GetIsDefault()==true` AND every real rule has
    `GetIsDefault()==false`.
  - New `pkg/api` test: `GetPolicies` REST JSON default row has
    `"is_default":true`; a real rule omits the key (byte-check no
    `is_default` on a real rule).
  - New cross-surface consistency test: the inventory `is_default` row's
    `action` equals the match-policies `default_used` `action` for a
    fall-through query on the same config (both derive from
    `cfg.Security.DefaultPolicy` / `policymatch`), so the two surfaces cannot
    silently diverge.
  - Guard: a config with a real zone-pair policy **named** `"default-policy"`
    yields exactly ONE `is_default=true` row (the synthetic one), and the
    real same-named rule has `is_default=false`.
- No dataplane/smoke/failover run required — this is a control-plane rendering
  change with no forwarding, HA, VRRP, or session-sync surface. (Stated
  explicitly so a reviewer does not demand an unnecessary cluster smoke.)
- Docs: update `docs/` API/observability notes that describe the default-policy
  row (grep for the #3363/#3375 default-policy documentation) to mention
  `is_default`, satisfying the CLAUDE.md docs-as-contract rule.

## 10. Out of scope (explicitly)

- Renaming `default_used` ↔ `is_default` (breaks the #3375 contract).
- Rewriting the default row's match arrays to `["any"]` (breaking + `any`
  collision — §5.3).
- Adding the typed marker to the CLI/gRPC **text** tables or the Prometheus
  labels (§5.5 — display surfaces, `-`/`-` convention retained).
- Introducing a proto enum/const symbol for `0xFFFFFFFF` (redundant once
  `is_default` ships; documented in the field comment instead).
- Any change to `DefaultPolicySentinelID` / `DefaultPolicyName` / the Rust
  `policy.rs` lockstep.
- A `scope` enum (default/zone-pair/global) generalization — `is_default` is
  the minimal fix; a broader scope enum is a separate design if ever wanted.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is this PLAN-KILL?** `policy_id==0xFFFFFFFF` is already an unambiguous,
   always-present (#3623) machine discriminator. Is the residual gap (sentinel
   not published in-schema + empty-array misread) real enough to justify a new
   wire field, or should we instead just document "key on
   `policy_id==DefaultPolicySentinelID`" and close as works-as-intended?
2. **Flag vs enum.** Is a single `is_default` bool the right shape, or does the
   inventory want a `scope` enum (`default`/`zone_pair`/`global`) that also
   subsumes the `*`/`*` global-tier convention (#3045/#3148/#3286)? Does an
   enum over-scope a Low issue?
3. **Empty arrays.** Is documenting "empty arrays mean match-ANY when
   is_default" sufficient, or must the default row emit an explicit any token
   for clients that never read the flag? (Weigh the `any` address-book
   collision + breaking-change cost from §5.3.)
4. **Naming divergence.** Is keeping `is_default` (inventory) distinct from
   `default_used` (match-policies) acceptable, or does L05 demand identical
   naming across surfaces (accepting a #3375 wire-contract break)?
5. **Text/Prometheus.** Is leaving the `-`/`-` text rows and Prometheus labels
   untouched defensible, or does "consistent across ALL surfaces" require a
   typed signal there too (and if so, how, given a Prometheus label can't carry
   a bool without churning every series)?
6. **Exactly-one invariant.** Is setting `is_default` structurally at the two
   synthetic-row construction sites robust against a future refactor that adds
   a third default-row producer, or should the flag be derived centrally (e.g.
   a shared `defaultPolicyRule()` builder both surfaces call)?
