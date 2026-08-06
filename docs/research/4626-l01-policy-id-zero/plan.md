# #4626 L01 — retire the overloaded `policy_id` wire value 0

## 1. Status

`DRAFT v1 — pending adversarial plan review`

Base: `origin/master` @ `b8b39a16a`. Research branch
`research/4626-l01-policy-id-zero`. **Plan only — no production code is touched
by this document.**

Scope is the **L01 half of #4626 ONLY**. M03 (multi-zone scoped-global scope)
shipped in PR #4787 and is re-verified as shipped in §4; it is out of scope and
is not re-derived here.

---

## 2. Issue framing

`policy_id` is a `u32` stamped on every session by the userspace dataplane
(#3056) and carried unchanged across the HA session-sync wire. The value **0**
has two incompatible meanings simultaneously:

1. **A real configured policy.** `policyRuleSlot.policyID()` is
   `PolicySetID*MaxRulesPerPolicy + RuleIndex`
   (`pkg/dataplane/userspace/policies.go:63`). For the first policy of the first
   zone-pair set, `PolicySetID == 0` and `RuleIndex == 0`, so it is assigned
   `policy_id 0`.
2. **"No policy admitted this session."** Host-inbound, neighbor-seed, fabric
   and tunnel installs all stamp `policy_id: 0`
   (`userspace-dp/src/afxdp/neighbor_dispatch.rs:625`,
   `afxdp/tunnel.rs:630`, `afxdp/flow_cache.rs:631`,
   `afxdp/event_emit.rs:262/306/362/498`), and
   `afxdp/bpf_map/publish_conntrack.rs:226` states the contract outright:
   "`0` stays the value for non-policy-forwarded sessions."

Nothing else on a session distinguishes the two readings — `SessionValue.Flags`
is NAT-only (`SessFlagSNAT`/`DNAT`/`StaticNAT`/`NAT64`/`NPTV6`,
`pkg/dataplane/types.go:665-669`).

Because of the overload, three sites carry a permanent workaround:

- `pkg/daemon/daemon_policy_invalidate.go:72-77` — the commit-time
  deletion-clear (#4234) skips the value entirely:

  ```go
  for key, id := range oldIDs {
          if id == 0 {
                  // Overloaded wire value — never sweep policy_id==0 sessions.
                  continue
          }
  ```

  This is a deliberate fail-SAFE **under-clear**: deleting or renaming the
  literal first security policy does not clear its sessions; they idle out.
- `pkg/dataplane/policy_display.go` (#6851) — every session-row display surface
  renders id 0 as `unattributed` rather than resolving it, and
  `pkg/logging/ringbuf.go:279-292` does the same for durable RT_FLOW syslog
  records. The under-claim is correct for the non-policy population and **wrong
  for the first policy's own records** — its denies log as `unattributed`.
- `userspace-dp/src/policy.rs:1814-1821` — the `DuplicatePolicyId` (M01)
  snapshot-integrity preflight excludes 0 from its uniqueness check, so two
  rules that both resolve to 0 are not caught.

The issue asks to **retire the overload** so the workarounds can be deleted and
the deletion-clear (and the deferred L14 default-policy invalidation) becomes
precise. Its suggested mechanism is "reserve 0 and start real policy ids at 1".
This plan treats that mechanism as **one candidate among several** and
recommends a different one (§5).

---

## 3. Honest scope/value framing

**This is not a live user-visible defect.** The two observable symptoms are both
already handled:

| Symptom | State on master |
|---|---|
| Sessions displayed under the first policy's name | **Fixed** by #6851 (six render sites + RT_FLOW resolver) |
| First-policy delete does not clear its sessions | **Present**, but it is an UNDER-clear, and Junos' own default is that established sessions survive a policy delete |
| First policy's denies log as `unattributed` | **Present** — an under-claim introduced by #6851, correct for the larger population |
| Two rules aliasing on `policy_id 0` not rejected | **Present**, only reachable from a corrupt/hand-built snapshot |

The value of this work is therefore:

1. **Deleting a load-bearing workaround.** Three sites currently encode "0 is
   ambiguous". After the change the ambiguity is gone and the code says what it
   means.
2. **Making the #4234 deletion-clear complete.** Today exactly one policy — the
   first — is exempt from Junos-default deletion-clear semantics.
3. **Unblocking L14** (route default-policy invalidation into the runtime-id
   framework), which couples to the same id space.
4. **Removing an under-claim on a durable audit surface.** RT_FLOW records ship
   off-box; the first policy's deny records currently say `unattributed`.

**If reviewers conclude the payoff is too small to justify the churn and the
mixed-version risk, PLAN-KILL is an acceptable verdict.** A prior 2-of-3
convergence on this issue (Codex + Claude SMR, 2026-07-09, issue comment #2)
landed on PLAN-DEFER for exactly that reason. That verdict has since expired:
#6851 shipped, `DefaultPolicySentinelID` established the reserved-sentinel
pattern, and the render-side guard the earlier plan feared would be needed
"either way" has already been built. This plan must be judged on today's tree,
not on that one — but a reviewer who re-derives PLAN-DEFER with today's facts is
giving a legitimate answer.

---

## 4. What is already shipped (and must be composed with, not re-done)

**M03 — SHIPPED, out of scope.** Verified firsthand on `b8b39a16a`:
`config.PolicyMatch.FromZones []string` / `.ToZones []string`
(`pkg/config/types_security.go:444-445`), compiler accumulates both slots
through `firewallMatchValues` (`pkg/config/compiler_security_policy.go:255-259`)
with `sortDedupZones` at `:372-373`, and the runtime carries
`GlobalZoneScope::Zones(SmallVec<[u16; 2]>)`. Nothing about M03 is outstanding.

**#3057 `DefaultPolicySentinelID` = `0xFFFFFFFF`** (`pkg/dataplane/types.go:534`,
`DEFAULT_POLICY_SENTINEL_ID` in `policy.rs`). The IMPLICIT default policy's deny
records carry it instead of 0. This is the *precedent* for a reserved sentinel
that "can never collide with a configured policy ID" and it travels in the
existing `policy_id` u32 with **no layout change**. It solves the *default
policy* case; it does not touch the first configured policy.

**#6851 render guards.** `dataplane.SessionPolicyName` /
`dataplane.ReservedPolicyName` / `dataplane.PeerSessionPolicyName`
(`pkg/dataplane/policy_display.go`) are the SSOT for "which ids must never reach
a name map", consumed by the two CLI sites, `pkg/api/sessions.go:1395,1449`,
`pkg/grpcapi/server_sessions.go:1703,1756`, and `pkg/logging/ringbuf.go:292`.
`UnattributedPolicyID = 0` and `UnattributedPolicyName = "unattributed"` already
exist. **Any path chosen here must keep these guards for the mixed-version
window** (an older peer keeps sending a bare 0 regardless of what the local id
space looks like).

**#3395 `reresolve_session_policy_id`** (`policy.rs:1587`). At the ~1s live-row
refresh and at SESSION_CLOSE, a LOCAL session's `policy_id` is re-resolved from
its bound counter's stable `rule_id` against the current snapshot. Two arms
matter here:
- `bound = Some(counter)` whose rule was deleted → `DEFAULT_POLICY_SENTINEL_ID`.
- `bound = None` — **idx-0 non-policy sessions AND every peer-synced session** —
  → keep the frozen stamped id. Peer-synced sessions therefore **never**
  re-resolve; whatever the peer stamped is what they carry for life.

**#3301 HA metadata carry.** `manager_ha.go:1653/1731` sends
`req.PolicyID = val.PolicyID` to the peer helper, documented as
"0 => unattributed / no counter / global timeout, the pre-#3301 behavior an old
helper still applies via serde(default)". The cross-chassis binary wire carries
`PolicyID` at a fixed offset (`pkg/cluster/sync_protocol.go:136/251` encode,
`:415/543` decode).

**Version machinery that already exists** (this is the hook any gate would use):
- `cluster.CurrentHAProtocolVersion` / `MinCompatHAProtocolVersion` /
  `LegacyHAProtocolVersion` (`pkg/cluster/heartbeat.go:27-46`), advertised in an
  **optional, length-tolerant heartbeat version trailer** alongside
  `SoftwareVersion` (`heartbeat.go:97-125`). Absent trailer ⇒ legacy.
- `cluster.SessionSyncWireVersion = uint16(CurrentHAProtocolVersion)`
  (`pkg/cluster/sync.go:36`).
- `userspace.ProtocolVersion = 4` (`pkg/dataplane/userspace/protocol.go:37`) /
  `CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 4`
  (`userspace-dp/src/protocol/control.rs:41`), enforced by **exact equality** at
  `server/handlers/snapshot.rs:25`, with the
  `ensure*ProtocolLocked` required-protocol gate family
  (`manager_compile.go:743-800`) as the "this config cannot be committed against
  this helper" precedent.

---

## 5. Concrete design — four path options

### 5.0 The invariant that decides everything

> A `policy_id` comparison is only sound when **the numbering function that
> stamped the session equals the numbering function that produced the set being
> compared against.**

`deletedPolicyRuntimeIDs` is safe today precisely because both sides come from
the same binary: the sweep set is `PolicyIDsByStableKey(oldCfg)`, computed with
the same `policyID()` that stamped the live sessions.

Two facts bound the blast radius of breaking that invariant:

- **Local sessions do not survive an xpfd restart.** The helper is a *child
  process* spawned by `ensureProcessLocked`
  (`pkg/dataplane/userspace/process.go:76-95`, `exec.Command(binary, ...)`);
  there is no adopt-existing-helper path, and the control socket is unlinked and
  re-created on every bring-up. Upgrading xpfd therefore starts a fresh helper
  with an **empty** session table. There is no intra-node old-stamp/new-compare
  skew.
- **Peer-synced sessions are exactly the population that does survive** — and on
  a rolling upgrade the freshly restarted node repopulates its **entire** table
  from the not-yet-upgraded peer, every row stamped in the peer's numbering.
  #3395 will never re-resolve them (`bound = None`).

So "the mixed-version hazard" is not a corner case: **on a rolling upgrade the
new node's whole session table carries old-meaning ids.**

### 5.1 Enumerating the failure that renumbering causes, in both directions

Assume any scheme that shifts real policy ids (the issue's literal request).
Call the shift `Δ` (`Δ = +1` for "start at 1").

**Direction 1 — new node ← old peer.** Old peer stamps policy *P* with `id`.
New node computes `id + Δ` for the same *P*.
- *Display*: `SessionPolicyName(names, id)` resolves `id` in the NEW map, which
  holds `id` for policy *P<sub>prev</sub>* — the policy one slot **earlier**.
  Result: a confident, wrong policy name on every peer-synced session. This is
  precisely the defect class #6851 just closed, re-opened across the whole
  policy space instead of just id 0.
- *Deletion-clear*: operator deletes *P*. New node's sweep set is
  `{id_P + Δ}` = `{id_Q}` where *Q* is the NEXT policy. Peer-synced sessions of
  *Q* carry `id_Q` → **swept**. Deleting *P* drops *Q*'s sessions: an
  over-clear, i.e. real forwarding loss on a policy that still exists.
  Simultaneously *P*'s own synced sessions (carrying `id_P`) are missed.

**Direction 2 — old node ← new peer.** The new node sends `id + Δ`; the old
node's code is fixed and cannot be taught anything.
- *Display*: resolves `id + Δ` in its own map → names the policy one slot
  **later**. Wrong name, and the old node still has the `if id == 0 { continue }`
  exclusion so nothing protects it.
- *Deletion-clear*: symmetric over-clear on the old node.

**Neither direction is fixed by a version bump alone.** Bumping
`CurrentHAProtocolVersion` makes `HAProtocolVersionMismatch()` true, which sets
`userspaceTransferReadiness` false and blocks **manual failover** and the #1930
mixed-base image-replace gate (`pkg/daemon/daemon_ha_userspace_readiness.go:93`,
`pkg/upgrade/cluster_cli.go:248`). It does **not** stop session sync — the sync
frame header (`syncHeader`, `sync.go:80-86`) has no version field and the
connection performs no version handshake. Verified firsthand: neither
`pkg/cluster/sync_admission.go` nor `pkg/cluster/sync_conn.go` contains a single
`version` reference, and no `sync*.go` production file reads
`HAProtocolVersion`/`SessionSyncWireVersion` on the receive path. Sessions keep
flowing and keep carrying old-meaning ids. A plan whose mixed-window answer is "bump the version"
is therefore **wrong on the facts**, and this is the single most likely way to
ship a silent regression here.

Making a version bump actually protect the id space would require **refusing
session sync** across the mismatched pair — turning every failover in the
upgrade window into a cold failover (whole table lost). That is a far larger
availability cost than the misattribution it prevents.

### 5.2 `MaxRulesPerPolicy` boundary arithmetic (the off-by-one trap)

`MaxRulesPerPolicy = 256`. The id space is a **packed** two-field encoding, and
two independent decoders unpack it with `divmod`:

- `policyRuleIDForCounter` (`pkg/dataplane/userspace/policycounters.go:90-91`):
  `policySetID := policyID / 256; ruleIndex := policyID % 256`.
- `pkg/api/metrics.go:1220` and ~14 further sites open-code the *encode* side
  `policySetID*MaxRulesPerPolicy + i`, including the display fallback
  `RuntimePolicyIndex` (`policies_ids.go:127`).

A **uniform `+1` on the final id** breaks this. Set *n* would occupy
`[n*256+1, n*256+256]`, so the top id of set *n* is `(n+1)*256`, which `divmod`
decodes as **set n+1, index 0**. `walkPolicyRuleSlots` explicitly permits a set
to fill its namespace exactly ("A policy set may exactly fill its 256-slot
namespace (indices 0..255)"), so this is reachable, and it is a *silent*
misattribution of a counter/Index to the wrong policy set.

The alternative — reserving index 0 **within each set** (`RuleIndex` starts at
1) — keeps `divmod` self-consistent (remainders stay in `[1,255]`, never
crossing a set boundary) but **reduces documented per-set capacity from 256 to
255** and changes the global set's first id from `256` to `257`
(`policy_namespace_3143_3145_test.go:219-220` pins the current value).

Either way there are **two id spaces to keep straight**: the span-accumulated
runtime `policy_id` and the raw-ordinal **counter handle** that
`ReadPolicyCounters` takes (`policycounters.go:47-68` documents the split). They
are already different values on a config with application-set expansion; a shift
applied to one and not the other, or a `RuntimePolicyIndex` fallback that
returns the unshifted raw ordinal, silently mixes spaces. Any renumbering path
must enumerate all ~14 open-coded encode sites plus both decode sites and treat
a missed one as a shipped defect.

### 5.3 Persisted state

**No migration is required.** Verified: `pkg/configstore` contains no
`PolicyID`/`policy_id` reference at all — the config DB and the JSONL audit
journal persist Junos configuration TEXT, and ids are derived at compile time
from that text on every load. The helper's `--state-file` holds runtime
dataplane state for a process whose lifetime is bounded by xpfd's (§5.0), and no
session table is restored across a restart. The only durable artifacts that
embed a numeric `policy_id` are **RT_FLOW syslog records already shipped
off-box**; a renumbering makes historical records disagree with a current
`show security policies` Index for the same policy, which is a real (if minor)
forensic-continuity cost that a non-renumbering path avoids entirely.

### 5.4 The four paths

#### Path A — uniform `+1` shift on `policyID()` (the issue's literal request)

`policies.go:63` becomes `... + s.RuleIndex + 1`.

**Rejected.** It hits every failure in §5.1 in both directions *and* the
`divmod` boundary break in §5.2. Listed only to be explicitly ruled out.

#### Path B — reserve index 0 per set (`RuleIndex` starts at 1) + additive space-version + ingress normalisation

Real ids become `set*256 + idx`, `idx ∈ [1,255]`; 0 is never assigned;
`divmod` stays consistent.

Mixed-window handling, both directions:
- Add an **optional heartbeat-trailer capability** `policy_id_space: u8`
  (absent ⇒ space 0, the current numbering) — additive, using the existing
  optional-trailer discipline, so **no `CurrentHAProtocolVersion` bump** and
  no failover blocking (the DHCP-lease-sync precedent, `sync.go:68-73`,
  explicitly endorses "additive and gated ⇒ do not bump").
- **Ingress**: a session arriving from a peer that has not advertised space 1
  has its `policy_id` rewritten to the reserved `0` on import → renders
  `unattributed` (already shipped) and is never swept (0 is reserved). Safe.
- **Egress**: to a peer that has not advertised space 1, send `policy_id - 1`
  (an exact inverse, since the delta is a uniform constant and both nodes
  compile the same text-synced config). This is what protects Direction 2, which
  ingress normalisation cannot reach.

**Cost**: capacity 256 → 255 per set; every open-coded encode/decode site in
§5.2 must move in lockstep; the operator-visible `show security policies` Index
shifts by one for every policy; RT_FLOW numeric ids shift, breaking continuity
with archived records; two new wire behaviours (ingress normalise, egress
downgrade) that must themselves be tested in both directions.

#### Path C — move the *sentinel*, not the *policies* (**RECOMMENDED**)

Keep `policyID()` exactly as it is. Instead, change what the **non-policy**
population stamps: introduce

```go
// pkg/dataplane/types.go
const NoPolicySentinelID uint32 = 0xFFFFFFFE   // mirrors NO_POLICY_SENTINEL_ID in policy.rs
```

and have host-inbound, neighbor-seed, fabric and tunnel installs stamp it
instead of 0 (`neighbor_dispatch.rs:625`, `tunnel.rs:630`, `flow_cache.rs:631`,
the `event_emit.rs` sites, and the host-inbound path). The value rides the
existing `policy_id` u32 — **no field, no layout, no protocol version changes
anywhere**, exactly as `DefaultPolicySentinelID` (`0xFFFFFFFF`) already does,
and the same "cannot collide with a real id" argument
(`pkg/dataplane/types.go:535-541`) covers `0xFFFFFFFE` verbatim.

After this, **going forward** `policy_id == 0` means the first configured policy
and nothing else. `ReservedPolicyName` gains the new sentinel (rendered
`unattributed`), and `reresolve_session_policy_id`'s `bound = None` arm is
unchanged (it already just preserves whatever was stamped).

**Why both mixed-version directions are safe with no gate at all:**

- *New node ← old peer.* The old peer's non-policy sessions still carry `0`. The
  new node keeps the #6851 render guard for 0 and keeps the
  `if id == 0 { continue }` exclusion for the deprecation window → behaviour is
  **byte-identical to today**. No new failure mode.
- *Old node ← new peer.* The new peer's non-policy sessions carry `0xFFFFFFFE`.
  The old node looks it up in its name map, **misses**, and renders "" (CLI
  numeric fallback / empty REST-gRPC field) instead of a wrong policy name — a
  strict improvement over today, where it would have rendered `unattributed`
  only because #6851 taught it about 0. Its deletion-clear can never contain
  `0xFFFFFFFE` in a sweep set (`PolicyIDsByStableKey` only emits real ids), so
  those sessions are never swept. Safe.

No id is ever reinterpreted as a different policy in either direction, because
**no real policy's id changes**. That is the whole point.

**Two-release removal of the workaround** (the brief's third question, answered
concretely): the `continue` **cannot** be removed on day one and **must lag by a
release**. On day one an old peer is still stamping 0-meaning-nothing; removing
the exclusion then would let a first-policy delete sweep that peer's
host-inbound/fabric/tunnel sessions — the exact mass-loss hazard the exclusion
exists to prevent. The removal becomes correct once
`MinCompatHAProtocolVersion` no longer admits a peer that stamps 0 for
non-policy sessions, which is the release boundary the project already models.
Release *N* ships the sentinel + a `NoPolicySentinelID` render arm and leaves
the exclusion in place with a comment naming the removal condition; release
*N+1* raises `MinCompatHAProtocolVersion` past the stamping change and deletes
the `continue`, the 0-render arm, and (see below) the M01 exclusion of 0.

**What this does NOT deliver**: `policy_id 0` is not *reserved* — it stays the
first policy's id. The issue's literal text asks for reservation. Path C
delivers the issue's stated *goal* (retire the overload; make the
deletion-clear precise; delete the workaround) without its stated *mechanism*.
A reviewer may legitimately reject this as not-the-ask; §11 Q1 puts that
question directly.

#### Path D — keep the ids, add an explicit `policy-attributed` discriminator bit

Thread a boolean "this `policy_id` is meaningful" through
`SessionMetadata` (Rust) → `publish_conntrack` → `SessionValue` (Go) → cluster
wire → display. It can ride a **free bit in the existing `LogFlags u8`** (bits
2-5 are unused; bits 6-7 are already used for userspace-only sync metadata) —
and `LogFlags` **is** on the cross-chassis wire at a fixed offset
(`sync_protocol.go:170/285` encode, `:455/586` decode), so this costs **zero
wire growth**. Old peer never sets it → receiver reads false → fail-safe. Old
receiver ignores the bit → unchanged.

Then `clearSessionsForPolicyIDs` matches `attributed && ids[PolicyID]` and the
`continue` can go **on day one**, because an unset bit already means "do not
attribute".

**Cost**: the discriminator must reach every surface that today reads the bare
scalar — including the RT_FLOW event codec (`event_stream/codec/rt_flow.rs`),
which is a *separate* path from the session table, or the durable syslog record
keeps the ambiguity Path C removes. More plumbing than Path C for the same end
state, and it leaves the wire scalar non-self-describing (an off-box collector
reading `policy_id` alone still cannot tell).

### 5.5 Recommendation

**Ship Path C.** It is the only path that removes the overload while changing
**no real policy's id**, which is what makes both mixed-version directions
provably safe without a protocol gate, without an ingress/egress translation
layer, without touching the ~14 open-coded packing sites, without a capacity
change, and without breaking numeric continuity with archived RT_FLOW records.
It reuses a pattern already shipped and load-bearing in this exact field
(`DefaultPolicySentinelID`), and its migration story is a clean two-release
deprecation rather than a live-window translation.

Path D is the credible runner-up and is *strictly better on one axis* (the
`continue` can go on day one). Prefer it only if reviewers judge the
deprecation lag unacceptable. Path B is defensible only if reviewers insist on
the literal "ids start at 1"; it should then be costed with the egress-downgrade
requirement included, which the issue text does not anticipate. Path A should be
recorded as rejected so it is not re-proposed.

---

## 6. Public API preservation

Path C preserves every signature and every value that is not the non-policy
sentinel:

- `userspace.StablePolicyRuleID`, `PolicyIDsByStableKey`, `RuntimePolicyIDs`,
  `RuntimePolicyIndex`, `walkPolicyRuleSlots`, `policyRuleSlot.policyID()` —
  unchanged, and every real policy keeps its current numeric id.
- `dataplane.SessionPolicyName`, `ReservedPolicyName`, `PeerSessionPolicyName` —
  signatures unchanged; `ReservedPolicyName` gains one `case`.
- `ReadPolicyCounters` / `policyRuleIDForCounter` — unchanged; the counter-handle
  namespace is untouched.
- gRPC `PolicyRule.policy_id` stays `optional uint32` (#3623 explicit presence);
  no `.proto` change, no regen.
- `cluster` wire layout, `SessionSyncWireVersion`, `CurrentHAProtocolVersion`,
  `userspace.ProtocolVersion` / `CONFIG_SNAPSHOT_PROTOCOL_VERSION` — all
  unchanged. **No `protocol_wire_v1.json` regeneration.**

New exported surface: `dataplane.NoPolicySentinelID` (+ a name constant if the
rendered string is to differ from `unattributed`; recommendation is to reuse
`UnattributedPolicyName` so operator-facing output does not change).

---

## 7. Hidden invariants the change must preserve

1. **Sentinel disjointness.** `0xFFFFFFFE` must be unreachable as a real id. The
   `DefaultPolicySentinelID` argument applies unchanged (a real id needs
   ~16.7M policy sets), and `walkPolicyRuleSlots` caps `ruleIndex` below 256 per
   set. Add a compile-time/unit assertion rather than relying on the prose.
2. **Cross-language constant equality.** `NoPolicySentinelID` (Go) ==
   `NO_POLICY_SENTINEL_ID` (Rust) must be pinned by a contract test, exactly as
   `DefaultPolicySentinelID` is.
3. **Reserved-before-lookup ordering.** `SessionPolicyName` and
   `PeerSessionPolicyName` document this as LOAD-BEARING; adding a third
   reserved value must go through `ReservedPolicyName` and must not be
   "simplified" into a map lookup with a fallback.
4. **`reresolve_session_policy_id` must not re-resolve the new sentinel.** The
   `bound = None` arm preserves the stamped value, which is correct; but a
   non-policy session that somehow carries a bound counter must not be
   re-stamped into a real id. Assert the `None` arm covers every non-policy
   install site.
5. **The deletion-clear's sweep set must never contain a reserved value.**
   `PolicyIDsByStableKey` derives from configured policies only; a test must pin
   that neither sentinel can enter the set.
6. **`DuplicatePolicyId` (M01) excludes 0 for a stated reason that may already
   be stale.** Its comment justifies the exclusion by "a legitimate older-peer /
   hand-built snapshot that simply omits policy_id (all-zero)" — but
   `apply_snapshot` rejects any snapshot whose `version` is not exactly
   `CONFIG_SNAPSHOT_PROTOCOL_VERSION` *before* the integrity preflight runs
   (`server/handlers/snapshot.rs:25`), so an older producer cannot reach it. If
   that holds on every entry point (there is a second version check at
   `snapshot.rs:446` — both must be audited), the 0-exclusion could be dropped
   independently of this work. **Do not fold that into the same change**; file
   it and cite the audit.
7. **HA delete-sync symmetry (#2468).** Any change to what the clear targets
   must keep the peer-side delete propagation identical, or a session dropped on
   the owner resurrects on failover.
8. **`policy_id` is node-local.** `PeerSessionPolicyName` documents that
   re-resolving an unreserved peer id against the LOCAL map is a fresh
   misattribution. Nothing in this change may start doing that.

---

## 8. Risk assessment

| Class | Path C | Path B | Note |
|---|---|---|---|
| **Behavioral regression** | **LOW** | **HIGH** | C changes no real id, so no comparison against a config-derived set changes meaning. B reinterprets every peer-synced id during the upgrade window (§5.1). |
| **Lifetime / borrow-checker** | **LOW** | **LOW** | Both are scalar-value changes; no new borrows, no allocation on the hot path. The stamping sites are struct-literal fields. |
| **Performance regression** | **NONE** | **NONE** | No hot-path work added. C changes a constant stored in `SessionMetadata`; D would add a bit test on the display/clear paths only. |
| **Architectural mismatch** | **LOW** | **MED** | C is the third instance of a pattern the codebase already committed to (#3057, #6851). B introduces a bidirectional wire-translation layer that exists nowhere else in this codebase and that must be maintained across future numbering changes. |

Residual risks for the recommended path:

- **The deprecation lag is real.** For one release the `continue` and the
  0-render arm stay, so the first policy's deletion-clear and its RT_FLOW
  attribution are unchanged. The issue is only *half* closed at release *N*.
  This must be stated in the PR and on the issue, not glossed.
- **Site-completeness.** Every non-policy stamping site must move together. A
  missed site keeps stamping 0 and becomes a *new* first-policy misattribution
  the moment the 0-render arm is removed in release *N+1*. The mitigation is an
  exhaustive-match/enumeration guard, not a grep.

---

## 9. Test plan

1. `cargo build --release` clean; full `cargo test --release` in `userspace-dp`
   (0 failed); `make test-go` across the affected packages (`pkg/dataplane`,
   `pkg/dataplane/userspace`, `pkg/daemon`, `pkg/cli`, `pkg/api`, `pkg/grpcapi`,
   `pkg/logging`, `pkg/cluster`).
2. **Cross-language constant contract test** pinning
   `dataplane.NoPolicySentinelID == NO_POLICY_SENTINEL_ID`, alongside the
   existing `DefaultPolicySentinelID` pin.
3. **Sentinel-disjointness test**: no config reachable through
   `walkPolicyRuleSlots` can produce either sentinel; and
   `PolicyIDsByStableKey` never emits one.
4. **Stamping-site completeness**: a Rust test that every non-policy install
   path (neighbor-seed, fabric, tunnel, host-inbound, flow-cache seed) produces
   `NO_POLICY_SENTINEL_ID`, each as its **own** assertion — one fixture per
   site, so removing any single site's change reds a distinct test.
5. **Mixed-version matrix, both directions**, as unit tests over the decode /
   render / clear functions (no cluster required):
   - old-peer session (`policy_id = 0`) → renders `unattributed`, is **not**
     swept when the first policy is deleted;
   - new-peer session (`policy_id = 0xFFFFFFFE`) on a node that knows the
     sentinel → renders `unattributed`, not swept;
   - new-peer session on a node that does **not** know it (simulate by calling
     the pre-change resolver) → renders empty, not swept — i.e. the
     Direction-2 claim in §5.4 is a *test*, not an assertion.
6. **Revert-probe discipline**: each new assertion must be shown RED when its
   specific production line is reverted — and the RED must be an assertion
   failure, not a build break.
7. **Loss-cluster smoke** (`loss:xpf-userspace-fw0/fw1`) is **required** because
   the change touches session metadata that crosses the HA wire: v4+v6,
   push+reverse, CoS-off and CoS-on, plus `make test-failover` (any change
   touching session sync must pass it). Confirm host-inbound (SSH to the
   firewall itself) and fabric sessions render `unattributed` and that a
   first-policy delete does not disturb them.
8. **Negative control** for the mixed-window tests: a session admitted by a real
   first policy (`policy_id = 0`) must be distinguishable in the *release N+1*
   test set from a non-policy session — otherwise the tests pass with the defect
   present.

---

## 10. Out of scope (explicitly)

- **M03** — shipped (#4787).
- **L14** (default-policy invalidation into the runtime-id framework) — unblocked
  by this work, not delivered by it.
- **Dropping `DuplicatePolicyId`'s 0-exclusion** — see §7.6; file separately with
  the entry-point audit.
- **Removing `optional` from gRPC `policy_id`** (#3623 explicit presence) — a
  proto wire change with no benefit here.
- **Removing the #6851 render guards** — they stay for the deprecation window
  and their `0` arm is only reconsidered at release *N+1*.
- **`MaxRulesPerPolicy` capacity changes** — only Path B implies one; the
  recommended path does not.
- **Any renumbering of real policy ids** — explicitly the thing this plan
  recommends against.

---

## 11. Open questions for adversarial review

**Q1 — Is Path C an acceptable answer to an issue that asked for "reserve 0 and
start real ids at 1"?** It achieves the goal (retire the overload, delete the
workaround, unblock L14) via the inverse mechanism (move the sentinel off 0
rather than move policies off 0). If a reviewer holds that the literal
reservation has value Path C does not capture — e.g. a future consumer that must
treat `policy_id == 0` as structurally invalid — say so and it changes the
recommendation to Path B with the §5.4 egress-downgrade included. **This
question alone can PLAN-KILL the recommendation.**

**Q2 — Is the §5.0 claim that local sessions cannot survive an xpfd restart
actually airtight?** The whole "only peer-synced sessions carry stale-numbering
ids" argument rests on it. `ensureProcessLocked` spawns the helper as a child
and unlinks the control socket, but: what happens if xpfd is SIGKILLed and the
orphaned helper keeps running with its table intact — can a newly started xpfd
ever reach that *old* helper (e.g. socket path raced, or a helper that re-binds)?
If yes, Path B acquires an intra-node skew it does not currently plan for, and
even Path C's reasoning about who stamps what needs revisiting.

**Q3 — Is the "bumping `CurrentHAProtocolVersion` does not stop session sync"
finding correct?** §5.1 asserts the sync connection has no version handshake and
that `HAProtocolVersionMismatch` only gates transfer readiness / the #1930
image-replace gate. If there is an admission path that *does* refuse sync frames
on version mismatch, Path B becomes materially cheaper and the recommendation
may flip. Verify against `pkg/cluster/sync_admission.go`, `sync_conn.go`,
`sync_auth.go`.

**Q4 — Is the two-release deprecation lag acceptable, or does it make the change
not worth shipping?** Release *N* leaves both visible symptoms (first-policy
delete does not clear; first-policy denies log `unattributed`) exactly as they
are today; only release *N+1* pays off. If the project has no mechanism that
reliably raises `MinCompatHAProtocolVersion` on a schedule, release *N+1* may
never arrive and Path C ships pure churn. Path D avoids the lag entirely at the
cost of more plumbing — is that trade worth reversing the recommendation?

**Q5 — Does Path C actually cover the RT_FLOW / event path, or only the session
table?** The events at `event_emit.rs:262/306/362/498` stamp `policy_id: 0`
independently of session install, and `event_stream/codec/rt_flow.rs` carries
its own `policy_id`. If any deny/screen/filter event legitimately carries 0
today for a reason unrelated to "no policy admitted this", moving those to the
sentinel could change what a collector sees in a way this plan has not costed.
Enumerate every one of those sites and classify it.

**Q6 — Is the `0xFFFFFFFE` choice right, or should the non-policy population
simply reuse `DefaultPolicySentinelID`?** A host-inbound session was not
admitted by the implicit default policy either, so reusing it would be a
different lie — but it would require no new constant, no contract test, and no
new render arm. Argue whether the distinction between "no policy applied" and
"the implicit default applied" is operationally load-bearing on the session and
RT_FLOW surfaces.

**Q7 — Should this be PLAN-KILLed as WONT-FIX instead?** The prior converged
verdict on this issue was PLAN-DEFER. Since then the *display* half was fixed by
#6851 and the remaining payoff is one exempt policy in the deletion-clear plus
one under-claimed name on a durable log surface. A reviewer who weighs that
against a cross-plane change touching HA-visible session metadata and concludes
"record it as an accepted, documented limitation and close" is giving a
defensible answer. State plainly which side you land on and why.
