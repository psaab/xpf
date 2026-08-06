# #4626 L01 — retire the overloaded `policy_id` wire value 0

## 1. Status

`REVISION v2 — round-1 reviews folded (Codex PLAN-NEEDS-MAJOR, Claude SMR
PLAN-NEEDS-MAJOR, AGY infra-blocked); recommendation FLIPPED to the literal
reservation`

**What changed from v1, and why.** v1 recommended moving the *sentinel* off 0
(Path C) rather than moving *policies* off 0. Round-1 review demolished two of
the three legs that recommendation stood on, and both retractions were verified
firsthand against the tree before folding:

- **v1 §5.2's `divmod`/capacity objection to renumbering was wrong.** I
  conflated two id namespaces the codebase deliberately keeps separate.
  `policyRuleIDForCounter` decodes the **raw slice-index counter handle**, not
  the runtime `policy_id` — its own doc comment says so
  (`pkg/dataplane/userspace/policycounters.go:47-68`), and no production caller
  passes a runtime id to that `divmod`. Under a uniform `+1` the runtime ranges
  are `[n*256+1, (n+1)*256]` and `[(n+1)*256+1, (n+2)*256]` — **disjoint**, with
  **no capacity loss** (all 256 slots retained). The objection is retracted in
  full; see §5.2.
- **A production path manufactures `policy_id 0` on a homogeneous
  new-build fleet.** The JSON/RPC session-delta fallback carries no policy id at
  all: `SessionDeltaInfo` (`userspace-dp/src/protocol/binding.rs:1147`) has no
  `policy_id` field, its constructor
  (`userspace-dp/src/afxdp/session_delta.rs:200`) never sets one, and the Go
  fallback loop drains that queue every 100 ms while disconnected and every 5 s
  while connected (`pkg/daemon/daemon_ha_userspace_stream.go:254`), stamping 0
  into the cluster session value. **Verified: the field list of
  `SessionDeltaInfo` contains no policy field.** This is decisive — see §5.0.1.

A third round-1 finding was also verified and widens the scope: there is a
**second** `if id == 0 { continue }` exclusion, in `changedPolicyRuntimeIDs`
(`pkg/daemon/daemon_policy_invalidate.go:443-447`, the policy-rematch half).
v1 named only the deletion-clear one.

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

Because of the overload, **four** sites carry a permanent workaround:

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
- `pkg/daemon/daemon_policy_invalidate.go:443-447` — the **same exclusion
  again**, in `changedPolicyRuntimeIDs`, the policy-rematch half (#4234's other
  leg, gated on `newCfg.Security.PolicyRematch`). Removing only the first
  `continue` leaves first-policy *rematch* invalidation broken. Any plan must
  name both. (Round-1 Codex finding, verified.)
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
| First-policy MODIFY does not rematch its sessions | **Present** — the second exclusion at `daemon_policy_invalidate.go:443-447` |
| First policy's denies log as `unattributed` | **Present** — an under-claim introduced by #6851, correct for the larger population |
| Two rules aliasing on `policy_id 0` not rejected | **Present**, only reachable from a corrupt/hand-built snapshot |
| Real sessions stamped `policy_id 0` by the JSON/RPC fallback | **Present and NOT previously recorded** (§5.0.1) — a live attribution hole on master, independent of this issue |

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

Three facts bound the blast radius of breaking that invariant. The first is
**narrower than v1 claimed** and the correction matters:

- **No helper ADOPTION path exists, but "no old-stamped local state survives a
  restart" is NOT proven.** The helper is a child process spawned by
  `ensureProcessLocked` (`pkg/dataplane/userspace/process.go:76-95`), the
  control socket is unlinked and re-created on every bring-up, and a graceful
  `stopLocked` (`process.go:197-227`) sends `shutdown` and reaps the child — so
  a new xpfd never talks to an old helper's table *through the control socket*.
  Round-1 review identified two residual channels that v1 asserted away and that
  a renumbering design MUST discharge explicitly rather than assume:
  1. **Orphan helper on the event socket.** After a SIGKILLed xpfd, the orphan
     survives and retries the event socket, which the new daemon starts
     *before* spawning its replacement helper, and
     `pkg/dataplane/userspace/eventstream.go:436` accepts an event-stream client
     without checking PID or helper incarnation. Old-stamped rows can therefore
     reach the new xpfd and be forwarded to the HA peer.
  2. **Pinned BPF session maps.** `sessions` and `sessions_v6` are in
     `pinnedMaps` (`pkg/dataplane/loader_userspace_shim.go:72-90`) and
     deliberately survive daemon restarts; their values carry `PolicyID`. There
     *is* a startup flush — `maps_sync.go:577` empties the userspace session map
     on the first ctrl-enable after daemon startup, gated by
     `!m.initialCtrlCleanupDone` — but that is a flush the design **depends
     on**, not an absence of state. It must be cited as a proof obligation with
     its own test, not assumed.
- **Peer-synced sessions are the population that certainly survives** — on a
  rolling upgrade the freshly restarted node repopulates its **entire** table
  from the not-yet-upgraded peer, every row stamped in the peer's numbering.
  #3395 never re-resolves them (`bound = None`).

So "the mixed-version hazard" is not a corner case: **on a rolling upgrade the
new node's whole session table carries old-meaning ids**, and there are two
additional intra-node channels a renumbering must fence.

### 5.0.1 The finding that decides the mechanism: zeros are MANUFACTURED

The question "should 0 mean the first policy, or should 0 mean nothing?" is not
a matter of taste in this codebase, because **`policy_id` is produced by paths
that structurally emit zero when they carry no value at all**:

- The JSON/RPC session-delta fallback carries **no policy id whatsoever**.
  `SessionDeltaInfo` (`userspace-dp/src/protocol/binding.rs:1147`) has no
  `policy_id` field — verified by enumerating its field list — and its
  constructor (`userspace-dp/src/afxdp/session_delta.rs:200`) never sets one,
  while the Go side's `SessionDelta` *does* expect `PolicyID`
  (`pkg/dataplane/userspace/protocol_ha.go:93`). The production fallback loop
  drains that queue every 100 ms while the event stream is disconnected and
  every 5 s even while connected
  (`pkg/daemon/daemon_ha_userspace_stream.go:254`), so the conversion stamps
  **0** into the cluster session value and a later reconciliation copy can
  overwrite an earlier, correct binary-stream copy on the peer.
- `PolicyID` is `json:"policy_id,omitempty"` on both the snapshot rule
  (`protocol_policies.go:305`) and the HA request (`protocol_ha.go:93`), and the
  Rust side decodes with `serde(default)`. **A zero is indistinguishable from an
  omission by construction.**

This is a live property of master, independent of anything this plan does. Its
consequence for the design is decisive:

> Under "0 is a real policy", every manufactured / defaulted / forgotten zero
> becomes a **confident attribution to the first configured policy** the moment
> the id-0 guards are removed — and, through the deletion-clear, a sweep of that
> policy's sessions. Under "0 is reserved", every manufactured zero degrades to
> **unattributed** — an under-claim that is already the shipped rendering.

The literal reservation is therefore not merely the issue's stated preference;
it is the option whose **default value fails safe** in a codebase that
demonstrably produces defaults. That property is what v1 failed to weigh, and it
is why the recommendation in §5.5 is now the literal reservation.

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

**Correction to v1's claim about what an old build renders for an id it does not
know.** v1 asserted "renders empty". It does not, uniformly — verified:
- CLI falls back to the numeric value (`pkg/cli/cli_show_flow.go:348`), printing
  e.g. `4294967294/4294967294`;
- REST and gRPC carry the numeric id with an empty name;
- **RT_FLOW renders the decimal string AS THE POLICY NAME**
  (`pkg/logging/ringbuf.go:292-301`: reserved check, then map lookup, then
  `fmt.Sprintf("%d", id)`), so a durable syslog record says
  `policy name 4294967294`.

That is still safe — no *configured policy* is misattributed — but it is not the
strict UX improvement v1 implied, and it applies to any scheme that puts an
unknown value on the wire toward an old peer.

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

### 5.2 `MaxRulesPerPolicy` boundary arithmetic — v1's objection RETRACTED

**v1 claimed a uniform `+1` shift corrupts the packed-id `divmod` decode and
forces per-set capacity from 256 down to 255. That claim was wrong and is
withdrawn.** It conflated two id namespaces the codebase keeps deliberately
separate:

- `policyRuleIDForCounter` (`pkg/dataplane/userspace/policycounters.go:90-91`)
  does `policyID / 256` / `policyID % 256` — but on the **raw slice-index
  counter handle**, not on the runtime `policy_id`. The function's own doc
  comment states the split explicitly (`policycounters.go:47-68`: "two distinct
  numeric namespaces coexist by design, and this resolver intentionally lives in
  the SLICE-INDEX one, NOT the span-accumulated snapshot-PolicyID one"), and no
  production caller passes a runtime id to it.

With that corrected, a uniform `+1` on the **runtime** id is clean:

| | set *n* occupies | |
|---|---|---|
| today | `[n*256, n*256+255]` | 256 slots |
| `+1` | `[n*256+1, n*256+256]` | 256 slots |

Set *n*'s maximum is `(n+1)*256`; set *n+1*'s minimum is `(n+1)*256+1`. The
ranges are **disjoint**, no id is shared, and `walkPolicyRuleSlots`'s
`ruleIndex+span > MaxRulesPerPolicy` guard is untouched because it caps the
**index**, not the final id. **All 256 slots per set are retained.** Nothing
needs to become 255.

The real arithmetic obligations that remain are narrower and must still be
discharged:

1. `RuntimePolicyIndex`'s fallback (`policies_ids.go:127`) returns the
   **unshifted** raw ordinal when the map misses. That miss only happens for a
   config that overflows `MaxRulesPerPolicy` and is rejected at apply, so it is
   not reachable in enforcement — but the fallback must be shifted too, or
   deleted, so the two spaces cannot silently mix.
2. Should a runtime-id `divmod` decoder ever be introduced, it must decode
   `id-1`. Add a comment at the SSOT (`policies.go:63`) saying so.
3. The 21 open-coded `policySetID*MaxRulesPerPolicy + i` occurrences (enumerated
   in `claude-smr-plan-r1.md` §S3) span **four** namespaces — runtime allocation,
   runtime-display fallback, legacy-compiler rule ids, and physical BPF map keys
   — and they do **not** all move together. The implementation must classify
   each one before touching it; treating them as a single space (as v1 implied)
   is itself a defect risk.

### 5.3 Persisted state — no config-DB migration, but three durable stores DO hold ids

**The config DB needs no migration.** Verified: `pkg/configstore` contains no
`PolicyID`/`policy_id` reference at all — it persists Junos configuration TEXT,
and ids are re-derived at compile time on every load. So there is no stored-id
schema to migrate and no rollback-compatibility problem in the config store.

**v1's broader "only RT_FLOW persists ids" claim was wrong.** Three durable
stores carry numeric policy ids and each needs an explicit disposition:

1. **Pinned BPF session maps.** `sessions` / `sessions_v6` are in `pinnedMaps`
   (`pkg/dataplane/loader_userspace_shim.go:72-90`) precisely so they survive a
   daemon restart, and their values carry `PolicyID`. The design relies on the
   first-ctrl-enable flush (`pkg/dataplane/userspace/maps_sync.go:577`, gated by
   `!m.initialCtrlCleanupDone`) to clear them; that reliance must be a **stated
   invariant with its own test**, because if the flush is ever narrowed the
   renumbering silently acquires an intra-node stale-id population.
2. **The helper state file.** It serializes the `ConfigSnapshot`, whose policy
   records contain `policy_id` (`userspace-dp/src/server/helpers/persistence.rs:25`).
   This is observability persistence, not restored runtime state, so it needs no
   migration — but a stale file read by an operator after an upgrade shows the
   old numbering and should be noted.
3. **RT_FLOW records already shipped off-box.** A renumbering makes archived
   records disagree with a current `show security policies` Index for the same
   policy. This is the genuine forensic-continuity cost of the recommended path
   and must go in the release note. It is bounded: the records carry the stable
   `rule_id` string too, so a collector that joins on `rule_id` is unaffected.

### 5.4 The four paths

#### Path A — bare uniform `+1` shift, nothing else

`policies.go:63` becomes `... + s.RuleIndex + 1`, with no compatibility work.

**Rejected**, but for **one** reason, not v1's two: it hits both mixed-version
failures in §5.1. The §5.2 arithmetic objection v1 also levelled at it is
withdrawn — the shift is arithmetically clean and costs no capacity. Path A is
rejected as *incomplete*, not as *wrong in principle*, and Path B′ is the
completed version of it.

#### Path B′ — uniform `+1` reservation + peer capability + ingress normalise + egress downgrade (**RECOMMENDED**)

This is the issue's literal request, made safe.

**Numbering.** `policyRuleSlot.policyID()` returns
`PolicySetID*MaxRulesPerPolicy + RuleIndex + 1`. Zero is never assigned to any
configured policy. All 256 slots per set are retained (§5.2). The
`RuntimePolicyIndex` fallback shifts with it. `UnattributedPolicyID = 0` keeps
its existing name and rendering (`unattributed`) and becomes **structurally**
true rather than an under-claim.

**Both id-0 exclusions are deleted** (`daemon_policy_invalidate.go:72-77` and
`:443-447`), because `PolicyIDsByStableKey` can no longer emit 0 — replace each
with an assertion that the sweep set contains neither reserved value, so a
future regression is caught rather than silently re-sweeping.

**Peer capability.** Advertise `policy_id_space: u8` in the existing **optional
heartbeat version trailer** (`pkg/cluster/heartbeat.go:97-125`), where an absent
trailer already means "legacy". Absent ⇒ space 0 (today's numbering); 1 ⇒
reserved space. This is additive and does **not** bump
`CurrentHAProtocolVersion`, so it does not block manual failover or trip the
#1930 mixed-base image gate — the DHCP-lease-sync precedent (`sync.go:68-73`)
endorses exactly this for additive, gated changes. It is a **capability**, not a
version gate, because §5.1 established that a version bump does not gate frame
admission anyway.

**Ingress normalisation** (protects Direction 1). A session imported from a peer
advertising space 0 has its `policy_id` rewritten to `0` (reserved) on import.
Both of that peer's populations collapse to `unattributed` — which is what every
surface already renders for id 0 today, and what the current exclusion already
does behaviourally. **Nothing regresses; the ambiguity is confined to the one
door that can absorb it.**

**Egress downgrade** (protects Direction 2 — the direction ingress cannot
reach). To a peer advertising space 0, send `policy_id - 1`, an exact inverse
because the delta is a uniform constant and both nodes compile the same
text-synced config. The old peer then resolves its own numbering correctly. If
reviewers judge the downgrade too clever, the fallback is to send `0` to a
space-0 peer, which is fail-safe (that peer renders `unattributed` and its own
exclusion refuses to sweep) at the cost of attribution during the window.

**Intra-node fencing** (the §5.0 residuals): the event-stream accept path must
reject a client that is not the current helper incarnation
(`eventstream.go:436`), and the first-ctrl-enable flush of the pinned session
maps must be pinned by a test (§5.3).

**Prerequisite, and it is independently worth doing:** add `policy_id` to
`SessionDeltaInfo` + its constructor so the JSON/RPC fallback stops
manufacturing zeros (§5.0.1). Under this path a manufactured zero is *harmless*
(it reads as `unattributed`), so this is a quality fix rather than a safety
gate — which is precisely the asymmetry that makes this path the right one.

**Costs, stated plainly:** the operator-visible `show security policies` Index
shifts by one for every policy; RT_FLOW numeric ids shift, breaking numeric
continuity with archived records (§5.3.3); two new wire behaviours must be
tested in both directions; and every one of the 21 open-coded sites must be
classified by namespace before being touched (§5.2.3).

#### Path C — move the *sentinel*, not the *policies* (**v1's recommendation — now REJECTED**)

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

> **Round-1 outcome: REJECTED.** Path C's *transitional* safety survived review
> — while both id-0 guards remain it is very nearly today's behaviour — but its
> **end state is unsafe**. Once the guards are removed, every manufactured or
> defaulted zero (§5.0.1: the JSON/RPC fallback carries no policy id at all;
> `omitempty` + `serde(default)` make zero indistinguishable from omission)
> becomes a confident attribution to the first configured policy **and** a sweep
> target when that policy is deleted. Path C's retirement mechanism was also
> fictional: release *N* adds no version or capability, so it is indistinguishable
> from every pre-*N* build, and `MinCompatHAProtocolVersion` is image metadata,
> not runtime sync admission — there is no boundary at which the guards could
> actually be dropped. Retained below in full because its *transitional*
> reasoning is sound and is reused by Path B′'s ingress normalisation.

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

**The predicate v1 gave was wrong.** `attributed && ids[PolicyID]` breaks
rolling compatibility: an old peer leaves the bit clear for **every** session,
including all its legitimate non-zero ids, so a deleted policy's synced sessions
stop being swept across the whole id space. The compatible rule is

```text
effective_attributed = policy_id != 0 || attributed_bit
```

i.e. the bit disambiguates **zero only** and every non-zero id keeps meaning
what it means. (Round-1 Codex finding; correct.)

With that correction the `continue` can go **on day one** for locally installed
sessions, which is Path D's genuine advantage.

**Cost**: more plumbing than v1 admitted. The bit must reach Rust
`SessionMetadata`, the same-host event flags, the JSON/RPC fallback (§5.0.1 —
which today carries no policy field at all), the Go→Rust import, the BPF
publication path (`log_flags` is currently hardcoded zero there), **and** the
separate RT_FLOW codec (`event_stream/codec/rt_flow.rs`) — otherwise the durable
syslog record keeps the ambiguity. It is not "one cheap bit". It also leaves the
wire scalar non-self-describing: an off-box collector reading `policy_id` alone
still cannot tell, and a *forgotten* field still defaults to a real policy.

### 5.5 Recommendation (revised at r2)

**Ship Path B′ — the literal reservation.** v1 recommended Path C; round-1
review removed both of the legs that recommendation rested on, and the revised
comparison is not close:

1. **Default-value safety is the deciding property.** §5.0.1 establishes that
   this codebase *manufactures* zeros on a production path (`SessionDeltaInfo`
   carries no policy id) and *structurally* (`omitempty` + `serde(default)`).
   Under Path B′ every such zero reads as `unattributed` — fail-safe. Under
   Path C every such zero becomes a confident first-policy attribution and a
   sweep target — fail-dangerous. A design whose forgotten-field behaviour is
   safe beats one whose forgotten-field behaviour is a security-surface lie,
   and no amount of test coverage substitutes for that asymmetry.
2. **The unique technical objection to renumbering evaporated.** §5.2's `divmod`
   corruption and capacity loss were my error. Renumbering is arithmetically
   clean and costs no slots.
3. **Path C's retirement mechanism did not exist.** Its guards could never
   actually be dropped, so it delivered no end state — only churn plus an
   automation-visible sentinel change.
4. **The compatibility machinery Path B′ needs is machinery Path C needed too.**
   Round-1 review concluded Path C would itself require a real capability /
   admission invariant to be viable. Once both need it, the path that reaches
   the correct end state wins.

Path D (attributed bit, with the corrected `policy_id != 0 || bit` predicate)
remains a viable runner-up and is the right answer if reviewers judge the
Index/RT_FLOW numeric shift unacceptable; it buys day-one precision at the cost
of threading a bit through six planes and still leaves a forgotten field
defaulting to a real policy. Path C is rejected. Path A is Path B′ without the
compatibility work and must not be shipped alone.

**Sequencing.** The `SessionDeltaInfo` policy-id gap (§5.0.1) should land
**first**, as its own small change: it is a real attribution hole on master
today, it is independently reviewable, and it shrinks the population of
manufactured zeros before the numbering moves.

---

## 6. Public API: what is preserved, and what visibly changes

**Preserved — signatures.** `userspace.StablePolicyRuleID`,
`PolicyIDsByStableKey`, `RuntimePolicyIDs`, `RuntimePolicyIndex`,
`walkPolicyRuleSlots`, `policyRuleSlot.policyID()`,
`dataplane.SessionPolicyName` / `ReservedPolicyName` /
`PeerSessionPolicyName`, `ReadPolicyCounters`. No signature moves.

**Preserved — namespaces and wire layout.** The raw-ordinal **counter-handle**
namespace (`policyRuleIDForCounter`) is untouched. gRPC `PolicyRule.policy_id`
stays `optional uint32` (#3623) — no `.proto` change, no regen. The
cross-chassis frame layout, `SessionSyncWireVersion`,
`CurrentHAProtocolVersion`, `userspace.ProtocolVersion` /
`CONFIG_SNAPSHOT_PROTOCOL_VERSION` are all unchanged; the capability rides the
**existing optional heartbeat trailer**, and `protocol_wire_v1.json` needs
regeneration only if `SessionDeltaInfo` gains its `policy_id` field (the §5.0.1
prerequisite), which is additive.

**CHANGED, and operator/automation visible — state it in the release note:**

| Surface | Before | After |
|---|---|---|
| `show security policies` **Index** | first policy `0` | first policy `1` (every policy +1) |
| RT_FLOW `policy_id` in syslog | `N` | `N+1`; archived records no longer join numerically to a live Index (they still join on the stable `rule_id` string) |
| REST / gRPC session `policy_id` | `N` | `N+1` |
| REST / gRPC / CLI for a non-policy session | `0` → name `unattributed` | `0` → name `unattributed` (**unchanged** — and now structurally true) |

Note the direction of the change: the ambiguous value keeps its rendering and
becomes honest; the unambiguous values shift by one. Any automation that pinned
literal Index/policy_id integers must be updated; automation joining on
`rule_id` is unaffected.

**Tests that pin current numbering and must be updated deliberately**, not
mechanically: `pkg/dataplane/userspace/policy_namespace_3143_3145_test.go:219-220`
(global set's first id `== MaxRulesPerPolicy`),
`pkg/api/security_policy_id_zero_3623_test.go:17` (asserts the first policy
legitimately has id 0 — this test's *premise* is what the change retires, so it
must be rewritten to assert the opposite, not deleted), and the
`userspace-dp/src/policy_tests.rs:7498/7515` cases that require two rules at
`policy_id 0` to parse.

---

## 7. Hidden invariants the change must preserve

1. **Zero is never assigned.** `walkPolicyRuleSlots` must be unable to emit 0 for
   any config, and `PolicyIDsByStableKey` / `RuntimePolicyIDs` must be unable to
   contain it. Pin with a property test over generated configs, not a single
   fixture — the guarantee is universal, so a one-config assertion does not bind
   it. Replace **both** deleted `if id == 0 { continue }` blocks with an
   assertion that the sweep set holds no reserved value, so a regression is
   caught rather than silently re-sweeping.
2. **The upper sentinel stays reachable-in-theory but rejected-in-practice.**
   `DefaultPolicySentinelID` (`0xFFFFFFFF`) is *arithmetically* producible at
   an absurd policy-set count; the shipped code relies on an impossibility
   argument (`pkg/dataplane/types.go:535-541`). The `+1` shift does not change
   that, but since this plan adds a second reserved boundary it should add a
   **production rejection** at the walker (refuse a config whose computed id
   reaches any reserved value) rather than extending the prose argument.
3. **Reserved-before-lookup ordering.** `SessionPolicyName` and
   `PeerSessionPolicyName` document this as LOAD-BEARING. `UnattributedPolicyID`
   keeps its value and its arm; the arm's *justification* changes from
   "ambiguous" to "reserved", and the comment must be rewritten or it will read
   as stale-and-wrong.
4. **`reresolve_session_policy_id`'s `bound = None` arm.** It preserves the
   stamped value, which stays correct: a session carrying the reserved 0 must
   never be re-stamped into a real id.
5. **Ingress normalisation must be the ONLY door.** Every path that admits a
   peer-originated `policy_id` must pass through it — the binary sync decode
   (`sync_protocol.go:415/543`) **and** the JSON/RPC fallback conversion
   (`daemon_ha_userspace_convert.go:385/483`). A missed door reintroduces the
   old-space ids the normalisation exists to exclude. Enumerate them; do not
   grep for one spelling.
6. **`DuplicatePolicyId` (M01) excludes 0 for a reason that is now confirmed
   stale.** Its comment justifies the exclusion by "a legitimate older-peer /
   hand-built snapshot that simply omits policy_id (all-zero)". `apply_snapshot`
   rejects any snapshot whose `version` is not exactly
   `CONFIG_SNAPSHOT_PROTOCOL_VERSION` **before** the integrity preflight
   (`server/handlers/snapshot.rs:25`), and round-1 review confirmed the second
   check at `:446` is the separate `bump_fib` handler, **not** another preflight
   ingress — so an older producer cannot reach it. Under Path B′ a real rule can
   no longer carry 0 either, so the exclusion becomes dead in both directions and
   the check should tighten to reject a duplicate 0. **File as its own change**;
   it is independent validator cleanup and must not be smuggled in under the
   numbering diff.
7. **HA delete-sync symmetry (#2468).** Any change to what the clear targets
   must keep the peer-side delete propagation identical, or a session dropped on
   the owner resurrects on failover.
8. **`policy_id` is node-local.** `PeerSessionPolicyName` documents that
   re-resolving an unreserved peer id against the LOCAL map is a fresh
   misattribution. The egress downgrade does **not** violate this: it rewrites
   an id the LOCAL node owns into the peer's space before sending, which is the
   opposite direction from re-resolving a foreign id locally.
9. **The junos-host distinction.** `to-zone junos-host then permit` DOES stamp a
   real admitting policy id (`poll_descriptor/mod.rs:1880-1900`); only the
   `NoMatch` arm is a non-policy install. A change that treats "host-inbound" as
   uniformly non-policy would erase a real attribution. Round-1 finding,
   verified.
10. **Helper incarnation on the event socket.** `eventstream.go:436` accepts a
    client without checking PID or incarnation, so an orphaned helper can feed
    old-stamped rows to a new daemon (§5.0). Path B′ must fence this, or an
    orphan becomes a third source of old-space ids that no peer capability
    describes.

---

## 8. Risk assessment

| Class | Path B′ (recommended) | Path C (rejected) | Path D | Note |
|---|---|---|---|---|
| **Behavioral regression** | **MED** | **LOW transitionally / HIGH at end state** | **MED** | B′ reinterprets peer-synced ids during the upgrade window and relies on ingress normalisation + egress downgrade to contain it. C is nearly today's behaviour while its guards stand, but its end state turns every manufactured zero into a confident attribution and a sweep target (§5.0.1). D is safe once the predicate is `policy_id != 0 \|\| bit`, but touches six planes. |
| **Lifetime / borrow-checker** | **LOW** | **LOW** | **LOW** | All three are scalar/flag changes at struct-literal sites; no new borrows, no hot-path allocation. |
| **Performance regression** | **NONE** | **NONE** | **NONE** | No hot-path work added; the bit test in D is on display/clear paths only. |
| **Architectural mismatch** | **MED** | **MED** | **MED** | B′ introduces a bidirectional wire translation that exists nowhere else here — but round-1 concluded C needs a capability/admission invariant too, so the asymmetry v1 claimed is not real. |

Residual risks for the recommended path, stated without softening:

- **The numeric shift is externally visible** (§6). Index, RT_FLOW ids and
  structured `policy_id` all move by one. Automation pinned to literal integers
  breaks. This is the price of the correct end state.
- **Translation completeness.** Ingress normalisation must cover *both* import
  doors (binary sync decode and the JSON/RPC fallback conversion), and the
  egress downgrade must cover both encode paths. A missed door is a silent
  cross-space id.
- **Capability trust.** The peer capability rides an optional trailer that a
  legacy peer simply omits — correct — but nothing authenticates it beyond the
  existing heartbeat auth. A peer that lies about its space is a
  misconfiguration, not an attack the plan defends against; say so rather than
  implying a guarantee.
- **Orphan-helper and pinned-map fencing** (§5.0, §7.10) are prerequisites, not
  nice-to-haves: each is an unlabelled source of old-space ids.
- **The `SessionDeltaInfo` gap is a live defect on master.** Even if this plan
  is never implemented, that path stamps `policy_id 0` on real sessions today
  and should be filed regardless of the outcome here.

---

## 9. Test plan

1. `cargo build --release` clean; full `cargo test --release` in `userspace-dp`
   (0 failed); `make test-go` across the affected packages (`pkg/dataplane`,
   `pkg/dataplane/userspace`, `pkg/daemon`, `pkg/cli`, `pkg/api`, `pkg/grpcapi`,
   `pkg/logging`, `pkg/cluster`).
2. **Zero-never-assigned property test** over generated configs (varying set
   count, policies per set, application-set expansion spans, nil zone-pair
   slots, globals): `walkPolicyRuleSlots`, `RuntimePolicyIDs` and
   `PolicyIDsByStableKey` never emit `0`. A single fixture does not bind a
   universal claim.
3. **Boundary test at the exact-fill edge**: a set with exactly 256 policies
   still produces ids inside its own range and no id collides with the next
   set's — the §5.2 disjointness argument as a test rather than a table.
4. **Both exclusions**: assert that the deletion-clear AND the rematch sweep
   sets each contain no reserved value, and that deleting/modifying the FIRST
   policy now clears its own sessions. One test per exclusion — a single test
   covering both would stay green if only one `continue` were removed.
5. **Mixed-version matrix, both directions**, as unit tests over the decode /
   render / clear / normalise / downgrade functions (no cluster required):
   - space-0 peer session imported → `policy_id` normalised to `0`, renders
     `unattributed`, not swept on a first-policy delete;
   - space-1 peer session imported → id preserved, renders the real policy,
     swept when that policy is deleted;
   - egress toward a space-0 peer → id downgraded by exactly one, and the
     round-trip through the old decoder names the right policy;
   - egress toward a space-1 peer → id sent unchanged.
   Each arm needs its **own** fixture so a single-arm regression reds a distinct
   test (one fixture binding one match arm).
6. **Negative control for the normalisation**: a LOCAL session admitted by the
   first policy (id `1` after the shift) must still be swept when that policy is
   deleted — otherwise the normalisation test passes with the fix absent.
7. **Pinned-map lifetime proof** (§5.3.1): a test that the first-ctrl-enable
   flush actually empties the pinned session maps, since the design depends on
   it rather than on their absence.
8. **Revert-probe discipline**: each new assertion must be shown RED when its
   specific production line is reverted — and the RED must be an **assertion
   failure**, not a build break. A `+1` that is removed will red many tests at
   once; that is not evidence that any particular test binds its own property,
   so each new assertion needs its own targeted mutation.
9. **Loss-cluster smoke** (`loss:xpf-userspace-fw0/fw1`) is **required** — the
   change touches session metadata that crosses the HA wire: v4+v6,
   push+reverse, CoS-off and CoS-on, plus `make test-failover` (mandatory for
   any session-sync change). Confirm host-inbound (SSH to the firewall itself),
   fabric and tunnel sessions render `unattributed`, that the FIRST policy's
   sessions now clear on its delete, and that a failover mid-stream does not
   drop sessions.
10. **Mixed-build cluster leg.** The one thing unit tests cannot cover is a real
    old binary. Run one failover cycle with node 0 on the new build and node 1
    on the pre-change build (and then reversed), and check attribution and
    clear behaviour on both. Without this leg the compatibility claims are
    reasoned, not measured, and the plan should say so rather than implying
    otherwise.

---

## 10. Out of scope (explicitly)

- **M03** — shipped (#4787).
- **L14** (default-policy invalidation into the runtime-id framework) — unblocked
  by this work, not delivered by it.
- **Dropping `DuplicatePolicyId`'s 0-exclusion** — see §7.6; independent
  validator cleanup, file separately.
- **Removing `optional` from gRPC `policy_id`** (#3623 explicit presence) — a
  proto wire change; harmless to leave, and removing it is not required once
  ids start at 1.
- **Removing the #6851 render guards** — `UnattributedPolicyID`'s arm STAYS. Its
  value and rendering do not change; only its justification does (from
  "ambiguous, so under-claim" to "reserved, so exact"). Deleting the guard would
  be a regression, not a cleanup.
- **`MaxRulesPerPolicy` capacity changes** — none. §5.2 retracts the claim that
  reservation costs a slot.
- **Screen/filter event ids** — `event_emit.rs:306/362/498` are filler fields the
  codec substitutes with `screen_id`/`filter_id`; they are not policy stamps and
  must not be touched (round-1 finding).

---

## 11. Open questions for adversarial review (r2)

Round-1 questions Q1-Q3 and Q5-Q6 are **resolved** and folded into the body:
the substitution was rejected (Q1 → §5.5), the restart-isolation claim was
narrowed and two residual channels named (Q2 → §5.0), the "version bump does not
gate sync frames" finding was independently verified (Q3 → §5.1), the event-site
inventory was corrected (Q5 → §10), and the second-sentinel choice is moot now
that the recommendation does not add one (Q6). The live questions are:

**Q1′ — Is the numeric shift acceptable to operators and automation?** Every
policy's `show security policies` Index moves by one, RT_FLOW records change
value, and archived records stop joining numerically to a live Index (§6, §5.3).
This is the largest externally visible cost of the recommended path and it has
no mitigation beyond a release note and the stable `rule_id` join. If reviewers
judge it unacceptable, the answer is Path D (attributed bit, `policy_id != 0 ||
bit`), which buys day-one precision with no numeric change at the cost of
threading a bit through six planes. **This question decides between the top two
paths.**

**Q2′ — Is the egress downgrade (`policy_id - 1` toward a space-0 peer) sound,
or too clever?** It is an exact inverse only while (a) the delta is a uniform
constant and (b) both nodes compile the same text-synced config. Config sync is
eventually consistent, so during a commit-propagation window the two nodes can
briefly hold different configs. Does that window break the inverse, and if so is
the fail-safe alternative (send `0` to a space-0 peer, accepting `unattributed`
for the window) strictly better? Argue with the config-sync ordering
(#3931 generation guard) in hand.

**Q3′ — Is a heartbeat-trailer capability the right carrier, or does this need a
real admission invariant?** Round-1 review argued that a capability which merely
*advertises* is weaker than one the receiver can *enforce*, since nothing stops a
misconfigured or hand-rolled peer from sending space-0 ids while advertising
space 1. Is advertise-only sufficient given that both nodes are operator-owned
appliances, or must the receiver validate (e.g. reject an id of 0 from a peer
claiming space 1)? A validating receiver is cheap here — under Path B′ a
space-1 peer should never send 0 — so the question is whether to make that a
hard reject or a counter.

**Q4′ — Should the `SessionDeltaInfo` policy-id gap be filed as its own issue
regardless of this plan's outcome?** It stamps `policy_id 0` onto real sessions
on a production path today (§5.0.1), independent of any renumbering. It looks
like a genuine standalone defect. Confirm or refute, and say whether it should
block this work or merely precede it.

**Q5′ — Is the intra-node fencing (orphan helper on the event socket, pinned-map
flush) a prerequisite or a separate hardening item?** Both are sources of
old-space ids that no peer capability describes (§5.0, §7.10). If they are
prerequisites, this plan's real scope is larger than the numbering change and
should be sequenced accordingly; if they are pre-existing and orthogonal, say so
and they leave the critical path.

**Q6′ — Should this still be PLAN-KILLed as WONT-FIX?** The prior converged
verdict was PLAN-DEFER, and #6851 already fixed the display half. What remains
is: one policy exempt from deletion-clear, one policy exempt from rematch, one
under-claimed name on a durable audit surface, and a codebase invariant that
zero-defaults fail safe. Weigh that against a cross-plane change with an
externally visible numeric shift and a bidirectional translation layer. A
reviewer who concludes "document the limitation and close" is giving a
defensible answer; state plainly which side you land on.
