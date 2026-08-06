# #4626 L01 — retire the overloaded `policy_id` wire value 0

## 1. Status

`REVISION v3 — rounds 1 and 2 folded. Recommendation: **Path D** (explicit
attributed discriminator). Path C rejected at r1; Path B′ (the literal
reservation) rejected at r2. Reviewers: Codex PLAN-NEEDS-MAJOR ×2, Claude SMR
PLAN-NEEDS-MAJOR ×2, AGY infra-blocked (7 documented attempts).`

### What changed at v3, and why

v2 flipped to the literal reservation (Path B′) on the strength of a
"default-value safety" argument. **Round 2 established independently, by both
reviewers, that the argument does not discriminate B′ from Path D** — with the
corrected predicate `effective_attributed = policy_id != 0 || attributed_bit`,
a forgotten field defaults to `(0, false)` and reads *unattributed* under D too.
With that leg gone, B′'s remaining costs are not survivable:

- **The translation layer corrupts both reserved sentinels.** A blind
  `policy_id - 1` egress downgrade maps `0` (unattributed) to `0xFFFFFFFF`,
  which an old peer reads as **`default-policy`** — a false attribution that is
  also eligible for default-policy clearing — and maps `0xFFFFFFFF`
  (`DefaultPolicySentinelID`, carried by real default-permit sessions) to
  `0xFFFFFFFE`, so default-policy invalidation misses it. The symmetric ingress
  rule ("rewrite every old id to 0") destroys the same sentinel.
- **`1 → 0` is an arithmetic inverse but not a behavioural one.** An old build
  resolves 0 through `ReservedPolicyName` *before* the map lookup and skips 0 in
  both invalidators, so the first policy — the one policy this issue is about —
  still renders `unattributed` and is still exempt from clearing on the old
  node.
- **Ordinary ids break under routine config skew.** C1 `[A,B,C]` → old ids
  `0,1,2`; the new node commits C2 `[A,C]` → B′ ids `1,2`; `C=2` downgrades to
  `1`; the old peer still on C1 reads `1` as `B`; when it applies C2 its
  deletion sweep for old `B=1` clears the freshly synced `C` session. The
  generation machinery does not close this: local apply completes before the
  config is pushed, and `configEpochStale` rejects only
  `epoch < max(applied, applying)`, so an equal-or-newer session is admitted
  before or during apply.
- **The capability cannot be validated.** A space-1 peer legitimately sends 0
  (for genuinely unattributed sessions) and the old/new non-zero domains
  overlap, so no receiver-side check can prove which numbering produced a bare
  scalar. Advertise-only is therefore not an admission invariant — and the
  carrier itself is unsound as drafted: the `"XPFA"` auth trailer sits
  immediately after the HA version, so a naive "read one more byte" reads `'X'`
  from an authenticated old peer, and session sync can connect and bulk-prime
  before the first 100 ms heartbeat, so "no capability seen yet" cannot be
  taken as "legacy".

**Path D is now the recommendation.** It reaches the same enforcement precision
with no numeric change, no translation layer, and no mixed-version window.

### What changed at v2 (retained — these corrections still stand)

v1 recommended moving the *sentinel* off 0 (Path C). Round-1 review demolished
two of the three legs that recommendation stood on, and both retractions were
verified firsthand against the tree before folding:

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
   in `claude-smr-plan-r1.md` §S3) span **five** namespaces, not four, and they
   do **not** move together. Corrected disposition (round-2 review, verified):

   | Class | Sites | Under a `+1` |
   |---|---|---|
   | runtime SSOT | `policies.go:64` | **must shift** |
   | legacy-compiler `PolicyRule.RuleID` | `compiler.go:924` + its global twin `:1059` | **must shift or be explicitly decoupled** — these keys populate `CompileResult.PolicyNames`, which the session/log/API renderers still consume, so leaving them behind makes new id 1 resolve to the OLD second policy's name |
   | runtime-display fallback | `policies_ids.go:123-127` | **delete, do not shift** — it fabricates a plausible id for a policy the walker never assigned one to, and can collide with another missing entry; surface the absence instead |
   | raw counter handles | 15 sites (`api/metrics.go:1220`, the REST/CLI/gRPC policy renderers, `policycounters.go:239/248`) | **must NOT shift** — shifting one silently reads the wrong counter |
   | physical BPF map keys | `maps_policy.go:45` + the scheduler-update twin `:268` | **must NOT shift** |

   A related invariant break sits outside that table: `pkg/policymatch`
   `matchedResult` indexes the partial `RuntimePolicyIDs` map directly
   (`policymatch.go:1516`), so a miss yields `Matched=true, PolicyID=0` — which
   would contradict a "zero is never assigned" invariant no matter which path
   ships. Fix or document it either way.

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

#### Path B′ — uniform `+1` reservation + peer capability + ingress normalise + egress downgrade (**REJECTED at r2**)

> **REJECTED.** The design below is the issue's literal request and it is
> arithmetically clean (§5.2), but round-2 review killed its compatibility
> layer on four independent grounds — sentinel corruption in both directions,
> a behavioural (not merely arithmetic) inverse failure on exactly the first
> policy, ordinary-id corruption under routine config skew, and an
> unvalidatable capability on an unsound carrier. All four are set out in §1.
> Retained in full because §5.2's arithmetic result and the site classification
> in §5.2.3 remain correct and are cited elsewhere, and because a future reader
> must be able to see *why* the literal request was not taken.

This is the issue's literal request, made safe — or so v2 argued.

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

#### Path D — keep the ids, add an explicit `policy-attributed` discriminator (**RECOMMENDED at v3**)

Thread a boolean "this `policy_id` is meaningful" through
`SessionMetadata` (Rust) → `publish_conntrack` → `SessionValue` (Go) → cluster
wire → display + clear. It can ride a **free bit in the existing `LogFlags u8`**
(bits 2-5 unused; bits 0-1 and 6-7 taken, `types.go:947-958`), and `LogFlags`
**is** carried on the cross-chassis wire at a fixed offset
(`sync_protocol.go:170/285` encode, `:455/586` decode) — **zero wire growth.**

**The predicate is the whole design and it must be exactly this:**

```text
effective_attributed = policy_id != 0 || attributed_bit
```

- A forgotten / defaulted field is `(0, false)` → **unattributed** (fail-safe).
- A real non-zero id from an **old** peer has the bit clear → the `!= 0` arm
  keeps it attributed, so a deleted policy's synced sessions still clear
  correctly across the whole id space.
- Only the first policy's `0` needs the bit, which is exactly the ambiguity
  being retired.

v1's `attributed && ids[PolicyID]` is **wrong** and must not be shipped: an old
peer leaves the bit clear for every session, so that form silently stops
sweeping every non-zero id during an upgrade.

**Why there is no mixed-version window.** No id changes meaning in either
direction. New node ← old peer: non-zero ids resolve correctly (same numbering),
zero reads unattributed — today's behaviour. Old node ← new peer: the old node
ignores an unknown `LogFlags` bit and resolves the id exactly as it does now;
the first policy's zero renders `unattributed` through its own #6851 guard —
again today's behaviour. **No capability, no translation, no negotiation, no
sentinel arithmetic.** Both reserved values (`0`, `0xFFFFFFFF`) keep their
meanings untouched, which is precisely where Path B′ failed.

**What it delivers.** Both `if id == 0 { continue }` exclusions
(`daemon_policy_invalidate.go:72-77` and `:443-447`) can be removed on day one,
with the clear matching `effective_attributed && ids[PolicyID]`; the first
policy's sessions clear on delete and rematch on modify; and its RT_FLOW denies
carry its real name instead of `unattributed`.

**Costs, stated plainly — this is not "one cheap bit":**

1. **Six planes.** Rust `SessionMetadata`; the same-host event flags; the
   JSON/RPC fallback (which today carries no policy field at all, §5.0.1); the
   Go→Rust import (`SessionSyncRequest`); the BPF publication path; and the
   **separate** RT_FLOW codec (`event_stream/codec/rt_flow.rs`) — without that
   last one the durable syslog record keeps the ambiguity this is meant to
   retire.
2. ~~**The BPF publication path hardcodes `log_flags: 0`**~~ — **RESOLVED, and
   it turns out to hand the design its shape.** The hardcode at
   `publish_conntrack.rs:240/382` is real, but `LogFlags` is **not** the
   helper→Go carrier for these bits. Go *synthesises* the byte in
   `daemon_ha_userspace_convert.go:373-379` and `:477-480` from **named
   booleans on the session delta** (`LogSessionInit`, `LogSessionClose`,
   `FabricIngress`, plus the tunnel-endpoint bit) and only then does it ride the
   cross-chassis `LogFlags` byte. The BPF-map mirror is a different,
   non-authoritative consumer. So the carrier is:

   | Hop | Mechanism |
   |---|---|
   | helper → Go | a **named boolean** `policy_attributed` on the session delta, alongside the three that already exist there — in the binary event-stream codec **and** in `SessionDeltaInfo` (Rust `binding.rs`, which already carries `log_session_init` / `log_session_close` / `fabric_ingress` and is exactly the struct missing `policy_id`, §5.0.1) |
   | Go internal | folded into a free `LogFlags` bit (2-5) in `daemon_ha_userspace_convert.go`, the same fold the other three already get |
   | Go → peer | rides the existing `LogFlags` byte at `sync_protocol.go:170/285` — **zero wire growth**, as claimed |
   | Go → helper | a named boolean on `SessionSyncRequest`, mirroring `log_session_init` |

   This follows an established pattern end to end rather than inventing one,
   and it composes with the §5.0.1 prerequisite: the same `SessionDeltaInfo`
   change adds `policy_id` and `policy_attributed` together.

   **Residual, and it is narrower:** the BPF mirror row *does* carry
   `policy_id` (`publish_conntrack.rs:227/369`) while its `log_flags` stays 0,
   so any Go surface that reads the MIRROR rather than the delta-derived table
   would see the id without the discriminator. Enumerate the mirror's consumers
   and confirm none of them resolve a policy name.
3. **The wire scalar stays non-self-describing.** An off-box collector reading
   `policy_id` alone still cannot distinguish. Mitigation: expose the
   discriminator explicitly on the structured surfaces (REST/gRPC session
   objects) and in the RT_FLOW record, rather than leaving it implicit.
4. **`policy_id 0` remains a valid configured id**, so a future validator cannot
   reject it structurally — the one durable advantage the literal reservation
   would have bought.

### 5.5 Recommendation (settled at v3)

**Ship Path D.** Two independent reviewers reached this conclusion in round 2
from different starting positions, and the reasoning is stable across rounds:

1. **The argument that carried v2's flip does not discriminate.** With the
   corrected predicate, a forgotten or defaulted field is `(0, false)` and reads
   *unattributed* under D exactly as it does under B′. §5.0.1's manufactured
   zeros are fail-safe under both, so default-value safety separates B′ from
   Path C — not from D. That was v2's error.
2. **B′'s compatibility layer is not correct and is not fixable cheaply.** It
   corrupts both reserved sentinels in both directions, it is not a
   *behavioural* inverse for the one policy the issue is about, it breaks
   ordinary ids under routine config skew that the generation guard does not
   close, and its capability cannot be validated by any receiver. See §1.
3. **D has no mixed-version window to get wrong.** Nothing changes meaning, so
   the failure modes B′ must engineer around do not exist.
4. **D changes nothing externally visible.** Index, RT_FLOW numeric ids and
   structured `policy_id` all keep their values; archived records keep joining.

What D gives up, honestly: `policy_id 0` remains a valid configured id, so the
scalar is not self-describing and a future validator cannot reject 0
structurally. That is the literal request's one durable advantage and D does not
deliver it. **If reviewers judge the self-describing scalar non-negotiable, the
correct answer is not B′ — it is PLAN-KILL / document-the-limitation**, because
B′'s translation layer is unsound at the values that matter.

Path A and Path B′ are rejected. Path C is rejected.

**Sequencing.** The `SessionDeltaInfo` gap (§5.0.1) lands **first**, as its own
change, and should carry `policy_counter_idx` and the application timeout too —
Go already declares and consumes all three (`protocol_ha.go:162`), so this is a
one-sided Rust omission with no wrong-meaning deployment window. It is a real
attribution hole on master today and is worth filing whatever this plan
converges to.

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

**Under the recommended Path D, no numeric value changes anywhere.** Index,
RT_FLOW ids, structured `policy_id`, counter handles, BPF map keys and the
proto's `optional` presence semantics (#3623 — `MatchPolicies` uses presence to
distinguish matched from unmatched, so `optional` **stays**) are all untouched.
Archived RT_FLOW records keep joining numerically to a live Index. The 21
open-coded packing sites and their five namespaces (§5.2.3) are **not touched at
all** — that table now documents what B′ *would* have had to do, and is retained
as the record of why the literal reservation was costly.

**CHANGED under Path D:**

| Surface | Before | After |
|---|---|---|
| Session row for the first configured policy | name `unattributed`, id `0` | **its real policy name**, id `0` |
| RT_FLOW deny record for the first policy | name `unattributed` | **its real policy name** |
| Session row for host-inbound / fabric / tunnel / old-peer | `unattributed`, id `0` | unchanged |
| First policy delete / modify | sessions idle out | sessions clear / rematch |
| REST + gRPC session objects | no discriminator | **new additive field** exposing whether `policy_id` is meaningful (§5.4 D cost 3) |
| `LogFlags` on the cross-chassis wire | bits 2-5 unused | one bit consumed; old readers ignore it |

Every change is in the direction of *more* precision on the ambiguous
population, and no existing field changes value or type. The only new surface is
the additive discriminator on the structured APIs and the RT_FLOW record.

**Tests whose premise the change retires** (rewrite, do not delete):
`pkg/api/security_policy_id_zero_3623_test.go:17` and
`pkg/grpcapi/server_policy_id_zero_3623_test.go:13` both assert that the first
policy legitimately has `policy_id 0` — under Path D that stays **true**, so
these keep passing; it is the *rendering* that changes and each needs a
companion asserting the discriminator. Under B′ they would have had to be
inverted; that difference is itself an argument for D.

---

## 7. Hidden invariants the change must preserve

1. **The predicate is `policy_id != 0 || attributed_bit` and the `!= 0` arm is
   LOAD-BEARING.** Any "simplification" to `attributed && ...` stops sweeping
   every non-zero id arriving from an old peer. This needs a comment saying so
   at the definition and a test whose only distinguishing mutation is dropping
   the `!= 0` arm.
2. **The discriminator must reach every plane that reads `policy_id`.** Six are
   named in §5.4-D. A plane that reads the scalar without the bit silently keeps
   today's ambiguity — and the RT_FLOW codec is the one that matters most,
   because its output is durable and shipped off-box.
3. **Reserved-before-lookup ordering.** `SessionPolicyName` /
   `PeerSessionPolicyName` document this as LOAD-BEARING.
   `DefaultPolicySentinelID`'s arm is untouched. `UnattributedPolicyID`'s arm
   must now be **conditional on the discriminator** rather than unconditional,
   and that is the single most delicate edit in the change: get it wrong in the
   permissive direction and #6851's misattribution returns.
4. **`PeerSessionPolicyName` must keep trusting the peer's own name for
   unreserved ids.** Policy ids are node-local; re-resolving a peer's id against
   the local map is a fresh misattribution on every mixed-config cluster.
5. **`reresolve_session_policy_id`'s `bound = None` arm** preserves the stamped
   value; the discriminator must ride alongside it unchanged, so a peer-synced
   session's bit is not lost at the refresh tick.
6. **Both reserved values keep their exact meanings.** `0` stays a valid
   configured id; `0xFFFFFFFF` stays the implicit-default sentinel. Path D
   introduces no sentinel arithmetic, and none may be added later without
   re-deriving §1's sentinel-corruption analysis.
7. **`pkg/policymatch` `matchedResult` indexes the partial `RuntimePolicyIDs`
   map** (`policymatch.go:1516`), so a miss yields `Matched=true, PolicyID=0` —
   a *synthetic* zero on an inventory surface. Under Path D that reads as
   "unattributed" only if the discriminator is plumbed there too; otherwise it
   silently names the first policy. Must be covered.
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

| Class | Path D (recommended) | Path B′ (rejected) | Path C (rejected) |
|---|---|---|---|
| **Behavioral regression** | **MED** — nothing changes meaning and there is no mixed-version window, but the discriminator must reach six planes and the `UnattributedPolicyID` render arm becomes conditional; getting that arm wrong in the permissive direction restores #6851's misattribution | **HIGH** — changes every public runtime id, translates every peer-synced session, couples async UDP capability state to TCP session admission, and corrupts both reserved sentinels at the values that matter (§1) | **HIGH at end state** — every manufactured zero becomes a confident attribution and a sweep target |
| **Lifetime / borrow-checker** | **LOW** | **LOW** | **LOW** |
| **Performance regression** | **NONE** — the bit test is on display/clear paths only | **NONE** | **NONE** |
| **Architectural mismatch** | **LOW** — an additive per-session flag on an existing carried byte is a shape this codebase already uses (the `LogFlagUserspace*` bits) | **HIGH** — a permanent bidirectional translation protocol whose correctness depends on config-propagation timing exists nowhere else here | **MED** |

Residual risks for the recommended path, stated without softening:

- **Plane completeness is the whole risk.** Six planes must carry the
  discriminator, and the RT_FLOW codec is a *separate* path from the session
  table. A missed plane leaves the ambiguity exactly where it hurts most —
  in a durable off-box record — while every test that looks at session rows
  goes green.
- **The BPF mirror carries `policy_id` with `log_flags` permanently 0**
  (`publish_conntrack.rs:227/369` vs `:240/382`). The carrier itself is fine
  (§5.4-D cost 2), but any Go consumer reading the mirror instead of the
  delta-derived table would see an id with no discriminator. Enumerate those
  consumers; this is the narrow residual of what looked like a blocking
  carrier problem.
- **The `UnattributedPolicyID` render arm becomes conditional.** It is currently
  unconditional and is documented as LOAD-BEARING in both directions. This is
  the single edit most likely to reintroduce the defect #6851 fixed.
- **The scalar stays ambiguous off-box** unless the structured surfaces and
  RT_FLOW expose the discriminator explicitly. That mitigation is part of the
  change, not a follow-up.
- **Intra-node channels remain unlabelled** (§5.0): an orphaned helper on the
  unauthenticated event socket and the pinned-map flush dependence. Under D
  these do not carry a *wrong-space* id — nothing changes space — so they drop
  from blocking to hardening. Confirm that read before relying on it.
- **The `SessionDeltaInfo` gap is a live defect on master.** Even if this plan
  is never implemented, that path stamps `policy_id 0` on real sessions today
  and should be filed regardless of the outcome here.

---

## 9. Test plan

1. `cargo build --release` clean; full `cargo test --release` in `userspace-dp`
   (0 failed); `make test-go` across the affected packages (`pkg/dataplane`,
   `pkg/dataplane/userspace`, `pkg/daemon`, `pkg/cli`, `pkg/api`, `pkg/grpcapi`,
   `pkg/logging`, `pkg/cluster`).
2. **The predicate's value matrix**, one fixture per cell so a single-cell
   regression reds a distinct test — `(policy_id, bit)` over
   `(0,false) (0,true) (N,false) (N,true) (0xFFFFFFFF,false) (0xFFFFFFFF,true)`
   for both render and clear. The `(N,false)` cell is the one that binds the
   `!= 0` arm: it is the old-peer case, and its only distinguishing mutation is
   dropping that arm.
3. **Both exclusions removed, separately.** One test for the deletion-clear and
   one for the rematch sweep — a single test covering both stays green if only
   one `continue` is removed.
4. **Per-plane coverage, one test per plane.** Session row, REST, gRPC, CLI,
   **RT_FLOW record**, and the peer fan-out (`PeerSessionPolicyName`). The
   RT_FLOW leg must assert on the emitted record, not on a shared resolver, or
   it does not bind the plane that matters.
5. **Mixed-version matrix, both directions**, as unit tests over the
   decode/render/clear functions:
   - old-peer session, real policy, bit clear → attributed, renders the real
     policy, **swept** when that policy is deleted;
   - old-peer session, `policy_id 0`, bit clear → unattributed, **not swept**;
   - new-peer session, first policy, bit set → real name, **swept**;
   - new-peer session, non-policy, bit clear → unattributed, not swept.
6. **Negative control**: a host-inbound session must NOT be swept when the first
   policy is deleted, in the same test file as the positive case — otherwise the
   positive test passes with an over-broad predicate.
7. **Mutation list that must each produce a distinct RED** (not just "revert the
   feature"): drop the `!= 0` arm; invert the render arm's condition; drop the
   bit from any one of the six planes; drop it from the cluster encode but not
   the decode; leave `policyNames[0]` reachable ahead of the guard.
8. **Revert-probe discipline**: each RED must be an **assertion failure**, not a
   build break.
9. **Loss-cluster smoke** (`loss:xpf-userspace-fw0/fw1`) is **required** — the
   change touches session metadata that crosses the HA wire: v4+v6,
   push+reverse, CoS-off and CoS-on, plus `make test-failover` (mandatory for
   any session-sync change). Confirm host-inbound (SSH to the firewall itself),
   fabric and tunnel sessions still render `unattributed`, that the FIRST
   policy's sessions now clear on delete and rematch on modify, and that a
   failover mid-stream drops nothing.
10. **Mixed-build cluster leg — necessary, and it must be designed not to be
    theatre.** A steady identical-config failover proves nothing about the
    decisive claim. It must pin the exact pre-change artifact, exercise
    first-policy / ordinary / unattributed / default-policy sessions, force a
    policy delete and a policy modify while the pair is mixed, reverse which
    node holds config authority as well as which node is new, and cross a
    reconnect. Without those it is a smoke test wearing a compatibility label.
11. **Affected-package list must include `pkg/policymatch`** (§7.7), which v2
    omitted and which synthesises `PolicyID=0` on a map miss.

---

## 10. Out of scope (explicitly)

- **M03** — shipped (#4787).
- **L14** (default-policy invalidation into the runtime-id framework) — unblocked
  by this work, not delivered by it.
- **Dropping `DuplicatePolicyId`'s 0-exclusion** — see §7.6; independent
  validator cleanup, file separately.
- **Removing `optional` from gRPC `policy_id`** (#3623 explicit presence) —
  **keep it.** `MatchPolicies` uses presence to distinguish matched from
  unmatched, and it is now an established compatibility contract. Under Path D
  its rationale (id 0 is a real policy) also stays literally true.
- **Any renumbering of real policy ids** — rejected (§5.5).
- **Any sentinel arithmetic on `policy_id`** — rejected; §1 shows where it
  corrupts `DefaultPolicySentinelID` and the unattributed value.
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

## 11. Open questions for adversarial review (r3)

Rounds 1-2 resolved: the Path-C substitution (rejected, §5.5), restart isolation
(narrowed, §5.0), the version-bump-does-not-gate-sync finding (verified, §5.1),
the event-site inventory (§10), the `divmod`/capacity objection (retracted,
§5.2), the egress-downgrade soundness (**killed**, §1), the ingress-door
inventory (corrected — the real doors are `sync_conn_read.go:98/124`; the
`daemon_ha_userspace_convert.go` path is *egress*, and normalising there would
have corrupted local ids), the heartbeat-capability carrier (**killed**, §1),
the site classification (five classes, §5.2.3), the `SessionDeltaInfo`
sequencing (field-first, no wrong-meaning window), and the risk rating. What
remains:

**Q1″ — RESOLVED before dispatch; verify the resolution rather than the
question.** The `log_flags: 0` hardcode does not block the carrier: `LogFlags`
is synthesised on the Go side from named booleans on the session delta
(`daemon_ha_userspace_convert.go:373-379/477-480`), so the discriminator travels
helper→Go as a boolean exactly like `log_session_init`, and only then rides the
existing `LogFlags` byte cross-chassis. Full hop table in §5.4-D cost 2. **What
still needs checking:** the BPF mirror row carries `policy_id` with
`log_flags` permanently 0, so enumerate the mirror's Go consumers and confirm
none of them resolve a policy name from it. If one does, that surface needs the
delta-derived value instead.

**Q2″ — Where should the discriminator live on the STRUCTURED surfaces?** §5.4-D
cost 3 says REST/gRPC and RT_FLOW should expose it explicitly rather than leave
the scalar ambiguous off-box. Is a boolean the right shape, or should the
surfaces emit a small enum (`policy` / `unattributed` / `default-policy`) that
also absorbs `DefaultPolicySentinelID` and retires the "two reserved values a
client must know about" problem entirely? The enum is more churn and more
value.

**Q3″ — Does Path D genuinely have no mixed-version window, or is that claim
resting on an unexamined path?** The argument is that no id changes meaning, so
both directions degrade to today's behaviour. Attack it: is there any consumer
that would behave differently on receiving a `LogFlags` byte with an unknown bit
set — a strict decoder, a bit-mask comparison, a byte-equality check in a test
or a reconcile path?

**Q4″ — Is the six-plane list complete?** Rust `SessionMetadata`, same-host
event flags, JSON/RPC fallback, Go→Rust import, BPF publication, RT_FLOW codec.
A missed plane leaves the ambiguity in place while session-row tests go green.
Enumerate independently rather than checking the list.

**Q5″ — Should this be PLAN-KILLed as WONT-FIX?** The remaining payoff is: one
policy exempt from deletion-clear, one exempt from rematch, and one under-claimed
name on a durable audit surface. Against that, Path D threads a discriminator
through six planes and makes the #6851 render guard conditional — the edit most
likely to reintroduce the defect that guard exists to prevent. A reviewer who
concludes "document the limitation and close" is giving a defensible answer.
Note that "reserve 0 instead" is **not** an available alternative to that
conclusion: §1 shows why. State plainly which side you land on.
