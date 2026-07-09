# Plan of action — #4626: multi-zone scoped-global scope (M03) + reserve policy_id 0 (L01)

- **Revision:** r1 (initial draft, pre-review)
- **Issue:** #4626 (split from #4415, codex-review-164 backlog)
- **Base:** `origin/master` @ `4eb28ae25` (verified current — every file:line below re-read on this SHA)
- **Mode:** `/research` — STOPS at PLAN-READY / PLAN-KILL / PLAN-DEFER. No PR, no production edits.
- **Reviewers:** Codex (hostile) + Claude SMR (hostile). AGY/gemini infra-down → 2-of-3 with documented Codex retries.

---

## 1. Status

Two coupled but INDEPENDENT sub-items. Proposed converged disposition:

| Sub-item | Verdict (proposed) | One-line |
|---|---|---|
| **M03** multi-zone scoped-global scope | **PLAN-READY** | Concrete cross-plane set-model slice; safe (config text-synced, snapshot per-node atomic); replaces a fail-closed interim with real Junos parity. |
| **L01** reserve policy_id 0 | **PLAN-DEFER** | Latent (not a live bug); the only clean end-state (renumber so no real policy is id 0) has a one-time HA-rolling-upgrade session-stamp mismatch window. Keep the current fail-safe under-clear unless a session-schema version bump lands to carry the migration. |

The two are coupled only through `policy_id`: M03's "expand `[a b]` into N single-zone
rules" shortcut is BLOCKED by the same `DuplicatePolicyId` guard L01 discusses — which is
WHY M03 must be a set-model change, not an expansion. They do not otherwise share code and
can ship independently.

---

## 2. Framing (the problem)

### M03
Junos `security policies global policy <p> match { from-zone [ trust dmz ]; to-zone [ ... ]; }`
(#3148) carries a ZONE LIST. xpf models the scope as a single `string`:

- `config.PolicyMatch.FromZone` / `.ToZone` are `string` (`pkg/config/types_security.go:410-411`
  — the scoped-GLOBAL scope; NOTE there are 3 other FromZone/ToZone string pairs in this file
  at `:350-351` (ZonePairPolicies), `:549` (#3096 NAT from-context), `:574-575` — those are NOT
  the target).
- The compiler reads only the FIRST value token: `pol.Match.FromZone = m.Keys[1]` /
  `= m.Children[0].Name()` (`pkg/config/compiler_security_policy.go:245-256`).

Before #4505 (L12) a `[ trust dmz ]` scope silently compiled to `trust` only — a
**security-relevant scope narrowing the operator never sees**. #4505 tagged both leaves
`scalar: true` (`pkg/config/schema_security.go:292-293`) so the list form is now **fail-closed
rejected at commit** (RED-guarded by `TestGlobalPolicyZoneListRejected4415`,
`pkg/config/schema_global_zone_list_4415_test.go:39`). Correct interim; not Junos behavior.

### L01
`policy_id` is a PACKED namespace: `policyRuleSlot.policyID() = PolicySetID*MaxRulesPerPolicy(256)
+ RuleIndex` (`pkg/dataplane/userspace/policies.go:53-54`). The FIRST policy (set 0, rule 0)
computes id **0**. Wire value 0 is OVERLOADED — it is simultaneously:
1. the literal first security policy's id, AND
2. the "unspecified" value stamped on non-security sessions (host-inbound / neighbor-seed /
   fabric / tunnel — `userspace-dp/src/afxdp/forwarding/mod.rs:811` stamps `policy_id: 0`), AND
3. the value an older/pre-#3056 producer or old-HA-peer leaves on EVERY session.

Consumers that must special-case 0 because of this overload:
- `deletedPolicyRuntimeIDs` EXCLUDES id 0 (`pkg/daemon/daemon_policy_invalidate.go:71`) — a
  deliberate fail-safe UNDER-clear: deleting the first policy leaves its sessions to idle out
  rather than sweeping every host-inbound/fabric/tunnel session (a #1960 mass-loss hazard).
  Mirrored by `changedPolicyRuntimeIDs` (`:382`).
- `parse_policy_state_with_counters` EXCLUDES 0 (and `DEFAULT_POLICY_SENTINEL_ID = u32::MAX`)
  from the `DuplicatePolicyId` integrity check (`userspace-dp/src/policy.rs:1731-1738`, M01).

---

## 3. Honest scope + value

### M03 — value: HIGH, scope: MEDIUM (cross-plane, ~10 Go files + 1 Rust enum + wire fixture)
Real vSRX parity. Removes a fail-closed reject and lets a scoped global narrow to a SET of
zone pairs (the common "this global applies to {trust,dmz}→{untrust}" idiom) with correct
membership matching and unfragmented counters/display. Folds in codex-164 **L04/L05** (file
the multi-zone scope as the parity gap — subsumed by shipping it) and **L12**'s positive-path
list-accept test.

### L01 — value: LOW, scope: HIGH-RISK (session-schema migration)
LATENT, not a live bug (see §5 quantification). The clean end-state (renumber so id 0 is
reserved) is a global id shift over an HA-synced + install-frozen per-session field — it
GENERALIZES the exact #1960/#3301-P2 mismatch hazard the id-0 exclusion exists to avoid.
Recommend DEFER.

---

## 4. Already-shipped single-zone reference (what to mirror)

The single-zone scope (#3148) is fully wired end-to-end and is the template the list model
generalizes:

- **Go typed model:** `PolicyMatch.FromZone/.ToZone string` (`types_security.go:410-411`);
  wildcard SSOT `IsWildcardZone` (`""`/`"any"` → all-zones, `:432`); display helper
  `GlobalPolicyAppliesToZone` (OR-of-sides, `:452`).
- **Matcher (Go policy-sim SSOT):** `globalScopeMatches` (`pkg/policymatch/policymatch.go:1081`)
  = `IsWildcardZone || (defined && scope==flow)`; used AND-combined at `:925-926` (transit)
  and `:1015` (host-inbound); `GlobalPolicyAppliesToZonePair` (`:1066`) for filtered views.
- **Strict commit gate:** `compiler_validate_strict_policy.go:596-608` rejects `from-zone
  junos-host` (#3611 Piece A) and any undefined match-zone.
- **Control socket (JSON snapshot):** `PolicyRuleSnapshot.MatchFromZone/MatchToZone string`
  (`pkg/dataplane/userspace/protocol.go:1260-1261`, `json:"match_from_zone,omitempty"`),
  populated by `policies_lower.go:212-213`; read by `policies_reject.go:169-174`,
  `zones_quarantine.go:110`.
- **gRPC:** `xpf.proto:304-305` `string match_from_zone = 11` / `= 12`; REST `api/types.go:211-212`;
  gRPC show `server_show_zones.go:275-276`, `server_show_policies_text.go:193/219-223/440-444`;
  Prometheus `api/metrics_counters.go:423-427`.
- **Rust runtime:** `GlobalZoneScope { Any, Zone(u16) }` (`policy.rs:221-227`); `matches(id)`
  (`:240`); `build_global_zone_scope` (name→scope, `""`/`"any"`→Any, else resolve-or-fail-closed,
  `:273`); `PolicyRule.global_from_zone/global_to_zone` (`:298-299`); AND-combined at
  `:2737` (transit) and `:2991` (host-inbound); `expand_side` for the cold-path histogram
  slot map (`:1617-1625`); wire `PolicyRuleSnapshot.match_from_zone/match_to_zone: String`
  (`userspace-dp/src/protocol/security.rs:453-456`, `serde(default)`).
- **Wire-parity fixture:** `userspace-dp/tests/fixtures/protocol_wire_v1.json:788-789`
  (`"match_from_zone": ""`), regenerated with `XPF_PROTOCOL_WIRE_REGEN=1 cargo test`
  (`userspace-dp/src/protocol/tests.rs:1705`).

---

## 5. Concrete design

### 5A. M03 — multi-zone scope, set model end-to-end

**Data model (Go).** `PolicyMatch.FromZone/.ToZone string` → `FromZones/ToZones []string`
(`types_security.go:410-411`). Rename is deliberate (plural) so the compiler and every reader
must be visited by the compiler (no silent single-string fallthrough). Empty slice = all-zones
(preserves the `""` wildcard). A one-element slice is the single-zone case, bit-identical on
the wire (see §6). Keep the current `IsWildcardZone` semantics: the SET is wildcard iff it is
empty OR contains `"any"` (an explicit `any` anywhere collapses to all-zones — matches
`build_global_zone_scope`).

**Schema + compiler (accumulate all tokens).** `schema_security.go:292-293`: drop
`scalar: true`, add `multi: true` (children:nil) — the same marker `source-address` /
`application` already carry two lines above (`:263-267`). Remove the L12 fail-closed comment
block (`:276-291`) and delete/repurpose `schema_global_zone_list_4415_test.go` into a
positive-accept test. Compiler (`compiler_security_policy.go:245-256`): replace the
`Keys[1]`-only reads with `pol.Match.FromZones = append(pol.Match.FromZones,
firewallMatchValues(m)...)` and same for `to-zone`. `firewallMatchValues`
(`compiler_firewall.go:768`) reads BOTH `Keys[1:]` AND `Children` — the canonical dual-AST
helper (the flat-set lexer collapses `[ trust dmz ]` onto `Keys=["from-zone","trust","dmz"]`;
the hierarchical block yields child leaves). `parseZoneList` (`compiler_nat.go:990`) is the
even-closer precedent (a NAT zone-list reader) but `firewallMatchValues` is the documented
SSOT for this exact `Keys[1:]+Children` leaf shape (`docs/config-schema.md:173-224`), so use it.

**Strict commit gate (per-element).** `compiler_validate_strict_policy.go:596-608`: the
`junos-host` reject and the `!defined()` check must run for EVERY element of both lists (loop),
not just the single value. Preserve the exact error messages, naming the offending element.

**Wildcard/display helpers.** `IsWildcardZone(s string)` stays (used elsewhere); add
`IsWildcardZoneSet([]string) bool` = `len==0 || slices.Contains("any")`. `GlobalPolicyAppliesToZone`
(`types_security.go:452`, OR-of-sides for the zone-detail AUDIT surface) → generalize to
"zone appears in FromZones-set-or-wildcard OR in ToZones-set-or-wildcard". `GlobalPolicyAppliesToZonePair`
(`policymatch.go:1066`, AND-of-axes for filtered views) → per-axis membership.

**Matcher (Go SSOT).** `globalScopeMatches(cfg, scopeZone, flowZone)` (`policymatch.go:1081`)
→ `globalScopeSetMatches(cfg, scopeZones []string, flowZone)` = wildcard-set OR
`any(defined(z) && z==flowZone for z in set)`. An UNDEFINED element must NOT widen — mirror
today's fail-closed (unresolved element contributes nothing; if NO element resolves+matches,
no match). Call sites `:925-926`, `:1015` become set calls; `matchedResult` currently takes
`pol.Match.FromZone, pol.Match.ToZone` (single) at `:933`/`:1019` for the reported zone context
— must accept the set (join for display, or report the matched element).

**Control socket + proto + REST.** `PolicyRuleSnapshot.MatchFromZone/MatchToZone string` →
`[]string` (`protocol.go:1260-1261`, keep json key `match_from_zone` / add `,omitempty`).
`policies_lower.go:212-213` copies the slice. `policies_reject.go:169-174` and
`zones_quarantine.go:110` iterate the slice. Proto `xpf.proto:304-305` `string` → `repeated
string` (regen `xpf.pb.go` via `make generate`/protoc); REST `api/types.go:211-212` → `[]string`;
gRPC/Prometheus readers (`server_show_zones.go`, `server_show_policies_text.go`,
`metrics_counters.go`) join/iterate.

**Rust runtime.** `GlobalZoneScope { Any, Zone(u16) }` → `{ Any, Zones(SmallVec<[u16;2]>) }`
(or a sorted `Vec<u16>`; 2-inline SmallVec covers the common case with no heap alloc — hot-path
rule, CLAUDE.md). `matches(id)` → `Any => true | Zones(zs) => zs.contains(&id)`.
`build_global_zone_scope(name)` → `build_global_zone_scope(names: &[String])`: empty OR any
`"any"` → `Any`; else resolve EACH element via `resolve_policy_zone_id`, fail the WHOLE snapshot
closed on ANY unresolvable element (`UnresolvableZoneReference`, preserving the #3402 posture).
`expand_side` (`:1617-1625`) → expand each concrete element (dedup). AND-combine unchanged at
`:2737`/`:2991`. Wire `match_from_zone/match_to_zone: String` → `Vec<String>`
(`protocol/security.rs:453-456`, keep `serde(default)` → empty vec = all-zones).

**Wire-parity fixture.** `match_from_zone: ""` → `[]` in `protocol_wire_v1.json:788-789`.
Regenerate with `XPF_PROTOCOL_WIRE_REGEN=1 cargo test --bin xpf-userspace-dp
wire_invariant_default_specimens`, review the diff (must be EXACTLY the two keys changing
`""`→`[]`, nothing else). The Go-side consumers of that fixture (`types_security.go:707`,
`pkg/dataplane/types.go`, `cold_path_status_test.go`) are unaffected (they pin array-length
constants, not these keys).

### 5B. L01 — reserve policy_id 0 (RECOMMEND DEFER)

**Current sentinel map (verified consistent Go↔Rust):**
- `0` = first-policy id AND "unspecified" (overloaded — the problem).
- `DEFAULT_POLICY_SENTINEL_ID = u32::MAX` (`policy.rs:155`) / Go `DefaultPolicySentinelID` =
  implicit default-policy id. Distinct, safe (`daemon_policy_invalidate.go:196-205`).
- `DEFAULT_POLICY_COUNTER_IDX = u32::MAX` — the counter handle for the default policy; per-rule
  counter handles are ALREADY 1-based (`policy_counter_idx = idx+1`, `session/entry.rs:80-95`),
  so the counter namespace has NO id-0 overload. The ONLY residual overload is the literal
  first-policy `policy_id == 0`.

**Live vs latent — QUANTIFIED:** LATENT.
- The id-0 exclusion's only observable effect is the fail-safe UNDER-clear: deleting/renaming
  the FIRST policy does not precise-clear its sessions; they idle out. This matches Junos
  (established sessions survive a policy delete unless explicitly cleared), so it is arguably
  CORRECT, not a bug.
- The M01 duplicate-check skip of 0 cannot mask a real corruption: a clean compile assigns id 0
  to exactly one policy (deterministic `walkPolicyRuleSlots`), so two real id-0 rules never occur.
- No security exposure (id-0 sessions were already admitted; nothing fails OPEN).

**Why no clean NON-breaking path:** reserving 0 (start the first policy at id 1 — either
`RuleIndex` base 1, or `PolicySetID` base 1 which reserves the whole [0..255] block) shifts at
least the first policy's id. `policy_id` is (a) stamped at install on every session
(`session/entry.rs:58`, #3056), (b) carried on sibling-worker replicas, AND (c) HA-synced
(SESSION_OPEN delta trailing u32 + `SessionSyncRequest.policy_id`, #3301). On a LIVE node a
config commit re-resolves the stamped id from the stable `rule_id`
(`reresolve_session_policy_id`, `policy.rs:1504`) for locally-bound sessions — so a same-node
renumber self-heals. The residual is the ROLLING-UPGRADE window: an old-numbered peer syncs a
session stamped with the OLD id to a new-numbered node, whose `bound=None` synced entry keeps
the frozen (now-wrong) id — the documented #3301-P2 residual, generalized from "only id 0" to
"the whole shifted block." A non-breaking path needs a session-schema `policy_id` migration OR
a dual-accept compat shim gated on a snapshot-version bump.

**Recommendation:** DEFER (keep current fail-safe). Ship only if a broader session-schema /
version bump lands that can carry the migration for free (couples to #4415 L14 — route
default-policy invalidation into the runtime-id framework). If forced to ship standalone, the
lowest-risk shape is `PolicySetID` base 1 (reserve [0..255], leaving 0 permanently unused) plus
a one-release compat note that the upgrade window may under-clear first-block sessions — but
that transitional cost buys only precise-clear of the first policy, which today merely idles
out. Not worth it standalone.

---

## 6. API / behavior preservation

- **Single-zone configs stay bit-identical.** `match from-zone trust` compiles to
  `FromZones=["trust"]` → wire `["trust"]` → `GlobalZoneScope::Zones(["trust"→id])` →
  `matches` is identical to today's `Zone(id)`. The `""`/omitted case → `[]` → `Any`, identical.
  No behavior change for any existing config; only the previously-REJECTED list form newly compiles.
- **Wire compat:** the JSON key `match_from_zone` is UNCHANGED — only its VALUE TYPE goes
  `string`→`array`. Because the config is TEXT-synced (each node compiles locally) and the
  control socket + gRPC + REST are per-node / atomic-per-deploy (xpfd + userspace-dp ship in
  ONE .deb, restart together — no old-helper-meets-new-xpfd window), the type change is safe.
  This is NOT an HA session-sync field (that's `SessionSyncRequest.policy_id`, untouched), so
  there is NO cross-node rolling-upgrade exposure for M03.
- **`serde(default)`** on the Rust field means an omitted key still decodes to empty vec =
  all-zones, so a hypothetical old-Go snapshot degrades safely.

---

## 7. Hidden invariants / gotchas

1. **Go↔Rust wire type must change on BOTH sides in lockstep.** `protocol.go` `[]string` and
   `protocol/security.rs` `Vec<String>` must land together; a `string`↔`array` skew makes serde
   FAIL the whole snapshot (fail-closed, but a broken deploy). The `protocol_wire_v1.json` regen
   is the tripwire — the diff MUST be exactly `""`→`[]` on the two keys.
2. **Flat-set bracketed-list dual-AST (#2419).** `[ trust dmz ]` collapses onto ONE leaf's
   `Keys` in BOTH parser shapes; the compiler MUST read `Keys[1:]` AND `Children` and accumulate
   (`firewallMatchValues`). Reading `Keys[1]` only is the #2419 bug. MUST test with
   `ParseSetCommand()` + `tree.SetPath()` loop, NEVER `NewParser()` (parser merges newlines).
3. **`multi: true` also changes REPLACE semantics (#3984).** After the marker, two separate
   `set ... match from-zone trust` / `set ... match from-zone dmz` statements ACCUMULATE
   (both kept) rather than the second REPLACING the first. That is the CORRECT Junos list
   semantics but a behavior change from `scalar` (which replaced). Document + test.
4. **AND (matcher) vs OR (audit display).** The runtime/policy-sim match is `from∈FromZones AND
   to∈ToZones`. The zone-DETAIL audit `GlobalPolicyAppliesToZone` is OR-of-sides (a zone that
   appears on EITHER side is "involved"). Both must generalize to set membership but keep their
   respective AND/OR combinators — do not accidentally unify them.
5. **Undefined element must fail closed, not widen.** An unresolved zone in a list contributes
   NOTHING (never all-zones). The strict commit gate rejects undefined elements, so the runtime
   only sees this on the tolerant/corrupt-snapshot path — match today's `globalScopeMatches`
   fail-closed.
6. **`expand_side` dedup.** `[ trust trust ]` or overlapping wildcard expansion must not emit
   duplicate `(from,to)` pairs into the cold-path slot map (BTreeSet already dedups; keep it).
7. **`matchedResult` reported zone context.** Today it reports the single scope string
   (`policymatch.go:933/1019`); with a set it must report the MATCHED element (or a joined
   label), or the `show ... match-policies` zone-context column drifts.
8. **L01 counter idx is already 1-based** — do not "fix" it; the only 0-overload is `policy_id`.

---

## 8. Risk table (4-class)

| Class | M03 | L01 |
|---|---|---|
| **Correctness** | Set membership must match Junos AND-of-axes; undefined-element fail-closed; per-element junos-host reject. Mitigated by SSOT reuse (`globalScopeSetMatches` mirrors Rust) + tests. | Renumber invalidates HA-synced/frozen session `policy_id` in the upgrade window (mismatch → wrong-policy attribution / miss on delete-clear). This is why DEFER. |
| **Wire/compat** | JSON value type `string`→`array` on a per-node-atomic surface — safe; fixture-regen tripwire catches skew. NOT an HA-sync field. | `policy_id` IS an HA-sync field — renumber is a cross-node rolling-upgrade break. |
| **Performance** | `Zones(SmallVec<[u16;2]>)` membership is O(k), k≈1-2; 2-inline = no heap on hot path. Cold-path expansion only. Negligible. | N/A (no hot-path change). |
| **Security** | Removes a fail-CLOSED reject → newly ACCEPTS the list; but the accepted semantics are STRICTER-or-equal (a real scope, no silent widening). Undefined element stays fail-closed. Net: no fail-open introduced. | Fail-safe under-clear is conservative (sessions idle out); no fail-open today. |

---

## 9. Test plan

### M03
- **Parser/dual-AST:** `ParseSetCommand("set security policies global policy p match from-zone
  [ trust dmz ]")` + `SetPath` loop → assert leaf `Keys=["from-zone","trust","dmz"]`; a
  hierarchical fixture must yield the identical compiled `FromZones`. Pin flat==hierarchical
  (the `parser_bracket_list_2419_test.go` pattern).
- **Compiler:** `[ trust dmz ]` → `Match.FromZones == ["trust","dmz"]` (BOTH populate — the
  regression the bug drops); `to-zone [ x y ]` same; single `from-zone trust` → `["trust"]`;
  omitted → empty. Two separate `set` lines accumulate (#3984). Repurpose
  `schema_global_zone_list_4415_test.go` (L12) into a POSITIVE list-accept test.
- **Strict gate:** `from-zone [ trust junos-host ]` rejected (per-element); `[ trust undefined ]`
  rejected naming `undefined`.
- **Go matcher SSOT:** a scoped global `from-zone [trust dmz] to-zone [untrust]` MATCHES
  (trust→untrust) and (dmz→untrust), does NOT match (wan→untrust) or (trust→dmz). Host-inbound
  `to-zone junos-host from-zone [trust dmz]` membership. `GlobalPolicyAppliesToZonePair` filtered
  view for a set.
- **Rust runtime:** `GlobalZoneScope::Zones` `matches` membership unit test; `build_global_zone_scope`
  multi-element resolve + fail-closed on one unresolvable; `expand_side` dedup;
  transit + host-inbound AND-combine at `:2737`/`:2991`. Extend `policy_global_zone_3148_test.go`
  / `zones_collision_3719_test.go` / `policy_reject_reasons_3376_test.go` for the list.
- **Wire parity:** `XPF_PROTOCOL_WIRE_REGEN=1 cargo test wire_invariant_default_specimens`;
  `git diff protocol_wire_v1.json` shows ONLY `""`→`[]` on the two keys. Round-trip a 2-zone
  snapshot Go→JSON→Rust.
- **Full suites:** `make test` (Go) + `cargo test` (Rust) green. `make build` +
  `make build-userspace-dp`. Proto regen (`make generate`) leaves a clean tree.
- **Smoke (at /engineer, not /research):** loss userspace cluster — commit a scoped-global with
  a 2-zone scope, verify `show security match-policies` and a real forwarding decision honor both
  zones; v4 + v6.

### L01 (only if un-deferred)
- Renumber unit test (first policy id != 0); `deletedPolicyRuntimeIDs` precise-clears the first
  policy WITHOUT the id-0 exclusion; M01 duplicate-check no longer skips 0; HA rolling-upgrade
  migration/compat-shim test for a session stamped with the OLD numbering.

---

## 10. Out of scope

- L01 renumber (DEFERRED — recorded, not built this pass).
- #4415 low-value follow-ups L02/L03 (lab-blocked smokes), L06/L07 (invalidate-file split /
  shared reader — partly done), L09 (10k-rule bench), L11 (doc), L13 (cross-surface counter test),
  L14 (default-policy inval into runtime-id framework — couples to L01, deferred with it).
- Any change to the single-zone `#3148` semantics beyond generalizing to a set.
- HA session-sync wire (`policy_id`) — untouched by M03.

---

## 11. Open questions (each invitable to PLAN-KILL)

1. **Rename `FromZone`→`FromZones` (plural, forces compiler visitation) vs keep the name and
   change only the type?** Rename is safer (every reader must be touched) but noisier. Keeping
   the name risks a silent single-string reader surviving. Recommend rename. Reviewer may KILL
   the rename in favor of a minimal type change.
2. **Wire: change the EXISTING `match_from_zone` field type `string`→`array`, or add NEW plural
   fields (`match_from_zones`) and keep the singular for a release?** Given per-node-atomic
   deploy, the type change is clean; the additive path is pure overhead here. But if the project
   wants a belt-and-suspenders no-type-change-ever wire rule, the additive path is the out.
   Recommend type change. — could PLAN-KILL if the project forbids wire value-type changes.
3. **`GlobalZoneScope::Zones` storage: `SmallVec<[u16;2]>` vs sorted `Vec<u16>` vs a bitmask
   over zone ids?** SmallVec avoids heap for the common ≤2 case; bitmask is O(1) membership but
   assumes a bounded zone-id space. Recommend SmallVec.
4. **L01: is the fail-safe under-clear actually a defect at all?** If Junos-correct (established
   sessions survive a policy delete), L01 is not just DEFER but arguably WONT-FIX for the
   observable behavior, and only the "clean sentinel" refactor value remains. Reviewer may
   PLAN-KILL L01 outright (close as working-as-intended).
5. **Does any consumer depend on `Match.FromZone` being a single comparable string (map key,
   equality, sort)?** Grep shows only display/format/membership readers, but a hidden
   equality/dedup on the scope string would break under a slice. Must confirm none before /engineer.
6. **Should M03 also normalize/dedup/sort the compiled `FromZones` (e.g. `[ dmz trust ]` vs
   `[ trust dmz ]`) for stable display + HA-symmetric expansion?** Recommend sort+dedup at
   compile; reviewer may prefer preserving config order.
7. **Is there a max-zones bound to enforce (a `[ z1 ... z64 ]` scope) to keep `expand_side`
   from exploding the cold-path slot map?** The 255-slot cap already truncates; confirm the
   truncation is graceful for a large scoped global.

---

## Recommendation

- **M03 → PLAN-READY.** Concrete, safe (no HA-wire exposure), high parity value. Drive via
  `/engineer 4626` scoped to M03 once open questions 1-3/5-6 are decided.
- **L01 → PLAN-DEFER** (recommend), with PLAN-KILL-as-WONT-FIX open (Q4) if reviewers agree the
  under-clear is Junos-correct. Do not renumber standalone.
