# Plan of action — #4626: multi-zone scoped-global scope (M03) + reserve policy_id 0 (L01)

- **Revision:** r2 (incorporates Codex r1 + Claude SMR r1)
- **Issue:** #4626 (split from #4415, codex-review-164 backlog)
- **Base:** `origin/master` @ `4eb28ae25` (verified — every file:line below re-read on this SHA)
- **Mode:** `/research` — STOPS at PLAN-READY / PLAN-KILL / PLAN-DEFER. No PR, no production edits.
- **Reviewers:** Codex (hostile) + Claude SMR (hostile). AGY/gemini infra-down → 2-of-3 with documented Codex retries.
- **r1→r2 deltas:** (1) wire model switched from string→array TYPE-CHANGE to ADDITIVE plural
  fields (`match_from_zones`/`match_to_zones`) per the project's #1961/#3301 both-sides doctrine
  — the r1 "bit-identical on wire" claim was WRONG (serde decode of the whole control request
  happens before any version gate, `handlers/mod.rs:88`; an in-place #1917 upgrade can transiently
  pair a new xpfd with a not-yet-restarted helper). (2) host-inbound `junos-host` set semantics
  pinned. (3) complete grep-verified consumer enumeration + a shared list-scope SSOT. (4) zone-local
  address-book resolution rule for a multi-zone scope. (5) `multi:true` fallout beyond bracket
  lists (member-delete, apply-groups union). (6) `matchedResult` reported-zone pinned.

---

## 1. Status

| Sub-item | Verdict (r2) | One-line |
|---|---|---|
| **M03** multi-zone scoped-global scope | **PLAN-READY** | Cross-plane set-model slice with an ADDITIVE-field wire (rolling-upgrade safe), a shared list-scope SSOT, pinned host-inbound/address-book semantics. Replaces the #4505 fail-closed reject with real Junos parity. |
| **L01** reserve policy_id 0 | **PLAN-DEFER** (PLAN-KILL-as-WONT-FIX also acceptable) | Latent, not a live bug; the under-clear is Junos-correct. The only clean end-state renumbers an HA-synced install-frozen per-session field. Keep the fail-safe unless a session-schema version bump lands. |

M03 and L01 are INDEPENDENT changes, coupled only through `policy_id`: M03's "expand `[a b]`
into N single-zone rules" shortcut is BLOCKED by the same `DuplicatePolicyId` guard L01
discusses — which is WHY M03 is a set-model change, not an expansion.

---

## 2. Framing (the problem)

### M03
Junos `security policies global policy <p> match { from-zone [ trust dmz ]; to-zone [ ... ]; }`
(#3148) carries a ZONE LIST. xpf models the scope as a single `string`:
- `config.PolicyMatch.FromZone`/`.ToZone` are `string` (`pkg/config/types_security.go:410-411`
  — the scoped-GLOBAL scope; there are 3 other FromZone/ToZone pairs in the file at `:350-351`
  (ZonePairPolicies), `:549` (#3096 NAT from-context), `:574-575` — NOT the target).
- The compiler reads only the FIRST value token: `pol.Match.FromZone = m.Keys[1]` /
  `= m.Children[0].Name()` (`pkg/config/compiler_security_policy.go:245-256`).

Before #4505 (L12) a `[ trust dmz ]` scope silently compiled to `trust` only. #4505 tagged both
leaves `scalar: true` (`pkg/config/schema_security.go:292-293`) → the list form is now
**fail-closed rejected at commit** (RED-guarded by `TestGlobalPolicyZoneListRejected4415`,
`pkg/config/schema_global_zone_list_4415_test.go:39`). Correct interim; not Junos behavior.

### L01
`policyRuleSlot.policyID() = PolicySetID*MaxRulesPerPolicy(256) + RuleIndex`
(`pkg/dataplane/userspace/policies.go:53-54`). The FIRST policy (set 0, rule 0) → id **0**. Wire
value 0 is OVERLOADED: first-policy id AND the "unspecified" value stamped on non-security
sessions (host-inbound / neighbor-seed / fabric / tunnel — `forwarding/mod.rs:811` stamps
`policy_id: 0`) AND the value a pre-#3056 / old-HA-peer producer leaves on every session.
Consumers special-case 0:
- `deletedPolicyRuntimeIDs` / `changedPolicyRuntimeIDs` EXCLUDE id 0
  (`pkg/daemon/daemon_policy_invalidate.go:71,382`) — a fail-safe UNDER-clear.
- `parse_policy_state_with_counters` excludes 0 AND `DEFAULT_POLICY_SENTINEL_ID=u32::MAX` from
  the `DuplicatePolicyId` integrity check (`userspace-dp/src/policy.rs:1730-1738`, M01).

---

## 3. Honest scope + value

- **M03 — value HIGH, scope MEDIUM** (~11 Go files + 1 Rust enum + additive wire fields + fixture).
  Real vSRX parity; removes a fail-closed reject. Subsumes codex-164 **L04/L05** (the parity gap
  IS the fix) and folds in **L12**'s positive-path list-accept test.
- **L01 — value LOW, scope HIGH-RISK** (session-schema migration). LATENT (§5B). Recommend DEFER.

---

## 4. Already-shipped single-zone reference (the template to generalize)

- **Go typed model:** `PolicyMatch.FromZone/.ToZone string` (`types_security.go:410-411`);
  wildcard SSOT `IsWildcardZone` (`:432`, `""`/`"any"`→all-zones); audit helper
  `GlobalPolicyAppliesToZone` (OR-of-sides, `:452`).
- **Matcher SSOT (Go policy-sim):** `globalScopeMatches` (`policymatch.go:1081`); AND-combined at
  `:925-926` (transit) and `:1015` (host-inbound, gated on `ToZone==JunosHostZone` at `:1012`);
  `GlobalPolicyAppliesToZonePair` (`:1066`, AND-of-axes for filtered views).
- **Strict commit gate:** `compiler_validate_strict_policy.go:596-608` — rejects `from-zone
  junos-host` (#3611 Piece A) + any undefined match-zone; ALLOWS `to-zone junos-host`.
- **Address-book (#3287):** `compiler_security_addressbook.go:229-206` resolves a scoped
  global's zone-local address refs against the scope zone's local book via `rewrite(zone,tokens)`
  (`:163`), which no-ops for a wildcard/empty scope (global book).
- **Control socket (JSON snapshot):** `PolicyRuleSnapshot.MatchFromZone/MatchToZone string`
  (`protocol.go:1260-1261`), populated by `policies_lower.go:212-213`; read by
  `policies_reject.go:169-174`, `zones_quarantine.go:110`.
- **gRPC/REST/CLI/Prom:** `xpf.proto:304-305`; `api/types.go:211-212`; `api/security.go:299-300`;
  `metrics_counters.go:423-427`; `server_show_zones.go:275-276`;
  `server_show_policies_text.go:193/219-223/440-444`; `cmd/cli/show_security.go:246-249`
  (reconstructs a `PolicyMatch` from `MatchFromZone/ToZone` → `GlobalPolicyAppliesToZone`).
- **Rust runtime:** `GlobalZoneScope { Any, Zone(u16) }` (`policy.rs:221-227`); `matches(id)`
  (`:240`); `build_global_zone_scope` (`:273`); `PolicyRule.global_from_zone/to_zone` (`:298-299`);
  AND-combined at `:2737` (transit) / `:2991` (host-inbound, `==Zone(JUNOS_HOST_ZONE_ID)`);
  `expand_side` cold-path slot map (`:1617-1625`); wire
  `match_from_zone/match_to_zone: String` (`protocol/security.rs:453-456`, `serde(default)`).
  Control request decode is `serde_json::from_slice` of the WHOLE `ControlRequest` BEFORE any
  version gate (`server/handlers/mod.rs:88`).
- **Wire-parity fixture:** `protocol_wire_v1.json:788-789`; regen `XPF_PROTOCOL_WIRE_REGEN=1`
  (`protocol/tests.rs:1705`).

---

## 5. Concrete design

### 5A. M03 — multi-zone scope, set model end-to-end

**A1. Data model (Go).** `PolicyMatch.FromZone/.ToZone string` → `FromZones/ToZones []string`
(`types_security.go:410-411`). Plural RENAME is deliberate — it forces the compiler to touch
every reader (no silent single-string fallthrough survives). Empty slice = all-zones. A
one-element slice = the single-zone case.

**A2. Shared list-scope SSOT (new, mandatory).** Add a small SSOT so NO surface invents its own
join/wildcard/match logic (Codex R4):
- `IsWildcardZoneSet(zs []string) bool` = `len(zs)==0 || slices.Contains(zs,"any")`.
- `ZoneScopeSetLabel(zs []string) string` = the canonical display join (`"any"` for wildcard,
  else `strings.Join(sorted-unique, " ")`), used by ALL display surfaces.
- `globalScopeSetMatches(cfg, zs []string, flowZone) bool` = `IsWildcardZoneSet(zs) ||
  any(defined(z) && z==flowZone)`. Mirrors the Rust `matches`. An undefined element contributes
  NOTHING (never widens to all-zones — matches today's fail-closed).

**A3. Schema + compiler (accumulate).** `schema_security.go:292-293`: drop `scalar:true`, add
`multi:true` (children:nil) — same marker `source-address`/`application` carry at `:263-267`.
Remove the L12 fail-closed comment block (`:276-291`). Compiler
(`compiler_security_policy.go:245-256`): `pol.Match.FromZones = append(pol.Match.FromZones,
firewallMatchValues(m)...)` (and to-zone). `firewallMatchValues` (`compiler_firewall.go:768`)
reads BOTH `Keys[1:]` AND `Children` — the documented dual-AST SSOT (`docs/config-schema.md:173-224`);
the leaves are DIRECT children of the global `match` node (verified), so the #2419 collapsed
shape `Keys=["from-zone","trust","dmz"]` is exactly what it reads. Sort+dedup the compiled
slice at compile for stable display + HA-symmetric expansion (open Q6).

**A4. Strict commit gate (per-element).** `compiler_validate_strict_policy.go:596-608`: loop
over EVERY element of both lists — `junos-host` reject applies to `from-zone` elements; the
undefined-zone reject applies to every element; error messages name the offending element.
Preserve the `to-zone junos-host` ALLOWANCE (see A6).

**A5. All consumers (grep-verified complete — Codex R4 + SMR R1/R2).** Route ALL through the A2
SSOT:
- `GlobalPolicyAppliesToZone` (`types_security.go:452`, OR-of-sides audit) → set membership per side.
- `globalScopeMatches` call sites (`policymatch.go:925-926,1015`) → `globalScopeSetMatches`.
- `GlobalPolicyAppliesToZonePair` (`policymatch.go:1066`, AND-of-axes) → per-axis set membership.
- `compiler_security_addressbook.go:229-206` (#3287 zone-local book) → see A7.
- `compiler_validate_warn.go:2040` (`ToZone != "junos-host"` host-inbound warn) → set predicate.
- Display/API/metrics: `api/security.go:299-300`, `metrics_counters.go:423-427`,
  `server_show_zones.go:275-276`, `server_show_policies_text.go:193/219-223/440-444`,
  `cmd/cli/show_security.go:246-249` → emit the slice / use `ZoneScopeSetLabel`.
- `policies_reject.go:169-174`, `zones_quarantine.go:110` → iterate the slice.

**A6. Host-inbound `junos-host` set semantics (Codex R2 — PINNED).** The host-inbound tier
matches a global only when its `to-zone` scope names `junos-host`; the transit tier matches only
concrete zones. To keep the predicate unambiguous and avoid the "any collapses to Any loses
explicit-host info" trap, **REJECT at commit a `to-zone` list that mixes `junos-host` with any
other token** — a `to-zone` scope is EITHER exactly `[junos-host]` (host-inbound global) OR an
all-concrete list (transit). `from-zone junos-host` stays rejected entirely. Then:
- Go: host-inbound tier selects globals whose `ToZones == ["junos-host"]`
  (`policymatch.go:1012`); transit tier's `globalScopeSetMatches` never sees junos-host (rejected
  from mixed lists; a lone `[junos-host]` is not a concrete transit zone).
- Rust: host-inbound path (`policy.rs:2991`) tests "`to` scope is exactly the junos-host id";
  add an explicit `is_host_scope()` predicate on `GlobalZoneScope` (false for `Any`, true iff the
  set is exactly the junos-host id) rather than `==Zone(JUNOS_HOST_ZONE_ID)`.
- `expand_side` already drops reserved (non-concrete) ids from transit expansion — unchanged.

**A7. Zone-local address book under a multi-zone scope (SMR R1 — PINNED).** `rewrite(zone,tokens)`
(`compiler_security_addressbook.go:163`) resolves a scoped global's zone-local address refs
against a SINGLE zone's book and already no-ops for a wildcard scope (global book). Rule:
**resolve zone-local books ONLY when the scope is a single concrete zone
(`len(FromZones)==1 && !wildcard`); a multi-zone scope resolves against the GLOBAL book** (the
same carve-out the unscoped/`any` global already gets — there is no single zone-local book for a
set). This preserves single-zone behavior EXACTLY and is a DOCUMENTED parity limitation
(multi-zone scoped globals cannot use zone-local address books). Test: `foo` in trust-local,
scope `[trust dmz]` → resolves against the global book, not `trust/foo`.

**A8. Wire — ADDITIVE plural fields (Codex R1 — replaces r1's type-change).** Do NOT change the
existing `match_from_zone`/`match_to_zone` field TYPE (serde decodes the whole control request
before any version gate — a `string`↔`array` mismatch hard-fails the request; an in-place #1917
upgrade may transiently pair a new xpfd with a not-yet-restarted old helper). Instead, per the
#1961/#3301 both-sides additive doctrine:
- ADD `match_from_zones`/`match_to_zones` (`Vec<String>` / `[]string`, `serde(default)` /
  `json:",omitempty"`) alongside the retained singular fields.
- New Go emits BOTH: singular = first element (backward-compat single-zone degradation for an
  old helper during the upgrade window), plural = the full list.
- New Rust PREFERS the plural when non-empty, else falls back to the singular (an old-Go snapshot
  that omits the plural → singular path, unchanged). `build_global_zone_scope` takes the
  resolved list (plural-or-[singular]).
- `protocol_wire_v1.json` gains two ADDITIVE keys (`match_from_zones: []`, `match_to_zones: []`);
  the singular keys stay `""`. Regen + review the diff (exactly two new keys). Proto
  `xpf.proto`: ADD `repeated string match_from_zones = <next>` / `match_to_zones` (keep the
  singular 11/12); REST `api/types.go` add plural slices. gRPC/CLI readers prefer plural.
- Old-helper degradation (first-zone-only for the brief upgrade window) is acceptable and
  documented: pre-#4626 the list was uncommittable, so no old helper ever saw a multi-zone scope
  until both nodes carry the new code.

**A9. Rust runtime.** `GlobalZoneScope { Any, Zone(u16) }` → `{ Any, Zones(SmallVec<[u16;2]>) }`
(2-inline → no heap for the common ≤2 case; hot-path alloc rule). `matches(id)` → `Any=>true |
Zones(zs)=>zs.contains(&id)`; add `is_host_scope()` (A6). `build_global_zone_scope(names:&[String])`:
empty OR any `"any"` → `Any`; else resolve EACH element, fail the WHOLE snapshot closed on any
unresolvable element (`UnresolvableZoneReference`, #3402 posture). `expand_side` (`:1617-1625`) →
expand each concrete element (BTreeSet dedups). AND-combine unchanged (`:2737`/`:2991`).

**A10. `matchedResult` reported zone (SMR S1).** The result's reported Source/Destination zone
must be the CONCRETE flow zone (`q.FromZone`/`q.ToZone`) the packet traversed, NOT a joined
scope label — so `show security match-policies` keeps a single concrete zone per column
(`policymatch.go:933/1019`). Verify the Rust reported-zone path matches.

### 5B. L01 — reserve policy_id 0 (RECOMMEND DEFER)

**Sentinel map (verified consistent Go↔Rust, both reviewers concur):** `0` = first-policy id
AND "unspecified" (the overload); `DEFAULT_POLICY_SENTINEL_ID=u32::MAX` (`policy.rs:155`) =
implicit default (distinct, safe); counter idx already 1-based with 0=no-counter
(`session/entry.rs:78`). The ONLY residual overload is the literal first-policy `policy_id==0`.

**LATENT, not a live bug (quantified):** the id-0 exclusion's only observable effect is a
fail-safe UNDER-clear — deleting/renaming the FIRST policy leaves its sessions to idle out
instead of precise-clearing them. This matches Junos (established sessions survive a policy
delete unless explicitly cleared), so it is arguably CORRECT. M01's duplicate-check skip of 0
cannot mask real corruption (a clean compile assigns id 0 to exactly one deterministic policy).
No security exposure (nothing fails OPEN).

**No clean non-breaking renumber path:** reserving 0 (first policy → id 1, via RuleIndex base 1
or PolicySetID base 1) shifts an id that is stamped at install on every session
(`session/entry.rs:50-58`, #3056), carried on worker replicas, AND HA-synced (SESSION_OPEN delta
+ `SessionSyncRequest.policy_id`, #3301). A LIVE node self-heals (`reresolve_session_policy_id`,
`policy.rs:1494` re-resolves from the stable `rule_id` for locally-bound sessions), but a
`bound=None` peer-synced session keeps the frozen (now-wrong) id — the documented #3301-P2
residual, GENERALIZED from "only id 0" to "the whole shifted block" during a rolling upgrade.

**Recommendation:** DEFER (keep the fail-safe). PLAN-KILL-as-WONT-FIX is also defensible (the
under-clear is Junos-correct — Q4). Ship only if a broader session-schema / version bump lands to
carry a `policy_id` migration for free (couples to #4415 L14). Do NOT renumber standalone.

---

## 6. API / behavior preservation

- **Single-zone configs stay bit-identical.** `match from-zone trust` → `FromZones=["trust"]` →
  wire singular `"trust"` + plural `["trust"]` → `GlobalZoneScope::Zones(["trust"→id])`,
  behaviorally identical to today's `Zone(id)`. `""`/omitted → `[]` → `Any`.
- **Wire is ADDITIVE + rolling-upgrade safe** (A8): the singular fields are unchanged; new plural
  fields default-empty on an old peer. No control-request decode failure, no HA session-sync
  exposure (`policy_id` is the HA field; match-zones are config-snapshot only, per-node).
- **Only the previously-REJECTED list form newly compiles** — no existing config changes behavior.

---

## 7. Hidden invariants / gotchas

1. **Additive wire, both sides in lockstep.** New plural fields land in `protocol.go` (Go) and
   `protocol/security.rs` (Rust) together; the fixture diff is EXACTLY two new keys.
2. **Flat-set bracketed-list dual-AST (#2419).** Read `Keys[1:]`+`Children`, accumulate
   (`firewallMatchValues`). TEST with `ParseSetCommand()`+`SetPath()`, NEVER `NewParser()`.
3. **`multi:true` changes more than bracket lists (Codex R3).** It also flips REPLACE→ACCUMULATE
   for repeated `set` lines (#3984, `ast_edit.go:278`), changes member-DELETE
   (`ast_edit.go:462`), and apply-groups UNION (`ast_groups.go:492`). All are the CORRECT Junos
   list semantics but behavior changes from `scalar` — test each shape.
4. **AND (matcher) vs OR (audit display).** Runtime/sim match = `from∈FromZones AND to∈ToZones`;
   zone-detail audit `GlobalPolicyAppliesToZone` = OR-of-sides. Generalize both to set membership
   but keep their respective combinators.
5. **Undefined element fails closed, never widens.** Strict gate rejects it at commit; the
   runtime fail-closed backstop matches today's `globalScopeMatches`.
6. **`junos-host` cannot mix in a to-zone list (A6).** Rejected at commit; the host predicate is
   `ToZones == ["junos-host"]` exactly.
7. **Zone-local address book: single-zone scope only (A7).** Multi-zone → global book (documented
   parity limit).
8. **`matchedResult` reports the concrete flow zone, not a scope label (A10).**
9. **L01 counter idx is already 1-based** — do not "fix" it; the only overload is `policy_id`.

---

## 8. Risk table (4-class)

| Class | M03 | L01 |
|---|---|---|
| **Correctness** | Set membership must match Junos AND-of-axes; per-element strict gate; junos-host no-mix; single-zone address-book carve-out. Mitigated by the A2 shared SSOT + exhaustive consumer list + tests. | Renumber invalidates HA-synced/frozen session `policy_id` in the upgrade window → DEFER. |
| **Wire/compat** | ADDITIVE plural fields + retained singular → rolling-upgrade safe (#1961/#3301 doctrine); fixture-regen tripwire. NOT an HA-sync field. | `policy_id` IS an HA-sync field — renumber is a cross-node break. |
| **Performance** | `Zones(SmallVec<[u16;2]>)` membership O(k), k≈1-2, no heap; cold-path expansion only. Negligible. | N/A. |
| **Security** | Removes a fail-CLOSED reject → newly ACCEPTS a STRICTER-or-equal real scope; undefined element stays fail-closed; no fail-open introduced. | Fail-safe under-clear is conservative; no fail-open. |

---

## 9. Test plan

### M03
- **Parser/dual-AST:** `ParseSetCommand(... match from-zone [ trust dmz ])`+`SetPath` loop →
  leaf `Keys=["from-zone","trust","dmz"]`; hierarchical block yields identical compiled `FromZones`
  (flat==hierarchical, the `parser_bracket_list_2419_test.go` pattern).
- **Compiler:** `[trust dmz]` → `FromZones==["trust","dmz"]` (BOTH populate — the bug); `to-zone
  [x y]` same; single → 1-elem; omitted → empty; sort+dedup. **Two separate `set` lines
  ACCUMULATE** (#3984); **member-delete** removes one element (`ast_edit.go:462`);
  **apply-groups union** (`ast_groups.go:492`). Repurpose `schema_global_zone_list_4415_test.go`
  (L12 RED-guard) into a POSITIVE accept test.
- **Strict gate:** `from-zone [trust junos-host]` rejected (per-element); `to-zone [junos-host
  untrust]` rejected (no-mix, A6); `[trust undefined]` rejected naming `undefined`; single
  `to-zone junos-host` still ALLOWED.
- **Address book (A7):** `foo` in trust-local, scope `[trust dmz]` → global-book resolution
  (NOT `trust/foo`); scope `[trust]` → `trust/foo` (single-zone unchanged).
- **Go matcher SSOT:** scoped `from-zone [trust dmz] to-zone [untrust]` matches (trust→untrust),
  (dmz→untrust), not (wan→untrust)/(trust→dmz). Host-inbound `[junos-host]`. `GlobalPolicyApplies*`
  audit + filtered-view for a set. `matchedResult` reports the concrete flow zone (A10).
- **Rust:** `Zones::matches` membership; `is_host_scope`; `build_global_zone_scope` multi-element
  + fail-closed on one unresolvable; `expand_side` dedup; AND-combine `:2737`/`:2991`; plural
  wire round-trip + old-snapshot (plural absent → singular fallback). Extend
  `policy_global_zone_3148_test.go`/`zones_collision_3719_test.go`/`policy_reject_reasons_3376_test.go`.
- **Wire parity:** `XPF_PROTOCOL_WIRE_REGEN=1 cargo test wire_invariant_default_specimens`; diff =
  exactly two NEW keys. Round-trip a 2-zone snapshot Go→JSON→Rust (both plural + singular present).
- **Full suites:** `make test` + `cargo test` green; `make build` + `make build-userspace-dp` +
  `make generate` (proto) leave a clean tree.
- **Smoke (at /engineer):** loss userspace cluster — commit a 2-zone scoped global, verify `show
  security match-policies` + a real forwarding decision honor BOTH zones; v4 + v6.

### L01 (only if un-deferred)
- Renumber unit test (first id != 0); `deletedPolicyRuntimeIDs` precise-clears the first policy
  without the id-0 exclusion; M01 no longer skips 0; HA rolling-upgrade migration/compat-shim test.

---

## 10. Out of scope

- L01 renumber (DEFERRED). #4415 L02/L03 (lab smokes), L06/L07 (partly done), L09 (bench), L11
  (doc), L13 (cross-surface counter test), L14 (default-policy inval — couples to L01, deferred).
- Any change to single-zone #3148 semantics beyond generalizing to a set.
- HA session-sync wire (`policy_id`) — untouched by M03.

---

## 11. Open questions (each invitable to PLAN-KILL)

1. **`FromZone`→`FromZones` rename (forces compiler visitation) vs keep name + change type?**
   Recommend rename (safer). — reviewer may prefer minimal type change.
2. **Wire: additive plural fields (recommended, A8) confirmed as the doctrine-correct path** — or
   does the project accept a value-type change given the helper is normally a child process?
   Recommend additive (Codex R1). Could still PLAN-KILL if additive overhead is judged not worth
   the multi-zone feature.
3. **`GlobalZoneScope` storage: `SmallVec<[u16;2]>` vs sorted `Vec<u16>` vs bitmask?** Recommend
   SmallVec.
4. **L01: is the fail-safe under-clear a defect at all, or WONT-FIX?** If Junos-correct, close L01
   as working-as-intended (PLAN-KILL) rather than DEFER.
5. **`junos-host` no-mix (A6): reject at commit (recommended) vs support mixed `[junos-host
   untrust]` via an explicit-host predicate + dual-tier participation?** Recommend reject-mix
   (simpler, exotic config). — reviewer may want full mixed support.
6. **Compile-time sort+dedup of the scope slice** (`[dmz trust]`==`[trust dmz]`) for stable
   display + HA-symmetric expansion — recommend yes; reviewer may prefer config-order preservation.
7. **Max-zones bound** to keep `expand_side` from exploding the 255-slot cold-path slot map — the
   cap already truncates; confirm graceful truncation for a large scoped global.

---

## Recommendation

- **M03 → PLAN-READY.** Concrete, rolling-upgrade safe (additive wire), high parity value.
  Drive via `/engineer 4626` scoped to M03 once Q1-Q3/Q5-Q6 are decided.
- **L01 → PLAN-DEFER** (recommend), with PLAN-KILL-as-WONT-FIX open (Q4). Do not renumber standalone.
