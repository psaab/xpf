# Codex hostile plan review — #4626 r1

Task ID: `task-mrdrh54a-lda2hl` (Codex session `019f47da-b750-75d0-b80d-71a88cc05f71`).
Verbatim verdict below.

---

Verdict: **M03: PLAN-KILL. L01: PLAN-DEFER.**

1. **M03 wire plan is not safe as written.**
   `match_from_zone` is an existing JSON field: Go emits a string at `protocol.go:1260`, Rust
   expects a `String` at `security.rs:453`, and request decode happens before the snapshot
   version gate at `handlers/mod.rs:88`. `serde(default)` only helps missing fields; it does not
   accept `"trust"` where `Vec<String>` is expected, or `["trust"]` where `String` is expected.
   The fixture also pins the old value type at `protocol_wire_v1.json:788`.

   The HA claim is only partly true: `SessionSyncRequest` carries `policy_id`, not match zones, at
   `control.rs:1030`, and helper `state.json` is not restored on boot per `snapshot.rs:324`. But
   the string-to-array value change still needs either additive plural fields or a protocol bump
   plus a real pre-publish gate. Existing gates only cover scheduler/persistent NAT at
   `manager_compile.go:595`.

   **Required:** add `match_from_zones`/`match_to_zones` and keep singular for compatibility, or
   bump `ProtocolVersion` and add a required gate/sentinel before publishing array-shaped
   snapshots. Update the plan's false "single-zone bit-identical on wire" claim.

2. **M03 host-inbound semantics are under-specified and currently wrong for sets.**
   Go explicitly consults only globals scoped to `to-zone junos-host`, not wildcard `any`, at
   `policymatch.go:941` and `policymatch.go:1012`. Rust hard-checks equality to
   `GlobalZoneScope::Zone(JUNOS_HOST_ZONE_ID)` at `policy.rs:2991`. A naive `Zones` enum will
   either miss `to-zone [junos-host untrust]` or accidentally pull `to-zone any` onto the host
   path.

   **Required:** add an explicit-host predicate: false for `Any`, true for a concrete set
   containing `junos-host`. Decide and test mixed `any` plus `junos-host`; the current "any
   anywhere collapses to Any" rule loses explicit-host information.

3. **The compiler/list accumulation direction is basically right, but the plan under-tests schema
   fallout.** The leaves are direct children of `match` at `schema_security.go:262`, and the
   current compiler indeed reads only the first token at `compiler_security_policy.go:246`.
   `firewallMatchValues` correctly reads `Keys[1:]` and children at `compiler_firewall.go:768`.

   But `multi:true` also changes replacement, member-delete, and apply-groups union behavior via
   `ast_edit.go:278`, `ast_edit.go:462`, and `ast_groups.go:492`.

   **Required:** tests for flat bracket, hierarchical block, repeated set accumulation, member
   delete, apply-groups union, order/dedup, and mixed `any`.

4. **The plan missed real consumers of `Match.FromZone` / `Match.ToZone`.**
   Address-book rewrite depends on the single scoped zone at `compiler_security_addressbook.go:204`.
   Host-inbound warnings use single `ToZone` at `compiler_validate_warn.go:2040`. Display/API/metrics
   also have direct string assumptions at `api/security.go:299`, `metrics_counters.go:423`,
   `server_show_policies_text.go:193`, and `show_security.go:246`.

   **Required:** add an exhaustive consumer checklist and a shared list-scope formatter/matcher. Do
   not let every surface invent its own join/wildcard behavior.

5. **Strict validation has the expected single-value assumption, plus a missed warning path.**
   Current strict gate checks one `FromZone` and one `ToZone` at
   `compiler_validate_strict_policy.go:596`. The plan catches that. It misses the warning path
   above and the address-book rewrite.

   **Required:** per-element strict errors naming the offending element; preserve `from-zone
   junos-host` reject, undefined-zone reject, and explicit `to-zone junos-host` allowance.

6. **L01 defer is the right call.**
   The first policy really is id 0 via `policies.go:53`. The delete/changed invalidators
   intentionally skip id 0 at `daemon_policy_invalidate.go:71` and `daemon_policy_invalidate.go:382`.
   Rust default policy is already `u32::MAX` at `policy.rs:155`, counter ids are already 1-based
   with `0` as no-counter at `session/entry.rs:78`, and duplicate policy-id checking excludes `0`
   and `u32::MAX` at `policy.rs:1730`.

   No clean non-breaking renumber path is visible because `policy_id` is stamped into sessions and
   HA-synced at `session/entry.rs:50`, while `bound=None` sessions keep the frozen stamped id at
   `policy.rs:1494`. Observable impact remains a conservative under-clear, not a live enforcement
   fail-open.

   **Required:** leave L01 deferred unless a session-schema/version migration lands. Do not
   renumber standalone.

---

## Disposition of Codex r1 findings in plan r2

- **#1 (wire):** ACCEPTED. r2 §5A-A8 switches to additive `match_from_zones`/`match_to_zones`
  (keep singular), new Rust prefers plural else singular, fixture gains two additive keys. The
  false "bit-identical on wire" claim is removed (r1→r2 delta note + §6).
- **#2 (host-inbound set):** ACCEPTED. r2 §5A-A6 rejects a `to-zone` list mixing `junos-host` with
  other tokens; adds `is_host_scope()` (false for `Any`, true iff the set is exactly the
  junos-host id). Mixed `any`+`junos-host` cannot occur (rejected).
- **#3 (multi:true fallout):** ACCEPTED. r2 invariant #3 + test plan add member-delete
  (`ast_edit.go:462`) + apply-groups union (`ast_groups.go:492`) + repeated-set accumulation +
  order/dedup.
- **#4 (missed consumers):** ACCEPTED. r2 §5A-A5 is a complete grep-verified checklist routed
  through a new shared SSOT (§5A-A2: `IsWildcardZoneSet` / `ZoneScopeSetLabel` /
  `globalScopeSetMatches`), incl. `compiler_security_addressbook.go`, `compiler_validate_warn.go`,
  `cmd/cli/show_security.go`.
- **#5 (strict per-element):** ACCEPTED. r2 §5A-A4 loops per element, preserves the junos-host
  reject/allowance + undefined-zone reject.
- **#6 (L01 defer):** ACCEPTED — matches r2 §5B and the Claude SMR.

M03's "PLAN-KILL" was a revise-not-abandon: every Required item is a bounded addition, all folded
into r2. Re-review requested to confirm M03 → PLAN-READY.
