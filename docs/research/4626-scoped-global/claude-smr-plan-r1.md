# Claude SMR — hostile plan review, #4626 r1

Reviewer: Claude (self-model review, HOSTILE). Base `origin/master` 4eb28ae25.
Target: `docs/research/4626-scoped-global/plan.md` r1.

## Verdict

- **M03 → PLAN-READY *WITH REQUIRED REVISIONS*** (not a clean pass — one material
  consumer missed, one semantic gap unhandled). Fix the two REQUIRED items below and it
  converges.
- **L01 → PLAN-DEFER** — agree with the plan. The LATENT quantification is correct and the
  renumber hazard is real. I'd go further: surface the PLAN-KILL-as-WONT-FIX option (Q4) as
  the *primary* recommendation, since the under-clear is Junos-correct.

## REQUIRED (M03 — must fix before /engineer)

**R1. MISSED CONSUMER — zone-local address-book resolution (#3287).**
`pkg/config/compiler_security_addressbook.go:204-205` calls
`rewrite(p.Match.FromZone, p.Match.SourceAddresses)` /
`rewrite(p.Match.ToZone, p.Match.DestinationAddresses)` for every GLOBAL policy. `rewrite`
(`:163`) takes a SINGLE zone name and rewrites zone-local address tokens to their
zone-qualified internal names (`zoneLocalQualify`) when `localDefines(zone, token)`. This is
NOT in the plan's §5A consumer list, and it is NOT a mechanical `[]string` swap — it is a
SEMANTIC problem:

- With `FromZones = [ trust dmz ]` and a `source-address foo` that is defined in trust's
  zone-local book, `rewrite` would qualify `foo` → `trust/foo`, but the rule's scope also
  admits dmz-ingress packets, for which `trust/foo` is the wrong (or non-resolving) book entry.
- If `foo` is defined in BOTH trust and dmz local books with different prefixes, there is no
  single correct rewrite — the flat shared `SourceAddresses []string` cannot carry a per-zone
  resolution.

`rewrite` ALREADY returns early for a wildcard/empty zone (`IsWildcardZone(zone)` → global
book, `:165`). The clean, well-defined extension that preserves single-zone behavior EXACTLY:
**a scoped global resolves zone-local books ONLY when its scope is a single concrete zone
(`len(FromZones)==1 && !wildcard`); a multi-zone scope resolves against the GLOBAL book**
(same carve-out the unscoped/`any` global already gets). This is a real parity LIMITATION
(multi-zone scoped globals can't use zone-local address books) that MUST be documented as a
known nuance, not silently dropped. The plan must add this consumer + the resolution rule +
a test (`foo` in trust-local, scope `[trust dmz]`, assert it resolves against the global book,
not `trust/foo`).

**R2. MISSED CONSUMER — warn validator.** `pkg/config/compiler_validate_warn.go:2040`
(`p.Match.ToZone != "junos-host"`) reads the scoped-global to-zone. Not in the plan's list.
Must be generalized (skip iff NO element is junos-host, or per-element). Grep for the full set
of readers is incomplete in §5A — R1 and R2 prove at least two were missed; the plan MUST
carry a COMPLETE grep-verified enumeration (the §11 Q5 "confirm none" is not enough — do it in
the plan, since I already found live misses).

## STRONG (M03 — address or explicitly wave)

**S1. `matchedResult` reported zone-context (plan invariant #7) is under-specified.**
`policymatch.go:933/1019` passes `pol.Match.FromZone, pol.Match.ToZone` into `matchedResult`
as the reported result zones (consumed by `show security match-policies`). With a set, what
does a single-valued "Source zone" column show for a `[trust dmz]` scope that matched a
trust-ingress packet? The plan says "report the matched element" — that is the right answer
(report the concrete zone the packet actually traversed, which the query carries as
`q.FromZone`), but the plan must PIN it: report `q.FromZone`/`q.ToZone` (the matched flow's
zones), NOT a joined label, so the column stays a single concrete zone. Verify the Rust
`PolicyEvaluationResult` reported-zone path (`policy.rs:2737` neighborhood) does the same.

**S2. `#3984` REPLACE→ACCUMULATE behavior change is real and under-tested in the plan.**
Flipping `scalar`→`multi` means two separate `set ... match from-zone trust` +
`set ... match from-zone dmz` statements now UNION instead of the second replacing the first.
The plan notes it (invariant #3) but the test plan doesn't explicitly cover the two-separate-
lines shape — add it (it is a distinct AST shape from the bracket list).

## CONFIRMED-OK (I tried to break these and could not)

- **Wire type-change safety.** I verified `match_from_zone`/`match_to_zone` are NOT in the HA
  session-sync path (`grep` of `pkg/cluster`, `userspace-dp/src/session`, `SessionSyncRequest`
  → zero hits). The helper is a CHILD process of xpfd (`exec.Command`,
  `pkg/dataplane/userspace/process.go:70`), so the control-socket JSON is ALWAYS same-version
  (an in-place #1917 upgrade replaces both binaries and respawns the child — no old-helper-
  meets-new-xpfd window). The config snapshot is recompiled locally each boot (not a persisted
  replay of an old-typed blob). The plan's "per-node atomic, no HA exposure" claim is CORRECT.
  The `string`→`array` value-type change of the existing serde field is safe.
- **Schema shape.** `from-zone`/`to-zone` are DIRECT children of the global-policy `match`
  node (`schema_security.go`), children:nil — so the #2419 collapsed leaf
  `Keys=["from-zone","trust","dmz"]` is exactly what `firewallMatchValues` reads. The helper
  choice is right.
- **L01 sentinel map.** Counter idx is already 1-based (`session/entry.rs:80`);
  `DEFAULT_POLICY_SENTINEL_ID=u32::MAX` is distinct and excluded alongside 0 in the
  `DuplicatePolicyId` check (`policy.rs:1731-1738`). The residual overload is exactly the
  first-policy `policy_id==0`. Plan is accurate.

## Nits

- N1. §5A says "delete/repurpose `schema_global_zone_list_4415_test.go`" — be explicit: it is a
  RED-guard (`TestGlobalPolicyZoneListRejected4415`) that asserts REJECTION; it must be
  INVERTED to a positive-accept test in the same PR or the suite goes red.
- N2. Add `IsWildcardZoneSet` next to `IsWildcardZone` as the single SSOT for both Go and (via
  mirror) the Rust `build_global_zone_scope` empty-or-contains-"any" collapse, so the two
  planes cannot drift (the same drift #3680 fixed for the scalar case).

## Bottom line

The wire-parity and L01 halves are solid and correctly reasoned. The M03 half is right in shape
but its consumer enumeration is INCOMPLETE — the zone-local address-book resolution (R1) is a
genuine semantic gap, not a mechanical reader, and it dictates a documented parity limitation.
Revise to r2 with R1+R2 (complete grep) + S1/S2 pinned, and M03 is PLAN-READY.
