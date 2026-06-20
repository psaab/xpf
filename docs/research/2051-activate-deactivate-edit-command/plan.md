# Plan: activate/deactivate edit command + load-set service parity (Batch B: #2051 + #2052)

Research branch: `research/review-015-triage`
Base: origin/master `ff38a92e1`
Source: `/tmp/codex-review-015.md` findings #3 (MEDIUM) and #4 (MEDIUM)
Direct follow-ups to #2008 H1 (the `inactive:` marker, just merged).
Companion-free research. Stops at PLAN-READY. NO production code changes here.

Batched because both findings are symptoms of one root cause: the config
edit/load surface has no single service contract, so each verb is hand-patched
into every switch (local CLI / remote CLI / gRPC / REST / configstore replay)
and they drift.

---

## 1. Issue framing

The `inactive:` marker (#2008 H1) shipped: inactive nodes parse, store,
display, and round-trip through `load set` (the flat-line replay now
understands `deactivate`/`activate` via `config.ParseSetVerb` +
`store.applyEditLine`). What did NOT ship:

### #2051 — no interactive activate/deactivate command

The PRIMITIVES exist:
- `config.ConfigTree.DeactivatePath`/`ActivatePath` — `pkg/config/ast_edit.go:372,382`
- `config.ParseSetVerb` — `pkg/config/parser.go:71`
- `store.applyEditLine` routes the verbs in replay — `pkg/configstore/store.go:1041-1056`

But there is NO interactive verb on any surface:
- store has no `DeactivateFromInput`/`ActivateFromInput` (only
  `SetFromInput`/`DeleteFromInput`, `store.go:833,858`)
- local CLI dispatch handles set/delete/copy/rename/insert only —
  `pkg/cli/cli_dispatch.go:302-317`
- cmdtree config-mode tree has no activate/deactivate entries
- gRPC `Set` routes copy/rename/insert by prefix then everything else through
  `SetFromInput` — `pkg/grpcapi/server_config.go:49-57` (so `deactivate ...`
  becomes the junk path `set deactivate ...`)
- REST `configSetHandler` -> `SetFromInput` only — `pkg/api/config.go:44-59`
- remote CLI has no activate/deactivate dispatch
- `pkg/config/README.md:120-122` explicitly notes this was deferred.

### #2052 — `load set` advertised but rejected by service surfaces

- cmdtree advertises `load set` — `pkg/cmdtree/tree.go:1046-1050`
- local CLI implements `load set terminal` -> `store.LoadSet` —
  `pkg/cli/cli_config.go:104-160` (local `load set <file>` is also rejected —
  only `terminal` source; minor)
- remote CLI rejects non-override/merge — `cmd/cli/main.go:382-385`
- gRPC `Load` rejects non-override/merge/empty — `pkg/grpcapi/server_config.go:128-142`
- REST `Load` rejects non-override/merge/empty — `pkg/api/config.go:228-243`
- proto comment documents nonexistent `replace`, omits `set` —
  `proto/xpf/v1/xpf.proto:101-104`

Consequence: `show | display set` output (now containing `deactivate` lines)
cannot be loaded back through the service path.

---

## 2. Blast radius

- `pkg/configstore/store.go` — possibly new `DeactivateFromInput`/
  `ActivateFromInput` (thin wrappers over `applyEditLine`/`ParseSetVerb` +
  `DeactivatePath`/`ActivatePath`).
- `pkg/cli/cli_dispatch.go` — two new dispatch cases.
- `pkg/cli/cli_config.go` — already supports `load set`; widen `<file>` source
  (minor).
- `cmd/cli/main.go` — remote CLI: dispatch activate/deactivate; accept
  `load set terminal`.
- `pkg/grpcapi/server_config.go` — `Set` prefix-route for activate/deactivate;
  `Load` accept `mode == "set"`.
- `pkg/api/config.go` — REST activate/deactivate handler(s); `Load` accept
  `set`.
- `pkg/cmdtree/tree.go` — add activate/deactivate config-mode entries +
  completion.
- `proto/xpf/v1/xpf.proto` — comment-only fix (override/merge/set; drop
  replace). No field change, no wire-format change.
- Completion (`pkg/config/schema_complete.go`) — activate/deactivate path
  completion should reuse `set`-path completion (paths to existing nodes).

No dataplane, no per-packet, no HA path. Pure control-plane plumbing on top of
already-tested primitives. Low risk.

## 3. Concrete design

### Multiple Path Options

**P-B1 (the abstraction): shared editcmd package vs per-surface wrappers.**

- **Option A (Codex's preference): a shared `pkg/configstore/editcmd` package**
  owning the full verb set (`set`/`delete`/`activate`/`deactivate`/`copy`/
  `rename`/`insert`), routed by local CLI, remote CLI, gRPC, REST, and load-set
  replay. Eliminates drift permanently.
- **Option B: add `DeactivateFromInput`/`ActivateFromInput` store methods + two
  cases per surface**, mirroring the existing `SetFromInput`/`DeleteFromInput`
  pattern.

RECOMMENDATION: **Option B, scoped tightly.** Rationale: the store already IS
the single contract — `SetFromInput`/`DeleteFromInput` exist and every surface
already calls them. `applyEditLine` already centralizes the verb switch for
replay. The drift Codex worries about is real but small (2 verbs, ~6 call
sites), and a brand-new `editcmd` package is a larger refactor that touches the
copy/rename/insert prefix-routing too — gold-plating relative to the gap. The
pragmatic increment: add the two `*FromInput` store methods (which internally
reuse `applyEditLine`/`ParseSetVerb`, so the verb logic stays in ONE place),
then route them. The gRPC `Set` already does prefix-routing (copy/rename/
insert); add activate/deactivate to that same prefix switch — that IS the
shared seam, just located in the store + the one gRPC switch rather than a new
package. If a future verb arrives, revisit Option A.

**P-B2 (gRPC verb routing): overload `Set` vs new RPCs.**
The remote CLI sends config edits over the `Set` RPC with the raw input string.
gRPC `Set` already inspects the input prefix (copy/rename/insert). Adding
`deactivate `/`activate ` to that prefix switch (-> `DeactivateFromInput`/
`ActivateFromInput`) needs NO proto change and keeps the remote CLI thin.
RECOMMENDATION: overload `Set` via prefix routing (no new RPC, no regen).
A dedicated REST endpoint is cleaner for REST (`/config/activate`,
`/config/deactivate`) since REST is verb-per-handler today; do that for REST.

**P-B3 (load set over gRPC): reuse LoadRequest.mode.**
Add `mode == "set"` to gRPC/REST `Load` -> `store.LoadSet` (returns applied
count; surface it in the response message or log). Proto comment fix only.
RECOMMENDATION: straightforward, no field change.

### Wiring sketch (Option B)

```go
// store.go
func (s *Store) DeactivateFromInput(input string) error {
    s.mu.Lock(); defer s.mu.Unlock()
    if s.candidate == nil { return errNotConfigMode }
    if err := applyEditLine(s.candidate, "deactivate "+input); err != nil { return err }
    s.dirty = true; return nil
}
// ActivateFromInput symmetric.
```

Local CLI dispatch: two cases prepend `GetEditPath()` like set/delete.
gRPC `Set`: `strings.HasPrefix(input, "deactivate ")` -> `DeactivateFromInput`.
REST: `/config/activate` + `/config/deactivate` handlers.
Remote CLI: dispatch `deactivate`/`activate` -> `client.Set({input})`.
gRPC/REST `Load`: `case "set": store.LoadSet(content)`.
cmdtree: add `activate`/`deactivate` config-mode entries + completion via the
existing set-path completer.

## 4. Hidden invariants

- `applyEditLine` expects a full flat line incl. verb; `*FromInput` must
  prepend the verb exactly once (the store wrapper, not the caller).
- Local CLI prepends `GetEditPath()` to the path for set/delete; activate/
  deactivate MUST do the same so edit-mode-relative paths work.
- gRPC `Set` prefix routing is order-sensitive: `deactivate` must be checked
  before any generic fallthrough (it already falls through to `SetFromInput`).
- `DeactivatePath` on an already-inactive node and `ActivatePath` on an active
  node must be idempotent/clear-erroring (verify `ast_edit.go` behavior; add
  test).
- `load set` returns an applied-count locally (`%d commands applied`); the
  service response should not silently drop it.
- Completion for activate/deactivate must offer paths to EXISTING nodes
  (including currently-inactive ones for `activate`), unlike `set` which
  offers schema-valid new paths.

## 5. Risk table

| Risk | Severity | Mitigation |
|------|----------|------------|
| gRPC Set prefix-route mis-orders and treats `deactivate x` as `set deactivate x` | Med | Add prefix case + test asserting the node becomes inactive, not a junk path |
| Completion offers wrong path universe (set-schema vs existing-nodes) | Low | activate over inactive nodes; reuse existing-node completer, test |
| Remote CLI / proto drift persists if only some surfaces updated | Med | Single PR touches all four surfaces + proto comment + cmdtree; parity test per surface |
| `load set <file>` still rejected locally (inconsistent) | Low | Widen local source to file too (in-scope minor) |
| proto comment edit triggers unnecessary regen | Low | Comment-only; no field change; regen is a no-op for wire |

## 6. Test plan

- store: `DeactivateFromInput` makes the node inactive; `ActivateFromInput`
  clears it; idempotency on double-deactivate/activate.
- local CLI: `deactivate <path>` then `show` displays `inactive:`; survives
  commit + `show | compare`; `activate` clears.
- remote CLI -> gRPC: `deactivate ...` routes to `DeactivatePath` (NOT a junk
  set); round-trip commit/show.
- REST: activate/deactivate endpoints; load mode=set with a body containing
  `deactivate` lines.
- gRPC `Load` mode=set with `display set` output containing `deactivate` lines
  -> reconstructs inactive nodes.
- cmdtree: completion offers activate/deactivate; activate completion lists
  currently-inactive paths.

## 7. Out of scope

- A full `pkg/.../editcmd` package refactor (P-B1 Option A) — deferred unless a
  third verb arrives.
- New gRPC RPCs for activate/deactivate (overload `Set` instead).
- `load replace` (the stale proto comment) — explicitly removed, not
  implemented.
- Any change to the `inactive:` marker semantics themselves (shipped in #2008).

## 8. Open questions

- **Q1**: REST — dedicated `/config/activate` endpoints vs reuse `/config/set`
  with a verb field? Recommend dedicated endpoints (REST is verb-per-handler).
- **Q2**: Should `activate`/`deactivate` accept a bare path at top level
  (no edit context) the same as `set`? Recommend yes, parity with set.
- **Q3**: Surface `LoadSet` applied-count over gRPC/REST (add to response) or
  log-only? Recommend add to response for parity with local CLI.

---

## 9. Hostile Claude-SMR self-review

**Are #2051 and #2052 real? YES, both verified.** #2052 is unambiguous: the
command tree literally advertises `load set`, local CLI honors it, and all
three service surfaces reject it with an error string that doesn't even mention
`set`. The proto comment documents a `replace` mode that exists nowhere. #2051
is equally concrete: the verbs are dispatched in flat-line replay but have zero
interactive entry point, and gRPC `Set` would silently mangle `deactivate ...`
into a junk path.

**Are they correctly rated MEDIUM (not HIGH)? YES.** Neither is a security or
data-loss defect. They are usability/parity gaps on a just-shipped feature. The
workaround for #2051 (paste deactivate lines via load set) is itself blocked by
#2052, which is why they batch — but the combined impact is "operator can't use
the standard Junos deactivate workflow remotely," not "firewall mis-enforces."
Correctly below the Batch A feed-enforcement HIGH.

**Should either be KILLed or DEFERred?** No KILL — both are real and the fix is
small and builds on shipped primitives (low risk, high parity value, directly
completes #2008's intent). I considered DEFER for #2051 on the grounds that
`inactive:` round-trips via load set already, but that argument collapses
because #2052 shows the load-set path is broken remotely too — so without this
batch, the `inactive:` feature is effectively local-CLI-only. Completing the
exposure is the natural close-out of #2008 and should not be left half-done.

**Where I push back on Codex:** Codex pushes a shared `editcmd` package as the
fix for both. I down-scope to Option B (store `*FromInput` wrappers + per-
surface routing) because (a) the store already IS the de-facto contract every
surface calls, (b) `applyEditLine` already centralizes the verb switch, so the
verb logic does NOT get duplicated, and (c) a new package would drag in the
copy/rename/insert prefix-routing rework, expanding blast radius for a 2-verb
gap. This keeps the change mechanical and reviewable. If the verb set grows
again, Option A becomes worth it — noted as a follow-up, not this increment.

**Sharpest risk I'd gate on:** the gRPC `Set` prefix-routing. The current
fallthrough sends ANY unrecognized verb to `SetFromInput`, which means a missed
prefix case doesn't error — it silently creates a bogus config node named after
the verb. The test MUST assert the node becomes inactive, not merely that the
call returns nil. A green "no error" test would pass against the broken
behavior.

### Recommendation

- **#2051: PLAN-READY** — ship via P-B1 Option B (store `*FromInput` wrappers)
  + P-B2 (overload gRPC `Set` prefix routing, dedicated REST endpoints). Low
  risk, completes #2008's intent, builds on shipped primitives. Gate on the
  gRPC-prefix-routing test asserting actual inactivation.
- **#2052: PLAN-READY** — ship together in the same PR (shared surfaces): add
  `mode == "set"` to gRPC/REST `Load`, accept `set` in remote CLI, fix the
  proto comment (drop `replace`, add `set`). Trivial, unblocks remote
  `inactive:` round-trip. Both are MEDIUM and correctly ranked below Batch A.
