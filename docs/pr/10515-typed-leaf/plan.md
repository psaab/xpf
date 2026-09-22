# Issue #10515 — DRAFT v2 plan

## STEP-0 result and live evidence

Issue #10515 remains **OPEN**. A direct GitHub search of merged PRs for `10515 OR "typed-leaf"` returned typed-leaf PRs such as #8872, #8441, #1682, and #1320, but no #10515 fix or tolerant-warning-surface change. The worktree base is `bfcbff49dddcb390f2f8c124c36908f815fb8d0d` on `fix/10515-typed-leaf`; the reported source is still present.

The live source path is:

- `pkg/configstore/store.go:772` — one `compileTreeLenient` helper.
- `pkg/configstore/store.go:785-787` — `schemaValidateExpandedTree` failure is sent only to `slog.Warn`; the error is discarded before `cfg` exists.
- Five production call sites reach the helper: `Store.Load`, `Store.SyncApply`, two pending-confirm rollback recovery branches, and `Store.RetainedGeneration`.
- Strict operator commit/check remains separate at `compileTreeStrict` and rejects the fixture.

The firsthand scratch repro used the existing fixture `class-of-service { schedulers be transmit-rate asd; }` with isolated `GOCACHE` and `GOTMPDIR`:

- strict schema validation rejected the value and named `asd`;
- lenient compile returned `err=nil`, `cfg.Warnings=[]`;
- `Store.Load` returned nil and installed an active config with `Warnings=[]`;
- `Store.SyncApply` returned nil with `Warnings=[]`;
- `config.ValidateConfig(active)` produced zero lines mentioning the violation;
- the captured slog sink received three identical typed-leaf WARN records (one direct lenient compile, one Load, one SyncApply).

This reproduces the issue's claim: the tolerated active value is live, but its only current signal is journald. The compiler evidence also explains why alarms cannot reconstruct it: `transmit-rate asd` is compiled to an unset/zero scheduler rate, so the original invalid token is gone from the typed `Config` before `ValidateConfig` runs.

## Blast radius and invariants

The production change needed to preserve the lost fact is local and pre-publish: capture the schema error in `compileTreeLenient`, compile leniently as today, and append a stable typed-leaf warning to the successfully compiled config. Do not rerun schema validation or reconstruct the value from `ValidateConfig`; the AST/error detail exists only at the current gate.

The observable-surface decision is broader:

- `cfg.Warnings` currently reaches commit responses through one REST projection and one gRPC projection, four local CLI commit/check render sites, four remote CLI render sites, and the daemon apply-time log loop.
- The four existing alarm renderers are `pkg/cli/cli_show_system.go`, `pkg/grpcapi/server_show_system.go`, `pkg/cli/cli_show_security_log.go`, and `pkg/grpcapi/server_show_security_text.go`. They recompute `config.ValidateConfig(cfg)` and do not read `cfg.Warnings`.
- There are five production `ValidateConfig` call sites: the compiler tailgate plus those four alarm renderers. `runTailGates` already appends every `ValidateConfig` result into `cfg.Warnings`.
- The warning-consumer audit explicitly says alarms recompute `ValidateConfig` and that warnings otherwise participate in none of the active-config identity/resync paths (`pkg/daemon/daemon_apply_mtu_warnings_9841.go:57-67`). Production config/HA identity hashes are text-based; the compiled warning slice must be populated before publication, not mutated afterward.
- `pkg/configstore/store_generation.go` has an active fast path returning the already-published compiled config and a history recompile path. The returned retained-generation object is consumed for IPsec generation attribution, not by an operator alarm reader.
- `pkg/configstore/store_persist.go` has two lenient pending-confirm recovery branches: expired rollback (the recompiled target becomes active) and live re-arm (the recompiled target remains `confirmPrevCfg` until promotion). Operator `Rollback(n)` only changes the candidate; its subsequent commit is strict and is not another tolerant ingress.
- `pkg/configstore/store_format.go:102-105` has a debug `ExportJSON` that marshals the compiled object, including warnings. Production text export, HA sync, and digest/resync paths remain text-based; the debug dump may gain the warning as intended diagnostic state.

The pinned invariant is important: broadening all alarms to consume all `cfg.Warnings` would expose every existing compiler advisory, duplicate the `ValidateConfig` lines already stored by `runTailGates`, change alarm counts/noise, and violate the documented warning-reader contract. A fix must scope the new alarm read to this typed-leaf class only.

## Acceptance mapping

The issue acceptance has two alternatives:

1. **Persistent cfg.Warnings-backed CLI/API/alarm record.** The primary designs below satisfy this without a new command: the warning is generated into the active compiled config, and all four existing alarm renderers read only the marked typed-leaf subset. Local CLI `show system alarms` and gRPC system-alarm output contain the marker text; local/remote `show security alarms detail` and its gRPC detail output contain the marker text, while non-detail security alarms expose the changed count only. The existing REST/gRPC commit warning projections and daemon log also retain the same line, but a commit response or journal is no longer the only path.
2. **Explicit journald-only contract.** A docs-only fallback could state that tolerated typed-leaf violations are intentionally visible only through `show log`/journald and that no config-status/alarm guarantee exists. This formally uses the issue's escape hatch but leaves the stated active-config observability defect unfixed and is not the recommended disposition without issue-owner acceptance of that trade-off.

The plan therefore treats a queryable existing alarm surface as required for a code fix. It does not treat appending to `cfg.Warnings` alone as acceptance-complete.

## Primary option 1 — scoped marker in cfg.Warnings, existing alarm readers

This is the minimum-change design and should be reviewed first.

1. In `compileTreeLenient`, retain `schemaErr` while preserving the existing journald WARN. After the lenient compile succeeds, append one deterministic warning with a machine-filterable stable prefix, for example:

   `[typed-leaf-tolerated] <schema error> (strict commit would reject this; issue #10515)`

   Wrap only `schemaErr.Error()`. Never extract or store raw AST values: existing schema-error redaction, including the secret-leaf contract from #8441/#8434, governs what the warning may reveal. The non-secret `asd` fixture therefore names `asd`, while a secret fixture retains its redacted error text. A fresh compiled config gets a fresh warning slice; no post-publication mutation is allowed.
2. Add one shared predicate/constant for the marker. The system alarm renderers append only marked typed-leaf warnings from `cfg.Warnings` to their existing `ValidateConfig(cfg)` result. Security alarm detail renderers do the same; their non-detail siblings render the resulting count only. They do not union all warning strings, rerun schema validation, or change ordinary alarm semantics. The marker cannot collide with the current `ValidateConfig` output, so no broad deduplication policy is needed.
3. Keep the existing commit-response and apply-log projections unchanged. A strict commit still rejects the same tree before compilation.

### Option 1 lifecycle and data flow

| Path | Set/clear behavior | Queryability and test boundary |
| --- | --- | --- |
| `Store.Load` | Parse the persisted tree, capture the schema error, compile leniently, append the marker, then assign `s.compiled` and publish the active snapshot. A clean persisted tree produces no marker. Restart regenerates it from the tree; the warning is active compiled state, not a separate disk field. | Both local and gRPC alarm renderers see the marker after Load. |
| `Store.SyncApply` | Parse/sanitize/rewrite as today, then use the same helper. The marker is in the compiled object before `s.compiled = compiled`, publication, and history replacement. A clean peer config replaces it with a clean warning slice. | Both local and gRPC alarm renderers see the marker after SyncApply. |
| Confirm recovery, expired | The previous tree is leniently recompiled in the expired branch. If it compiles, that result becomes `s.compiled` and active; its marker is immediately queryable. Existing compile-failure/ErrConfigCompile behavior is unchanged and has no compiled warning to publish. | Query after recovery promotion; do not claim a warning for the failed compile arm. |
| Confirm recovery, live re-arm | The previous tree is leniently recompiled into `confirmPrevCfg` while the unconfirmed active tree remains active. The marker is not an active alarm before promotion. When the timer promotes the target, that already-compiled config becomes active and the marker becomes queryable. | Test post-promotion visibility and pre-promotion non-visibility separately. |
| `RetainedGeneration` active fast path | Returns the already-published `s.compiled`, so any active marker is preserved by pointer identity. | This object is consumed by IPsec generation attribution, not an alarm reader; no new operator surface is claimed. |
| `RetainedGeneration` history path | Recompiles a copied history tree through the same helper, so the returned ephemeral config deterministically carries the marker when the historical tree is invalid. | Test deterministic marker construction for the history recompile; do not describe this dead object as an alarm surface. |
| Operator `Rollback(n)` | Changes only the candidate. It does not call `compileTreeLenient`; the next operator commit remains strict and rejects the invalid tree. No marker is set by this path. | No rollback-specific tolerant query test is required; the strict commit cell owns this boundary. |
| Next clean strict commit | A fresh compiled config replaces the old one. The strict schema gate refuses the invalid value; a clean commit has no marker, so the alarm clears without a separate clear operation. | Assert marker absent and alarm output clean after replacement. |

Appending before `s.compiled` assignment and active-snapshot publication avoids the post-publish warning mutation race documented by #9841. Warning order is deterministic: existing compiler warnings retain their order, followed by the single schema marker.

## Primary option 2 — #7640-style typed sidecar plus existing surfaces

If a machine-readable record or stable metric is required, use the in-tree #7640 precedent rather than inventing a new command:

1. Add a typed compiled field `Config.LenientTypedLeafViolations []LenientTypedLeafViolation`, analogous to `Config.LenientNATTerminalActionRules`. Each record carries only the already-redacted `schemaErr.Error()` text plus a stable issue/class marker; the error text includes any safe path/value detail supplied by the existing schema contract, and the record never stores or extracts a raw AST value. Populate it at the same pre-compile schema-error capture point, and append the human-readable warning to `cfg.Warnings` for existing commit/log consumers.
2. Have all four existing alarm renderers read the typed field through one shared renderer helper and annotate the existing alarm output only for this violation class. Ordinary `cfg.Warnings` remain outside alarms. Add a bounded control-plane gauge for the violation count, following #7640's metric precedent; the gauge is zero for a clean active config and rebuilt on every compile.
3. Use the existing system/security alarm renderers as the annotation surface, add local/remote/gRPC parity tests, and do not add a new CLI/RPC/REST command. Keep the sidecar `json:"-"` if it is not part of the wire contract, and preserve the lifecycle table above.

This option costs a typed model field, metric descriptor/collector wiring, and existing-renderer annotations, but avoids string-prefix filtering and provides stable per-violation identity. Option 1 is smaller when the alarm line is sufficient.


## Rejected/secondary options

### Union-all `cfg.Warnings` into alarms — rejected

This is not a viable option. `runTailGates` appends every `ValidateConfig` line into `cfg.Warnings`, so unioning the two sources duplicates every such line, not merely potentially. It would newly alarm numerous existing advisory classes, change alarm counts/noise, and violate the documented invariant that alarms recompute `ValidateConfig` while warnings otherwise participate in none. It also must modify all four alarm renderers, not only the two system renderers. Only the marked subset or typed sidecar is acceptable.

### New `show system commit warnings`/active-warning CLI+RPC/REST contract — secondary only

A dedicated surface is coherent only if the requirement is specifically to expose wholesale or structured active `cfg.Warnings` outside the alarm model. It is not minimal for this Low observability bug because options 1 and 2 reuse existing CLI/API alarm surfaces and scope the output to the defect.

Its contract cost must be explicit before selecting it:

- local CLI command parsing, rendering, and CLI authorization;
- remote CLI topic mapping and rendering;
- gRPC ShowText dispatcher topic plus response shape;
- `pkg/cmdtree/showtext_topic.go` canonical command mapping;
- permission-table entries and the completeness guards `TestEveryShowTextTopicHasAPermission_5278` and `TestEveryShowTextTopicHasACanonicalCommand7172`;
- REST handler, JSON shape, and REST authz mapping;
- local/remote/gRPC/REST parity and silence tests; and
- reconciliation of the existing in-tree `show system commit warnings` promise in `routing_instance_inert_protocols_9374.go` and `docs/log/9374.md`, because no such command currently exists.

That is a product/API contract for a Low-severity issue, so this option is eliminated unless issue-owner requirements reject the existing alarm surfaces.

## Verification plan with defect pins

Every test must bind an observable contract and state the regression it catches:

| Cell | Observable assertion | Defect that must turn it RED |
| --- | --- | --- |
| Strict gate | The real strict `configstore.CheckText`/commit-check path rejects the fixture and names `transmit-rate`/`asd`. | Removing/bypassing `compileTreeStrict` schema validation, or testing only compiler acceptance, would falsely admit the operator-authored value. |
| Lenient compiler | `compileTreeLenient` returns a non-nil config and nil error, with exactly one `[typed-leaf-tolerated]` warning containing the path, value, and issue marker. | Deleting the post-compile append, losing the pre-compile error, or hard-rejecting the tolerant path. |
| Load ingress | Persist the fixture, call `Store.Load`, assert active config is non-nil, marker is present, system alarm text contains it, security alarm detail text contains it, and security alarm non-detail output has the corresponding count. | Routing Load through strict compile, dropping the warning before `s.compiled=compiled`, or leaving one of the four alarm readers unwired. |
| SyncApply ingress | Call `Store.SyncApply` with the fixture, assert nil error, active compiled marker, system alarm text and security alarm detail text include it, and non-detail security output has the corresponding count. | Routing peer sync through strict compile, dropping the warning, or wiring only the Load path. This is a separate cell because the two ingresses can drift. |
| Confirm recovery | Exercise expired recovery and assert the reverted target's marker is active/queryable; exercise live re-arm then promotion and assert the marker is absent before promotion and present after. | Publishing the wrong compiled object, claiming a marker for a failed compile, or treating `confirmPrevCfg` as active before promotion. |
| Retained generation | Active fast path returns the published object with its marker; history path recompiles deterministically with the same marker. Do not claim either ephemeral result is itself an alarm source. | Recompiling without the shared helper or nondeterministic warning construction. |
| Alarm scope control | A config with ordinary existing `cfg.Warnings` but no typed marker produces the same `ValidateConfig`-based alarm output/count as before; a clean config emits no typed-leaf line. Run all four renderers. | Unioning all warnings into alarms, printing unconditionally, or changing existing warning counts/noise. |
| RED-on-revert | Revert the append while keeping tolerant nil-error/active behavior: Load, SyncApply, and query-surface assertions must fail. Revert a marker predicate to all-warnings: alarm-scope control must fail. | A regression suite that only proves compilation or journald logging, rather than persistence and queryability. |

Existing strict and tolerant no-brick cells remain in the affected configstore suite; new cells must not replace them with lower-layer compiler-only probes. The focused configstore, CLI, and gRPC test files are run before any project-wide validation.

## Acceptance decision after design review

Recommend **option 1** unless structured metrics/path identity make option 2 necessary. Either gives a persistent active `cfg.Warnings`-backed record and an existing CLI/API/alarm reader, preserves strict rejection and no-brick tolerance, and avoids a new command contract. Reject union-all. Treat option 3 as out of scope unless the issue owner explicitly requires wholesale machine-readable warning history. Treat docs-only journald as an explicit acceptance alternative, not as an unannounced implementation shortcut.

No production code was changed in this DRAFT v2 plan round.
