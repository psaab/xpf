# Issue #10515 — DRAFT v1 plan

## STEP-0 result

Issue #10515 is still **OPEN**. `gh pr list --state merged --search "10515"` and the merged-PR search for `typed-leaf warning tolerant` found no fix for this issue. The current worktree is at base `bfcbff49dddcb390f2f8c124c36908f815fb8d0d` (`fix/10515-typed-leaf`), and the source still contains the reported journald-only behavior.

The live source path is:

- `pkg/configstore/store.go:772` — one `compileTreeLenient` helper.
- `pkg/configstore/store.go:785-787` — `schemaValidateExpandedTree` failure is sent only to `slog.Warn`; the error is discarded before `cfg` exists.
- Five production call sites reach the helper: `Store.Load`, `Store.SyncApply`, two pending-confirm rollback recovery branches, and `Store.RetainedGeneration`.
- Strict operator commit/check remains separate at `compileTreeStrict` and rejects the fixture.

The firsthand scratch repro used the existing fixture `class-of-service { schedulers be transmit-rate asd; }`:

- strict schema validation rejected the value and named `asd`;
- lenient compile returned `err=nil`, `cfg.Warnings=[]`;
- `Store.Load` returned nil and installed an active config with `Warnings=[]`;
- `Store.SyncApply` returned nil with `Warnings=[]`;
- `config.ValidateConfig(active)` produced zero lines mentioning the violation;
- the captured slog sink received three identical typed-leaf WARN records (one direct lenient compile, one Load, one SyncApply).

This reproduces the issue's claim: the tolerated active value is live, but its only current signal is journald.

## Blast radius

The mechanical part is local: one tolerant compile helper can preserve the schema error as a warning after compilation, using the same `cfg.Warnings` carrier already used by the compiler's other tolerant gates. The observable-surface decision is not local:

- `cfg.Warnings` currently reaches commit responses through one REST projection, one gRPC projection, four local CLI commit/check render sites, four remote CLI render sites, and the daemon apply-time log loop.
- The two `show system alarms` implementations (`pkg/cli/cli_show_system.go` and `pkg/grpcapi/server_show_system.go`) recompute `config.ValidateConfig(cfg)` instead of reading `cfg.Warnings`.
- There are five production `ValidateConfig` call sites (compiler tailgate plus local/remote system and security alarm renderers). The warning-consumer audit explicitly says alarms recompute `ValidateConfig` and that warnings otherwise participate in none of the active-config identity/resync paths (`pkg/daemon/daemon_apply_mtu_warnings_9841.go:57-67`).
- Existing configstore tests pin the strict/tolerant split and multiple tolerant warning paths, but no current test pins this typed-leaf schema error in `cfg.Warnings` or a post-load/post-sync query surface.

The main compatibility risk is broadening `show system alarms` to consume all compiled warnings: that would make every existing compiler advisory an active alarm, change alarm counts/noise, and potentially duplicate lines already recomputed by `ValidateConfig`. A dedicated query surface avoids that semantic change but requires command/API/authz plumbing.

## Design questions to resolve before implementation

1. Should all `cfg.Warnings` become active `show system alarms` entries, or should typed-leaf/load warnings have a dedicated warning-status surface?
2. If alarms consume `cfg.Warnings`, should they union with `ValidateConfig(cfg)` and deduplicate, or should `ValidateConfig` become the sole derived source? What is the expected lifecycle/count for existing warnings?
3. Which external surfaces are required: local CLI, gRPC `ShowText`, REST, or all three? There is no implemented `show system commit warnings` command today.
4. Must the record be named as a generic schema warning or include path/value/issue metadata, and should it survive retained-generation/rollback recompilation exactly as the active config warning does?
5. Are config warnings intended as alarms for every tolerant gate, or only this typed-leaf class? Existing comments state the current warning carrier is intended for commit responses and apply logs, not active alarms.

## Candidate designs

### A. Extend `show system alarms` (smallest code diff, largest behavior change)

1. Make `compileTreeLenient` retain the schema error and append a deterministic `cfg.Warnings` entry after successful lenient compilation; keep the existing slog WARN for journald continuity.
2. Change both system-alarm renderers to union `cfg.Warnings` with `ValidateConfig(cfg)` using stable deduplication.
3. Add strict/tolerant, Load, SyncApply, retained-generation, and local/remote alarm regression tests.

This directly satisfies the acceptance wording, but exposes all existing compiler warnings as alarms and changes alarm counts for configurations that already have `cfg.Warnings`.

### B. Add a dedicated active-config warning command (recommended for review)

1. Preserve the same production compiler change in `compileTreeLenient`, with a stable warning string that names the schema error and issue.
2. Add a dedicated `show system commit warnings`/active-config warnings renderer backed by `Store.ActiveConfig().Warnings`; expose the same data through the selected RPC/REST contract and command authorization tables.
3. Leave `show system alarms`'s existing `ValidateConfig` semantics unchanged.
4. Add end-to-end tests for Load and SyncApply followed by the chosen local and remote query surfaces, plus strict rejection and RED-on-revert coverage.

This is the least surprising alarm behavior, but it is a new CLI/API contract and needs exact command and authorization design.

### C. Add a structured warning-status resource

1. Preserve the compiler change from A/B.
2. Add a versioned status endpoint/RPC returning active config warnings, with lifecycle and deduplication rules explicit in the schema.
3. Add CLI rendering that consumes that resource and tests for restart, sync, rollback, and active-config replacement.

This gives API consumers a stable machine-readable contract but has the largest schema and transport blast radius.

## Proposed implementation sequence after design approval

1. Decide A/B/C and document the selected warning lifecycle and external surfaces.
2. Add a helper in `compileTreeLenient` that keeps the schema error for post-compile warning append; retain the existing journal line and strict-path rejection unchanged.
3. Add a configstore regression fixture covering strict reject, lenient `cfg.Warnings`, `Store.Load`, `Store.SyncApply`, and retained/rollback compilation as applicable.
4. Add query-surface tests for the selected contract. Include a RED-on-revert assertion that deleting the warning append makes the test fail while the tolerant path still returns nil and remains active.
5. Run the affected configstore, CLI, API, and/or gRPC suites; run the project-wide validation only after all lanes land.

No production code was changed in this DRAFT v1 plan round.
