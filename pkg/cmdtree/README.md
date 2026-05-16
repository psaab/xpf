# pkg/cmdtree

Single source of truth for every CLI command tree (operational +
configuration). Used by the local CLI, the remote CLI, and the gRPC
tab-completion RPC. Adding a command here automatically propagates to all
three frontends.

## Entry points

- `Node` — `tree.go`. Tree node: description, static children,
  `DynamicFn`/`ContextDynamicFn` for config-aware completions. Optional
  typed-leaf fields (`ValueType`, `ValueDesc`, `ValueExamples`,
  `Validator`) describe the value a leaf accepts — see "Typed leaves"
  below.
- `Candidate` — `tree.go`. `(name, desc)` pair surfaced during tab
  completion.
- `OperationalTree` — `tree.go`. Canonical root for `show`, `clear`,
  `request`, `monitor`, `ping`, `traceroute`, etc.
- `ConfigTopLevel` — root for the `set`/`delete` configuration grammar.
- `ConfigClassOfServiceSchedulers` — `tree.go`. Per-leaf typed-value
  schema for `set class-of-service schedulers <name> { ... }` (#1319
  Phase 2). Reused by the config-mode `set` completion tree and by
  `SchemaValidate`.
- `KeysFromTree(tree)` — `tree.go`. Used by `pkg/cli` and `pkg/grpcapi`
  for Junos-style prefix matching.
- `WriteHelp`, `LookupDesc`, `PrintTreeHelp`, `CompleteFromTree` — the
  helper API the three frontends consume.
- `SchemaValidate(tree, cfg)` — `schema_validate.go`. The commit-check
  gate (#1319). Walks the AST against typed-leaf cmdtree Nodes and
  invokes their `Validator` on each value; called by
  `pkg/configstore.compileTree` against an apply-groups-expanded clone
  BEFORE compile so garbage like `transmit-rate asd` fails loud at
  `commit check`, including when it arrives through `groups { ... }`.

## Typed leaves (#1319)

A `Node` with `ValueType != ValueAny` is a typed leaf: it expects
exactly one value of the declared kind at the next slot.

- `?` completion surfaces `ValueDesc` + `ValueExamples` so the operator
  sees what's accepted instead of an empty cursor.
- `SchemaValidate` invokes the leaf's `Validator` at commit-check.
  Validators are stateless string-checkers (`config.ValidateRate`,
  `config.ValidateByteSize`, ...) declared in `pkg/config` so they
  share the same parsers the compiler uses.

This PR ships typed leaves only for `class-of-service schedulers`
(`transmit-rate`, `priority`, `buffer-size`). Every other Node remains
on `ValueAny` (zero value) — no behaviour change. Leaves are only typed
when the compiler consumes them today; scheduler-level `shaping-rate`
is intentionally not listed because shaping is implemented under
`class-of-service interfaces ... unit ... shaping-rate`.

`transmit-rate exact` is accepted only as the Junos split-modifier form
when the same scheduler also has a typed `transmit-rate <rate>` value.
An exact-only scheduler line still fails commit-check because the compiler
would otherwise treat it as exact-with-zero-rate.

`buffer-size` intentionally accepts only byte-size values with explicit
`k`/`m`/`g` suffixes. Percent buffer sizes need a compiler/runtime
representation before the schema can safely accept them (#1336); accepting
`10%` while the dataplane only receives `buffer_size_bytes` would turn a
validation improvement back into a silent zero-byte compile.

Adding a new typed subtree means:

1. populate `ValueType` + `Validator` on the relevant Node(s);
2. add a small walker entry to `schema_validate.go` (one per top-level
   subtree we want gated);
3. nothing else — no compiler changes, no parser changes.

## Callers

`pkg/cli`, `pkg/grpcapi`, `cmd/cli`.

## Dependencies

`pkg/config` only.

## Gotchas

- `DynamicFn` and `ContextDynamicFn` run inside the interactive readline
  loop — they must not block on I/O, locks held by long operations, or
  network calls. Snapshot the candidate config once; iterate.
- `ContextDynamicFn` receives the words consumed so far, so completions
  can depend on earlier args (e.g. zone-pair → policy-name suggestions).
- The `tree.go` file is large by design (it's grammar). Don't refactor it
  into many small files just to reduce LOC — the single-file form is what
  makes it greppable for "where is this command defined?".
