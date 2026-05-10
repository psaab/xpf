# pkg/cmdtree

Single source of truth for every CLI command tree (operational +
configuration). Used by the local CLI, the remote CLI, and the gRPC
tab-completion RPC. Adding a command here automatically propagates to all
three frontends.

## Entry points

- `Node` — `tree.go:23`. Tree node: description, static children,
  `DynamicFn`/`ContextDynamicFn` for config-aware completions.
- `Candidate` — `tree.go:49`. `(name, desc)` pair surfaced during tab
  completion.
- `OperationalTree` — `tree.go:56`. Canonical root for `show`, `clear`,
  `request`, `monitor`, `ping`, `traceroute`, etc.
- `ConfigTopLevel` — root for the `set`/`delete` configuration grammar.
- `KeysFromTree(tree)` — `tree.go:927`. Used by `pkg/cli` and `pkg/grpcapi`
  for Junos-style prefix matching.
- `WriteHelp`, `LookupDesc`, `PrintTreeHelp`, `CompleteFromTree` — the
  helper API the three frontends consume.

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
