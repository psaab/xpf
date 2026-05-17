# pkg/config

Junos configuration parser, AST, typed data model, and compilation
pipeline. Three phases: text → AST (`ConfigTree`) → typed `Config` struct.
Handles both hierarchical (`family inet { dhcp; }`) and flat set
(`set interfaces eth0 unit 0 family inet dhcp`) syntaxes.

This is the foundation almost every other package imports. It depends on
nothing internal.

## Entry points

- `Lexer` — `lexer.go`.
- `Parser` — `parser.go`. **Hierarchical** input.
- `ParseSetCommand(input string) ([]string, error)` — `parser.go`.
  Parses one flat-set line into the path components. The caller then
  applies that path with `tree.SetPath()` to build the AST.
- `ConfigTree` — `ast.go`. Hierarchical node tree built by both shapes.
- `Config` — `types.go`. The fully typed result every consumer wants.
- `CompileConfig(tree) (*Config, error)` — `compiler.go`. AST-to-typed-
  struct walker. Clones the tree, expands `apply-groups` (with
  `${node}` fallback for cluster mode), then dispatches over AST
  nodes via a switch statement to fill the typed `Config`. Eleven
  `compiler*.go` files in this package, ~7.6K LOC total
  (`compiler.go` + `compiler_interfaces.go`, `compiler_routing.go`,
  `compiler_security.go`, `compiler_services.go`, `compiler_system.go`,
  `compiler_firewall.go`, `compiler_nat.go`, `compiler_ipsec.go`,
  `compiler_protocols.go`, `compiler_class_of_service.go`).
  Note: this is the **AST → typed Go struct** stage; the BPF-map
  compilation (zones, policies, NAT IDs, etc.) happens later in
  `pkg/dataplane.Manager.Compile`.
- `Validate*` functions — `schema_validators.go`. Stateless string
  validators (`ValidateRate`, `ValidateByteSize`,
  `ValidateByteSizeOrPercent`,
  `ValidateInteger(min,max)`, `ValidateEnum(allowed)`,
  `ValidatePercent(min,max)`) for the #1319 typed-leaf gate. Attached
  to `cmdtree.Node.Validator` fields and dispatched by
  `cmdtree.SchemaValidate` at commit-check time, on the same
  apply-groups-expanded tree the compiler consumes, so garbage like
  `transmit-rate asd` fails loud instead of silently zeroing in the
  existing parsers. Scheduler `buffer-size` validation accepts byte
  sizes with explicit suffixes and percent values with an explicit `%`
  suffix. The compiler stores percent values separately from
  `BufferSizeBytes`; the userspace snapshot adds `buffer_size_percent`
  while preserving the legacy `buffer_size_bytes` field. The Rust
  userspace dataplane resolves percent buffers against the interface CoS
  burst pool when a scheduler is bound to an interface queue.
  `parseBandwidthLimitStrict` / `parseBurstSizeLimitStrict` /
  `parseScaledDecimalUnitStrict` in `compiler_protocols.go` are the
  error-returning siblings of the legacy zero-return parsers — the legacy
  versions keep their "unset = 0" contract for compatibility.

## Callers

Almost everyone. The package has no internal dependencies.

## Gotchas

The compiler must accept both AST shapes:

- Hierarchical `family inet { dhcp; }` lowers to `Node{Keys:["family","inet"]}`
  with a child `Node{Keys:["dhcp"]}`.
- Flat `set interfaces eth0 unit 0 family inet dhcp` lowers to
  `Node{Keys:["family"]}` with child `Node{Keys:["inet"]}`.

If you only handle one shape, set-syntax tests will look fine but real
hierarchical commits will break (or vice versa).

**Testing flat-set syntax:** ALWAYS use `ParseSetCommand()` + a
`tree.SetPath()` loop, NEVER `NewParser()` on a multi-line set blob. The
parser treats newlines as whitespace and merges multiple set lines into
one giant node. This trap has bitten the project repeatedly — see
CLAUDE.md.

**C struct alignment:** when mirroring C BPF structs in Go, match `sizeof`
exactly with trailing `Pad [N]byte` fields. cilium/ebpf serializes map
values in native endian, not big-endian, so use `binary.NativeEndian`
when packing IP addresses (already in network byte order on the wire).
