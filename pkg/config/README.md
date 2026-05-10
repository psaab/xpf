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
- `ParseSetCommand(line) (*Node, error)` — for **one** flat-set line.
- `ConfigTree` — `ast.go`. Hierarchical node tree built by both shapes.
- `Config` — `types.go`. The fully typed result every consumer wants.
- The compiler — eleven `compiler*.go` files in `pkg/config/`
  (`compiler.go` plus per-area files: interfaces, routing, security,
  services, system, firewall, NAT, IPsec, protocols,
  class-of-service, plus `compiler.go` itself), ~7.6K LOC total.
  Phase dispatch in `compiler.go` runs zone IDs → screen profile IDs
  → zones → address book → applications → policies → NAT (incl.
  static, NAT64, NPTv6) → screen profiles → default policy → flow
  timeouts → firewall filters → flow config → port mirroring.

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
