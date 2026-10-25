package config

// #16604: Juniper's `default` routing-instance literal in a NAT
// `from`/`to routing-instance` scope names the master (global) instance.
// The dataplane represents that instance by the empty string — an
// interface in no named instance resolves to "" (Rust
// `ifindex_to_routing_instance` unwrap_or(""); Go interface snapshots
// carry ""), and every NAT scope matcher treats an empty rule field as
// the master/unscoped value on that axis.
//
// Before #16604 the #15278 gate blessed the literal as "defined" but
// nothing lowered it, so the string "default" reached the snapshots
// verbatim and never equalled the packet's "" — every SNAT/DNAT/
// static/NAT64 rule-set scoped `routing-instance default` committed
// clean and matched nothing, and the Go/Rust interface-NAT
// registration keyed by the same literal never selected a
// main-instance egress.
//
// The lowering is an EXPLICIT master constraint, not a synonym for an
// absent scope: authoring `routing-instance default` must match
// main-instance traffic only, never a named VRF. The typed config
// therefore carries "" plus a per-side provenance flag (see
// NATRuleSet / StaticNATRuleSet / NAT64RuleSet `*RoutingInstanceDefault`
// fields). Snapshot builders stamp the wire token
// NATDefaultRoutingInstanceWire, and the Rust matchers compare it
// against the packet's "" — so `rule=default egress=main` matches and
// `rule=default egress=VR1` does not, while an unscoped (empty) rule
// still matches both. A routing-instance actually NAMED `default`
// under `routing-instances` keeps selecting that named instance: the
// literal is only the master alias when no such instance is declared
// (the FBF #11308 posture — there, strict rejects the ambiguous
// combination outright; NAT keeps the declaration winning because
// NAT scope matching by name predates the alias and operators may
// already rely on it; see natRoutingInstanceIsDefaultAlias16604).

// NATDefaultRoutingInstanceWire is the snapshot/wire token for an
// explicit `routing-instance default` (master-instance) NAT scope.
// It is deliberately distinct from both "" (unscoped) and any legal
// instance name an operator could mean as a VRF, and it never appears
// in authored config — only on the wire between the Go snapshot
// builders and the Rust dataplane (and in Rust-constructed test
// snapshots). Old helpers ignore nothing here: a pre-#16604 helper
// receiving the token treats the rule as scoped to a nonexistent
// instance and never matches it (fail-closed), while the new helper
// matches it against main-instance traffic only.
const NATDefaultRoutingInstanceWire = "\x00xpf-default-routing-instance"

// IsNATDefaultRoutingInstanceWire reports whether s is the explicit
// master-instance wire token above.
func IsNATDefaultRoutingInstanceWire(s string) bool {
	return s == NATDefaultRoutingInstanceWire
}

// natRoutingInstanceIsDefaultAlias16604 reports whether the authored
// NAT scope value `name` is the master-instance alias: the literal
// `default` with NO routing-instance of that name declared. When an
// instance named `default` IS declared, the value keeps its literal
// meaning (that named instance) — matching by name, exactly as the
// dataplane resolves an interface belonging to it.
func natRoutingInstanceIsDefaultAlias16604(cfg *Config, name string) bool {
	if name != FBFDefaultRoutingInstance {
		return false
	}
	if cfg == nil {
		return true
	}
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name == name {
			return false
		}
	}
	return true
}

// NormalizeNATRoutingInstanceScope16604 lowers one authored NAT
// routing-instance scope value for snapshot emission: the master alias
// becomes the wire token, every other value (including "" and a
// declared instance named `default`) passes through unchanged. cfg may
// be nil (hand-built configs in tests); a nil cfg declares no instance,
// so the literal is the alias.
func NormalizeNATRoutingInstanceScope16604(cfg *Config, name string) string {
	if name == "" {
		return ""
	}
	if natRoutingInstanceIsDefaultAlias16604(cfg, name) {
		return NATDefaultRoutingInstanceWire
	}
	return name
}

// NATRoutingInstanceScopeWire is the snapshot value for a typed NAT
// routing-instance scope field plus its explicit-master provenance
// flag. Builders must use it (never the raw field) so the alias
// lowering lives in exactly one place.
func NATRoutingInstanceScopeWire(cfg *Config, value string, explicitDefault bool) string {
	if explicitDefault {
		return NATDefaultRoutingInstanceWire
	}
	return NormalizeNATRoutingInstanceScope16604(cfg, value)
}
