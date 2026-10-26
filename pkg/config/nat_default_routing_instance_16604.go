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
// The literal is declaration-sensitive: without a routing-instance named
// `default`, it is an explicit master constraint, not an absent scope. The
// typed config therefore carries "" plus a per-side provenance flag (see
// NATRuleSet / StaticNATRuleSet / NAT64RuleSet `*RoutingInstanceDefault`
// fields). Snapshot builders stamp the wire token
// NATDefaultRoutingInstanceWire, and Rust matches it against the packet's
// empty routing-instance only.
//
// If a routing-instance named `default` IS declared, the authored literal
// keeps its meaning as that named instance: NAT scope matching by name
// predates the alias and operators may already rely on it. This follows the
// FBF #11308 posture — there, strict rejects the ambiguous combination
// outright; NAT keeps the declaration winning.

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

// lowerNATDefaultRoutingInstanceAliases16604 runs after every top-level
// section has compiled, when cfg can distinguish the master alias from an
// instance actually named `default`. Only an undeclared literal is lowered;
// declared-name scopes remain literal for the snapshot builders and matcher.
func lowerNATDefaultRoutingInstanceAliases16604(cfg *Config) {
	if cfg == nil || !natRoutingInstanceIsDefaultAlias16604(cfg, FBFDefaultRoutingInstance) {
		return
	}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		if value, isDefault := lowerNATRoutingInstanceScope16604(rs.FromRoutingInstance); isDefault {
			rs.FromRoutingInstance, rs.FromRoutingInstanceDefault = value, true
		}
		if value, isDefault := lowerNATRoutingInstanceScope16604(rs.ToRoutingInstance); isDefault {
			rs.ToRoutingInstance, rs.ToRoutingInstanceDefault = value, true
		}
	}
	if dnat := cfg.Security.NAT.Destination; dnat != nil {
		for _, rs := range dnat.RuleSets {
			if rs == nil {
				continue
			}
			if value, isDefault := lowerNATRoutingInstanceScope16604(rs.FromRoutingInstance); isDefault {
				rs.FromRoutingInstance, rs.FromRoutingInstanceDefault = value, true
			}
			if value, isDefault := lowerNATRoutingInstanceScope16604(rs.ToRoutingInstance); isDefault {
				rs.ToRoutingInstance, rs.ToRoutingInstanceDefault = value, true
			}
		}
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		if value, isDefault := lowerNATRoutingInstanceScope16604(rs.FromRoutingInstance); isDefault {
			rs.FromRoutingInstance, rs.FromRoutingInstanceDefault = value, true
		}
	}
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil {
			continue
		}
		if value, isDefault := lowerNATRoutingInstanceScope16604(rs.FromRoutingInstance); isDefault {
			rs.FromRoutingInstance, rs.FromRoutingInstanceDefault = value, true
		}
		for i, ri := range rs.FromRoutingInstances {
			if value, isDefault := lowerNATRoutingInstanceScope16604(ri); isDefault {
				rs.FromRoutingInstances[i], rs.FromRoutingInstanceDefault = value, true
			}
		}
	}
}
