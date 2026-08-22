package config

import "strings"

// lifeline.go is the SSOT for host-inbound LIFELINE interface matching (#3682).
// Before #3682 the matcher lived privately in pkg/dataplane/userspace/zones.go
// and drove the host-inbound deny-scoping decision, but no operator-visible zone
// view could re-derive it, so a zone-assigned lifeline interface silently
// dropped out of the host-inbound default-deny with nothing to render the
// exemption. Hoisting the matcher here lets the shared host-inbound presenter
// (host_inbound_view.go) surface the exemption on every text zone view while the
// dataplane path keeps using the identical logic (userspace/zones.go now
// delegates here) — one source of truth for both enforcement and display.

// LifelineBaseName strips the unit suffix (".0") and surrounding whitespace from
// a logical interface name, returning the bare device name used for lifeline
// matching ("fxp0.0" -> "fxp0", "fab1.0" -> "fab1"). Returns "" for an empty
// name.
func LifelineBaseName(name string) string {
	base := strings.TrimSpace(name)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base
}

// HostInboundLifelineSet resolves the set of management / cluster-control
// LIFELINE interface base names that must NEVER be subjected to a host-inbound
// deny. It is the config-aware superset of the always-on defaults:
//
//   - fxp0 (out-of-band management) is always a lifeline.
//   - The chassis-cluster control-interface and fabric interface(s) are added
//     from config so an operator-renamed control link (e.g.
//     `control-interface fxp1`) or a non-default fabric name is excluded too.
//     This is the #3277 fix: the old matcher hardcoded fxp0/em0/fab* and so left
//     a configured `control-interface fxp1` SUBJECT to host-inbound deny scoping
//     -> potential heartbeat drop -> HA split-brain.
//
// em0 (the canonical cluster-control default name) and the fabric prefix fab*
// stay matched unconditionally in HostInboundLifelineInterface so the canonical
// default-named configs remain byte-identical (#3070/#3172/#3224 behavior is
// preserved). A standalone config (no chassis-cluster stanza) contributes no
// extra names here, so its only lifeline is fxp0 (em0/fab* are no-ops because
// such interfaces are not present) — #1960.
func HostInboundLifelineSet(cfg *Config) map[string]bool {
	set := map[string]bool{"fxp0": true}
	if cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		for _, name := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
			if base := LifelineBaseName(name); base != "" {
				set[base] = true
			}
		}
	}
	return set
}

// HostInboundLifelineInterface reports whether the given logical interface name
// is a management / cluster-control LIFELINE that must NEVER be subjected to a
// host-inbound deny. The lifeline set is the config-derived set (fxp0 plus the
// configured chassis-cluster control-interface / fabric interfaces, #3277) UNION
// the always-on backward-compatible defaults em0 (cluster control plane /
// heartbeat default name) and the fabric links (fab*). Denying host-bound
// traffic on these would strand management or break HA. The base name (before
// the unit suffix) is matched so "fxp0.0" / "em0.0" are caught too.
//
// #5250 (A3-b2 F3): the unconditional fabric fallback is an EXACT canonical-name
// match ("fab" + one or more digits), not the old `strings.HasPrefix(base,
// "fab")` bypass. The daemon only ever creates fab0/fab1
// (daemon_apply_interfaces.go, daemon_ha_fabric.go) and any operator-renamed
// fabric link is already contributed by HostInboundLifelineSet from the
// chassis-cluster stanza, so the prefix form bought nothing while silently
// exempting an unrelated interface literally named "fab-foo"/"fabric-uplink"
// from host-inbound default-deny — reachable in device-map mode (#1956), where
// a mapped NIC may be renamed to an operator-chosen name. Narrowing the
// fallback cannot strand a real fabric or control link: those names come from
// config, not from this prefix.
func HostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
	base := LifelineBaseName(name)
	if base == "" {
		return false
	}
	if lifelines[base] {
		return true
	}
	return base == "em0" || isCanonicalFabricName(base)
}

// isCanonicalFabricName reports whether base is one of the daemon-created
// fabric device names — the literal "fab" followed by at least one digit and
// nothing else ("fab0", "fab1", "fab10"). "fab", "fab-foo", "fabx0" and
// "fabric0" are NOT canonical: a configured fabric interface with such a name
// reaches the lifeline set through HostInboundLifelineSet instead.
func isCanonicalFabricName(base string) bool {
	rest, ok := strings.CutPrefix(base, "fab")
	if !ok || rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	return true
}
