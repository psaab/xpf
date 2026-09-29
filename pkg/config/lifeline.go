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
// deny:
//
//   - fxp0 (out-of-band management) is always a lifeline.
//   - Chassis-cluster control and fabric interfaces are included only when
//     configured, including operator-renamed links. Fabric-options
//     member-interfaces also explicitly identify a cluster fabric interface.
//
// Bare interface names such as em0/fab0 are not proof of a management or
// cluster role and are not implicit lifelines (#11068). A standalone config
// therefore contributes only fxp0.
func HostInboundLifelineSet(cfg *Config) map[string]bool {
	set := map[string]bool{"fxp0": true}
	if cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		for _, name := range []string{cc.ControlInterface, cc.FabricInterface, cc.Fabric1Interface} {
			if base := LifelineBaseName(name); base != "" {
				set[base] = true
			}
		}
		// fabric-options member-interfaces is also explicit role configuration.
		// Include both local and peer-side fabric interfaces: both are configured
		// cluster fabric links even though only one is local on a given node.
		for name, ifc := range cfg.Interfaces.Interfaces {
			if ifc != nil && len(ifc.FabricMembers) > 0 {
				if base := LifelineBaseName(name); base != "" {
					set[base] = true
				}
			}
		}
	}
	return set
}

// HostInboundLifelineInterface reports whether the given logical interface name
// is an explicitly identified management / cluster-control LIFELINE that must
// NEVER be subjected to a host-inbound deny. The set is fxp0 plus configured
// chassis-cluster control/fabric links, including interfaces with explicit
// fabric-options member-interfaces; interface names alone do not imply a role
// (#11068). The base name (before the unit suffix) is matched so "fxp0.0" and
// configured links such as "hb0.0" are caught too.
func HostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
	base := LifelineBaseName(name)
	return base != "" && lifelines[base]
}
