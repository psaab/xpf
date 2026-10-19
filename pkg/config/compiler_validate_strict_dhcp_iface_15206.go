package config

import (
	"fmt"
	"sort"
	"strings"
)

// dhcpServerIfaceRef15206 is one authored DHCP-server group interface
// reference, with the family and group that name it.
type dhcpServerIfaceRef15206 struct {
	family string // "dhcp-local-server" / "dhcpv6-local-server"
	group  string
	ref    string
}

// dhcpServerGroupIfaceRefs15206 enumerates every non-empty interface ref
// of both DHCP-server families in deterministic (family, group, authored)
// order. Shared by the strict gate below and the #9407 ValidateConfig
// advisory so the two surfaces can never disagree about which refs exist.
func dhcpServerGroupIfaceRefs15206(cfg *Config) []dhcpServerIfaceRef15206 {
	if cfg == nil {
		return nil
	}
	families := []struct {
		label string
		local *DHCPLocalServerConfig
	}{
		{"dhcp-local-server", cfg.System.DHCPServer.DHCPLocalServer},
		{"dhcpv6-local-server", cfg.System.DHCPServer.DHCPv6LocalServer},
	}
	var out []dhcpServerIfaceRef15206
	for _, fam := range families {
		if fam.local == nil || len(fam.local.Groups) == 0 {
			continue
		}
		names := make([]string, 0, len(fam.local.Groups))
		for name := range fam.local.Groups {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			g := fam.local.Groups[name]
			if g == nil {
				continue
			}
			for _, ref := range g.Interfaces {
				if ref == "" {
					continue
				}
				out = append(out, dhcpServerIfaceRef15206{family: fam.label, group: name, ref: ref})
			}
		}
	}
	return out
}

// validateDHCPServerInterfaceRefStrict hard-rejects, at commit /
// commit-check, a DHCP-server group interface ref that names no configured
// interface or unit (#15206, A17-03 — the #9407 residual).
//
// #9407 taught the daemon to resolve the ref through
// Config.ResolveKernelIfName, and left an advisory for the one case that
// resolver cannot resolve: its honest fallback returns the ref verbatim,
// so an undeclared unit renders into Kea's interfaces-config as a device
// name the kernel does not have (`reth1.7` -> `reth1.7`, `ge-0/0/9.0` ->
// `ge-0-0-9.0`). The advisory said "the segment gets no leases". That
// understates the blast radius: Kea validates the rendered file as one
// unit, a nonexistent interface in interfaces-config makes it refuse to
// load the file, and every pool of the family stops serving — the same
// whole-family outage #9785 / #14601 / #15028 gate against through other
// leaves. The strict path therefore refuses the ref at Store.Commit.
//
// Declared-ness is judged by the shared unresolvedInterfaceRef against
// the declared-interface index (config spelling and Linux dash spelling,
// #8829), exactly as the #9407 advisory and the #15048 VRRP track-ref
// gate judge it, so a declared bare interface, a declared unit (including
// a VLAN unit), a reth, a dash-spelled name, and a legitimately dotted
// DECLARED interface name (#8994) all stay legal. Scope parity with
// the #9407 advisory and the #15048 gate: with no interfaces stanza
// there is no declared set to judge against (a degenerate config for
// every subsystem, guarded elsewhere), so the gate is silent there.
// The check is purely structural, independent of node-local reth
// member resolution.
//
// On the tolerant load / peer-sync paths the compileExpanded call site
// downgrades this to a warning (opts.lenientDHCPServerIfaceRef) so an
// already-persisted or peer-synced config an older binary accepted still
// boots (#1960 no-brick). Such a config is arbitrated at the daemon
// by the render belt (FilterKeaInterfaces15206), which drops the
// phantom so the healthy pools of the family keep serving; the
// #9407 ValidateConfig advisory carries the same whole-family
// wording on the alarm surfaces that recompute from the active config.
func validateDHCPServerInterfaceRefStrict(cfg *Config) error {
	// Scope parity with the #9407 advisory and the #15048 gate: with no
	// interfaces stanza there is no declared set to judge against, and
	// the config is degenerate for every subsystem, not just DHCP.
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	refs := dhcpServerGroupIfaceRefs15206(cfg)
	if len(refs) == 0 {
		return nil
	}
	declared := declaredInterfaceIndex(cfg)
	// One tunnel-name map for the whole walk (#8862): building it per ref
	// is quadratic. It is used only to NAME the device Kea will be given
	// in the refusal; the declared-ness verdict above it is structural.
	tunMap := tunnelNameMapFn(cfg)
	lifelines := HostInboundLifelineSet(cfg)
	for _, r := range refs {
		// Explicit non-declared classes the runtime still serves: wildcard
		// selectors (#6696: `ge-*` is a schema-validated element) and
		// lifelines (fxp0 & friends exist outside the interfaces stanza).
		if strings.HasSuffix(r.ref, "*") || HostInboundLifelineInterface(r.ref, lifelines) {
			continue
		}
		reason := unresolvedInterfaceRef(declared, r.ref)
		if reason == "" {
			continue
		}
		device := cfg.resolveKernelIfNameWith(r.ref, tunMap)
		return fmt.Errorf("system services %s group %q interface %q %s — Kea will be given "+
			"device name %q, which is not a configured device; Kea refuses to load the "+
			"rendered file, so every pool of the %s family stops serving, not just this "+
			"segment; name a configured interface or unit (#15206)",
			r.family, r.group, r.ref, reason, device, r.family)
	}
	return nil
}
