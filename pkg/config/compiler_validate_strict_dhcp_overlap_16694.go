package config

import (
	"fmt"
	"sort"
	"strings"
)

// dhcpFamilyOverlap16694 pairs one DHCP-server family with the relay
// family that shares its UDP port: v4 server (Kea Dhcp4, port 67) with
// the v4 relay, v6 server (Kea Dhcp6, port 547) with the v6 relay.
type dhcpFamilyOverlap16694 struct {
	serverLabel string // "dhcp-local-server" / "dhcpv6-local-server"
	relayLabel  string // "dhcp-relay" / "dhcp-relay dhcpv6"
	server      *DHCPLocalServerConfig
	relayV4     map[string]*DHCPRelayGroup
	relayV6     map[string]*DHCPRelayV6Group
}

// dhcpOverlapHit16694 is one resolved kernel device claimed by both a
// server group and a relay group of the same family.
type dhcpOverlapHit16694 struct {
	device      string
	serverLabel string
	serverGroup string
	serverRef   string
	relayLabel  string
	relayGroup  string
	relayRef    string
}

func (h dhcpOverlapHit16694) message(issue string) string {
	return fmt.Sprintf("system services %s group %q interface %q and forwarding-options %s group %q interface %q both resolve to kernel device %q: "+
		"the DHCP server and the DHCP relay both bind the same UDP port on that device, so whichever starts second fails to bind and the segment is served by only one of the two configured services while both report healthy; "+
		"name the interface on only one of the two services (%s)",
		h.serverLabel, h.serverGroup, h.serverRef, h.relayLabel, h.relayGroup, h.relayRef, h.device, issue)
}

// validateDHCPServerRelayOverlapStrict refuses, at commit /
// commit-check, a resolved kernel device appearing in both a
// dhcp-local-server group and a dhcp-relay group of the same family
// (v6: dhcpv6-local-server vs dhcp-relay dhcpv6) (#16694).
//
// Kea binds <iface-addr>:67 (raw fallback / udp service socket) and
// the relay binds 0.0.0.0:67 with SO_BINDTODEVICE per interface, so
// whichever service binds second gets EADDRINUSE: Kea keeps running
// with no sockets (and still passes the unit-active check) or the
// relay session fails, while commit and status both read healthy and
// the segment's DHCP behaviour depends on start order.
//
// Resolution mirrors the daemon: both sides resolve every authored
// ref through cfg.resolveKernelIfNameWith (one hoisted tunnel map,
// #8862) — the same resolver Kea's interface list (#9407) and the
// relay's bind (#9406) use — and the comparison keys a trailing ".0"
// onto the bare device (dhcpResolvedDevice15028), so a reth ref and
// its member ref, a unit-0 ref and its bare parent, and both spellings
// of one name all collide exactly as they do at bind time. Wildcard
// refs (ge-*, #6696) are not resolved by that resolver; they are
// expanded over the declared interfaces so a wildcard server group
// still collides with a concrete relay ref it covers (and vice
// versa). With no interfaces stanza the declared set is empty, so
// wildcard refs match nothing and only refs that resolve identically
// without any declaration (exact same spelling, reth pair) collide —
// the gate does not invent a declared set to judge against.
//
// On the tolerant load / peer-sync paths the compileExpanded call
// site downgrades this to a warning (opts.lenientDHCPServerRelayOverlap)
// so an already-persisted or peer-synced config still boots (#1960).
func validateDHCPServerRelayOverlapStrict(cfg *Config) error {
	hit, ok := dhcpServerRelayOverlap16694(cfg)
	if !ok {
		return nil
	}
	return fmt.Errorf("%s", hit.message("#16694"))
}

// dhcpServerRelayOverlapWarnings is the ValidateConfig twin of the
// #16694 strict gate for the recompute-from-active alarm surfaces
// (#4788 doctrine): a box already carrying the overlap — committed
// by an older build, loaded leniently per #1960 — still hears about
// it. It walks the same shared enumeration, so the two surfaces can
// never disagree about which overlaps exist.
func dhcpServerRelayOverlapWarnings(cfg *Config) []string {
	hits := dhcpServerRelayOverlaps16694(cfg)
	if len(hits) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(hits))
	for _, hit := range hits {
		warnings = append(warnings, hit.message("#16694"))
	}
	return warnings
}

func dhcpServerRelayOverlap16694(cfg *Config) (dhcpOverlapHit16694, bool) {
	hits := dhcpServerRelayOverlaps16694(cfg)
	if len(hits) == 0 {
		return dhcpOverlapHit16694{}, false
	}
	return hits[0], true
}

func dhcpServerRelayOverlaps16694(cfg *Config) []dhcpOverlapHit16694 {
	if cfg == nil {
		return nil
	}
	relay := cfg.ForwardingOptions.DHCPRelay
	var relayV4 map[string]*DHCPRelayGroup
	var relayV6 map[string]*DHCPRelayV6Group
	if relay != nil {
		relayV4 = relay.Groups
		if relay.V6 != nil {
			relayV6 = relay.V6.Groups
		}
	}
	families := []dhcpFamilyOverlap16694{
		{serverLabel: "dhcp-local-server", relayLabel: "dhcp-relay", server: cfg.System.DHCPServer.DHCPLocalServer, relayV4: relayV4},
		{serverLabel: "dhcpv6-local-server", relayLabel: "dhcp-relay dhcpv6", server: cfg.System.DHCPServer.DHCPv6LocalServer, relayV6: relayV6},
	}
	tunMap := tunnelNameMapFn(cfg)
	var hits []dhcpOverlapHit16694
	for _, fam := range families {
		hits = append(hits, dhcpFamilyOverlaps16694(cfg, tunMap, fam)...)
	}
	return hits
}

type dhcpRef16694 struct {
	group string
	ref   string
}

func dhcpFamilyOverlaps16694(cfg *Config, tunMap map[string]string, fam dhcpFamilyOverlap16694) []dhcpOverlapHit16694 {
	if fam.server == nil || len(fam.server.Groups) == 0 {
		return nil
	}
	// Relay side: device -> first relay ref (deterministic order).
	relayByDevice := make(map[string]dhcpRef16694)
	addRelay := func(group, ref string) {
		if ref == "" {
			return
		}
		for _, dev := range dhcpRefDevices16694(cfg, tunMap, ref) {
			if _, ok := relayByDevice[dev]; !ok {
				relayByDevice[dev] = dhcpRef16694{group: group, ref: ref}
			}
		}
	}
	if fam.relayV4 != nil {
		names := make([]string, 0, len(fam.relayV4))
		for name := range fam.relayV4 {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			g := fam.relayV4[name]
			if g == nil {
				continue
			}
			for _, ref := range g.Interfaces {
				addRelay(name, ref)
			}
		}
	}
	if fam.relayV6 != nil {
		names := make([]string, 0, len(fam.relayV6))
		for name := range fam.relayV6 {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			g := fam.relayV6[name]
			if g == nil {
				continue
			}
			for _, ref := range g.Interfaces {
				addRelay(name, ref)
			}
		}
	}
	if len(relayByDevice) == 0 {
		return nil
	}
	// Server side in deterministic (group, authored) order; first hit
	// per device wins so the reported pair is stable.
	serverNames := make([]string, 0, len(fam.server.Groups))
	for name := range fam.server.Groups {
		serverNames = append(serverNames, name)
	}
	sort.Strings(serverNames)
	reported := make(map[string]bool)
	var hits []dhcpOverlapHit16694
	for _, name := range serverNames {
		g := fam.server.Groups[name]
		if g == nil {
			continue
		}
		for _, ref := range g.Interfaces {
			if ref == "" {
				continue
			}
			for _, dev := range dhcpRefDevices16694(cfg, tunMap, ref) {
				r, ok := relayByDevice[dev]
				if !ok || reported[dev] {
					continue
				}
				reported[dev] = true
				hits = append(hits, dhcpOverlapHit16694{
					device:      dev,
					serverLabel: fam.serverLabel,
					serverGroup: name,
					serverRef:   ref,
					relayLabel:  fam.relayLabel,
					relayGroup:  r.group,
					relayRef:    r.ref,
				})
			}
		}
	}
	return hits
}

// dhcpRefDevices16694 resolves one authored DHCP group interface ref
// to the kernel device(s) it denotes at bind time. Concrete refs
// resolve through the canonical resolver with the ".0" keying of
// #15028. A wildcard ref (ge-*, #6696) matches every declared
// interface name (and its unit-0 / Linux spellings) and resolves to
// each matching device; with no declared interfaces it matches
// nothing, so the gate stays silent rather than inventing devices.
func dhcpRefDevices16694(cfg *Config, tunMap map[string]string, ref string) []string {
	if !strings.Contains(ref, "*") {
		return []string{dhcpResolvedDevice15028(cfg.resolveKernelIfNameWith(ref, tunMap))}
	}
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var devices []string
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	add := func(candidate string) {
		if !globMatch(ref, candidate) {
			return
		}
		dev := dhcpResolvedDevice15028(cfg.resolveKernelIfNameWith(candidate, tunMap))
		if !seen[dev] {
			seen[dev] = true
			devices = append(devices, dev)
		}
	}
	for _, name := range names {
		add(name)
		add(name + ".0")
		if linux := LinuxIfName(name); linux != name {
			add(linux)
			add(linux + ".0")
		}
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			continue
		}
		units := make([]int, 0, len(ifc.Units))
		for num := range ifc.Units {
			units = append(units, num)
		}
		sort.Ints(units)
		for _, num := range units {
			add(fmt.Sprintf("%s.%d", name, num))
		}
	}
	return devices
}
