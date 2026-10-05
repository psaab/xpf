package config

import (
	"fmt"
	"net/netip"
	"sort"
)

type wireGuardListenerRef struct {
	name   string
	tunnel *TunnelConfig
}

func (c *Config) wireGuardListeners() []wireGuardListenerRef {
	if c == nil {
		return nil
	}
	var out []wireGuardListenerRef
	add := func(name string, tunnel *TunnelConfig) {
		if tunnel != nil && tunnel.Mode == "wireguard" && tunnel.WgListenPort != 0 {
			out = append(out, wireGuardListenerRef{name: name, tunnel: tunnel})
		}
	}
	for ifName, iface := range c.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		add(ifName, iface.Tunnel)
		for unitNum, unit := range iface.Units {
			if unit != nil {
				add(fmt.Sprintf("%s.%d", ifName, unitNum), unit.Tunnel)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (c *Config) wireGuardSourceOwners() (map[netip.Addr]string, map[netip.Addr]bool) {
	owners := make(map[netip.Addr]string)
	ambiguous := make(map[netip.Addr]bool)
	if c == nil {
		return owners, ambiguous
	}
	zones := InterfaceZoneMap(c)
	add := func(zone, value string) {
		if zone == "" {
			return
		}
		address, ok := parseWireGuardLocalAddress(value)
		if !ok {
			return
		}
		if owner, exists := owners[address]; exists && owner != zone {
			ambiguous[address] = true
			return
		}
		owners[address] = zone
	}
	for ifName, iface := range c.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		for unitNum, unit := range iface.Units {
			if unit == nil {
				continue
			}
			zone := zones[fmt.Sprintf("%s.%d", ifName, unitNum)]
			for _, address := range unit.Addresses {
				add(zone, address)
			}
			for _, group := range unit.VRRPGroups {
				if group == nil {
					continue
				}
				for _, address := range group.VirtualAddresses {
					add(zone, address)
				}
			}
		}
	}
	return owners, ambiguous
}

func parseWireGuardLocalAddress(value string) (netip.Addr, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().Unmap(), true
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

// WireGuardSourceLessInterfaces lists configured listeners with no explicit
// outer source address. Their serving zone cannot be derived for scoped
// host-inbound admission, so the compiler warns before commit.
func (c *Config) WireGuardSourceLessInterfaces() []string {
	var out []string
	for _, listener := range c.wireGuardListeners() {
		if listener.tunnel.Source == "" {
			out = append(out, listener.name)
		}
	}
	return out
}

// WireGuardInvalidSourceInterfaces lists listeners whose configured source is
// not a uniquely zone-owned local address. The listener remains fail-closed.
func (c *Config) WireGuardInvalidSourceInterfaces() []string {
	owners, ambiguous := c.wireGuardSourceOwners()
	var out []string
	for _, listener := range c.wireGuardListeners() {
		if listener.tunnel.Source == "" {
			continue
		}
		address, err := netip.ParseAddr(listener.tunnel.Source)
		if err != nil {
			out = append(out, listener.name)
			continue
		}
		address = address.Unmap()
		if _, ok := owners[address]; !ok || ambiguous[address] {
			out = append(out, listener.name)
		}
	}
	return out
}

// WireGuardListenPorts returns the sorted, de-duplicated set of non-zero
// WireGuard UDP listen ports configured across every interface-level and
// per-unit tunnel whose Mode is "wireguard" (#5582). The dataplane uses the
// selected set for listener steering; host-inbound admission is separately
// derived from each listener's configured outer source-address owner zone.
//
// A Mode=="wireguard" tunnel with WgListenPort==0 is skipped: the WireGuard
// compiler hard-rejects a zero/out-of-range listen-port at commit
// (compiler_validate_wireguard.go, #3863), so a zero here only arises on a
// partially-built or tolerant-load config, and admitting UDP/0 would be
// meaningless. Returns nil (not an empty slice) when no WG tunnel is
// configured, so callers can treat "no WG" as a cheap len()==0 test.
func (c *Config) WireGuardListenPorts() []uint16 {
	if c == nil {
		return nil
	}
	seen := map[uint16]bool{}
	add := func(tc *TunnelConfig) {
		if tc == nil || tc.Mode != "wireguard" || tc.WgListenPort == 0 {
			return
		}
		seen[tc.WgListenPort] = true
	}
	for _, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		add(ifc.Tunnel)
		for _, unit := range ifc.Units {
			if unit != nil {
				add(unit.Tunnel)
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// WireGuardUnzonedInterfaces lists listeners without a zone-owned source
// address that also have no zone on their tunnel interface (#11076). A tunnel
// interface itself may be unzoned while its explicit source belongs to a
// unique zone; that listener is still admitted on the source owner's ingress.
func (c *Config) WireGuardUnzonedInterfaces() []string {
	zones := InterfaceZoneMap(c)
	owners, ambiguous := c.wireGuardSourceOwners()
	var out []string
	for _, listener := range c.wireGuardListeners() {
		if zone := zones[listener.name]; zone != "" {
			continue
		}
		source, err := netip.ParseAddr(listener.tunnel.Source)
		if err == nil {
			source = source.Unmap()
			if _, ok := owners[source]; ok && !ambiguous[source] {
				continue
			}
		}
		out = append(out, listener.name)
	}
	return out
}
