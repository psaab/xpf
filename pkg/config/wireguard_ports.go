package config

import (
	"fmt"
	"sort"
)

// WireGuardSourceLessInterfaces lists zoned WireGuard listeners with no
// configured outer source address. Their serving zone cannot be derived for
// scoped host-inbound admission, so the compiler warns before commit.
func (c *Config) WireGuardSourceLessInterfaces() []string {
	if c == nil {
		return nil
	}
	zones := InterfaceZoneMap(c)
	seen := make(map[string]bool)
	var out []string
	add := func(ifaceKey string, tc *TunnelConfig) {
		if tc == nil || tc.Mode != "wireguard" || tc.WgListenPort == 0 || tc.Source != "" {
			return
		}
		if zone, ok := zones[ifaceKey]; !ok || zone == "" {
			return
		}
		if !seen[ifaceKey] {
			seen[ifaceKey] = true
			out = append(out, ifaceKey)
		}
	}
	for ifName, ifc := range c.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		add(ifName, ifc.Tunnel)
		for unitNum, unit := range ifc.Units {
			if unit != nil {
				add(fmt.Sprintf("%s.%d", ifName, unitNum), unit.Tunnel)
			}
		}
	}
	sort.Strings(out)
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

// WireGuardUnzonedInterfaces lists "interface-or-unit" refs carrying a
// WireGuard tunnel that bind no security zone (#11076). Sorted, deduped, nil
// when empty. The validator warns on these: without a zone the tunnel's
// listen port gets no host-inbound accept.
func (c *Config) WireGuardUnzonedInterfaces() []string {
	cfg := c
	if cfg == nil {
		return nil
	}
	zones := InterfaceZoneMap(cfg)
	seen := make(map[string]bool)
	var out []string
	add := func(ifaceKey string, tc *TunnelConfig) {
		if tc == nil || tc.Mode != "wireguard" || tc.WgListenPort == 0 {
			return
		}
		if zone, ok := zones[ifaceKey]; ok && zone != "" {
			return
		}
		if !seen[ifaceKey] {
			seen[ifaceKey] = true
			out = append(out, ifaceKey)
		}
	}
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		add(ifName, ifc.Tunnel)
		for unitNum, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			add(fmt.Sprintf("%s.%d", ifName, unitNum), unit.Tunnel)
		}
	}
	sort.Strings(out)
	return out
}
