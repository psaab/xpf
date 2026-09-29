package config

import (
	"fmt"
	"sort"
)

// WireGuardListenPorts returns the sorted, de-duplicated set of non-zero
// WireGuard UDP listen ports configured across every interface-level and
// per-unit tunnel whose Mode is "wireguard" (#5582). It is the compile-time
// SSOT for the host-inbound kernel filter's DYNAMIC WireGuard admission.
//
// The XDP shim deliberately steers local-destination UDP on the configured WG
// listen port to the kernel (userspace-xdp wg_steer_to_kernel), so the
// userspace WireGuard control socket can receive the outer transport. Without a
// matching host-inbound admission, a FRESH passive (responder-only) handshake to
// a restricted zoned address is conntrack NEW, misses the per-zone service
// accepts, and is dropped by the host-inbound catch-all — so a supported
// responder-only WireGuard listener can never come up (#5582). The daemon
// host-inbound builder consumes this set to emit exactly one coarse
// `udp dport <ports> accept` on the input hook (buildHostInboundFilterPayload),
// admitting the configured WG port(s) to every firewall-local address — the
// same local-destination scope the shim steers — while leaving every other
// host-bound service under the per-zone default-deny.
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

// WireGuardZonePorts maps each security zone to the sorted WireGuard UDP
// listen ports of the tunnels bound to that zone's interfaces (#11076). It is
// the compile-time SSOT for SCOPED host-inbound WG admission: each zone's
// ports render as a `daddr <zone-addrs> udp dport <ports> accept` inside that
// zone's host-inbound section — ordered with zone policy, never above it —
// instead of the former global bare accept.
//
// Zone resolution reuses InterfaceZoneMap (same fan-up/fan-down +
// quarantine rules the host-inbound views enforce). A tunnel whose interface
// binds no zone contributes nothing: its handshake cannot arrive (fail
// closed), and the compile tailgate warns. Ports within a zone are
// sorted+deduped; zones with no WG tunnels are absent (not empty). Returns
// nil when no zoned WG tunnel exists.
func (c *Config) WireGuardZonePorts() map[string][]uint16 {
	cfg := c
	if cfg == nil {
		return nil
	}
	zones := InterfaceZoneMap(cfg)
	byZone := make(map[string]map[uint16]bool)
	add := func(ifaceKey string, tc *TunnelConfig) {
		if tc == nil || tc.Mode != "wireguard" || tc.WgListenPort == 0 {
			return
		}
		zone, ok := zones[ifaceKey]
		if !ok || zone == "" {
			return
		}
		if byZone[zone] == nil {
			byZone[zone] = make(map[uint16]bool)
		}
		byZone[zone][tc.WgListenPort] = true
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
	if len(byZone) == 0 {
		return nil
	}
	out := make(map[string][]uint16, len(byZone))
	for zone, ports := range byZone {
		list := make([]uint16, 0, len(ports))
		for p := range ports {
			list = append(list, p)
		}
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
		out[zone] = list
	}
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
