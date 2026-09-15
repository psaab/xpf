package userspace

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

func buildTunnelEndpointSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []TunnelEndpointSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	ifaceByName := make(map[string]InterfaceSnapshot, len(interfaces))
	rgByAddress := make(map[string]int)
	for _, iface := range interfaces {
		if iface.Name == "" || iface.Ifindex <= 0 {
			continue
		}
		ifaceByName[iface.Name] = iface
		if iface.RedundancyGroup <= 0 {
			continue
		}
		for _, addr := range iface.Addresses {
			ip, _, err := net.ParseCIDR(addr.Address)
			if err != nil || ip == nil {
				continue
			}
			rgByAddress[ip.String()] = iface.RedundancyGroup
		}
	}
	if len(ifaceByName) == 0 {
		return nil
	}
	out := make([]TunnelEndpointSnapshot, 0)
	// #1873: ids are content-derived (config.StableTunnelEndpointID of
	// the unit-qualified interface name), NOT positional — adding or
	// removing one tunnel can never renumber another, and both HA
	// nodes compute identical ids from identical config. usedIDs is
	// the fail-closed belt-and-braces behind the commit-time collision
	// gate (validateTunnelEndpointIDCollisionAST): a snapshot must
	// never carry two rows with one id, so the later-sorting collider
	// is dropped loudly. Iteration is sorted (names + unit numbers),
	// so the drop is deterministic.
	usedIDs := make(map[uint16]string)
	addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
		if tunnel == nil {
			return
		}
		// WireGuard endpoints carry the peer in WgEndpoint and need no
		// Source/Destination (#1432 S2a); a WG endpoint configured with
		// only WgEndpoint must not be dropped by the GRE source/dest gate.
		// The non-WG source/dest gate and the interface-level-WG
		// single-lowest-unit pick now live in the SSOT emitter
		// (config.EmitTunnelEndpointNames), so addEndpoint trusts the
		// emitter's filtering; the redundant guard is retained as a
		// defense-in-depth no-op against future call paths.
		isWireguard := tunnel.Mode == "wireguard"
		if !isWireguard && (tunnel.Source == "" || tunnel.Destination == "") {
			return
		}
		iface, ok := ifaceByName[ifName]
		if !ok {
			return
		}
		outerFamily := "inet"
		transportTable := "inet.0"
		if dst := net.ParseIP(tunnel.Destination); dst != nil && dst.To4() == nil {
			outerFamily = "inet6"
			transportTable = "inet6.0"
		} else if src := net.ParseIP(tunnel.Source); src != nil && src.To4() == nil {
			outerFamily = "inet6"
			transportTable = "inet6.0"
		}
		if tunnel.RoutingInstance != "" {
			if outerFamily == "inet6" {
				transportTable = tunnel.RoutingInstance + ".inet6.0"
			} else {
				transportTable = tunnel.RoutingInstance + ".inet.0"
			}
		}
		// #2703: an omitted tunnel TTL is stored as the default-64 sentinel 0
		// (pkg/config/types_routing.go); authored values require 1..255 (#9899).
		// The kernel-tunnel path applies that default
		// (pkg/routing/tunnel.go: `if ttl == 0 { ttl = 64 }`); the AF_XDP
		// transit path must mirror it BEFORE the value reaches the snapshot,
		// else the Rust frame builders write outer TTL/hop-limit 0 and every
		// default-config GRE/IPIP/WG outer packet is dropped at the first hop
		// (a deterministic blackhole that looks like underlay loss). An
		// explicitly-configured non-zero TTL is preserved unchanged.
		ttl := tunnel.TTL
		if ttl == 0 {
			ttl = 64
		}
		redundancyGroup := iface.RedundancyGroup
		if redundancyGroup <= 0 {
			if src := net.ParseIP(tunnel.Source); src != nil {
				redundancyGroup = rgByAddress[src.String()]
			}
		}
		// For WG the outer family follows the peer endpoint address
		// (the Source/Destination heuristic above sees empty strings).
		// With multi-peer (#1434) the family is a tunnel-level property
		// (one UDP socket); WgOuterFamilyV6 resolves it from the
		// endpoint-bearing peer(s) (validateWireguardPeers rejects
		// mixed-family at commit).
		if isWireguard && tunnel.WgOuterFamilyV6() {
			outerFamily = "inet6"
		}
		id := config.StableTunnelEndpointID(ifName)
		if owner, taken := usedIDs[id]; taken {
			slog.Error("tunnel endpoint id collision — dropping later-sorting tunnel (#1873)",
				"kept", owner, "dropped", ifName, "id", id)
			return
		}
		snap := TunnelEndpointSnapshot{
			ID:              id,
			Interface:       ifName,
			LinuxName:       iface.LinuxName,
			Ifindex:         iface.Ifindex,
			Zone:            iface.Zone,
			RedundancyGroup: redundancyGroup,
			MTU:             iface.MTU,
			Mode:            tunnel.Mode,
			OuterFamily:     outerFamily,
			Source:          tunnel.Source,
			Destination:     tunnel.Destination,
			Key:             tunnel.Key,
			TTL:             ttl,
			TransportTable:  transportTable,
		}
		if isWireguard {
			snap.WgListenPort = tunnel.WgListenPort
			snap.WgLocalPrivkeyHex = tunnel.WgLocalPrivkeyHex.Reveal()
			// Copy the peer set sorted by pubkey hex so both HA nodes
			// serialize byte-identical snapshots (compile determinism,
			// #1434 §5.4) and the wire fixture is stable regardless of
			// the order peers were authored in.
			peers := make([]TunnelWgPeerWire, 0, len(tunnel.WgPeers))
			for _, p := range tunnel.WgPeers {
				peers = append(peers, TunnelWgPeerWire{
					WgPeerPubkeyHex:   p.PublicKeyHex,
					WgAllowedIPs:      p.AllowedIPs,
					WgEndpoint:        p.Endpoint,
					WgKeepaliveSecs:   p.KeepaliveSecs,
					WgPresharedKeyHex: p.PresharedKeyHex.Reveal(),
				})
			}
			sort.Slice(peers, func(i, j int) bool {
				return peers[i].WgPeerPubkeyHex < peers[j].WgPeerPubkeyHex
			})
			snap.WgPeers = peers
		}
		out = append(out, snap)
		usedIDs[id] = ifName
	}
	// #1914: the configured tunnel-endpoint NAME set (which refs the
	// builder would emit, including the interface-level-WG
	// single-lowest-unit pick and the non-WG source/dest gate) is owned by
	// the SSOT emitter config.EmitTunnelEndpointNames. The builder then
	// intersects with the runtime InterfaceSnapshot rows (addEndpoint's
	// ifaceByName lookup) and applies the usedIDs collision drop. The
	// commit-time collision gate (validateTunnelEndpointIDCollisionAST)
	// drives its per-node views through the same emitter, so the gate and
	// the builder can never drift (parity-pinned by
	// TestEmitTunnelEndpointNamesMatchesBuilder).
	for _, ep := range config.EmitTunnelEndpointNames(cfg) {
		addEndpoint(ep.Name, ep.Tunnel)
	}
	return out
}

// wgEndpointSetSummary returns a canonical "id:iface:port@ifindex"
// summary of the snapshot's WireGuard endpoint set (#1866 D3). Used by
// logWgEndpointSetTransitionLocked to emit a publish-boundary log line
// whenever the WG endpoint set the helper is being given changes —
// paired with the Rust-side apply-boundary log, one journal capture
// disambiguates "Go published a stale set" from "Rust skipped the
// prune" if a teardown leak ever recurs.
func wgEndpointSetSummary(snap *ConfigSnapshot) string {
	if snap == nil {
		return ""
	}
	parts := make([]string, 0, len(snap.TunnelEndpoints))
	for _, ep := range snap.TunnelEndpoints {
		if ep.Mode != "wireguard" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d:%s:%d@%d", ep.ID, ep.Interface, ep.WgListenPort, ep.Ifindex))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// logWgEndpointSetTransitionLocked logs (Info, state-transition-only)
// when the WG endpoint set of an outgoing snapshot differs from the
// previously published one, then records the new set. Call after a
// SUCCESSFUL apply_snapshot publish so the recorded set tracks what the
// helper actually accepted. Caller must hold m.mu.
func (m *Manager) logWgEndpointSetTransitionLocked(snap *ConfigSnapshot, path string) {
	set := wgEndpointSetSummary(snap)
	if set == m.lastPublishedWgEndpoints {
		return
	}
	slog.Info("userspace: WG endpoint set changed in published snapshot",
		"path", path,
		"old", m.lastPublishedWgEndpoints,
		"new", set)
	m.lastPublishedWgEndpoints = set
}
