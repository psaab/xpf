package config

import (
	"fmt"
	"sort"
	"strings"
)

// MaxSteeredWireGuardPorts is the number of distinct WireGuard listen ports
// the dataplane steers onto its AF_XDP WireGuard path (#9587, #1434 Increment
// 2). It bounds UserspaceCtrl.wg_ports, ConfigSnapshot.WgSteeredListenPorts
// and the helper ForwardingState set alike; the Go constant is the SSOT the
// snapshot/ctrl programmers assert against, and the Rust sides carry the same
// bound as WG_STEERED_PORT_SET_MAX (pinned equal by the cross-plane ctrl-ABI
// test). More distinct ports than this keep the exact #9521 posture: commit
// warning naming them plus kernel-path transport dropped and counted.
const MaxSteeredWireGuardPorts = 8

// SteeredWireGuardListenPorts returns the distinct non-zero WireGuard listen
// ports in EMITTER order (EmitTunnelEndpointNames: interfaces sorted by name,
// units ascending), with first-seen dedup. It returns nil when no WireGuard
// tunnel carries a listen port.
//
// #9521: this is the single derivation of "which ports are steered", and three
// consumers read the triple SplitSteeredPorts builds from it:
//
//   - validateWireguardSteeredPortSet, below, names selected vs overflow in
//     the commit warning;
//   - pkg/dataplane/userspace stamps the SELECTED set onto the helper
//     snapshot as ConfigSnapshot.WgSteeredListenPorts, and the ctrl-block
//     programmer encodes THAT field into the shim's count+array;
//   - the helper reads the same snapshot field to decide which WireGuard
//     control threads may hand kernel-path transport plaintext to their wgN
//     TUN: every selected port's may, every other port's is dropped.
//
// It is derived from the CONFIGURATION, never from the live interface rows.
// That is the second half of #9521. The shim set used to be the first
// WireGuard endpoint that SURVIVED buildTunnelEndpointSnapshots' intersection
// with the live InterfaceSnapshot rows, so when the warned tunnel's netdev was
// absent the NEXT tunnel's port was programmed — a port the operator had just
// been told was not steered — and nothing at commit time could see it.
// Deriving the set here, once, makes "the ports the warning names" and "the
// ports the dataplane programs" one value by construction. A tunnel whose
// netdev is absent simply has no endpoint to serve its still-steered port.
//
// Order is EmitTunnelEndpointNames' order — the SSOT emitter the snapshot
// builder drives, so the answer is stable across commits and identical on
// both HA nodes. A tunnel with WgListenPort == 0 is skipped: the strict
// WireGuard gate (validateOneWireguardTunnel, #3863) rejects it at commit, so
// it only arises on a tolerant load, and it contributes no steerable port
// either way. Two tunnels SHARING one listen port contribute one entry
// (dedup); they collide on the kernel UDP bind instead (bind_wg_socket sets
// no SO_REUSEPORT), which is a different failure and not this gate's subject.
func SteeredWireGuardListenPorts(cfg *Config) []uint16 {
	if cfg == nil {
		return nil
	}
	var out []uint16
	seen := map[uint16]bool{}
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel == nil || ep.Tunnel.Mode != "wireguard" || ep.Tunnel.WgListenPort == 0 {
			continue
		}
		if p := ep.Tunnel.WgListenPort; !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// SplitSteeredPorts is the SINGLE selection site: it takes the emitter-ordered
// distinct set and returns (full, selected, overflow). Selected is the first
// MaxSteeredWireGuardPorts entries in emitter order — the previously working
// emitter-first port is position 0 and can never be truncated away — sorted
// ascending for encoding; overflow is the remainder, sorted ascending. With
// no more ports than the bound, selection == full and overflow is empty.
// Sorting is presentation/encoding only: no caller may recover emitter order
// from a sorted list, so selection takes the emitter-ordered input directly.
func SplitSteeredPorts(emitterOrdered []uint16) (full, selected, overflow []uint16) {
	full = append([]uint16(nil), emitterOrdered...)
	n := len(full)
	if n > MaxSteeredWireGuardPorts {
		n = MaxSteeredWireGuardPorts
	}
	selected = append([]uint16(nil), full[:n]...)
	overflow = append([]uint16(nil), full[n:]...)
	sort.Slice(selected, func(i, j int) bool { return selected[i] < selected[j] })
	sort.Slice(overflow, func(i, j int) bool { return overflow[i] < overflow[j] })
	return full, selected, overflow
}

// validateWireguardSteeredPortSet emits a commit WARNING (never a hard
// reject) when the configuration declares MORE distinct WireGuard UDP listen
// ports than the dataplane steers (MaxSteeredWireGuardPorts). Silent when
// every configured port fits the steered set.
//
// THE MECHANISM. The AF_XDP shim steers WireGuard for a bounded SET of listen
// ports (#9587): `UserspaceCtrl.wg_ports[0..wg_port_count]` holds them, and
// the shim's worker-claim predicate (`wg_worker_claims_record`,
// userspace-xdp/src/lib.rs) requires set membership. A transport-data record
// for a steered port is claimed by the worker, decapsulated inside the
// pipeline and adjudicated under the tunnel's logical ingress zone (#8274).
// A record for ANY OTHER configured listen port fails the predicate, falls
// to the generic local-destination arm and is handed to the kernel, where
// that tunnel's own control thread receives it on its bound socket — the
// host-inbound filter admits every configured listen port
// (config.WireGuardListenPorts), and the helper runs a control thread per
// WireGuard endpoint.
//
// #9521: what that control thread did next was the defect. It decrypted the
// record and wrote the plaintext inner packet to the wgN TUN, and the kernel
// forwarded it with no zone policy, no session, no NAT and no counters — so an
// authenticated peer on an unsteered port reached whatever the kernel routed
// to, bounded only by that peer's allowed-ips (a source-ownership check, not a
// destination policy). The helper now DROPS a transport record that reaches an
// unsteered port's socket — counted as `rx_unsteered_transport_drops`, the
// `unsteered-port` receive-drop reason — instead of writing it to the TUN.
// Handshake and cookie records are untouched, so that tunnel still completes
// handshakes and still sends; what it no longer does is deliver inbound
// traffic the dataplane did not adjudicate.
//
// So the two kinds of port differ in what happens to inbound traffic, and the
// warning has to say which is which:
//
//	steered ports  transport data -> worker decap -> zone/session/policy/NAT
//	other ports    transport data -> kernel -> control thread -> DROPPED
//
// #9016 recorded the earlier second row — "-> wgN TUN -> kernel forwards, no
// zone policy" — which was true until #9521, and it corrected a still earlier
// claim that the unsteered tunnel was "dead". Neither sentence may come back:
// the tunnel is not dead (it handshakes and sends), and it no longer forwards
// unadjudicated plaintext.
//
// A WARNING, not a reject. The configuration is legal, the steered tunnels
// keep working exactly as configured, and rejecting would change commit
// acceptance for configs that commit clean at every released version and
// leave an operator unable to commit an unrelated change (#1960 no-brick).
// The warning describes the current behaviour and names the refused ports; it
// must not promise a bigger set, nor rule one out.
//
// The selected set comes from SplitSteeredPorts — the same triple the
// dataplane programs — so the ports this warning names ARE the ports the shim
// steers, including when a warned tunnel's netdev is absent at runtime. Two
// WireGuard tunnels that SHARE one listen port contribute one set entry and
// draw no warning; they collide on the kernel UDP bind instead
// (bind_wg_socket sets no SO_REUSEPORT), which is a different failure and not
// this gate's subject.
func validateWireguardSteeredPortSet(cfg *Config) []string {
	_, selected, overflow := SplitSteeredPorts(SteeredWireGuardListenPorts(cfg))
	if len(overflow) == 0 {
		return nil
	}
	owners := make(map[uint16][]string)
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel == nil || ep.Tunnel.Mode != "wireguard" || ep.Tunnel.WgListenPort == 0 {
			continue
		}
		owners[ep.Tunnel.WgListenPort] = append(owners[ep.Tunnel.WgListenPort], ep.Name)
	}
	entry := func(port uint16) string {
		return fmt.Sprintf("%d (%s)", port, strings.Join(owners[port], ", "))
	}
	steered := make([]string, 0, len(selected))
	for _, port := range selected {
		steered = append(steered, entry(port))
	}
	refused := make([]string, 0, len(overflow))
	for _, port := range overflow {
		refused = append(refused, entry(port))
	}
	return []string{fmt.Sprintf(
		"wireguard: %d distinct listen-ports are configured, but the dataplane "+
			"steers inbound WireGuard transport for only %d of them (at most %d). "+
			"listen-ports %s ARE steered onto the AF_XDP WireGuard path, where "+
			"decapsulated traffic is adjudicated under the tunnel's ingress "+
			"zone (screen, session, policy, NAT). "+
			"listen-ports %s are NOT steered, and inbound transport for those "+
			"tunnels is REFUSED rather than forwarded unadjudicated: a transport "+
			"record that reaches one through the kernel is DROPPED (counted as an "+
			"unsteered-port receive drop) instead of being written to its wgN TUN, "+
			"where the kernel would forward it with no zone policy, no session "+
			"and no counters. "+
			"Handshakes still complete and outbound traffic still flows, so those "+
			"tunnels can come up and still pass no inbound traffic. (#9587.)",
		len(selected)+len(overflow), len(selected), MaxSteeredWireGuardPorts,
		strings.Join(steered, ", "), strings.Join(refused, ", "))}
}
