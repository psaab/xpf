package config

import (
	"fmt"
	"sort"
	"strings"
)

// SteeredWireGuardListenPort returns the ONE WireGuard listen port the
// dataplane steers onto its AF_XDP WireGuard path, and the tunnel-endpoint
// reference that owns it. It returns (0, "") when no WireGuard tunnel carries a
// listen port.
//
// #9521: this is the single derivation of "which port is steered", and three
// consumers read it:
//
//   - validateWireguardSingleSteeredPort, below, names it in the commit warning;
//   - pkg/dataplane/userspace stamps it onto the helper snapshot as
//     ConfigSnapshot.WgSteeredListenPort, and snapshotWgListenPort programs the
//     shim ctrl block's single steering scalar from THAT field;
//   - the helper reads the same snapshot field to decide which WireGuard
//     control threads may hand kernel-path transport plaintext to their wgN
//     TUN: only the steered port's may, every other port's is dropped.
//
// It is derived from the CONFIGURATION, never from the live interface rows.
// That is the second half of #9521. The shim scalar used to be the first
// WireGuard endpoint that SURVIVED buildTunnelEndpointSnapshots' intersection
// with the live InterfaceSnapshot rows, so when the warned tunnel's netdev was
// absent the NEXT tunnel's port was programmed — the port the operator had just
// been told was not steered — and nothing at commit time could see it. Deriving
// the port here, once, makes "the port the warning names" and "the port the
// dataplane programs" one value by construction. A tunnel whose netdev is
// absent simply has no endpoint to serve its still-steered port.
//
// Order is EmitTunnelEndpointNames' order — interfaces sorted by name, units
// ascending — the SSOT emitter the snapshot builder drives, so the answer is
// stable across commits and identical on both HA nodes. A tunnel with
// WgListenPort == 0 is skipped: the strict WireGuard gate
// (validateOneWireguardTunnel, #3863) rejects it at commit, so it only arises
// on a tolerant load, and it contributes no steerable port either way.
func SteeredWireGuardListenPort(cfg *Config) (uint16, string) {
	if cfg == nil {
		return 0, ""
	}
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel == nil || ep.Tunnel.Mode != "wireguard" || ep.Tunnel.WgListenPort == 0 {
			continue
		}
		return ep.Tunnel.WgListenPort, ep.Name
	}
	return 0, ""
}

// validateWireguardSingleSteeredPort emits a commit WARNING (never a hard
// reject) when the configuration declares WireGuard tunnels on more than one
// distinct UDP listen port.
//
// THE MECHANISM. The AF_XDP shim steers WireGuard for a SINGLE listen port.
// `UserspaceCtrl.wg_listen_port` holds one port, and the shim's worker-claim
// predicate (`wg_worker_claims_record`, userspace-xdp/src/lib.rs) requires
// `parsed.flow_dst_port == ctrl.wg_listen_port`. A transport-data record for
// that port is claimed by the worker, decapsulated inside the pipeline and
// adjudicated under the tunnel's logical ingress zone (#8274). A record for ANY
// OTHER configured listen port fails the predicate, falls to the generic
// local-destination arm and is handed to the kernel, where that tunnel's own
// control thread receives it on its bound socket — the host-inbound filter
// admits every configured listen port (config.WireGuardListenPorts), and the
// helper runs a control thread per WireGuard endpoint.
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
//	steered port   transport data -> worker decap -> zone/session/policy/NAT
//	other ports    transport data -> kernel -> control thread -> DROPPED
//
// #9016 recorded the earlier second row — "-> wgN TUN -> kernel forwards, no
// zone policy" — which was true until #9521, and it corrected a still earlier
// claim that the unsteered tunnel was "dead". Neither sentence may come back:
// the tunnel is not dead (it handshakes and sends), and it no longer forwards
// unadjudicated plaintext.
//
// A WARNING, not a reject. The configuration is legal, the steered tunnel works
// exactly as configured, and rejecting would change commit acceptance for
// configs that commit clean at every released version and leave an operator
// unable to commit an unrelated change (#1960 no-brick). Steering a port SET is
// #1434 Increment 2, tracked as #9587: a verifier-gated userspace-xdp
// change with a documented v6-line-rate sensitivity that must clear the loss
// cluster. The warning describes the current behaviour and names the tracking
// issue; it must not promise the fix, nor rule it out.
//
// The steered port comes from SteeredWireGuardListenPort, which is also what the
// dataplane programs, so the port this warning names IS the port the shim
// steers — including when that tunnel's netdev is absent at runtime. Two
// WireGuard tunnels that SHARE one listen port lose nothing to the single
// steering scalar and draw no warning; they collide on the kernel UDP bind
// instead (bind_wg_socket sets no SO_REUSEPORT), which is a different failure
// and not this gate's subject.
func validateWireguardSingleSteeredPort(cfg *Config) []string {
	steeredPort, steeredName := SteeredWireGuardListenPort(cfg)
	if steeredPort == 0 {
		return nil
	}
	strandedPorts := make([]uint16, 0, 1)
	strandedTunnels := make(map[uint16][]string)
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		if ep.Tunnel == nil || ep.Tunnel.Mode != "wireguard" || ep.Tunnel.WgListenPort == 0 {
			continue
		}
		port := ep.Tunnel.WgListenPort
		if port == steeredPort {
			continue
		}
		if _, seen := strandedTunnels[port]; !seen {
			strandedPorts = append(strandedPorts, port)
		}
		strandedTunnels[port] = append(strandedTunnels[port], ep.Name)
	}
	if len(strandedPorts) == 0 {
		return nil
	}
	sort.Slice(strandedPorts, func(i, j int) bool { return strandedPorts[i] < strandedPorts[j] })

	stranded := make([]string, 0, len(strandedPorts))
	for _, port := range strandedPorts {
		stranded = append(stranded, fmt.Sprintf("%d (%s)", port, strings.Join(strandedTunnels[port], ", ")))
	}
	strandedNoun, strandedVerb, strandedSubject := "listen-port", "is", "that tunnel"
	if len(strandedPorts) > 1 {
		strandedNoun, strandedVerb, strandedSubject = "listen-ports", "are", "those tunnels"
	}
	return []string{fmt.Sprintf(
		"wireguard: %d distinct listen-ports are configured, but the dataplane "+
			"steers inbound WireGuard transport for only ONE of them. "+
			"listen-port %d (%s) IS steered onto the AF_XDP WireGuard path, where "+
			"its decapsulated traffic is adjudicated under the tunnel's ingress "+
			"zone (screen, session, policy, NAT). "+
			"%s %s %s NOT steered, and inbound transport for %s is REFUSED rather "+
			"than forwarded unadjudicated: a transport record that reaches %s "+
			"through the kernel is DROPPED (counted as an unsteered-port receive "+
			"drop) instead of being written to its wgN TUN, where the kernel would "+
			"forward it with no zone policy, no session and no counters. "+
			"Handshakes still complete and outbound traffic still flows, so %s can "+
			"come up and still pass no inbound traffic. Only one WireGuard "+
			"listen-port can be steered until multi-port steering lands (#1434 "+
			"Increment 2, tracked as #9587).",
		len(strandedPorts)+1, steeredPort, steeredName,
		strandedNoun, strings.Join(stranded, ", "), strandedVerb, strandedSubject,
		strandedSubject, strandedSubject)}
}
