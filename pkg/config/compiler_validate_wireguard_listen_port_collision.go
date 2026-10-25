package config

import (
	"fmt"
	"strings"
)

// wgListenPortKey is the socket identity of one WireGuard endpoint: its
// listen port plus the bind device the helper selects for its transport
// table. The helper binds one `[::]:port` socket per endpoint with no
// SO_REUSEADDR/SO_REUSEPORT (userspace-dp wg_control/sock.rs), pinning it
// to `vrf-<instance>` when the transport table names an instance and
// leaving it wildcard otherwise (wg_outer_bind_device_for_transport_table).
// Two endpoints whose keys collide therefore cannot both bind: whichever
// control thread spawns second fails with EADDRINUSE, exits, and respawns
// every 3 s forever, and that tunnel never completes a handshake (#16531).
//
// A wildcard (default-instance) socket conflicts with EVERY bind on the
// same port, device-bound or not — the kernel rejects a second bind of
// [::]:port while a wildcard socket holds it, and vice versa. Two
// device-bound sockets on DIFFERENT VRF devices do not conflict: each
// SO_BINDTODEVICE bind owns its own device-scoped port space. The key
// therefore carries the device only to distinguish VRF/VRF pairs; the
// collision predicate below treats an empty device (wildcard) as
// colliding with any device on the same port.
type wgListenPortKey struct {
	port   uint16
	device string // "" = wildcard (default instance); "vrf-<instance>" otherwise
}

// wgListenBindDevice returns the SO_BINDTODEVICE value the helper will use
// for a WireGuard endpoint whose effective transport instance is instance
// ("" = default). It mirrors wg_outer_bind_device_for_transport_table:
// inet.0/inet6.0 map to no device, "<instance>.inet[6].0" maps to
// "vrf-<instance>". The instance here is the CONFIG-level routing-instance
// name resolved by the same rules the snapshot builder applies
// (tunnels.go: explicit TunnelConfig.RoutingInstance first, then the
// interface's routing-instance membership), so the gate and the helper
// agree on which sockets collide.
func wgListenBindDevice(instance string) string {
	if instance == "" {
		return ""
	}
	return "vrf-" + instance
}

// wgListenPortCollides reports whether two socket keys cannot coexist.
// Same port is required; then a wildcard on either side collides with
// anything, and two device binds collide only on the same device.
func wgListenPortCollides(a, b wgListenPortKey) bool {
	if a.port != b.port || a.port == 0 {
		return false
	}
	if a.device == "" || b.device == "" {
		return true
	}
	return a.device == b.device
}

func (k wgListenPortKey) describe() string {
	if k.device == "" {
		return fmt.Sprintf("listen-port %d (default routing-instance, wildcard socket)", k.port)
	}
	return fmt.Sprintf("listen-port %d (routing-instance %s, socket bound to %s)",
		k.port, strings.TrimPrefix(k.device, "vrf-"), k.device)
}

// wgEndpointTransportInstance resolves the effective transport
// routing-instance for one emitted WireGuard endpoint, mirroring
// buildTunnelEndpointSnapshots (pkg/dataplane/userspace/tunnels.go):
// the tunnel's explicit RoutingInstance wins; a merged interface-level
// endpoint already carries a unit-contributed scope in that field
// (mergeWireguardUnitPeers); otherwise the RIListMember the daemon stamps
// for list membership, and finally the routing-instance whose interface
// list names this endpoint. RIListMember is empty at compile time (the
// daemon populates it later), so the list-membership arm resolves through
// the config's own RoutingInstances, exactly as
// wireguardRoutingInstances9909 does for the sibling #9909 gate.
//
// A tunnel claimed by MULTIPLE instances is already refused/quarantined
// by the #9909 gate, which runs before this one; taking the first
// deterministic scope here cannot hide a collision that gate missed,
// because a multi-claim tunnel never reaches the dataplane as two sockets.
func wgEndpointTransportInstance(cfg *Config, tunMap map[string]string, ep TunnelEndpointName) string {
	tc := ep.Tunnel
	if tc == nil {
		return ""
	}
	if tc.RoutingInstance != "" {
		return tc.RoutingInstance
	}
	if tc.RIListMember != "" {
		return tc.RIListMember
	}
	scopes := wireguardRoutingInstances9909(cfg, tunMap, tc)
	if len(scopes) > 0 {
		return scopes[0]
	}
	return ""
}

// validateWireguardListenPortCollisionStrict rejects two WireGuard
// endpoints whose listen sockets cannot both bind (#16531).
//
// The defect this closes: two WG tunnels on one listen-port in the same
// instance — or one in the default instance and one in any VRF — commit
// clean, and at runtime each endpoint's control thread binds its own
// [::]:port socket with no reuse option, so the second bind fails with
// EADDRINUSE, the thread exits and respawns every 3 s, and that tunnel
// never handshakes. Spawn order decides which tunnel dies, so a helper
// restart can move the outage. The only signal was a repeating
// wg_bind_listen_port exception in the journal. This is the #3863 class
// ("validated at commit, tunnel permanently dead, no signal") and the
// WireGuard analogue of the #10654 duplicate-GRE-outer gate, which
// explicitly skipped WireGuard because WG rows carry no outer pair —
// the listen socket is WG's collision surface instead.
//
// Scope, deliberately narrow:
//   - Only DISTINCT endpoint definitions participate. The emitter's
//     by-construction dedup is reused: an interface-level WG tunnel emits
//     ONE merged endpoint however many units contribute peers, so
//     multi-unit peers on one interface never self-collide. Two endpoints
//     backed by the same *TunnelConfig object (pure inheritance) are one
//     definition fanned out, mirroring the GRE gate's byObject dedupe.
//   - VRF/VRF on one port with DIFFERENT instances stays legal: each
//     socket is bound to its own vrf-<instance> device and the kernel
//     keeps those port spaces apart. Same instance, or wildcard against
//     anything, collides.
//   - A forwarding-instance scope has no VRF device; the #9909 gate
//     already refuses it on the strict path (and quarantines it on the
//     lenient path) before this gate runs, so it needs no key here. If
//     such a tunnel somehow reaches this gate its instance still maps to
//     vrf-<instance>, which can only make this gate agree with #9909,
//     never weaken it.
//   - WgListenPort == 0 is skipped: validateOneWireguardTunnel (#3863)
//     already rejects it strictly, and a zero port binds nothing.
//
// Strict (commit / commit-check): hard-reject naming both tunnel refs and
// the shared socket identity. Lenient (load / peer-sync): warn so a config
// committed before this gate existed still BOOTS (#1960 no-brick); the
// runtime keeps the colliding tunnel inert (its bind fails) rather than
// ambiguously shared, exactly the posture the lenient GRE gate relies on.
//
// This gate does NOT implement SO_REUSEPORT or a shared demux socket:
// with reuseport the kernel would hash datagrams to an arbitrary engine
// and MAC1 keyed on the wrong engine's key would drop them, so reuse
// cannot make same-port tunnels work. Refusing at commit is the fix the
// contract allows ("a committed tunnel must either work or be refused").
func validateWireguardListenPortCollisionStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	var tunMap map[string]string
	tunMapReady := false
	getTunMap := func() map[string]string {
		if !tunMapReady {
			tunMap = tunnelNameMapFn(cfg)
			tunMapReady = true
		}
		return tunMap
	}

	type owner struct {
		name string
		key  wgListenPortKey
	}
	var owners []owner
	byObject := make(map[*TunnelConfig]struct{})
	// Emitter order is sorted by endpoint name, so the first reported
	// collision is stable across runs and both HA nodes report identically.
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		tc := ep.Tunnel
		if tc == nil || tc.Mode != TunnelModeWireGuard || tc.WgListenPort == 0 {
			continue
		}
		if _, done := byObject[tc]; done {
			continue
		}
		byObject[tc] = struct{}{}
		key := wgListenPortKey{
			port:   tc.WgListenPort,
			device: wgListenBindDevice(wgEndpointTransportInstance(cfg, getTunMap(), ep)),
		}
		var hit *owner
		for i := range owners {
			if wgListenPortCollides(owners[i].key, key) {
				hit = &owners[i]
				break
			}
		}
		if hit == nil {
			owners = append(owners, owner{name: ep.Name, key: key})
			continue
		}
		msg := fmt.Sprintf("wireguard tunnels %q and %q share %s — each tunnel binds its own UDP socket for that port with no port sharing, so whichever control thread starts second fails to bind (EADDRINUSE), respawns every 3s and never completes a handshake; give one tunnel a different listen-port or move it to a different routing-instance (#16531)",
			hit.name, ep.Name, key.describe())
		if lenient {
			warnings = append(warnings, msg)
			continue
		}
		return warnings, fmt.Errorf("%s", msg)
	}
	return warnings, nil
}
