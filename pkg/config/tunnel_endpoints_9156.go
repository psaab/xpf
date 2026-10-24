package config

// TunnelHasUsableEndpoints reports whether a tunnel carries the endpoints its
// mode needs to forward a packet.
//
// #9156: this predicate already existed, TWICE, in two places that disagreed —
// and the disagreement is what turns a lost `destination` into a blackhole
// rather than a missing interface.
//
//	EmitTunnelEndpointNames (tunnelemit.go), which decides what the DATAPLANE
//	learns:            Mode != "wireguard" && (Source == "" || Destination == "")  -> skip
//
//	collectAppliedTunnels (pkg/daemon), which decides what device the ROUTING
//	side creates:      Source != "" || Mode == "wireguard"                         -> apply
//	                   ...and its per-UNIT loop screened nothing at all.
//
// A tunnel with a source and no destination therefore passed the routing gate
// and failed the dataplane one: the TUN was created, brought up
// (pkg/routing/tunnel.go) and given its configured addresses, while the
// dataplane held no endpoint for it. An operator can zone it, route into it,
// and every packet disappears.
//
// The routing package HAS a correct guard for this
// (`localIP == nil || remoteIP == nil` -> warn and refuse) and it is dead code:
// its own comment records that the daemon always sets AnchorOnly, and
// dataplane.EffectiveType("") is TypeUserspace on every box, so Apply always
// dispatches to applyAnchorLocked — which has no endpoint check at all.
//
// One predicate, used by both, is what stops them drifting apart again. It is
// deliberately the STRICTER of the two (the emitter's), because the emitter's
// is the one that decides whether the tunnel can carry traffic: creating a
// device the dataplane cannot forward through is the failure, not the
// remedy.
//
// WireGuard is exempt for the reason #1432 and #1736 both record: it carries
// its peer in WgEndpoint and needs no Source/Destination, and screening it on
// Source left the persistent wgN TUN uncreated while the dataplane's control
// thread waited to open it.
func TunnelHasUsableEndpoints(t *TunnelConfig) bool {
	if t == nil {
		return false
	}
	if t.Mode == TunnelModeWireGuard {
		return true
	}
	return t.Source != "" && t.Destination != ""
}
