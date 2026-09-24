package config

import (
	"fmt"
	"net"
)

// greOuterKey is the decap identity of one GRE tunnel endpoint: the outer
// (source, destination) pair plus the GRE key. Two GRE-mode endpoints that
// share all three match exactly the same inbound frames, so decap cannot
// attribute the traffic to either one.
type greOuterKey struct {
	source      string
	destination string
	key         uint32
}

// validateGreDuplicateOuterStrict rejects two GRE tunnels that share an
// identical outer (source, destination, key) triple (#10654).
//
// The defect this closes: the triple passed strict commit clean, and Rust
// decap (`match_tunnel_endpoint`, userspace-dp/src/afxdp/gre.rs) iterates
// the `gre_decap_index` bucket in snapshot order and returns the first
// key-matching endpoint — so every inbound frame of the duplicated tunnel
// was attributed to whichever endpoint sorts first. Deterministic, but
// ambiguous: the losing tunnel's counters, zone ingress, and session
// ownership silently describe traffic the operator assigned to it.
//
// The gate walks EmitTunnelEndpointNames — the same SSOT emitter the
// snapshot builder consumes — so "which endpoints reach the dataplane" is
// answered once, not re-derived. Only GRE-kind modes (`gre`, `ip6gre`,
// mirroring Rust `tunnel_mode_kind`) participate: WireGuard rows carry no
// outer pair and are never decap-indexed, and `ipip` is owned by the
// sibling unimplemented gate. A half-configured tunnel is already declined
// by the emitter and never reaches the dataplane, so it cannot collide.
//
// Key semantics (mirroring the decap predicate exactly):
//   - Key 0 is "unkeyed" (types_routing.go), but it is still part of the
//     triple: two unkeyed tunnels on one outer pair both match every
//     unkeyed frame and collide.
//   - A keyed tunnel and an unkeyed tunnel on one outer pair do NOT
//     collide: a keyed frame matches only the keyed row
//     (`key_present && endpoint.key == key`) and an unkeyed frame matches
//     only the unkeyed row (`!key_present || key == 0`). The Rust comment
//     calls this out as disambiguated-by-key, and the gate agrees —
//     rejecting it would forbid a working shape.
//   - Direction matters: (A,B) and (B,A) are different tunnels in
//     different decap buckets and never collide.
//
// Normalization: endpoints are compared by net.ParseIP + String(), so IPv6
// respellings of one address ("2001:db8::1" vs "2001:0db8::1") collide as
// they do in the Rust bucket key (parsed IpAddr). The one deliberate
// over-approximation is a v4-mapped literal ("::ffff:192.0.2.1"), which Go
// renders as dotted-quad while Rust parses as V6: the gate rejects that
// pathological pair on the strict path rather than tracking two spellings
// of one confusion. An unparseable endpoint is skipped — a malformed
// literal is a schema-level concern, not a cross-field duplicate (same
// posture as validateOneTunnelOuterFamily).
//
// Strict (commit / commit-check): hard-reject naming both tunnel refs and
// the shared triple. Lenient (load / peer-sync): warn so a config
// committed before this gate existed still BOOTS (#1960 no-brick) — the Go
// snapshot builder drops the later-sorting duplicate loudly (`usedGreOuter`,
// pkg/dataplane/userspace/tunnels.go, the #1873 usedIDs pattern), so the
// snapshot carries one row per triple and the leniently-loaded tunnel is
// inert rather than ambiguously attributed.
func validateGreDuplicateOuterStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string
	// Emitter order is sorted-by-Name, so the first reported collision is
	// stable across runs and both HA nodes report identically.
	seen := make(map[greOuterKey]string)
	for _, ep := range EmitTunnelEndpointNames(cfg) {
		tc := ep.Tunnel
		if tc.Mode != "gre" && tc.Mode != "ip6gre" {
			continue
		}
		src := net.ParseIP(tc.Source)
		dst := net.ParseIP(tc.Destination)
		if src == nil || dst == nil {
			continue
		}
		k := greOuterKey{source: src.String(), destination: dst.String(), key: tc.Key}
		owner, dup := seen[k]
		if !dup {
			seen[k] = ep.Name
			continue
		}
		keyDesc := fmt.Sprintf("key %d", tc.Key)
		if tc.Key == 0 {
			keyDesc = "key 0 (unkeyed)"
		}
		msg := fmt.Sprintf("duplicate GRE outer (source %s, destination %s, %s) already claimed by tunnel %q — inbound decap would attribute every frame of that tunnel to whichever endpoint sorts first (#10654)",
			k.source, k.destination, keyDesc, owner)
		if lenient {
			warnings = append(warnings, fmt.Sprintf("tunnel %q: %s", ep.Name, msg))
			continue
		}
		return warnings, fmt.Errorf("tunnel %q: %s", ep.Name, msg)
	}
	return warnings, nil
}
