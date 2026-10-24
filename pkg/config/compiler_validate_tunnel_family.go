package config

import (
	"fmt"
	"net"
	"sort"
)

// validateTunnelOuterFamilyStrict enforces the cross-field outer-family
// invariant on every non-WireGuard tunnel (#5162): the OUTER source and
// OUTER destination of a GRE/IPIP tunnel must be the SAME address family.
//
// The defect this closes: per-leaf validation accepts a v4 source and a
// v6 destination independently (each is a valid IP literal), so a mixed
// pair COMMITS CLEAN. The Go snapshot producer
// (pkg/dataplane/userspace/tunnels.go) then tags the endpoint `inet6` if
// EITHER endpoint is v6, and the Rust populate_tunnel_endpoints trusts
// that declared family. The GRE encoder subsequently hits the AF_INET6
// arm, finds a v4 endpoint, and returns None → every encapsulated packet
// is SILENTLY dropped with no operator signal. This mirrors the sibling
// WireGuard cross-field family gate (validateWireguardPeersStrict:
// endpoint-bearing peers must agree on outer family — one UDP socket =
// one family) but applies it to the GRE/IPIP outer source/destination
// pair, which had no such gate.
//
// WireGuard is intentionally skipped here: a WG tunnel carries no
// Source/Destination pair (the peer endpoint lives in WgPeers), and its
// outer family is already validated by validateWireguardPeersStrict.
//
// Strict (commit / commit-check): hard-reject a mixed-family pair naming
// the tunnel and the two families, so the operator sees the
// misconfiguration and it never reaches the dataplane to drop silently.
// Lenient (load / peer-sync): downgrade to a warning so a config
// committed before this gate existed (or synced from a peer running an
// older build) still BOOTS (#1960 no-brick) — the Rust helper
// independently skips a mixed-family non-WG row (fail-closed with a loud
// eprintln, forwarding_build/tunnels.rs), so the leniently-loaded bad
// tunnel is inert rather than a silent inet6-tagged blackhole.
func validateTunnelOuterFamilyStrict(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	var warnings []string

	// Deterministic iteration order so the first reported error is stable
	// across runs and both HA nodes report identically.
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)

	emit := func(label string, err error) error {
		if err == nil {
			return nil
		}
		if lenient {
			warnings = append(warnings, fmt.Sprintf("tunnel %s: %v", label, err))
			return nil
		}
		return fmt.Errorf("tunnel %s: %w", label, err)
	}

	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		if ifc.Tunnel != nil {
			label := tunnelLabel(ifName, -1, ifc.Tunnel)
			if err := emit(label, validateOneTunnelOuterFamily(ifc.Tunnel)); err != nil {
				return warnings, err
			}
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, n := range unitNums {
			unit := ifc.Units[n]
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			label := tunnelLabel(ifName, n, unit.Tunnel)
			if err := emit(label, validateOneTunnelOuterFamily(unit.Tunnel)); err != nil {
				return warnings, err
			}
		}
	}
	return warnings, nil
}

// validateOneTunnelOuterFamily checks the outer source/destination family
// agreement of a single tunnel. Returns nil for WireGuard (no
// Source/Destination pair; family validated by
// validateWireguardPeersStrict), for a tunnel missing either endpoint
// (the emitter's source/dest gate declines to emit a half-configured
// non-WG endpoint, so it never reaches the dataplane), and for an
// unparseable endpoint (a malformed literal cannot be classified — that
// is a separate schema-level concern, not a cross-field family
// mismatch). It rejects ONLY a pair where both endpoints parse to
// concrete IPs of DIFFERENT families.
func validateOneTunnelOuterFamily(tc *TunnelConfig) error {
	if tc == nil || tc.Mode == TunnelModeWireGuard {
		return nil
	}
	if tc.Source == "" || tc.Destination == "" {
		return nil
	}
	src := net.ParseIP(tc.Source)
	dst := net.ParseIP(tc.Destination)
	if src == nil || dst == nil {
		return nil
	}
	srcV6 := src.To4() == nil
	dstV6 := dst.To4() == nil
	if srcV6 != dstV6 {
		return fmt.Errorf(
			"outer source %s (%s) and destination %s (%s) are different address families; "+
				"a GRE/IPIP tunnel encapsulates in ONE outer IP family, so both endpoints "+
				"must be IPv4 or both IPv6 (a mixed pair commits clean but the dataplane "+
				"silently drops every encapsulated packet, #5162)",
			tc.Source, familyName(srcV6), tc.Destination, familyName(dstV6))
	}
	return nil
}

// familyName renders the operator-facing family label for a tunnel
// endpoint from the "is IPv6" boolean.
func familyName(isV6 bool) string {
	if isV6 {
		return "IPv6"
	}
	return "IPv4"
}
