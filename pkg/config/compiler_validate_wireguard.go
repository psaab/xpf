package config

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// validateWireguardPeersStrict enforces the multi-peer WireGuard
// commit-time invariants (#1434) over every compiled WG tunnel
// (interface-level and per-unit). It returns warnings on the lenient
// path and a hard error on the strict path.
//
// The gates (all LOCKED by the plan review rounds,
// docs/research/1434-multitunnel-wg/plan.md §5.5/§5.6, plus the #3863
// local-identity gate):
//
//   - Missing/invalid listen-port = REJECT. A WG tunnel needs a
//     listen-port in [1,65535] to bind its UDP socket; the Rust
//     hydrate drops a row whose wg_listen_port is 0 (#3863).
//   - Missing/malformed private-key = REJECT. The local static key is
//     exactly 64 hex chars (32-byte X25519); hydrate drops a row whose
//     private key does not decode (#3863).
//   - Zero-peer = REJECT. A WG tunnel with no peer can never handshake;
//     xpf has no dynamic peer learning (peers are config-static).
//   - Duplicate peer pubkey = REJECT. The per-tunnel gate protects each
//     unit, and the merged-view gate protects an interface-level WireGuard
//     endpoint when two units author the same key; the latter runs before
//     first-wins emission can discard one unit's routing intent. The Rust
//     engine reconcile only debug_asserts on duplicates (release builds would
//     mis-index the AllowedIPs LPM and the peer slab); the Go control plane is
//     the named owner of the dup-reject contract (engine.rs).
//   - Malformed pubkey = REJECT. A WG static key is exactly 64 hex
//     chars (32-byte X25519). A bad key today fails silently at the
//     dataplane (hydrate_wg_identity drops the whole row).
//   - Malformed preshared-key = REJECT (when present). Same 64-hex
//     shape (#1434 B2).
//   - Mixed endpoint family = REJECT. One WG interface binds one kernel
//     UDP socket = one outer transport family. Peers that DECLARE an
//     endpoint must all agree on v4-vs-v6; a responder-only peer (no
//     endpoint) does not constrain the family.
//
// AllowedIPs broader/narrower overlap across peers is NOT rejected —
// valid WG configs overlap (a catch-all peer plus a more-specific peer),
// and the engine LPM resolves longest-prefix deterministically. An EXACT
// duplicate prefix (same network + length + family) on two different peers
// IS rejected, though: the cryptokey routing table is a prefix->peer map,
// so an exact tie has no longest-prefix winner — the engine's LPM lookup
// resolves it by stable-sort insertion order, silently blackholing the
// loser for that prefix (#2445). Reject it at commit so the operator's
// intent is never masked by an implementation-defined tie-break.
func validateWireguardPeersStrict(cfg *Config, lenient bool) ([]string, error) {
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
			warnings = append(warnings, fmt.Sprintf("wireguard %s: %v", label, err))
			return nil
		}
		return fmt.Errorf("wireguard %s: %w", label, err)
	}

	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		if ifc.Tunnel != nil && ifc.Tunnel.Mode == "wireguard" {
			label := tunnelLabel(ifName, -1, ifc.Tunnel)
			if err := emit(label, validateOneWireguardTunnel(ifc.Tunnel)); err != nil {
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
			if unit == nil || unit.Tunnel == nil || unit.Tunnel.Mode != "wireguard" {
				continue
			}
			label := tunnelLabel(ifName, n, unit.Tunnel)
			if err := emit(label, validateOneWireguardTunnel(unit.Tunnel)); err != nil {
				return warnings, err
			}
			if err := emit(label, unitWireguardIdentityOverride(ifc, unit.Tunnel)); err != nil {
				return warnings, err
			}
		}
		// Interface-level WireGuard emits ONE endpoint with the interface
		// and every unit's peers merged into it. Validate that merged view
		// before mergeWireguardUnitPeers can first-wins deduplicate a peer
		// authored by two different units.
		if ifc.Tunnel != nil && ifc.Tunnel.Mode == "wireguard" {
			if err := emit(ifName, validateMergedWireguardUnitPeers(ifName, ifc, unitNums)); err != nil {
				return warnings, err
			}
		}
	}
	return warnings, nil
}

// validateMergedWireguardUnitPeers rejects a peer public key authored by two
// different units that feed one interface-level WireGuard endpoint. A unit's
// compiled WgPeers includes the interface-level peers inherited by that unit,
// so those parent keys are intentionally excluded from the ownership map: the
// repeated inherited copies are expected, while two unit-owned copies are a
// merged-view conflict.
//
// This gate is deliberately scoped to an interface-level WireGuard tunnel.
// A WireGuard tunnel authored only at unit level emits one endpoint per unit,
// so equal keys there do not enter mergeWireguardUnitPeers and retain the
// existing single-tunnel behavior.
func validateMergedWireguardUnitPeers(ifName string, ifc *InterfaceConfig, unitNums []int) error {
	if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != "wireguard" {
		return nil
	}
	if len(unitNums) == 0 {
		return nil
	}
	inherited := make(map[string]struct{}, len(ifc.Tunnel.WgPeers))
	for _, p := range ifc.Tunnel.WgPeers {
		inherited[p.PublicKeyHex] = struct{}{}
	}
	owners := make(map[string]int)
	for _, unitNum := range unitNums {
		unit := ifc.Units[unitNum]
		if unit == nil || unit.Tunnel == nil {
			continue
		}
		for _, p := range unit.Tunnel.WgPeers {
			if _, isInherited := inherited[p.PublicKeyHex]; isInherited {
				continue
			}
			if owner, exists := owners[p.PublicKeyHex]; exists {
				if owner == unitNum {
					// A duplicate within one unit is owned by the
					// per-tunnel validator above, not this merged gate.
					continue
				}
				return fmt.Errorf("duplicate peer public key %q is declared by WireGuard units %q and %q; one merged endpoint cannot retain both units' routing intent",
					p.PublicKeyHex,
					fmt.Sprintf("%s.%d", ifName, owner),
					fmt.Sprintf("%s.%d", ifName, unitNum))
			}
			owners[p.PublicKeyHex] = unitNum
		}
	}
	return nil
}

// unitWireguardIdentityOverride refuses a unit that changes the local
// WireGuard IDENTITY of an interface-level tunnel (#7786).
//
// TunnelConfig states the model: WgListenPort and WgLocalPrivkeyHex are
// TUNNEL-level -- "one kernel UDP socket, one local identity per WG interface"
// -- while WgPeers is the per-peer set. A unit under an interface-level
// `tunnel mode wireguard` therefore contributes PEERS, which are merged into
// the interface's single emitted endpoint (EmitTunnelEndpointNames). A unit
// that overrides the listen port or the private key is asking for a SECOND
// local identity on one logical interface, which that model has no
// representation for.
//
// It is refused rather than implemented because the shape is half-wired today
// in a way that misleads: routing materialises the unit's TUN and
// WireGuardListenPorts() already collects the unit's port, so the host-inbound
// filter opens it -- and no endpoint is ever emitted for it, so nothing
// listens on a port the firewall advertises as open. Merging it instead would
// be worse than refusing: it would fold a DIFFERENT identity's peers into the
// parent endpoint, where they would be offered the parent's key.
//
// Scope is deliberately narrow. This fires only under an interface-level
// WireGuard tunnel. `interfaces wgN unit 0 tunnel mode wireguard` with no
// interface-level stanza is the canonical per-unit spelling, it emits its own
// endpoint through the per-unit branch, and it is untouched here.
func unitWireguardIdentityOverride(ifc *InterfaceConfig, unitTunnel *TunnelConfig) error {
	if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.Mode != "wireguard" || unitTunnel == nil {
		return nil
	}
	if unitTunnel.WgListenPort != ifc.Tunnel.WgListenPort {
		return fmt.Errorf("unit overrides the WireGuard listen-port of the interface-level "+
			"tunnel (%d vs %d); listen-port and private-key are properties of the WireGuard "+
			"interface, which is ONE UDP socket and ONE local identity, so a unit may add "+
			"`peer` entries but cannot define a second identity. Configure the second "+
			"identity on its own interface",
			unitTunnel.WgListenPort, ifc.Tunnel.WgListenPort)
	}
	if !strings.EqualFold(unitTunnel.WgLocalPrivkeyHex.Reveal(), ifc.Tunnel.WgLocalPrivkeyHex.Reveal()) {
		return fmt.Errorf("unit overrides the WireGuard private-key of the interface-level " +
			"tunnel; listen-port and private-key are properties of the WireGuard interface, " +
			"which is ONE UDP socket and ONE local identity, so a unit may add `peer` " +
			"entries but cannot define a second identity. Configure the second identity on " +
			"its own interface")
	}
	return nil
}

// tunnelLabel renders an operator-facing identifier for a WG tunnel in
// an error message: the tunnel's own Name when set, else the
// interface[.unit] coordinates.
func tunnelLabel(ifName string, unit int, tc *TunnelConfig) string {
	if tc != nil && tc.Name != "" {
		return tc.Name
	}
	if unit >= 0 {
		return fmt.Sprintf("%s.%d", ifName, unit)
	}
	return ifName
}

// validateOneWireguardTunnel applies the per-tunnel WG gates to a single
// tunnel: first the LOCAL identity (listen-port + private-key), then the
// per-peer gates over WgPeers.
//
// Local identity (#3863). The Rust hydrate_wg_identity
// (userspace-dp/src/afxdp/forwarding_build/tunnels.rs) drops the WHOLE
// tunnel row — a silent, permanent, no-signal VPN outage — when the local
// identity does not parse: `wg_listen_port == 0` (a WG tunnel with no
// listen port cannot bind its UDP socket, and the shim steering gate
// reads port 0 as "no WG") or the local private key fails
// decode_wg_key_hex (not exactly 64 hex chars decoding to 32 bytes).
// parseTunnelWireguard silently collapses a missing/0/out-of-range
// listen-port to WgListenPort == 0 and stores private-key verbatim, so a
// bad or absent local identity would otherwise COMMIT CLEAN and then
// produce a dead tunnel with no diagnostic. Reject it at commit
// (fail-closed) so the commit-accept set never exceeds the
// runtime-hydrate set. The listen-port VALUE bound is also enforced at
// the schema layer (schema_interfaces.go ValidateInteger(1,65535)), but
// that runs only on the author path and cannot see a MISSING leaf; this
// compiler gate is the universal chokepoint every compile/load/HA-sync
// path funnels through. Checked before the peer gates to mirror the Rust
// order (listen_port -> local privkey -> peers).
func validateOneWireguardTunnel(tc *TunnelConfig) error {
	if tc.WgListenPort == 0 {
		return fmt.Errorf("listen-port is missing or out of range (a WireGuard tunnel requires a listen-port of 1-65535 to bind its UDP socket; the dataplane drops a tunnel whose listen-port is 0 or unparseable)")
	}
	// Validate the REAL key material, not the redacted Secret form
	// (#2053) — a redacted "<redacted>" string would never be 64 hex and
	// would false-reject. The error deliberately does NOT echo the key
	// (unlike the peer PUBLIC key below): the private key is secret.
	if !isWireguardKeyHex(tc.WgLocalPrivkeyHex.Reveal()) {
		return fmt.Errorf("private-key is invalid or missing (expected 64 hex chars / 32-byte X25519 private key; the dataplane drops a tunnel whose private-key does not decode)")
	}
	if len(tc.WgPeers) == 0 {
		return fmt.Errorf("tunnel has no peer (a peerless WireGuard tunnel can never handshake; configure at least one `peer <public-key>`)")
	}
	seen := make(map[string]struct{}, len(tc.WgPeers))
	// Cryptokey routing table is a prefix->peer map; an exact-duplicate
	// prefix on two peers has no longest-prefix winner, so the engine LPM
	// resolves it by insertion order and silently strips the loser's
	// routing (#2445). Key by canonical masked CIDR (network address +
	// length + family) so host-bit and zero-compression spelling
	// differences (10.0.0.5/24 vs 10.0.0.0/24, ::1/64 vs ::/64) compare
	// equal; value is the owning peer's pubkey for the error message.
	prefixOwner := make(map[string]string)
	var endpointFamilyV6 *bool
	for i, p := range tc.WgPeers {
		if !isWireguardKeyHex(p.PublicKeyHex) {
			return fmt.Errorf("peer %d has an invalid public key (expected 64 hex chars / 32-byte X25519, got %q)", i, p.PublicKeyHex)
		}
		if _, dup := seen[p.PublicKeyHex]; dup {
			return fmt.Errorf("duplicate peer public key %q (each peer on a WireGuard tunnel must have a unique public key)", p.PublicKeyHex)
		}
		seen[p.PublicKeyHex] = struct{}{}

		if p.PresharedKeyHex != "" && !isWireguardKeyHex(string(p.PresharedKeyHex)) {
			return fmt.Errorf("peer %q has an invalid preshared key (expected 64 hex chars / 32 bytes)", p.PublicKeyHex)
		}

		if p.Endpoint != "" {
			fam, err := endpointFamily(p.Endpoint)
			if err != nil {
				return fmt.Errorf("peer %q has an invalid endpoint %q: %w", p.PublicKeyHex, p.Endpoint, err)
			}
			// #7158: a HOSTNAME endpoint returns nil and does not participate
			// in this gate. Its family is not knowable at commit, and a guess
			// would be wrong in both directions: assuming v4 rejects a valid
			// dual-stack config, and assuming "matches whatever is there"
			// accepts a config that cannot work.
			//
			// This preserves the gate exactly for every config that reached it
			// before. Hostnames were a hard reject until now, so no previously
			// ACCEPTED config gains a peer here and no previously REJECTED
			// mixed-literal config starts passing — the literals still pin the
			// family between themselves.
			//
			// The family a hostname actually resolves to is enforced where it
			// becomes knowable: the control thread's resolver keeps only
			// answers matching the interface socket's family, and counts the
			// ones it discards, so a name that resolves to the wrong family is
			// visible rather than a silent no-initiate.
			//
			// NOT `continue`: this block sits inside the per-peer loop, above
			// the allowed-ips validation, so skipping the rest of the iteration
			// would exempt every hostname-endpoint peer from the malformed-CIDR
			// and duplicate-prefix gates — commit-clean, then dropped at
			// hydrate, which is the silent-degradation shape this whole
			// validator exists to prevent.
			if fam != nil {
				if endpointFamilyV6 == nil {
					endpointFamilyV6 = fam
				} else if *endpointFamilyV6 != *fam {
					return fmt.Errorf("peers declare endpoints of mixed address family; a WireGuard interface binds one UDP socket, so all endpoint-bearing peers must use the same outer family (IPv4 or IPv6)")
				}
			}
		}

		for _, cidr := range p.AllowedIPs {
			// #5194 A3-b3-F6: reject a MALFORMED allowed-ips prefix at commit.
			// The Rust hydrate (forwarding_build/tunnels.rs) parses each entry
			// with ipnet::IpNet and `Err(_) => continue`, silently dropping a
			// malformed prefix while KEEPING the peer — an all-malformed list
			// yields an empty AllowedIPs set (a peer that routes nothing) with no
			// diagnostic. Parse every entry here so the commit-accept set never
			// exceeds the runtime-hydrate set; the lenient path downgrades this to
			// a warning via emit() (the caller wraps validateOneWireguardTunnel).
			if _, perr := netip.ParsePrefix(cidr); perr != nil {
				return fmt.Errorf("peer %q has a malformed allowed-ips prefix %q: %v (expected CIDR like 10.0.0.0/24 or 2001:db8::/48)", p.PublicKeyHex, cidr, perr)
			}
			canon := canonicalAllowedIPPrefix(cidr)
			if owner, dup := prefixOwner[canon]; dup && owner != p.PublicKeyHex {
				return fmt.Errorf("allowed-ips prefix %s is claimed by two peers (%q and %q); the cryptokey routing table maps a prefix to exactly one peer, so an exact-duplicate prefix has no longest-prefix winner and silently strips one peer's route — give each peer distinct allowed-ips", canon, owner, p.PublicKeyHex)
			}
			// First claimant wins the map entry; a same-peer repeat (the
			// engine dedups exact entries per peer) is harmless and not a
			// conflict.
			if _, exists := prefixOwner[canon]; !exists {
				prefixOwner[canon] = p.PublicKeyHex
			}
		}
	}
	return nil
}

// canonicalAllowedIPPrefix returns a comparison key for a WireGuard
// AllowedIPs prefix. A parseable CIDR is reduced to its canonical masked
// form (network address + prefix length) so two prefixes that denote the
// same cryptokey-routing entry compare equal regardless of host-bit
// spelling or IPv6 zero-compression (10.0.0.5/24 == 10.0.0.0/24,
// 2001:db8::1/32 == 2001:db8::/32). An unparseable string is keyed
// verbatim; an exact verbatim repeat still surfaces as a duplicate here.
//
// #5194 A3-b3-F6: malformed prefixes are now REJECTED at strict commit (and
// warned on tolerant load) by the netip.ParsePrefix gate in
// validateOneWireguardTunnel, so on the strict path an unparseable string never
// reaches this key builder. The verbatim fallback therefore only matters on the
// tolerant load path, where a malformed entry survives as a warning; keying it
// verbatim keeps the same-prefix dedup working there too.
func canonicalAllowedIPPrefix(cidr string) string {
	if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
		return ipNet.String()
	}
	return cidr
}

// isWireguardKeyHex reports whether s is exactly 64 hex characters (a
// 32-byte WireGuard X25519 key). Matches the Rust decode_wg_key_hex
// gate so the commit reject and the dataplane hydrate agree.
func isWireguardKeyHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// endpointFamily validates a WireGuard peer endpoint and classifies its outer
// address family. The endpoint MUST be a `host:port` (IPv6 as `[addr]:port`)
// with a numeric UDP port in 1..65535. The host may be an IP literal or a DNS
// hostname.
//
// The return is nil for a hostname, whose family is not knowable at commit —
// see the mixed-family gate at the call site for why that is the correct
// answer rather than a guess.
//
// # Why the port rules stay strict (#5182)
//
// The pre-#7158 gate additionally required an IP LITERAL, to uphold: every
// endpoint the strict commit ACCEPTS hydrates to a real `SocketAddr` with the
// authored port and can therefore INITIATE. That invariant is preserved, not
// relaxed — it is restated in terms of the time of USE rather than the time of
// commit: an accepted endpoint resolves to a `SocketAddr` when the WireGuard
// control thread comes to initiate. What is dropped is only the claim that the
// address is knowable at commit, which was never true for a DDNS peer.
//
// The port half is unchanged and still strict, because it IS knowable at
// commit: a port-less or zero-port endpoint can never initiate no matter what
// DNS returns. Before the lexer preserved the bracketed `[v6]:port` token, a v6
// endpoint arrived port-stripped and had to be accepted as a bare IP — that
// leniency is what silently degraded every IPv6 peer to responder-only.
//
// # Why this does NOT resolve
//
// Deliberately no DNS lookup here. Two independent reasons, either sufficient:
//
//   - A commit is a config transaction. A lookup in it is a blocking network
//     call whose latency is an unreachable resolver's timeout, so a broken
//     resolver would hang commits — including the commit that would FIX the
//     resolver.
//   - Resolving at commit and caching the answer is wrong even when it works.
//     A DDNS endpoint changes; that is the entire reason for using one. A
//     commit-time answer is correct at commit and silently stale a day later,
//     which is a worse failure than not resolving, because it looks configured.
//
// So the address is resolved where it is used, by the WireGuard control
// thread's resolver, and re-resolved on a bounded schedule.
func endpointFamily(endpoint string) (*bool, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("must be host:port (IPv6 as [addr]:port): %w", err)
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("UDP port %q is not a number in 1..65535", portStr)
	}
	if ip := net.ParseIP(host); ip != nil {
		v6 := ip.To4() == nil
		return &v6, nil
	}
	if !isDNSHostname(host) {
		return nil, fmt.Errorf("host %q is neither an IP literal nor a valid DNS hostname", host)
	}
	return nil, nil
}

// isDNSHostname reports whether s is a syntactically valid DNS hostname
// (RFC 1123): 1..253 characters, dot-separated labels of 1..63 characters,
// each label alphanumeric-or-hyphen and not starting or ending with a hyphen.
//
// Syntax only, on purpose. This must not consult DNS — see endpointFamily.
// It exists so an obvious typo (an empty label, a space, a stray bracket) is
// still a commit error rather than a peer that can never initiate and whose
// only symptom is a resolver counter.
//
// A single trailing dot (the fully-qualified form) is accepted and normalized
// away before the label walk; Go's resolver accepts it, so rejecting it here
// would refuse a name the dataplane can in fact use.
func isDNSHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}
	// A name consisting only of digits and dots is a malformed IP literal, not
	// a hostname: net.ParseIP already rejected it, and treating it as a name
	// would accept "10.0.0.999:51820" as a DDNS endpoint and defer a certain
	// failure to the resolver.
	allDigitsAndDots := true
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			allDigitsAndDots = false
			break
		}
	}
	if allDigitsAndDots {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c >= '0' && c <= '9':
			case c == '-':
			default:
				return false
			}
		}
	}
	return true
}
