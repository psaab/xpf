package config

import (
	"fmt"
	"sort"
)

// TunnelEndpointName pairs the unit-qualified tunnel endpoint name the
// dataplane snapshot builder would emit with the matching TunnelConfig.
//
// The Name is the CANONICAL "%s.%d" (or bare interface) ref keyed by the
// builder's per-interface emission rules; the Tunnel is the same
// *TunnelConfig the builder reads to populate the snapshot row. The
// builder consumes the {Name, Tunnel} set, intersects it with the runtime
// InterfaceSnapshot rows, and applies the usedIDs collision drop — none of
// which this emitter does. The commit-time collision gate
// (validateTunnelEndpointIDCollisionAST) uses only the Name field.
type TunnelEndpointName struct {
	Name   string
	Tunnel *TunnelConfig
}

// EmitTunnelEndpointNames is the single source of truth for the set of
// CONFIGURED tunnel endpoints the dataplane snapshot builder
// (buildTunnelEndpointSnapshots) would emit from a typed, already-expanded
// *Config. It is a pure function of the typed config:
//
//   - it does NOT consult runtime InterfaceSnapshot rows (those do not
//     exist at commit time);
//   - it does NOT apply the StableTunnelEndpointID usedIDs collision drop
//     (the builder owns that fail-closed belt);
//   - it applies the same non-WireGuard source/destination gate the
//     builder's addEndpoint applies (drop a non-WG tunnel with empty
//     Source or Destination);
//   - it applies the same interface-level-WireGuard single-lowest-unit
//     pick (#1910): one persistent TUN per interface-level WG tunnel, keyed
//     by the lowest configured unit ref;
//   - for a non-WireGuard interface that carries BOTH an interface-level
//     tunnel and per-unit tunnel stanzas, it emits each unit's OWN
//     TunnelConfig — key, source/destination endpoint, TTL, and
//     routing-instance — instead of the interface-level object, so per-unit
//     GRE/IPIP overrides survive the emit (#5635); a unit with no tunnel
//     stanza inherits the interface-level tunnel unchanged;
//   - it formats every ref as the canonical "%s.%d" the builder formats
//     from the int-keyed Units map (leading-zero / overflow / last-wins
//     unit canonicalization is already resolved by compileInterfaces when
//     it built the int-keyed map, so it is inherited for free).
//
// The result is sorted by Name for deterministic iteration. The collision
// gate's per-node views (View 2 / View 3) feed an expanded candidate
// through compileInterfaces into a throwaway InterfacesConfig and then
// through this emitter, so the gate sees exactly the names the builder
// would publish — without ever calling CompileConfig* (which would recurse
// into the gate) and without consulting the post-usedIDs snapshot.
//
// buildTunnelEndpointSnapshots is refactored to source its configured-name
// set from this emitter; a differential parity test
// (TestEmitTunnelEndpointNamesMatchesBuilder) pins the two to one another
// so the gate and the builder can never drift (#1910 r2-r6 drift class).
func EmitTunnelEndpointNames(cfg *Config) []TunnelEndpointName {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	ifaceNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifaceNames = append(ifaceNames, name)
	}
	sort.Strings(ifaceNames)

	out := make([]TunnelEndpointName, 0)
	add := func(name string, tunnel *TunnelConfig) {
		if tunnel == nil {
			return
		}
		// Mirror addEndpoint's non-WG source/destination gate: a
		// non-WireGuard tunnel without both endpoints is never emitted.
		// WireGuard carries its peer in WgEndpoint and needs no
		// Source/Destination (#1432 S2a).
		//
		// #9156: the predicate is shared with the ROUTING side's
		// collectAppliedTunnels, which used to screen on Source alone (and on
		// nothing at all for per-unit tunnels). The two disagreeing is what let
		// a destination-less tunnel be created and brought up while this
		// emitter gave the dataplane no endpoint for it.
		if !TunnelHasUsableEndpoints(tunnel) {
			return
		}
		out = append(out, TunnelEndpointName{Name: name, Tunnel: tunnel})
	}

	for _, name := range ifaceNames {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if iface.Tunnel != nil {
			if len(iface.Units) == 0 {
				// #9899 P2: an interface that authored units but kept none
				// had every unit quarantined on the lenient path — it is not
				// unitless, so the bare-name fallback must not activate.
				if iface.AuthoredUnits {
					continue
				}
				add(name, iface.Tunnel)
				continue
			}
			unitNums := make([]int, 0, len(iface.Units))
			for unitNum := range iface.Units {
				unitNums = append(unitNums, unitNum)
			}
			sort.Ints(unitNums)
			if iface.Tunnel.Mode == "wireguard" {
				// Interface-level WireGuard is ONE persistent TUN; the
				// builder emits exactly one endpoint keyed by the lowest
				// configured unit ref (#1910). Mirror that here.
				//
				// #7786: that single endpoint carries the MERGED peer set,
				// not the interface-level object's peers alone. A unit's own
				// tunnel stanza under an interface-level WireGuard holds
				// per-unit PEERS, and this branch used to discard every
				// per-unit TunnelConfig — so a peer authored under a unit was
				// compiled, deep-copied (#3898) and validated, and then never
				// reached the dataplane, because tunnels.go builds WgPeers
				// from the emitted endpoint's TunnelConfig and that is the
				// only config->dataplane path for them. The non-WireGuard
				// branch below already emits the unit's own TunnelConfig for
				// exactly this reason (#5635); this is the same decision
				// applied to the branch that skipped it, in the form the
				// one-TUN model allows.
				add(fmt.Sprintf("%s.%d", name, unitNums[0]),
					mergeWireguardUnitPeers(iface, unitNums))
				continue
			}
			for _, unitNum := range unitNums {
				// #5635: a unit that carries its OWN tunnel stanza holds
				// the per-unit GRE/IPIP overrides — key, source/destination
				// endpoint, TTL, and routing-instance — that the compiler
				// cloned from the interface-level tunnel and then applied on
				// top of (compiler_interfaces.go: cloneForUnit + the
				// unit-level tunnel parse). Emit that per-unit TunnelConfig,
				// NOT the interface-level object, so the dataplane snapshot
				// builder (buildTunnelEndpointSnapshots) and the commit-time
				// collision gate see the unit's real endpoint instead of the
				// interface-level defaults. A unit with no tunnel stanza
				// (unit.Tunnel == nil) still inherits the interface-level
				// tunnel unchanged.
				tunnel := iface.Tunnel
				if unit := iface.Units[unitNum]; unit != nil && unit.Tunnel != nil {
					tunnel = unit.Tunnel
				}
				add(fmt.Sprintf("%s.%d", name, unitNum), tunnel)
			}
			continue
		}
		if len(iface.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			add(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
		}
	}
	return out
}

// mergeWireguardUnitPeers returns the TunnelConfig for the single endpoint an
// interface-level WireGuard interface emits: the interface-level object, with
// every unit's peers merged in (#7786).
//
// WHY MERGE RATHER THAN EMIT PER UNIT. TunnelConfig documents the model this
// follows (types_routing.go): WgListenPort and WgLocalPrivkeyHex are
// TUNNEL-level -- "one kernel UDP socket, one local identity per WG interface"
// -- while WgPeers is the per-peer set. So a unit's peers are additive to the
// one interface, and emitting a second endpoint per unit would put two
// endpoints on one listen port and one private key. Nothing would catch that:
// two WireGuard tunnels sharing a listen port compile without complaint today
// and WireGuardListenPorts() simply de-duplicates them. A unit that overrides
// the port or the key is a different local identity and is refused at commit
// instead (compiler_validate_wireguard.go), so it never reaches here.
//
// Within each per-unit tunnel, the peer set cannot conflict on the strict
// path: validateOneWireguardTunnel rejects duplicate public keys. The
// merged-view validator separately rejects a key authored by two different
// units before this first-wins deduplication runs. On the lenient path, a
// warning may permit this function to retain its first-wins behavior, making
// the warning the operator-visible signal for the dropped routing intent.
// De-duplication by pubkey is therefore total on the strict path, while this
// function remains deliberately defensive for tolerant loads.
//
// The result is sorted by pubkey. Iteration here is already deterministic
// (unitNums is sorted, and peers keep their authored order within a unit), and
// the snapshot builder sorts by pubkey again before serializing, which is what
// actually pins the #1434 5.4 byte-identical-across-HA-nodes property. Sorting
// here buys the same determinism for the OTHER consumers of this emitter --
// the strict-tunnel validators and the endpoint-collision gate read
// ep.Tunnel.WgPeers directly and never see the builder's sort.
//
// Returns the interface-level object UNCHANGED, same pointer, when no unit
// contributes a peer. That keeps the overwhelmingly common WireGuard config
// allocation-free through this path and leaves every existing endpoint
// byte-identical.
func mergeWireguardUnitPeers(iface *InterfaceConfig, unitNums []int) *TunnelConfig {
	contributes := false
	for _, unitNum := range unitNums {
		unit := iface.Units[unitNum]
		if unit != nil && unit.Tunnel != nil && len(unit.Tunnel.WgPeers) > 0 {
			contributes = true
			break
		}
	}
	if !contributes {
		return iface.Tunnel
	}

	// cloneForUnit is the audited deep copy (#3898): a plain struct copy would
	// share the parent's WgPeers backing array, so appending here would write
	// into the interface-level tunnel every sibling also reads. The name is
	// preserved -- this endpoint is still the interface-level device.
	merged := iface.Tunnel.cloneForUnit(iface.Tunnel.Name)
	seen := make(map[string]bool, len(merged.WgPeers))
	for _, p := range merged.WgPeers {
		seen[p.PublicKeyHex] = true
	}
	for _, unitNum := range unitNums {
		unit := iface.Units[unitNum]
		if unit == nil || unit.Tunnel == nil {
			continue
		}
		for _, p := range unit.Tunnel.WgPeers {
			if seen[p.PublicKeyHex] {
				continue
			}
			seen[p.PublicKeyHex] = true
			cp := p
			if p.AllowedIPs != nil {
				cp.AllowedIPs = append([]string(nil), p.AllowedIPs...)
			}
			merged.WgPeers = append(merged.WgPeers, cp)
		}
	}
	sort.Slice(merged.WgPeers, func(i, j int) bool {
		return merged.WgPeers[i].PublicKeyHex < merged.WgPeers[j].PublicKeyHex
	})
	return merged
}
