package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// parseDHGroup converts a Junos/vSRX dh-group value to its numeric
// Diffie-Hellman group. It accepts both the prefixed Junos spelling
// ("group14", "group19") and a bare number ("14"). TrimPrefix leaves a
// bare number unchanged, so a single Atoi handles both forms. The ok
// return is false when the value does not parse, leaving the caller's
// DHGroup at its zero value.
//
// This is the single source of truth for dh-group parsing across the
// Phase 1 IKE proposal, the Phase 2 ESP proposal, and the PFS keys
// stanza so the three sites cannot drift (#2639: the Phase 2 site used a
// bare strconv.Atoi and silently dropped "group14", leaving the ESP
// proposal with no PFS group).
func parseDHGroup(v string) (int, bool) {
	g := strings.TrimPrefix(v, "group")
	if n, err := strconv.Atoi(g); err == nil {
		return n, true
	}
	return 0, false
}

// classifyDHGroup maps a raw `dh-group` / `keys` token to its compiled form
// (#9919 F-161). It returns the numeric group to STORE plus the InvalidSpec
// to record; exactly one of them is non-zero/non-empty:
//   - spellable group ("14", "group19") -> (n, "")
//   - unparseable ("nonsense"), unspellable numeric ("99", "17", "0", "-5"),
//     or present-but-empty ("") -> (0, raw) with "(empty)" for "".
//
// Storing only spellable numerics (and recording everything else) mirrors the
// #9008 lifetime floor (store only n>=1): a stored DHGroup is always valid
// or absent, so downstream cannot silently drop a term it cannot see. The
// "(empty)" marker exists because the case arm firing with an empty value
// means the leaf was AUTHORED empty (a typo like bare `keys;`, reachable per
// #8845) — distinct from the leaf being absent, where this is never called.
func classifyDHGroup(v string) (int, string) {
	if n, ok := parseDHGroup(v); ok {
		if _, spellable := DHGroupKeyword(n); spellable {
			return n, ""
		}
	}
	if v == "" {
		return 0, "(empty)"
	}
	return 0, v
}

func compileIKE(node *Node, sec *SecurityConfig) error {
	if sec.IPsec.IKEProposals == nil {
		sec.IPsec.IKEProposals = make(map[string]*IKEProposal)
	}
	if sec.IPsec.IKEPolicies == nil {
		sec.IPsec.IKEPolicies = make(map[string]*IKEPolicy)
	}
	if sec.IPsec.Gateways == nil {
		sec.IPsec.Gateways = make(map[string]*IPsecGateway)
	}

	// IKE proposals (Phase 1 crypto)
	for _, inst := range namedInstances(node.FindChildren("proposal")) {
		prop := &IKEProposal{Name: inst.name}
		// #8939: a flat run drops every leaf after the first, so
		// `authentication-algorithm sha1 authentication-method pre-shared-keys
		// dh-group group14` compiles to the algorithm alone -- no DH group and
		// no authentication method, i.e. phase-1 crypto selected by default
		// rather than by the operator.
		for _, p := range expandFlatRun(inst.node.Children, securityNamedLeafSchema8939(node, "proposal")) {
			v := nodeVal(p)
			switch p.Name() {
			case "authentication-method":
				prop.AuthMethod = v
			case "encryption-algorithm":
				prop.EncryptionAlg = v
			case "authentication-algorithm":
				prop.AuthAlg = v
			case "dh-group":
				// #9919 F-161: store only a spellable group; record anything
				// else (unparseable, unlisted numeric, empty) for the
				// validator to reject/warn and the renderer to skip. A bare
				// Atoi-store silently dropped the modp term (#2639 shape).
				n, bad := classifyDHGroup(v)
				prop.DHGroup, prop.DHGroupInvalidSpec = n, bad
			case "lifetime-seconds":
				// #9008: RECORD a value that is not a usable positive
				// integer instead of dropping it on the floor. Atoi
				// failure leaves the field at 0 (indistinguishable from
				// "not configured") and a NEGATIVE parses cleanly and
				// would otherwise be stored and rendered, so neither case
				// is recoverable downstream from the int alone. The floor
				// mirrors the schema's ValidateIntegerMin(1) on this leaf
				// so the tolerant path warns exactly where the strict
				// commit gate rejects.
				if n, err := strconv.Atoi(v); err == nil && n >= 1 {
					prop.LifetimeSeconds = n
				} else if v != "" {
					prop.LifetimeSecondsInvalidSpec = v
				}
			}
		}
		sec.IPsec.IKEProposals[prop.Name] = prop
	}

	// IKE policies (Phase 1 mode + PSK + proposal ref)
	for _, inst := range namedInstances(node.FindChildren("policy")) {
		// #8436: FIND-OR-CREATE, not construct-and-overwrite.
		//
		// A fresh struct per block plus `IKEPolicies[name] = pol` below is
		// last-wins-with-a-whole-wipe: two `policy P { ... }` blocks in a
		// hierarchical config file silently discard everything the first one
		// carried — mode, PSK, proposals. The #8436 census classifies this site
		// as SILENT, meaning configuration the operator authored is lost with
		// no commit error.
		//
		// Find-or-create is the disposition the census names as the correct one
		// (it is what dhcp-relay already does), and it makes the hierarchical
		// spelling agree with the flat-set spelling, which merges. That
		// agreement is the conservation property #8436 asks to be bound rather
		// than another per-container registry row.
		//
		// Reachable only through a hierarchical config file, `load merge` or
		// `load override` — flat `set` merges correctly today.
		pol := sec.IPsec.IKEPolicies[inst.name]
		if pol == nil {
			pol = &IKEPolicy{Name: inst.name}
		}
		for _, p := range expandFlatRun(inst.node.Children, securityNamedLeafSchema8939(node, "policy")) {
			v := nodeVal(p)
			switch p.Name() {
			case "mode":
				pol.Mode = v
			case "proposal-set":
				// #4297 (V-1): predefined proposal-set shorthand. Captured
				// here and expanded into concrete synthetic proposals after
				// both the proposal and policy maps are built
				// (expandIKEProposalSets), so the common vSRX idiom commits a
				// working tunnel instead of being silently dropped.
				pol.ProposalSet = v
			case "proposals":
				// Multi-value leaf (#3904): `proposals [ p1 p2 ]` collapses
				// onto Keys[1:] (hierarchical / clean flat-set) and/or child
				// nodes (declared-leaf flat-set split). Read EVERY reference
				// via firewallMatchValues; reading only Keys[1] (nodeVal)
				// dropped all but the first, narrowing phase-1 negotiation.
				pol.Proposals = append(pol.Proposals, firewallMatchValues(p)...)
			case "pre-shared-key":
				// "pre-shared-key ascii-text VALUE" or children
				if len(p.Keys) >= 3 {
					pol.PSK = Secret(p.Keys[2])
				} else {
					for _, c := range p.Children {
						if c.Name() == "ascii-text" {
							pol.PSK = Secret(nodeVal(c))
						}
					}
				}
			}
		}
		sec.IPsec.IKEPolicies[pol.Name] = pol
	}

	// #4297 (V-1): expand any predefined IKE proposal-set into concrete
	// synthetic proposals now that both the proposal and policy maps exist.
	expandIKEProposalSets(sec)

	// IKE gateways
	for _, inst := range namedInstances(node.FindChildren("gateway")) {
		gw := sec.IPsec.Gateways[inst.name]
		if gw == nil {
			gw = &IPsecGateway{Name: inst.name}
		}
		for _, p := range expandFlatRun(inst.node.Children, gatewayLeafSchema8939(node)) {
			v := nodeVal(p)
			switch p.Name() {
			case "address":
				if v != "" {
					gw.Address = v
				}
			case "local-address":
				if v != "" {
					gw.LocalAddress = v
				}
			case "ike-policy":
				if v != "" {
					gw.IKEPolicy = v
				}
			case "external-interface":
				if v != "" {
					gw.ExternalIface = v
				}
			case "local-certificate":
				if v != "" {
					gw.LocalCertificate = v
				}
			case "version":
				if v != "" {
					gw.Version = v
				}
			case "no-nat-traversal":
				gw.NoNATTraversal = true
				gw.NATTraversal = "disable"
			case "nat-traversal":
				if v != "" {
					gw.NATTraversal = v
				}
				if v == "disable" {
					gw.NoNATTraversal = true
				}
			case "dead-peer-detection":
				parseDeadPeerDetectionNode(p, gw, resolveSchemaChild(gatewayLeafSchema8939(node), "dead-peer-detection"))
			case "local-identity":
				if len(p.Keys) >= 3 {
					gw.LocalIDType = p.Keys[1]
					gw.LocalIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.LocalIDType = c.Name()
						gw.LocalIDValue = nodeVal(c)
					}
				}
			case "remote-identity":
				if len(p.Keys) >= 3 {
					gw.RemoteIDType = p.Keys[1]
					gw.RemoteIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.RemoteIDType = c.Name()
						gw.RemoteIDValue = nodeVal(c)
					}
				}
			case "dynamic":
				// "dynamic hostname FQDN" or children. A `dynamic` block
				// with no hostname marks a responder-only / dynamic-IP peer
				// (remote_addrs = %any) — see the IPsec-stanza copy below
				// and resolveRemoteAddr (#2404).
				if len(p.Keys) >= 3 && p.Keys[1] == "hostname" {
					gw.DynamicHostname = p.Keys[2]
					// #3332: compact-hierarchical `dynamic hostname <fqdn>
					// <extra>` collapses onto the parent's Keys; the FQDN is a
					// single token at Keys[2], so Keys[3:] is operator garbage
					// the compiler silently dropped. Record it for the strict
					// trailing-token gate.
					if len(p.Keys) > 3 {
						gw.DynamicHostnameExtras = append(gw.DynamicHostnameExtras, p.Keys[3:]...)
					}
				} else {
					for _, c := range p.Children {
						if c.Name() == "hostname" && len(c.Keys) >= 2 {
							gw.DynamicHostname = c.Keys[1]
						}
					}
				}
				if gw.DynamicHostname == "" {
					gw.ResponderOnly = true
				}
			}
		}
		sec.IPsec.Gateways[gw.Name] = gw
	}

	return nil
}

// parseDeadPeerDetectionNode compiles a `dead-peer-detection` stanza on an IKE
// gateway. The presence of the stanza — in ANY form — enables DPD (#3994):
//
//   - bare `dead-peer-detection;`            → enable with Junos defaults
//   - `dead-peer-detection interval <n>;`    → enable + tune the probe interval
//   - `dead-peer-detection threshold <n>;`   → enable + tune the retry count
//   - `dead-peer-detection always-send;`     → enable + explicit mode
//     (also optimized / probe-idle-tunnel)
//
// Enablement is tracked on gw.DPDEnable, independent of the mode. The previous
// implementation overloaded the DeadPeerDetect mode string as the enable flag,
// which mishandled two forms: the bare statement produced an empty mode and was
// read as DISABLED downstream, and an interval-only / threshold-only stanza let
// nodeVal() pick up the sub-field name ("interval"/"threshold") as a bogus mode
// (DPD enabled but with a mode that mapped to no dpd_action). Both forms now
// enable DPD with the mode left empty (Junos default behaviour), and only a
// real mode keyword sets DeadPeerDetect.
//
// Tokens may ride on the node's own Keys (compact-hierarchical
// `dead-peer-detection always-send` / `dead-peer-detection interval 10`) or on
// child nodes (flat-set and block forms), so both are scanned.
func parseDeadPeerDetectionNode(node *Node, gw *IPsecGateway, container *schemaNode) {
	if gw == nil || node == nil {
		return
	}

	gw.DPDEnable = true

	keys := node.Keys
	for i := 1; i < len(keys); i++ {
		switch keys[i] {
		case "always-send", "optimized", "probe-idle-tunnel":
			gw.DeadPeerDetect = keys[i]
		case "interval":
			if i+1 < len(keys) {
				if n, err := strconv.Atoi(keys[i+1]); err == nil {
					gw.DPDInterval = n
				}
				i++
			}
		case "threshold":
			if i+1 < len(keys) {
				if n, err := strconv.Atoi(keys[i+1]); err == nil {
					gw.DPDThreshold = n
				}
				i++
			}
		}
	}

	// #8939: `set … dead-peer-detection always-send interval 10 threshold 4`
	// nests ONE node under `always-send` carrying ["interval","10","threshold",
	// "4"], so the switch below saw a single child named `interval` and never
	// reached `threshold`. The keys loop above reads the HIERARCHICAL spelling
	// (`dead-peer-detection interval 10;` on one line) -- a different shape, and
	// its presence is why this site read as already-walking.
	for _, c := range expandFlatRun(node.Children, container) {
		switch c.Name() {
		case "always-send", "optimized", "probe-idle-tunnel":
			gw.DeadPeerDetect = c.Name()
		case "interval":
			if n, err := strconv.Atoi(nodeVal(c)); err == nil {
				gw.DPDInterval = n
			}
		case "threshold":
			if n, err := strconv.Atoi(nodeVal(c)); err == nil {
				gw.DPDThreshold = n
			}
		}
	}
}

func compileIPsec(node *Node, sec *SecurityConfig) error {
	if sec.IPsec.Proposals == nil {
		sec.IPsec.Proposals = make(map[string]*IPsecProposal)
	}
	if sec.IPsec.Policies == nil {
		sec.IPsec.Policies = make(map[string]*IPsecPolicyDef)
	}
	if sec.IPsec.VPNs == nil {
		sec.IPsec.VPNs = make(map[string]*IPsecVPN)
	}

	// IPsec proposals (Phase 2 crypto)
	for _, inst := range namedInstances(node.FindChildren("proposal")) {
		prop := &IPsecProposal{Name: inst.name}
		// #8939, phase 2: the same drop leaves a proposal with no
		// `encryption-algorithm` -- an ESP proposal that names no cipher.
		for _, p := range expandFlatRun(inst.node.Children, securityNamedLeafSchema8939(node, "proposal")) {
			v := nodeVal(p)
			switch p.Name() {
			case "protocol":
				prop.Protocol = v
			case "encryption-algorithm":
				prop.EncryptionAlg = v
			case "authentication-algorithm":
				prop.AuthAlg = v
			case "dh-group":
				// #9919 F-161: mirror of the Phase-1 site above — store only
				// a spellable group, record the raw token otherwise.
				n, bad := classifyDHGroup(v)
				prop.DHGroup, prop.DHGroupInvalidSpec = n, bad
			case "lifetime-seconds":
				// #9008: RECORD a value that is not a usable positive
				// integer instead of dropping it on the floor. Atoi
				// failure leaves the field at 0 (indistinguishable from
				// "not configured") and a NEGATIVE parses cleanly and
				// would otherwise be stored and rendered, so neither case
				// is recoverable downstream from the int alone. The floor
				// mirrors the schema's ValidateIntegerMin(1) on this leaf
				// so the tolerant path warns exactly where the strict
				// commit gate rejects.
				if n, err := strconv.Atoi(v); err == nil && n >= 1 {
					prop.LifetimeSeconds = n
				} else if v != "" {
					prop.LifetimeSecondsInvalidSpec = v
				}
			case "lifetime-kilobytes":
				// #4313: captured for the closed-world leaf-completeness of
				// `security ipsec proposal` and the accepted-only advisory
				// (compiler_validate_warn.go). Volume-based rekey is not yet
				// programmed into the ESP child SA, so the value is recorded
				// but not enforced.
				if n, err := strconv.Atoi(v); err == nil {
					prop.LifetimeKilobytes = n
				}
			}
		}
		sec.IPsec.Proposals[prop.Name] = prop
	}

	// IPsec policies (PFS + proposal reference)
	for _, inst := range namedInstances(node.FindChildren("policy")) {
		pol := &IPsecPolicyDef{Name: inst.name}
		// NOT expandFlatRun'd, deliberately. `security ipsec policy` declares
		// three children -- `perfect-forward-secrecy` (a CONTAINER),
		// `proposals` (MULTI) and `proposal-set` -- so exactly ONE is an
		// eligible flat-run leaf and the #8939 collector drops the container
		// as "only one eligible leaf". It has no census row and cannot have
		// one. Its packed spelling DOES lose a value in both orderings:
		//
		//   proposal-set S perfect-forward-secrecy keys G  -> PFS group lost
		//   perfect-forward-secrecy keys G proposal-set S  -> proposal-set lost
		//
		// but neither is the flat-run chain: the first needs the
		// perfect-forward-secrecy reader to accept its arg packed onto Keys
		// (the #2419/#6690 dual-shape class), and the second needs a hoist out
		// of a container leaf's body, which expandFlatRun refuses BY DESIGN.
		// Filed separately rather than smuggled in here; a call added here
		// would be inert and would read as coverage.
		for _, p := range inst.node.Children {
			switch p.Name() {
			case "proposal-set":
				// #4297 (V-1): predefined ESP proposal-set shorthand;
				// expanded after the maps are built (expandIPsecProposalSets).
				pol.ProposalSet = nodeVal(p)
			case "proposals":
				// Multi-value leaf (#3904): read EVERY ESP proposal reference
				// (Keys[1:] + child nodes) — mirror of the IKE policy loop.
				pol.Proposals = append(pol.Proposals, firewallMatchValues(p)...)
			case "perfect-forward-secrecy":
				for _, c := range p.Children {
					if c.Name() == "keys" {
						// #9919 F-161: mirror of the proposal sites — a bad
						// PFS value records InvalidSpec instead of silently
						// disabling PFS (the #8844/#8845 silent-disable).
						n, bad := classifyDHGroup(nodeVal(c))
						pol.PFSGroup, pol.PFSGroupInvalidSpec = n, bad
					}
				}
			}
		}
		sec.IPsec.Policies[pol.Name] = pol
	}

	// #4297 (V-1): expand any predefined ESP proposal-set into concrete
	// synthetic proposals now that both maps exist.
	expandIPsecProposalSets(sec)

	// Gateways (may appear under ipsec or ike)
	if sec.IPsec.Gateways == nil {
		sec.IPsec.Gateways = make(map[string]*IPsecGateway)
	}
	for _, inst := range namedInstances(node.FindChildren("gateway")) {
		gw := sec.IPsec.Gateways[inst.name]
		if gw == nil {
			gw = &IPsecGateway{Name: inst.name}
		}
		for _, p := range expandFlatRun(inst.node.Children, gatewayLeafSchema8939(node)) {
			v := nodeVal(p)
			switch p.Name() {
			case "address":
				if v != "" {
					gw.Address = v
				}
			case "local-address":
				if v != "" {
					gw.LocalAddress = v
				}
			case "ike-policy":
				if v != "" {
					gw.IKEPolicy = v
				}
			case "external-interface":
				if v != "" {
					gw.ExternalIface = v
				}
			case "local-certificate":
				if v != "" {
					gw.LocalCertificate = v
				}
			case "version":
				if v != "" {
					gw.Version = v
				}
			case "no-nat-traversal":
				gw.NoNATTraversal = true
				gw.NATTraversal = "disable"
			case "nat-traversal":
				if v != "" {
					gw.NATTraversal = v
				}
				if v == "disable" {
					gw.NoNATTraversal = true
				}
			case "dead-peer-detection":
				parseDeadPeerDetectionNode(p, gw, resolveSchemaChild(gatewayLeafSchema8939(node), "dead-peer-detection"))
			case "local-identity":
				if len(p.Keys) >= 3 {
					gw.LocalIDType = p.Keys[1]
					gw.LocalIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.LocalIDType = c.Name()
						gw.LocalIDValue = nodeVal(c)
					}
				}
			case "remote-identity":
				if len(p.Keys) >= 3 {
					gw.RemoteIDType = p.Keys[1]
					gw.RemoteIDValue = p.Keys[2]
				} else if len(p.Children) > 0 {
					for _, c := range p.Children {
						gw.RemoteIDType = c.Name()
						gw.RemoteIDValue = nodeVal(c)
					}
				}
			case "dynamic":
				// A `dynamic` block with no hostname marks a responder-only
				// / dynamic-IP peer: the peer initiates from an unknown
				// address, so the gateway carries no remote_addrs target and
				// renders remote_addrs = %any (#2404).
				if len(p.Keys) >= 3 && p.Keys[1] == "hostname" {
					gw.DynamicHostname = p.Keys[2]
					// #3332: compact-hierarchical trailing tokens past the FQDN.
					if len(p.Keys) > 3 {
						gw.DynamicHostnameExtras = append(gw.DynamicHostnameExtras, p.Keys[3:]...)
					}
				} else {
					for _, c := range p.Children {
						if c.Name() == "hostname" {
							gw.DynamicHostname = nodeVal(c)
						}
					}
				}
				if gw.DynamicHostname == "" {
					gw.ResponderOnly = true
				}
			}
		}
		sec.IPsec.Gateways[gw.Name] = gw
	}

	// VPN tunnels
	for _, inst := range namedInstances(node.FindChildren("vpn")) {
		// #8436: find-or-create, same reasoning as `security ike policy` above.
		// The census classifies this site as SILENT — two `vpn V { ... }` blocks
		// in a hierarchical config file discard everything the first carried,
		// with no commit error.
		vpn := sec.IPsec.VPNs[inst.name]
		if vpn == nil {
			vpn = &IPsecVPN{Name: inst.name}
		}
		vpnSchema := ipsecVPNLeafSchema8939()
		// #9088: segment the run against a schema that also knows the two leaves
		// the COMPILER reads here and setSchema does not declare -- `gateway`
		// and `ipsec-policy`. Without them expandFlatRun has no cut point at the
		// head of `gateway G ipsec-policy P bind-interface st0.1` and passes the
		// whole run through, so the compiler takes the first value and drops the
		// crypto policy and the XFRM binding. Both losses commit clean.
		for _, p := range expandFlatRun(inst.node.Children, ipsecVPNRunSchema9088()) {
			v := nodeVal(p)
			switch p.Name() {
			case "bind-interface":
				vpn.BindInterface = v
			case "df-bit":
				vpn.DFBit = v
			case "establish-tunnels":
				vpn.EstablishTunnels = v
			case "ike":
				// Nested ike { gateway X; ipsec-policy Y; }
				for _, c := range expandFlatRun(p.Children, resolveSchemaChild(vpnSchema, "ike")) {
					cv := nodeVal(c)
					switch c.Name() {
					case "gateway":
						vpn.Gateway = cv
					case "ipsec-policy":
						vpn.IPsecPolicy = cv
					}
				}
			case "gateway":
				vpn.Gateway = v
			case "ipsec-policy":
				vpn.IPsecPolicy = v
			case "local-identity":
				vpn.LocalID = v
			case "remote-identity":
				vpn.RemoteID = v
			case "pre-shared-key":
				vpn.PSK = Secret(v)
			case "local-address":
				vpn.LocalAddr = v
			case "manual":
				// #4300 (V-4): manual-key SA block. Captured (not compiled
				// into an SA — xpf has no manual-key path) so
				// validateIPsecManualKeyStrict rejects it at commit rather
				// than leaving a silent dead tunnel.
				vpn.Manual = true
			case "vpn-monitor":
				// #4299 (V-3): accepted-but-not-enforced. Capture the stanza
				// so ValidateConfig emits an advisory; xpf has no ICMP-probe
				// liveness / st0 interface-state coupling yet.
				vpn.VPNMonitor = true
				for _, c := range expandFlatRun(p.Children, resolveSchemaChild(vpnSchema, "vpn-monitor")) {
					switch c.Name() {
					case "source-interface":
						vpn.VPNMonitorSourceInterface = nodeVal(c)
					case "destination-ip":
						vpn.VPNMonitorDestinationIP = nodeVal(c)
					case "optimized":
						vpn.VPNMonitorOptimized = true
					}
				}
			}
		}
		for _, tsInst := range namedInstances(inst.node.FindChildren("traffic-selector")) {
			if vpn.TrafficSelectors == nil {
				vpn.TrafficSelectors = make(map[string]*IPsecTrafficSelector)
			}
			ts := &IPsecTrafficSelector{Name: tsInst.name}
			for _, p := range expandFlatRun(tsInst.node.Children, ipsecTrafficSelectorSchema8939()) {
				switch p.Name() {
				case "local-ip":
					ts.LocalIP = nodeVal(p)
				case "remote-ip":
					ts.RemoteIP = nodeVal(p)
				}
			}
			vpn.TrafficSelectors[ts.Name] = ts
		}
		sec.IPsec.VPNs[vpn.Name] = vpn
	}

	return nil
}

// validateIPsecGatewayReferencesStrict (#2074) rejects an IPsec VPN that
// references an IKE gateway which is neither a defined gateway object
// (carrying an address or dynamic hostname) nor a usable inline
// IP/hostname. Without this check, renderConfig would emit
// `remote_addrs = <gateway-name>` — a config-object name strongSwan
// cannot use — producing a silently-dead tunnel with no diagnostic.
//
// It runs on the fully-compiled *Config (the strict-validator chain in
// compileExpanded), so both `ike { gateway }` and `ipsec { gateway }`
// definitions are present in sec.IPsec.Gateways regardless of which
// stanza was authored first. The caller downgrades this to a warning on
// the tolerant load / peer-sync paths (lenientIPsecGatewayRefs) so a
// config persisted by an older binary, or synced from a peer, still
// boots; commit / commit-check stay strict.
//
// VPN names are sorted so a multi-VPN config reports a deterministic
// first failure.
func validateIPsecGatewayReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec
	if len(ipsec.VPNs) == 0 {
		return nil
	}
	names := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		vpn := ipsec.VPNs[name]
		if vpn == nil || vpn.Gateway == "" {
			// A VPN may legitimately omit the remote endpoint (the
			// generated connection simply has no remote_addrs line).
			continue
		}
		if gw, ok := ipsec.Gateways[vpn.Gateway]; ok {
			if gw.Address == "" && gw.DynamicHostname == "" && !gw.ResponderOnly {
				return fmt.Errorf("security ipsec vpn %s: ike gateway %q "+
					"has no address or dynamic hostname; the tunnel would "+
					"never establish", name, vpn.Gateway)
			}
			// A responder-only gateway (dynamic block, no address/hostname)
			// legitimately omits remote_addrs and renders %any (#2404).
			continue // resolves to a defined, addressed (or responder-only) gateway
		}
		if IsUsableIPsecEndpoint(vpn.Gateway) {
			continue // legacy inline literal IP / dotted hostname
		}
		return fmt.Errorf("security ipsec vpn %s: ike gateway %q is not "+
			"defined and is not a valid address or hostname", name, vpn.Gateway)
	}
	return nil
}

// IsUsableIPsecEndpoint reports whether s is something strongSwan can
// place in a swanctl `remote_addrs` directly: a literal IP address, or a
// plausible dotted DNS hostname / FQDN. It deliberately REJECTS a bare
// config-object name with no hostname structure (e.g. a typo'd gateway
// reference such as `gw-to-hq`), so such a name is caught at commit
// rather than DNS-probed forever at runtime (#2074).
//
// It lives in pkg/config so that both the commit-time validator
// (validateIPsecGatewayReferencesStrict, pkg/config) and the swanctl
// render belt (pkg/ipsec, which imports pkg/config) share one predicate
// with no import cycle.
func IsUsableIPsecEndpoint(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	return isPlausibleHostname(s)
}

// isPlausibleHostname reports whether s looks like a multi-label DNS
// hostname / FQDN: it must contain at least one dot (Rule A — this is
// what distinguishes an operator-supplied peer hostname from a typo'd
// single-label gateway object name), and every dot-separated label must
// be a syntactically valid host label (1-63 chars, alphanumeric with
// internal hyphens, no leading/trailing hyphen). Total length is capped
// at 253. A single trailing dot is accepted as the absolute-root marker
// of a fully qualified domain name ("vpn.example.com." — Junos accepts
// it); "..", a leading/interior empty label, and a bare "." are still
// rejected. No regexp — a manual byte scan keeps it allocation-free.
//
// The single-label-hostname limitation (a bare `vpnpeer` resolvable via
// the system resolver is rejected) is intentional and documented: define
// a proper `security ike gateway <name> { address <ip>; }` (or
// `dynamic { hostname <fqdn>; }`) instead.
func isPlausibleHostname(s string) bool {
	if len(s) == 0 {
		return false
	}
	// A single trailing dot is the absolute-root marker of a fully
	// qualified domain name (e.g. "vpn.example.com."); Junos accepts it.
	// Strip exactly one terminal dot so the label scan below treats it as
	// a valid absolute FQDN rather than a name with an empty last label.
	// A name that is only dots ("."), ends in ".." (empty last label), or
	// has a leading/interior empty label is NOT made valid by this: after
	// stripping one trailing dot the scan still rejects "", a trailing
	// dot, or any "..".
	//
	// The strip MUST precede the 253-octet presentation cap: RFC 1035 §3.1
	// counts only the labels (max 253 chars), and the absolute-root dot
	// does not consume part of that budget. A maximal 253-char FQDN written
	// in absolute form is 254 bytes including the trailing "." and is valid
	// (#2596) — capping the raw byte length first wrongly rejected it.
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
		if len(s) == 0 {
			return false // name was just "."
		}
	}
	if len(s) > 253 {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	labelLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if labelLen == 0 {
				return false // empty label (leading dot or "..")
			}
			if s[i-1] == '-' {
				return false // label ends with hyphen
			}
			labelLen = 0
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			labelLen++
		case c == '-':
			if labelLen == 0 {
				return false // label begins with hyphen
			}
			labelLen++
		default:
			return false // illegal character for a hostname
		}
		if labelLen > 63 {
			return false
		}
	}
	// Trailing label must be non-empty and not end with a hyphen.
	if labelLen == 0 {
		return false // trailing dot => empty last label
	}
	if s[len(s)-1] == '-' {
		return false
	}
	// RFC 3696 §2 / RFC 1123 §2.1: the rightmost (top-level) label of a
	// hostname must not be entirely numeric — that is the rule that
	// disambiguates a hostname from a dotted-decimal IPv4 literal. A botched
	// IP such as "10.0.0.999" fails net.ParseIP (999 > 255) yet is otherwise
	// a run of digit-only labels, so without this gate it masquerades as a
	// "plausible hostname", passes endpoint validation, and then fails to
	// resolve when strongSwan loads the generated remote_addrs — a config
	// that commits but never establishes the tunnel (#5630). Reject an
	// all-numeric last label. A valid IPv4/IPv6 literal is already accepted
	// by the net.ParseIP branch in IsUsableIPsecEndpoint before this scan is
	// reached, so real address literals are unaffected.
	lastDot := strings.LastIndexByte(s, '.')
	tld := s[lastDot+1:]
	allNumeric := true
	for i := 0; i < len(tld); i++ {
		if tld[i] < '0' || tld[i] > '9' {
			allNumeric = false
			break
		}
	}
	if allNumeric {
		return false
	}
	return true
}

// gatewayLeafSchema8939 resolves the `gateway` container under whichever
// security parent is being compiled, so expandFlatRun can tell one of its
// leaves from a value token. `security ike gateway` and `security ipsec
// gateway` are DISTINCT schema nodes with distinct leaf sets -- they share the
// IPsecGateway struct and duplicate the reader, which is why both loops need
// this rather than one of them covering the other.
func gatewayLeafSchema8939(parent *Node) *schemaNode {
	if parent == nil || len(parent.Keys) == 0 {
		return nil
	}
	sec := resolveSchemaChild(setSchema, "security")
	branch := resolveSchemaChild(sec, parent.Keys[0])
	gw := resolveSchemaChild(branch, "gateway")
	if gw == nil {
		return nil
	}
	if gw.wildcard != nil {
		return gw.wildcard
	}
	return gw
}

// ipsecVPNLeafSchema8939 resolves `security ipsec vpn <name>` so expandFlatRun
// can tell one of the VPN's own leaves from a value token.
//
// This container is NOT in the #8939 ratchet fixture and never was. The
// generator synthesizes `bind-interface ge-0/0/0` -- the alphabetically first
// eligible leaf, handed a placeholder that the #5297 secure-tunnel gate
// rejects -- so BOTH arms fail to compile and the row leaves the population as
// `unmeasured` rather than as a loser. It was found by compiling the container
// by hand.
func ipsecVPNLeafSchema8939() *schemaNode {
	sec := resolveSchemaChild(setSchema, "security")
	ipsec := resolveSchemaChild(sec, "ipsec")
	vpn := resolveSchemaChild(ipsec, "vpn")
	if vpn == nil {
		return nil
	}
	if vpn.wildcard != nil {
		return vpn.wildcard
	}
	return vpn
}

// ipsecTrafficSelectorSchema8939 resolves `security ipsec vpn <name>
// traffic-selector <name>`. Shared with the #4098/#5692 admission gate in
// compiler_ipsec_trafficselector.go, which walks the same children and needs
// the same segmentation -- fixing only the compiler would leave the packed
// spelling rejected at commit, so the fix would never be reachable.
func ipsecTrafficSelectorSchema8939() *schemaNode {
	ts := resolveSchemaChild(ipsecVPNLeafSchema8939(), "traffic-selector")
	if ts == nil {
		return nil
	}
	if ts.wildcard != nil {
		return ts.wildcard
	}
	return ts
}

// securityNamedLeafSchema8939 resolves `security <branch> <kind> <name>` for
// expandFlatRun, where branch is whichever of `ike` / `ipsec` is being
// compiled and kind is `proposal` or `policy`. The four containers are
// DISTINCT schema nodes with distinct leaf sets and four duplicated readers,
// so one helper parameterised by both is the only shape that does not invite
// a copy per site.
//
// CHANNEL, measured rather than assumed: all four are CLOSED-WORLD subtrees
// (#4313 flipped `security ipsec proposal`), so the packed spelling is
// REJECTED on the operator commit path and reaches this code only via
// Store.Load and Store.SyncApply. These are lenient-only rows; the fix is
// still worth making because a persisted or peer-synced config carries the
// truncation with nothing watching, but the operator-typed story does not
// apply and is deliberately not told here.
func securityNamedLeafSchema8939(parent *Node, kind string) *schemaNode {
	if parent == nil || len(parent.Keys) == 0 {
		return nil
	}
	sec := resolveSchemaChild(setSchema, "security")
	branch := resolveSchemaChild(sec, parent.Keys[0])
	n := resolveSchemaChild(branch, kind)
	if n == nil {
		return nil
	}
	if n.wildcard != nil {
		return n.wildcard
	}
	return n
}
