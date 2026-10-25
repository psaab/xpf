package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/ipsecname"
)

// validateIPsecSANameCollisionsStrict rejects a config in which two IPsec VPNs render the same
// swanctl SA name (#9624).
//
// The renderer keeps child names unique only WITHIN one VPN (#5122). Across VPNs, two
// ordinary-looking configs render one name twice:
//   - VPN `a` with selector `b-c`, and VPN `a-b` with selector `c`, both render child `a-b-c`;
//   - VPN `blue` with selector `red` renders child `blue-red`, and VPN `blue-red` with no
//     selector renders connection `blue-red` and child `blue-red`.
//
// `swanctl --initiate --child <name>` identifies a child by name alone, so xpf cannot say which
// tunnel strongSwan brings up. `swanctl --list-sas` reports the same name for SAs of different
// VPNs, so HA IPsec SA sync publishes a string that identifies no single tunnel. The #9511
// attribution then re-initiates such a name only on a node owning every candidate's redundancy
// group, so on a per-RG failover the tunnel can stay down until the remote initiates.
//
// The names come from ipsecname.SANames, the same derivation the renderer's
// effectiveTrafficSelectors uses, so the gate checks exactly what renders. Every configured VPN
// takes part, including one the renderer would skip: the commit-time gates already reject most
// skip causes, and a collision with a skipped VPN is still one rename away from a real one.
func validateIPsecSANameCollisionsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	vpns := cfg.Security.IPsec.VPNs
	vpnNames := make([]string, 0, len(vpns))
	for name := range vpns {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)

	owners := make(map[string][]string)
	for _, vpn := range vpnNames {
		var selectors []string
		if v := vpns[vpn]; v != nil {
			for sel := range v.TrafficSelectors {
				selectors = append(selectors, sel)
			}
		}
		for _, sa := range ipsecname.SANames(vpn, selectors) {
			owners[sa] = append(owners[sa], vpn)
		}
	}

	saNames := make([]string, 0, len(owners))
	for sa := range owners {
		saNames = append(saNames, sa)
	}
	sort.Strings(saNames)
	for _, sa := range saNames {
		if len(owners[sa]) < 2 {
			continue
		}
		quoted := make([]string, len(owners[sa]))
		for i, vpn := range owners[sa] {
			quoted[i] = fmt.Sprintf("%q", vpn)
		}
		return fmt.Errorf("security ipsec vpns %s all render the swanctl SA name %q: swanctl "+
			"identifies a child SA by name alone, so it cannot tell these tunnels apart and HA "+
			"failover could re-initiate the wrong one or none; rename a VPN or a traffic-selector",
			strings.Join(quoted, ", "), sa)
	}
	return nil
}

// validateIPsecGatewayNameCollisionStrict rejects a config in which a
// VPN with an inline/empty endpoint (no gateway object) has the same
// (sanitized) name as a gateway object that at least one other VPN
// references (#16676, R3-A16-01).
//
// Since #15024 a VPN referencing a defined gateway renders under the
// gateway name, while an inline VPN renders under its own name. Both
// share one swanctl connection namespace. When an inline VPN named
// "siteA" coexists with gateway "siteA" referenced by VPN "zzz", the
// two would fold into one connection "siteA": the first sorted member
// supplies remote_addrs/auth/proposals and the other's peer is dropped
// silently, so its children (including the st0 if_id) negotiate with
// the wrong peer. The render belt (gatewayKeyFor's "inline-" prefix
// in pkg/ipsec) separates them by construction on tolerant load; this
// gate makes strict commit reject the ambiguous naming so the
// operator renames one object. VPNs sharing the SAME gateway object
// intentionally share a connection (#15024) and are not rejected; a
// gateway object no VPN references, and a VPN whose name equals its
// OWN referenced gateway, fold with no second peer and are accepted.
func validateIPsecGatewayNameCollisionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ipsec := &cfg.Security.IPsec
	if len(ipsec.VPNs) == 0 || len(ipsec.Gateways) == 0 {
		return nil
	}
	// Gateway names (sanitized, as rendered) referenced as a gateway
	// object by at least one VPN.
	referenced := make(map[string]string) // sanitized gateway name -> gateway name
	for _, vpn := range ipsec.VPNs {
		if vpn == nil || vpn.Gateway == "" {
			continue
		}
		if _, ok := ipsec.Gateways[vpn.Gateway]; ok {
			referenced[ipsecname.SwanctlValue(vpn.Gateway)] = vpn.Gateway
		}
	}
	if len(referenced) == 0 {
		return nil
	}
	names := make([]string, 0, len(ipsec.VPNs))
	for name := range ipsec.VPNs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		vpn := ipsec.VPNs[name]
		if vpn == nil {
			continue
		}
		// Named-gateway VPNs intentionally share their gateway's
		// connection; only inline/empty (non-gateway-object) VPNs
		// key by their own name and can fold into it.
		if vpn.Gateway != "" {
			if _, ok := ipsec.Gateways[vpn.Gateway]; ok {
				continue
			}
		}
		key := ipsecname.SwanctlValue(name)
		if gwName, clash := referenced[key]; clash {
			return fmt.Errorf("security ipsec vpn %q has an inline ike gateway endpoint but its name "+
				"collides with ike gateway %q referenced by another vpn: both would render as the "+
				"single swanctl connection %q, so one peer would be dropped and its traffic "+
				"negotiated with the wrong peer — rename the vpn or the gateway (#16676)",
				name, gwName, key)
		}
	}
	return nil
}
