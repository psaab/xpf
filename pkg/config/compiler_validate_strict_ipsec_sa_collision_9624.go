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
