package userspace

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// The host-inbound LIFELINE matcher is the SSOT in pkg/config (lifeline.go,
// #3682) so the shared host-inbound presenter can render the exemption on the
// operator-visible zone views. These thin wrappers keep the dataplane call sites
// and the #3277 fail-on-revert tests reading against the local names while the
// matching logic (fxp0 + configured control/fabric + em0/fab* defaults) lives in
// exactly one place shared with display.

func hostInboundLifelineSet(cfg *config.Config) map[string]bool {
	return config.HostInboundLifelineSet(cfg)
}

func hostInboundLifelineInterface(name string, lifelines map[string]bool) bool {
	return config.HostInboundLifelineInterface(name, lifelines)
}

// hostIPFromCIDR returns the bare host IP of a "ip/prefix" string (or a bare
// IP). Returns "" if unparseable.
func hostIPFromCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(s); err == nil && ip != nil {
		return ip.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

// authoredZoneRefs returns the operator's LITERAL `security-zone <z> interfaces
// <ref>` bindings, expanded to every logical identity the reference SPEAKS FOR
// but never to one it does not (#6722):
//
//   - canonicalised through CanonicalInterfaceUnitRef, so ".01" and ".1" agree
//     with the snapshot's unit naming;
//   - a BARE interface reference is fanned DOWN onto that interface's configured
//     units, because in xpf `security-zone lan interfaces ge-0/0/1` MEANS "every
//     unit of ge-0/0/1 is in lan" — that is the semantics buildInterfaceZoneMap
//     defines and the ingress half has always enforced, so a unit of a bare-
//     referenced interface really is authored, not inheriting a sentence about
//     somebody else;
//   - a unit-suffixed reference is NOT fanned UP to its base. That is the
//     direction that manufactures a claim about a DIFFERENT identity: `st0.1`
//     names one unit, and writing `st0` from it says something about `st0.0`
//     (which shares the base netdev) that the operator never said.
//
// It is the PROVENANCE half of buildInterfaceZoneMap. That map derives in BOTH
// directions; only the fan-UP is a restatement of a sentence about another
// identity, and once several config identities collapse onto ONE netdev
// (`snapshotLinuxName`) such a derived entry becomes indistinguishable from an
// authored one by inspection of the result alone. stampEgressZones (the sole
// consumer of this map, in interfaces.go) needs to tell them apart, so the
// provenance is recorded here rather than
// reconstructed downstream from the outcome. Reconstructing it is exactly what
// #6722 attempted four times, and each attempt was holed by a new config shape.
//
// FAIL-ON-REVERT for the fan-down: drop it and
// TestBareInterfaceZoneRefReachesItsOwnNetdevUnits_6722 goes RED. Without it a
// unit that lands on its OWN netdev (any VLAN unit; any non-zero unit) is
// reached by NEITHER rule 2 — no authored reference names its row — NOR rule 3,
// which is skipped precisely because a unit row IS on that ifindex. The ifindex
// resolves no egress zone at all while its rows carry the operator's zone, so
// the INGRESS half attributes traffic to `lan` and the EGRESS half answers the 0
// sentinel: every transit flow out of a bare-referenced trunk's VLAN units falls
// to the default policy. origin/master answered the operator's zone there.
//
// The write policy mirrors buildInterfaceZoneMap exactly — sorted zone names,
// first-write-wins, same fan-down over the same unit set — so a reference
// claimed by two zones resolves to the SAME zone in both maps and this function
// introduces no second opinion about it.
func authoredZoneRefs(cfg *config.Config) map[string]string {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	out := make(map[string]string, len(cfg.Security.Zones))
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, rawIface := range zone.Interfaces {
			if rawIface == "" {
				continue
			}
			// #9821: resolve declared-first like the mirrors: a ref naming a
			// declared interface fans down even when dotted; a unit ref binds
			// its canonical Literal so padded spellings agree.
			s := cfg.SplitInterfaceUnitRef(rawIface)
			if _, exists := out[s.Literal]; !exists {
				out[s.Literal] = zoneName
			}
			// A unit-suffixed reference speaks for exactly that unit. Do NOT
			// write the base (that is buildInterfaceZoneMap's fan-UP, the
			// derivation this map exists to keep out).
			if s.HasUnit {
				continue
			}
			// A bare reference speaks for every configured unit of the
			// interface. Mirrors buildInterfaceZoneMap's fan-down exactly,
			// including that a present-but-nil unit slot still takes a key, so
			// the two maps hold the same references.
			if ifCfg := cfg.Interfaces.Interfaces[s.Base]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					unitName := fmt.Sprintf("%s.%d", s.Base, unitNum)
					if _, exists := out[unitName]; !exists {
						out[unitName] = zoneName
					}
				}
			}
		}
	}
	return out
}

// quarantinedZoneNames returns the zone names the StableZoneID quarantine will
// drop for this config (#6722). It reads the SAME name set quarantineCollidingZones
// does — buildZoneSnapshots publishes exactly cfg.Security.Zones — so the two
// cannot drift apart.
func quarantinedZoneNames(cfg *config.Config) map[string]struct{} {
	if cfg == nil || len(cfg.Security.Zones) < 2 {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	return config.ZoneQuarantineExclusions(names)
}

func buildInterfaceZoneMap(cfg *config.Config) map[string]string {
	// #6640: the resolution itself lives in pkg/config so the commit-time
	// advisories can reason about the SAME object this builder enforces. See
	// config.InterfaceZoneMap for the fan-up/fan-down rules and the #5878
	// canonicalisation.
	return config.InterfaceZoneMap(cfg)
}
