// protocols_render_ospfv3.go renders the OSPFv3 stanza of
// generateProtocolsCluster15158 (#16125 verbatim extraction).
//
// The body below is the contiguous `if ospfv3 != nil` subtree moved
// verbatim out of generateProtocolsCluster15158; output ordering,
// the shared BFD accumulator and every render belt are unchanged.

package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderOSPFv316125 renders the OSPFv3 stanza (router block plus
// per-interface blocks) into b. Moved verbatim from
// generateProtocolsCluster15158 (#16125); bfd is the shared BFD
// accumulator owned by the caller.
func (m *Manager) renderOSPFv316125(b *strings.Builder, ospfv3 *config.OSPFv3Config, vrfSuffix string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, clusterMode bool, qnhMetrics *qnhMetricScope11447, bfd *bfdSection) {
	// #16572: `protocols ospf3 disable` renders nothing at all.
	if ospfv3 != nil && ospfv3.Disable {
		return
	}
	if ospfv3 != nil {
		fmt.Fprintf(b, "router ospf6%s\n", vrfSuffix)
		// #16620: pin OSPFv3 to Junos preferences (internal 10,
		// external 150); see protocol_distance_16620.go.
		b.WriteString(junosOSPF6DistanceLine)
		if validRouterID(ospfv3.RouterID) {
			fmt.Fprintf(b, " ospf6 router-id %s\n", ospfv3.RouterID)
		}
		// IPv6 OSPF ECMP mirrors the OSPFv4 block: FRR ospf6d requires an
		// explicit "maximum-paths <N>" under "router ospf6" to install
		// equal-cost multipath. OSPFv3 reuses the same global forwarding-table
		// ECMP knob (ecmpMaxPaths) as OSPFv4 — there is no separate OSPFv3
		// maximum-paths config leaf (#2997).
		if ecmpMaxPaths > 1 {
			fmt.Fprintf(b, " maximum-paths %d\n", ecmpMaxPaths)
		}
		for _, area := range ospfv3.Areas {
			if area == nil || area.AreaType == "" {
				continue
			}
			if !validFRROSPFArea(area.ID) || (area.AreaType != "stub" && area.AreaType != "nssa") || isBackboneArea14585(area.ID) {
				slog.Warn("frr: omitting an OSPFv3 area-type stanza with an invalid area id or type (#11401)",
					"area", sanitizeFRRValue(area.ID), "area_type", sanitizeFRRValue(area.AreaType))
				continue
			}
			if area.NoSummary {
				fmt.Fprintf(b, " area %s %s no-summary\n", area.ID, area.AreaType)
			} else {
				fmt.Fprintf(b, " area %s %s\n", area.ID, area.AreaType)
			}
		}
		b.WriteString(m.resolveRedistributeChainCluster15158(ospfv3.Export, policyOptions, "ospf6", clusterMode, qnhMetricScopeForDaemon11447(qnhMetrics, "ospf6")))
		b.WriteString("exit\n!\n")
		// OSPFv3 interface settings + per-interface area activation. FRR
		// stable/10.6 moved area activation from the removed router-level
		// `interface <name> area <id>` command to the INTERFACE_NODE form
		// `ipv6 ospf6 area <id>`. Emit the interface block unconditionally so
		// an interface with no optional settings still gets activated.
		// Equivalent area-ID spellings and authored aliases can remain
		// distinct model objects while resolving to one Linux device. Union
		// disjoint settings into one context. Strict compilation rejects
		// conflicting values; tolerant input keeps the first present value and
		// warns. Area activation retains the first fragment's spelling, so the
		// output intentionally follows fragment order.
		type ospfRenderV3State12186 struct {
			area     ospfRenderArea11400
			settings config.OSPFv3InterfaceUnion12186
		}
		renderedAreaByInterface := make(map[string]ospfRenderV3State12186)
		interfaceOrder := make([]string, 0)
		for _, area := range ospfv3.Areas {
			areaKey := ospfAreaIdentity11400(area.ID)
			for _, iface := range area.Interfaces {
				if iface.Disable {
					continue
				}
				state, seen := renderedAreaByInterface[iface.Name]
				if seen && state.area.key != areaKey {
					slog.Warn("frr: dropping an OSPFv3 interface assigned to multiple areas; keeping the first area (#11400)",
						"interface", sanitizeFRRValue(iface.Name),
						"first_area", sanitizeFRRValue(state.area.id),
						"dropped_area", sanitizeFRRValue(area.ID))
					continue
				}
				if !seen {
					state.area = ospfRenderArea11400{key: areaKey, id: area.ID}
					interfaceOrder = append(interfaceOrder, iface.Name)
				}
				warnOSPFInterfaceConflict12186("OSPFv3", iface.Name, state.settings.Merge(iface))
				renderedAreaByInterface[iface.Name] = state
			}
		}
		for _, name := range interfaceOrder {
			state := renderedAreaByInterface[name]
			iface := state.settings.OSPFv3Interface
			fmt.Fprintf(b, "interface %s\n", iface.Name)
			if validFRROSPFArea(state.area.id) {
				fmt.Fprintf(b, " ipv6 ospf6 area %s\n", state.area.id)
			} else {
				slog.Warn("frr: omitting an OSPFv3 interface area activation with an invalid area id (#9820)",
					"area", sanitizeFRRValue(state.area.id), "interface", sanitizeFRRValue(iface.Name))
			}
			if iface.Passive {
				b.WriteString(" ipv6 ospf6 passive\n")
			}
			if iface.Cost > 0 {
				fmt.Fprintf(b, " ipv6 ospf6 cost %d\n", frrClampInt("ospf3 cost", iface.Cost, 65535))
			}
			// Adjacency timers + DR priority (#4285): hello/dead must
			// match the neighbor. HasPriority gates the line; priority 0
			// ("never DR") emits, unset omits.
			if iface.HelloInterval > 0 {
				fmt.Fprintf(b, " ipv6 ospf6 hello-interval %d\n", iface.HelloInterval)
			}
			if iface.DeadInterval > 0 {
				fmt.Fprintf(b, " ipv6 ospf6 dead-interval %d\n", iface.DeadInterval)
			}
			if iface.RetransmitInt > 0 {
				fmt.Fprintf(b, " ipv6 ospf6 retransmit-interval %d\n", iface.RetransmitInt)
			}
			if iface.HasPriority {
				fmt.Fprintf(b, " ipv6 ospf6 priority %d\n", iface.Priority)
			}
			if iface.BFD {
				if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
					profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
					bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
					// #16813: ospf6d's write_config always prints the
					// bare `ipv6 ospf6 bfd` enable line and then the
					// profile line when a profile is set. Rendering
					// only the profile line makes every
					// `frr-reload.py --test` delete the running bare
					// line — a perpetual diff that can never certify
					// the #15203 re-check. Emit the pair FRR holds.
					b.WriteString(" ipv6 ospf6 bfd\n")
					fmt.Fprintf(b, " ipv6 ospf6 bfd profile %s\n", profile)
				} else {
					b.WriteString(" ipv6 ospf6 bfd\n")
				}
			}
			b.WriteString("exit\n!\n")
		}
	}
}
