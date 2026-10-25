// protocols_render_ospf.go renders the OSPFv2 stanza of
// generateProtocolsCluster15158 (#16125 verbatim extraction).
//
// The body below is the contiguous `if ospf != nil` subtree moved
// verbatim out of generateProtocolsCluster15158; output ordering,
// the shared BFD accumulator and every render belt are unchanged.

package frr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// renderOSPF16125 renders the OSPFv2 stanza (including the trailing
// virtual-link stanza) into b. Moved verbatim from
// generateProtocolsCluster15158 (#16125); bfd is the shared BFD
// accumulator owned by the caller.
func (m *Manager) renderOSPF16125(b *strings.Builder, ospf *config.OSPFConfig, vrfSuffix string, ecmpMaxPaths int, policyOptions *config.PolicyOptionsConfig, bgpAcceptDefault map[string]bool, qnhMetrics *qnhMetricScope11447, clusterMode bool, bfd *bfdSection) {
	// #16572: `protocols ospf disable` renders nothing at all.
	if ospf != nil && ospf.Disable {
		return
	}
	if ospf != nil {
		fmt.Fprintf(b, "router ospf%s\n", vrfSuffix)
		if validRouterID(ospf.RouterID) {
			fmt.Fprintf(b, " ospf router-id %s\n", ospf.RouterID)
		}
		// #9408: ReferenceBandwidthMbps is ALREADY in FRR's unit (Mbps) and
		// already range-checked against `auto-cost reference-bandwidth
		// (1-4294967)` — the bits/s -> Mbps conversion and the range gate both
		// live in pkg/config (ospfReferenceBandwidthMbps). Render verbatim; do
		// not re-scale here, and do not accept a raw operator token at this
		// layer.
		if ospf.ReferenceBandwidthMbps > 0 {
			fmt.Fprintf(b, " auto-cost reference-bandwidth %d\n", ospf.ReferenceBandwidthMbps)
		}
		if ospf.PassiveDefault {
			b.WriteString(" passive-interface default\n")
		}
		type passiveAreaState11400 struct {
			key              string
			directiveEmitted bool
		}
		passiveAreaByInterface := make(map[string]passiveAreaState11400)
		for _, area := range ospf.Areas {
			areaKey := ospfAreaIdentity11400(area.ID)
			for _, iface := range area.Interfaces {
				if iface.Disable {
					continue
				}
				firstArea, seen := passiveAreaByInterface[iface.Name]
				if seen && firstArea.key != areaKey {
					continue
				}
				if !seen {
					firstArea.key = areaKey
				}
				// OSPFv2 area membership is activated per-interface in the
				// "interface <name>" block below via "ip ospf area <id>", NOT
				// with a "network <prefix> area" statement here. A global
				// "network 0.0.0.0/0 area" matches EVERY IPv4 interface in
				// the VRF (over-activation; render order silently decides the
				// area when multiple areas exist), and FRR ospfd does not
				// support mixing "network" and "ip ospf" activation on one
				// instance (#1712). passive-interface directives are
				// independent of activation and remain under "router ospf".
				if ospf.PassiveDefault {
					if iface.NoPassive && !firstArea.directiveEmitted {
						fmt.Fprintf(b, " no passive-interface %s\n", iface.Name)
						firstArea.directiveEmitted = true
					}
				} else if iface.Passive && !firstArea.directiveEmitted {
					fmt.Fprintf(b, " passive-interface %s\n", iface.Name)
					firstArea.directiveEmitted = true
				}
				passiveAreaByInterface[iface.Name] = firstArea
			}
		}
		// Collect valid virtual links for a trailing stanza (#15016).
		var virtualLinks15016 []struct {
			area *config.OSPFArea
			vl   *config.OSPFVirtualLink
		}
		for _, area := range ospf.Areas {
			if area.AreaType != "" {
				if !validFRROSPFArea(area.ID) {
					slog.Warn("frr: omitting an OSPF area stanza with an invalid area id (#9820)",
						"area", sanitizeFRRValue(area.ID))
				} else if isBackboneArea14585(area.ID) {
					slog.Warn("frr: omitting an OSPF area-type stanza for the backbone area (#14585)",
						"area", sanitizeFRRValue(area.ID), "area_type", sanitizeFRRValue(area.AreaType))
				} else if area.NoSummary {
					fmt.Fprintf(b, " area %s %s no-summary\n", area.ID, area.AreaType)
				} else {
					fmt.Fprintf(b, " area %s %s\n", area.ID, area.AreaType)
				}
			}
			for _, vl := range area.VirtualLinks {
				// #9493: both operands are raw config strings. Omit a link the
				// commit gate would refuse rather than emit a line FRR rejects.
				if !validRouterID(vl.NeighborID) || config.ValidateOSPFArea(vl.TransitArea) != nil ||
					!frrOperandOrOmit("ospf virtual-link transit-area", vl.TransitArea) {
					slog.Warn("frr: omitting an OSPF virtual-link with a malformed neighbor or transit area (#9493)",
						"neighbor", sanitizeFRRValue(vl.NeighborID), "transit_area", sanitizeFRRValue(vl.TransitArea))
					continue
				}
				// #15016: omit a VL whose transit is backbone/stub/NSSA.
				if reason := config.VirtualLinkTransitInvalid15016(ospf, vl); reason != "" {
					slog.Warn("frr: omitting an OSPF virtual-link with an invalid transit area (#15016)",
						"neighbor", sanitizeFRRValue(vl.NeighborID), "transit_area", sanitizeFRRValue(vl.TransitArea), "reason", reason)
					continue
				}
				virtualLinks15016 = append(virtualLinks15016, struct {
					area *config.OSPFArea
					vl   *config.OSPFVirtualLink
				}{area, vl})
			}
		}
		if ecmpMaxPaths > 1 {
			fmt.Fprintf(b, " maximum-paths %d\n", ecmpMaxPaths)
		}
		b.WriteString(m.resolveRedistributeChainCluster15158(ospf.Export, policyOptions, "ospf", clusterMode, qnhMetricScopeForDaemon11447(qnhMetrics, "ospf")))
		b.WriteString("exit\n!\n")
		// OSPF interface settings + per-interface area activation. The
		// "interface <name>" block is emitted UNCONDITIONALLY for each unique
		// configured OSPF interface because "ip ospf area <id>" is now the
		// sole activation mechanism (the global "network 0.0.0.0/0 area"
		// line was removed above, #1712). Cost / network-type / auth / BFD
		// lines remain optional within the block.
		// Equivalent area-ID spellings and authored interface aliases can
		// remain distinct model objects while resolving to one Linux device.
		// Union disjoint settings into one context. Strict compilation rejects
		// conflicting values; tolerant input keeps the first present value and
		// warns. Area activation retains the first fragment's spelling, so the
		// output intentionally follows fragment order.
		type ospfRenderV2State12186 struct {
			area     ospfRenderArea11400
			settings config.OSPFInterfaceUnion12186
		}
		renderedAreaByInterface := make(map[string]ospfRenderV2State12186)
		interfaceOrder := make([]string, 0)
		for _, area := range ospf.Areas {
			areaKey := ospfAreaIdentity11400(area.ID)
			for _, iface := range area.Interfaces {
				state, seen := renderedAreaByInterface[iface.Name]
				if seen && state.area.key != areaKey {
					slog.Warn("frr: dropping an OSPF interface assigned to multiple areas; keeping the first area (#11400)",
						"interface", sanitizeFRRValue(iface.Name),
						"first_area", sanitizeFRRValue(state.area.id),
						"dropped_area", sanitizeFRRValue(area.ID))
					continue
				}
				if !seen {
					state.area = ospfRenderArea11400{key: areaKey, id: area.ID}
					interfaceOrder = append(interfaceOrder, iface.Name)
				}
				if iface.Disable {
					continue
				}
				warnOSPFInterfaceConflict12186("OSPF", iface.Name, state.settings.Merge(iface))
				renderedAreaByInterface[iface.Name] = state
			}
		}
		for _, name := range interfaceOrder {
			state := renderedAreaByInterface[name]
			iface := state.settings.OSPFInterface
			if iface.Disable {
				continue
			}
			// #14388 (DR6-H4): decide MD5 survivability BEFORE emitting the
			// interface header. If AuthType is md5 but no key survives
			// (all key-ids out of 1..255, all secrets empty, or all secrets
			// unsafe as a single vtysh token), emitting the block would run
			// OSPF with null authentication while the config states MD5.
			// Two adjacent routers leniently loading the same template
			// would then form an unauthenticated adjacency. Omit the whole
			// interface block (area activation included) so no adjacency
			// can form; a peer still requiring MD5 refuses anyway.
			var md5Block strings.Builder
			if iface.AuthType == "md5" {
				authEmitted := false
				for i := range state.settings.MD5Keys {
					key := &state.settings.MD5Keys[i]
					if key.Key.Reveal() == "" {
						continue
					}
					if key.ID < 1 || key.ID > 255 {
						slog.Warn("frr: omitting OSPF MD5 authentication with an invalid key-id (#11794)",
							"interface", sanitizeFRRValue(iface.Name), "key_id", key.ID)
						continue
					}
					tok, ok := authTokenOrOmit("ospf-md5", &key.Key)
					if !ok {
						continue
					}
					// #16628: ospfd truncates an MD5 key over 16
					// characters, so rendering it verbatim churns
					// every frr-reload (delete-and-add) and the
					// effective key diverges from the config.
					// Withhold only this entry; a valid rollover
					// key on the same interface still renders,
					// and if none survives the #14388 omission
					// below drops the whole interface. Length is
					// the resolved (post-$9$-decode) token, in
					// runes, matching the config gate.
					if len([]rune(tok)) > config.MaxOSPFMD5KeyLen {
						slog.Warn("frr: omitting OSPF MD5 key exceeding the 16-character maximum accepted by ospfd; ospfd would truncate it and every reload would delete and re-add it (#16628)",
							"interface", sanitizeFRRValue(iface.Name), "key_id", key.ID,
							"key_len", len([]rune(tok)), "max", config.MaxOSPFMD5KeyLen)
						continue
					}
					if !authEmitted {
						md5Block.WriteString(" ip ospf authentication message-digest\n")
						authEmitted = true
					}
					fmt.Fprintf(&md5Block, " ip ospf message-digest-key %d md5 %s\n", key.ID, tok)
				}
				if !authEmitted {
					slog.Warn("frr: omitting OSPF interface with MD5 authentication but no renderable MD5 key (#14388)",
						"interface", sanitizeFRRValue(iface.Name), "area", sanitizeFRRValue(state.area.id))
					continue
				}
			}
			// #14397: the #14388 pre-check above covers md5 (including the
			// keyless selection, whose keys are all empty); simple with an
			// empty key needs the same fail-closed omission here, or the
			// interface would be activated with ip ospf area and zero
			// authentication lines. The strict gate rejects this at
			// commit; a tolerant-loaded config must never run
			// unauthenticated. Do NOT emit a keyless authentication line —
			// FRR adjacency behaviour for it is not established.
			//
			// #14977 (D33-05): the same fail-closed rule covers a simple
			// key that is non-empty but unrenderable as a single vtysh
			// token (pre-validate it HERE, before the interface header,
			// and reuse the token below), and any non-empty AuthType
			// that is neither md5 nor simple — including a key carried
			// with no type at all. Previously those shapes emitted
			// `ip ospf area` with zero authentication lines: an
			// unauthenticated adjacency. OSPF's AuthType is assigned
			// only from matched compiler keywords (pkg/config
			// auth_type.go), so a foreign value can only arrive via a
			// direct/tolerant construction; omitting the whole
			// interface block is the #14388 answer.
			var ospfSimpleTok14977 string
			if iface.AuthType == "simple" {
				if iface.AuthKey.Reveal() == "" {
					slog.Warn("frr: omitting OSPF interface with simple authentication configured but no key; refusing to activate it unauthenticated (#14397)",
						"interface", sanitizeFRRValue(iface.Name), "authentication_type", iface.AuthType)
					continue
				}
				tok, ok := authTokenOrOmit("ospf-simple", &iface.AuthKey)
				if !ok {
					slog.Warn("frr: omitting OSPF interface with an unrenderable simple authentication key; refusing to activate it unauthenticated (#14977)",
						"interface", sanitizeFRRValue(iface.Name))
					continue
				}
				// #16628: ospfd truncates a simple-password over 8
				// characters, so rendering it verbatim churns every
				// frr-reload (delete-and-add) and the effective
				// password diverges from the config. Fail closed
				// exactly like the unrenderable-token arm: omit the
				// whole interface rather than activating it
				// unauthenticated or with a truncated key. Length
				// is the resolved token, in runes.
				if len([]rune(tok)) > config.MaxOSPFSimplePasswordLen {
					slog.Warn("frr: omitting OSPF interface with a simple-password exceeding the 8-character maximum accepted by ospfd; ospfd would truncate it and every reload would delete and re-add it (#16628)",
						"interface", sanitizeFRRValue(iface.Name),
						"key_len", len([]rune(tok)), "max", config.MaxOSPFSimplePasswordLen)
					continue
				}
				ospfSimpleTok14977 = tok
			} else if iface.AuthType != "" && iface.AuthType != "md5" {
				slog.Warn("frr: omitting OSPF interface with an unrecognized authentication-type; refusing to activate it unauthenticated (#14977)",
					"interface", sanitizeFRRValue(iface.Name), "authentication_type", sanitizeFRRValue(iface.AuthType))
				continue
			} else if iface.AuthType == "" && iface.AuthKey.Reveal() != "" {
				slog.Warn("frr: omitting OSPF interface with an authentication key but no authentication-type; refusing to activate it unauthenticated (#14977)",
					"interface", sanitizeFRRValue(iface.Name))
				continue
			}
			fmt.Fprintf(b, "interface %s\n", iface.Name)
			if iface.Cost > 0 {
				fmt.Fprintf(b, " ip ospf cost %d\n", frrClampInt("ospf cost", iface.Cost, 65535))
			}
			// Adjacency timers + DR priority (#4285). hello/dead MUST
			// match the neighbor or the adjacency never forms; FRR keeps
			// its defaults (hello 10s, dead 40s, priority 1) when unset.
			if iface.HelloInterval > 0 {
				fmt.Fprintf(b, " ip ospf hello-interval %d\n", iface.HelloInterval)
			}
			if iface.DeadInterval > 0 {
				fmt.Fprintf(b, " ip ospf dead-interval %d\n", iface.DeadInterval)
			}
			if iface.RetransmitInt > 0 {
				fmt.Fprintf(b, " ip ospf retransmit-interval %d\n", iface.RetransmitInt)
			}
			// HasPriority gates the line; 0 is a valid value ("never DR").
			if iface.HasPriority {
				fmt.Fprintf(b, " ip ospf priority %d\n", iface.Priority)
			}
			if iface.NetworkType != "" {
				fmt.Fprintf(b, " ip ospf network %s\n", iface.NetworkType)
			}
			if iface.AuthType == "md5" {
				b.WriteString(md5Block.String())
			} else if iface.AuthType == "simple" {
				// #11462/#14977: emit only the token pre-validated above;
				// an unrenderable key already omitted the whole block.
				b.WriteString(" ip ospf authentication\n")
				fmt.Fprintf(b, " ip ospf authentication-key %s\n", ospfSimpleTok14977)
			}
			if iface.BFD {
				if iface.BFDInterval > 0 || iface.BFDMultiplier > 0 {
					profile := bfdProfileName(iface.BFDInterval, iface.BFDMultiplier)
					bfd.addProfile(profile, bfdProfile{iface.BFDInterval, iface.BFDMultiplier})
					// #15015: `ip ospf bfd profile` alone does NOT
					// enable BFD in FRR 10.6 — ospfd's profile DEFUN
					// refuses ("ip ospf bfd has not been set") unless
					// bfd_config already exists, and
					// ospf_bfd_write_config prints ` ip ospf bfd`
					// before the profile line. Emit the bare enable
					// first or no BFD session ever runs.
					b.WriteString(" ip ospf bfd\n")
					fmt.Fprintf(b, " ip ospf bfd profile %s\n", profile)
				} else {
					b.WriteString(" ip ospf bfd\n")
				}
			}
			if validFRROSPFArea(state.area.id) {
				fmt.Fprintf(b, " ip ospf area %s\n", state.area.id)
			} else {
				slog.Warn("frr: omitting an OSPF interface area activation with an invalid area id (#9820)",
					"area", sanitizeFRRValue(state.area.id), "interface", sanitizeFRRValue(iface.Name))
			}
			b.WriteString("exit\n!\n")
		}
		// #15016: emit virtual links in a second router ospf stanza after
		// interface activation, so FRR has the transit area on first load.
		if len(virtualLinks15016) > 0 {
			fmt.Fprintf(b, "router ospf%s\n", vrfSuffix)
			if validRouterID(ospf.RouterID) {
				fmt.Fprintf(b, " ospf router-id %s\n", ospf.RouterID)
			}
			for _, e := range virtualLinks15016 {
				fmt.Fprintf(b, " area %s virtual-link %s\n", e.vl.TransitArea, e.vl.NeighborID)
			}
			b.WriteString("exit\n!\n")
		}
	}
}
