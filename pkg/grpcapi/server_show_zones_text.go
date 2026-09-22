// Phase 8 of #1043: extract the `zones-detail` ShowText case body
// into a dedicated method. Same methodology as Phases 1-7 (#1148,
// #1150, #1151, #1153, #1154, #1155, #1156): semantic relocation, no
// behavior change. The case body is moved verbatim apart from
// (a) `&buf` references becoming `buf` (passed-in `*strings.Builder`)
// and (b) the original `if cfg == nil { … } else { … long body }`
// flattened into early-return form. Output is unchanged.

package grpcapi

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
	"github.com/psaab/xpf/pkg/zonecounters"
)

// showZonesDetail renders per-zone configuration plus dataplane traffic
// counters, policy references, interface details, screen profile
// breakdown, and policy-rule summaries.
// #9065: filter narrows the render to one zone. The remote CLI can now bind a
// zone name to this topic (`show security zones <name> detail`, which the local
// console has always honoured and pkg/cmdtree has always offered), so the
// server must honour it — a client that sends a selector the server ignores
// shows the operator every zone with nothing saying their selector was
// discarded, which is the same silence the dropped selector produced.
//
// An unmatched selector writes a NOT-FOUND line rather than an empty body, for
// the reason the caller's own zone filter errors: "no such zone" and "this zone
// is empty" must not read identically.
func (s *Server) showZonesDetail(cfg *config.Config, filter string, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		buf.WriteString("No security zones configured\n")
		return
	}
	allZoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		allZoneNames = append(allZoneNames, name)
	}
	sort.Strings(allZoneNames)
	quarantined := config.ZoneQuarantineExclusions(allZoneNames)
	zoneNames := make([]string, 0, len(allZoneNames))
	for _, name := range allZoneNames {
		if filter != "" && name != filter {
			continue
		}
		zoneNames = append(zoneNames, name)
	}
	if len(zoneNames) == 0 {
		fmt.Fprintf(buf, "security zone %q not found\n", filter)
		return
	}
	sort.Strings(zoneNames)
	cr := s.applyResult()
	if cr != nil && config.ZoneInventoryDiffers(allZoneNames, cr.ZoneIDs) {
		buf.WriteString(config.ZoneQuarantineDriftNote + "\n")
	}
	// #3408: surface a per-zone counter read failure as a warning AFTER all
	// zones rather than silently dropping the traffic-statistics block.
	var readErr error
	for _, name := range zoneNames {
		zone := cfg.Security.Zones[name]
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		var zoneID uint16
		reason := ""
		if _, excluded := quarantined[name]; excluded {
			reason = config.ZoneQuarantineExcludedReason(name, cfg)
			zoneID = config.StableZoneID(name)
		} else if cr != nil {
			zoneID = cr.ZoneIDs[name]
		}
		survivor := ""
		if reason != "" {
			survivor = config.StableZoneIDOwner(allZoneNames, zoneID)
		}
		if zoneID > 0 {
			if survivor != "" {
				fmt.Fprintf(buf, "Zone: %s (id: %d) %s\n", name, zoneID,
					config.ZoneQuarantineIDQualifierFor(survivor))
			} else {
				fmt.Fprintf(buf, "Zone: %s (id: %d)\n", name, zoneID)
			}
		} else {
			fmt.Fprintf(buf, "Zone: %s\n", name)
		}
		if reason != "" {
			buf.WriteString(config.ZoneQuarantineHeadlineFor(zoneID, survivor) + "\n")
		}
		if zone.Description != "" {
			fmt.Fprintf(buf, "  Description: %s\n", zone.Description)
		}
		if reason != "" {
			fmt.Fprintf(buf, "  Interfaces: %s %s\n", strings.Join(zone.Interfaces, ", "), config.ZoneQuarantineInterfacesQualifier)
		} else {
			fmt.Fprintf(buf, "  Interfaces: %s\n", strings.Join(zone.Interfaces, ", "))
		}
		if zone.TCPRst {
			buf.WriteString("  TCP RST: enabled\n")
		}
		if zone.ScreenProfile != "" {
			fmt.Fprintf(buf, "  Screen: %s\n", zone.ScreenProfile)
		}
		// #3654: render the zone-level admitted set, the no-stanza default-deny
		// posture line, AND any per-interface host-inbound override through the
		// shared config presenter (H07/M03) so gRPC text stays in lockstep with
		// the local CLI and the structured inventory. #3682: the presenter also
		// renders the management/cluster-control lifeline interfaces excluded
		// from host-inbound deny scoping so the implicit exemption is auditable.
		for _, line := range zone.HostInboundViewWithLifelines(
			config.HostInboundLifelineSet(cfg)).Render(config.HostInboundLabels{
			Indent:         "  ",
			Sep:            ", ",
			ServicesLabel:  "Host-inbound system-services",
			ProtocolsLabel: "Host-inbound protocols",
		}) {
			buf.WriteString(line)
			buf.WriteString("\n")
		}
		// #7181: the lines above are DESIRED config. This one is what the kernel
		// is actually enforcing. Rendered next to the stanza deliberately -- an
		// operator reading a default-deny posture needs the applied state in the
		// same glance, because "configured" and "in force" were previously
		// indistinguishable here.
		if s.hostInboundAppliedFn != nil {
			if ap := s.hostInboundAppliedFn(); ap.Known {
				fmt.Fprintf(buf, "  Host-inbound applied: %s (generation %d)\n",
					ap.AppliedStateLabel(), ap.Generation)
				if ap.GapFenceActive {
					buf.WriteString("  Host-inbound gap fence: ACTIVE " +
						"(an address is denied by the additive fence, not the main table)\n")
				}
			}
		}
		// Traffic counters. Never read the survivor's live counters under a
		// quarantined name: the builder omits that zone from the dataplane.
		if reason != "" {
			buf.WriteString(config.ZoneQuarantineCountersLine + "\n")
		} else if s.dp != nil && s.dp.IsLoaded() && zoneID > 0 {
			ingress, errIn := s.dp.ReadZoneCounters(zoneID, 0)
			egress, errOut := s.dp.ReadZoneCounters(zoneID, 1)
			switch {
			case errors.Is(errIn, dataplane.ErrCounterNotPopulated) ||
				errors.Is(errOut, dataplane.ErrCounterNotPopulated):
				// #6843: per-zone accounting IS implemented and populated
				// (#3651). ErrCounterNotPopulated now means the helper has
				// published nothing for THIS zone, which has three causes: a
				// pre-#3651 helper, a zone past the helper's hot-path slot
				// capacity (its traffic really is uncounted), or an idle zone.
				// Naming "not implemented" was accurate under the #3643 HIDE
				// and is now actively misleading — with 64+ zones one `show
				// security zones` prints real byte counts for slotted zones and
				// "not implemented" for overflowed ones, pointing the operator
				// at the wrong cause.
				// #6895: one canonical spelling for all three surfaces — and
				// this renderer previously had NO #6845 overflow
				// specialisation, so the same cluster reported slot exhaustion
				// on the local CLI and the generic three-cause line here.
				buf.WriteString(zonecounters.UnavailableLineFor(
					s.zoneCounterLayoutVersion(), s.zoneCounterOverflowActive()) + "\n")
			case errIn == nil && errOut == nil:
				buf.WriteString("  Traffic statistics:\n")
				fmt.Fprintf(buf, "    Input:  %d packets, %d bytes\n", ingress.Packets, ingress.Bytes)
				fmt.Fprintf(buf, "    Output: %d packets, %d bytes\n", egress.Packets, egress.Bytes)
			default:
				if readErr == nil {
					if errIn != nil {
						readErr = errIn
					} else {
						readErr = errOut
					}
				}
			}
		}
		// Policies referencing this zone
		var policyRefs []string
		for _, zpp := range cfg.Security.Policies {
			// #3476: skip a nil zone-pair set (tolerant / HA-sync config
			// path the runtime walker skips) rather than dereferencing
			// zpp.FromZone.
			if zpp == nil {
				continue
			}
			if zpp.FromZone == name || zpp.ToZone == name {
				dir := "from"
				peer := zpp.ToZone
				if zpp.ToZone == name {
					dir = "to"
					peer = zpp.FromZone
				}
				policyRefs = append(policyRefs, fmt.Sprintf("%s %s (%d rules)", dir, peer, len(zpp.Policies)))
			}
		}
		if len(policyRefs) > 0 {
			if reason != "" {
				fmt.Fprintf(buf, "  Policies: %s %s\n", strings.Join(policyRefs, ", "), config.ZoneQuarantinePoliciesQualifier)
			} else {
				fmt.Fprintf(buf, "  Policies: %s\n", strings.Join(policyRefs, ", "))
			}
		}
		// Detail: per-interface info
		if len(zone.Interfaces) > 0 {
			buf.WriteString("  Interface details:\n")
			for _, ifName := range zone.Interfaces {
				fmt.Fprintf(buf, "    %s:\n", ifName)
				// #5910: `ok` proves KEY presence, not a non-nil value — the
				// tolerant load / HA config-sync path admits a present-but-nil
				// InterfaceConfig (#3494/#5068). Walk units via the shared
				// nil-safe iterator so a nil interface/unit slot is skipped, not
				// dereferenced (a raw `range ifc.Units` panics the daemon).
				if ifc, ok := config.LookupInterface(cfg, ifName); ok {
					config.RangeUnits(ifc, func(_ int, unit *config.InterfaceUnit) {
						for _, addr := range unit.Addresses {
							fmt.Fprintf(buf, "      Address: %s\n", addr)
						}
						if unit.DHCP {
							buf.WriteString("      DHCPv4: enabled\n")
						}
						if unit.DHCPv6 {
							buf.WriteString("      DHCPv6: enabled\n")
						}
					})
				}
			}
		}
		// Screen profile detail
		if zone.ScreenProfile != "" {
			// #3476: a present-but-nil screen-profile map value (tolerant /
			// HA-sync config path) must not panic on profile.TCP.Land.
			if profile, ok := cfg.Security.Screen[zone.ScreenProfile]; ok && profile != nil {
				fmt.Fprintf(buf, "  Screen profile details (%s):\n", zone.ScreenProfile)
				// #3327: route the enabled-check inventory through the shared
				// SSOT (config.ScreenChecks / config.ScreenThresholds via
				// screenEnabledCheckList) instead of a hand-built list that
				// omitted port-scan, ip-sweep, the source/destination session
				// limits, and icmp-fragment.
				if checks := screenEnabledCheckList(profile); len(checks) > 0 {
					fmt.Fprintf(buf, "    Enabled checks: %s\n", strings.Join(checks, ", "))
				}
			}
		}
		// Policy detail breakdown. #3658 (M04/M05): span all THREE tiers the
		// runtime evaluates in order — zone-pair, applicable GLOBAL policies,
		// then the effective default-policy catch-all — so this gRPC-text peer
		// of the local-CLI renderer (pkg/cli/cli_show_security_zones.go) can no
		// longer hide a global rule that affects the zone (M04) nor collapse to
		// a bare "(no policies)" that obscures the unmatched-transit disposition
		// (M05). #3684: it also threads the per-rule inventory metadata the
		// name+action summary dropped — runtime policy id (M11), scheduler
		// binding + runtime-inactive state (H03/#3624), log/count/exclusion
		// modifiers (M12), and the default-policy log posture + sentinel id
		// (M13). Rendering is delegated to policymatch.ZoneDetailPolicySummary,
		// the SSOT shared with the local-CLI renderer (L10) so the two surfaces
		// stay byte-identical. Parity with REST (pkg/api/security.go) + gRPC
		// GetPolicies (#3363).
		schedActive, haveSched := s.policySchedulerActiveState()
		if reason != "" {
			buf.WriteString("  " + config.ZoneQuarantinePoliciesQualifier + "\n")
		}
		for _, line := range policymatch.ZoneDetailPolicySummary(cfg, name, schedActive, haveSched) {
			buf.WriteString(line)
			buf.WriteString("\n")
		}
		buf.WriteString("\n")
	}
	if readErr != nil {
		fmt.Fprintf(buf, "warning: zone counter read failed (traffic statistics may be incomplete): %v\n", readErr)
	}
}

// --- #1700: residual ShowText branches ---

func (s *Server) showTestZone(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	params := strings.TrimPrefix(req.Topic, "test-zone:")
	var ifName string
	var parseErr error
	// #4814: mirror the #4589 showTestRouting hardening (itself mirroring
	// #3696's showTestPolicy fix). The old `if len(parts) == 2 && ...`
	// with no else/default arm SILENTLY dropped a malformed segment (no
	// `=`) or an unrecognized key (e.g. `interfac=ge-0/0/0`, a typo) —
	// ifName stayed empty with no diagnostic, and the operator saw the
	// generic "Missing interface parameter" fallback instead of a message
	// naming their actual typo. Report a malformed segment (no key=value,
	// or an empty key/value) and an unknown key instead of ignoring it. A
	// bare `test-zone:` (empty params) still falls through to the
	// "Missing interface parameter" diagnostic below.
	if params != "" {
		// #5649 (C181-C09): reject a repeated selector key. Without a `seen`
		// set a duplicate `interface=a,interface=b` silently LAST-WON in the
		// switch below, so the archived diagnostic reported a DIFFERENT
		// interface's zone/posture than the operator typed. This mirrors the
		// #4921 showTestRouting and #3709 showTestPolicy duplicate-selector
		// contract (server_show_routes_text.go).
		seen := map[string]bool{}
		for _, kv := range strings.Split(params, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				if parseErr == nil {
					parseErr = fmt.Errorf("malformed selector segment %q (expected key=value)", kv)
				}
				continue
			}
			if seen[parts[0]] {
				// A duplicate KNOWN key would last-win below; a duplicate
				// UNKNOWN key already recorded an "unknown selector" error on
				// its first occurrence (parseErr is set-once), so this only
				// overrides when no earlier grammar error was captured.
				if parseErr == nil {
					parseErr = fmt.Errorf("selector %q specified more than once", parts[0])
				}
				continue
			}
			seen[parts[0]] = true
			switch parts[0] {
			case "interface":
				ifName = parts[1]
			default:
				if parseErr == nil {
					parseErr = fmt.Errorf("unknown selector %q", parts[0])
				}
			}
		}
	}
	if parseErr != nil {
		// Report malformed grammar / an unknown key before anything else, so
		// a typo cannot silently fall through to the generic "missing
		// parameter" message. A selector grammar error is a client-input
		// error independent of config availability, so it precedes the
		// nil-cfg check.
		fmt.Fprintf(buf, "%v\n", parseErr)
	} else if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else if ifName == "" {
		buf.WriteString("Missing interface parameter\n")
	} else {
		found := false
		allZoneNames := make([]string, 0, len(cfg.Security.Zones))
		for zoneName := range cfg.Security.Zones {
			allZoneNames = append(allZoneNames, zoneName)
		}
		sort.Strings(allZoneNames)
		for _, zoneName := range allZoneNames {
			zone := cfg.Security.Zones[zoneName]
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			for _, iface := range zone.Interfaces {
				if iface == ifName {
					fmt.Fprintf(buf, "Interface %s belongs to zone: %s\n", ifName, zoneName)
					if reason := config.ZoneQuarantineExcludedReason(zoneName, cfg); reason != "" {
						id := config.StableZoneID(zoneName)
						survivor := config.StableZoneIDOwner(allZoneNames, id)
						fmt.Fprintf(buf, "  %s\n", config.ZoneQuarantineTestZoneQualifierFor(id, survivor))
					}
					if zone.Description != "" {
						fmt.Fprintf(buf, "  Description: %s\n", zone.Description)
					}
					if zone.ScreenProfile != "" {
						fmt.Fprintf(buf, "  Screen:      %s\n", zone.ScreenProfile)
					}
					// #3654 (H08/M03): this is the per-interface admission
					// DIAGNOSTIC, so report the EFFECTIVE (zone UNION interface)
					// set for THIS interface and flag when it is governed by an
					// interface-local override rather than only the zone set.
					// #3682: also flag when THIS interface is a management /
					// cluster-control lifeline excluded from host-inbound deny.
					lifeline := config.HostInboundLifelineInterface(
						ifName, config.HostInboundLifelineSet(cfg))
					for _, line := range zone.RenderInterfaceHostInbound(ifName, lifeline,
						config.HostInboundLabels{
							Indent:         "  ",
							Sep:            ", ",
							ServicesLabel:  "Host-inbound services",
							ProtocolsLabel: "Host-inbound protocols",
						}) {
						buf.WriteString(line)
						buf.WriteString("\n")
					}
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			fmt.Fprintf(buf, "Interface %s is not assigned to any security zone\n", ifName)
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

// zoneCounterOverflowActive reports whether the dataplane says its per-zone
// hot-path slot table has OVERFLOWED (#6845), mirroring the local CLI's probe of
// the same bit so the two surfaces cannot disagree about a cluster's state.
//
// FAILS TO FALSE on any error, deliberately and for the same reason the CLI
// does: the caller uses it to REPLACE a truthful three-cause message with a
// specific one-cause message, so a wrong true would send the operator to reduce
// their zone count when the real cause might be an idle zone. An unreachable
// helper means "cannot say", and "cannot say" must fall back to the honest
// ambiguous line rather than guess.
//
// Read only on the branch that has already decided the zone is unpopulated, so
// it costs nothing on the healthy path.
func (s *Server) zoneCounterOverflowActive() bool {
	if s == nil {
		return false
	}
	// #2114: probe through dpProbe(), NEVER the stored dp field. Under the live
	// indirection an assertion on the field answers "capability absent" for a
	// perfectly HEALTHY backend that implements it — here that would silently
	// suppress the #6845 overflow line and leave the operator reading the
	// generic three-cause message on a cluster whose slot table really has
	// overflowed. The daemon_dp_probe_canary_test.go guard caught exactly that.
	provider, ok := s.dpProbe().(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return false
	}
	status, err := provider.Status()
	if err != nil {
		return false
	}
	return status.ZoneCounterOverflowActive
}

// zoneCounterLayoutVersion mirrors zoneCounterOverflowActive for the layout
// version, returning the SENTINEL rather than 0 when no status could be read
// (#7087): 0 means a pre-#3651 helper on this wire, so a read failure must not
// render as one.
func (s *Server) zoneCounterLayoutVersion() uint32 {
	// Through dpProbe(), never the stored dp field — same #2114 reason as the
	// sibling above: under the live indirection an assertion on the field
	// answers "capability absent" for a healthy backend, which here would
	// report LayoutVersionUnknown and render the generic line on a box whose
	// helper version is perfectly readable.
	provider, ok := s.dpProbe().(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return zonecounters.LayoutVersionUnknown
	}
	status, err := provider.Status()
	if err != nil {
		return zonecounters.LayoutVersionUnknown
	}
	return status.ZoneCounterLayoutVersion
}
