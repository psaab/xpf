package cli

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/policymatch"
	"github.com/psaab/xpf/pkg/zonecounters"
)

func (c *CLI) showZonesDisplay(cfg *config.Config, detail bool, filterZone string) error {
	// Sort zone names for stable output
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	cr := c.applyResult()
	quarantined := config.ZoneQuarantineExclusions(zoneNames)
	if cr != nil && zoneShowInventoryDiffers(zoneNames, cr.ZoneIDs) {
		fmt.Println(config.ZoneQuarantineDriftNote)
	}

	// #3408: surface a per-zone counter read failure as a warning AFTER all
	// zones are rendered, rather than silently dropping the traffic-statistics
	// block (which would read like a true zero).
	var readErr error
	for _, name := range zoneNames {
		if filterZone != "" && name != filterZone {
			continue
		}
		zone := cfg.Security.Zones[name]
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}

		// Resolve the zone ID used for display and counter lookup. A
		// quarantined name retains its stable ID for attribution, but that
		// ID is not installed for this name and its live counters are not
		// attributable.
		var zoneID uint16
		reason := config.ZoneQuarantineExcludedReason(name, cfg)
		if _, excluded := quarantined[name]; excluded {
			zoneID = config.StableZoneID(name)
		} else if cr != nil {
			zoneID = cr.ZoneIDs[name]
		}
		survivor := ""
		if reason != "" {
			survivor = config.StableZoneIDOwner(zoneNames, zoneID)
		}

		// Junos format: "Security zone: <name>"
		fmt.Printf("Security zone: %s\n", name)
		if reason != "" {
			// Keep the #10490 canary's original reason line while adding the
			// shared prospective marker required by the text contract.
			fmt.Printf("  Quarantine: %s\n", reason)
			fmt.Println(config.ZoneQuarantineHeadlineFor(zoneID, survivor))
		}
		if zoneID > 0 {
			if reason != "" {
				fmt.Printf("  Zone ID: %d %s\n", zoneID,
					config.ZoneQuarantineIDQualifierFor(survivor))
			} else {
				fmt.Printf("  Zone ID: %d\n", zoneID)
			}
		}
		if zone.Description != "" {
			fmt.Printf("  Description: %s\n", zone.Description)
		}
		tcpRstStr := "Off"
		if zone.TCPRst {
			tcpRstStr = "On"
		}
		fmt.Printf("  Send reset for non-SYN session TCP packets: %s\n", tcpRstStr)
		fmt.Printf("  Policy configurable: Yes\n")
		if zone.ScreenProfile != "" {
			fmt.Printf("  Screen: %s\n", zone.ScreenProfile)
		}
		fmt.Printf("  Interfaces bound: %d\n", len(zone.Interfaces))
		interfaceHeader := "  Interfaces:"
		if reason != "" {
			interfaceHeader += " " + config.ZoneQuarantineInterfacesQualifier
		}
		fmt.Println(interfaceHeader)
		for _, ifName := range zone.Interfaces {
			fmt.Printf("    %s\n", ifName)
		}
		// #3654: render the zone-level admitted set, the no-stanza default-deny
		// posture line, AND any per-interface host-inbound override through the
		// shared config presenter so this surface can no longer hide overrides
		// or a default-deny zone (H04/M03). #3682: the presenter also renders
		// the management/cluster-control lifeline interfaces excluded from
		// host-inbound deny scoping, so the implicit exemption is auditable.
		for _, line := range zone.HostInboundViewWithLifelines(
			config.HostInboundLifelineSet(cfg)).Render(config.HostInboundLabels{
			Indent:         "  ",
			Sep:            " ",
			ServicesLabel:  "Allowed host-inbound traffic",
			ProtocolsLabel: "Allowed host-inbound protocols",
		}) {
			fmt.Println(line)
		}

		// Per-zone traffic counters (xpf extension, not in Junos)
		if reason != "" {
			fmt.Println(config.ZoneQuarantineCountersLine)
		} else if c.dp != nil && c.dp.IsLoaded() && zoneID > 0 {
			ingress, errIn := c.dp.ReadZoneCounters(zoneID, 0)
			egress, errOut := c.dp.ReadZoneCounters(zoneID, 1)
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
				// #6845: when the helper reports its slot table has OVERFLOWED,
				// say so instead of listing three causes the operator has no way
				// to choose between. Overflow is the only one of the three that
				// needs action — traffic is genuinely being missed — and the bit
				// that identifies it is already on the wire
				// (ProcessStatus.ZoneCounterOverflowActive) and was read by
				// nothing. The generic line stays for the other two causes,
				// because with no overflow they remain genuinely ambiguous and
				// naming one would be a guess.
				// #6895: one canonical spelling for all three surfaces.
				fmt.Println(zonecounters.UnavailableLineFor(
					zoneCounterLayoutVersion(c), zoneCounterOverflowActive(c)))
			case errIn == nil && errOut == nil:
				fmt.Println("  Traffic statistics:")
				fmt.Printf("    Input:  %d packets, %d bytes\n",
					ingress.Packets, ingress.Bytes)
				fmt.Printf("    Output: %d packets, %d bytes\n",
					egress.Packets, egress.Bytes)
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

		// Detail mode: per-interface breakdown, per-policy details, screen profile summary
		if detail {
			// Per-interface detail
			if len(zone.Interfaces) > 0 {
				fmt.Println("  Interface details:")
				for _, ifName := range zone.Interfaces {
					fmt.Printf("    %s:\n", ifName)
					// #5325: a zone binds a LOGICAL interface such as
					// "ge-0/0/9.0" or "reth0.50", but
					// cfg.Interfaces.Interfaces is keyed by the BASE name
					// ("ge-0/0/9" / "reth0"). The prior direct lookup missed
					// every unit-qualified reference, so a correctly addressed
					// interface rendered with NO Address/DHCP lines and looked
					// unaddressed in this policy-audit surface. Split off the
					// unit suffix, look up the base, and (when a unit was
					// named) render only that unit's addresses/DHCP. Mirrors the
					// #4908/C175-HC-116 repair in showChassisClusterStatus.
					base := ifName
					wantUnit := -1
					if parts := strings.SplitN(ifName, ".", 2); len(parts) == 2 {
						base = parts[0]
						if u, err := strconv.Atoi(parts[1]); err == nil {
							wantUnit = u
						}
					}
					ifc, ok := config.LookupInterface(cfg, base)
					// #5910: `ok` proves KEY presence, not a non-nil value — the
					// tolerant load / HA config-sync path admits a present-but-nil
					// InterfaceConfig (#3494/#5068). Guard nil AND walk units via
					// the shared nil-safe iterator (a raw `range ifc.Units` /
					// `unit.Number` nil-derefs and panics the daemon).
					if !ok || ifc == nil {
						continue
					}
					config.RangeUnits(ifc, func(_ int, unit *config.InterfaceUnit) {
						if wantUnit >= 0 && unit.Number != wantUnit {
							return
						}
						for _, addr := range unit.Addresses {
							fmt.Printf("      Address: %s\n", addr)
						}
						if unit.DHCP {
							fmt.Printf("      DHCPv4: enabled\n")
						}
						if unit.DHCPv6 {
							fmt.Printf("      DHCPv6: enabled\n")
						}
					})
				}
			}

			// Screen profile details
			if zone.ScreenProfile != "" {
				// #3476: a present-but-nil screen-profile map value (tolerant
				// / HA-sync config path) must not panic on profile.TCP.Land.
				if profile, ok := cfg.Security.Screen[zone.ScreenProfile]; ok && profile != nil {
					fmt.Printf("  Screen profile details (%s):\n", zone.ScreenProfile)
					// #3327: route the enabled-check inventory through the
					// cross-package SSOT (config.ScreenEnabledCheckList ->
					// config.ScreenChecks / config.ScreenThresholds) instead of a
					// hand-built list that omitted port-scan, ip-sweep, the
					// source/destination session limits, and icmp-fragment. This
					// is the local-CLI peer of the gRPC showZonesDetail renderer
					// and shares the same SSOT so neither can drift.
					if checks := config.ScreenEnabledCheckList(profile); len(checks) > 0 {
						fmt.Printf("    Enabled checks: %s\n", strings.Join(checks, ", "))
					} else {
						fmt.Printf("    Enabled checks: (none)\n")
					}
				}
			}

			// Policy detail breakdown. #3658 (M04/M05): the summary spans all
			// THREE tiers the runtime evaluates in order — zone-pair, then
			// applicable GLOBAL policies, then the effective default-policy
			// catch-all — so a zone-centric audit can no longer hide a global
			// rule that permits/denies the zone's traffic (M04) nor collapse to
			// a bare "(no policies)" that obscures whether unmatched transit is
			// denied or permitted (M05). #3684: it now also threads the per-rule
			// inventory metadata the name+action summary dropped — runtime
			// policy id (M11), scheduler binding + runtime-inactive state
			// (H03/#3624), log/count/address-exclusion modifiers (M12), and the
			// default-policy log posture + sentinel id (M13). The rendering is
			// delegated to policymatch.ZoneDetailPolicySummary, the SSOT shared
			// with the gRPC-text renderer (L10) so the two surfaces cannot
			// drift. Parity with the REST inventory (pkg/api/security.go) and
			// gRPC GetPolicies (#3363).
			if reason != "" {
				fmt.Println("  " + config.ZoneQuarantinePoliciesQualifier)
			}
			schedActive, haveSched := c.policySchedulerActiveState()
			for _, line := range policymatch.ZoneDetailPolicySummary(cfg, name, schedActive, haveSched) {
				fmt.Println(line)
			}
		}

		fmt.Println()
	}
	if readErr != nil {
		fmt.Printf("warning: zone counter read failed (traffic statistics may be incomplete): %v\n", readErr)
	}
	if filterZone != "" {
		if _, ok := cfg.Security.Zones[filterZone]; !ok {
			fmt.Printf("Zone '%s' not found\n", filterZone)
		}
	}
	return nil
}

func zoneShowInventoryDiffers(names []string, applied map[string]uint16) bool {
	if len(names) != len(applied) {
		return true
	}
	for _, name := range names {
		if _, ok := applied[name]; !ok {
			return true
		}
	}
	return false
}

// zoneCounterOverflowActive reports whether the helper says its per-zone
// hot-path slot table has overflowed (#6845).
//
// Fails to FALSE on any error, deliberately: the caller uses it to REPLACE a
// truthful three-cause message with a specific one-cause message, so a wrong
// true would tell the operator to go reduce their zone count when the real cause
// might be an idle zone. An unreachable helper means "cannot say", and "cannot
// say" must fall back to the honest ambiguous line rather than guess.
//
// The status read is per-invocation of `show security zones` and only on the
// branch that has already decided the zone is unpopulated, so it costs nothing on
// the healthy path.
// zoneCounterLayoutVersion reports the helper's per-zone counter layout version,
// or unknownToCaller when no status could be read.
//
// #7087: it returns the SENTINEL rather than 0 on a failed read, because 0 is a
// meaningful value on this wire — absent field means a pre-#3651 helper. A read
// failure and an old helper are different states and must not render the same
// sentence; that conflation is the defect this accessor exists to avoid.
func zoneCounterLayoutVersion(c *CLI) uint32 {
	if c == nil {
		return zonecounters.LayoutVersionUnknown
	}
	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		return zonecounters.LayoutVersionUnknown
	}
	return status.ZoneCounterLayoutVersion
}

func zoneCounterOverflowActive(c *CLI) bool {
	if c == nil {
		return false
	}
	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		return false
	}
	return status.ZoneCounterOverflowActive
}
