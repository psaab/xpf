package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

func (c *CLI) showScreen() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	// #5806: report unresolved screen-profile references FIRST. A zone can
	// claim a profile that is not defined (tolerant load / HA config-sync /
	// rolling upgrade — strict commit rejects it, those paths only warn), and
	// the dataplane then enforces NONE of that zone's screen checks. The
	// early return below is the worst case for exactly this: when the profile
	// definitions are absent entirely, it prints "No screen profiles
	// configured" and returns, so the stranded reference is never mentioned.
	for _, line := range dpuserspace.ScreenUnresolvedProfileLines(cfg) {
		fmt.Println(line)
	}
	// #7059: and the THIRD state — a zone whose profile IS defined but enables
	// no checks. That resolves, so the block above stays silent, yet the
	// dataplane publishes no snapshot and enforces nothing. Without this the
	// profile renders with its zone list and an empty check inventory, which
	// reads as "trust is screened".
	for _, line := range dpuserspace.ScreenInertProfileLines(cfg) {
		fmt.Println(line)
	}

	if len(cfg.Security.Screen) == 0 {
		fmt.Println("No screen profiles configured")
		return nil
	}

	// Build reverse map: profile name -> zones using it
	zonesByProfile := make(map[string][]string)
	for name, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		if zone.ScreenProfile != "" {
			zonesByProfile[zone.ScreenProfile] = append(
				zonesByProfile[zone.ScreenProfile], name)
		}
	}

	for name, profile := range cfg.Security.Screen {
		// #3476: skip a nil profile map value (reachable on the tolerant /
		// HA-sync config path the runtime walker skips) rather than
		// dereferencing profile.TCP.Land.
		if profile == nil {
			continue
		}
		fmt.Printf("Screen profile: %s\n", name)

		// #3327: drive the enabled-check inventory from the cross-package SSOT
		// (config.ScreenEnabledCheckList -> config.ScreenChecks /
		// config.ScreenThresholds) instead of a hand-built presence list that
		// omitted port-scan, ip-sweep, the source/destination session limits,
		// and icmp-fragment even though the compiler and userspace dataplane
		// fully enforce them. One line per enabled check, threshold-bearing
		// checks annotated with the configured value — the local-CLI peer of
		// the gRPC showScreen renderer, sharing the same SSOT so neither drifts.
		for _, c := range config.ScreenEnabledCheckList(profile) {
			fmt.Printf("  %s\n", c)
		}

		// Zones using this profile
		if zones, ok := zonesByProfile[name]; ok {
			fmt.Printf("  Applied to zones: %s\n", strings.Join(zones, ", "))
		} else {
			fmt.Println("  Applied to zones: (none)")
		}

		fmt.Println()
	}

	// Show screen drop counters (total + per-type)
	if c.dp != nil && c.dp.IsLoaded() {
		// #3345: surface a counter-read failure rather than printing a clean
		// zero that hides a degraded counter bridge.
		var readErr error
		readCtr := func(idx uint32) uint64 {
			v, err := c.dp.ReadGlobalCounter(idx)
			if err != nil && readErr == nil {
				readErr = err
			}
			return v
		}

		totalDrops := readCtr(dataplane.GlobalCtrScreenDrops)
		fmt.Printf("Total screen drops: %d\n", totalDrops)

		if totalDrops > 0 {
			// #3343: shared screen-reason table so the per-reason breakdown
			// includes port-scan / ip-sweep / session-limit and matches the
			// other surfaces.
			for i := range dataplane.ScreenReasonCounters {
				rc := &dataplane.ScreenReasonCounters[i]
				v := readCtr(rc.Index)
				if v > 0 {
					fmt.Printf("  %-25s %d\n", rc.Label+":", v)
				}
			}
		}
		// #3345: check AFTER all reads (incl. the per-type loop) so a failure
		// on ANY read — not just the first — is surfaced. An early check
		// before the loop would let a late read print a stale 0.
		if readErr != nil {
			fmt.Printf("warning: screen counter read failed (counters may be incomplete): %v\n", readErr)
		}
	}

	return nil
}

func (c *CLI) showScreenIdsOption(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	profile, ok := cfg.Security.Screen[name]
	if !ok || profile == nil {
		// #3476: a present-but-nil profile value (tolerant / HA-sync path)
		// must not panic on profile.TCP.Land.
		fmt.Printf("Screen profile '%s' not found\n", name)
		return nil
	}

	fmt.Printf("Screen object status:\n\n")
	fmt.Printf("  %-45s %s\n", "Name", "Value")
	if profile.TCP.Land {
		fmt.Printf("  %-45s %s\n", "TCP land attack", "enabled")
	}
	if profile.TCP.SynFin {
		fmt.Printf("  %-45s %s\n", "TCP SYN+FIN", "enabled")
	}
	if profile.TCP.NoFlag {
		fmt.Printf("  %-45s %s\n", "TCP no-flag", "enabled")
	}
	if profile.TCP.FinNoAck {
		fmt.Printf("  %-45s %s\n", "TCP FIN-no-ACK", "enabled")
	}
	if profile.TCP.WinNuke {
		fmt.Printf("  %-45s %s\n", "TCP WinNuke", "enabled")
	}
	if profile.TCP.SynFrag {
		fmt.Printf("  %-45s %s\n", "TCP SYN fragment", "enabled")
	}
	if profile.TCP.SynFlood != nil {
		fmt.Printf("  %-45s %d\n", "TCP SYN flood attack threshold", profile.TCP.SynFlood.AttackThreshold)
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood source threshold", profile.TCP.SynFlood.SourceThreshold)
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood destination threshold", profile.TCP.SynFlood.DestinationThreshold)
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			fmt.Printf("  %-45s %d\n", "TCP SYN flood timeout", profile.TCP.SynFlood.Timeout)
		}
	}
	if profile.ICMP.PingDeath {
		fmt.Printf("  %-45s %s\n", "ICMP ping of death", "enabled")
	}
	if profile.ICMP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %d\n", "ICMP flood threshold", profile.ICMP.FloodThreshold)
	}
	if profile.IP.SourceRouteOption {
		fmt.Printf("  %-45s %s\n", "IP source route option", "enabled")
	}
	if profile.IP.TearDrop {
		fmt.Printf("  %-45s %s\n", "IP teardrop (tear-drop)", "enabled")
	}
	if profile.UDP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %d\n", "UDP flood threshold", profile.UDP.FloodThreshold)
	}
	// #3327: this enabled-only status table is the same class of hand-built
	// inventory as the detail table — before #3327 it omitted icmp-fragment,
	// port-scan, ip-sweep, and the source/destination session limits even
	// though they are enforced. Surface them (the trailing token matches the
	// canonical config.ScreenCheck* name) so no screen-inventory renderer
	// drifts from the config.ScreenChecks SSOT. Mirrors gRPC showScreenIDSOption.
	if profile.ICMP.Fragment {
		fmt.Printf("  %-45s %s\n", "ICMP fragment (icmp-fragment)", "enabled")
	}
	if profile.TCP.PortScanThreshold > 0 {
		fmt.Printf("  %-45s %d us\n", "TCP port scan window (port-scan)", profile.TCP.PortScanThreshold)
	}
	if profile.IP.IPSweepThreshold > 0 {
		fmt.Printf("  %-45s %d us\n", "IP sweep window (ip-sweep)", profile.IP.IPSweepThreshold)
	}
	if profile.LimitSession.SourceIPBased > 0 {
		fmt.Printf("  %-45s %d\n", "Session limit source (limit-session-source)", profile.LimitSession.SourceIPBased)
	}
	if profile.LimitSession.DestinationIPBased > 0 {
		fmt.Printf("  %-45s %d\n", "Session limit destination (limit-session-destination)", profile.LimitSession.DestinationIPBased)
	}

	// Show zones using this profile
	var zones []string
	for zname, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		if zone.ScreenProfile == name {
			zones = append(zones, zname)
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		fmt.Printf("\n  Bound to zones: %s\n", strings.Join(zones, ", "))
	}
	return nil
}

func (c *CLI) showScreenIdsOptionDetail(name string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	profile, ok := cfg.Security.Screen[name]
	if !ok || profile == nil {
		// #3476: a present-but-nil profile value must not panic on the
		// profile.TCP.* derefs below.
		fmt.Printf("Screen profile '%s' not found\n", name)
		return nil
	}

	fmt.Printf("Screen object status (detail):\n\n")
	fmt.Printf("  %-45s %-12s %s\n", "Name", "Value", "Default")

	// TCP checks
	fmt.Printf("  %-45s %-12s %s\n", "TCP land attack",
		enabledStr(profile.TCP.Land), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP SYN+FIN",
		enabledStr(profile.TCP.SynFin), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP no-flag",
		enabledStr(profile.TCP.NoFlag), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP FIN-no-ACK",
		enabledStr(profile.TCP.FinNoAck), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP WinNuke",
		enabledStr(profile.TCP.WinNuke), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "TCP SYN fragment",
		enabledStr(profile.TCP.SynFrag), "disabled")

	if profile.TCP.SynFlood != nil {
		fmt.Printf("  %-45s %-12s %s\n", "TCP SYN flood protection", "enabled", "disabled")
		fmt.Printf("  %-45s %-12d %s\n", "  Attack threshold",
			profile.TCP.SynFlood.AttackThreshold, "200")
		if profile.TCP.SynFlood.AlarmThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Alarm threshold",
				profile.TCP.SynFlood.AlarmThreshold, "512")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Alarm threshold", "(default)", "512")
		}
		if profile.TCP.SynFlood.SourceThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Source threshold",
				profile.TCP.SynFlood.SourceThreshold, "4000")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Source threshold", "(default)", "4000")
		}
		if profile.TCP.SynFlood.DestinationThreshold > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Destination threshold",
				profile.TCP.SynFlood.DestinationThreshold, "4000")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Destination threshold", "(default)", "4000")
		}
		if profile.TCP.SynFlood.Timeout > 0 {
			fmt.Printf("  %-45s %-12d %s\n", "  Timeout (seconds)",
				profile.TCP.SynFlood.Timeout, "20")
		} else {
			fmt.Printf("  %-45s %-12s %s\n", "  Timeout (seconds)", "(default)", "20")
		}
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "TCP SYN flood protection", "disabled", "disabled")
	}

	// ICMP checks
	fmt.Printf("  %-45s %-12s %s\n", "ICMP ping of death",
		enabledStr(profile.ICMP.PingDeath), "disabled")
	if profile.ICMP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "ICMP flood threshold",
			profile.ICMP.FloodThreshold, "1000")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "ICMP flood threshold", "disabled", "disabled")
	}

	// IP checks
	fmt.Printf("  %-45s %-12s %s\n", "IP source route option",
		enabledStr(profile.IP.SourceRouteOption), "disabled")
	fmt.Printf("  %-45s %-12s %s\n", "IP teardrop",
		enabledStr(profile.IP.TearDrop), "disabled")

	// UDP checks
	if profile.UDP.FloodThreshold > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "UDP flood threshold",
			profile.UDP.FloodThreshold, "1000")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "UDP flood threshold", "disabled", "disabled")
	}

	// #3327: this is the full-universe detail view (every check with its value
	// AND default, including disabled ones), so it cannot be driven by the
	// enabled-only config.ScreenChecks list; instead it is completed with a row
	// for each of the five previously-omitted checks (icmp-fragment, port-scan,
	// ip-sweep, the source/destination session limits) so it can no longer
	// drift from the enforced set. Mirrors gRPC showScreenIDSOptionDetail.
	fmt.Printf("  %-45s %-12s %s\n", "ICMP fragment (icmp-fragment)",
		enabledStr(profile.ICMP.Fragment), "disabled")
	if profile.TCP.PortScanThreshold > 0 {
		fmt.Printf("  %-45s %-12s %s\n", "TCP port scan window (port-scan)", fmt.Sprintf("%d us", profile.TCP.PortScanThreshold), "disabled")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "TCP port scan window (port-scan)", "disabled", "disabled")
	}
	if profile.IP.IPSweepThreshold > 0 {
		fmt.Printf("  %-45s %-12s %s\n", "IP sweep window (ip-sweep)", fmt.Sprintf("%d us", profile.IP.IPSweepThreshold), "disabled")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "IP sweep window (ip-sweep)", "disabled", "disabled")
	}
	if profile.LimitSession.SourceIPBased > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "Session limit source (limit-session-source)", profile.LimitSession.SourceIPBased, "disabled")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "Session limit source (limit-session-source)", "disabled", "disabled")
	}
	if profile.LimitSession.DestinationIPBased > 0 {
		fmt.Printf("  %-45s %-12d %s\n", "Session limit destination (limit-session-destination)", profile.LimitSession.DestinationIPBased, "disabled")
	} else {
		fmt.Printf("  %-45s %-12s %s\n", "Session limit destination (limit-session-destination)", "disabled", "disabled")
	}

	// Zones using this profile
	var zones []string
	for zname, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		if zone.ScreenProfile == name {
			zones = append(zones, zname)
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		fmt.Printf("\n  Bound to zones: %s\n", strings.Join(zones, ", "))
	} else {
		fmt.Printf("\n  Bound to zones: (none)\n")
	}
	return nil
}

func (c *CLI) showScreenStatistics(zoneName string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}
	cr := c.applyResult()
	if cr == nil {
		fmt.Println("no compile result available")
		return nil
	}
	zoneID, ok := cr.ZoneIDs[zoneName]
	if !ok {
		fmt.Printf("Zone '%s' not found\n", zoneName)
		return nil
	}
	fs, err := c.dp.ReadFloodCounters(zoneID)
	screenProfile := ""
	if z, ok := cfg.Security.Zones[zoneName]; ok && z != nil { // #3493: nil zone value
		screenProfile = z.ScreenProfile
	}
	if errors.Is(err, dataplane.ErrCounterNotPopulated) {
		// #3651: the userspace dataplane DOES source per-zone flood counters
		// now, but this zone has none published. Say so explicitly rather than
		// printing a misleading 0 -- ErrCounterNotPopulated covers a helper
		// with no per-zone flood accounting, a zone past the dataplane's
		// hot-path slot capacity (its flood events really are uncounted), and a
		// zone that has simply never tripped a flood check. Naming "not
		// implemented" was accurate under the #3643 HIDE and is now actively
		// misleading. Global/aggregate screen drop visibility remains via
		// `show security screen` and the #3343 per-reason counters.
		fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
		if screenProfile != "" {
			fmt.Printf("  Screen profile: %s\n", screenProfile)
		}
		fmt.Println("  Per-zone flood counters: not available " +
			"(no per-zone flood counts published for this zone: helper predates " +
			"per-zone flood accounting, the zone exceeded the dataplane's " +
			"hot-path slot capacity, or the zone has recorded no flood events)")
		fmt.Print(c.screenSYNCookieCounterRows())
		return nil
	}
	if err != nil {
		fmt.Printf("Error reading flood counters: %v\n", err)
		return nil
	}
	totalSyn, totalICMP, totalUDP := fs.SynCount, fs.ICMPCount, fs.UDPCount
	fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
	if screenProfile != "" {
		fmt.Printf("  Screen profile: %s\n", screenProfile)
	}
	fmt.Printf("  %-30s %s\n", "Counter", "Value")
	fmt.Printf("  %-30s %d\n", "SYN flood events", totalSyn)
	fmt.Printf("  %-30s %d\n", "ICMP flood events", totalICMP)
	fmt.Printf("  %-30s %d\n", "UDP flood events", totalUDP)
	fmt.Print(c.screenSYNCookieCounterRows())
	return nil
}

func (c *CLI) showScreenStatisticsAll() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}
	if c.dp == nil || !c.dp.IsLoaded() {
		fmt.Println("dataplane not loaded")
		return nil
	}
	cr := c.applyResult()
	if cr == nil {
		fmt.Println("no compile result available")
		return nil
	}
	// Collect zone names and sort for deterministic output
	var zones []string
	for name := range cr.ZoneIDs {
		zones = append(zones, name)
	}
	sort.Strings(zones)

	// #3408: surface a per-zone flood-counter read failure as a warning AFTER
	// all zones, rather than silently dropping the zone (which reads as "no
	// flood events for that zone").
	var readErr error
	for _, zoneName := range zones {
		zoneID := cr.ZoneIDs[zoneName]
		fs, err := c.dp.ReadFloodCounters(zoneID)
		screenProfile := ""
		if z, ok := cfg.Security.Zones[zoneName]; ok && z != nil { // #3493: nil zone value
			screenProfile = z.ScreenProfile
		}
		if errors.Is(err, dataplane.ErrCounterNotPopulated) {
			// #3651: per-zone flood counters ARE sourced now; this zone has
			// none published (see the single-zone branch above for the three
			// causes). NOT a read failure -- do not set readErr (no false #3408
			// warning) and do not print a misleading 0; render an explicit
			// "not available" row for the zone.
			fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
			if screenProfile != "" {
				fmt.Printf("  Screen profile: %s\n", screenProfile)
			}
			fmt.Println("  Per-zone flood counters: not available " +
				"(no per-zone flood counts published for this zone: helper predates " +
				"per-zone flood accounting, the zone exceeded the dataplane's " +
				"hot-path slot capacity, or the zone has recorded no flood events)")
			fmt.Println()
			continue
		}
		if err != nil {
			if readErr == nil {
				readErr = err
			}
			// #3344: do not silently drop the zone on a read failure — emit
			// a per-zone error row naming the affected zone. The trailing
			// #3408 warning is an aggregate "incomplete" flag but cannot say
			// WHICH zone is degraded; this row preserves the zone in the
			// listing and matches the single-zone error wording.
			fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
			fmt.Printf("  Error reading flood counters: %v\n", err)
			fmt.Println()
			continue
		}
		fmt.Printf("Screen statistics for zone '%s':\n", zoneName)
		if screenProfile != "" {
			fmt.Printf("  Screen profile: %s\n", screenProfile)
		}
		fmt.Printf("  %-30s %s\n", "Counter", "Value")
		fmt.Printf("  %-30s %d\n", "SYN flood events", fs.SynCount)
		fmt.Printf("  %-30s %d\n", "ICMP flood events", fs.ICMPCount)
		fmt.Printf("  %-30s %d\n", "UDP flood events", fs.UDPCount)
		fmt.Println()
	}
	if rows := c.screenSYNCookieCounterRows(); rows != "" {
		fmt.Print(rows)
	}
	if readErr != nil {
		fmt.Printf("warning: flood counter read failed (screen statistics may be incomplete): %v\n", readErr)
	}
	return nil
}

func (c *CLI) screenSYNCookieCounterRows() string {
	status, err := c.userspaceDataplaneStatus()
	if err != nil {
		return ""
	}
	return dpformat.FormatSYNCookieCounterRows(dpformat.SumSYNCookieCounters(status))
}
