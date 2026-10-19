package config

import "fmt"

// Screen inventory presentation (#3327).
//
// REST (`GET /api/v1/security/screen`) and gRPC (`GetScreen`) both expose a
// structured inventory of the configured screen profiles. Before #3327 each
// API carried its own byte-identical copy of the enabled-checks helper, and
// both copies omitted several checks the compiler and userspace dataplane
// fully enforce (port-scan, ip-sweep, the source/destination session limits,
// and the ICMP-fragment check) plus every numeric threshold. An operator or
// controller reading structured state could therefore believe those screens
// were absent even when configured and active, and could never read the
// configured threshold values.
//
// ScreenChecks and ScreenThresholds are the single source of truth consumed by
// both APIs, so the inventory can never again drift from the enforced set. The
// presence set returned by ScreenChecks is kept a superset of the checks
// buildScreenSnapshots (pkg/dataplane/userspace/screens.go) feeds to the
// dataplane: every enforced check has an inventory entry.

// Screen check name constants. These are the stable wire/JSON tokens emitted in
// the REST/gRPC screen inventory `checks` list. Threshold-bearing checks reuse
// the same token as the key in the ScreenThresholds map.
const (
	ScreenCheckSynFlood                = "syn-flood"
	ScreenCheckLand                    = "land"
	ScreenCheckWinNuke                 = "winnuke"
	ScreenCheckSynFrag                 = "syn-frag"
	ScreenCheckSynFin                  = "syn-fin"
	ScreenCheckTCPNoFlag               = "tcp-no-flag"
	ScreenCheckFinNoAck                = "fin-no-ack"
	ScreenCheckPingDeath               = "ping-death"
	ScreenCheckICMPFlood               = "icmp-flood"
	ScreenCheckUDPFlood                = "udp-flood"
	ScreenCheckSourceRouteOption       = "source-route-option"
	ScreenCheckTearDrop                = "tear-drop"
	ScreenCheckICMPFragment            = "icmp-fragment"
	ScreenCheckPortScan                = "port-scan"
	ScreenCheckIPSweep                 = "ip-sweep"
	ScreenCheckLimitSessionSource      = "limit-session-source"
	ScreenCheckLimitSessionDestination = "limit-session-destination"
	ScreenCheckAlarmWithoutDrop        = "alarm-without-drop"
)

// Threshold keys that do not map onto a single presence check name. The
// SYN-flood profile carries several distinct numeric thresholds, so they are
// keyed individually rather than collapsed onto the `syn-flood` presence token.
const (
	ScreenThreshSynFloodAttack      = "syn-flood-attack-threshold"
	ScreenThreshSynFloodAlarm       = "syn-flood-alarm-threshold"
	ScreenThreshSynFloodSource      = "syn-flood-source-threshold"
	ScreenThreshSynFloodDestination = "syn-flood-destination-threshold"
	ScreenThreshSynFloodTimeout     = "syn-flood-timeout"
)

// ScreenChecks returns the enabled screen check names for a profile, in a
// stable order. A nil profile (reachable on the tolerant / HA-sync config path
// the runtime walker skips) renders as "no checks" (nil) rather than panicking.
//
// The returned set is a superset of the checks the dataplane enforces for the
// profile: every check buildScreenSnapshots feeds to the userspace helper has a
// corresponding token here. This is the single source of truth for both the
// REST and gRPC screen inventories (#3327).
func ScreenChecks(p *ScreenProfile) []string {
	if p == nil {
		return nil
	}
	var checks []string
	if p.TCP.SynFlood != nil {
		checks = append(checks, ScreenCheckSynFlood)
	}
	if p.TCP.Land {
		checks = append(checks, ScreenCheckLand)
	}
	if p.TCP.WinNuke {
		checks = append(checks, ScreenCheckWinNuke)
	}
	if p.TCP.SynFrag {
		checks = append(checks, ScreenCheckSynFrag)
	}
	if p.TCP.SynFin {
		checks = append(checks, ScreenCheckSynFin)
	}
	if p.TCP.NoFlag {
		checks = append(checks, ScreenCheckTCPNoFlag)
	}
	if p.TCP.FinNoAck {
		checks = append(checks, ScreenCheckFinNoAck)
	}
	if p.TCP.PortScanThreshold > 0 {
		checks = append(checks, ScreenCheckPortScan)
	}
	if p.ICMP.PingDeath {
		checks = append(checks, ScreenCheckPingDeath)
	}
	if p.ICMP.Fragment {
		checks = append(checks, ScreenCheckICMPFragment)
	}
	if p.ICMP.FloodThreshold > 0 {
		checks = append(checks, ScreenCheckICMPFlood)
	}
	if p.UDP.FloodThreshold > 0 {
		checks = append(checks, ScreenCheckUDPFlood)
	}
	if p.IP.SourceRouteOption {
		checks = append(checks, ScreenCheckSourceRouteOption)
	}
	if p.IP.TearDrop {
		checks = append(checks, ScreenCheckTearDrop)
	}
	if p.IP.IPSweepThreshold > 0 {
		checks = append(checks, ScreenCheckIPSweep)
	}
	if p.LimitSession.SourceIPBased > 0 {
		checks = append(checks, ScreenCheckLimitSessionSource)
	}
	if p.LimitSession.DestinationIPBased > 0 {
		checks = append(checks, ScreenCheckLimitSessionDestination)
	}
	// #15649 V10-04: alarm-without-drop is a profile-wide modifier, not a
	// check, but the structured inventory must expose it or an audit-only
	// profile is indistinguishable from a drop-enforcing one. It sorts
	// last so existing check order is unchanged for drop profiles (which
	// never emit it).
	if p.AlarmWithoutDrop {
		checks = append(checks, ScreenCheckAlarmWithoutDrop)
	}
	return checks
}

// ScreenThresholds returns the configured numeric thresholds for a profile,
// keyed by check name (or by a SYN-flood-specific key for the several
// SYN-flood sub-thresholds). Only thresholds explicitly configured to a
// positive value are included; a nil profile or one carrying no numeric
// threshold returns nil. This lets a structured-state consumer distinguish a
// default threshold from an intentionally tight (or accidentally clamped) one
// (#3327).
func ScreenThresholds(p *ScreenProfile) map[string]int {
	if p == nil {
		return nil
	}
	thresholds := make(map[string]int)
	if p.ICMP.FloodThreshold > 0 {
		thresholds[ScreenCheckICMPFlood] = p.ICMP.FloodThreshold
	}
	if p.UDP.FloodThreshold > 0 {
		thresholds[ScreenCheckUDPFlood] = p.UDP.FloodThreshold
	}
	if p.TCP.PortScanThreshold > 0 {
		thresholds[ScreenCheckPortScan] = p.TCP.PortScanThreshold
	}
	if p.IP.IPSweepThreshold > 0 {
		thresholds[ScreenCheckIPSweep] = p.IP.IPSweepThreshold
	}
	if p.LimitSession.SourceIPBased > 0 {
		thresholds[ScreenCheckLimitSessionSource] = p.LimitSession.SourceIPBased
	}
	if p.LimitSession.DestinationIPBased > 0 {
		thresholds[ScreenCheckLimitSessionDestination] = p.LimitSession.DestinationIPBased
	}
	if sf := p.TCP.SynFlood; sf != nil {
		if sf.AttackThreshold > 0 {
			thresholds[ScreenThreshSynFloodAttack] = sf.AttackThreshold
		}
		if sf.AlarmThreshold > 0 {
			thresholds[ScreenThreshSynFloodAlarm] = sf.AlarmThreshold
		}
		if sf.SourceThreshold > 0 {
			thresholds[ScreenThreshSynFloodSource] = sf.SourceThreshold
		}
		if sf.DestinationThreshold > 0 {
			thresholds[ScreenThreshSynFloodDestination] = sf.DestinationThreshold
		}
		if sf.Timeout > 0 {
			thresholds[ScreenThreshSynFloodTimeout] = sf.Timeout
		}
	}
	if len(thresholds) == 0 {
		return nil
	}
	return thresholds
}

// ScreenEnabledCheckList renders the enabled screen checks for a profile as a
// stable, SSOT-sourced list, each threshold-bearing token annotated with its
// configured value (e.g. "icmp-flood(threshold:1000)"). It is the single
// rendering of the enabled-screen inventory shared by every enabled-only text
// renderer — REST/gRPC `show security zones`/`show security screen` and the
// equivalent local-CLI views — so none of them can drift from ScreenChecks /
// ScreenThresholds (#3327). Before #3327 each renderer hand-built its own
// presence list and silently omitted port-scan, ip-sweep, the source/
// destination session limits, and icmp-fragment even though the compiler and
// userspace dataplane fully enforce them. A nil profile or one with no enabled
// check returns nil.
func ScreenEnabledCheckList(p *ScreenProfile) []string {
	checks := ScreenChecks(p)
	if len(checks) == 0 {
		return nil
	}
	thresholds := ScreenThresholds(p)
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		// SYN-flood keys its numeric value under the attack-threshold key
		// rather than the bare "syn-flood" presence token.
		key := c
		if c == ScreenCheckSynFlood {
			key = ScreenThreshSynFloodAttack
		}
		if v, ok := thresholds[key]; ok {
			out = append(out, fmt.Sprintf("%s(threshold:%d)", c, v))
			continue
		}
		out = append(out, c)
	}
	return out
}
