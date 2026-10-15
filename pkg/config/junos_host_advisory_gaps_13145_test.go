package config

import (
	"strings"
	"testing"
)

// #13145 (D2-14): three host-inbound advisory gaps in
// compiler_validate_warn_host_inbound.go.
//
//  1. A `from-zone any to-zone junos-host` application-narrowed permit
//     passed zoneByName(cfg, "any") == nil to the #7374 gap check, so the
//     warning was skipped for every zone the wildcard covers.
//  2. A global `to-zone junos-host` permit scanned every zone, ignoring
//     p.Match.FromZones, quarantine exclusions and lifeline-only zones,
//     so it warned on zones the policy does not apply to / that are not
//     renderable.
//  3. validateHostInboundOverrideReplaceWarnings (#6515) compared the
//     interface override against the RAW zone service list instead of
//     ZoneLevelSystemServicesFor, falsely reporting #7490-withheld dhcp
//     as lost to the override.
//
// Warnings stay WARN-only: these are advisories, not commit errors.

func junosHostWarnContains(ws []string, name, substr string) bool {
	for _, w := range ws {
		if strings.Contains(w, name) && strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// Case 1: from-zone any must expand across zones for the #7374 gap check.
func TestJunosHostFromZoneAnyAppGapWarns13145(t *testing.T) {
	lines := policyBase7374([]string{"junos-ssh"}, []string{"ssh", "https", "ping"})
	// Rewrite the zone-pair as from-zone any (same test helper builds untrust).
	for i, l := range lines {
		lines[i] = strings.ReplaceAll(l, "from-zone untrust to-zone junos-host", "from-zone any to-zone junos-host")
	}
	cfg := compileGap7374(t, lines)
	ws := validateJunosHostDirectDeliveryWarnings(cfg)
	if !junosHostWarnContains(ws, "app-only", "application-restricted permit") {
		t.Fatalf("from-zone any app-narrowed permit with a zone gap must warn (#7374); got %v", ws)
	}
}

// Control for case 1: from-zone any covering exactly the admitted set is silent.
func TestJunosHostFromZoneAnyNoGapSilent13145(t *testing.T) {
	lines := policyBase7374([]string{"junos-ssh", "junos-ping"}, []string{"ssh", "ping"})
	for i, l := range lines {
		lines[i] = strings.ReplaceAll(l, "from-zone untrust to-zone junos-host", "from-zone any to-zone junos-host")
	}
	cfg := compileGap7374(t, lines)
	for _, w := range validateJunosHostDirectDeliveryWarnings(cfg) {
		if strings.Contains(w, "application-restricted permit") {
			t.Fatalf("from-zone any permit covering the admit set must not warn; got %v", w)
		}
	}
}

// Case 2a: a global permit scoped by from-zone to a zone WITH a gap warns;
// scoped only to a zone WITHOUT a gap (or to no applicable zone) is silent.
func TestJunosHostGlobalFromZonesScoping13145(t *testing.T) {
	base := func() []string {
		return []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.2.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.3.1/24",
			"set security zones security-zone untrust interfaces ge-0/0/0.0",
			"set security zones security-zone untrust host-inbound-traffic system-services ssh",
			"set security zones security-zone untrust host-inbound-traffic system-services https",
			"set security zones security-zone trust interfaces ge-0/0/1.0",
			"set security zones security-zone trust host-inbound-traffic system-services ssh",
		}
	}
	global := func(from string) []string {
		lines := base()
		lines = append(lines,
			"set security policies global policy g-only match source-address any",
			"set security policies global policy g-only match destination-address any",
			"set security policies global policy g-only match application junos-ssh",
			"set security policies global policy g-only match to-zone junos-host",
			"set security policies global policy g-only then permit")
		if from != "" {
			lines = append(lines, "set security policies global policy g-only match from-zone "+from)
		}
		return lines
	}

	// Scoped to trust (ssh only, no gap): must NOT warn even though untrust has a gap.
	cfg := compileGap7374(t, global("trust"))
	for _, w := range validateJunosHostDirectDeliveryWarnings(cfg) {
		if strings.Contains(w, "g-only") && strings.Contains(w, "application-restricted permit") {
			t.Fatalf("global permit scoped to gap-free trust must not warn; got %v", w)
		}
	}
	// Scoped to untrust (ssh+https gap): must warn.
	cfg = compileGap7374(t, global("untrust"))
	if !junosHostWarnContains(validateJunosHostDirectDeliveryWarnings(cfg), "g-only", "application-restricted permit") {
		t.Fatalf("global permit scoped to untrust with gap must warn")
	}
	// Unscoped global: warns (any zone gap).
	cfg = compileGap7374(t, global(""))
	if !junosHostWarnContains(validateJunosHostDirectDeliveryWarnings(cfg), "g-only", "application-restricted permit") {
		t.Fatalf("unscoped global permit with a zone gap must warn")
	}
}

// Case 2b: a global permit scoped only to a lifeline-only zone (fxp0) must
// not emit the #7374 gap warning for that zone.
func TestJunosHostGlobalLifelineOnlySilent13145(t *testing.T) {
	cfg := compileGap7374(t, []string{
		"set interfaces fxp0 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone mgmt interfaces fxp0.0",
		"set security zones security-zone mgmt host-inbound-traffic system-services ssh",
		"set security zones security-zone mgmt host-inbound-traffic system-services https",
		"set security policies global policy g-life match source-address any",
		"set security policies global policy g-life match destination-address any",
		"set security policies global policy g-life match application junos-ssh",
		"set security policies global policy g-life match from-zone mgmt",
		"set security policies global policy g-life match to-zone junos-host",
		"set security policies global policy g-life then permit",
	})
	for _, w := range validateJunosHostDirectDeliveryWarnings(cfg) {
		if strings.Contains(w, "g-life") && strings.Contains(w, "application-restricted permit") {
			t.Fatalf("global permit applying only to lifeline-only mgmt zone must not warn (#7374); got %v", w)
		}
	}
}

// Case 3: #7490-withheld dhcp must not be reported as lost to an override.
func TestHostInboundOverrideWithheldDHCPNotLost13145(t *testing.T) {
	cfg := compileGap7374(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set system services dhcp-local-server group g1 interface ge-0/0/0.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services ping",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ping",
	})
	ws := validateHostInboundOverrideReplaceWarnings(cfg)
	for _, w := range ws {
		if strings.Contains(w, "dhcp") {
			t.Fatalf("#7490-withheld dhcp must not be reported as lost by #6515 override warning; got %v", ws)
		}
	}
	if len(ws) != 0 {
		t.Fatalf("override repeating the #7490-effective zone set loses nothing; want no warnings, got %v", ws)
	}
}

// Control for case 3: a genuinely lost non-withheld token still warns.
func TestHostInboundOverrideRealLossStillWarns13145(t *testing.T) {
	cfg := compileGap7374(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services https",
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh",
	})
	ws := validateHostInboundOverrideReplaceWarnings(cfg)
	if len(ws) != 1 || !strings.Contains(ws[0], "https") {
		t.Fatalf("override dropping https must still warn (#6515); got %v", ws)
	}
}
