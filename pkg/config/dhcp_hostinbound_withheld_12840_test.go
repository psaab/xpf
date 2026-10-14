package config

import (
	"strings"
	"testing"
)

// #12840 — the #6460 bypass advisory consulted the EFFECTIVE host-inbound
// set, which #7490 deliberately withholds the zone-level `dhcp`/`bootp`
// authorization from DHCP server/relay interfaces. Every compiled
// dhcp-local-server config whose zone admitted dhcp at the zone level (named
// or via `all`) therefore drew a false #6460 warning whose remedy — add the
// token TO THE ZONE — could never take effect on that interface: the token
// was already there, and the flip withholds it regardless. The dedicated
// #6519/#7490 advisory already reports the withholding, with the
// per-interface restatement as its remedy.
//
// These tests go through CompileConfig so the #7490 stamp is derived by the
// real P5 hook, exactly as in production; hand-built fixtures that never
// stamp would stay green through the defect.

func compile12840(t *testing.T, lines ...string) *Config {
	t.Helper()
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func warningsContaining(warnings []string, substr string) []string {
	var out []string
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			out = append(out, w)
		}
	}
	return out
}

const zoneRemedy12840 = "add `host-inbound-traffic system-services dhcp` to zone \"trust\""

func TestDHCPBypassWarningSuppressedWhenZoneTokenWithheld12840(t *testing.T) {
	for _, tc := range []struct {
		name    string
		zoneSvc string
	}{
		{"zone names dhcp", "dhcp"},
		{"zone names all", "all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compile12840(t,
				"set interfaces ge-0/0/5 unit 0 family inet address 10.0.5.1/24",
				"set security zones security-zone trust interfaces ge-0/0/5.0",
				"set security zones security-zone trust host-inbound-traffic system-services "+tc.zoneSvc,
				"set system services dhcp-local-server group lan interface ge-0/0/5.0",
			)
			if got := warningsContaining(cfg.Warnings, "(#6460)"); len(got) != 0 {
				t.Fatalf("zone-level %q is withheld from the server interface by #7490 and already reported by the #6519 advisory; no #6460 warning may fire, got %v", tc.zoneSvc, got)
			}
			// The withholding must still be reported — by the dedicated
			// advisory, whose remedy is the per-interface restatement.
			if got := warningsContaining(cfg.Warnings, "NO LONGER authorizes"); len(got) == 0 {
				t.Fatalf("precondition: the #6519/#7490 withholding advisory must fire so suppression is not silence, warnings=%v", cfg.Warnings)
			}
		})
	}
}

func TestDHCPBypassWarningStillFiresWhenZoneOmitsToken12840(t *testing.T) {
	cfg := compile12840(t,
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.5.1/24",
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	got := warningsContaining(cfg.Warnings, "(#6460)")
	if len(got) != 1 {
		t.Fatalf("a zone that never admitted dhcp must still draw the #6460 warning, got %v (all warnings %v)", got, cfg.Warnings)
	}
	if !strings.Contains(got[0], zoneRemedy12840) {
		t.Fatalf("a genuine zone-level omission keeps the zone-level remedy, got %q", got[0])
	}
}

func TestDHCPBypassWarningWithheldRemedyIsPerInterface12840(t *testing.T) {
	// Zone admits dhcp, but a per-interface stanza REPLACES the zone set
	// (#6515) and omits dhcp: the warning is genuine, yet neither
	// "the zone omits it" nor "add it to the zone" is true or effective.
	cfg := compile12840(t,
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.5.1/24",
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set security zones security-zone trust interfaces ge-0/0/5.0 host-inbound-traffic system-services ssh",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	got := warningsContaining(cfg.Warnings, "(#6460)")
	if len(got) != 1 {
		t.Fatalf("an interface override omitting dhcp must still draw the #6460 warning, got %v (all warnings %v)", got, cfg.Warnings)
	}
	if strings.Contains(got[0], zoneRemedy12840) {
		t.Fatalf("the remedy must not send the operator to the zone stanza that is withheld/replaced here, got %q", got[0])
	}
	if !strings.Contains(got[0], "to interface \"ge-0/0/5.0\" in zone \"trust\"") {
		t.Fatalf("the remedy must name the per-interface stanza, got %q", got[0])
	}
}

func TestDHCPBypassWarningUnaffectedFamilies12840(t *testing.T) {
	// dhcpv6 is outside the #7490 vendor sentence: a zone that omits dhcpv6
	// still draws the v6 warning even on a compiled server config.
	cfg := compile12840(t,
		"set interfaces ge-0/0/5 unit 0 family inet6 address 2001:db8::1/64",
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set system services dhcpv6-local-server group lan6 interface ge-0/0/5.0",
	)
	if got := warningsContaining(cfg.Warnings, "(#6460)"); len(got) != 1 || !strings.Contains(got[0], "dhcpv6-local-server") {
		t.Fatalf("the v6 family must keep warning when the zone omits dhcpv6, got %v (all warnings %v)", got, cfg.Warnings)
	}

	// bootp alone never admitted dhcp: the v4 warning still fires.
	cfg4 := compile12840(t,
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.5.1/24",
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services bootp",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	if got := warningsContaining(cfg4.Warnings, "(#6460)"); len(got) != 1 {
		t.Fatalf("a bootp-only zone never admitted dhcp, so the #6460 warning must fire, got %v (all warnings %v)", got, cfg4.Warnings)
	}
}
