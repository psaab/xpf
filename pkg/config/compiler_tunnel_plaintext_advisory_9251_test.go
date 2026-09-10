package config

import (
	"reflect"
	"strings"
	"testing"
)

// #9251: the plaintext advisories' group headings and unzoned caveat are no
// longer shared, and plaintextAdvisoryWording has no defaults. A comment saying
// "every field is required" protects nothing; these cells are the guard.

// TestPlaintextAdvisoryWordingsAreCompleteAndDistinct: every field of both
// wordings is set, and the sentences that say what a zone MEANS differ between
// the protocols.
func TestPlaintextAdvisoryWordingsAreCompleteAndDistinct(t *testing.T) {
	ipsec := secureTunnelPlaintextAdvisoryWording()
	wg := wireGuardPlaintextAdvisoryWording()
	for name, w := range map[string]plaintextAdvisoryWording{"ipsec_5619": ipsec, "wireguard_5618": wg} {
		v := reflect.ValueOf(w)
		for i := 0; i < v.NumField(); i++ {
			if strings.TrimSpace(v.Field(i).String()) == "" {
				t.Errorf("%s: plaintextAdvisoryWording.%s is empty. The renderer has no "+
					"default, so this advisory would render a blank line where its own "+
					"account belongs", name, v.Type().Field(i).Name)
			}
		}
	}
	for _, f := range []struct{ field, ipsec, wg string }{
		{"zonedHeading", ipsec.zonedHeading, wg.zonedHeading},
		{"zonedSuffix", ipsec.zonedSuffix, wg.zonedSuffix},
		{"unzonedHeading", ipsec.unzonedHeading, wg.unzonedHeading},
		{"unzonedCaveat", ipsec.unzonedCaveat, wg.unzonedCaveat},
	} {
		if f.ipsec == f.wg {
			t.Errorf("%s is identical for IPsec and WireGuard (%q). Since #8274 a "+
				"WireGuard tunnel's zone is enforced on its dataplane path and an IPsec "+
				"tunnel's is not, so one sentence cannot be true of both (#9251)",
				f.field, f.wg)
		}
	}
}

// TestPlaintextAdvisoriesDoNotBorrowEachOthersAccount drives BOTH advisories
// through one compile, each with a zoned and an unzoned tunnel, and checks the
// RENDERED text: each carries its own headings and caveat and none of the
// other's. The field-level cell above stays green if the RENDERER ignores a
// field and writes a fixed string; this one does not.
func TestPlaintextAdvisoriesDoNotBorrowEachOthersAccount(t *testing.T) {
	var lines []string
	lines = append(lines, wgTunnel5618("wg0", 0, 51820, wgKeyA, wgKeyB)...)
	lines = append(lines, wgTunnel5618("wg1", 0, 51821, wgKeyB, wgKeyC)...)
	lines = append(lines,
		"set security zones security-zone vpn interfaces wg0.0",
		"set security ipsec vpn zoned bind-interface st0.0",
		"set security zones security-zone vpn2 interfaces st0.0",
		"set security ipsec vpn bare bind-interface st1.0",
	)
	cfg := compileWarn5618(t, lines...)

	wgAdv := plaintextWarnings5618(cfg)
	ipsecAdv := plaintextWarnings5619(cfg)
	if len(wgAdv) != 1 || len(ipsecAdv) != 1 {
		t.Fatalf("want one advisory per protocol, got WireGuard %d and IPsec %d: %v",
			len(wgAdv), len(ipsecAdv), cfg.Warnings)
	}
	for _, own := range []string{ipsecPlaintextZonedHeading, ipsecPlaintextUnzonedHeading, ipsecPlaintextUnzonedCaveat} {
		if !strings.Contains(ipsecAdv[0], own) {
			t.Errorf("the IPsec advisory lost its own sentence %q: %s", own, ipsecAdv[0])
		}
		if strings.Contains(wgAdv[0], own) {
			t.Errorf("the WireGuard advisory rendered IPsec's sentence %q: %s", own, wgAdv[0])
		}
	}
	for _, own := range []string{wgPlaintextZonedHeading, wgPlaintextUnzonedHeading, wgPlaintextUnzonedCaveat} {
		if !strings.Contains(wgAdv[0], own) {
			t.Errorf("the WireGuard advisory lost its own sentence %q: %s", own, wgAdv[0])
		}
		if strings.Contains(ipsecAdv[0], own) {
			t.Errorf("the IPsec advisory rendered WireGuard's sentence %q: %s", own, ipsecAdv[0])
		}
	}
}
