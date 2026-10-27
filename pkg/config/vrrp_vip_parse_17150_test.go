package config

import "testing"

// TestParseVRRPVIPAgreement17150 pins the shared VIP parse (#17150):
// one verdict per string for the commit-time counter and the exported
// parse pkg/vrrp consumes. Before #17150 the commit-time counter used
// ParseCIDR-first while pkg/vrrp's strip-at-"/" helpers counted
// "10.0.0.1/33" as a real IPv4 address.
//
// FAIL-ON-REVERT: restoring a strip-then-ParseIP counter (or making
// ParseVRRPVIP accept "/33") counts the malformed rows below and fails.
func TestParseVRRPVIPAgreement17150(t *testing.T) {
	cases := []struct {
		vip    string
		wantOK bool
		wantV4 bool
	}{
		{"10.0.0.1/33", false, false},
		{"10.0.0.1/x", false, false},
		{"10.0.0.1", true, true},
		{"10.0.0.1/24", true, true},
		{"FE80::AB/64", true, false},
		{"2001:0DB8::10/64", true, false},
		{"not-an-address", false, false},
	}
	for _, c := range cases {
		p, ok := ParseVRRPVIP(c.vip)
		if ok != c.wantOK {
			t.Errorf("ParseVRRPVIP(%q) ok=%v, want %v", c.vip, ok, c.wantOK)
			continue
		}
		if ok && p.Addr().Is4() != c.wantV4 {
			t.Errorf("ParseVRRPVIP(%q) Is4=%v, want %v", c.vip, p.Addr().Is4(), c.wantV4)
		}
		n4, n6 := countVRRPVIPFamilies([]string{c.vip})
		if (n4+n6 == 1) != c.wantOK {
			t.Errorf("countVRRPVIPFamilies(%q) = (%d,%d), wantOK=%v", c.vip, n4, n6, c.wantOK)
		}
		if c.wantOK && c.wantV4 && n4 != 1 {
			t.Errorf("countVRRPVIPFamilies(%q) n4=%d, want 1", c.vip, n4)
		}
		if c.wantOK && !c.wantV4 && n6 != 1 {
			t.Errorf("countVRRPVIPFamilies(%q) n6=%d, want 1", c.vip, n6)
		}
		// The host helper must agree: nil exactly when the parse fails.
		if (vrrpVIPHostIP(c.vip) == nil) == c.wantOK {
			t.Errorf("vrrpVIPHostIP(%q) nil-mismatch with ParseVRRPVIP ok=%v", c.vip, c.wantOK)
		}
	}

	// Capacity-counter agreement cell: cap-sized valid set + malformed
	// entry still fits; cap-sized + one distinct valid VIP does not.
	vips := vipCountV4(MaxVRRPVirtualAddressesIPv4)
	withBad := append(append([]string(nil), vips...), "10.0.0.1/33")
	if err := vrrpVIPCountErr("test", withBad); err != nil {
		t.Errorf("vrrpVIPCountErr(cap + 10.0.0.1/33) = %v, want nil (malformed skipped)", err)
	}
	over := append(append([]string(nil), vips...), vipCountV4(MaxVRRPVirtualAddressesIPv4 + 1)[MaxVRRPVirtualAddressesIPv4])
	if err := vrrpVIPCountErr("test", over); err == nil {
		t.Error("vrrpVIPCountErr(cap + distinct valid) = nil, want over-capacity error (control)")
	}

	// Dedupe identity: bare == host-route, prefix-preserving otherwise.
	if DedupeVRRPVIPs([]string{"10.0.0.1", "10.0.0.1/32"}) != nil &&
		len(DedupeVRRPVIPs([]string{"10.0.0.1", "10.0.0.1/32"})) != 1 {
		t.Errorf("DedupeVRRPVIPs(bare, /32) = %v, want 1 entry",
			DedupeVRRPVIPs([]string{"10.0.0.1", "10.0.0.1/32"}))
	}
	if len(DedupeVRRPVIPs([]string{"10.0.0.1/24", "10.0.0.1/32"})) != 2 {
		t.Error("DedupeVRRPVIPs(/24, /32) must keep 2 entries (prefix-preserving, #11482)")
	}
	if len(DedupeVRRPVIPs([]string{"2001:db8::10/64", "2001:0DB8:0:0:0:0:0:10/64"})) != 1 {
		t.Error("DedupeVRRPVIPs(uppercase expanded alias) must keep 1 entry")
	}
}
