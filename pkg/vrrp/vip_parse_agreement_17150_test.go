package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestVIPParseAgreement17150 is the #17150 regression: every surviving VIP
// helper and both capacity counters must give ONE verdict per string.
// Before the shared config.ParseVRRPVIP parse, the strip-at-"/" helpers
// (splitVIPsByFamily, vipFamiliesIn, familyOfAddrs) counted a malformed
// CIDR such as "10.0.0.1/33" as a real IPv4 address while the
// ParseCIDR-first helpers (parseVIPIdentity, config counter) ignored it.
//
// FAIL-ON-REVERT: reverting any helper to strip-then-ParseIP makes the
// "10.0.0.1/33" / "10.0.0.1/x" rows count as IPv4 on that side only and
// this test fails on the disagreement.
func TestVIPParseAgreement17150(t *testing.T) {
	cases := []struct {
		vip     string
		wantOK  bool
		wantV4  bool // family when wantOK
		wantFam string
	}{
		{"10.0.0.1/33", false, false, ""},          // malformed prefix: not a VIP anywhere
		{"10.0.0.1/x", false, false, ""},           // malformed prefix text
		{"10.0.0.1", true, true, "inet"},           // bare v4
		{"10.0.0.1/24", true, true, "inet"},        // v4 CIDR
		{"10.0.0.1/32", true, true, "inet"},        // v4 host route
		{"FE80::AB/64", true, false, "inet6"},      // uppercase v6 CIDR
		{"2001:0DB8::10/64", true, false, "inet6"}, // expanded uppercase v6
		{"not-an-address", false, false, ""},
		{"::ffff:10.0.0.1", true, true, "inet"},      // bare mapped == v4 host
		{"::ffff:10.0.0.1/120", true, true, "inet"},  // mapped CIDR /120 == v4 /24
		{"::ffff:10.0.0.1/128", true, true, "inet"},  // mapped /128 == v4 /32
		{"::ffff:10.0.0.1/96", true, true, "inet"},   // mapped /96 == v4 /0
		{"::ffff:10.0.0.1/95", true, false, "inet6"}, // sub-96 mapped: kept mapped
	}
	for _, c := range cases {
		p, ok := config.ParseVRRPVIP(c.vip)
		if ok != c.wantOK {
			t.Errorf("ParseVRRPVIP(%q) ok=%v, want %v", c.vip, ok, c.wantOK)
			continue
		}
		if ok && p.Addr().Is4() != c.wantV4 {
			t.Errorf("ParseVRRPVIP(%q) Is4=%v, want %v", c.vip, p.Addr().Is4(), c.wantV4)
		}

		v4, v6 := splitVIPsByFamily([]string{c.vip})
		if got := len(v4) + len(v6); (got == 1) != c.wantOK {
			t.Errorf("splitVIPsByFamily(%q) counted %d, wantOK=%v", c.vip, got, c.wantOK)
		}
		if c.wantOK {
			if c.wantV4 && (len(v4) != 1 || len(v6) != 0) {
				t.Errorf("splitVIPsByFamily(%q) = v4:%d v6:%d, want v4 only", c.vip, len(v4), len(v6))
			}
			if !c.wantV4 && (len(v6) != 1 || len(v4) != 0) {
				t.Errorf("splitVIPsByFamily(%q) = v4:%d v6:%d, want v6 only", c.vip, len(v4), len(v6))
			}
		}

		has4, has6 := vipFamiliesIn([]string{c.vip})
		if has4 != (c.wantOK && c.wantV4) || has6 != (c.wantOK && !c.wantV4) {
			t.Errorf("vipFamiliesIn(%q) = (%v,%v), wantOK=%v v4=%v", c.vip, has4, has6, c.wantOK, c.wantV4)
		}

		if fam := familyOfAddrs([]string{c.vip}); fam != c.wantFam {
			t.Errorf("familyOfAddrs(%q) = %q, want %q", c.vip, fam, c.wantFam)
		}

		host, fam, pok := parseVIPIdentity(c.vip)
		if pok != c.wantOK || fam != c.wantFam {
			t.Errorf("parseVIPIdentity(%q) = (%q,%q,%v), want ok=%v fam=%q", c.vip, host, fam, pok, c.wantOK, c.wantFam)
		}
		if pok && host == "" {
			t.Errorf("parseVIPIdentity(%q) ok with empty host", c.vip)
		}

		// canonAddr is the #2516 exclusion key: it must be the net.IP
		// lookup form. A mapped VIP must key as "10.0.0.1" (the form
		// resolveLocalIPv4's ip4.String() produces), never as
		// "::ffff:10.0.0.1", or the VIP leaks into source selection.
		if c.wantOK && (c.vip == "::ffff:10.0.0.1" || c.vip == "::ffff:10.0.0.1/120" || c.vip == "::ffff:10.0.0.1/128" || c.vip == "::ffff:10.0.0.1/96" || c.vip == "::ffff:10.0.0.1/95") {
			wantCanon := "::ffff:10.0.0.1"
			if c.vip != "::ffff:10.0.0.1/95" {
				wantCanon = "10.0.0.1"
			}
			if got := canonAddr(c.vip); got != wantCanon {
				t.Errorf("canonAddr(%q) = %q, want %q (net.IP lookup form)", c.vip, got, wantCanon)
			}
			if pok && host != canonAddr(c.vip) {
				t.Errorf("parseVIPIdentity(%q) host %q != canonAddr %q: claim and exclusion keys must agree", c.vip, host, canonAddr(c.vip))
			}
		}
		if c.wantOK {
			if err := checkAdvertCapacity([]string{c.vip}); err != nil {
				t.Errorf("checkAdvertCapacity(%q) = %v, want nil (single valid VIP)", c.vip, err)
			}
		}
	}

	// Both capacity counters: a malformed entry must not inflate either
	// family on either side. 255 valid v4 VIPs + one "/33" must fit the
	// runtime guard exactly as the commit-time counter counts 255.
	vips := make([]string, 0, MaxConfiguredVIPs(false)+1)
	for i := 1; i <= MaxConfiguredVIPs(false); i++ {
		vips = append(vips, capacityBoundaryVIP(false, i))
	}
	vips = append(vips, "10.0.0.1/33")
	if err := checkAdvertCapacity(vips); err != nil {
		t.Errorf("checkAdvertCapacity(255 valid + 10.0.0.1/33) = %v, want nil: "+
			"the malformed entry must be skipped, not counted as a 256th IPv4 VIP", err)
	}
	// Control: a 256th DISTINCT valid VIP still exceeds the guard.
	over := append(append([]string(nil), vips[:MaxConfiguredVIPs(false)]...), capacityBoundaryVIP(false, MaxConfiguredVIPs(false)+1))
	if err := checkAdvertCapacity(over); err == nil {
		t.Error("checkAdvertCapacity(256 distinct valid IPv4 VIPs) = nil, want over-capacity error (control)")
	}

	// Host identity: bare and host-route spellings collide; prefix differs.
	if h1, _, ok1 := parseVIPIdentity("10.0.0.1"); !ok1 || h1 != "10.0.0.1" {
		t.Errorf("parseVIPIdentity(bare) = (%q,%v), want 10.0.0.1", h1, ok1)
	}
	if config.VRRPVIPIdentity("10.0.0.1") != config.VRRPVIPIdentity("10.0.0.1/32") {
		t.Errorf("VRRPVIPIdentity: bare and /32 spellings must share one identity, got %q vs %q",
			config.VRRPVIPIdentity("10.0.0.1"), config.VRRPVIPIdentity("10.0.0.1/32"))
	}
	if config.VRRPVIPIdentity("10.0.0.1/24") == config.VRRPVIPIdentity("10.0.0.1/32") {
		t.Error("VRRPVIPIdentity: /24 and /32 must stay distinct (prefix-preserving, #11482)")
	}
	if got := config.DedupeVRRPVIPs([]string{"10.0.0.1", "10.0.0.1/32", "10.0.0.2/24"}); len(got) != 2 {
		t.Errorf("DedupeVRRPVIPs(bare + /32 alias + distinct) = %v, want 2 entries", got)
	}
	// Mapped spellings claim as the IPv4 host they denote.
	if h, fam, ok := parseVIPIdentity("::ffff:10.0.0.1/120"); !ok || h != "10.0.0.1" || fam != "inet" {
		t.Errorf("parseVIPIdentity(mapped /120) = (%q,%q,%v), want (10.0.0.1,inet,true)", h, fam, ok)
	}
	if h, fam, ok := parseVIPIdentity("::ffff:10.0.0.1"); !ok || h != "10.0.0.1" || fam != "inet" {
		t.Errorf("parseVIPIdentity(bare mapped) = (%q,%q,%v), want (10.0.0.1,inet,true)", h, fam, ok)
	}
	// Dedupe: mapped /120 == v4 /24 (one identity); bare mapped == v4 /32 == bare v4 (one identity) — two distinct prefix identities total.
	if got := config.DedupeVRRPVIPs([]string{"::ffff:10.0.0.1/120", "10.0.0.1/24", "::ffff:10.0.0.1", "10.0.0.1/32", "10.0.0.1"}); len(got) != 2 {
		t.Errorf("DedupeVRRPVIPs(mapped aliases) = %v, want 2 entries (10.0.0.1/24 and 10.0.0.1/32)", got)
	}
}
