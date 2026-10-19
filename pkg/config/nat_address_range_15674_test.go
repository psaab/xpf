package config

import (
	"strings"
	"testing"
)

// #15674: expandAddressRange silently rewrote non-/32 endpoint masks to
// /32 (net.ParseCIDR discards the mask), rejected valid IPv6 ranges, and
// hard-failed CompileConfigLenient on malformed/reversed ranges.
//
// RED on pre-fix: (a) /24 endpoints compiled to /32s with no record;
// (b) IPv6 ranges errored on both paths; (c) reversed ranges errored
// on the lenient path.

func TestExpandAddressRange15674(t *testing.T) {
	// (b) IPv6 bare and /128 forms expand to /128 members.
	for _, tc := range [][2]string{
		{"2001:db8::1", "2001:db8::10"},
		{"2001:db8::1/128", "2001:db8::10/128"},
	} {
		got, err := expandAddressRange(tc[0], tc[1])
		if err != nil {
			t.Fatalf("expandAddressRange(%q,%q): %v", tc[0], tc[1], err)
		}
		if len(got) != 16 || got[0] != "2001:db8::1/128" || got[15] != "2001:db8::10/128" {
			t.Fatalf("IPv6 expansion = %v", got)
		}
	}
	// IPv4 bare and /32 forms still expand.
	got, err := expandAddressRange("203.0.113.1", "203.0.113.3")
	if err != nil || len(got) != 3 || got[0] != "203.0.113.1/32" {
		t.Fatalf("IPv4 expansion = %v err=%v", got, err)
	}
	// Non-host masks rejected, not silently rewritten.
	for _, tc := range [][2]string{
		{"203.0.113.1/24", "203.0.113.5/24"},
		{"2001:db8::1/64", "2001:db8::5/64"},
		{"203.0.113.1/24", "203.0.113.5"},
	} {
		if _, err := expandAddressRange(tc[0], tc[1]); err == nil {
			t.Errorf("expandAddressRange(%q,%q) accepted non-host mask", tc[0], tc[1])
		}
	}
	// Mixed family rejected.
	if _, err := expandAddressRange("203.0.113.1", "2001:db8::1"); err == nil {
		t.Error("mixed-family range accepted")
	}
	// Reversed rejected by the expander (recorded by callers).
	if _, err := expandAddressRange("203.0.113.10", "203.0.113.1"); err == nil {
		t.Error("reversed range accepted")
	}
	// Oversized IPv6 range still sentinel-capped.
	if _, err := expandAddressRange("2001:db8::1", "2001:db8::1:1"); err == nil {
		t.Error("oversized IPv6 range accepted")
	}
}

func TestPoolAddressRangeMaskAndV6_15674(t *testing.T) {
	// (a) /24 endpoints: strict rejects, lenient loads without the range,
	// recorded as invalid, pool marked unusable (no members).
	cfg, lerr, serr := compileBoth8814(t, natPoolText8814("address 203.0.113.1/24 to 203.0.113.5/24;"))
	if lerr != nil {
		t.Fatalf("lenient must load (#15674): %v", lerr)
	}
	if serr == nil {
		t.Fatal("strict must reject non-host-mask range")
	}
	pool := cfg.Security.NAT.SourcePools["p1"]
	if pool == nil || len(pool.InvalidAddressRanges) != 1 {
		t.Fatalf("InvalidAddressRanges not recorded: %+v", pool)
	}
	if len(pool.Addresses) != 0 {
		t.Fatalf("invalid range installed addresses %v (silent /32 rewrite)", pool.Addresses)
	}
	if r := SourceNATPoolUnusableReason(pool); r == "" {
		t.Error("pool of only an invalid range must be unusable on lenient path")
	}
	foundWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "203.0.113.1/24") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Errorf("lenient warnings do not name the invalid range: %v", cfg.Warnings)
	}

	// (b) IPv6 pool ranges compile on both paths to /128 members.
	for _, body := range []string{
		"address 2001:db8::1 to 2001:db8::10;",
		"address 2001:db8::1/128 to 2001:db8::10/128;",
	} {
		cfg2, lerr2, serr2 := compileBoth8814(t, natPoolText8814(body))
		if lerr2 != nil || serr2 != nil {
			t.Fatalf("%s: lenient=%v strict=%v", body, lerr2, serr2)
		}
		p := cfg2.Security.NAT.SourcePools["p1"]
		if len(p.Addresses) != 16 || p.Addresses[0] != "2001:db8::1/128" {
			t.Fatalf("%s: addresses=%v", body, p.Addresses)
		}
		if r := SourceNATPoolUnusableReason(p); r != "" {
			t.Errorf("%s: valid IPv6 pool unusable: %s", body, r)
		}
	}

	// (c) Reversed range: lenient warns/loads, strict rejects.
	cfg3, lerr3, serr3 := compileBoth8814(t, natPoolText8814("address 203.0.113.10 to 203.0.113.1;"))
	if lerr3 != nil {
		t.Fatalf("reversed range bricked lenient load: %v", lerr3)
	}
	if serr3 == nil {
		t.Fatal("strict must reject reversed range")
	}
	if len(cfg3.Warnings) == 0 {
		t.Error("reversed range produced no lenient warning")
	}
	if p := cfg3.Security.NAT.SourcePools["p1"]; p == nil || len(p.InvalidAddressRanges) != 1 {
		t.Fatalf("reversed range not recorded: %+v", p)
	}
}

func TestProxyARPAddressRange15674(t *testing.T) {
	// Non-host mask via proxy-arp: strict rejects, lenient loads.
	cfg, lerr, serr := compileBoth8814(t, proxyARPText8814("address 203.0.113.1/24 to 203.0.113.5/24;"))
	if lerr != nil {
		t.Fatalf("lenient proxy-arp must load: %v", lerr)
	}
	if serr == nil {
		t.Fatal("strict must reject proxy-arp non-host-mask range")
	}
	if len(cfg.Security.NAT.ProxyARP) != 1 || len(cfg.Security.NAT.ProxyARP[0].InvalidRangeSpecs) != 1 {
		t.Fatalf("proxy InvalidRangeSpecs not recorded: %+v", cfg.Security.NAT.ProxyARP)
	}
	if len(cfg.Security.NAT.ProxyARP[0].Addresses) != 0 {
		t.Fatalf("proxy invalid range installed %v", cfg.Security.NAT.ProxyARP[0].Addresses)
	}
	// IPv6 proxy-arp range expands to /128s on both paths.
	cfg2, lerr2, serr2 := compileBoth8814(t, proxyARPText8814("address 2001:db8::1 to 2001:db8::3;"))
	if lerr2 != nil || serr2 != nil {
		t.Fatalf("IPv6 proxy range: lenient=%v strict=%v", lerr2, serr2)
	}
	if got := cfg2.Security.NAT.ProxyARP[0].Addresses; len(got) != 3 || got[0] != "2001:db8::1/128" {
		t.Fatalf("IPv6 proxy expansion = %v", got)
	}
	// Reversed proxy range: lenient loads, strict rejects.
	_, lerr3, serr3 := compileBoth8814(t, proxyARPText8814("address 203.0.113.9 to 203.0.113.1;"))
	if lerr3 != nil {
		t.Fatalf("reversed proxy range bricked lenient: %v", lerr3)
	}
	if serr3 == nil {
		t.Fatal("strict must reject reversed proxy range")
	}
}
