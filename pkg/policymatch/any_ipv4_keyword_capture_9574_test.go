package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9574 — `show security match-policies` with an object named after a
// match-all CIDR. Channel: config.CompileConfig (strict).

func TestObjectNamedAMatchAllCIDRDoesNotCaptureTheKeywordVerdict9574(t *testing.T) {
	base := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies default-policy permit-all",
	}
	deny := func(src string) []string { return policy9523("d1", src, "any", "deny") }
	for _, tc := range []struct {
		name    string
		lines   []string
		probe   string
		dst     string
		matched bool
	}{
		{"any-ipv4 with address 0.0.0.0/0", append([]string{"set security address-book global address 0.0.0.0/0 10.99.0.0/16"}, deny("any-ipv4")...), "10.0.1.5", "10.0.2.5", true},
		{"any-ipv6 with address ::/0", append([]string{"set security address-book global address ::/0 2001:db8:99::/48"}, deny("any-ipv6")...), "2001:db8:1::5", "2001:db8:2::5", true},
		{"any-ipv4 with address-set 0.0.0.0/0", append([]string{
			"set security address-book global address a1 10.99.0.0/16",
			"set security address-book global address-set 0.0.0.0/0 address a1",
		}, deny("any-ipv4")...), "10.0.1.5", "10.0.2.5", true},
		{"any-ipv4 with zone-local 0.0.0.0/0", append([]string{
			"set security zones security-zone trust address-book address 0.0.0.0/0 10.99.0.0/16",
		}, deny("any-ipv4")...), "10.0.1.5", "10.0.2.5", true},
		// Family scope survives: any-ipv4 does not match IPv6.
		{"any-ipv4 does not match IPv6", append([]string{"set security address-book global address 0.0.0.0/0 10.99.0.0/16"}, deny("any-ipv4")...), "2001:db8:1::5", "2001:db8:2::5", false},
		// Name-before-literal: a TYPED 0.0.0.0/0 names the object.
		{"typed 0.0.0.0/0 names the object (outside it)", append([]string{"set security address-book global address 0.0.0.0/0 10.99.0.0/16"}, deny("0.0.0.0/0")...), "10.0.1.5", "10.0.2.5", false},
		{"typed 0.0.0.0/0 names the object (inside it)", append([]string{"set security address-book global address 0.0.0.0/0 10.99.0.0/16"}, deny("0.0.0.0/0")...), "10.99.0.5", "10.0.2.5", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := compileSet9523(t, append(append([]string{}, base...), tc.lines...), false)
			if err != nil {
				t.Fatalf("fixture must commit: %v", err)
			}
			res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP(tc.probe), DstIP: net.ParseIP(tc.dst), Protocol: "tcp", SrcPort: 40000, DstPort: 80})
			if res.ContentRejected {
				t.Fatalf("unexpected ContentRejected: %v", res.ContentRejectionReasons)
			}
			if tc.matched && (!res.Matched || res.PolicyName != "d1" || res.Action != config.PolicyDeny) {
				t.Errorf("#9574: want the deny to match %s, got Matched=%v Policy=%q DefaultUsed=%v", tc.probe, res.Matched, res.PolicyName, res.DefaultUsed)
			}
			if !tc.matched && res.Matched {
				t.Errorf("want no match for %s, got Policy=%q", tc.probe, res.PolicyName)
			}
		})
	}
}
