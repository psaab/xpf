package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11340 — version-bounded Junos defaults define junos-ping/junos-pingv6 as
// unconstrained ICMP/ICMPv6 applications. The separate junos-icmp-ping object
// is echo-request-only (type 8). These tests pin the predefined app expansion
// that is sent to the userspace matcher.

func icmpAppCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	return cfg
}

func TestJunosPingApplicationsExpandUnconstrained_11340(t *testing.T) {
	for _, tc := range []struct {
		name, protocol string
	}{
		{"junos-ping", "icmp"},
		{"junos-pingv6", "icmpv6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			terms, ok := expandUserspacePolicyApplications(icmpAppCfg(), []string{tc.name})
			if !ok || len(terms) != 1 {
				t.Fatalf("expandUserspacePolicyApplications(%s): got ok=%v terms=%d, want one term",
					tc.name, ok, len(terms))
			}
			if terms[0].Protocol != tc.protocol {
				t.Fatalf("%s Protocol = %q, want %q", tc.name, terms[0].Protocol, tc.protocol)
			}
			if terms[0].ICMPType != nil || terms[0].ICMPCode != nil {
				t.Fatalf("%s must match all types/codes, got type=%v code=%v",
					tc.name, terms[0].ICMPType, terms[0].ICMPCode)
			}
		})
	}
}

func TestJunosIcmpPingExpandsToEchoRequestTypeConstraint_11340(t *testing.T) {
	terms, ok := expandUserspacePolicyApplications(icmpAppCfg(), []string{"junos-icmp-ping"})
	if !ok || len(terms) != 1 {
		t.Fatalf("expandUserspacePolicyApplications(junos-icmp-ping): got ok=%v terms=%d, want one term",
			ok, len(terms))
	}
	if terms[0].Protocol != "icmp" || terms[0].ICMPType == nil || *terms[0].ICMPType != 8 {
		t.Fatalf("junos-icmp-ping term = %+v, want ICMP type 8", terms[0])
	}
	if terms[0].ICMPCode != nil {
		t.Fatalf("junos-icmp-ping ICMPCode = %d, want nil", *terms[0].ICMPCode)
	}
}

func TestJunosIcmpAllStaysUnconstrained(t *testing.T) {
	cfg := icmpAppCfg()
	for _, name := range []string{"junos-icmp-all", "junos-icmp6-all"} {
		terms, ok := expandUserspacePolicyApplications(cfg, []string{name})
		if !ok {
			t.Fatalf("expandUserspacePolicyApplications(%s) ok=false, want true", name)
		}
		if len(terms) != 1 {
			t.Fatalf("%s: len(terms) = %d, want 1", name, len(terms))
		}
		if terms[0].ICMPType != nil {
			t.Fatalf("%s: ICMPType = %d, want nil (match all ICMP)", name, *terms[0].ICMPType)
		}
		if terms[0].ICMPCode != nil {
			t.Fatalf("%s: ICMPCode = %d, want nil", name, *terms[0].ICMPCode)
		}
	}
}
