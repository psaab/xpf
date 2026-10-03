package config

import (
	"reflect"
	"testing"
)

func TestHostInboundMulticastRules11571(t *testing.T) {
	got := HostInboundMulticastRules([]string{"VRRP", "oSpF", "OSPF"})
	want := []HostInboundMulticastRule{
		{Protocol: "ospf", Family: "ip", Group: "224.0.0.5"},
		{Protocol: "ospf", Family: "ip", Group: "224.0.0.6"},
		{Protocol: "vrrp", Family: "ip", Group: "224.0.0.18"},
		{Protocol: "vrrp", Family: "ip6", Group: "ff02::12"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HostInboundMulticastRules(case variants and duplicates) = %#v, want %#v", got, want)
	}
	if again := HostInboundMulticastRules([]string{"ospf", "vrrp"}); !reflect.DeepEqual(again, got) {
		t.Fatalf("multicast rules depend on token order: %#v != %#v", again, got)
	}
	if got := HostInboundMulticastRules([]string{"BGP", "isis", "unknown"}); len(got) != 0 {
		t.Fatalf("non-catalog protocols produced multicast rules: %#v", got)
	}

	all := HostInboundMulticastRules([]string{"ALL"})
	seenProtocols := make(map[string]bool)
	for i, rule := range all {
		if rule.Protocol == "" || rule.Group == "" || (rule.Family != "ip" && rule.Family != "ip6") {
			t.Fatalf("invalid expanded multicast rule: %#v", rule)
		}
		seenProtocols[rule.Protocol] = true
		if i > 0 {
			prev := all[i-1]
			if prev.Protocol > rule.Protocol ||
				(prev.Protocol == rule.Protocol && prev.Family > rule.Family) ||
				(prev.Protocol == rule.Protocol && prev.Family == rule.Family && prev.Group > rule.Group) {
				t.Fatalf("expanded rules are not deterministically sorted: %#v", all)
			}
			if prev.Protocol == rule.Protocol && prev.Family == rule.Family && prev.Group == rule.Group {
				t.Fatalf("duplicate expanded multicast rule: %#v", rule)
			}
		}
	}
	for _, token := range HostInboundMulticastProtocolTokens() {
		if !seenProtocols[token] {
			t.Errorf("protocols all did not expand catalog token %q", token)
		}
	}
	if !reflect.DeepEqual(all, HostInboundMulticastRules([]string{"all"})) {
		t.Fatal("protocols all expansion is not case-insensitive")
	}
}

func TestHostInboundMulticastGroups11571(t *testing.T) {
	want := map[string][]string{
		"ip":  {"224.0.0.1", "224.0.0.13", "224.0.0.18", "224.0.0.2", "224.0.0.22", "224.0.0.4", "224.0.0.5", "224.0.0.6", "224.0.0.9"},
		"ip6": {"ff02::12", "ff02::5", "ff02::6", "ff02::9", "ff02::d"},
	}
	for family, expected := range want {
		got := HostInboundMulticastGroupsForFamily(family)
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("HostInboundMulticastGroupsForFamily(%q) = %#v, want sorted unique %#v", family, got, expected)
		}
		if len(got) > 0 {
			got[0] = "mutated"
		}
		if next := HostInboundMulticastGroupsForFamily(family); !reflect.DeepEqual(next, expected) {
			t.Fatalf("HostInboundMulticastGroupsForFamily(%q) aliases catalog storage: %#v", family, next)
		}
	}
	if got := HostInboundMulticastGroupsForFamily("inet"); got != nil {
		t.Fatalf("unknown family returned catalog groups: %#v", got)
	}
	if got := HostInboundMulticastGroupsForFamily(" IP "); !reflect.DeepEqual(got, want["ip"]) {
		t.Fatalf("family matching is not case-insensitive: %#v", got)
	}
}
