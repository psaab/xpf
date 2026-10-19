package config

import (
	"strings"
	"testing"
)

// #15207 A18-02/A18-03 regression.

// A18-02: typed ICMPv6 + simple + multi-term Junos predefined apps.
func TestPredefined15207_ICMPv6TypedApps(t *testing.T) {
	cases := []struct {
		name string
		typ  uint8
		code *uint8
	}{
		{"junos-icmp6-dst-unreach-route", 1, u8p(0)},
		{"junos-icmp6-dst-unreach-admin", 1, u8p(1)},
		{"junos-icmp6-dst-unreach-beyond", 1, u8p(2)},
		{"junos-icmp6-dst-unreach-addr", 1, u8p(3)},
		{"junos-icmp6-dst-unreach-port", 1, u8p(4)},
		{"junos-icmp6-packet-too-big", 2, u8p(0)},
		{"junos-icmp6-time-exceed-transit", 3, u8p(0)},
		{"junos-icmp6-time-exceed-reassembly", 3, u8p(1)},
		{"junos-icmp6-param-prob-header", 4, u8p(0)},
		{"junos-icmp6-param-prob-nexthdr", 4, u8p(1)},
		{"junos-icmp6-param-prob-option", 4, u8p(2)},
		{"junos-icmp6-echo-request", 128, nil},
		{"junos-icmp6-echoreq", 128, nil},
		{"junos-icmp6-echo-reply", 129, nil},
	}
	for _, tc := range cases {
		app, ok := PredefinedApplications[tc.name]
		if !ok {
			t.Errorf("%s missing from PredefinedApplications", tc.name)
			continue
		}
		if app.Protocol != "icmpv6" {
			t.Errorf("%s Protocol=%q want icmpv6", tc.name, app.Protocol)
		}
		if app.ICMPType == nil || *app.ICMPType != tc.typ {
			t.Errorf("%s ICMPType=%v want %d", tc.name, app.ICMPType, tc.typ)
		}
		if tc.code == nil {
			if app.ICMPCode != nil {
				t.Errorf("%s ICMPCode=%d want nil", tc.name, *app.ICMPCode)
			}
		} else if app.ICMPCode == nil || *app.ICMPCode != *tc.code {
			t.Errorf("%s ICMPCode=%v want %d", tc.name, app.ICMPCode, *tc.code)
		}
	}
}

func TestPredefined15207_SimpleAndSets(t *testing.T) {
	simple := map[string]struct{ proto, port string }{
		"junos-pptp":     {"tcp", "1723"},
		"junos-sctp-any": {"132", ""},
		"junos-rsh":      {"tcp", "514"},
	}
	for name, want := range simple {
		app, ok := PredefinedApplications[name]
		if !ok {
			t.Errorf("%s missing", name)
			continue
		}
		if app.Protocol != want.proto || app.DestinationPort != want.port {
			t.Errorf("%s = %s/%s want %s/%s", name, app.Protocol, app.DestinationPort, want.proto, want.port)
		}
	}
	sets := map[string][]string{
		"junos-talk":  {"junos-talk-udp", "junos-talk-tcp"},
		"junos-ntalk": {"junos-ntalk-udp", "junos-ntalk-tcp"},
		"junos-stun":  {"junos-stun-udp", "junos-stun-tcp"},
		"junos-mgcp":  {"junos-mgcp-ua", "junos-mgcp-ca"},
	}
	for name, want := range sets {
		set, ok := PredefinedApplicationSets[name]
		if !ok {
			t.Errorf("set %s missing", name)
			continue
		}
		if strings.Join(set.Applications, ",") != strings.Join(want, ",") {
			t.Errorf("set %s members=%v want %v", name, set.Applications, want)
		}
		if _, isApp := PredefinedApplications[name]; isApp {
			t.Errorf("%s must be set-only (app would shadow set)", name)
		}
	}
	// members exist
	for _, m := range []string{"junos-talk-udp", "junos-talk-tcp", "junos-stun-udp", "junos-stun-tcp"} {
		if _, ok := PredefinedApplications[m]; !ok {
			t.Errorf("member %s missing", m)
		}
	}
}

// A18-02 acceptance via CompileConfig: policy referencing new names commits.
func TestPredefined15207_PolicyCommits(t *testing.T) {
	for _, name := range []string{"junos-icmp6-packet-too-big", "junos-pptp", "junos-sctp-any", "junos-talk", "junos-stun", "junos-rsh", "junos-mgcp"} {
		tree := flatTreeFromSets(t,
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p match source-address any",
			"set security policies from-zone trust to-zone untrust policy p match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p match application "+name,
			"set security policies from-zone trust to-zone untrust policy p then permit",
		)
		if _, err := CompileConfig(tree); err != nil {
			t.Errorf("policy with %s: %v", name, err)
		}
	}
}

// A18-03: never accepted and maps to sentinel.
func TestAppTimeoutNever15207(t *testing.T) {
	for _, leaf := range []string{"inactivity-timeout", "timeout"} {
		tree := flatTreeFromSets(t, referencedTimeoutApp(leaf, "never")...)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("%s never: %v", leaf, err)
		}
		app := cfg.Applications.Applications["BAD"]
		if app == nil || !app.InactivityTimeoutNever || app.InactivityTimeout != 0 {
			t.Fatalf("%s never: got %+v", leaf, app)
		}
	}
	// term form
	tree := flatTreeFromSets(t, referencedTimeoutTermApp("never")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("term never: %v", err)
	}
	if app := cfg.Applications.Applications["MULTI-t1"]; app == nil || !app.InactivityTimeoutNever {
		t.Fatalf("term never: got %+v", app)
	}
	// control: numeric still works, malformed still rejected
	tree = flatTreeFromSets(t, referencedTimeoutApp("inactivity-timeout", "thirty")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("thirty must still reject")
	}
	if err := SchemaValidate(flatTreeFromSets(t, referencedTimeoutApp("inactivity-timeout", "never")...), nil); err != nil {
		t.Fatalf("SchemaValidate never: %v", err)
	}
}
