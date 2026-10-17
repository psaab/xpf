package config

import "testing"

// TestApplicationMatchWidened14355 pins the widening/never-matching split
// #14355 relies on: only drops that lost a constraint widen the compiled
// term; a retained port/icmp constraint on a protocol that cannot satisfy
// it never matches and is not widening. Settings leaves never widen.
func TestApplicationMatchWidened14355(t *testing.T) {
	u8 := func(v uint8) *uint8 { return &v }
	cases := []struct {
		name string
		app  *Application
		want bool
	}{
		{"value-less destination-port", &Application{Protocol: "tcp", IncompleteDirectLeaves: []string{"destination-port"}}, true},
		{"malformed icmp-type", &Application{Protocol: "icmp", UnknownICMP: []string{"bogus"}}, true},
		{"icmp-code without type", &Application{Protocol: "icmp", ICMPCode: u8(0)}, true},
		{"conflicting destination-port", &Application{Protocol: "tcp", DestinationPort: "80", DuplicateDirectLeaves: []string{"destination-port"}}, true},
		{"port on protocol 0", &Application{Protocol: "0", DestinationPort: "80"}, false},
		{"port on gre", &Application{Protocol: "gre", DestinationPort: "80"}, false},
		{"source-port on icmp", &Application{Protocol: "icmp", SourcePort: "123"}, false},
		{"icmp-type on tcp", &Application{Protocol: "tcp", DestinationPort: "80", ICMPType: u8(8)}, false},
		{"settings leaf only", &Application{Protocol: "tcp", DestinationPort: "80", IncompleteDirectLeaves: []string{"inactivity-timeout"}}, false},
		{"clean", &Application{Protocol: "tcp", DestinationPort: "80"}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := ApplicationMatchWidened(tc.app); got != tc.want {
			t.Errorf("%s: ApplicationMatchWidened = %v, want %v (drops=%q)", tc.name, got, tc.want, ApplicationMatchDrops(tc.app))
		}
	}
}
