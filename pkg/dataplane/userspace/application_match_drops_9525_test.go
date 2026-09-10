package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9525 on the wire: a tolerant-path application drop refuses the reference, so
// the policy carries the #3261 __unsupported__ sentinel (the helper refuses the
// whole snapshot) and PolicyContentRejectionReasons names the application.

func policyText9525(apps, ref, action, def string) string {
	if apps != "" {
		apps = "applications { " + apps + " } "
	}
	return apps + `security { zones { security-zone trust; security-zone untrust; } ` +
		`policies { default-policy { ` + def + `; } from-zone trust to-zone untrust { policy p1 { ` +
		`match { source-address any; destination-address any; application ` + ref + `; } ` +
		`then { ` + action + `; } } } } }`
}

func wireTerms9525(t *testing.T, cfg *config.Config) []PolicyApplicationSnapshot {
	t.Helper()
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("policy snapshot build: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 policy rule, got %d", len(rules))
	}
	return rules[0].ApplicationTerms
}

func TestTolerantApplicationDropRefusesThePolicy9525(t *testing.T) {
	cases := []struct {
		name, apps, action, def string
	}{
		{"V3 icmp destination-port 80 under a deny", `application a { protocol icmp; destination-port 80; }`, "deny", "permit-all"},
		{"V4 term icmp-type 999 under a permit", `application a { term t1 { protocol icmp; icmp-type 999; } }`, "permit", "deny-all"},
		{"icmp source-port under a deny", `application a { protocol icmp; source-port 80; }`, "deny", "permit-all"},
		{"sctp destination-port under a permit", `application a { protocol sctp; destination-port 80; }`, "permit", "deny-all"},
		{"icmp-type on tcp under a deny", `application a { protocol tcp; destination-port 22; icmp-type 8; }`, "deny", "permit-all"},
		{"icmp-code without icmp-type under a permit", `application a { term t1 { protocol icmp; icmp-code 3; } }`, "permit", "deny-all"},
		{"dangling destination-port under a permit", `application a { protocol tcp; destination-port; }`, "permit", "deny-all"},
		{"conflicting destination-port in a term under a deny", `application a { term t1 { protocol tcp; destination-port 22; destination-port 23; } }`, "deny", "permit-all"},
		{"mixed application nested in a set under a deny", `application inner { protocol tcp; destination-port 23; term t1 { protocol udp; destination-port 53; } } application-set a { application inner; application junos-ssh; }`, "deny", "permit-all"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := lenientHier9571(t, policyText9525(c.apps, "a", c.action, c.def))
			terms := wireTerms9525(t, cfg)
			if len(terms) != 1 || terms[0].Protocol != unsupportedApplicationSentinel {
				t.Fatalf("the policy must lower to the __unsupported__ sentinel alone; wire terms: %+v", terms)
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) != 1 || !strings.Contains(reasons[0], `application "a"`) {
				t.Fatalf("want one mirror reason naming application \"a\"; got %q", reasons)
			}
		})
	}
}

// TestTolerantApplicationControlsKeepTheirWire9525 pins the terms that must still
// install, byte for byte on the wire encoding: the issue's icmp-type 8 and
// junos-icmp-all controls, a clean port term, and a settings-only drop (a
// malformed timeout), which the tolerant path keeps installing.
func TestTolerantApplicationControlsKeepTheirWire9525(t *testing.T) {
	u8 := func(v uint8) *uint8 { return &v }
	cases := []struct {
		name, apps, ref string
		want            []PolicyApplicationSnapshot
	}{
		{"icmp-type 8 term", `application a { term t1 { protocol icmp; icmp-type 8; } }`, "a",
			[]PolicyApplicationSnapshot{{Name: "a-t1", Protocol: "icmp", ICMPType: u8(8)}}},
		{"junos-icmp-all", ``, "junos-icmp-all",
			[]PolicyApplicationSnapshot{{Name: "junos-icmp-all", Protocol: "icmp"}}},
		{"tcp destination-port 22", `application a { protocol tcp; destination-port 22; }`, "a",
			[]PolicyApplicationSnapshot{{Name: "a", Protocol: "tcp", DestinationPort: "22"}}},
		{"malformed inactivity-timeout", `application a { protocol tcp; destination-port 22; inactivity-timeout thirty; }`, "a",
			[]PolicyApplicationSnapshot{{Name: "a", Protocol: "tcp", DestinationPort: "22"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := lenientHier9571(t, policyText9525(c.apps, c.ref, "permit", "deny-all"))
			got, err := json.Marshal(wireTerms9525(t, cfg))
			if err != nil {
				t.Fatal(err)
			}
			want, err := json.Marshal(c.want)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("control wire changed:\n got %s\nwant %s", got, want)
			}
			if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
				t.Fatalf("control must not be refused; reasons %q", reasons)
			}
		})
	}
}
