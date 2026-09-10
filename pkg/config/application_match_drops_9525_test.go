package config

import (
	"strings"
	"testing"
)

// #9525: which tolerant-path application drops refuse the policy, and which do
// not. The userspace wire and the simulator verdicts are bound in
// pkg/dataplane/userspace and pkg/policymatch; this file binds the predicate
// itself, one arm per row, against the strict gate that downgrades each member.

func policyText9525(apps, ref, action, def string) string {
	if apps != "" {
		apps = "applications { " + apps + " } "
	}
	return apps + `security { zones { security-zone trust; security-zone untrust; } ` +
		`policies { default-policy { ` + def + `; } from-zone trust to-zone untrust { policy p1 { ` +
		`match { source-address any; destination-address any; application ` + ref + `; } ` +
		`then { ` + action + `; } } } } }`
}

func parse9525(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func lenient9525(t *testing.T, text string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(parse9525(t, text))
	if err != nil {
		t.Fatalf("the tolerant compile must still accept the fixture (#1960 no-brick): %v", err)
	}
	return cfg
}

// TestApplicationReferenceMatchDropsNamesEachMember9525 walks every refused
// member. Each row is first confirmed to be a member of the downgrade (strict
// rejects it, the tolerant compile accepts it), then the predicate must name
// the specific drop, so a row cannot pass on another arm's reason.
func TestApplicationReferenceMatchDropsNamesEachMember9525(t *testing.T) {
	mixedInner := `application inner { protocol tcp; destination-port 23; term t1 { protocol udp; destination-port 53; } }`
	cases := []struct {
		name, apps, want string
	}{
		{"destination-port on icmp", `application a { protocol icmp; destination-port 80; }`,
			`destination-port "80" on protocol "icmp", which presents no destination port`},
		{"destination-port on gre", `application a { protocol gre; destination-port 80; }`,
			`destination-port "80" on protocol "gre"`},
		{"destination-port on sctp", `application a { protocol sctp; destination-port 80; }`,
			`destination-port "80" on protocol "sctp"`},
		{"source-port on icmp", `application a { protocol icmp; source-port 80; }`,
			`source-port "80" on protocol "icmp", which the dataplane compares with the sender-chosen ICMP query Identifier`},
		{"source-port on icmpv6", `application a { protocol icmpv6; source-port 80; }`,
			`on protocol "icmpv6", which the dataplane compares with the sender-chosen ICMP query Identifier`},
		{"source-port on gre", `application a { protocol gre; source-port 80; }`,
			`source-port "80" on protocol "gre", which presents no source port`},
		{"icmp-type 999 direct", `application a { protocol icmp; icmp-type 999; }`,
			`icmp-type/icmp-code "999" is not an integer in 0..255`},
		{"icmp-type 999 in a term", `application a { term t1 { protocol icmp; icmp-type 999; } }`,
			`application "a-t1": icmp-type/icmp-code "999"`},
		{"icmp-code 999 in a term", `application a { term t1 { protocol icmp; icmp-type 8; icmp-code 999; } }`,
			`icmp-type/icmp-code "999"`},
		{"icmp-type on tcp", `application a { protocol tcp; destination-port 22; icmp-type 8; }`,
			`icmp-type/icmp-code on non-ICMP protocol "tcp"`},
		{"icmp-code without icmp-type", `application a { term t1 { protocol icmp; icmp-code 3; } }`,
			`icmp-code without icmp-type`},
		{"dangling destination-port", `application a { protocol tcp; destination-port; }`,
			`statement "destination-port" is missing its value`},
		{"dangling icmp-type in a term", `application a { term t1 { protocol icmp; icmp-type; } }`,
			`term statement "icmp-type" is missing its value`},
		{"conflicting destination-port", `application a { protocol tcp; destination-port 22; destination-port 23; }`,
			`conflicting "destination-port" values, of which only the last is enforced`},
		{"conflicting destination-port in a term", `application a { term t1 { protocol tcp; destination-port 22; destination-port 23; } }`,
			`conflicting "destination-port" values inside a term`},
		{"conflicting protocol", `application a { protocol tcp; protocol udp; destination-port 53; }`,
			`conflicting "protocol" values`},
		{"direct body mixed with a term", `application a { protocol tcp; destination-port 23; term t1 { protocol udp; destination-port 53; } }`,
			`application "a": its direct match body was discarded`},
		{"mixed application nested in a set", mixedInner + ` application-set a { application inner; application junos-ssh; }`,
			`application "inner": its direct match body was discarded`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := policyText9525(c.apps, "a", "deny", "permit-all")
			if _, err := CompileConfig(parse9525(t, text)); err == nil {
				t.Fatalf("fixture is not a member of the downgrade: strict CompileConfig accepted it")
			}
			cfg := lenient9525(t, text)
			drops := ApplicationReferenceMatchDrops("a", &cfg.Applications)
			if !strings.Contains(strings.Join(drops, "\n"), c.want) {
				t.Fatalf("drops for %q must name %q; got %q", c.name, c.want, drops)
			}
		})
	}
}

// TestApplicationReferenceMatchDropsControls9525 is the load-bearing half: what
// must still be installed. The first group commits cleanly. The second group is
// strict-rejected but only tunes a matched session (a timeout or an alg), so the
// tolerant path keeps installing it; refusing it would drop transit for a
// config whose match is exactly what was authored.
func TestApplicationReferenceMatchDropsControls9525(t *testing.T) {
	cases := []struct {
		name, apps, ref string
		strictAccepts   bool
	}{
		{"tcp destination-port", `application a { protocol tcp; destination-port 22; }`, "a", true},
		{"numeric tcp destination-port", `application a { protocol 6; destination-port 22; }`, "a", true},
		{"udp source and destination port", `application a { protocol udp; source-port 1024-65535; destination-port 53; }`, "a", true},
		{"icmp with no ports", `application a { protocol icmp; }`, "a", true},
		{"gre with no ports", `application a { protocol gre; }`, "a", true},
		{"icmp-type 8 in a term", `application a { term t1 { protocol icmp; icmp-type 8; } }`, "a", true},
		{"protocol 1 with icmp-type 8", `application a { term t1 { protocol 1; icmp-type 8; } }`, "a", true},
		{"icmpv6 type and code", `application a { term t1 { protocol icmpv6; icmp-type 1; icmp-code 4; } }`, "a", true},
		{"same-value repeat", `application a { term t1 { protocol tcp; destination-port 22; destination-port 22; } }`, "a", true},
		{"user set of clean applications", `application b { protocol tcp; destination-port 22; } application-set a { application b; application junos-https; }`, "a", true},
		{"predefined junos-ping", ``, "junos-ping", true},
		{"predefined junos-icmp-all", ``, "junos-icmp-all", true},
		{"malformed inactivity-timeout", `application a { protocol tcp; destination-port 22; inactivity-timeout thirty; }`, "a", false},
		{"dangling inactivity-timeout", `application a { protocol tcp; destination-port 22; inactivity-timeout; }`, "a", false},
		{"dangling inactivity-timeout in a term", `application a { term t1 { protocol tcp; destination-port 22; inactivity-timeout; } }`, "a", false},
		{"conflicting inactivity-timeout", `application a { protocol tcp; destination-port 22; inactivity-timeout 30; inactivity-timeout 60; }`, "a", false},
		{"conflicting alg in a term", `application a { term t1 { protocol tcp; destination-port 21; alg ftp; alg tftp; } }`, "a", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text := policyText9525(c.apps, c.ref, "permit", "deny-all")
			_, serr := CompileConfig(parse9525(t, text))
			if c.strictAccepts && serr != nil {
				t.Fatalf("control must commit: %v", serr)
			}
			if !c.strictAccepts && serr == nil {
				t.Fatalf("settings-only control must still be a strict reject (else it proves nothing about the downgrade)")
			}
			cfg := lenient9525(t, text)
			if drops := ApplicationReferenceMatchDrops(c.ref, &cfg.Applications); len(drops) != 0 {
				t.Fatalf("control %q must not be refused; drops: %q", c.name, drops)
			}
		})
	}
}

// TestApplicationLeafPartition9525 binds the match/settings split to the arity
// contract it classifies: every value-taking application leaf is exactly one of
// the two, so a new leaf cannot reach the tolerant path unclassified.
func TestApplicationLeafPartition9525(t *testing.T) {
	if len(valueTakingApplicationLeaves) == 0 {
		t.Fatal("valueTakingApplicationLeaves is empty; the partition check would be vacuous")
	}
	for leaf := range valueTakingApplicationLeaves {
		if applicationMatchLeaves9525[leaf] == applicationSettingLeaves9525[leaf] {
			t.Errorf("value-taking leaf %q must be exactly one of match (%v) or settings (%v)",
				leaf, applicationMatchLeaves9525[leaf], applicationSettingLeaves9525[leaf])
		}
	}
	for _, part := range []map[string]bool{applicationMatchLeaves9525, applicationSettingLeaves9525} {
		for leaf := range part {
			if !valueTakingApplicationLeaves[leaf] {
				t.Errorf("classified leaf %q is not a value-taking application leaf", leaf)
			}
		}
	}
}

// TestPredefinedApplicationsCarryNoMatchDrops9525 is the population control:
// the predicate runs over whatever a reference resolves to, predefined junos-*
// objects included, so every one of them must stay installable.
func TestPredefinedApplicationsCarryNoMatchDrops9525(t *testing.T) {
	apps := &ApplicationsConfig{}
	if len(PredefinedApplications) < 10 || len(PredefinedApplicationSets) == 0 {
		t.Fatalf("predefined tables look empty (%d apps, %d sets); the sweep would be vacuous",
			len(PredefinedApplications), len(PredefinedApplicationSets))
	}
	for name := range PredefinedApplications {
		if drops := ApplicationReferenceMatchDrops(name, apps); len(drops) != 0 {
			t.Errorf("predefined application %q must not be refused; drops: %q", name, drops)
		}
	}
	for name := range PredefinedApplicationSets {
		if drops := ApplicationReferenceMatchDrops(name, apps); len(drops) != 0 {
			t.Errorf("predefined application-set %q must not be refused; drops: %q", name, drops)
		}
	}
}

// TestPortOnNonPortProtocolStrictText9525 pins the corrected strict text. The
// old text said a non-port protocol presents ports of 0; for icmp/icmpv6 the
// source side carries the query Identifier, which the sender chooses.
func TestPortOnNonPortProtocolStrictText9525(t *testing.T) {
	_, serr := CompileConfig(parse9525(t, policyText9525(
		`application a { protocol icmp; source-port 80; }`, "a", "deny", "permit-all")))
	if serr == nil || !strings.Contains(serr.Error(), "ICMP query Identifier, a value the sender chooses") {
		t.Fatalf("source-port on icmp must name the sender-chosen Identifier; got %v", serr)
	}
	_, derr := CompileConfig(parse9525(t, policyText9525(
		`application a { protocol icmp; destination-port 80; }`, "a", "deny", "permit-all")))
	if derr == nil || !strings.Contains(derr.Error(), "presents no destination port") {
		t.Fatalf("destination-port on icmp must say the protocol presents no destination port; got %v", derr)
	}
	for _, err := range []error{serr, derr} {
		if strings.Contains(err.Error(), "always 0") {
			t.Fatalf("the strict text must not claim a non-port protocol presents ports of 0: %v", err)
		}
	}
}
