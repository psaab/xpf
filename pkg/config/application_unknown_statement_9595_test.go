package config

import (
	"strings"
	"testing"
)

// #9595: which unrecognized application statements the tolerant path refuses.
// Every row is first confirmed to be a strict reject (a member of the
// downgrade) and then checked against ApplicationReferenceMatchDrops.

const policyLines9595 = "set security zones security-zone lan\n" +
	"set security zones security-zone wan\n" +
	"set security policies default-policy deny-all\n" +
	"set security policies from-zone lan to-zone wan policy p1 match source-address any\n" +
	"set security policies from-zone lan to-zone wan policy p1 match destination-address any\n" +
	"set security policies from-zone lan to-zone wan policy p1 match application a\n" +
	"set security policies from-zone lan to-zone wan policy p1 then permit"

// tree9595 builds a tree from hierarchical application text, or from flat set
// lines when sets is non-empty.
func tree9595(t *testing.T, hier string, sets []string) *ConfigTree {
	t.Helper()
	if len(sets) == 0 {
		text := "applications { " + hier + " } security { zones { security-zone lan; security-zone wan; } " +
			"policies { default-policy { deny-all; } from-zone lan to-zone wan { policy p1 { " +
			"match { source-address any; destination-address any; application a; } then { permit; } } } } }"
		tree, errs := NewParser(text).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		return tree
	}
	tree := &ConfigTree{}
	for _, line := range append(append([]string(nil), sets...), strings.Split(policyLines9595, "\n")...) {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

type row9595 struct {
	name, hier string
	sets       []string
	want       string // substring the refusal must carry; "" means must stay armed
}

func check9595(t *testing.T, r row9595) {
	t.Helper()
	if _, err := CompileConfig(tree9595(t, r.hier, r.sets)); err == nil {
		t.Fatalf("fixture is not a member of the downgrade: strict CompileConfig accepted it")
	}
	cfg, err := CompileConfigLenient(tree9595(t, r.hier, r.sets))
	if err != nil {
		t.Fatalf("the tolerant compile must still accept the fixture (#1960 no-brick): %v", err)
	}
	drops := strings.Join(ApplicationReferenceMatchDrops("a", &cfg.Applications), "\n")
	switch {
	case r.want == "" && drops != "":
		t.Fatalf("%s must stay armed (#6524), got drops: %s", r.name, drops)
	case r.want != "" && !strings.Contains(drops, r.want):
		t.Fatalf("%s must be refused naming %q, got drops: %q", r.name, r.want, drops)
	}
}

// A lost match constraint on an otherwise protocol-wide application, in every
// parser shape, and a misspelled set member naming a real application.
func TestUnknownStatementLosingAConstraintIsRefused9595(t *testing.T) {
	for _, r := range []row9595{
		{"hier tcp + destination-poort 22", `application a { protocol tcp; destination-poort 22; }`, nil, `constraint-shaped value "22"`},
		{"flat chain tcp destination-poort 22", "", []string{"set applications application a protocol tcp destination-poort 22"}, `constraint-shaped value "22"`},
		{"flat lines tcp, then destination-poort 22", "", []string{"set applications application a protocol tcp", "set applications application a destination-poort 22"}, `constraint-shaped value "22"`},
		{"udp + source-prot 53", `application a { protocol udp; source-prot 53; }`, nil, `constraint-shaped value "53"`},
		{"icmp + icmp-typ 8", `application a { protocol icmp; icmp-typ 8; }`, nil, `constraint-shaped value "8"`},
		{"icmpv6 + icmp6-type 128 (a real Junos leaf)", `application a { protocol icmpv6; icmp6-type 128; }`, nil, `constraint-shaped value "128"`},
		{"udp + rpc-program-number 100003 (a real Junos leaf)", `application a { protocol udp; rpc-program-number 100003; }`, nil, `constraint-shaped value "100003"`},
		{"tcp + application-protocol ssh (a real Junos leaf)", `application a { protocol tcp; application-protocol ssh; }`, nil, `constraint-shaped value "ssh"`},
		{"term tcp + destination-poort 22", `application a { term t1 { protocol tcp; destination-poort 22; } }`, nil, `constraint-shaped value "22"`},
		{"flat term chain", "", []string{"set applications application a term t1 protocol tcp destination-poort 22"}, `constraint-shaped value "22"`},
		{"set member applicaton junos-ssh", `application-set a { application junos-telnet; applicaton junos-ssh; }`, nil, `names "junos-ssh"`},
		{"direct stray on a term-bearing application", `application a { destination-poort 22; term t1 { protocol tcp; } }`, nil, `constraint-shaped value "22"`},
		{"tcp 22 with the destination-port keyword missing (a bracket-tail value)", `application a { protocol tcp 22; }`, nil, `constraint-shaped value "22"`},
		{"hier destination-poort { 22; } (the value in a child node)", `application a { protocol tcp; destination-poort { 22; } }`, nil, `constraint-shaped value "22"`},
		{"icmp + icmp-typ echo-request (a named type)", `application a { protocol icmp; icmp-typ echo-request; }`, nil, `constraint-shaped value "echo-request"`},
		{"set member applicaton-set naming a set", `application-set inner { application junos-ssh; } application-set a { application junos-telnet; applicaton-set inner; }`, nil, `names "inner"`},
	} {
		t.Run(r.name, func(t *testing.T) { check9595(t, r) })
	}
}

// The load-bearing half: #6524's stray statement, and every stray the line
// keeps armed. The first row is exactly TestStrayStatementDoesNotDisarmSiblingLeaves.
func TestUnrelatedStrayStatementStaysArmed9595(t *testing.T) {
	for _, r := range []row9595{
		{"#6524 flat: tcp, dport 8080, stray bogus value", "", []string{"set applications application a protocol tcp", "set applications application a destination-port 8080", "set applications application a bogus value"}, ""},
		{"hier tcp/8080 + bogus value", `application a { protocol tcp; destination-port 8080; bogus value; }`, nil, ""},
		{"protocol-wide tcp + non-numeric bogus value", `application a { protocol tcp; bogus value; }`, nil, ""},
		{"tcp/22 + misspelled timeout 30 (beside a retained port)", `application a { protocol tcp; destination-port 22; inactivity-timout 30; }`, nil, ""},
		{"tcp/21 + misspelled alg ftp (beside a retained port)", `application a { protocol tcp; destination-port 21; alg-typo ftp; }`, nil, ""},
		{"gre (no match dimension) + bogus 5", `application a { protocol gre; bogus 5; }`, nil, ""},
		{"term tcp/22 + bogus value", `application a { term t1 { protocol tcp; destination-port 22; bogus value; } }`, nil, ""},
		{"protocol-wide icmp + foo bar", `application a { protocol icmp; foo bar; }`, nil, ""},
		{"udp sport 1024 + inactivity-timout 30 (beside a retained source-port)", `application a { protocol udp; source-port 1024; inactivity-timout 30; }`, nil, ""},
		{"icmp-type 8 + icmp-cod 0 (beside a retained icmp-type; a limit, #9603)", `application a { protocol icmp; icmp-type 8; icmp-cod 0; }`, nil, ""},
		{"set descripton x", `application-set a { application junos-telnet; descripton x; }`, nil, ""},
	} {
		t.Run(r.name, func(t *testing.T) { check9595(t, r) })
	}
}

// The deliberate over-reach, pinned so it is a stated boundary rather than an
// accident: on a protocol-wide application a numeric or named-port stray is
// structurally identical to a lost port, so it fails closed.
func TestConstraintShapedStrayOnAProtocolWideApplicationIsRefused9595(t *testing.T) {
	for _, r := range []row9595{
		{"tcp only + bogus 8080", `application a { protocol tcp; bogus 8080; }`, nil, `constraint-shaped value "8080"`},
		{"tcp only + alg-typo ftp", `application a { protocol tcp; alg-typo ftp; }`, nil, `constraint-shaped value "ftp"`},
	} {
		t.Run(r.name, func(t *testing.T) { check9595(t, r) })
	}
}

// The recording the predicate reads: the whole unrecognized run, in both
// shapes, carried to term applications, and the set member's value.
func TestUnknownStatementTokensAreRecorded9595(t *testing.T) {
	flat, err := CompileConfigLenient(tree9595(t, "", []string{"set applications application a protocol tcp destination-poort 22"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(flat.Applications.Applications["a"].UnknownDirectTokens, " "); got != "destination-poort 22" {
		t.Fatalf("flat chain UnknownDirectTokens = %q, want %q", got, "destination-poort 22")
	}
	hier, err := CompileConfigLenient(tree9595(t, `application a { protocol tcp; destination-port 8080; bogus value; }`, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(hier.Applications.Applications["a"].UnknownDirectTokens, " "); got != "bogus value" {
		t.Fatalf("hierarchical UnknownDirectTokens = %q, want %q", got, "bogus value")
	}
	set, err := CompileConfigLenient(tree9595(t, `application-set a { application junos-telnet; applicaton junos-ssh; }`, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(set.Applications.ApplicationSets["a"].UnknownMemberValues, " "); got != "junos-ssh" {
		t.Fatalf("UnknownMemberValues = %q, want %q", got, "junos-ssh")
	}
}

// The value-shape authority: port specs (named ports included), decimal
// integers and ranges, and ICMP types; not words.
func TestConstraintShapedToken9595(t *testing.T) {
	for tok, want := range map[string]bool{
		"22": true, "22-25": true, "ssh": true, "100003": true, "128": true, "echo-request": true,
		"": false, "value": false, "bar": false, "web": false,
		"1be617c0-31a5-11cf-a7d8-00805f48a135": false,
	} {
		if got := constraintShapedToken9595(tok); got != want {
			t.Errorf("constraintShapedToken9595(%q) = %v, want %v", tok, got, want)
		}
	}
}
