package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9570 — a zone-pair stanza naming the reserved `junos-global` sentinel, on the
// TOLERANT compile channel (config.CompileConfigLenient: boot load, HA sync,
// upgrade). Strict commit rejects every spelling, so a strict fixture here would
// assert over an empty set; each fixture below is compiled leniently and pinned
// to ground truth first.

func compileLenient9570(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant compile refused the fixture, so nothing below measures the tolerant path: %v", err)
	}
	return cfg
}

func compileStrict9570(t *testing.T, lines []string) error {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	_, err := config.CompileConfig(tree)
	return err
}

func base9570() []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
		"set security policies default-policy deny-all",
	}
}

func zonePair9570(from, to, name, action string) []string {
	p := "set security policies from-zone " + from + " to-zone " + to + " policy " + name + " "
	return []string{p + "match source-address any", p + "match destination-address any", p + "match application any", p + "then " + action}
}

func global9570(name, action string, scope ...string) []string {
	p := "set security policies global policy " + name + " "
	out := []string{p + "match source-address any", p + "match destination-address any", p + "match application any"}
	for _, s := range scope {
		out = append(out, p+"match "+s)
	}
	return append(out, p+"then "+action)
}

func cat9570(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func markedSentinelRule9570(name, from, to string) PolicyRuleSnapshot {
	r := zonePairRule9410(name, from, to)
	r.zonePairGlobalSentinelSide = config.ZonePairGlobalSentinelSide(from, to)
	return r
}

func hasAppSentinel9570(r PolicyRuleSnapshot) bool {
	for _, term := range r.ApplicationTerms {
		if term.Name == unsupportedApplicationSentinel || term.Protocol == unsupportedApplicationSentinel {
			return true
		}
	}
	return false
}

func ruleNamed9570(t *testing.T, rules []PolicyRuleSnapshot, name string) PolicyRuleSnapshot {
	t.Helper()
	for _, r := range rules {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no built rule named %q among %d rules", name, len(rules))
	return PolicyRuleSnapshot{}
}

// TestZonePairGlobalSentinelIsPoisonedOnTheTolerantPath9570 is the builder half.
//
// Before #9570 the builder copied `junos-global` onto the wire verbatim and the
// helper enforced the rule as a device-wide global permit (measured: lan->wan
// and untrust->lan both Permit under default deny). The both-sided spelling was
// the worst case: wire-identical to a real global rule, so the Go mirror
// reported nothing and the simulator returned the default verdict while the
// helper permitted every zone pair.
//
// The poison is asserted ON THE MARSHALLED WIRE BYTES, because the helper reads
// the wire, not the build-time marker.
func TestZonePairGlobalSentinelIsPoisonedOnTheTolerantPath9570(t *testing.T) {
	for _, tc := range []struct{ name, from, to, side string }{
		{"from-side", "junos-global", "trust", "from-zone"},
		{"to-side", "trust", "junos-global", "to-zone"},
		{"both-sided", "junos-global", "junos-global", "from-zone and to-zone"},
		{"from-any to sentinel", "any", "junos-global", "to-zone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileLenient9570(t, cat9570(base9570(),
				zonePair9570(tc.from, tc.to, "p1", "permit"),
				zonePair9570("trust", "untrust", "healthy", "permit")))

			// Ground truth: the fixture still constructs the malformed shape.
			found := false
			for _, zpp := range cfg.Security.Policies {
				if zpp != nil && zpp.FromZone == tc.from && zpp.ToZone == tc.to {
					found = true
				}
			}
			if !found {
				t.Fatalf("fixture no longer compiles a %s->%s zone-pair stanza; the cell would pass vacuously", tc.from, tc.to)
			}

			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			p1 := ruleNamed9570(t, rules, "p1")
			if p1.FromZone != tc.from || p1.ToZone != tc.to {
				t.Errorf("zone strings must stay verbatim (the reason and the rule id name them), got %s->%s", p1.FromZone, p1.ToZone)
			}
			if !hasAppSentinel9570(p1) {
				t.Fatalf("#9570: the zone-pair rule naming junos-global carries no %q poison, so the "+
					"helper would enforce it; application terms: %+v", unsupportedApplicationSentinel, p1.ApplicationTerms)
			}
			if p1.zonePairGlobalSentinelSide != tc.side {
				t.Errorf("marker = %q, want %q", p1.zonePairGlobalSentinelSide, tc.side)
			}
			wire, err := json.Marshal(p1)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(wire), `"`+unsupportedApplicationSentinel+`"`) {
				t.Fatalf("the poison is not on the wire the helper reads: %s", wire)
			}

			healthy := ruleNamed9570(t, rules, "healthy")
			if hasAppSentinel9570(healthy) || healthy.zonePairGlobalSentinelSide != "" {
				t.Errorf("a healthy sibling rule was poisoned: %+v", healthy)
			}

			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) != 1 {
				t.Fatalf("want exactly ONE reason for the poisoned rule, got %d: %v", len(reasons), reasons)
			}
			got := reasons[0]
			wantPrefix := "policy " + tc.from + "->" + tc.to + "/p1 "
			if !strings.HasPrefix(got, wantPrefix) {
				t.Errorf("the reason must render the ZONE-PAIR scope %q (a both-sided stanza is not a global "+
					"policy), got: %s", wantPrefix, got)
			}
			for _, want := range []string{`"junos-global"`, "as its " + tc.side + ":", "WHOLE POLICY SNAPSHOT", "security policies global"} {
				if !strings.Contains(got, want) {
					t.Errorf("reason lacks %q: %s", want, got)
				}
			}
			for _, bad := range []string{"cannot represent", "references undefined"} {
				if strings.Contains(got, bad) {
					t.Errorf("reason carries the misleading %q wording: %s", bad, got)
				}
			}
		})
	}
}

// TestZonePairGlobalSentinelAcceptingControls9570 is the load-bearing half.
//
// Refusing every snapshot would make both planes "agree" and would be worse
// than the defect: a real `security policies global` rule would stop being
// enforced. Each row here also COMMITS on the strict channel, which is what
// proves it is a legitimate config and not a second malformed one.
func TestZonePairGlobalSentinelAcceptingControls9570(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"real global, unscoped", cat9570(base9570(), global9570("g1", "permit"))},
		{"real global, scoped", cat9570(base9570(), global9570("g1", "permit", "from-zone trust", "to-zone untrust"))},
		{"real global beside a zone-pair rule", cat9570(base9570(), zonePair9570("trust", "untrust", "zp", "deny"), global9570("g1", "permit"))},
		{"zone-pair trust->untrust", cat9570(base9570(), zonePair9570("trust", "untrust", "p1", "permit"))},
		{"zone-pair from-any", cat9570(base9570(), zonePair9570("any", "untrust", "p1", "permit"))},
		{"zone-pair to-any", cat9570(base9570(), zonePair9570("trust", "any", "p1", "permit"))},
		{"zone-pair to junos-host", cat9570(base9570(), zonePair9570("trust", "junos-host", "p1", "permit"))},
		{"zone whose name contains the sentinel", cat9570(base9570(),
			[]string{"set security zones security-zone junos-global-edge"},
			zonePair9570("junos-global-edge", "trust", "p1", "permit"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := compileStrict9570(t, tc.lines); err != nil {
				t.Fatalf("control is not a legitimate config (strict commit refused it): %v", err)
			}
			cfg := compileLenient9570(t, tc.lines)
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if len(rules) == 0 {
				t.Fatal("the control built no rules, so it asserts nothing")
			}
			for _, r := range rules {
				if hasAppSentinel9570(r) || r.zonePairGlobalSentinelSide != "" {
					t.Errorf("#9570 OVER-REJECTION: legitimate rule %s->%s/%s was poisoned", r.FromZone, r.ToZone, r.Name)
				}
			}
			if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
				t.Errorf("#9570 OVER-REJECTION: a legitimate config is reported refused: %v", reasons)
			}
		})
	}
}

// TestZonePairGlobalSentinelBesideARealGlobalRule9570: the two rules below have
// IDENTICAL zone strings on the wire. Only the one from the zone-pair list may be
// poisoned, and the reason must name it as a zone-pair rule.
func TestZonePairGlobalSentinelBesideARealGlobalRule9570(t *testing.T) {
	cfg := compileLenient9570(t, cat9570(base9570(),
		global9570("g1", "permit"),
		zonePair9570("junos-global", "junos-global", "zp1", "permit")))
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	g1, zp1 := ruleNamed9570(t, rules, "g1"), ruleNamed9570(t, rules, "zp1")
	if g1.FromZone != zp1.FromZone || g1.ToZone != zp1.ToZone {
		t.Fatalf("fixture premise broken: the two rules are no longer wire-identical in zone strings (%s->%s vs %s->%s)",
			g1.FromZone, g1.ToZone, zp1.FromZone, zp1.ToZone)
	}
	if hasAppSentinel9570(g1) {
		t.Error("the real global rule was poisoned")
	}
	if !hasAppSentinel9570(zp1) {
		t.Error("the zone-pair rule with the global rule's zone strings was not poisoned")
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) != 1 || !strings.HasPrefix(reasons[0], "policy junos-global->junos-global/zp1 ") {
		t.Fatalf("want one reason naming the zone-pair rule, got %v", reasons)
	}
}

// TestZonePairGlobalSentinelWithAZoneLiterallyNamedJunosGlobal9570 covers the
// other tolerant downgrade that meets this one: a zone DEFINED as junos-global
// (#3055, warned not rejected on this path). The zone-pair stanza then passes
// the defined-zone check, and the zone mirror's resolver finds the name, so only
// the dedicated arm can report it.
func TestZonePairGlobalSentinelWithAZoneLiterallyNamedJunosGlobal9570(t *testing.T) {
	cfg := compileLenient9570(t, cat9570(base9570(),
		[]string{"set security zones security-zone junos-global"},
		zonePair9570("junos-global", "trust", "p1", "permit")))
	if _, ok := cfg.Security.Zones["junos-global"]; !ok {
		t.Fatal("fixture premise broken: the tolerant compile no longer keeps a zone named junos-global")
	}
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !hasAppSentinel9570(ruleNamed9570(t, rules, "p1")) {
		t.Fatal("rule naming a zone called junos-global was not poisoned")
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 1 {
		t.Fatalf("want one reason, got %v", reasons)
	}
}
