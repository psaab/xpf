package config

import (
	"encoding/json"
	"testing"
)

// Issue 8875: the top-level `security` containers admitted NO children, so the
// fully-elided spelling lost the whole stanza while the braced and once-elided
// spellings delivered it:
//
//	security { policies { from-zone a to-zone b { policy p } } }   1
//	security { policies from-zone a to-zone b { policy p } }       1
//	security policies from-zone a to-zone b { policy p }           0
//
// Clean on both paths, no warning. The zone-pair policy set is the product's
// primary enforcement surface; losing it denies all inter-zone traffic, because
// the compiled default policy is DENY. A total outage, not a fail-open -- worth
// stating because `PolicyPermit` is `iota`, so a dropped set landing on a zeroed
// field LOOKS like permit-everything until it is measured.
//
// One missing admission, three symptoms: policies, zones and screen.
//
// The depth axis, and only d3 can regress -- d1 and d2 are controls that
// already worked and must keep working. A cell testing one depth is green
// before and after the fix.

type securityElision8875 struct {
	name string
	d1   string // fully braced          security { C { body } }
	d2   string // container brace elided security { C <inst> { body } }
	d3   string // top-level elided       security C <inst> { body }
}

func securityElisionCases8875() []securityElision8875 {
	// TWO policies, so a fold that re-attaches the body as a SIBLING of the
	// deepest packed node -- producing a zone-pair that EXISTS but is empty,
	// which reads as configured and is worse than the pair being absent --
	// cannot pass by delivering one of them.
	twoPol := "policy p1 { match { source-address any; destination-address any; application any; } then { permit; } } " +
		"policy p2 { match { source-address any; destination-address any; application any; } then { deny; } }"
	zoneBody := "host-inbound-traffic { system-services { ping; } } description xpfdesc;"
	screenBody := "ids-option s1 { icmp { flood { threshold 100; } } }"
	// The zones must be DEFINED or the strict path rejects the policy for
	// referencing an undefined zone, and the arm fails for a reason unrelated
	// to elision. Added identically to all three depths, so the comparison is
	// unaffected.
	zdef := "security { zones { security-zone trust { } security-zone untrust { } } } "
	return []securityElision8875{
		{
			name: "zone-pair policies",
			d1:   zdef + "security { policies { from-zone trust to-zone untrust { " + twoPol + " } } }",
			d2:   zdef + "security { policies from-zone trust to-zone untrust { " + twoPol + " } }",
			d3:   zdef + "security policies from-zone trust to-zone untrust { " + twoPol + " }",
		},
		{
			name: "global policies",
			d1:   zdef + "security { policies { global { " + twoPol + " } } }",
			d2:   zdef + "security { policies global { " + twoPol + " } }",
			d3:   zdef + "security policies global { " + twoPol + " }",
		},
		{
			name: "zones",
			d1:   "security { zones { security-zone z1 { " + zoneBody + " } } }",
			d2:   "security { zones security-zone z1 { " + zoneBody + " } }",
			d3:   "security zones security-zone z1 { " + zoneBody + " }",
		},
		{
			name: "screen",
			d1:   "security { screen { " + screenBody + " } }",
			d2:   "security { screen " + screenBody + " }",
			d3:   "security screen " + screenBody,
		},
	}
}

func compileSecurity8875(t *testing.T, text string) (*Config, string) {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture does not parse (%q): %v", text, perrs[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("lenient compile failed for %q: %v", text, err)
	}
	// The strict path must accept it too.
	tree2, _ := NewParser(text).Parse()
	if _, serr := compileTree(tree2, strictCompileOpts(), nil); serr != nil {
		t.Errorf("strict compile REJECTED %q: %v", text, serr)
	}
	// Compare CONTENTS, not counts: a digest of the compiled security section
	// catches a policy that arrives with the wrong action or an empty body,
	// which len() cannot see.
	b, err := json.Marshal(cfg.Security)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return cfg, string(b)
}

// securityLiveness8875 fails when a braced reference carries nothing, so an
// equality against it cannot pass vacuously. This is not decoration: reading
// Security.Policies for GLOBAL policies made both arms return 0 during the
// investigation, which is indistinguishable from "dropped in both spellings".
// A control that fails the same way as the subject cannot distinguish them.
func securityLiveness8875(t *testing.T, name string, cfg *Config) {
	t.Helper()
	inner := 0
	for _, zp := range cfg.Security.Policies {
		inner += len(zp.Policies)
	}
	zoneSvc := 0
	for _, z := range cfg.Security.Zones {
		if z.HostInboundTraffic != nil {
			zoneSvc += len(z.HostInboundTraffic.SystemServices)
		}
	}
	if inner+len(cfg.Security.GlobalPolicies)+zoneSvc+len(cfg.Security.Screen) == 0 {
		t.Fatalf("%s: the braced reference compiled to an EMPTY security section — every comparison against it is vacuous", name)
	}
}

func TestSecurityTopLevelElisionKeepsContents8875(t *testing.T) {
	for _, c := range securityElisionCases8875() {
		t.Run(c.name, func(t *testing.T) {
			ref, refDigest := compileSecurity8875(t, c.d1)
			securityLiveness8875(t, c.name, ref)

			for _, arm := range []struct{ depth, text string }{
				{"d2", c.d2},
				{"d3", c.d3},
			} {
				_, got := compileSecurity8875(t, arm.text)
				if got != refDigest {
					t.Errorf("%s %s does not match the braced spelling.\n braced: %s\n %s:     %s",
						c.name, arm.depth, refDigest, arm.depth, got)
				}
			}
		})
	}
}

// The zone-pair must not arrive EMPTY. A fold that re-attaches the braced body
// as a sibling of the deepest packed node yields a pair that exists with no
// policies in it — which renders as configured and is worse than absent.
func TestZonePairIsNotEmptyAtDepth3_8875(t *testing.T) {
	text := "security { zones { security-zone trust { } security-zone untrust { } } } " +
		"security policies from-zone trust to-zone untrust { " +
		"policy p1 { match { source-address any; destination-address any; application any; } then { permit; } } }"
	cfg, _ := compileSecurity8875(t, text)
	if len(cfg.Security.Policies) != 1 {
		t.Fatalf("got %d zone pairs, want 1", len(cfg.Security.Policies))
	}
	zp := cfg.Security.Policies[0]
	if zp.FromZone != "trust" || zp.ToZone != "untrust" {
		t.Errorf("zone pair is %q->%q, want trust->untrust", zp.FromZone, zp.ToZone)
	}
	if len(zp.Policies) != 1 {
		t.Fatalf("zone pair EXISTS but carries %d policies — a pair that renders as configured and enforces nothing", len(zp.Policies))
	}
	if zp.Policies[0].Name != "p1" {
		t.Errorf("policy name = %q, want p1", zp.Policies[0].Name)
	}
}

// The severity of losing the policy set depends entirely on what zero policies
// falls back to, and that fallback is currently a fact nothing asserts.
//
//	PolicyPermit PolicyAction = iota   // == 0, the ZERO VALUE of the field
//	PolicyDeny
//	PolicyReject
//
// A config with no `default-policy` compiles to DENY because the compiler sets
// it EXPLICITLY, not because the field defaults to it. Nothing pins that today,
// so a `PolicyAction` reordering -- or a refactor that drops the explicit set
// and lets the field keep its zero value -- would silently convert a
// fail-CLOSED outage into a fail-OPEN breach. The elision defect above is one
// way to reach the fallback; a NAT or apply-groups bug is another. The guard
// belongs to the fallback, not to any one route into it.
//
// The assertion is deliberately on "not the zero value" rather than only on
// "== PolicyDeny": that is the property which stops holding the moment the
// explicit set is removed, whichever order the enum happens to be in.
func TestDefaultPolicyIsDenyAndNotMerelyTheZeroValue8875(t *testing.T) {
	var zero PolicyAction
	if zero != PolicyPermit {
		t.Fatalf("premise moved: the zero value of PolicyAction is no longer PolicyPermit (got %v). "+
			"Re-read this cell before adjusting it — the fail-open hazard it guards may have changed shape", zero)
	}

	const noDefaultPolicy = "security { zones { security-zone trust { } security-zone untrust { } } " +
		"policies { from-zone trust to-zone untrust { policy p1 { match { source-address any; " +
		"destination-address any; application any; } then { permit; } } } } }"

	cfg, _ := compileSecurity8875(t, noDefaultPolicy)

	// Liveness: the fixture must actually reach the policy compiler, or the
	// assertion below is about an empty config rather than a real one.
	if len(cfg.Security.Policies) == 0 {
		t.Fatal("fixture compiled no zone pairs — the default-policy assertion would be measuring an empty config")
	}
	if cfg.Security.DefaultPolicy == zero {
		t.Errorf("an unconfigured default policy compiled to the ZERO VALUE (%v = PolicyPermit). "+
			"Losing the policy set now FAILS OPEN: every inter-zone flow is permitted rather than denied. "+
			"The compiler must set the default explicitly", cfg.Security.DefaultPolicy)
	}
	if cfg.Security.DefaultPolicy != PolicyDeny {
		t.Errorf("unconfigured default policy = %v, want PolicyDeny", cfg.Security.DefaultPolicy)
	}
}
