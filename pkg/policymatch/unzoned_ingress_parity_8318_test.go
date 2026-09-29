package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8318/#11067: the simulator must deny an unzoned ingress and a resolved
// unzoned egress regardless of default-policy. The simulator query has no FIB
// input, so it cannot distinguish a zero-identity NoRoute whose dataplane
// decision still follows the default.
//
// Both direction cells MUST use default-policy permit-all. Under `deny-all` the
// old and new implementations both return Deny for unknown zones, so a deny-all
// result assertion alone proves nothing; the direction-specific flags and
// DefaultUsed assertions pin the terminal gate.
func TestUnzonedIngressDeniesRegardlessOfDefaultPolicy8318(t *testing.T) {
	permitAll := func() *config.Config {
		return &config.Config{Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyPermit,
			Zones:         zones("trust", "untrust"),
		}}
	}

	t.Run("unknown FromZone denies under permit-all", func(t *testing.T) {
		res := Match(permitAll(), Query{
			FromZone: "not-a-zone", ToZone: "untrust", Protocol: "tcp", DstPort: 80,
		})
		if res.Action != config.PolicyDeny {
			t.Fatalf("unknown FromZone must DENY under default-policy permit-all "+
				"(the runtime denies from_id == 0 unconditionally, #6682); got %v",
				ActionString(res.Action))
		}
		if !res.UnzonedIngress {
			t.Error("the result must carry UnzonedIngress so the verdict is not " +
				"misattributed to default-policy in operator-facing output")
		}
		// The reason must not be attributed to the operator's default. On a
		// permit-all box "deny (default)" would name a default that produced no
		// such thing.
		if res.DefaultUsed {
			t.Error("DefaultUsed must be FALSE: its contract is that Action is the " +
				"configured default-policy, and this Deny overrides it")
		}
		if got := res.DisplayAction(); !strings.Contains(got, "ingress zone unknown") {
			t.Errorf("DisplayAction must name the cause, got %q", got)
		}
		if got := res.DisplayAction(); strings.Contains(got, "(default)") {
			t.Errorf("DisplayAction must NOT read as a default verdict, got %q", got)
		}
	})

	// A resolved unknown TO zone is the egress deny, not the default-policy.
	t.Run("unknown ToZone denies as unzoned egress under permit-all", func(t *testing.T) {
		res := Match(permitAll(), Query{
			FromZone: "trust", ToZone: "not-a-zone", Protocol: "tcp", DstPort: 80,
		})
		if res.Action != config.PolicyDeny {
			t.Fatalf("unknown ToZone must DENY under default-policy permit-all "+
				"(the runtime denies resolved to_id == 0, #11067); got %v",
				ActionString(res.Action))
		}
		if !res.UnzonedEgress || res.UnzonedIngress || res.DefaultUsed {
			t.Fatalf("unknown ToZone must carry only UnzonedEgress and not use "+
				"default-policy, got %+v", res)
		}
		if got := res.DisplayAction(); !strings.Contains(got, "egress zone unknown") {
			t.Errorf("DisplayAction must name the egress cause, got %q", got)
		}
	})

	// Both unknown: the ingress rule wins, because the runtime's from_id check
	// runs first and returns before the to_id fall-through is reached.
	t.Run("both unknown denies as ingress", func(t *testing.T) {
		res := Match(permitAll(), Query{
			FromZone: "nope", ToZone: "also-nope", Protocol: "tcp", DstPort: 80,
		})
		if res.Action != config.PolicyDeny || !res.UnzonedIngress {
			t.Fatalf("both-unknown must take the ingress deny (the runtime checks "+
				"from_id first and returns); got action=%v unzoned=%v",
				ActionString(res.Action), res.UnzonedIngress)
		}
	})

	// The deny-all rows are controls for unchanged action behavior. They cannot
	// distinguish a default deny from the two unzoned gates, so assert the cause
	// flags on each side as well.
	t.Run("deny-all still attributes each unzoned direction", func(t *testing.T) {
		denyAll := &config.Config{Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
		}}
		if res := Match(denyAll, Query{FromZone: "nope", ToZone: "untrust", Protocol: "tcp", DstPort: 80}); !res.UnzonedIngress || res.DefaultUsed {
			t.Errorf("unknown FromZone must remain an ingress deny under deny-all, got %+v", res)
		}
		if res := Match(denyAll, Query{FromZone: "trust", ToZone: "nope", Protocol: "tcp", DstPort: 80}); !res.UnzonedEgress || res.DefaultUsed {
			t.Errorf("unknown ToZone must be an egress deny under deny-all, got %+v", res)
		}
	})

	// Eligibility is unchanged (#3355): an unknown zone must still not match a
	// from-any/to-any wildcard. Without this row a "fix" that simply made the
	// unknown zone eligible could pass the deny rows by matching a wildcard
	// PERMIT and then being denied for some other reason.
	t.Run("unknown zone is still ineligible for the wildcard tier", func(t *testing.T) {
		wildcard := &config.Config{Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{{
				FromZone: "any", ToZone: "any",
				Policies: []*config.Policy{{
					Name:   "permit-any-any",
					Match:  config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}},
					Action: config.PolicyPermit,
				}},
			}},
		}}
		res := Match(wildcard, Query{FromZone: "nope", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
		if res.Matched {
			t.Fatalf("an unknown FromZone must remain INELIGIBLE for the from-any/to-any "+
				"tier (#3355) — it matched %q", res.PolicyName)
		}
		if res.Action != config.PolicyDeny || !res.UnzonedIngress {
			t.Fatalf("and it must land on the unzoned-ingress deny; got action=%v unzoned=%v",
				ActionString(res.Action), res.UnzonedIngress)
		}
	})
}
