package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10253 (nft mirror falls through on action+next-term): a non-routing-instance
// term carrying a REAL terminating action (accept/discard/reject/unknown)
// AND `then next term` is a contradiction the strict commit gate rejects
// (validateFilterTerminalConflictStrict, #5142/#9140), but the tolerant load /
// peer-sync path downgrades that gate to a warning (#1960 no-brick), so the
// shape can still reach this lowering from an already-persisted or peer-synced
// config. The Rust evaluator resolves the contradiction in favour of the
// action — `continue_term: snap.action.is_empty() &&
// snap.routing_instance.is_empty()` (userspace-dp/src/filter/compiler.rs,
// #5142) — and TERMINATES. #10012 fixed the snapshot RENDER to mirror that
// predicate; the nft LOWERING still branched on
// `(term.NextTerm || term.Action == "") && term.RoutingInstance == ""`
// (daemon_nft_term_lower.go:527, pkg/nftables/netlink_lo0.go:262) and fell
// through, emitting no rule (or a non-terminating modifier rule) where the
// runtime enforces a terminating verdict.
//
// These cells pin the corrected contract: any non-empty action terminates on
// the nft path regardless of the advisory NextTerm bit, with the honored
// log/count modifiers riding the terminating rule. Actionless terms and
// routing-instance terms are unchanged.
//
// FAIL-ON-REVERT: restore the `(term.NextTerm || ...)` fall-through branch
// and the issue cells go RED — the lowering again emits no terminating
// verdict while the Rust predicate terminates.

// TestNftActionNextTermTerminatesMirroringRust10253 is the issue cell: every
// non-empty action with NextTerm set must lower to its terminating verdict,
// exactly as the same term without NextTerm does.
func TestNftActionNextTermTerminatesMirroringRust10253(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	single := []struct {
		name   string
		action string
		want   string
	}{
		{"accept", "accept", "accept"},
		{"discard", "discard", "drop"},
		// An unknown non-empty action must still fail CLOSED to drop (#3724
		// M08) — the NextTerm bit must not suppress the fail-closed verdict
		// into a silent fall-through.
		{"unknown-fails-closed", "frobnicate", "drop"},
	}
	for _, c := range single {
		t.Run(c.name, func(t *testing.T) {
			for _, fam := range []string{"ip", "ip6"} {
				term := &config.FirewallFilterTerm{
					Name:     "clash",
					Action:   c.action,
					NextTerm: true,
				}
				if got := nftRule(t, term, fam, prefixLists); got != c.want {
					t.Errorf("action %q + next-term (%s): got %q, want terminating %q "+
						"(must terminate like Rust continue_term=false, #5142/#10253)",
						c.action, fam, got, c.want)
				}
			}
		})
	}

	// reject+next-term must reach the faithful two-rule lowering (TCP RST +
	// ICMP admin-prohibited, #3445), not fall through to no rule.
	t.Run("reject", func(t *testing.T) {
		for _, fam := range []string{"ip", "ip6"} {
			term := &config.FirewallFilterTerm{
				Name:     "clash",
				Action:   "reject",
				NextTerm: true,
			}
			rules := nftRulesFromTerm(term, fam, prefixLists)
			want := []string{
				"meta l4proto 6 reject with tcp reset",
				"reject with icmpx type admin-prohibited",
			}
			if len(rules) != len(want) {
				t.Fatalf("reject + next-term (%s): got %d rules, want %d: %v "+
					"(must terminate like Rust, #10253)", fam, len(rules), len(want), rules)
			}
			for i := range want {
				if rules[i] != want[i] {
					t.Errorf("reject + next-term (%s) rule[%d]: got %q, want %q",
						fam, i, rules[i], want[i])
				}
			}
		}
	})

	// The honored modifiers must ride the TERMINATING rule — a single rule
	// carrying log + counter + verdict — not a non-terminating modifier rule
	// that leaves later terms reachable.
	t.Run("modifiers-ride-terminating-rule", func(t *testing.T) {
		term := &config.FirewallFilterTerm{
			Name:     "clash-mods",
			Count:    "hits",
			Log:      true,
			Action:   "accept",
			NextTerm: true,
		}
		rules := nftRulesFromTerm(term, "ip", prefixLists)
		want := `log prefix "xpf-lo0 clash-mods: " counter name "xpflo0_hits" accept`
		if len(rules) != 1 {
			t.Fatalf("accept + next-term + log/count: got %d rules, want 1: %v", len(rules), rules)
		}
		if rules[0] != want {
			t.Errorf("accept + next-term + log/count:\n  got:  %s\n  want: %s", rules[0], want)
		}
	})
}

// TestNftActionlessAndRITermsUnaffected10253 pins the unchanged shapes: an
// actionless term still falls through (no rule without a honored modifier, a
// NON-TERMINATING rule with one), a pure terminal still terminates, and a
// routing-instance term still terminates as accept with or without NextTerm
// (#3427 M08, #9140). GREEN before and after the fix.
func TestNftActionlessAndRITermsUnaffected10253(t *testing.T) {
	prefixLists := map[string]*config.PrefixList{}

	// Explicit `then next term` with no action and no honored modifier: no rule.
	for _, fam := range []string{"ip", "ip6"} {
		term := &config.FirewallFilterTerm{Name: "t1", NextTerm: true}
		if got := nftRule(t, term, fam, prefixLists); got != "" {
			t.Errorf("pure fall-through (%s): got %q, want no rule", fam, got)
		}
	}

	// Modifier-only fall-through (with and without the explicit bit): exactly
	// one NON-TERMINATING rule — the modifiers, no verdict.
	for _, c := range []struct {
		name string
		term *config.FirewallFilterTerm
	}{
		{"explicit-bit", &config.FirewallFilterTerm{Name: "t1", Count: "hits", Log: true, NextTerm: true}},
		{"implicit-modifier-only", &config.FirewallFilterTerm{Name: "t1", Count: "hits", Log: true}},
	} {
		rules := nftRulesFromTerm(c.term, "ip", prefixLists)
		if len(rules) != 1 {
			t.Fatalf("%s: got %d rules, want 1: %v", c.name, len(rules), rules)
		}
		for _, verdict := range []string{"accept", "drop", "reject"} {
			if strings.Contains(rules[0], verdict) {
				t.Errorf("%s: fall-through emitted a terminating %q: %q", c.name, verdict, rules[0])
			}
		}
	}

	// Pure terminal without NextTerm: unchanged.
	if got := nftRule(t, &config.FirewallFilterTerm{Name: "t1", Action: "discard"}, "ip", prefixLists); got != "drop" {
		t.Errorf("pure discard: got %q, want %q", got, "drop")
	}

	// Routing-instance terms terminate as accept with or without NextTerm.
	for _, nextTerm := range []bool{false, true} {
		term := &config.FirewallFilterTerm{
			Name:            "steer",
			RoutingInstance: "mgmt-vrf",
			NextTerm:        nextTerm,
		}
		if got := nftRule(t, term, "ip", prefixLists); got != "accept" {
			t.Errorf("routing-instance (nextTerm=%v): got %q, want terminating %q", nextTerm, got, "accept")
		}
	}
}

// TestLo0PayloadActionNextTermShadowsLaterDeny10253 is the end-to-end proof:
// an accept term carrying NextTerm followed by a discard term must TERMINATE
// at the first term (first-match-wins), so the accept appears in the payload
// above the drop. Before the fix the first term emitted nothing and the
// discard stood alone — the kernel mirror enforced a different policy than
// the Rust evaluator on the same config.
func TestLo0PayloadActionNextTermShadowsLaterDeny10253(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0-in": {
			Name: "lo0-in",
			Terms: []*config.FirewallFilterTerm{
				{Name: "clash", Protocols: []string{"tcp"}, Action: "accept", NextTerm: true},
				{Name: "block-ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: "discard"},
			},
		},
	}

	payload := buildLo0FilterPayload(cfg, "lo0-in", "")

	if !strings.Contains(payload, "meta l4proto 6 accept") {
		t.Fatalf("accept + next-term emitted no terminating accept in the lo0 payload " +
			"(fell through while Rust terminates, #10253):\n%s", payload)
	}
	if !strings.Contains(payload, "th dport 22 drop") {
		t.Fatalf("discard term missing from lo0 payload:\n%s", payload)
	}
	acceptIdx := strings.Index(payload, "meta l4proto 6 accept")
	dropIdx := strings.Index(payload, "th dport 22 drop")
	if acceptIdx > dropIdx {
		t.Fatalf("term order inverted in the payload:\n%s", payload)
	}
}
