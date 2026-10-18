package routing

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14699: a non-empty `except` prefix-list combined with a match-any
// positive (`0.0.0.0/0`, `::/0`, `any`, or a positive prefix-list
// expanding to 0.0.0.0/0) is the strict-valid #4338 Junos idiom
// "match any EXCEPT the listed prefixes". resolvePBRDirection used to
// treat the match-any token as making the direction unconstrained and
// then drop the except "positive-wins", returning [""] — a match-all
// ip rule that steers the very prefixes Junos says to exclude. An ip
// rule has no negated from/to, so the term must FAIL CLOSED: 0 rules
// with a degraded error, never a match-all steer.
//
// The DSCP `ef` on each term keeps the term from being "unconstrained"
// for unrelated reasons, so the asserted 0-rule outcome is attributable
// to the except mechanism alone.
//
// FAIL-ON-REVERT: restoring the positive-wins warn branch (ignoring a
// non-empty except when unconstrainedSeen/hasPositive/hasPositiveRef)
// makes every cell below emit a rule (match-all [""] or the positive
// set) with no degraded error, turning this test RED.
func TestResolvePBRDirectionMatchAnyPlusExceptFailsClosed(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}
	mgmt := map[string]*config.PrefixList{
		"mgmt": {Name: "mgmt", Prefixes: []string{"10.9.0.0/16"}},
	}

	cases := []struct {
		name   string
		family string
		term   *config.FirewallFilterTerm
		pls    map[string]*config.PrefixList
	}{
		{
			name:   "v4 0.0.0.0/0 source plus except",
			family: "inet",
			term: &config.FirewallFilterTerm{
				Name:              "t",
				DSCPs:             []string{"ef"},
				SourceAddresses:   []string{"0.0.0.0/0"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt", Except: true}},
				RoutingInstance:   "ATT",
			},
			pls: mgmt,
		},
		{
			name:   "v6 ::/0 source plus except",
			family: "inet6",
			term: &config.FirewallFilterTerm{
				Name:              "t",
				DSCPs:             []string{"ef"},
				SourceAddresses:   []string{"::/0"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt6", Except: true}},
				RoutingInstance:   "ATT",
			},
			pls: map[string]*config.PrefixList{
				"mgmt6": {Name: "mgmt6", Prefixes: []string{"2001:db8:9::/48"}},
			},
		},
		{
			name:   "any destination plus except",
			family: "inet",
			term: &config.FirewallFilterTerm{
				Name:            "t",
				DSCPs:           []string{"ef"},
				DestAddresses:   []string{"any"},
				DestPrefixLists: []config.PrefixListRef{{Name: "mgmt", Except: true}},
				RoutingInstance: "ATT",
			},
			pls: mgmt,
		},
		{
			name:   "positive prefix-list expanding to 0.0.0.0/0 plus except",
			family: "inet",
			term: &config.FirewallFilterTerm{
				Name:  "t",
				DSCPs: []string{"ef"},
				SourcePrefixLists: []config.PrefixListRef{
					{Name: "all"},
					{Name: "mgmt", Except: true},
				},
				RoutingInstance: "ATT",
			},
			pls: map[string]*config.PrefixList{
				"all":  {Name: "all", Prefixes: []string{"0.0.0.0/0"}},
				"mgmt": {Name: "mgmt", Prefixes: []string{"10.9.0.0/16"}},
			},
		},
		{
			name:   "specific positive plus except (tolerant path)",
			family: "inet",
			term: &config.FirewallFilterTerm{
				Name:              "t",
				DSCPs:             []string{"ef"},
				SourceAddresses:   []string{"10.0.0.0/8"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt", Except: true}},
				RoutingInstance:   "ATT",
			},
			pls: mgmt,
		},
		{
			name:   "positive prefix-list plus except (tolerant path)",
			family: "inet",
			term: &config.FirewallFilterTerm{
				Name:  "t",
				DSCPs: []string{"ef"},
				SourcePrefixLists: []config.PrefixListRef{
					{Name: "corp"},
					{Name: "mgmt", Except: true},
				},
				RoutingInstance: "ATT",
			},
			pls: map[string]*config.PrefixList{
				"corp": {Name: "corp", Prefixes: []string{"10.1.0.0/16"}},
				"mgmt": {Name: "mgmt", Prefixes: []string{"10.9.0.0/16"}},
			},
		},
		{
			name:   "empty positive prefix-list plus non-empty except",
			family: "inet",
			term: &config.FirewallFilterTerm{
				Name:  "t",
				DSCPs: []string{"ef"},
				SourcePrefixLists: []config.PrefixListRef{
					{Name: "empty"},
					{Name: "mgmt", Except: true},
				},
				RoutingInstance: "ATT",
			},
			pls: map[string]*config.PrefixList{
				"empty": {Name: "empty"},
				"mgmt":  {Name: "mgmt", Prefixes: []string{"10.9.0.0/16"}},
			},
		},
		{
			// The idiom with no other selector in either direction:
			// pre-fix this returned [""] and buildPBRFromFilter then
			// dropped it only via the generic unconstrained-term
			// guard. Post-fix the EXCEPT error must be the recorded
			// degraded cause (asserted via substring below), not the
			// generic "unconstrained routing-instance" message.
			name:   "0.0.0.0/0 plus except with no other selector",
			family: "inet",
			term: &config.FirewallFilterTerm{
				Name:              "t",
				SourceAddresses:   []string{"0.0.0.0/0"},
				SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt", Except: true}},
				RoutingInstance:   "ATT",
			},
			pls: mgmt,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter := &config.FirewallFilter{
				Name:  "pbr-except-14699",
				Terms: []*config.FirewallFilterTerm{tc.term},
			}
			rules, err := BuildPBRRules(pbrTestConfig(tc.family, filter, instances, tc.pls))
			if len(rules) != 0 {
				t.Fatalf("non-empty except must drop the term (0 rules), got %d: %+v", len(rules), rules)
			}
			if err == nil {
				t.Fatal("non-empty except must return a degraded error (fail-closed)")
			}
			if !strings.Contains(err.Error(), "except") ||
				!strings.Contains(err.Error(), "cannot represent") {
				t.Fatalf("degraded error must name the unrepresentable except, got: %v", err)
			}
		})
	}
}

// #14699 controls: shapes that must KEEP their current behavior.
//
//   - A defined-EMPTY except carves nothing out, so 0.0.0.0/0 + empty
//     except stays one unconstrained rule, and a specific positive +
//     empty except keeps exactly the positive set.
//   - A pure non-empty except (no positive at all) still drops.
//   - A specific positive with NO except is untouched.
func TestResolvePBRDirectionExceptControls14699(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "ATT", TableID: 101}}

	t.Run("match-any plus defined-empty except stays match-all", func(t *testing.T) {
		pls := map[string]*config.PrefixList{"none": {Name: "none"}}
		filter := &config.FirewallFilter{
			Name: "pbr-except-14699-ctl",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:              "t",
					DSCPs:             []string{"ef"},
					SourceAddresses:   []string{"0.0.0.0/0"},
					SourcePrefixLists: []config.PrefixListRef{{Name: "none", Except: true}},
					RoutingInstance:   "ATT",
				},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
		if err != nil {
			t.Fatalf("defined-empty except must not degrade, got err: %v", err)
		}
		if len(rules) != 1 || rules[0].Src != "" {
			t.Fatalf("defined-empty except must yield one unconstrained rule (Src \"\"), got %+v", rules)
		}
	})

	t.Run("specific positive plus defined-empty except keeps positive set", func(t *testing.T) {
		pls := map[string]*config.PrefixList{"none": {Name: "none"}}
		filter := &config.FirewallFilter{
			Name: "pbr-except-14699-ctl",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:              "t",
					DSCPs:             []string{"ef"},
					SourceAddresses:   []string{"10.0.0.0/8"},
					SourcePrefixLists: []config.PrefixListRef{{Name: "none", Except: true}},
					RoutingInstance:   "ATT",
				},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
		if err != nil {
			t.Fatalf("defined-empty except must not degrade, got err: %v", err)
		}
		if len(rules) != 1 || rules[0].Src != "10.0.0.0/8" {
			t.Fatalf("empty except must keep the positive set (Src 10.0.0.0/8), got %+v", rules)
		}
	})

	t.Run("pure non-empty except still drops", func(t *testing.T) {
		pls := map[string]*config.PrefixList{
			"mgmt": {Name: "mgmt", Prefixes: []string{"10.9.0.0/16"}},
		}
		filter := &config.FirewallFilter{
			Name: "pbr-except-14699-ctl",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:              "t",
					DSCPs:             []string{"ef"},
					SourcePrefixLists: []config.PrefixListRef{{Name: "mgmt", Except: true}},
					RoutingInstance:   "ATT",
				},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, pls))
		if len(rules) != 0 {
			t.Fatalf("pure non-empty except must emit 0 rules, got %d: %+v", len(rules), rules)
		}
		if err == nil {
			t.Fatal("pure non-empty except must return a degraded error")
		}
	})

	t.Run("specific positive without except untouched", func(t *testing.T) {
		filter := &config.FirewallFilter{
			Name: "pbr-except-14699-ctl",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:            "t",
					DSCPs:           []string{"ef"},
					SourceAddresses: []string{"10.0.0.0/8"},
					RoutingInstance: "ATT",
				},
			},
		}
		rules, err := BuildPBRRules(pbrTestConfig("inet", filter, instances, nil))
		if err != nil {
			t.Fatalf("plain positive must not degrade, got err: %v", err)
		}
		if len(rules) != 1 || rules[0].Src != "10.0.0.0/8" {
			t.Fatalf("plain positive must yield its rule (Src 10.0.0.0/8), got %+v", rules)
		}
	})
}
