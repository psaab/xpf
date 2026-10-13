package configstore

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12537: a group's packed policy term whose tail the generic packed-body
// expander cannot model — `from route-filter 10.0.0.0/8 orlonger reject` — was
// dropped wholesale when it merged with an inline `term T then accept`: strict
// CheckText accepted and the term compiled match-all accept (no route-filter).
// The direct spelling is rejected by #11779 (`from reject`). A group-carried
// term must validate, and compile, as its direct spelling does.

const routePolicyDefs12537 = "policy-options { prefix-list PA { 10.0.0.0/8; } " +
	"prefix-list PB { 192.168.0.0/16; } community C1 members 65000:1; } "

// routePolicyGroup12537 applies group G, holding groupTerm, to policy P whose
// inline body is inline.
func routePolicyGroup12537(groupTerm, inline string) string {
	return "groups { G { policy-options { policy-statement P { " + groupTerm + " } } } } " +
		routePolicyDefs12537 + "policy-options { apply-groups G; policy-statement P { " + inline + " } }"
}

// routePolicyDirect12537 spells a term inline, with no group.
func routePolicyDirect12537(term string) string {
	return routePolicyDefs12537 + "policy-options { policy-statement P { " + term + " } }"
}

// rejectPolicyText12537 requires CheckText, CommitCheck, and Commit to refuse
// text with an error naming want.
func rejectPolicyText12537(t *testing.T, text, want string) {
	t.Helper()
	if _, err := CheckText(text, 0); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("CheckText error = %v, want one naming %q", err, want)
	}
	store := newTestStore(t)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer store.ExitConfigure()
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.CommitCheck(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("CommitCheck error = %v, want one naming %q", err, want)
	}
	if _, err := store.Commit(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Commit error = %v, want one naming %q", err, want)
	}
}

// policyTermCompiled12537 requires CheckText to accept text and returns the
// compiled form of policy P's only term.
func policyTermCompiled12537(t *testing.T, text string) *config.PolicyTerm {
	t.Helper()
	cfg, err := CheckText(text, 0)
	if err != nil {
		t.Fatalf("CheckText: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 1 {
		t.Fatalf("policy P terms = %+v, want exactly one", ps)
	}
	return ps.Terms[0]
}

// policyTermSummary12537 renders the compiled match and action fields the
// cells below compare.
func policyTermSummary12537(tm *config.PolicyTerm) string {
	var rfs []string
	for _, rf := range tm.RouteFilters {
		rfs = append(rfs, rf.Prefix+" "+rf.MatchType)
	}
	return fmt.Sprintf("action=%q rf=%q proto=%q pl=%q community=%q/%q aspp=%q unknown=%q",
		tm.Action, rfs, tm.FromProtocols, tm.PrefixList, tm.CommunityOp, tm.CommunityAdd,
		tm.ASPathPrepend, tm.UnknownFrom)
}

func TestRouteFilterGroupTailActionRejected_12537(t *testing.T) {
	const term = "term T from route-filter 10.0.0.0/8 orlonger reject;"
	group := "groups { G { policy-options { policy-statement P { " + term + " } } } } "
	for name, tc := range map[string]struct{ text, want string }{
		"top apply / packed then": {
			group + "apply-groups G; policy-options { policy-statement P { term T then accept; } }",
			"`from reject` is not enforced",
		},
		"top apply / block then": {
			group + "apply-groups G; policy-options { policy-statement P { term T { then accept; } } }",
			"unconsumed route-filter token \"reject\"",
		},
		"policy-options apply / packed then": {
			group + "policy-options { apply-groups G; policy-statement P { term T then accept; } }",
			"`from reject` is not enforced",
		},
		"policy-options apply / block then": {
			group + "policy-options { apply-groups G; policy-statement P { term T { then accept; } } }",
			"unconsumed route-filter token \"reject\"",
		},
		"inline from": {
			group + "policy-options { apply-groups G; policy-statement P { term T from protocol static then accept; } }",
			"`from reject` is not enforced",
		},
		"wildcard policy-statement": {
			"groups { G { policy-options { policy-statement <*> { " + term + " } } } } " +
				"policy-options { apply-groups G; policy-statement P { term T then accept; } }",
			"`from reject` is not enforced",
		},
		"bad group first": {
			"groups { G1 { policy-options { policy-statement P { " + term + " } } } " +
				"G2 { policy-options { policy-statement P { term T from protocol static; } } } } " +
				"policy-options { apply-groups [ G1 G2 ]; policy-statement P { term T then accept; } }",
			"`from reject` is not enforced",
		},
		"bad group second": {
			"groups { G1 { policy-options { policy-statement P { term T from protocol static; } } } " +
				"G2 { policy-options { policy-statement P { " + term + " } } } } " +
				"policy-options { apply-groups [ G1 G2 ]; policy-statement P { term T then accept; } }",
			"unconsumed route-filter token \"reject\"",
		},
		// Group adopted with no inline term at all: already rejected, pin it.
		"group only": {
			group + "apply-groups G;",
			"`from reject` is not enforced",
		},
		// Direct contrast.
		"direct": {
			"policy-options { policy-statement P { " + term + " } }",
			"`from reject` is not enforced",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rejectPolicyText12537(t, tc.text, tc.want)
		})
	}
	t.Run("accept tail", func(t *testing.T) {
		rejectPolicyText12537(t, routePolicyGroup12537(
			"term T from route-filter 10.0.0.0/8 orlonger accept;", "term T then accept;"),
			"`from accept` is not enforced")
	})
}

// Valid group-carried route-filters must survive merging with an inline then.
func TestRouteFilterGroupValidSurvivesMerge_12537(t *testing.T) {
	cases := map[string]struct {
		groupTerm string
		wantRF    int
		wantMatch string
	}{
		"orlonger":   {"term T from route-filter 10.0.0.0/8 orlonger;", 1, "orlonger"},
		"exact":      {"term T from route-filter 10.0.0.0/8 exact;", 1, "exact"},
		"upto":       {"term T from route-filter 10.0.0.0/8 upto /24;", 1, "upto"},
		"two":        {"term T from route-filter 10.0.0.0/8 orlonger route-filter 192.168.0.0/16 exact;", 2, ""},
		"mixed-from": {"term T from protocol static route-filter 10.0.0.0/8 orlonger;", 1, "orlonger"},
		// The expander declines `community add C1`: these reach the rebuild.
		"then community":   {"term T from route-filter 10.0.0.0/8 orlonger then community add C1;", 1, "orlonger"},
		"protocol list":    {"term T from protocol static bgp route-filter 10.0.0.0/8 orlonger;", 1, "orlonger"},
		"bracketed + then": {"term T from protocol [ static bgp ] route-filter 10.0.0.0/8 exact then community add C1;", 1, "exact"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			text := "groups { G { policy-options { policy-statement P { " + tc.groupTerm + " } } } } " +
				routePolicyDefs12537 + "policy-options { apply-groups G; policy-statement P { term T then accept; } }"
			tree, perrs := config.NewParser(text).Parse()
			if len(perrs) > 0 {
				t.Fatal(perrs)
			}
			if err := tree.ExpandGroups(); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatal(err)
			}
			ps := cfg.PolicyOptions.PolicyStatements["P"]
			if ps == nil || len(ps.Terms) != 1 {
				t.Fatalf("terms = %+v", ps)
			}
			tm := ps.Terms[0]
			if tm.Action != "accept" {
				t.Fatalf("action = %q, want accept (inline then wins)", tm.Action)
			}
			if len(tm.RouteFilters) != tc.wantRF {
				t.Fatalf("route-filters = %v, want %d", tm.RouteFilters, tc.wantRF)
			}
			if tc.wantMatch != "" && tm.RouteFilters[0].MatchType != tc.wantMatch {
				t.Fatalf("match-type = %q, want %q", tm.RouteFilters[0].MatchType, tc.wantMatch)
			}
			if _, err := CheckText(text, 0); err != nil {
				t.Fatalf("CheckText valid group route-filter: %v", err)
			}
		})
	}
}

// Invalid tails other than action words must also not be silently dropped.
func TestRouteFilterGroupInvalidTailsRejected_12537(t *testing.T) {
	for _, tail := range []string{"", "orlonger foo", "exact 17", "upto", "upto /129", "orlongerr",
		"orlonger /24", "upto /24 /16"} {
		t.Run(tail, func(t *testing.T) {
			text := "groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 " + tail + "; } } } } apply-groups G; policy-options { policy-statement P { term T then accept; } }"
			if _, err := CheckText(text, 0); err == nil {
				t.Fatalf("CheckText accepted group route-filter tail %q", tail)
			}
		})
	}
}

// #12687: a group route-filter whose trailer does not parse was dropped the
// same way (permit-all, no warning) against an inline then, packed or braced.
// The #12537 rebuild hands the trailer to the route-filter gates.
func TestRouteFilterGroupUnparseableTrailerRejected_12687(t *testing.T) {
	for _, tc := range []struct{ trailer, want string }{
		{"upto /bogus", `"/bogus"`},
		{"prefix-length-range /24-/abc", "prefix-length-range: malformed range"},
		{"through bogus", `through "bogus"`},
	} {
		groupTerm := "term T from route-filter 10.0.0.0/8 " + tc.trailer + ";"
		for name, inline := range map[string]string{
			"packed then": "term T then accept;",
			"braced then": "term T { then accept; }",
		} {
			t.Run(tc.trailer+"/"+name, func(t *testing.T) {
				rejectPolicyText12537(t, routePolicyGroup12537(groupTerm, inline), tc.want)
			})
		}
		t.Run(tc.trailer+"/direct", func(t *testing.T) {
			rejectPolicyText12537(t, routePolicyDirect12537(
				"term T from route-filter 10.0.0.0/8 "+tc.trailer+" then accept;"), tc.want)
		})
	}
}

// #12696 review B1: firewall filter terms must keep their own grammar through
// apply-groups. Rebuilding their `from` with the routing-policy reader split
// `destination-port 80` into a valueless leaf plus a stray value; strict
// refused valid configs and the tolerant path compiled empty match sets.
func TestFirewallGroupTermsKeepTheirMatches_12537(t *testing.T) {
	type want struct {
		action    string
		proto     []string
		dport     []string
		src       []string
		icmp      []int
		prefixLst string
	}
	for _, tc := range []struct {
		name, fam, groupTerm, inline string
		want                         want
	}{
		{"protocol + destination-port", "inet", "term T from protocol tcp destination-port 80;", "term T then accept;",
			want{action: "accept", proto: []string{"tcp"}, dport: []string{"80"}}},
		{"source-address", "inet", "term T from source-address 10.0.0.0/8;", "term T then discard;",
			want{action: "discard", src: []string{"10.0.0.0/8"}}},
		{"source-address with group then", "inet", "term T from source-address 10.0.0.0/8 then count C1;", "term T then discard;",
			want{action: "discard", src: []string{"10.0.0.0/8"}}},
		{"inline from", "inet", "term T then count C1;", "term T from protocol udp destination-port 53 then accept;",
			want{action: "accept", proto: []string{"udp"}, dport: []string{"53"}}},
		{"both from", "inet", "term T from source-address 10.0.0.0/8;", "term T from protocol tcp then discard;",
			want{action: "discard", proto: []string{"tcp"}, src: []string{"10.0.0.0/8"}}},
		{"braced inline", "inet", "term T from protocol tcp destination-port 80;", "term T { then accept; }",
			want{action: "accept", proto: []string{"tcp"}, dport: []string{"80"}}},
		{"icmp-type", "inet", "term T from protocol icmp icmp-type 8;", "term T then accept;",
			want{action: "accept", proto: []string{"icmp"}, icmp: []int{8}}},
		{"source-prefix-list", "inet", "term T from source-prefix-list PL;", "term T then accept;",
			want{action: "accept", prefixLst: "PL"}},
		{"inet6 source-address", "inet6", "term T from source-address 2001:db8::/32;", "term T then discard;",
			want{action: "discard", src: []string{"2001:db8::/32"}}},
		{"inet6 next-header + destination-port", "inet6", "term T from next-header tcp destination-port 443;", "term T then accept;",
			want{action: "accept", proto: []string{"tcp"}, dport: []string{"443"}}},
		{"inet6 inline from", "inet6", "term T then count C1;", "term T from next-header udp destination-port 53 then accept;",
			want{action: "accept", proto: []string{"udp"}, dport: []string{"53"}}},
	} {
		t.Run(tc.fam+"/"+tc.name, func(t *testing.T) {
			text := "groups { G { firewall { family " + tc.fam + " { filter F { " + tc.groupTerm + " } } } } } " +
				"policy-options { prefix-list PL { 10.0.0.0/8; } } apply-groups G; " +
				"firewall { family " + tc.fam + " { filter F { " + tc.inline + " } } }"
			term := func(cfg *config.Config) *config.FirewallFilterTerm {
				t.Helper()
				filters := cfg.Firewall.FiltersInet
				if tc.fam == "inet6" {
					filters = cfg.Firewall.FiltersInet6
				}
				f := filters["F"]
				if f == nil || len(f.Terms) != 1 {
					t.Fatalf("filter F = %+v, want one term", f)
				}
				return f.Terms[0]
			}
			cfg, err := CheckText(text, 0)
			if err != nil {
				t.Fatalf("CheckText: %v", err)
			}
			got := term(cfg)
			var prefixLst string
			if len(got.SourcePrefixLists) == 1 {
				prefixLst = got.SourcePrefixLists[0].Name
			}
			if got.Action != tc.want.action || !slices.Equal(got.Protocols, tc.want.proto) ||
				!slices.Equal(got.DestinationPorts, tc.want.dport) || !slices.Equal(got.SourceAddresses, tc.want.src) ||
				!slices.Equal(got.ICMPTypes, tc.want.icmp) || prefixLst != tc.want.prefixLst {
				t.Fatalf("term = action %q proto %q dport %q src %q icmp %v prefix-lists %v, want %+v",
					got.Action, got.Protocols, got.DestinationPorts, got.SourceAddresses, got.ICMPTypes,
					got.SourcePrefixLists, tc.want)
			}
			// The tolerant (boot / peer-sync) compile must not carry the
			// markers that make the dataplane refuse the whole snapshot.
			tree, perrs := config.NewParser(text).Parse()
			if len(perrs) > 0 {
				t.Fatal(perrs)
			}
			lenient, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatal(err)
			}
			if lt := term(lenient); len(lt.ValuelessFrom) > 0 || len(lt.UnknownFrom) > 0 {
				t.Fatalf("tolerant compile marked valueless %q unknown %q", lt.ValuelessFrom, lt.UnknownFrom)
			}
		})
	}
}

// #12696 review B2: a term with two `from` clauses is valid directly and must
// merge as one `from`, without a stray `from` leaf or a duplicated filter.
func TestPolicyGroupTwoFromClauses_12537(t *testing.T) {
	const want = `action="accept" rf=["10.0.0.0/8 orlonger"] proto=["static"] pl=[] community=""/"" aspp=[] unknown=[]`
	for name, text := range map[string]string{
		"group side":  routePolicyGroup12537("term T from protocol static from route-filter 10.0.0.0/8 orlonger;", "term T then accept;"),
		"inline side": routePolicyGroup12537("term T then accept;", "term T from protocol static from route-filter 10.0.0.0/8 orlonger;"),
		"direct":      routePolicyDirect12537("term T from protocol static from route-filter 10.0.0.0/8 orlonger then accept;"),
	} {
		t.Run(name, func(t *testing.T) {
			if got := policyTermSummary12537(policyTermCompiled12537(t, text)); got != want {
				t.Fatalf("term = %s\nwant   %s", got, want)
			}
		})
	}
	t.Run("rebuilt group side names the tail", func(t *testing.T) {
		text := routePolicyGroup12537(
			"term T from protocol static from route-filter 10.0.0.0/8 orlonger reject;", "term T then accept;")
		rejectPolicyText12537(t, text, "`from reject` is not enforced")
		if _, err := CheckText(text, 0); err == nil || strings.Contains(err.Error(), "`from from`") {
			t.Fatalf("CheckText error = %v, the second `from` opens a clause", err)
		}
	})
}

// #12696 review F3: through a group, a term the expander declines must compile
// as its direct spelling — every value of an unbracketed list, a quoted `then`
// as the clause word, and the actions the group carries.
func TestPolicyGroupTermMatchesDirectSpelling_12537(t *testing.T) {
	for _, tc := range []struct{ name, groupTerm, inline, direct string }{
		{"protocol list", "term T from protocol static bgp;", "term T then accept;",
			"term T from protocol static bgp then accept;"},
		{"prefix-list list", "term T from prefix-list PA PB;", "term T then accept;",
			"term T from prefix-list PA PB then accept;"},
		{"quoted then", `term T from route-filter 10.0.0.0/8 orlonger "then" accept;`, "term T then accept;",
			`term T from route-filter 10.0.0.0/8 orlonger "then" accept;`},
		{"then community", "term T from route-filter 10.0.0.0/8 orlonger then community add C1;", "term T then accept;",
			"term T from route-filter 10.0.0.0/8 orlonger then community add C1 accept;"},
		{"then-first from", "term T then community add C1 from protocol static;", "term T then accept;",
			"term T then community add C1 accept from protocol static;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := policyTermSummary12537(policyTermCompiled12537(t, routePolicyDirect12537(tc.direct)))
			got := policyTermSummary12537(policyTermCompiled12537(t, routePolicyGroup12537(tc.groupTerm, tc.inline)))
			if got != want {
				t.Fatalf("group-merged term = %s\ndirect spelling   = %s", got, want)
			}
		})
	}
}

// #12696 review F4: a malformed group `then` must not vanish beside the inline
// one. Strict rejects it with the direct spelling's #12517 diagnostic, and the
// tolerant path warns and keeps the group's action instead of accepting.
func TestPolicyGroupMalformedThenRejected_12537(t *testing.T) {
	const want = `then reject: unknown modifier "bogus"`
	for name, text := range map[string]string{
		"group then vs inline then": routePolicyGroup12537(
			"term T from route-filter 10.0.0.0/8 orlonger then reject bogus;", "term T then accept;"),
		"group then vs inline from": routePolicyGroup12537(
			"term T then reject bogus;", "term T from route-filter 10.0.0.0/8 orlonger;"),
		"tail after an operand": routePolicyGroup12537(
			"term T from route-filter 10.0.0.0/8 orlonger then local-preference 200 reject bogus;", "term T then accept;"),
		"direct": routePolicyDirect12537("term T from route-filter 10.0.0.0/8 orlonger then reject bogus;"),
	} {
		t.Run(name, func(t *testing.T) { rejectPolicyText12537(t, text, want) })
	}
	t.Run("tolerant", func(t *testing.T) {
		tree, perrs := config.NewParser(routePolicyGroup12537(
			"term T from route-filter 10.0.0.0/8 orlonger then reject bogus;", "term T then accept;")).Parse()
		if len(perrs) > 0 {
			t.Fatal(perrs)
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatal(err)
		}
		tm := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
		if tm.Action != "reject" || len(tm.RouteFilters) != 1 {
			t.Fatalf("tolerant term = %s, want the group's reject and route-filter", policyTermSummary12537(tm))
		}
		if !slices.ContainsFunc(cfg.Warnings, func(w string) bool { return strings.Contains(w, want) }) {
			t.Fatalf("tolerant warnings = %q, want one naming %q", cfg.Warnings, want)
		}
	})
}

// The mirror image: an inline term the expander declines (an unbracketed
// list, `then community add C1`) bailed promotion, and the group's
// route-filter was dropped — `term T then community add C1 accept` compiled
// match-all. The inline term is rebuilt too; its own values still win.
func TestPolicyInlineDeclinedKeepsGroupFrom_12537(t *testing.T) {
	const groupRF = "term T from route-filter 10.0.0.0/8 orlonger;"
	for _, tc := range []struct{ name, groupTerm, inline, want string }{
		{"inline community add", groupRF, "term T then community add C1 accept;",
			`action="accept" rf=["10.0.0.0/8 orlonger"] proto=[] pl=[] community="add"/"65000:1" aspp=[] unknown=[]`},
		{"inline protocol list", groupRF, "term T from protocol static bgp then accept;",
			`action="accept" rf=["10.0.0.0/8 orlonger"] proto=["static" "bgp"] pl=[] community=""/"" aspp=[] unknown=[]`},
		{"inline then-first from", groupRF, "term T then accept from protocol static bgp;",
			`action="accept" rf=["10.0.0.0/8 orlonger"] proto=["static" "bgp"] pl=[] community=""/"" aspp=[] unknown=[]`},
		{"inline as-path-prepend wins",
			"term T from route-filter 10.0.0.0/8 orlonger then as-path-prepend 65001;",
			"term T then as-path-prepend 65002 65002 community add C1 accept;",
			`action="accept" rf=["10.0.0.0/8 orlonger"] proto=[] pl=[] community="add"/"65000:1" aspp=["65002" "65002"] unknown=[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyTermSummary12537(policyTermCompiled12537(t, routePolicyGroup12537(tc.groupTerm, tc.inline))); got != tc.want {
				t.Fatalf("term = %s\nwant   %s", got, tc.want)
			}
		})
	}
	// A malformed inline term still fails exactly as written.
	t.Run("inline unknown action", func(t *testing.T) {
		rejectPolicyText12537(t, routePolicyGroup12537(groupRF, "term T then rejct accept;"), `then: unknown action "rejct"`)
	})
	t.Run("inline tail", func(t *testing.T) {
		rejectPolicyText12537(t, routePolicyGroup12537(groupRF,
			"term T from route-filter 192.168.0.0/16 orlonger reject then accept;"), "`from reject` is not enforced")
	})
}
