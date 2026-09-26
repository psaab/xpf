package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGeneratePolicyOptions_SetClauseSanitizedAndPrefixListOmitted_10823
// preserves #4482's hostile newline-injection coverage for values that remain
// sanitized onto their directive lines. The #10823 render belt now parses
// policy-options prefix-list entries as CIDRs before sanitization: malformed
// newline-bearing values are warned and omitted (fail-closed) rather than
// emitted as sanitized-but-invalid FRR prefixes. Inline route-filter entries
// already use the same fail-closed ParseCIDR posture (#2105).
//
// #4498 completes coverage for the remaining sanitized route-map slots. This
// test drives a newline payload through each one, verifies no injected
// top-level command appears, and checks that both malformed top-level
// prefix-list entries and malformed inline route-filters are absent:
//
//   - malformed IPv4 / IPv6 policy-options prefix-list entries (#10823)
//   - match community / match as-path                   (#4482)
//   - set community (replace / additive)                (#4482)
//   - set comm-list delete / set as-path prepend         (#4482)
//   - set ip / ipv6 next-hop / origin / source-protocol   (#4498)
//
// The NAME slots render through frrName rather than sanitizeFRRValue; their
// assertions below keep the injected values bounded to one FRR token.
func TestGeneratePolicyOptions_SetClauseSanitizedAndPrefixListOmitted_10823(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			// Newline-injecting invalid CIDRs exercise both family arms.
			// The #10823 ParseCIDR belt must omit these before sanitization.
			"pl-evil":  {Name: "pl-evil", Prefixes: []string{"10.0.0.0/8\n router bgp 65000"}},
			"pl-evil6": {Name: "pl-evil6", Prefixes: []string{"2001:db8::/32\n router bgp 65000"}},
		},
		Communities: map[string]*config.CommunityDef{
			// A `match community` name must now resolve to an emitted list
			// under #10822; define this one so the test exercises name
			// sanitation rather than the dangling-reference guard.
			"cm1\n neighbor 7.7.7.7 remote-as 65000": {
				Name:    "cm1\n neighbor 7.7.7.7 remote-as 65000",
				Members: []string{"65000:100"},
			},
		},
		ASPaths: map[string]*config.ASPathDef{
			// The t3 `match as-path` name slot must resolve: since #9881
			// the renderer never emits a dangling match (a reject term
			// over an absent list renders deny-all, other terms skip the
			// branch), so an undefined list would drop the very line this
			// test sanitizes. Defining it keeps the test on the
			// sanitization contract — and exercises frrName on the
			// `bgp as-path access-list` definition line too.
			"ap1\n router bgp 65000": {Name: "ap1\n router bgp 65000", Regex: "65000"},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{
						Name: "t1",
						// set community (whole-attribute replace) — injection.
						Community: "65000:1\n neighbor 6.6.6.6 remote-as 65000",
						Action:    "accept",
					},
					{
						Name: "t2",
						// set as-path prepend — injection with a legitimate
						// space between ASNs that must survive.
						ASPathPrepend: []string{"65001\n router bgp 65000", "65001"},
						Action:        "accept",
					},
					{
						Name: "t3",
						// match source-protocol / match community / match
						// as-path / set ip next-hop / set origin — every
						// remaining scalar free-text slot in one term.
						FromProtocols: []string{"bgp\n router bgp 65000"},
						FromCommunity: []string{"cm1\n neighbor 7.7.7.7 remote-as 65000"},
						FromASPath:    []string{"ap1\n router bgp 65000"},
						NextHop:       "1.2.3.4\n router bgp 65000",
						Origin:        "igp\n router bgp 65000",
						Action:        "accept",
					},
					{
						Name: "t4",
						// set community <v> additive — injection.
						CommunityOp:  "add",
						CommunityAdd: "65000:2\n neighbor 8.8.8.8 remote-as 65000",
						Action:       "accept",
					},
					{
						Name: "t5",
						// set comm-list <name> delete — injection.
						CommunityOp:     "delete",
						CommunityDelete: []string{"clist1\n neighbor 9.9.9.9 remote-as 65000"},
						Action:          "accept",
					},
					{
						Name: "t6",
						// set ipv6 next-hop global — a next-hop containing ":"
						// routes through the IPv6 render arm.
						NextHop: "2001:db8::1\n router bgp 65000",
						Action:  "accept",
					},
					{
						Name: "t7",
						// Inline route-filter with a control-char prefix. The
						// #2105 net.ParseCIDR belt fails-closed BEFORE the
						// sanitize call, so no prefix-list line is emitted at
						// all (asserted below).
						RouteFilters: []*config.RouteFilter{
							{Prefix: "10.9.0.0/16\n router bgp 65000", MatchType: "orlonger"},
						},
						Action: "accept",
					},
				},
			},
		},
	}

	got := m.generatePolicyOptions(po)

	// No injected top-level command line may appear: every rendered line must
	// be an FRR policy-options directive, never a bare `router bgp` /
	// `neighbor` that an injected newline would have created.
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "router bgp") || strings.HasPrefix(trimmed, "neighbor ") {
			t.Fatalf("config injection: rendered a standalone %q line:\n%s", trimmed, got)
		}
	}

	// Every still-sanitized route-map payload must survive collapsed onto its
	// single directive line (newline → space). The prefix-list payloads below
	// are instead rejected by ParseCIDR and have dedicated omission assertions.
	wantOnOneLine := []struct {
		slot string
		want string
	}{
		{"set community (replace)", " set community 65000:1  neighbor 6.6.6.6 remote-as 65000\n"},
		{"set as-path prepend", " set as-path prepend 65001  router bgp 65000 65001\n"},
		{"match source-protocol", " match source-protocol bgp  router bgp 65000\n"},
		// #9493: the three NAME slots (match community, match as-path, set
		// comm-list) render through frrName, not sanitizeFRRValue, and are
		// asserted below. Collapsing a name onto one line still split it into
		// extra FRR arguments, so FRR rejected the line; frrName renders it as
		// one token.
		{"set ip next-hop", " set ip next-hop 1.2.3.4  router bgp 65000\n"},
		// NOTE: `set origin` moved OUT of this sanitize-onto-one-line list by
		// #4919. The origin slot is now fail-closed by the validBGPOrigin
		// render belt (only igp | egp | incomplete render), so the injection
		// payload "igp\n router bgp 65000" is skipped entirely rather than
		// sanitized onto one line — a strictly stronger guarantee, asserted
		// separately below. (Parity with the route-filter CIDR fail-closed belt
		// already documented in this test.)
		{"set community additive", " set community 65000:2  neighbor 8.8.8.8 remote-as 65000 additive\n"},
		{"set ipv6 next-hop", " set ipv6 next-hop global 2001:db8::1  router bgp 65000\n"},
	}
	for _, tc := range wantOnOneLine {
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s not sanitized onto one line (want %q), got:\n%s", tc.slot, tc.want, got)
		}
	}
	for _, malformed := range []string{"10.0.0.0/8", "2001:db8::/32"} {
		if strings.Contains(got, malformed) {
			t.Errorf("policy-options prefix-list: malformed CIDR %q must be omitted, got:\n%s", malformed, got)
		}
	}

	for _, tc := range []struct{ slot, want string }{
		{"match community", " match community " + frrName("cm1\n neighbor 7.7.7.7 remote-as 65000") + "\n"},
		{"match as-path", " match as-path " + frrName("ap1\n router bgp 65000") + "\n"},
		{"set comm-list delete", " set comm-list " + frrName("clist1\n neighbor 9.9.9.9 remote-as 65000") + " delete\n"},
	} {
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s did not render as one token (want %q), got:\n%s", tc.slot, tc.want, got)
		}
	}

	// Inline route-filter: the malformed prefix is fail-closed by the #2105
	// net.ParseCIDR belt, so the payload never reaches the rendered config at
	// all (neither the CIDR nor its injected tail appears).
	if strings.Contains(got, "10.9.0.0/16") {
		t.Errorf("inline route-filter: malformed prefix should be fail-closed (skipped), got:\n%s", got)
	}

	// set origin (#4919): the invalid origin payload ("igp\n router bgp 65000")
	// is fail-closed by the validBGPOrigin render belt — only igp | egp |
	// incomplete render. No `set origin` line derived from the payload may
	// appear at all (the earlier no-standalone-`router bgp`-line guard already
	// covers the injected tail; this pins the fail-closed skip of the origin
	// slot specifically).
	if strings.Contains(got, "set origin igp  router bgp 65000") {
		t.Errorf("set origin: invalid origin should be fail-closed (skipped) by #4919, got:\n%s", got)
	}
}
