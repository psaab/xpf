package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGeneratePolicyOptions_SetClauseAndPrefixListSanitized_4482 is a
// FAIL-ON-REVERT guard for the residual #4097 sanitize-belt bypass on the
// tolerant-load path. #4097 wrapped the `bgp community-list` / `bgp as-path
// access-list` DEFINITIONS in sanitizeFRRValue, but left the route-map `set
// community` / `set as-path prepend` clauses AND the `ip/ipv6 prefix-list`
// entries rendering with a bare %s. A value that carries an embedded newline
// (materialized from a stored `\n` escape by the lexer on a leniently-loaded /
// peer-synced / rolled-back config — the paths the strict #1798 commit gate
// does NOT cover) would then inject a standalone frr.conf command.
//
// The fix routes ALL FRR-rendered free-text through sanitizeFRRValue regardless
// of load path, collapsing the newline to a space so the value stays on its
// single rendered line. Reverting any of the wrapped sites turns this RED: a
// bare `router bgp` / `neighbor` line appears in the managed section.
//
// #4498 completes the coverage. The original guard exercised only 3 of the
// route-map free-text slots (prefix-list, set community, set as-path prepend);
// this test now drives an injection payload through EVERY wrapped slot so a
// revert of any one of them is caught:
//
//   - ip / ipv6 prefix-list entry            (#4482)
//   - match community                        (#4482)
//   - match as-path                          (#4482)
//   - set community (replace)                (#4482)
//   - set community <v> additive             (#4482)
//   - set comm-list <name> delete            (#4482)
//   - set as-path prepend                    (#4482)
//   - set ip / ipv6 next-hop                 (#4498 residual)
//   - set origin                             (#4498 residual)
//   - match source-protocol                  (#4498 residual)
//
// The inline route-filter prefix-list slot (renderRouteFilterEntry) is also a
// sanitizeFRRValue call site, but it sits BEHIND the #2105 net.ParseCIDR belt:
// a control-char prefix fails net.ParseCIDR and the entry is skipped entirely
// (fail-closed) before the sanitize call is ever reached, so its sanitize is
// pure defense-in-depth and cannot be exercised with a control-char payload.
// The test asserts that fail-closed property directly (no injected line, and
// the malformed prefix never appears in the output).
func TestGeneratePolicyOptions_SetClauseAndPrefixListSanitized_4482(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			// Newline-injecting prefix values — IPv4 and IPv6 variants
			// exercise both the `ip` and `ipv6` prefix-list render arms.
			"pl-evil":  {Name: "pl-evil", Prefixes: []string{"10.0.0.0/8\n router bgp 65000"}},
			"pl-evil6": {Name: "pl-evil6", Prefixes: []string{"2001:db8::/32\n router bgp 65000"}},
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

	// Every wrapped slot's payload must survive collapsed onto its single
	// directive line (newline → space, so the "\n " in each payload becomes a
	// double space). A per-slot assertion pinpoints exactly which sanitize
	// call regressed if one is reverted.
	wantOnOneLine := []struct {
		slot string
		want string
	}{
		{"ip prefix-list", "ip prefix-list pl-evil seq 5 permit 10.0.0.0/8  router bgp 65000\n"},
		{"ipv6 prefix-list", "ipv6 prefix-list pl-evil6 seq 5 permit 2001:db8::/32  router bgp 65000\n"},
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
