package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGeneratePolicyOptions_InjectionSanitized_4097 is a FAIL-ON-REVERT guard
// for the #4097 render-side belt. A `policy-options community` member or a
// `policy-options as-path` regex is rendered into a rest-of-line frr.conf token
// (bgp community-list / as-path access-list). Before the fix these two were the
// ONLY free-text FRR fields the module rendered with a bare %s — bypassing
// sanitizeFRRValue, the third of the documented #1798 defense layers ("the
// render-side belt ... at each free-text file interpolation"), which every auth
// / description field already uses.
//
// The embedded-newline injection itself is caught earlier by the #1798 AST
// gate (validateNodesControlChars hard-rejects on commit; sanitizeNodesControl-
// Chars scrubs on load) — see pkg/config TestFRRPolicyValueControlCharsBlocked_
// 4097 — so this belt is defense-in-depth for any future path that hands the
// renderer a typed value the AST walk never saw. sanitizeFRRValue collapses the
// newline to a space so the whole value stays on the single rendered line; a
// legitimate space inside an as-path regex (a multi-AS path) survives (FRR
// reads the regex as a rest-of-line token). Reverting the render-site sanitize
// turns this RED: a standalone `router bgp 65000` / `neighbor` line appears.
func TestGeneratePolicyOptions_InjectionSanitized_4097(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		Communities: map[string]*config.CommunityDef{
			// Newline-injecting member (sorts first: "evilc" < "okc").
			"evilc": {Name: "evilc", Members: []string{"65000:100\n router bgp 65000"}},
			// Normal member — must render unchanged.
			"okc": {Name: "okc", Members: []string{"65000:100"}},
		},
		ASPaths: map[string]*config.ASPathDef{
			// Newline-injecting regex ("evil" < "ok").
			"evil": {Name: "evil", Regex: "^1$\n router bgp 65000\n neighbor 6.6.6.6 remote-as 65000"},
			// Normal regex WITH a legitimate space — must survive verbatim.
			"ok": {Name: "ok", Regex: "^65001 65002$"},
		},
	}

	got := m.generatePolicyOptions(po)

	// No injected top-level command line may appear: every rendered line must
	// be an FRR policy-options directive (or a `!` separator), never a bare
	// `router bgp` / `neighbor` that the injected newline would have created.
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "router bgp") || strings.HasPrefix(trimmed, "neighbor ") {
			t.Fatalf("config injection: rendered a standalone %q line:\n%s", trimmed, got)
		}
	}

	// The injected content survives, but collapsed onto the single permit line.
	wantASPathEvil := "bgp as-path access-list evil permit ^1$  router bgp 65000  neighbor 6.6.6.6 remote-as 65000\n"
	if !strings.Contains(got, wantASPathEvil) {
		t.Errorf("as-path regex not sanitized onto one line; want %q in:\n%s", wantASPathEvil, got)
	}
	// #9490: a community member that is not an FRR community literal now OMITS
	// its definition at render, through the shared ValidCommunityMember
	// predicate, instead of collapsing onto one line. The collapsed line
	// `... permit 65000:100  router bgp 65000` was itself rejected by FRR's
	// community parser (`router` is no community), failing the whole reload.
	// Omission is strictly stronger, and the no-injected-line assertion above
	// still holds.
	if strings.Contains(got, "community-list standard evilc") || strings.Contains(got, "community-list expanded evilc") {
		t.Errorf("an injected community member must omit its definition, got:\n%s", got)
	}

	// The normal values render unchanged — a legitimate space is preserved.
	if !strings.Contains(got, "bgp as-path access-list ok permit ^65001 65002$\n") {
		t.Errorf("normal as-path regex altered:\n%s", got)
	}
	if !strings.Contains(got, "bgp community-list standard okc permit 65000:100\n") {
		t.Errorf("normal community member altered:\n%s", got)
	}
}
