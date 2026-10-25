package cli

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// multiAppPolicyIndexConfig mirrors the dataplane userspace fixture: policy set
// 0 holds "allow-web" (an application-set expanding to junos-http + junos-https,
// span 2) followed by "allow-ssh" (single application, span 1), plus a global
// "global-allow" policy. The runtime/RT_FLOW policy ID is span-accumulated, so
// allow-ssh occupies runtime slot 2 (NOT the raw ordinal 1) and the global set
// starts contiguously at 3 (#16560).
func multiAppPolicyIndexConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"web-apps": {
			Name:         "web-apps",
			Applications: []string{"junos-http", "junos-https"},
		},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{
			{
				Name:   "allow-web",
				Match:  config.PolicyMatch{Applications: []string{"web-apps"}},
				Action: config.PolicyPermit,
			},
			{
				Name:   "deny-ssh",
				Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
				Action: config.PolicyDeny,
			},
		},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:   "global-allow",
		Match:  config.PolicyMatch{Applications: []string{"junos-ssh"}},
		Action: config.PolicyPermit,
	}}
	return cfg
}

// policyDetailIndex extracts the `Index: N` value printed for a named policy in
// `show security policies detail` output.
func policyDetailIndex(t *testing.T, out, policyName string) uint32 {
	t.Helper()
	re := regexp.MustCompile(`Policy: ` + regexp.QuoteMeta(policyName) + `,.*Index: (\d+)`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("policy %q Index line not found in output:\n%s", policyName, out)
	}
	v, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatalf("parse Index %q: %v", m[1], err)
	}
	return uint32(v)
}

// Test_3063_PolicyDetailIndexMatchesRuntimePolicyID is the fail-on-revert guard.
// The displayed detail Index must equal the span-accumulated runtime/RT_FLOW
// policy ID so an operator cross-referencing a policy-deny log lands on the
// correct row. deny-ssh follows a 2-term app-set policy, so its runtime Index is
// 2 (NOT the raw ordinal 1), and the global policy's Index is MaxRulesPerPolicy.
//
// Reverting the fix (display Index back to policySetID*MaxRulesPerPolicy + i)
// makes deny-ssh print Index 1 → this test goes RED.
func Test_3063_PolicyDetailIndexMatchesRuntimePolicyID(t *testing.T) {
	cfg := multiAppPolicyIndexConfig()
	c := &CLI{}

	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})

	if got := policyDetailIndex(t, out, "allow-web"); got != 0 {
		t.Fatalf("allow-web Index = %d, want 0", got)
	}
	if got := policyDetailIndex(t, out, "deny-ssh"); got != 2 {
		t.Fatalf("deny-ssh Index = %d, want 2 (span-accumulated runtime ID, NOT raw ordinal 1)", got)
	}
	if got := policyDetailIndex(t, out, "global-allow"); got != 3 {
		t.Fatalf("global-allow Index = %d, want 3 (contiguous base of the global set, #16560)", got)
	}
}

// Test_3063_PolicyDetailDispatchIndexMatchesRuntimePolicyID asserts the same on
// the second detail surface (the dispatch `show security policies detail` body
// reached via handleShow), which also repeated the raw-ordinal Index.
func Test_3063_PolicyDetailDispatchIndexMatchesRuntimePolicyID(t *testing.T) {
	store := newConfigStore(t, t.TempDir()+"/xpf.conf")
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"security zones security-zone lan",
		"security zones security-zone wan",
		"applications application-set web-apps application junos-http",
		"applications application-set web-apps application junos-https",
		"security policies from-zone lan to-zone wan policy allow-web match source-address any",
		"security policies from-zone lan to-zone wan policy allow-web match destination-address any",
		"security policies from-zone lan to-zone wan policy allow-web match application web-apps",
		"security policies from-zone lan to-zone wan policy allow-web then permit",
		"security policies from-zone lan to-zone wan policy deny-ssh match source-address any",
		"security policies from-zone lan to-zone wan policy deny-ssh match destination-address any",
		"security policies from-zone lan to-zone wan policy deny-ssh match application junos-ssh",
		"security policies from-zone lan to-zone wan policy deny-ssh then deny",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := &CLI{store: store}

	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"security", "policies", "detail"}); err != nil {
			t.Fatalf("handleShow: %v", err)
		}
	})
	if !strings.Contains(out, "deny-ssh") {
		t.Fatalf("dispatch detail output missing deny-ssh:\n%s", out)
	}
	if got := policyDetailIndex(t, out, "deny-ssh"); got != 2 {
		t.Fatalf("dispatch deny-ssh Index = %d, want 2 (runtime ID, not raw ordinal 1)", got)
	}
}

// Test_3063_SingleAppPolicyIndexUnchanged is the byte-identical regression: with
// no multi-application policy, every policy's span is 1, so the runtime Index
// equals the raw ordinal and the displayed Index is unchanged from pre-#3063.
func Test_3063_SingleAppPolicyIndexUnchanged(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{
			{Name: "p0", Match: config.PolicyMatch{Applications: []string{"junos-ssh"}}, Action: config.PolicyPermit},
			{Name: "p1", Match: config.PolicyMatch{Applications: []string{"junos-http"}}, Action: config.PolicyDeny},
			{Name: "p2", Action: config.PolicyPermit},
		},
	}}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "g0", Action: config.PolicyDeny},
	}
	c := &CLI{}

	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesDetail: %v", err)
		}
	})

	for name, want := range map[string]uint32{"p0": 0, "p1": 1, "p2": 2, "g0": 3} {
		if got := policyDetailIndex(t, out, name); got != want {
			t.Fatalf("%s Index = %d, want %d (single-app config must be byte-identical to raw ordinal)", name, got, want)
		}
	}
}
