package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestChildNameCollisionDisambiguated is the #5122 RED-on-revert guard. Two
// distinct traffic-selector names that differ ONLY in a sanitized character
// (`site/a` vs `site:a` — both legal Junos identifier chars) both sanitize to
// the base `site-a`. Before the fix effectiveTrafficSelectors emitted TWO
// `tun1-site-a {` child sections with identical names, so strongSwan rejected
// the config or silently merged/lost one selector. The fix appends a stable
// hash of the original selector name to each colliding entry, so both sections
// render with DISTINCT names and neither selector is dropped.
//
// Reverting the disambiguation in policy.go makes both sections share the name
// `tun1-site-a` and this test goes RED.
func TestChildNameCollisionDisambiguated(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"site/a": {Name: "site/a", LocalIP: "10.0.1.0/24", RemoteIP: "10.0.9.0/24"},
					"site:a": {Name: "site:a", LocalIP: "10.0.2.0/24", RemoteIP: "10.0.9.0/24"},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
	}

	got := m.generateConfig(cfg)

	// #6824: read the child sections out of the PARSED document rather than by
	// scanning for lines that look like section openers. The parser also
	// rejects two sections sharing a name under one parent outright, which is
	// the #5122 defect stated as a structural property instead of inferred from
	// a name list.
	children := parseSwanctlDoc(t, got).at(t, "connections", "tun1", "children")
	names := children.childNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 child sections for the two selectors, got %d: %v\n%s",
			len(names), names, children)
	}
	if names[0] == names[1] {
		t.Fatalf("distinct selectors site/a and site:a rendered DUPLICATE child "+
			"section name %q (strongSwan would reject/merge one selector, #5122):\n%s",
			names[0], children)
	}
	// Both selectors must survive to the render. Containment could only say the
	// two local_ts values appear SOMEWHERE; what matters is that they land in
	// two DIFFERENT child sections, so neither selector was overwritten.
	byLocalTS := map[string]string{}
	for _, n := range names {
		byLocalTS[children.at(t, n).setting(t, "local_ts")] = n
	}
	for _, want := range []string{"10.0.1.0/24", "10.0.2.0/24"} {
		if _, ok := byLocalTS[want]; !ok {
			t.Errorf("no child section carries local_ts = %s; sections carry %v\n%s",
				want, byLocalTS, children)
		}
	}
	if len(byLocalTS) != 2 {
		t.Errorf("the two selectors did not land in two distinct child sections: %v", byLocalTS)
	}
	// Both disambiguated names must keep the sanitized base as a prefix so the
	// naming stays recognizable / stable-shaped.
	for _, n := range names {
		if !strings.HasPrefix(n, "tun1-site-a") {
			t.Fatalf("disambiguated child section %q lost the sanitized base prefix "+
				"tun1-site-a:\n%s", n, got)
		}
	}
}

// TestChildNameNonCollidingUnchanged is the no-churn negative control: two
// selectors whose sanitized bases already differ (and a lone selector) keep
// their plain `connName-<sanitized>` names with NO hash suffix. Only an actual
// collision may trigger disambiguation.
func TestChildNameNonCollidingUnchanged(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"alpha": {Name: "alpha", LocalIP: "10.0.1.0/24", RemoteIP: "10.0.9.0/24"},
					"beta":  {Name: "beta", LocalIP: "10.0.2.0/24", RemoteIP: "10.0.9.0/24"},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
	}

	// #6824: the child-section names come from the parsed tree, so a name that
	// appears in the document but is NOT a child of this connection can no
	// longer satisfy the assertion.
	children := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "tun1", "children")
	names := children.childNames()
	want := map[string]bool{"tun1-alpha": true, "tun1-beta": true}
	if len(names) != 2 {
		t.Fatalf("expected 2 child sections, got %d: %v\n%s", len(names), names, children)
	}
	for _, n := range names {
		if !want[n] {
			t.Fatalf("non-colliding selector rendered unexpected/disambiguated name "+
				"%q (want one of %v):\n%s", n, want, children)
		}
	}
}

// TestChildNameSingleSelectorUnchanged asserts a normal single selector renders
// its `connName-<sanitized>` name unchanged (no disambiguator applied).
func TestChildNameSingleSelectorUnchanged(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: "10.0.1.0/24", RemoteIP: "10.0.9.0/24"},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
	}

	// #6824: `Contains(got, "tun1-ts1 {\n")` depended on brace placement and
	// would also match the text appearing inside a value. Resolving the path
	// asserts the section EXISTS where it belongs.
	parseSwanctlDoc(t, m.generateConfig(cfg)).
		at(t, "connections", "tun1", "children", "tun1-ts1")
}
