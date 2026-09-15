package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRenderTrafficSelectorSanitizesInjection is the #4098 render RED-on-revert
// guard. A `traffic-selector local-ip / remote-ip` whose value carries a
// materialized newline (the Junos lexer turns a quoted `\n` into a real
// newline) must NOT reach the swanctl.conf children{} block verbatim: the raw
// renderer emitted `local_ts = <value>` unescaped, so the newline started a
// fresh `updown = <script>` line inside the child block — a config-injection
// executed by the root charon daemon (root RCE). renderConfig now runs
// local_ts / remote_ts through sanitizeSwanctlValue (control chars -> spaces),
// parity with the sibling child SA name, so the injected line collapses onto
// the local_ts value and is inert.
//
// Reverting the sanitizeSwanctlValue wrap in policy.go makes the rendered
// config contain a standalone `updown = ...` line and this test goes RED.
func TestRenderTrafficSelectorSanitizesInjection(t *testing.T) {
	const injectedLocal = "10.0.0.0/24\n        updown = /tmp/pwn.sh"
	const injectedRemote = "10.0.1.0/24\n        esp_proposals = null-null"

	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: injectedLocal, RemoteIP: injectedRemote},
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

	// #6824: assert on the parsed document, not on lines. A line scan asks
	// whether an injected setting appears anywhere; what actually matters is
	// whether it became a SETTING of the child section -- which is what
	// strongSwan would act on. Parsing says so directly.
	doc := parseSwanctlDoc(t, got)

	// The injected settings must not exist as settings ANYWHERE. Scoping this
	// to the expected child section would pass on a render that emitted a
	// SIBLING child carrying `updown = /tmp/pwn.sh` -- a live child-SA location
	// where charon executes it as root, which is the whole reason this test
	// exists. The old line scan covered the whole document and the first
	// structural conversion narrowed it; that was a real loss of power.
	doc.hasNoSettingAnywhere(t, "updown")
	// The deleted check was `HasPrefix(trimmed, "esp_proposals = null-null")` --
	// a line prefix on a NAMED key, not a bare token. A bare-substring form is
	// wrong here in the over-reject direction: the sanitized remote_ts value
	// legitimately contains the injected text, collapsed onto one line, which
	// is exactly what the belt is supposed to do to it.
	doc.hasNoSettingValuePrefixAnywhere(t, "esp_proposals", "null-null")

	child := doc.at(t, "connections", "tun1", "children", "tun1-ts1")

	// The sanitized value stays on the local_ts line (newline -> space), so
	// the tunnel still carries the operator's selector prefix — the belt does
	// not drop the whole value. The prefix check is on the VALUE of a setting
	// at a known path, which is a different claim from "these bytes appear
	// somewhere in the document".
	if lts := child.setting(t, "local_ts"); !strings.HasPrefix(lts, "10.0.0.0/24") {
		t.Errorf("children.tun1-ts1.local_ts = %q, want it to still start with 10.0.0.0/24", lts)
	}
}

// TestRenderTrafficSelectorNormalUnchanged is the over-reject negative control:
// a well-formed CIDR selector renders byte-for-byte as before (the sanitize
// belt is a no-op on a clean value).
func TestRenderTrafficSelectorNormalUnchanged(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: "10.0.0.0/24", RemoteIP: "10.0.1.0/24"},
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
	// #6824: the old needles carried a trailing "\n" purely to approximate
	// "the value ends here" -- an equality assertion at a known path states
	// that outright, and additionally pins WHICH child section carries it.
	child := parseSwanctlDoc(t, m.generateConfig(cfg)).
		at(t, "connections", "tun1", "children", "tun1-ts1")
	child.requireSetting(t, "local_ts", "10.0.0.0/24")
	child.requireSetting(t, "remote_ts", "10.0.1.0/24")
}
