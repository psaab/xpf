package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// buildAddrCfg constructs the minimal renderable IPsecConfig used by the
// #6469 render-belt tests: one gateway + one VPN + a resolvable ike/ipsec
// policy chain so renderConfig emits a full connection block. The caller
// picks which endpoint field carries the value under test.
func buildAddrCfg(gwAddr, gwDyn, gwLocal, vpnLocal string) *config.IPsecConfig {
	// Mirror the proven-minimal endpoint_render_5630 fixture: gateway + VPN
	// + a resolvable ipsec policy/proposal is enough for renderConfig to emit
	// a full connection block with local_addrs / remote_addrs. No IKE policy
	// chain is required (an absent ike-policy does not skip the VPN).
	return &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: gwAddr, DynamicHostname: gwDyn, LocalAddress: gwLocal},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw", IPsecPolicy: "ipsec-pol", LocalAddr: vpnLocal},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes256", AuthAlg: "sha256"},
		},
	}
}

// TestSwanctlAddrInjectionNeutralized_6469 is the fail-on-revert guard for
// #6469: the swanctl local_addrs / remote_addrs render sites must run the
// endpoint value through sanitizeSwanctlValue so an embedded newline cannot
// inject a live swanctl directive on a validation-bypassed path (HA peer-sync
// of a pre-fix config, or a directly-constructed IPsecConfig — both bypass
// the commit-time endpoint gate). Reverting the sanitize wrap back to a raw
// `%s` makes each case fail with a clean assertion: the injected directive
// reappears as its own indented line.
func TestSwanctlAddrInjectionNeutralized_6469(t *testing.T) {
	// Payload: a legitimate-looking address, an embedded newline, then an
	// indented swanctl directive the attacker wants promoted into the
	// connection block. reauth_time is emitted by NO code path in this
	// fixture, so its appearance as a bare line is proof of injection.
	const inject = "203.0.113.1\n    reauth_time = 0"
	const injectedDirectiveKey = "reauth_time"

	cases := []struct {
		name string
		cfg  *config.IPsecConfig
		// addrKey / addrPrefix: the sanitized address must still lead the
		// value of this setting, proving the connection rendered (the VPN was
		// not skipped) and the belt ran in place rather than dropping the
		// field. #6824: a key + a path, not a rendered line.
		addrKey    string
		addrPrefix string
	}{
		{
			name:       "remote via gateway Address",
			cfg:        buildAddrCfg(inject, "", "", ""),
			addrKey:    "remote_addrs",
			addrPrefix: "203.0.113.1",
		},
		{
			name:       "remote via gateway DynamicHostname",
			cfg:        buildAddrCfg("", inject, "198.51.100.7", ""),
			addrKey:    "remote_addrs",
			addrPrefix: "203.0.113.1",
		},
		{
			name:       "local via gateway LocalAddress",
			cfg:        buildAddrCfg("198.51.100.7", "", inject, ""),
			addrKey:    "local_addrs",
			addrPrefix: "203.0.113.1",
		},
		{
			name:       "local via vpn LocalAddr",
			cfg:        buildAddrCfg("198.51.100.7", "", "", inject),
			addrKey:    "local_addrs",
			addrPrefix: "203.0.113.1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
			doc := parseSwanctlDoc(t, m.generateConfig(c.cfg))

			// #6824: the injection is neutralized iff the directive never
			// becomes a SETTING anywhere in the parsed document. That is what
			// strongSwan would act on, and it fires whatever value the payload
			// carried -- where the old line scan matched only the exact
			// injected text.
			doc.hasNoSettingAnywhere(t, injectedDirectiveKey)

			// The sanitized value must still lead the address setting: the belt
			// collapses the newline to a space, so the address renders inert
			// on one line rather than the field being dropped or the VPN
			// skipped.
			conn := doc.at(t, "connections", "tun")
			if v := conn.setting(t, c.addrKey); !strings.HasPrefix(v, c.addrPrefix) {
				t.Fatalf("connections.tun.%s = %q, want it to still start with %q",
					c.addrKey, v, c.addrPrefix)
			}
		})
	}
}

// TestSwanctlAddrLegitPreserved_6469 is the over-escape guard: a legitimate
// endpoint — a single IPv4, a comma-separated multi-address list, an IPv6
// literal, and the responder-only "%any" sentinel — must render BYTE-
// IDENTICAL through the sanitize belt. sanitizeSwanctlValue only touches
// C0/DEL control bytes, so `.`, `,`, `:` and `%` all survive; this test pins
// that the #6469 fix does not mangle a real address list or IPv6 endpoint.
func TestSwanctlAddrLegitPreserved_6469(t *testing.T) {
	cases := []struct {
		name   string
		gwAddr string
		want   string
	}{
		{
			name:   "single IPv4",
			gwAddr: "203.0.113.1",
			want:   "203.0.113.1",
		},
		{
			name:   "comma-separated multi-address list",
			gwAddr: "203.0.113.1,203.0.113.2",
			want:   "203.0.113.1,203.0.113.2",
		},
		{
			name:   "IPv6 literal",
			gwAddr: "2001:db8::1",
			want:   "2001:db8::1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
			parseSwanctlDoc(t, m.generateConfig(buildAddrCfg(c.gwAddr, "", "", ""))).
				at(t, "connections", "tun").
				requireSetting(t, "remote_addrs", c.want)
		})
	}

	// Responder-only (%any) must survive the belt untouched — '%' is not a
	// control byte, and this is the sentinel for a dynamic-IP peer.
	t.Run("responder-only %any", func(t *testing.T) {
		cfg := buildAddrCfg("", "", "", "")
		cfg.Gateways["gw"].ResponderOnly = true
		m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
		parseSwanctlDoc(t, m.generateConfig(cfg)).
			at(t, "connections", "tun").
			requireSetting(t, "remote_addrs", "%any")
	})
}

// TestSwanctlProposalsInjectionNeutralized_6469 is the fail-closed companion
// to the endpoint sanitizer: proposal algorithm values are now rejected by
// the same SectionSafe allowlist at render, so a persisted control-byte
// payload cannot reach either unquoted proposal slot. The VPN is skipped and
// the stale SA teardown path uses the rendered set.
func TestSwanctlProposalsInjectionNeutralized_6469(t *testing.T) {
	ikeCfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "ike-pol"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-prop"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-prop": {Name: "ike-prop", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes256\n    reauth_time = 0"},
		},
	}
	espCfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw", IPsecPolicy: "ipsec-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes256\n        updown = /tmp/pwn.sh"},
		},
	}
	for _, tc := range []struct {
		name string
		cfg  *config.IPsecConfig
	}{
		{name: "IKE proposals newline injection", cfg: ikeCfg},
		{name: "ESP esp_proposals updown->root injection", cfg: espCfg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, rendered, err := (&Manager{}).renderConfig(tc.cfg)
			if err != nil {
				t.Fatalf("render returned error instead of tolerant skip: %v", err)
			}
			if rendered["tun"] {
				t.Fatal("unsafe proposal VPN must be omitted from rendered connection set")
			}
			for _, directive := range []string{"reauth_time", "updown"} {
				if strings.Contains(text, directive+" =") {
					t.Fatalf("injected directive became live in rendered config: %q\n%s", directive, text)
				}
			}
			if strings.Contains(text, "proposals =") || strings.Contains(text, "esp_proposals =") {
				t.Fatalf("unsafe proposal slot must not be emitted:\n%s", text)
			}
		})
	}
}

// TestSwanctlProposalsLegitPreserved_6469 is the over-escape guard for the
// proposal fold: a legitimate multi-proposal list — dashed swanctl tokens
// (aes256-sha256-modp2048) comma-joined for a `proposals [ p1 p2 ]` offer —
// must render BYTE-IDENTICAL through the sanitize belt on BOTH the IKE
// `proposals` and the ESP `esp_proposals` line. sanitizeSwanctlValue only
// touches control bytes, so `-` and `,` survive.
func TestSwanctlProposalsLegitPreserved_6469(t *testing.T) {
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "ike-pol"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw", IPsecPolicy: "ipsec-pol"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-a", "ike-b"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-a": {Name: "ike-a", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"ike-b": {Name: "ike-b", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-128-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-a", "esp-b"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"esp-b": {Name: "esp-b", EncryptionAlg: "aes-128-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
	}
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	got := m.generateConfig(cfg)

	// #6824: the two needles carried leading indentation ("    " vs "        ")
	// purely to distinguish Phase 1 from Phase 2, and a trailing "\n" to mean
	// "the value ends here". Both are properties of the tree, so state them as
	// such -- the assertions now survive a change to the renderer's indent and
	// still reject a value with anything appended.
	const wantList = "aes256-sha256-modp2048,aes128-sha256-modp2048"
	parseSwanctlDoc(t, got).at(t, "connections", "tun").requireSetting(t, "proposals", wantList)
	childSA_3904(t, got, "tun").requireSetting(t, "esp_proposals", wantList)
}
