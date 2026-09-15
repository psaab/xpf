package ipsec

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildESPProposal_JunosGCMSuffix is the #2125 ESP-render
// regression: a Junos-native GCM encryption-algorithm name renders to
// the canonical 16-octet-ICV swanctl token (aes256gcm16). Pre-fix the
// normalizer only stripped "-cbc"/"-" and produced the bare alias
// "aes256gcm", so these assertions FAIL on the old code
// (non-tautological). Note: the bare alias is ALSO valid strongSwan
// (it maps to ENCR_AES_GCM_ICV16), so this test pins the explicit-ICV
// spelling for clarity/consistency — it is not guarding against a parse
// failure. (The parse-affecting #2125 fix is the IKE PRF, covered by
// TestBuildIKEProposal_JunosGCMSuffixAndPRF below.)
func TestBuildESPProposal_JunosGCMSuffix(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-256-gcm dh14",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm", DHGroup: 14},
			"aes256gcm16-modp2048",
		},
		{
			"aes-192-gcm dh14",
			&config.IPsecProposal{EncryptionAlg: "aes-192-gcm", DHGroup: 14},
			"aes192gcm16-modp2048",
		},
		{
			"aes-128-gcm dh14",
			&config.IPsecProposal{EncryptionAlg: "aes-128-gcm", DHGroup: 14},
			"aes128gcm16-modp2048",
		},
		{
			"aes-256-gcm no dh",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm"},
			"aes256gcm16",
		},
		{
			// GCM must never emit a separate integrity algorithm even
			// when AuthAlg is set — AEAD carries its own ICV.
			"aes-256-gcm ignores auth",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm", AuthAlg: "hmac-sha-256", DHGroup: 14},
			"aes256gcm16-modp2048",
		},
		{
			// Already-suffixed legacy form is preserved unchanged.
			"legacy aes256gcm128 unchanged",
			&config.IPsecProposal{EncryptionAlg: "aes256gcm128", DHGroup: 14},
			"aes256gcm128-modp2048",
		},
		{
			// Non-GCM CBC path: the Junos truncation suffix (-128) maps to
			// the strongSwan base integrity keyword sha256, NOT the invalid
			// dash-stripped "sha256128" (#3851).
			"non-gcm cbc integ",
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256-modp2048",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildESPProposal(tt.prop, 0); got != tt.want {
				t.Errorf("buildESPProposal(%q) = %q, want %q", tt.prop.EncryptionAlg, got, tt.want)
			}
		})
	}
}

// TestBuildIKEProposal_JunosGCMSuffixAndPRF is the #2125 regression for
// IKE (Phase 1): a Junos GCM name must render to aes<N>gcm16 AND carry
// an explicit PRF (IKEv2 AEAD has no integrity alg to derive a PRF
// from). Pre-fix the IKE builders emitted bare "aes256gcm" with no PRF.
func TestBuildIKEProposal_JunosGCMSuffixAndPRF(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-256-gcm default prf",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm", DHGroup: 14},
			"aes256gcm16-prfsha256-modp2048",
		},
		{
			"aes-256-gcm prf from sha384 auth",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm", AuthAlg: "hmac-sha-384", DHGroup: 14},
			"aes256gcm16-prfsha384-modp2048",
		},
		{
			"aes-128-gcm prf from sha512 auth",
			&config.IPsecProposal{EncryptionAlg: "aes-128-gcm", AuthAlg: "hmac-sha-512", DHGroup: 14},
			"aes128gcm16-prfsha512-modp2048",
		},
		{
			"non-gcm cbc unchanged",
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256-modp2048",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildIKEProposal(tt.prop); got != tt.want {
				t.Errorf("buildIKEProposal(%q) = %q, want %q", tt.prop.EncryptionAlg, got, tt.want)
			}
		})
	}
}

// TestBuildIKEProposalFromIKE_JunosGCMSuffixAndPRF mirrors the IKE GCM
// regression for the IKE-proposal-object path (buildIKEProposalFromIKE).
func TestBuildIKEProposalFromIKE_JunosGCMSuffixAndPRF(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IKEProposal
		want string
	}{
		{
			"aes-256-gcm default prf",
			&config.IKEProposal{EncryptionAlg: "aes-256-gcm", DHGroup: 14},
			"aes256gcm16-prfsha256-modp2048",
		},
		{
			"aes-256-gcm prf from sha-512 auth",
			&config.IKEProposal{EncryptionAlg: "aes-256-gcm", AuthAlg: "sha-512", DHGroup: 14},
			"aes256gcm16-prfsha512-modp2048",
		},
		{
			"non-gcm cbc unchanged",
			&config.IKEProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"aes256-sha256-modp2048",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildIKEProposalFromIKE(tt.prop); got != tt.want {
				t.Errorf("buildIKEProposalFromIKE(%q) = %q, want %q", tt.prop.EncryptionAlg, got, tt.want)
			}
		})
	}
}

// TestFormatDHGroup_ECPandMODP is the #2392 regression: elliptic-curve DH
// groups must render their strongSwan ECP/curve keyword (group 19 ->
// ecp256, 20 -> ecp384, 21 -> ecp521, 31 -> curve25519), NOT modp<bits>.
// Pre-#2392 every builder formatted the suffix as fmt.Sprintf("modp%d",
// dhGroupBits(group)), so group 19/20 emitted the strongSwan-invalid
// tokens modp256/modp384 and the whole proposal was rejected at swanctl
// load. MODP groups (e.g. 14 -> modp2048) must keep rendering modp<bits>.
//
// Fail-on-revert: reverting formatDHGroup to fmt.Sprintf("modp%d",
// dhGroupBits(group)) makes group 19 render "modp256" instead of
// "ecp256", which fails the ecp* assertions below. The trailing
// counter-factual block reconstructs the pre-fix formula and proves it
// produces the invalid token, so the test is not tautological.
func TestFormatDHGroup_ECPandMODP(t *testing.T) {
	tests := []struct {
		group int
		want  string
	}{
		// MODP groups — unchanged pre-#2392 behaviour.
		{1, "modp768"},
		{2, "modp1024"},
		{5, "modp1536"},
		{14, "modp2048"},
		{15, "modp3072"},
		{16, "modp4096"},
		// Elliptic-curve (ECP) groups — the #2392 fix.
		{19, "ecp256"},
		{20, "ecp384"},
		{21, "ecp521"},
		{25, "ecp192"},
		{26, "ecp224"},
		// Brainpool ECP groups.
		{27, "ecp224bp"},
		{28, "ecp256bp"},
		{29, "ecp384bp"},
		{30, "ecp512bp"},
		// Montgomery curves.
		{31, "curve25519"},
		{32, "curve448"},
		// MODP-with-prime-order-subgroup (RFC 5114) — the #2604 fix.
		// Before #2604 these fell through to modp<dhGroupBits>; dhGroupBits
		// has no 22/23/24 case so they emitted the strongSwan-invalid
		// tokens modp22/modp23/modp24.
		{22, "modp1024s160"},
		{23, "modp2048s224"},
		{24, "modp2048s256"},
	}
	for _, tt := range tests {
		if got := formatDHGroup(tt.group); got != tt.want {
			t.Errorf("formatDHGroup(%d) = %q, want %q", tt.group, got, tt.want)
		}
	}

	// Counter-factual: the pre-fix formula renders the strongSwan-invalid
	// modp<bits> token. For the EC groups 19/20 this proves the #2392 fix
	// is load-bearing; for the RFC 5114 groups 22/23/24 it proves the #2604
	// fix is load-bearing (the old code WOULD fail the assertions above) —
	// neither is a tautology.
	for _, g := range []int{19, 20, 22, 23, 24} {
		old := fmt.Sprintf("modp%d", dhGroupBits(g))
		if got := formatDHGroup(g); got == old {
			t.Errorf("formatDHGroup(%d) = %q still matches the pre-fix invalid token %q",
				g, got, old)
		}
	}
}

// TestProposalBuilders_ECPGroupAcrossAllSites asserts that ALL FOUR
// proposal render sites route the DH-group suffix through formatDHGroup,
// so EC groups 19/20/21/31 emit ecp256/ecp384/ecp521/curve25519 and the
// RFC 5114 groups 22/23/24 emit modp1024s160/modp2048s224/modp2048s256
// (#2604) — not modp<bits> — and MODP group 14 still emits modp2048 (no
// regression):
//
//  1. buildIKEProposalFromIKE  (IKE proposal object path)
//  2. buildIKEProposal         (legacy IPsec-proposal-as-IKE path)
//  3. buildESPProposal         (ESP / Phase-2 path)
//  4. resolveESPSettings PFS override (resolved chain, #9919: the dangling
//     fallback this site pinned is now a skip; the ECP spelling coverage
//     moves to the resolved chain where PFS still applies)
func TestProposalBuilders_ECPGroupAcrossAllSites(t *testing.T) {
	type groupCase struct {
		group  int
		suffix string
	}
	groupCases := []groupCase{
		{14, "modp2048"}, // MODP no-regression
		{19, "ecp256"},
		{20, "ecp384"},
		{21, "ecp521"},
		{31, "curve25519"},
		// RFC 5114 MODP-with-prime-order-subgroup groups — the #2604 fix.
		{22, "modp1024s160"},
		{23, "modp2048s224"},
		{24, "modp2048s256"},
	}

	for _, gc := range groupCases {
		// Site 1: buildIKEProposalFromIKE.
		if got, want := buildIKEProposalFromIKE(
			&config.IKEProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: gc.group}),
			"aes256-sha256-"+gc.suffix; got != want {
			t.Errorf("buildIKEProposalFromIKE(group %d) = %q, want %q", gc.group, got, want)
		}

		// Site 2: buildIKEProposal.
		if got, want := buildIKEProposal(
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: gc.group}),
			"aes256-sha256-"+gc.suffix; got != want {
			t.Errorf("buildIKEProposal(group %d) = %q, want %q", gc.group, got, want)
		}

		// Site 3: buildESPProposal (DH group via the proposal field).
		if got, want := buildESPProposal(
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: gc.group}, 0),
			"aes256-sha256-"+gc.suffix; got != want {
			t.Errorf("buildESPProposal(DHGroup %d) = %q, want %q", gc.group, got, want)
		}

		// Site 3b: buildESPProposal with the PFS group override.
		if got, want := buildESPProposal(
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256"}, gc.group),
			"aes256-sha256-"+gc.suffix; got != want {
			t.Errorf("buildESPProposal(pfs %d) = %q, want %q", gc.group, got, want)
		}

		// Site 4: resolveESPSettings with a RESOLVED chain and a PFS group.
		// The policy resolves and its proposal resolves, so the PFS group
		// overrides onto the rendered proposal with its canonical spelling.
		cfg := &config.IPsecConfig{
			Policies: map[string]*config.IPsecPolicyDef{
				"pol1": {Name: "pol1", PFSGroup: gc.group, Proposals: []string{"esp1"}},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp1": {Name: "esp1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256"},
			},
		}
		vpn := &config.IPsecVPN{IPsecPolicy: "pol1"}
		if got, _, err := resolveESPSettings(cfg, vpn); err != nil || got != "aes256-sha256-"+gc.suffix {
			t.Errorf("resolveESPSettings PFS override (group %d) = (%q, %v), want %q",
				gc.group, got, err, "aes256-sha256-"+gc.suffix)
		}
	}
}

// TestGenerateConfig_JunosGCM is an end-to-end render check that a
// Junos-native aes-256-gcm proposal produces a valid, ICV-suffixed
// esp_proposals line through generateConfig (#2125).
func TestGenerateConfig_JunosGCM(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "gcm"},
		},
		Proposals: map[string]*config.IPsecProposal{
			"gcm": {Name: "gcm", EncryptionAlg: "aes-256-gcm", DHGroup: 14},
		},
	}
	// #6824: equality at the child SA pins the canonical spelling. The bare
	// alias was a DOCUMENT-WIDE absence and stays one -- equality here cannot
	// speak for a `aes256gcm-modp2048` emitted under some other section.
	got := m.generateConfig(cfg)
	childSA_3904(t, got, "tun1").requireSetting(t, "esp_proposals", "aes256gcm16-modp2048")
	parseSwanctlDoc(t, got).hasNoValueSubstringAnywhere(t, "aes256gcm-modp2048")
}

// TestEscapeSwanctlQuoted unit-tests the swanctl double-quoted-string
// escaper directly (#2126). Order matters: backslash doubled first,
// then quote escaped.
func TestEscapeSwanctlQuoted(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no special chars", "supersecret", "supersecret"},
		{"embedded quote", `pa"ss`, `pa\"ss`},
		{"embedded backslash", `pa\ss`, `pa\\ss`},
		{"backslash then n stays literal", `a\nb`, `a\\nb`},
		{"both quote and backslash", `a"\b`, `a\"\\b`},
		{"trailing quote", `secret"`, `secret\"`},
		{"leading quote", `"secret`, `\"secret`},
		{"quote then backslash order", `"\`, `\"\\`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeSwanctlQuoted(tt.in); got != tt.want {
				t.Errorf("escapeSwanctlQuoted(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestGenerateConfig_PSKWithQuote is the #2126 end-to-end regression: a
// PSK containing a double-quote must render as a balanced, escaped
// quoted secret (secret = "pa\"ss"), not the corrupted secret = "pa"ss"
// the pre-fix code produced.
func TestGenerateConfig_PSKWithQuote(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           `pa"ss`,
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	// #6824: an exact match on the secret setting subsumes the separate
	// "corrupted form absent" needle -- the unescaped spelling cannot equal
	// the escaped one.
	secretSetting_6824(t, got, "ike-site-a", `"pa\"ss"`)
	assertBalancedSecretQuotes(t, got)
}

// TestGenerateConfig_PSKWithBackslash covers a PSK containing a literal
// backslash (#2126) — it must be doubled so the swanctl lexer reads one
// literal backslash back.
func TestGenerateConfig_PSKWithBackslash(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           `pa\ss`,
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	secretSetting_6824(t, m.generateConfig(cfg), "ike-site-a", `"pa\\ss"`)
}

// TestGenerateConfig_PSKTrailingBackslash is the adversarial corner a PSK
// ending in a single backslash: it must render as a doubled backslash
// (secret = "pass\\") so the trailing backslash does NOT escape the
// closing quote. assertBalancedSecretQuotes is the lexer-accurate gate.
func TestGenerateConfig_PSKTrailingBackslash(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           `pass\`,
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	secretSetting_6824(t, got, "ike-site-a", `"pass\\"`)
	assertBalancedSecretQuotes(t, got)
}

// TestGenerateConfig_IdentityWithCommaQuoted is the #2126 regression for
// the identity lines: a distinguished-name identity with spaces/commas
// must render quoted so swanctl parses it as a single value rather than
// truncating at the first space/comma.
func TestGenerateConfig_IdentityWithCommaQuoted(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "k"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:          "gw",
				Address:       "203.0.113.1",
				LocalAddress:  "198.51.100.1",
				LocalIDType:   "inet",
				LocalIDValue:  "CN=fw, O=acme",
				RemoteIDType:  "inet",
				RemoteIDValue: `peer"name`,
			},
		},
	}
	// #6824: `id` is emitted in BOTH the local{} and remote{} auth rounds, so
	// containment could not say which round carried which identity -- the two
	// old needles would both have passed with the values swapped.
	conn := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "tun")
	conn.at(t, "local").requireSetting(t, "id", `"CN=fw, O=acme"`)
	conn.at(t, "remote").requireSetting(t, "id", `"peer\"name"`)
}

// secretBlock is a parsed `secrets { ike-<name> { ... } }` entry.
type secretBlock struct {
	secret string
	ids    []string
}

// parseSecretBlocks extracts every ike-<name> secret block from a rendered
// swanctl config, keyed by block name (e.g. "ike-vpn-a"), with its secret
// value and the ordered id-<n> selector values (surrounding quotes
// stripped). It is deliberately small: the rendered secrets are simple
// enough that a leading/trailing double-quote trim recovers the value.
func parseSecretBlocks(t *testing.T, cfg string) map[string]secretBlock {
	t.Helper()
	// #6824: built on the shared document parser rather than a second bespoke
	// line scanner. The old version tracked `inSecrets` and flushed on a bare
	// "}", so a nesting change anywhere above could silently reassign blocks;
	// resolving secrets{} as a path cannot.
	out := map[string]secretBlock{}
	unquote := func(v string) string { return strings.Trim(v, `"`) }
	doc := parseSwanctlDoc(t, cfg)
	sec, ok := doc.children["secrets"]
	if !ok {
		return out
	}
	for _, name := range sec.order {
		node := sec.children[name]
		blk := secretBlock{}
		if vals, ok := node.settings["secret"]; ok && len(vals) == 1 {
			blk.secret = unquote(vals[0])
		}
		for _, k := range node.settingNames() {
			if strings.HasPrefix(k, "id-") {
				for _, v := range node.settings[k] {
					blk.ids = append(blk.ids, unquote(v))
				}
			}
		}
		out[name] = blk
	}
	return out
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestGenerateConfig_PSKIDSelectors_TwoVPNs is the #3952 regression: two
// PSK VPNs to DIFFERENT peers must each render a secret scoped to ITS peer
// with an id selector, so strongSwan never binds the wrong PSK. A PSK
// secret with no id matches ANY peer; with two PSKs strongSwan could pick
// the wrong secret for a peer and IKE auth fails. Goes RED on revert
// (no id selectors emitted → the id-contains assertions fail).
func TestGenerateConfig_PSKIDSelectors_TwoVPNs(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"vpn-a": {Gateway: "gw-a", PSK: "psk-alpha"},
			"vpn-b": {Gateway: "gw-b", PSK: "psk-bravo"},
		},
		Gateways: map[string]*config.IPsecGateway{
			// Same local firewall, two distinct remote peers.
			"gw-a": {Name: "gw-a", Address: "203.0.113.1", LocalAddress: "198.51.100.10"},
			"gw-b": {Name: "gw-b", Address: "203.0.113.2", LocalAddress: "198.51.100.10"},
		},
	}
	blocks := parseSecretBlocks(t, m.generateConfig(cfg))

	a, ok := blocks["ike-vpn-a"]
	if !ok {
		t.Fatalf("missing ike-vpn-a secret block")
	}
	b, ok := blocks["ike-vpn-b"]
	if !ok {
		t.Fatalf("missing ike-vpn-b secret block")
	}
	if a.secret != "psk-alpha" || b.secret != "psk-bravo" {
		t.Fatalf("wrong PSKs: a=%q b=%q", a.secret, b.secret)
	}
	// Each secret carries an id selector for ITS own peer address.
	if len(a.ids) == 0 {
		t.Errorf("ike-vpn-a has no id selector (PSK matches any peer — #3952)")
	}
	if len(b.ids) == 0 {
		t.Errorf("ike-vpn-b has no id selector (PSK matches any peer — #3952)")
	}
	if !containsStr(a.ids, "203.0.113.1") {
		t.Errorf("ike-vpn-a id selectors %v missing its peer 203.0.113.1", a.ids)
	}
	if !containsStr(b.ids, "203.0.113.2") {
		t.Errorf("ike-vpn-b id selectors %v missing its peer 203.0.113.2", b.ids)
	}
	// Scoping: neither secret claims the OTHER peer's identity.
	if containsStr(a.ids, "203.0.113.2") {
		t.Errorf("ike-vpn-a id selectors %v wrongly claim vpn-b's peer", a.ids)
	}
	if containsStr(b.ids, "203.0.113.1") {
		t.Errorf("ike-vpn-b id selectors %v wrongly claim vpn-a's peer", b.ids)
	}
}

// TestGenerateConfig_PSKIDSelectors_ExplicitIDs asserts that when a gateway
// configures explicit remote/local IKE identities, the PSK secret is
// scoped by those identities (the values the peer actually negotiates),
// not the gateway address. The remote-id is the discriminator; the
// local-id rides along as a harmless extra owner (#3952).
func TestGenerateConfig_PSKIDSelectors_ExplicitIDs(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"vpn": {Gateway: "gw", PSK: "k"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:          "gw",
				Address:       "203.0.113.9",
				LocalAddress:  "198.51.100.10",
				RemoteIDType:  "hostname",
				RemoteIDValue: "peer.example.com",
				LocalIDType:   "hostname",
				LocalIDValue:  "fw.example.com",
			},
		},
	}
	blocks := parseSecretBlocks(t, m.generateConfig(cfg))
	blk, ok := blocks["ike-vpn"]
	if !ok {
		t.Fatalf("missing ike-vpn secret block")
	}
	// Remote-id (formatted @fqdn) must be present as the peer selector.
	if !containsStr(blk.ids, "@peer.example.com") {
		t.Errorf("id selectors %v missing configured remote-id @peer.example.com", blk.ids)
	}
	// Local-id rides along.
	if !containsStr(blk.ids, "@fw.example.com") {
		t.Errorf("id selectors %v missing configured local-id @fw.example.com", blk.ids)
	}
	// The remote-id supersedes the address as the peer identity.
	if containsStr(blk.ids, "203.0.113.9") {
		t.Errorf("id selectors %v used the address instead of the configured remote-id", blk.ids)
	}
}

// TestGenerateConfig_PSKIDSelectors_SingleVPN confirms a single PSK VPN
// still renders a valid secret (now carrying an id — harmless with one
// PSK) so the fix does not regress the common single-tunnel case (#3952).
func TestGenerateConfig_PSKIDSelectors_SingleVPN(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"solo": {Gateway: "10.0.2.1", PSK: "onlysecret", BindInterface: "st0.0"},
		},
	}
	blocks := parseSecretBlocks(t, m.generateConfig(cfg))
	blk, ok := blocks["ike-solo"]
	if !ok {
		t.Fatalf("missing ike-solo secret block")
	}
	if blk.secret != "onlysecret" {
		t.Errorf("wrong PSK: %q", blk.secret)
	}
	// Legacy inline gateway shape: the peer address is the id selector.
	if !containsStr(blk.ids, "10.0.2.1") {
		t.Errorf("single-VPN id selectors %v missing the inline peer 10.0.2.1", blk.ids)
	}
}

// TestGenerateConfig_PSKIDSelectors_ResponderAnyAndCert covers the two
// no-scoping cases (#3952): a responder-only %any peer with no configured
// remote-id emits NO id (%any is not a usable identity — legacy any-peer
// behavior preserved, never a literal `id = "%any"`), and a cert VPN with
// no PSK emits no secret block at all (so no stray id leaks).
func TestGenerateConfig_PSKIDSelectors_ResponderAnyAndCert(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"roadwarrior": {Gateway: "gw-dyn", PSK: "dynsecret"},
			"cert-vpn":    {Gateway: "gw-cert"},
		},
		Gateways: map[string]*config.IPsecGateway{
			// Dynamic responder-only peer, no remote-id → nothing to scope by.
			"gw-dyn": {Name: "gw-dyn", ResponderOnly: true, LocalAddress: "198.51.100.10"},
			// Cert gateway, no PSK anywhere.
			"gw-cert": {Name: "gw-cert", Address: "203.0.113.20", LocalCertificate: "fw-cert"},
		},
	}
	got := m.generateConfig(cfg)
	blocks := parseSecretBlocks(t, got)

	rw, ok := blocks["ike-roadwarrior"]
	if !ok {
		t.Fatalf("missing ike-roadwarrior secret block")
	}
	if len(rw.ids) != 0 {
		t.Errorf("responder-only %%any peer should emit no id selector, got %v", rw.ids)
	}
	// Belt: a literal id = "%any" would defeat the scoping and match all.
	//
	// #6824: this was previously guarded by
	// `Contains(got, "%any") && Contains(got, "id-")` -- a condition about the
	// document as a whole gating a check about THIS block's selectors. A
	// render that dropped the %any sentinel elsewhere would skip the belt
	// entirely. The inner check is the claim; assert it unconditionally.
	if containsStr(rw.ids, "%any") {
		t.Errorf("emitted a literal %%any id selector")
	}
	if _, ok := blocks["ike-cert-vpn"]; ok {
		t.Errorf("cert VPN with no PSK must not emit a secret block")
	}
}

// assertBalancedSecretQuotes verifies every "secret = " line has exactly
// the opening + closing quote with no unescaped interior double-quote —
// i.e. the rendered secret block is parseable by the swanctl lexer.
func assertBalancedSecretQuotes(t *testing.T, cfg string) {
	t.Helper()
	for _, line := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "secret = ") {
			continue
		}
		val := strings.TrimPrefix(trimmed, "secret = ")
		if len(val) < 2 || val[0] != '"' {
			t.Errorf("secret value not opened with a quote: %q", val)
			continue
		}
		// Walk from after the opening quote exactly as the swanctl lexer
		// would: a backslash escapes the next char (so it can never
		// terminate the string), and the FIRST unescaped double-quote is
		// the real terminator. The line is balanced only if that
		// terminator is the last character — catching both an unescaped
		// interior quote (terminates early) and an odd trailing backslash
		// run that escapes the would-be closing quote (e.g. `"foo\"`).
		term := -1
		for i := 1; i < len(val); i++ {
			if val[i] == '\\' {
				i++ // skip the escaped char
				continue
			}
			if val[i] == '"' {
				term = i
				break
			}
		}
		switch {
		case term == -1:
			t.Errorf("secret value never closes (escaped/unterminated quote): %q", val)
		case term != len(val)-1:
			t.Errorf("secret value terminates before end of line (unescaped interior quote): %q", val)
		}
	}
}

// strongSwanIntegKeywords is the set of integrity-algorithm proposal
// keywords that strongSwan/charon actually accepts (the short spellings
// from src/libstrongswan/crypto/proposal/proposal_keywords_static.txt).
// A token outside this set makes charon reject the WHOLE proposal, so the
// tunnel silently never loads — the #3851 failure mode.
var strongSwanIntegKeywords = map[string]bool{
	"md5":    true,
	"sha1":   true,
	"sha224": true,
	"sha256": true,
	"sha384": true,
	"sha512": true,
}

// TestNormalizeAuthAlg_JunosToStrongSwan is the #3851 regression: every
// canonical Junos authentication-algorithm spelling — including the
// explicit HMAC truncation-length suffix Junos uses for ESP
// (hmac-sha-256-128, hmac-sha1-96, ...) — must map to a strongSwan-VALID
// base integrity keyword. The pre-fix normalizer dash-stripped the name
// and produced "sha256128"/"sha196"/"md596", which are NOT strongSwan
// keywords, so charon rejected the ESP proposal and the tunnel never
// loaded. This table pins the VALID output; it goes RED on revert (the
// old code returns the invalid dash-stripped token, which is not in
// strongSwanIntegKeywords).
func TestNormalizeAuthAlg_JunosToStrongSwan(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		// Junos ESP spellings with explicit truncation length.
		{"hmac-sha-256-128", "sha256"},
		{"hmac-sha256-128", "sha256"},
		{"hmac-sha-384-192", "sha384"},
		{"hmac-sha-512-256", "sha512"},
		{"hmac-sha1-96", "sha1"},
		{"hmac-sha-1-96", "sha1"},
		{"hmac-md5-96", "md5"},
		// Junos ESP spellings without a truncation suffix.
		{"hmac-sha-256", "sha256"},
		{"hmac-sha-384", "sha384"},
		{"hmac-sha-512", "sha512"},
		{"hmac-sha1", "sha1"},
		{"hmac-md5", "md5"},
		// Junos IKE (Phase 1) short spellings.
		{"sha-256", "sha256"},
		{"sha-384", "sha384"},
		{"sha-512", "sha512"},
		{"sha1", "sha1"},
		{"sha-1", "sha1"},
		{"md5", "md5"},
		// Already-normalized swanctl tokens are idempotent.
		{"sha256", "sha256"},
		{"sha384", "sha384"},
		{"sha512", "sha512"},
		// Case-insensitive.
		{"HMAC-SHA-256-128", "sha256"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := normalizeAuthAlg(tt.in)
			if got != tt.want {
				t.Fatalf("normalizeAuthAlg(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if !strongSwanIntegKeywords[got] {
				t.Fatalf("normalizeAuthAlg(%q) = %q, which is NOT a strongSwan integrity keyword (charon would reject the whole proposal)", tt.in, got)
			}
		})
	}
}

// TestBuildProposals_IntegTokenStrongSwanValid asserts that the assembled
// ESP and IKE proposal STRINGS carry a strongSwan-valid integrity token
// for the canonical Junos ESP auth-algorithm name that shipped broken.
// The whole proposal string must parse: aes256-sha256-modp2048, not
// aes256-sha256128-modp2048 (which charon rejects wholesale).
func TestBuildProposals_IntegTokenStrongSwanValid(t *testing.T) {
	espProp := &config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14}
	if got, want := buildESPProposal(espProp, 0), "aes256-sha256-modp2048"; got != want {
		t.Fatalf("buildESPProposal() = %q, want %q", got, want)
	}
	assertProposalIntegValid(t, buildESPProposal(espProp, 0))

	ikeProp := &config.IKEProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14}
	if got, want := buildIKEProposalFromIKE(ikeProp), "aes256-sha256-modp2048"; got != want {
		t.Fatalf("buildIKEProposalFromIKE() = %q, want %q", got, want)
	}
	assertProposalIntegValid(t, buildIKEProposalFromIKE(ikeProp))
}

// assertProposalIntegValid checks that a rendered non-AEAD proposal of the
// form <enc>-<integ>-<dh> carries an integrity token strongSwan accepts.
func assertProposalIntegValid(t *testing.T, proposal string) {
	t.Helper()
	parts := strings.Split(proposal, "-")
	if len(parts) != 3 {
		t.Fatalf("proposal %q not in <enc>-<integ>-<dh> form", proposal)
	}
	if integ := parts[1]; !strongSwanIntegKeywords[integ] {
		t.Fatalf("proposal %q carries integrity token %q that strongSwan does not accept — charon would reject the whole proposal", proposal, integ)
	}
}

// secretSetting_6824 asserts secrets.<block>.secret renders exactly want,
// INCLUDING its surrounding quotes.
//
// Containment on `secret = "..."` could not distinguish the secrets block from
// any other place the renderer might emit the same bytes, and could not reject a
// value with something appended.
func secretSetting_6824(t *testing.T, doc, block, want string) {
	t.Helper()
	parseSwanctlDoc(t, doc).at(t, "secrets", block).requireSetting(t, "secret", want)
}
