package ipsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestGenerateConfig_Basic(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           "supersecret",
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	// #6824: read the settings at their paths. The old block asserted nine
	// substrings against the whole document, which said nothing about where
	// any of them landed -- and `auth = psk` in particular is emitted in BOTH
	// the local{} and remote{} rounds, so a render that emitted it in neither
	// the right one nor both was indistinguishable from a correct one.
	doc := parseSwanctlDoc(t, m.generateConfig(cfg))
	conn := doc.at(t, "connections", "site-a")
	conn.requireSetting(t, "local_addrs", "10.0.1.1")
	conn.requireSetting(t, "remote_addrs", "10.0.2.1")
	conn.at(t, "local").requireSetting(t, "auth", "psk")
	conn.at(t, "remote").requireSetting(t, "auth", "psk")
	// The xfrmi interface ids belong to the CHILD SA, not the connection --
	// a placement the old whole-document needles could not express, and would
	// have accepted either way.
	kids := conn.at(t, "children")
	if len(kids.order) != 1 {
		t.Fatalf("expected exactly one child SA, got %v\n%s", kids.childNames(), kids)
	}
	child := kids.at(t, kids.order[0])
	child.requireSetting(t, "if_id_in", "1")
	child.requireSetting(t, "if_id_out", "1")
	doc.at(t, "secrets", "ike-site-a").requireSetting(t, "secret", `"supersecret"`)
}

func TestGenerateConfig_WithProposal(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: "strong",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"strong": {
				Name:          "strong",
				EncryptionAlg: "aes256-cbc",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
		},
	}
	childSA_3904(t, m.generateConfig(cfg), "tun1").
		requireSetting(t, "esp_proposals", "aes256-sha256-modp2048")
}

func TestGenerateConfig_GCMNoAuth(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: "gcm",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"gcm": {
				Name:          "gcm",
				EncryptionAlg: "aes256gcm128",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
		},
	}
	// GCM mode should skip auth algorithm — no integrity token is emitted
	// for an AEAD cipher (the caller takes the gcmPRF branch, not
	// normalizeAuthAlg), so the strongSwan integrity keyword must be absent.
	//
	// #6824: equality at the child SA pins the value that MUST be there. The
	// original also claimed the integrity token appears NOWHERE, which equality
	// at one path does NOT subsume -- nothing stops another section carrying it
	// -- so that half is restored as a document-wide absence.
	got := m.generateConfig(cfg)
	childSA_3904(t, got, "tun1").requireSetting(t, "esp_proposals", "aes256gcm128-modp2048")
	parseSwanctlDoc(t, got).hasNoValueSubstringAnywhere(t, "sha256-modp2048")
}

func TestXfrmiIfID(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"st0.0", 1},
		{"st0.1", 2},
		{"st1.0", 65537},
		{"st5.0", 327681},
		{"st0", 1},
		{"", 0},
		{"eth0", 0},
		{"st", 0},
	}
	for _, tt := range tests {
		if got := xfrmiIfID(tt.input); got != tt.want {
			t.Errorf("xfrmiIfID(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestDHGroupBits(t *testing.T) {
	tests := []struct {
		group int
		want  int
	}{
		{1, 768},
		{2, 1024},
		{5, 1536},
		{14, 2048},
		{15, 3072},
		{16, 4096},
		{19, 256},
		{20, 384},
		{99, 99}, // passthrough for unknown
	}
	for _, tt := range tests {
		if got := dhGroupBits(tt.group); got != tt.want {
			t.Errorf("dhGroupBits(%d) = %d, want %d", tt.group, got, tt.want)
		}
	}
}

func TestBuildESPProposal(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-sha256-dh14",
			&config.IPsecProposal{EncryptionAlg: "aes256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256-modp2048",
		},
		{
			"defaults",
			&config.IPsecProposal{},
			"aes256",
		},
		{
			// #2392: EC DH group 20 must render the strongSwan ECP keyword
			// ecp384, NOT the invalid modp384 this case pinned before the
			// formatDHGroup fix.
			"gcm-no-auth-ecp",
			&config.IPsecProposal{EncryptionAlg: "aes256gcm128", AuthAlg: "hmac-sha512", DHGroup: 20},
			"aes256gcm128-ecp384",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildESPProposal(tt.prop, 0); got != tt.want {
				t.Errorf("buildESPProposal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildESPProposal_PFSOverride(t *testing.T) {
	prop := &config.IPsecProposal{
		EncryptionAlg: "aes256-cbc",
		AuthAlg:       "hmac-sha256-128",
		DHGroup:       2,
	}
	got := buildESPProposal(prop, 14)
	if got != "aes256-sha256-modp2048" {
		t.Fatalf("buildESPProposal() with PFS override = %q, want aes256-sha256-modp2048", got)
	}
}

// TestResolveESPSettings_DanglingProposalSkips is the #9919 F-090 contract:
// when an IPsec policy resolves but NONE of its proposal references do, the
// resolver returns errESPChainUnresolved (IKE parity, #2270) so the caller
// SKIPS the VPN — never a fabricated suite. This replaces the #2073
// fallback assertion (which pinned the emitted aes256-sha256-modp2048
// suite); the PFS group is preserved only when a proposal resolves.
func TestResolveESPSettings_DanglingProposalSkips(t *testing.T) {
	cfg := &config.IPsecConfig{
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {
				Name:      "ipsec-pol",
				PFSGroup:  14,
				Proposals: []string{"does-not-exist"},
			},
		},
		// Proposals deliberately omits "does-not-exist" — dangling ref.
	}
	vpn := &config.IPsecVPN{IPsecPolicy: "ipsec-pol"}

	got, _, err := resolveESPSettings(cfg, vpn)
	if !errors.Is(err, errESPChainUnresolved) {
		t.Fatalf("dangling ESP proposal ref must fail closed with errESPChainUnresolved, got (%q, %v)", got, err)
	}
	if got == "default" || got == "aes256-sha256" || got == "aes256-sha256-modp2048" {
		t.Fatalf("dangling ESP proposal ref rendered a substitute suite %q; want skip (empty + sentinel)", got)
	}
}

// TestResolveESPSettings_DanglingProposalNoPFSkips is the no-PFS half of the
// #9919 F-090 contract: a dangling proposal reference with NO configured PFS
// skips exactly like the with-PFS half (no availability asymmetry driven by
// whether PFS happened to be configured — the #4117 rationale retired by
// the never-fabricate skip).
func TestResolveESPSettings_DanglingProposalNoPFSkips(t *testing.T) {
	cfg := &config.IPsecConfig{
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {
				Name:      "ipsec-pol",
				PFSGroup:  0,
				Proposals: []string{"does-not-exist"},
			},
		},
		// Proposals deliberately omits "does-not-exist" — dangling ref.
	}
	vpn := &config.IPsecVPN{IPsecPolicy: "ipsec-pol"}

	got, _, err := resolveESPSettings(cfg, vpn)
	if !errors.Is(err, errESPChainUnresolved) {
		t.Fatalf("dangling ESP proposal ref (no PFS) must fail closed with errESPChainUnresolved, got (%q, %v)", got, err)
	}
	if got != "" {
		t.Fatalf("dangling ESP proposal ref (no PFS) rendered %q; want skip (empty + sentinel)", got)
	}
}

// TestResolveESPSettings_DanglingPolicyRefSkips covers the sibling dangling
// case (#9919 F-090): the VPN names an ipsec-policy that is not defined at
// all (neither a policy object nor a legacy proposal of that name). It
// skips with errESPChainUnresolved, like the dangling-proposal half.
func TestResolveESPSettings_DanglingPolicyRefSkips(t *testing.T) {
	cfg := &config.IPsecConfig{
		// Neither Policies nor Proposals defines "ipsec-pol".
	}
	vpn := &config.IPsecVPN{IPsecPolicy: "ipsec-pol"}

	got, _, err := resolveESPSettings(cfg, vpn)
	if !errors.Is(err, errESPChainUnresolved) {
		t.Fatalf("dangling ESP policy ref must fail closed with errESPChainUnresolved, got (%q, %v)", got, err)
	}
	if got != "" {
		t.Fatalf("dangling ESP policy ref rendered %q; want skip (empty + sentinel)", got)
	}
}

// TestGenerateConfig_DanglingProposalSkips is the #9919 F-090 full-render
// regression: a dangling ESP proposal reference SKIPS the VPN (no
// connection block, no fabricated esp_proposals) while a healthy sibling
// still renders — one bad reference never zeroes a healthy tunnel.
func TestGenerateConfig_DanglingProposalSkips(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				LocalID:     "10.0.1.0/24",
				RemoteID:    "10.0.2.0/24",
			},
			"healthy": {
				Gateway:  "172.16.0.2",
				LocalID:  "10.0.3.0/24",
				RemoteID: "10.0.4.0/24",
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", PFSGroup: 0, Proposals: []string{"does-not-exist"}},
		},
	}
	got, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if rendered["tun1"] {
		t.Errorf("dangling-ESP VPN tun1 was rendered; want skip.\n%s", got)
	}
	if !rendered["healthy"] {
		t.Errorf("healthy sibling VPN was dropped alongside the dangling one; want it rendered.\n%s", got)
	}
	parseSwanctlDoc(t, got).at(t, "connections").hasNoChild(t, "tun1")
	if strings.Contains(got, "aes256-sha256") {
		t.Errorf("render contains a fabricated fallback suite for the dangling reference.\n%s", got)
	}
}

// TestResolveESPSettings_NoPolicyStaysDefault is the (D) regression: a VPN
// with no IPsec policy emits "default" with no error and no PFS.
func TestResolveESPSettings_NoPolicyStaysDefault(t *testing.T) {
	cfg := &config.IPsecConfig{}
	vpn := &config.IPsecVPN{}
	got, lifetime, err := resolveESPSettings(cfg, vpn)
	if err != nil {
		t.Fatalf("no-policy VPN must not error: %v", err)
	}
	if got != "default" || lifetime != 0 {
		t.Errorf("resolveESPSettings = (%q, %d), want (default, 0)", got, lifetime)
	}
}

// TestGenerateConfig_DanglingPolicyRefSkips checks the full render for the
// dangling-POLICY half: the VPN names an undefined ipsec-policy, so no
// connection block is emitted and no orphan secret is written, while the
// healthy sibling (connection and secret) renders.
//
// The secret half is pinned in two phases so the omission cannot pass
// vacuously: first the SAME PSK-carrying VPN renders its secret against a
// resolving chain (positive control), then the chain breaks and the secret
// must disappear with the connection.
func TestGenerateConfig_DanglingPolicyRefSkips(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	mkVPNs := func(policy string) map[string]*config.IPsecVPN {
		return map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: policy,
				PSK:         "tun1-secret",
				LocalID:     "10.0.1.0/24",
				RemoteID:    "10.0.2.0/24",
			},
			"healthy": {
				Gateway:  "172.16.0.2",
				PSK:      "healthy-secret",
				LocalID:  "10.0.3.0/24",
				RemoteID: "10.0.4.0/24",
			},
		}
	}

	// Phase 1: resolving chain — both connections and both secrets render.
	resolving := &config.IPsecConfig{
		VPNs: mkVPNs("ipsec-pol"),
		Proposals: map[string]*config.IPsecProposal{
			"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}},
		},
	}
	got, rendered, err := m.renderConfig(resolving)
	if err != nil {
		t.Fatalf("renderConfig (resolving): %v", err)
	}
	if !rendered["tun1"] || !rendered["healthy"] {
		t.Fatalf("positive control must render both VPNs, got %v\n%s", rendered, got)
	}
	ctrl := parseSwanctlDoc(t, got)
	ctrl.at(t, "secrets", "ike-tun1").requireSetting(t, "secret", `"tun1-secret"`)
	ctrl.at(t, "secrets", "ike-healthy").requireSetting(t, "secret", `"healthy-secret"`)

	// Phase 2: the chain breaks — tun1's connection AND secret disappear,
	// while the healthy sibling keeps both.
	broken := &config.IPsecConfig{VPNs: mkVPNs("does-not-exist")}
	got, rendered, err = m.renderConfig(broken)
	if err != nil {
		t.Fatalf("renderConfig (dangling): %v", err)
	}
	if rendered["tun1"] {
		t.Errorf("dangling-policy VPN tun1 was rendered; want skip.\n%s", got)
	}
	if !rendered["healthy"] {
		t.Errorf("healthy sibling VPN was dropped alongside the dangling one; want it rendered.\n%s", got)
	}
	doc := parseSwanctlDoc(t, got)
	doc.at(t, "connections").hasNoChild(t, "tun1")
	doc.at(t, "secrets").hasNoChild(t, "ike-tun1")
	doc.at(t, "secrets", "ike-healthy").requireSetting(t, "secret", `"healthy-secret"`)
}

// readSAFixture loads a captured `swanctl --list-sas` golden fixture. The
// fixtures pin parseSAOutput to the format the installed strongSwan actually
// emits (the parser previously assumed an "ipsec statusall"-style layout that
// swanctl never produces, #3937).
func readSAFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

func TestParseSAOutput(t *testing.T) {
	sas := parseSAOutput(readSAFixture(t, "swanctl_list_sas_single.txt"))
	if len(sas) != 1 {
		t.Fatalf("expected 1 SA, got %d: %+v", len(sas), sas)
	}
	sa := sas[0]
	// RED-on-revert: the pre-#3937 parser left every field but name/state
	// blank against real swanctl output. Each assertion below fails (empty)
	// if the parser regresses to the assumed "statusall" layout.
	checks := []struct {
		name, got, want string
	}{
		{"Name", sa.Name, "site-a"},
		{"ConnectionName", sa.ConnectionName, "site-a"},
		{"State", sa.State, "INSTALLED"},
		{"LocalAddr", sa.LocalAddr, "10.0.1.1"},
		{"RemoteAddr", sa.RemoteAddr, "10.0.2.1"},
		{"LocalTS", sa.LocalTS, "10.0.1.0/24"},
		{"RemoteTS", sa.RemoteTS, "10.0.2.0/24"},
		{"InBytes", sa.InBytes, "1420"},
		{"OutBytes", sa.OutBytes, "1638"},
		{"InPackets", sa.InPackets, "12"},
		{"OutPackets", sa.OutPackets, "14"},
		{"SPIIn", sa.SPIIn, "c1234567"},
		{"SPIOut", sa.SPIOut, "c7654321"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if !strings.Contains(sa.Rekey, "rekeying in 3358s") {
		t.Errorf("Rekey = %q, want it to carry the child timing line", sa.Rekey)
	}
}

func TestParseSAOutput_TwoTunnels(t *testing.T) {
	sas := parseSAOutput(readSAFixture(t, "swanctl_list_sas_two.txt"))
	if len(sas) != 2 {
		t.Fatalf("expected 2 SAs, got %d: %+v", len(sas), sas)
	}
	if sas[0].Name != "site-a" || sas[0].RemoteAddr != "10.0.2.1" || sas[0].InBytes != "1420" {
		t.Errorf("unexpected first tunnel: %+v", sas[0])
	}
	// IPv6 endpoint: the "[port]" suffix must be stripped without eating the
	// v6 host colons.
	if sas[1].Name != "site-b" || sas[1].ConnectionName != "site-b" {
		t.Errorf("unexpected second tunnel name: %+v", sas[1])
	}
	if sas[1].LocalAddr != "2001:db8:1::1" || sas[1].RemoteAddr != "2001:db8:2::1" {
		t.Errorf("v6 endpoint parse wrong: local=%q remote=%q", sas[1].LocalAddr, sas[1].RemoteAddr)
	}
	if sas[1].LocalTS != "2001:db8:1::/64" || sas[1].RemoteTS != "2001:db8:2::/64" {
		t.Errorf("v6 traffic selectors wrong: local=%q remote=%q", sas[1].LocalTS, sas[1].RemoteTS)
	}
	if sas[1].InBytes != "204800" || sas[1].OutBytes != "198400" {
		t.Errorf("v6 byte counters wrong: in=%q out=%q", sas[1].InBytes, sas[1].OutBytes)
	}
}

func TestParseSAOutput_MultiChild(t *testing.T) {
	output := `site-a: #1, ESTABLISHED, IKEv2, 8f7c1c8e3a2b1234_i* 4d3c2b1a09876543_r
  local  '10.0.1.1' @ 10.0.1.1[500]
  remote '10.0.2.1' @ 10.0.2.1[500]
  established 42s ago, rekeying in 13342s
  site-a-ts1: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    in  aaaa1111,  100 bytes,    1 packets
    out bbbb2222,  200 bytes,    2 packets
    local  10.0.1.0/24
    remote 10.0.2.0/24
  site-a-ts2: #2, reqid 2, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    in  cccc3333,  300 bytes,    3 packets
    out dddd4444,  400 bytes,    4 packets
    local  10.0.3.0/24
    remote 10.0.4.0/24
`
	sas := parseSAOutput(output)
	if len(sas) != 2 {
		t.Fatalf("expected 2 child SAs, got %d", len(sas))
	}
	if sas[0].Name != "site-a-ts1" || sas[0].ConnectionName != "site-a" {
		t.Fatalf("unexpected first child: %+v", sas[0])
	}
	if sas[0].LocalTS != "10.0.1.0/24" || sas[0].InBytes != "100" {
		t.Errorf("first child fields wrong: %+v", sas[0])
	}
	// Both children inherit the parent IKE SA endpoints (swanctl prints them
	// once, on the IKE header block).
	if sas[0].RemoteAddr != "10.0.2.1" || sas[1].RemoteAddr != "10.0.2.1" {
		t.Errorf("children did not inherit endpoint: %+v / %+v", sas[0], sas[1])
	}
	if sas[1].Name != "site-a-ts2" || sas[1].ConnectionName != "site-a" {
		t.Fatalf("unexpected second child: %+v", sas[1])
	}
	if sas[1].LocalTS != "10.0.3.0/24" || sas[1].OutBytes != "400" {
		t.Errorf("second child fields wrong: %+v", sas[1])
	}
}

func TestParseSAOutput_ConnectingNoChild(t *testing.T) {
	// An IKE SA still negotiating (no child SA yet) is reported by its IKE
	// name/state so the operator can see the tunnel is coming up.
	output := `site-c: #3, CONNECTING, IKEv2
  local  '10.0.1.1' @ 10.0.1.1[500]
  remote '10.0.9.1' @ 10.0.9.1[500]
`
	sas := parseSAOutput(output)
	if len(sas) != 1 {
		t.Fatalf("expected 1 SA, got %d: %+v", len(sas), sas)
	}
	if sas[0].Name != "site-c" || sas[0].State != "CONNECTING" {
		t.Errorf("unexpected connecting SA: %+v", sas[0])
	}
	if sas[0].RemoteAddr != "10.0.9.1" {
		t.Errorf("connecting endpoint not parsed: %+v", sas[0])
	}
}

func TestGenerateConfig_GatewayReference(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"remote-gw": {
				Name:         "remote-gw",
				Address:      "10.0.2.1",
				LocalAddress: "10.0.1.1",
				IKEPolicy:    "ike-aes256",
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				Gateway:       "remote-gw", // reference to gateway name
				IPsecPolicy:   "esp-aes256",
				PSK:           "mysecret",
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"ike-aes256": {
				Name:          "ike-aes256",
				EncryptionAlg: "aes256-cbc",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
			"esp-aes256": {
				Name:          "esp-aes256",
				EncryptionAlg: "aes256-cbc",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
		},
	}
	got := m.generateConfig(cfg)

	// Should resolve gateway address, not use "remote-gw" as IP
	// #6824: `proposals = ...` is the Phase-1 offer on the connection and
	// `esp_proposals = ...` the Phase-2 offer on the child SA. The old
	// Contains(got, "proposals = aes256-sha256-modp2048") needle matched the
	// esp_proposals line too, so the IKE assertion passed even with the
	// Phase-1 line missing entirely.
	conn := parseSwanctlDoc(t, got).at(t, "connections", "site-a")
	conn.requireSetting(t, "remote_addrs", "10.0.2.1")
	conn.requireSetting(t, "local_addrs", "10.0.1.1")
	conn.requireSetting(t, "proposals", "aes256-sha256-modp2048")
	childSA_3904(t, got, "site-a").
		requireSetting(t, "esp_proposals", "aes256-sha256-modp2048")
}

func TestGenerateConfig_DirectGatewayIP(t *testing.T) {
	// When gateway is an IP (not a reference), it should be used directly
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways:  map[string]*config.IPsecGateway{},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"direct": {
				Gateway:   "172.16.0.1",
				LocalAddr: "172.16.0.2",
				PSK:       "key123",
			},
		},
	}
	conn := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "direct")
	conn.requireSetting(t, "remote_addrs", "172.16.0.1")
	conn.requireSetting(t, "local_addrs", "172.16.0.2")
}

func TestBuildIKEProposal(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-sha256-dh14",
			&config.IPsecProposal{EncryptionAlg: "aes256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256-modp2048",
		},
		{
			"defaults",
			&config.IPsecProposal{},
			"aes256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildIKEProposal(tt.prop); got != tt.want {
				t.Errorf("buildIKEProposal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSAOutput_Empty(t *testing.T) {
	sas := parseSAOutput("")
	if len(sas) != 0 {
		t.Errorf("expected 0 SAs for empty input, got %d", len(sas))
	}
}

func TestParseSAOutput_Multiple(t *testing.T) {
	// One established tunnel with a child SA plus one still-connecting IKE SA
	// with no child, in real swanctl layout. The established tunnel is
	// reported by its child SA (INSTALLED), the connecting one by its IKE SA.
	output := `site-a: #1, ESTABLISHED, IKEv2, 8f7c1c8e3a2b1234_i* 4d3c2b1a09876543_r
  local  '10.0.1.1' @ 10.0.1.1[500]
  remote '10.0.2.1' @ 10.0.2.1[500]
  established 42s ago, rekeying in 13342s
  site-a: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    in  c1234567,  1420 bytes,    12 packets,     2s ago
    out c7654321,  1638 bytes,    14 packets,     2s ago
    local  10.0.1.0/24
    remote 10.0.2.0/24
site-b: #2, CONNECTING, IKEv2
  local  '10.0.1.1' @ 10.0.1.1[500]
  remote '10.0.3.1' @ 10.0.3.1[500]
`
	sas := parseSAOutput(output)
	if len(sas) != 2 {
		t.Fatalf("expected 2 SAs, got %d: %+v", len(sas), sas)
	}
	if sas[0].Name != "site-a" || sas[0].State != "INSTALLED" {
		t.Errorf("sa[0] = %+v", sas[0])
	}
	if sas[1].Name != "site-b" {
		t.Errorf("sa[1] name = %q", sas[1].Name)
	}
	if sas[1].State != "CONNECTING" {
		t.Errorf("sa[1] state = %q, want CONNECTING", sas[1].State)
	}
}

func TestGenerateConfig_IKEChain(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {
				Name:          "ike-p1",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "sha-256",
				DHGroup:       14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {
				Name:      "ike-pol",
				Mode:      "main",
				Proposals: []string{"ike-p1"},
				PSK:       "secret123",
			},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {
				Name:           "gw1",
				Address:        "203.0.113.1",
				LocalAddress:   "198.51.100.1",
				IKEPolicy:      "ike-pol",
				Version:        "v2-only",
				NoNATTraversal: true,
				DeadPeerDetect: "always-send",
				LocalIDType:    "hostname",
				LocalIDValue:   "vpn.example.com",
				RemoteIDType:   "inet",
				RemoteIDValue:  "203.0.113.1",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-p2": {
				Name:          "esp-p2",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "hmac-sha-256-128",
				DHGroup:       14,
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {
				Name:      "ipsec-pol",
				PFSGroup:  14,
				Proposals: []string{"esp-p2"},
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				Name:             "site-a",
				Gateway:          "gw1",
				IPsecPolicy:      "ipsec-pol",
				BindInterface:    "st0.0",
				DFBit:            "copy",
				EstablishTunnels: "immediately",
			},
		},
	}
	got := m.generateConfig(cfg)

	// #6824: each expectation now names the PATH it must sit at. The old table
	// asserted fifteen substrings against the whole document, and two of its
	// rows -- "local identity" and "remote identity" -- would both have passed
	// with the two identities SWAPPED, because `id` is emitted in both auth
	// rounds and containment cannot say which round it matched. Two more rows
	// were mutually satisfiable: "IKE proposal" looked for
	// `proposals = aes256-sha256-modp2048`, which is a substring of the
	// esp_proposals line, so it passed with the Phase-1 offer missing.
	doc := parseSwanctlDoc(t, got)
	kids := doc.at(t, "connections", "site-a", "children")
	if len(kids.order) != 1 {
		t.Fatalf("expected exactly one child SA, got %v\n%s", kids.childNames(), kids)
	}
	childName := kids.order[0]

	checks := []struct {
		name string
		path []string
		key  string
		want string
	}{
		{"IKE version", []string{"connections", "site-a"}, "version", "2"},
		{"local addr", []string{"connections", "site-a"}, "local_addrs", "198.51.100.1"},
		{"remote addr", []string{"connections", "site-a"}, "remote_addrs", "203.0.113.1"},
		{"no NAT-T", []string{"connections", "site-a"}, "encap", "no"},
		{"DPD", []string{"connections", "site-a"}, "dpd_delay", "10s"},
		{"DPD timeout", []string{"connections", "site-a"}, "dpd_timeout", "50s"},
		{"local identity", []string{"connections", "site-a", "local"}, "id", `"@vpn.example.com"`},
		{"remote identity", []string{"connections", "site-a", "remote"}, "id", `"203.0.113.1"`},
		{"IKE proposal", []string{"connections", "site-a"}, "proposals", "aes256-sha256-modp2048"},
		{"ESP proposal", []string{"connections", "site-a", "children", childName}, "esp_proposals", "aes256-sha256-modp2048"},
		{"copy DF", []string{"connections", "site-a", "children", childName}, "copy_df", "yes"},
		{"start action", []string{"connections", "site-a", "children", childName}, "start_action", "start"},
		{"DPD action", []string{"connections", "site-a", "children", childName}, "dpd_action", "restart"},
		{"XFRM if_id", []string{"connections", "site-a", "children", childName}, "if_id_in", "1"},
		{"PSK from IKE policy", []string{"secrets", "ike-site-a"}, "secret", `"secret123"`},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			doc.at(t, c.path...).requireSetting(t, c.key, c.want)
		})
	}
}

func TestGenerateConfig_DynamicHostname(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		// The ike-policy -> ike-proposal chain must resolve, else
		// renderConfig fail-closed-skips the VPN (#2270).
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol1": {Name: "pol1", Proposals: []string{"ike-p1"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {Name: "ike-p1", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		Gateways: map[string]*config.IPsecGateway{
			"dyn-gw": {
				Name:            "dyn-gw",
				DynamicHostname: "peer.example.com",
				IKEPolicy:       "pol1",
				Version:         "v2-only",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:       "dyn-gw",
				BindInterface: "st0.1",
				PSK:           "key456",
			},
		},
	}
	got := m.generateConfig(cfg)
	conn := parseSwanctlDoc(t, got).at(t, "connections", "tun1")
	conn.requireSetting(t, "remote_addrs", "peer.example.com")
	conn.requireSetting(t, "version", "2")
	// The xfrmi ids belong to the child SA. The old needles found them
	// anywhere in the document, so a render that emitted them on the
	// CONNECTION -- where charon would ignore them -- passed identically.
	child := childSA_3904(t, got, "tun1")
	child.requireSetting(t, "if_id_in", "2")
	child.requireSetting(t, "if_id_out", "2")
}

func TestFormatIdentity(t *testing.T) {
	tests := []struct {
		idType, idValue, want string
	}{
		{"hostname", "vpn.example.com", "@vpn.example.com"},
		{"fqdn", "peer.example.com", "@peer.example.com"},
		{"inet", "10.0.0.1", "10.0.0.1"},
		{"", "10.0.0.1", "10.0.0.1"},
	}
	for _, tt := range tests {
		got := formatIdentity(tt.idType, tt.idValue)
		if got != tt.want {
			t.Errorf("formatIdentity(%q, %q) = %q, want %q", tt.idType, tt.idValue, got, tt.want)
		}
	}
}

func TestGenerateConfig_NATTraversal_Disable(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1", NATTraversal: "disable", NoNATTraversal: true},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	doc := parseSwanctlDoc(t, m.generateConfig(cfg))
	doc.at(t, "connections", "tun").requireSetting(t, "encap", "no")
	// Document-wide, as the deleted needle was: a SIBLING connection carrying
	// forceencaps would have failed the old check and passes a path-scoped one.
	doc.hasNoSettingAnywhere(t, "forceencaps")
}

// #10474: xpf's `force` value maps to the swanctl setting `encap = yes`,
// not the legacy ipsec.conf/starter `forceencaps` setting. strongSwan's
// migration table maps the latter to `connections.<conn>.encap`; the
// generated swanctl config must contain only the native key so strongSwan
// 6.x accepts and establishes the tunnel.
func TestGenerateConfig_NATTraversal_Force(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1", NATTraversal: "force"},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	conn := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "tun")
	conn.requireSetting(t, "encap", "yes")
	conn.hasNoSetting(t, "forceencaps")
}

func TestGenerateConfig_NATTraversal_Enable(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1", NATTraversal: "enable"},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	// Enable is the strongSwan default — no encap/forceencaps lines needed.
	//
	// #6824: the old `encap = no` needle was value-specific, so a render that
	// emitted `encap = yes` (also wrong here -- nothing should be emitted)
	// passed. Absence of the KEY is the actual claim.
	// Document-wide, as the original needles were. Scoping an absence to one
	// path is a weaker claim than the one being replaced, even when the fixture
	// renders a single connection today.
	doc := parseSwanctlDoc(t, m.generateConfig(cfg))
	doc.at(t, "connections", "tun")
	doc.hasNoSettingAnywhere(t, "encap")
	doc.hasNoSettingAnywhere(t, "forceencaps")
}

func TestGenerateConfig_NATTraversal_Default(t *testing.T) {
	// When NATTraversal is empty (not set), and NoNATTraversal is false,
	// strongSwan auto-detects NAT — no encap lines needed.
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1"},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	// #6824: `Contains(got, "encap")` also matched `forceencaps`, so this
	// could never distinguish the two keys. Assert both absences explicitly.
	doc := parseSwanctlDoc(t, m.generateConfig(cfg))
	doc.at(t, "connections", "tun")
	doc.hasNoSettingAnywhere(t, "encap")
	doc.hasNoSettingAnywhere(t, "forceencaps")
}

func TestGenerateConfig_NoNATTraversal_Legacy(t *testing.T) {
	// Legacy NoNATTraversal=true without NATTraversal field.
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1", NoNATTraversal: true},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	parseSwanctlDoc(t, m.generateConfig(cfg)).
		at(t, "connections", "tun").
		requireSetting(t, "encap", "no")
}

func TestGenerateConfig_AggressiveMode(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"aggr-pol": {
				Name:      "aggr-pol",
				Mode:      "aggressive",
				Proposals: []string{"ike-p1"},
				PSK:       "secret",
			},
		},
		// The ike-policy -> ike-proposal chain must resolve, else
		// renderConfig fail-closed-skips the VPN (#2270).
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {Name: "ike-p1", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:      "gw",
				Address:   "10.0.0.1",
				IKEPolicy: "aggr-pol",
				Version:   "v1-only",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw"},
		},
	}
	conn := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "tun")
	conn.requireSetting(t, "aggressive", "yes")
	conn.requireSetting(t, "version", "1")
}

func TestGenerateConfig_AggressiveMode_NotSet(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"main-pol": {
				Name:      "main-pol",
				Mode:      "main",
				Proposals: []string{"ike-p1"},
				PSK:       "secret",
			},
		},
		// The ike-policy -> ike-proposal chain must resolve, else
		// renderConfig fail-closed-skips the VPN (#2270).
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {Name: "ike-p1", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:      "gw",
				Address:   "10.0.0.1",
				IKEPolicy: "main-pol",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw"},
		},
	}
	doc := parseSwanctlDoc(t, m.generateConfig(cfg))
	doc.at(t, "connections", "tun")
	doc.hasNoSettingAnywhere(t, "aggressive")
}

func TestGenerateConfig_DFBit(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	tests := []struct {
		name  string
		dfbit string
		// want is the value copy_df must carry; "" means the key must be
		// ABSENT. #6824 folded away the old notWant column: an exact match on
		// the setting already rejects the opposite value, and the two columns
		// could disagree without anything noticing.
		want string
	}{
		// #4015: df-bit set/clear were inverted. strongSwan copy_df=no CLEARS
		// the outer DF bit, so it must map to Junos "clear" (allow
		// fragmentation), NOT "set". "set" (and "copy") preserve/copy the DF
		// bit via copy_df=yes (strongSwan cannot force DF=1).
		{"copy", "copy", "yes"},
		{"set", "set", "yes"},
		{"clear", "clear", "no"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.IPsecConfig{
				Proposals: map[string]*config.IPsecProposal{},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {Gateway: "10.0.0.1", DFBit: tt.dfbit},
				},
			}
			// copy_df is a CHILD SA setting; the old needles found it anywhere.
			rendered := m.generateConfig(cfg)
			child := childSA_3904(t, rendered, "tun")
			// The deleted notWant column rejected the OPPOSITE value anywhere in
			// the document, not merely at this path. Equality below pins what
			// must be here; this pins that the other value is nowhere.
			opposite := map[string]string{"yes": "no", "no": "yes"}[tt.want]
			if opposite != "" {
				parseSwanctlDoc(t, rendered).
					hasNoSettingValuePrefixAnywhere(t, "copy_df", opposite)
			}
			if tt.want == "" {
				// Document-wide: the old notWant column asked whether the token
				// appeared at all, and narrowing that to the child SA would let
				// a stray copy_df elsewhere through.
				parseSwanctlDoc(t, m.generateConfig(cfg)).hasNoSettingAnywhere(t, "copy_df")
				return
			}
			child.requireSetting(t, "copy_df", tt.want)
		})
	}
}

func TestGenerateConfig_EstablishTunnels(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "10.0.0.1", EstablishTunnels: "immediately"},
		},
	}
	childSA_3904(t, m.generateConfig(cfg), "tun").
		requireSetting(t, "start_action", "start")

	// on-traffic should NOT produce start_action
	cfg.VPNs["tun"].EstablishTunnels = "on-traffic"
	offDoc := m.generateConfig(cfg)
	childSA_3904(t, offDoc, "tun")
	parseSwanctlDoc(t, offDoc).hasNoSettingAnywhere(t, "start_action")
}

func TestGenerateConfig_IKELifetime(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {
				Name:            "ike-p1",
				AuthMethod:      "pre-shared-keys",
				EncryptionAlg:   "aes-256-cbc",
				AuthAlg:         "sha-256",
				DHGroup:         14,
				LifetimeSeconds: 28800,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol1": {Name: "pol1", Proposals: []string{"ike-p1"}, PSK: "secret"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "pol1"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw"},
		},
	}
	// #6824: `rekey_time` is emitted on BOTH the IKE connection and the child
	// SA, so the old needle could be satisfied by the child's line while the
	// IKE lifetime was missing. Pin the connection.
	conn := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "tun")
	conn.requireSetting(t, "rekey_time", "28800s")
	// #9919 F-163: no rand_time beside the IKE rekey_time — strongSwan's
	// default jitter applies.
	conn.hasNoSetting(t, "rand_time")
}

func TestGenerateConfig_ESPLifetime(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{
			"esp-p2": {
				Name:            "esp-p2",
				EncryptionAlg:   "aes-256-cbc",
				AuthAlg:         "hmac-sha-256-128",
				LifetimeSeconds: 3600,
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "203.0.113.1", IPsecPolicy: "ipsec-pol"},
		},
	}
	// The ESP lifetime is the CHILD's rekey_time -- the mirror of the IKE
	// case above, and indistinguishable from it under containment.
	// #9919 F-163: no rand_time beside it either.
	child := childSA_3904(t, m.generateConfig(cfg), "tun")
	child.requireSetting(t, "rekey_time", "3600s")
	child.hasNoSetting(t, "rand_time")
}

func TestGenerateConfig_DPDModes(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:           "gw",
				Address:        "10.0.0.1",
				DeadPeerDetect: "probe-idle-tunnel",
				DPDInterval:    7,
				DPDThreshold:   3,
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", EstablishTunnels: "on-traffic"},
		},
	}
	// dpd_delay/dpd_timeout are IKE-level; dpd_action is on the child SA.
	// The old loop asserted all three against the whole document, so it could
	// not have caught any of them landing in the wrong section.
	doc := parseSwanctlDoc(t, m.generateConfig(cfg))
	conn := doc.at(t, "connections", "tun")
	conn.requireSetting(t, "dpd_delay", "7s")
	conn.requireSetting(t, "dpd_timeout", "21s")
	childSA_3904(t, m.generateConfig(cfg), "tun").requireSetting(t, "dpd_action", "trap")
}

// TestGenerateConfig_DPDBareAndTuningForms compiles a full tunnel from flat-set
// commands and renders the swanctl config, asserting the DPD stanza forms flow
// end-to-end (#3994). It builds the config through the real compile path (no
// hand-set DeadPeerDetect/DPDEnable), so it goes RED on revert of the parse +
// deriveDPD fix: a bare `dead-peer-detection` would compile to a disabled DPD
// and the rendered config would lack dpd_delay.
func TestGenerateConfig_DPDBareAndTuningForms(t *testing.T) {
	compileFromSet := func(t *testing.T, cmds []string) *config.IPsecConfig {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%v): %v", path, err)
			}
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return &cfg.Security.IPsec
	}

	base := []string{
		`set security ike proposal ike-p1 authentication-method pre-shared-keys`,
		`set security ike proposal ike-p1 dh-group group14`,
		`set security ike proposal ike-p1 encryption-algorithm aes-256-cbc`,
		`set security ike policy pol1 mode main`,
		`set security ike policy pol1 proposals ike-p1`,
		`set security ike policy pol1 pre-shared-key ascii-text mysecret`,
		`set security ike gateway gw1 ike-policy pol1`,
		`set security ike gateway gw1 address 203.0.113.1`,
		`set security ipsec proposal esp-p2 protocol esp`,
		`set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc`,
		`set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128`,
		`set security ipsec policy ipsec-pol proposals esp-p2`,
		`set security ipsec vpn tun1 bind-interface st0.0`,
		`set security ipsec vpn tun1 ike gateway gw1`,
		`set security ipsec vpn tun1 ike ipsec-policy ipsec-pol`,
	}
	with := func(extra ...string) []string {
		return append(append([]string{}, base...), extra...)
	}
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("bare enables DPD with defaults", func(t *testing.T) {
		out := m.generateConfig(compileFromSet(t, with(`set security ike gateway gw1 dead-peer-detection`)))
		conn := parseSwanctlDoc(t, out).at(t, "connections", "tun1")
		conn.requireSetting(t, "dpd_delay", "10s")
		conn.requireSetting(t, "dpd_timeout", "50s")
		childSA_3904(t, out, "tun1").requireSetting(t, "dpd_action", "clear")
	})

	t.Run("interval-only tunes delay", func(t *testing.T) {
		out := m.generateConfig(compileFromSet(t, with(`set security ike gateway gw1 dead-peer-detection interval 20`)))
		parseSwanctlDoc(t, out).at(t, "connections", "tun1").
			requireSetting(t, "dpd_delay", "20s")
	})

	t.Run("always-send maps to restart", func(t *testing.T) {
		out := m.generateConfig(compileFromSet(t, with(`set security ike gateway gw1 dead-peer-detection always-send`)))
		childSA_3904(t, out, "tun1").requireSetting(t, "dpd_action", "restart")
	})

	t.Run("no DPD stanza emits no dpd", func(t *testing.T) {
		out := m.generateConfig(compileFromSet(t, base))
		doc := parseSwanctlDoc(t, out)
		doc.at(t, "connections", "tun1")
		doc.hasNoSettingAnywhere(t, "dpd_delay")
	})
}

func TestGenerateConfig_JunosObfuscatedPSK(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "10.0.0.1", PSK: "$9$SpRrMLYgaZDirexdwgUDzFn9uO1RhlKW"},
		},
	}
	got, _, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig() error = %v", err)
	}
	secretsOnly_6824(t, got).requireSetting(t, "secret", `"QZ1agnL21L"`)
}

func TestGenerateConfig_PubkeyAuth(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {
				Name:          "ike-p1",
				AuthMethod:    "rsa-signatures",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "sha-256",
				DHGroup:       14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol1": {Name: "pol1", Proposals: []string{"ike-p1"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:             "gw",
				Address:          "203.0.113.1",
				IKEPolicy:        "pol1",
				LocalCertificate: "gw-cert.pem",
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw"},
		},
	}
	// #6824: `auth` and `certs` are emitted in the local{} round. The old
	// needles matched either round, so a render that put the LOCAL certificate
	// under remote{} -- where charon reads it as the peer's -- passed.
	doc := parseSwanctlDoc(t, m.generateConfig(cfg))
	local := doc.at(t, "connections", "tun", "local")
	local.requireSetting(t, "auth", "pubkey")
	local.requireSetting(t, "certs", `"gw-cert.pem"`)
	// No PSK anywhere: pubkey auth must not emit a secret in ANY section.
	doc.hasNoSettingAnywhere(t, "secret")
}

func TestGenerateConfig_TrafficSelectors(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {
				Gateway: "10.0.0.1",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"corp-a": {Name: "corp-a", LocalIP: "10.0.1.0/24", RemoteIP: "10.10.1.0/24"},
					"corp-b": {Name: "corp-b", LocalIP: "10.0.2.0/24", RemoteIP: "10.10.2.0/24"},
				},
			},
		},
	}
	// #6824: the six old needles would ALL have been satisfied with corp-a's
	// selectors rendered inside corp-b's child section and vice versa -- the
	// pairing is the entire point of a traffic selector, and containment
	// cannot express it.
	kids := parseSwanctlDoc(t, m.generateConfig(cfg)).at(t, "connections", "tun", "children")
	for _, c := range []struct{ name, local, remote string }{
		{"tun-corp-a", "10.0.1.0/24", "10.10.1.0/24"},
		{"tun-corp-b", "10.0.2.0/24", "10.10.2.0/24"},
	} {
		child := kids.at(t, c.name)
		child.requireSetting(t, "local_ts", c.local)
		child.requireSetting(t, "remote_ts", c.remote)
	}
}

// TestEffectiveTrafficSelectors_NilVPN guards the #2022 nil-deref: the
// vpn==nil branch previously dereferenced vpn.LocalID/vpn.RemoteID and
// panicked. A nil VPN must yield no children, not a panic. Run with
// t.Fatalf-on-panic so the test fails (not crashes) against pre-fix code.
func TestEffectiveTrafficSelectors_NilVPN(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("effectiveTrafficSelectors(nil) panicked: %v", r)
		}
	}()
	got := effectiveTrafficSelectors("tun", nil)
	if len(got) != 0 {
		t.Fatalf("nil VPN: want no children, got %d: %+v", len(got), got)
	}
}

// TestEffectiveTrafficSelectors_NoSelectors confirms the non-nil VPN with
// zero traffic selectors still falls back to a single default child built
// from LocalID/RemoteID — the behavior the broken nil-OR-empty guard used
// to share. The #2022 fix must not regress this path.
func TestEffectiveTrafficSelectors_NoSelectors(t *testing.T) {
	vpn := &config.IPsecVPN{LocalID: "10.0.1.0/24", RemoteID: "10.10.1.0/24"}
	got := effectiveTrafficSelectors("tun", vpn)
	if len(got) != 1 {
		t.Fatalf("want 1 default child, got %d: %+v", len(got), got)
	}
	c := got[0]
	if c.Name != "tun" || c.LocalTS != "10.0.1.0/24" || c.RemoteTS != "10.10.1.0/24" {
		t.Fatalf("unexpected default child: %+v", c)
	}
}

func TestPrepareConfig_ExternalInterfaceLocalAddress(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							PrimaryAddress: "198.51.100.1/24",
							Addresses:      []string{"198.51.100.1/24"},
						},
					},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {
						Name:          "gw",
						Address:       "203.0.113.1",
						ExternalIface: "wan0.0",
					},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {Gateway: "gw"},
				},
			},
		},
	}

	prepared := PrepareConfig(cfg)
	if prepared.Gateways["gw"].LocalAddress != "198.51.100.1" {
		t.Fatalf("resolved local-address = %q, want 198.51.100.1", prepared.Gateways["gw"].LocalAddress)
	}
}

// dualStackCfg builds a config whose external interface carries BOTH an IPv4
// and an IPv6 address, and whose gateway is reached by a dynamic hostname.
// The local-address family is therefore ambiguous unless it is constrained to
// the resolved remote family.
func dualStackCfg(hostname string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							// IPv4 listed first so a family-agnostic
							// selection would wrongly win it for the IPv6
							// peer (the #2757 bug).
							Addresses: []string{
								"198.51.100.1/24",
								"2001:db8:1::1/64",
							},
						},
					},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {
						Name:            "gw",
						DynamicHostname: hostname,
						ExternalIface:   "wan0.0",
					},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {Gateway: "gw"},
				},
			},
		},
	}
}

// TestPrepareConfig_DynamicHostnameFamilyMatch is the #2757 fail-on-revert
// guard: a dual-stack appliance reaching a dynamic-hostname gateway must
// source the IKE SA from the local-address whose family matches the family
// the peer resolves to. If the family-matching is reverted (the empty
// gateway.Address yields a family-agnostic hint), the IPv4 address — listed
// first on the interface — wins for the IPv6 peer and this test goes RED.
func TestPrepareConfig_DynamicHostnameFamilyMatch(t *testing.T) {
	orig := resolveHostFamily
	t.Cleanup(func() { resolveHostFamily = orig })

	tests := []struct {
		name          string
		resolvedFam   int
		wantLocalAddr string
	}{
		{"ipv6 peer selects ipv6 local", 6, "2001:db8:1::1"},
		{"ipv4 peer selects ipv4 local", 4, "198.51.100.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolveHostFamily = func(host string) int {
				if host != "peer.example.com" {
					t.Fatalf("unexpected host lookup: %q", host)
				}
				return tc.resolvedFam
			}
			cfg := dualStackCfg("peer.example.com")
			prepared := PrepareConfig(cfg)
			got := prepared.Gateways["gw"].LocalAddress
			if got != tc.wantLocalAddr {
				t.Fatalf("local-address = %q, want %q (family %d)",
					got, tc.wantLocalAddr, tc.resolvedFam)
			}
		})
	}
}

// TestDefaultResolveHostFamily_BoundedDegrades exercises the REAL default
// resolver implementation (not an injected fake) and proves it (a) is bounded
// by resolveHostFamilyTimeout and (b) degrades to family 0 on failure rather
// than hanging the synchronous commit/apply path (#2757 review fold). It uses
// the RFC 6761 reserved `.invalid` TLD, which is guaranteed never to resolve,
// so the lookup fails (NXDOMAIN / no such host) without depending on a
// reachable nameserver. The hard deadline (4x the timeout) catches a
// regression that drops the context bound; the expected return is 0.
func TestDefaultResolveHostFamily_BoundedDegrades(t *testing.T) {
	done := make(chan int, 1)
	go func() { done <- defaultResolveHostFamily("xpf-2757-nonexistent.invalid") }()

	select {
	case fam := <-done:
		if fam != 0 {
			t.Fatalf("unresolvable host family = %d, want 0 (degrade-to-agnostic)", fam)
		}
	case <-time.After(4 * resolveHostFamilyTimeout):
		t.Fatalf("default resolver did not return within %v — context bound missing",
			4*resolveHostFamilyTimeout)
	}
}

// TestPrepareConfig_DynamicHostnameDualStackPeer verifies that when the peer
// resolves to BOTH families (no explicit preference), local-address selection
// stays family-agnostic and degrades to the interface's first usable address
// rather than guessing — and that a single-stack interface still resolves.
func TestPrepareConfig_DynamicHostnameDualStackPeer(t *testing.T) {
	orig := resolveHostFamily
	t.Cleanup(func() { resolveHostFamily = orig })
	resolveHostFamily = func(string) int { return 0 } // dual-stack peer

	cfg := dualStackCfg("peer.example.com")
	prepared := PrepareConfig(cfg)
	got := prepared.Gateways["gw"].LocalAddress
	if got != "198.51.100.1" {
		t.Fatalf("dual-stack peer local-address = %q, want 198.51.100.1 (first usable)", got)
	}
}

// TestPrepareConfig_DynamicHostnameFamilyFallback verifies the single-stack
// fallback: an IPv6-only peer against an IPv4-only interface still yields the
// IPv4 local-address rather than an empty local_addrs.
func TestPrepareConfig_DynamicHostnameFamilyFallback(t *testing.T) {
	orig := resolveHostFamily
	t.Cleanup(func() { resolveHostFamily = orig })
	resolveHostFamily = func(string) int { return 6 } // IPv6 peer

	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"198.51.100.1/24"}}, // IPv4 only
					},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {
						Name:            "gw",
						DynamicHostname: "peer.example.com",
						ExternalIface:   "wan0.0",
					},
				},
				VPNs: map[string]*config.IPsecVPN{"tun": {Gateway: "gw"}},
			},
		},
	}
	prepared := PrepareConfig(cfg)
	if got := prepared.Gateways["gw"].LocalAddress; got != "198.51.100.1" {
		t.Fatalf("IPv6-peer/IPv4-only-iface local-address = %q, want 198.51.100.1 (fallback)", got)
	}
}

// multiDynamicHostnameCfg builds a config with a single dual-stack external
// interface and n dynamic-hostname gateways (each LocalAddress unset, so
// PrepareConfig resolves the local-address per gateway via a family hint). The
// interface carries both an IPv4 and an IPv6 address so the resolved
// local-address directly reflects the per-gateway family hint: family 4 →
// 198.51.100.1, family 6 → 2001:db8:1::1.
func multiDynamicHostnameCfg(n int) *config.Config {
	gws := make(map[string]*config.IPsecGateway, n)
	vpns := make(map[string]*config.IPsecVPN, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("gw%d", i)
		gws[name] = &config.IPsecGateway{
			Name:            name,
			DynamicHostname: fmt.Sprintf("peer%d.example.com", i),
			ExternalIface:   "wan0.0",
		}
		vpns[fmt.Sprintf("tun%d", i)] = &config.IPsecVPN{Gateway: name}
	}
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{
							"198.51.100.1/24",
							"2001:db8:1::1/64",
						}},
					},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{Gateways: gws, VPNs: vpns},
		},
	}
}

// TestPrepareConfig_DynamicHostnameParallelResolve is the #4547 fail-on-revert
// guard. Dynamic-hostname gateways resolve a family hint via a DNS lookup
// bounded by resolveHostFamilyTimeout. Resolving N such gateways SEQUENTIALLY
// in the commit apply stalls the commit up to N×timeout under a slow/failing
// resolver; PrepareConfig now resolves the per-gateway hints concurrently
// (bounded pool), so N gateways cost ~one lookup of wall-clock, not N.
//
// The injected resolver sleeps perLookup per call. With n gateways under the
// concurrency cap, a parallel resolve completes in ~perLookup; a sequential
// resolve needs ~n×perLookup. The deadline below (n/2 × perLookup) is safely
// above the parallel time and safely below the sequential time, so reverting
// the parallelization (back to an inline per-gateway lookup) makes this RED.
// The test also asserts each gateway's family hint is applied correctly and is
// identical to what the sequential per-gateway lookup produced, and that
// exactly one lookup happened per gateway (no redundant or dropped lookups).
func TestPrepareConfig_DynamicHostnameParallelResolve(t *testing.T) {
	orig := resolveHostFamily
	t.Cleanup(func() { resolveHostFamily = orig })

	const (
		n         = 6 // under resolveFamilyHintConcurrency (8) → all run at once
		perLookup = 150 * time.Millisecond
	)

	var calls int64
	// Deterministic per-host family: even index → IPv4, odd index → IPv6.
	// The stub is invoked concurrently, so it must be goroutine-safe (it reads
	// only its host argument and an atomic counter).
	resolveHostFamily = func(host string) int {
		atomic.AddInt64(&calls, 1)
		time.Sleep(perLookup)
		var idx int
		if _, err := fmt.Sscanf(host, "peer%d.example.com", &idx); err != nil {
			return -1 // unexpected host → forces a mismatch assertion below
		}
		if idx%2 == 0 {
			return 4
		}
		return 6
	}

	cfg := multiDynamicHostnameCfg(n)

	start := time.Now()
	prepared := PrepareConfig(cfg)
	elapsed := time.Since(start)

	deadline := (n / 2) * perLookup
	if elapsed >= deadline {
		t.Fatalf("PrepareConfig took %v for %d dynamic-hostname gateways; "+
			"want < %v (parallel). Sequential per-gateway lookup regressed (#4547)",
			elapsed, n, deadline)
	}

	if got := atomic.LoadInt64(&calls); got != n {
		t.Fatalf("resolver called %d times, want exactly %d (one per gateway)", got, n)
	}

	// Each gateway's local-address must reflect its own family hint, identical
	// to the sequential resolution: even → IPv4 (198.51.100.1), odd → IPv6.
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("gw%d", i)
		want := "2001:db8:1::1"
		if i%2 == 0 {
			want = "198.51.100.1"
		}
		if got := prepared.Gateways[name].LocalAddress; got != want {
			t.Fatalf("gateway %s local-address = %q, want %q (family hint mismatch)",
				name, got, want)
		}
	}
}

// #1798 belt test: a pre-shared key (or identity) carrying an embedded
// newline must not inject extra swanctl.conf sections/keys even if
// commit-time validation were bypassed.
func TestGenerateConfig_NewlineSecretDoesNotInject(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           "secret\ninclude /etc/evil.conf",
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	// #6824: a leaked `include` would parse as an unrecognised line and the
	// parser fails on it, so parsing at all is the leak check. The scan is kept
	// alongside because `include /etc/evil.conf` without an "=" is exactly the
	// shape the parser refuses, and stating the intent here is worth the four
	// lines.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "include ") {
			t.Fatalf("injected swanctl directive leaked:\n%s", got)
		}
	}
	secretsOnly_6824(t, got).requireSetting(t, "secret", `"secret include /etc/evil.conf"`)
}

// remoteAddrsValues returns every value rendered on a `remote_addrs = `
// line in the swanctl output (one per emitted connection), or an empty
// slice if there are none. It lets the #2074 tests assert specifically
// that a gateway config-object NAME never appears as a remote_addrs
// value (a substring match on the whole config would falsely flag the
// connection-name line).
func remoteAddrsValues(t *testing.T, cfg string) []string {
	t.Helper()
	// #6824: collected from the parsed tree rather than by scanning for a
	// "remote_addrs = " line prefix. Same intent as the old scanner -- read the
	// VALUES so the connection-name line cannot false-flag -- but it now also
	// sees a setting the renderer indented differently, and cannot be fooled by
	// the text appearing inside another value.
	var out []string
	var walk func(*swanctlNode)
	walk = func(n *swanctlNode) {
		out = append(out, n.settings["remote_addrs"]...)
		for _, name := range n.order {
			walk(n.children[name])
		}
	}
	walk(parseSwanctlDoc(t, cfg))
	return out
}

// TestRenderConfig_GatewayNameNeverLeaks exercises #2074: a bare gateway
// config-object NAME must never reach swanctl `remote_addrs`. The render
// belt skips an unrenderable VPN rather than leaking its name; valid
// shapes (defined+addressed gateway, inline IP/FQDN, empty gateway) are
// preserved. These sub-cases fail against pre-fix code, which emitted
// `remote_addrs = <gateway-name>` for the dangling / addressless cases.
func TestRenderConfig_GatewayNameNeverLeaks(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("resolved gateway with address", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"corp-gw": {Name: "corp-gw", Address: "203.0.113.7"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "corp-gw", PSK: "k"},
			},
		}
		got, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		vals := remoteAddrsValues(t, got)
		if len(vals) != 1 || vals[0] != "203.0.113.7" {
			t.Fatalf("remote_addrs = %v, want [203.0.113.7]\n%s", vals, got)
		}
		for _, v := range vals {
			if v == "corp-gw" {
				t.Fatalf("gateway NAME leaked into remote_addrs:\n%s", got)
			}
		}
	})

	t.Run("dangling gateway name is skipped, no leak", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			// "typo-gw" is referenced but never defined, and is not a
			// usable IP / dotted hostname. Benign PSK auth so no other
			// render error path fires (this isolates the leak path).
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "typo-gw", PSK: "k"},
			},
		}
		got, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v (skip should not error)", err)
		}
		if strings.Contains(got, "typo-gw") {
			t.Fatalf("dangling gateway NAME leaked into config:\n%s", got)
		}
		if vals := remoteAddrsValues(t, got); len(vals) != 0 {
			t.Fatalf("expected no remote_addrs, got %v\n%s", vals, got)
		}
		parseSwanctlDoc(t, got).at(t, "secrets").hasNoChild(t, "ike-tun")
	})

	t.Run("addressless gateway is skipped, no leak", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				// Exists but has neither Address nor DynamicHostname.
				"bare-gw": {Name: "bare-gw"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "bare-gw", PSK: "k"},
			},
		}
		got, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if strings.Contains(got, "bare-gw") {
			t.Fatalf("addressless gateway NAME leaked:\n%s", got)
		}
		if vals := remoteAddrsValues(t, got); len(vals) != 0 {
			t.Fatalf("expected no remote_addrs, got %v\n%s", vals, got)
		}
	})

	t.Run("dotless single-label name is skipped", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "vpnpeer", PSK: "k"},
			},
		}
		got, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if vals := remoteAddrsValues(t, got); len(vals) != 0 {
			t.Fatalf("dotless name should be skipped, got remote_addrs %v\n%s", vals, got)
		}
	})

	t.Run("inline literal IP is preserved", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "198.51.100.9", PSK: "k"},
			},
		}
		got, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if vals := remoteAddrsValues(t, got); len(vals) != 1 || vals[0] != "198.51.100.9" {
			t.Fatalf("remote_addrs = %v, want [198.51.100.9]\n%s", vals, got)
		}
	})

	t.Run("inline dotted hostname is preserved", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "peer.example.com", PSK: "k"},
			},
		}
		got, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if vals := remoteAddrsValues(t, got); len(vals) != 1 || vals[0] != "peer.example.com" {
			t.Fatalf("remote_addrs = %v, want [peer.example.com]\n%s", vals, got)
		}
	})

	t.Run("empty gateway emits connection with no remote_addrs", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "", PSK: "k", BindInterface: "st0.0"},
			},
		}
		got, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		parseSwanctlDoc(t, got).at(t, "connections", "tun")
		if vals := remoteAddrsValues(t, got); len(vals) != 0 {
			t.Fatalf("empty gateway should emit no remote_addrs, got %v\n%s", vals, got)
		}
	})

	// Regression guard for the round-2 cold-boot defect: a healthy VPN
	// must still render (and keep its remote_addrs) when a sibling VPN is
	// skipped. Pre-fix / v1-style whole-render-abort would have dropped
	// the healthy tunnel too.
	t.Run("one bad VPN does not zero a healthy sibling", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"good-gw": {Name: "good-gw", Address: "192.0.2.10"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"good": {Gateway: "good-gw", PSK: "k1"},
				"bad":  {Gateway: "missing-gw", PSK: "k2"},
			},
		}
		got, _, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		// #6824: the old needle carried two leading spaces and a trailing
		// newline to approximate "a connection-level section opener" -- an
		// assertion about the renderer's INDENT standing in for one about the
		// tree. Resolving the path says it directly.
		doc := parseSwanctlDoc(t, got)
		doc.at(t, "connections", "good")
		vals := remoteAddrsValues(t, got)
		if len(vals) != 1 || vals[0] != "192.0.2.10" {
			t.Fatalf("healthy remote_addrs = %v, want [192.0.2.10]\n%s", vals, got)
		}
		if strings.Contains(got, "missing-gw") {
			t.Fatalf("bad gateway NAME leaked:\n%s", got)
		}
		doc.at(t, "connections").hasNoChild(t, "bad")
		doc.at(t, "secrets").hasNoChild(t, "ike-bad")
		doc.at(t, "secrets", "ike-good")
	})
}

// TestGenerateConfig_ResponderOnlyGateway is the #2404 fail-on-revert
// guard: a gateway carrying a `dynamic` block with no address and no
// hostname is responder-only — the peer dials in from a dynamic source
// address. The render MUST emit `remote_addrs = %any` so strongSwan
// listens for the inbound IKE instead of skipping the connection.
//
// Counter-factual pin: before #2404, resolveRemoteAddr returned ok=false
// for a gateway with neither Address nor DynamicHostname, so renderConfig
// skipped the VPN entirely (no `dyn {` connection block, no
// `remote_addrs = %any`). Reverting the ResponderOnly handling makes both
// assertions below fail.
func TestGenerateConfig_ResponderOnlyGateway(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"dial-in": {
				Name:          "dial-in",
				ResponderOnly: true,
				LocalAddress:  "203.0.113.5",
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"dyn": {
				Gateway: "dial-in",
				PSK:     "supersecret",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	conn := parseSwanctlDoc(t, got).at(t, "connections", "dyn")
	conn.requireSetting(t, "remote_addrs", "%any")
	conn.requireSetting(t, "local_addrs", "203.0.113.5")
}

// secretsOnly_6824 resolves the document's single secrets block, failing if the
// render produced anything other than exactly one. "Exactly one" is part of the
// claim: with two blocks, a containment assertion could not say which one it
// matched.
func secretsOnly_6824(t *testing.T, doc string) *swanctlNode {
	t.Helper()
	sec := parseSwanctlDoc(t, doc).at(t, "secrets")
	if len(sec.order) != 1 {
		t.Fatalf("expected exactly one secrets block, got %v\n%s", sec.childNames(), sec)
	}
	return sec.at(t, sec.order[0])
}
