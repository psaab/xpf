package ipsec

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9919 F-161 render cells: a VPN whose EFFECTIVE Diffie-Hellman group is
// unusable (unparseable token, present-but-empty leaf, or a numeric group the
// renderer cannot spell) SKIPS rather than silently drop its modp term or
// render an empty keyword charon refuses. The commit-time gate
// (validateIPsecDHGroupsStrict) rejects these up front; these cells pin the
// render belt for the tolerant load / peer-sync path and directly-constructed
// configs.

// TestUnlistedDHGroupSkipsVPN_9919 pins the skip for each unspellable-numeric
// route: an ESP proposal DH, the real-but-omitted group 17, an IKE proposal
// DH, and a policy PFS group. On revert (no DH check) every subtest renders
// a trailing-dash proposal and goes RED.
func TestUnlistedDHGroupSkipsVPN_9919(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), configPath: t.TempDir() + "/xpf.conf"}

	t.Run("ESP proposal 99", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 99},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with ESP dh-group 99 was rendered; want skip.\n%s", got)
		}
		parseSwanctlDoc(t, got).at(t, "connections").hasNoChild(t, "tun1")
	})

	t.Run("ESP real-but-omitted 17", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 17},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with omitted group 17 was rendered; want skip.\n%s", got)
		}
	})

	t.Run("IKE proposal 99", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			IKEProposals: map[string]*config.IKEProposal{
				"ike-p1": {Name: "ike-p1", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 99, AuthMethod: "pre-shared-keys"},
			},
			IKEPolicies: map[string]*config.IKEPolicy{
				"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-p1"}},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw1": {Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "gw1"},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig must skip, not abort, on a bad IKE DH group: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with IKE dh-group 99 was rendered; want skip.\n%s", got)
		}
	})

	t.Run("PFS 99", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", PFSGroup: 99, Proposals: []string{"esp-p2"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with PFS group 99 was rendered; want skip.\n%s", got)
		}
	})

	t.Run("negative group skips", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: -5},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with dh-group -5 was rendered (modp term silently omitted); want skip.\n%s", got)
		}
	})

	t.Run("recorded InvalidSpec skips", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroupInvalidSpec: "nonsense"},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with unparseable dh-group was rendered (PFS silently dropped); want skip.\n%s", got)
		}
	})
}

// TestPFSEffectiveGroupOnly_9919 pins the PFS-override rule: the policy PFS
// group replaces each proposal's dh-group in buildESPProposal, so only the
// EFFECTIVE group is judged. A good PFS renders despite bad proposal DH
// (the overridden terms are inert); a bad PFS skips despite good proposal
// DH (no silent fallback to a group the operator did not choose for PFS).
func TestPFSEffectiveGroupOnly_9919(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), configPath: t.TempDir() + "/xpf.conf"}

	t.Run("good PFS overrides bad proposal DH", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 99},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", PFSGroup: 14, Proposals: []string{"esp-p2"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["tun1"] {
			t.Fatalf("VPN with good PFS 14 was skipped over an overridden bad proposal DH; want render.\n%s", got)
		}
		childSA_3904(t, got, "tun1").requireSetting(t, "esp_proposals", "aes256-sha256-modp2048")
	})

	t.Run("bad PFS poisons good proposal DH", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", PFSGroup: 99, Proposals: []string{"esp-p2"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with bad PFS 99 was rendered (PFS intent silently discarded); want skip.\n%s", got)
		}
	})
}

// TestPartialDHListRendersGoodEntries_9919 pins #3904 ANY-semantics for DH:
// a bad-DH entry drops from a multi-proposal list like a dangling reference,
// and only when NOTHING remains renderable does the VPN skip.
func TestPartialDHListRendersGoodEntries_9919(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), configPath: t.TempDir() + "/xpf.conf"}

	t.Run("IKE good+bad renders good only", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			IKEProposals: map[string]*config.IKEProposal{
				"ike-good": {Name: "ike-good", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14, AuthMethod: "pre-shared-keys"},
				"ike-bad":  {Name: "ike-bad", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 99, AuthMethod: "pre-shared-keys"},
			},
			IKEPolicies: map[string]*config.IKEPolicy{
				"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-good", "ike-bad"}},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw1": {Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "gw1"},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["tun1"] {
			t.Fatalf("VPN with one good + one bad IKE proposal was skipped; want the good entry rendered.\n%s", got)
		}
		parseSwanctlDoc(t, got).at(t, "connections", "tun1").requireSetting(t, "proposals", "aes256-sha256-modp2048")
	})

	t.Run("IKE bad+bad skips", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			IKEProposals: map[string]*config.IKEProposal{
				"ike-bad1": {Name: "ike-bad1", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 99, AuthMethod: "pre-shared-keys"},
				"ike-bad2": {Name: "ike-bad2", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 33, AuthMethod: "pre-shared-keys"},
			},
			IKEPolicies: map[string]*config.IKEPolicy{
				"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-bad1", "ike-bad2"}},
			},
			Gateways: map[string]*config.IPsecGateway{
				"gw1": {Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "gw1"},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig must skip, not abort: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with only bad-DH IKE proposals was rendered; want skip.\n%s", got)
		}
	})

	t.Run("ESP good+bad renders good only", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-good": {Name: "esp-good", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
				"esp-bad":  {Name: "esp-bad", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 99},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-good", "esp-bad"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if !rendered["tun1"] {
			t.Fatalf("VPN with one good + one bad ESP proposal was skipped; want the good entry rendered.\n%s", got)
		}
		childSA_3904(t, got, "tun1").requireSetting(t, "esp_proposals", "aes256-sha256-modp2048")
	})

	t.Run("ESP bad+bad skips", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "ipsec-pol"},
			},
			Proposals: map[string]*config.IPsecProposal{
				"esp-bad1": {Name: "esp-bad1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 99},
				"esp-bad2": {Name: "esp-bad2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroupInvalidSpec: "nonsense"},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-bad1", "esp-bad2"}},
			},
		}
		got, rendered, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig: %v", err)
		}
		if rendered["tun1"] {
			t.Errorf("VPN with only bad-DH ESP proposals was rendered; want skip.\n%s", got)
		}
	})
}

// TestBadDHSkipsLeavesHealthySibling_9919 is the one-bad-reference rule for
// DH: a skipped bad-DH VPN never zeroes a healthy tunnel, and the skip
// resolves through the sentinel (not a whole-render abort).
func TestBadDHSkipsLeavesHealthySibling_9919(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), configPath: t.TempDir() + "/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"bad":     {Gateway: "172.16.0.1", IPsecPolicy: "bad-pol"},
			"healthy": {Gateway: "172.16.0.2", IPsecPolicy: "good-pol"},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-bad":  {Name: "esp-bad", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 99},
			"esp-good": {Name: "esp-good", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"bad-pol":  {Name: "bad-pol", Proposals: []string{"esp-bad"}},
			"good-pol": {Name: "good-pol", Proposals: []string{"esp-good"}},
		},
	}
	got, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	if rendered["bad"] {
		t.Errorf("bad-DH VPN was rendered; want skip.\n%s", got)
	}
	if !rendered["healthy"] {
		t.Errorf("healthy sibling was dropped alongside the bad-DH VPN; want it rendered.\n%s", got)
	}
	childSA_3904(t, got, "healthy").requireSetting(t, "esp_proposals", "aes256-sha256-modp2048")
}

// TestResolveDHGroupsReturnSkipSentinels_9919 pins the resolver-level
// contract: bad DH surfaces as errDHGroupUnresolved (skip-class), distinct
// from errESPChainUnresolved / errIKEChainUnresolved (dangling) and from
// hard errors (abort-class).
func TestResolveDHGroupsReturnSkipSentinels_9919(t *testing.T) {
	t.Run("ESP bad DH", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			Proposals: map[string]*config.IPsecProposal{
				"esp-p2": {Name: "esp-p2", DHGroup: 99},
			},
			Policies: map[string]*config.IPsecPolicyDef{
				"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}},
			},
		}
		_, _, err := resolveESPSettings(cfg, &config.IPsecVPN{IPsecPolicy: "ipsec-pol"})
		if !errors.Is(err, errDHGroupUnresolved) {
			t.Fatalf("bad ESP DH must return errDHGroupUnresolved, got %v", err)
		}
	})

	t.Run("IKE bad DH", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			IKEProposals: map[string]*config.IKEProposal{
				"ike-p1": {Name: "ike-p1", DHGroup: 99, AuthMethod: "pre-shared-keys"},
			},
			IKEPolicies: map[string]*config.IKEPolicy{
				"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-p1"}},
			},
		}
		gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"}
		_, _, _, _, err := resolveIKESettings(cfg, gw)
		if !errors.Is(err, errDHGroupUnresolved) {
			t.Fatalf("bad IKE DH must return errDHGroupUnresolved, got %v", err)
		}
	})

	t.Run("IKE legacy bad DH", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			Proposals: map[string]*config.IPsecProposal{
				"legacy": {Name: "legacy", DHGroup: 99},
			},
		}
		gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1", IKEPolicy: "legacy"}
		_, _, _, _, err := resolveIKESettings(cfg, gw)
		if !errors.Is(err, errDHGroupUnresolved) {
			t.Fatalf("bad legacy-proposal DH must return errDHGroupUnresolved, got %v", err)
		}
	})
}

// TestNoRandTimeEmitted_9919 is the #9919 F-163 contract: rekey_time is
// emitted WITHOUT rand_time on both the IKE connection and the ESP child,
// so strongSwan's default rekey jitter (rand_time = over_time = 10% of
// rekey_time) applies and co-timed tunnels do not rekey together.
func TestNoRandTimeEmitted_9919(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), configPath: t.TempDir() + "/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {Name: "ike-p1", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 28800, AuthMethod: "pre-shared-keys"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol1": {Name: "pol1", Proposals: []string{"ike-p1"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "pol1"},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", LifetimeSeconds: 3600},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p2"}},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", IPsecPolicy: "ipsec-pol"},
		},
	}
	got := m.generateConfig(cfg)
	doc := parseSwanctlDoc(t, got)
	doc.at(t, "connections", "tun").requireSetting(t, "rekey_time", "28800s")
	doc.at(t, "connections", "tun").hasNoSetting(t, "rand_time")
	child := childSA_3904(t, got, "tun")
	child.requireSetting(t, "rekey_time", "3600s")
	child.hasNoSetting(t, "rand_time")
	doc.hasNoSettingAnywhere(t, "rand_time")
}
