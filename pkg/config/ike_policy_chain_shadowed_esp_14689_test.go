package config

import (
	"strings"
	"testing"
)

// #14689 (D10-04): a defined ike-policy whose proposal chain is broken must
// never be rescued by an ESP proposal that happens to share the policy name.
// The strict chain validator, the proposal-agreement check, and the missing-PSK
// gate must all see the authored IKE policy, not the shadowed ESP fallback.

func shadowedESPFallbackCommands(proposals []string, includeVPNSecret bool) []string {
	cmds := []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ike policy ike-pol mode main",
		// An ESP proposal authored under the same name as the ike-policy.
		// Legacy direct-proposal fallback is legitimate only when NO
		// ike-policy of that name was authored.
		"set security ipsec proposal ike-pol protocol esp",
		"set security ipsec proposal ike-pol encryption-algorithm aes-256-cbc",
		"set security ipsec proposal ike-pol authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal ike-pol dh-group group14",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	}
	if len(proposals) == 1 {
		cmds = append(cmds, "set security ike policy ike-pol proposals "+proposals[0])
	} else if len(proposals) > 1 {
		cmds = append(cmds, "set security ike policy ike-pol proposals [ "+strings.Join(proposals, " ")+" ]")
	}
	if includeVPNSecret {
		cmds = append(cmds, "set security ipsec vpn tun1 pre-shared-key fixture-secret")
	}
	return cmds
}

func addIKEProposal14689(authMethod string, lifetime int, name string) []string {
	cmds := []string{
		"set security ike proposal " + name + " authentication-method " + authMethod,
		"set security ike proposal " + name + " encryption-algorithm aes-256-cbc",
		"set security ike proposal " + name + " authentication-algorithm sha-256",
		"set security ike proposal " + name + " dh-group group14",
	}
	if lifetime != 0 {
		cmds = append(cmds, "set security ike proposal "+name+" lifetime-seconds "+itoa14689(lifetime))
	}
	return cmds
}

func itoa14689(v int) string {
	if v == 3600 {
		return "3600"
	}
	if v == 28800 {
		return "28800"
	}
	return "3600"
}

// Variant 1: defined ike-policy with a dangling proposal, shadowed by an ESP
// proposal of the same name. Strict gates must reject the dangling reference;
// they must not treat the ESP entry as rescuing the broken IKE chain.
func TestValidateIKEPolicyChainRejectsShadowedESPFallbackAndConflictingProposals_Dangling(t *testing.T) {
	cmds := shadowedESPFallbackCommands([]string{"does-not-exist"}, true)
	tree := buildTreeFromSet(t, cmds)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a defined ike-policy with a dangling proposal shadowed by a same-named ESP proposal; expected rejection (#14689)")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error %q must name the dangling ike-proposal", err.Error())
	}
	if !strings.Contains(err.Error(), "ike-pol") {
		t.Errorf("error %q must name the ike-policy", err.Error())
	}
}

// Variant 2: defined ike-policy whose resolvable proposals disagree on
// connection-level auth/lifetime, shadowed by an ESP proposal. Even though the
// chain partially resolves, agreement must still be checked over every resolved
// proposal; the shadow must not skip it, and a partially-dangling list must not
// hide the conflict among the resolved entries.
func TestValidateIKEPolicyChainRejectsShadowedESPFallbackAndConflictingProposals_Conflicting(t *testing.T) {
	cmds := shadowedESPFallbackCommands([]string{"prop-psk", "prop-ecdsa"}, true)
	cmds = append(cmds, addIKEProposal14689("pre-shared-keys", 3600, "prop-psk")...)
	cmds = append(cmds, addIKEProposal14689("ecdsa-signatures", 3600, "prop-ecdsa")...)
	tree := buildTreeFromSet(t, cmds)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted conflicting IKE proposals shadowed by a same-named ESP proposal; expected rejection (#14689)")
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Errorf("error %q must report the authentication conflict", err.Error())
	}
}

// Partially-dangling list: [dangling, prop-psk] with no PSK anywhere. The chain
// gate must reject the dangling entry, and the PSK gate must not return false
// on the first dangling entry while the runtime would skip it and resolve
// prop-psk (PSK auth) — either gate firing satisfies commit rejection, but the
// PSK helper itself is pinned directly below.
func TestValidateIKEPolicyChainRejectsPartialDanglingShadowed(t *testing.T) {
	cmds := shadowedESPFallbackCommands([]string{"dangling", "prop-psk"}, false)
	cmds = append(cmds, addIKEProposal14689("pre-shared-keys", 3600, "prop-psk")...)
	tree := buildTreeFromSet(t, cmds)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted [dangling, prop-psk] with no PSK shadowed by a same-named ESP proposal; expected rejection (#14689)")
	}
}

// Direct gate-level pins (independent of which strict gate fires first in
// CompileConfig): the chain validator and the PSK validator must each reject
// the shadowed / partially-dangling shapes on a directly-constructed Config.
func TestIKEChainShadowedESPGatesDirect14689(t *testing.T) {
	mk := func(proposals []string) *Config {
		cfg := &Config{}
		cfg.Security.IPsec = IPsecConfig{
			IKEPolicies: map[string]*IKEPolicy{
				"ike-pol": {Name: "ike-pol", Proposals: proposals},
			},
			IKEProposals: map[string]*IKEProposal{
				"prop-psk":   {Name: "prop-psk", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 3600},
				"prop-ecdsa": {Name: "prop-ecdsa", AuthMethod: "ecdsa-signatures", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14, LifetimeSeconds: 3600},
			},
			Proposals: map[string]*IPsecProposal{
				"ike-pol": {Name: "ike-pol", Protocol: "esp", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
			},
			Gateways: map[string]*IPsecGateway{
				"gw1": {Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"},
			},
			VPNs: map[string]*IPsecVPN{
				"tun1": {Name: "tun1", Gateway: "gw1", BindInterface: "st0"},
			},
		}
		return cfg
	}

	t.Run("chain gate rejects dangling shadowed by ESP", func(t *testing.T) {
		if err := validateIKEPolicyChainReferencesStrict(mk([]string{"does-not-exist"})); err == nil {
			t.Fatal("validateIKEPolicyChainReferencesStrict accepted dangling ike-proposal shadowed by same-named ESP proposal")
		} else if !strings.Contains(err.Error(), "does-not-exist") {
			t.Errorf("error %q must name dangling proposal", err.Error())
		}
	})

	t.Run("chain gate rejects empty-proposals policy shadowed by ESP", func(t *testing.T) {
		if err := validateIKEPolicyChainReferencesStrict(mk(nil)); err == nil {
			t.Fatal("validateIKEPolicyChainReferencesStrict accepted ike-policy with no proposals shadowed by same-named ESP proposal")
		} else if !strings.Contains(err.Error(), "has no proposals configured") {
			t.Errorf("error %q must say no proposals configured", err.Error())
		}
	})

	t.Run("chain gate rejects conflicting resolvable proposals", func(t *testing.T) {
		if err := validateIKEPolicyChainReferencesStrict(mk([]string{"prop-psk", "prop-ecdsa"})); err == nil {
			t.Fatal("validateIKEPolicyChainReferencesStrict accepted conflicting proposals")
		} else if !strings.Contains(err.Error(), "authentication") {
			t.Errorf("error %q must report authentication conflict", err.Error())
		}
	})

	t.Run("chain gate still checks agreement when list is partially dangling", func(t *testing.T) {
		err := validateIKEPolicyChainReferencesStrict(mk([]string{"dangling", "prop-psk", "prop-ecdsa"}))
		if err == nil {
			t.Fatal("validateIKEPolicyChainReferencesStrict accepted partially-dangling conflicting list")
		}
		// Either the dangling entry or the conflict is a valid rejection;
		// the gate must not pass silently.
		if !strings.Contains(err.Error(), "dangling") && !strings.Contains(err.Error(), "authentication") {
			t.Errorf("error %q must name dangling proposal or authentication conflict", err.Error())
		}
	})

	t.Run("PSK gate sees resolved PSK proposal behind a dangling first entry", func(t *testing.T) {
		cfg := mk([]string{"dangling", "prop-psk"})
		if err := validateIPsecPSKPresenceStrict(cfg); err == nil {
			t.Fatal("validateIPsecPSKPresenceStrict accepted [dangling, prop-psk] with no PSK; first-dangling return hid the PSK proposal the runtime resolves")
		} else if !strings.Contains(err.Error(), "no pre-shared key is configured") {
			t.Errorf("error %q must report missing PSK", err.Error())
		}
	})

	t.Run("PSK gate does not need a PSK when every resolved proposal is pubkey behind pubkey-first list", func(t *testing.T) {
		cfg := mk([]string{"prop-ecdsa"})
		if err := validateIPsecPSKPresenceStrict(cfg); err != nil {
			t.Fatalf("validateIPsecPSKPresenceStrict rejected pubkey VPN: %v", err)
		}
	})

	t.Run("legacy fallback still accepted when no ike-policy authored", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.IPsec = IPsecConfig{
			Proposals: map[string]*IPsecProposal{
				"ike-pol": {Name: "ike-pol", Protocol: "esp", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
			},
			Gateways: map[string]*IPsecGateway{
				"gw1": {Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"},
			},
			VPNs: map[string]*IPsecVPN{
				"tun1": {Name: "tun1", Gateway: "gw1", BindInterface: "st0"},
			},
		}
		if err := validateIKEPolicyChainReferencesStrict(cfg); err != nil {
			t.Fatalf("legacy direct-proposal fallback must stay accepted: %v", err)
		}
	})
}
