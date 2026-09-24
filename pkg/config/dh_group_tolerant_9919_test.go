package config

import (
	"strings"
	"testing"
)

// #9919 F-161 + F-090 config-channel cells.
//
// F-161: an unparseable or unspellable `dh-group` / `keys` value is rejected
// at strict commit (via SchemaValidate AND validateIPsecDHGroupsStrict) and
// WARNS on the tolerant load / peer-sync path (CompileConfigLenient,
// CompileConfigForNodeLenient) instead of silently dropping the modp term.
// F-090: a VPN whose `ipsec-policy` names neither a policy nor a proposal is
// rejected at strict commit and warns on the tolerant path.

func dhWarning9919(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "ipsec dh-group") {
			return true
		}
	}
	return false
}

func espChainWarning9919(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "ipsec policy proposal reference") {
			return true
		}
	}
	return false
}

// TestTolerantDHGroupWarns_9919 pins the tolerant-path voice for every bad-DH
// route: unparseable IKE/ESP values, an unlisted numeric, and a bad PFS value.
// Each must WARN (naming dh-group) without bricking the boot (#1960).
func TestTolerantDHGroupWarns_9919(t *testing.T) {
	t.Run("unparseable ike dh-group", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{
			"set security ike proposal ike-p1 authentication-method pre-shared-keys",
			"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal ike-p1 authentication-algorithm sha-256",
			"set security ike proposal ike-p1 dh-group nonsense",
			"set security ike policy ike-pol proposals ike-p1",
			"set security ike gateway gw1 address 192.0.2.1",
			"set security ike gateway gw1 ike-policy ike-pol",
			"set security ipsec vpn tun1 ike gateway gw1",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile bricked (want warn, not reject): %v", err)
		}
		if prop := cfg.Security.IPsec.IKEProposals["ike-p1"]; prop == nil || prop.DHGroup != 0 || prop.DHGroupInvalidSpec != "nonsense" {
			t.Fatalf("unparseable dh-group not recorded: %+v", prop)
		}
		if !dhWarning9919(cfg.Warnings) {
			t.Errorf("tolerant load warned nothing about dh-group; warnings=%v", cfg.Warnings)
		}
	})

	t.Run("unparseable esp dh-group", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{
			"set security ipsec proposal esp-p2 protocol esp",
			"set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc",
			"set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128",
			"set security ipsec proposal esp-p2 dh-group nonsense",
			"set security ipsec policy ipsec-pol proposals esp-p2",
			"set security ipsec vpn tun1 ike gateway 192.0.2.1",
			"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile bricked: %v", err)
		}
		if !dhWarning9919(cfg.Warnings) {
			t.Errorf("tolerant load warned nothing about dh-group; warnings=%v", cfg.Warnings)
		}
	})

	t.Run("unlisted numeric 99", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{
			"set security ike proposal ike-p1 authentication-method pre-shared-keys",
			"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal ike-p1 authentication-algorithm sha-256",
			"set security ike proposal ike-p1 dh-group 99",
			"set security ike policy ike-pol proposals ike-p1",
			"set security ike gateway gw1 address 192.0.2.1",
			"set security ike gateway gw1 ike-policy ike-pol",
			"set security ipsec vpn tun1 ike gateway gw1",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile bricked: %v", err)
		}
		if !dhWarning9919(cfg.Warnings) {
			t.Errorf("tolerant load of dh-group 99 warned nothing; warnings=%v", cfg.Warnings)
		}
	})

	t.Run("unlisted pfs keys 99", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{
			"set security ipsec proposal esp-p2 protocol esp",
			"set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc",
			"set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128",
			"set security ipsec policy ipsec-pol proposals esp-p2",
			"set security ipsec policy ipsec-pol perfect-forward-secrecy keys 99",
			"set security ipsec vpn tun1 ike gateway 192.0.2.1",
			"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile bricked: %v", err)
		}
		if pol := cfg.Security.IPsec.Policies["ipsec-pol"]; pol == nil || pol.PFSGroup != 0 || pol.PFSGroupInvalidSpec != "99" {
			t.Fatalf("bad PFS value not recorded: %+v", pol)
		}
		if !dhWarning9919(cfg.Warnings) {
			t.Errorf("tolerant load of PFS keys 99 warned nothing; warnings=%v", cfg.Warnings)
		}
	})

	t.Run("negative and zero record", func(t *testing.T) {
		for _, v := range []string{"-5", "0", "group0"} {
			tree := buildTreeFromSet(t, []string{
				"set security ike proposal ike-p1 authentication-method pre-shared-keys",
				"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
				"set security ike proposal ike-p1 authentication-algorithm sha-256",
				"set security ike proposal ike-p1 dh-group " + v,
				"set security ike policy ike-pol proposals ike-p1",
				"set security ike gateway gw1 address 192.0.2.1",
				"set security ike gateway gw1 ike-policy ike-pol",
				"set security ipsec vpn tun1 ike gateway gw1",
			})
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile bricked on %q: %v", v, err)
			}
			if prop := cfg.Security.IPsec.IKEProposals["ike-p1"]; prop == nil || prop.DHGroupInvalidSpec == "" {
				t.Fatalf("dh-group %q left no InvalidSpec (would silently drop the term): %+v", v, prop)
			}
			if !dhWarning9919(cfg.Warnings) {
				t.Errorf("tolerant load of dh-group %q warned nothing; warnings=%v", v, cfg.Warnings)
			}
		}
	})

	t.Run("mixed-version peer sync warns", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{
			"set security ike proposal ike-p1 authentication-method pre-shared-keys",
			"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal ike-p1 authentication-algorithm sha-256",
			"set security ike proposal ike-p1 dh-group 99",
			"set security ike policy ike-pol proposals ike-p1",
			"set security ike gateway gw1 address 192.0.2.1",
			"set security ike gateway gw1 ike-policy ike-pol",
			"set security ipsec vpn tun1 ike gateway gw1",
		})
		cfg, err := CompileConfigForNodeLenient(tree, 0)
		if err != nil {
			t.Fatalf("node-lenient compile bricked a mixed-version peer sync: %v", err)
		}
		if !dhWarning9919(cfg.Warnings) {
			t.Errorf("peer-sync load of dh-group 99 warned nothing; warnings=%v", cfg.Warnings)
		}
	})
}

// TestStrictDHGroupRejects_9919 pins the strict channel end-to-end: every
// bad-DH route is hard-rejected by CompileConfig (schema and/or the new
// validator), each naming the value. Valid groups are the degeneracy
// control: they must compile AND stay silent on both paths.
func TestStrictDHGroupRejects_9919(t *testing.T) {
	badIKE := func(v string) []string {
		return []string{
			"set security ike proposal ike-p1 authentication-method pre-shared-keys",
			"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal ike-p1 authentication-algorithm sha-256",
			"set security ike proposal ike-p1 dh-group " + v,
			"set security ike policy ike-pol proposals ike-p1",
			"set security ike gateway gw1 address 192.0.2.1",
			"set security ike gateway gw1 ike-policy ike-pol",
			"set security ipsec vpn tun1 ike gateway gw1",
			"set security ipsec vpn tun1 bind-interface st0",
		}
	}
	for _, tc := range []struct{ val, want string }{
		{"99", "99"},
		{"nonsense", "nonsense"},
		{"17", "17"},
		{"-5", "-5"},
		{"0", "0"},
	} {
		if _, err := CompileConfig(buildTreeFromSet(t, badIKE(tc.val))); err == nil {
			t.Errorf("strict commit ACCEPTED ike dh-group %q; want rejection naming the value", tc.val)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("strict commit rejected dh-group %q but not naming it: %v", tc.val, err)
		}
	}

	badPFS := func(v string) []string {
		return []string{
			"set security ipsec proposal esp-p2 protocol esp",
			"set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc",
			"set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128",
			"set security ipsec policy ipsec-pol proposals esp-p2",
			"set security ipsec policy ipsec-pol perfect-forward-secrecy keys " + v,
			"set security ipsec vpn tun1 ike gateway 192.0.2.1",
			"set security ipsec vpn tun1 bind-interface st0",
			"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
		}
	}
	for _, v := range []string{"99", "nonsense"} {
		if _, err := CompileConfig(buildTreeFromSet(t, badPFS(v))); err == nil {
			t.Errorf("strict commit ACCEPTED PFS keys %q; want rejection", v)
		}
	}

	// Degeneracy control: valid groups compile on both paths and warn on
	// neither. A gate that rejected everything would satisfy every row above.
	for _, v := range []string{"14", "group14", "group19", "2", "group32"} {
		strict, err := CompileConfig(buildTreeFromSet(t, badIKE(v)))
		if err != nil {
			t.Errorf("strict commit rejected the valid group %q: %v", v, err)
			continue
		}
		if dhWarning9919(strict.Warnings) {
			t.Errorf("strict compile of valid group %q warned about dh-group: %v", v, strict.Warnings)
		}
		lenient, err := CompileConfigLenient(buildTreeFromSet(t, badIKE(v)))
		if err != nil {
			t.Errorf("lenient compile rejected the valid group %q: %v", v, err)
			continue
		}
		if dhWarning9919(lenient.Warnings) {
			t.Errorf("lenient compile of valid group %q warned about dh-group: %v", v, lenient.Warnings)
		}
		if prop := lenient.Security.IPsec.IKEProposals["ike-p1"]; prop == nil || prop.DHGroup == 0 || prop.DHGroupInvalidSpec != "" {
			t.Errorf("valid group %q did not compile cleanly: %+v", v, prop)
		}
	}
}

// TestDHGateIsLenientOnTheTolerantPath_9919 pins #1960 for the new gate: the
// flag must be registered in lenientCompileOpts, or a persisted or
// peer-synced config carrying a bad DH value would fail to load and the node
// would not boot. RED-on-revert: unregister lenientIPsecDHGroup and the
// registration assertion fails (and the lenient cells above start bricking).
func TestDHGateIsLenientOnTheTolerantPath_9919(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike proposal ike-p1 authentication-method pre-shared-keys",
		"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-p1 authentication-algorithm sha-256",
		"set security ike proposal ike-p1 dh-group 99",
		"set security ike policy ike-pol proposals ike-p1",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
	})
	strictCfg, strictErr := CompileConfig(tree)
	_ = strictCfg
	if strictErr == nil {
		t.Fatal("precondition: the fixture must be rejected by the STRICT channel, or the lenient assertion below is vacuous")
	}
	if !lenientCompileOpts().lenientIPsecDHGroup {
		t.Fatal("lenientIPsecDHGroup is NOT registered in the tolerant opt set — a leniently-loaded or peer-synced config carrying a bad DH value would fail to compile and the node would not boot (#1960)")
	}
	if _, err := CompileConfigLenient(tree); err != nil {
		t.Fatalf("lenient compile rejected the bad-DH fixture (want warn): %v", err)
	}
}

// TestDanglingVPNPolicyChain_9919 pins the #9919 F-090 config channel: a VPN
// whose `ipsec-policy` names neither a policy nor a proposal is rejected at
// strict commit and warns (without bricking) on both tolerant arms. Empty
// (no policy authored) stays accepted everywhere: it is the intentional
// default, not a dangling reference.
func TestDanglingVPNPolicyChain_9919(t *testing.T) {
	dangling := []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy does-not-exist",
	}
	if _, err := CompileConfig(buildTreeFromSet(t, dangling)); err == nil {
		t.Error("strict commit ACCEPTED a VPN with a dangling ipsec-policy; want rejection naming vpn+policy")
	} else if !strings.Contains(err.Error(), "tun1") || !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("strict rejection does not name the vpn and policy: %v", err)
	}

	for _, arm := range []struct {
		name    string
		compile func(*ConfigTree) (*Config, error)
	}{
		{"standalone", CompileConfigLenient},
		{"node-aware", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
	} {
		cfg, err := arm.compile(buildTreeFromSet(t, dangling))
		if err != nil {
			t.Errorf("%s: lenient compile bricked a dangling vpn-policy (want warn): %v", arm.name, err)
			continue
		}
		if !espChainWarning9919(cfg.Warnings) {
			t.Errorf("%s: expected an ipsec policy proposal reference warning, got %v", arm.name, cfg.Warnings)
		}
	}

	// Empty-policy control: no ipsec-policy authored is the legitimate
	// default and must compile clean on every channel.
	empty := []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	}
	if _, err := CompileConfig(buildTreeFromSet(t, empty)); err != nil {
		t.Errorf("strict commit rejected a VPN with no ipsec-policy (intentional default): %v", err)
	}
	if cfg, err := CompileConfigLenient(buildTreeFromSet(t, empty)); err != nil {
		t.Errorf("lenient compile rejected a VPN with no ipsec-policy: %v", err)
	} else if espChainWarning9919(cfg.Warnings) {
		t.Errorf("lenient compile warned about an empty (default) ipsec-policy: %v", cfg.Warnings)
	}
}
