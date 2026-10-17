package config

import (
	"strings"
	"testing"
)

// #14588 (Y09-01): an IKE proposal with NO dh-group passed strict commit
// but rendered `aes256-sha256` — a proposal with no key-exchange method
// that strongSwan 6.1.0 refuses ("invalid value for: proposals, config
// discarded, loaded 0 of 1"). The value gate
// (validateIPsecDHGroupsStrict) only sees present-but-bad values; an
// absent dh-group (DHGroup 0, no InvalidSpec) was invisible to it.
//
// The fix: validateIPsecIkeDHGroupsPresentStrict walks VPN -> gateway ->
// ike-policy -> ike-proposal (plus the legacy direct-proposal fallback)
// and rejects a DH-less IKE proposal referenced by a rendered VPN at
// strict commit, warns on the tolerant path, and the renderer skips the
// VPN (pkg/ipsec). ESP proposals with no dh-group are NOT judged: ESP
// without a DH term is a valid no-PFS suite.

func ikeMissingDHFixture14588() []string {
	return []string{
		"set security ike proposal ike-p1 authentication-method pre-shared-keys",
		"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-p1 authentication-algorithm sha-256",
		// no dh-group
		"set security ike policy ike-pol proposals ike-p1",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	}
}

func withDH14588(lines []string, dh string) []string {
	out := append([]string{}, lines...)
	// Insert the dh-group line after the encryption-algorithm line.
	for i, l := range out {
		if strings.Contains(l, "encryption-algorithm") {
			out = append(out[:i+1:i+1], out[i:]...)
			out[i+1] = "set security ike proposal ike-p1 dh-group " + dh
			break
		}
	}
	return out
}

// TestStrictRejectsIKEProposalNoDHGroup14588 is the decisive acceptance
// cell from the issue: CheckText / strict compile must reject an IKE
// proposal referenced by a rendered VPN with no dh-group, and the
// message must name `dh-group`.
//
// RED on origin/master: strict compile accepted the fixture (commitErr
// = <nil>, rendered `aes256-sha256`). GREEN after the fix.
func TestStrictRejectsIKEProposalNoDHGroup14588(t *testing.T) {
	_, err := CompileConfig(buildTreeFromSet(t, ikeMissingDHFixture14588()))
	if err == nil {
		t.Fatal("strict commit ACCEPTED an IKE proposal with no dh-group referenced by a rendered VPN; " +
			"it renders `aes256-sha256` (no key-exchange method) and strongSwan refuses the whole file " +
			"(\"invalid value for: proposals, config discarded, loaded 0 of 1\") — the #7165 commit=>loadable breach")
	}
	if !strings.Contains(err.Error(), "dh-group") {
		t.Errorf("rejection does not name dh-group: %v", err)
	}
	if !strings.Contains(err.Error(), "ike-p1") {
		t.Errorf("rejection does not name the proposal: %v", err)
	}
}

// TestStrictRejectsLegacyIKEProposalNoDHGroup14588 covers the legacy
// direct-proposal fallback: the gateway's ike-policy value names an
// IPsec proposal rendered as IKE (resolveIKESettings' fallback). A
// DH-less proposal there renders the same unloadable IKE proposal.
func TestStrictRejectsLegacyIKEProposalNoDHGroup14588(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ipsec proposal esp-legacy protocol esp",
		"set security ipsec proposal esp-legacy encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp-legacy authentication-algorithm hmac-sha-256-128",
		// no dh-group; esp-legacy is named as the gateway's ike-policy
		"set security ipsec policy ipsec-pol proposals esp-legacy",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy esp-legacy",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("strict commit ACCEPTED a DH-less IPsec proposal referenced as the IKE proposal via the legacy fallback")
	}
	if !strings.Contains(err.Error(), "dh-group") {
		t.Errorf("rejection does not name dh-group: %v", err)
	}
}

// TestValidDHGroupsStillCompile14588 is the cited control from the
// issue probe: `dh-group group14` (and other valid spellings) must keep
// compiling on both paths and warn on neither. A gate that rejected
// everything would satisfy the rejection cells above.
func TestValidDHGroupsStillCompile14588(t *testing.T) {
	for _, dh := range []string{"group14", "14", "group19", "2", "group32"} {
		strict, err := CompileConfig(buildTreeFromSet(t, withDH14588(ikeMissingDHFixture14588(), dh)))
		if err != nil {
			t.Errorf("strict commit rejected the valid dh-group %q: %v", dh, err)
			continue
		}
		for _, w := range strict.Warnings {
			if strings.Contains(w, "dh-group") {
				t.Errorf("strict compile of valid dh-group %q warned: %q", dh, w)
			}
		}
		if prop := strict.Security.IPsec.IKEProposals["ike-p1"]; prop == nil || prop.DHGroup == 0 || prop.DHGroupInvalidSpec != "" {
			t.Errorf("valid dh-group %q did not compile to a DH group: %+v", dh, prop)
		}
		lenient, err := CompileConfigLenient(buildTreeFromSet(t, withDH14588(ikeMissingDHFixture14588(), dh)))
		if err != nil {
			t.Errorf("lenient compile rejected the valid dh-group %q: %v", dh, err)
			continue
		}
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "dh-group") {
				t.Errorf("lenient compile of valid dh-group %q warned: %q", dh, w)
			}
		}
	}
}

// TestBadDHGroupStillRejected14588 is the second cited control: an
// invalid dh-group (group99) must keep being rejected, naming the
// value. The missing-DH gate must not swallow or replace the value gate.
func TestBadDHGroupStillRejected14588(t *testing.T) {
	_, err := CompileConfig(buildTreeFromSet(t, withDH14588(ikeMissingDHFixture14588(), "group99")))
	if err == nil {
		t.Fatal("strict commit ACCEPTED dh-group group99 (the pre-existing control); want rejection")
	}
	if !strings.Contains(err.Error(), "99") {
		t.Errorf("rejection of group99 does not name the value: %v", err)
	}
}

// TestTolerantWarnsIKEProposalNoDHGroup14588 pins the #1960 doctrine for
// the new gate: a persisted or peer-synced DH-less IKE proposal must
// still BOOT (warn, not reject) on both tolerant arms, and the warning
// must name dh-group so the operator (not charon) is the diagnostic.
func TestTolerantWarnsIKEProposalNoDHGroup14588(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{
		{"CompileConfigLenient", CompileConfigLenient},
		{"CompileConfigForNodeLenient", func(tr *ConfigTree) (*Config, error) { return CompileConfigForNodeLenient(tr, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.fn(buildTreeFromSet(t, ikeMissingDHFixture14588()))
			if err != nil {
				t.Fatalf("%s bricked a DH-less IKE proposal (want warn, not reject): %v", tc.name, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "dh-group") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s warned nothing about the missing dh-group; warnings=%v", tc.name, cfg.Warnings)
			}
			if prop := cfg.Security.IPsec.IKEProposals["ike-p1"]; prop == nil || prop.DHGroup != 0 || prop.DHGroupInvalidSpec != "" {
				t.Errorf("fixture did not compile to a DH-less proposal (DHGroup=%+v); the test would be vacuous", prop)
			}
		})
	}
}

// TestMissingDHGateIsLenientOnTolerantPath14588 pins the lenient flag
// registration: without it a persisted DH-less config would fail to
// load and the node would not boot. RED on revert (flag unregistered).
func TestMissingDHGateIsLenientOnTolerantPath14588(t *testing.T) {
	if !lenientCompileOpts().lenientIKEProposalMissingDH {
		t.Fatal("lenientIKEProposalMissingDH is NOT registered in the tolerant opt set — a leniently-loaded or peer-synced config carrying a DH-less IKE proposal would fail to compile and the node would not boot (#1960)")
	}
}

// TestOrphanIKEProposalNoDHGroupAccepted14588 pins the scope boundary:
// an IKE proposal no rendered VPN references never reaches charon, so
// strict commit must NOT reject it. Over-broad rejection here would
// break configs that carry an unused template proposal.
func TestOrphanIKEProposalNoDHGroupAccepted14588(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike proposal orphan authentication-method pre-shared-keys",
		"set security ike proposal orphan encryption-algorithm aes-256-cbc",
		"set security ike proposal orphan authentication-algorithm sha-256",
		// no dh-group, and no policy/gateway/VPN references orphan
		"set security ike proposal good authentication-method pre-shared-keys",
		"set security ike proposal good encryption-algorithm aes-256-cbc",
		"set security ike proposal good authentication-algorithm sha-256",
		"set security ike proposal good dh-group group14",
		"set security ike policy ike-pol proposals good",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("strict commit rejected an orphan DH-less IKE proposal that no VPN renders: %v", err)
	}
}

// TestESPNoDHGroupStillAccepted14588 pins the other scope boundary: an
// ESP proposal with no dh-group is a valid no-PFS suite (Junos `basic`
// ESP set) and must keep committing — only IKE proposals require a DH
// term.
func TestESPNoDHGroupStillAccepted14588(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ipsec proposal esp-p2 protocol esp",
		"set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128",
		// no dh-group: legitimate no-PFS ESP
		"set security ipsec policy ipsec-pol proposals esp-p2",
		"set security ike proposal ike-p1 authentication-method pre-shared-keys",
		"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-p1 authentication-algorithm sha-256",
		"set security ike proposal ike-p1 dh-group group14",
		"set security ike policy ike-pol proposals ike-p1",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy ipsec-pol",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("strict commit rejected an ESP proposal with no dh-group (valid no-PFS): %v", err)
	}
}

// TestProposalSetIKEStillAccepted14588: a policy using `proposal-set`
// expands to synthetic proposals that all carry a DH group, so the
// referenced-proposal walk must see them (expansion runs before the
// uniform gates) and accept.
func TestProposalSetIKEStillAccepted14588(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike policy ike-pol proposal-set standard",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("strict commit rejected an IKE policy using proposal-set standard (synthetic proposals carry DH groups): %v", err)
	}
}
