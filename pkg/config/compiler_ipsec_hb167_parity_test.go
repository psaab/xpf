package config

import (
	"strings"
	"testing"
)

// fable-review-167 IPsec/VPN parity fixes.
//
//	V-1 (#4297): predefined proposal-set expands to concrete proposals so
//	             the common vSRX shorthand commits a working tunnel.
//	V-2 (#4298): `proposal ... protocol ah` is rejected at commit, never
//	             silently rendered as ESP with a fabricated cipher.
//	V-3 (#4299): `vpn-monitor` is accepted with an advisory (not dropped).
//	V-4 (#4300): `manual { ... }` manual-key SA is rejected (no dead tunnel).
//	V-5 (#4301): `establish-tunnels` value is enum-validated.

// resolvedIKE gathers the crypto of every synthetic/real proposal an IKE
// policy references, in order.
func resolvedIKE(t *testing.T, cfg *Config, policy string) []*IKEProposal {
	t.Helper()
	pol := cfg.Security.IPsec.IKEPolicies[policy]
	if pol == nil {
		t.Fatalf("ike policy %q missing after compile", policy)
	}
	var out []*IKEProposal
	for _, ref := range pol.Proposals {
		p := cfg.Security.IPsec.IKEProposals[ref]
		if p == nil {
			t.Fatalf("ike policy %q references unresolvable proposal %q", policy, ref)
		}
		out = append(out, p)
	}
	return out
}

func resolvedESP(t *testing.T, cfg *Config, policy string) []*IPsecProposal {
	t.Helper()
	pol := cfg.Security.IPsec.Policies[policy]
	if pol == nil {
		t.Fatalf("ipsec policy %q missing after compile", policy)
	}
	var out []*IPsecProposal
	for _, ref := range pol.Proposals {
		p := cfg.Security.IPsec.Proposals[ref]
		if p == nil {
			t.Fatalf("ipsec policy %q references unresolvable proposal %q", policy, ref)
		}
		out = append(out, p)
	}
	return out
}

// V-1: `proposal-set standard` on both the IKE and IPsec policy must let a
// full VPN commit AND expand to the Junos-documented concrete proposals.
//
// FAIL-ON-REVERT: without expandIKE/IPsecProposalSets the policies carry no
// resolvable proposal — the gateway -> ike-policy chain fails closed and
// CompileConfig returns an error, so the t.Fatalf below fires (RED). The
// per-member crypto assertions additionally pin the expansion table.
func TestProposalSetStandardExpands_4297(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security ike policy ike-pol proposal-set standard",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec policy esp-pol proposal-set standard",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy esp-pol",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("proposal-set standard must commit a working tunnel, got: %v", err)
	}

	ike := resolvedIKE(t, cfg, "ike-pol")
	if len(ike) != 2 {
		t.Fatalf("IKE standard set = %d proposals, want 2", len(ike))
	}
	if ike[0].EncryptionAlg != "3des-cbc" || ike[0].AuthAlg != "sha1" || ike[0].DHGroup != 2 ||
		ike[0].AuthMethod != "pre-shared-keys" {
		t.Errorf("IKE standard[0] = %+v, want 3des-cbc/sha1/g2/pre-shared-keys", ike[0])
	}
	if ike[1].EncryptionAlg != "aes-128-cbc" || ike[1].AuthAlg != "sha1" || ike[1].DHGroup != 2 {
		t.Errorf("IKE standard[1] = %+v, want aes-128-cbc/sha1/g2", ike[1])
	}

	esp := resolvedESP(t, cfg, "esp-pol")
	if len(esp) != 2 {
		t.Fatalf("ESP standard set = %d proposals, want 2", len(esp))
	}
	if esp[0].Protocol != "esp" || esp[0].EncryptionAlg != "3des-cbc" || esp[0].AuthAlg != "hmac-sha1-96" {
		t.Errorf("ESP standard[0] = %+v, want esp/3des-cbc/hmac-sha1-96", esp[0])
	}
	if esp[1].EncryptionAlg != "aes-128-cbc" || esp[1].AuthAlg != "hmac-sha1-96" {
		t.Errorf("ESP standard[1] = %+v, want aes-128-cbc/hmac-sha1-96", esp[1])
	}
}

// V-1: suiteb-gcm-128 expands to the RFC 6379 Suite-B members (AES-GCM +
// ECDSA + ECP group 19). Compiled without a full VPN chain to avoid
// pubkey/cert prerequisites — expansion is reference-independent.
func TestProposalSetSuiteB128Expands_4297(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ike policy ike-sb proposal-set suiteb-gcm-128",
		"set security ipsec policy esp-sb proposal-set suiteb-gcm-128",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("proposal-set suiteb-gcm-128 must compile, got: %v", err)
	}
	ike := resolvedIKE(t, cfg, "ike-sb")
	if len(ike) != 1 || ike[0].EncryptionAlg != "aes-128-gcm" || ike[0].DHGroup != 19 ||
		ike[0].AuthMethod != "ecdsa-signatures" {
		t.Errorf("IKE suiteb-gcm-128 = %+v, want [aes-128-gcm/g19/ecdsa-signatures]", ike)
	}
	esp := resolvedESP(t, cfg, "esp-sb")
	if len(esp) != 1 || esp[0].EncryptionAlg != "aes-128-gcm" || esp[0].DHGroup != 19 {
		t.Errorf("ESP suiteb-gcm-128 = %+v, want [aes-128-gcm/g19]", esp)
	}
}

// V-1: the `basic` set is DH group 1 in Phase-1 (Junos documents `basic` =
// group1; `compatible`/`standard` are group2). A real vSRX peer with
// `proposal-set basic` offers group1/DES in Phase-1, so offering group2 would
// mismatch the DH group and no proposal would negotiate.
//
// FAIL-ON-REVERT: the old group-2 basic rows make the DHGroup assertions RED.
// The ESP `basic` set carries NO PFS group (0) — Junos `basic` is no-PFS.
func TestProposalSetBasicDHGroup1_4297(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ike policy ike-b proposal-set basic",
		"set security ipsec policy esp-b proposal-set basic",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("proposal-set basic must compile, got: %v", err)
	}
	ike := resolvedIKE(t, cfg, "ike-b")
	if len(ike) != 2 {
		t.Fatalf("IKE basic set = %d proposals, want 2", len(ike))
	}
	if ike[0].EncryptionAlg != "des-cbc" || ike[0].AuthAlg != "sha1" || ike[0].DHGroup != 1 {
		t.Errorf("IKE basic[0] = %+v, want des-cbc/sha1/g1 (Junos basic is DH group 1)", ike[0])
	}
	if ike[1].EncryptionAlg != "des-cbc" || ike[1].AuthAlg != "md5" || ike[1].DHGroup != 1 {
		t.Errorf("IKE basic[1] = %+v, want des-cbc/md5/g1", ike[1])
	}
	// ESP basic is no-PFS (DHGroup 0) with DES + SHA1/MD5.
	esp := resolvedESP(t, cfg, "esp-b")
	if len(esp) != 2 {
		t.Fatalf("ESP basic set = %d proposals, want 2", len(esp))
	}
	for i, p := range esp {
		if p.EncryptionAlg != "des-cbc" || p.DHGroup != 0 {
			t.Errorf("ESP basic[%d] = %+v, want des-cbc + no PFS (DHGroup 0)", i, p)
		}
	}
	if esp[0].AuthAlg != "hmac-sha1-96" || esp[1].AuthAlg != "hmac-md5-96" {
		t.Errorf("ESP basic auth = %q/%q, want hmac-sha1-96/hmac-md5-96", esp[0].AuthAlg, esp[1].AuthAlg)
	}
}

// V-1: an explicit proposals list wins over proposal-set (mutually exclusive
// in Junos; the set only fills an empty list).
func TestProposalSetYieldsToExplicitProposals_4297(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ike proposal ike-x authentication-method pre-shared-keys",
		"set security ike proposal ike-x encryption-algorithm aes-256-cbc",
		"set security ike policy ike-pol proposal-set standard",
		"set security ike policy ike-pol proposals ike-x",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pol := cfg.Security.IPsec.IKEPolicies["ike-pol"]
	if len(pol.Proposals) != 1 || pol.Proposals[0] != "ike-x" {
		t.Errorf("explicit proposals must win over proposal-set, got %v", pol.Proposals)
	}
}

// V-1: an unknown proposal-set keyword is rejected at commit by the schema
// enum (SchemaValidate). FAIL-ON-REVERT: an untyped leaf stores the typo and
// returns nil.
func TestProposalSetUnknownRejected_4297(t *testing.T) {
	tree := flatTreeFromSets(t, "set security ike policy ike-pol proposal-set standrd")
	if err := SchemaValidate(tree, nil); err == nil ||
		!strings.Contains(err.Error(), "standrd") {
		t.Fatalf("unknown proposal-set must be rejected naming the typo, got: %v", err)
	}
	// every supported keyword still commits
	for _, s := range ProposalSetNames() {
		ok := flatTreeFromSets(t, "set security ipsec policy p proposal-set "+s)
		if err := SchemaValidate(ok, nil); err != nil {
			t.Errorf("proposal-set %q rejected: %v", s, err)
		}
	}
}

// V-2: `proposal ... protocol ah` must be REJECTED at commit — never
// silently rendered as ESP with a fabricated cipher.
//
// FAIL-ON-REVERT: without validateIPsecProposalProtocolStrict the AH proposal
// compiles clean (protocol captured, ignored) and CompileConfig returns nil,
// so the expect-error below fires RED. The render belt is covered in pkg/ipsec.
func TestProtocolAHRejected_4298(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ipsec proposal AHPROP protocol ah",
		"set security ipsec proposal AHPROP authentication-algorithm hmac-sha-256-128",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("protocol ah must be rejected at commit (never silent ESP substitution)")
	}
	if !strings.Contains(err.Error(), "AHPROP") || !strings.Contains(err.Error(), "ah") {
		t.Errorf("reject error should name the AH proposal, got: %v", err)
	}
	// Tolerant path downgrades to a warning so a persisted/peer-synced config
	// still boots (the render belt keeps the fabricated ESP tunnel out).
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile of protocol ah must warn, not error: %v", lerr)
	}
	if !warningsContain(cfg.Warnings, "protocol") {
		t.Errorf("lenient path should warn about the AH proposal, warnings: %v", cfg.Warnings)
	}
}

// V-3: `vpn-monitor` is accepted (committed) with an advisory, not dropped.
func TestVPNMonitorAdvisory_4299(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone untrust",
		"set security ike policy ike-pol proposal-set standard",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec policy esp-pol proposal-set standard",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 ike ipsec-policy esp-pol",
		"set security ipsec vpn tun1 vpn-monitor source-interface ge-0/0/0",
		"set security ipsec vpn tun1 vpn-monitor destination-ip 172.16.0.1",
		"set security ipsec vpn tun1 vpn-monitor optimized",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("vpn-monitor must be accepted, got: %v", err)
	}
	vpn := cfg.Security.IPsec.VPNs["tun1"]
	if vpn == nil || !vpn.VPNMonitor || !vpn.VPNMonitorOptimized ||
		vpn.VPNMonitorSourceInterface != "ge-0/0/0" || vpn.VPNMonitorDestinationIP != "172.16.0.1" {
		t.Errorf("vpn-monitor fields not captured: %+v", vpn)
	}
	if !warningsContain(ValidateConfig(cfg), "vpn-monitor") {
		t.Errorf("vpn-monitor should raise an accepted-but-not-enforced advisory, got: %v", ValidateConfig(cfg))
	}
}

// V-4: a `manual { ... }` manual-key SA must be rejected at commit — no
// silent dead tunnel.
//
// FAIL-ON-REVERT: without validateIPsecManualKeyStrict the manual block is
// dropped silently and the VPN compiles to an empty shell (CompileConfig ==
// nil error), so the expect-error below fires RED.
func TestManualKeyRejected_4300(t *testing.T) {
	tree := buildTree(t, []string{
		"set security ipsec vpn tun1 manual protocol esp",
		"set security ipsec vpn tun1 manual spi 256",
		"set security ipsec vpn tun1 bind-interface st0",
		"set security ipsec vpn tun1 manual encryption-algorithm aes-256-cbc",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("manual-key SA must be rejected at commit (no silent dead tunnel)")
	}
	if !strings.Contains(err.Error(), "tun1") || !strings.Contains(err.Error(), "manual") {
		t.Errorf("reject error should name the vpn + manual, got: %v", err)
	}
	cfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile of manual-key must warn, not error: %v", lerr)
	}
	if !warningsContain(cfg.Warnings, "manual") {
		t.Errorf("lenient path should warn about the manual-key SA, warnings: %v", cfg.Warnings)
	}
}

// V-5: `establish-tunnels` is enum-validated. A typo is rejected; every valid
// mode commits.
//
// FAIL-ON-REVERT: the untyped leaf accepts any string and SchemaValidate
// returns nil for the typo.
func TestEstablishTunnelsEnum_4301(t *testing.T) {
	bad := flatTreeFromSets(t, "set security ipsec vpn tun1 establish-tunnels on-tarffic")
	if err := SchemaValidate(bad, nil); err == nil || !strings.Contains(err.Error(), "on-tarffic") {
		t.Fatalf("establish-tunnels typo must be rejected naming the value, got: %v", err)
	}
	for _, m := range []string{"immediately", "on-traffic", "responder-only"} {
		ok := flatTreeFromSets(t, "set security ipsec vpn tun1 establish-tunnels "+m)
		if err := SchemaValidate(ok, nil); err != nil {
			t.Errorf("establish-tunnels %q rejected: %v", m, err)
		}
	}
}
