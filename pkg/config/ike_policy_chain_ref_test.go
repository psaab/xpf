package config

import (
	"strings"
	"testing"
)

// #2270: a gateway naming an ike-policy whose chain cannot resolve made
// resolveIKESettings return an empty proposal, which renderConfig omitted —
// strongSwan then negotiated phase-1 with its compiled-in default set
// instead of the configured crypto (a silent downgrade). The commit-time
// validator validateIKEPolicyChainReferencesStrict hard-rejects the
// dangling reference; the tolerant load / peer-sync paths downgrade it to a
// warning so a previously-committed config still boots.

// (a) commit with a gateway referencing an undefined ike-policy must be
// hard-rejected.
func TestIKEGatewayDanglingPolicyRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy does-not-exist",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a gateway with an undefined ike-policy; expected rejection")
	}
	for _, want := range []string{"gw1", "does-not-exist", "default"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// (b) an ike-policy whose `proposals` reference names no defined
// ike-proposal must be hard-rejected.
func TestIKEPolicyDanglingProposalRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ike policy ike-pol mode main",
		"set security ike policy ike-pol proposals no-such-proposal",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an ike-policy with a dangling proposal reference; expected rejection")
	}
	for _, want := range []string{"ike-pol", "no-such-proposal"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// (b2) an ike-policy that is DEFINED but has no `proposals` leaf at all
// (pol.Proposals == "") must be hard-rejected with a clear "no proposals
// configured" message — not the pre-#2279 "undefined ike-proposal \"\""
// which sent the operator hunting for a proposal literally named "".
func TestIKEPolicyMissingProposalsLeafRejected(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		// ike-pol is defined (mode set) but carries no `proposals` leaf.
		"set security ike policy ike-pol mode main",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an ike-policy with no proposals leaf; expected rejection")
	}
	if !strings.Contains(err.Error(), "has no proposals configured") {
		t.Errorf("error %q must say the ike-policy has no proposals configured", err.Error())
	}
	// The confusing pre-#2279 phrasing must be gone.
	if strings.Contains(err.Error(), `undefined ike-proposal ""`) {
		t.Errorf("error %q still reports the misleading empty-proposal name", err.Error())
	}
	if !strings.Contains(err.Error(), "ike-pol") {
		t.Errorf("error %q must name the offending ike-policy", err.Error())
	}
}

// (b3) the dangling-ike-policy message must NOT assert a single authoring
// stanza: a gateway can be authored under `security ike` OR `security ipsec`
// (#2279). The stanza-agnostic phrasing names both so the operator can find
// the offending gateway regardless of where it was written.
func TestIKEGatewayDanglingPolicyMessageStanzaAgnostic(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy does-not-exist",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a gateway with an undefined ike-policy; expected rejection")
	}
	msg := err.Error()
	// Both candidate stanzas are named so the message is not misleading.
	for _, want := range []string{"security ike", "security ipsec", "gw1", "does-not-exist"} {
		if !strings.Contains(msg, want) {
			t.Errorf("stanza-agnostic message %q missing %q", msg, want)
		}
	}
}

// (c) a fully resolvable chain compiles cleanly and the IKE proposal object
// is present so the renderer emits a non-empty `proposals =` line.
func TestIKEPolicyResolvableChainAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike proposal ike-aes256 authentication-method pre-shared-keys",
		"set security ike proposal ike-aes256 encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-aes256 authentication-algorithm sha-256",
		"set security ike proposal ike-aes256 dh-group group14",
		"set security ike policy ike-pol mode main",
		"set security ike policy ike-pol proposals ike-aes256",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a fully resolvable IKE chain: %v", err)
	}
	pol := cfg.Security.IPsec.IKEPolicies["ike-pol"]
	if pol == nil || len(pol.Proposals) != 1 || pol.Proposals[0] != "ike-aes256" {
		t.Fatalf("ike-policy ike-pol not compiled with proposals=ike-aes256: %+v", pol)
	}
	if _, ok := cfg.Security.IPsec.IKEProposals["ike-aes256"]; !ok {
		t.Fatal("ike-proposal ike-aes256 not compiled")
	}
}

// (d) a gateway with no ike-policy at all is the intentional no-policy case
// (strongSwan defaults are the operator's choice) — it must compile cleanly.
func TestIKEGatewayNoPolicyAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a gateway with no ike-policy: %v", err)
	}
}

// The legacy direct-proposal fallback: a gateway whose ike-policy value is
// itself the NAME of a defined IPsec (Phase 2) proposal renders a non-empty
// proposal via buildIKEProposal, so it must NOT be rejected.
func TestIKEGatewayLegacyDirectProposalAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ipsec proposal direct-prop protocol esp",
		"set security ipsec proposal direct-prop encryption-algorithm aes-256-cbc",
		"set security ipsec proposal direct-prop authentication-algorithm hmac-sha-256-128",
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy direct-prop",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 bind-interface st0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected the legacy direct-proposal ike-policy fallback: %v", err)
	}
}

// An orphan gateway (defined but not referenced by any VPN) with a dangling
// ike-policy never reaches render, so it must not fault — Junos only faults
// a gateway in use.
func TestIKEOrphanGatewayDanglingPolicyAccepted(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		// Healthy referenced tunnel.
		"set security ike proposal ike-aes256 authentication-method pre-shared-keys",
		"set security ike proposal ike-aes256 encryption-algorithm aes-256-cbc",
		"set security ike proposal ike-aes256 authentication-algorithm sha-256",
		"set security ike policy ike-pol proposals ike-aes256",
		"set security ike gateway gw-good address 192.0.2.1",
		"set security ike gateway gw-good ike-policy ike-pol",
		"set security ipsec vpn tun1 ike gateway gw-good",
		"set security ipsec vpn tun1 bind-interface st0",
		// Orphan gateway with a dangling policy, referenced by nothing.
		"set security ike gateway gw-orphan address 192.0.2.2",
		"set security ike gateway gw-orphan ike-policy nonexistent",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig faulted an unreferenced orphan gateway with a dangling ike-policy: %v", err)
	}
}

// Fail-on-revert: a counter-factual that reconstructs the PRE-fix acceptance
// (validator absent) and proves the dangling-ike-policy config WOULD have
// compiled clean. If validateIKEPolicyChainReferencesStrict is ever removed
// from the strict chain, TestIKEGatewayDanglingPolicyRejected starts passing
// without an error — this test documents that the validator is the only thing
// standing between a dangling reference and a silent crypto downgrade.
func TestIKEPolicyChainValidatorIsLoadBearing(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy does-not-exist",
		"set security ipsec vpn tun1 ike gateway gw1",
	})
	// The compiled config (skipping the strict gate) carries the dangling
	// reference. Confirm the gate is what rejects it: without the validator,
	// the gateway resolves but its ike-policy chain does not — the exact
	// fall-through resolveIKESettings used to render as an empty proposal.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must accept the dangling ref (warn): %v", err)
	}
	gw := cfg.Security.IPsec.Gateways["gw1"]
	if gw == nil || gw.IKEPolicy != "does-not-exist" {
		t.Fatalf("expected gateway gw1 carrying the dangling ike-policy reference, got %+v", gw)
	}
	if _, ok := cfg.Security.IPsec.IKEPolicies["does-not-exist"]; ok {
		t.Fatal("test premise broken: ike-policy does-not-exist must NOT be defined")
	}
	// And the strict path MUST reject the same tree.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig accepted the dangling ike-policy; the validator is not wired")
	}
}

// The tolerant load / peer-sync paths (CompileConfigLenient and
// CompileConfigForNodeLenient) downgrade the dangling-reference error to a
// warning so an already-persisted or peer-synced config still boots (#1960
// no-brick).
func TestIKEPolicyChainDanglingLenientDowngrade(t *testing.T) {
	cmds := []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 ike-policy does-not-exist",
		"set security ipsec vpn tun1 ike gateway gw1",
	}

	hasIKEWarning := func(cfg *Config) bool {
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "ike-policy chain reference") {
				return true
			}
		}
		return false
	}

	t.Run("standalone", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildTreeFromSet(t, cmds))
		if err != nil {
			t.Fatalf("CompileConfigLenient hard-failed a dangling ike-policy ref; must downgrade to warning: %v", err)
		}
		if !hasIKEWarning(cfg) {
			t.Errorf("expected an ike-policy chain reference warning, got %v", cfg.Warnings)
		}
	})

	t.Run("node-aware", func(t *testing.T) {
		cfg, err := CompileConfigForNodeLenient(buildTreeFromSet(t, cmds), 0)
		if err != nil {
			t.Fatalf("CompileConfigForNodeLenient hard-failed a dangling ike-policy ref; must downgrade to warning (HA peer-sync): %v", err)
		}
		if !hasIKEWarning(cfg) {
			t.Errorf("expected an ike-policy chain reference warning, got %v", cfg.Warnings)
		}
	})
}
