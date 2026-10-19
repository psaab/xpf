package ipsec

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5494: a valid, established VPN whose config becomes UNRENDERABLE on the
// tolerant persisted / peer-synced load path (a broken gateway reference, an
// unresolved ike-policy chain, or a `protocol ah` proposal) is OMITTED from
// the swanctl render, yet `swanctl --load-all` still SUCCEEDS. Before this
// fix Apply diffed the applied set by raw VPN NAME (every VPN map key), so an
// unrenderable-but-still-configured VPN looked unchanged: no removal was
// detected, terminateRemovedConns was not called, and strongSwan's existing
// child SA kept forwarding under stale (now-unloaded) selectors/credentials
// while the apply reported convergence — a security fail-open.
//
// The invariant: after a SUCCESSFUL apply, every forwarding child SA must
// correspond to a connection that was actually RENDERED+LOADED, or be torn
// down. Apply now diffs the EXACT rendered connection set renderConfig
// emitted, so a VPN that dropped out of the render is treated as a removal
// and its live SA is terminated.
//
// This deliberately FLIPS the previous documented-intentional behavior (an
// unrenderable VPN used to keep its SAs to survive TRANSIENT unrenderability).
// The security argument wins for an IPsec appliance: an unrenderable VPN is
// already non-functional for rekey / new-SA establishment, so keeping a stale
// child SA authorized buys no real availability while leaving a compromised /
// mis-synced peer forwarding under old policy.
//
// RED-on-revert: restore the name-keyed diff (diff the raw VPN map keys
// instead of the rendered set) and every terminate assertion below goes RED —
// the unrenderable target's SA is NOT torn (the fail-open this issue closes).

// renderableTwoVPN builds a config with two VPNs ("target" and "sibling"),
// both fully renderable: each names a gateway with a literal address and a
// resolvable ike-policy chain plus a resolvable ESP policy. Per-test callers
// break "target" one skip class at a time and assert "sibling" is untouched.
func renderableTwoVPN() *config.IPsecConfig {
	return &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ikeprop": {
				Name: "ikeprop", AuthMethod: "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ikepol": {Name: "ikepol", Proposals: []string{"ikeprop"}, PSK: config.Secret("ike-psk")},
		},
		Proposals: map[string]*config.IPsecProposal{
			"espprop": {Name: "espprop", Protocol: "esp", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esppol": {Name: "esppol", Proposals: []string{"espprop"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-target":  {Name: "gw-target", Address: "192.0.2.1", IKEPolicy: "ikepol"},
			"gw-sibling": {Name: "gw-sibling", Address: "192.0.2.2", IKEPolicy: "ikepol"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"target":  {PSK: "fixture-secret", Name: "target", Gateway: "gw-target", IPsecPolicy: "esppol"},
			"sibling": {PSK: "fixture-secret", Name: "sibling", Gateway: "gw-sibling", IPsecPolicy: "esppol"},
		},
	}
}

// applyBaselineTwoVPN applies the fully-renderable two-VPN config and asserts
// the baseline invariants: nothing is terminated and no --list-sas probe is
// issued (nothing departed the rendered set). After it returns both
// connections are tracked in prevConnNames and both have live SAs staged.
func applyBaselineTwoVPN(t *testing.T, m *Manager, rec *swanctlRecorder) {
	t.Helper()
	if err := m.Apply(renderableTwoVPN()); err != nil {
		t.Fatalf("baseline Apply: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("baseline Apply must not terminate anything, got %v", got)
	}
	if rec.sawListSAs() {
		t.Fatalf("baseline Apply must not query SAs (nothing departed the render)")
	}
	// Both connections are now up with live child SAs. #15024: the IKE
	// SAs are gateway-named (gw-target/gw-sibling); children keep VPN names.
	rec.listSAs = liveSA("gw-target", "gw-sibling")
}

// assertTargetTornSiblingKept drives Apply(broken) — which must SUCCEED (the
// unrenderable VPN is SKIPPED, not a hard render error) — and asserts exactly
// the unrenderable target's stale SA is torn while the still-renderable
// sibling keeps its SA.
func assertTargetTornSiblingKept(t *testing.T, m *Manager, rec *swanctlRecorder, broken *config.IPsecConfig) {
	t.Helper()
	if err := m.Apply(broken); err != nil {
		t.Fatalf("Apply with an unrenderable VPN must still succeed "+
			"(skip, not hard error): %v", err)
	}
	// #15024: terminate/tracking are connection-keyed (gateway names).
	got := rec.terminateCalls()
	if len(got) != 1 || got[0] != "gw-target" {
		t.Fatalf("the unrenderable target's stale SA must be torn down "+
			"exactly once, got %v", got)
	}
	if m.tracks("gw-target") {
		t.Fatal("gw-target must not remain tracked after it dropped out of the render")
	}
	if !m.tracks("gw-sibling") {
		t.Fatal("the still-renderable sibling must remain tracked (not torn)")
	}
}

// TestUnrenderableGatewayRefTerminatesSA_5494: target's gateway reference
// becomes a dangling single-label (dotless) name, so resolveRemoteAddr skips
// the VPN (#2074) — render succeeds but omits target. Its stale SA is torn.
func TestUnrenderableGatewayRefTerminatesSA_5494(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	applyBaselineTwoVPN(t, m, rec)

	broken := renderableTwoVPN()
	// Dangling, dotless gateway name: not a defined gateway object, not a
	// literal IP / dotted hostname → not a usable endpoint → skipped.
	broken.VPNs["target"].Gateway = "no-such-gateway"

	assertTargetTornSiblingKept(t, m, rec, broken)
}

// TestUnrenderableAddresslessGatewayTerminatesSA_5494: target's gateway
// object exists but loses its address (no address / hostname / responder-only),
// the other #2074 skip branch (resolveRemoteAddr ok=false for a defined-but-
// unroutable gateway). Render succeeds but omits target; its stale SA is torn.
func TestUnrenderableAddresslessGatewayTerminatesSA_5494(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	applyBaselineTwoVPN(t, m, rec)

	broken := renderableTwoVPN()
	broken.Gateways["gw-target"].Address = "" // nothing routable, not responder-only

	assertTargetTornSiblingKept(t, m, rec, broken)
}

// TestUnrenderableIKEChainTerminatesSA_5494: target's gateway names an
// ike-policy whose chain does not resolve, so resolveIKESettings returns
// errIKEChainUnresolved and renderConfig SKIPS target (#2270) rather than emit
// a proposal-less (silently downgraded) connection. Render succeeds but omits
// target; its stale SA is torn.
func TestUnrenderableIKEChainTerminatesSA_5494(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	applyBaselineTwoVPN(t, m, rec)

	broken := renderableTwoVPN()
	// Point target's gateway at an ike-policy that is defined nowhere (no
	// IKEPolicies entry, no legacy Proposals entry) → chain unresolved.
	broken.Gateways["gw-target"].IKEPolicy = "dangling-ikepol"

	assertTargetTornSiblingKept(t, m, rec, broken)
}

// TestUnrenderableAHProposalTerminatesSA_5494: target's ipsec-policy resolves
// to a `protocol ah` proposal, which has no ESP render path, so renderConfig
// SKIPS target (#4298) rather than fabricate an ESP cipher. Render succeeds
// but omits target; its stale SA is torn.
func TestUnrenderableAHProposalTerminatesSA_5494(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	applyBaselineTwoVPN(t, m, rec)

	broken := renderableTwoVPN()
	// Give target an AH proposal/policy; sibling keeps the ESP policy.
	broken.Proposals["ah-prop"] = &config.IPsecProposal{Name: "ah-prop", Protocol: "ah", AuthAlg: "hmac-sha-256-128"}
	broken.Policies["ah-pol"] = &config.IPsecPolicyDef{Name: "ah-pol", Proposals: []string{"ah-prop"}}
	broken.VPNs["target"].IPsecPolicy = "ah-pol"

	assertTargetTornSiblingKept(t, m, rec, broken)
}

// TestReapplyRenderableDoesNotTerminate_5494: re-applying an UNCHANGED,
// fully-renderable config must terminate nothing. This guards against the
// rendered-set diff over-terminating a connection that IS still loaded — the
// precision side of the fix (do not tear SAs for connections still rendered).
func TestReapplyRenderableDoesNotTerminate_5494(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	applyBaselineTwoVPN(t, m, rec)

	if err := m.Apply(renderableTwoVPN()); err != nil {
		t.Fatalf("re-apply of the same renderable config: %v", err)
	}
	if got := rec.terminateCalls(); len(got) != 0 {
		t.Fatalf("re-applying an unchanged renderable config must not terminate, got %v", got)
	}
}

// TestGenuineRemovalStillTerminates_5494: the #3941 behavior is preserved —
// a VPN the operator actually DELETES (absent from the new config entirely)
// still has its live SA torn down. Same teardown path, unchanged.
func TestGenuineRemovalStillTerminates_5494(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	applyBaselineTwoVPN(t, m, rec)

	reduced := renderableTwoVPN()
	delete(reduced.VPNs, "target") // operator deletes target outright

	if err := m.Apply(reduced); err != nil {
		t.Fatalf("delete Apply: %v", err)
	}
	got := rec.terminateCalls()
	if len(got) != 1 || got[0] != "gw-target" {
		t.Fatalf("a genuinely deleted VPN must still be terminated, got %v", got)
	}
}

// TestUnrenderableWithFailedReloadDoesNotTerminate_5494: the #4898 gate is
// preserved on the unrenderable path too. When target becomes unrenderable
// AND `swanctl --load-all` FAILS, the previous config is still the loaded,
// effective one — Apply must return the error, terminate NOTHING, and keep
// prevConnNames so a later successful apply retries the teardown. The
// fail-closed teardown fires only on a SUCCESSFULLY reloaded render.
//
// RED-on-revert (for the #4898 coupling): move promotion/teardown before the
// reload-success gate and this fails — a failed reload would tear the
// still-loaded target.
func TestUnrenderableWithFailedReloadDoesNotTerminate_5494(t *testing.T) {
	reloadErr := errors.New("charon vici socket refused")
	rec := &reloadRecorder{loadErr: reloadErr}
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = rec.run

	if err := m.Apply(renderableTwoVPN()); err != nil {
		t.Fatalf("baseline Apply: %v", err)
	}
	rec.listSAs = liveSA("gw-target", "gw-sibling")

	// target becomes unrenderable, but the reload fails.
	rec.failLoadAll = true
	broken := renderableTwoVPN()
	broken.VPNs["target"].Gateway = "no-such-gateway"
	err := m.Apply(broken)
	if err == nil {
		t.Fatal("Apply must return the swanctl --load-all failure")
	}
	if !errors.Is(err, reloadErr) {
		t.Fatalf("Apply error must wrap the reload error, got %v", err)
	}
	if got := rec.terminated(); len(got) != 0 {
		t.Fatalf("a failed reload must not terminate any connection "+
			"(target is still the loaded, effective config), got %v", got)
	}
	if !m.tracks("gw-target") || !m.tracks("gw-sibling") {
		t.Fatal("prevConnNames must still track both connections after a failed reload " +
			"so a later successful apply retries the teardown")
	}

	// Reload recovers; the same unrenderable apply now tears target's stale SA.
	rec.failLoadAll = false
	if err := m.Apply(broken); err != nil {
		t.Fatalf("recovered Apply: %v", err)
	}
	if got := rec.terminated(); len(got) != 1 || got[0] != "gw-target" {
		t.Fatalf("the recovered apply must terminate the now-unrenderable target, got %v", got)
	}
}
