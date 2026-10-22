package config

import (
	"strings"
	"testing"
)

// #4313 PR-C — three more PRODUCTION closed-world subtree flips, on top of
// PR-B's destination-NAT then (schema_closedworld_nat_then_4313_test.go).
//
// Each flipped subtree is LEAF-COMPLETE (schema_security.go): every valid
// Junos keyword under it is modeled AND the compiler (compiler_ipsec.go) reads
// exactly that keyword set, so closing the subtree cannot false-reject a valid
// config (the #4191 class the umbrella warns about). An unmodeled keyword (a
// typo, or garbage) under a flipped subtree is now REJECTED at strict commit
// (SchemaValidate) instead of committing clean and being silently dropped by
// the compiler — the #4313 silent-inert bug.
//
//	- security ipsec vpn <v> traffic-selector <ts>: local-ip | remote-ip
//	- security ipsec vpn <v> vpn-monitor:            source-interface |
//	                                                 destination-ip | optimized
//	- security {ike,ipsec} gateway <gw> dead-peer-detection:
//	     always-send | optimized | probe-idle-tunnel | interval | threshold
//
// These tests use the production ParseSetCommand + SetPath + SchemaValidate
// path. Each rejection test is RED on revert of the closedWorld flag: without
// it, SchemaValidate returns nil (open-world silent-accept) and the test fails.

// --- traffic-selector -------------------------------------------------------

// tsSet builds a minimal IPsec VPN traffic-selector whose body is the supplied
// set lines (e.g. "local-ip 10.0.0.0/24", "bogus 1.2.3.4").
func tsSet(bodyLines ...string) []string {
	out := []string{"set security ipsec vpn v1 bind-interface st0.0"}
	for _, l := range bodyLines {
		out = append(out, "set security ipsec vpn v1 traffic-selector ts1 "+l)
	}
	return out
}

// TestClosedWorldTrafficSelector_RejectsUnknownKeyword is the RED-on-revert
// discriminator: an unmodeled keyword under the closed-world traffic-selector
// is rejected at strict commit. On revert of closedWorld the same input is
// silently accepted (SchemaValidate returns nil) and this test fails.
func TestClosedWorldTrafficSelector_RejectsUnknownKeyword(t *testing.T) {
	tree := buildTree(t, tsSet("bogus 10.0.0.0/24"))
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("an unmodeled keyword under the closed-world traffic-selector must be rejected at commit (RED on revert: silently accepted + dropped)")
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the keyword and the closed-world subtree, got: %v", err)
	}
}

// TestClosedWorldTrafficSelector_RejectsTypo is the VALUE of the fix: a
// fat-fingered `local-op` for `local-ip` is caught at commit rather than
// silently ignored — the operator learns the selector prefix would be dropped
// and the wrong crypto proxy-id negotiated.
func TestClosedWorldTrafficSelector_RejectsTypo(t *testing.T) {
	tree := buildTree(t, tsSet("local-op 10.0.0.0/24"))
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("a typo'd traffic-selector leaf (local-op) must be rejected at commit, not silently dropped")
	}
	if !strings.Contains(err.Error(), "local-op") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the typo and the closed-world subtree, got: %v", err)
	}
}

// TestClosedWorldTrafficSelector_AcceptsValid proves no false-reject: every
// valid Junos traffic-selector leaf still commits clean under closed-world,
// both as separate set lines and combined.
func TestClosedWorldTrafficSelector_AcceptsValid(t *testing.T) {
	// each leaf on its own
	for _, leaf := range []string{"local-ip 10.0.0.0/24", "remote-ip 0.0.0.0/0"} {
		tree := buildTree(t, tsSet(leaf))
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("valid traffic-selector leaf %q must commit clean under closed-world, got: %v", leaf, err)
		}
	}
	// both together (the real-world shape)
	tree := buildTree(t, tsSet("local-ip 10.0.0.0/24", "remote-ip 0.0.0.0/0"))
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("a full traffic-selector (local-ip + remote-ip) must commit clean under closed-world, got: %v", err)
	}
}

// --- vpn-monitor ------------------------------------------------------------

func vpnMonitorSet(bodyLines ...string) []string {
	out := []string{"set security ipsec vpn v1 bind-interface st0.0"}
	for _, l := range bodyLines {
		out = append(out, "set security ipsec vpn v1 vpn-monitor "+l)
	}
	return out
}

func TestClosedWorldVPNMonitor_RejectsUnknownKeyword(t *testing.T) {
	tree := buildTree(t, vpnMonitorSet("bogus 1.2.3.4"))
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("an unmodeled keyword under the closed-world vpn-monitor must be rejected at commit (RED on revert)")
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the keyword and the closed-world subtree, got: %v", err)
	}
}

func TestClosedWorldVPNMonitor_RejectsTypo(t *testing.T) {
	tree := buildTree(t, vpnMonitorSet("destintion-ip 1.2.3.4"))
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("a typo'd vpn-monitor leaf (destintion-ip) must be rejected at commit, not silently dropped")
	}
	if !strings.Contains(err.Error(), "destintion-ip") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the typo and the closed-world subtree, got: %v", err)
	}
}

func TestClosedWorldVPNMonitor_AcceptsValid(t *testing.T) {
	for _, leaf := range []string{"source-interface ge-0-0-0", "destination-ip 1.2.3.4", "optimized"} {
		tree := buildTree(t, vpnMonitorSet(leaf))
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("valid vpn-monitor leaf %q must commit clean under closed-world, got: %v", leaf, err)
		}
	}
	tree := buildTree(t, vpnMonitorSet("source-interface ge-0-0-0", "destination-ip 1.2.3.4", "optimized"))
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("a full vpn-monitor stanza must commit clean under closed-world, got: %v", err)
	}
}

// --- dead-peer-detection (both the ike-gateway and ipsec-gateway copies) -----

// dpdSet builds a minimal gateway carrying a dead-peer-detection body. scope is
// "ike" or "ipsec" — both gateway blocks model the identical DPD subtree and
// both are flipped closed-world.
func dpdSet(scope string, bodyLines ...string) []string {
	base := "set security " + scope + " gateway gw1 "
	out := []string{base + "address 198.51.100.1"}
	for _, l := range bodyLines {
		out = append(out, base+"dead-peer-detection "+l)
	}
	return out
}

func TestClosedWorldDeadPeerDetection_RejectsUnknownKeyword(t *testing.T) {
	for _, scope := range []string{"ike", "ipsec"} {
		tree := buildTree(t, dpdSet(scope, "bogus 10"))
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("[%s gateway] an unmodeled keyword under the closed-world dead-peer-detection must be rejected at commit (RED on revert)", scope)
		}
		if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "closed-world") {
			t.Fatalf("[%s gateway] error must name the keyword and the closed-world subtree, got: %v", scope, err)
		}
	}
}

func TestClosedWorldDeadPeerDetection_RejectsTypo(t *testing.T) {
	for _, scope := range []string{"ike", "ipsec"} {
		tree := buildTree(t, dpdSet(scope, "intervl 10"))
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("[%s gateway] a typo'd DPD leaf (intervl) must be rejected at commit, not silently dropped", scope)
		}
		if !strings.Contains(err.Error(), "intervl") || !strings.Contains(err.Error(), "closed-world") {
			t.Fatalf("[%s gateway] error must name the typo and the closed-world subtree, got: %v", scope, err)
		}
	}
}

func TestClosedWorldDeadPeerDetection_AcceptsValid(t *testing.T) {
	for _, scope := range []string{"ike", "ipsec"} {
		// each keyword on its own
		for _, leaf := range []string{"always-send", "optimized", "probe-idle-tunnel", "interval 10", "threshold 5"} {
			tree := buildTree(t, dpdSet(scope, leaf))
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("[%s gateway] valid DPD leaf %q must commit clean under closed-world, got: %v", scope, leaf, err)
			}
		}
		// a real-world tuned stanza
		tree := buildTree(t, dpdSet(scope, "always-send", "interval 10", "threshold 5"))
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("[%s gateway] a tuned dead-peer-detection stanza must commit clean under closed-world, got: %v", scope, err)
		}
	}
}
