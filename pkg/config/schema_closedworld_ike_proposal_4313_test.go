package config

import (
	"strings"
	"testing"
)

// #4313 — another PRODUCTION closed-world subtree flip, extending PR-B's
// destination-NAT then and PR-C's IPsec option containers (traffic-selector,
// vpn-monitor, dead-peer-detection) plus #4578's master-password.
//
// The Phase-1 IKE proposal crypto container (`security ike proposal <name>`)
// now sets schemaNode.closedWorld (schema_security.go). Its subtree is
// LEAF-COMPLETE: the full Junos grammar is exactly authentication-method,
// authentication-algorithm, dh-group, encryption-algorithm, lifetime-seconds,
// and description — all modeled — and the compiler (compiler_ipsec.go, the IKE
// proposal loop) reads a strict subset of those (description is cosmetic /
// compiler-ignored). Every leaf carries its value on the same statement line
// (no nested value block in Junos), so closing the subtree cannot false-reject
// a valid config (the #4191 class the umbrella warns about).
//
// Silent-drop here FAILS OPEN on crypto: before the flip a typo in
// `encryption-algorithm` / `authentication-algorithm` committed clean and the
// compiler negotiated the Phase-1 SA WITHOUT the operator's chosen cipher/hash
// — a silent downgrade. The flip REJECTS the typo at strict commit
// (SchemaValidate) instead of committing clean and being silently dropped by
// the compiler — the #4313 silent-inert bug.
//
// These tests use the production ParseSetCommand + SetPath + SchemaValidate
// path (buildTree). Each rejection test is RED on revert of the closedWorld
// flag: without it, SchemaValidate returns nil (open-world silent-accept) and
// the test fails.

// ikeProposalSet builds a minimal IKE proposal whose body is the supplied set
// lines (e.g. "encryption-algorithm aes-256-cbc", "bogus x").
func ikeProposalSet(bodyLines ...string) []string {
	out := []string{}
	for _, l := range bodyLines {
		out = append(out, "set security ike proposal p1 "+l)
	}
	return out
}

// TestClosedWorldIKEProposal_RejectsUnknownKeyword is the core RED-on-revert
// discriminator: an unmodeled keyword under the closed-world IKE proposal is
// rejected at strict commit. On revert of closedWorld the same input is
// silently accepted (SchemaValidate returns nil) and this test fails — proving
// the flip closes the #4313 silent-inert gap.
func TestClosedWorldIKEProposal_RejectsUnknownKeyword(t *testing.T) {
	tree := buildTree(t, ikeProposalSet("bogus aes-256-cbc"))
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("an unmodeled keyword under the closed-world IKE proposal must be rejected at commit (RED on revert: silently accepted + dropped)")
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the keyword and the closed-world subtree, got: %v", err)
	}
}

// TestClosedWorldIKEProposal_RejectsCryptoTypo is the VALUE of the fix: a
// fat-fingered crypto leaf (`encryption-algorith`, `authentication-algoritm`)
// is caught at commit rather than silently ignored — the operator learns the
// chosen cipher/hash would be dropped and the Phase-1 SA silently downgraded.
func TestClosedWorldIKEProposal_RejectsCryptoTypo(t *testing.T) {
	for _, typo := range []string{
		"encryption-algorith aes-256-cbc",
		"authentication-algoritm sha-256",
		"authentication-methid pre-shared-keys",
		"dh-grop group14",
	} {
		tree := buildTree(t, ikeProposalSet(typo))
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("a typo'd IKE proposal crypto leaf %q must be rejected at commit, not silently dropped (crypto fails open)", typo)
		}
		// the first token is the misspelled keyword
		bad := strings.Fields(typo)[0]
		if !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "closed-world") {
			t.Fatalf("error must name the typo %q and the closed-world subtree, got: %v", bad, err)
		}
	}
}

// TestClosedWorldIKEProposal_AcceptsValid proves no false-reject: every valid
// Junos IKE proposal leaf still commits clean under closed-world — each on its
// own AND combined into a fully-specified real-world proposal (the shape the
// existing parser tests use), plus the cosmetic `description` that was modeled
// to make the subtree leaf-complete.
func TestClosedWorldIKEProposal_AcceptsValid(t *testing.T) {
	// each modeled leaf on its own
	for _, leaf := range []string{
		"authentication-method pre-shared-keys",
		"authentication-algorithm sha-256",
		"dh-group group14",
		"encryption-algorithm aes-256-cbc",
		"lifetime-seconds 28800",
		`description "corp phase-1 proposal"`,
	} {
		tree := buildTree(t, ikeProposalSet(leaf))
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("valid IKE proposal leaf %q must commit clean under closed-world, got: %v", leaf, err)
		}
	}
	// a fully-specified proposal (the real-world shape)
	full := buildTree(t, ikeProposalSet(
		"authentication-method pre-shared-keys",
		"authentication-algorithm sha-256",
		"dh-group group14",
		"encryption-algorithm aes-256-cbc",
		"lifetime-seconds 28800",
	))
	if err := SchemaValidate(full); err != nil {
		t.Fatalf("a fully-specified IKE proposal must commit clean under closed-world, got: %v", err)
	}
}

// TestClosedWorldIKEProposal_LenientDoesNotBrick documents the #1960 no-brick
// contract: the closed-world reject is a SchemaValidate error, which the
// tolerant Store.Load / SyncApply ingress downgrades to a warning
// (configstore.compileTreeLenient). At the compile layer the schema gate is
// NOT run — the lenient path is precisely CompileConfigLenient — so a config
// with the typo still COMPILES (the unknown leaf silently dropped, exactly the
// pre-gate behaviour the lenient path preserves) rather than bricking the load.
// This is the strict-reject / lenient-warn split (#1960/#1319): strict commit
// rejects, tolerant load warns-and-continues.
func TestClosedWorldIKEProposal_LenientDoesNotBrick(t *testing.T) {
	typoTree := buildTree(t, append(
		ikeProposalSet("encryption-algorith aes-256-cbc"),
		"set security ike policy pol1 proposals p1",
	))
	// strict gate rejects (the operator commit path)
	if err := SchemaValidate(typoTree); err == nil {
		t.Fatal("precondition: strict SchemaValidate must reject the typo")
	}
	// lenient compile (the Store.Load / SyncApply path) must NOT brick — the
	// compiler silently drops the unknown leaf and produces a config.
	if _, err := CompileConfigLenient(typoTree); err != nil {
		t.Fatalf("the lenient load/peer-sync path must not brick on a closed-world typo (#1960); got: %v", err)
	}
}
