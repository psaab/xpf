package config

import (
	"strings"
	"testing"
)

// #4313 — another PRODUCTION closed-world subtree flip: the Phase-2 ESP
// crypto container `security ipsec proposal <name>`, the sibling of the
// already-closed Phase-1 `security ike proposal`.
//
// The subtree is LEAF-COMPLETE: the full Junos grammar is exactly protocol,
// encryption-algorithm, authentication-algorithm, dh-group, lifetime-seconds,
// lifetime-kilobytes, and description. The first five were already modeled;
// this change modeled lifetime-kilobytes (the ESP volume-rekey knob that
// distinguishes the Phase-2 proposal from the Phase-1 IKE proposal — Phase-1
// has none) and the cosmetic description, so a valid proposal carrying either
// is not false-rejected (the #4191 class). The compiler (compiler_ipsec.go,
// the IPsec proposal loop) reads a subset of the modeled set (description is
// cosmetic / compiler-ignored; lifetime-kilobytes is captured but
// accepted-only). Every leaf carries its value on the same statement line (no
// nested value block in Junos), so closed-world never descends into an AST
// child of a value leaf in either parser shape.
//
// Silent-drop here FAILS OPEN on crypto: before the flip a typo in
// `encryption-algorithm` / `authentication-algorithm` committed clean and the
// compiler negotiated the ESP SA WITHOUT the operator's chosen cipher/hash — a
// silent downgrade. The flip REJECTS the typo at strict commit (SchemaValidate)
// instead of committing clean and being silently dropped by the compiler — the
// #4313 silent-inert bug.
//
// These tests use the production ParseSetCommand + SetPath + SchemaValidate
// path (buildTree). Each rejection test is RED on revert of the closedWorld
// flag: without it, SchemaValidate returns nil (open-world silent-accept) and
// the test fails.

// ipsecProposalSet builds a minimal IPsec (Phase-2) proposal whose body is the
// supplied set lines (e.g. "encryption-algorithm aes-256-cbc", "bogus x").
func ipsecProposalSet(bodyLines ...string) []string {
	out := []string{}
	for _, l := range bodyLines {
		out = append(out, "set security ipsec proposal p1 "+l)
	}
	return out
}

// TestClosedWorldIPsecProposal_RejectsUnknownKeyword is the core RED-on-revert
// discriminator: an unmodeled keyword under the closed-world IPsec proposal is
// rejected at strict commit. On revert of closedWorld the same input is
// silently accepted (SchemaValidate returns nil) and this test fails — proving
// the flip closes the #4313 silent-inert gap.
func TestClosedWorldIPsecProposal_RejectsUnknownKeyword(t *testing.T) {
	tree := buildTree(t, ipsecProposalSet("bogus aes-256-cbc"))
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("an unmodeled keyword under the closed-world IPsec proposal must be rejected at commit (RED on revert: silently accepted + dropped)")
	}
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "closed-world") {
		t.Fatalf("error must name the keyword and the closed-world subtree, got: %v", err)
	}
}

// TestClosedWorldIPsecProposal_RejectsCryptoTypo is the VALUE of the fix: a
// fat-fingered crypto leaf is caught at commit rather than silently ignored —
// the operator learns the chosen cipher/hash/PFS would be dropped and the ESP
// SA silently downgraded.
func TestClosedWorldIPsecProposal_RejectsCryptoTypo(t *testing.T) {
	for _, typo := range []string{
		"encryption-algorith aes-256-cbc",
		"authentication-algoritm hmac-sha-256-128",
		"dh-grop group14",
		"protcol esp",
		// a typo on the ESP-only volume-rekey knob (silently keeps the
		// lifetime-seconds-only rekey the operator meant to harden)
		"lifetime-kilobyte 100000",
	} {
		tree := buildTree(t, ipsecProposalSet(typo))
		err := SchemaValidate(tree, nil)
		if err == nil {
			t.Fatalf("a typo'd IPsec proposal leaf %q must be rejected at commit, not silently dropped (crypto fails open)", typo)
		}
		// the first token is the misspelled keyword
		bad := strings.Fields(typo)[0]
		if !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "closed-world") {
			t.Fatalf("error must name the typo %q and the closed-world subtree, got: %v", bad, err)
		}
	}
}

// TestClosedWorldIPsecProposal_AcceptsValid proves no false-reject: every valid
// Junos IPsec proposal leaf still commits clean under closed-world — each on
// its own AND combined into a fully-specified real-world proposal — including
// the two leaves added to make the subtree leaf-complete (lifetime-kilobytes,
// description).
func TestClosedWorldIPsecProposal_AcceptsValid(t *testing.T) {
	// each modeled leaf on its own
	for _, leaf := range []string{
		"protocol esp",
		"encryption-algorithm aes-256-cbc",
		"authentication-algorithm hmac-sha-256-128",
		"dh-group group14",
		"lifetime-seconds 28800",
		"lifetime-kilobytes 100000",
		`description "corp phase-2 proposal"`,
	} {
		tree := buildTree(t, ipsecProposalSet(leaf))
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("valid IPsec proposal leaf %q must commit clean under closed-world, got: %v", leaf, err)
		}
	}
	// a fully-specified proposal (the real-world shape)
	full := buildTree(t, ipsecProposalSet(
		"protocol esp",
		"encryption-algorithm aes-256-cbc",
		"authentication-algorithm hmac-sha-256-128",
		"dh-group group14",
		"lifetime-seconds 28800",
		"lifetime-kilobytes 100000",
	))
	if err := SchemaValidate(full, nil); err != nil {
		t.Fatalf("a fully-specified IPsec proposal must commit clean under closed-world, got: %v", err)
	}
}

// TestClosedWorldIPsecProposal_LenientDoesNotBrick documents the #1960 no-brick
// contract: the closed-world reject is a SchemaValidate error, which the
// tolerant Store.Load / SyncApply ingress downgrades to a warning
// (configstore.compileTreeLenient). At the compile layer the schema gate is
// NOT run — the lenient path is precisely CompileConfigLenient — so a config
// with the typo still COMPILES (the unknown leaf silently dropped) rather than
// bricking the load.
func TestClosedWorldIPsecProposal_LenientDoesNotBrick(t *testing.T) {
	typoTree := buildTree(t, append(
		ipsecProposalSet("encryption-algorith aes-256-cbc"),
		"set security ipsec policy pol1 proposals p1",
	))
	// strict gate rejects (the operator commit path)
	if err := SchemaValidate(typoTree, nil); err == nil {
		t.Fatal("precondition: strict SchemaValidate must reject the typo")
	}
	// lenient compile (the Store.Load / SyncApply path) must NOT brick.
	if _, err := CompileConfigLenient(typoTree); err != nil {
		t.Fatalf("the lenient load/peer-sync path must not brick on a closed-world typo (#1960); got: %v", err)
	}
}

// TestClosedWorldIPsecProposal_LifetimeKilobytesAdvisory proves the modeled
// lifetime-kilobytes is captured and surfaces the accepted-only advisory so an
// operator is not silently misled into believing volume-based rekey is
// enforced.
func TestClosedWorldIPsecProposal_LifetimeKilobytesAdvisory(t *testing.T) {
	tree := buildTree(t, ipsecProposalSet("lifetime-kilobytes 100000", "authentication-algorithm hmac-sha-256-128"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if p := cfg.Security.IPsec.Proposals["p1"]; p == nil || p.LifetimeKilobytes != 100000 {
		t.Fatalf("lifetime-kilobytes must be captured into IPsecProposal.LifetimeKilobytes, got: %#v", p)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "lifetime-kilobytes") && strings.Contains(w, "accepted-only") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected an accepted-only lifetime-kilobytes advisory, got warnings: %v", cfg.Warnings)
	}
}
