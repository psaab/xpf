package config

import (
	"strings"
	"testing"
)

// #7441 — the `chassis cluster strict-session-auth` leaf: its compile, its
// strict gate, and the ordering that makes the gate reachable at all.

func clusterTreeWithLeaves7441(t *testing.T, leaves ...[]string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	if err := tree.SetPath([]string{"chassis", "cluster", "cluster-id", "22"}); err != nil {
		t.Fatalf("SetPath cluster-id: %v", err)
	}
	if err := tree.SetPath([]string{"chassis", "cluster", "node", "0"}); err != nil {
		t.Fatalf("SetPath node: %v", err)
	}
	for _, l := range leaves {
		if err := tree.SetPath(append([]string{"chassis", "cluster"}, l...)); err != nil {
			t.Fatalf("SetPath %v: %v", l, err)
		}
	}
	return tree
}

// TestStrictSessionAuthCompiles7441 pins the compile in both directions. A leaf
// the compiler never reads would leave the runtime posture permanently off
// while `show configuration` displayed it — the exact shape of a security
// control that is present and inert.
func TestStrictSessionAuthCompiles7441(t *testing.T) {
	withLeaf := clusterTreeWithLeaves7441(t,
		[]string{"authentication-key", "a-real-control-link-psk-value"},
		[]string{"strict-session-auth"})
	cfg, err := CompileConfigLenient(withLeaf)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.StrictSessionAuth {
		t.Fatal("`strict-session-auth` did not compile to StrictSessionAuth=true; the " +
			"runtime posture would stay off while the config displays it as set")
	}

	// The negative half: absence must compile to false, or the posture would be
	// on for every cluster and a rolling upgrade would break by default.
	without := clusterTreeWithLeaves7441(t,
		[]string{"authentication-key", "a-real-control-link-psk-value"})
	cfg2, err := CompileConfigLenient(without)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg2.Chassis.Cluster != nil && cfg2.Chassis.Cluster.StrictSessionAuth {
		t.Fatal("StrictSessionAuth is true with the leaf ABSENT — the posture would be " +
			"declared for every cluster, dropping any peer that cannot answer the " +
			"in-place upgrade")
	}
}

// TestStrictSessionAuthWithoutAKeyIsRejected7441 covers the gate, and the
// ORDERING that makes it reachable.
//
// validateClusterAuthKeyStrict already rejects a keyless cluster on its own, so
// a gate ordered after it could never fire and would be a comment pretending to
// be code. This asserts the operator gets the message about what THEY did.
func TestStrictSessionAuthWithoutAKeyIsRejected7441(t *testing.T) {
	tree := clusterTreeWithLeaves7441(t, []string{"strict-session-auth"})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a config declaring strict-session-auth with no authentication-key " +
			"committed cleanly; the posture is inert without a key, so the operator " +
			"believes a hole is closed that is still open")
	}
	if !strings.Contains(err.Error(), "strict-session-auth") {
		t.Fatalf("the rejection does not name `strict-session-auth`, so this gate is "+
			"UNREACHABLE — validateClusterAuthKeyStrict fired first and the operator is "+
			"told only to add a key, with no hint that their posture leaf did nothing.\n"+
			"got: %v", err)
	}

	// Control: with a key, the same tree must compile. Without this the cell
	// above is satisfied by a gate that rejects the leaf unconditionally.
	keyed := clusterTreeWithLeaves7441(t,
		[]string{"authentication-key", "a-real-control-link-psk-value"},
		[]string{"strict-session-auth"})
	if _, err := CompileConfig(keyed); err != nil {
		t.Fatalf("strict-session-auth with a key must commit: %v", err)
	}
}

// TestStrictSessionAuthWithoutAKeyIsATolerantWarning7441 is the #1960 no-brick
// half: the SAME config must LOAD, with a warning.
//
// A node whose on-disk config carries the combination — written by an older
// binary, or pushed by a peer — must still boot. An inert posture leaf is no
// more dangerous at runtime than not setting it, so hard-failing the tolerant
// path would brick a node over a no-op.
func TestStrictSessionAuthWithoutAKeyIsATolerantWarning7441(t *testing.T) {
	tree := clusterTreeWithLeaves7441(t, []string{"strict-session-auth"})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path REJECTED a config it must tolerate; a node holding "+
			"this on disk would fail to boot (#1960): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "strict-session-auth") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the tolerant path accepted the config with no warning naming "+
			"`strict-session-auth`. Silence here is the worst outcome: the operator "+
			"keeps believing the posture is enforcing.\nwarnings: %v", cfg.Warnings)
	}
	// The posture still compiles to true — the leaf is honoured, it is simply
	// inert until a key exists. A tolerant path that silently cleared it would
	// make the next keyed commit behave differently from the same config.
	if !cfg.Chassis.Cluster.StrictSessionAuth {
		t.Error("the tolerant path cleared the posture leaf rather than warning about it")
	}
}

// TestStrictSessionAuthIsInTheSetSchema7441 binds the config-mode grammar.
//
// setSchema is what the CLI completes `set chassis cluster ...` against
// (docs/config-schema.md), so a leaf missing from it is one an operator cannot
// discover with `?` or tab even if the compiler happens to read it.
//
// The instrument is CompleteSetPath, NOT SchemaValidate. That was the first
// thing tried and its control failed: SchemaValidate accepts an unknown
// chassis-cluster leaf, so "SchemaValidate accepts strict-session-auth" is true
// of every string and proves nothing about the schema entry. The control below
// is kept, now against an instrument that can actually report the negative.
func TestStrictSessionAuthIsInTheSetSchema7441(t *testing.T) {
	got := CompleteSetPath([]string{"chassis", "cluster", ""})
	var found bool
	for _, c := range got {
		if c == "strict-session-auth" {
			found = true
		}
	}
	if !found {
		t.Fatalf("`strict-session-auth` is not offered under `set chassis cluster`, so "+
			"the operator cannot discover the leaf with ? or tab.\noffered: %v", got)
	}

	// Control, in the direction that can fail: the completer is not simply
	// echoing whatever it is asked about.
	for _, c := range got {
		if c == "strict-session-auth-typo" {
			t.Fatal("the completer offered a leaf that does not exist; the assertion " +
				"above is satisfied by any string and binds nothing")
		}
	}
	// Non-vacuity: an empty completion list would make both cells above pass.
	if len(got) < 5 {
		t.Fatalf("only %d completions under `chassis cluster` (%v); the completer is not "+
			"reading the stanza this test claims to check", len(got), got)
	}
}
