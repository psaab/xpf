package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #6611: cluster control-channel authentication was DORMANT in every
// configuration this repository ships, documents and tests. The mechanism
// existed — fabric gRPC auth (#4357), heartbeat HMAC (#4326), session-sync
// challenge/response (#4369) — but all three key off `chassis cluster
// authentication-key`, all three fail OPEN when it is absent, and NO config in
// the tree set it. These tests lock both halves of the fix: the strict commit
// gate that refuses an unkeyed cluster, and the shipped configs that now carry
// a key so the ENFORCING runtime path is what the smoke cluster exercises.

// TestUnkeyedClusterRejectedOnCommit_6611 is the primary fail-on-revert guard.
// RED on revert: with validateClusterAuthKeyStrict removed (or its call site
// dropped from runUniformGatesClusterZone) CompileConfig returns nil and this
// assertion fires.
func TestUnkeyedClusterRejectedOnCommit_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	})
	cfg, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("commit accepted a chassis cluster with no authentication-key: "+
			"the fabric gRPC listener, heartbeat and session-sync channel all "+
			"fail OPEN unkeyed, so this config runs an unauthenticated control "+
			"channel (compiled cfg=%v)", cfg != nil)
	}
	if !strings.Contains(err.Error(), "authentication-key") {
		t.Fatalf("reject message does not name the missing leaf: %v", err)
	}
	// The remediation must be actionable: name the exact set command.
	if !strings.Contains(err.Error(), "chassis cluster authentication-key") {
		t.Fatalf("reject message does not tell the operator what to set: %v", err)
	}
}

// TestUnkeyedClusterWhitespaceKeyRejected_6611 covers the near-miss shape: a
// key of only whitespace satisfies the runtime's len(key) > 0 test and would
// "work" as a PSK with no entropy. The strict gate treats it as unset.
func TestUnkeyedClusterWhitespaceKeyRejected_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		`set chassis cluster authentication-key "   "`,
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("commit accepted a whitespace-only authentication-key")
	}
}

// TestKeyedClusterCommitsClean_6611 is the NEGATIVE CONTROL for the gate: a
// properly keyed cluster must still commit, so the guard cannot be passing by
// rejecting every cluster config. It also asserts the key actually reached the
// compiled Secret — a gate that accepted the config but dropped the key would
// leave the runtime just as unauthenticated.
func TestKeyedClusterCommitsClean_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key a-real-cluster-psk-6611",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected a properly keyed cluster: %v", err)
	}
	if got := cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal(); got != "a-real-cluster-psk-6611" {
		t.Fatalf("ControlLinkAuthKey = %q, want the configured PSK", got)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "downgraded to warning on tolerant path") &&
			strings.Contains(w, "authentication-key") {
			t.Fatalf("keyed cluster emitted the missing-key warning: %q", w)
		}
		if strings.Contains(w, "authentication-key is") ||
			strings.Contains(w, "looks like a placeholder") {
			t.Fatalf("a 22-character non-placeholder key emitted a strength "+
				"warning: %q", w)
		}
	}
}

// TestShortClusterAuthKeyWarnsNotRejected_6611 pins the deliberate asymmetry
// between absence and weakness. Absence is binary and is rejected; strength is
// a continuum, so a short key WARNS on both paths and still commits. Rejecting
// it would create a new brick class — including via bootstrapFromFile, which is
// unattended — for an operator who already configured authentication.
func TestShortClusterAuthKeyWarnsNotRejected_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key abc",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected a short but real key (must warn, not reject): %v", err)
	}
	var found string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "authentication-key is 3 characters") {
			found = w
			break
		}
	}
	if found == "" {
		t.Fatalf("no key-strength warning for a 3-character key; warnings=%v", cfg.Warnings)
	}
	if !strings.Contains(found, "16 or more is advised") {
		t.Fatalf("strength warning does not state the advised floor: %q", found)
	}
	if !strings.Contains(found, "duplicate-identity beacon") ||
		!strings.Contains(found, "forge") {
		t.Fatalf("short-key warning omits the beacon forgery risk: %q", found)
	}

	// The key itself must never be rendered.
	if strings.Contains(found, "abc") {
		t.Fatalf("strength warning leaked the key: %q", found)
	}
}

// TestPlaceholderClusterAuthKeyWarns_6611 covers the copied-reference-config
// case: the shipped configs carry PUBLISHED lab values, so a config using one
// satisfies the gate while remaining forgeable by anyone who has read the repo.
// It cannot be a hard reject — test/incus/cluster-setup.sh deploys
// docs/ha-cluster.conf verbatim — so it warns.
func TestPlaceholderClusterAuthKeyWarns_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key xpf-lab-ha-psk-cluster-1-CHANGE-ME",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected a placeholder key (must warn, not reject): %v", err)
	}
	var found string
	for _, w := range cfg.Warnings {
		// Match on the stable noun, not the phrasing: the wording changed
		// when the advisory stopped naming the matched marker (that named a
		// key exactly equal to it). See
		// TestStrengthWarningNeverRendersTheKey_6611, which covers the
		// key-EQUALS-marker case this test's own leak check below misses —
		// it only exercises a key that CONTAINS one.
		if strings.Contains(w, "placeholder") {
			found = w
			break
		}
	}
	if found == "" {
		t.Fatalf("no placeholder warning for a shipped lab key; warnings=%v", cfg.Warnings)
	}
	if strings.Contains(found, "xpf-lab-ha-psk") {
		t.Fatalf("placeholder warning leaked the key: %q", found)
	}
}

// TestClusterAuthKeyStrengthWarningsOnTolerantPath_6611 proves the advisories
// are path-independent: a provisioning/day-0 config loaded leniently gets the
// same signal an operator commit does.
func TestClusterAuthKeyStrengthWarningsOnTolerantPath_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key xy",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path rejected a short key: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "authentication-key is 2 characters") {
			return
		}
	}
	t.Fatalf("tolerant path emitted no key-strength warning; warnings=%v", cfg.Warnings)
}

// TestStandaloneEmitsNoStrengthWarning_6611 is the strength guard's NEGATIVE
// CONTROL: no cluster stanza means no key to judge.
func TestStandaloneEmitsNoStrengthWarning_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected a standalone config: %v", err)
	}
	if got := ClusterAuthKeyStrengthWarnings(cfg); got != nil {
		t.Fatalf("standalone config produced key-strength warnings: %v", got)
	}
}

// TestNoClusterStanzaUnaffected_6611 is the second NEGATIVE CONTROL: a
// standalone (non-clustered) config has no control channel to authenticate and
// must be untouched by the gate.
func TestNoClusterStanzaUnaffected_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected a standalone config: %v", err)
	}
	if cfg.Chassis.Cluster != nil {
		t.Fatal("standalone config unexpectedly compiled a cluster stanza")
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "cluster authentication") {
			t.Fatalf("standalone config emitted a cluster auth warning: %q", w)
		}
	}
}

// TestUnkeyedClusterWarnsOnTolerantPath_6611 pins the migration contract, and
// is the reason this gate does not brick an upgrade. A cluster that was
// already unkeyed before the gate existed reaches the compiler through the
// TOLERANT path on daemon startup (configstore load) and on peer config-sync.
// That path must WARN and still produce a usable config — the node boots, the
// cluster forms, and the operator is told to set a key. #1960 no-brick.
func TestUnkeyedClusterWarnsOnTolerantPath_6611(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster reth-count 2",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path rejected an unkeyed cluster (would brick an "+
			"upgrade of an existing unkeyed cluster): %v", err)
	}
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("tolerant path did not compile the cluster stanza")
	}
	var found string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "authentication-key") {
			found = w
			break
		}
	}
	if found == "" {
		t.Fatalf("tolerant path did not warn about the unkeyed cluster; warnings=%v",
			cfg.Warnings)
	}
	if !strings.Contains(found, "downgraded to warning on tolerant path") {
		t.Fatalf("warning does not follow the uniform-gate downgrade wording: %q", found)
	}
}

// TestClusterAuthKeyGateErrorIsValueIndependent_6611 proves the strict gate's
// message carries no key material. `authentication-key` is a Secret leaf
// (compiler_system.go) precisely so it never reaches a log or a CLI render, and
// a gate that echoed the configured value would undo that. Two DIFFERENT
// whitespace-only keys must produce a byte-identical error, which can only hold
// if the message is a constant rather than a rendering of the leaf.
func TestClusterAuthKeyGateErrorIsValueIndependent_6611(t *testing.T) {
	errFor := func(key string) string {
		tree := buildTree(t, []string{
			"set chassis cluster cluster-id 1",
			`set chassis cluster authentication-key "` + key + `"`,
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("commit accepted a whitespace-only authentication-key %q", key)
		}
		return err.Error()
	}
	a, b := errFor(" "), errFor("      ")
	if a != b {
		t.Fatalf("gate error varies with the key value — it is rendering key "+
			"material:\n  %q\n  %q", a, b)
	}
	if strings.Contains(a, `"`) {
		t.Fatalf("gate error quotes a value; it must name only the leaf: %q", a)
	}
}

// shippedClusterConfigs are every config file in the repository that carries a
// `chassis cluster` stanza and is either deployed by the test tooling or
// presented to operators as the reference wiring. #6611 acceptance criterion 1.
//
// test/incus/cluster-setup.sh and test/incus/test-private-rg.sh push
// docs/ha-cluster.conf onto real cluster VMs, and pkg/config's golden harness
// compiles docs/ha-cluster.conf + docs/ha-cluster-userspace.conf — so these are
// live artifacts, not prose.
var shippedClusterConfigs = []string{
	"../../docs/ha-cluster.conf",
	"../../docs/ha-cluster-loss.conf",
	"../../docs/ha-cluster-userspace.conf",
	"../../test/incus/xpf-cluster-fw0.conf",
	"../../test/incus/xpf-cluster-fw1.conf",
	"../../examples/deploy/ha-pair.conf",
}

// TestShippedClusterConfigsAreKeyed_6611 is the regression lock on the other
// half of #6611: every config this project ships or deploys must configure the
// control-channel PSK, so the smoke cluster exercises the ENFORCING branch of
// fabricAuthDecision / heartbeatAuthDecision / performSyncHandshake rather than
// the keyConfigured == false shortcut. It compiles each file for BOTH nodes,
// which is what the daemon actually runs, so a key hidden inside a single
// node's group (and therefore absent on the peer) still fails.
//
// RED on revert: drop the authentication-key line from any of these files.
func TestShippedClusterConfigsAreKeyed_6611(t *testing.T) {
	for _, rel := range shippedClusterConfigs {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			raw, err := os.ReadFile(rel)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			for _, nodeID := range []int{0, 1} {
				tree := hierTree(t, string(raw))
				cfg, err := CompileConfigForNode(tree, nodeID)
				if err != nil {
					t.Fatalf("%s: CompileConfigForNode(%d) failed — a shipped "+
						"cluster config must commit cleanly: %v", rel, nodeID, err)
				}
				if cfg.Chassis.Cluster == nil {
					t.Fatalf("%s: node %d compiled no chassis cluster stanza",
						rel, nodeID)
				}
				if strings.TrimSpace(cfg.Chassis.Cluster.ControlLinkAuthKey.Reveal()) == "" {
					t.Fatalf("%s: node %d has NO chassis cluster authentication-key "+
						"— the fabric gRPC listener, heartbeat and session-sync "+
						"channel all fail OPEN, so this reference config deploys an "+
						"unauthenticated cluster control channel (#6611)", rel, nodeID)
				}
			}
		})
	}
}

// TestShippedClusterConfigsUseOneKeyPerCluster_6611 guards the property that
// makes the PSK usable at all: both nodes of one cluster must derive the SAME
// key. A ${node}-scoped key would authenticate nothing — each node would sign
// with a secret its peer cannot verify, and the dual-accept grace would silently
// keep the channel unauthenticated forever instead of failing loudly.
func TestShippedClusterConfigsUseOneKeyPerCluster_6611(t *testing.T) {
	for _, rel := range shippedClusterConfigs {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			raw, err := os.ReadFile(rel)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			cfg0, err := CompileConfigForNode(hierTree(t, string(raw)), 0)
			if err != nil {
				t.Fatalf("%s: node 0 compile: %v", rel, err)
			}
			cfg1, err := CompileConfigForNode(hierTree(t, string(raw)), 1)
			if err != nil {
				t.Fatalf("%s: node 1 compile: %v", rel, err)
			}
			if cfg0.Chassis.Cluster.ControlLinkAuthKey != cfg1.Chassis.Cluster.ControlLinkAuthKey {
				t.Fatalf("%s: node 0 and node 1 derive DIFFERENT control-link keys "+
					"— the PSK must be cluster-wide, not ${node}-scoped", rel)
			}
		})
	}
}

// TestStrengthWarningNeverRendersTheKey_6611 pins the disclosure the advisory
// itself produced. The warning used to name the placeholder marker it matched,
// on the reasoning that a marker is a repository literal rather than operator
// key material. That holds until the two coincide: a key of exactly
// `change-me` makes the marker AND the key the same string, so the warning
// printed the whole key into commit output and the log — the exact exposure it
// exists to warn about.
//
// The keys below are deliberately EQUAL to, and SUBSTRINGS around, the
// markers. A fix that only stopped naming the marker for long keys, or only on
// one compile path, fails here.
func TestStrengthWarningNeverRendersTheKey_6611(t *testing.T) {
	for _, key := range []string{
		"change-me",
		"CHANGE-ME",
		"example-only",
		"xx-change-me-xx",
		"Change-Me-Now-Really-Long-Enough-To-Pass-The-Length-Advice",
	} {
		tree := buildTree(t, []string{
			"set chassis cluster cluster-id 1",
			"set chassis cluster node 0",
			"set chassis cluster reth-count 2",
			"set chassis cluster authentication-key " + key,
			"set chassis cluster redundancy-group 1 node 0 priority 200",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("key %q: compile: %v", key, err)
		}
		warnings := ClusterAuthKeyStrengthWarnings(cfg)
		if len(warnings) == 0 {
			t.Errorf("key %q produced no strength warning; a published "+
				"placeholder must always warn", key)
			continue
		}
		joined := strings.Join(warnings, " ")
		if !strings.Contains(joined, "duplicate-identity beacon") ||
			!strings.Contains(joined, "forge") {
			t.Errorf("key-strength warning for %q omits the beacon forgery surface: %v", key, warnings)
		}
		for _, w := range warnings {
			if strings.Contains(w, key) {
				t.Errorf("strength warning rendered the KEY %q verbatim: %s\n"+
					"The advisory must report that a placeholder matched WITHOUT "+
					"naming which, because when the key IS the marker the two are "+
					"the same string.", key, w)
			}
		}
	}
}
