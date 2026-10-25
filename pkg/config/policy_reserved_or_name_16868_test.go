package config

import (
	"strings"
	"testing"
)

// #16868 gate4: generated cross-chain OR redistribute names
// (readable structural form and `xpf-or-<digest>` hash form) must
// be unspellable by operator policy-statements — an ordered chain
// [xpf-or-<digest>-xpf or] would otherwise reproduce the hash
// name exactly and merge with the OR map in FRR's global
// namespace. validatePolicyReservedOrNameStrict16868 reserves the
// prefix/marker namespace: strict-reject at commit, lenient-warn
// on load (render-side redistChainMapCollision15156 refuses too).

func TestPolicyReservedOrNameRejected16868(t *testing.T) {
	for _, name := range []string{"xpf-or-2aff27e47a5d420d-xpf", "A-xpf-or-B"} {
		tree := buildTreeFromSet(t, []string{
			"set policy-options policy-statement " + name + " term t1 from protocol static",
			"set policy-options policy-statement " + name + " term t1 then accept",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("CompileConfig accepted OR-namespace policy %q; expected rejection (#16868)", name)
		} else if !strings.Contains(err.Error(), "reserved") {
			t.Errorf("error for %q must name the reservation: %v", name, err)
		}
	}
}

func TestPolicyReservedOrNormalNameAccepted16868(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement NORMAL-GUARD term t1 from protocol static",
		"set policy-options policy-statement NORMAL-GUARD term t1 then accept",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("normal policy name must compile: %v", err)
	}
}

// Joined markers across member boundaries are refused too:
// [xpf or-<digest>-xpf or] joins into the OR namespace even
// though each member alone is legal.
func TestPolicyReservedOrJoinedSplitRejected16868(t *testing.T) {
	sets := []string{"set routing-options autonomous-system 65000"}
	for _, n := range []string{"xpf", "or-2aff27e47a5d420d-xpf", "or"} {
		sets = append(sets,
			"set policy-options policy-statement "+n+" term t1 from protocol static",
			"set policy-options policy-statement "+n+" term t1 then accept")
	}
	sets = append(sets,
		"set protocols bgp group g type external",
		"set protocols bgp group g peer-as 65001",
		"set protocols bgp group g neighbor 10.0.0.2 export xpf",
		"set protocols bgp group g neighbor 10.0.0.2 export or-2aff27e47a5d420d-xpf",
		"set protocols bgp group g neighbor 10.0.0.2 export or")
	tree := buildTreeFromSet(t, sets)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("joined split-name chain must be rejected (#16868 gate5)")
	}
}

func TestPolicyReservedOrNameLenientWarns16868(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set policy-options policy-statement xpf-or-abc term t1 from protocol static",
		"set policy-options policy-statement xpf-or-abc term t1 then accept",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must boot with a warning, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "reserved OR namespace") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient compile must warn on the OR namespace, warnings: %v", cfg.Warnings)
	}
}
