package config

import (
	"strings"
	"testing"
)

// #15237 cohort (A53-02/A53-04/A53-06/A53-07): config-mode navigation
// parity. These cells exercise the exact mechanisms in the issue:
// identity-aware `up`, bare copy/rename destinations, and quoted
// re-joining of path tokens. FAIL-ON-REVERT: reverting
// PopEditPathIdentity to a per-token pop, BareDestinationParent to
// dst[:len-nk], or JoinConfigPathTokens to strings.Join turns the
// corresponding cells RED.

func TestPopEditPathIdentity15237(t *testing.T) {
	// Acceptance: edit security zones security-zone trust; up -> [security zones].
	got := PopEditPathIdentity([]string{"security", "zones", "security-zone", "trust"})
	if strings.Join(got, " ") != "security zones" {
		t.Fatalf("PopEditPathIdentity(zone cursor) = %v, want [security zones] (#15237 A53-02)", got)
	}
	// Compound identity: from-zone trust to-zone untrust is ONE node (args:3).
	got = PopEditPathIdentity([]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust"})
	if strings.Join(got, " ") != "security policies" {
		t.Fatalf("PopEditPathIdentity(policy cursor) = %v, want [security policies] (#15237 A53-02)", got)
	}
	// Plain single-token identities still pop one level; root stays root.
	if got := PopEditPathIdentity([]string{"system"}); len(got) != 0 {
		t.Fatalf("PopEditPathIdentity([system]) = %v, want empty", got)
	}
	if got := PopEditPathIdentity(nil); len(got) != 0 {
		t.Fatalf("PopEditPathIdentity(nil) = %v, want empty", got)
	}
	// up n via the shared prefix resolver: two identities up from the zone cursor.
	target, inner, ok := ParseTopUpPrefix15082([]string{"security", "zones", "security-zone", "trust"}, "up 1")
	if !ok || inner != nil || strings.Join(target, " ") != "security zones" {
		t.Fatalf("up 1 from zone cursor = %v,%v,%v, want [security zones] bare (#15237 A53-02)", target, inner, ok)
	}
}

func TestRenameBareDestinationStaysInZonePair15237(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy deny-ssh match source-address any",
		"set security policies from-zone trust to-zone untrust policy deny-ssh match destination-address any",
		"set security policies from-zone trust to-zone untrust policy deny-ssh match application any",
		"set security policies from-zone trust to-zone untrust policy deny-ssh then deny",
	})
	// Junos form from the zone-pair cursor: full src, bare dst identity.
	src := []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "deny-ssh"}
	dst := []string{"policy", "deny-ssh-v2"}
	if err := tree.RenamePath(src, dst); err != nil {
		t.Fatalf("RenamePath bare dst: %v (#15237 A53-04)", err)
	}
	out := tree.FormatSet()
	if !strings.Contains(out, "policy deny-ssh-v2") {
		t.Fatalf("renamed policy not under zone pair:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(line, "set "))
		if strings.HasPrefix(trimmed, "policy deny-ssh-v2") {
			t.Fatalf("rename detached policy to root stanza: %q (#15237 A53-04)\n%s", line, out)
		}
	}
	// Commit check must pass on the renamed tree (control: it compiled before).
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("renamed tree fails commit check: %v (#15237 A53-04)", err)
	}
}

func TestCopyBareDestinationStaysUnderInterfaces15237(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	})
	src := []string{"interfaces", "ge-0/0/0"}
	dst := []string{"ge-0/0/2"}
	if err := tree.CopyPath(src, dst); err != nil {
		t.Fatalf("CopyPath bare dst: %v (#15237 A53-04)", err)
	}
	out := tree.FormatSet()
	if !strings.Contains(out, "interfaces ge-0/0/2") {
		t.Fatalf("copy did not land under interfaces:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(line, "set "))
		if strings.HasPrefix(trimmed, "ge-0/0/2 ") || trimmed == "ge-0/0/2" {
			t.Fatalf("copy created root ge-0/0/2 stanza: %q (#15237 A53-04)\n%s", line, out)
		}
	}
}

func TestJoinConfigPathTokensPreservesInteriorWhitespace15237(t *testing.T) {
	joined := JoinConfigPathTokens([]string{"system", "services", "ssh", "message", "a  b"})
	// The re-lexed tokens must recover the value as ONE token with doubled space.
	path, err := ParseSetCommand("set " + joined)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", joined, err)
	}
	if len(path) == 0 || path[len(path)-1] != "a  b" {
		t.Fatalf("joined %q re-lexed to %v, want last token %q (#15237 A53-07)", joined, path, "a  b")
	}
	// Control: plain tokens are unquoted (no churn for ordinary paths).
	if got := JoinConfigPathTokens([]string{"system", "host-name", "edge1"}); got != "system host-name edge1" {
		t.Fatalf("plain join = %q, want unquoted", got)
	}
}
