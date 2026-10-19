package config

import (
	"strings"
	"testing"
)

// #15083 (A53-05): SetPath's single-value-leaf replacement built a fresh Node
// without carrying Inactive/Annotation, so re-setting an inactive, annotated
// leaf silently re-activated it and dropped its comment at the next commit.
// The credential case: a deactivated encrypted-password rotated by `set`
// re-enabled password login with no operator notice.

// findLeaf15083 walks the tree by first-key names and returns the leaf.
func findLeaf15083(t *testing.T, tree *ConfigTree, names ...string) *Node {
	t.Helper()
	var nodes = tree.Children
	var n *Node
	for _, name := range names {
		n = nil
		for _, c := range nodes {
			if len(c.Keys) > 0 && c.Keys[0] == name {
				n = c
				break
			}
		}
		if n == nil {
			t.Fatalf("node %q not found under %v", name, names)
		}
		nodes = n.Children
	}
	return n
}

func TestSetPathSingleValueLeafPreservesInactiveAnnotation15083(t *testing.T) {
	tree := mustParse(t, `system {
    root-authentication {
        /* rotated 2026-10-01, parked until rollout */
        inactive: encrypted-password "$6$old";
    }
}`)
	// Annotate via the operator path (parser does not lift /* */ into
	// Annotation; AnnotatePath is the annotate command's entry point).
	annPath := []string{"system", "root-authentication", "encrypted-password"}
	if err := tree.AnnotatePath(annPath, "rotated 2026-10-01, parked until rollout"); err != nil {
		t.Fatalf("AnnotatePath: %v", err)
	}
	leaf := findLeaf15083(t, tree, "system", "root-authentication", "encrypted-password")
	if !leaf.Inactive || leaf.Annotation == "" {
		t.Fatalf("setup: leaf Inactive=%v Annotation=%q, want inactive+annotated", leaf.Inactive, leaf.Annotation)
	}

	// Re-set, even to a new value (rotation) — the exact A53-05 probe.
	path, err := ParseSetCommand(`set system root-authentication encrypted-password "$6$new"`)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	leaf = findLeaf15083(t, tree, "system", "root-authentication", "encrypted-password")
	if len(leaf.Keys) != 2 || leaf.Keys[1] != "$6$new" {
		t.Fatalf("value not replaced: Keys=%v", leaf.Keys)
	}
	if !leaf.Inactive {
		t.Fatalf("re-set re-activated the leaf: Inactive=false, want true (A53-05)")
	}
	if leaf.Annotation != "rotated 2026-10-01, parked until rollout" {
		t.Fatalf("re-set dropped annotation: %q", leaf.Annotation)
	}
	out := tree.Format()
	if !strings.Contains(out, `inactive: encrypted-password "$6$new";`) {
		t.Fatalf("formatted config lost inactive marker:\n%s", out)
	}
	if !strings.Contains(out, "/* rotated 2026-10-01, parked until rollout */") {
		t.Fatalf("formatted config lost annotation:\n%s", out)
	}
	// The inactive leaf must stay excluded from compilation.
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.RootAuthentication != nil && cfg.System.RootAuthentication.EncryptedPassword.Reveal() == "$6$new" {
		t.Fatalf("inactive encrypted-password compiled as active credential")
	}
}

func TestSetPathSingleValueLeafSameValuePreservesInactive15083(t *testing.T) {
	tree := mustParse(t, `system {
    host-name old-name;
}`)
	path, err := ParseSetCommand(`set system host-name old-name`)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	// Deactivate + annotate the single-value leaf, then re-set same value.
	if err := tree.DeactivatePath([]string{"system", "host-name"}); err != nil {
		t.Fatalf("DeactivatePath: %v", err)
	}
	if err := tree.AnnotatePath([]string{"system", "host-name"}, "parked host"); err != nil {
		t.Fatalf("AnnotatePath: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath same value: %v", err)
	}
	leaf := findLeaf15083(t, tree, "system", "host-name")
	if !leaf.Inactive {
		t.Fatalf("same-value re-set re-activated host-name")
	}
	if leaf.Annotation != "parked host" {
		t.Fatalf("same-value re-set dropped annotation: %q", leaf.Annotation)
	}
}

func TestSetPathSingleValueLeafActiveUnannotatedControl15083(t *testing.T) {
	// Control: an active, unannotated leaf re-set behaves exactly as before.
	tree := mustParse(t, `system {
    host-name old-name;
}`)
	path, err := ParseSetCommand(`set system host-name new-name`)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	leaf := findLeaf15083(t, tree, "system", "host-name")
	if leaf.Inactive || leaf.Annotation != "" {
		t.Fatalf("control leaf gained state: Inactive=%v Annotation=%q", leaf.Inactive, leaf.Annotation)
	}
	if len(leaf.Keys) != 2 || leaf.Keys[1] != "new-name" {
		t.Fatalf("control value not replaced: %v", leaf.Keys)
	}
	// Duplicate collapse still holds: exactly one host-name leaf.
	sys := findLeaf15083(t, tree, "system")
	count := 0
	for _, c := range sys.Children {
		if len(c.Keys) > 0 && c.Keys[0] == "host-name" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("host-name leaf count = %d, want 1", count)
	}
}

func TestSetPathMultiLeafStillKeepsNode15083(t *testing.T) {
	// Adjacent control: the flag/multi arm already keeps the node; an
	// inactive multi leaf re-set must remain inactive (exact-duplicate path).
	tree := mustParse(t, `system {
    root-authentication {
        inactive: ssh-ed25519 "ssh-ed25519 AAAA";
    }
}`)
	path, err := ParseSetCommand(`set system root-authentication ssh-ed25519 "ssh-ed25519 AAAA"`)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	leaf := findLeaf15083(t, tree, "system", "root-authentication", "ssh-ed25519")
	if !leaf.Inactive {
		t.Fatalf("multi leaf lost Inactive on duplicate re-set")
	}
}
