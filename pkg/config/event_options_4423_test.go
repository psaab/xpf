package config

import (
	"errors"
	"strings"
	"testing"
)

// #4423 M9: a delete of a missing path must wrap the typed ErrPathNotFound
// sentinel so tolerant callers (the event-options change-configuration batch)
// can errors.Is it instead of substring-matching the message text.
func TestDeletePathWrapsErrPathNotFound(t *testing.T) {
	tree := &ConfigTree{}
	set, err := ParseSetCommand("set system host-name base")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := tree.SetPath(set); err != nil {
		t.Fatalf("setpath: %v", err)
	}

	// Delete a path that does not exist.
	err = tree.DeletePath([]string{"system", "domain-name", "nope"})
	if err == nil {
		t.Fatal("delete of a missing path should error")
	}
	if !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("missing-path delete error %v does not wrap ErrPathNotFound", err)
	}
	// The human-readable prefix is preserved for any remaining string matchers.
	if !strings.Contains(err.Error(), "path not found") {
		t.Fatalf("error text %q lost its 'path not found' prefix", err.Error())
	}
}

// #4423 M9 (regression): a delete whose INTERMEDIATE container is absent (more
// tokens remain past a schema container that is not configured) is the fourth
// not-found site in deletePath — distinct from the leaf-miss (removeMatchingNode)
// and member-miss (removeMultiLeafMembers) the other tests cover. It is the most
// common defensive-remediation shape (`delete <subtree>` when the parent is not
// configured) and MUST wrap ErrPathNotFound, or applyOnce's errors.Is tolerance
// aborts the batch.
func TestDeletePathContainerMissWrapsErrPathNotFound(t *testing.T) {
	tree := &ConfigTree{}
	set, err := ParseSetCommand("set system host-name base")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := tree.SetPath(set); err != nil {
		t.Fatalf("setpath: %v", err)
	}
	// routing-options is not configured: an absent intermediate container.
	err = tree.DeletePath([]string{"routing-options", "static", "route", "0.0.0.0/0"})
	if err == nil {
		t.Fatal("deleting under an absent container should error")
	}
	if !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("container-miss delete error %v does not wrap ErrPathNotFound", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected the container-miss return, got %q", err.Error())
	}
}

// #4423 M9: a member-delete that names an absent value of a multi-leaf also
// wraps ErrPathNotFound.
func TestDeletePathMissingMemberWrapsErrPathNotFound(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range []string{
		"set firewall family inet filter f term t from protocol tcp",
	} {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	// Delete a protocol member that is not present.
	err := tree.DeletePath([]string{"firewall", "family", "inet", "filter", "f",
		"term", "t", "from", "protocol", "udp"})
	if err == nil {
		t.Fatal("deleting an absent member should error")
	}
	if !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("absent-member delete error %v does not wrap ErrPathNotFound", err)
	}
}

// #4423 L1: two hierarchical `policy foo { ... }` blocks must MERGE into one
// event-options policy (matching flat-set/display-set and Junos merge
// semantics), not coexist as duplicate same-named policies that clobber each
// other's runtime state in the engine.
func TestCompileEventOptionsMergesDuplicatePolicyBlocks(t *testing.T) {
	cfgText := `
event-options {
    policy foo {
        events ping_test_failed;
        then {
            change-configuration {
                commands {
                    "set system host-name changed";
                }
            }
        }
    }
    policy foo {
        events ping_test_completed;
    }
}
`
	p := NewParser(cfgText)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("got %d event-options policies; duplicate 'policy foo' blocks must merge to 1",
			len(cfg.EventOptions))
	}
	pol := cfg.EventOptions[0]
	if pol.Name != "foo" {
		t.Fatalf("merged policy name = %q; want foo", pol.Name)
	}
	// Events from BOTH blocks are present.
	haveEvent := func(name string) bool {
		for _, e := range pol.Events {
			if e == name {
				return true
			}
		}
		return false
	}
	if !haveEvent("ping_test_failed") || !haveEvent("ping_test_completed") {
		t.Fatalf("merged events %v missing one of the two blocks' events", pol.Events)
	}
	// The then-commands from the first block survive the merge.
	if len(pol.ThenCommands) != 1 || pol.ThenCommands[0] != "set system host-name changed" {
		t.Fatalf("merged then-commands = %v; want the first block's command", pol.ThenCommands)
	}
}
