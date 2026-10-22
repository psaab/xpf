package config

import "testing"

// #2622: `from source-port-except` / `from destination-port-except` are the
// NEGATED port match conditions (match every port EXCEPT the listed ones), the
// counterpart to the positive source-port / destination-port matches. These
// tests assert the new schema leaves validate, that bracketed lists collapse
// onto the term per #2419, and that the compiler accumulates the values into
// the SourcePortsExcept / DestPortsExcept slices across BOTH parser AST shapes.
//
// FAIL-ON-REVERT: drop the `source-port-except` / `destination-port-except`
// cases from compiler_firewall.go and the SourcePortsExcept / DestPortsExcept
// slices stay empty — assertStrSet then fails (expected [80 443] / [22], got
// nothing). Drop the schema leaves and SchemaValidate rejects the flat-set
// command, failing the round-trip below.

func TestFirewallPortExceptHierarchical(t *testing.T) {
	input := `firewall {
    family inet {
        filter pe {
            term t {
                from {
                    destination-port-except 80;
                    destination-port-except 443;
                    source-port-except 22;
                }
                then discard;
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	f := cfg.Firewall.FiltersInet["pe"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %#v", f)
	}
	term := f.Terms[0]
	assertStrSet(t, "destination-port-except", term.DestPortsExcept, []string{"80", "443"})
	assertStrSet(t, "source-port-except", term.SourcePortsExcept, []string{"22"})
}

func TestFirewallPortExceptFlatSetBracketList(t *testing.T) {
	cmds := []string{
		// Bracketed list collapses onto a single leaf's Keys (#2419) — the
		// compiler must read child.Keys[1:] AND child.Children.
		"set firewall family inet filter pe term t from destination-port-except [ 80 443 ]",
		"set firewall family inet filter pe term t from source-port-except 22",
		"set firewall family inet filter pe term t then discard",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// The new leaves must validate (they are schema-declared multi-value).
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected source/destination-port-except: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	f := cfg.Firewall.FiltersInet["pe"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("expected 1 term, got %#v", f)
	}
	term := f.Terms[0]
	// #2419: the whole bracket list must survive, not just the first element.
	assertStrSet(t, "destination-port-except", term.DestPortsExcept, []string{"80", "443"})
	assertStrSet(t, "source-port-except", term.SourcePortsExcept, []string{"22"})
}

// inet6 parity: the same leaves exist under family inet6.
func TestFirewallPortExceptInet6(t *testing.T) {
	cmds := []string{
		"set firewall family inet6 filter pe6 term t from destination-port-except 53",
		"set firewall family inet6 filter pe6 term t then discard",
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected inet6 destination-port-except: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	f := cfg.Firewall.FiltersInet6["pe6"]
	if f == nil || len(f.Terms) != 1 {
		t.Fatalf("expected 1 inet6 term, got %#v", f)
	}
	assertStrSet(t, "destination-port-except", f.Terms[0].DestPortsExcept, []string{"53"})
}
