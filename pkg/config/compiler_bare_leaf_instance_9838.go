package config

import "fmt"

// compiler_bare_leaf_instance_9838.go carries the #9838 commit-side gate: an
// interface or a routing instance written as a BARE LEAF compiles to nothing.
//
//	interfaces { ge-0/0/0; }      -> no interface (silently)
//	interfaces { ge-0/0/0 { } }    -> interface ge-0/0/0
//	routing-instances { ri1; }     -> no instance (silently)
//	routing-instances { ri1 { } }  -> instance ri1
//
// compileInterfaces skips every IsLeaf child (compiler_interfaces.go) and
// compileRoutingInstances skips single-key leaves (compiler_routing.go),
// while a zone written as a leaf compiles via namedInstances exactly like
// its braced spelling — so the two spellings of one statement diverge with
// no error and no warning. Measured at 9603f2a5f.
//
// The acceptance allows either compiling the leaf like its braced spelling
// or refusing it. This gate refuses: compiling the leaf would mint a new
// compiled shape (and need wildcard-group parity per #9801 plus keyword
// guards against phantom interfaces from apply-macro / traceoptions
// leaves), while refusing keeps every compiled shape unchanged and the zone
// behavior byte-identical.
//
// Strictness follows the sibling AST gates: hard-reject at commit /
// commit-check, downgrade to a cfg.Warnings entry on the tolerant load /
// peer-sync paths (#1960 no-brick). The lenient warning names the dropped
// statement, closing the silence on that path too — the instance is still
// not compiled there.
//
// Scope is the bare single-key leaf only. Multi-key leaves are other
// issues' territory: brace-elided routing instances are normalized to the
// braced shape before validation (#9620), and apply-macro / packed tails
// belong to the #2419 inventory, not to this gate.
func validateBareLeafInstance9838(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string

	emit := func(format string, args ...interface{}) error {
		msg := fmt.Sprintf(format, args...)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	// #5675/#5691/#5741: forEachChild unions across EVERY top-level root,
	// not just the first — a hierarchical config can split `interfaces { }`
	// or `routing-instances { }` across sibling roots and compileSections
	// dispatches every one.
	walkErr := forEachChild(nodes, "interfaces", func(ifaces *Node) error {
		for _, child := range ifaces.Children {
			if !child.IsLeaf || len(child.Keys) != 1 {
				continue
			}
			name := child.Keys[0]
			// Keywords directly under `interfaces` are not interfaces
			// (dup_named_blocks.go); a bare one stays whatever it was.
			if nonInterfaceIfKeyword[name] {
				continue
			}
			if err := emit("interfaces %s: written as a bare leaf (%q;) which "+
				"compiles to no interface — write %q with braces, or remove "+
				"it (#9838)", name, name, name+" { ... }"); err != nil {
				return err
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	walkErr = forEachChild(nodes, "routing-instances", func(ris *Node) error {
		for _, child := range ris.Children {
			if !child.IsLeaf || len(child.Keys) != 1 {
				continue
			}
			// An apply statement is not an instance (#9657); group
			// expansion strips apply-groups but the others stay.
			if isApplyStatementNode(child) {
				continue
			}
			name := child.Keys[0]
			if err := emit("routing-instances %s: written as a bare leaf "+
				"(%q;) which compiles to no routing instance — write %q "+
				"with braces, or remove it (#9838)", name, name, name+" { ... }"); err != nil {
				return err
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}
