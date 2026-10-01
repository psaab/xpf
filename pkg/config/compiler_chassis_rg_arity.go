package config

import "fmt"

// compiler_chassis_rg_arity.go carries the #6588 commit-side gate for tokens
// attached to a redundancy-group statement that TAKES NO ARGUMENT.
//
// `preempt`, `strict-vip-ownership`, and `allow-degraded-routing-takeover` are
// flags: their compilers set a bool and never look at the node beyond its name.
// discarded in silence:
//
//	redundancy-group 1 preempt weight 255;      -> Preempt=true, `weight 255` gone
//	redundancy-group 1 preempt delay 5;         -> Preempt=true, `delay 5` gone
//	redundancy-group 1 preempt { delay 5; }     -> Preempt=true, the block gone
//
// This is the same silent-no-effect class as the packed-statement drop #6588
// fixes, and unlike the value-position collision documented on
// redundancyGroupStatements it needs no implausible input — a stray token or a
// half-remembered Junos option is ordinary operator typing. `preempt delay`,
// `preempt limit` and `preempt period` in particular are real Junos SRX syntax
// that xpf does not implement, so accepting them silently tells the operator
// they configured a preempt delay when nothing of the sort exists.
//
// Neither path caught it before this gate: SchemaValidate accepts
// `set chassis cluster redundancy-group 1 preempt delay 5` (measured), and the
// compiled struct is a plain bool with nowhere to record the discarded tokens,
// so the check has to run on the AST.
//
// Strictness follows the sibling chassis gates: hard-reject at commit /
// commit-check, downgrade to a cfg.Warnings entry on the tolerant load /
// peer-sync paths (#1960 no-brick).

// redundancyGroupNoArgStatements lists the redundancy-group statements that
// carry no argument.
//
// It is a SEPARATE set from redundancyGroupStatements rather than derived from
// it, because arity is not recoverable from a func value — every handler has
// the same signature whether or not it reads the node. The two are kept in step
// by TestRedundancyGroupNoArgStatementsAreRegistered_6588, which fails if a name
// here is not a registered statement.
//
// Adding a flag statement means adding it here as well as to the dispatch
// table. Leaving it out is not silent in the way a missing dispatch entry is —
// the statement still compiles — it only means its trailing tokens keep being
// ignored quietly.
var redundancyGroupNoArgStatements = map[string]bool{
	"preempt":                         true,
	"strict-vip-ownership":            true,
	"allow-degraded-routing-takeover": true,
}

// validateRGNoArgStatementsAST walks the chassis cluster subtree and reports
// every no-argument redundancy-group statement that carries tokens or a body.
//
// It reads the statement nodes through redundancyGroupBody, the same splitter
// compileChassis dispatches from, so the gate sees exactly the nodes the
// compiler sees — including the packed instance line and the bare
// `redundancy-group { <id> ... }` wrapper.
//
// Returns (warnings, nil) when lenient, (nil, error) on the first offender when
// strict.
func validateRGNoArgStatementsAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string

	emit := func(format string, args ...interface{}) error {
		msg := fmt.Sprintf(format, args...)
		if lenient {
			warnings = append(warnings, msg)
			return nil
		}
		return fmt.Errorf("%s", msg)
	}

	walkErr := forEachChild(nodes, "chassis", func(chassis *Node) error {
		return forEachChild(chassis.Children, "cluster", func(cluster *Node) error {
			for _, rgInst := range namedInstances(cluster.FindChildren("redundancy-group")) {
				for _, child := range redundancyGroupBody(rgInst.node) {
					name := child.Name()
					if !redundancyGroupNoArgStatements[name] {
						continue
					}
					// Keys[0] is the statement itself; anything after it was
					// written as an inline argument. Children are a block body.
					// Both are discarded by the compiler, so both are reported.
					if len(child.Keys) > 1 {
						if err := emit("chassis cluster redundancy-group %s %s: takes no "+
							"argument but carries %q — those tokens are silently discarded, so "+
							"the configuration does not do what it reads as; remove them",
							rgInst.name, name, child.Keys[1:]); err != nil {
							return err
						}
						continue
					}
					if len(child.Children) > 0 {
						if err := emit("chassis cluster redundancy-group %s %s: takes no "+
							"argument but carries a %q block — it is silently discarded, so the "+
							"configuration does not do what it reads as; remove it",
							rgInst.name, name, child.Children[0].Name()); err != nil {
							return err
						}
					}
				}
			}
			return nil
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return warnings, nil
}
