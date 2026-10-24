package config

import (
	"fmt"
	"sort"
	"strings"
)

// #16456: the `chassis cluster` body and the `chassis cluster
// redundancy-group <n>` body were open-world.
//
// A misspelt statement at either level strict-committed clean with
// byte-identical warnings and compiled to nothing:
//
//	set chassis cluster redundancy-group 1 interface-monitr ge-0/0/1 weight 255
//	set chassis cluster redundancy-group 1 preemt
//	set chassis cluster redundancy-group 1 ip-monitorng family inet 10.0.0.1 weight 100
//	set chassis cluster redundancy-grup 1 node 0 priority 200
//	set chassis cluster heartbeat-intervalzq 200
//
// compileChassis dispatches RG statements through
// redundancyGroupStatements with no else arm, and reads the cluster
// body with FindChild calls that simply miss an unknown keyword, so
// the monitor / preempt / ip-monitoring the operator configured never
// reaches the compiled config. The cluster Monitor never watches the
// interface, a link-down deducts no weight, and no failover happens —
// discovered only during the outage it was meant to prevent, on both
// nodes, because config sync replicates the typo.
//
// This gate is the scoped AST pre-walk the fix direction requires. It
// is deliberately NOT `closedWorld: true` on `redundancy-group` or on
// `cluster`: that flag INHERITS (see #9017), so arming it on
// `redundancy-group <n>` would close every descendant
// (`interface-monitor`, the `ip-monitoring family inet <addr>` wildcard
// body, ...) and arming it on `cluster` would close the RG subtree
// beneath it — the #8882 measurement problem. This gate judges exactly
// two levels and inherits nothing.
//
// The permitted sets are READ FROM THE SSOTs that already exist so a
// statement declared later is permitted automatically (#9017's rule):
// at the cluster level, the keys of clusterStatements (the packed-line
// splitter table, bound to schemaChassis by
// TestClusterSplitterAndSchemaAgree_6672); at the RG level, the keys of
// redundancyGroupStatements (the compiler's own dispatch table). No
// third hand-written list is introduced.
//
// It runs on the AST (pre-walk, after compact normalization, before
// section compilation) for the reason the defect exists at all: an
// unknown statement at these levels compiles to NOTHING, so by the
// time cfg.Chassis.Cluster exists there is no trace of the dropped
// token left to validate. The RG half reads statements through
// redundancyGroupBody — the same splitter compileChassis dispatches
// from, which returns one node per statement and leaves an unknown
// packed token folded onto its predecessor — so a packed typo is
// judged in the predecessor's tail (see checkRGTail16456); the cluster
// half reads through clusterBodyStatements / normalizedClusterNode,
// the same splitter compileChassis reads, so packed cluster bodies and
// the flat-set chain shapes are judged exactly as compiled.
//
// Strict (commit / commit-check) hard-rejects the first offender.
// Lenient (Store.Load / Store.SyncApply) warns once per distinct
// finding so an already-persisted or peer-synced config still BOOTS
// (#1960); compilation continues with the pre-#16456 behaviour there
// (the dropped statement stays dropped — the warning is the
// diagnostic, exactly as the sibling AST gates #15046/#16450 do).
//
// Apply statements (apply-groups / apply-groups-except / apply-macro,
// #7029) are Junos meta statements permitted at any hierarchy point
// and are never judged, at either level. Quoted/bracketed tokens are
// authored values, never statement heads (#9635).

// clusterStatementTokens16456 returns the sorted statement keywords a
// `chassis cluster` body may contain, read from clusterStatements.
func clusterStatementTokens16456() []string {
	out := make([]string, 0, len(clusterStatements))
	for k := range clusterStatements {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rgStatementTokens16456 returns the sorted statement keywords a
// `redundancy-group` body may contain, read from
// redundancyGroupStatements.
func rgStatementTokens16456() []string {
	out := make([]string, 0, len(redundancyGroupStatements))
	for k := range redundancyGroupStatements {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type chassisClusterGate16456 struct {
	lenient  bool
	warnings []string
	seen     map[string]bool
}

func (g *chassisClusterGate16456) report(msg string) error {
	if !g.lenient {
		return fmt.Errorf("%s", msg)
	}
	if !g.seen[msg] {
		g.seen[msg] = true
		g.warnings = append(g.warnings, msg)
	}
	return nil
}

func (g *chassisClusterGate16456) checkCluster(tok string, declared []string) error {
	if tok == "" || isApplyStatementKeyword(tok) {
		return nil
	}
	if _, ok := clusterStatements[tok]; ok {
		return nil
	}
	return g.report(fmt.Sprintf(
		"chassis cluster: unknown statement %q (#16456): "+
			"the compiler reads only %s here; remove the typo — the line is dropped and the cluster runs without it",
		tok, strings.Join(declared, ", ")))
}

func (g *chassisClusterGate16456) checkRG(rgName, tok string, declared []string) error {
	if tok == "" || isApplyStatementKeyword(tok) {
		return nil
	}
	if _, ok := redundancyGroupStatements[tok]; ok {
		return nil
	}
	return g.report(fmt.Sprintf(
		"chassis cluster redundancy-group %s: unknown statement %q (#16456): "+
			"the compiler reads only %s here; remove the typo — the line is dropped, so no monitor, ip-monitoring or preempt it carried ever takes effect and the group does not fail over on it",
		rgName, tok, strings.Join(declared, ", ")))
}

// validateChassisClusterUnknownAST16456 is the #16456 gate. See file doc.
func validateChassisClusterUnknownAST16456(nodes []*Node, lenient bool) ([]string, error) {
	clusterDeclared := clusterStatementTokens16456()
	rgDeclared := rgStatementTokens16456()
	if len(clusterDeclared) == 0 || len(rgDeclared) == 0 {
		// Tables unreadable: decline to judge rather than refuse every
		// cluster config (mirrors #9323/#9552/#16450).
		return nil, nil
	}
	g := &chassisClusterGate16456{lenient: lenient, seen: map[string]bool{}}
	for _, n := range nodes {
		if n == nil || n.Name() != "chassis" {
			continue
		}
		if err := g.walkChassis(n, clusterDeclared, rgDeclared); err != nil {
			return g.warnings, err
		}
	}
	return g.warnings, nil
}

// walkChassis judges one `chassis` node. The cluster body is resolved
// through normalizedClusterNode — the same view compileChassis reads —
// so every spelling (container, packed on the cluster line, packed on
// the chassis line, sibling `cluster` blocks folded) is judged once, in
// compiled form. A chassis node with no cluster at all (standalone
// device-map box) has nothing to judge.
func (g *chassisClusterGate16456) walkChassis(chassis *Node, clusterDeclared, rgDeclared []string) error {
	cluster := normalizedClusterNode(chassis)
	if cluster == nil {
		return nil
	}
	for _, stmt := range cluster.Children {
		if stmt == nil || len(stmt.Keys) == 0 {
			continue
		}
		name := stmt.Name()
		if isApplyStatementKeyword(name) {
			continue
		}
		if name == "redundancy-group" {
			// The instance keyword itself resolved; judge its body.
			// (A misspelt `redundancy-grup` never reaches here — it is
			// not "redundancy-group", so the cluster-level check below
			// judges it as an unknown cluster statement.)
			for _, rgInst := range namedInstances([]*Node{stmt}) {
				if err := g.walkRG(rgInst.name, rgInst.node, rgDeclared); err != nil {
					return err
				}
			}
			continue
		}
		if err := g.checkCluster(name, clusterDeclared); err != nil {
			return err
		}
		// A known statement can still carry a folded packed tail:
		// the cluster splitter reserves only the statement's declared
		// value slot(s), so a typo packed after a value-carrying
		// statement (`authentication-key <psk> heartbeat-intervalzq
		// 200;` as one line) stays folded onto that statement's node
		// and never surfaces as its own child. Judge the tokens past
		// the value slot.
		if err := g.checkClusterTail16456(stmt, clusterDeclared); err != nil {
			return err
		}
	}
	return nil
}

// checkClusterTail16456 judges statement heads folded onto a KNOWN
// cluster statement's packed tail. Tokens at or past
// 1+clusterStatementArity(name) are not the statement's value; the
// first token there that is not itself a known cluster statement (a
// following statement the splitter would have separated had it been
// known — defensive; the splitter already separates those) is an
// unknown head. Only the first is reported: everything after it is
// that unknown statement's own tail. Quoted/bracketed tokens are
// authored values (#9635) and end the scan. Flag statements
// (arity 0) own no tail slot, so their first tail token is judged the
// same way.
func (g *chassisClusterGate16456) checkClusterTail16456(stmt *Node, clusterDeclared []string) error {
	from := 1 + clusterStatementArity(stmt.Name())
	for i := from; i < len(stmt.Keys); i++ {
		if stmt.KeyQuoted(i) || stmt.KeyBracketed(i) {
			return nil
		}
		tok := stmt.Keys[i]
		if isApplyStatementKeyword(tok) {
			return nil
		}
		if _, ok := clusterStatements[tok]; ok {
			// A following known statement the splitter separated in
			// every other shape; nothing folded to judge past it.
			return nil
		}
		return g.checkCluster(tok, clusterDeclared)
	}
	return nil
}

// walkRG judges the body statements of one redundancy-group instance,
// read through redundancyGroupBody (the compiler's own splitter).
func (g *chassisClusterGate16456) walkRG(rgName string, rgNode *Node, rgDeclared []string) error {
	for _, child := range redundancyGroupBody(rgNode) {
		if child == nil || len(child.Keys) == 0 {
			continue
		}
		name := child.Name()
		if isApplyStatementKeyword(name) {
			continue
		}
		if _, ok := redundancyGroupStatements[name]; !ok {
			if err := g.checkRG(rgName, name, rgDeclared); err != nil {
				return err
			}
			continue
		}
		// A known statement on a PACKED line absorbs every following
		// token that is not itself a known statement keyword (the
		// splitter only re-arms at known keywords), so a packed typo
		// after a known statement is folded into that statement's tail
		// and never surfaces as its own node. Judge the tail.
		if err := g.checkRGTail16456(rgName, child, rgDeclared); err != nil {
			return err
		}
	}
	return nil
}

// checkRGTail16456 judges tokens folded onto a KNOWN statement's tail
// by the packed splitter, plus the statement's child nodes.
//
// A token in the tail is a statement head only where the preceding
// statement cannot absorb it as a value:
//
//   - a flag statement (preempt / strict-vip-ownership /
//     allow-degraded-routing-takeover — redundancyGroupNoArgStatements)
//     takes no argument at all, so EVERY tail token past any child the
//     #6588 arity gate already owns is a would-be statement head. Only
//     the first is reported: everything after it is that unknown
//     statement's own tail (and when the statement also carries
//     children, the arity gate owns the whole shape — skip here to
//     avoid double-reporting the same line).
//   - `interface-monitor` / `ip-monitoring` are variadic: their tails
//     carry free-form entry names and attribute values
//     (`ge-0/0/1 weight 255`, `family inet 10.0.0.1 weight 100`) that
//     no local information distinguishes from a statement head — the
//     exact residual #6588/#6665 document for the splitter itself. Not
//     judged.
//   - `node` / `gratuitous-arp-count` tails are the fixed
//     `priority <n>` / `<count>` shapes; a typo there
//     (`node 0 priorty 200`) is owned by the closedWorld `node` schema
//     arm on the strict commit path (the issue's positive control).
//     Not judged.
//
// Child nodes of a flag statement are its block body
// (`preempt { delay 5; }`), owned by the #6588 arity gate. Children of
// other statements are entry/property bodies whose keywords belong to
// those statements' own grammars (monitorEntryNodes /
// packedStatementProps readers), not to the RG level. Not judged.
func (g *chassisClusterGate16456) checkRGTail16456(rgName string, child *Node, rgDeclared []string) error {
	if !redundancyGroupNoArgStatements[child.Name()] {
		return nil
	}
	if len(child.Children) > 0 {
		// Block body: the #6588 arity gate owns it.
		return nil
	}
	for i := 1; i < len(child.Keys); i++ {
		if child.KeyQuoted(i) || child.KeyBracketed(i) {
			return nil
		}
		return g.checkRG(rgName, child.Keys[i], rgDeclared)
	}
	return nil
}
