package config

// compiler_chassis_cluster_packed.go undoes a PACKED `chassis cluster` body
// (#6672) — the one-level-up twin of the redundancy-group packing
// compiler_system.go already undoes (#6588/#6665).
//
// THE DEFECT. A packed statement puts all its tokens on ONE node's Keys with no
// Children. compileChassis reads the cluster body with FindChild, i.e. off
// `.Children`, so all four spellings below had to be handled and only the first
// two were:
//
//	chassis { cluster { cluster-id 1; node 0; } }   -> compiles (container)
//	chassis { cluster cluster-id 1 node 0; }        -> ClusterConfig, EMPTY
//	chassis cluster { cluster-id 1; node 0; }       -> Cluster == nil
//	chassis cluster cluster-id 1 node 0;            -> Cluster == nil
//
// The blast radius is the whole stanza: cluster-id, node identity, the control
// PSK, the fabric addresses, every redundancy group. The commit SUCCEEDS and
// `show configuration` echoes what the operator wrote, so nothing indicates the
// firewall is running with no cluster configuration at all. At the
// redundancy-group level the same shape lost one group's election priority
// (#6588); here it loses the cluster.
//
// TWO CONSUMERS, ONE SPLITTER. The body is normalized BEFORE both the compiler
// and the schema walker, not inside each. That matters for more than tidiness:
// making the packed spelling COMPILE without also making it VALIDATE would open
// a range-gate escape that does not exist today. Every cluster value is gated by
// its typed schema leaf (`cluster-id` 0..255 — one byte of the RETH virtual MAC;
// `reth-advertise-interval` 10..40959 — the encodable range of a 12-bit VRRP
// wire field), and the schema WALKER only reaches a statement that sits at its
// modeled depth. A packed statement sits below it, so no validator fires. While
// the packed form compiled to nothing that was harmless; the moment it compiles,
// an ungated MAC byte and an ungated VRRP interval reach the runtime by writing
// the config on one line. Normalizing first means the EXISTING validators fire
// on the packed body unchanged — one source of bounds, no parallel table to
// drift.

// clusterStatements is the SINGLE SOURCE OF TRUTH for what a `chassis cluster`
// body may contain, and for how many tokens each statement consumes as its
// VALUE before the splitter may open another statement.
//
// Two consumers read it: the packed-line splitter below, and the tests that
// pin packed-vs-container agreement per statement. It is deliberately a
// keyword->arity map rather than a keyword->compiler-func dispatch table (the
// shape redundancyGroupStatements uses): compileChassis reads the cluster body
// as a flat if-chain of heterogeneous types (int, string, bool, Secret), and
// rewriting 150 lines of it into closures to derive the token set would be a
// much larger and riskier change than the defect warrants. The binding is
// instead BEHAVIOURAL — see TestEveryCompiledClusterStatementIsSplit_6672,
// which compiles each candidate keyword in container form and requires anything
// the compiler actually honours to appear here. That test is the reason this
// table cannot silently fall behind the compiler, and it does not model the
// compiler's SOURCE TEXT, which is the tool #6588 rejected.
//
// THE ARITY IS WHAT STOPS A VALUE TOKEN FROM RE-ARMING THE SPLITTER (#6665). A
// splitter with no positional state opens a new statement wherever a registered
// keyword appears, INCLUDING where a value is expected: `control-interface node`
// would otherwise compile to no control interface plus a fabricated `node`
// statement, silently changing which node this box believes it is. Every
// statement with a value slot reserves exactly one token.
var clusterStatements = map[string]int{
	// Value-carrying statements: exactly one token each.
	"cluster-id":                    1,
	"node":                          1,
	"reth-count":                    1,
	"heartbeat-interval":            1,
	"heartbeat-threshold":           1,
	"authentication-key":            1,
	"additional-authentication-key": 1,
	"control-interface":             1,
	"peer-address":                  1,
	"fabric-interface":              1,
	"fabric-peer-address":           1,
	"fabric1-interface":             1,
	"fabric1-peer-address":          1,
	"reth-advertise-interval":       1,
	"peer-fencing":                  1,
	"takeover-hold-time":            1,
	// `redundancy-group <id>` — the id is its value slot; everything after it
	// belongs to the group's own body until a cluster-only keyword or the next
	// `redundancy-group`. See clusterBodyStatements.
	"redundancy-group": 1,

	// Valueless flags: the token after them genuinely opens a statement.
	"control-link-recovery":         0,
	"strict-session-auth":           0,
	"configuration-synchronize":     0,
	"nat-state-synchronization":     0,
	"ipsec-session-synchronization": 0,
	"dhcp-lease-synchronization":    0,
	"hitless-restart":               0,
	"no-reth-vrrp":                  0,
	"private-rg-election":           0,
	"no-private-rg-election":        0,
	// Accepted for Junos compatibility and never compiled (schema_chassis.go
	// documents it as ignored). Registered anyway: an unregistered keyword is
	// not inert, it FOLDS onto whatever statement precedes it on a packed
	// line, so leaving a known-ignored statement out would corrupt its
	// NEIGHBOUR rather than itself.
	"control-ports": 0,
}

const clusterKeyword = "cluster"
const redundancyGroupKeyword = "redundancy-group"

// isClusterStatement reports whether tok opens a `chassis cluster` body
// statement.
func isClusterStatement(tok string) bool {
	_, ok := clusterStatements[tok]
	return ok
}

// clusterStatementArity is how many tokens tok consumes as its VALUE before the
// splitter may open another statement.
func clusterStatementArity(tok string) int { return clusterStatements[tok] }

// clusterBodyStatements splits a packed `chassis cluster` body into one node per
// statement, then appends any real children (a config may carry both).
//
// skip is how many leading identity Keys to drop: 1 for a `cluster` node
// (`cluster <body>`), 2 for a chassis node carrying the whole thing
// (`chassis cluster <body>`).
//
// WHY THIS IS NOT packedStatementPropsArity. That helper (#6665) is flat: one
// open statement, an arity countdown, and any registered keyword re-arms it.
// A cluster body nests — `redundancy-group <id>` is followed by the GROUP's
// statements, which redundancyGroupBody re-splits with its own table — and the
// two tables OVERLAP on exactly one token, `node`. Under the flat rule
// `redundancy-group 1 node 0 priority 200` re-arms at `node`, which sets the
// CLUSTER's node identity to 0 and drops the group's election priority: the
// precise failure #6588 exists to prevent, reintroduced one level up.
//
// The nesting rule is therefore: once `redundancy-group` opens, a token
// re-arms the splitter only if it is `redundancy-group` itself or a cluster
// statement that is NOT also a redundancy-group statement. Overlap tokens
// resolve to the INNER scope, which is the only reading that preserves the
// group's own `node <id> priority <p>`. `reth-count` and friends are
// cluster-only, so a cluster statement written after a packed group is still
// compiled rather than swallowed.
//
// The RG tail additionally honours redundancyGroupStatementArity while it is
// open, so an interface named after a cluster-only keyword
// (`interface-monitor reth-count weight 255`) stays in the monitor's value slot
// instead of being stolen — the #6665 reservation, applied across the nesting
// boundary.
func clusterBodyStatements(cfgNode *Node, skip int) []*Node {
	stmts := splitClusterKeys(cfgNode.Keys, skip, cfgNode.Line, cfgNode.Column)
	// A CHILD can be packed too: `cluster { node 1 reth-count 2; }` is one child
	// carrying two statements, the shape #6588 undoes at the redundancy-group
	// level. Split each child's KEYS with the same table, and hand the child's
	// own Children to the LAST statement they belong to — a `redundancy-group`
	// body stays with the redundancy-group, where redundancyGroupBody re-splits
	// it with the RG table rather than this one.
	for _, c := range cfgNode.Children {
		if c == nil {
			continue
		}
		stmts = append(stmts, splitPackedClusterChild(c)...)
	}
	return stmts
}

// splitPackedClusterChild returns c unchanged — the SAME pointer, so Inactive,
// Annotation and key provenance are preserved — when its keys are already one
// statement, and otherwise the statements packed onto them.
func splitPackedClusterChild(c *Node) []*Node {
	parts := splitClusterKeys(c.Keys, 0, c.Line, c.Column)
	if len(parts) <= 1 {
		return []*Node{c}
	}
	parts[len(parts)-1].Children = c.Children
	parts[len(parts)-1].IsLeaf = c.IsLeaf && len(c.Children) == 0
	return parts
}

func splitClusterKeys(keys []string, skip, line, column int) []*Node {
	var stmts []*Node
	if len(keys) > skip {
		var cur *Node
		pending := 0   // value tokens the open CLUSTER statement must absorb
		inRG := false  // the open statement is a redundancy-group tail
		rgPending := 0 // value tokens the open RG statement must absorb
		for _, tok := range keys[skip:] {
			if pending > 0 {
				pending--
				cur.Keys = append(cur.Keys, tok)
				continue
			}
			if inRG && tok != redundancyGroupKeyword {
				if rgPending > 0 {
					rgPending--
					cur.Keys = append(cur.Keys, tok)
					continue
				}
				if isRedundancyGroupStatement(tok) {
					rgPending = redundancyGroupStatementArity(tok)
					cur.Keys = append(cur.Keys, tok)
					continue
				}
			}
			if cur == nil || isClusterStatement(tok) {
				cur = &Node{Keys: []string{tok}, Line: line, Column: column}
				stmts = append(stmts, cur)
				pending = clusterStatementArity(tok)
				inRG = tok == redundancyGroupKeyword
				rgPending = 0
				continue
			}
			cur.Keys = append(cur.Keys, tok)
		}
	}
	return stmts
}

// normalizedClusterNode returns the `chassis cluster` node with its body in
// Children, across all four spellings, or nil when the chassis stanza carries
// no cluster at all.
//
// The container spelling is returned UNTOUCHED — same pointer, no clone — so
// the overwhelmingly common path allocates nothing and cannot be perturbed by
// this code at all.
func normalizedClusterNode(chassisNode *Node) *Node {
	if chassisNode == nil {
		return nil
	}
	if cn := chassisNode.FindChild(clusterKeyword); cn != nil {
		if !clusterBodyNeedsSplit(cn, 1) {
			return cn // `cluster { ... }` — already one node per statement.
		}
		return synthesizedClusterNode(cn, 1)
	}
	// `chassis cluster ...` — the keyword is packed onto the chassis node's own
	// Keys, so FindChild sees nothing and the pre-#6672 compiler returned early
	// with Cluster == nil. This covers both the fully packed body and
	// `chassis cluster { ... }`, where the braces put the body in Children but
	// the `cluster` keyword is still on the chassis line.
	if len(chassisNode.Keys) > 1 && chassisNode.Keys[1] == clusterKeyword {
		return synthesizedClusterNode(chassisNode, 2)
	}
	return nil
}

func synthesizedClusterNode(n *Node, skip int) *Node {
	return &Node{
		Keys:     []string{clusterKeyword},
		Children: clusterBodyStatements(n, skip),
		Line:     n.Line,
		Column:   n.Column,
	}
}

// chassisClusterIsPacked reports whether a chassis node carries a cluster body
// in a spelling the container-shaped readers cannot see.
func chassisClusterIsPacked(chassisNode *Node) bool {
	if chassisNode == nil {
		return false
	}
	if cn := chassisNode.FindChild(clusterKeyword); cn != nil {
		return clusterBodyNeedsSplit(cn, 1)
	}
	return len(chassisNode.Keys) > 1 && chassisNode.Keys[1] == clusterKeyword
}

// clusterBodyNeedsSplit reports whether any statement of this cluster body is
// packed — on the cluster line itself (`cluster <body>`) or onto one of its
// children (`cluster { node 1 reth-count 2; }`, the #6588 shape at cluster
// level). False means every statement is already its own node and the caller
// must return the body untouched, which is the overwhelmingly common path.
func clusterBodyNeedsSplit(cn *Node, skip int) bool {
	if cn == nil {
		return false
	}
	if len(cn.Keys) > skip {
		return true
	}
	for _, c := range cn.Children {
		if c == nil {
			continue
		}
		if len(splitClusterKeys(c.Keys, 0, c.Line, c.Column)) > 1 {
			return true
		}
	}
	return false
}

// normalizePackedChassisCluster returns a tree whose packed `chassis cluster`
// bodies are expanded into children, so a reader that walks `.Children` — the
// schema walker, and compileChassis via normalizedClusterNode — sees the same
// statements for every spelling.
//
// It returns the ORIGINAL tree, uncloned, when nothing is packed. That is the
// common path and it must stay free; it also means a caller cannot tell the
// two apart by identity alone, which is why the test for this asserts on a
// tree that IS packed and fails loudly if the transform declined to run.
func normalizePackedChassisCluster(t *ConfigTree) *ConfigTree {
	if t == nil {
		return nil
	}
	var out []*Node
	for i, n := range t.Children {
		if n == nil || n.Name() != "chassis" || !chassisClusterIsPacked(n) {
			continue
		}
		if out == nil {
			out = make([]*Node, len(t.Children))
			copy(out, t.Children)
		}
		out[i] = normalizedChassisNode(n)
	}
	if out == nil {
		return t
	}
	return &ConfigTree{Children: out}
}

// normalizedChassisNode rebuilds one `chassis` node with its cluster body
// expanded, preserving every sibling statement (a `device-map` under a
// standalone box's chassis stanza must survive — #1956 R-7).
func normalizedChassisNode(chassisNode *Node) *Node {
	cluster := normalizedClusterNode(chassisNode)
	out := &Node{
		Keys:       []string{"chassis"},
		IsLeaf:     false,
		Annotation: chassisNode.Annotation,
		Inactive:   chassisNode.Inactive,
		Line:       chassisNode.Line,
		Column:     chassisNode.Column,
	}
	for _, c := range chassisNode.Children {
		if c != nil && c.Name() == clusterKeyword {
			continue // replaced by the normalized node below
		}
		// A `chassis cluster <body>` node's children ARE the cluster body and
		// were already folded in by clusterBodyStatements; keep siblings only
		// for the `chassis { ... }` shape.
		if len(chassisNode.Keys) > 1 && chassisNode.Keys[1] == clusterKeyword {
			continue
		}
		out.Children = append(out.Children, c)
	}
	if cluster != nil {
		out.Children = append(out.Children, cluster)
	}
	return out
}
