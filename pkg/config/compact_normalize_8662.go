package config

// Brace-elided ("compact") statement normalization — #8662, first increment of
// the #2419 normalizer.
//
// Junos accepts a stanza's body without braces:
//
//	match { source-address a1; }     the braced form
//	match source-address a1;         the same statement, braces elided
//
// The parser represents them differently. Braced gives a container node with a
// child; elided packs the whole tail onto the container's own Keys:
//
//	BLOCK    Keys=[match]                   children=[ Keys=[source-address a1] ]
//	COMPACT  Keys=[match source-address a1] children=[]
//
// A compiler stanza that reads only `prop.Children` — which most do — therefore
// sees nothing in the elided form, and the statement is silently dropped on a
// commit that reports success. `pkg/config/testdata/compact_block_divergences_2419.txt`
// is the measured inventory of that: 433 sites, of which 414 compile the elided
// spelling to a config identical to an EMPTY stanza.
//
// This pass rewrites the packed form into the braced form so both spellings
// compile identically. It is deliberately SCOPED for this increment (see
// compactNormalizeInScope) rather than applied to all 433: the full sweep is
// the #2419 normalizer proper, whose stated goal in
// compact_block_inventory_regen_2419_test.go is to "drive this file to zero
// data lines".
//
// WHY TRUNCATING THE TAIL IS SAFE HERE, and why that is not a general licence.
// Some containers DO read their packed tail — `redundancy-group 0 node 0
// priority 200` is the shipped HA config's spelling, and compileChassis reads
// the value straight out of the node's key tail (see the `packedTail` opt-in in
// schema.go). Moving such a tail into a child would BREAK those readers.
//
// Every site in scope here is one the inventory records as DIVERGENT with the
// elided form compiling to the empty stanza — which is a positive measurement
// that the tail is currently ignored at that container. So there is nothing to
// break: the value reaches no reader today. The inventory is the safety
// evidence, and a site may only be added to this pass's scope once it appears
// there.
func normalizeCompactStanzas(tree *ConfigTree) int {
	if tree == nil {
		return 0
	}
	return normalizeCompactStanzasWithScope(tree, compactNormalizeInScope)
}

// normalizeCompactStanzasWithScope is normalizeCompactStanzas with the scope
// decision supplied by the caller. Production has exactly one caller and passes
// compactNormalizeInScope; tests pass a recorder to observe which keys the pass
// consults, or a widened predicate to explore past a refusal.
//
// An injection point rather than a reassignable package var, deliberately: a
// mutable global is reassignable by anything in the package, a test that
// forgets to restore it poisons every later test, and it makes t.Parallel() a
// data race. None of those failure modes announce themselves. This shape has no
// rule to remember. (Design: team-lead, reviewing the var form.)
func normalizeCompactStanzasWithScope(tree *ConfigTree, inScope func(containerKeyword, head string) bool) int {
	if tree == nil {
		return 0
	}
	return normalizeCompactNodes(tree.Children, setSchema, inScope)
}

func normalizeCompactNodes(nodes []*Node, schema *schemaNode, inScope func(containerKeyword, head string) bool) int {
	if schema == nil {
		return 0
	}
	n := 0
	for i, node := range nodes {
		if node == nil || len(node.Keys) == 0 {
			continue
		}
		kw := node.Keys[0]
		child := schemaChildFor(schema, kw) // #9685
		if child == nil {
			continue
		}
		// #9620: a brace-elided routing instance packs its statements onto the
		// instance NAME's node, which no (container, head) scope pair can name.
		if schema == schemaRoutingInstances && child == schema.wildcard {
			n += normalizeElidedRoutingInstance9620(node, child)
		}
		// The node's own identity is its keyword plus its declared args.
		identity := 1 + child.args
		// #8763: a compoundKey container carries its second key as an
		// enumerated CHILD rather than an `args` token, so `identity` does not
		// count it. `family inet` is one node whose schema is
		// family.children["inet"]; without this the recursion below would hand
		// that node's children the schema for `family`, advancing the schema
		// one level where the node advanced two, and NOTHING beneath a braced
		// `family inet { … }` would ever be visited -- not "declined to fold",
		// never asked.
		//
		// It bites exactly where the second token is a child keyword. `unit 0`
		// is unaffected because there the second token is an instance arg and
		// `args` is precisely what `identity` counts. Every compoundKey
		// declaration in the schema is named `family`
		// (TestCompoundKeyNodesAreExactlyTheFamilyNodes8763), so this is a
		// bounded surface rather than an open-ended one.
		childSub := child
		if child.compoundKey && len(node.Keys) > identity {
			if sub, ok := child.children[node.Keys[identity]]; ok && sub != nil {
				identity++
				childSub = sub
			}
		}
		// #8850: a node may carry a packed tail AND a braced body at once --
		// `security { zones security-zone z1 { host-inbound-traffic { ... } } }`
		// is Keys=["zones","security-zone","z1"] with Children=[the zone body].
		// The old `len(node.Children) == 0` guard declined those silently, so an
		// elided container brace dropped the ENTIRE stanza: zones=0, screens=0,
		// filters=0, with no error on either path.
		//
		// The body must be re-attached UNDER the deepest packed node, never left
		// as a SIBLING of it. Leaving it as a sibling is wrong in the silent
		// direction and is the trap this fix nearly shipped: the zone then
		// EXISTS with an empty body, which reads as configured and is worse than
		// the zone being absent. Measured on the way: braced gave
		// hostInboundTraffic=[ping], sibling-attachment gave <nil>.
		//
		// Same rule packedBodyChildren already applies for READERS (#6821): they
		// spell one path, so the nested block belongs under the deepest packed
		// node.
		if len(node.Keys) > identity {
			head := node.Keys[identity]
			// The tail only reads as an elided BODY if its first token names a
			// child of this container. Otherwise it is this node's own
			// multi-value payload (a bracketed list, a multi: true leaf) and
			// must be left alone.
			// The container the scope predicate is asked about is the one that
			// actually HOLDS the head. After a compoundKey descent that is the
			// sub-key (`inet`), not the compound keyword (`family`) -- which is
			// the same pair production already asks for the separately-braced
			// spelling `family { inet filter …; }`, so the two spellings resolve
			// to one scope entry instead of two.
			ckw := kw
			if childSub != child && identity >= 2 {
				ckw = node.Keys[identity-1]
			}
			if _, isBody := childSub.children[head]; isBody && inScope(ckw, head) {
				// #8880: DECLINE rather than STRAND. The parser splits a run of
				// statements packed onto an elided container's line into
				// SIBLINGS, and only the first carries the container keyword:
				//
				//	security { policies from-zone a to-zone b {…} from-zone c to-zone d {…} }
				//	  -> [policies from-zone a to-zone b]{…}   and   [from-zone c to-zone d]{…}
				//
				// Folding only the first builds `policies { from-zone a … }` and
				// leaves the second as a sibling of `policies` — a `from-zone`
				// node directly under `security`, a position the schema does not
				// model and the compiler silently ignores. Measured: a whole
				// zone-pair policy set discarded on a clean commit.
				//
				// So if the NEXT sibling is a continuation of the container this
				// fold would create, take neither half: leave the tree exactly as
				// authored. Declining is the established response (#8866) and it
				// is the only one available here — absorbing the sibling would
				// mean rewriting the PARENT's child slice, which this walk does
				// not hold.
				//
				// The check is deliberately "is a declared child of the
				// container", not "is unambiguous". 348 of 384 (parent,
				// container) pairs share no child name, but 36 do — e.g.
				// `class-of-service > interfaces` shares `classifiers` with its
				// own parent — and for those a continuation cannot be told from
				// a sibling at all. Declining covers both.
				if declineStrandingFold8880(nodes, i, childSub) {
					continue
				}
				tail := append([]string(nil), node.Keys[identity:]...)
				body := node.Children
				// #8921: KeysQuoted and KeysBracketed are PER-KEY masks (ast.go:
				// nil, or exactly len(Keys)), so they have to move with the keys
				// or they describe the wrong tokens. This fold used to move only
				// Keys: the container kept a mask longer than its own Keys and
				// every statement it created carried none. The authored quote was
				// therefore gone by the time the #9027 self-repeat gate read it,
				// and `group g1 export A "export";` was REFUSED at commit while
				// `group g1 { export A "export"; }` committed -- two spellings of
				// one statement, split by the pass whose job is to make them one.
				quoted := keyMask8921(node.KeysQuoted, len(node.Keys))
				bracketed := keyMask8921(node.KeysBracketed, len(node.Keys))
				node.Keys = append([]string(nil), node.Keys[:identity]...)
				node.Children = nil
				node.IsLeaf = false
				stmts := splitPackedStatements8768(tail, childSub)
				// #8850: a braced body plus a MULTI-statement run is ambiguous --
				// nothing in the tree says which statement the body belongs to.
				// Measured: `address-book address-set s1 { address a1; } address a2
				// ...;` compiled to the SET ONLY, losing a2, because the body was
				// attached to the last statement while it belongs to the first.
				//
				// Decline rather than guess, per the #8768 rule for a tail outside
				// the modelled grammar. A single-statement run is unambiguous (the
				// body can only belong to it) and is exactly the zones/screens/
				// host-inbound shape this relaxation exists for.
				//
				// Restore and fall THROUGH to the recursion below rather than
				// `continue`: skipping it would leave the declined node's braced
				// body unvisited, which is a change master does not make.
				if len(body) > 0 && len(stmts) > 1 {
					node.Keys = append(node.Keys, tail...)
					node.Children = body
				} else {
					node.setKeysQuoted(maskSlice8921(quoted, 0, identity))
					node.setKeysBracketed(maskSlice8921(bracketed, 0, identity))
					// splitPackedStatements8768 returns consecutive slices of
					// tail, so each statement's mask starts where the previous
					// statement's keys ended.
					off := identity
					for i, stmt := range stmts {
						child := &Node{Keys: stmt, IsLeaf: true}
						child.setKeysQuoted(maskSlice8921(quoted, off, off+len(stmt)))
						child.setKeysBracketed(maskSlice8921(bracketed, off, off+len(stmt)))
						off += len(stmt)
						// The braced body belongs to the LAST packed statement --
						// the deepest node the run names. Attaching it to the
						// container, or to every statement, invents structure the
						// operator did not write.
						if i == len(stmts)-1 && len(body) > 0 {
							child.Children = body
							child.IsLeaf = false
						}
						node.Children = append(node.Children, child)
					}
					n++
				}
			}
		}
		// #9656 (M40): fan a security-zone group out into one zone statement per
		// member, before the statements under `zones` are folded and validated.
		if childSub == zonesSchema9656 {
			n += expandZoneGroups9656(node, childSub.children["security-zone"])
		}
		n += splitBracedPackedChildren8886(node, childSub)
		n += normalizeCompactNodes(node.Children, childSub, inScope)
	}
	return n
}

// splitPackedStatements8768 divides a packed tail into one node per STATEMENT,
// instead of moving the whole run into a single child.
//
// The fold emitted `tail` as one node, which is right only when the run holds
// one statement. A run may hold several, and then every statement after the
// first was swallowed into the first one's Keys and lost:
//
//	policy p1 pre-shared-key ascii-text SEKRIT mode main;
//	  before -> policy p1 { [pre-shared-key ascii-text SEKRIT mode main] }
//	  after  -> policy p1 { [pre-shared-key ascii-text SEKRIT] [mode main] }
//
// THE BOUNDARY IS ANSWERED BY consumeNodeKeys, NOT GUESSED. Asking "is this
// token a sibling keyword" is not sufficient and is actively wrong: a VALUE may
// coincide with a sibling keyword, and #4313 makes some tails open-world. The
// measured case is `then { source-nat pool P persistent-nat permit off; }`,
// where `off` is a source-nat child AND a value inside a sub-grammar the schema
// does not model. Splitting on the name invents a second translation action and
// rejects a config that commits today — there is a cell for it,
// TestOpenWorldTailContainingOffStillCommits_7033, and it is why the
// name-matching version of this function was abandoned.
//
// So this borrows packedBodyChildren's contract: consume each statement by the
// schema's own count, and THE MOMENT a token leaves the modelled grammar, stop
// and hand back the whole tail unsplit. Not guessing is the entire safety
// argument; a partial split is worse than none because it publishes a shape the
// operator did not write.
func splitPackedStatements8768(tail []string, container *schemaNode) [][]string {
	if len(tail) == 0 || container == nil || !container.packedStatements {
		return [][]string{tail}
	}
	var out [][]string
	rest := tail
	for len(rest) > 0 {
		childSchema := resolveSchemaChild(container, rest[0])
		if childSchema == nil {
			// Outside the modelled grammar: do not guess where the next
			// statement starts. Everything measured so far is discarded and the
			// tail is returned whole, which is the pre-#8768 behaviour.
			return [][]string{tail}
		}
		n, _ := consumeNodeKeys(rest, childSchema)
		if n <= 0 || n > len(rest) {
			return [][]string{tail}
		}
		// A CONTAINER head followed by more tokens is a NESTED ELISION, and the
		// run cannot be split through it: nothing says whether what follows is
		// the container's own elided BODY or a sibling statement. Splitting
		// guesses "sibling", and that guess silently reparents data:
		//
		//	global address-set s1 address a1;
		//	  split   -> address-set s1 (EMPTY) + a top-level address a1
		//	             with no prefix
		//	  whole   -> address-set s1 with member a1        (master, correct)
		//
		// The set still EXISTS after the bad split, just empty, with a phantom
		// address beside it -- an object that reads as configured, which is the
		// inversion this whole line of work exists to avoid. Both paths are
		// silent: strict and lenient accept it either way.
		//
		// Returning the tail whole is exactly the pre-#8768 behaviour for this
		// shape, so a container head costs the run its split rather than its
		// meaning.
		if len(childSchema.children) > 0 && n < len(rest) {
			return [][]string{tail}
		}
		out = append(out, append([]string(nil), rest[:n]...))
		rest = rest[n:]
	}
	if len(out) <= 1 {
		return [][]string{tail}
	}
	return out
}

// normalizeCompactForValidation returns a tree with every admitted compact
// stanza folded, for the typed-leaf walk to validate (issue 8867).
//
// It never mutates the argument: SchemaValidate runs on the operator's
// candidate tree, which the caller persists, so folding in place would rewrite
// the stored configuration as a side effect of checking it. When nothing folds
// the original is returned and the clone is discarded.
func normalizeCompactForValidation(tree *ConfigTree) *ConfigTree {
	if tree == nil {
		return nil
	}
	clone := tree.Clone()
	if normalizeCompactStanzas(clone) == 0 {
		return tree
	}
	return clone
}

// declineStrandingFold8880 reports whether the node at index i must NOT be
// folded because the sibling that follows it is a continuation of the container
// the fold would create.
//
// A continuation is a following sibling whose head names a declared child of
// that container. Such a sibling can only have come from the same packed run —
// the schema does not model it in the parent's position — so folding the first
// half while leaving it behind produces a tree the compiler cannot represent.
func declineStrandingFold8880(nodes []*Node, i int, container *schemaNode) bool {
	if container == nil || i+1 >= len(nodes) {
		return false
	}
	next := nodes[i+1]
	if next == nil || len(next.Keys) == 0 {
		return false
	}
	_, isChild := container.children[next.Keys[0]]
	return isChild
}

// splitBracedPackedChildren8886 splits a child statement whose Keys carry MORE
// THAN ONE statement, inside an INTACT braced body.
//
//	security { flow { aging { early-ageout 10 high-watermark 90; } } }
//	  parses to ONE leaf  [early-ageout 10 high-watermark 90]
//	  compiles to         early-ageout=10, high-watermark=0
//
// The value of every statement after the first is silently discarded, on a
// clean commit. This is NOT the brace-elision shape: the container's brace is
// present and nothing is elided — the operator merely omitted a semicolon,
// which is the commonest typo there is, and `show configuration` renders it back
// exactly as written.
//
// It reuses splitPackedStatements8768 and is gated on the SAME opt-in, so one
// flag governs both spellings of a packed run rather than a container being
// fixed for the elided form and left broken for the braced one. A container that
// has not opted in is untouched.
//
// Unlike the #8880 stranding case this split is reachable: here the CONTAINER is
// the node being visited, so its Children slice is in hand and can be rewritten.
// There it was the parent's slice, which the walk does not hold.
func splitBracedPackedChildren8886(node *Node, container *schemaNode) int {
	if node == nil || container == nil || !container.packedStatements {
		return 0
	}
	var out []*Node
	changed := 0
	for _, ch := range node.Children {
		// Only a childless leaf can be a packed RUN. A node with children is a
		// braced body, and splitting it would have to decide which statement
		// the body belongs to — the ambiguity #8850 declines rather than guess.
		if ch == nil || len(ch.Children) > 0 || len(ch.Keys) < 2 {
			out = append(out, ch)
			continue
		}
		// #8921: the per-key masks travel with the keys onto every statement
		// built from a slice of ch.Keys, which otherwise loses the authored
		// quote/bracket bit of each token. (The split DECISION does not read
		// them yet; that, together with the #8437 fusion gate, is issue 9635.)
		quoted := keyMask8921(ch.KeysQuoted, len(ch.Keys))
		bracketed := keyMask8921(ch.KeysBracketed, len(ch.Keys))
		stmts := splitPackedStatements8768(ch.Keys, container)
		if len(stmts) < 2 {
			out = append(out, ch)
			continue
		}
		off := 0
		for _, st := range stmts {
			stmt := &Node{Keys: append([]string(nil), st...), IsLeaf: true}
			stmt.setKeysQuoted(maskSlice8921(quoted, off, off+len(st)))
			stmt.setKeysBracketed(maskSlice8921(bracketed, off, off+len(st)))
			off += len(st)
			out = append(out, stmt)
		}
		changed++
	}
	if changed > 0 {
		node.Children = out
	}
	return changed
}

// NormalizeCompactForScan returns a tree with every admitted compact stanza
// folded, for a reader that walks the RAW AST rather than the compiled config
// (issue 8898).
//
// The normalizer runs inside the compiler, so anything reading the compiled
// Config sees folded stanzas for free. A reader that scans the tree directly
// does not -- it sees whatever the operator typed, and an admitted pair is
// invisible to it. `configstore.effectiveMasterPasswordPRF` is one such reader:
// it resolves the at-rest KDF selector by walking `system` blocks, so
// admitting `system master-password` to the scope fixed the COMPILED config and
// changed nothing for the consumer that actually decides the encryption.
//
// This is the same shape as #8867, where SchemaValidate walked the
// un-normalized tree and validated nothing in the packed spelling. Same cause,
// different consumer: the fold is a property of the compile path, and every
// reader outside it has to opt in.
//
// It never mutates the argument -- callers hold trees that get persisted -- and
// returns the original when nothing folds.
// keyMask8921 returns m when it is a per-key mask over n keys, and nil
// otherwise. A mask of any other length is not provenance (see ast.go), so it
// must not be sliced as if it were.
func keyMask8921(m []bool, n int) []bool {
	if len(m) != n {
		return nil
	}
	return m
}

// maskSlice8921 is m[from:to], or nil when m carries no provenance. The
// setKeysQuoted / setKeysBracketed setters copy and normalize the result.
func maskSlice8921(m []bool, from, to int) []bool {
	if m == nil || from < 0 || from > to || to > len(m) {
		return nil
	}
	return m[from:to]
}

func NormalizeCompactForScan(tree *ConfigTree) *ConfigTree {
	return normalizeCompactForValidation(tree)
}
