package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #8939: a flat `set` command naming TWO leaves under one container builds a
// NESTED CHAIN, not siblings:
//
//	set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1 destination 10.0.0.2
//	  ... [tunnel] -> [source 10.0.0.1] -> [destination 10.0.0.2]
//
// The issue filed this as a GRAMMAR defect and proposed rejecting such a
// command at parse time. THAT REMEDY IS WRONG, and this file is the
// measurement that says so.
//
// The chain is built identically for every container. What differs is whether
// the CONTAINER'S COMPILER walks below the first leaf. Measured on the same
// grammar shape, one command each:
//
//	applications application myapp protocol tcp destination-port 8080
//	   packed  proto="tcp" dport="8080"      <- compiler walks (#6524)
//	   split   proto="tcp" dport="8080"
//
//	interfaces gr-0/0/0 unit 0 tunnel source A destination B
//	   packed  src="10.0.0.1" dst=""         <- compiler does NOT walk
//	   split   src="10.0.0.1" dst="10.0.0.2"
//
// So rejecting at parse time would reject a spelling that a large minority of
// containers handle CORRECTLY today — `applications` among them, which has a
// whole test file (compiler_application_chained_leaves_6524_test.go) devoted
// to the chained form working.
//
// THE RATCHET. This file compiles a packed pair and its split equivalent for
// every container declaring two value-taking sibling leaves, and records which
// containers LOSE the second leaf. A container may move from LOSE to WALK
// (that is the fix, and the fixture must be updated); it may never move from
// WALK to LOSE without this test failing, because that is a silent
// configuration-loss regression on an accepted spelling.
//
// WHAT THIS INSTRUMENT STRUCTURALLY CANNOT SEE, AND WHICH ONE CAN.
//
// AN AGGREGATE RATCHET CANNOT SEE A FIX THAT BREAKS A NEIGHBOUR INSIDE THE
// SAME ROW. A row records one container and two or three of its leaves. A
// change that makes the container start walking AND simultaneously stops it
// reading a DIFFERENT leaf produces exactly the same fixture delta as a clean
// fix: the row leaves the loser list either way.
//
// That is not hypothetical. Fixing `system login class` hoisted the children
// of every terminating leaf, which is wrong for a `multi` leaf whose children
// are VALUES (#2419: `permissions { view; configure; }`). The container began
// walking and `permissions` went inert in the same change, and THIS FILE
// REPORTED IT AS 53 -> 52 WITH NO OTHER ROW MOVING.
//
// `TestSchemaSpellingDifferentialGate` caught it, because it reports
// PER-SPELLING verdicts -- "read here, inert there" surfaces there as a
// disagreement rather than collapsing into one number. That is the same shape
// as #9077 deleting the #8807 predicate's container recovery while every
// aggregate stayed green: an instrument reporting a single number per subject
// cannot distinguish a fix from a fix-plus-a-break.
//
// So a green delta HERE is necessary and not sufficient. Land a container fix
// only with the differential gate green too.
//
// WHAT THIS INSTRUMENT DOES NOT SEE, stated because the count will be quoted:
//   - one pair per container (the two alphabetically-first eligible leaves),
//     so a container recorded as WALK may still lose a DIFFERENT pair;
//   - containers whose synthetic values do not compile are skipped, not
//     cleared -- they are unmeasured;
//   - depth is capped, and `groups` is not traversed.
//
// The recorded count is therefore a LOWER BOUND on affected containers and is
// not comparable to the issue title's figure, which was produced by a
// different (schema-shape) instrument. Two instruments disagreeing is a fact
// about the instruments until someone reconciles them.

const flatSetChainFixture = "testdata/flat_set_chain_losers_8939.txt"

func flatSetSyntheticValue(name string) string {
	switch {
	case strings.Contains(name, "address"), strings.Contains(name, "source"),
		strings.Contains(name, "destination"), strings.Contains(name, "gateway"),
		strings.Contains(name, "neighbor"), strings.Contains(name, "next-hop"):
		return "10.0.0.1"
	case strings.Contains(name, "port"):
		return "8080"
	case strings.Contains(name, "interface"):
		return "ge-0/0/0"
	case strings.Contains(name, "time"), strings.Contains(name, "limit"),
		strings.Contains(name, "size"), strings.Contains(name, "count"),
		strings.Contains(name, "priority"), strings.Contains(name, "weight"),
		strings.Contains(name, "metric"), strings.Contains(name, "mtu"),
		strings.Contains(name, "ttl"), strings.Contains(name, "timeout"):
		return "10"
	default:
		return "xpfval"
	}
}

// flatSetChainPairs enumerates (container, leafA, leafB) triples: two leaves
// under one container that take a value and declare no children of their own.
// flatSetChainRow is a container path plus the leaves to synthesize under it.
// It is a STRUCT rather than a flat []string because recovering the leaf count
// from a flat row required re-querying the schema, and that guess was wrong as
// soon as rows could be either two or three leaves wide: it split the instance
// placeholder `arg1` off as a leaf, producing rows like
// `security ike gateway [arg1 | address | external-interface]` whose synthesized
// config is nonsense. A fix to those containers then could not clear them.
// The count is data; it should not be re-derived.
type flatSetChainRow struct {
	container []string
	leaves    []flatSetLeaf
}

// flatSetLeaf is a leaf NAME together with its arity, because the two are
// needed together and re-deriving either has already gone wrong once here
// (flatSetLeafCount, #9078). ARITY IS THE POINT: a leaf declaring `args: 0` is
// a FLAG, and handing it a synthesized value produces a command no operator can
// write --
//
//	generator  monday all-day xpfval exclude xpfval   ->  exclude=false
//	operator   monday all-day exclude                 ->  exclude=true
//
// -- so all fifteen `schedulers scheduler <s> <weekday>` rows were UNCLEARABLE
// BY CONSTRUCTION. A correct fix to that family (#9081) cleared none of them,
// because the row asked a question about a malformed input. Making them clear
// would have required teaching the compiler to swallow a stray token after an
// args:0 flag, which is shaping production to satisfy an instrument.
//
// Third defect of this shape in this generator, after `arg1`-as-leaf and
// flatSetLeafCount: a SYNTHETIC CONFIG THAT IS NOT A CONFIG, producing a row no
// correct fix can clear. Found by lane-8388 reporting what actually cleared
// instead of what was predicted to clear.
type flatSetLeaf struct {
	name string
	args int
	// placeholder is the schema's OWN token shape for this slot, e.g.
	// "ascii-text <key>" for a 2-arg leaf. Used when args >= 2, where a single
	// value cannot fill the slot.
	//
	// #9149, the THIRD sub-cause of one class. A leaf with `args: 2` --
	// `security ike policy <p> pre-shared-key`, which Junos writes as
	// `pre-shared-key ascii-text <secret>` -- was handed ONE token. The
	// statement lands nowhere, split(2) equals split(1), vacuity control 2
	// fires, and the row is filed as "the last leaf is not observable at all":
	// a confident claim about the compiler produced by a command with the
	// wrong NUMBER OF ARGUMENTS.
	//
	// Three sub-causes now, one class, all of them the harness GUESSING WHERE
	// IT COULD HAVE ASKED:
	//
	//	the value derived from the leaf's NAME       -> #9108 (valueExamples)
	//	the value that fails a TYPE validator        -> #9108 (valueExamples)
	//	the value with the wrong ARITY               -> here (placeholder)
	//
	// Every one synthesizes a config the schema itself would reject, and in
	// every one the schema carried the answer on the node the whole time --
	// `valueExamples`, then `args`, then `placeholder`.
	placeholder string
	// example is the schema's OWN illustrative value for this slot
	// (`valueExamples[0]`), empty when the schema declares none.
	//
	// #9108: the generator used to derive every value from the leaf's NAME.
	// For a TYPED slot that is a guess against a validator, and it loses:
	// measured, 57 of the 530 leaves in census rows declare a valueType and
	// 42 of those received the bare placeholder `xpfval`, which their
	// validator rejects. `isis authentication-type` -- the leaf in the
	// MD5-downgrade finding -- was one of them, with the schema sitting on
	// the literal string `md5` the whole time.
	//
	// The consequence is worse than the args:0 defect, because it lands in
	// `vacuous` rather than `unmeasured`. `unmeasured` is honest about being
	// a non-result; VACUOUS READS AS A VERDICT -- "the last leaf is not
	// observable in the typed config at all" -- and that is a confident claim
	// about the compiler produced by a defect in the harness. Controlled by
	// lane-8388 at three containers:
	//
	//	lldp  transmit-interval  placeholder -> observable=false
	//	lldp  transmit-interval  REAL VALUE  -> observable=TRUE
	//	aging low-watermark      placeholder -> observable=false
	//	aging low-watermark      REAL VALUE  -> observable=TRUE
	//
	// And a `vacuous` row is EXCLUDED FROM THE LOSER LIST, so a container
	// whose third leaf is typed can never produce a three-leaf loser row --
	// which silently removes the two-versus-three discrimination #9078/#9079
	// exist to provide, at exactly the containers a typed third leaf makes
	// interesting.
	example string
}

// spell renders the leaf as an operator would write it: a flag alone, a
// value-taking leaf with its synthesized value.
func (l flatSetLeaf) spell() string {
	if l.args == 0 {
		return l.name
	}
	if l.args >= 2 {
		if toks := flatSetPlaceholderTokens(l.placeholder, l.args, l.name); toks != "" {
			return l.name + " " + toks
		}
	}
	if l.example != "" {
		return l.name + " " + l.example
	}
	return l.name + " " + flatSetSyntheticValue(l.name)
}

// flatSetPlaceholderTokens renders a multi-arg slot from the schema's own
// placeholder: a bare word is a LITERAL keyword and is kept verbatim, an
// <angled> segment is a value and gets a synthetic one. "ascii-text <key>"
// therefore yields "ascii-text xpfval".
//
// Returns "" when the placeholder does not account for exactly `args` tokens,
// rather than padding or truncating -- a slot this function cannot fill
// honestly should fall through to the existing path and be visible as such,
// not be filled with a guess wearing the schema's authority.
func flatSetPlaceholderTokens(placeholder string, args int, leafName string) string {
	if placeholder == "" {
		return ""
	}
	fields := strings.Fields(placeholder)
	if len(fields) != args {
		return ""
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if strings.HasPrefix(f, "<") && strings.HasSuffix(f, ">") {
			out = append(out, flatSetSyntheticValue(strings.Trim(f, "<>")))
			continue
		}
		out = append(out, f)
	}
	return strings.Join(out, " ")
}

// flatSetCollectorReach records what the COLLECTOR discarded before the census
// ran. THE RATCHET GUARDS THE POPULATION; THE POPULATION IS FILTERED FIRST.
//
// A guard, however correct, only ever sees what survived the filter above it --
// so a pre-filter blind spot is a different failure from a missing guard and
// cannot be caught by tightening one. lane-8015 found exactly this in the
// #8436 duplicate-block census: 139 eligible containers, 85 discarded by the
// collector, 9 examined, and the headline read `SILENT: 0`.
//
// This collector discards a container that declares fewer than two ELIGIBLE
// leaves, where eligible means `children == nil && wildcard == nil && !multi`.
// Both exclusions are defensible -- a leaf with children is a container, and a
// `multi` leaf absorbs a trailing run BY DESIGN (#2419 bracketed lists) -- but
// defensible is not the same as visible, and `losers=48` over 140 containers
// and over 376 are the same string.
type flatSetCollectorReach struct {
	visited  int // containers walked (depth<=6, groups excluded)
	zeroLeaf int // dropped: no eligible leaf
	oneLeaf  int // dropped: exactly one, so no two-leaf run is possible
	reached  int // 2+ eligible leaves -- these are what the census measures
}

var flatSetReach flatSetCollectorReach

func flatSetChainPairs() []flatSetChainRow {
	flatSetReach = flatSetCollectorReach{}
	var out []flatSetChainRow
	seen := map[string]bool{}
	var walk func(path []string, n *schemaNode, depth int)
	walk = func(path []string, n *schemaNode, depth int) {
		if depth > 6 || n == nil || n.children == nil {
			return
		}
		var leaves []flatSetLeaf
		for k, c := range n.children {
			if c != nil && c.children == nil && c.wildcard == nil && !c.multi {
				lf := flatSetLeaf{name: k, args: c.args, placeholder: c.placeholder}
				if len(c.valueExamples) > 0 {
					lf.example = c.valueExamples[0]
				}
				leaves = append(leaves, lf)
			}
		}
		sort.Slice(leaves, func(i, j int) bool { return leaves[i].name < leaves[j].name })
		if key := strings.Join(path, " "); !seen["reach:"+key] {
			seen["reach:"+key] = true
			flatSetReach.visited++
			switch len(leaves) {
			case 0:
				flatSetReach.zeroLeaf++
			case 1:
				flatSetReach.oneLeaf++
			default:
				flatSetReach.reached++
			}
		}
		if len(leaves) >= 2 {
			if key := strings.Join(path, " "); !seen[key] {
				seen[key] = true
				// BOTH WIDTHS, and the reason is a measured coverage loss.
				//
				// Two leaves cannot discriminate the correct fix from a
				// recursive descent (a descent passes at two and drops the
				// third), so #9078 widened this to three. But widening MOVED
				// containers out of the measured population: `security ike
				// gateway` and `security ipsec gateway` were two-leaf losers,
				// and at three leaves they fall into the unmeasured/vacuous
				// buckets -- so a real fix to both changed the loser list by
				// exactly nothing. Verified by taking that fix onto this
				// ratchet: the fixture came back byte-identical, 34 before and
				// 34 after, while `vacuous` moved 42->44.
				//
				// So neither width alone is the instrument. Two leaves has the
				// coverage; three leaves has the discrimination. Emitting both
				// keeps each container's total-loss row AND, where a third
				// eligible leaf exists, the row that a descent-shaped fix
				// cannot clear.
				cp := append([]string{}, path...)
				out = append(out, flatSetChainRow{cp, append([]flatSetLeaf{}, leaves[:2]...)})
				if len(leaves) >= 3 {
					out = append(out, flatSetChainRow{cp, append([]flatSetLeaf{}, leaves[:3]...)})
				}
			}
		}
		var keys []string
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c := n.children[k]
			if c == nil || c.children == nil {
				continue
			}
			np := append(append([]string{}, path...), k)
			for i := 0; i < c.args; i++ {
				np = append(np, "arg1")
			}
			walk(np, c, depth+1)
			if c.wildcard != nil {
				walk(append(append([]string{}, np...), "wname"), c.wildcard, depth+1)
			}
		}
	}
	walk(nil, setSchema, 0)
	return out
}

// flatSetAdmitted reports whether the CLOSED-WORLD typed-leaf gate accepts
// these lines -- i.e. whether an operator could commit them.
//
// #9088: THIS COLUMN WAS MISSING AND ITS ABSENCE CONFLATED TWO DEFECT CLASSES
// WITH DIFFERENT SEVERITIES. This census calls CompileConfig, but the operator
// path is `Store.Commit -> compileTree -> compileTreeStrict`, which runs
// `schemaValidateExpandedTreeForNode` FIRST. So every row here has been
// measuring the TOLERANT channel and being reported as the operator channel.
//
//	rejected by the gate   the packed spelling cannot be typed. The compiler
//	                       defect is real but reachable only through
//	                       `Store.Load` (boot from the persisted DB) and
//	                       `Store.SyncApply` (HA config sync from the peer),
//	                       which use compileTreeLenient and downgrade the same
//	                       gate to a slog.Warn -- so the value is truncated
//	                       where no operator is watching.
//
//	accepted by the gate   operator-reachable. Commits clean, renders in `show
//	                       configuration`, enforces less than it says.
//
// The discriminator is NOT the container: it is whether the schema DECLARES
// the leaves. A fully declared container catches the packed run on its own
// arity check; one whose leaves the compiler reads but `setSchema` never
// declared has no closed-world check to fail, so the run sails through. THE
// SCHEMA BEING BEHIND THE COMPILER IS WHAT MAKES A SITE OPERATOR-REACHABLE --
// the class is a property of the (container, declaration) pair, not of the
// container. Found by lane-8388.
//
// This calls SchemaValidateWithDefinitions directly rather than
// configstore.compileTreeStrict, because configstore imports config. The
// census fixtures carry no `groups` and no `inactive:` nodes, so the
// expansion and stripping that wrapper performs are identity here; if a
// fixture ever gains either, this approximation stops being one.
// flatSetAdmittedAnyOrder reports whether ANY leaf order is admitted.
//
// #9100: the channel column tested the ALPHABETICAL order only, which is not
// what an operator is constrained to.
//
// #9113 CORRECTS THE RULE THIS COMMENT USED TO STATE. It said a flat run is
// rejected iff the leaf it STARTS at declares a type/validator. That is HALF.
// Measured through compileTreeStrict across four containers:
//
//	container                    unknown-kw   run@untyped   run@typed
//	system login class           ACCEPT       ACCEPT        REJECT
//	security ike gateway         ACCEPT       ACCEPT        REJECT
//	security ipsec proposal      REJECT       REJECT        REJECT
//	security flow tcp-session    REJECT       --            REJECT
//
//	A flat run is ACCEPTED iff the container is OPEN-WORLD *and* the leaf it
//	starts at is UNTYPED. Either condition alone rejects it.
//
// `security ipsec proposal` is the counter-example that falsifies the
// leaf-only form: its starting leaf is untyped (`validator=false valueType=0`)
// and the run is rejected anyway, because #4313 made that container
// closed-world. The container half is lane-8526's (their #9091 measures it
// directly at 102 containers); the leaf half is lane-8388's; NEITHER IS THE
// DISCRIMINATOR ALONE.
//
// THE COLUMN ITSELF WAS NEVER WRONG, and the distinction matters for how much
// to trust it: it calls SchemaValidateWithDefinitions, which is the real gate,
// so every row's verdict is measured rather than derived from this rule. What
// was wrong is the EXPLANATION -- the third time this file has carried a
// correct measurement under a wrong account of why.
//
// The mechanism, now stated for the leaf half only: a validated leaf routes to
// the typed-leaf branch, whose modifier-child check refuses the trailing
// tokens, while an untyped `args:1` leaf falls through to the container branch
// that by #3332's compiler-faithful contract deliberately ignores leftover
// Keys. That is why REACHABILITY IS ORDER-DEPENDENT WITHIN AN OPEN-WORLD
// CONTAINER:
//
//	ike gateway   address A external-interface E   ACCEPTED
//	ike gateway   version v2-only address A        SCHEMA-REJECT
//	login class   allow-commands "x" idle-timeout 30   ACCEPTED
//	login class   idle-timeout 30 allow-commands "x"   SCHEMA-REJECT
//
// Testing one order therefore makes `lenient-only` unsound: it means "not
// reachable in the order I happened to synthesize", and an operator types
// whichever order they like. Measured: 21 rows flip to OPERATOR once every
// first-leaf position is tried -- among them `chassis cluster
// redundancy-group` and `protocols bgp`.
//
// OPERATOR is the dangerous verdict, so the column must take the union. A
// false `lenient-only` hides an operator-reachable silent drop; a false
// OPERATOR only over-warns.
func flatSetAdmittedAnyOrder(base string, leaves []flatSetLeaf) bool {
	for i := range leaves {
		reordered := append([]flatSetLeaf{leaves[i]},
			append(append([]flatSetLeaf{}, leaves[:i]...), leaves[i+1:]...)...)
		line := base
		for _, lf := range reordered {
			line += " " + lf.spell()
		}
		if flatSetAdmitted([]string{line}) {
			return true
		}
	}
	return false
}

func flatSetAdmitted(lines []string) bool {
	tr := &ConfigTree{}
	for _, l := range lines {
		toks, err := ParseSetCommand(l)
		if err != nil {
			return false
		}
		if err := tr.SetPath(toks); err != nil {
			return false
		}
	}
	return SchemaValidateWithDefinitions(tr, tr, nil) == nil
}

func flatSetCompile(lines []string) (*Config, error) {
	tr := &ConfigTree{}
	for _, l := range lines {
		toks, err := ParseSetCommand(l)
		if err != nil {
			return nil, err
		}
		if err := tr.SetPath(toks); err != nil {
			return nil, err
		}
	}
	return CompileConfig(tr)
}

// TestFlatSetChainWalkRatchet8939 is the ratchet. It also carries the two
// controls that make its numbers mean anything.
func TestFlatSetChainWalkRatchet8939(t *testing.T) {
	// ---- CONTROL 1 (the claim the issue's remedy would break) -------------
	// `applications` MUST compile the packed chain identically to the split
	// form. If this ever fails, the "reject at parse time" remedy stops being
	// wrong for the reason stated above and this file's argument needs
	// re-deriving rather than re-running.
	appPacked, err := flatSetCompile([]string{
		"set applications application myapp protocol tcp destination-port 8080",
	})
	if err != nil {
		t.Fatalf("control: packed applications did not compile: %v", err)
	}
	appSplit, err := flatSetCompile([]string{
		"set applications application myapp protocol tcp",
		"set applications application myapp destination-port 8080",
	})
	if err != nil {
		t.Fatalf("control: split applications did not compile: %v", err)
	}
	if !reflect.DeepEqual(appPacked, appSplit) {
		t.Errorf("CONTROL FAILED: `applications` no longer walks the packed chain.\n" +
			"This file argues that #8939's parse-time rejection is wrong BECAUSE some\n" +
			"compilers walk the chain correctly, and `applications` is the witness.\n" +
			"If the witness is gone, re-derive the argument -- do not just update it.")
	}
	if got := appPacked.Applications.Applications["myapp"]; got == nil || got.DestinationPort != "8080" {
		t.Errorf("CONTROL is VACUOUS: packed applications did not set destination-port; "+
			"got %+v. Two equal-but-empty compiles prove nothing.", got)
	}

	// ---- CONTROL 2 (the witness on the other side) ------------------------
	tunPacked, err := flatSetCompile([]string{
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1 destination 10.0.0.2",
	})
	if err != nil {
		t.Fatalf("control: packed tunnel did not compile: %v", err)
	}
	u := flatSetFirstUnitTunnel(tunPacked, "gr-0/0/0")
	if u == nil || u.Source != "10.0.0.1" || u.Destination != "10.0.0.2" {
		t.Fatalf("CONTROL FIXED: packed tunnel must retain both source and destination; got %+v", u)
	}

	// ---- the census -------------------------------------------------------
	empty, _ := flatSetCompile(nil)
	var losers []string
	var walked, vacuous, unmeasured int
	for _, p := range flatSetChainPairs() {
		cont, leaves := p.container, p.leaves
		base := "set " + strings.Join(cont, " ")

		packedLine := base
		var splitLines []string
		for _, lf := range leaves {
			packedLine += " " + lf.spell()
			splitLines = append(splitLines, base+" "+lf.spell())
		}
		packed, ep := flatSetCompile([]string{packedLine})
		split, es := flatSetCompile(splitLines)
		if ep != nil || es != nil || packed == nil || split == nil {
			unmeasured++
			continue
		}
		if reflect.DeepEqual(packed, split) {
			// VACUITY CONTROL 1: both empty proves nothing about walking.
			if empty != nil && reflect.DeepEqual(packed, empty) {
				vacuous++
				continue
			}
			// VACUITY CONTROL 2, and it is the one that matters at three
			// leaves. An equal comparison means nothing if the LAST leaf is
			// not observable in the typed config at all: both spellings then
			// compile to the same thing for a reason that has nothing to do
			// with walking the chain, and the row reports WALKED having
			// measured nothing.
			//
			// Found by the count moving the WRONG WAY. Going from two leaves
			// to three moved containers from LOSE to WALK -- `schedulers
			// scheduler <s> friday` among them -- which cannot happen if the
			// measurement is sound, because a third leaf can only expose more
			// loss. Without this control the three-leaf ratchet reported 34
			// losers and 45 walked, and four of those "fixes" were leaves the
			// compiler never reads.
			if prev, e := flatSetCompile(splitLines[:len(splitLines)-1]); e == nil &&
				prev != nil && reflect.DeepEqual(split, prev) {
				vacuous++
				continue
			}
			walked++
			if os.Getenv("SHOW_WALKED_8939") != "" {
				wn := make([]string, 0, len(leaves))
				for _, lf := range leaves {
					wn = append(wn, lf.name)
				}
				fmt.Printf("WALKED %s [%s]\n", strings.Join(cont, " "), strings.Join(wn, " | "))
			}
			continue
		}
		// HOW MUCH is lost, not merely that something is. With three leaves
		// this separates the two fix shapes: a recursive descent recovers leaf
		// B and still drops C, which is `partial`; total loss is `total`.
		kind := "differs"
		if prefix, e := flatSetCompile(splitLines[:1]); e == nil && prefix != nil &&
			reflect.DeepEqual(packed, prefix) {
			kind = "total"
		} else if len(splitLines) > 2 {
			if prefix, e := flatSetCompile(splitLines[:2]); e == nil && prefix != nil &&
				reflect.DeepEqual(packed, prefix) {
				kind = "partial(descent-shaped)"
			}
		}
		names := make([]string, 0, len(leaves))
		for _, lf := range leaves {
			names = append(names, lf.name)
		}
		// #9088: the ADMISSION CHANNEL, because a row an operator can type is
		// a different defect from one only boot and HA sync can reach.
		channel := "lenient-only"
		if flatSetAdmittedAnyOrder(base, leaves) {
			channel = "OPERATOR"
		}
		losers = append(losers, strings.Join(cont, " ")+"  ["+
			strings.Join(names, " | ")+"]  "+kind+"  "+channel)
	}
	sort.Strings(losers)

	// #10078's security-level schema completion changes the combined-tree
	// population from the current-master baseline
	// `walked=111,vacuous=38,unmeasured=80` to
	// `walked=111,vacuous=36,unmeasured=83`; the three loser rows are
	// byte-for-byte unchanged, so no loss signal was cleared. Collector reach
	// moves from 379/139 to 385/140 as the schema population is admitted.
	// This is a measured population-count ratchet update, not a loser-set
	// relaxation.
	//
	// THE COUNTS ARE PART OF THE FIXTURE, and that is a mutation result, not a
	// flourish. With only the loser set recorded, deleting the observability
	// vacuity control above passes: removing it moves rows between `vacuous`
	got := fmt.Sprintf("# counts: losers=%d walked=%d vacuous=%d unmeasured=%d\n"+
		"# collector reach: %d containers walked, %d reached the census "+
		"(%d dropped: no eligible leaf, %d dropped: only one)\n",
		len(losers), walked, vacuous, unmeasured,
		flatSetReach.visited, flatSetReach.reached,
		flatSetReach.zeroLeaf, flatSetReach.oneLeaf) +
		strings.Join(losers, "\n") + "\n"
	if os.Getenv("UPDATE_8939") != "" {
		if err := os.WriteFile(flatSetChainFixture, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s (%d losers, %d walked, %d vacuous, %d unmeasured)",
			flatSetChainFixture, len(losers), walked, vacuous, unmeasured)
		return
	}
	wantB, err := os.ReadFile(flatSetChainFixture)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with UPDATE_8939=1)", flatSetChainFixture, err)
	}
	if string(wantB) != got {
		t.Errorf("the #8939 flat-set chain-loss set MOVED.\n"+
			"measured %d losers, %d walked, %d vacuous, %d unmeasured.\n\n"+
			"A container leaving this list is a FIX -- regenerate with UPDATE_8939=1\n"+
			"and name the fix in the commit. A container ENTERING it is a silent\n"+
			"configuration-loss regression: an accepted `set` command now drops its\n"+
			"second leaf with no error, and `show configuration` still renders what\n"+
			"the operator typed.\n\ndiff:\n%s",
			len(losers), walked, vacuous, unmeasured, flatSetDiff(string(wantB), got))
	}
	// THIS FLOOR WAS WRONG AND FIRING IT IS HOW I FOUND OUT. It read
	// `walked < 20`, on the belief -- published in PR #8999 and on #8939 --
	// that ~41 containers demonstrably walk the chain. Two corrections:
	//
	//  1. Most of that 41 was VACUOUS. Those rows compared equal because the
	//     last leaf is not observable in the typed config at all, not because
	//     any compiler walked anything. With the observability control the
	//     honest number is 5.
	//  2. `applications` -- the witness the whole argument rests on -- is NOT
	//     IN THIS POPULATION. Its match leaves are `multi` or carry children,
	//     so the eligibility predicate excludes them. The count never had
	//     anything to say about it.
	//
	// So the argument against a parse-time rejection does not rest on the
	// census count and never did. It rests on the `applications` control at
	// the top of this test, which drives a real value through a real compile
	// and asserts it (`dport == "8080"`). That control is the floor.
	if walked < 1 {
		t.Errorf("zero containers in the census population walk the chain. That is "+
			"not fatal to this file's argument -- the `applications` control above "+
			"carries it -- but it means the census can no longer corroborate it, "+
			"and the issue comment quoting these numbers should say so. (walked=%d, "+
			"vacuous=%d, losers=%d)", walked, vacuous, len(losers))
	}
}

func flatSetFirstUnitTunnel(c *Config, iface string) *TunnelConfig {
	i := c.Interfaces.Interfaces[iface]
	if i == nil {
		return nil
	}
	for _, u := range i.Units {
		if u.Tunnel != nil {
			return u.Tunnel
		}
	}
	return i.Tunnel
}

func flatSetDiff(want, got string) string {
	w := map[string]bool{}
	for _, l := range strings.Split(want, "\n") {
		if l != "" {
			w[l] = true
		}
	}
	g := map[string]bool{}
	for _, l := range strings.Split(got, "\n") {
		if l != "" {
			g[l] = true
		}
	}
	var b strings.Builder
	for l := range g {
		if w[l] {
			continue
		}
		if strings.HasPrefix(l, "# counts:") {
			fmt.Fprintf(&b, "  ! counts moved, now: %s\n", strings.TrimPrefix(l, "# counts: "))
			continue
		}
		if strings.HasPrefix(l, "# collector reach:") {
			fmt.Fprintf(&b, "  ! COLLECTOR REACH moved, now: %s\n",
				strings.TrimPrefix(l, "# collector reach: "))
			continue
		}
		fmt.Fprintf(&b, "  + NEWLY LOSING (regression): %s\n", l)
	}
	for l := range w {
		if g[l] {
			continue
		}
		if strings.HasPrefix(l, "# counts:") {
			fmt.Fprintf(&b, "  ! counts were:       %s\n", strings.TrimPrefix(l, "# counts: "))
			continue
		}
		if strings.HasPrefix(l, "# collector reach:") {
			fmt.Fprintf(&b, "  ! COLLECTOR REACH was:        %s\n",
				strings.TrimPrefix(l, "# collector reach: "))
			continue
		}
		fmt.Fprintf(&b, "  - no longer losing (fixed):  %s\n", l)
	}
	return b.String()
}
