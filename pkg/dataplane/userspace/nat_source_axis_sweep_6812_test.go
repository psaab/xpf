package userspace

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #6812 round 10: the axis sweep, CLOSED OVER THE STRUCT RATHER THAN OVER A
// LIST OF CALLS.
//
// Round 9 asked the anti-coincidence question "of every axis, in both
// directions" — but the axes were a hand-written sequence of helper calls, so a
// column nobody remembered to sweep was still silently unguarded. Round 9's own
// sentence about round 8 ("the answer was a list, and a list is exactly what
// failed") applied to round 9 too: it had moved the list up one level, from
// axis names to helper calls, not removed it.
//
// The concrete holes that closure at that level left open, all of them real:
//
//   - CounterID. The builder fixture called buildSourceNATSnapshots(cfg, nil),
//     so every emitted ID was zero while production supplies populated
//     FNV-derived IDs. A stable (tier, CounterID) tiebreak reorders production
//     and was invisible here.
//   - Pool cardinality and port capacity. Every pool had exactly one member and
//     the default 1024-65535 range, so a sort by len(PoolAddresses), by port
//     capacity, or by derived charge was a no-op on this fixture and not in
//     general.
//   - Anything else the author was not thinking about — which is the whole
//     failure mode, and the reason the answer cannot be another list.
//
// So the sweep walks the STRUCT. collectAxisKeys6812 reflects over every field
// of the value a comparator would read, recursing into nested structs and
// pointers, and emits one column per field plus a `.len` column per slice or
// map. A field added to SourceNATRuleSnapshot later joins the sweep with no
// edit here; a field whose type has no order-preserving encoding hard-FAILS
// rather than being skipped. That is closure at FIELD granularity, by
// construction.
//
// WHAT THIS IS STILL NOT CLOSED OVER, stated plainly rather than left for the
// next reviewer to find: keys DERIVED from fields by arithmetic. A comparator
// may key on (PortHigh-PortLow+1), on a computed budget charge, or on a prefix
// length — none of which is a field, and no reflective walk can enumerate the
// functions someone might write. Field-level closure does not imply derived-key
// coverage either: every pool member address can differ (column varies) while
// every pool has exactly one member (len constant). The two mitigations, both
// explicit:
//
//	(a) `.len` of every slice is swept mechanically, which covers the
//	    cardinality shape;
//	(b) the remaining derived keys a caller cares about are added as FIELDS OF A
//	    WRAPPER STRUCT that the sweep then treats like any other column. That
//	    wrapper's field list IS a list, and it is the only list left. It is one
//	    place, and it is visible.
//
// And the exemption round 9 got wrong. Round 9 skipped a CONSTANT column
// silently, on the argument that a stable sort keyed on a value identical for
// every element cannot permute anything. That argument is sound only when the
// column is invariant for every PRODUCTION input. Fixture-only constancy is not
// regression coverage — it is a blind spot. So a constant column is no longer
// skipped: it must be REGISTERED, and its registration records which of the two
// it is. An unregistered constant column fails; a registered column that turns
// out to vary everywhere fails as stale. The registries below are therefore the
// honest enumeration of what this fixture does not guard.

// axisExemption6812 records a column a fixture does not vary, and — the
// distinction round 10 turns on — whether it can vary in production at all.
//
// Round 11: the productionConstant claim is no longer taken on trust. Round 10
// checked fixture constancy and stale names mechanically and left the harder
// half — "is this really invariant for every production input?" — as prose.
// Marking, say, a per-rule PoolName production-constant would have stayed green,
// and Junos allows a pool per rule. That is the registry's own version of the
// hole it exists to close. Every productionConstant entry now carries a WITNESS:
// an independently built sequence, constructed to make the column VARY if the
// claim were false. TestProductionConstantAxesAreWitnessed_6812 runs them.
type axisExemption6812 struct {
	// productionConstant is true ONLY when the column is invariant for every
	// input the production path can produce. A stable sort keyed on such a
	// column is a no-op everywhere, so there is genuinely nothing to be blind
	// to and the exemption costs no coverage.
	//
	// false records a real BLIND SPOT: the column varies in production but not
	// in this fixture, so a sort keyed on it would reorder production and stay
	// green here. Recording it is not the same as closing it; it is the
	// difference between a hole that is known and one that is not.
	productionConstant bool
	why                string
	witness            axisWitness6812
}

// fixtureConstantAxes6812 registers columns this fixture happens not to vary
// while production can. Each one is an admitted blind spot.
func fixtureConstantAxes6812(why string, cols ...string) map[string]axisExemption6812 {
	return newAxisExemptions6812(false, why, cols...)
}

// productionConstantAxes6812 registers columns that cannot vary for ANY
// production input, so exempting them costs nothing. It REQUIRES a witness —
// see axisWitness6812. The conservative direction remains
// fixtureConstantAxes6812, which over-reports blindness rather than
// under-reporting it and needs no witness because it claims nothing.
func productionConstantAxes6812(why string, w axisWitness6812, cols ...string) map[string]axisExemption6812 {
	out := newAxisExemptions6812(true, why, cols...)
	for c, ex := range out {
		ex.witness = w
		out[c] = ex
	}
	return out
}

func newAxisExemptions6812(production bool, why string, cols ...string) map[string]axisExemption6812 {
	out := make(map[string]axisExemption6812, len(cols))
	for _, c := range cols {
		out[c] = axisExemption6812{productionConstant: production, why: why}
	}
	return out
}

// axisWitness6812 is the ADVERSARIAL evidence behind a productionConstant
// claim: an independently constructed sequence in which the column would vary
// if the claim were false. A witness that merely rebuilds the fixture proves
// nothing — it must populate, on purpose, whatever the claim says can never
// differ.
type axisWitness6812 struct {
	name   string
	groups func(t *testing.T) []axisGroup6812
}

// assertProductionConstantWitnesses6812 runs every witness a table references
// and requires each claimed column to EXIST in the witness projection and be
// CONSTANT within every one of its groups. A column that is absent fails as
// loudly as one that varies: a claim about a column the witness never emits is
// not a checked claim.
func assertProductionConstantWitnesses6812(t *testing.T, what string, tables ...map[string]axisExemption6812) {
	t.Helper()
	byWitness := map[string][]string{}
	witnesses := map[string]axisWitness6812{}
	for _, tbl := range tables {
		for col, ex := range tbl {
			if !ex.productionConstant {
				continue
			}
			if ex.witness.groups == nil {
				t.Fatalf("%s: column %q is registered production-constant (%q) with NO "+
					"witness. The claim is that no production input can make it vary; "+
					"supply a sequence that would make it vary if that were false.",
					what, col, ex.why)
			}
			byWitness[ex.witness.name] = append(byWitness[ex.witness.name], col)
			witnesses[ex.witness.name] = ex.witness
		}
	}
	names := make([]string, 0, len(byWitness))
	for n := range byWitness {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		cols := byWitness[n]
		sort.Strings(cols)
		groups := witnesses[n].groups(t)
		if len(groups) == 0 {
			t.Fatalf("%s: witness %q produced no groups", what, n)
		}
		for _, g := range groups {
			if len(g.slots) < 2 {
				t.Fatalf("%s: witness %q group %s has %d slots; a one-element sequence is "+
					"constant on every column and witnesses nothing",
					what, n, g.label, len(g.slots))
			}
			seen := map[string][]string{}
			for i, slot := range g.slots {
				collectAxisKeys6812(t, "", reflect.ValueOf(slot), true, 0, func(col, key string) {
					for len(seen[col]) < i {
						seen[col] = append(seen[col], "")
					}
					seen[col] = append(seen[col], key)
				})
			}
			for _, col := range cols {
				vals, ok := seen[col]
				if !ok {
					t.Fatalf("%s: witness %q group %s emits no column %q, so the "+
						"production-constant claim on it is unchecked. Either the column "+
						"was renamed or the witness does not reach the same type.",
						what, n, g.label, col)
				}
				for len(vals) < len(g.slots) {
					vals = append(vals, "")
				}
				if !axisIsConstant6812(vals) {
					t.Fatalf("%s: column %q is registered PRODUCTION-CONSTANT but VARIES in "+
						"witness %q group %s: %q. The claim is false — reclassify it as a "+
						"fixture-constant blind spot.", what, col, n, g.label, vals)
				}
			}
		}
	}
}

// mergeAxisExemptions6812 unions exemption tables, panicking on a duplicate
// column so one column cannot carry two contradictory classifications.
func mergeAxisExemptions6812(tables ...map[string]axisExemption6812) map[string]axisExemption6812 {
	out := map[string]axisExemption6812{}
	for _, tbl := range tables {
		for col, ex := range tbl {
			if prev, dup := out[col]; dup {
				panic(fmt.Sprintf("#6812 axis exemption %q registered twice (%q and %q)",
					col, prev.why, ex.why))
			}
			out[col] = ex
		}
	}
	return out
}

// axisGroup6812 is one sequence of declaration slots the sweep must find
// non-monotone. The production sorts under test are STABLE and keyed on the
// scope tier, so a tiebreak can only permute within one tier — and a
// within-block reorder can only permute within one rule-set. The property
// therefore has to hold per group, not over the whole emitted slice.
type axisGroup6812 struct {
	label string
	slots []any
}

// BEGIN SHARED COLLECTOR (#6812 round 11). This block is DUPLICATED verbatim
// in the sibling package's sweep file, because a Go test helper cannot be shared
// across packages without exporting it from production — and paying production
// API surface for test convenience is the wrong trade. What matters is not that
// there is one copy but that the two copies DO NOT DISAGREE, which is a weaker
// and cheaper property: TestAxisCollectorTwinsAgree_6812 runs both collectors
// over an identical probe value and requires identical column sets, and
// TestAxisCollectorTwinsAreTextuallyIdentical_6812 requires this marked region
// to match byte for byte. A deliberate divergence is still possible — it just
// has to be declared in those tests instead of appearing silently.
const axisKeyMaxDepth6812 = 8

// #6812 round 10 claimed a two-way dichotomy — a field is SWEPT or it STOPS the
// test. A switch-for-switch probe of the collector found a third outcome,
// SILENTLY SKIPPED, and it landed on precisely the case the round claimed to
// close: with every fixture pointer nil, a nil pointee emitted only `.nil` and
// every field of the pointee was skipped, so adding a field to
// PersistentNATConfig or DeterministicNATConfig changed no column. A `[]byte`
// emitted `.len` and `[0]` and dropped the rest; a map emitted only `.len`, so
// three one-entry maps keyed {N:2}, {N:0}, {N:1} were indistinguishable while a
// comparator keying on the sole key reorders them.
//
// A PARTIAL column is worse than no column, because it reads as coverage.
//
// Round 11 removes the third outcome. Every kind the collector meets does
// exactly one of:
//
//	(a) contribute an ORDER-PRESERVING column for its own value;
//	(b) contribute a TOTAL column over its contents (`.all`, `.entries`) — a
//	    column no change to those contents can be invisible to;
//	(c) enumerate the contained TYPE's schema with ABSENT keys. The columns
//	    still exist, so a field added to the contained type still produces one
//	    and still has to be registered. For a pointer this happens when the
//	    value is missing (a nil pointee); for a MAP it happens ALWAYS, populated
//	    or not — round 13, because returning early on a populated map made this
//	    outcome degrade into "silently skipped" exactly where nobody was
//	    looking, and made the column SET depend on the value instead of the
//	    type;
//	(d) declare itself UNENCODABLE by emitting a `…-UNENCODED` column, which the
//	    registry then forces someone to justify in writing;
//	(e) STOP the test.
//
// THREE PRECISION NOTES, all measured this round (#6812 round 12), because each
// is the kind of thing a reader would otherwise have to re-derive:
//
//  1. THE SCHEMA WALK IS TRANSITIVE; GUARDEDNESS IS NOT. Recursing a nil
//     pointee walks that pointee's own pointer fields too, bounded only by the
//     depth cap — TestCollectorEnumeratesANilPointeesFields_6812 asserts a
//     column two indirections behind an always-nil gateway. So "a new field
//     cannot be silently omitted" holds all the way down. What stops at the
//     gateway is COVERAGE: every column under an absent pointer is constant, so
//     each is a registered blind spot, and "a sort keyed through this pointer is
//     guarded" holds nowhere below it. The two are easy to conflate and only the
//     first is a closure claim.
//
//  2. A SEQUENCE'S CONTENT IS TOTAL; ITS PER-INDEX ORDERING IS NOT. `.all` and
//     `.entries` are injective over contents, so no change to a slice tail or a
//     map entry can be invisible. That injectivity is CONDITIONAL on
//     axisEscapeKey6812 and was false without it (#6812 round 13): the joins
//     wrote keys raw, so an element field carrying the record separator could
//     re-partition the record and two different slices encoded identically.
//     TestAxisEncodingIsInjective_6812 is the measurement, on the exact
//     counterexample. But the only per-element column is `[0]`:
//     there is no `[1]`, and no per-entry column at all. A comparator keying
//     specifically on `x[1]`, or on one map entry, therefore has no column of
//     its own — neither asserted non-monotone nor registered. Live today for
//     PoolAddresses / Pool.Addresses, whose `[1]` does not exist (measured).
//     Narrower than "the tail is unswept": the tail is visible, its ordering is
//     not.
//
//  3. time.Time IS SPECIAL-CASED FOR A REASON. The generic struct walk would
//     read `wall`, `ext` and `loc.nil`, and `wall` carries the monotonic-clock
//     flag in bit 63 — so its lexicographic order is NOT chronological and the
//     collector's central invariant would break silently for it. The special
//     case encodes UnixNano instead, and cell P5 measures that it is
//     load-bearing. The residual: any OTHER type whose in-memory representation
//     is not order-isomorphic to its semantic order takes the generic walk and
//     would break the invariant the same way. No such type is swept today.
//
// Keys are TAGGED. A present value encodes as "\x01"+key, an absent one as
// "\x00". Absent sorts below every present key, and a uniform present-prefix
// preserves order among present keys — so a column that is absent in some slots
// and present in others is comparable, and "absent" can never collide with a
// legitimately empty string.
//
// Keys are also ESCAPED where they are JOINED (#6812 round 13). The three
// structural bytes below delimit the composite encodings, and until round 13 a
// key was written into them raw — so a value CARRYING a structural byte could
// re-partition the record and two different values could encode identically:
//
//	[]elem{{A: "x\x1eB=\x01y", B: "z"}}  and  []elem{{A: "x", B: "y\x1eB=\x01z"}}
//
// both flattened to `A=\x01x\x1eB=\x01y\x1eB=\x01z\x1e`, so `.all` — the column
// whose whole job is to be TOTAL over contents — was not injective and a
// difference in the slice could be invisible after all. Nested containers hit
// the same hole without any adversarial string: a `.all` key is itself a
// composite full of \x1e, and embedding it raw one level up re-partitions the
// outer record.
//
// axisEscapeKey6812 at the join closes both. See its comment for why escaping
// there — rather than at each leaf — is what makes every nesting level exactly
// once-escaped.
const (
	axisAbsentKey6812  = "\x00"
	axisPresentTag6812 = "\x01"
	// axisEscByte6812 introduces a two-byte escape; the other three are the
	// structural delimiters of the composite encodings (record / group / unit).
	axisEscByte6812   = '\x1c'
	axisRecordSep6812 = '\x1e'
	axisGroupSep6812  = '\x1d'
	axisUnitSep6812   = '\x1f'
)

// axisEscapeKey6812 makes a key safe to embed in a composite encoding: after
// it, the only \x1c / \x1d / \x1e / \x1f bytes in the result are the delimiters
// the ENCODER wrote, so every composite splits back one way only.
//
// The mapping is a two-byte escape with a distinct printable tag per byte, so
// decoding is unambiguous and the escape byte itself is escaped:
//
//	\x1c -> \x1cE   \x1d -> \x1cG   \x1e -> \x1cR   \x1f -> \x1cU
//
// WHERE IT IS APPLIED, and why that is the whole fix: at the JOIN in
// axisEncodeValue6812, to the key of every column, once. A leaf key and a
// composite key (`.all`, `.entries`) go through the same call, so a container
// nested N deep is escaped exactly N times on the way up and the outer stream
// can never see an inner delimiter. Escaping at each LEAF instead would leave
// composite keys — which are built from already-escaped pieces — unescaped at
// the level that embeds them.
//
// It is NOT applied to column NAMES. Names are Go field names plus the fixed
// suffixes this collector appends (`.nil`, `.len`, `.all`, `.entries`, `[0]`,
// `{key}`, `{value}`, `.dynamic-type`, `.dynamic-UNENCODED`), none of which can
// contain a structural byte or an `=`; so splitting a record at its FIRST `=`
// recovers the name and the key uniquely, and a key containing `=` is harmless.
//
// The two length-prefixed joins (axisEncodeSeq6812, axisEncodeMap6812) were
// already unambiguous at their own delimiter — `%08d:` pins each element's
// extent — but the \x1f split INSIDE a map entry was not, and is now: an
// escaped key contains no \x1f, and neither do column names, so the one \x1f in
// an entry is the one the encoder wrote.
//
// The present/absent TAGS are deliberately not escaped: they are a one-byte
// prefix on the whole key, never a delimiter inside it, so "\x01"+key stays
// injective in key with no help.
func axisEscapeKey6812(s string) string {
	if !strings.ContainsAny(s, "\x1c\x1d\x1e\x1f") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case axisEscByte6812:
			b.WriteString("\x1cE")
		case axisGroupSep6812:
			b.WriteString("\x1cG")
		case axisRecordSep6812:
			b.WriteString("\x1cR")
		case axisUnitSep6812:
			b.WriteString("\x1cU")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func axisLeaf6812(present bool, key string) string {
	if !present {
		return axisAbsentKey6812
	}
	return axisPresentTag6812 + key
}

func axisUintKey6812(u uint64) string { return fmt.Sprintf("%020d", u) }
func axisIntKey6812(i int64) string   { return axisUintKey6812(uint64(i) + 1<<63) }
func axisBoolKey6812(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

var axisTimeType6812 = reflect.TypeOf(time.Time{})

// collectAxisKeys6812 flattens v into every column a comparator could key on,
// calling add(column, key) once per column.
//
// `present` false means the VALUE is missing and only its TYPE is being walked —
// a nil pointer's pointee, an empty slice's element, an empty map's key/value.
// Every leaf under it emits the absent key, which keeps the column in existence
// (so a new field is still caught) without inventing a value.
func collectAxisKeys6812(t *testing.T, path string, v reflect.Value, present bool, depth int, add func(col, key string)) {
	t.Helper()
	if depth > axisKeyMaxDepth6812 {
		t.Fatalf("axis sweep: recursion past depth %d at %q — the sweep cannot enumerate a "+
			"cyclic or unexpectedly deep type, so it must not claim closure over it",
			axisKeyMaxDepth6812, path)
	}
	switch v.Kind() {
	case reflect.String:
		add(path, axisLeaf6812(present, v.String()))
	case reflect.Bool:
		add(path, axisLeaf6812(present, axisBoolKey6812(v.Bool())))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		add(path, axisLeaf6812(present, axisUintKey6812(v.Uint())))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Offset binary: +2^63 maps the signed range onto the unsigned one
		// order-preservingly, so the zero-padded decimal sorts numerically
		// including negatives.
		add(path, axisLeaf6812(present, axisIntKey6812(v.Int())))
	case reflect.Struct:
		// time.Time would otherwise walk into wall/ext/loc — three columns whose
		// lexicographic order is NOT chronological, i.e. a partial column that
		// reads as coverage. One ordered column instead.
		if v.Type() == axisTimeType6812 {
			var nanos int64
			if present {
				nanos = v.Interface().(time.Time).UnixNano()
			}
			add(path, axisLeaf6812(present, axisIntKey6812(nanos)))
			return
		}
		tp := v.Type()
		for i := 0; i < tp.NumField(); i++ {
			sub := tp.Field(i).Name
			if path != "" {
				sub = path + "." + sub
			}
			collectAxisKeys6812(t, sub, v.Field(i), present, depth+1, add)
		}
	case reflect.Pointer:
		add(path+".nil", axisLeaf6812(present, axisBoolKey6812(v.IsNil())))
		if !present || v.IsNil() {
			// (c) The pointee's SCHEMA still emits columns. This is the case
			// round 10 got wrong: without it a field added to a type every
			// fixture leaves nil changes nothing at all.
			collectAxisKeys6812(t, path, reflect.Zero(v.Type().Elem()), false, depth+1, add)
			return
		}
		collectAxisKeys6812(t, path, v.Elem(), true, depth+1, add)
	case reflect.Interface:
		add(path+".nil", axisLeaf6812(present, axisBoolKey6812(v.IsNil())))
		if !present || v.IsNil() {
			// (d) A nil interface hides its payload schema: the dynamic type is
			// not knowable from the static one, so there is nothing to
			// enumerate. Declare it rather than skip it — the registry then
			// makes someone write down why that is acceptable.
			add(path+".dynamic-UNENCODED", axisAbsentKey6812)
			return
		}
		// A change of concrete type is itself an axis a comparator can read.
		add(path+".dynamic-type", axisLeaf6812(true, v.Elem().Type().String()))
		collectAxisKeys6812(t, path, v.Elem(), true, depth+1, add)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice {
			// nil and empty are DIFFERENT states and a comparator can see both.
			add(path+".nil", axisLeaf6812(present, axisBoolKey6812(v.IsNil())))
		}
		add(path+".len", axisLeaf6812(present, axisUintKey6812(uint64(v.Len()))))
		// (b) TOTAL over contents: every element, in order. No element past the
		// first can change without changing this column.
		add(path+".all", axisLeaf6812(present && v.Len() > 0, axisEncodeSeq6812(t, v, depth+1)))
		if present && v.Len() > 0 {
			collectAxisKeys6812(t, path+"[0]", v.Index(0), true, depth+1, add)
			return
		}
		collectAxisKeys6812(t, path+"[0]", reflect.Zero(v.Type().Elem()), false, depth+1, add)
	case reflect.Map:
		add(path+".nil", axisLeaf6812(present, axisBoolKey6812(v.IsNil())))
		add(path+".len", axisLeaf6812(present, axisUintKey6812(uint64(v.Len()))))
		// (b) TOTAL over contents. Map iteration has no order, so the entries
		// are SORTED before joining, which makes the column a function of the
		// contents alone. This is what makes {N:2}, {N:0}, {N:1} three distinct
		// keys instead of three identical `.len=1`s.
		add(path+".entries", axisLeaf6812(present && v.Len() > 0, axisEncodeMap6812(t, v, depth+1)))
		// (c) The key/value SCHEMA columns, ALWAYS — #6812 round 13.
		//
		// Until round 13 these were emitted only for an empty or nil map: a
		// populated one returned here. That reinstated the THIRD OUTCOME this
		// collector claims to have removed, in the one shape nobody checked. A
		// field added to a POPULATED map's value type produced no new column
		// at all, so it was silently skipped rather than registered — measured:
		//
		//	populated map, before adding field B:  [M.entries M.len M.nil]
		//	populated map,  after adding field B:  [M.entries M.len M.nil]
		//	the slice analogue gains S[0].B
		//
		// It also made the map column SET a function of the VALUE rather than
		// the TYPE, which is worse than it sounds: a fixture holding one empty
		// map and one populated map of the same type emitted the schema columns
		// for the empty slot only, and the sweep back-filled the missing slot
		// with "" — manufacturing a column that VARIES across slots and so reads
		// as guarded, when nothing about either map was being compared.
		//
		// The keys stay ABSENT even when the map is populated, which is the
		// honest encoding: unlike a slice's `[0]`, a map has no canonical first
		// entry to project. Content coverage is `.entries`, which is total; the
		// schema columns exist to keep a new field from vanishing, and a
		// constant column is a REGISTERED blind spot rather than an unknown one.
		collectAxisKeys6812(t, path+"{key}", reflect.Zero(v.Type().Key()), false, depth+1, add)
		collectAxisKeys6812(t, path+"{value}", reflect.Zero(v.Type().Elem()), false, depth+1, add)
	default:
		// (e) Floats have no order-preserving fixed-width decimal encoding here,
		// and chan/func/unsafe.Pointer have no meaningful order at all.
		t.Fatalf("axis sweep: field %q has kind %s, for which this sweep has no "+
			"ORDER-PRESERVING key encoding. Add one, or give the containing type a "+
			"`…-UNENCODED` declaration. Skipping it would drop a column silently, which "+
			"is the exact failure this sweep exists to prevent.", path, v.Kind())
	}
}

// axisEncodeValue6812 renders ONE value as a single total string: every column
// it would emit, sorted by column name and joined. Injective over the value, so
// nothing about it can be invisible to a caller that embeds this.
//
// The injectivity rests on axisEscapeKey6812 (#6812 round 13). Before it, the
// claim was false for any value able to carry a \x1e — see the counterexample
// on the const block — and TestAxisEncodingIsInjective_6812 is the measurement
// that the repaired form separates it.
func axisEncodeValue6812(t *testing.T, v reflect.Value, depth int) string {
	t.Helper()
	cols := map[string]string{}
	collectAxisKeys6812(t, "", v, true, depth, func(col, key string) {
		cols[col] = key
	})
	names := make([]string, 0, len(cols))
	for c := range cols {
		names = append(names, c)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, c := range names {
		fmt.Fprintf(&b, "%s=%s\x1e", c, axisEscapeKey6812(cols[c]))
	}
	return b.String()
}

// axisEncodeSeq6812 renders a slice/array in order, length-tagged per element so
// the concatenation stays injective.
func axisEncodeSeq6812(t *testing.T, v reflect.Value, depth int) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < v.Len(); i++ {
		e := axisEncodeValue6812(t, v.Index(i), depth)
		fmt.Fprintf(&b, "%08d:%s\x1d", len(e), e)
	}
	return b.String()
}

// axisEncodeMap6812 renders a map as its SORTED (key, value) pairs.
func axisEncodeMap6812(t *testing.T, v reflect.Value, depth int) string {
	t.Helper()
	entries := make([]string, 0, v.Len())
	iter := v.MapRange()
	for iter.Next() {
		entries = append(entries,
			axisEncodeValue6812(t, iter.Key(), depth)+"\x1f"+
				axisEncodeValue6812(t, iter.Value(), depth))
	}
	sort.Strings(entries)
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%08d:%s\x1d", len(e), e)
	}
	return b.String()
}

// END SHARED COLLECTOR (#6812 round 11).

// sweepAxes6812 asserts the round-9 anti-coincidence property — declaration
// order is not sorted on this column, in EITHER direction — for every column
// every group's slots emit, and requires every constant column to be registered.
//
// `what` names the swept value in failure text; `exempt` is the honest record
// of what the fixture does not guard.
func sweepAxes6812(t *testing.T, what string, groups []axisGroup6812, exempt map[string]axisExemption6812) {
	t.Helper()
	if len(groups) == 0 {
		t.Fatalf("axis sweep %s: no groups — a sweep over nothing certifies nothing", what)
	}
	// PASS 1: project every group into its columns. Classification is GLOBAL,
	// not per group: a column can be constant in one grouping and vary in
	// another — Snapshot.FromInterface is empty for every zone-tier rule-set and
	// permuted across the interface-tier ones — and that is a registered blind
	// spot in the first group and a guarded axis in the second, not a defect.
	perGroup := make([]map[string][]string, len(groups))
	constantSomewhere := map[string]bool{}
	var unregistered []string
	for gi, g := range groups {
		if len(g.slots) < 3 {
			t.Fatalf("axis sweep %s / %s: %d slots; a sequence shorter than three is "+
				"ascending or descending by construction and cannot be de-correlated from "+
				"both sort directions", what, g.label, len(g.slots))
		}
		cols := map[string][]string{}
		for i, slot := range g.slots {
			seen := map[string]bool{}
			collectAxisKeys6812(t, "", reflect.ValueOf(slot), true, 0, func(col, key string) {
				if seen[col] {
					t.Fatalf("axis sweep %s / %s: column %q emitted twice for slot %d",
						what, g.label, col, i)
				}
				seen[col] = true
				// Back-fill slots that did not emit this column (a slice that
				// is empty in some slots and populated in others). "" sorts
				// below every encoded key, which keeps the comparison total.
				for len(cols[col]) < i {
					cols[col] = append(cols[col], "")
				}
				cols[col] = append(cols[col], key)
			})
		}
		for col, vals := range cols {
			for len(vals) < len(g.slots) {
				vals = append(vals, "")
			}
			cols[col] = vals
			if !axisIsConstant6812(vals) {
				continue
			}
			if _, registered := exempt[col]; !registered {
				unregistered = append(unregistered,
					fmt.Sprintf("%s in %s (constant %q)", col, g.label, vals[0]))
				continue
			}
			constantSomewhere[col] = true
		}
		perGroup[gi] = cols
	}
	var stale []string
	for col, ex := range exempt {
		if !constantSomewhere[col] {
			stale = append(stale, fmt.Sprintf("%s (registered %q)", col, ex.why))
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)
	if len(unregistered) > 0 || len(stale) > 0 {
		t.Fatalf("axis sweep %s: the exemption table does not describe this fixture.\n"+
			"CONSTANT but unregistered (%d): %v\n"+
			"REGISTERED but constant in no group (%d): %v\n"+
			"A stable sort keyed on a constant column cannot permute anything HERE, so no "+
			"assertion in this fixture can see such a sort — but fixture-only constancy is "+
			"NOT regression coverage. If the column varies for any production input, a "+
			"tiebreak on it reorders production while this fixture stays green. Either VARY "+
			"the column, or register it with productionConstant set honestly: true only if "+
			"it cannot vary for ANY production input, false to record an admitted blind "+
			"spot. A stale entry means the field was renamed or removed, or the fixture now "+
			"varies it everywhere and it is guarded — delete it.",
			what, len(unregistered), unregistered, len(stale), stale)
	}

	// PASS 2: the round-9 property, on every column that actually varies in the
	// group — registered or not. A registered column is blind where it is
	// constant and must still be non-monotone where it moves.
	guarded := map[string]bool{}
	for gi, g := range groups {
		cols := perGroup[gi]
		names := make([]string, 0, len(cols))
		for col := range cols {
			names = append(names, col)
		}
		sort.Strings(names)
		for _, col := range names {
			if axisIsConstant6812(cols[col]) {
				continue
			}
			guarded[col] = true
			assertDeclarationOrderIsNotSortedBy6812(t,
				fmt.Sprintf("%s / %s / %s", what, g.label, col), cols[col])
		}
	}
	// Report the split rather than leaving it to be re-derived by whoever asks
	// next whether this fixture is closed. `go test -v` prints all three lists,
	// and the middle one is the answer to "what is still blind here".
	//
	// EVERY COUNT HERE NEEDS ITS POPULATION, and there are TWO (#6812 round 12).
	// Rounds 10 and 11 both reported a "guarded columns" figure that was really
	// a CELL count — the same column swept at two groupings counts twice — so
	// round 10's "25 guarded" was 22 distinct columns and round 11's "30" was
	// likewise inflated. Stated with their populations, measured at this head:
	//
	//	POPULATION A, CELLS (sweep x column):  186 = 29 guarded + 139
	//	                                       fixture-constant + 18 prod-constant
	//	POPULATION B, DISTINCT COLUMNS:        129 = 25 guarded somewhere +
	//	                                       104 never guarded
	//	                                       (builder 57 cols, walk 72)
	//
	// Population B is the honest answer to "how much of the struct is guarded";
	// population A is the honest answer to "how many assertions does the sweep
	// make". Neither is wrong, and quoting one while naming the other is.
	//
	// AND READ A RISING BLIND COUNT AS THE FIX WORKING, NOT AS A REGRESSION.
	// Round 10 reported 74 fixture-constant columns and this reports 139, over a
	// universe that grew from 108 cells to 186. Nothing became blind. The
	// collector stopped SILENTLY SKIPPING nil pointees, list schemas and
	// container contents, so holes that already existed started being counted.
	// A blind-spot count that rises after a fix to the instrument is the
	// instrument seeing further; the number to be suspicious of is one that
	// falls without a named reason.
	var guardedNames, blindNames, nonAxisNames []string
	for col := range guarded {
		guardedNames = append(guardedNames, col)
	}
	for col, ex := range exempt {
		if guarded[col] {
			continue
		}
		if ex.productionConstant {
			nonAxisNames = append(nonAxisNames, col)
			continue
		}
		blindNames = append(blindNames, col)
	}
	sort.Strings(guardedNames)
	sort.Strings(blindNames)
	sort.Strings(nonAxisNames)
	t.Logf("axis sweep %s: %d columns GUARDED in at least one group %v; %d FIXTURE-CONSTANT "+
		"and therefore unguarded %v; %d PRODUCTION-CONSTANT non-axes %v",
		what, len(guardedNames), guardedNames, len(blindNames), blindNames,
		len(nonAxisNames), nonAxisNames)
}

func axisIsConstant6812(vals []string) bool {
	for _, v := range vals {
		if v != vals[0] {
			return false
		}
	}
	return true
}

// snapshotAxisSlot6812 is what TestBuilderEmittedOrderIsStableWithinATier_6812
// sweeps: the emitted snapshot the production comparator reads.
//
// It carries NO derived column, and the reason is the round-12 finding (#6812).
// Round 11 added `DerivedPortCapacity = len(PoolAddresses) × width` here on the
// argument that reflection cannot reach derived keys. That formula is not one
// production computes: the Go charge walk spends
// `Σ sourceNATPoolMemberHostCount(member) × range` and the Rust apply boundary
// spends `allocator_capacity(total_pool, …)` over the EXPANDED addresses. The
// three agreed only because every fixture pool member was a bare host — the
// fixture-coincidence class this whole round exists to eliminate, sitting inside
// the one construct added because reflection could not reach it.
//
// A WRAPPER COLUMN ASSERTING A DERIVED KEY IS A SECOND IMPLEMENTATION OF THAT
// KEY, AND SECOND IMPLEMENTATIONS DRIFT. The walk-side wrapper
// (pkg/config, ruleAxisSlot6812) keeps its derived columns by READING what
// sourceNATAggregateReferencedCharges produced. This side has no such function
// to read: the builder computes no charge, and the value it would need lives in
// Rust. Writing it here would be exactly the second implementation. So the
// column is gone rather than wrong, and the inputs a capacity is derived from —
// PortLow, PortHigh, PoolAddresses and its `.len` and `.all` — stay swept and
// de-correlated on their own.
type snapshotAxisSlot6812 struct {
	Snapshot SourceNATRuleSnapshot
}

// builderTierAxisExemptions6812 is the honest enumeration of what the builder
// fixture does NOT guard at the per-tier grouping: columns a (tier, X) tiebreak
// could key on that this fixture holds constant, so such a sort would be
// invisible here.
//
// Every entry is fixture-constant, not production-constant: no column of
// SourceNATRuleSnapshot is invariant for all production inputs, so there is
// nothing here that can be exempted for free. Round 9's silent skip treated
// this whole set as costless; it is not.
var builderTierAxisExemptions6812 = mergeAxisExemptions6812(
	productionConstantAxes6812(
		"`address-persistent` is ONE config-global bit — Security.NAT.AddressPersistent "+
			"(types_security.go:620) — stamped identically onto every emitted rule by "+
			"nat_source.go:223. No config can make it differ between two rules, at any "+
			"grouping, so exempting it costs nothing. Round 10 recorded it as a fixture "+
			"blind spot, which over-reported the hole.",
		snapshotGlobalWitness6812(),
		"Snapshot.AddressPersistent",
	),
	fixtureConstantAxes6812(
		"the fixture's rule-sets carry a `from` clause only and no routing-instance "+
			"scope, so these stay empty for every slot. Production sets them and a "+
			"tiebreak keyed on one would reorder it.",
		"Snapshot.ToZone", "Snapshot.ToInterface",
		"Snapshot.FromRoutingInstance", "Snapshot.ToRoutingInstance",
	),
	fixtureConstantAxes6812(
		"constant only in the tier where that scope axis is unset — interface-tier "+
			"rule-sets carry no `from zone`, zone-tier ones no `from interface` — and "+
			"GUARDED in the other tier, which is why the entry is not stale. Production "+
			"can set both on one rule-set (the tier is the MIN of the two contexts), so "+
			"within a tier this remains a hole.",
		"Snapshot.FromZone", "Snapshot.FromInterface",
	),
	fixtureConstantAxes6812(
		"the fixture gives every rule exactly one match prefix and no destination, "+
			"port or application constraint, so these list shapes never move. `.all` is "+
			"the round-11 TOTAL column over a list's contents — constant here because the "+
			"contents are constant — and `.nil` distinguishes an unset list from an empty "+
			"one, which this fixture also never varies.",
		"Snapshot.SourceAddresses.len", "Snapshot.SourceAddresses.nil",
		"Snapshot.DestinationAddresses.len", "Snapshot.DestinationAddresses.nil",
		"Snapshot.DestinationAddresses.all", "Snapshot.DestinationAddresses[0]",
		"Snapshot.PoolAddresses.nil",
		"Snapshot.MatchDestinationPorts.len", "Snapshot.MatchDestinationPorts.nil",
		"Snapshot.MatchDestinationPorts.all",
		"Snapshot.MatchApplications.len", "Snapshot.MatchApplications.nil",
		"Snapshot.MatchApplications.all",
	),
	fixtureConstantAxes6812(
		"round-11 SCHEMA columns: the fixture leaves these lists EMPTY in every slot, so "+
			"the collector walks the element TYPE with absent keys rather than skipping "+
			"it. That is the point — a field added to NatAppTermWire or NatPortRangeWire "+
			"produces a new unregistered column here even though no fixture rule carries "+
			"an application or port term. The columns are constant because the lists are "+
			"empty, and a comparator keying on a populated term is unguarded.",
		"Snapshot.MatchDestinationPorts[0].Low", "Snapshot.MatchDestinationPorts[0].High",
		"Snapshot.MatchApplications[0].Protocol",
		"Snapshot.MatchApplications[0].Ports.len", "Snapshot.MatchApplications[0].Ports.nil",
		"Snapshot.MatchApplications[0].Ports.all",
		"Snapshot.MatchApplications[0].Ports[0].Low", "Snapshot.MatchApplications[0].Ports[0].High",
		"Snapshot.MatchApplications[0].SrcPorts.len", "Snapshot.MatchApplications[0].SrcPorts.nil",
		"Snapshot.MatchApplications[0].SrcPorts.all",
		"Snapshot.MatchApplications[0].SrcPorts[0].Low", "Snapshot.MatchApplications[0].SrcPorts[0].High",
	),
	fixtureConstantAxes6812(
		"no interface-mode, no-NAT-off, persistent-NAT, address-persistent or "+
			"port-no-translation modifier is configured here, so each stays at its zero "+
			"value; all are per-rule-set settable in production.",
		"Snapshot.InterfaceMode", "Snapshot.Off", "Snapshot.PoolNoTranslation",
		"Snapshot.PersistentNAT",
		"Snapshot.PersistentNATPermitAnyRemoteHost", "Snapshot.PersistentNATPermit",
		"Snapshot.PersistentNATInactivityTimeout",
	),
	fixtureConstantAxes6812(
		"every pool here is healthy and within budget, so the poison marker never "+
			"fires. A poisoned pool is precisely the state #6812 introduces, and a "+
			"tiebreak keyed on the marker would reorder such a config.",
		"Snapshot.PoolUnusable", "Snapshot.PoolUnusableReason",
	),
	fixtureConstantAxes6812(
		"no rule here authors an empty `match`, so the #9874 fail-closed poison "+
			"never fires. A poisoned rule is precisely the state that drops "+
			"instead of translating, and a tiebreak keyed on the marker would "+
			"reorder such a config.",
		"Snapshot.LenientMatchDropped",
	),
	fixtureConstantAxes6812(
		"no pool here is deterministic-CGNAT, so the whole #4559 block is zero.",
		"Snapshot.DeterministicMode", "Snapshot.DeterministicBlockSize",
		"Snapshot.DeterministicBlocksPerIP", "Snapshot.DeterministicHostBase",
		"Snapshot.DeterministicHostCount",
	),
)

// builderRuleSetAxisExemptions6812 is the same enumeration one nesting level
// in, for a reorder WITHIN one rule-set's block.
//
// The dominant hole is structural and worth naming: this fixture points every
// rule of a rule-set at the SAME pool, because assertions (1) and (2) identify
// a rule-set's block by PoolName. So no pool-derived within-set sort is caught
// here — not the pool name, not its members, not its port range, not the
// capacity derived from them. Junos lets each rule of a rule-set choose its own
// pool, so that is a real gap and not a non-axis.
var builderRuleSetAxisExemptions6812 = mergeAxisExemptions6812(
	productionConstantAxes6812(
		"`address-persistent` is ONE config-global bit — Security.NAT.AddressPersistent "+
			"(types_security.go:620) — stamped identically onto every emitted rule by "+
			"nat_source.go:223. No config can make it differ between two rules, at any "+
			"grouping, so exempting it costs nothing. Round 10 recorded it as a fixture "+
			"blind spot, which over-reported the hole.",
		snapshotGlobalWitness6812(),
		"Snapshot.AddressPersistent",
	),
	fixtureConstantAxes6812(
		"one pool per rule-set here (assertions (1) and (2) key a rule-set's block on "+
			"PoolName), so every pool-derived column is constant within a block. Junos "+
			"allows a different pool per rule, so a within-set sort keyed on any of these "+
			"would reorder production and stay green here.",
		"Snapshot.PoolName", "Snapshot.PoolAddresses.len", "Snapshot.PoolAddresses[0]",
		"Snapshot.PoolAddresses.all", "Snapshot.PoolAddresses.nil",
		"Snapshot.PortLow", "Snapshot.PortHigh",
		"Snapshot.PoolNoTranslation", "Snapshot.PoolUnusable", "Snapshot.PoolUnusableReason",
		"Snapshot.DeterministicMode", "Snapshot.DeterministicBlockSize",
		"Snapshot.DeterministicBlocksPerIP", "Snapshot.DeterministicHostBase",
		"Snapshot.DeterministicHostCount",
	),
	fixtureConstantAxes6812(
		"no rule here authors an empty `match`, so the #9874 fail-closed poison "+
			"is false in every slot of every block. A within-set sort keyed on "+
			"the marker would reorder a config carrying a poisoned rule and "+
			"stay green here.",
		"Snapshot.LenientMatchDropped",
	),
	productionConstantAxes6812(
		"scope is a property of the RULE-SET: buildSourceNATSnapshotsWithFeeds stamps "+
			"all six from `rs` for every rule of that rule-set, so within one block they "+
			"are identical for EVERY config — not just this fixture. A within-block sort "+
			"keyed on any of them is a no-op in production too, so exempting them here "+
			"costs no coverage. (At the per-TIER grouping they are a different matter, "+
			"and that table records them honestly.)",
		snapshotWitness6812(),
		"Snapshot.FromZone", "Snapshot.ToZone", "Snapshot.FromInterface",
		"Snapshot.ToInterface", "Snapshot.FromRoutingInstance", "Snapshot.ToRoutingInstance",
	),
	fixtureConstantAxes6812(
		"same list-shape and modifier gaps as the per-tier table, one level in — "+
			"including the round-11 `.nil`, `.all` and empty-list SCHEMA columns, which "+
			"exist here for the same reason: a field added to NatAppTermWire or "+
			"NatPortRangeWire must produce a column even though this fixture carries no "+
			"application or port term.",
		"Snapshot.SourceAddresses.len", "Snapshot.SourceAddresses.nil",
		"Snapshot.DestinationAddresses.len", "Snapshot.DestinationAddresses.nil",
		"Snapshot.DestinationAddresses.all", "Snapshot.DestinationAddresses[0]",
		"Snapshot.MatchDestinationPorts.len", "Snapshot.MatchDestinationPorts.nil",
		"Snapshot.MatchDestinationPorts.all",
		"Snapshot.MatchDestinationPorts[0].Low", "Snapshot.MatchDestinationPorts[0].High",
		"Snapshot.MatchApplications.len", "Snapshot.MatchApplications.nil",
		"Snapshot.MatchApplications.all", "Snapshot.MatchApplications[0].Protocol",
		"Snapshot.MatchApplications[0].Ports.len", "Snapshot.MatchApplications[0].Ports.nil",
		"Snapshot.MatchApplications[0].Ports.all",
		"Snapshot.MatchApplications[0].Ports[0].Low", "Snapshot.MatchApplications[0].Ports[0].High",
		"Snapshot.MatchApplications[0].SrcPorts.len", "Snapshot.MatchApplications[0].SrcPorts.nil",
		"Snapshot.MatchApplications[0].SrcPorts.all",
		"Snapshot.MatchApplications[0].SrcPorts[0].Low", "Snapshot.MatchApplications[0].SrcPorts[0].High",
		"Snapshot.InterfaceMode", "Snapshot.Off",
		"Snapshot.PersistentNAT", "Snapshot.PersistentNATPermitAnyRemoteHost",
		"Snapshot.PersistentNATPermit", "Snapshot.PersistentNATInactivityTimeout",
	),
)

// snapshotWitness6812 is the adversarial sequence behind this package's
// production-constant claims (#6812 round 11). It is built to make those
// columns VARY if the claims were false:
//
//   - the three rule-sets between them populate ALL SIX scope fields — zone,
//     interface and routing-instance, on both the from and the to side — so the
//     claim "scope is a property of the rule-set" is witnessed where each field
//     is SET, not only where the round-10 fixture left four of them empty;
//   - within a rule-set the rules reference DIFFERENT pools, with different
//     members, port ranges and rule names, so a false claim on any pool-derived
//     column — PoolName is the obvious candidate, and Junos does allow a pool
//     per rule — fails here instead of passing quietly;
//   - `address-persistent` is SET, so that column is witnessed at its other
//     value rather than only at the zero one.
//
// One from-kind and one to-kind per rule-set is deliberate. compileNATSource
// expands a rule-set carrying several `from` kinds into the CROSS PRODUCT of
// from-kind × to-kind — measured here: six clauses on one named rule-set
// compile to NINE rule-sets, each with exactly one of each. So "all six
// populated on one compiled rule-set" is not a representable input, and a
// witness that tried to build it would be grouping over something the config
// model cannot produce.
//
// Groups are per RULE-SET, keyed on the rule-NAME prefix rather than on any
// scope field — using scope to group would make the check circular, since
// scope constancy is the thing being witnessed.
func snapshotWitness6812() axisWitness6812 {
	return axisWitness6812{
		name: "six-scope-kinds, pool-per-rule, address-persistent",
		groups: func(t *testing.T) []axisGroup6812 {
			t.Helper()
			return snapshotWitnessGroups6812(t, false)
		},
	}
}

// snapshotGlobalWitness6812 is the same config swept as ONE sequence. It
// witnesses the claims that hold across a whole config rather than within a
// rule-set — AddressPersistent is a single config-global bit stamped onto every
// rule — and it deliberately has the scope fields VARYING inside it, which is
// why the two witnesses cannot be one.
func snapshotGlobalWitness6812() axisWitness6812 {
	return axisWitness6812{
		name: "one config, whole emitted sequence, address-persistent SET",
		groups: func(t *testing.T) []axisGroup6812 {
			t.Helper()
			return snapshotWitnessGroups6812(t, true)
		},
	}
}

func snapshotWitnessGroups6812(t *testing.T, whole bool) []axisGroup6812 {
	{
		t.Helper()
		kinds := []struct{ name, from, to string }{
			{"wa", "from zone z1", "to zone y1"},
			{"wb", "from interface ge-0/0/1.0", "to interface ge-0/0/9.1"},
			{"wc", "from routing-instance vrfa", "to routing-instance vrfb"},
		}
		cmds := []string{"set security nat source address-persistent"}
		for k, rs := range kinds {
			cmds = append(cmds,
				fmt.Sprintf("set security nat source rule-set %s %s", rs.name, rs.from),
				fmt.Sprintf("set security nat source rule-set %s %s", rs.name, rs.to),
			)
			for r := 0; r < 3; r++ {
				pool := fmt.Sprintf("wp%d%d", k, r)
				cmds = append(cmds,
					fmt.Sprintf("set security nat source pool %s address 198.51.%d.%d", pool, 100+k, 10+r),
					fmt.Sprintf("set security nat source pool %s port range %d to %d", pool, 2000+100*r, 2050+100*r),
					fmt.Sprintf("set security nat source rule-set %s rule %s_r%d match source-address 10.9.%d.0/24", rs.name, rs.name, r, r),
					fmt.Sprintf("set security nat source rule-set %s rule %s_r%d then source-nat pool %s", rs.name, rs.name, r, pool),
				)
			}
		}
		tree := &config.ConfigTree{}
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("witness ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("witness SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("witness CompileConfigLenient: %v", err)
		}
		out := buildSourceNATSnapshots(cfg, nil)
		byRuleSet := map[string][]any{}
		var order []string
		for _, s := range out {
			key, _, ok := strings.Cut(s.Name, "_")
			if !ok {
				t.Fatalf("witness rule name %q carries no rule-set prefix", s.Name)
			}
			if _, seen := byRuleSet[key]; !seen {
				order = append(order, key)
			}
			byRuleSet[key] = append(byRuleSet[key], snapshotAxisSlot6812{Snapshot: s})
		}
		if len(order) != len(kinds) {
			t.Fatalf("witness produced %d rule-set groups %v, want %d — the scope kinds "+
				"did not compile to one rule-set each", len(order), order, len(kinds))
		}
		if whole {
			var all []any
			for _, k := range order {
				all = append(all, byRuleSet[k]...)
			}
			return []axisGroup6812{{label: "witness whole sequence", slots: all}}
		}
		groups := make([]axisGroup6812, 0, len(order))
		for _, k := range order {
			groups = append(groups, axisGroup6812{label: "witness rule-set " + k, slots: byRuleSet[k]})
		}
		return groups
	}
}

// TestProductionConstantAxesAreWitnessed_6812 is the round-11 answer to "the
// productionConstant truth is not mechanically checked". Every such claim in
// this package's registries is run against its witness.
func TestProductionConstantAxesAreWitnessed_6812(t *testing.T) {
	assertProductionConstantWitnesses6812(t, "builder axis registries",
		builderTierAxisExemptions6812, builderRuleSetAxisExemptions6812)
}
