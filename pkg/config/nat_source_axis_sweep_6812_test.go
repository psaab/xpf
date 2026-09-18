package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// #6812 round 10: the axis sweep, CLOSED OVER THE STRUCT RATHER THAN OVER A
// LIST OF CALLS. Twin of pkg/dataplane/userspace/nat_source_axis_sweep_6812_test.go;
// a test helper cannot be shared across packages without exporting it from
// production, and the two fixtures sweep different types anyway.
//
// Round 9 asked the anti-coincidence question "of every axis, in both
// directions" — but through a hand-written sequence of helper calls, so a
// column nobody remembered to sweep was still silently unguarded. Round 9's own
// sentence about round 8 ("the answer was a list, and a list is exactly what
// failed") applied to round 9 too: it moved the list up one level, from axis
// names to helper calls, rather than removing it. On this side the four calls
// covered Rule.Name, Then.PoolName, Match.SourceAddress and the pool's first
// member — and nothing else, including the pool's CARDINALITY and PORT RANGE,
// both of which were identical for every pool so a sort keyed on either was a
// no-op here and not in general.
//
// So the sweep walks the STRUCT. collectAxisKeys6812 reflects over every field
// of the value a comparator would read, recursing into nested structs and
// pointers, and emits one column per field plus a `.len` column per slice or
// map. A field added to NATRule, NATMatch, NATThen or NATPool later joins the
// sweep with no edit here; a field whose type has no order-preserving encoding
// hard-FAILS rather than being skipped. That is closure at FIELD granularity,
// by construction.
//
// "By construction" was not true for one shape until round 13: a POPULATED map
// returned before emitting its key/value schema columns, so a field added to a
// populated map's value type produced no column at all — silently skipped, the
// outcome round 11 claims to have removed. Latent, because no map is swept
// today; repaired at the reflect.Map arm, where the reasoning is written down.
//
// WHAT IT IS STILL NOT CLOSED OVER: keys DERIVED from fields by arithmetic. A
// comparator may key on the port-range width, on a computed budget charge, or
// on a prefix length — none of which is a field, and no reflective walk can
// enumerate the functions someone might write. Field-level closure does not
// imply derived-key coverage: every pool member can differ (column varies)
// while every pool has exactly one member (len constant). Two mitigations:
// `.len` of every slice is swept mechanically, and the remaining derived keys
// are declared as FIELDS OF A WRAPPER STRUCT that the sweep then treats like
// any other column. That wrapper's field list is a list — it is the only one
// left, it is in one place, and it is visible.
//
// And the exemption round 9 got wrong. Round 9 skipped a CONSTANT column
// silently, arguing that a stable sort keyed on a value identical for every
// element cannot permute anything. Sound only when the column is invariant for
// every PRODUCTION input; fixture-only constancy is a blind spot, not a
// non-axis. A constant column is therefore no longer skipped — it must be
// REGISTERED, and the registration records which of the two it is.

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
	// green here. Recording it is not closing it; it is the difference between
	// a hole that is known and one that is not.
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
// non-monotone. The walk sorts rule-sets STABLY by scope tier and then walks
// each rule-set's rules in order, so a tiebreak permutes only within one tier
// and a rule sort only within one rule-set: the property has to hold per group.
type axisGroup6812 struct {
	label string
	slots []any
}

// NOTE for this package's copy, kept OUTSIDE the shared region so the twins stay
// textually identical: the nil-pointee case below is not hypothetical here —
// PersistentNATConfig and DeterministicNATConfig are both reached from NATPool,
// which this fixture sweeps, and both are nil in every fixture pool.
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
// every group's slots emit, and requires every constant column to be
// registered.
func sweepAxes6812(t *testing.T, what string, groups []axisGroup6812, exempt map[string]axisExemption6812) {
	t.Helper()
	if len(groups) == 0 {
		t.Fatalf("axis sweep %s: no groups — a sweep over nothing certifies nothing", what)
	}
	// PASS 1: project every group into its columns. Classification is GLOBAL,
	// not per group: a column can be constant in one grouping and vary in
	// another, and that is a registered blind spot in the first and a guarded
	// axis in the second, not a defect.
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

// ruleAxisSlot6812 is what TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812
// sweeps: the rule the charge walk reads, the pool it resolves through
// Then.PoolName (a tiebreak can key on pool properties just as easily as on the
// rule's own), and the DERIVED keys neither struct carries as a field.
//
// The derived keys are READ FROM PRODUCTION, not recomputed (#6812 round 12).
// Round 11 shipped `DerivedPortCapacity = len(members) × width`, which is NOT
// the charge: sourceNATAggregateReferencedCharges computes
// `Σ sourceNATPoolMemberHostCount(member) × range`. The two agree only when
// every member is a bare host, which every fixture pool was — a fixture
// coincidence, inside the one construct that exists BECAUSE derived keys cannot
// be reached by reflection. A pool member that is a prefix broke the agreement
// and nothing noticed.
//
// The general form is worth more than the fix: A WRAPPER COLUMN ASSERTING A
// DERIVED KEY IS A SECOND IMPLEMENTATION OF THAT KEY, AND SECOND
// IMPLEMENTATIONS DRIFT. The wrapper exists to EXPOSE the value to the sweep,
// not to compute it. So these fields carry what
// sourceNATAggregateReferencedCharges produced for this rule's pool, verbatim;
// TestDerivedChargeColumnsComeFromProduction_6812 pins that, and the fixture now
// carries a prefix member so the two formulas would disagree if anyone
// reintroduced one.
type ruleAxisSlot6812 struct {
	Rule *NATRule
	Pool *NATPool
	// ChargeAddrs and ChargePortCap are the production charge for this rule's
	// pool — the expanded host count and the allocator port capacity the
	// aggregate budget actually spends.
	ChargeAddrs   uint64
	ChargePortCap uint64
}

// productionChargeByPool6812 indexes what the PRODUCTION charge walk computed,
// keyed by pool name. The sweep's derived columns read this instead of
// recomputing, so there is no second implementation to drift (#6812 round 12).
func productionChargeByPool6812(t *testing.T, cfg *Config) map[string]sourceNATAggregatePoolCharge {
	t.Helper()
	out := map[string]sourceNATAggregatePoolCharge{}
	for _, c := range sourceNATAggregateReferencedCharges(cfg) {
		out[c.name] = c
	}
	return out
}

// ruleAxisSlots6812 is the ONE place a ruleAxisSlot6812 is built (#6812 round
// 13). Every caller — the sweep in
// TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812, the
// production-constant witness walkWitness6812, and the derived-column guard
// TestDerivedChargeColumnsComeFromProduction_6812 — goes through it.
//
// Round 12 had THREE independent constructions of this struct from the same
// inputs, and the guard was one of them: it built its own literal and then
// asserted about that literal, which is `x := T{F: v}; if x.F != v` — a
// tautology that binds nothing but the struct definition. Replacing the SWEEP's
// construction with the naive `len(members) × width` product left the whole
// package green, because the guard never saw the value the sweep used.
//
// There is no legitimate reason for three constructions of one slot from one
// config to differ, so they are collapsed rather than cross-checked: a shared
// constructor makes divergence unrepresentable, where an agreement test would
// only make it detectable.
func ruleAxisSlots6812(t *testing.T, what string, cfg *Config, rules []*NATRule) []ruleAxisSlot6812 {
	t.Helper()
	charges := productionChargeByPool6812(t, cfg)
	slots := make([]ruleAxisSlot6812, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			t.Fatalf("%s: a nil rule reached the slot builder; the charge walk's own nil "+
				"guard is defensive and the sweep has no value to project", what)
		}
		pool := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
		if pool == nil {
			t.Fatalf("%s: rule %s references pool %q, which is not defined; the pool-side "+
				"axes have no value to expose", what, rule.Name, rule.Then.PoolName)
		}
		if len(pool.Addresses) == 0 && pool.Address == "" {
			t.Fatalf("%s: rule %s references pool %q with no members; the pool-address axis "+
				"is not defined", what, rule.Name, rule.Then.PoolName)
		}
		ch, ok := charges[rule.Then.PoolName]
		if !ok {
			t.Fatalf("%s: rule %s references pool %q, which the production charge walk did "+
				"not charge; the derived columns READ that charge rather than recomputing "+
				"it, so an uncharged pool has no value to expose", what, rule.Name,
				rule.Then.PoolName)
		}
		slots = append(slots, ruleAxisSlot6812{
			Rule:          rule,
			Pool:          pool,
			ChargeAddrs:   ch.addrs,
			ChargePortCap: ch.portCap,
		})
	}
	return slots
}

// axisAnySlots6812 boxes what ruleAxisSlots6812 built for sweepAxes6812, which
// takes []any because it sweeps more than one slot type. Boxing is the ONLY
// thing it does — no caller may rebuild a slot on the way in.
func axisAnySlots6812(slots []ruleAxisSlot6812) []any {
	out := make([]any, 0, len(slots))
	for _, s := range slots {
		out = append(out, s)
	}
	return out
}

// walkRuleAxisExemptions6812 is the honest enumeration of what
// TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812 does NOT guard:
// columns a within-rule-set sort could key on that this fixture holds constant,
// so such a sort would be invisible here.
//
// Three of the twenty-nine are genuinely free — the walk itself has already
// filtered those variations out before the first charge, so there is nothing to
// discriminate. The other twenty-six are admitted blind spots.
var walkRuleAxisExemptions6812 = mergeAxisExemptions6812(
	productionConstantAxes6812(
		"compileNATSource appends only non-nil rules (compiler_nat_source.go:969 is "+
			"the sole non-test append into Security.NAT.Source), so no config the "+
			"compiler produces puts a nil in the slice this fixture walks. The charge "+
			"walk's own `rule == nil` guard is defensive.",
		walkWitness6812(),
		"Rule.nil",
	),
	fixtureConstantAxes6812(
		"#8814. NOT production-constant: a pool CAN carry an oversized "+
			"`address <low> to <high>` range on the tolerant load / peer-sync path, "+
			"which is the entire point of recording it rather than erroring — "+
			"CompileConfigLenient accepts such a config and the strict gate "+
			"(validateNATPoolAddressRangeStrict) is what refuses it at commit. What "+
			"makes the column constant HERE is that this fixture authors no range at "+
			"all, so nothing can exceed the cap. Registered as a FIXTURE blind spot "+
			"rather than a production invariant, because claiming the latter would "+
			"assert that no config the compiler produces can populate the field, and "+
			"that is false by construction.",
		"Pool.OversizedAddressRanges.nil", "Pool.OversizedAddressRanges.len",
		"Pool.OversizedAddressRanges.all", "Pool.OversizedAddressRanges[0]",
	),
	fixtureConstantAxes6812(
		"NOT production-constant, corrected in round 11. Round 10 classified this "+
			"alongside Rule.nil on the argument that the charge walk filters a dangling "+
			"pool reference out before charging (compiler_validate_strict_nat.go:3192) — "+
			"true, and a different statement from the registry's own definition. "+
			"CompileConfigLenient PERMITS a dangling reference "+
			"(compiler_nat_pool_ref_5626_test.go:164), so `Pool` CAN be nil for a config "+
			"the compiler produces; what makes it constant HERE is this fixture's own "+
			"precondition, which Fatalfs on a nil pool. Order-irrelevant after filtering "+
			"is not the same as invariant for every input, so the entry moves rather "+
			"than the definition.",
		"Pool.nil",
	),
	productionConstantAxes6812(
		"every rule reachable through cfg.Security.NAT.Source is produced by "+
			"compileNATSource, whose only write to this field is NATSource — and "+
			"NATSource is NATType's zero value, so an unwritten field carries it too. "+
			"The column is NATSource for every config the compiler can produce.",
		walkWitness6812(),
		"Rule.Then.Type",
	),
	productionConstantAxes6812(
		"a source rule cannot carry a protocol match. The ONLY non-test writer of "+
			"Match.Protocol / Match.Protocols is compiler_nat_destination.go:167-169, "+
			"and destination rules never enter Security.NAT.Source. Round 10 recorded "+
			"these as fixture blind spots, which over-reported the hole.",
		walkWitness6812(),
		"Rule.Match.Protocol", "Rule.Match.Protocols.len", "Rule.Match.Protocols.nil",
		"Rule.Match.Protocols.all", "Rule.Match.Protocols[0]",
	),
	productionConstantAxes6812(
		"the DNAT-compat scalars cannot be set on a SOURCE pool. compileNATSource "+
			"constructs its pools fresh (`pool := &NATPool{Name: inst.name}`, "+
			"compiler_nat_source.go:471) and is the sole writer of SourcePools (:686); "+
			"the only non-test writers of Address / AddressInvalidSpec / Port / PortRaw "+
			"are in compiler_nat_destination.go, on DNAT pool objects this map never "+
			"aliases. Round 10 recorded these as fixture blind spots too.",
		walkWitness6812(),
		"Pool.Address", "Pool.AddressInvalidSpec", "Pool.Port", "Pool.PortRaw",
	),
	fixtureConstantAxes6812(
		"the fixture gives each rule ONE literal source prefix and no address-book "+
			"name, destination, port, protocol or application constraint, so these stay "+
			"at their zero value — and with them every key derived from those lists' "+
			"CONTENTS is unguarded too, not just the lengths. Production sets any of "+
			"them per rule.",
		"Rule.Match.SourceAddresses.len", "Rule.Match.SourceAddresses.nil",
		"Rule.Match.SourceAddressName",
		"Rule.Match.SourceAddressNames.len", "Rule.Match.SourceAddressNames.nil",
		"Rule.Match.SourceAddressNames.all", "Rule.Match.SourceAddressNames[0]",
		"Rule.Match.DestinationAddress",
		"Rule.Match.DestinationAddresses.len", "Rule.Match.DestinationAddresses.nil",
		"Rule.Match.DestinationAddresses.all", "Rule.Match.DestinationAddresses[0]",
		"Rule.Match.DestinationAddressName",
		"Rule.Match.DestinationAddressNames.len", "Rule.Match.DestinationAddressNames.nil",
		"Rule.Match.DestinationAddressNames.all", "Rule.Match.DestinationAddressNames[0]",
		"Rule.Match.DestinationPort",
		"Rule.Match.DestinationPorts.len", "Rule.Match.DestinationPorts.nil",
		"Rule.Match.DestinationPorts.all", "Rule.Match.DestinationPorts[0]",
		"Rule.Match.InvalidDestinationPorts.len", "Rule.Match.InvalidDestinationPorts.nil",
		"Rule.Match.InvalidDestinationPorts.all", "Rule.Match.InvalidDestinationPorts[0]",
		"Rule.Match.ReversedDestinationPortRanges.len",
		"Rule.Match.ReversedDestinationPortRanges.nil",
		"Rule.Match.ReversedDestinationPortRanges.all",
		"Rule.Match.ReversedDestinationPortRanges[0]",
		"Rule.Match.Application",
		"Rule.Match.Applications.len", "Rule.Match.Applications.nil",
		"Rule.Match.Applications.all", "Rule.Match.Applications[0]",
	),
	fixtureConstantAxes6812(
		"round-11 POINTEE-SCHEMA columns, and the reason round 11 exists. Every pool "+
			"here leaves `PersistentNAT` and `Deterministic` nil, and round 10's collector "+
			"emitted only `.nil` and SILENTLY SKIPPED every field behind the pointer — so "+
			"adding a field to PersistentNATConfig or DeterministicNATConfig changed no "+
			"column at all. The collector now walks the pointee TYPE with absent keys, so "+
			"those fields have columns and a new one lands here unregistered. They are "+
			"constant because no fixture pool is persistent-NAT or deterministic-CGNAT, "+
			"and a comparator keying on a populated one is unguarded.",
		"Pool.PersistentNAT.Permit", "Pool.PersistentNAT.InactivityTimeout",
		"Pool.Deterministic.BlockSize", "Pool.Deterministic.HostAddress",
	),
	fixtureConstantAxes6812(
		"every rule here is plain pool-mode source NAT: no `then source-nat interface` "+
			"and no `off` exemption. Both are per-rule settable in production.",
		"Rule.Then.Interface", "Rule.Then.Off",
	),
	fixtureConstantAxes6812(
		"#8430 compile-time diagnostic state: whether the rule AUTHORED a `match` "+
			"container at all, as opposed to omitting it. The compiled NATMatch cannot "+
			"tell those apart, and they are different intentions: a scope-only rule "+
			"(`from zone` / `to zone` with no match) deliberately translates everything "+
			"in that scope and is legitimate, while `match { }` or "+
			"`match { source-address; }` is an operator whose constraint evaporated and "+
			"whose rule the dataplane then reads as UNCONSTRAINED. Constant true here "+
			"because every rule in this fixture authors a match; in production it is "+
			"false for every scope-only rule, so this is a real blind spot and NOT "+
			"production-constant. Registered rather than varied for the same reason as "+
			"thenAuthored below: nothing sorts or compares on it — it is read once by "+
			"validateNATRuleMatchConstrainedStrict and never reaches the dataplane "+
			"ITSELF. What reaches the wire is the EXPORTED marker #9874 derives "+
			"from it (LenientMatchDropped, own column below), not this bit. If "+
			"that ever changes, vary it instead.",
		"Rule.matchAuthored",
	),
	fixtureConstantAxes6812(
		"#9874 fail-closed poison, derived from matchAuthored above: whether "+
			"the rule authored a `match` that constrains nothing. Constant "+
			"false here because every fixture rule carries a populated match; "+
			"in production it is true for every tolerant-loaded empty-match "+
			"rule, so this is a real blind spot and NOT production-constant. "+
			"Registered rather than varied because nothing sorts or compares "+
			"on it: the snapshot builders copy it onto the wire and the Rust "+
			"table drops such a rule closed. If a comparator ever keys on "+
			"it, vary it instead.",
		"Rule.LenientMatchDropped",
	),
	fixtureConstantAxes6812(
		"#9877 compile-time diagnostic state: `match` children the compiler did "+
			"not read (a typo'd leaf beside a valid one), recorded so the lenient "+
			"gate can warn and the snapshot builder can fail closed. Constant "+
			"nil/empty here because no fixture rule carries an unknown leaf; in "+
			"production any typo'd leaf populates it on the tolerant path, so "+
			"this is a real blind spot and NOT production-constant. Registered "+
			"rather than varied for the same reason as matchAuthored above: "+
			"nothing sorts or compares on it — it is read once by "+
			"validateNATUnknownMatchLeavesStrict and the snapshot exclusion "+
			"predicates and never reaches the dataplane (`json:\"-\"`). If that "+
			"ever changes, vary it instead.",
		"Rule.UnknownMatchLeaves.nil", "Rule.UnknownMatchLeaves.len",
		"Rule.UnknownMatchLeaves.all", "Rule.UnknownMatchLeaves[0]",
	),
	fixtureConstantAxes6812(
		"#7013 compile-time diagnostic state: what ONE `then` container authored, kept "+
			"so validateNATTerminalActionCardinalityStrict can see a pool the resolved "+
			"NATThen scalar already discarded. Constant at exactly one authored pool "+
			"here because every rule in this fixture is plain pool-mode source NAT — in "+
			"production it is 0 for an `interface` or `off` rule, so this is a real blind "+
			"spot and NOT production-constant. It is registered rather than varied "+
			"because nothing sorts or compares on it: it is read once by the strict gate "+
			"and never reaches the dataplane. If that ever changes, vary it instead.\n"+
			"Only the LENGTH columns are registered: the pool NAMES vary rule to rule "+
			"here, so `.all`/`[0]` are guarded and registering them was rejected as "+
			"over-reach by this table's own stale-entry check.",
		"Rule.thenAuthored.Pools.len", "Rule.thenAuthored.Pools.nil",
	),
	fixtureConstantAxes6812(
		"#7033 authored terminal action MODES, the companion of the pool names above. "+
			"Every rule in this fixture is plain pool-mode source NAT, so the recorded "+
			"mode list is exactly [pool] for all of them and all four columns are "+
			"constant — unlike the pool NAMES, which vary. In production it varies on "+
			"both axes: `off` and `interface` rules record a different mode, and a "+
			"packed cross-mode contradiction records two before the strict gate refuses "+
			"the commit. So this is a real blind spot, not a production constant. "+
			"Nothing sorts or compares on it — it is read by the packed-contradiction "+
			"gate and its lenient enumerator and never reaches the dataplane.",
		"Rule.thenAuthored.Modes.len", "Rule.thenAuthored.Modes.nil",
		"Rule.thenAuthored.Modes.all", "Rule.thenAuthored.Modes[0]",
	),
	fixtureConstantAxes6812(
		"pool fields this fixture never configures. Address/Port/PortRaw are the DNAT "+
			"compatibility scalars, PortRangeInvalidSpec is the #5457 rejected-range "+
			"marker (every range here is valid), and no pool is routing-instance-scoped, "+
			"port-overloaded, no-translation, persistent-NAT or deterministic-CGNAT. A "+
			"tiebreak keyed on any of them would reorder a config that sets it.",
		"Pool.PortRangeInvalidSpec", "Pool.Addresses.nil",
		"Pool.PortNoTranslation", "Pool.PortOverloadingFactor", "Pool.RoutingInstance",
		"Pool.PersistentNAT.nil", "Pool.Deterministic.nil",
	),
)

// walkWitness6812 is the adversarial sequence behind this package's
// production-constant claims (#6812 round 11). Each claim says a column cannot
// vary for any production input; this config is built to make it vary if that
// were false:
//
//   - it carries DESTINATION NAT alongside source NAT, with a DNAT rule that
//     sets `match protocol tcp` and a DNAT pool that sets both `address` and
//     `port`. Those are exactly the fields claimed unreachable from the source
//     side, and here they are populated — on the other side of the compiler;
//   - its source rule-set's rules reference DIFFERENT pools, so a false claim on
//     any pool-derived column fails instead of passing quietly;
//   - it declares several rules per rule-set, so `Rule.nil` is witnessed over a
//     real sequence rather than a singleton.
//
// Groups are per source RULE-SET, which is the scope the walk's rule order is
// asserted at.
func walkWitness6812() axisWitness6812 {
	return axisWitness6812{
		name: "source + destination NAT, DNAT protocol/address/port populated",
		groups: func(t *testing.T) []axisGroup6812 {
			t.Helper()
			cmds := []string{
				// The DNAT half: the fields the source-side claims say are
				// unreachable, set on purpose.
				"set security nat destination pool dp address 203.0.113.200",
				"set security nat destination pool dp address port 8080",
				"set security nat destination rule-set DRS from zone untrust",
				"set security nat destination rule-set DRS rule dr0 match protocol tcp",
				"set security nat destination rule-set DRS rule dr0 match destination-address 198.51.100.9/32",
				"set security nat destination rule-set DRS rule dr0 then destination-nat pool dp",
				// The source half, one rule-set, three rules, three pools.
				"set security nat source rule-set WRS from zone trust",
			}
			for r := 0; r < 3; r++ {
				pool := fmt.Sprintf("wq%d", r)
				cmds = append(cmds,
					fmt.Sprintf("set security nat source pool %s address 198.51.%d.1", pool, 200+r),
					fmt.Sprintf("set security nat source pool %s port range %d to %d", pool, 3000+100*r, 3050+100*r),
					fmt.Sprintf("set security nat source rule-set WRS rule wr%d match source-address 10.7.%d.0/24", r, r),
					fmt.Sprintf("set security nat source rule-set WRS rule wr%d then source-nat pool %s", r, pool),
				)
			}
			cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
			if err != nil {
				t.Fatalf("witness CompileConfigLenient: %v", err)
			}
			// The DNAT half must really have compiled, or the witness is not
			// adversarial and the claims it backs are unchecked.
			if n := len(cfg.Security.NAT.Destination.RuleSets); n == 0 {
				t.Fatalf("witness compiled NO destination rule-sets; the claims that a source " +
					"rule cannot carry a protocol match, and a source pool cannot carry the " +
					"DNAT-compat scalars, would then be witnessed against a config that has " +
					"no destination side at all")
			}
			var groups []axisGroup6812
			for _, rs := range cfg.Security.NAT.Source {
				// ONE slot builder, shared with the sweep and the derived-column
				// guard (#6812 round 13) — see ruleAxisSlots6812.
				slots := ruleAxisSlots6812(t, "witness rule-set "+rs.Name, cfg, rs.Rules)
				groups = append(groups, axisGroup6812{
					label: "witness rule-set " + rs.Name,
					slots: axisAnySlots6812(slots),
				})
			}
			return groups
		},
	}
}

// TestProductionConstantAxesAreWitnessed_6812 is the round-11 answer to "the
// productionConstant truth is not mechanically checked".
func TestProductionConstantAxesAreWitnessed_6812(t *testing.T) {
	assertProductionConstantWitnesses6812(t, "walk axis registry", walkRuleAxisExemptions6812)
}
