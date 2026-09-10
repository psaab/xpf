package dataplane

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// #7097: the peer-install node-local scrub must not fall behind the struct.
//
// A peer-owned session must not inherit fields that only mean something on the
// node that produced them. Before this change FOUR install sites each carried
// their own hand-written list of those fields, and every one of them listed the
// five FIB fields and not the #4983 ingress pair that #6928 added to the ABI.
// Nothing reached any of them with a non-zero value — pkg/cluster's session wire
// never encodes the pair — so the incompleteness was latent, which is exactly
// why nothing noticed it.
//
// The fix is one list (`ScrubNodeLocal`, session_node_local.go). These tests are
// the two halves that keep it one list:
//
//   - the CENSUS below asserts the helper zeroes the declared node-local set and
//     NOTHING else, by filling every field with a non-zero sentinel through
//     reflection and comparing both directions. It reads no marker comment and
//     no hand-maintained name list against the struct, so a field added to the
//     helper without being declared fails as loudly as one declared without
//     being zeroed. The field COUNT is pinned separately, so a new field on the
//     struct forces a human to classify it.
//   - the DELEGATION pin asserts every peer-install site calls the helper and
//     none has re-grown a private list.

// nodeLocalSessionFields are the fields a peer-owned row must NOT inherit.
// FIB* are the resolved EGRESS of a lookup the ORIGINATING node performed;
// IngressIfindex / IngressVlanID are the #4983 ingress-binding identity,
// node-local for the same reason (node 0's `ge-0-0-1` and node 1's `ge-7-0-1`
// are different numbers for one logical RETH member).
//
// IngressIfaceFold (#7095) is deliberately NOT here, and the distinction is the
// whole reason that field exists. It is a fold of the RETH-RELATIVE name
// (`reth0.50`), which both chassis agree on by construction — it is the one
// ingress-identity field that is MEANT to survive the wire, and the receiving
// node resolves it back to its own {ifindex, vlan}. Scrubbing it would delete
// the peer's answer and put every synced session back on the #4792 zone
// approximation, which is exactly what #7095 removed.
//
// TunnelDiscriminator (#7188) is NOT here either, and for a stronger reason
// than #7095's. It is not merely cluster-agreeable, it is SYMMETRIC BY
// CONSTRUCTION: an RFC 2890 GRE Key is carried identically in both directions
// of a tunnel and is identical on both chassis — being symmetric is precisely
// why that field was chosen as the discriminator over the PPTP call ID and the
// ESP SPI, which are allocated per-direction. Scrubbing it would put both of a
// peer's same-endpoint keyed tunnels back on one key, which is the aliasing
// #7188 exists to remove.
// partiallyScrubbedSessionFields are fields the scrub modifies WITHOUT zeroing,
// mapped to the exact bits it is allowed to clear.
//
// #8612. `LogFlags` is not node-local as a whole — it carries userspace sync
// metadata the peer legitimately owns — but one bit of it is:
// LogFlagUserspaceTunnelEndpoint says "FibGen holds a tunnel endpoint id, not a
// FIB generation". FibGen IS node-local and is zeroed, so the bit describing it
// must go with it or the row asserts a value it no longer carries.
//
// This map exists because the census below could not otherwise SEE such a
// change, and saying so is the point: `zeroedFields` detects only a non-zero ->
// zero transition, so ANY partial mutation of a field was invisible to it. The
// "and nothing else" guarantee in this file's header was therefore weaker than
// it read — it held for whole-field zeroing and said nothing about a field the
// scrub merely edits. `changedFields` below closes that.
//
// #8612 UPDATE: this map is now EMPTY, and that is the fix rather than a
// regression. It held `LogFlags -> LogFlagUserspaceTunnelEndpoint`, asserting
// that the scrub clears the tunnel bit. It does not any more: the bit describes
// a value that is now preserved, so clearing it would again make the flag and
// the value disagree. The entry was a guard asserting the erasure was correct.
// The map itself is kept -- the next partially-scrubbed field needs it, and the
// machinery below is what makes such a field visible at all.
var partiallyScrubbedSessionFields = map[string]uint64{}

var nodeLocalSessionFields = map[string]bool{
	"FibIfindex":     true,
	"FibVlanID":      true,
	"FibDmac":        true,
	"FibSmac":        true,
	"IngressIfindex": true,
	"IngressVlanID":  true,
}

// #8612: fields whose node-locality is CONDITIONAL, mapped to the LogFlags bit
// that makes them cluster-stable. With the bit CLEAR the field is node-local and
// must be zeroed; with it SET the field must SURVIVE untouched.
//
// `FibGen` is the only one, and it is here rather than in the list above because
// the two readings are genuinely different data. As a FIB generation it is this
// node's number and worthless on the peer. Under
// LogFlagUserspaceTunnelEndpoint it is a `config.StableTunnelEndpointID` --
// FNV-1a over the interface NAME alone -- which pkg/config/tunnelid.go
// documents as crossing the cluster in this exact field, identical on both
// nodes by construction. Zeroing it destroys an identity the receiver cannot
// re-derive, because every local re-derivation on that path is seeded from the
// ifindex the same scrub zeroed.
//
// THIS MAP EXISTS BECAUSE THE CENSUS COULD NOT OTHERWISE SEE THE CASE, which is
// the same reason `partiallyScrubbedSessionFields` was added: a field that is
// sometimes scrubbed and sometimes not satisfies neither directional check
// above, so before #8612 it could only be declared unconditionally -- and it
// was, which is how a guard came to assert the erasure was correct.
var conditionallyNodeLocalSessionFields = map[string]uint64{
	"FibGen": uint64(LogFlagUserspaceTunnelEndpoint),
}

// fillNonZero sets every settable field of a struct to a non-zero sentinel, so
// "this field came back zero" means the scrub zeroed it rather than the fixture
// never having set it. A fixture that left a field at its zero value would make
// the scrub look complete for a field it never touches.
func fillNonZero(t *testing.T, v reflect.Value) {
	t.Helper()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if !f.CanSet() {
			continue
		}
		switch f.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			f.SetUint(0x5A)
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			f.SetInt(0x5A)
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Array:
			for j := 0; j < f.Len(); j++ {
				if f.Index(j).Kind() == reflect.Uint8 {
					f.Index(j).SetUint(0x5A)
				}
			}
		case reflect.Struct:
			fillNonZero(t, f)
		default:
			// A field kind this helper cannot seed would read as "scrubbed" for
			// free. Fail rather than quietly under-cover it.
			t.Fatalf("field %s has kind %s, which fillNonZero does not seed — "+
				"the zero/non-zero comparison below would be vacuous for it (#7097)",
				v.Type().Field(i).Name, f.Kind())
		}
	}
}

// zeroedFields reports which top-level fields of `after` are zero while the
// same field of `before` was not.
func zeroedFields(before, after reflect.Value) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < before.NumField(); i++ {
		name := before.Type().Field(i).Name
		b, a := before.Field(i), after.Field(i)
		if !b.IsZero() && a.IsZero() {
			out[name] = true
		}
	}
	return out
}

// changedFields reports every top-level field that differs between `before` and
// `after`, whether or not it became zero.
//
// This is the strictly stronger companion to zeroedFields: a scrub that clears
// one BIT of a multi-bit field, or that sets a field to a different non-zero
// value, is a change the zero-transition test cannot represent.
func changedFields(before, after reflect.Value) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < before.NumField(); i++ {
		name := before.Type().Field(i).Name
		if !reflect.DeepEqual(before.Field(i).Interface(), after.Field(i).Interface()) {
			out[name] = true
		}
	}
	return out
}

// scrubGateSet reports whether the LogFlags gate bit was set on the PRE-scrub
// value. It reads `before` deliberately: the scrub may legitimately change
// LogFlags, so the arm a field should be judged under is the one the row
// arrived in, not the one it leaves in.
func scrubGateSet(before reflect.Value, gate uint64) bool {
	f := before.FieldByName("LogFlags")
	if !f.IsValid() {
		return false
	}
	return f.Uint()&gate != 0
}

// scrubCensusViolations is the census PROPER, returning one string per
// violation instead of reporting them.
//
// EXTRACTED (#8612 follow-up) for the reason `headroomCensusViolations` was:
// a census that has only ever run against the real structs and the real
// declaration maps is indistinguishable from one that always returns nil. The
// `partial` arm made that concrete -- once its only entry
// was removed, the arm could not fail against any input the suite offered, so
// nothing would have noticed it rotting. Taking the maps as parameters lets a
// synthetic fixture drive every arm in BOTH directions.
func scrubCensusViolations(
	before, after reflect.Value,
	nodeLocal map[string]bool,
	partial map[string]uint64,
	conditional map[string]uint64,
) []string {
	var viol []string
	add := func(format string, args ...any) { viol = append(viol, fmt.Sprintf(format, args...)) }
	scrubbed := zeroedFields(before, after)
	if len(scrubbed) == 0 {
		add("the scrub zeroed NOTHING — the fixture or the call did not run, " +
			"and the two directional checks below would both pass vacuously (#7097)")
		return viol
	}
	for name := range nodeLocal {
		if !scrubbed[name] {
			add("%s is NODE-LOCAL but survived the peer-install scrub. A "+
				"peer-owned row can then inherit this node's number and render a "+
				"confidently wrong answer — worse than the zero the consumer falls "+
				"back on (#7097)", name)
		}
	}
	for name := range scrubbed {
		if nodeLocal[name] {
			continue
		}
		// #8612: a conditional field may legitimately be zeroed -- but only on
		// the arm where its gate bit is CLEAR. Zeroing it with the bit SET is
		// the defect this issue is about, and is caught by the conditional
		// block below rather than silently excused here.
		if gate, ok := conditional[name]; ok {
			if scrubGateSet(before, gate) {
				continue // reported precisely below
			}
			continue
		}
		add("the scrub zeroes %s, which is NOT declared node-local. Either "+
			"it is node-local and this list is stale, or the scrub is destroying "+
			"a field the peer legitimately owns (#7097)", name)
	}

	// #8612: the CONDITIONAL arm. Each declared field is node-local only when
	// its gate bit is clear; with the bit set the value is cluster-stable and
	// must survive. Both directions are asserted, so neither "always zero it"
	// (the pre-#8612 erasure) nor "never zero it" (which would leak this node's
	// FIB generation onto a peer row) passes.
	for name, gate := range conditional {
		b := before.FieldByName(name)
		a := after.FieldByName(name)
		if !b.IsValid() || !a.IsValid() {
			add("conditionally-node-local field %s is not present on this "+
				"struct — the declaration is stale (#8612)", name)
			continue
		}
		if b.Uint() == 0 {
			add("the fixture left %s at zero, so neither arm of the "+
				"conditional assertion can distinguish preserved from scrubbed — "+
				"fillNonZero must seed it (#8612)", name)
		}
		if scrubGateSet(before, gate) {
			if a.Uint() != b.Uint() {
				add("%s was scrubbed to %#x with its gate bit %#x SET, but under "+
					"that bit the field is a StableTunnelEndpointID — a pure fold of "+
					"the interface NAME that both nodes compute identically and that "+
					"pkg/cluster/sync_protocol.go encodes on the wire. Zeroing it "+
					"destroys an identity the receiver cannot re-derive, because the "+
					"local fallback is seeded from the ifindex this same scrub zeroes "+
					"(#8612)", name, a.Uint(), gate)
			}
			continue
		}
		if a.Uint() != 0 {
			add("%s survived the scrub with its gate bit %#x CLEAR. Without that "+
				"bit the field is a node-local FIB generation, and a peer row "+
				"inheriting this node's number renders a confidently wrong answer "+
				"(#7097)", name, gate)
		}
	}

	// #8612: the same two directions again, over ANY change rather than only a
	// zero transition. Without this arm a scrub that edits a field instead of
	// zeroing it passes both checks above while doing something nobody
	// declared.
	changed := changedFields(before, after)
	for name := range changed {
		if nodeLocal[name] {
			continue
		}
		// #8612: conditional fields get BOTH their directions asserted in the
		// dedicated block below, which is stricter than this one — it checks the
		// value against the gate rather than merely allowing a change. Skipping
		// here would be a hole if that block did not exist; it does, and the
		// `!b.IsValid()` arm there fails if a declaration goes stale.
		if _, ok := conditional[name]; ok {
			continue
		}
		mask, declared := partial[name]
		if !declared {
			add("the scrub MODIFIES %s, which is declared neither node-local nor "+
				"partially scrubbed. A field the scrub edits rather than zeroes is "+
				"invisible to the zero-transition census above, so it has to be "+
				"declared here or not touched (#8612)", name)
			continue
		}
		b := before.FieldByName(name)
		a := after.FieldByName(name)
		if b.Kind() < reflect.Uint || b.Kind() > reflect.Uint64 {
			add("%s is declared partially scrubbed but is kind %s; the mask "+
				"comparison below only models unsigned integers (#8612)", name, b.Kind())
			continue
		}
		if got, want := a.Uint(), b.Uint()&^mask; got != want {
			add("the scrub changed %s to %#x, want %#x (%#x with mask %#x "+
				"cleared). It may clear ONLY the declared bits — the rest of this "+
				"field is metadata the peer owns (#8612)", name, got, want, b.Uint(), mask)
		}
	}
	for name, mask := range partial {
		b := before.FieldByName(name)
		if !b.IsValid() {
			continue
		}
		if b.Uint()&mask == 0 {
			add("the fixture left %s with none of the mask %#x set, so the "+
				"partial-scrub assertion is vacuous — fillNonZero must seed those "+
				"bits (#8612)", name, mask)
		}
		if !changed[name] {
			add("%s carries declared node-local bits %#x that SURVIVED the "+
				"scrub. FibGen is zeroed, so a surviving "+
				"LogFlagUserspaceTunnelEndpoint asserts a tunnel endpoint the row no "+
				"longer carries — an invariant a flag-only consumer would trust (#8612)",
				name, mask)
		}
	}
	return viol
}

// assertScrubCensus reports what the census found, against the real maps.
func assertScrubCensus(t *testing.T, before, after reflect.Value) {
	t.Helper()
	for _, v := range scrubCensusViolations(
		before, after,
		nodeLocalSessionFields,
		partiallyScrubbedSessionFields,
		conditionallyNodeLocalSessionFields,
	) {
		t.Error(v)
	}
}

// The census on the single-sourced helper itself.
func TestScrubNodeLocalCoversExactlyTheNodeLocalFields7097(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)
		val.ScrubNodeLocal()
		assertScrubCensus(t, before, reflect.ValueOf(val))
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)
		val.ScrubNodeLocal()
		assertScrubCensus(t, before, reflect.ValueOf(val))
	})
}

// The wiring bind for the two session-store install sites: the census above
// proves the HELPER is right, this proves the store actually CALLS it. A
// sessionStoreTestDP does not implement clusterSyncedSessionInstaller, so the
// early return is not taken and the scrub branch runs.
func TestPeerInstallStoreScrubsNodeLocalFields7097(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)

		dp := &sessionStoreTestDP{}
		key := SessionKey{Protocol: 6}
		if err := (dataPlaneSessionStore{dp: dp}).putClusterSyncedV4Raw(key, val); err != nil {
			t.Fatalf("putClusterSyncedV4Raw: %v", err)
		}
		got, ok := dp.v4[key]
		if !ok {
			t.Fatal("the store did not install the row — the scrub branch was not " +
				"reached and this cell measures nothing")
		}
		assertScrubCensus(t, before, reflect.ValueOf(got))
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)

		dp := &sessionStoreTestDP{}
		key := SessionKeyV6{Protocol: 6}
		if err := (dataPlaneSessionStore{dp: dp}).putClusterSyncedV6Raw(key, val); err != nil {
			t.Fatalf("putClusterSyncedV6Raw: %v", err)
		}
		got, ok := dp.v6[key]
		if !ok {
			t.Fatal("the store did not install the row — the scrub branch was not " +
				"reached and this cell measures nothing")
		}
		assertScrubCensus(t, before, reflect.ValueOf(got))
	})
}

// The population pin. The census compares the helper against a DECLARED set;
// this is what stops that set going stale silently. A field added to
// SessionValue is either node-local (add it to ScrubNodeLocal AND to
// nodeLocalSessionFields) or it is not (update this number) — either way a human
// classifies it, which is the step #6928 skipped.
func TestSessionValueFieldCountIsPinned7097(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		want int
	}{
		// 38/39 since #7239 added RoutingDomain (37/38 after #7188's
		// TunnelDiscriminator, 36/37 after #7095's IngressIfaceFold). All three
		// are classified NOT node-local and are therefore absent from
		// ScrubNodeLocal / nodeLocalSessionFields — see the note on
		// nodeLocalSessionFields.
		//
		// The #7239 classification, stated rather than assumed, because this is
		// the step #6928 skipped: RoutingDomain is
		// `StableRoutingInstanceTableID(name)`, a pure function of the
		// routing-instance NAME. Both nodes compute the SAME number for the same
		// instance from identical config, with no synced or persisted state.
		// That is exactly the property that makes it legal on the wire, and it
		// is what distinguishes it from IngressIfindex — an ifindex is
		// node-local and names a different NIC on the peer, which is why #6928
		// declined to sync one and why #7095 had to invent a name fold instead.
		// A cluster-stable number needs no scrub.
		//
		// 39/40 since #9412 added TCPCloseClass, classified NOT node-local. It is
		// the OWNING node's TCP close class (0 open, 1 CLOSING, 2 TIME_WAIT,
		// 3 RST), computed from the packets that node saw, and carried to the
		// peer precisely so the peer's copy reaps on the right window after a
		// failover. It names no local resource: no ifindex, no FIB result, no
		// MAC. It means the same thing on either node. Scrubbing it would
		// reintroduce #9412, where a session that closed on the primary imports
		// on the established window.
		{"SessionValue", reflect.TypeOf(SessionValue{}), 39},
		{"SessionValueV6", reflect.TypeOf(SessionValueV6{}), 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.typ.NumField(); got != tc.want {
				t.Fatalf("%s has %d fields, pinned at %d. A new field must be "+
					"classified: node-local fields go in BOTH ScrubNodeLocal and "+
					"nodeLocalSessionFields; everything else just updates this number "+
					"(#7097)", tc.name, got, tc.want)
			}
		})
	}
}

// clusterSyncedInstallSites are every function that installs a session the
// CLUSTER PEER owns. Each must delegate the node-local strip to ScrubNodeLocal
// rather than keep its own list.
//
// The manager pair is the branch PRODUCTION takes: putClusterSyncedV4Raw's
// scrub runs only when the dataplane does not implement
// clusterSyncedSessionInstaller, and the userspace manager does implement it. A
// behavioural test for the manager pair would need a real BPF map (its whole
// package's manager tests t.Skipf without CAP_SYS_ADMIN/memlock), so it would
// SKIP on developer machines — which is why this pin is structural. It is not a
// substitute for the census: the census proves the helper is complete, this
// proves nobody bypasses it.
var clusterSyncedInstallSites = map[string][]string{
	"session_store.go": {
		"putClusterSyncedV4Raw",
		"putClusterSyncedV6Raw",
	},
	"userspace/manager_sessions.go": {
		"SetClusterSyncedSessionV4",
		"SetClusterSyncedSessionV6",
	},
}

func TestClusterSyncedInstallSitesDelegateTheScrub7097(t *testing.T) {

	for file, fns := range clusterSyncedInstallSites {
		t.Run(file, func(t *testing.T) {
			path := filepath.Join(".", filepath.FromSlash(file))
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			fset := token.NewFileSet()
			// Parsing with the Go parser, not a text scan, is what makes this
			// immune to being satisfied by its own doc comment: comments are not
			// expressions and never appear in the AST walked below.
			f, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			found := map[string]bool{}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				var want bool
				for _, name := range fns {
					if fd.Name.Name == name {
						want = true
					}
				}
				if !want {
					continue
				}
				found[fd.Name.Name] = true

				var callsScrub bool
				var ownList []string
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CallExpr:
						if sel, ok := x.Fun.(*ast.SelectorExpr); ok &&
							sel.Sel.Name == "ScrubNodeLocal" {
							callsScrub = true
						}
					case *ast.AssignStmt:
						for _, lhs := range x.Lhs {
							sel, ok := lhs.(*ast.SelectorExpr)
							if !ok {
								continue
							}
							if nodeLocalSessionFields[sel.Sel.Name] {
								ownList = append(ownList, sel.Sel.Name)
							}
						}
					}
					return true
				})

				if !callsScrub {
					t.Errorf("%s does not call ScrubNodeLocal. A peer-install site "+
						"that strips node-local fields by hand is how #7097 happened: "+
						"#6928 added IngressIfindex/IngressVlanID to the ABI and every "+
						"private list silently stopped covering the field class it "+
						"existed to cover", fd.Name.Name)
				}
				if len(ownList) > 0 {
					t.Errorf("%s assigns node-local fields directly (%s). Delete the "+
						"private list and let ScrubNodeLocal own it, or this site will "+
						"drift from the others again (#7097)",
						fd.Name.Name, strings.Join(ownList, ", "))
				}
			}

			// Anti-vacuity: a renamed or moved function must fail here, not
			// silently reduce this cell to zero checks.
			for _, name := range fns {
				if !found[name] {
					t.Errorf("%s not found in %s — this pin checked nothing for it. "+
						"If the function moved, move this entry with it (#7097)",
						name, file)
				}
			}
		})
	}
}

// #8612: the OTHER arm. Every cell above seeds LogFlags via fillNonZero, which
// sets the tunnel bit, so they all exercise "gate SET -> FibGen preserved". With
// only those, `ScrubNodeLocal` could stop zeroing FibGen ALTOGETHER and the
// suite would stay green — a peer row would then inherit this node's FIB
// generation, which is the #7097 defect the conditional was carved out of.
//
// These two clear the bit first, so the field is judged as the node-local FIB
// generation it is in that state.
func TestScrubZeroesFibGenWhenTheTunnelBitIsClear8612(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		val.LogFlags &^= LogFlagUserspaceTunnelEndpoint
		if val.FibGen == 0 {
			t.Fatal("fixture must seed a non-zero FibGen or the assertion is vacuous")
		}
		before := reflect.ValueOf(val)
		val.ScrubNodeLocal()
		if val.FibGen != 0 {
			t.Errorf("FibGen survived the scrub as %#x with the tunnel bit CLEAR — "+
				"in that state it is a node-local FIB generation (#7097)", val.FibGen)
		}
		assertScrubCensus(t, before, reflect.ValueOf(val))
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		val.LogFlags &^= LogFlagUserspaceTunnelEndpoint
		before := reflect.ValueOf(val)
		val.ScrubNodeLocal()
		if val.FibGen != 0 {
			t.Errorf("v6 FibGen survived the scrub as %#x with the tunnel bit CLEAR "+
				"(#7097)", val.FibGen)
		}
		assertScrubCensus(t, before, reflect.ValueOf(val))
	})
}

// #8612: and the arm the fix is FOR, asserted directly rather than only through
// the reflective census — a reader looking for "what does this change do" should
// find one cell that says it in field terms.
func TestScrubPreservesTheTunnelEndpointIdentity8612(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		val.LogFlags |= LogFlagUserspaceTunnelEndpoint
		wantGen, wantFlags := val.FibGen, val.LogFlags
		val.ScrubNodeLocal()
		if val.FibGen != wantGen {
			t.Errorf("the tunnel endpoint id was scrubbed to %#x, want %#x preserved. "+
				"It is a StableTunnelEndpointID — a fold of the interface NAME both "+
				"nodes compute identically (#1873) — not a node-local number (#8612)",
				val.FibGen, wantGen)
		}
		if val.LogFlags&LogFlagUserspaceTunnelEndpoint == 0 {
			t.Errorf("the tunnel bit was cleared though its value survives; flag and " +
				"value must agree, and they now agree by KEEPING both (#8612)")
		}
		if val.LogFlags != wantFlags {
			t.Errorf("LogFlags changed to %#x, want %#x — the scrub must not edit "+
				"flags the peer owns (#8612)", val.LogFlags, wantFlags)
		}
		// The ifindex is still scrubbed: that IS node-local, and it is why the
		// local re-derivation cannot rebuild the identity on its own.
		if val.FibIfindex != 0 {
			t.Errorf("FibIfindex must still be scrubbed (#7097)")
		}
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		val.LogFlags |= LogFlagUserspaceTunnelEndpoint
		wantGen := val.FibGen
		val.ScrubNodeLocal()
		if val.FibGen != wantGen {
			t.Errorf("v6 tunnel endpoint id scrubbed to %#x, want %#x (#8612)",
				val.FibGen, wantGen)
		}
		if val.LogFlags&LogFlagUserspaceTunnelEndpoint == 0 {
			t.Errorf("v6 tunnel bit cleared though its value survives (#8612)")
		}
	})
}

// #8612: carrying the tunnel endpoint id across the cluster is safe ONLY while
// every reader of FibGen tests the flag that says which of its two meanings it
// holds. That is true today at exactly two sites, and this cell is what keeps it
// true: a new reader that tests `FibGen != 0` alone would read a peer's tunnel
// endpoint id as this node's FIB generation.
//
// The claim is a POPULATION claim, so it is measured rather than asserted. The
// scan reports what it found beside what is expected, and fails on a mismatch in
// EITHER direction — a new unguarded reader, or the guarded ones disappearing
// (which would mean the pattern stopped matching and the census had gone blind).
func TestEveryFibGenReaderIsFlagGated8612(t *testing.T) {
	root := headroomRepoRoot(t)
	readRe := regexp.MustCompile(`\.FibGen\b`)
	writeRe := regexp.MustCompile(`\.FibGen\s*=|FibGen:`)
	gateRe := regexp.MustCompile(`LogFlagUserspaceTunnelEndpoint`)
	// The wire codec moves the field verbatim in both directions and cannot
	// interpret it, so it is not a reader in the sense this cell is about.
	codec := filepath.Join("pkg", "cluster", "sync_protocol.go")

	var guarded, unguarded []string
	err := filepath.WalkDir(filepath.Join(root, "pkg"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if rel == codec {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if !readRe.MatchString(line) || writeRe.MatchString(line) {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			// Same line, or the two above it — a gate further away than that is
			// not this read's gate (the #8241 census learned the same lesson
			// about inheriting evidence from distant prose).
			lo := i - 2
			if lo < 0 {
				lo = 0
			}
			where := fmt.Sprintf("%s:%d", rel, i+1)
			if gateRe.MatchString(strings.Join(lines[lo:i+1], "\n")) {
				guarded = append(guarded, where)
			} else {
				unguarded = append(unguarded, where)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// DEGENERACY / POSITIVE CONTROL. A scan that matched nothing looks identical
	// to a clean tree, and the clean answer is the one we want to be able to
	// trust. If this fires, the pattern has stopped matching — not the readers.
	if len(guarded) == 0 {
		t.Fatalf("the census found NO flag-gated FibGen reader. The two known ones "+
			"(manager_sessionsync_request.go) must match, or this cell is blind and "+
			"its silence means nothing (#8612). unguarded=%v", unguarded)
	}
	if len(unguarded) > 0 {
		t.Errorf("FibGen is read WITHOUT testing LogFlagUserspaceTunnelEndpoint at "+
			"%d site(s): %v.\nSince #8612 the field carries a cluster-stable tunnel "+
			"endpoint id when that bit is set and a node-local FIB generation when it "+
			"is not, so a reader that does not test the bit will interpret a peer's "+
			"tunnel id as this node's generation. Test the flag, or read through a "+
			"helper that does.", len(unguarded), unguarded)
	}
	t.Logf("#8612 FibGen reader census: %d guarded, %d unguarded — %v",
		len(guarded), len(unguarded), guarded)
}

// #8612 follow-up: exercise the census machinery itself, against a SYNTHETIC
// struct and synthetic declaration maps.
//
// WHY THIS EXISTS. `partiallyScrubbedSessionFields` is now empty — its only
// entry declared the tunnel-bit clearing that #8612 removed. An empty map means
// the arm that reads it cannot fail against anything the suite offers, so the
// machinery added in #8613 to make partial scrubs visible became unfalsifiable:
// it would be discovered broken by the first person to declare a real partially
// scrubbed field, which is the worst possible time.
//
// Keeping the map without exercising it is a claim written into inert code. So
// the arms are driven here with fixtures the real structs cannot currently
// produce, in BOTH directions — a census that only ever returns nil is
// indistinguishable from a correct one.
type synthScrubRow struct {
	LogFlags uint64
	Meta     uint32
	Gen      uint16
}

func synthCensus(before, after synthScrubRow, nodeLocal map[string]bool,
	partial map[string]uint64, conditional map[string]uint64) []string {
	return scrubCensusViolations(
		reflect.ValueOf(before), reflect.ValueOf(after), nodeLocal, partial, conditional)
}

func TestScrubCensusPartialArmCanActuallyFail8612(t *testing.T) {
	nodeLocal := map[string]bool{"Gen": true}
	partial := map[string]uint64{"Meta": 0x0f}
	conditional := map[string]uint64{}

	// CLEAN: only the declared bits of Meta are cleared, and the declared
	// node-local field is zeroed. The census must be silent.
	before := synthScrubRow{LogFlags: 0xff, Meta: 0xff, Gen: 7}
	clean := synthScrubRow{LogFlags: 0xff, Meta: 0xff &^ 0x0f, Gen: 0}
	if v := synthCensus(before, clean, nodeLocal, partial, conditional); len(v) != 0 {
		t.Fatalf("the census reported %v on a correct partial scrub — it cannot "+
			"distinguish compliance from violation, so the checks below prove nothing", v)
	}

	// VIOLATION 1: an EXTRA bit outside the declared mask was cleared. This is
	// the case the arm exists for, and the case that has had no coverage since
	// the map was emptied.
	extra := synthScrubRow{LogFlags: 0xff, Meta: 0xff &^ 0x1f, Gen: 0}
	if v := synthCensus(before, extra, nodeLocal, partial, conditional); len(v) == 0 {
		t.Error("the census accepted a scrub that cleared bits OUTSIDE the declared " +
			"mask. The partial-scrub arm is inert — the exact rot this cell exists " +
			"to prevent (#8612)")
	}

	// VIOLATION 2: the field is modified but NOT declared partially scrubbed.
	// Distinct arm, distinct failure.
	undeclared := synthScrubRow{LogFlags: 0xf0, Meta: 0xff, Gen: 0}
	if v := synthCensus(before, undeclared, nodeLocal, map[string]uint64{}, conditional); len(v) == 0 {
		t.Error("the census accepted a modification to a field declared neither " +
			"node-local nor partially scrubbed (#8612)")
	}

	// VIOLATION 3: the fixture does not set the declared mask bits, so the
	// assertion would be vacuous. The census must say so rather than pass.
	vacuous := synthScrubRow{LogFlags: 0xff, Meta: 0xf0, Gen: 7}
	if v := synthCensus(vacuous, synthScrubRow{LogFlags: 0xff, Meta: 0xf0, Gen: 0},
		nodeLocal, partial, conditional); len(v) == 0 {
		t.Error("the census passed on a fixture that never set the declared mask " +
			"bits — a vacuous partial-scrub assertion must be reported (#8612)")
	}
}

// The conditional arm gets the same treatment, and for the same reason: today
// it has exactly one real declaration, so a fixture-shaped hole in it would be
// invisible.
func TestScrubCensusConditionalArmCanActuallyFail8612(t *testing.T) {
	// `Meta` is a genuine node-local field here purely so the fixture always
	// zeroes SOMETHING: the census's own degeneracy guard fires on a scrub that
	// zeroed nothing, and it is right to — without it every arm below would pass
	// vacuously. Discovered by that guard firing on the first draft of this cell.
	nodeLocal := map[string]bool{"Meta": true}
	partial := map[string]uint64{}
	conditional := map[string]uint64{"Gen": 0x40}

	// Gate SET -> the value must survive.
	setBefore := synthScrubRow{LogFlags: 0x40, Meta: 3, Gen: 9}
	if v := synthCensus(setBefore, synthScrubRow{LogFlags: 0x40, Meta: 0, Gen: 9},
		nodeLocal, partial, conditional); len(v) != 0 {
		t.Fatalf("preserving a gated value was reported as a violation: %v", v)
	}
	if v := synthCensus(setBefore, synthScrubRow{LogFlags: 0x40, Meta: 0, Gen: 0},
		nodeLocal, partial, conditional); len(v) == 0 {
		t.Error("the census accepted ZEROING a field whose gate bit was SET — that " +
			"is the #8612 erasure itself, and the conditional arm must catch it")
	}

	// Gate CLEAR -> the value must be zeroed.
	clearBefore := synthScrubRow{LogFlags: 0x00, Meta: 3, Gen: 9}
	if v := synthCensus(clearBefore, synthScrubRow{LogFlags: 0x00, Meta: 0, Gen: 0},
		nodeLocal, partial, conditional); len(v) != 0 {
		t.Fatalf("zeroing an ungated value was reported as a violation: %v", v)
	}
	if v := synthCensus(clearBefore, synthScrubRow{LogFlags: 0x00, Meta: 0, Gen: 9},
		nodeLocal, partial, conditional); len(v) == 0 {
		t.Error("the census accepted PRESERVING a field whose gate bit was CLEAR — " +
			"in that state it is a node-local FIB generation and must not reach a " +
			"peer row (#7097)")
	}
}
