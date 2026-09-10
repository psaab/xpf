package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9410 — the zone-resolution arm of the fail-closed policy-content mirror.
//
// These cells drive `collectPolicyZoneRejections` DIRECTLY, on hand-built
// snapshots, because that is the only way to reach the states the mirror exists
// for: the helper resolves against the ZONE SNAPSHOT, whose map drops a zone
// with id 0 or an id in the reserved range, and no config can be authored that
// produces those (`StableZoneID` folds into [1, MaxUsableZoneID]). A
// config-driven test can only ever exercise "the zone is absent from cfg", which
// is the case a config-side predicate would already have caught — see
// TestPolicyZoneRejectionReadsTheSnapshotNotTheConfig9410 for why that
// difference is the whole reason this mirror reads the snapshot.
//
// The end-to-end behaviour (`show security match-policies` refusing to fabricate
// a verdict) is asserted in pkg/policymatch.

func zones9410(pairs ...any) []ZoneSnapshot {
	var out []ZoneSnapshot
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, ZoneSnapshot{Name: pairs[i].(string), ID: uint16(pairs[i+1].(int))})
	}
	return out
}

func zonePairRule9410(name, from, to string) PolicyRuleSnapshot {
	return PolicyRuleSnapshot{RuleID: name, Name: name, FromZone: from, ToZone: to}
}

func globalRule9410(name string, fromScope, toScope []string) PolicyRuleSnapshot {
	return PolicyRuleSnapshot{
		RuleID: name, Name: name,
		FromZone: "junos-global", ToZone: "junos-global",
		MatchFromZones: fromScope, MatchToZones: toScope,
	}
}

// TestPolicyZoneRejectionCatchesEveryUnresolvablePath9410 walks each path on
// which the helper refuses the WHOLE snapshot.
//
// THE LOAD-BEARING ROWS ARE THE ACCEPTING ONES. A gate that reports a rejection
// for an unresolvable zone is satisfiable by reporting one for EVERYTHING, and
// that would make `show security match-policies` useless on every healthy
// config — a worse defect than the fabricated verdict being fixed, and the #4191
// over-rejection class. So every wildcard and every resolvable spelling is
// asserted to produce NO reason, in the same table.
func TestPolicyZoneRejectionCatchesEveryUnresolvablePath9410(t *testing.T) {
	zs := zones9410("trust", 10, "untrust", 20)
	for _, tc := range []struct {
		name     string
		rules    []PolicyRuleSnapshot
		wantZone string // "" => must produce NO reason
	}{
		// --- REJECTING ---
		{"zone-pair unresolvable from", []PolicyRuleSnapshot{zonePairRule9410("r", "ghost", "untrust")}, "ghost"},
		{"zone-pair unresolvable to", []PolicyRuleSnapshot{zonePairRule9410("r", "trust", "ghost")}, "ghost"},
		{"global scope unresolvable from", []PolicyRuleSnapshot{globalRule9410("g", []string{"ghost"}, nil)}, "ghost"},
		{"global scope unresolvable to", []PolicyRuleSnapshot{globalRule9410("g", nil, []string{"ghost"})}, "ghost"},
		{"global scope unresolvable BESIDE a resolvable sibling",
			[]PolicyRuleSnapshot{globalRule9410("g", []string{"trust", "ghost"}, nil)}, "ghost"},
		{
			// #6464: an empty element inside a NON-wildcard set is not the `any`
			// wildcard. build_global_zone_scope fails it closed explicitly rather
			// than relying on the map never holding an empty name, so the mirror
			// does too.
			"global scope with an EMPTY element",
			[]PolicyRuleSnapshot{globalRule9410("g", []string{"trust", ""}, nil)}, "",
		},

		// --- ACCEPTING (the over-rejection controls) ---
		{"zone-pair fully resolvable", []PolicyRuleSnapshot{zonePairRule9410("r", "trust", "untrust")}, ""},
		{"zone-pair from-any wildcard", []PolicyRuleSnapshot{zonePairRule9410("r", "any", "untrust")}, ""},
		{"zone-pair to-any wildcard", []PolicyRuleSnapshot{zonePairRule9410("r", "trust", "any")}, ""},
		{"zone-pair both-any wildcard", []PolicyRuleSnapshot{zonePairRule9410("r", "any", "any")}, ""},
		{"global unscoped (nil scope = Any)", []PolicyRuleSnapshot{globalRule9410("g", nil, nil)}, ""},
		{"global explicit any", []PolicyRuleSnapshot{globalRule9410("g", []string{"any"}, nil)}, ""},
		{"global any BESIDE a ghost (the whole set is the wildcard)",
			[]PolicyRuleSnapshot{globalRule9410("g", []string{"any", "ghost"}, nil)}, ""},
		{"global scope fully resolvable", []PolicyRuleSnapshot{globalRule9410("g", []string{"trust"}, []string{"untrust"})}, ""},
		{
			// #3019: the reserved self-traffic zone resolves by NAME and is never in
			// the snapshot map, so a mirror that only consulted the map would
			// reject every `to-zone junos-host` policy — i.e. every host-inbound
			// rule on the box.
			"zone-pair to junos-host", []PolicyRuleSnapshot{zonePairRule9410("r", "trust", "junos-host")}, "",
		},
		{"global scope naming junos-host", []PolicyRuleSnapshot{globalRule9410("g", nil, []string{"junos-host"})}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := collectPolicyZoneRejections(tc.rules, zs)
			if tc.wantZone == "" && tc.name == "global scope with an EMPTY element" {
				// the empty-element row rejects, but the offending token is ""
				if len(got) != 1 {
					t.Fatalf("#9410: an EMPTY scope element must be refused exactly as an "+
						"unresolvable name (#6464); got %d reasons %v", len(got), got)
				}
				return
			}
			if tc.wantZone == "" {
				if len(got) != 0 {
					t.Fatalf("#9410 OVER-REJECTION: a resolvable/wildcard rule produced %d "+
						"reason(s): %v\nThis arm gates every permit/deny verdict "+
						"`show security match-policies` reports, so a false rejection here "+
						"makes the command useless on a healthy config — worse than the "+
						"fabricated verdict it exists to prevent.", len(got), got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("#9410: want exactly 1 reason naming %q, got %d: %v", tc.wantZone, len(got), got)
			}
			if !strings.Contains(got[0], `"`+tc.wantZone+`"`) {
				t.Errorf("#9410: the reason does not name the offending zone %q, so an "+
					"operator is told the snapshot is bad without being pointed at the "+
					"token: %s", tc.wantZone, got[0])
			}
			if !strings.Contains(got[0], "WHOLE POLICY SNAPSHOT") {
				t.Errorf("#9410: the reason does not say the whole SNAPSHOT is refused. "+
					"Per-rule wording would imply the other policies still apply, which is "+
					"the opposite of what the helper does: %s", got[0])
			}
		})
	}
}

// TestPolicyZoneRejectionReadsTheSnapshotNotTheConfig9410 is the cell that
// justifies the whole design, and nothing else reaches it.
//
// The obvious implementation reuses the compiler's predicate over
// `cfg.Security.Zones`. That answers a DIFFERENT question: the helper resolves
// against `zone_name_to_id_from_snapshot`, which DROPS a zone whose id is 0, or
// whose name is empty, or whose id is at/above the reserved floor. For such a
// zone a config-side predicate says "defined, resolvable" while the helper
// cannot resolve it and refuses the snapshot — the simulator agreeing with the
// compiler while disagreeing with the dataplane, which is the SHAPE of #9410
// rather than its fix.
//
// These ids are unreachable from any authored config (StableZoneID folds into
// [1, MaxUsableZoneID]), which is exactly why the rows are hand-built: a
// config-driven fixture cannot tell the two implementations apart.
func TestPolicyZoneRejectionReadsTheSnapshotNotTheConfig9410(t *testing.T) {
	for _, tc := range []struct {
		name string
		zs   []ZoneSnapshot
	}{
		{"id 0 is unaddressable", []ZoneSnapshot{{Name: "trust", ID: 0}}},
		{"an empty name is unaddressable", []ZoneSnapshot{{Name: "", ID: 10}}},
		{"an id at the reserved floor collides with the sentinels",
			[]ZoneSnapshot{{Name: "trust", ID: config.ZoneIDReservedMin}}},
		{"an id above the reserved floor",
			[]ZoneSnapshot{{Name: "trust", ID: config.ZoneIDReservedMin + 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// POSITIVE CONTROL: the SAME zone name at an addressable id must produce
			// NO reason, or this row is just asserting that an absent zone is
			// rejected and says nothing about the snapshot/config difference.
			if got := collectPolicyZoneRejections(
				[]PolicyRuleSnapshot{zonePairRule9410("r", "trust", "any")},
				[]ZoneSnapshot{{Name: "trust", ID: 10}}); len(got) != 0 {
				t.Fatalf("POSITIVE CONTROL: an addressable zone was rejected: %v", got)
			}
			got := collectPolicyZoneRejections(
				[]PolicyRuleSnapshot{zonePairRule9410("r", "trust", "any")}, tc.zs)
			if len(got) != 1 {
				t.Fatalf("#9410: a zone the SNAPSHOT MAP drops (%s) must be reported as "+
					"unresolvable even though it is present in the snapshot list — the "+
					"helper's map applies the same three exclusions, and a config-side "+
					"predicate cannot see them. got %d reasons %v", tc.name, len(got), got)
			}
		})
	}
}

// TestPolicyZoneRejectionReportsFromBeforeTo9410 pins the reported SIDE on a
// rule whose BOTH sides are unresolvable.
//
// The helper's arms are ordered `(None, _)` before `(_, None)`, which is also
// the Go strict gate's order and is asserted on the Rust side by
// `unknown_zone_pair_fails_closed` ("from-zone is reported first (matches the Go
// strict-gate order)"). An operator comparing a simulator reason against a
// helper log must see the same zone named, so the order is copied rather than
// left to whichever branch happens to come first.
func TestPolicyZoneRejectionReportsFromBeforeTo9410(t *testing.T) {
	got := collectPolicyZoneRejections(
		[]PolicyRuleSnapshot{zonePairRule9410("r", "ghost-from", "ghost-to")},
		zones9410("trust", 10))
	if len(got) != 1 {
		t.Fatalf("want exactly one reason for a rule with both sides unresolvable, got %v", got)
	}
	if !strings.Contains(got[0], `"ghost-from"`) {
		t.Errorf("#9410: the FROM zone must be reported first, matching the helper's arm "+
			"order and its own assertion in unknown_zone_pair_fails_closed; got %s", got[0])
	}
	if strings.Contains(got[0], `"ghost-to"`) {
		t.Errorf("#9410: both sides were reported for one rule; the helper emits one "+
			"UnresolvableZoneReference and names the FROM zone: %s", got[0])
	}
}

// TestPolicyZoneRejectionEmptyElementClauseIsExercisable9410 makes the #6464
// empty-element clause KILLABLE instead of merely correct.
//
// The clause reads:
//
//	if name == "" { return true, name }
//
// and the Rust it mirrors says in its own comment why it is written explicitly:
// *"the map never holds an empty name, but that invariant belongs to
// `zone_name_to_id_from_snapshot` and must not be load-bearing here."* That is
// exactly right, and it is also why the clause SURVIVES its own mutation on an
// ordinary fixture: with the resolver's empty-name skip intact, an empty scope
// element fails to resolve through the map anyway, so removing the clause changes
// nothing and the cell above passes for a reason other than the clause under
// test.
//
// Measured: dropping the clause SURVIVES, and dropping it TOGETHER WITH the
// resolver's empty-name skip also survived — because no fixture put an
// empty-named zone in the snapshot for the skip to have skipped. This cell
// supplies exactly that snapshot, which is the only shape in which the two
// defences are distinguishable:
//
//	skip kept, clause kept      "" not in the map  -> REJECT (both agree)
//	skip kept, clause dropped   "" not in the map  -> REJECT (the skip carries it)
//	skip dropped, clause kept   "" IS in the map   -> REJECT (the clause carries it)
//	skip dropped, clause dropped "" IS in the map  -> ACCEPT, and this cell REDS
//
// So the clause is now defence against a state the tree can actually be in
// (a corrupt / hand-built / mixed-version-HA snapshot, which is the only way an
// empty-named zone reaches the wire), rather than a comment asserting it is
// needed.
func TestPolicyZoneRejectionEmptyElementClauseIsExercisable9410(t *testing.T) {
	// A snapshot carrying an EMPTY-NAMED zone. The resolver's skip drops it, so
	// the map has no "" key; without the skip it would.
	zs := []ZoneSnapshot{{Name: "trust", ID: 10}, {Name: "", ID: 30}}

	// POSITIVE CONTROL: a resolvable scope over this same snapshot must NOT be
	// rejected, or the assertion below is satisfied by a snapshot that rejects
	// everything and says nothing about the empty element.
	if got := collectPolicyZoneRejections(
		[]PolicyRuleSnapshot{globalRule9410("g", []string{"trust"}, nil)}, zs); len(got) != 0 {
		t.Fatalf("POSITIVE CONTROL: a resolvable scope was rejected over the empty-named-zone "+
			"snapshot: %v", got)
	}

	got := collectPolicyZoneRejections(
		[]PolicyRuleSnapshot{globalRule9410("g", []string{"trust", ""}, nil)}, zs)
	if len(got) != 1 {
		t.Fatalf("#9410/#6464: an EMPTY scope element must be refused even when the snapshot "+
			"carries an empty-named zone. Both the resolver's empty-name skip and the "+
			"explicit empty-element check must hold for this to fail closed; got %d reasons %v",
			len(got), got)
	}
}
