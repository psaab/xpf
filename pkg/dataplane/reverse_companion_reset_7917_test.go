package dataplane

import (
	"reflect"
	"testing"
)

// #7917: the reverse companion must not inherit the FORWARD direction's ingress
// identity.
//
// `mirrorSessionPairV4`/`V6` used to synthesize a reverse companion by copying
// the forward value, swapping the zones, and clearing the cached FIB result. They
// did not clear the #4983 ingress identity, so the companion carried the forward
// direction's ingress binding — a value `pkg/dataplane/types.go` names as a
// legitimate-`0` population, because a prediction of where the reply will arrive
// is not an observation of where it did and routing may be asymmetric.
//
// #8015 deleted those Go-side companion builders; the helper's
// `synthesized_synced_reverse_entry` is the only companion builder left and it
// applies the same rule (pinned by
// `synthesized_synced_reverse_entry_carries_no_ingress_identity_7917`). These
// cells outlive that deletion on purpose: they pin the RULE and its divergence
// from `ScrubNodeLocal`, which is what stops a future node-local field from
// silently becoming a companion reset — see the note in
// `session_reverse_companion.go`.
//
// These tests use the same census shape as the #7097 scrub guard (fill every
// field with a sentinel, compare the zeroed set against a declared set in BOTH
// directions), and add the one thing that change did not need: a pin that this
// reset and `ScrubNodeLocal` stay DIFFERENT rules.

// companionResetFields are the fields a reverse companion must not inherit.
var companionResetFields = map[string]bool{
	// Forward egress — the reply's egress is a separate lookup.
	"FibIfindex": true,
	"FibVlanID":  true,
	"FibDmac":    true,
	"FibSmac":    true,
	// Forward ingress — unobserved for the reply, in all three spellings.
	"IngressIfindex":   true,
	"IngressVlanID":    true,
	"IngressIfaceFold": true,
	// #9752: the installing-table identity is the forward steer outcome;
	// companions resolve unstamped (R1).
	"InstallTableDomain": true,
	"InstallTableCheck":  true,
}

// conditionallyUnobservedCompanionFields mirrors
// `conditionallyNodeLocalSessionFields` (#8612): fields the reset clears only
// while a LogFlags bit is CLEAR, and must leave untouched while it is SET.
//
// `FibGen` moved here from the list above in #8597 K74, and the move is the
// interesting part of that row. #8612 established that under
// LogFlagUserspaceTunnelEndpoint the field is not a FIB generation at all but a
// `config.StableTunnelEndpointID` — an FNV-1a fold of the interface NAME that
// pkg/config/tunnelid.go documents as crossing the cluster in this exact field,
// identical on both nodes by construction. A name-derived identity is not an
// OBSERVATION, so "the reverse direction has not observed this yet" does not
// reach it.
//
// #8612 corrected `ScrubNodeLocal` and did NOT correct this reset, because
// since #8015 the reset had no callers and nothing could make the staleness
// observable. K74 added the first callers back, at the two `PutClusterSynced*`
// explicit-reverse sites — and FibGen, unlike IngressIfaceFold, IS carried in
// the on-map ABI (`bpf_session_value.go`), so wiring the reset as the finding
// literally prescribed would have zeroed a live tunnel endpoint id on every
// peer-installed reverse companion of a tunnelled session.
var conditionallyUnobservedCompanionFields = map[string]uint64{
	"FibGen": uint64(LogFlagUserspaceTunnelEndpoint),
}

func assertCompanionCensus(t *testing.T, before, after reflect.Value) {
	t.Helper()
	reset := zeroedFields(before, after)
	if len(reset) == 0 {
		t.Fatal("the companion reset cleared NOTHING — the fixture or the call did " +
			"not run, and the two directional checks below would both pass vacuously")
	}
	for name := range companionResetFields {
		if _, conditional := conditionallyUnobservedCompanionFields[name]; conditional {
			t.Errorf("%s is declared BOTH unconditionally and conditionally "+
				"unobserved; the two lists must not overlap or the directional "+
				"checks below contradict each other (#8597 K74)", name)
			continue
		}
		if !reset[name] {
			t.Errorf("%s records something the REVERSE direction has not observed, "+
				"but the companion inherited it from the forward session. That is a "+
				"confident value on an unobserved binding, which is the failure mode "+
				"`0` exists to avoid (#7917)", name)
		}
	}
	for name := range reset {
		if _, conditional := conditionallyUnobservedCompanionFields[name]; conditional {
			// Judged by the flag-state cells below, not here: in this fixture
			// the bit may be either way, so neither "cleared" nor "survived"
			// is a violation on its own.
			continue
		}
		if !companionResetFields[name] {
			t.Errorf("the companion reset clears %s, which is not declared unobserved. "+
				"Either it is and this list is stale, or the reset is destroying a "+
				"field the companion legitimately carries — the forward row's counters "+
				"and zones are deliberately NOT reset here (#7917)", name)
		}
	}
}

func TestReverseCompanionResetCoversExactlyTheUnobservedFields7917(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)
		val.ResetUnobservedForReverseCompanion()
		assertCompanionCensus(t, before, reflect.ValueOf(val))
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		before := reflect.ValueOf(val)
		val.ResetUnobservedForReverseCompanion()
		assertCompanionCensus(t, before, reflect.ValueOf(val))
	})
}

// The divergence pin. The tempting simplification is to make the companion call
// `ScrubNodeLocal` — it clears most of the same fields. This asserts why that is
// wrong, in a form that fails if someone does it.
//
// The two rules answer different questions:
//
//	ScrubNodeLocal                    "does this value belong to another NODE?"
//	ResetUnobservedForReverseCompanion "has this DIRECTION observed this yet?"
//
// `IngressIfaceFold` is where they visibly part company, and it is not a
// hypothetical: #7095 added it as a CLUSTER-STABLE fold whose whole purpose is
// to cross the wire, so the node-local scrub must leave it alone — while the
// companion must clear it, because the wire request derives its ingress identity
// from the fold and would otherwise stamp the forward binding on the reply.
func TestCompanionResetAndNodeLocalScrubAreDifferentRules7917(t *testing.T) {
	if !companionResetFields["IngressIfaceFold"] {
		t.Fatal("the companion reset must clear IngressIfaceFold: the helper wire " +
			"request derives its ingress identity from the fold, so a companion that " +
			"keeps it stamps the FORWARD direction's binding on the reply (#7917)")
	}
	if nodeLocalSessionFields["IngressIfaceFold"] {
		t.Fatal("ScrubNodeLocal must NOT clear IngressIfaceFold: it is the #7095 " +
			"CLUSTER-STABLE fold, and zeroing it on a peer install is what it exists " +
			"to prevent — the #4983 identity would stop surviving a failover (#7917)")
	}
	if reflect.DeepEqual(companionResetFields, nodeLocalSessionFields) {
		t.Fatal("the reverse-companion reset and the node-local scrub now cover the " +
			"same fields. They are different rules — 'belongs to another node' and " +
			"'this direction has not observed it' — and collapsing them makes every " +
			"future node-local field a companion reset and vice versa, neither of " +
			"which follows (#7917)")
	}

	// Anti-vacuity: the check above is only meaningful while both sets are
	// non-empty and actually overlap. Two unrelated sets would satisfy
	// !DeepEqual for the wrong reason.
	var shared int
	for name := range companionResetFields {
		if nodeLocalSessionFields[name] {
			shared++
		}
	}
	if shared == 0 {
		t.Fatal("the two sets no longer overlap at all, so the divergence assertion " +
			"above proves nothing about them being confusable — re-read whether " +
			"either list is still describing what this test thinks it describes")
	}

	// #8597 K74. The two rules now AGREE about FibGen, and that agreement is
	// not a collapse of the divergence above — they still part company on
	// IngressIfaceFold, which is the field the divergence was always about.
	// They agree here because #8612's argument is about what the VALUE IS (a
	// name-derived identity, not a measurement), which is upstream of both
	// questions: a value that is not an observation is neither node-local nor
	// unobserved. If a future change makes one of them conditional on a
	// different bit than the other, that is a real divergence and this fires.
	if !reflect.DeepEqual(conditionallyUnobservedCompanionFields, conditionallyNodeLocalSessionFields) {
		t.Errorf("the conditional lists disagree:\ncompanion=%v\nscrub=%v\n"+
			"Both encode #8612's single fact — LogFlagUserspaceTunnelEndpoint says "+
			"FibGen holds a cluster-stable tunnel endpoint id rather than a "+
			"node-local FIB generation. One list learning a bit the other has not "+
			"is how this went wrong the first time (#8597 K74)",
			conditionallyUnobservedCompanionFields, conditionallyNodeLocalSessionFields)
	}
}

// The arm the K74 correction is FOR, asserted in field terms rather than only
// through the reflective census — the same shape as
// TestScrubPreservesTheTunnelEndpointIdentity8612 one file over.
func TestCompanionResetPreservesTheTunnelEndpointIdentity_8597(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		val.LogFlags |= LogFlagUserspaceTunnelEndpoint
		wantGen, wantFlags := val.FibGen, val.LogFlags
		if wantGen == 0 {
			t.Fatal("fixture must seed a non-zero FibGen or this cell is vacuous")
		}
		val.ResetUnobservedForReverseCompanion()
		if val.FibGen != wantGen {
			t.Errorf("the companion reset cleared the tunnel endpoint id to %#x, want "+
				"%#x preserved. Under LogFlagUserspaceTunnelEndpoint the field is a "+
				"StableTunnelEndpointID folded from the interface NAME, identical on "+
				"both nodes and in both directions — config, not an observation the "+
				"reply direction is missing (#8612 via #8597 K74)", val.FibGen, wantGen)
		}
		if val.LogFlags != wantFlags {
			t.Errorf("LogFlags changed to %#x, want %#x — the reset must not edit the "+
				"flag that describes a value it preserved (#8612)", val.LogFlags, wantFlags)
		}
		// The unconditional half must still happen, or "preserved" would just
		// mean the reset did nothing.
		if val.FibIfindex != 0 || val.IngressIfaceFold != 0 {
			t.Errorf("FibIfindex=%d IngressIfaceFold=%d — both must still be cleared; "+
				"a cell that only checks the preserved field passes a reset that was "+
				"deleted outright (#7917)", val.FibIfindex, val.IngressIfaceFold)
		}
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		val.LogFlags |= LogFlagUserspaceTunnelEndpoint
		wantGen := val.FibGen
		val.ResetUnobservedForReverseCompanion()
		if val.FibGen != wantGen {
			t.Errorf("v6 companion reset cleared the tunnel endpoint id to %#x, want "+
				"%#x (#8597 K74)", val.FibGen, wantGen)
		}
		if val.FibIfindex != 0 || val.IngressIfaceFold != 0 {
			t.Errorf("v6: FibIfindex=%d IngressIfaceFold=%d must still be cleared",
				val.FibIfindex, val.IngressIfaceFold)
		}
	})
}

// The other arm. Without this, the reset could stop clearing FibGen ALTOGETHER
// and the suite would stay green — a companion would then carry the forward
// direction's FIB generation, which is the #7917 defect the conditional was
// carved out of, not a fix to it.
func TestCompanionResetZeroesFibGenWhenTheTunnelBitIsClear_8597(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		var val SessionValue
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		val.LogFlags &^= LogFlagUserspaceTunnelEndpoint
		if val.FibGen == 0 {
			t.Fatal("fixture must seed a non-zero FibGen or this cell is vacuous")
		}
		val.ResetUnobservedForReverseCompanion()
		if val.FibGen != 0 {
			t.Errorf("FibGen survived as %#x with the tunnel bit CLEAR — in that "+
				"state it is the forward direction's FIB generation, which the reply "+
				"has not resolved (#7917)", val.FibGen)
		}
	})
	t.Run("v6", func(t *testing.T) {
		var val SessionValueV6
		fillNonZero(t, reflect.ValueOf(&val).Elem())
		val.LogFlags &^= LogFlagUserspaceTunnelEndpoint
		val.ResetUnobservedForReverseCompanion()
		if val.FibGen != 0 {
			t.Errorf("v6 FibGen survived as %#x with the tunnel bit CLEAR (#7917)",
				val.FibGen)
		}
	})
}
