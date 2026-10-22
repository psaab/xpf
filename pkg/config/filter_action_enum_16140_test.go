package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// #16140: FirewallFilterTerm.Action / TerminalActions are the
// string-underlying FilterAction enum {Unset, Accept, Reject, Discard};
// NextTerm stays bool. This file pins the three decisive properties:
//
//  1. G1 marshal-diff: the typed fields marshal to exactly the
//     pre-change JSON tokens, so the snapshot wire bytes do not move
//     (the #8892 golden regen is reflection-only; see the v66 STANDS
//     ledger entry in snapshot_shape_version_8892_test.go).
//  2. The compiler only ever writes the typed constants (or Unset),
//     across every authored terminal and both spellings.
//  3. NextTerm coexists with a terminal as independent evidence: the
//     strict gate still sees NextTerm && terminal != "" (#5142/#9140),
//     i.e. folding NextTerm into the enum would have lost the conflict.
//
// FAIL-ON-REVERT: change FilterAction's underlying values (or revert
// Action to plain string and write a raw token) and
// TestFilterActionEnumMarshalDiff16140 /
// TestFilterActionEnumCompilerWritesOnlyConstants16140 go RED.

func TestFilterActionEnumMarshalDiff16140(t *testing.T) {
	// Pre-change (string-typed) marshal bytes, captured on origin/master
	// 974028945c for the same logical terms. The typed form must produce
	// byte-identical Action/TerminalActions tokens.
	cases := []struct {
		name string
		term *FirewallFilterTerm
		want string // the exact Action/TerminalActions fragment
	}{
		{"accept", &FirewallFilterTerm{Name: "t1", Action: FilterActionAccept, TerminalActions: []FilterAction{FilterActionAccept}},
			`"Action":"accept","TerminalActions":["accept"]`},
		{"discard", &FirewallFilterTerm{Name: "t2", Action: FilterActionDiscard, TerminalActions: []FilterAction{FilterActionDiscard}},
			`"Action":"discard","TerminalActions":["discard"]`},
		{"reject", &FirewallFilterTerm{Name: "t3", Action: FilterActionReject, TerminalActions: []FilterAction{FilterActionReject}},
			`"Action":"reject","TerminalActions":["reject"]`},
		{"unset-next-term", &FirewallFilterTerm{Name: "t4", NextTerm: true},
			`"Action":"","TerminalActions":null`},
		{"conflict-order", &FirewallFilterTerm{Name: "t5", Action: FilterActionDiscard, TerminalActions: []FilterAction{FilterActionAccept, FilterActionDiscard}},
			`"Action":"discard","TerminalActions":["accept","discard"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.term)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(got), tc.want) {
				t.Fatalf("marshal-diff vs pre-change bytes:\n got %s\nwant fragment %s", got, tc.want)
			}
			// Round-trip: a pre-change (plain-string) payload must decode
			// to the typed constants, so stored configs / peer sync in
			// the old spelling load identically.
			var back FirewallFilterTerm
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back.Action != tc.term.Action || !reflect.DeepEqual(back.TerminalActions, tc.term.TerminalActions) {
				t.Fatalf("round-trip = {%q %v}, want {%q %v}", back.Action, back.TerminalActions, tc.term.Action, tc.term.TerminalActions)
			}
			if back.NextTerm != tc.term.NextTerm {
				t.Fatalf("NextTerm round-trip = %v, want %v (NextTerm stays bool)", back.NextTerm, tc.term.NextTerm)
			}
		})
	}
	// The zero value is Unset and is the empty token.
	if FilterActionUnset != "" || FilterActionAccept != "accept" || FilterActionReject != "reject" || FilterActionDiscard != "discard" {
		t.Fatalf("enum tokens moved: unset=%q accept=%q reject=%q discard=%q",
			FilterActionUnset, FilterActionAccept, FilterActionReject, FilterActionDiscard)
	}
	// Type-level pin: Action/TerminalActions are the enum, NextTerm bool.
	termType := reflect.TypeOf(FirewallFilterTerm{})
	if f, _ := termType.FieldByName("Action"); f.Type != reflect.TypeOf(FilterAction("")) {
		t.Fatalf("Action type = %s, want config FilterAction", f.Type)
	}
	if f, _ := termType.FieldByName("TerminalActions"); f.Type != reflect.TypeOf([]FilterAction{}) {
		t.Fatalf("TerminalActions type = %s, want []FilterAction", f.Type)
	}
	if f, _ := termType.FieldByName("NextTerm"); f.Type.Kind() != reflect.Bool {
		t.Fatalf("NextTerm type = %s, want bool (must not fold into the enum)", f.Type)
	}
}

func TestFilterActionEnumCompilerWritesOnlyConstants16140(t *testing.T) {
	for _, tc := range []struct {
		then string
		want FilterAction
	}{
		{"accept", FilterActionAccept},
		{"reject", FilterActionReject},
		{"discard", FilterActionDiscard},
		{"next term", FilterActionUnset},
		{"count c1", FilterActionUnset},
	} {
		t.Run(tc.then, func(t *testing.T) {
			tree := flatTreeFromSets(t, filterWithThen(tc.then)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.then, err)
			}
			term := cfg.Firewall.FiltersInet["f1"].Terms[0]
			if term.Action != tc.want {
				t.Fatalf("then %q compiled Action=%q, want %q", tc.then, term.Action, tc.want)
			}
			for _, a := range term.TerminalActions {
				if a != FilterActionAccept && a != FilterActionReject && a != FilterActionDiscard {
					t.Fatalf("then %q wrote non-enum TerminalActions entry %q", tc.then, a)
				}
			}
			if tc.want != FilterActionUnset {
				if len(term.TerminalActions) != 1 || term.TerminalActions[0] != tc.want {
					t.Fatalf("then %q TerminalActions=%v, want [%q]", tc.then, term.TerminalActions, tc.want)
				}
			}
			// NextTerm is set only by the explicit fall-through spelling.
			if wantNext := tc.then == "next term"; term.NextTerm != wantNext {
				t.Fatalf("then %q NextTerm=%v, want %v", tc.then, term.NextTerm, wantNext)
			}
		})
	}
	// Unknown action fails closed to the typed discard on the lenient path.
	tree := flatTreeFromSets(t, filterWithThen("frobnicate")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if got := cfg.Firewall.FiltersInet["f1"].Terms[0].Action; got != FilterActionDiscard {
		t.Fatalf("unknown action lenient Action=%q, want FilterActionDiscard", got)
	}
}

func TestFilterActionEnumNextTermConflictPreserved16140(t *testing.T) {
	// Co-authored terminal + next-term must still be rejected by the
	// strict gate: NextTerm (bool) and the terminal (enum) are
	// independent evidence. Folding NextTerm into the enum would make
	// this shape unrepresentable and the gate blind.
	tree := flatTreeFromSets(t,
		"set firewall family inet filter f1 term t1 from protocol tcp",
		"set firewall family inet filter f1 term t1 then discard",
		"set firewall family inet filter f1 term t1 then next term",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("discard + next term must still reject at commit (NextTerm && terminal evidence lost)")
	} else if !strings.Contains(err.Error(), "next term") {
		t.Fatalf("conflict error must name next term, got %v", err)
	}
	// The lenient path keeps both pieces of evidence on the term.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	term := cfg.Firewall.FiltersInet["f1"].Terms[0]
	if !term.NextTerm || term.Action == FilterActionUnset {
		t.Fatalf("lenient term lost conflict evidence: NextTerm=%v Action=%q", term.NextTerm, term.Action)
	}
}
