package config

import (
	"fmt"
	"testing"
)

// #9153: a firewall-filter `then` clause written on ONE set line lost actions
// past the second, and when the lost one was the TERMINATING action the term
// fell through — a fail-open on a clean commit with zero warnings.
//
//	set ... term t1 then count c1 log discard
//	  -> action=""  count="c1"  log=true      the `discard` is GONE
//
// The tree explains it: SetPath builds the #8939 flat chain, and the last link
// carries a packed RUN on one node's Keys —
//
//	then > [count c1] > [log discard]
//
// flattenThenChain8939 hoists each nested node out of the chain but a node whose
// Keys are `[log discard]` is still ONE node, and compileFilterThen reads its
// first key and drops the rest. So the chain fix was necessary and not
// sufficient: hoisting moved the run without splitting it.
//
// EVERY CASE IS ASSERTED AGAINST THE SAME ACTIONS WRITTEN AS SEPARATE LINES,
// not against a hand-written expectation. That is what makes the cell resistant
// to being "fixed" by a levelling-down: a compiler that dropped the actions in
// both spellings would fail the reference check below, which requires the split
// form to actually produce the terminating action.
func TestFilterThenPackedRunKeepsEveryAction9153(t *testing.T) {
	const base = "set firewall family inet filter F term t1 "
	policer := []string{
		"set firewall policer p1 if-exceeding bandwidth-limit 1000000",
		"set firewall policer p1 if-exceeding burst-size-limit 15000",
		"set firewall policer p1 then discard",
	}

	compile := func(t *testing.T, lines []string) *FirewallFilterTerm {
		t.Helper()
		tr := &ConfigTree{}
		for _, l := range lines {
			p, err := ParseSetCommand(l)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", l, err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", l, err)
			}
		}
		c, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		f := c.Firewall.FiltersInet["F"]
		if f == nil || len(f.Terms) == 0 {
			t.Fatal("no term compiled")
		}
		return f.Terms[0]
	}
	render := func(tm *FirewallFilterTerm) string {
		return fmt.Sprintf("action=%q count=%q log=%v dscp=%q policer=%q",
			tm.Action, tm.Count, tm.Log, tm.DSCPRewrite, tm.Policer)
	}

	for _, tc := range []struct {
		name    string
		prereq  []string
		packed  string
		split   []string
		wantAct FilterAction // the terminating action the SPLIT form must produce
	}{
		{
			name:    "two actions",
			packed:  base + "then count c1 discard",
			split:   []string{base + "then count c1", base + "then discard"},
			wantAct: FilterActionDiscard,
		},
		{
			// THE FAIL-OPEN. Three actions, and the one lost is the terminator.
			name:    "three actions, terminator last",
			packed:  base + "then count c1 log discard",
			split:   []string{base + "then count c1", base + "then log", base + "then discard"},
			wantAct: FilterActionDiscard,
		},
		{
			// Order matters: with the terminator FIRST a modifier was lost
			// instead, which is quieter and still wrong.
			name:    "three actions, terminator first",
			packed:  base + "then discard log count c1",
			split:   []string{base + "then discard", base + "then log", base + "then count c1"},
			wantAct: FilterActionDiscard,
		},
		{
			// Four actions, two of them argument-bearing. This is the row that
			// needs #9124's arity fix underneath: `count c1` must not be cut at
			// its VALUE.
			name:   "four actions, two argument-bearing",
			prereq: policer,
			packed: base + "then count c1 dscp af11 policer p1",
			split:  []string{base + "then count c1", base + "then dscp af11", base + "then policer p1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			split := compile(t, append(append([]string{}, tc.prereq...), tc.split...))
			// REFERENCE ARM. If the split form does not produce the terminating
			// action, the comparison below is between two broken results.
			if tc.wantAct != FilterActionUnset && split.Action != tc.wantAct {
				t.Fatalf("the SPLIT control produced action=%q, want %q — the comparison "+
					"below would be against a broken reference", split.Action, tc.wantAct)
			}
			packed := compile(t, append(append([]string{}, tc.prereq...), tc.packed))
			if got, want := render(packed), render(split); got != want {
				t.Errorf("the packed spelling does not match the split one (#9153):\n"+
					"  packed %s\n  split  %s\n  line: %s", got, want, tc.packed)
			}
		})
	}
}
