package configstore

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// #8438: `interface-range` expansion was uncapped and superlinear — 32,000
// members took 142 s at commit with zero diagnostic, on the strict path AND
// the tolerant peer-sync / boot path.
//
// The cost is driven by the PRODUCT of members and shared statements, because
// each shared statement is replayed through ConfigTree.SetPath under each
// member and SetPath finds the member by a linear scan of the `interfaces`
// root, which by then holds every member. Measured before the fix:
//
//	members  shared  compile
//	  2,000     1     0.4 s
//	  4,096     1     1.4 s
//	  4,096     3    23.2 s
//	  4,096     6    77.9 s
//	  2,000    20   268   s
//
// That table is why this is not a member-count cap. A 4096-MEMBER limit — the
// number the sibling `member-range` guard already ships, and the obvious fix —
// admits every row: 4,096 members with six shared statements is a 78-second
// commit it waves straight through.

// rangeBody8438 builds one interface-range with `members` members (spelled as
// a `member` list, or as repeated `member-range` statements when useRange is
// set) and `shared` shared statements.
func rangeBody8438(members, shared int, useRange bool) string {
	var b strings.Builder
	b.WriteString("interfaces {\n    interface-range R {\n")
	if useRange {
		const per = 2000
		for k := 0; k*per < members; k++ {
			fmt.Fprintf(&b, "        member-range ge-0/%d/0 to ge-0/%d/%d;\n", k, k, per-1)
		}
	} else {
		for i := 0; i < members; i++ {
			fmt.Fprintf(&b, "        member ge-0/0/%d;\n", i)
		}
	}
	b.WriteString("        mtu 9000;\n")
	if shared > 1 {
		b.WriteString("        vlan-tagging;\n")
	}
	// #16723: shared statements after the first were untagged `unit <j>`
	// blocks, which the #15034 gate now rejects (non-zero unit without
	// vlan-id), and repeated `unit 0` blocks trip the #8427 duplicate
	// gate. The budget subject is members x shared STATEMENTS, so the
	// remaining shared statements are tagged units (vlan-id == unit
	// number) — same replay count, gate-compliant shape. The extra
	// vlan-tagging statement is emitted only when shared > 1, so the
	// at-budget row (shared=1, exactly 4096 applications) is unmoved.
	for j := 0; j < shared-1; j++ {
		fmt.Fprintf(&b, "        unit %d { vlan-id %d; family inet { address 10.%d.0.1/24; } }\n", j+1, j+1, j)
	}
	b.WriteString("    }\n}\n")
	return b.String()
}

// TestInterfaceRangeBudgetRejectsOversizedExpansion8438 is the fail-on-revert
// guard for the three shapes that were accepted before the budget existed.
//
// It also binds the HARM, not just the disposition: each case must finish well
// inside a bound that the pre-fix code could not meet (the fastest of these was
// 18.9 s, the slowest 268 s). The bound is deliberately loose — two orders of
// magnitude above the ~30 ms these now take — so it fails on a reverted budget
// rather than on a slow machine.
func TestInterfaceRangeBudgetRejectsOversizedExpansion8438(t *testing.T) {
	cases := []struct {
		name            string
		members, shared int
		useRange        bool
		wasSeconds      float64
	}{
		// The issue's headline: an uncapped `member` list.
		{"member-list-32k", 32000, 1, false, 142},
		// The SAME budget must be debited by the other spelling. The shipped
		// per-range `member-range` cap is 4096 PER STATEMENT, so eight 2,000-wide
		// ranges slipped 16,000 interfaces past it with zero warnings — the cap
		// was never a budget. A member-list-only fix leaves this row green.
		{"member-range-repetition-16k", 16000, 1, true, 18.9},
		// The row a member-COUNT cap cannot see: under any 4096-member limit,
		// yet a 78-second commit.
		{"under-member-cap-4096x6", 4096, 6, false, 77.9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			_, err := CheckText(rangeBody8438(tc.members, tc.shared, tc.useRange), 0)
			elapsed := time.Since(start)
			if err == nil {
				t.Fatalf("expected commit to reject an over-budget interface-range expansion "+
					"(%d members x %d shared statements; took %.0fs before the budget existed)",
					tc.members, tc.shared, tc.wasSeconds)
			}
			for _, want := range []string{"interface-range", "exceeds"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not contain %q", err.Error(), want)
				}
			}
			if elapsed > 15*time.Second {
				t.Fatalf("rejection took %s — the budget must be charged BEFORE the replay, "+
					"not after (this shape took %.0fs to expand before the fix)",
					elapsed.Round(time.Millisecond), tc.wasSeconds)
			}
		})
	}
}

// TestInterfaceRangeAtBudgetStillExpands8438 is the POSITIVE CONTROL, and it
// binds the result rather than the acceptance: a config exactly AT the limit
// must still commit AND must still produce all 4,096 expanded interfaces. A
// guard that rejected everything would satisfy every cell above and fail here.
func TestInterfaceRangeAtBudgetStillExpands8438(t *testing.T) {
	cfg, err := CheckText(rangeBody8438(4096, 1, false), 0)
	if err != nil {
		t.Fatalf("a config exactly at the expansion budget must still commit: %v", err)
	}
	if got := len(cfg.Interfaces.Interfaces); got != 4096 {
		t.Fatalf("expanded %d interfaces, want 4096 — the budget must not perturb an "+
			"accepted expansion", got)
	}
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/4095"]; ifc == nil || ifc.MTU != 8986 { // #16723/#16594: authored 9000 stored as effective 8986 (media MTU minus Ethernet header)
		t.Fatalf("the last member did not receive the range's shared config: %+v", ifc)
	}
}

// TestInterfaceRangeRealisticSizeUnaffected8438 is the anti-over-rejection
// guard at the size real configurations actually use. The largest
// interface-range anywhere in this tree, fixtures included, is 23 members, and
// no shipped .conf uses the construct at all — so this is roughly two orders of
// magnitude of headroom, and the budget is a safety valve rather than a policy
// anyone will meet.
func TestInterfaceRangeRealisticSizeUnaffected8438(t *testing.T) {
	cfg, err := CheckText(rangeBody8438(23, 10, false), 0)
	if err != nil {
		t.Fatalf("a realistic 23-member range with 10 shared statements must commit: %v", err)
	}
	if got := len(cfg.Interfaces.Interfaces); got != 23 {
		t.Fatalf("expanded %d interfaces, want 23", got)
	}
}

// TestInterfaceRangeBudgetLenientAtStoreIngress8438 is the #1960 no-brick half,
// bound at the STORE INGRESS rather than at the validator: Store.SyncApply must
// still accept a config an older binary persisted or a peer synced, downgrading
// the rejection to a warning.
//
// It also asserts the expansion is SKIPPED on that path, which is the point:
// warning and expanding anyway would leave the peer and every subsequent boot
// stalled for minutes to hours, since the harm IS the replay. Skipping matches
// what the shipped per-range `member-range` cap already does with an over-limit
// range.
func TestInterfaceRangeBudgetLenientAtStoreIngress8438(t *testing.T) {
	s := newTestStore(t)
	start := time.Now()
	compiled, err := s.SyncApply(rangeBody8438(32000, 1, false), nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("SyncApply must tolerate an over-budget peer-synced config: %v", err)
	}
	found := false
	for _, w := range compiled.Warnings {
		if strings.Contains(w, "interface-range") && strings.Contains(w, "exceeds") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded interface-range budget warning, got %d warnings: %v",
			len(compiled.Warnings), compiled.Warnings)
	}
	if got := len(compiled.Interfaces.Interfaces); got != 0 {
		t.Fatalf("tolerant path expanded %d interfaces — it must SKIP the expansion, "+
			"otherwise the boot it is meant to protect still stalls on the replay", got)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("tolerant path took %s — it must decline BEFORE the replay", elapsed.Round(time.Millisecond))
	}
}
