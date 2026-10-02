package routing

import (
	"errors"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

type fakeRuleOps7422 struct {
	v4, v6 []netlink.Rule
	errV4  error
	errV6  error
}

func (f fakeRuleOps7422) RuleAdd(*netlink.Rule) error { return nil }
func (f fakeRuleOps7422) RuleDel(*netlink.Rule) error { return nil }
func (f fakeRuleOps7422) RuleAddDSCP(*netlink.Rule, uint8) error {
	return nil
}
func (f fakeRuleOps7422) RuleList(family int) ([]netlink.Rule, error) {
	if family == syscall.AF_INET {
		return f.v4, f.errV4
	}
	return f.v6, f.errV6
}

func rule7422(prio int) netlink.Rule { return netlink.Rule{Priority: prio} }

// #7422/#11440: the applied gauge reports PBR-band occupancy only. Structural
// mismatches are counted separately against desired rules by
// PBRAppliedStatus; occupancy still counts an in-band even slot without
// claiming its table or match fields are correct.
func TestPBRAppliedStatusBandAndValidity7422(t *testing.T) {
	base := config.PBRRulePriorityBase
	top := base + config.PBRRuleWindow

	for _, tc := range []struct {
		name  string
		ops   ruleOps
		want  int
		wantK bool
	}{
		{"empty kernel", fakeRuleOps7422{}, 0, true},
		{"one lookup at the band base", fakeRuleOps7422{v4: []netlink.Rule{rule7422(base)}}, 1, true},
		{"last lookup inside the band", fakeRuleOps7422{v4: []netlink.Rule{rule7422(top - 2)}}, 1, true},
		{"last shadow inside the band is excluded", fakeRuleOps7422{v4: []netlink.Rule{rule7422(top - 1)}}, 0, true},
		{"unreachable shadow is not counted as steering", fakeRuleOps7422{v4: []netlink.Rule{rule7422(base + 1)}}, 0, true},
		// The edges. Both are the off-by-one that would miscount.
		{"one below the band is NOT ours", fakeRuleOps7422{v4: []netlink.Rule{rule7422(base - 1)}}, 0, true},
		{"the first priority above the band is NOT ours", fakeRuleOps7422{v4: []netlink.Rule{rule7422(top)}}, 0, true},
		// The neighbours that actually exist on a live box, so "count by band"
		// is shown to exclude them rather than merely asserted to.
		{"kernel main/default, leak rules, and legacy PBR are not ours",
			fakeRuleOps7422{v4: []netlink.Rule{
				rule7422(0), rule7422(config.NextTableRulePriorityBase),
				rule7422(config.PBRRulePriorityBase - 1), rule7422(config.LegacyPBRRulePriorityBase),
				rule7422(30000), rule7422(33000), rule7422(32766), rule7422(32767),
			}}, 0, true},
		{"both families count lookup slots, not shadows",
			fakeRuleOps7422{
				v4: []netlink.Rule{rule7422(base), rule7422(base + 1)},
				v6: []netlink.Rule{rule7422(base + 2), rule7422(base + 3)},
			}, 2, true},

		// Validity. A failed read must not be reported as a count.
		{"v4 read failure invalidates", fakeRuleOps7422{errV4: errors.New("boom")}, 0, false},
		{"v6 read failure invalidates even when v4 succeeded",
			fakeRuleOps7422{v4: []netlink.Rule{rule7422(base)}, errV6: errors.New("boom")}, 0, false},
		{"nil ops invalidates", nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, ok := PBRAppliedStatus(tc.ops, nil)
			if ok != tc.wantK {
				t.Fatalf("validity = %v, want %v", ok, tc.wantK)
			}
			if ok && got != tc.want {
				t.Fatalf("count = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPBRAppliedStatusDetectsWrongTableInBand11440(t *testing.T) {
	base := config.PBRRulePriorityBase
	desired := []PBRRule{{
		Family:  syscall.AF_INET,
		TableID: 100,
		IifName: "eth0",
		Src:     "192.0.2.0/24",
		Dst:     "198.51.100.8/32",
		IPProto: 6,
		Sport:   &PBRPortRange{Lo: 1000, Hi: 2000},
		Dport:   &PBRPortRange{Lo: 443, Hi: 443},
	}}
	expected, valid := pbrExpectedLookupRule(desired[0], base)
	if !valid {
		t.Fatal("fixture rule must materialize")
	}

	occupancy, mismatched, ok := PBRAppliedStatus(
		fakeRuleOps7422{v4: []netlink.Rule{expected}},
		desired,
	)
	if !ok || occupancy != 1 || mismatched != 0 {
		t.Fatalf("matching rule: occupancy=%d mismatched=%d ok=%v, want 1/0/true",
			occupancy, mismatched, ok)
	}

	wrongTable := expected
	wrongTable.Table++
	occupancy, mismatched, ok = PBRAppliedStatus(
		fakeRuleOps7422{v4: []netlink.Rule{wrongTable}},
		desired,
	)
	if !ok || occupancy != 1 || mismatched != 1 {
		t.Fatalf("wrong-table in-band rule: occupancy=%d mismatched=%d ok=%v, want 1/1/true",
			occupancy, mismatched, ok)
	}
	wrongMatch := expected
	wrongMatch.IifName = "eth1"
	occupancy, mismatched, ok = PBRAppliedStatus(
		fakeRuleOps7422{v4: []netlink.Rule{wrongMatch}},
		desired,
	)
	if !ok || occupancy != 1 || mismatched != 1 {
		t.Fatalf("wrong-match in-band rule: occupancy=%d mismatched=%d ok=%v, want 1/1/true",
			occupancy, mismatched, ok)
	}
	duplicate := []netlink.Rule{expected, expected}
	occupancy, mismatched, ok = PBRAppliedStatus(
		fakeRuleOps7422{v4: duplicate},
		desired,
	)
	if !ok || occupancy != 2 || mismatched != 1 {
		t.Fatalf("duplicate in-band rule: occupancy=%d mismatched=%d ok=%v, want 2/1/true",
			occupancy, mismatched, ok)
	}

	unexpectedPriority := expected
	unexpectedPriority.Priority += 2
	occupancy, mismatched, ok = PBRAppliedStatus(
		fakeRuleOps7422{v4: []netlink.Rule{unexpectedPriority}},
		desired,
	)
	if !ok || occupancy != 1 || mismatched != 2 {
		t.Fatalf("unexpected in-band rule: occupancy=%d mismatched=%d ok=%v, want 1/2/true",
			occupancy, mismatched, ok)
	}

	occupancy, mismatched, ok = PBRAppliedStatus(fakeRuleOps7422{}, desired)
	if !ok || occupancy != 0 || mismatched != 1 {
		t.Fatalf("missing desired rule: occupancy=%d mismatched=%d ok=%v, want 0/1/true",
			occupancy, mismatched, ok)
	}
}

// A PARTIAL read must not publish a partial truth. This is the row that would
// pass if the family loop returned early with whatever it had — the metric
// would silently halve during an IPv6 hiccup, which is worse than an absent
// series because it looks like a real regression.
func TestPBRAppliedStatusRefusesAPartialRead7422(t *testing.T) {
	base := config.PBRRulePriorityBase
	ops := fakeRuleOps7422{
		v4:    []netlink.Rule{rule7422(base), rule7422(base + 1)},
		errV6: errors.New("v6 unavailable"),
	}
	got, _, ok := PBRAppliedStatus(ops, nil)
	if ok {
		t.Fatalf("a failed v6 read must invalidate the whole count, got %d with ok=true", got)
	}
}
