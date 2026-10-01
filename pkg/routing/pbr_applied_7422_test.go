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

// #7422 row 12: xpf_pbr_rules_applied counts PBR steering lookup rules, not
// their paired unreachable shadows, and reports whether readback SUCCEEDED.
//
// The lookup occupies the even priority in each pair because netlink v1.3.1
// does not expose a rule's fib-rule action on readback. Rows straddle the
// priority-band edges and both positions of a pair.
func TestPBRAppliedCountBandAndValidity7422(t *testing.T) {
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
			got, ok := PBRAppliedCount(tc.ops)
			if ok != tc.wantK {
				t.Fatalf("validity = %v, want %v", ok, tc.wantK)
			}
			if ok && got != tc.want {
				t.Fatalf("count = %d, want %d", got, tc.want)
			}
		})
	}
}

// A PARTIAL read must not publish a partial truth. This is the row that would
// pass if the family loop returned early with whatever it had — the metric
// would silently halve during an IPv6 hiccup, which is worse than an absent
// series because it looks like a real regression.
func TestPBRAppliedCountRefusesAPartialRead7422(t *testing.T) {
	base := config.PBRRulePriorityBase
	ops := fakeRuleOps7422{
		v4:    []netlink.Rule{rule7422(base), rule7422(base + 1)},
		errV6: errors.New("v6 unavailable"),
	}
	got, ok := PBRAppliedCount(ops)
	if ok {
		t.Fatalf("a failed v6 read must invalidate the whole count, got %d with ok=true", got)
	}
}
