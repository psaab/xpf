package routing

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// stubRuleOps16174 drives clearMatchingRules directly: RuleList serves
// per-family fixtures (or an injected dump error) and RuleDel fails with
// delErr, if any. dels records the priorities actually attempted, in
// order, so the walk order of the shared skeleton is observable.
type stubRuleOps16174 struct {
	byFamily map[int][]netlink.Rule
	listErr  map[int]error
	delErr   error
	dels     []int
}

func (s *stubRuleOps16174) RuleAdd(*netlink.Rule) error { return nil }

func (s *stubRuleOps16174) RuleAddDSCP(*netlink.Rule, uint8) error { return nil }

func (s *stubRuleOps16174) RuleList(family int) ([]netlink.Rule, error) {
	if err := s.listErr[family]; err != nil {
		return nil, err
	}
	return s.byFamily[family], nil
}

func (s *stubRuleOps16174) RuleDel(r *netlink.Rule) error {
	s.dels = append(s.dels, r.Priority)
	return s.delErr
}

func skeletonRule16174(family, prio int) netlink.Rule {
	r := netlink.NewRule()
	r.Family = family
	r.Priority = prio
	return *r
}

// TestClearMatchingRulesSkeleton16174 is the #16174 decisive table over
// the shared clear skeleton, parameterised once instead of per manager:
// list-error aggregated (and the other family still walked), ENOENT
// delete swallowed, real delete errors aggregated in walk order, and
// non-matching rules never attempted. The per-manager clear() tests
// (TestRulesClearListErrorSurfaced, TestNextTableRibGroupClear*
// in rules_test.go) pin the same contract through each twin's own
// predicate and kind string; this test fails if the skeleton itself
// swallows, reorders, or mislabels a failure for any future caller.
func TestClearMatchingRulesSkeleton16174(t *testing.T) {
	listBoom := errors.New("dump boom")
	delBoom := errors.New("del boom")

	tests := []struct {
		name     string
		ops      *stubRuleOps16174
		match    func(netlink.Rule) bool
		wantErrs []error // nil = success; else errors.Is membership, in order
		wantText []string
		wantDels []int
	}{
		{
			name: "list error aggregated, other family still walked",
			ops: &stubRuleOps16174{
				byFamily: map[int][]netlink.Rule{
					unix.AF_INET6: {skeletonRule16174(unix.AF_INET6, 11)},
				},
				listErr: map[int]error{unix.AF_INET: listBoom},
			},
			match:    func(netlink.Rule) bool { return true },
			wantErrs: []error{listBoom},
			wantText: []string{"list test-kind rules family 2: dump boom"},
			wantDels: []int{11},
		},
		{
			name: "ENOENT delete swallowed",
			ops: &stubRuleOps16174{
				byFamily: map[int][]netlink.Rule{
					unix.AF_INET: {skeletonRule16174(unix.AF_INET, 7)},
				},
				delErr: unix.ENOENT,
			},
			match:    func(netlink.Rule) bool { return true },
			wantDels: []int{7},
		},
		{
			name: "real delete errors aggregated in walk order",
			ops: &stubRuleOps16174{
				byFamily: map[int][]netlink.Rule{
					unix.AF_INET: {
						skeletonRule16174(unix.AF_INET, 1),
						skeletonRule16174(unix.AF_INET, 2),
					},
					unix.AF_INET6: {skeletonRule16174(unix.AF_INET6, 3)},
				},
				delErr: delBoom,
			},
			match:    func(netlink.Rule) bool { return true },
			wantErrs: []error{delBoom, delBoom, delBoom},
			wantText: []string{
				"delete stale test-kind rule prio 1: del boom",
				"delete stale test-kind rule prio 2: del boom",
				"delete stale test-kind rule prio 3: del boom",
			},
			wantDels: []int{1, 2, 3},
		},
		{
			name: "list errors from both families keep family order",
			ops: &stubRuleOps16174{
				listErr: map[int]error{
					unix.AF_INET:  listBoom,
					unix.AF_INET6: listBoom,
				},
			},
			match:    func(netlink.Rule) bool { return true },
			wantErrs: []error{listBoom, listBoom},
			wantText: []string{
				"list test-kind rules family 2: dump boom",
				"list test-kind rules family 10: dump boom",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := clearMatchingRules(tc.ops, "test-kind", tc.match)
			if len(tc.wantErrs) == 0 {
				if err != nil {
					t.Fatalf("clearMatchingRules = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Fatalf("clearMatchingRules = nil, want joined %v", tc.wantErrs)
				}
				joined, ok := err.(interface{ Unwrap() []error })
				if !ok {
					t.Fatalf("clearMatchingRules error %T does not unwrap to a join: %v", err, err)
				}
				got := joined.Unwrap()
				if len(got) != len(tc.wantErrs) {
					t.Fatalf("joined errors = %v, want %d entries", got, len(tc.wantErrs))
				}
				for i, want := range tc.wantErrs {
					if !errors.Is(got[i], want) {
						t.Errorf("joined[%d] = %v, want wrapping %v", i, got[i], want)
					}
					if got[i].Error() != tc.wantText[i] {
						t.Errorf("joined[%d] text = %q, want %q", i, got[i].Error(), tc.wantText[i])
					}
				}
				// The joined rendering preserves walk order end to end.
				full := err.Error()
				last := -1
				for _, text := range tc.wantText {
					idx := strings.Index(full, text)
					if idx < 0 || idx < last {
						t.Fatalf("joined error %q does not contain %q in order", full, text)
					}
					last = idx
				}
			}
			if fmt.Sprint(tc.ops.dels) != fmt.Sprint(tc.wantDels) {
				t.Errorf("attempted deletes = %v, want %v", tc.ops.dels, tc.wantDels)
			}
		})
	}
}

// partialDelOps16174 fails RuleDel with ENOENT for one priority and a
// real error for every other attempted delete.
type partialDelOps16174 struct {
	*stubRuleOps16174
	enoentPrio int
}

func (p *partialDelOps16174) RuleDel(r *netlink.Rule) error {
	p.dels = append(p.dels, r.Priority)
	if r.Priority == p.enoentPrio {
		return unix.ENOENT
	}
	return errors.New("del boom")
}

// TestClearMatchingRulesPartialDelete16174 covers the mixed partial
// delete: one matched rule already gone (ENOENT, swallowed) and one
// matched rule failing for real (aggregated), with the non-matching
// rule never attempted.
func TestClearMatchingRulesPartialDelete16174(t *testing.T) {
	ops := &partialDelOps16174{
		stubRuleOps16174: &stubRuleOps16174{
			byFamily: map[int][]netlink.Rule{
				unix.AF_INET: {
					skeletonRule16174(unix.AF_INET, 1), // not matched
					skeletonRule16174(unix.AF_INET, 2), // ENOENT
					skeletonRule16174(unix.AF_INET, 3), // real failure
				},
			},
		},
		enoentPrio: 2,
	}
	err := clearMatchingRules(ops, "test-kind", func(r netlink.Rule) bool {
		return r.Priority >= 2
	})
	if err == nil {
		t.Fatal("clearMatchingRules = nil, want the real delete failure")
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) != 1 {
		t.Fatalf("joined errors = %v, want exactly the prio-3 failure", err)
	}
	if got, want := joined.Unwrap()[0].Error(), "delete stale test-kind rule prio 3: del boom"; got != want {
		t.Errorf("joined[0] = %q, want %q", got, want)
	}
	if fmt.Sprint(ops.dels) != "[2 3]" {
		t.Errorf("attempted deletes = %v, want [2 3] (prio 1 unmatched)", ops.dels)
	}
}
