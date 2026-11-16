package userspace

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
)

// #19110 (codex-d NEW P2-1): a refused #14133 refresh attach is readiness debt
// and is retried on a later status tick. These cells run at the PRODUCTION
// refresh budgets (zero): the refusal gives up at once.

type debtFixture19110 struct {
	m       *Manager
	cfg     *config.Config
	mu      sync.Mutex
	refuse  bool
	native  map[int]int
	refresh func() (bool, error)
}

func (f *debtFixture19110) setRefuse(v bool) {
	f.mu.Lock()
	f.refuse = v
	f.mu.Unlock()
}

func (f *debtFixture19110) nativeAttempts(ifindex int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.native[ifindex]
}

func (f *debtFixture19110) retry(now time.Time) {
	f.m.mu.Lock()
	f.m.retryRefreshAttachDebtLocked(now)
	f.m.mu.Unlock()
}

func (f *debtFixture19110) debt() map[int]string {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	out := map[int]string{}
	for k, v := range f.m.refreshAttachDebt {
		out[k] = v
	}
	return out
}

// newDebtFixture19110: RETH member ge-0-0-0 is recreated, 17 -> 29, and the
// refresh attaches the new ifindex. With member=false the member stays
// resolved at 17, so the refused 29 is NOT a configured data member.
func newDebtFixture19110(t *testing.T, member bool) *debtFixture19110 {
	t.Helper()
	prevLookup := linkByNameFn
	t.Cleanup(func() { linkByNameFn = prevLookup })
	linkByNameFn = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, EncapType: "ether"}}, nil
	}
	cfg := interfaceLinkRefreshConfig11530()
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfg.Interfaces.Interfaces["ge-0/0/0"] = &config.InterfaceConfig{Name: "ge-0/0/0", RedundantParent: "reth0"}
	m, _, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-0", 17, 1500)
	m.bpfShim = dataplane.New()
	m.SetRGPrimaryProvider(func(int) (bool, bool) { return true, true }) // cluster config: #15919 publish gate
	current := 17
	old := ifindexByNameFn
	ifindexByNameFn = func(name string) (int, error) {
		if name == "ge-0-0-0" {
			return current, nil
		}
		return 0, fmt.Errorf("no %s", name)
	}
	t.Cleanup(func() { ifindexByNameFn = old })
	f := &debtFixture19110{m: m, cfg: cfg, native: map[int]int{}}
	t.Cleanup(dataplane.SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		if op != "attach" {
			return true, nil
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if !generic {
			f.native[ifindex]++
		}
		if ifindex == 29 && f.refuse {
			return true, fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, syscall.EBUSY)
		}
		return true, nil
	}))
	m.refreshGenericDataMembers(cfg) // the compile that precedes every refresh
	setLink(29, 9000)
	if member {
		current = 29
	}
	f.refresh = func() (bool, error) { return m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0") }
	return f
}

func missingReason19110(reasons []string) (string, bool) {
	for _, r := range reasons {
		if strings.Contains(r, missingDataMemberReasonMarker) {
			return r, true
		}
	}
	return "", false
}

// A healthy standby (peer alive) whose RETH member is recreated and refused is
// NOT takeover-ready. The TRUE twin is the same refresh with no refusal.
func TestRefusedRefreshAttachIsReadinessDebt19110(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("refuse=%v", refuse), func(t *testing.T) {
			f := newDebtFixture19110(t, true)
			f.setRefuse(refuse)
			if _, err := f.refresh(); err != nil {
				t.Fatalf("refresh: %v (a failed attach must not fail the publication)", err)
			}
			if f.nativeAttempts(29) != 1 {
				t.Fatalf("fixture: %d native attempts on the recreated ifindex 29, want 1", f.nativeAttempts(29))
			}
			r, ok := missingReason19110(reasons19110(f.m, true))
			if !refuse {
				if ok {
					t.Fatalf("an attached member raised %q", r)
				}
				return
			}
			if !ok {
				t.Fatalf("a refused refresh attach left RETH member ge-0-0-0 with NO XDP, and readiness has no "+
					"reason for it (reasons %v): a standby could be handed traffic on it", reasons19110(f.m, true))
			}
			for _, want := range []string{"ge-0-0-0", "ifindex 29", "device or resource busy"} {
				if !strings.Contains(r, want) {
					t.Errorf("reason %q does not name %q", r, want)
				}
			}
			if got := MapHATakeoverBlocker(r); got != HATakeoverBlockerXDPMissingDataMember {
				t.Errorf("blocker = %q, want %q", got, HATakeoverBlockerXDPMissingDataMember)
			}
			if !slices.Contains(f.m.HATakeoverReadiness().Blockers, HATakeoverBlockerXDPMissingDataMember) {
				t.Error("the takeover-blocker metric does not carry xdp_missing_data_member")
			}
		})
	}
}

// The debt is retried on a LATER status tick, not before it is due, and a
// successful retry clears the reason with no commit in between.
func TestRefreshAttachDebtRetriesOnALaterTickAndClears19110(t *testing.T) {
	f := newDebtFixture19110(t, true)
	f.setRefuse(true)
	if _, err := f.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(f.debt()) == 0 {
		t.Fatal("a refused refresh attach recorded no attach debt")
	}
	f.retry(time.Now())
	if n := f.nativeAttempts(29); n != 1 {
		t.Fatalf("the retry ran before it was due (%d native attempts, want 1): a tick right after the "+
			"failure must not retry", n)
	}
	f.setRefuse(false)
	f.retry(time.Now().Add(refreshAttachRetryMax + time.Second))
	if n := f.nativeAttempts(29); n != 2 {
		t.Fatalf("a due tick made %d native attempts in total, want 2: the debt was not retried", n)
	}
	if _, ok := missingReason19110(reasons19110(f.m, true)); ok {
		t.Errorf("the retry attached ge-0-0-0, yet readiness still blocks: the debt was not cleared")
	}
	if d := f.debt(); len(d) != 0 {
		t.Errorf("debt %v left after a successful retry", d)
	}
	f.retry(time.Now().Add(time.Hour))
	if n := f.nativeAttempts(29); n != 2 {
		t.Errorf("a tick with no debt attempted again (%d native attempts)", n)
	}
}

// Consecutive failed retries back off, 1 s doubling to the 30 s cap, each
// counted from the failure, so a persistent refusal costs one attach syscall
// per backoff, never a wait under m.mu.
func TestRefreshAttachDebtBacksOffToACap19110(t *testing.T) {
	f := newDebtFixture19110(t, true)
	f.setRefuse(true)
	if _, err := f.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var got []time.Duration
	backoff := func() time.Duration {
		f.m.mu.Lock()
		defer f.m.mu.Unlock()
		if until := time.Until(f.m.refreshAttachRetryAt); until > f.m.refreshAttachBackoff || until <= 0 {
			t.Errorf("retry due in %s, outside (0, backoff %s]", until, f.m.refreshAttachBackoff)
		}
		return f.m.refreshAttachBackoff
	}
	got = append(got, backoff())
	for i := 0; i < 6; i++ {
		f.retry(time.Now().Add(time.Hour))
		got = append(got, backoff())
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		30 * time.Second, 30 * time.Second}
	if !slices.Equal(got, want) {
		t.Errorf("backoff %v, want %v", got, want)
	}
	if n := f.nativeAttempts(29); n != 7 {
		t.Errorf("%d native attempts, want 7 (one per pass)", n)
	}
}

// A lone owner has no better node: no readiness reason, but the blocker metric
// (peer-alive form) still shows the missing member.
func TestRefreshAttachDebtDoesNotBlockALoneOwner19110(t *testing.T) {
	f := newDebtFixture19110(t, true)
	f.setRefuse(true)
	if _, err := f.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if r, ok := missingReason19110(reasons19110(f.m, false)); ok {
		t.Errorf("with no live peer the missing member blocked takeover (%q); a lone owner gets the ERROR "+
			"log and the metric instead", r)
	}
	if !slices.Contains(f.m.HATakeoverReadiness().Blockers, HATakeoverBlockerXDPMissingDataMember) {
		t.Error("a lone owner with a missing data member does not surface the metric blocker")
	}
}

// A refused interface that is not a configured RETH data member is retried,
// but it is not a readiness reason (F4's scope).
func TestRefreshAttachDebtOnANonMemberIsRetriedButDoesNotBlock19110(t *testing.T) {
	f := newDebtFixture19110(t, false)
	f.setRefuse(true)
	if _, err := f.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, owed := f.debt()[29]; !owed {
		t.Fatal("fixture: the refused non-member ifindex 29 is not in the attach debt")
	}
	if r, ok := missingReason19110(reasons19110(f.m, true)); ok {
		t.Errorf("a non-member blocked takeover: %q", r)
	}
	f.retry(time.Now().Add(time.Hour))
	if n := f.nativeAttempts(29); n != 2 {
		t.Errorf("the non-member's debt was not retried (%d native attempts, want 2)", n)
	}
}

// A successful compile makes the debt due at once, so the next status tick
// drops whatever the compile attached instead of waiting out the backoff.
func TestCompileMakesRefreshAttachDebtDue19110(t *testing.T) {
	f := newDebtFixture19110(t, true)
	f.setRefuse(true)
	if _, err := f.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	f.retry(time.Now())
	if n := f.nativeAttempts(29); n != 1 {
		t.Fatalf("fixture: retried before due (%d attempts)", n)
	}
	f.m.refreshGenericDataMembers(f.cfg) // a successful compile's tail
	f.retry(time.Now())
	if n := f.nativeAttempts(29); n != 2 {
		t.Errorf("after a successful compile the next tick did not re-run the reconcile (%d attempts, want 2)", n)
	}
}

// The status loop is what retries: its tick body must call the retry hook.
func TestStatusLoopRetriesRefreshAttachDebt19110(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "process_status.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "statusLoop" || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if ce, ok := n.(*ast.CallExpr); ok {
				if se, ok := ce.Fun.(*ast.SelectorExpr); ok && se.Sel.Name == "retryRefreshAttachDebtLocked" {
					found = true
				}
			}
			return true
		})
	}
	if !found {
		t.Error("statusLoop never calls retryRefreshAttachDebtLocked: a failed refresh attach would wait for an " +
			"unrelated apply")
	}
}
