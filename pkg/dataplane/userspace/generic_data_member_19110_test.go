package userspace

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
)

// #19110 F4, the userspace half: a RETH data member left in unintended generic
// XDP mode is a takeover-readiness reason while the peer is alive. A lone owner
// gets the ERROR log and the metric blocker, but no reason.

func f4Config19110(cluster bool) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0"},                           // fabric parent: not a data member
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"}, // node0's LAN member
		"ge-7/0/1": {Name: "ge-7/0/1", RedundantParent: "reth1"}, // node1's: remote here
	}
	if cluster {
		cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	}
	return cfg
}

func f4Manager19110(t *testing.T, unintended map[int]string) *Manager {
	t.Helper()
	old := ifindexByNameFn
	ifindexByNameFn = func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 4, nil
		case "ge-0-0-1":
			return 5, nil
		}
		return 0, fmt.Errorf("no such interface %s", name)
	}
	t.Cleanup(func() { ifindexByNameFn = old })
	m := New()
	m.clusterHA = true
	m.unintendedGenericXDPHook = func() map[int]string { return unintended }
	return m
}

func reasons19110(m *Manager, peerAlive bool) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, r := m.takeoverReadyLocked(peerAlive)
	return r
}

func hasGenericReason19110(reasons []string) (string, bool) {
	for _, r := range reasons {
		if strings.Contains(r, genericDataMemberReasonMarker) {
			return r, true
		}
	}
	return "", false
}

func TestGenericDataMemberBlocksTakeoverWhilePeerAlive19110(t *testing.T) {
	m := f4Manager19110(t, map[int]string{5: "invalid argument"})
	m.refreshGenericDataMembers(f4Config19110(true))

	r, ok := hasGenericReason19110(reasons19110(m, true))
	if !ok {
		t.Fatal("a RETH data member in unintended generic XDP mode is not a takeover-readiness reason " +
			"while the peer is alive: the node could be handed traffic on a member that may forward " +
			"nothing (#19110)")
	}
	if !strings.Contains(r, "ge-0-0-1") || !strings.Contains(r, "invalid argument") {
		t.Errorf("reason %q does not name the member and the native refusal", r)
	}
	if got := MapHATakeoverBlocker(r); got != HATakeoverBlockerXDPGenericDataMember {
		t.Errorf("blocker = %q, want %q", got, HATakeoverBlockerXDPGenericDataMember)
	}
	if !slices.Contains(m.HATakeoverReadiness().Blockers, HATakeoverBlockerXDPGenericDataMember) {
		t.Error("the takeover-blocker metric does not carry xdp_generic_data_member")
	}
}

func TestGenericDataMemberDoesNotBlockALoneOwner19110(t *testing.T) {
	m := f4Manager19110(t, map[int]string{5: "invalid argument"})
	m.refreshGenericDataMembers(f4Config19110(true))

	if r, ok := hasGenericReason19110(reasons19110(m, false)); ok {
		t.Errorf("with no live peer the member blocked takeover (%q): a lone owner has no better node, "+
			"so it gets the ERROR log and metric instead", r)
	}
	// The metric is computed in the peer-alive form, so a lone owner still
	// shows it.
	if !slices.Contains(m.HATakeoverReadiness().Blockers, HATakeoverBlockerXDPGenericDataMember) {
		t.Error("a lone owner with a generic data member does not surface the metric blocker")
	}
}

func TestGenericNonMemberAndNonClusterAreExempt19110(t *testing.T) {
	// The fabric parent (ifindex 4) is generic by design and is no data member.
	m := f4Manager19110(t, map[int]string{4: "invalid argument"})
	m.refreshGenericDataMembers(f4Config19110(true))
	if r, ok := hasGenericReason19110(reasons19110(m, true)); ok {
		t.Errorf("a non-member generic interface blocked takeover: %q", r)
	}

	m = f4Manager19110(t, map[int]string{5: "invalid argument"})
	m.refreshGenericDataMembers(f4Config19110(false))
	if r, ok := hasGenericReason19110(reasons19110(m, true)); ok {
		t.Errorf("a standalone config produced a RETH data-member reason: %q", r)
	}
}

func TestGenericDataMemberReasonClearsWhenNative19110(t *testing.T) {
	unintended := map[int]string{5: "invalid argument"}
	m := f4Manager19110(t, nil)
	m.unintendedGenericXDPHook = func() map[int]string { return unintended }
	cfg := f4Config19110(true)
	m.refreshGenericDataMembers(cfg)
	if _, ok := hasGenericReason19110(reasons19110(m, true)); !ok {
		t.Fatal("fixture: the reason was not raised")
	}
	unintended = map[int]string{}
	m.refreshGenericDataMembers(cfg)
	if r, ok := hasGenericReason19110(reasons19110(m, true)); ok {
		t.Errorf("the member attached native, yet the reason stayed: %q", r)
	}
}

// Compile must refresh the set after the attach pass: the readiness reason is
// only as fresh as the last refresh. This is structural, because a real Compile
// needs a loaded shim.
func TestCompileRefreshesGenericDataMembersAfterTheAttach19110(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "manager_compile.go", nil, 0)
	if err != nil {
		t.Fatalf("parse manager_compile.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "Compile" && fd.Recv != nil {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("(*Manager).Compile not found")
	}
	shim, refresh := token.NoPos, token.NoPos
	ast.Inspect(fn, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "CompileUserspaceShim":
					shim = call.Pos()
				case "refreshGenericDataMembers":
					refresh = call.Pos()
				}
			}
		}
		return true
	})
	if shim == token.NoPos {
		t.Fatal("Compile no longer calls CompileUserspaceShim; this guard can no longer see the attach")
	}
	if refresh == token.NoPos || refresh < shim {
		t.Error("Compile does not call refreshGenericDataMembers after CompileUserspaceShim: a RETH data " +
			"member left in generic by the attach pass would not become a takeover-readiness reason (#19110)")
	}
}

// R23 P2-2: the #14133 interface-link refresh (a re-probed VF gets a new
// ifindex, no commit) attaches through the shim manager's classifier, not a
// bare AttachXDP, and recomputes the F4 reason. These drive the real refresh
// entry point with a real shim manager behind the #18740 transition seam.
func refreshClassifierFixture19110(t *testing.T, native error) (*Manager, *[]string, func() (bool, error)) {
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
	t.Cleanup(dataplane.SetXDPOccupancyBudgetForTest(300*time.Millisecond, 100*time.Millisecond))
	// The member resolves to the link's CURRENT ifindex: 17 at compile time,
	// 29 after the VF is re-probed. Only the refresh's re-resolution can point
	// F4 at the new ifindex.
	current := 17
	old := ifindexByNameFn
	ifindexByNameFn = func(name string) (int, error) {
		if name == "ge-0-0-0" {
			return current, nil
		}
		return 0, fmt.Errorf("no %s", name)
	}
	t.Cleanup(func() { ifindexByNameFn = old })
	ops := &[]string{}
	t.Cleanup(dataplane.SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		*ops = append(*ops, fmt.Sprintf("%s/%d/%v", op, ifindex, generic))
		if op != "attach" || generic || ifindex != 29 {
			return true, nil
		}
		return true, native
	}))
	// Production order: a compile of cfg always precedes a refresh, and it makes
	// cfg the F4 membership authority that the refresh re-resolves.
	m.refreshGenericDataMembers(cfg)
	setLink(29, 9000)
	current = 29
	return m, ops, func() (bool, error) { return m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0") }
}

func TestRefreshAttachRecordsUnintendedGenericForF419110(t *testing.T) {
	m, ops, refresh := refreshClassifierFixture19110(t,
		fmt.Errorf("attach XDP to ifindex 29: %w", syscall.EINVAL))
	if _, err := refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !slices.Contains(*ops, "attach/29/false") || !slices.Contains(*ops, "attach/29/true") {
		t.Fatalf("fixture: the refresh did not try native then generic on the re-probed ifindex 29 (ops %v)", *ops)
	}
	reasons := reasons19110(m, true)
	if r, ok := hasGenericReason19110(reasons); !ok || !strings.Contains(r, "ge-0-0-0") {
		t.Errorf("a refresh that left the RETH member ge-0-0-0 in generic after a native EINVAL raised no "+
			"F4 reason (reasons %v): a re-probed VF could promote with a generic member", reasons)
	}
}

func TestRefreshAttachNeverFallsBackOnARefusal19110(t *testing.T) {
	_, ops, refresh := refreshClassifierFixture19110(t,
		fmt.Errorf("attach XDP to ifindex 29: %w", syscall.EBUSY))
	if _, err := refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !slices.Contains(*ops, "attach/29/false") {
		t.Fatalf("fixture: no native attempt on ifindex 29 (ops %v)", *ops)
	}
	if slices.Contains(*ops, "attach/29/true") {
		t.Errorf("the refresh path fell back to generic after a REFUSAL (EBUSY) (ops %v); #19110 forbids "+
			"that on every attach path", *ops)
	}
}

// Codex note (cached readiness): the reason is live. When the shim's record
// drops the member (a post-acceptance DetachXDP), readiness stops blocking at
// once, with no compile or refresh in between.
func TestGenericDataMemberReasonFollowsTheLiveRecord19110(t *testing.T) {
	unintended := map[int]string{5: "invalid argument"}
	m := f4Manager19110(t, nil)
	m.unintendedGenericXDPHook = func() map[int]string { return unintended }
	m.refreshGenericDataMembers(f4Config19110(true))
	if _, ok := hasGenericReason19110(reasons19110(m, true)); !ok {
		t.Fatal("fixture: the reason was not raised")
	}
	unintended = map[int]string{} // DetachXDP cleared the record; NO refresh
	if r, ok := hasGenericReason19110(reasons19110(m, true)); ok {
		t.Errorf("readiness still blocks on %q after the shim's record dropped the member: a cached "+
			"reason outlives the detach until the next compile", r)
	}
}

// Codex delta P2-1 / R23 NEW-1, through the real refresh, at the PRODUCTION
// budgets: three untracked ingress interfaces refuse permanently. The
// reconciliation holds m.mu, which UpdateRGActive (the HA cutover) also needs,
// so it must not wait at all. Each interface gets exactly ONE native attempt,
// no generic attempt (a refusal never falls back), and the whole refresh
// returns in far less than any refusal budget.
func TestRefreshNeverWaitsUnderTheManagerMutex19110(t *testing.T) {
	prevLookup := linkByNameFn
	t.Cleanup(func() { linkByNameFn = prevLookup })
	linkByNameFn = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, EncapType: "ether"}}, nil
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {}, "ge-0/0/1": {}, "ge-0/0/2": {},
		}},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0", "ge-0/0/1", "ge-0/0/2"}},
		}},
	}
	idx := map[string]int{"ge-0-0-0": 17, "ge-0-0-1": 41, "ge-0-0-2": 42}
	m, _, _ := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-0", 17, 1500)
	oldBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = oldBuild })
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		if i, ok := idx[name]; ok {
			return i, 1500, "02:00:00:00:19:10", nil
		}
		return 0, 0, "", nil
	}
	m.bpfShim = dataplane.New()
	native, generic := map[int]int{}, map[int]int{}
	t.Cleanup(dataplane.SetXDPTransitionSeamForTest(func(op string, ifindex int, gen bool) (bool, error) {
		if op != "attach" {
			return true, nil
		}
		if gen {
			generic[ifindex]++
		} else {
			native[ifindex]++
		}
		return true, fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, syscall.EBUSY)
	}))
	idx["ge-0-0-0"] = 40 // the recreated link: the refresh publishes and reconciles

	start := time.Now()
	if _, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	el := time.Since(start)
	for _, i := range []int{40, 41, 42} {
		if native[i] == 0 {
			t.Fatalf("fixture: the refresh never attempted ifindex %d (native %v)", i, native)
		}
		if native[i] != 1 {
			t.Errorf("ifindex %d: %d native attempts under m.mu, want exactly 1: the refresh path retried "+
				"a refusal while holding the mutex the HA cutover needs", i, native[i])
		}
		if generic[i] != 0 {
			t.Errorf("ifindex %d: %d generic attempts after a refusal, want 0", i, generic[i])
		}
	}
	if el > 250*time.Millisecond {
		t.Errorf("the refresh held m.mu for %s against three refusing interfaces; it must not wait at all "+
			"(R23 NEW-1)", el.Round(time.Millisecond))
	}
}

// Codex delta P2-2: the F4 member map follows the CONFIG AUTHORITY, the most
// recent compile, not whichever snapshot a refresh happens to republish. B adds
// RETH member ge-0-0-1, which is generic. A stale status-loop reconciliation of
// the retained config A, which lacks that member, must not drop it from F4.
func TestStaleRefreshCannotReplaceTheCompiledMembership19110(t *testing.T) {
	old := ifindexByNameFn
	ifindexByNameFn = func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 4, nil
		case "ge-0-0-1":
			return 5, nil
		}
		return 0, fmt.Errorf("no %s", name)
	}
	t.Cleanup(func() { ifindexByNameFn = old })
	cfgA := &config.Config{}
	cfgA.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfgA.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
	}
	cfgB := &config.Config{}
	cfgB.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfgB.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
	}
	m := New()
	m.clusterHA = true
	t.Cleanup(dataplane.SetLinkPinPathForTest(t.TempDir()))
	m.bpfShim = dataplane.New()
	m.unintendedGenericXDPHook = func() map[int]string { return map[int]string{5: "invalid argument"} }

	m.refreshGenericDataMembers(cfgB) // compile B: its member ge-0-0-1 is generic
	if _, ok := hasGenericReason19110(reasons19110(m, true)); !ok {
		t.Fatal("fixture: compile B did not raise the reason for its generic member")
	}
	m.mu.Lock()
	m.reconcileInterfaceAttachmentsForRefreshLocked(&ConfigSnapshot{Config: cfgA}) // stale A republication
	m.mu.Unlock()
	if r, ok := hasGenericReason19110(reasons19110(m, true)); !ok || !strings.Contains(r, "ge-0-0-1") {
		t.Errorf("a stale reconciliation of the retained config A replaced compile B's membership: "+
			"B's generic member ge-0-0-1 no longer blocks takeover (reasons %v)", reasons19110(m, true))
	}
}
