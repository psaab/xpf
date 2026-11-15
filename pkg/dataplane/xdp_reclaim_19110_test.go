package dataplane

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// #19110, the head-only cells: they use the reclaim, diagnostic and record
// seams the fix introduces, so they do not compile at master. RED-at-master for
// these properties is shown by the mutants named in docs/log/19110.md;
// xdp_attach_occupied_19110_test.go and xdp_stale_link_release_19110_test.go
// are the master-compilable cells.

// fakeReclaimLink19110 records the reclaim's calls on the pinned link.
type fakeReclaimLink19110 struct {
	mu        *sync.Mutex
	events    *[]string
	name      string
	detachErr error
	unpinErr  error
	path      string
	unpinRmOK bool // a successful Unpin removes the file, as cilium's does
}

func (f *fakeReclaimLink19110) rec(e string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.events = append(*f.events, e+"/"+f.name)
}

func (f *fakeReclaimLink19110) Detach() error { f.rec("detach"); return f.detachErr }
func (f *fakeReclaimLink19110) Unpin() error {
	f.rec("unpin")
	if f.unpinErr != nil {
		return f.unpinErr
	}
	if f.unpinRmOK {
		_ = os.Remove(f.path)
	}
	return nil
}
func (f *fakeReclaimLink19110) Close() error { f.rec("close"); return nil }

type reclaimHarness19110 struct {
	mu     sync.Mutex
	events []string
	// load decides what loading the pin at path returns. nil means "a fake
	// link that detaches and unpins cleanly".
	load func(path string) (reclaimableXDPLink, error)
}

func newReclaimHarness19110(t *testing.T) *reclaimHarness19110 {
	t.Helper()
	h := &reclaimHarness19110{}
	old := loadPinnedXDPLinkFn
	loadPinnedXDPLinkFn = func(path string) (reclaimableXDPLink, error) {
		h.mu.Lock()
		h.events = append(h.events, "load/"+filepath.Base(path))
		h.mu.Unlock()
		if h.load != nil {
			return h.load(path)
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("load pinned link: %w", unix.ENOENT)
		}
		return h.fake(path, nil, nil), nil
	}
	t.Cleanup(func() { loadPinnedXDPLinkFn = old })
	return h
}

func (h *reclaimHarness19110) fake(path string, detachErr, unpinErr error) *fakeReclaimLink19110 {
	return &fakeReclaimLink19110{mu: &h.mu, events: &h.events, name: filepath.Base(path),
		detachErr: detachErr, unpinErr: unpinErr, path: path, unpinRmOK: true}
}

func (h *reclaimHarness19110) trace() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.events...)
}

func seedPinBody19110(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
}

// C1: a live stale link is DETACHED (synchronously) before its pin goes, and
// its handle is closed.
func TestReclaimDetachesThenUnpinsThenCloses19110(t *testing.T) {
	h := newReclaimHarness19110(t)
	dir := t.TempDir()
	pin := filepath.Join(dir, "xdp_5")
	seedPinBody19110(t, pin, "live")

	r := reclaimStaleXDPLinkPin(pin)

	want := []string{"load/xdp_5", "detach/xdp_5", "unpin/xdp_5", "close/xdp_5"}
	if got := h.trace(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("reclaim calls = %v, want %v: the link must be detached before its pin is dropped "+
			"(an unlink alone only schedules the release)", got, want)
	}
	if r.outcome != reclaimDetached || r.err != nil {
		t.Errorf("outcome = %s (%v), want detached", r.outcome, r.err)
	}
	if _, err := os.Stat(pin); err == nil {
		t.Error("the pin still exists after a clean reclaim")
	}
}

// C1a–C1f: the failure contract. Reclaim never aborts; Close always runs once
// the link is open.
func TestReclaimFailureContract19110(t *testing.T) {
	cases := []struct {
		name        string
		pinIsDir    bool // a non-empty directory: os.Remove fails
		load        func(h *reclaimHarness19110, path string) (reclaimableXDPLink, error)
		onBPFFS     bool
		wantOutcome xdpReclaimOutcome
		wantGone    bool
		wantEvents  []string
	}{
		{name: "C1a_enoent", wantOutcome: reclaimNoPin, wantGone: true,
			load: func(_ *reclaimHarness19110, _ string) (reclaimableXDPLink, error) {
				return nil, fmt.Errorf("load pinned link: %w", unix.ENOENT)
			}},
		{name: "C1b_not_a_link", wantOutcome: reclaimNotALink, wantGone: true,
			load: func(_ *reclaimHarness19110, path string) (reclaimableXDPLink, error) {
				return nil, fmt.Errorf("%s is not a Link", path)
			}},
		{name: "C1b2_errnoless_info_failure_is_unknown", wantOutcome: reclaimDeferred, wantGone: true,
			// cilium's RawLink.Info wraps OBJ_GET_INFO_BY_FD with %s: a LIVE
			// link whose info read failed arrives errno-less. It must not
			// pass as "not a link" (R23 P3-1).
			load: func(_ *reclaimHarness19110, _ string) (reclaimableXDPLink, error) {
				return nil, errors.New("link info: bad file descriptor")
			}},
		{name: "C1c_eacces_off_bpffs", onBPFFS: false, wantOutcome: reclaimNotALink, wantGone: true,
			load: func(_ *reclaimHarness19110, _ string) (reclaimableXDPLink, error) {
				return nil, fmt.Errorf("load pinned link: %w", unix.EACCES)
			}},
		{name: "C1d_eacces_on_bpffs_unknown", onBPFFS: true, wantOutcome: reclaimDeferred, wantGone: true,
			load: func(_ *reclaimHarness19110, _ string) (reclaimableXDPLink, error) {
				return nil, fmt.Errorf("load pinned link: %w", unix.EACCES)
			}},
		{name: "C1d_eperm_unknown", wantOutcome: reclaimDeferred, wantGone: true,
			load: func(_ *reclaimHarness19110, _ string) (reclaimableXDPLink, error) {
				return nil, fmt.Errorf("load pinned link: %w", unix.EPERM)
			}},
		{name: "C1e_detach_fails", wantOutcome: reclaimDeferred, wantGone: true,
			wantEvents: []string{"detach", "unpin", "close"},
			load: func(h *reclaimHarness19110, path string) (reclaimableXDPLink, error) {
				return h.fake(path, errors.New("detach: operation not supported"), nil), nil
			}},
		{name: "C1f_unpin_fails", pinIsDir: true, wantOutcome: reclaimDetachedPinStuck, wantGone: false,
			wantEvents: []string{"detach", "unpin", "close"},
			load: func(h *reclaimHarness19110, path string) (reclaimableXDPLink, error) {
				return h.fake(path, nil, errors.New("unpin: permission denied")), nil
			}},
		{name: "C1h_detach_and_unpin_fail", pinIsDir: true, wantOutcome: reclaimStuck, wantGone: false,
			wantEvents: []string{"detach", "unpin", "close"},
			load: func(h *reclaimHarness19110, path string) (reclaimableXDPLink, error) {
				return h.fake(path, errors.New("detach failed"), errors.New("unpin failed")), nil
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newReclaimHarness19110(t)
			h.load = func(path string) (reclaimableXDPLink, error) { return tc.load(h, path) }
			oldFS := pinOnBPFFSFn
			pinOnBPFFSFn = func(string) (bool, error) { return tc.onBPFFS, nil }
			t.Cleanup(func() { pinOnBPFFSFn = oldFS })

			dir := t.TempDir()
			pin := filepath.Join(dir, "xdp_5")
			if tc.pinIsDir {
				if err := os.MkdirAll(filepath.Join(pin, "keep"), 0700); err != nil {
					t.Fatal(err)
				}
			} else if tc.name != "C1a_enoent" {
				seedPinBody19110(t, pin, "x")
			}

			r := reclaimStaleXDPLinkPin(pin)

			if r.outcome != tc.wantOutcome {
				t.Errorf("outcome = %s (%v), want %s", r.outcome, r.err, tc.wantOutcome)
			}
			_, statErr := os.Stat(pin)
			if gone := statErr != nil; gone != tc.wantGone {
				t.Errorf("pin gone = %v, want %v", gone, tc.wantGone)
			}
			if tc.wantEvents != nil {
				var got []string
				for _, e := range h.trace() {
					if !strings.HasPrefix(e, "load/") {
						got = append(got, strings.SplitN(e, "/", 2)[0])
					}
				}
				if strings.Join(got, " ") != strings.Join(tc.wantEvents, " ") {
					t.Errorf("link calls = %v, want %v (Close runs on every path once the link is open)",
						got, tc.wantEvents)
				}
			}
		})
	}
}

// C1g: per-interface order. The sweep leaves pending pins alone, and the attach
// pass reclaims each interface immediately before its own first attach. A
// registered link's pin is never reclaimed.
func TestReclaimRunsImmediatelyBeforeEachInterfacesAttach19110(t *testing.T) {
	h := newReclaimHarness19110(t)
	dir := withTempPinDir9847(t)
	for _, n := range []string{"xdp_4", "xdp_5", "xdp_6", "xdp_9"} {
		seedPinBody19110(t, filepath.Join(dir, n), "stale")
	}
	restore := SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		h.mu.Lock()
		h.events = append(h.events, fmt.Sprintf("%s/%d", op, ifindex))
		h.mu.Unlock()
		return true, nil
	})
	t.Cleanup(restore)

	m := New()
	m.SetLinkForTest(6, &pinTrackingLink9847{}, nil) // registered: never reclaimed

	m.removeUserspaceShimXDPLinkPins([]int{4, 5, 6})
	var loads []string
	for _, e := range h.trace() {
		if strings.HasPrefix(e, "load/") {
			loads = append(loads, e)
		}
	}
	if got := loads; strings.Join(got, " ") != "load/xdp_9" {
		t.Fatalf("sweep reclaimed %v, want only xdp_9: pending (4, 5) and registered (6) pins are "+
			"left for the attach pass", got)
	}
	h.mu.Lock()
	h.events = nil
	h.mu.Unlock()

	if err := m.attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{4, 5, 6}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	var order []string
	for _, e := range h.trace() {
		if strings.HasPrefix(e, "load/") || strings.HasPrefix(e, "attach/") {
			order = append(order, e)
		}
	}
	want := []string{"load/xdp_4", "attach/4", "load/xdp_5", "attach/5", "attach/6"}
	if strings.Join(order, " ") != strings.Join(want, " ") {
		t.Errorf("order = %v, want %v: each interface's reclaim must come immediately before its own "+
			"attach, and a registered link's pin is never reclaimed", order, want)
	}
}

// C1h, the attach half: a reclaim that could neither detach nor unpin leaves a
// LIVE pin. The attach must not reuse it. It is a fresh attach that the kernel
// refuses, and it ends in ErrXDPOccupied naming the reclaim failure.
func TestStuckReclaimEndsInOccupiedNotReuse19110(t *testing.T) {
	h := newReclaimHarness19110(t)
	dir := withTempPinDir9847(t)
	if err := os.MkdirAll(filepath.Join(dir, "xdp_5", "keep"), 0700); err != nil {
		t.Fatal(err)
	}
	h.load = func(path string) (reclaimableXDPLink, error) {
		return h.fake(path, errors.New("detach failed"), errors.New("unpin failed")), nil
	}
	shortenOccupancyBudget19110(t, 300*time.Millisecond, 100*time.Millisecond)
	stubOccupantProbe19110(t, "native XDP program 77 on ge-0-0-1 (ifindex 5)", nil)
	restore := SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		if op == "attach" {
			return true, occupiedErr19110(ifindex, unix.EBUSY)
		}
		return true, nil
	})
	t.Cleanup(restore)

	err := New().attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{5}})
	if !errors.Is(err, ErrXDPOccupied) || !errors.Is(err, unix.EBUSY) {
		t.Fatalf("err = %v, want ErrXDPOccupied wrapping EBUSY", err)
	}
	if !strings.Contains(err.Error(), "stale pin reclaim: stuck") {
		t.Errorf("the give-up error does not name the failed reclaim: %v", err)
	}
}

// C1i: a reclaim that falls back (here, the pin cannot be opened: EPERM) does
// not abort the apply. The attach that follows decides, and here it succeeds.
func TestDeferredReclaimDoesNotAbortTheAttach19110(t *testing.T) {
	h := newReclaimHarness19110(t)
	dir := withTempPinDir9847(t)
	seedPinBody19110(t, filepath.Join(dir, "xdp_5"), "stale")
	h.load = func(string) (reclaimableXDPLink, error) {
		return nil, fmt.Errorf("load pinned link: %w", unix.EPERM)
	}
	restore := SetXDPTransitionSeamForTest(func(string, int, bool) (bool, error) { return true, nil })
	t.Cleanup(restore)

	if err := New().attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{5}}); err != nil {
		t.Fatalf("attach = %v: a reclaim that could not open the pin must fall back to the unlink, "+
			"not abort the apply", err)
	}
}

// The fresh-only half, structurally and TRANSITIVELY (R23 P3-6): nothing
// reachable from AttachXDP may load a pin. That covers AttachXDP itself, its
// receiver's methods, and the package functions it calls. A reuse (load a pin,
// Update it) needs a load, so the walk flags link.LoadPinnedLink and the reclaim
// seam loadPinnedXDPLinkFn. The repair's identity check, pinnedXDPLinkIsOursFn,
// is a function VARIABLE that only reads the link ID; the walk does not follow
// variables.
func TestAttachXDPIsFreshOnly19110(t *testing.T) {
	fset := token.NewFileSet()
	decls := map[string][]*ast.FuncDecl{}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		pf, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range pf.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				decls[fd.Name.Name] = append(decls[fd.Name.Name], fd)
			}
		}
	}
	start := decls["AttachXDP"]
	if len(start) == 0 {
		t.Fatal("(*Manager).AttachXDP not found")
	}
	seen := map[*ast.FuncDecl]bool{}
	queue := append([]*ast.FuncDecl(nil), start...)
	for len(queue) > 0 {
		fd := queue[0]
		queue = queue[1:]
		if seen[fd] {
			continue
		}
		seen[fd] = true
		recv := ""
		if fd.Recv != nil && len(fd.Recv.List) == 1 && len(fd.Recv.List[0].Names) == 1 {
			recv = fd.Recv.List[0].Names[0].Name
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			follow := false
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name, follow = fn.Name, true
			case *ast.SelectorExpr:
				name = fn.Sel.Name
				if id, ok := fn.X.(*ast.Ident); ok && recv != "" && id.Name == recv {
					follow = true
				}
			}
			if name == "LoadPinnedLink" || name == "loadPinnedXDPLinkFn" {
				t.Errorf("%s (reachable from AttachXDP) calls %s at %s: a pin this process did not "+
					"create must never be reused (#19110 fresh-only)", fd.Name.Name, name, fset.Position(call.Pos()))
			}
			if follow {
				queue = append(queue, decls[name]...)
			}
			return true
		})
	}
	if len(seen) < 3 {
		t.Fatalf("the walk visited only %d function(s) from AttachXDP; the census is not following calls", len(seen))
	}
}

func shortenOccupancyBudget19110(t *testing.T, budget, diag time.Duration) {
	t.Helper()
	ob, od := xdpOccupancyBudget, xdpOccupancyDiagBudget
	xdpOccupancyBudget, xdpOccupancyDiagBudget = budget, diag
	t.Cleanup(func() { xdpOccupancyBudget, xdpOccupancyDiagBudget = ob, od })
}

func stubOccupantProbe19110(t *testing.T, s string, err error) {
	t.Helper()
	old := xdpOccupantProbeFn
	xdpOccupantProbeFn = func(int) (string, error) { return s, err }
	t.Cleanup(func() { xdpOccupantProbeFn = old })
}

func refuseAll19110(t *testing.T, errno unix.Errno) {
	t.Helper()
	restore := SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		if op == "attach" {
			return true, occupiedErr19110(ifindex, errno)
		}
		return true, nil
	})
	t.Cleanup(restore)
}

// C3c: an upper device carrying XDP is named in the give-up error, and the
// kernel's errno is kept.
func TestOccupiedErrorNamesTheUpperDevice19110(t *testing.T) {
	withTempPinDir9847(t)
	newReclaimHarness19110(t)
	shortenOccupancyBudget19110(t, 300*time.Millisecond, 200*time.Millisecond)
	stubOccupantProbe19110(t, "upper fab0 (ifindex 9) carries generic XDP program 12", nil)
	refuseAll19110(t, unix.EEXIST)

	err := New().attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{4}})
	if !errors.Is(err, ErrXDPOccupied) || !errors.Is(err, unix.EEXIST) {
		t.Fatalf("err = %v, want ErrXDPOccupied wrapping EEXIST", err)
	}
	if !strings.Contains(err.Error(), "upper fab0 (ifindex 9)") {
		t.Errorf("the give-up error does not name the upper device: %v", err)
	}
}

// C3d: a probe failure, or a probe that finds nothing, reports "occupant
// unknown" and keeps the kernel's errno. EBUSY is a refusal, not proof of an
// occupant.
func TestProbeFailureKeepsTheErrnoAndSaysUnknown19110(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    string
		err  error
	}{
		{"probe_error", "", errors.New("netlink: resource temporarily unavailable")},
		{"nothing_found", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTempPinDir9847(t)
			newReclaimHarness19110(t)
			shortenOccupancyBudget19110(t, 300*time.Millisecond, 200*time.Millisecond)
			stubOccupantProbe19110(t, tc.s, tc.err)
			refuseAll19110(t, unix.EBUSY)

			err := New().attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{5}})
			if !errors.Is(err, ErrXDPOccupied) || !errors.Is(err, unix.EBUSY) {
				t.Fatalf("err = %v, want ErrXDPOccupied still wrapping EBUSY", err)
			}
			if !strings.Contains(err.Error(), "occupant: unknown") {
				t.Errorf("the give-up error claims an occupant it did not find: %v", err)
			}
		})
	}
}

// C3e: the diagnostic budget is AGGREGATE. A probe that hangs does not hold the
// pass past the occupancy budget plus the diagnostic budget.
func TestHungProbeIsBoundedByTheDiagnosticBudget19110(t *testing.T) {
	withTempPinDir9847(t)
	newReclaimHarness19110(t)
	shortenOccupancyBudget19110(t, 300*time.Millisecond, 200*time.Millisecond)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	old := xdpOccupantProbeFn
	xdpOccupantProbeFn = func(int) (string, error) { <-block; return "", nil }
	t.Cleanup(func() { xdpOccupantProbeFn = old })
	refuseAll19110(t, unix.EBUSY)

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- New().attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{5}}) }()
	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a hung probe held the attach pass for 5 s: the diagnostic wait is unbounded")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("a hung probe held the pass for %s; the diagnostic budget is 200 ms", el)
	}
	if !strings.Contains(fmt.Sprint(err), "diagnostic budget spent") {
		t.Errorf("err = %v, want the budget-spent diagnostic", err)
	}
}

// Identity-checked repair: a pin that is present but names another (dead) link
// is replaced by this link's pin.
func TestRepairReplacesAPinThatIsNotThisLinks19110(t *testing.T) {
	dir := withTempPinDir9847(t)
	seedPinBody19110(t, filepath.Join(dir, "xdp_5"), "stale")
	fake := &pinTrackingLink9847{}

	if err := ensureXDPLinkPinned(5, fake); err != nil {
		t.Fatalf("ensure over a stale pin = %v, want nil (replaced)", err)
	}
	if fake.pinCalls != 1 {
		t.Errorf("Pin calls = %d, want 1: a present pin that is not this link's must be replaced, "+
			"not trusted", fake.pinCalls)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "xdp_5")); string(b) != "pin" {
		t.Errorf("pin body = %q after repair, want this link's pin", b)
	}
}

// ... and when the stale pin cannot be removed, Close says the shutdown was not
// hitless, even though a file exists at the pin path.
func TestCloseReportsAnUnreplaceableStalePinAsDegraded19110(t *testing.T) {
	dir := withTempPinDir9847(t)
	if err := os.MkdirAll(filepath.Join(dir, "xdp_11", "keep"), 0700); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.SetLinkForTest(11, &pinTrackingLink9847{}, nil)

	err := m.Close()
	if err == nil || !strings.Contains(err.Error(), "11") {
		t.Fatalf("Close = %v, want a degraded report naming ifindex 11: the path is occupied by "+
			"something that is not this link's pin", err)
	}
}

// F4, dataplane half: the generic-fallback record. EOPNOTSUPP (the driver has
// no native XDP at all) is the supported generic and is not reported. Any other
// native refusal that ended in generic is.
//
// What clears it (R23 P2-3): a RE-COMMIT does NOT. The registered generic link
// short-circuits AttachXDP ("already attached"), so no native attempt is made.
// A detach, or a fresh process (an xpfd restart), does. The fixture models
// production: after the first pass the generic link is REGISTERED, and the
// second pass sees the short-circuit, as AttachXDP returns it.
func TestUnintendedGenericRecord19110(t *testing.T) {
	newReclaimHarness19110(t)
	withTempPinDir9847(t)
	m := New()
	native := map[int]error{}
	restore := SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		if op != "attach" {
			return true, nil
		}
		if _, ok := m.xdpLinkFor(ifindex); ok {
			return true, fmt.Errorf("XDP already attached to ifindex %d", ifindex)
		}
		if generic {
			return true, nil
		}
		return true, native[ifindex]
	})
	native[5] = occupiedErr19110(5, unix.EINVAL)     // mlx5 with LRO on
	native[6] = occupiedErr19110(6, unix.EOPNOTSUPP) // no ndo_bpf (iavf)
	if err := m.attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{5, 6}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got := m.UnintendedGenericXDP()
	if got[5] != "invalid argument" {
		t.Errorf("ifindex 5 (native EINVAL, then generic) not reported unintended: %v", got)
	}
	if _, ok := got[6]; ok {
		t.Errorf("ifindex 6 (EOPNOTSUPP: no native XDP) reported unintended; that generic is the "+
			"supported deployment: %v", got)
	}

	// Production: the generic attach registered a link.
	m.SetLinkForTest(5, &pinTrackingLink9847{}, nil)
	native[5] = nil // the operator fixed LRO
	if err := m.attachUserspaceShimXDP(&CompileResult{pendingXDP: []int{5}}); err != nil {
		t.Fatalf("re-commit pass: %v", err)
	}
	if _, ok := m.UnintendedGenericXDP()[5]; !ok {
		t.Error("a re-commit cleared the record, but in production the registered generic link " +
			"short-circuits AttachXDP and no native attach happens: the record (and the F4 reason) " +
			"must stay, and the remediation must say restart")
	}

	restore()
	if err := m.DetachXDP(5); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, ok := m.UnintendedGenericXDP()[5]; ok {
		t.Error("DetachXDP removed the generic link but left its generic-fallback record")
	}
	if got := New().UnintendedGenericXDP(); len(got) != 0 {
		t.Errorf("a fresh Manager (an xpfd restart) carries a record: %v", got)
	}
}

// P2-2, the dataplane half: the single-interface attach the #14133 refresh
// uses applies the compile pass's rules. An unsupported native attach falls
// back and is recorded; a refusal never becomes a generic attempt.
func TestShimInterfaceAttachIsClassified19110(t *testing.T) {
	withTempPinDir9847(t)
	newReclaimHarness19110(t)
	t.Cleanup(SetXDPOccupancyBudgetForTest(300*time.Millisecond, 100*time.Millisecond))
	stubOccupantProbe19110(t, "", nil)
	var ops []string
	native := map[int]error{29: occupiedErr19110(29, unix.EINVAL), 30: occupiedErr19110(30, unix.EBUSY)}
	restore := SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		ops = append(ops, fmt.Sprintf("%s/%d/%v", op, ifindex, generic))
		if op != "attach" || generic {
			return true, nil
		}
		return true, native[ifindex]
	})
	t.Cleanup(restore)
	m := New()

	if err := m.AttachShimXDPInterface(29, false); err != nil {
		t.Fatalf("EINVAL interface: %v", err)
	}
	if m.UnintendedGenericXDP()[29] != "invalid argument" {
		t.Errorf("the refresh attach's EINVAL->generic fallback was not recorded for F4: %v", m.UnintendedGenericXDP())
	}
	err := m.AttachShimXDPInterface(30, false)
	if !errors.Is(err, ErrXDPOccupied) || !errors.Is(err, unix.EBUSY) {
		t.Errorf("a persistent refusal on the refresh path = %v, want ErrXDPOccupied wrapping EBUSY", err)
	}
	for _, o := range ops {
		if o == "attach/30/true" {
			t.Errorf("the refresh path attempted generic after a refusal (ops %v)", ops)
		}
	}
}

var _ link.Link = (*pinTrackingLink9847)(nil)
