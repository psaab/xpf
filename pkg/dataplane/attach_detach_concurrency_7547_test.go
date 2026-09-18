package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf/link"
)

// #7547: AttachXDP/DetachXDP are read-modify-write sequences whose atomicity
// rests on a claim in a comment. #10302 adds the XDP ownership lease that
// serializes each whole attach/detach transition, including the kernel syscall,
// against the armed forward-fence actuation.
//
// #6740 made every INDIVIDUAL map access safe. The dedicated ownership lease is
// separate from m.mu, so l.Close() does not run under the broad registry mutex
// needed by the 1 Hz status path. The lease is held only against other XDP
// ownership transitions and the fence's read side.
//
// The executable cell below pins the per-ifindex serialization that prevents
// two concurrent callers from closing the same cilium/ebpf link.

// countingLink7547 is a link.Link that touches no kernel state and records
// whether two goroutines are ever inside Close() at the same instant.
//
// The embedded interface is nil, so any method other than the two overridden
// here panics rather than silently succeeding — which is what keeps this fake
// from quietly absorbing a call the real sequence makes.
type countingLink7547 struct {
	link.Link
	closes  atomic.Int64
	unpins  atomic.Int64
	inClose atomic.Int64
	overlap atomic.Bool
	release chan struct{}
}

func (f *countingLink7547) Unpin() error { f.unpins.Add(1); return nil }

func (f *countingLink7547) Close() error {
	if f.inClose.Add(1) > 1 {
		f.overlap.Store(true)
	}
	if f.release != nil {
		<-f.release
	}
	f.inClose.Add(-1)
	f.closes.Add(1)
	return nil
}

// TestDetachXDPIsSerializedWithFenceLease7547 pins the #10302 ownership lease.
// Two concurrent calls for one ifindex must not both Unpin/Close the same
// handle; the second call waits until the first removes the registry entry.
func TestDetachXDPIsSerializedWithFenceLease7547(t *testing.T) {
	m := New()
	fl := &countingLink7547{release: make(chan struct{})}
	m.setXDPLink(7547, fl)

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.DetachXDP(7547) }()
	}
	// Let the first call enter Close, then release it. The second call cannot
	// enter Close while the first holds the XDP ownership write lease.
	for range 1_000_000 {
		if fl.inClose.Load() >= 1 {
			break
		}
		runtime.Gosched()
	}
	close(fl.release)
	wg.Wait()

	if got := fl.closes.Load(); got != 1 {
		t.Fatalf("Close() called %d times, want one serialized close", got)
	}
	if got := fl.unpins.Load(); got != 1 {
		t.Fatalf("Unpin() called %d times, want one serialized unpin", got)
	}
	if fl.overlap.Load() {
		t.Fatal("concurrent DetachXDP calls entered Close simultaneously")
	}
}

// serializingAuthority records, for each call site of AttachXDP/DetachXDP, what
// keeps the caller within the dataplane's ownership protocol. The #10302 lease
// now serializes the functions themselves; the census still ensures every
// caller reaches those leased methods rather than bypassing them.
//
// Keyed "<pkg-relative path>:<enclosing func>".
var serializingAuthority = map[string]string{
	// Measured, not assumed — the census below rejected an earlier hand-written
	// version of this map, which is the point of having it.
	"pkg/dataplane/compiler.go:Compile":                                   "dataplane XDP ownership lease plus daemon applySem",
	"pkg/dataplane/loader.go:attachUserspaceShimXDP":                      "dataplane XDP ownership lease plus daemon applySem",
	"pkg/dataplane/userspace/manager_compile.go:syncInterfaceAttachments": "userspace Manager m.mu plus dataplane XDP ownership lease",
}

// TestEveryAttachDetachCallerIsSerialized7547 is the guard the issue asks for.
//
// This enumerates the call sites and requires each to be registered with the
// ownership protocol. Adding a caller without adding a row reds, and writing
// the row forces the author to name what makes the call safe.
//
// Deliberately EXACT in both directions: a stale row for a call site that no
// longer exists is worse than no row, because it reads as coverage.
func TestEveryAttachDetachCallerIsSerialized7547(t *testing.T) {
	// BOTH packages that call these, not just this one. An earlier version of
	// this census scanned only pkg/dataplane and would have missed
	// pkg/dataplane/userspace's DetachXDP loop entirely — the very call site
	// #7547 names as the one that runs while the 1 Hz status path does. A
	// census that cannot see a caller is worse than none.
	roots := []string{".", "userspace"}
	found := map[string]bool{}
	fset := token.NewFileSet()
	var scannedFiles int
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read %s: %v", root, err)
		}
		pkgPath := "pkg/dataplane"
		if root != "." {
			pkgPath = filepath.Join(pkgPath, root)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s/%s: %v", root, name, err)
			}
			scannedFiles++
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					se, ok := ce.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if se.Sel.Name != "AttachXDP" && se.Sel.Name != "DetachXDP" {
						return true
					}
					// link.AttachXDP is cilium/ebpf's constructor, not our method.
					if id, ok := se.X.(*ast.Ident); ok && id.Name == "link" {
						return true
					}
					found[pkgPath+"/"+name+":"+fd.Name.Name] = true
					return true
				})
			}
		}
	}
	// Non-vacuity: a scan that parsed nothing, or a matcher that stopped
	// matching, would otherwise report an empty set that trivially agrees with
	// an empty expectation.
	if scannedFiles < 5 {
		t.Fatalf("scanned only %d production files in pkg/dataplane; the census is "+
			"not reading the package it claims to audit", scannedFiles)
	}
	if len(found) == 0 {
		t.Fatal("found ZERO AttachXDP/DetachXDP call sites in pkg/dataplane. Either " +
			"they moved, or the matcher stopped matching — both are a broken census, " +
			"not a clean tree")
	}

	for _, site := range sortedKeys7547(found) {
		if _, ok := serializingAuthority[site]; !ok {
			t.Errorf("%s calls AttachXDP/DetachXDP with no registered serializing "+
				"authority.\n"+
				"  These are read-modify-write sequences that release the lock across\n"+
				"  l.Close() (#6740 — the syscall must not run under the mutex the 1 Hz\n"+
				"  status path needs), so two concurrent calls for one ifindex both\n"+
				"  Close() the SAME handle. cilium/ebpf's FD.Close races on fd.raw and\n"+
				"  double-closes the fd number, which can close an unrelated reused fd.\n"+
				"  Add a row to serializingAuthority naming what prevents concurrency\n"+
				"  at THIS call site — or add per-ifindex exclusion (#7547).", site)
		}
	}
	for _, site := range sortedKeys7547(mapOfKeys7547(serializingAuthority)) {
		// Rows for non-call-sites (interface declarations, the method itself)
		// are documentation and are exempt from the reverse check.
		if !found[site] {
			t.Errorf("serializingAuthority registers %s, but no such call site exists "+
				"in pkg/dataplane any more. A stale row reads as coverage; remove it "+
				"or correct the location.", site)
		}
	}
}

func sortedKeys7547(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mapOfKeys7547(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
