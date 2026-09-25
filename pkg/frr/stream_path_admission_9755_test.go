package frr

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// #9755: StreamBGPRoutes does NOT go through Manager.vtysh, so it takes no
// diagcmd.VtyshLimiter slot. The funnel's comment used to claim "nothing in this
// package can reach vtysh except through here", which was false for this one
// path, and the #9143 census had no row for it.
//
// THE CONTRACT CHOSEN, of the two the issue offers: the stream path stays
// EXEMPT from the process-wide buffered bound and keeps its own, rather than
// being routed through a streaming form of the funnel.
//
// The reason is in pkg/api/routing.go's own rationale and it is a good one. A
// full-RIB stream is deliberately allowed a 10-minute progress budget, far
// longer than the funnel's 15 s. Making it take one of four shared slots would
// let a single slow reader hold a quarter of the budget for every FRR status
// surface on the box for ten minutes — trading a documentation inaccuracy for a
// real availability regression. And a SHARED limiter would imply a cross-surface
// bound that does not exist: the gRPC and CLI `show route protocol bgp` paths
// call the BUFFERED GetBGPRoutes, which runs to completion before any client
// sees a byte and so cannot be pinned by a slow reader.
//
// The cost of that choice is that the exemption is invisible, which is what made
// the written invariant false for months. These cells make it VISIBLE: the
// exemption is asserted here, the aggregate is stated at the limiter, and
// TestStreamPathKeepsExactlyOneBoundedCaller9755 fails the moment a second
// caller appears without a bound of its own.

// streamExec9755 records whether the stream path reached the executor.
type streamExec9755 struct {
	RecordingExecutor
	entered chan struct{}
}

func (s *streamExec9755) VtyshStream(ctx context.Context, _ string) (io.ReadCloser, func() error, error) {
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

// The exemption, asserted against a SATURATED limiter, beside the buffered
// control that must still be refused. Without the control this cell could not
// tell "exempt" from "the limiter was not actually full".
func TestStreamBGPRoutesIsExemptFromTheVtyshFunnel9755(t *testing.T) {
	withFreshVtyshLimiter9143(t, 1)
	release, err := diagcmd.VtyshLimiter.Acquire()
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	defer release()

	// CONTROL: the buffered twin of this very read IS behind the bound. If this
	// stops being refused, the limiter is not saturated and the row below proves
	// nothing.
	ctrl := &blockingExec9143{}
	mc := NewForTest(t.TempDir()+"/frr.conf", ctrl)
	if _, err := mc.GetBGPRoutes(context.Background()); !errors.Is(err, ErrVtyshBusy) {
		t.Fatalf("control: the buffered GetBGPRoutes must be refused at a full limiter, got %v", err)
	}

	// The stream path is exempt by design: it reaches the executor.
	se := &streamExec9755{entered: make(chan struct{}, 1)}
	ms := NewForTest(t.TempDir()+"/frr.conf", se)
	done := make(chan error, 1)
	go func() {
		_, e := ms.StreamBGPRoutes(context.Background(), 10, func(BGPRoute) error { return nil })
		done <- e
	}()
	select {
	case err := <-done:
		if errors.Is(err, ErrVtyshBusy) {
			t.Fatalf("the stream path is documented EXEMPT from the buffered funnel, but was refused: %v.\n"+
				"If it was deliberately routed through the funnel, this cell and the contract text at "+
				"pkg/frr/vtysh.go, pkg/diagcmd/limiter.go and pkg/frr/README.md must change together", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the stream path BLOCKED at a full limiter; it is meant to be exempt, not queued")
	}
	select {
	case <-se.entered:
	default:
		t.Fatalf("the stream path never reached the executor, so this cell is not observing the exemption")
	}
}

// #9755: the executor's streaming read is only safe while every caller has
// independent concurrency admission and an elapsed budget. #10708 adds a
// second caller for the bounded gRPC unary response.
func TestStreamPathKeepsEveryCallerBounded9755(t *testing.T) {
	inFRR := callSitesOfSelector9755(t, ".", "VtyshStream")
	if len(inFRR) != 1 || inFRR[0] != "StreamBGPRoutes" {
		t.Fatalf("VtyshStream call sites in pkg/frr: %v, want exactly [StreamBGPRoutes].\n"+
			"Every other operational read goes through Manager.vtysh and takes a VtyshLimiter slot; "+
			"a new direct streaming call inherits neither that bound nor a deadline", inFRR)
	}

	owners := []struct {
		dir     string
		limiter string
		budget  string
	}{
		{dir: "../api", limiter: "ribStreamLimiter", budget: "bgpStreamTotalBudget"},
		{dir: "../grpcapi", limiter: "grpcBGPStreamLimiter", budget: "bgpGRPCStreamBudget"},
	}
	for _, owner := range owners {
		callers := callersAcrossPkg9755(t, owner.dir, "StreamBGPRoutes")
		if len(callers) != 1 {
			t.Fatalf("StreamBGPRoutes callers under %s: %v, want exactly one", owner.dir, callers)
		}
		file := strings.SplitN(callers[0], ":", 2)[0]
		src, err := os.ReadFile(filepath.Join(owner.dir, file))
		if err != nil {
			t.Fatalf("read %s/%s: %v", owner.dir, file, err)
		}
		if !strings.Contains(string(src), owner.limiter) {
			t.Fatalf("%s/%s calls StreamBGPRoutes without its bounded admission %s",
				owner.dir, file, owner.limiter)
		}
		if !strings.Contains(string(src), owner.budget) {
			t.Fatalf("%s/%s calls StreamBGPRoutes without its elapsed bound %s",
				owner.dir, file, owner.budget)
		}
	}
}

// callSitesOfSelector9755 returns the enclosing function names of every call to
// x.<sel>(...) in the non-test .go files of dir.
func callSitesOfSelector9755(t *testing.T, dir, sel string) []string {
	t.Helper()
	var out []string
	forEachGoFile9755(t, dir, func(name string, fset *token.FileSet, f *ast.File) {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if s, ok := call.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == sel {
					out = append(out, fn.Name.Name)
				}
				return true
			})
		}
	})
	return out
}

// callersAcrossPkg9755 returns one entry per CALL SITE of x.<sel>(...) under
// dir, as "file:func".
//
// Call sites, not files: counting files would let a second call added to the
// SAME file inherit the exemption silently, which is the whole failure mode this
// census exists to catch.
func callersAcrossPkg9755(t *testing.T, dir, sel string) []string {
	t.Helper()
	var out []string
	forEachGoFile9755(t, dir, func(name string, fset *token.FileSet, f *ast.File) {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if s, ok := call.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == sel {
					out = append(out, name+":"+fn.Name.Name)
				}
				return true
			})
		}
	})
	return out
}

func forEachGoFile9755(t *testing.T, dir string, fn func(string, *token.FileSet, *ast.File)) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		seen++
		fn(name, fset, f)
	}
	if seen == 0 {
		t.Fatalf("no non-test .go files found under %s — the census scanned nothing, "+
			"which is a clean board that proves nothing", dir)
	}
}
