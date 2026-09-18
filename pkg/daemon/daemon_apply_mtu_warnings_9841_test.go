package daemon

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func mtuTestRecords9841() []dataplane.MTUUnconverged {
	return []dataplane.MTUUnconverged{{
		Name: "ge-0-0-2", ConfigRef: "ge-0/0/2", WantMTU: 9000, LiveMTU: 1500,
		Grade:  dataplane.MTUGradeWriteFailed,
		Detail: "LinkSetMTU refused: operation not supported",
	}}
}

func requireMTUWarning9841(t *testing.T, cfg *config.Config) string {
	t.Helper()
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#9841)") {
			for _, want := range []string{"ge-0/0/2", "ge-0-0-2", "9000", "1500", "[write-failed]"} {
				if !strings.Contains(w, want) {
					t.Fatalf("commit warning %q must name %q", w, want)
				}
			}
			return w
		}
	}
	t.Fatalf("no (#9841) line in commit warnings: %v", cfg.Warnings)
	return ""
}

// The committing wrapper projects this attempt's records onto a RESPONSE
// COPY carrying the commit warnings (foreign lines preserved) and leaves
// the applied object untouched — the dataplane snapshot retains that
// pointer, so mutating it would race snapshot readers.
func TestApplyConfigLockedForCommitWarnsUnconvergedMTU9841(t *testing.T) {
	d, dp, cfg := minimalApplyCtxDaemon(t)
	cfg.Warnings = []string{"foreign advisory"}
	dp.applyResult = &dataplane.ApplyResult{UnconvergedMTUs: mtuTestRecords9841()}

	resp, err := d.applyConfigLockedForCommit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("applyConfigLockedForCommit: %v", err)
	}
	if resp == cfg {
		t.Fatalf("response is the applied pointer: records must project onto a copy, never mutate the retained object")
	}
	if len(resp.Warnings) != 2 || resp.Warnings[0] != "foreign advisory" {
		t.Fatalf("response warnings = %v, want [foreign advisory, mtu line]", resp.Warnings)
	}
	requireMTUWarning9841(t, resp)
	if len(cfg.Warnings) != 1 || cfg.Warnings[0] != "foreign advisory" {
		t.Fatalf("applied warnings = %v, want the input untouched", cfg.Warnings)
	}
}

// A successful apply that publishes nothing (stale probe) projects
// nothing: the wrapper returns the applied pointer itself — no copy, no
// lines — and must not warn from another apply's records.
func TestApplyConfigLockedForCommitSkipsWithoutFreshPublish9841(t *testing.T) {
	d, dp, cfg := minimalApplyCtxDaemon(t)
	cfg.Warnings = []string{"foreign advisory"}
	dp.applyResult = &dataplane.ApplyResult{UnconvergedMTUs: mtuTestRecords9841()}
	dp.holdLastApply = true

	resp, err := d.applyConfigLockedForCommit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("applyConfigLockedForCommit: %v", err)
	}
	if resp != cfg {
		t.Fatalf("stale probe copied the config: no fresh publish means no projection, no copy")
	}
	if len(cfg.Warnings) != 1 || cfg.Warnings[0] != "foreign advisory" {
		t.Fatalf("warnings = %v, want only the foreign line: no fresh publish, no sync", cfg.Warnings)
	}
}

// With no dataplane the wrapper is a pass-through: no probe, no copy.
func TestApplyConfigLockedForCommitNoDataplaneSkips9841(t *testing.T) {
	d, _, cfg := minimalApplyCtxDaemon(t)
	d.setDataplane(nil) // publish nothing through the cell
	cfg.Warnings = []string{"foreign advisory"}

	resp, err := d.applyConfigLockedForCommit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("applyConfigLockedForCommit: %v", err)
	}
	if resp != cfg || len(cfg.Warnings) != 1 {
		t.Fatalf("resp=%p cfg=%p warnings=%v, want the input pointer with only the foreign line", resp, cfg, cfg.Warnings)
	}
}

// A failed commit reports the error, not warnings: failure with a stale
// probe stays silent (the MTU lines recur on the next attempt while the
// host stays unconverged), and the applied object is untouched.
func TestApplyConfigLockedForCommitFailsSilent9841(t *testing.T) {
	d, dp, cfg := minimalApplyCtxDaemon(t)
	cfg.Warnings = []string{"foreign advisory"}
	injected := errors.New("simulated helper failure")
	dp.applyErr = injected

	resp, err := d.applyConfigLockedForCommit(context.Background(), cfg)
	if !errors.Is(err, injected) {
		t.Fatalf("applyConfigLockedForCommit = %v, want the injected failure", err)
	}
	if resp != nil {
		t.Fatalf("failed apply returned a response object: failures speak through errors")
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#9841)") {
			t.Fatalf("failed apply warned %q: failures speak through errors", w)
		}
	}
}

// OWNERSHIP: a background-shaped apply (bare applyConfigLocked, the path
// feed/rollback/debt/boot take) projects nothing — it returns no response
// object at all. Only the committing wrapper projects, and only onto a
// response copy.
func TestBackgroundApplyLeavesWarningsUntouched9841(t *testing.T) {
	d, dp, cfg := minimalApplyCtxDaemon(t)
	before := []string{"foreign advisory", "interface MTU not realized: stale line (#9841)"}
	cfg.Warnings = append([]string(nil), before...)
	dp.applyResult = &dataplane.ApplyResult{UnconvergedMTUs: mtuTestRecords9841()}

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}
	if len(cfg.Warnings) != len(before) {
		t.Fatalf("warnings = %v, want the input verbatim %v", cfg.Warnings, before)
	}
	for i := range before {
		if cfg.Warnings[i] != before[i] {
			t.Fatalf("warnings = %v, want the input verbatim %v", cfg.Warnings, before)
		}
	}
}

// An identical re-commit warns again (fresh compiled, full apply, fresh
// publication): same persistent state, same answer. No duplication within
// either response, and neither applied object is touched.
func TestIdenticalRecommitWarnsTwice9841(t *testing.T) {
	d, dp, _ := minimalApplyCtxDaemon(t)
	dp.applyResult = &dataplane.ApplyResult{UnconvergedMTUs: mtuTestRecords9841()}

	for i := 0; i < 2; i++ {
		cfg := &config.Config{Warnings: []string{"foreign advisory"}}
		resp, err := d.applyConfigLockedForCommit(context.Background(), cfg)
		if err != nil {
			t.Fatalf("re-commit %d: %v", i, err)
		}
		if len(resp.Warnings) != 2 {
			t.Fatalf("re-commit %d response = %v, want exactly [foreign, mtu line]", i, resp.Warnings)
		}
		requireMTUWarning9841(t, resp)
		if len(cfg.Warnings) != 1 {
			t.Fatalf("re-commit %d applied = %v, want the input untouched", i, cfg.Warnings)
		}
	}
}

// The returned object — the exact value the commit RPCs project — carries
// the line on a response copy, while the applied input keeps only its
// validation warnings. Transport from here is the generically pinned
// configWarnings carrier.
func TestApplyAndSyncCommittedReturnsMTUWarnings9841(t *testing.T) {
	d, dp, _ := minimalApplyCtxDaemon(t)
	dp.applyResult = &dataplane.ApplyResult{UnconvergedMTUs: mtuTestRecords9841()}
	compiled := &config.Config{Warnings: []string{"foreign advisory"}}

	got, err := d.applyAndSyncCommitted(&config.Config{}, compiled, peerSyncNever)
	if err != nil {
		t.Fatalf("applyAndSyncCommitted: %v", err)
	}
	if got == compiled {
		t.Fatalf("returned the applied pointer: the response must project onto a copy")
	}
	requireMTUWarning9841(t, got)
	if len(compiled.Warnings) != 1 {
		t.Fatalf("applied warnings = %v, want only the foreign line", compiled.Warnings)
	}
}

// The projection cannot perturb config identity: the applied digest reads
// tree text, and the active object itself is never written — only the
// response copy carries the line.
func TestCommittedDigestStableAcrossMTUSync9841(t *testing.T) {
	d := applyMarkerDaemon9175(t)
	promote9175(t, d, "system host-name mtu-test;\n")
	dp := &runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{UnconvergedMTUs: mtuTestRecords9841()}}
	d.setDataplane(dp)

	before := d.store.ActiveDigest()
	if before == "" {
		t.Fatalf("no active digest after promotion")
	}
	cfg := d.store.ActiveConfig()
	resp, err := d.applyConfigLockedForCommit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("applyConfigLockedForCommit: %v", err)
	}
	requireMTUWarning9841(t, resp)
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "(#9841)") {
			t.Fatalf("active config carries %q: the projection must not write through to store-active", w)
		}
	}
	if got := d.store.ActiveDigest(); got != before {
		t.Fatalf("active digest changed across the warning sync: %q -> %q", before, got)
	}
}

// Cross-commit race hammer: post-return projections of commit A's RESPONSE
// run free while commit attempts on FRESH configs (the production shape:
// every commit compiles fresh) apply+project under applySem. Clean under
// -race iff no storage is shared — a shared/global warnings buffer trips
// it. Each response carries its own lines; each applied input keeps only
// its foreign line.
func TestMTUWarningsCrossCommitRace9841(t *testing.T) {
	d, dp, _ := minimalApplyCtxDaemon(t)
	d.applySem = semaphore.NewWeighted(1)
	dp.applyResult = &dataplane.ApplyResult{UnconvergedMTUs: mtuTestRecords9841()}

	committedA := &config.Config{Warnings: []string{"foreign advisory"}}
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	respA, err := d.applyConfigLockedForCommit(context.Background(), committedA)
	d.applySem.Release(1)
	if err != nil {
		t.Fatalf("commit A: %v", err)
	}
	wantA := append([]string(nil), respA.Warnings...)
	if len(wantA) != 2 {
		t.Fatalf("commit A response = %v, want [foreign, mtu line]", wantA)
	}

	project := func() []string {
		return append([]string(nil), respA.Warnings...)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2000 {
				if got := project(); len(got) != 2 {
					t.Errorf("projection %d warnings, want 2 (stable across foreign commits)", len(got))
					return
				}
			}
		}()
	}
	for q := range 4 {
		wg.Add(1)
		go func(q int) {
			defer wg.Done()
			for i := range 15 {
				fresh := &config.Config{Warnings: []string{"foreign advisory"}}
				if err := d.applySem.Acquire(context.Background(), 1); err != nil {
					t.Errorf("applier %d acquire: %v", q, err)
					return
				}
				resp, err := d.applyConfigLockedForCommit(context.Background(), fresh)
				d.applySem.Release(1)
				if err != nil {
					t.Errorf("applier %d commit %d: %v", q, i, err)
					return
				}
				if len(resp.Warnings) != 2 {
					t.Errorf("applier %d commit %d response = %v, want [foreign, mtu line]", q, i, resp.Warnings)
					return
				}
				if len(fresh.Warnings) != 1 {
					t.Errorf("applier %d commit %d applied = %v, want the input untouched", q, i, fresh.Warnings)
					return
				}
			}
		}(q)
	}
	// No-op commits run after the hammer: a mid-hammer backend swap would
	// mix generation domains across appliers' probes — a shape production
	// never takes outside teardown, which fails the apply anyway.
	wg.Wait()
	d.setDataplane(&runtimeOnlyApplyTestDP{})
	for i := range 5 {
		fresh := &config.Config{Warnings: []string{"foreign advisory"}}
		if err := d.applySem.Acquire(context.Background(), 1); err != nil {
			t.Fatalf("acquire: %v", err)
		}
		resp, err := d.applyConfigLockedForCommit(context.Background(), fresh)
		d.applySem.Release(1)
		if err != nil {
			t.Fatalf("no-op commit %d: %v", i, err)
		}
		if resp != fresh || len(fresh.Warnings) != 1 {
			t.Fatalf("no-op commit %d: want the input pointer with only foreign, got resp=%p warnings=%v",
				i, resp, fresh.Warnings)
		}
	}
	if len(respA.Warnings) != len(wantA) {
		t.Fatalf("commit A response moved under foreign commits: %v", respA.Warnings)
	}
	for i := range wantA {
		if respA.Warnings[i] != wantA[i] {
			t.Fatalf("commit A response moved under foreign commits: %v", respA.Warnings)
		}
	}
}

// Aliased-serialization race hammer: the production alias the cross-commit
// hammer above does NOT cover. The dataplane snapshot retains the APPLIED
// pointer (builder.go Config: cfg), and the status loop keeps serializing
// it under the userspace mutex while later commits apply — so serializers
// here read the SAME object the wrapper is projecting from, lock-free, in
// the configWarnings shape. Clean under -race iff the wrapper never writes
// through the alias: a write-through implementation stores cfg.Warnings
// while a serializer reads it and the detector trips. Each response still
// carries its own lines, and the shared original keeps only its foreign
// line throughout.
func TestMTUWarningsAliasedSerializationRace9841(t *testing.T) {
	d, dp, _ := minimalApplyCtxDaemon(t)
	d.applySem = semaphore.NewWeighted(1)
	dp.applyResult = &dataplane.ApplyResult{UnconvergedMTUs: mtuTestRecords9841()}

	shared := &config.Config{Warnings: []string{"foreign advisory"}}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3000 {
				// The retained-snapshot reader shape: copy the warnings
				// out, as configWarnings and the wire copies do.
				got := append([]string(nil), shared.Warnings...)
				if len(got) != 1 || got[0] != "foreign advisory" {
					t.Errorf("serializer saw %v: the applied object must never gain lines", got)
					return
				}
			}
		}()
	}
	for q := range 4 {
		wg.Add(1)
		go func(q int) {
			defer wg.Done()
			for i := range 15 {
				if err := d.applySem.Acquire(context.Background(), 1); err != nil {
					t.Errorf("applier %d acquire: %v", q, err)
					return
				}
				resp, err := d.applyConfigLockedForCommit(context.Background(), shared)
				d.applySem.Release(1)
				if err != nil {
					t.Errorf("applier %d commit %d: %v", q, i, err)
					return
				}
				if len(resp.Warnings) != 2 {
					t.Errorf("applier %d commit %d response = %v, want [foreign, mtu line]", q, i, resp.Warnings)
					return
				}
				if resp == shared {
					t.Errorf("applier %d commit %d: response aliases the applied object", q, i)
					return
				}
			}
		}(q)
	}
	wg.Wait()
	if len(shared.Warnings) != 1 || shared.Warnings[0] != "foreign advisory" {
		t.Fatalf("shared applied object = %v, want only the foreign line", shared.Warnings)
	}
}

// Wiring canary: the committing wrapper has exactly one production call
// site, inside applyAndSyncCommitted — the choke both operator commit
// paths funnel through. A future commit entrypoint bypassing the choke
// loses warnings silently; a second wrapper site double-projects. Either
// trips this count. (Behavioural cells above prove the wrapper works;
// this proves the commit flow reaches it.)
func TestApplyAndSyncCommittedSyncsMTUWarnings9841(t *testing.T) {
	files := packageGoFiles(t)
	fset := token.NewFileSet()
	calls := 0
	var callers []string
	for _, file := range files {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		var enclosing string
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				enclosing = n.Name.Name
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "applyConfigLockedForCommit" {
					calls++
					callers = append(callers, enclosing)
				}
			}
			return true
		})
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 applyConfigLockedForCommit call site in package daemon, found %d (%v)", calls, callers)
	}
	if callers[0] != "applyAndSyncCommitted" {
		t.Fatalf("the wrapper is called from %s, want applyAndSyncCommitted", callers[0])
	}
}
