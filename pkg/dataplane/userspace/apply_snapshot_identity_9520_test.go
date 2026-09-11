package userspace

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #9520 cells. The helper half (the refusal and its prefix) is pinned in
// userspace-dp/src/server/tests.rs. These pin the Go half, and
// TestSnapshotContentConflictPrefixMatchesTheHelper9520 binds the two by reading
// the Rust constant instead of restating it.

var rustContentConflictPrefixRe9520 = regexp.MustCompile(`SNAPSHOT_CONTENT_CONFLICT_PREFIX:\s*&str\s*=\s*"([^"]*)"\s*;`)

func TestSnapshotContentConflictPrefixMatchesTheHelper9520(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/protocol/control.rs")
	if err != nil {
		t.Fatalf("read the helper source that owns the refusal prefix: %v", err)
	}
	// Strip line comments first: a gate satisfiable by a doc comment proves
	// nothing about the constant the helper actually emits.
	var stripped strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			stripped.WriteString("\n")
			continue
		}
		stripped.WriteString(line)
		stripped.WriteString("\n")
	}
	match := rustContentConflictPrefixRe9520.FindStringSubmatch(stripped.String())
	if match == nil {
		t.Fatal("SNAPSHOT_CONTENT_CONFLICT_PREFIX not found in userspace-dp/src/protocol/control.rs — " +
			"renamed or moved, so Go can no longer recognise the refusal that proves the helper holds " +
			"a generation, and a reused-generation conflict is refused on every retry (#9520)")
	}
	if match[1] != snapshotContentConflictPrefix {
		t.Fatalf("refusal prefix disagreement: helper emits %q, Go matches %q — every content "+
			"conflict would read as an ordinary refusal and never be republished past",
			match[1], snapshotContentConflictPrefix)
	}
}

// TestContentConflictIsClassifiedOnTheRealSocketPath9520 drives
// requestDetailedLocked over a real socket. The behavioural cells below reach
// the wrapper through controlRequestHook, which bypasses the decoder, so this is
// what proves production classifies the helper's refusal.
func TestContentConflictIsClassifiedOnTheRealSocketPath9520(t *testing.T) {
	refusal := func(msg string) string {
		raw, err := json.Marshal(ControlResponse{OK: false, Error: msg})
		if err != nil {
			t.Fatalf("marshal reply: %v", err)
		}
		return string(raw)
	}
	cases := []struct {
		name  string
		reply string // empty: close without answering
		want  bool
	}{
		{"content_conflict", refusal(snapshotContentConflictPrefix + ` generation 8 is installed with content digest "a"; this apply carries "b"`), true},
		{"integrity_refusal", refusal("snapshot integrity error: unknown zone"), false},
		{"prefix_not_at_the_start", refusal("wrapped: " + snapshotContentConflictPrefix), false},
		{"eof_without_reply", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "ctl.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Skipf("unix socket unavailable: %v", err)
			}
			defer ln.Close()
			go func() {
				conn, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				defer conn.Close()
				var req ControlRequest
				_ = json.NewDecoder(conn).Decode(&req)
				if tc.reply != "" {
					_, _ = conn.Write([]byte(tc.reply + "\n"))
				}
			}()
			m := New()
			m.cfg.ControlSocket = sock
			_, err = m.requestDetailedLocked(ControlRequest{Type: "apply_snapshot"})
			if err == nil {
				t.Fatal("premise: the fixture did not produce a failure")
			}
			if got := isSnapshotContentConflict(err); got != tc.want {
				t.Fatalf("isSnapshotContentConflict(%v) = %v, want %v", err, got, tc.want)
			}
		})
	}
}

// TestApplySnapshotCarriesAContentDigestFreeOfIdentityFields9520: the digest is
// stamped on what is sent, equals snapshotContentHash of it, does not move with
// the identity fields (a retry of the same content must match), and does move
// with content.
func TestApplySnapshotCarriesAContentDigestFreeOfIdentityFields9520(t *testing.T) {
	var sent []ConfigSnapshot
	m := New()
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			sent = append(sent, *req.Snapshot)
		}
		return nil
	}
	snap := ConfigSnapshot{Version: ProtocolVersion, Generation: 7, FIBGeneration: 3,
		GeneratedAt: time.Unix(100, 0).UTC(), DefaultPolicy: "permit"}
	m.mu.Lock()
	err := m.requestApplySnapshotLocked(&snap, nil)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("requestApplySnapshotLocked: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("sent %d apply_snapshot requests, want 1", len(sent))
	}
	got := sent[0].ContentDigest
	sum, ok := snapshotContentHash(&sent[0])
	if !ok {
		t.Fatal("snapshotContentHash failed on the sent snapshot")
	}
	if want := hex.EncodeToString(sum[:]); got != want || len(got) != 64 {
		t.Fatalf("sent content_digest %q, want the 64-hex snapshotContentHash %q", got, want)
	}

	identity := snap
	identity.Generation, identity.FIBGeneration = 99, 42
	identity.GeneratedAt = time.Unix(200, 0).UTC()
	identity.ContentDigest = "left over from an earlier stamp"
	if err := stampSnapshotContentDigest(&identity); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if identity.ContentDigest != got {
		t.Fatalf("changing only generation, fib_generation, generated_at and the old digest moved the "+
			"digest %q -> %q: an idempotent retry would be refused as a conflict", got, identity.ContentDigest)
	}

	content := snap
	content.DefaultPolicy = "deny"
	if err := stampSnapshotContentDigest(&content); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if content.ContentDigest == got {
		t.Fatal("a content change did not move the digest: the helper could not tell the two applies apart")
	}
}

// TestApplySnapshotHasOneSendSite9520: a send outside requestApplySnapshotLocked
// carries no digest and cannot republish past a conflict.
func TestApplySnapshotHasOneSendSite9520(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var outside []string
	inWrapper := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || lit.Value != `"apply_snapshot"` {
					return true
				}
				if fn.Name.Name == "requestApplySnapshotLocked" {
					inWrapper++
				} else {
					outside = append(outside, fmt.Sprintf("%s (%s)", fset.Position(lit.Pos()), fn.Name.Name))
				}
				return true
			})
		}
	}
	if inWrapper == 0 {
		t.Fatal("liveness: no \"apply_snapshot\" literal found in requestApplySnapshotLocked — the scan " +
			"is not reading this package, so an empty result below would mean nothing")
	}
	if len(outside) > 0 {
		t.Errorf("apply_snapshot is sent outside requestApplySnapshotLocked:\n  %s\n"+
			"such a send carries no content digest and does not republish past a content conflict (#9520)",
			strings.Join(outside, "\n  "))
	}
}

// TestCompileCommitsThePublishedGeneration9520 pins applyCompiledSnapshot's
// bookkeeping STRUCTURALLY: without real BPF maps it fails before apply_snapshot
// (see TestAttachmentsNotDetachedBeforePublish_5485), so no behavioural cell can
// reach the adopt. The published copy's generation must be adopted into snap
// after the publish and before snap becomes m.lastSnapshot, because everything
// after (published generation, applied view, recordApplyResultLocked) reads it.
func TestCompileCommitsThePublishedGeneration9520(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "manager_compile.go", nil, 0)
	if err != nil {
		t.Fatalf("parse manager_compile.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "applyCompiledSnapshot" {
			fn = d
		}
	}
	if fn == nil {
		t.Fatal("applyCompiledSnapshot not found in manager_compile.go")
	}
	var publish, retain token.Pos
	var adopts []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "publishSnapshotFailClosedLocked":
				if publish == token.NoPos {
					publish = x.Pos()
				}
			case "adoptPublishedGenerationLocked":
				adopts = append(adopts, x)
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "lastSnapshot" {
					continue
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "m" && publish != token.NoPos && retain == token.NoPos {
					retain = x.Pos()
				}
			}
		}
		return true
	})
	if publish == token.NoPos || retain == token.NoPos {
		t.Fatalf("premise: applyCompiledSnapshot no longer publishes (%v) and then retains m.lastSnapshot (%v)",
			publish != token.NoPos, retain != token.NoPos)
	}
	if len(adopts) != 1 {
		t.Fatalf("applyCompiledSnapshot calls adoptPublishedGenerationLocked %d times, want 1: without it a "+
			"content-conflict republish leaves snap and m.generation on the refused generation", len(adopts))
	}
	adopt := adopts[0]
	if !(publish < adopt.Pos() && adopt.Pos() < retain) {
		t.Fatalf("adoptPublishedGenerationLocked must run after publishSnapshotFailClosedLocked and before " +
			"m.lastSnapshot = snap, or the retained snapshot records the refused generation")
	}
	if len(adopt.Args) != 2 {
		t.Fatalf("adoptPublishedGenerationLocked has %d args, want 2", len(adopt.Args))
	}
	first, ok1 := adopt.Args[0].(*ast.Ident)
	second, ok2 := adopt.Args[1].(*ast.SelectorExpr)
	secondX, ok3 := ast.Expr(nil), false
	if ok2 {
		secondX, ok3 = second.X, true
	}
	if !ok1 || first.Name != "snap" || !ok3 || second.Sel.Name != "Generation" ||
		secondX.(*ast.Ident).Name != "publishSnap" {
		t.Fatal("applyCompiledSnapshot must adopt publishSnap.Generation into snap")
	}
}

// applyRecorder9520 answers each apply_snapshot with the next scripted reply
// (nil once exhausted) and records what was sent. A success fills the status the
// way the helper does, so a caller that drops the status on a retry programs a
// stale ctrl generation and ctrl (the helper-status map fake) shows it.
type applyRecorder9520 struct {
	sent    []ConfigSnapshot
	replies []error
	ctrl    *fakeCtrlMap
}

func (r *applyRecorder9520) hook(req ControlRequest, status *ProcessStatus) error {
	if req.Type != "apply_snapshot" {
		return nil
	}
	r.sent = append(r.sent, *req.Snapshot)
	if len(r.replies) > 0 {
		reply := r.replies[0]
		r.replies = r.replies[1:]
		if reply != nil {
			return reply
		}
	}
	if status != nil {
		*status = ProcessStatus{
			ConfigSnapshotProtocolVersion: ProtocolVersion,
			LastSnapshotGeneration:        req.Snapshot.Generation,
			LastFIBGeneration:             req.Snapshot.FIBGeneration,
		}
	}
	return nil
}

func (r *applyRecorder9520) generations() []uint64 {
	out := make([]uint64, len(r.sent))
	for i, s := range r.sent {
		out[i] = s.Generation
	}
	return out
}

// contentConflict9520 is the helper's refusal when generation gen is installed
// with other content; server/tests.rs pins the helper emitting the prefix.
func contentConflict9520(gen uint64) error {
	return newHelperRejection(fmt.Sprintf("%s generation %d is installed with content digest %q; this apply carries %q",
		snapshotContentConflictPrefix, gen, "landed", "retry"))
}

// errLostResponse9520 is a round trip the helper committed whose response never
// arrived: a transport error, not an in-band refusal.
var errLostResponse9520 = fmt.Errorf("read unix ->/run/xpf/userspace-dp.sock: %w", os.ErrDeadlineExceeded)

func scheduledPolicyConfig9520() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:          "scheduled-allow",
			SchedulerName: "workhours",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
			Action: config.PolicyPermit,
		}},
	}}
	cfg.Schedulers = map[string]*config.SchedulerConfig{"workhours": {Name: "workhours"}}
	return cfg
}

// newRepublishManager9520 is a running-helper manager that last published
// generation 7 of snap.
func newRepublishManager9520(snap *ConfigSnapshot, rec *applyRecorder9520) *Manager {
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.generation = 7
	m.lastSnapshot = snap
	m.publishedSnapshot = 7
	if h, ok := snapshotContentHash(snap); ok {
		m.lastSnapshotHash = h
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.helperStatusObserved = true
	rec.ctrl = &fakeCtrlMap{}
	m.helperStatusCtrlMapHook = rec.ctrl
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	// The success path's helper-status sync re-programs the classifier maps;
	// seam them the way newDeferredPublishFixture9337 does.
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.controlRequestHook = rec.hook
	return m
}

// TestScheduleRepublishAfterALostResponseMovesPastTheLandedGeneration9520 is the
// issue's acceptance shape. A window-OPEN republish lands at generation 8 but
// its response is lost, so m.generation stays 7. The window then CLOSES and the
// republish rebuilds and re-sends generation 8, which the helper holds with the
// open window. The helper refuses it (server/tests.rs), and the closed window
// must land on generation 9 in the same call. A permit decision cached or stamped
// under generation 8 then goes stale, instead of the closed window being
// installed under 8 and those decisions staying fresh.
func TestScheduleRepublishAfterALostResponseMovesPastTheLandedGeneration9520(t *testing.T) {
	cfg := scheduledPolicyConfig9520()
	rec := &applyRecorder9520{replies: []error{errLostResponse9520, contentConflict9520(8)}}
	m := newRepublishManager9520(mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0), rec)

	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": true}); err == nil {
		t.Fatal("premise: the lost response must surface as an error, or the scheduler never retries")
	}
	if m.generation != 7 {
		t.Fatalf("a transport error must not move the generation (#5134, #3780): got %d", m.generation)
	}
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err != nil {
		t.Fatalf("the closing-window republish must converge in this call, not a 60s scheduler tick later: %v", err)
	}

	if got := rec.generations(); !slices.Equal(got, []uint64{8, 8, 9}) {
		t.Fatalf("apply_snapshot generations = %v, want [8 8 9] (open lands at 8, closed reuses 8, closed republished at 9)", got)
	}
	open, reused, republished := rec.sent[0], rec.sent[1], rec.sent[2]
	if open.ContentDigest == "" || open.ContentDigest == reused.ContentDigest {
		t.Fatalf("premise: the open and closed windows must be different content (digests %q, %q), "+
			"or the real helper would ACK the reuse and this cell measures nothing", open.ContentDigest, reused.ContentDigest)
	}
	if schedPolicyInactive5328(t, open.Policies, "scheduled-allow") {
		t.Fatal("premise: the open-window publish must carry the policy active")
	}
	if !schedPolicyInactive5328(t, republished.Policies, "scheduled-allow") {
		t.Fatal("the republish on generation 9 must carry the CLOSED window")
	}
	if republished.ContentDigest != reused.ContentDigest {
		t.Fatal("the republish must carry the refused content unchanged, on a new generation only")
	}
	if m.generation != 9 || m.lastSnapshot.Generation != 9 || m.publishedSnapshot != 9 || m.appliedSnapshot.Generation != 9 {
		t.Fatalf("bookkeeping must commit the generation actually published (9): generation=%d last=%d published=%d applied=%d",
			m.generation, m.lastSnapshot.Generation, m.publishedSnapshot, m.appliedSnapshot.Generation)
	}
	if got := rec.ctrl.stored.ConfigGeneration; got != 9 {
		t.Fatalf("userspace_ctrl.ConfigGeneration = %d after the republish, want 9: the retry's status must reach "+
			"applyHelperStatusLocked, or the shim runs against a stale generation", got)
	}
}

func TestRouteOverlayRepublishMovesPastAHeldGeneration9520(t *testing.T) {
	cfg := overlayTestConfig()
	rec := &applyRecorder9520{replies: []error{contentConflict9520(8)}}
	m := newRepublishManager9520(mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0), rec)

	overlay := []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"}}
	published, err := m.PublishRouteOverlaySnapshot(cfg, overlay, nil)
	if err != nil || !published {
		t.Fatalf("PublishRouteOverlaySnapshot after a content conflict: published=%v err=%v", published, err)
	}
	if got := rec.generations(); !slices.Equal(got, []uint64{8, 9}) {
		t.Fatalf("apply_snapshot generations = %v, want [8 9]", got)
	}
	if m.generation != 9 || m.lastSnapshot.Generation != 9 || m.publishedSnapshot != 9 {
		t.Fatalf("overlay bookkeeping must commit 9: generation=%d last=%d published=%d",
			m.generation, m.lastSnapshot.Generation, m.publishedSnapshot)
	}
	if got := m.routeOverlaySnapshot(); len(got) != 1 || got[0].NextHop != "172.16.80.1" {
		t.Fatalf("the converged publish must commit the desired overlay: %+v", got)
	}
}

func TestDeferredWorkerArmMovesPastAHeldGeneration9520(t *testing.T) {
	snap, err := buildSnapshot(&config.Config{}, config.UserspaceConfig{}, 7, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	snap.DeferWorkers = true
	rec := &applyRecorder9520{replies: []error{contentConflict9520(8)}}
	m := newRepublishManager9520(snap, rec)
	m.RecordDeferredWorkerArmDebt()

	m.mu.Lock()
	err = m.retryDeferredWorkerArmLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("retryDeferredWorkerArmLocked after a content conflict: %v", err)
	}
	if got := rec.generations(); !slices.Equal(got, []uint64{8, 9}) {
		t.Fatalf("apply_snapshot generations = %v, want [8 9]", got)
	}
	if m.generation != 9 || m.lastSnapshot.Generation != 9 || m.publishedSnapshot != 9 ||
		m.lastSnapshot.DeferWorkers || m.pendingWorkerArm {
		t.Fatalf("worker-arm bookkeeping must commit 9 and settle the debt: generation=%d last=%d published=%d defer=%v debt=%v",
			m.generation, m.lastSnapshot.Generation, m.publishedSnapshot, m.lastSnapshot.DeferWorkers, m.pendingWorkerArm)
	}
}

func TestDeferredSyncPublishMovesPastAHeldGeneration9520(t *testing.T) {
	f := newDeferredPublishFixture9337(t, nil)
	rec := &applyRecorder9520{replies: []error{contentConflict9520(8)}}
	f.m.controlRequestHook = rec.hook
	if err := f.runSync(t); err != nil {
		t.Fatalf("syncSnapshotLocked after a content conflict: %v", err)
	}
	if got := rec.generations(); !slices.Equal(got, []uint64{8, 9}) {
		t.Fatalf("apply_snapshot generations = %v, want [8 9]", got)
	}
	m := f.m
	if m.generation != 9 || m.lastSnapshot.Generation != 9 || m.publishedSnapshot != 9 || m.appliedSnapshot.Generation != 9 {
		t.Fatalf("deferred-sync bookkeeping must commit 9: generation=%d last=%d published=%d applied=%d",
			m.generation, m.lastSnapshot.Generation, m.publishedSnapshot, m.appliedSnapshot.Generation)
	}
}

// TestOnlyTheContentConflictRefusalMovesTheGeneration9520: #5134's rule that a
// failed apply does not burn a generation holds for every failure except the
// refusal proving the helper has it, the retry is bounded to one, and it is not
// attempted once the process is stopping.
func TestOnlyTheContentConflictRefusalMovesTheGeneration9520(t *testing.T) {
	integrity := newHelperRejection("snapshot integrity error: unknown zone")
	cases := []struct {
		name           string
		replies        []error
		shutdown       bool
		wantGens       []uint64
		wantGeneration uint64
	}{
		{"integrity_refusal_is_not_consumption", []error{integrity}, false, []uint64{8}, 7},
		{"transport_error_is_not_consumption", []error{errLostResponse9520}, false, []uint64{8}, 7},
		{"conflict_then_integrity_refusal_consumes_only_the_held_generation", []error{contentConflict9520(8), integrity}, false, []uint64{8, 9}, 8},
		{"conflict_then_transport_error_consumes_only_the_held_generation", []error{contentConflict9520(8), errLostResponse9520}, false, []uint64{8, 9}, 8},
		{"a_second_conflict_is_consumed_but_not_chased", []error{contentConflict9520(8), contentConflict9520(9)}, false, []uint64{8, 9}, 9},
		{"conflict_during_shutdown_is_not_retried", []error{contentConflict9520(8)}, true, []uint64{8}, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := scheduledPolicyConfig9520()
			rec := &applyRecorder9520{replies: tc.replies}
			m := newRepublishManager9520(mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0), rec)
			if tc.shutdown {
				m.BeginControlShutdown()
			}
			if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{"workhours": false}); err == nil {
				t.Fatal("premise: every scripted reply here ends in a failure the caller must see")
			}
			if got := rec.generations(); !slices.Equal(got, tc.wantGens) {
				t.Fatalf("apply_snapshot generations = %v, want %v", got, tc.wantGens)
			}
			if m.generation != tc.wantGeneration {
				t.Fatalf("m.generation = %d, want %d", m.generation, tc.wantGeneration)
			}
			if m.lastSnapshot.Generation != 7 || m.publishedSnapshot != 7 {
				t.Fatalf("a failed publish must not advance the retained snapshot: last=%d published=%d",
					m.lastSnapshot.Generation, m.publishedSnapshot)
			}
		})
	}
}

// TestOverlayRevertAfterALostResponseIsRepublished9520 (Codex review finding 1).
// A lost response can land overlay B while m.lastSnapshotHash still describes
// the baseline A. If the desired overlay then reverts to A, its hash matches and
// the dedup used to skip the publish, leaving B enforced indefinitely.
func TestOverlayRevertAfterALostResponseIsRepublished9520(t *testing.T) {
	cfg := overlayTestConfig()
	rec := &applyRecorder9520{replies: []error{errLostResponse9520, contentConflict9520(8)}}
	m := newRepublishManager9520(mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0), rec)

	if published, err := m.PublishRouteOverlaySnapshot(cfg, nil, nil); err != nil || published || len(rec.sent) != 0 {
		t.Fatalf("premise: the baseline overlay must dedup against the published snapshot with no send "+
			"(published=%v err=%v sends=%d), or the revert below proves nothing about the dedup", published, err, len(rec.sent))
	}
	b := []config.RouteOverlayEntry{{Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover"}}
	if _, err := m.PublishRouteOverlaySnapshot(cfg, b, nil); err == nil {
		t.Fatal("premise: the lost response must surface as an error")
	}
	published, err := m.PublishRouteOverlaySnapshot(cfg, nil, nil)
	if err != nil || !published {
		t.Fatalf("a revert to the baseline after a lost response must be REPUBLISHED, not deduplicated against "+
			"content the helper may no longer hold: published=%v err=%v", published, err)
	}
	if got := rec.generations(); !slices.Equal(got, []uint64{8, 8, 9}) {
		t.Fatalf("apply_snapshot generations = %v, want [8 8 9] (B lost at 8, the revert refused at 8, republished at 9)", got)
	}
	if m.applySnapshotOutcomeUnknown {
		t.Fatal("a successful apply must clear the unknown-outcome mark")
	}
	if published, err := m.PublishRouteOverlaySnapshot(cfg, nil, nil); err != nil || published || len(rec.sent) != 3 {
		t.Fatalf("once an apply has succeeded the dedup must work again: published=%v err=%v sends=%d", published, err, len(rec.sent))
	}
}

// TestSyncShortcutsStandDownAfterALostResponse9520 (Codex review finding 1).
// syncSnapshotLocked has two shortcuts that skip a publish on Go's own
// bookkeeping: the generation-only catch-up and the content-hash dedup. After a
// lost response both may be describing content the helper does not hold, so
// they must publish instead. The rows without a lost response are the controls:
// the same state skips the send, so the publish is the mark's doing.
func TestSyncShortcutsStandDownAfterALostResponse9520(t *testing.T) {
	cases := []struct {
		name         string
		helperGen    uint64 // generation the helper reports
		seedHash     bool   // lastSnapshotHash already equals the snapshot's hash
		lostResponse bool
		wantSends    int
	}{
		{"catch_up_after_a_lost_response_publishes", 8, false, true, 2},
		{"catch_up_without_one_skips_the_send", 8, false, false, 0},
		{"hash_dedup_after_a_lost_response_publishes", 1, true, true, 2},
		{"hash_dedup_without_one_skips_the_send", 1, true, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeferredPublishFixture9337(t, nil)
			rec := &applyRecorder9520{}
			if tc.lostResponse {
				rec.replies = []error{errLostResponse9520}
			}
			f.m.controlRequestHook = rec.hook
			f.m.lastStatus.LastSnapshotGeneration = tc.helperGen
			if tc.seedHash {
				h, ok := snapshotContentHash(f.snap)
				if !ok {
					t.Fatal("snapshotContentHash failed")
				}
				f.m.lastSnapshotHash = h
			}
			if tc.lostResponse {
				lost := *f.snap
				f.m.mu.Lock()
				err := f.m.requestApplySnapshotLocked(&lost, nil)
				f.m.mu.Unlock()
				if err == nil || !f.m.applySnapshotOutcomeUnknown {
					t.Fatalf("premise: the lost response must fail and mark the outcome unknown (err=%v)", err)
				}
			}
			if err := f.runSync(t); err != nil {
				t.Fatalf("syncSnapshotLocked: %v", err)
			}
			if len(rec.sent) != tc.wantSends {
				t.Fatalf("apply_snapshot sends = %d, want %d", len(rec.sent), tc.wantSends)
			}
			if f.m.publishedSnapshot != 8 {
				t.Fatalf("publishedSnapshot = %d, want 8 either way", f.m.publishedSnapshot)
			}
		})
	}
}

// TestOnlyASuccessfulApplyClearsAnUnknownOutcome9520: an in-band refusal leaves
// the mark as it was, because the helper kept whatever it held.
func TestOnlyASuccessfulApplyClearsAnUnknownOutcome9520(t *testing.T) {
	integrity := newHelperRejection("snapshot integrity error: unknown zone")
	steps := []struct {
		reply error
		want  bool
	}{
		{integrity, false},          // a refusal with nothing unknown stays known
		{errLostResponse9520, true}, // a lost response makes it unknown
		{integrity, true},           // a refusal does not make it known again
		{nil, false},                // only a success does
	}
	m := New()
	for i, step := range steps {
		reply := step.reply
		m.controlRequestHook = func(ControlRequest, *ProcessStatus) error { return reply }
		snap := ConfigSnapshot{Version: ProtocolVersion, Generation: uint64(10 + i)}
		m.mu.Lock()
		_ = m.requestApplySnapshotLocked(&snap, nil)
		got := m.applySnapshotOutcomeUnknown
		m.mu.Unlock()
		if got != step.want {
			t.Fatalf("step %d (reply %v): applySnapshotOutcomeUnknown = %v, want %v", i, reply, got, step.want)
		}
	}
}

// TestAFailedRetryAfterAConflictStillFailsClosed9520 (Codex review finding 3):
// when the republish after a content conflict fails, the deferred-sync publish
// still applies publishSnapshotFailClosedLocked's split to that failure. The
// maps are not rolled back and ctrl is disabled, exactly as for a first-attempt
// failure (the #9337 cells).
func TestAFailedRetryAfterAConflictStillFailsClosed9520(t *testing.T) {
	cases := []struct {
		name  string
		retry error
	}{
		{"conflict_then_integrity_refusal", newHelperRejection("snapshot integrity error: unknown zone")},
		{"conflict_then_transport_error", errLostResponse9520},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeferredPublishFixture9337(t, nil)
			rec := &applyRecorder9520{replies: []error{contentConflict9520(8), tc.retry}}
			f.m.controlRequestHook = rec.hook
			if err := f.runSync(t); err == nil {
				t.Fatal("syncSnapshotLocked returned nil after the republish failed")
			}
			if got := rec.generations(); !slices.Equal(got, []uint64{8, 9}) {
				t.Fatalf("apply_snapshot generations = %v, want [8 9]", got)
			}
			if got := f.rollbacks(); len(got) != 0 {
				t.Fatalf("classifier maps were rolled back %d time(s) after a failed republish", len(got))
			}
			if f.ctrl.stored.Enabled != 0 {
				t.Fatalf("userspace_ctrl.Enabled = %d after a failed republish, want 0 (fail closed)", f.ctrl.stored.Enabled)
			}
			if f.m.publishedSnapshot != 1 || f.m.generation != 8 {
				t.Fatalf("publishedSnapshot=%d generation=%d, want 1 unchanged and 8 consumed",
					f.m.publishedSnapshot, f.m.generation)
			}
		})
	}
}
