package configstore

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18962, configstore half. The commit-outcome WORDING of the schema walk's
// valueless-statement refusal is now selected by the arm the caller already
// runs: every commit / commit-check / auth-safe / peer-strict caller passes
// strict (compileTreeStrictJudged, compileAuthSafeCandidate,
// validatePeerStrictPipelineJudged), and the tolerant Store.Load /
// Store.SyncApply ingress (compileTreeLenient) passes lenient — where the
// finding is logged-and-continued and the booted config really does silently
// lack the statement, which is what the drop wording states.
//
// Nothing about the split may change tolerant-vs-strict BEHAVIOUR: the strict
// walk must still refuse the same tree, the lenient walk must still REPORT
// the same finding (tolerance is the caller's downgrade, never the walk's
// silence), and a persisted valueless config must still boot (#1960
// no-brick, the #8867 structure argument).
const (
	strictTail18962cs  = "the compiler would silently drop a valueless statement, so the commit is refused"
	lenientTail18962cs = "the compiler drops a valueless statement, so this commits clean and the " +
		"configuration silently does not carry it"
)

// The wording arms through the two real funnels every configstore caller
// reaches: schemaValidateExpandedTreeForNode(tree, nodeID, false) is the
// commit/commit-check/auth-safe/peer-strict call, and (…, true) is exactly
// what compileTreeLenient invokes on Load/SyncApply.
func TestValuelessTailArmsThroughTheStore_18962(t *testing.T) {
	text := "interfaces { ge-0/0/0 { description; } }"
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: parse: %v", errs[0])
	}
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))

	err := schemaValidateExpandedTreeForNode(tree, s.nodeID, false)
	if err == nil {
		t.Fatal("the strict arm accepted a valueless `description`")
	}
	if !strings.Contains(err.Error(), "`description` declares a value and none was given") ||
		!strings.Contains(err.Error(), strictTail18962cs) {
		t.Fatalf("strict arm must carry the refusal tail: %v", err)
	}
	if strings.Contains(err.Error(), "commits clean") {
		t.Fatalf("a commit-refusing error must not claim the commit succeeded: %v", err)
	}

	lerr := schemaValidateExpandedTreeForNode(tree, s.nodeID, true)
	if lerr == nil {
		t.Fatal("the lenient walk went silent — the tolerant ingress still needs the finding to log")
	}
	if !strings.Contains(lerr.Error(), "`description` declares a value and none was given") ||
		!strings.Contains(lerr.Error(), lenientTail18962cs) {
		t.Fatalf("lenient arm must carry the drop tail: %v", lerr)
	}
	if strings.Contains(lerr.Error(), "commit is refused") {
		t.Fatalf("a logged-and-continued finding must not claim a refusal that did not happen: %v", lerr)
	}
}

// The behaviour half: threading the wording flag through the configstore
// callers must not move the tolerant/strict boundary. A persisted valueless
// leaf boots (mirrors the #8867 structure cell), and the strict commit path
// still refuses the same tree.
func TestValuelessLeafTolerantBootStrictRefuseUnmoved_18962(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	text := "interfaces { ge-0/0/0 { description; } }"
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}
	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying a valueless leaf. The "+
			"#1319/#8867 tolerant split must keep this path booting (#1960 no-brick): %v", err)
	}
	if booted.ActiveConfig() == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil — the daemon reads " +
			"ActiveConfig(), so a nil there is the same blackout as a load failure")
	}
	if err := schemaValidateExpandedTreeForNode(tree, booted.nodeID, false); err == nil {
		t.Fatal("the strict commit path must still refuse the same tree the tolerant path booted")
	}
}

// Seat fold (Kimi MERGE-NEEDS-MINOR / GLM MERGE-READY): the two cells above
// pin the WALK's arms but not the PRODUCTION callers' arguments — flipping
// the literal arm at store.go's strict/tolerant call sites, the peer gate,
// or the auth-safe gate would restore the strict-arm untruth while those
// cells stayed green. The four cells below drive the real seams end to end.
// All are hermetically drivable, so no source-census pin is needed.
const valuelessDescription18962 = "interfaces { ge-0/0/0 { description; } }"

// Seam (a), strict: CheckText is the `xpfd check-config` / day-0 gate and
// funnels compileTreeStrict -> compileTreeStrictJudged -> the strict call at
// store.go:809. The refusal the operator sees must carry the strict tail.
func TestValuelessTailThroughCheckTextStrictSeam_18962(t *testing.T) {
	_, err := CheckText(valuelessDescription18962, -1)
	if err == nil {
		t.Fatal("CheckText accepted a valueless `description`")
	}
	if !strings.Contains(err.Error(), "`description` declares a value and none was given") ||
		!strings.Contains(err.Error(), strictTail18962cs) {
		t.Fatalf("the strict commit-check seam must carry the refusal tail: %v", err)
	}
	if strings.Contains(err.Error(), "commits clean") {
		t.Fatalf("a commit-check refusal must not claim the commit succeeded: %v", err)
	}
}

// Seam (b), peer-strict: validatePeerStrictPipeline (the narrowest production
// entry of validatePeerStrictPipelineJudged) runs the strict pipeline on the
// PEER node's view — the call at peer_strict_pipeline_9619.go:81. A shared
// commit carrying a valueless leaf must be refused with the strict tail for
// the peer, wrapped in the #9619 peer-error head.
func TestValuelessTailThroughPeerStrictSeam_18962(t *testing.T) {
	tree, errs := config.NewParser(valuelessDescription18962).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: parse: %v", errs[0])
	}
	err := validatePeerStrictPipeline(tree, 0)
	if err == nil {
		t.Fatal("the peer-strict seam accepted a valueless `description` for node1's view")
	}
	if !strings.Contains(err.Error(), "peer node1") ||
		!strings.Contains(err.Error(), "`description` declares a value and none was given") ||
		!strings.Contains(err.Error(), strictTail18962cs) {
		t.Fatalf("the peer-strict seam must wrap the refusal tail for the peer: %v", err)
	}
	if strings.Contains(err.Error(), "commits clean") {
		t.Fatalf("a peer-strict refusal must not claim the shared commit succeeded: %v", err)
	}
}

// Seam (c), auth-safe: compileAuthSafeCandidate validates the authored
// cleartext candidate BEFORE hashing — the call at
// auth_hash_commit_10826.go:16. A valueless leaf must be refused there with
// the strict tail, before any secret is derived.
func TestValuelessTailThroughAuthSafeSeam_18962(t *testing.T) {
	tree, errs := config.NewParser(valuelessDescription18962).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: parse: %v", errs[0])
	}
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	_, _, err := s.compileAuthSafeCandidate(tree, false)
	if err == nil {
		t.Fatal("the auth-safe seam accepted a valueless `description`")
	}
	if !strings.Contains(err.Error(), "`description` declares a value and none was given") ||
		!strings.Contains(err.Error(), strictTail18962cs) {
		t.Fatalf("the auth-safe seam must carry the refusal tail: %v", err)
	}
	if strings.Contains(err.Error(), "commits clean") {
		t.Fatalf("an auth-safe refusal must not claim the commit succeeded: %v", err)
	}
}

// Seam (d), tolerant: Store.Load -> compileTreeLenient -> the lenient call at
// store.go:1046. The valueless finding is not a typed-leaf error
// (IsTypedLeafSchemaError excludes scalar-arity refusals), so its lenient
// wording surfaces in the downgrade slog line rather than persisted
// Config.Warnings — capture the default logger and pin the lenient tail in
// exactly the line the operator/journal sees, so the tolerant caller's true
// argument is pinned through the real funnel.
func TestValuelessLenientTailThroughLoadSeam_18962(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(valuelessDescription18962).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load REFUSED a persisted config carrying a valueless leaf (#1960 no-brick): %v", err)
	}
	if booted.ActiveConfig() == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil")
	}
	logged := logs.String()
	if !strings.Contains(logged, "`description` declares a value and none was given") ||
		!strings.Contains(logged, lenientTail18962cs) {
		t.Fatalf("the tolerant Load downgrade line must carry the lenient drop tail; logged:\n%s", logged)
	}
	if strings.Contains(logged, "commit is refused") {
		t.Fatalf("a logged-and-continued finding must not claim a refusal that did not happen; logged:\n%s", logged)
	}
}
