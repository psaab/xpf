package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15995 (A8-01, gRPC arm): deny-configuration "^security ipsec" was
// evaluated only on the joined requested path, so ShowConfig{["security"]}
// was admitted and the handler rendered the whole security subtree —
// ipsec included. Same for scoped ShowCompare / ShowRollback. The gate
// now prices every rendered descendant of the target/slot trees.
//
// Fixture: ancestor-view class (deny ^security ipsec, view+configure),
// config with security{zones,ipsec,policies} + interfaces. Rollback slot 1
// and a staged candidate carry the same shape so compare/rollback arms
// have denied descendants to disclose.

const ancestor15995Config = `
system {
    host-name ancestor-15995;
    login {
        user ancuser { class ancestor-view; }
        user openuser { class open-view; }
        class ancestor-view {
            permissions [ view configure ];
            deny-configuration "^security ipsec";
        }
        class open-view {
            permissions [ view configure ];
        }
    }
}
security {
    zones {
        security-zone trust {
            description "ZONE-DESC-15995";
            interfaces [ ge-0/0/0.0 ];
        }
    }
    ipsec {
        vpn vpn1 { bind-interface st0.0; ike { gateway 192.0.2.1; } pre-shared-key ascii-text dummy15995; }
    }
    policies {
        from-zone trust to-zone trust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`

const ancestor15995Passwd = `root:x:0:0:root:/root:/bin/bash
ancuser:x:4260:4260::/home/ancuser:/bin/bash
openuser:x:4261:4261::/home/openuser:/bin/bash
`

const (
	uidAncestor15995 = 4260
	uidOpen15995     = 4261
)

func ancestor15995Server(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(ancestor15995Passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	commit := func(text string) {
		t.Helper()
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(text); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		store.ExitConfigure()
	}
	commit(ancestor15995Config)
	// Slot 1 = first config (with the denied ipsec descendant).
	commit(strings.Replace(ancestor15995Config, "ancestor-15995", "ancestor-15995-b", 1))
	// Stage a candidate so scoped compares have both arms.
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure candidate: %v", err)
	}
	if err := store.SetFromInput("security zones security-zone trust description CANDIDATE-15995"); err != nil {
		t.Fatalf("stage candidate: %v", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return &Server{store: store}
}

func TestShowConfigAncestorDeniedDescendant15995(t *testing.T) {
	s := ancestor15995Server(t)
	ctx := ctxWithPeerUID(uidAncestor15995)

	// The leak: ancestor admitted pre-fix, renders denied ipsec.
	wantDenied14707(t, "ShowConfig ACTIVE [security] (deny ^security ipsec; renders ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}))
	wantDenied14707(t, "ShowConfig CANDIDATE [security] (deny ^security ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_CANDIDATE, Path: []string{"security"}}))
	wantDenied14707(t, "ShowConfig ACTIVE [security] display set (deny ^security ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}, Format: pb.ConfigFormat_SET}))
	// Direct denied path: control (already denied pre-fix).
	wantDenied14707(t, "ShowConfig ACTIVE [security ipsec] (control)",
		s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security", "ipsec"}}))

	// Allowed siblings / unrelated subtrees stay admitted.
	for _, path := range [][]string{
		{"security", "zones"},
		{"security", "policies"},
		{"interfaces"},
		{"system"},
	} {
		if err := s.authorizeRPC(ctx, show14707Method("ShowConfig"),
			&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: path}); err != nil {
			t.Errorf("ShowConfig ACTIVE %v must stay admitted: %v", path, err)
		}
	}

	// End-to-end: handler output through the admitted context must not
	// carry the denied descendant for the allowed sibling, and the
	// ancestor request must never reach the handler admitted.
	ctx2, err := s.authorizeRPCContext(ctxWithPeerUID(uidAncestor15995), show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security", "zones"}})
	if err != nil {
		t.Fatalf("authorize zones context: %v", err)
	}
	resp, herr := s.ShowConfig(ctx2, &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security", "zones"}})
	if herr != nil {
		t.Fatalf("ShowConfig zones handler: %v", herr)
	}
	if !strings.Contains(resp.Output, "ZONE-DESC-15995") {
		t.Errorf("zones render lost its content:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "ipsec") {
		t.Errorf("zones render disclosed ipsec:\n%s", resp.Output)
	}
}

// Fold F3/C4: the handler must render the generation the gate priced.
// After authorization, the live candidate is edited to carry a marker
// the snapshot does not have; the rendered output must be the priced
// (pre-edit) generation — proving price and render share one snapshot
// (and that the gate's walk never raced the in-place candidate edit).
func TestShowConfigRendersPricedSnapshot15995(t *testing.T) {
	s := ancestor15995Server(t)
	req := &pb.ShowConfigRequest{Target: pb.ConfigTarget_CANDIDATE, Path: []string{"security", "zones"}}
	ctx, err := s.authorizeRPCContext(ctxWithPeerUID(uidAncestor15995), show14707Method("ShowConfig"), req)
	if err != nil {
		t.Fatalf("authorize zones candidate: %v", err)
	}
	// Concurrent-generation edit AFTER pricing: stage a new marker in
	// the live candidate. A render that re-resolved the store would
	// disclose POST-PRICE-15995; the priced snapshot must not.
	if err := s.store.SetFromInput("security zones security-zone trust description POST-PRICE-15995"); err != nil {
		t.Fatalf("post-price candidate edit: %v", err)
	}
	resp, herr := s.ShowConfig(ctx, req)
	if herr != nil {
		t.Fatalf("ShowConfig handler: %v", herr)
	}
	if strings.Contains(resp.Output, "POST-PRICE-15995") {
		t.Errorf("handler rendered a different generation than the gate priced:\n%s", resp.Output)
	}
	if !strings.Contains(resp.Output, "CANDIDATE-15995") {
		t.Errorf("priced snapshot lost its candidate content:\n%s", resp.Output)
	}
}

// Fold 3 (2): a candidate absent at pricing must render absent even if
// a candidate appears before the handler runs — never the live tree.
func TestShowConfigAbsentCandidateRendersAbsent15995(t *testing.T) {
	s := ancestor15995Server(t)
	// Exit config mode so no candidate exists at pricing time.
	s.store.ExitConfigure()
	req := &pb.ShowConfigRequest{Target: pb.ConfigTarget_CANDIDATE, Path: []string{"security", "zones"}}
	ctx, err := s.authorizeRPCContext(ctxWithPeerUID(uidAncestor15995), show14707Method("ShowConfig"), req)
	if err != nil {
		t.Fatalf("authorize absent candidate: %v", err)
	}
	// Another session stages a candidate AFTER pricing.
	if err := s.store.EnterConfigure(); err != nil {
		t.Fatalf("enter configure: %v", err)
	}
	defer s.store.ExitConfigure()
	if err := s.store.SetFromInput("security zones security-zone trust description LATE-CANDIDATE-15995"); err != nil {
		t.Fatalf("stage late candidate: %v", err)
	}
	resp, herr := s.ShowConfig(ctx, req)
	if herr != nil {
		t.Fatalf("ShowConfig: %v", herr)
	}
	if strings.Contains(resp.Output, "LATE-CANDIDATE-15995") || strings.Contains(resp.Output, "ZONE-DESC-15995") {
		t.Errorf("handler rendered live candidate created after pricing (priced absence violated):\n%s", resp.Output)
	}
}

// Fold 3 (4): candidate-baseline rollback compare with NO candidate
// must return the store's mode error, not a removals diff; the
// active-baseline twin (no candidate needed) still diffs.
func TestShowCompareNoCandidateMode15995(t *testing.T) {
	s := ancestor15995Server(t)
	s.store.ExitConfigure() // no candidate
	ctx := ctxWithPeerUID(uidAncestor15995)
	// Authorization itself admits (scoped path, allowed zones); the
	// handler must then refuse the candidate-baseline compare.
	actx, err := s.authorizeRPCContext(ctx, show14707Method("ShowCompare"),
		&pb.ShowCompareRequest{RollbackN: 1, Path: []string{"security", "zones"}})
	if err != nil {
		t.Fatalf("authorize scoped rollback compare: %v", err)
	}
	if _, herr := s.ShowCompare(actx, &pb.ShowCompareRequest{RollbackN: 1, Path: []string{"security", "zones"}}); herr == nil {
		t.Error("ShowCompare rollback-vs-candidate with no candidate SUCCEEDED (want mode error, #15995 fold3-4)")
	} else if !strings.Contains(herr.Error(), "not in configuration mode") {
		t.Errorf("ShowCompare no-candidate error = %v, want mode error", herr)
	}
	// Active-baseline twin succeeds without a candidate.
	bctx, err := s.authorizeRPCContext(ctx, show14707Method("ShowCompare"),
		&pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true, Path: []string{"security", "zones"}})
	if err != nil {
		t.Fatalf("authorize active-baseline compare: %v", err)
	}
	if _, herr := s.ShowCompare(bctx, &pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true, Path: []string{"security", "zones"}}); herr != nil {
		t.Errorf("active-baseline compare without candidate refused: %v", herr)
	}
}

func TestShowCompareRollbackAncestorDeniedDescendant15995(t *testing.T) {
	s := ancestor15995Server(t)
	ctx := ctxWithPeerUID(uidAncestor15995)

	wantDenied14707(t, "ShowCompare [security] candidate-vs-active (renders ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"),
			&pb.ShowCompareRequest{Path: []string{"security"}}))
	wantDenied14707(t, "ShowCompare [security] rollback-vs-candidate",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"),
			&pb.ShowCompareRequest{RollbackN: 1, Path: []string{"security"}}))
	wantDenied14707(t, "ShowCompare [security] active-baseline",
		s.authorizeRPC(ctx, show14707Method("ShowCompare"),
			&pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true, Path: []string{"security"}}))
	wantDenied14707(t, "ShowRollback 1 [security] (renders ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 1, Path: []string{"security"}}))
	wantDenied14707(t, "ShowRollback 0 [security] (active renders ipsec)",
		s.authorizeRPC(ctx, show14707Method("ShowRollback"),
			&pb.ShowRollbackRequest{N: 0, Path: []string{"security"}}))

	for _, tc := range []struct {
		what string
		m    string
		req  any
	}{
		{"ShowCompare [security zones]", "ShowCompare", &pb.ShowCompareRequest{Path: []string{"security", "zones"}}},
		{"ShowRollback 1 [security zones]", "ShowRollback", &pb.ShowRollbackRequest{N: 1, Path: []string{"security", "zones"}}},
		{"ShowRollback 1 [interfaces]", "ShowRollback", &pb.ShowRollbackRequest{N: 1, Path: []string{"interfaces"}}},
	} {
		if err := s.authorizeRPC(ctx, show14707Method(tc.m), tc.req); err != nil {
			t.Errorf("%s must stay admitted: %v", tc.what, err)
		}
	}

	// Unrestricted control: the ancestor read is admitted.
	ctxOpen := ctxWithPeerUID(uidOpen15995)
	if err := s.authorizeRPC(ctxOpen, show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE, Path: []string{"security"}}); err != nil {
		t.Errorf("open-view ShowConfig [security] must stay admitted: %v", err)
	}
}

// Fold 6: the whole-show arm must authorize with the snapshot's OWN
// cfg (scfg), not the cfg authorizeRPCContext read earlier. Witness:
// call the gate with a STALE cfg whose class carries no restriction
// (as if authorizeInputs raced a restricting commit) while the store
// snapshot's cfg restricts the class — whole show must refuse. The
// scoped arm already priced with scfg; the whole arm discarded it.
func TestShowWholePricesWithSnapshotCfg15995(t *testing.T) {
	s := ancestor15995Server(t)
	s.store.ExitConfigure()
	// Stale cfg: same classes, but ancestor-view WITHOUT the deny.
	staleCfg := func() *config.Config {
		tree, errs := config.NewParser(strings.Replace(ancestor15995Config,
			`deny-configuration "^security ipsec";`, ``, 1)).Parse()
		if len(errs) > 0 {
			t.Fatalf("stale fixture parse: %v", errs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("stale fixture compile: %v", err)
		}
		return cfg
	}()
	if _, restricted, err := config.ConfigurationLoginRegexesFor(staleCfg, "ancestor-view"); err != nil || restricted {
		t.Fatalf("stale fixture must be unrestricted (restricted=%v err=%v)", restricted, err)
	}
	if _, err := s.authorizeRPCConfigRead(staleCfg, "ancestor-view", show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}); err == nil {
		t.Error("whole ShowConfig priced with STALE cfg was ADMITTED though snapshot cfg restricts the class (#15995 fold6)")
	}
	// Control: with the store's current cfg it also refuses (above is
	// the discriminating cell only if stale alone changes the answer).
	if _, err := s.authorizeRPCConfigRead(s.store.ActiveConfig(), "ancestor-view", show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}); err == nil {
		t.Error("whole ShowConfig with current cfg admitted (control broken)")
	}
}

// Fold 6 handler-level witness: whole ShowConfig through
// authorizeRPCContext (the production interceptor path) + handler.
// The store restricts ancuser's class; authorize with the store's
// CURRENT cfg via the full context (which internally captures the
// snapshot cfg) — the handler must never be reached admitted. An
// admitted context that rendered (the pre-fix stale-pairing shape at
// handler level) fails here.
func TestShowWholeHandlerStaleInterleave15995(t *testing.T) {
	s := ancestor15995Server(t)
	s.store.ExitConfigure()
	ctx, err := s.authorizeRPCContext(ctxWithPeerUID(uidAncestor15995), show14707Method("ShowConfig"),
		wholeReq15995())
	if err == nil {
		resp, herr := s.ShowConfig(ctx, wholeReq15995())
		if herr != nil {
			t.Fatalf("handler err after admitted gate: %v", herr)
		}
		t.Fatalf("whole ShowConfig ADMITTED at handler for restricted class; output:\n%s", resp.Output)
	}
	// Open control through the same handler path renders.
	octx, err := s.authorizeRPCContext(ctxWithPeerUID(uidOpen15995), show14707Method("ShowConfig"), wholeReq15995())
	if err != nil {
		t.Fatalf("open whole authorize: %v", err)
	}
	resp, herr := s.ShowConfig(octx, wholeReq15995())
	if herr != nil {
		t.Fatalf("open whole handler: %v", herr)
	}
	if !strings.Contains(resp.Output, "ipsec") {
		t.Errorf("open whole render lost ipsec:\n%s", resp.Output)
	}
}


func wholeReq15995() *pb.ShowConfigRequest {
	return &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}
}

// Fold-6 strengthening (gRPC): force the stale interleave through the
// REAL gate entry (authorizeRPCConfigRead — the exact call
// authorizeRPCContext makes at authz.go) handing it the STALE cfg
// while the store snapshot is already restricted, then drive the
// HANDLER. Two facts established:
//  1. At the gate: stale cfg does NOT admit (gate re-reads cfg+tree in
//     the single ShowConfigSnapshot capture, store_format.go).
//  2. At the handler: an admitted context is the only route in; since
//     the gate refuses, construct the admitted-side control via the
//     open class and verify handler rendering, then verify the
//     restricted class cannot obtain an admitted context by ANY of
//     stale/current cfg through the gate entry.
// Production has no seam to inject a stale cfg INTO
// authorizeRPCContext itself (cfg := s.activeConfig() is read inside
// it immediately before the gate call, one statement, no hook) —
// by-construction: the only cfg the gate can price with besides the
// caller's is the single-capture scfg, which is what (1) exercises.
func TestShowWholeStaleGateThenHandler15995(t *testing.T) {
	s := ancestor15995Server(t)
	s.store.ExitConfigure()
	staleCfg := func() *config.Config {
		tree, errs := config.NewParser(strings.Replace(ancestor15995Config,
			`deny-configuration "^security ipsec";`, ``, 1)).Parse()
		if len(errs) > 0 {
			t.Fatalf("stale parse: %v", errs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("stale compile: %v", err)
		}
		return cfg
	}()
	// (1) Gate entry with stale cfg: refused + no snapshots rendered.
	snaps, err := s.authorizeRPCConfigRead(staleCfg, "ancestor-view", show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE})
	if err == nil {
		t.Fatalf("gate admitted stale cfg (snaps=%+v); handler would render", snaps)
	}
	// (2) Handler side: restricted class cannot get an admitted ctx
	// through authorizeRPCContext; open class can and renders.
	if _, err := s.authorizeRPCContext(ctxWithPeerUID(uidAncestor15995), show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE}); err == nil {
		t.Fatal("authorizeRPCContext admitted restricted whole show")
	}
	octx, err := s.authorizeRPCContext(ctxWithPeerUID(uidOpen15995), show14707Method("ShowConfig"),
		&pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE})
	if err != nil {
		t.Fatalf("open authorize: %v", err)
	}
	resp, herr := s.ShowConfig(octx, &pb.ShowConfigRequest{Target: pb.ConfigTarget_ACTIVE})
	if herr != nil || !strings.Contains(resp.Output, "ipsec") {
		t.Errorf("open handler render = herr=%v hasIpsec=%v", herr, herr == nil && strings.Contains(resp.Output, "ipsec"))
	}
}
