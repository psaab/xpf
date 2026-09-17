package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #10001 agreement cell: the local CLI and the gRPC surface render
// `routing-instances-detail` from independent copies of the instance-static
// loop, and the gRPC copy omitted next-table rows (no NextHops → no row) plus
// every exclusion reason. The two surfaces must list the SAME rows with the
// SAME reasons on the same config.
//
// The fixture is ingested through the REAL tolerant ingress
// (Store.SyncApply → compileTreeLenient), not a hand-built Config: a
// per-instance next-table is hard-rejected at strict commit (#5830), so the
// state under test exists only on the lenient load / peer-sync path —
// exactly when the operator most needs the surface to name the drop.
//
// Why AGREEMENT and not a literal: the CLI twin is the reference shape, and
// pinning the gRPC side to a literal it wrote itself cannot catch the next
// one-copy-only drift (#7357 §3). Agreement alone is not enough either — two
// surfaces broken identically agree — so both sides are also anchored to
// config.StaticRouteExclusions, the verdict the builder consults (third
// party, not a literal).
//
// RED-ON-REVERT: drop the NextTable arm from the gRPC renderer and the gRPC
// block loses the row while the CLI block keeps it — the sides disagree and
// the gRPC side disagrees with the verdict.
func TestRoutingInstancesDetailNextTableSurfacesAgree_10001(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	cfg, err := store.SyncApply(`routing-instances {
    target {
        instance-type virtual-router;
    }
    leaker {
        instance-type virtual-router;
        routing-options {
            static {
                route 10.0.0.0/8 {
                    next-table target.inet.0;
                }
                route 192.168.0.0/16 {
                    next-hop 10.0.0.1;
                }
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply() error = %v — the fixture's premise is that the LENIENT "+
			"peer-sync path admits a per-instance next-table (the strict commit gate "+
			"rejects it, #5830). If sync now rejects it too, this state is "+
			"unreachable and the test must be rewritten, not relaxed", err)
	}

	// Ground truth. Without these pins a predicate that stopped recognising
	// the shape would make both surfaces agree on "installed" and the whole
	// cell would pass over an empty set.
	var leak, healthy *config.StaticRoute
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name != "leaker" {
			continue
		}
		for _, sr := range ri.StaticRoutes {
			switch {
			case sr.NextTable != "":
				leak = sr
			default:
				healthy = sr
			}
		}
	}
	if leak == nil || healthy == nil {
		t.Fatalf("tolerant sync did not compile both fixture routes: %+v", cfg.RoutingInstances)
	}
	const wantReason = "next-table is not supported under a routing-instance — no ip rule is installed for it"
	excluded := config.StaticRouteExclusions(cfg)
	if got := excluded[leak]; got != wantReason {
		t.Fatalf("fixture no longer constructs a dropped next-table leak: reason = %q, want %q", got, wantReason)
	}
	if got := excluded[healthy]; got != "" {
		t.Fatalf("fixture's healthy route is not healthy: reason = %q", got)
	}

	srv := grpcapi.NewServer("", grpcapi.Config{Store: store})
	c := &CLI{store: store}

	resp, err := srv.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "routing-instances-detail"})
	if err != nil {
		t.Fatalf("ShowText(routing-instances-detail): %v", err)
	}
	grpcBlock := nextTableStaticBlock10001(resp.GetOutput())
	cliOut := captureStdout(t, func() {
		if err := c.showRoutingInstances(true); err != nil {
			t.Fatalf("showRoutingInstances(true): %v", err)
		}
	})
	cliBlock := nextTableStaticBlock10001(cliOut)

	// 1. THE AGREEMENT. Neither side is pinned to a literal; they are pinned
	//    to each other.
	if strings.Join(grpcBlock, "\n") != strings.Join(cliBlock, "\n") {
		t.Errorf("the two `routing-instances-detail` surfaces disagree about the "+
			"instance statics.\n  gRPC (what the REMOTE cli prints): %q"+
			"\n  local CLI: %q", grpcBlock, cliBlock)
	}

	// 2. ANTI-VACUITY. Two surfaces broken identically agree, so the shared
	//    block must carry the leak row AND its builder verdict — the whole
	//    point of rendering it.
	joined := strings.Join(grpcBlock, "\n")
	if !strings.Contains(joined, "10.0.0.0/8 -> next-table target") {
		t.Errorf("neither surface renders the configured next-table row — the "+
			"agreement above is vacuous. gRPC block: %q", grpcBlock)
	}
	if !strings.Contains(joined, "NOT INSTALLED: "+wantReason) {
		t.Errorf("neither surface carries the leak's exclusion reason — the "+
			"agreement above is vacuous. gRPC block: %q", grpcBlock)
	}
	// 3. Negative control on BOTH sides: exactly one annotation each — the
	//    healthy route must stay quiet everywhere.
	if n := strings.Count(resp.GetOutput(), "NOT INSTALLED"); n != 1 {
		t.Errorf("gRPC NOT INSTALLED annotations = %d, want exactly 1:\n%s", n, resp.GetOutput())
	}
	if n := strings.Count(cliOut, "NOT INSTALLED"); n != 1 {
		t.Errorf("CLI NOT INSTALLED annotations = %d, want exactly 1:\n%s", n, cliOut)
	}
}

// nextTableStaticBlock10001 extracts the static-route rows and their
// annotations from a rendered `routing-instances-detail`, in order. Comparing
// the BLOCK rather than one line is deliberate: the row without its reason
// reads as installed, and the reason without its row is unattributable.
func nextTableStaticBlock10001(out string) []string {
	var got []string
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if strings.Contains(t, "->") || strings.HasPrefix(t, "NOT INSTALLED") {
			got = append(got, t)
		}
	}
	return got
}
