package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #10235 agreement cell: the local CLI and gRPC surfaces must render the
// per-instance inet6.0 statics from the same compiled Config. Before the fix,
// both independent loops visited only ri.StaticRoutes, so the v6 rows and
// their StaticRouteExclusions verdicts were absent from both surfaces.
//
// RED-ON-REVERT: remove either surface's Inet6StaticRoutes loop and the
// extracted static block disagrees, while the anti-vacuity assertions below
// still require all configured v6 rows and the refusal reason.
func TestRoutingInstancesDetailInet6SurfacesAgree_10235(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	cfg, err := store.SyncApply(`routing-instances {
    target {
        instance-type virtual-router;
    }
    holder {
        instance-type virtual-router;
        routing-options {
            static {
                route 192.168.0.0/16 {
                    next-hop 10.0.0.1;
                }
            }
            rib inet6.0 {
                static {
                    route 2001:db8:100::/48 {
                        next-table target.inet6.0;
                    }
                    route 2001:db8:200::/48 {
                        next-hop 2001:db8::1;
                    }
                    route 2001:db8:300::/48 discard;
                }
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply() error = %v — the fixture's premise is that the tolerant ingress admits a per-instance inet6 next-table row", err)
	}

	var v6LeakFound bool
	var v6Count int
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name != "holder" {
			continue
		}
		v6Count = len(ri.Inet6StaticRoutes)
		for _, sr := range ri.Inet6StaticRoutes {
			if sr != nil && sr.NextTable != "" {
				v6LeakFound = true
			}
		}
	}
	if !v6LeakFound || v6Count != 3 {
		t.Fatalf("tolerant sync did not compile all three holder inet6 statics: found leak=%v count=%d", v6LeakFound, v6Count)
	}

	const wantReason = "NOT INSTALLED: next-table is not supported under a routing-instance — no ip rule is installed for it"
	srv := grpcapi.NewServer("", grpcapi.Config{Store: store})
	resp, err := srv.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "routing-instances-detail"})
	if err != nil {
		t.Fatalf("ShowText(routing-instances-detail): %v", err)
	}
	cliOut := captureStdout(t, func() {
		if err := (&CLI{store: store}).showRoutingInstances(true); err != nil {
			t.Fatalf("showRoutingInstances(true): %v", err)
		}
	})

	grpcBlock := inet6StaticBlock10235(resp.GetOutput())
	cliBlock := inet6StaticBlock10235(cliOut)
	if grpcBlock != cliBlock {
		t.Fatalf("the CLI and gRPC `routing-instances-detail` surfaces disagree about per-instance statics:\n  gRPC: %q\n  CLI:  %q", grpcBlock, cliBlock)
	}

	// Anti-vacuity: agreement must contain the v4 block unchanged, the new v6
	// block, all three v6 rows, and the one builder refusal reason.
	for _, want := range []string{
		"Static routes: 1",
		"Static routes (inet6.0): 3",
		"2001:db8:100::/48 -> next-table target",
		"2001:db8:200::/48 -> 2001:db8::1",
		"2001:db8:300::/48 -> discard",
		wantReason,
	} {
		if !strings.Contains(grpcBlock, want) {
			t.Errorf("agreed static block omits %q:\n%s", want, grpcBlock)
		}
	}
	if n := strings.Count(grpcBlock, "NOT INSTALLED"); n != 1 {
		t.Errorf("agreed v6 static block has %d NOT INSTALLED annotations, want exactly 1:\n%s", n, grpcBlock)
	}
}

func inet6StaticBlock10235(out string) string {
	start := strings.Index(out, "Instance: holder\n")
	if start < 0 {
		return ""
	}
	block := out[start:]
	if end := strings.Index(block, "\nInstance: "); end >= 0 {
		block = block[:end]
	}
	var rows []string
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "Static routes") || strings.Contains(trimmed, "->") || strings.HasPrefix(trimmed, "NOT INSTALLED") {
			rows = append(rows, trimmed)
		}
	}
	return strings.Join(rows, "\n")
}
