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

func TestCrossFamilyStaticRouteExclusionSurfacesAgree11421(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	cfg, err := store.SyncApply(`routing-options {
    static {
        route 10.0.0.0/8 {
            next-hop 2001:db8::1;
            next-hop 192.0.2.1;
        }
        route 192.168.0.0/16 {
            next-hop 192.0.2.254;
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply() error = %v — the tolerant peer-sync path must retain the rejected route for annotation", err)
	}

	var bad, healthy *config.StaticRoute
	for _, route := range cfg.RoutingOptions.StaticRoutes {
		switch route.Destination {
		case "10.0.0.0/8":
			bad = route
		case "192.168.0.0/16":
			healthy = route
		}
	}
	if bad == nil || healthy == nil {
		t.Fatalf("tolerant sync did not compile both route fixtures: %+v", cfg.RoutingOptions.StaticRoutes)
	}
	wantReason := config.StaticRouteNextHopFamilyMismatchReason(bad)
	if wantReason == "" {
		t.Fatal("fixture does not carry a cross-family gateway")
	}
	excluded := config.StaticRouteExclusions(cfg)
	if got := excluded[bad]; got != wantReason {
		t.Fatalf("shared exclusion = %q, want %q", got, wantReason)
	}
	if got := excluded[healthy]; got != "" {
		t.Fatalf("same-family control route exclusion = %q", got)
	}

	grpcServer := grpcapi.NewServer("", grpcapi.Config{Store: store})
	grpcResp, err := grpcServer.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "routing-options"})
	if err != nil {
		t.Fatalf("ShowText(routing-options): %v", err)
	}
	cliOut := captureStdout(t, func() {
		if err := (&CLI{store: store}).showRoutingOptions(); err != nil {
			t.Fatalf("showRoutingOptions(): %v", err)
		}
	})

	for name, out := range map[string]string{"CLI": cliOut, "gRPC": grpcResp.GetOutput()} {
		if !strings.Contains(out, bad.Destination) || !strings.Contains(out, "NOT INSTALLED: "+wantReason) {
			t.Errorf("%s does not annotate the excluded route with the shared reason:\n%s", name, out)
		}
		if !strings.Contains(out, healthy.Destination) || strings.Count(out, "NOT INSTALLED") != 1 {
			t.Errorf("%s omitted the healthy control or annotated it:\n%s", name, out)
		}
	}
}
func TestStaticRouteTierPreferencesVisibleOnCLIAndGRPC_12084(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	_, err := store.SyncApply(`routing-options {
    static {
        route 2602:ffd3::/40 {
            next-hop 2602:ffd3:ffff::1;
            preference 5;
        }
    }
    rib inet6.0 {
        static {
            route 2602:ffd3::/40 {
                next-hop 2602:ffd3:ffff::2;
                preference 200;
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply: %v", err)
	}

	grpcServer := grpcapi.NewServer("", grpcapi.Config{Store: store})
	grpcResp, err := grpcServer.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "routing-options"})
	if err != nil {
		t.Fatalf("ShowText(routing-options): %v", err)
	}
	cliOut := captureStdout(t, func() {
		if err := (&CLI{store: store}).showRoutingOptions(); err != nil {
			t.Fatalf("showRoutingOptions: %v", err)
		}
	})
	wants := map[string]string{
		"2602:ffd3:ffff::1": "5",
		"2602:ffd3:ffff::2": "200",
	}
	for surface, output := range map[string]string{"CLI": cliOut, "gRPC": grpcResp.GetOutput()} {
		for gateway, preference := range wants {
			var rows []string
			for _, line := range strings.Split(output, "\n") {
				if strings.Contains(line, gateway) {
					rows = append(rows, line)
				}
			}
			if len(rows) != 1 {
				t.Errorf("%s rows for %s = %q, want one row", surface, gateway, rows)
				continue
			}
			fields := strings.Fields(rows[0])
			if len(fields) == 0 || fields[len(fields)-1] != preference {
				t.Errorf("%s row = %q, want per-tier preference %s", surface, rows[0], preference)
			}
		}
	}
}
