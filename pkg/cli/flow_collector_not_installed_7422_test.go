// #6565 row 11 / #7422: `show security flow monitoring` and `show
// forwarding-options` rendered every configured flow-server straight from
// config, so a collector buildFlowExportSnapshots SKIPS printed as an active
// export target. Port 0 is the worst shape — the CLI suppresses the `:0`
// suffix, so `Collector: 10.0.0.1` is indistinguishable from a healthy
// collector on a default port, and the builder's port-0 branch did not even
// warn (unlike its out-of-range sibling), so there was no journal record
// either.
//
// Reachability is NOT the lenient-load backstop the NAT/CoS families need:
// nothing validates a flow-server port at commit, so the fixture below reaches
// the state through an ORDINARY commit.
package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// flowCollectorStore commits one installable collector and one the builder
// skips.
//
// Two collectors, not one: with a single skipped collector a renderer that
// annotated unconditionally would pass every cell. The armed one is the
// negative control that makes "annotates" mean "annotates the right one".
func flowCollectorStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
forwarding-options {
    sampling {
        instance s1 {
            input {
                rate 100;
            }
            family inet {
                output {
                    flow-server 10.0.0.1 {
                        port 2055;
                    }
                    flow-server 10.0.0.2;
                }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v — the fixture's premise is that a "+
			"flow-server with no `port` commits cleanly. If a strict gate now "+
			"rejects it, this row is reachable only through the lenient "+
			"Load/SyncApply path and the fixture must move there, not relax", err)
	}
	cfg := store.ActiveConfig()
	inst := cfg.ForwardingOptions.Sampling.Instances["s1"]
	if inst == nil || inst.FamilyInet == nil || len(inst.FamilyInet.FlowServers) != 2 {
		t.Fatalf("compiled sampling instance = %+v, want 2 flow-servers", inst)
	}
	// Ground truth. Without this pin a compiler that started defaulting the
	// port would make every assertion below agree on "nothing to annotate" and
	// the file would pass over an empty set.
	var armed, dropped *config.FlowServer
	for _, fs := range inst.FamilyInet.FlowServers {
		switch fs.Address {
		case "10.0.0.1":
			armed = fs
		case "10.0.0.2":
			dropped = fs
		}
	}
	if armed == nil || dropped == nil {
		t.Fatalf("fixture collectors not both compiled: %+v", inst.FamilyInet.FlowServers)
	}
	if got := config.FlowServerExcludedReason(dropped); got == "" {
		t.Fatalf("fixture no longer constructs a skipped collector (port = %d)", dropped.Port)
	}
	if got := config.FlowServerExcludedReason(armed); got != "" {
		t.Fatalf("fixture's healthy collector is not healthy: reason = %q", got)
	}
	return store
}

// TestCLIFlowCollectorSurfacesAnnotateTheSkippedCollector7422 drives BOTH local
// renderers over one config and requires the same verdict from each. Deleting
// the annotation from either reds exactly one subtest.
func TestCLIFlowCollectorSurfacesAnnotateTheSkippedCollector7422(t *testing.T) {
	store := flowCollectorStore(t)
	c := &CLI{store: store}

	surfaces := []struct {
		name   string
		render func() error
	}{
		{"show_security_flow_monitoring", c.showFlowMonitoring},
		{"show_forwarding-options", c.showForwardingOptions},
	}

	for _, s := range surfaces {
		t.Run(s.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := s.render(); err != nil {
					t.Fatalf("%s: %v", s.name, err)
				}
			})

			dropped := collectorLine7422(t, out, "10.0.0.2")
			if !strings.Contains(dropped, "NOT INSTALLED") {
				t.Fatalf("%s renders a collector the snapshot builder SKIPS as an "+
					"active export target — the operator sees a collector that "+
					"receives nothing.\n--- line ---\n%s\n--- output ---\n%s",
					s.name, dropped, out)
			}
			if !strings.Contains(dropped, "no `port` configured") {
				t.Fatalf("%s annotated the skipped collector without naming the "+
					"cause, so the operator cannot tell WHICH condition dropped "+
					"it.\n--- line ---\n%s", s.name, dropped)
			}

			armed := collectorLine7422(t, out, "10.0.0.1")
			if strings.Contains(armed, "NOT INSTALLED") {
				t.Fatalf("%s annotated a collector the dataplane DOES install — "+
					"crying wolf on a working export.\n--- line ---\n%s", s.name, armed)
			}
		})
	}
}

// collectorLine7422 returns the single render line for one collector, so an
// assertion cannot be satisfied by an annotation printed against the OTHER
// collector. Matching "NOT INSTALLED" anywhere in the whole output would pass
// for a renderer that annotated the healthy one.
func collectorLine7422(t *testing.T, out, addr string) string {
	t.Helper()
	// #16723: the two surfaces label the same collector differently
	// ("Collector:" in showFlowMonitoring, "Flow server:" in
	// showForwardingOptions), and one surface's block can contain the
	// other label's address line — matching on the address alone
	// collected both. Isolate by the surface's own label.
	var hits []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, addr) && (strings.Contains(l, "Collector:") || strings.Contains(l, "Flow server:")) {
			hits = append(hits, l)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("expected exactly 1 render line for collector %s, found %d "+
			"(%v) — the block extractor no longer isolates one collector and "+
			"the assertions below would be reading the wrong one\n--- output ---\n%s",
			addr, len(hits), hits, out)
	}
	return hits[0]
}
