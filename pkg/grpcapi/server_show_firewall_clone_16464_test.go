package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16464: lenient clone counters must fold into the authored filter on the
// gRPC raw views. Probe acceptance: shared-fbf/steer prints 100 (40+60).
//
// FAIL-ON-REVERT: using the plain (config-less) counter index leaves the
// clone row under __xpf_11589_suppressed_N, which SortedFilterNames hides,
// so steer prints 40.
const clone16464Tree = `routing-instances {
    member-ri {
        instance-type vrf;
        interface ge-0/0/1.0;
    }
    steer-ri {
        instance-type forwarding;
    }
}
firewall {
    family inet {
        filter shared-fbf {
            term steer {
                from {
                    source-address {
                        192.0.2.0/24;
                    }
                }
                then count hits;
                then routing-instance steer-ri;
            }
        }
    }
}
interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                filter {
                    input shared-fbf;
                }
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                filter {
                    input shared-fbf;
                }
            }
        }
    }
}
`

func TestShowFirewallCloneCountersFold16464(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(clone16464Tree, nil); err != nil {
		t.Fatalf("SyncApply (lenient): %v", err)
	}
	cfg := store.ActiveConfig()
	cloneName := ""
	for name, f := range cfg.Firewall.FiltersInet {
		if src, _ := f.SuppressedMemberFBF11321(); src == "shared-fbf" {
			cloneName = name
		}
	}
	if cloneName == "" {
		t.Fatalf("premise: no clone synthesized in %+v", cfg.Firewall.FiltersInet)
	}
	s := &Server{store: store, dp: &firewallFilterShowUserspaceDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "shared-fbf", TermName: "steer", Packets: 40, Bytes: 4000},
			{Family: "inet", FilterName: cloneName, TermName: "steer", Packets: 60, Bytes: 6000},
		}},
	}}
	var buf strings.Builder
	s.showFirewall(cfg, &buf)
	out := buf.String()
	if !strings.Contains(out, "Hit count: 100 packets, 10000 bytes") {
		t.Fatalf("showFirewall = %q, want folded Hit count: 100 packets, 10000 bytes", out)
	}
	if strings.Contains(out, cloneName) {
		t.Fatalf("showFirewall leaks clone name %q: %q", cloneName, out)
	}
	if strings.Count(out, "Hit count:") != 1 {
		t.Fatalf("showFirewall = %q, want exactly one hit-count line", out)
	}
	// Single-filter topic.
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-filter:shared-fbf"})
	if err != nil {
		t.Fatalf("ShowText single: %v", err)
	}
	if out := resp.GetOutput(); !strings.Contains(out, "Hit count: 100 packets, 10000 bytes") {
		t.Fatalf("showFirewallFilter = %q, want folded 100/10000", out)
	}
}
