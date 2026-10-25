package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16547: a runtime-quarantined rule (iface_snat_egress_overlap on the
// applied snapshot) must surface as not_installed on the structured gRPC
// surfaces. The config-only verdict cannot see it — the pool definition
// is usable — so without the runtime fold these tests fail.

type natVerdictsGRPCDP struct {
	*dataplane.Manager
	verdicts dpuserspace.AppliedNATSnapshotVerdicts
}

func (d *natVerdictsGRPCDP) IsLoaded() bool { return true }
func (d *natVerdictsGRPCDP) AppliedNATSnapshotVerdicts() dpuserspace.AppliedNATSnapshotVerdicts {
	return d.verdicts
}

func quarantinedVerdicts16547() dpuserspace.AppliedNATSnapshotVerdicts {
	return dpuserspace.AppliedNATSnapshotVerdicts{
		Available:      true,
		SourceNATRules: map[string]string{"r1": "iface_snat_egress_overlap"},
		SourceNATPools: map[string]string{"p1": "iface_snat_egress_overlap"},
		NAT64Rules:     map[string]string{},
	}
}

func TestGetNATRuleStatsRuntimeQuarantine16547(t *testing.T) {
	srv := natStructuredServer(t, sourceCfg("203.0.113.10/32"))
	srv.dp = &natVerdictsGRPCDP{Manager: dataplane.New(), verdicts: quarantinedVerdicts16547()}

	resp, err := srv.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATRuleStats: %v", err)
	}
	if len(resp.GetRules()) != 1 {
		t.Fatalf("want 1 rule, got %d", len(resp.GetRules()))
	}
	r := resp.GetRules()[0]
	if !r.GetNotInstalled() {
		t.Fatal("runtime-quarantined rule reports not_installed=false; the config-only verdict cannot see iface_snat_egress_overlap (#16547)")
	}
	if !strings.Contains(r.GetNotInstalledReason(), "interface") {
		t.Errorf("reason = %q, want prose naming the interface-SNAT overlap", r.GetNotInstalledReason())
	}

	// GetNATSource must agree.
	src, err := srv.GetNATSource(context.Background(), &pb.GetNATSourceRequest{})
	if err != nil {
		t.Fatalf("GetNATSource: %v", err)
	}
	if len(src.GetRules()) != 1 || !src.GetRules()[0].GetNotInstalled() {
		t.Fatalf("GetNATSource disagrees: %+v", src.GetRules())
	}

	// GetNATPoolStats must agree at pool level.
	pools, err := srv.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats: %v", err)
	}
	found := false
	for _, p := range pools.GetPools() {
		if p.GetName() == "p1" {
			found = true
			if !p.GetNotInstalled() {
				t.Error("pool p1 reports not_installed=false under runtime quarantine")
			}
			if p.GetTotalPorts() != 0 {
				t.Errorf("quarantined pool total_ports = %d, want 0", p.GetTotalPorts())
			}
		}
	}
	if !found {
		t.Fatal("pool p1 missing from GetNATPoolStats")
	}
}

func TestGetNATRuleStatsRuntimeControlArmed16547(t *testing.T) {
	// Available runtime view with no quarantine: rule stays armed.
	srv := natStructuredServer(t, sourceCfg("203.0.113.10/32"))
	srv.dp = &natVerdictsGRPCDP{Manager: dataplane.New(), verdicts: dpuserspace.AppliedNATSnapshotVerdicts{
		Available:      true,
		SourceNATRules: map[string]string{},
		SourceNATPools: map[string]string{},
		NAT64Rules:     map[string]string{},
	}}
	resp, err := srv.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATRuleStats: %v", err)
	}
	if len(resp.GetRules()) != 1 || resp.GetRules()[0].GetNotInstalled() {
		t.Fatalf("armed control marked not_installed: %+v", resp.GetRules())
	}

	// Unavailable runtime view (no provider verdicts): also armed.
	srv2 := natStructuredServer(t, sourceCfg("203.0.113.10/32"))
	resp2, err := srv2.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATRuleStats (no dp): %v", err)
	}
	if len(resp2.GetRules()) != 1 || resp2.GetRules()[0].GetNotInstalled() {
		t.Fatalf("no-runtime control marked not_installed: %+v", resp2.GetRules())
	}
}
