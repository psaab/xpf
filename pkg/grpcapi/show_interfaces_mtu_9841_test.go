package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// mtuShowGRPCDP9841 is a grpcRuntime fake publishing a scripted last-apply
// result. It embeds *dataplane.Manager to satisfy the rest of the
// interface and overrides only IsLoaded + LastApplyResult.
type mtuShowGRPCDP9841 struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *mtuShowGRPCDP9841) IsLoaded() bool                          { return false }
func (d *mtuShowGRPCDP9841) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }

func mtuLoGRPC9841(t *testing.T, dp *mtuShowGRPCDP9841) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    lo { unit 0 { family inet { address 127.0.0.2/32; } } }
}
security {
    zones {
        security-zone trust {
            interfaces { lo.0; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store, dp: dp}
}

// The remote text twin annotates the same phys row the local CLI does, from
// the same last-apply records through the same shared helper — and a
// row-consumed record never reprints as a leftover.
func TestShowInterfacesDetailMTUAnnotate9841(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	rec := dataplane.MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: lo.MTU + 1000, LiveMTU: lo.MTU, Grade: dataplane.MTUGradeWriteFailed,
		ExpectIfindex: lo.Index, Detail: "refused"}
	s := mtuLoGRPC9841(t, &mtuShowGRPCDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}})
	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail: %v", err)
	}
	if !strings.Contains(resp.Output, "Physical interface: lo") {
		t.Fatalf("fixture did not render the lo phys row:\n%s", resp.Output)
	}
	if !strings.Contains(resp.Output, "MTU unconverged: ") {
		t.Errorf("twin phys row missing its annotation:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "no matching interface row") {
		t.Errorf("row-consumed record reprinted as a leftover:\n%s", resp.Output)
	}
}

// Rowless records render in the twin's leftover section on an unfiltered
// query — and ahead of the not-found line when the filter matches no row
// (the twin answers with output, not a Go error, like the local error path
// prints before returning).
func TestShowInterfacesDetailMTULeftover9841(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	rec := dataplane.MTUUnconverged{Name: "ge-0-0-9", ConfigRef: "ge-0/0/9",
		WantMTU: 9000, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed, Detail: "refused"}
	s := mtuLoGRPC9841(t, &mtuShowGRPCDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}})

	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail: %v", err)
	}
	for _, want := range []string{"MTU unconverged (no matching interface row):", "ge-0/0/9"} {
		if !strings.Contains(resp.Output, want) {
			t.Errorf("unfiltered twin missing leftover %q:\n%s", want, resp.Output)
		}
	}

	resp, err = s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{Filter: "ge-0/0/9"})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail: %v", err)
	}
	for _, want := range []string{"MTU unconverged (no matching interface row):", "ge-0/0/9", "not found in configuration"} {
		if !strings.Contains(resp.Output, want) {
			t.Errorf("filtered twin missing %q:\n%s", want, resp.Output)
		}
	}
}

// #9841 marker survival: a record the daemon wrapper syncs onto the
// compiled object applyAndSyncCommitted returns must reach the Commit RPC
// response through the generic configWarnings projection — no per-advisory
// transport wiring. CommitCheck, which runs no apply, carries no marker.
func TestCommitCarriesMTUUnconvergedMarker9841(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set interfaces lo unit 0 description mtu-marker"); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	rec := dataplane.MTUUnconverged{Name: "ge-0-0-9", ConfigRef: "ge-0/0/9",
		WantMTU: 9000, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed}
	s := &Server{
		store: store,
		commitFn: func(_ context.Context, _ configstore.CommitAuthority, _ string) (*config.Config, error) {
			compiled, err := store.Commit()
			if err != nil {
				return nil, err
			}
			// What the daemon's applyConfigLockedForCommit returns post-apply:
			// a response copy projecting the records, never the applied
			// object itself.
			return dataplane.WithMTUWarningsForResponse9841(compiled, []dataplane.MTUUnconverged{rec}), nil
		},
	}

	chk, err := s.CommitCheck(context.Background(), &pb.CommitCheckRequest{})
	if err != nil {
		t.Fatalf("CommitCheck RPC: %v", err)
	}
	if n := countMentioning(chk.Warnings, "interface MTU not realized"); n != 0 {
		t.Errorf("CommitCheck carried %d MTU markers, want 0 (no apply ran); got %v", n, chk.Warnings)
	}

	cm, err := s.Commit(context.Background(), &pb.CommitRequest{})
	if err != nil {
		t.Fatalf("Commit RPC: %v", err)
	}
	if n := countMentioning(cm.Warnings, "interface MTU not realized"); n != 1 {
		t.Errorf("Commit delivered %d MTU markers, want 1; got %v", n, cm.Warnings)
	}
	if n := countMentioning(cm.Warnings, "ge-0/0/9"); n != 1 {
		t.Errorf("Commit marker names the wrong ref; got %v", cm.Warnings)
	}
}

// Twin of the local aliased-spelling cell: a "lo.080" zone member matches
// the record carrying the same authored ConfigRef exactly.
func TestShowInterfacesDetailMTUAliasedRef9841(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    lo {
        vlan-tagging;
        unit 80 { vlan-id 80; family inet { address 127.0.0.2/32; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { lo.080; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	rec := dataplane.MTUUnconverged{Name: "lo.80", ConfigRef: "lo.080",
		WantMTU: 1500, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed}
	s := &Server{store: store, dp: &mtuShowGRPCDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}}
	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail: %v", err)
	}
	if !strings.Contains(resp.Output, "Logical interface lo.80") {
		t.Fatalf("fixture did not render the lo.80 unit section:\n%s", resp.Output)
	}
	if !strings.Contains(resp.Output, "MTU unconverged: ") {
		t.Errorf("twin aliased row missing its annotation:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "no matching interface row") {
		t.Errorf("exactly-matched record reprinted as a leftover:\n%s", resp.Output)
	}
}

// Twin of the local member-fallback cell: the reth unit row falls back
// through the actual member child.
func TestShowInterfacesDetailMTUMemberFallback9841(t *testing.T) {
	s := rethShowGRPCStore(t)
	rec := dataplane.MTUUnconverged{Name: "ge-0-0-2.50", ConfigRef: "ge-0/0/2.50",
		WantMTU: 9000, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed}
	s.dp = &mtuShowGRPCDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}
	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{Filter: "reth0"})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail: %v", err)
	}
	if !strings.Contains(resp.Output, "MTU unconverged: ") {
		t.Errorf("twin reth row missing its member-fallback annotation:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "no matching interface row") {
		t.Errorf("fallback-consumed record reprinted as a leftover:\n%s", resp.Output)
	}
}
