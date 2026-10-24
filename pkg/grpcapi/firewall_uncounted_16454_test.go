package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16454: gRPC mirror of pkg/cli firewall_uncounted_16454_test.go — an
// uncounted term must never render a numeric Hit count even when a
// legacy helper publishes a row for it; a counted-but-idle term still
// renders 0.
//
// FAIL-ON-REVERT: dropping `term.Count != ""` from the Hit-count
// conditions in server_show_firewall.go re-renders the uncounted term's
// published 0 and the count==1 check goes RED.
func newUncounted16454Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter edge term block from destination-port 22",
		"firewall family inet filter edge term block then discard",
		"firewall family inet filter edge term counted-idle from destination-port 80",
		"firewall family inet filter edge term counted-idle then count hits",
		"firewall family inet filter edge term counted-idle then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func uncounted16454Server(store *configstore.Store) *Server {
	return &Server{
		store: store,
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
					{Family: "inet", FilterName: "edge", TermName: "block", TermOrdinal: 0, Packets: 0, Bytes: 0},
					{Family: "inet", FilterName: "edge", TermName: "counted-idle", TermOrdinal: 1, Packets: 0, Bytes: 0},
				},
			},
		},
	}
}

func assertUncounted16454(t *testing.T, out string) {
	t.Helper()
	if strings.Count(out, "Hit count:") != 1 {
		t.Fatalf("output = %q, want exactly one Hit count (counted-idle only)", out)
	}
	if !strings.Contains(out, "Hit count: 0 packets, 0 bytes") {
		t.Fatalf("output = %q, want counted-but-idle term to render 0", out)
	}
	idx := strings.Index(out, "Term: block")
	if idx < 0 {
		t.Fatalf("output = %q, want block term rendered", out)
	}
	seg := out[idx:]
	if next := strings.Index(seg, "Term: counted-idle"); next >= 0 {
		seg = seg[:next]
	}
	if strings.Contains(seg, "Hit count:") {
		t.Fatalf("output = %q, uncounted term rendered a numeric Hit count (#16454)", out)
	}
}

func TestShowTextFirewallUncountedTermNoHitCount16454(t *testing.T) {
	s := uncounted16454Server(newUncounted16454Store(t))
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall"})
	if err != nil {
		t.Fatalf("ShowText(firewall) error = %v", err)
	}
	assertUncounted16454(t, resp.GetOutput())
}

func TestShowTextFirewallFilterUncountedTermNoHitCount16454(t *testing.T) {
	s := uncounted16454Server(newUncounted16454Store(t))
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-filter:edge"})
	if err != nil {
		t.Fatalf("ShowText(firewall-filter:edge) error = %v", err)
	}
	assertUncounted16454(t, resp.GetOutput())
}
