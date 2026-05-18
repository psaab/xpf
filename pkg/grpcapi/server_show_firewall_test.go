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

type firewallFilterShowUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (f *firewallFilterShowUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

func newFirewallFilterShowStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter bandwidth-output term 0 from destination-port 80",
		"firewall family inet filter bandwidth-output term 0 then accept",
		"firewall family inet6 filter bandwidth-output term 0 from destination-port 5201",
		"firewall family inet6 filter bandwidth-output term 0 then count iperf-a-v6",
		"firewall family inet6 filter bandwidth-output term 0 then accept",
		"firewall family inet6 filter bandwidth-output term 1 from destination-port 5300",
		"firewall family inet6 filter bandwidth-output term 1 then accept",
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

func TestShowTextFirewallFilterHonorsFamilyAndUserspaceCounters(t *testing.T) {
	store := newFirewallFilterShowStore(t)
	s := &Server{
		store: store,
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
					{
						Family:     "inet6",
						FilterName: "bandwidth-output",
						TermName:   "0",
						Packets:    7,
						Bytes:      1024,
					},
				},
			},
		},
	}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-filter:bandwidth-output:inet6"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	out := resp.GetOutput()
	if !strings.Contains(out, "Filter: bandwidth-output (family inet6)") {
		t.Fatalf("output = %q, want inet6 filter heading", out)
	}
	if strings.Contains(out, "destination-port 80") {
		t.Fatalf("output = %q, unexpectedly rendered inet family term", out)
	}
	if !strings.Contains(out, "destination-port 5201") {
		t.Fatalf("output = %q, want inet6 destination-port 5201", out)
	}
	if !strings.Contains(out, "Hit count: 7 packets, 1024 bytes") {
		t.Fatalf("output = %q, want userspace hit counters", out)
	}
	if strings.Count(out, "Hit count:") != 1 {
		t.Fatalf("output = %q, want a hit count only for the counted term", out)
	}
}

func TestShowTextScreenSYNCookieCounterRowsUsesUserspaceStatus(t *testing.T) {
	s := &Server{
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				Bindings: []dpuserspace.BindingStatus{
					{
						SYNCookieChallenges:        2,
						SYNCookieSecretUnavailable: 3,
						SYNCookieAckValid:          5,
						SYNCookieAckInvalid:        7,
						SYNCookieBypass:            11,
					},
					{
						SYNCookieChallenges:        13,
						SYNCookieSecretUnavailable: 17,
						SYNCookieAckValid:          19,
						SYNCookieAckInvalid:        23,
						SYNCookieBypass:            29,
					},
				},
			},
		},
	}

	out := s.screenSYNCookieCounterRows()
	for _, want := range []string{
		"Userspace SYN-cookie scope",
		"all bindings",
		"SYN-cookie challenges",
		"15",
		"SYN-cookie secret unavailable",
		"20",
		"SYN-cookie ACK valid",
		"24",
		"SYN-cookie ACK invalid",
		"30",
		"SYN-cookie bypass",
		"40",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("screen SYN-cookie rows missing %q:\n%s", want, out)
		}
	}
}
