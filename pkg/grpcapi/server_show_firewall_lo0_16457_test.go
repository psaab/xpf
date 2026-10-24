package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #16457: gRPC `show firewall filter <lo0-filter>` and `show firewall`
// render the kernel inet xpf_lo0 count; non-lo0 filters are unchanged.
func TestShowTextFirewallFilterLo0KernelCounter16457(t *testing.T) {
	orig := readLo0CountersGRPC
	defer func() { readLo0CountersGRPC = orig }()
	calls := 0
	readLo0CountersGRPC = func() ([]xnft.Lo0Count, error) {
		calls++
		return []xnft.Lo0Count{{Counter: "ssh-deny", Packets: 42, Bytes: 4200}}, nil
	}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter protect-re term ssh from protocol tcp",
		"firewall family inet filter protect-re term ssh from destination-port 22",
		"firewall family inet filter protect-re term ssh then count ssh-deny",
		"firewall family inet filter protect-re term ssh then discard",
		"firewall family inet filter edge term t1 then accept",
		"interfaces lo0 unit 0 family inet filter input protect-re",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	s := &Server{store: store, dp: &firewallFilterShowUserspaceDP{Manager: dataplane.New()}}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-filter:protect-re"})
	if err != nil {
		t.Fatalf("ShowText: %v", err)
	}
	if out := resp.GetOutput(); !strings.Contains(out, "Kernel lo0 counter ssh-deny: 42 packets, 4200 bytes") {
		t.Fatalf("output = %q, want kernel lo0 ssh-deny 42", out)
	}
	if calls == 0 {
		t.Fatal("kernel lo0 lookup never invoked for lo0 filter")
	}

	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall"})
	if err != nil {
		t.Fatalf("ShowText firewall: %v", err)
	}
	if out := resp.GetOutput(); !strings.Contains(out, "Kernel lo0 counter ssh-deny: 42 packets, 4200 bytes") {
		t.Fatalf("all-filters output = %q, want kernel lo0 ssh-deny 42", out)
	}

	before := calls
	resp, err = s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-filter:edge"})
	if err != nil {
		t.Fatalf("ShowText edge: %v", err)
	}
	if out := resp.GetOutput(); strings.Contains(out, "Kernel lo0 counter") {
		t.Fatalf("edge output = %q, non-lo0 filter must not render kernel line", out)
	}
	if calls != before {
		t.Fatalf("lookup calls for non-lo0 = %d, want %d (unchanged)", calls, before)
	}
}
