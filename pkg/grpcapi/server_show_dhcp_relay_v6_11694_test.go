package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestGRPCShowTextDHCPRelayV6NamesGroupAndServers11694(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"set forwarding-options dhcp-relay dhcpv6 server-group sg6 2001:db8::5",
		"set forwarding-options dhcp-relay dhcpv6 group g6 active-server-group sg6",
		"set forwarding-options dhcp-relay dhcpv6 group g6 interface ge-0/0/0.0",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	s := NewServer("", Config{Store: store})
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "dhcp-relay"})
	if err != nil {
		t.Fatalf("ShowText(dhcp-relay): %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{"DHCPv6 server groups:", "sg6", "2001:db8::5", "DHCPv6 relay groups:", "g6", "ge-0/0/0.0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("gRPC show-text dhcp-relay missing %q; got:\n%s", want, out)
		}
	}
}
