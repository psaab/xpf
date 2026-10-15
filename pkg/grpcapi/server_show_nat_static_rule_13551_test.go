package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestShowTextStaticNATRuleTopicsRenderRequestedDetail13551(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	commands := []string{
		"set security zones security-zone trust",
		"set security nat static rule-set rs1 from zone trust",
		"set security nat static rule-set rs1 rule r1 match destination-address 192.0.2.1/32",
		"set security nat static rule-set rs1 rule r1 match source-address 10.0.0.0/24",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.1/32",
	}
	if _, err := store.LoadSet(strings.Join(commands, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	server := &Server{store: store}

	plain, err := server.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "nat-static-rule"})
	if err != nil {
		t.Fatalf("ShowText(nat-static-rule): %v", err)
	}
	if !strings.Contains(plain.Output, "Rule: r1") || !strings.Contains(plain.Output, "Then static-nat prefix") {
		t.Fatalf("plain static rule output is incomplete: %q", plain.Output)
	}
	if strings.Contains(plain.Output, "Match source-address") {
		t.Fatalf("plain static rule unexpectedly includes detail fields: %q", plain.Output)
	}

	detail, err := server.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "nat-static-rule-detail"})
	if err != nil {
		t.Fatalf("ShowText(nat-static-rule-detail): %v", err)
	}
	if !strings.Contains(detail.Output, "Match source-address:      10.0.0.0/24") {
		t.Fatalf("static NAT detail topic did not render the source restriction: %q", detail.Output)
	}
}
