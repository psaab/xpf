package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15269 cohort gRPC arms.

func TestGRPCScreenSynFloodUnset15269(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{
		Screen: map[string]*config.ScreenProfile{
			"p": {Name: "p", TCP: config.TCPScreen{SynFlood: &config.SynFloodConfig{AttackThreshold: 200}}},
		},
	}}
	var b strings.Builder
	s := &Server{}
	if _, err := s.showScreenIDSOptionDetail(&pb.ShowTextRequest{Topic: "screen-ids-option-detail:p"}, cfg, &b); err != nil {
		t.Fatalf("detail: %v", err)
	}
	out := b.String()
	if strings.Contains(out, "(default)") {
		t.Errorf("must not render (default):\n%s", out)
	}
	for _, want := range []string{"disabled", "512 (not applied)", "4000 (not applied)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestGRPCTerseDisabled15269(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"reth0": {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, Disable: true, Addresses: []string{"172.16.50.8/24"}},
			51: {Number: 51, Addresses: []string{"172.16.51.8/24"}},
		}},
		"ge-0/0/5": {Name: "ge-0/0/5", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Disable: true, Addresses: []string{"10.0.5.8/24"}},
		}},
	}
	resp, err := (&Server{}).showInterfacesTerse(cfg, "")
	if err != nil {
		t.Fatalf("terse: %v", err)
	}
	out := resp.Output
	lines := strings.Split(out, "\n")
	find := func(p string) string {
		for _, l := range lines {
			if strings.HasPrefix(l, p) {
				return l
			}
		}
		return ""
	}
	if l := find("reth0.50"); !strings.Contains(l, "down") || strings.Contains(l, "172.16.50.8") {
		t.Errorf("reth0.50 must be down without address: %q\n%s", l, out)
	}
	if l := find("reth0.51"); !strings.Contains(l, "172.16.51.8") {
		t.Errorf("reth0.51 control must keep address: %q\n%s", l, out)
	}
	if l := find("ge-0/0/5.0"); !strings.Contains(l, "down") {
		t.Errorf("ge-0/0/5.0 must be down: %q\n%s", l, out)
	}
}

func TestGRPCDNATSourceMatch15269(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp1 address 10.0.0.5",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule scoped match source-address 198.51.100.0/24",
		"set security nat destination rule-set drs rule scoped match destination-address 203.0.113.10/32",
		"set security nat destination rule-set drs rule scoped then destination-nat pool dp1",
		"set security nat destination rule-set drs rule open match destination-address 203.0.113.11/32",
		"set security nat destination rule-set drs rule open then destination-nat pool dp1",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s := &Server{store: store}
	resp, err := s.GetNATDestination(context.Background(), &pb.GetNATDestinationRequest{})
	if err != nil {
		t.Fatalf("GetNATDestination: %v", err)
	}
	byName := map[string]*pb.NATDestInfo{}
	for _, r := range resp.Rules {
		byName[r.Name] = r
	}
	if got := byName["scoped"].GetSourceMatch(); got != "198.51.100.0/24" {
		t.Errorf("scoped source_match=%q, want 198.51.100.0/24", got)
	}
	if got := byName["open"].GetSourceMatch(); got != "0.0.0.0/0" {
		t.Errorf("open source_match=%q, want 0.0.0.0/0", got)
	}
	// ShowText detail must carry it too.
	var buf strings.Builder
	cfg := store.ActiveConfig()
	// Use natshow via ShowText path: call GetNATDestination already; text via server_show_nat helper is exercised in natshow tests.
	_ = buf
	_ = cfg
}
