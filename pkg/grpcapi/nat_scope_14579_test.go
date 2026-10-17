package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #14579: structured NAT surfaces must carry the #3096 non-zone scope.
// A scoped consumer otherwise sees empty zones and assumes match-any.
func TestNATStructuredScope14579(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(`set security nat source rule-set rs-iface from interface ge-0/0/1.0
set security nat source rule-set rs-iface to zone untrust
set security nat source rule-set rs-iface rule r1 match source-address 0.0.0.0/0
set security nat source rule-set rs-iface rule r1 then source-nat interface
set security nat source rule-set rs-zone from zone trust
set security nat source rule-set rs-zone to zone untrust
set security nat source rule-set rs-zone rule r2 match source-address 0.0.0.0/0
set security nat source rule-set rs-zone rule r2 then source-nat interface
set security nat destination rule-set rs-dri from routing-instance blue
set security nat destination rule-set rs-dri rule d1 match destination-address 198.51.100.7
set security nat destination rule-set rs-dri rule d1 then destination-nat off`); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s := &Server{store: store}

	src, err := s.GetNATSource(context.Background(), &pb.GetNATSourceRequest{})
	if err != nil {
		t.Fatalf("GetNATSource: %v", err)
	}
	if len(src.Rules) != 2 {
		t.Fatalf("GetNATSource rules = %d, want 2", len(src.Rules))
	}
	byRule := map[string]*pb.NATSourceInfo{}
	for _, r := range src.Rules {
		byRule[r.SourceMatch] = r
		_ = r
	}
	// Rules carry no name on NATSourceInfo; distinguish by scope fields.
	var scoped, zoned *pb.NATSourceInfo
	for _, r := range src.Rules {
		if r.FromInterface != "" {
			scoped = r
		}
		if r.FromZone == "trust" {
			zoned = r
		}
	}
	if scoped == nil || scoped.FromInterface != "ge-0/0/1.0" || scoped.ToZone != "untrust" {
		t.Errorf("scoped source info missing FromInterface: %+v", src.Rules)
	}
	if zoned == nil {
		t.Errorf("zone source info missing FromZone trust: %+v", src.Rules)
	}

	stats, err := s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{NatType: "destination"})
	if err != nil {
		t.Fatalf("GetNATRuleStats: %v", err)
	}
	if len(stats.Rules) != 1 || stats.Rules[0].FromRoutingInstance != "blue" {
		t.Errorf("dest rule stats = %+v, want FromRoutingInstance blue", stats.Rules)
	}
}
