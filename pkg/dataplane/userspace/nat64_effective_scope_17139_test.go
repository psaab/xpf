package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17139: the snapshot builder must see the same union the gate and the
// scoped owner key see. A hand-built rule-set whose singular disagrees
// with its plural — FromZone="a", FromZones=["b"] — ships {b,a} on the
// wire (list order first, singular appended), via the single
// config.NAT64Effective* normaliser.
func TestBuildNAT64SnapshotsEffectiveScopeUnion17139(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.1/32"}},
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name: "rs1", Prefix: "64:ff9b::/96", SourcePool: "p64",
		FromZone: "a", FromZones: []string{"b"},
	}}
	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snaps))
	}
	if !reflect.DeepEqual(snaps[0].FromZones, []string{"b", "a"}) {
		t.Fatalf("wire FromZones = %v, want [b a] (union)", snaps[0].FromZones)
	}
	if snaps[0].FromZone != "a" {
		t.Fatalf("wire FromZone = %q, want a (singular mirror)", snaps[0].FromZone)
	}

	riCfg := &config.Config{}
	riCfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.1/32"}},
	}
	riCfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name: "rs1", Prefix: "64:ff9b::/96", SourcePool: "p64",
		FromRoutingInstance: "r1", FromRoutingInstances: []string{"r2"},
	}}
	riSnaps := buildNAT64Snapshots(riCfg)
	if len(riSnaps) != 1 {
		t.Fatalf("RI snapshots = %d, want 1", len(riSnaps))
	}
	if !reflect.DeepEqual(riSnaps[0].FromRoutingInstances, []string{"r2", "r1"}) {
		t.Fatalf("wire FromRoutingInstances = %v, want [r2 r1] (union)", riSnaps[0].FromRoutingInstances)
	}
	if riSnaps[0].FromRoutingInstance != "r1" {
		t.Fatalf("wire FromRoutingInstance = %q, want r1 (singular mirror)", riSnaps[0].FromRoutingInstance)
	}

	// "default" singular + "" list member + explicit-master flag lowers
	// to ONE wire token on the snapshot, not a duplicated token.
	defaultCfg := &config.Config{}
	defaultCfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.1/32"}},
	}
	defaultCfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{{
		Name: "rs1", Prefix: "64:ff9b::/96", SourcePool: "p64",
		FromRoutingInstance: "default", FromRoutingInstances: []string{""},
		FromRoutingInstanceDefault: true,
	}}
	defaultSnaps := buildNAT64Snapshots(defaultCfg)
	if len(defaultSnaps) != 1 {
		t.Fatalf("default snapshots = %d, want 1", len(defaultSnaps))
	}
	if !reflect.DeepEqual(defaultSnaps[0].FromRoutingInstances, []string{config.NATDefaultRoutingInstanceWire}) {
		t.Fatalf("wire FromRoutingInstances(default+\"\"+flag) = %q, want [%q] (one token)", defaultSnaps[0].FromRoutingInstances, config.NATDefaultRoutingInstanceWire)
	}
}

// #17139: the pre-v64 protocol-truncation gate predicate must count the
// effective union, not the raw plural. Divergent singular r1 beside
// plural [r2] ships [r2 r1] on the wire, so it is multi; default+""+flag
// collapses to one wire token, so it is not.
func TestConfigHasMultiRoutingInstanceNAT64EffectiveUnion17139(t *testing.T) {
	cfg := func(rs *config.NAT64RuleSet) *config.Config {
		c := &config.Config{}
		c.Security.NAT.NAT64 = []*config.NAT64RuleSet{rs}
		return c
	}
	if !configHasMultiRoutingInstanceNAT64(cfg(&config.NAT64RuleSet{
		Name: "rs1", Prefix: "64:ff9b::/96",
		FromRoutingInstance: "r1", FromRoutingInstances: []string{"r2"},
	})) {
		t.Fatal("divergent singular r1 + plural [r2] must be multi (builder ships [r2 r1])")
	}
	if !ConfigHasMultiRoutingInstanceNAT64(cfg(&config.NAT64RuleSet{
		Name: "rs1", Prefix: "64:ff9b::/96",
		FromRoutingInstance: "r1", FromRoutingInstances: []string{"r2"},
	})) {
		t.Fatal("exported predicate must agree on divergent singular+plural")
	}
	if configHasMultiRoutingInstanceNAT64(cfg(&config.NAT64RuleSet{
		Name: "rs1", Prefix: "64:ff9b::/96",
		FromRoutingInstance: "default", FromRoutingInstances: []string{""},
		FromRoutingInstanceDefault: true,
	})) {
		t.Fatal("default+\"\"+flag must collapse to one effective token, not multi")
	}
	if configHasMultiRoutingInstanceNAT64(cfg(&config.NAT64RuleSet{
		Name: "rs1", Prefix: "64:ff9b::/96",
		FromRoutingInstance: "r1", FromRoutingInstances: []string{"r1"},
	})) {
		t.Fatal("singular already in plural must dedup to one, not multi")
	}
	if configHasMultiRoutingInstanceNAT64(cfg(&config.NAT64RuleSet{
		Name: "rs1", Prefix: "64:ff9b::/96", FromRoutingInstance: "r1",
	})) {
		t.Fatal("singular-only must not be multi")
	}
	if configHasMultiRoutingInstanceNAT64(nil) {
		t.Fatal("nil cfg must not be multi")
	}
}
