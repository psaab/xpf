package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14110: compileNAT registered persistent-NAT pool IPs from only
// pool.Addresses and, for a CIDR member, only its parsed base IP. The
// userspace SNAT allocator instead expands config.SourceNATPoolMembers
// (singular Address plus Addresses, every prefix member expanded), so a
// session translated to any other member IP failed LookupPool on Go-side
// deletion and its persistent binding was silently not preserved.

type persistentPoolDP14110 struct {
	idProbeDP
	pnat *PersistentNATTable
}

func (d *persistentPoolDP14110) GetPersistentNAT() *PersistentNATTable { return d.pnat }

func persistentPoolCfg14110() *config.Config {
	persistent := &config.PersistentNATConfig{Permit: config.PersistentNATPermitAnyRemoteHost, InactivityTimeout: 600}
	return &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			NAT: config.NATConfig{
				SourcePools: map[string]*config.NATPool{
					"cidr-pool": {
						Name:          "cidr-pool",
						Addresses:     []string{"192.0.2.0/29", "2001:db8:1::/126"},
						PersistentNAT: persistent,
					},
					"singular-pool": {
						Name:          "singular-pool",
						Address:       "198.51.100.7",
						PersistentNAT: persistent,
					},
					"bad-pool": {
						Name:          "bad-pool",
						Addresses:     []string{"not-an-ip", "203.0.113.0/24"},
						PersistentNAT: persistent,
					},
					"wide-pool": {
						Name:          "wide-pool",
						Addresses:     []string{"10.0.0.0/15"},
						PersistentNAT: persistent,
					},
				},
				Source: []*config.NATRuleSet{
					{
						Name: "rs1", FromZone: "trust", ToZone: "untrust",
						Rules: []*config.NATRule{
							{Name: "r-cidr", Then: config.NATThen{PoolName: "cidr-pool"}},
							{Name: "r-singular", Then: config.NATThen{PoolName: "singular-pool"}},
							{Name: "r-bad", Then: config.NATThen{PoolName: "bad-pool"}},
							{Name: "r-wide", Then: config.NATThen{PoolName: "wide-pool"}},
						},
					},
				},
			},
		},
	}
}

func compilePersistentPools14110(t *testing.T) *PersistentNATTable {
	t.Helper()
	cfg := persistentPoolCfg14110()
	pnat := NewPersistentNATTable()
	dp := &persistentPoolDP14110{pnat: pnat}
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	if err := compileNAT(dp, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	return pnat
}

func TestPersistentNATPoolRegistrationExpandsMembers14110(t *testing.T) {
	pnat := compilePersistentPools14110(t)

	// Every member of the /29, not just its base 192.0.2.0.
	for _, s := range []string{
		"192.0.2.0", "192.0.2.1", "192.0.2.5", "192.0.2.7",
		"2001:db8:1::", "2001:db8:1::2", "2001:db8:1::3",
	} {
		ip := netip.MustParseAddr(s)
		pool, cfg, ok := pnat.LookupPool(ip)
		if !ok || pool != "cidr-pool" {
			t.Errorf("LookupPool(%s) = %q, ok=%v; want cidr-pool (cfg=%+v)", s, pool, ok, cfg)
		}
	}
	// Singular `address` form.
	if pool, _, ok := pnat.LookupPool(netip.MustParseAddr("198.51.100.7")); !ok || pool != "singular-pool" {
		t.Errorf("singular pool.Address not registered: pool=%q ok=%v", pool, ok)
	}
	// Fail-closed: an unusable pool (bad member poisons whole pool; over-cap
	// prefix) registers nothing — not even its valid members / base.
	for _, s := range []string{"203.0.113.0", "203.0.113.9", "10.0.0.0", "10.0.1.5"} {
		if pool, _, ok := pnat.LookupPool(netip.MustParseAddr(s)); ok {
			t.Errorf("LookupPool(%s) = %q; unusable pool must register nothing", s, pool)
		}
	}
	// Preservation across recompile: second compile clears + re-registers the
	// same expanded set (no stale narrowing).
	cfg := persistentPoolCfg14110()
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	if err := compileNAT(&persistentPoolDP14110{pnat: pnat}, cfg, result); err != nil {
		t.Fatalf("recompile: %v", err)
	}
	if _, _, ok := pnat.LookupPool(netip.MustParseAddr("192.0.2.6")); !ok {
		t.Error("after recompile, 192.0.2.6 no longer resolves to its persistent pool")
	}

	// End-to-end consumer: preservePersistentNATV4 saves a binding for a
	// non-base CIDR member (NATSrcIP in native-endian form, as in
	// session_store_test.go).
	nat4 := netip.MustParseAddr("192.0.2.5").As4()
	natIPU32 := binary.NativeEndian.Uint32(nat4[:])
	store := dataPlaneSessionStore{dp: &persistentPoolDP14110{pnat: pnat}}
	key := SessionKey{SrcIP: [4]byte{10, 0, 0, 9}, SrcPort: 12345}
	val := SessionValue{Flags: SessFlagSNAT, NATSrcIP: natIPU32, NATSrcPort: 40001}
	store.preservePersistentNATV4(key, val)
	b := pnat.Lookup(netip.MustParseAddr("10.0.0.9"), 12345, "cidr-pool")
	if b == nil {
		t.Fatal("preservePersistentNATV4 saved no binding for NAT IP 192.0.2.5 (non-base /29 member)")
	}
	if b.NatIP != netip.MustParseAddr("192.0.2.5") || b.NatPort != 40001 {
		t.Errorf("preserved binding = %v:%d, want 192.0.2.5:40001", b.NatIP, b.NatPort)
	}
}
