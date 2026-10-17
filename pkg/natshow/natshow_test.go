package natshow

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// natFixtureConfig builds a deterministic NAT configuration exercising
// source, destination, static, and nptv6 rule-sets so the golden
// renderers below assert byte-for-byte output. The bytes here are the
// pre-#1687 gRPC ShowText contract (server_show_nat.go); the CLI path
// produced identical bytes and both now route through these funcs.
func natFixtureConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name: "rs-src", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{
				{
					Name:  "r1",
					Match: config.NATMatch{SourceAddress: "10.0.1.0/24", Protocol: "tcp"},
					Then:  config.NATThen{PoolName: "p-src"},
				},
			},
		},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p-src": {Name: "p-src", Addresses: []string{"203.0.113.1"}, PortLow: 0, PortHigh: 0},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p-dst": {Name: "p-dst", Address: "10.0.30.5", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name: "rs-dst", FromZone: "untrust",
				Rules: []*config.NATRule{
					{
						Name:  "d1",
						Match: config.NATMatch{DestinationAddress: "198.51.100.7/32", DestinationPort: 443, Protocol: "tcp"},
						Then:  config.NATThen{PoolName: "p-dst"},
					},
				},
			},
		},
	}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs-static", FromZone: "trust",
			Rules: []*config.StaticNATRule{
				{Name: "s1", Match: "192.0.2.10", Then: "10.0.1.10"},
				{Name: "n1", Match: "2001:db8:a::/64", Then: "fd00:a::/64", IsNPTv6: true},
			},
		},
	}
	return cfg
}

func TestRenderSourceRuleDetailGolden(t *testing.T) {
	cfg := natFixtureConfig()
	dp := dataplane.New() // IsLoaded() == false -> no session counts
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, dp, nil)
	want := "source NAT rule: r1\n" +
		"  Rule-set: rs-src                        ID: 1\n" +
		"    From zone: trust    To zone: untrust\n" +
		"    Match:\n" +
		"      Source addresses:      10.0.1.0/24\n" +
		"      Destination addresses: 0.0.0.0/0\n" +
		"      IP protocol:           tcp\n" +
		"    Action:                  pool p-src\n" +
		"    Pool addresses:          203.0.113.1\n" +
		"    Port range:              1024-65535\n" +
		// #7423 rows 3+4: an UNARMED dataplane no longer renders measured-looking
		// zeros. Both rows say so positively rather than being omitted.
		"    Translation hits:        n/a (dataplane not armed)\n" +
		"\n" +
		"  Rule-set rs-src: sessions for this zone pair: n/a (dataplane not armed)\n\n"
	if got := b.String(); got != want {
		t.Fatalf("RenderSourceRuleDetail mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderSourceRuleDetailEmpty(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, &config.Config{}, nil, nil)
	if got, want := b.String(), "No source NAT rules configured\n"; got != want {
		t.Fatalf("empty source: got=%q want=%q", got, want)
	}
}

func TestRenderDestRuleDetailGolden(t *testing.T) {
	cfg := natFixtureConfig()
	dp := dataplane.New()
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, dp, nil)
	want := "destination NAT rule: d1\n" +
		"  Rule-set: rs-dst                        ID: 1\n" +
		"    From zone: untrust\n" +
		"    Match:\n" +
		"      Destination addresses: 198.51.100.7/32\n" +
		"      Destination port:      443\n" +
		"      IP protocol:           tcp\n" +
		"    Action:                  pool p-dst\n" +
		"    Pool address:            10.0.30.5\n" +
		"    Pool port:               8080\n" +
		// #7423 rows 3+4: see the source sibling.
		"    Translation hits:        n/a (dataplane not armed)\n" +
		"\n" +
		"  Rule-set rs-dst: sessions for this zone pair: n/a (dataplane not armed)\n\n"
	if got := b.String(); got != want {
		t.Fatalf("RenderDestRuleDetail mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderDestRuleDetailEmpty(t *testing.T) {
	// All three branches of the gRPC guard share the same message:
	// nil cfg, non-nil cfg with nil Destination, and non-nil
	// Destination with zero RuleSets (the len(RuleSets)==0 branch that
	// the CLI dispatcher's pre-guard does NOT cover — so the shared
	// renderer must, and this case proves it).
	withEmptyRuleSets := &config.Config{}
	withEmptyRuleSets.Security.NAT.Destination = &config.DestinationNATConfig{RuleSets: nil}
	for _, c := range []*config.Config{nil, {}, withEmptyRuleSets} {
		var b strings.Builder
		RenderDestRuleDetail(context.Background(), &b, c, nil, nil)
		if got, want := b.String(), "No destination NAT rules configured\n"; got != want {
			t.Fatalf("empty dest: got=%q want=%q", got, want)
		}
	}
}

func TestRenderStaticGolden(t *testing.T) {
	cfg := natFixtureConfig()
	var b strings.Builder
	RenderStatic(&b, cfg)
	want := "Static NAT rule-set: rs-static\n" +
		"  From zone: trust\n" +
		"  Rule: s1\n" +
		"    Match destination-address: 192.0.2.10\n" +
		"    Then static-nat prefix:    10.0.1.10\n" +
		"  Rule: n1\n" +
		"    Match destination-address: 2001:db8:a::/64\n" +
		"    Then nptv6-prefix:         fd00:a::/64\n" +
		"\n"
	if got := b.String(); got != want {
		t.Fatalf("RenderStatic mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderStaticEmpty(t *testing.T) {
	var b strings.Builder
	RenderStatic(&b, &config.Config{})
	if got, want := b.String(), "No static NAT rules configured.\n"; got != want {
		t.Fatalf("empty static: got=%q want=%q", got, want)
	}
}

func TestRenderNPTv6Golden(t *testing.T) {
	cfg := natFixtureConfig()
	var b strings.Builder
	RenderNPTv6(&b, cfg)
	want := "Rule-set             Rule                 External prefix                                    Internal prefix                                   \n" +
		"rs-static            n1                   2001:db8:a::/64                                    fd00:a::/64                                       \n"
	if got := b.String(); got != want {
		t.Fatalf("RenderNPTv6 mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderNPTv6Empty(t *testing.T) {
	var b strings.Builder
	RenderNPTv6(&b, &config.Config{})
	if got, want := b.String(), "No NPTv6 rules configured.\n"; got != want {
		t.Fatalf("empty nptv6: got=%q want=%q", got, want)
	}
}

func TestRenderPersistentNilReader(t *testing.T) {
	var b strings.Builder
	RenderPersistent(&b, nil)
	if got, want := b.String(), "Persistent NAT table not available\n"; got != want {
		t.Fatalf("nil reader: got=%q want=%q", got, want)
	}
}

func TestRenderPersistentEmpty(t *testing.T) {
	dp := dataplane.New()
	var b strings.Builder
	RenderPersistent(&b, dp)
	if got, want := b.String(), "No persistent NAT bindings\n"; got != want {
		t.Fatalf("empty persistent: got=%q want=%q", got, want)
	}
}

func TestRenderPersistentDetailNilReader(t *testing.T) {
	var b strings.Builder
	RenderPersistentDetail(context.Background(), &b, nil)
	if got, want := b.String(), "Persistent NAT table not available\n"; got != want {
		t.Fatalf("nil reader: got=%q want=%q", got, want)
	}
}

// dataplane.New() returns *dataplane.Manager, which satisfies the
// natshow.Reader interface — compile-time assertion so a method-set
// drift breaks the build, not just a test.
var _ Reader = (*dataplane.Manager)(nil)

// fakeReader exercises the loaded path (IsLoaded()==true) so the
// session-count, translation-hit, and persistent-binding branches —
// which dataplane.New() leaves dormant (IsLoaded()==false) — are
// covered by golden assertions.
type fakeReader struct {
	v4       []dataplane.SessionValue
	v6       []dataplane.SessionValueV6
	counters map[uint32]dataplane.CounterValue
	pnat     *dataplane.PersistentNATTable
}

func (f *fakeReader) IsLoaded() bool { return true }
func (f *fakeReader) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, v := range f.v4 {
		if !fn(dataplane.SessionKey{}, v) {
			break
		}
	}
	return nil
}
func (f *fakeReader) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, v := range f.v6 {
		if !fn(dataplane.SessionKeyV6{}, v) {
			break
		}
	}
	return nil
}
func (f *fakeReader) ReadNATRuleCounter(id uint32) (dataplane.CounterValue, error) {
	return f.counters[id], nil
}
func (f *fakeReader) GetPersistentNAT() *dataplane.PersistentNATTable { return f.pnat }

func TestRenderSourceRuleDetailLoadedGolden(t *testing.T) {
	cfg := natFixtureConfig()
	cfg.Security.NAT.SourcePools["p-src"].PersistentNAT = &config.PersistentNATConfig{}
	dp := &fakeReader{
		// One forward SNAT session in the rs-src zone pair (zone IDs
		// 7=trust, 8=untrust per the apply result below).
		v4: []dataplane.SessionValue{
			{Flags: dataplane.SessFlagSNAT, IsReverse: 0, IngressZone: 7, EgressZone: 8},
			{Flags: dataplane.SessFlagSNAT, IsReverse: 1, IngressZone: 7, EgressZone: 8}, // reverse: skipped
		},
		counters: map[uint32]dataplane.CounterValue{5: {Packets: 42, Bytes: 4200}},
	}
	cr := &dataplane.ApplyResult{
		ZoneIDs:       map[string]uint16{"trust": 7, "untrust": 8},
		NATCounterIDs: map[string]uint32{dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "rs-src", "r1"): 5},
	}
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, cfg, dp, func() *dataplane.ApplyResult { return cr })
	want := "source NAT rule: r1\n" +
		"  Rule-set: rs-src                        ID: 1\n" +
		"    From zone: trust    To zone: untrust\n" +
		"    Match:\n" +
		"      Source addresses:      10.0.1.0/24\n" +
		"      Destination addresses: 0.0.0.0/0\n" +
		"      IP protocol:           tcp\n" +
		"    Action:                  pool p-src\n" +
		"    Persistent NAT:          enabled\n" +
		"    Pool addresses:          203.0.113.1\n" +
		"    Port range:              1024-65535\n" +
		"    Translation hits:        42 packets  4200 bytes\n" +
		"\n" +
		// #7423 row 4: reported once at the scope it measures (the zone pair),
		// not once per rule.
		"  Rule-set rs-src: sessions for this zone pair: 1\n\n"
	if got := b.String(); got != want {
		t.Fatalf("loaded source detail mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderDestRuleDetailLoadedGolden(t *testing.T) {
	cfg := natFixtureConfig()
	dp := &fakeReader{
		v4: []dataplane.SessionValue{
			{Flags: dataplane.SessFlagDNAT, IsReverse: 0, IngressZone: 8, EgressZone: 9},
		},
		counters: map[uint32]dataplane.CounterValue{6: {Packets: 7, Bytes: 700}},
	}
	cr := &dataplane.ApplyResult{
		ZoneIDs:       map[string]uint16{"untrust": 8, "dmz": 9},
		NATCounterIDs: map[string]uint32{dataplane.NATCounterKey(dataplane.NATCounterTypeDest, "rs-dst", "d1"): 6},
	}
	var b strings.Builder
	RenderDestRuleDetail(context.Background(), &b, cfg, dp, func() *dataplane.ApplyResult { return cr })
	want := "destination NAT rule: d1\n" +
		"  Rule-set: rs-dst                        ID: 1\n" +
		"    From zone: untrust\n" +
		"    Match:\n" +
		"      Destination addresses: 198.51.100.7/32\n" +
		"      Destination port:      443\n" +
		"      IP protocol:           tcp\n" +
		"    Action:                  pool p-dst\n" +
		"    Pool address:            10.0.30.5\n" +
		"    Pool port:               8080\n" +
		"    Translation hits:        7 packets  700 bytes\n" +
		"\n" +
		// #7423 row 4: see the source sibling.
		"  Rule-set rs-dst: sessions for this zone pair: 1\n\n"
	if got := b.String(); got != want {
		t.Fatalf("loaded dest detail mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestRenderPersistentLoadedGolden(t *testing.T) {
	pnat := dataplane.NewPersistentNATTable()
	now := time.Now()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.1.5"),
		SrcPort:  1111,
		NatIP:    netip.MustParseAddr("203.0.113.1"),
		NatPort:  40000,
		PoolName: "p-src",
		LastSeen: now,
		Timeout:  600 * time.Second,
	})
	dp := &fakeReader{pnat: pnat}
	var b strings.Builder
	RenderPersistent(&b, dp)
	got := b.String()
	// Timeout is time-relative (Truncate(time.Second)); assert the
	// stable prefix + the binding row's fixed columns.
	wantHead := "Total persistent NAT bindings: 1\n\n" +
		"Source IP            SrcPort  NAT IP               NATPort  Pool            Timeout   \n"
	if !strings.HasPrefix(got, wantHead) {
		t.Fatalf("persistent header mismatch:\n got=%q\nwantHead=%q", got, wantHead)
	}
	// Fixed columns up to (but excluding) the time-relative Timeout
	// value; %-15s pads "p-src" to 15 chars.
	if !strings.Contains(got, "10.0.1.5             1111     203.0.113.1          40000    p-src          ") {
		t.Fatalf("persistent row mismatch: got=%q", got)
	}
}

func TestRenderPersistentDetailLoadedGolden(t *testing.T) {
	pnat := dataplane.NewPersistentNATTable()
	now := time.Now()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.1.5"),
		SrcPort:  1111,
		NatIP:    netip.MustParseAddr("203.0.113.1"),
		NatPort:  40000,
		PoolName: "p-src",
		LastSeen: now,
		Timeout:  600 * time.Second,
	})
	// A forward SNAT session whose NATSrcIP/Port matches the binding,
	// so Current sessions == 1. NATSrcIP is native-endian network-order
	// (CLAUDE.md byte order) — build it the same way the renderer
	// recovers it.
	var ip4 [4]byte
	copy(ip4[:], netip.MustParseAddr("203.0.113.1").AsSlice())
	dp := &fakeReader{
		pnat: pnat,
		v4: []dataplane.SessionValue{
			{Flags: dataplane.SessFlagSNAT, IsReverse: 0,
				NATSrcIP:   binary.NativeEndian.Uint32(ip4[:]),
				NATSrcPort: 40000},
		},
	}
	var b strings.Builder
	RenderPersistentDetail(context.Background(), &b, dp)
	got := b.String()
	if !strings.Contains(got, "Total persistent NAT bindings: 1\n\n") {
		t.Fatalf("detail count missing: %q", got)
	}
	if !strings.Contains(got, "  Reflexive IP:       203.0.113.1\n  Reflexive port:     40000\n") {
		t.Fatalf("detail reflexive missing: %q", got)
	}
	if !strings.Contains(got, "  Current sessions:   1\n") {
		t.Fatalf("detail session count != 1: %q", got)
	}
}

// TestRenderPersistentDetailPermitModes asserts the persistent-NAT detail
// SHOW path renders each three-way permit mode DISTINCTLY (#3193). Before
// #3193 the renderer printed only a binary "Any remote host: yes" line, so
// target-host and target-host-port were indistinguishable. The fail-on-
// revert assertion below (targetHost != targetHostPort output) goes RED if
// the renderer is reverted to the binary flag.
func TestRenderPersistentDetailPermitModes(t *testing.T) {
	render := func(p config.PersistentNATPermit) string {
		pnat := dataplane.NewPersistentNATTable()
		pnat.Save(&dataplane.PersistentNATBinding{
			SrcIP:    netip.MustParseAddr("10.0.1.5"),
			SrcPort:  1111,
			NatIP:    netip.MustParseAddr("203.0.113.1"),
			NatPort:  40000,
			PoolName: "p-src",
			LastSeen: time.Now(),
			Timeout:  600 * time.Second,
			Permit:   p,
		})
		var b strings.Builder
		RenderPersistentDetail(context.Background(), &b, &fakeReader{pnat: pnat})
		return b.String()
	}

	anyRemote := render(config.PersistentNATPermitAnyRemoteHost)
	targetHost := render(config.PersistentNATPermitTargetHost)
	targetHostPort := render(config.PersistentNATPermitTargetHostPort)

	if !strings.Contains(anyRemote, "  Permit:             any-remote-host\n") {
		t.Errorf("any-remote-host not rendered: %q", anyRemote)
	}
	if !strings.Contains(targetHost, "  Permit:             target-host\n") {
		t.Errorf("target-host not rendered: %q", targetHost)
	}
	if !strings.Contains(targetHostPort, "  Permit:             target-host-port\n") {
		t.Errorf("target-host-port not rendered: %q", targetHostPort)
	}
	// Fail-on-revert: the two non-any modes MUST render distinctly. A
	// binary permit-any-remote-host flag would collapse both to identical
	// output and trip this.
	if targetHost == targetHostPort {
		t.Fatalf("target-host and target-host-port render identically:\n%q", targetHost)
	}
	if anyRemote == targetHost || anyRemote == targetHostPort {
		t.Fatalf("any-remote-host not distinct from target modes")
	}
}
