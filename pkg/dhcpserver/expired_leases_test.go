package dhcpserver

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// keaELPView reads back the rendered `expired-leases-processing` block from
// either a Dhcp4 or Dhcp6 generated config. Using json.RawMessage for the
// block lets us distinguish an ABSENT key (nil) from a present-but-empty
// block ({}) — the H1 vs enabled-no-knobs distinction.
type keaELPDoc struct {
	Dhcp4 struct {
		ExpiredLeases json.RawMessage `json:"expired-leases-processing"`
	} `json:"Dhcp4"`
	Dhcp6 struct {
		ExpiredLeases json.RawMessage `json:"expired-leases-processing"`
	} `json:"Dhcp6"`
}

func readELPRaw(t *testing.T, path string, family int) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc keaELPDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal kea%d: %v", family, err)
	}
	if family == 6 {
		return doc.Dhcp6.ExpiredLeases
	}
	return doc.Dhcp4.ExpiredLeases
}

func readELPMap(t *testing.T, path string, family int) map[string]any {
	t.Helper()
	raw := readELPRaw(t, path, family)
	if raw == nil {
		t.Fatalf("expired-leases-processing key absent in kea%d (%s)", family, path)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal expired-leases-processing kea%d: %v", family, err)
	}
	return m
}

func v6Config(ifaces ...string) *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{
				"g0": {
					Name:       "g0",
					Interfaces: ifaces,
					Pools: []*config.DHCPPool{{
						Name:     "p0",
						Subnet:   "2001:db8::/64",
						RangeLow: "2001:db8::100", RangeHigh: "2001:db8::200",
					}},
				},
			},
		},
	}
}

// wantInt asserts a JSON number field equals want (JSON numbers decode to
// float64 into an `any` map).
func wantInt(t *testing.T, m map[string]any, key string, want int) {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Errorf("expired-leases-processing missing key %q (%+v)", key, m)
		return
	}
	f, ok := v.(float64)
	if !ok {
		t.Errorf("key %q: want number, got %T (%v)", key, v, v)
		return
	}
	if int(f) != want {
		t.Errorf("key %q: got %d, want %d", key, int(f), want)
	}
}

func wantAbsent(t *testing.T, m map[string]any, key string) {
	t.Helper()
	if _, ok := m[key]; ok {
		t.Errorf("key %q should be omitted, got %v", key, m[key])
	}
}

// TestKea4ExpiredLeasesOmittedWhenAbsent is the cardinal H1 test (v4): a
// config WITHOUT an expired-leases-processing block must omit the key
// entirely, byte-identical to pre-#1387 output.
func TestKea4ExpiredLeasesOmittedWhenAbsent(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.Apply(v4Config("ge-0-0-0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if raw := readELPRaw(t, m.confPath4, 4); raw != nil {
		t.Errorf("config without expired-leases-processing must omit the key, got %s", raw)
	}
}

// TestKea6ExpiredLeasesOmittedWhenAbsent is the cardinal H1 test (v6).
func TestKea6ExpiredLeasesOmittedWhenAbsent(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	if err := m.Apply(v6Config("ge-0-0-0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if raw := readELPRaw(t, m.confPath6, 6); raw != nil {
		t.Errorf("config without expired-leases-processing must omit the key, got %s", raw)
	}
}

// TestKeaExpiredLeasesDisabledBlockOmitted is the H1 disabled-omit test: a
// PRESENT but Enabled==false block (even with knobs set) must STILL omit
// the key. The disabled omit is unconditional (SMR MAJOR-1).
func TestKeaExpiredLeasesDisabledBlockOmitted(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := v4Config("ge-0-0-0")
	cfg.DHCPLocalServer.ExpiredLeases = &config.DHCPExpiredLeasesConfig{
		Enabled:           false,
		ReclaimTimerWait:  10,
		HoldReclaimedTime: 600,
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if raw := readELPRaw(t, m.confPath4, 4); raw != nil {
		t.Errorf("disabled block must omit the key, got %s", raw)
	}
}

// TestKea4ExpiredLeasesRendersAllKnobs is the FAIL-ON-REVERT render proof
// (v4): an enabled block with every knob set renders the exact Kea
// expired-leases-processing JSON. Deleting the call site or the helper drops
// the key and fails this test.
func TestKea4ExpiredLeasesRendersAllKnobs(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := v4Config("ge-0-0-0")
	cfg.DHCPLocalServer.ExpiredLeases = &config.DHCPExpiredLeasesConfig{
		Enabled:                 true,
		ReclaimTimerWait:        10,
		FlushReclaimedTimerWait: 25,
		HoldReclaimedTime:       600,
		MaxReclaimLeases:        100,
		MaxReclaimLeasesSet:     true,
		MaxReclaimTime:          250,
		MaxReclaimTimeSet:       true,
		UnwarnedReclaimCycles:   5,
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	elp := readELPMap(t, m.confPath4, 4)
	wantInt(t, elp, "reclaim-timer-wait-time", 10)
	wantInt(t, elp, "flush-reclaimed-timer-wait-time", 25)
	wantInt(t, elp, "hold-reclaimed-time", 600)
	wantInt(t, elp, "max-reclaim-leases", 100)
	wantInt(t, elp, "max-reclaim-time", 250)
	wantInt(t, elp, "unwarned-reclaim-cycles", 5)
}

// TestKea6ExpiredLeasesRendersAllKnobs is the v6 FAIL-ON-REVERT render proof.
func TestKea6ExpiredLeasesRendersAllKnobs(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := v6Config("ge-0-0-0")
	cfg.DHCPv6LocalServer.ExpiredLeases = &config.DHCPExpiredLeasesConfig{
		Enabled:                 true,
		ReclaimTimerWait:        7,
		FlushReclaimedTimerWait: 14,
		HoldReclaimedTime:       1800,
		MaxReclaimLeases:        50,
		MaxReclaimLeasesSet:     true,
		MaxReclaimTime:          100,
		MaxReclaimTimeSet:       true,
		UnwarnedReclaimCycles:   3,
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	elp := readELPMap(t, m.confPath6, 6)
	wantInt(t, elp, "reclaim-timer-wait-time", 7)
	wantInt(t, elp, "flush-reclaimed-timer-wait-time", 14)
	wantInt(t, elp, "hold-reclaimed-time", 1800)
	wantInt(t, elp, "max-reclaim-leases", 50)
	wantInt(t, elp, "max-reclaim-time", 100)
	wantInt(t, elp, "unwarned-reclaim-cycles", 3)
}

// TestKeaExpiredLeasesMaxLeasesZeroVsUnset pins invariant H2: max-leases 0
// (unlimited) renders "max-reclaim-leases": 0 distinctly from not setting it
// (key omitted). A naive `if x > 0` render would make 0 (unlimited)
// un-expressible. Same discipline for max-time.
func TestKeaExpiredLeasesMaxLeasesZeroVsUnset(t *testing.T) {
	t.Run("max-leases 0 renders 0 (unlimited)", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		cfg := v4Config("ge-0-0-0")
		cfg.DHCPLocalServer.ExpiredLeases = &config.DHCPExpiredLeasesConfig{
			Enabled:             true,
			MaxReclaimLeases:    0,
			MaxReclaimLeasesSet: true,
			MaxReclaimTime:      0,
			MaxReclaimTimeSet:   true,
		}
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		elp := readELPMap(t, m.confPath4, 4)
		wantInt(t, elp, "max-reclaim-leases", 0)
		wantInt(t, elp, "max-reclaim-time", 0)
	})

	t.Run("max-leases unset omits the key", func(t *testing.T) {
		m, _ := testManager(t, map[string]bool{}, "")
		cfg := v4Config("ge-0-0-0")
		cfg.DHCPLocalServer.ExpiredLeases = &config.DHCPExpiredLeasesConfig{
			Enabled:          true,
			ReclaimTimerWait: 10,
			// MaxReclaimLeasesSet / MaxReclaimTimeSet stay false.
		}
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		elp := readELPMap(t, m.confPath4, 4)
		wantInt(t, elp, "reclaim-timer-wait-time", 10)
		wantAbsent(t, elp, "max-reclaim-leases")
		wantAbsent(t, elp, "max-reclaim-time")
	})
}

// TestKeaExpiredLeasesOneKnobOmitsRest proves each numeric field emits only
// when set: enabling with a single timer renders just that key, leaving the
// rest absent (an operator tunes one knob without pinning the others).
func TestKeaExpiredLeasesOneKnobOmitsRest(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := v4Config("ge-0-0-0")
	cfg.DHCPLocalServer.ExpiredLeases = &config.DHCPExpiredLeasesConfig{
		Enabled:          true,
		ReclaimTimerWait: 30,
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	elp := readELPMap(t, m.confPath4, 4)
	wantInt(t, elp, "reclaim-timer-wait-time", 30)
	for _, k := range []string{
		"flush-reclaimed-timer-wait-time", "hold-reclaimed-time",
		"max-reclaim-leases", "max-reclaim-time", "unwarned-reclaim-cycles",
	} {
		wantAbsent(t, elp, k)
	}
}

// TestKeaExpiredLeasesEnabledNoKnobsEmptyBlock pins Open Q1's resolution:
// Enabled==true with no knobs renders a present empty block ({}), NOT an
// absent key, so the operator sees the feature is on. (Distinct from the
// disabled/nil unconditional omit of H1.)
func TestKeaExpiredLeasesEnabledNoKnobsEmptyBlock(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := v4Config("ge-0-0-0")
	cfg.DHCPLocalServer.ExpiredLeases = &config.DHCPExpiredLeasesConfig{Enabled: true}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	raw := readELPRaw(t, m.confPath4, 4)
	if raw == nil {
		t.Fatal("enabled-no-knobs must render a present empty block, got absent key")
	}
	elp := readELPMap(t, m.confPath4, 4)
	if len(elp) != 0 {
		t.Errorf("enabled-no-knobs must render {}, got %+v", elp)
	}
}

// TestKeaExpiredLeasesPerFamilyIndependence pins that the v4 and v6 blocks
// are tuned independently: a config carrying ONLY a v4 block must NOT render
// the key under Dhcp6, and vice-versa.
func TestKeaExpiredLeasesPerFamilyIndependence(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	cfg := &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: v4Config("ge-0-0-0").DHCPLocalServer.Groups,
			ExpiredLeases: &config.DHCPExpiredLeasesConfig{
				Enabled: true, ReclaimTimerWait: 11,
			},
		},
		DHCPv6LocalServer: &config.DHCPLocalServerConfig{
			Groups: v6Config("ge-0-0-0").DHCPv6LocalServer.Groups,
			// no ExpiredLeases on v6
		},
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	elp4 := readELPMap(t, m.confPath4, 4)
	wantInt(t, elp4, "reclaim-timer-wait-time", 11)
	if raw := readELPRaw(t, m.confPath6, 6); raw != nil {
		t.Errorf("v6 has no block configured; key must be absent under Dhcp6, got %s", raw)
	}
}

// TestKeaExpiredLeasesOutOfRangeKnobsOmittedWithWarning pins #16691's
// tolerant-path behaviour: a stored or peer-synced config can carry a
// knob above Kea's hard maximum (the schema gate only warns there),
// and rendering it verbatim would make Kea refuse the whole family
// file. The renderer must omit ONLY the offending knob, warn naming
// the leaf, and keep the in-range knobs — and the family must still
// apply. Boundary values render verbatim with no warning.
func TestKeaExpiredLeasesOutOfRangeKnobsOmittedWithWarning(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	var warns []string
	m.SetWarnForTesting(func(msg string, args ...any) {
		warns = append(warns, msg)
		for i := 0; i+1 < len(args); i += 2 {
			if s, ok := args[i+1].(string); ok {
				warns = append(warns, s)
			}
		}
	})
	cfg := v4Config("ge-0-0-0")
	cfg.DHCPLocalServer.ExpiredLeases = &config.DHCPExpiredLeasesConfig{
		Enabled:                 true,
		ReclaimTimerWait:        65536,      // above Kea max 65535
		FlushReclaimedTimerWait: 25,         // in range
		HoldReclaimedTime:       4294967296, // above Kea max
		MaxReclaimLeases:        4294967296, // above Kea max
		MaxReclaimLeasesSet:     true,
		MaxReclaimTime:          30000, // above Kea max 10000 (issue probe)
		MaxReclaimTimeSet:       true,
		UnwarnedReclaimCycles:   65536, // above Kea max 65535
	}
	if err := m.Apply(cfg); err != nil {
		t.Fatalf("Apply with out-of-range knobs must still serve the family, got %v", err)
	}
	elp := readELPMap(t, m.confPath4, 4)
	wantInt(t, elp, "flush-reclaimed-timer-wait-time", 25)
	for _, k := range []string{
		"reclaim-timer-wait-time", "hold-reclaimed-time",
		"max-reclaim-leases", "max-reclaim-time", "unwarned-reclaim-cycles",
	} {
		wantAbsent(t, elp, k)
	}
	joined := strings.Join(warns, " ")
	for _, leaf := range []string{"reclaim-timer", "hold-time", "max-leases", "max-time", "unwarned-cycles"} {
		if !strings.Contains(joined, leaf) {
			t.Errorf("warning must name omitted leaf %q, warnings: %v", leaf, warns)
		}
	}
	if strings.Contains(joined, "flush-timer") {
		t.Errorf("in-range flush-timer must not warn, warnings: %v", warns)
	}
}

// TestKeaExpiredLeasesBoundaryKnobsRenderVerbatim is the #16691
// boundary control: every knob at Kea's maximum renders exactly, with
// no warning, on both families.
func TestKeaExpiredLeasesBoundaryKnobsRenderVerbatim(t *testing.T) {
	for _, family := range []int{4, 6} {
		m, _ := testManager(t, map[string]bool{}, "")
		warned := false
		m.SetWarnForTesting(func(msg string, args ...any) { warned = true })
		elpCfg := &config.DHCPExpiredLeasesConfig{
			Enabled:                 true,
			ReclaimTimerWait:        65535,
			FlushReclaimedTimerWait: 65535,
			HoldReclaimedTime:       4294967295,
			MaxReclaimLeases:        4294967295,
			MaxReclaimLeasesSet:     true,
			MaxReclaimTime:          10000,
			MaxReclaimTimeSet:       true,
			UnwarnedReclaimCycles:   65535,
		}
		var cfg *config.DHCPServerConfig
		var path string
		if family == 4 {
			cfg = v4Config("ge-0-0-0")
			cfg.DHCPLocalServer.ExpiredLeases = elpCfg
			path = m.confPath4
		} else {
			cfg = v6Config("ge-0-0-0")
			cfg.DHCPv6LocalServer.ExpiredLeases = elpCfg
			path = m.confPath6
		}
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("family %d Apply: %v", family, err)
		}
		if warned {
			t.Errorf("family %d: boundary knobs must not warn", family)
		}
		elp := readELPMap(t, path, family)
		wantInt(t, elp, "reclaim-timer-wait-time", 65535)
		wantInt(t, elp, "flush-reclaimed-timer-wait-time", 65535)
		wantInt(t, elp, "hold-reclaimed-time", 4294967295)
		wantInt(t, elp, "max-reclaim-leases", 4294967295)
		wantInt(t, elp, "max-reclaim-time", 10000)
		wantInt(t, elp, "unwarned-reclaim-cycles", 65535)
	}
}
