package ra

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildRA_Basic(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{
				{
					Prefix:     "2001:db8:1::/64",
					OnLink:     true,
					Autonomous: true,
				},
			},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	if ra.RouterLifetime != 1800*time.Second {
		t.Errorf("RouterLifetime = %v, want 1800s", ra.RouterLifetime)
	}
	if ra.CurrentHopLimit != 64 {
		t.Errorf("CurrentHopLimit = %d, want 64", ra.CurrentHopLimit)
	}
	if ra.ManagedConfiguration {
		t.Error("ManagedConfiguration should be false")
	}
	if ra.OtherConfiguration {
		t.Error("OtherConfiguration should be false")
	}
	if ra.RouterSelectionPreference != ndp.Medium {
		t.Errorf("Preference = %v, want Medium", ra.RouterSelectionPreference)
	}

	// Check source LLA option.
	var foundSLLA bool
	for _, opt := range ra.Options {
		if lla, ok := opt.(*ndp.LinkLayerAddress); ok && lla.Direction == ndp.Source {
			foundSLLA = true
			if lla.Addr.String() != "00:11:22:33:44:55" {
				t.Errorf("SLLA = %s, want 00:11:22:33:44:55", lla.Addr)
			}
		}
	}
	if !foundSLLA {
		t.Error("missing source link-layer address option")
	}

	// Check prefix.
	var foundPrefix bool
	for _, opt := range ra.Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			foundPrefix = true
			if pi.PrefixLength != 64 {
				t.Errorf("PrefixLength = %d, want 64", pi.PrefixLength)
			}
			wantPrefix := netip.MustParseAddr("2001:db8:1::")
			if pi.Prefix != wantPrefix {
				t.Errorf("Prefix = %s, want %s", pi.Prefix, wantPrefix)
			}
			if !pi.OnLink {
				t.Error("OnLink should be true")
			}
			if !pi.AutonomousAddressConfiguration {
				t.Error("Autonomous should be true")
			}
			if pi.ValidLifetime != time.Duration(defaultValidLifetime)*time.Second {
				t.Errorf("ValidLifetime = %v, want %ds", pi.ValidLifetime, defaultValidLifetime)
			}
			if pi.PreferredLifetime != time.Duration(defaultPreferredLifetime)*time.Second {
				t.Errorf("PreferredLifetime = %v, want %ds", pi.PreferredLifetime, defaultPreferredLifetime)
			}
		}
	}
	if !foundPrefix {
		t.Error("missing prefix information option")
	}
}

func TestBuildRA_ManagedStateful(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:     "trust0",
			ManagedConfig: true,
			OtherStateful: true,
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()
	if !ra.ManagedConfiguration {
		t.Error("ManagedConfiguration should be true")
	}
	if !ra.OtherConfiguration {
		t.Error("OtherConfiguration should be true")
	}
}

func TestBuildRA_DNSServers(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:  "trust0",
			DNSServers: []string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	var found bool
	for _, opt := range ra.Options {
		if rdnss, ok := opt.(*ndp.RecursiveDNSServer); ok {
			found = true
			if len(rdnss.Servers) != 2 {
				t.Fatalf("got %d DNS servers, want 2", len(rdnss.Servers))
			}
			want1 := netip.MustParseAddr("2001:4860:4860::8888")
			want2 := netip.MustParseAddr("2001:4860:4860::8844")
			if rdnss.Servers[0] != want1 {
				t.Errorf("DNS[0] = %s, want %s", rdnss.Servers[0], want1)
			}
			if rdnss.Servers[1] != want2 {
				t.Errorf("DNS[1] = %s, want %s", rdnss.Servers[1], want2)
			}
		}
	}
	if !found {
		t.Error("missing RDNSS option")
	}
}

func TestBuildRA_NAT64(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:   "trust0",
			NAT64Prefix: "64:ff9b::/96",
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	var found bool
	for _, opt := range ra.Options {
		if pref64, ok := opt.(*ndp.PREF64); ok {
			found = true
			wantPrefix := netip.MustParsePrefix("64:ff9b::/96")
			if pref64.Prefix != wantPrefix {
				t.Errorf("PREF64 = %s, want %s", pref64.Prefix, wantPrefix)
			}
		}
	}
	if !found {
		t.Error("missing PREF64 option")
	}
}

func TestBuildRA_NAT64WithLifetime(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:       "trust0",
			NAT64Prefix:     "64:ff9b::/96",
			NAT64PrefixLife: 1800,
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	for _, opt := range ra.Options {
		if pref64, ok := opt.(*ndp.PREF64); ok {
			// PREF64 lifetime is quantized to 8-second granularity.
			want := 1800 * time.Second
			// Allow rounding to nearest 8s.
			diff := pref64.Lifetime - want
			if diff < 0 {
				diff = -diff
			}
			if diff > 8*time.Second {
				t.Errorf("PREF64 Lifetime = %v, want ~%v", pref64.Lifetime, want)
			}
			return
		}
	}
	t.Error("missing PREF64 option")
}

func TestBuildRA_LifetimeAndMTU(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:       "trust0",
			DefaultLifetime: 1800,
			MaxAdvInterval:  600,
			MinAdvInterval:  200,
			LinkMTU:         1280,
			Prefixes: []*config.RAPrefix{
				{
					Prefix:        "2001:db8::/64",
					OnLink:        true,
					Autonomous:    true,
					ValidLifetime: 86400,
					PreferredLife: 14400,
				},
			},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	if ra.RouterLifetime != 1800*time.Second {
		t.Errorf("RouterLifetime = %v, want 1800s", ra.RouterLifetime)
	}

	// Check MTU option.
	var foundMTU bool
	for _, opt := range ra.Options {
		if mtu, ok := opt.(*ndp.MTU); ok {
			foundMTU = true
			if mtu.MTU != 1280 {
				t.Errorf("MTU = %d, want 1280", mtu.MTU)
			}
		}
	}
	if !foundMTU {
		t.Error("missing MTU option")
	}

	// Check prefix lifetimes.
	for _, opt := range ra.Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			if pi.ValidLifetime != 86400*time.Second {
				t.Errorf("ValidLifetime = %v, want 86400s", pi.ValidLifetime)
			}
			if pi.PreferredLifetime != 14400*time.Second {
				t.Errorf("PreferredLifetime = %v, want 14400s", pi.PreferredLifetime)
			}
		}
	}
}

// TestBuildRA_PrefLifeClampedToValidLife is the #2271 regression. RFC 4861
// §4.6.2 requires PreferredLifetime <= ValidLifetime; buildRA must clamp the
// preferred lifetime down to the valid lifetime so a misconfigured (or
// 0-defaulted) pair never advertises a malformed PrefixInformation that
// conforming hosts (RFC 4862 §5.5.3) ignore.
//
// The matrix exercises: ordered pairs (no-op), the inverted pair that triggers
// the clamp, 0-config (defaults), a mix of an explicit valid life with an
// over-large preferred life, equal lifetimes, and the "infinite" (max-int)
// endpoints in both positions.
func TestBuildRA_PrefLifeClampedToValidLife(t *testing.T) {
	const infinite = 4294967295 // 0xffffffff: largest lifetime an operator can express
	cases := []struct {
		name      string
		valid     int // pfx.ValidLifetime config
		preferred int // pfx.PreferredLife config
		wantValid int // expected advertised valid lifetime (seconds)
		wantPref  int // expected advertised preferred lifetime (seconds)
	}{
		{"ordered_no_clamp", 86400, 14400, 86400, 14400},
		{"inverted_clamps_pref_down", 100, 200, 100, 100},
		{"equal_no_clamp", 3600, 3600, 3600, 3600},
		{"both_zero_uses_defaults", 0, 0, defaultValidLifetime, defaultPreferredLifetime},
		// valid=0 -> default valid (2592000), explicit pref below the default
		// valid: no clamp. defaultPreferredLifetime (604800) <= 2592000.
		{"valid_default_pref_explicit_ok", 0, 1000, defaultValidLifetime, 1000},
		// valid=0 -> default valid (2592000), explicit pref ABOVE the default
		// valid would be malformed -> clamp down to the default valid life.
		{"valid_default_pref_over_clamps", 0, defaultValidLifetime + 1, defaultValidLifetime, defaultValidLifetime},
		// pref=0 -> default preferred (604800); valid explicitly smaller ->
		// the defaulted preferred life must be clamped down to the valid life.
		{"pref_default_over_valid_clamps", 100, 0, 100, 100},
		// Infinite valid life: any preferred life (even infinite) is <= it.
		{"infinite_valid_finite_pref", infinite, 14400, infinite, 14400},
		{"infinite_both_equal", infinite, infinite, infinite, infinite},
		// Infinite preferred life but finite valid life: clamp the preferred
		// life all the way down to the finite valid life.
		{"infinite_pref_finite_valid_clamps", 86400, infinite, 86400, 86400},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &sender{
				cfg: &config.RAInterfaceConfig{
					Interface: "trust0",
					Prefixes: []*config.RAPrefix{
						{
							Prefix:        "2001:db8::/64",
							OnLink:        true,
							Autonomous:    true,
							ValidLifetime: tc.valid,
							PreferredLife: tc.preferred,
						},
					},
				},
				iface: &net.Interface{
					Name:         "trust0",
					HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				},
			}

			ra := s.buildRA()

			var pi *ndp.PrefixInformation
			for _, opt := range ra.Options {
				if p, ok := opt.(*ndp.PrefixInformation); ok {
					pi = p
					break
				}
			}
			if pi == nil {
				t.Fatal("missing prefix information option")
			}

			wantValid := time.Duration(tc.wantValid) * time.Second
			wantPref := time.Duration(tc.wantPref) * time.Second
			if pi.ValidLifetime != wantValid {
				t.Errorf("ValidLifetime = %v, want %v", pi.ValidLifetime, wantValid)
			}
			if pi.PreferredLifetime != wantPref {
				t.Errorf("PreferredLifetime = %v, want %v", pi.PreferredLifetime, wantPref)
			}

			// The RFC 4861 §4.6.2 invariant itself: preferred MUST NOT exceed
			// valid. This is the fail-on-revert pin — if the clamp is removed,
			// inverted/over-large cases advertise pref > valid and fail here.
			if pi.PreferredLifetime > pi.ValidLifetime {
				t.Errorf("RFC 4861 §4.6.2 violated: PreferredLifetime (%v) > ValidLifetime (%v)",
					pi.PreferredLifetime, pi.ValidLifetime)
			}
		})
	}
}

func TestBuildRA_MultipleInterfaces(t *testing.T) {
	m := New()
	// Verify manager starts empty.
	if len(m.senders) != 0 {
		t.Fatalf("new manager has %d senders, want 0", len(m.senders))
	}
}

func TestBuildRA_PrefixFlags(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{
				{Prefix: "2001:db8:1::/64", OnLink: false, Autonomous: false},
			},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	for _, opt := range ra.Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			if pi.OnLink {
				t.Error("OnLink should be false")
			}
			if pi.AutonomousAddressConfiguration {
				t.Error("Autonomous should be false")
			}
			return
		}
	}
	t.Error("missing prefix information option")
}

func TestBuildRA_Preference(t *testing.T) {
	tests := []struct {
		pref string
		want ndp.Preference
	}{
		{"high", ndp.High},
		{"low", ndp.Low},
		{"medium", ndp.Medium},
		{"", ndp.Medium},
	}

	for _, tt := range tests {
		s := &sender{
			cfg: &config.RAInterfaceConfig{
				Interface:  "trust0",
				Preference: tt.pref,
			},
			iface: &net.Interface{
				Name:         "trust0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
		}

		ra := s.buildRA()
		if ra.RouterSelectionPreference != tt.want {
			t.Errorf("pref=%q: got %v, want %v", tt.pref, ra.RouterSelectionPreference, tt.want)
		}
	}
}

func TestConfigEqual_Same(t *testing.T) {
	a := &config.RAInterfaceConfig{
		Interface:     "trust0",
		ManagedConfig: true,
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
		DNSServers: []string{"2001:4860:4860::8888"},
	}
	b := &config.RAInterfaceConfig{
		Interface:     "trust0",
		ManagedConfig: true,
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
		DNSServers: []string{"2001:4860:4860::8888"},
	}

	if !configEqual(a, b) {
		t.Error("identical configs should be equal")
	}
}

func TestConfigEqual_Different(t *testing.T) {
	a := &config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
		},
	}
	b := &config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes: []*config.RAPrefix{
			{Prefix: "2001:db8:1::/64", OnLink: true, Autonomous: true},
		},
	}

	if configEqual(a, b) {
		t.Error("different prefixes should not be equal")
	}
}

func TestConfigEqual_DifferentDNS(t *testing.T) {
	a := &config.RAInterfaceConfig{
		Interface:  "trust0",
		DNSServers: []string{"2001:4860:4860::8888"},
	}
	b := &config.RAInterfaceConfig{
		Interface:  "trust0",
		DNSServers: []string{"2001:4860:4860::8844"},
	}

	if configEqual(a, b) {
		t.Error("different DNS should not be equal")
	}
}

func TestConfigEqual_DifferentFlags(t *testing.T) {
	a := &config.RAInterfaceConfig{Interface: "trust0", ManagedConfig: true}
	b := &config.RAInterfaceConfig{Interface: "trust0", ManagedConfig: false}

	if configEqual(a, b) {
		t.Error("different ManagedConfig should not be equal")
	}
}

// TestConfigEqual_DifferentReachableTime asserts that a commit changing ONLY
// reachable-time is detected as NOT-equal so Apply restarts the sender and the
// new value reaches the wire (#4570). RED-on-revert: drop the ReachableTime
// comparison from configEqual and this fails.
func TestConfigEqual_DifferentReachableTime(t *testing.T) {
	a := &config.RAInterfaceConfig{Interface: "trust0", ReachableTime: 30000}
	b := &config.RAInterfaceConfig{Interface: "trust0", ReachableTime: 60000}

	if configEqual(a, b) {
		t.Error("different ReachableTime should not be equal (sender must restart)")
	}
}

// TestConfigEqual_DifferentRetransTimer asserts that a commit changing ONLY
// retransmit-timer is detected as NOT-equal (#4570). RED-on-revert: drop the
// RetransTimer comparison from configEqual and this fails.
func TestConfigEqual_DifferentRetransTimer(t *testing.T) {
	a := &config.RAInterfaceConfig{Interface: "trust0", RetransTimer: 1000}
	b := &config.RAInterfaceConfig{Interface: "trust0", RetransTimer: 2000}

	if configEqual(a, b) {
		t.Error("different RetransTimer should not be equal (sender must restart)")
	}
}

// TestConfigEqual_EquivalentNAT64Prefix asserts that two textually-different
// but equivalent NAT64 CIDR forms compare EQUAL, so a cosmetic re-type does
// not trigger a spurious RA sender restart (#4590 A5-03). RED-on-revert:
// restore the raw-string `a.NAT64Prefix != b.NAT64Prefix` compare and this
// fails (the two forms are unequal as strings).
func TestConfigEqual_EquivalentNAT64Prefix(t *testing.T) {
	a := &config.RAInterfaceConfig{Interface: "trust0", NAT64Prefix: "64:ff9b::/96"}
	b := &config.RAInterfaceConfig{Interface: "trust0", NAT64Prefix: "0064:ff9b:0:0::/96"}

	if !configEqual(a, b) {
		t.Error("equivalent NAT64 prefix forms should be equal (no spurious restart)")
	}
}

// TestConfigEqual_DifferentNAT64Prefix asserts a genuine NAT64 prefix change
// is still detected as NOT-equal (the normalization must not mask real edits).
func TestConfigEqual_DifferentNAT64Prefix(t *testing.T) {
	a := &config.RAInterfaceConfig{Interface: "trust0", NAT64Prefix: "64:ff9b::/96"}
	b := &config.RAInterfaceConfig{Interface: "trust0", NAT64Prefix: "2001:db8::/96"}

	if configEqual(a, b) {
		t.Error("different NAT64 prefixes should not be equal (sender must restart)")
	}
}

// TestConfigEqual_EquivalentAdvertisedPrefix asserts the same normalization
// applies to advertised on-link prefixes, not just NAT64 (#4590 A5-03).
func TestConfigEqual_EquivalentAdvertisedPrefix(t *testing.T) {
	a := &config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes:  []*config.RAPrefix{{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true}},
	}
	b := &config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes:  []*config.RAPrefix{{Prefix: "2001:0db8:0:0::/64", OnLink: true, Autonomous: true}},
	}

	if !configEqual(a, b) {
		t.Error("equivalent advertised prefix forms should be equal (no spurious restart)")
	}
}

// TestPrefixEqual_MalformedFallsBackToStringCompare asserts that when a CIDR
// fails to parse, prefixEqual falls back to an exact string compare so a real
// change is never masked (#4590 A5-03).
func TestPrefixEqual_MalformedFallsBackToStringCompare(t *testing.T) {
	if prefixEqual("not-a-cidr", "also-not-a-cidr") {
		t.Error("distinct unparseable strings must not be treated as equal")
	}
	if !prefixEqual("", "") {
		t.Error("two unset (empty) prefixes must be equal")
	}
	if !prefixEqual("garbage", "garbage") {
		t.Error("identical unparseable strings must be equal via string fallback")
	}
	if prefixEqual("64:ff9b::/96", "") {
		t.Error("a set prefix must differ from unset")
	}
}

// TestConfigEqual_SameTimers guards against a spurious restart: two configs
// with identical reachable-time/retransmit-timer (including the 0=unspecified
// default) stay equal, so a no-op commit does not create an RA gap.
func TestConfigEqual_SameTimers(t *testing.T) {
	a := &config.RAInterfaceConfig{Interface: "trust0", ReachableTime: 30000, RetransTimer: 1000}
	b := &config.RAInterfaceConfig{Interface: "trust0", ReachableTime: 30000, RetransTimer: 1000}

	if !configEqual(a, b) {
		t.Error("identical timers should be equal (no spurious sender restart)")
	}
}

func TestRandomAdvInterval(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			MaxAdvInterval: 600,
			MinAdvInterval: 200,
		},
	}

	for i := 0; i < 100; i++ {
		d := s.randomAdvInterval()
		if d < 200*time.Second || d > 600*time.Second {
			t.Errorf("interval %v out of [200s, 600s]", d)
		}
	}
}

func TestRandomAdvInterval_Defaults(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{},
	}

	for i := 0; i < 100; i++ {
		d := s.randomAdvInterval()
		// Default max=600, min=200 (600/3)
		if d < 200*time.Second || d > 600*time.Second {
			t.Errorf("interval %v out of [200s, 600s]", d)
		}
	}
}

func TestBuildRA_RethVirtualMAC(t *testing.T) {
	// reth0, node 0 RETH virtual MAC: 02:bf:72:CC:RR:(2*index+node) = ...:00.
	rethMAC := net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x01, 0x00}
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{
				{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
			},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: rethMAC,
		},
	}

	ra := s.buildRA()

	// Verify SLLA uses the RETH virtual MAC.
	for _, opt := range ra.Options {
		if lla, ok := opt.(*ndp.LinkLayerAddress); ok && lla.Direction == ndp.Source {
			if lla.Addr.String() != rethMAC.String() {
				t.Errorf("SLLA = %s, want RETH MAC %s", lla.Addr, rethMAC)
			}
			return
		}
	}
	t.Error("missing source link-layer address option")
}

func TestManagerDiff_AddRemove(t *testing.T) {
	m := New()

	// Start with no senders.
	if len(m.senders) != 0 {
		t.Fatalf("new manager has %d senders", len(m.senders))
	}

	// Calling Clear on empty manager should not error.
	if err := m.Clear(); err != nil {
		t.Fatalf("Clear on empty: %v", err)
	}

	// Calling Withdraw on empty manager should not error.
	if err := m.Withdraw(); err != nil {
		t.Fatalf("Withdraw on empty: %v", err)
	}
}

// TestBuildRA_MarshalRoundtrip verifies the built RA can be marshaled
// to binary and parsed back by the ndp library.
func TestBuildRA_MarshalRoundtrip(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:       "trust0",
			ManagedConfig:   true,
			OtherStateful:   true,
			DefaultLifetime: 1800,
			Preference:      "high",
			LinkMTU:         1280,
			Prefixes: []*config.RAPrefix{
				{
					Prefix:        "2001:db8::/64",
					OnLink:        true,
					Autonomous:    true,
					ValidLifetime: 86400,
					PreferredLife: 14400,
				},
			},
			DNSServers: []string{"2001:4860:4860::8888"},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	// Marshal to binary.
	b, err := ndp.MarshalMessage(ra)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}

	// Parse back.
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	parsed, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatal("parsed message is not RouterAdvertisement")
	}

	if parsed.RouterLifetime != 1800*time.Second {
		t.Errorf("parsed RouterLifetime = %v, want 1800s", parsed.RouterLifetime)
	}
	if !parsed.ManagedConfiguration {
		t.Error("parsed ManagedConfiguration should be true")
	}
	if !parsed.OtherConfiguration {
		t.Error("parsed OtherConfiguration should be true")
	}
	if parsed.RouterSelectionPreference != ndp.High {
		t.Errorf("parsed Preference = %v, want High", parsed.RouterSelectionPreference)
	}
}

// TestBuildRA_PREF64MarshalRoundtrip verifies that the PREF64 option
// survives marshal+parse roundtrip and appears in the raw bytes.
func TestBuildRA_PREF64MarshalRoundtrip(t *testing.T) {
	s := &sender{
		cfg: &config.RAInterfaceConfig{
			Interface:       "trust0",
			NAT64Prefix:     "64:ff9b::/96",
			NAT64PrefixLife: 1800,
			Prefixes: []*config.RAPrefix{
				{
					Prefix:     "2001:db8::/64",
					OnLink:     true,
					Autonomous: true,
				},
			},
			DNSServers: []string{"2001:4860:4860::8888"},
		},
		iface: &net.Interface{
			Name:         "trust0",
			HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
	}

	ra := s.buildRA()

	// Verify PREF64 option is in the RA struct.
	var foundInStruct bool
	for _, opt := range ra.Options {
		if _, ok := opt.(*ndp.PREF64); ok {
			foundInStruct = true
		}
	}
	if !foundInStruct {
		t.Fatal("PREF64 option not in RA struct before marshal")
	}

	// Marshal to binary.
	b, err := ndp.MarshalMessage(ra)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}

	// Scan raw bytes for option type 38 (PREF64).
	// RA header is 4 (ICMPv6) + 12 (RA body) = 16 bytes.
	// Options start at offset 16.
	var foundRaw bool
	off := 16
	for off+2 <= len(b) {
		optType := b[off]
		optLen := int(b[off+1]) * 8
		if optLen == 0 {
			break
		}
		t.Logf("raw option: type=%d len=%d at offset %d", optType, optLen, off)
		if optType == 38 {
			foundRaw = true
		}
		off += optLen
	}
	if !foundRaw {
		t.Fatalf("PREF64 (type 38) not found in raw marshaled bytes (len=%d): %x", len(b), b)
	}

	// Parse back.
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	parsed, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatal("parsed message is not RouterAdvertisement")
	}

	var foundParsed bool
	for _, opt := range parsed.Options {
		if pref64, ok := opt.(*ndp.PREF64); ok {
			foundParsed = true
			wantPrefix := netip.MustParsePrefix("64:ff9b::/96")
			if pref64.Prefix != wantPrefix {
				t.Errorf("parsed PREF64 prefix = %s, want %s", pref64.Prefix, wantPrefix)
			}
			// 1800s / 8 = 225, so roundtrip should be 225*8 = 1800s
			if pref64.Lifetime != 1800*time.Second {
				t.Errorf("parsed PREF64 lifetime = %v, want 1800s", pref64.Lifetime)
			}
		}
	}
	if !foundParsed {
		t.Error("PREF64 option not found after parse roundtrip")
	}
}
