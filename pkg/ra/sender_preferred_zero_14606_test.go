package ra

// #14606: an explicitly-set preferred lifetime of 0 (deprecated prefix,
// RFC 4862 §5.5.4 / RFC 8415 §21.22 for the PD source) must reach the wire
// as preferred=0, not the 7-day default.
//
// Pre-fix buildRA treated every PreferredLife <= 0 as unset, so a delegated
// IAPREFIX{0,7200} was emitted as preferred=7200 (default clamped to valid).
//
// RED-on-revert: restoring `if prefLife <= 0 { prefLife = default }` for the
// Delegated+Set cell (or ignoring PreferredLifeSet in buildRA) makes the
// deprecated cell emit 7200.

import (
	"net"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// wirePIO14606 marshals a single-prefix RA and returns the wire lifetimes.
func wirePIO14606(t *testing.T, pfx *config.RAPrefix) (valid, pref uint32, autonomous bool) {
	t.Helper()
	s := newSender(&config.RAInterfaceConfig{
		Interface:      "lo",
		MaxAdvInterval: 600,
		MinAdvInterval: 200,
		Prefixes:       []*config.RAPrefix{pfx},
	}, &net.Interface{Name: "lo", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}})
	ra := s.buildRA()
	if ra == nil {
		t.Fatal("buildRA returned nil")
	}
	b, err := ndp.MarshalMessage(ra)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	got, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatalf("parsed %T, want *ndp.RouterAdvertisement", msg)
	}
	var pi *ndp.PrefixInformation
	for _, opt := range got.Options {
		if p, ok := opt.(*ndp.PrefixInformation); ok {
			if pi != nil {
				t.Fatal("more than one PIO on the wire")
			}
			pi = p
		}
	}
	if pi == nil {
		t.Fatal("no PIO on the wire")
	}
	return uint32(pi.ValidLifetime / time.Second), uint32(pi.PreferredLifetime / time.Second), pi.AutonomousAddressConfiguration
}

func TestBuildRA_14606_DeprecatedDelegatedPreferredZero(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pfx       *config.RAPrefix
		wantValid uint32
		wantPref  uint32
	}{
		{
			name: "delegated deprecated preferred 0 stays 0",
			pfx: &config.RAPrefix{Prefix: "2606:4700:900d::/64", OnLink: true, Autonomous: true,
				Delegated: true, ValidLifetime: 7200, PreferredLife: 0, PreferredLifeSet: true},
			wantValid: 7200, wantPref: 0,
		},
		{
			name: "delegated normal preferred preserved",
			pfx: &config.RAPrefix{Prefix: "2606:4700:900e::/64", OnLink: true, Autonomous: true,
				Delegated: true, ValidLifetime: 7200, PreferredLife: 3600, PreferredLifeSet: true},
			wantValid: 7200, wantPref: 3600,
		},
		{
			name:      "operator no lifetime leaf still gets 7-day default",
			pfx:       &config.RAPrefix{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
			wantValid: defaultValidLifetime, wantPref: defaultPreferredLifetime,
		},
		{
			name: "operator explicit preferred 0 via compiler flag stays 0",
			pfx: &config.RAPrefix{Prefix: "2001:db8:1::/64", OnLink: true, Autonomous: true,
				ValidLifetime: 7200, PreferredLife: 0, PreferredLifeSet: true},
			wantValid: 7200, wantPref: 0,
		},
		{
			// Backward compat: a hand-built / peer-synced delegated prefix
			// that predates PreferredLifeSet (flag false, value 0) keeps
			// the historical default, exactly like an unset operator prefix.
			name: "delegated legacy unset preferred still defaults",
			pfx: &config.RAPrefix{Prefix: "2606:4700:900f::/64", OnLink: true, Autonomous: true,
				Delegated: true, ValidLifetime: 7200},
			wantValid: 7200, wantPref: 7200, // default 604800 clamped to valid 7200
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid, pref, autonomous := wirePIO14606(t, tc.pfx)
			if valid != tc.wantValid || pref != tc.wantPref {
				t.Errorf("wire PIO valid=%d preferred=%d, want %d/%d (#14606)", valid, pref, tc.wantValid, tc.wantPref)
			}
			if !autonomous {
				t.Error("A flag must stay true (deprecated only affects preferred lifetime, RFC 4862 §5.5.4)")
			}
		})
	}
}

// TestConfigEqual_14606_PreferredLifeSetRestarts pins the change detector:
// toggling only the explicit-set flag changes the wire preferred lifetime
// (0 vs 7-day default), so Apply must restart the sender.
func TestConfigEqual_14606_PreferredLifeSetRestarts(t *testing.T) {
	mk := func(set bool) *config.RAInterfaceConfig {
		return &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true,
				Delegated: true, ValidLifetime: 7200, PreferredLife: 0, PreferredLifeSet: set}},
		}
	}
	if configEqual(mk(true), mk(false)) {
		t.Error("configEqual=true for PreferredLifeSet true vs false with PreferredLife=0; " +
			"Apply would keep the stale sender and the deprecated signal would never reach the wire (#14606)")
	}
	if !configEqual(mk(true), mk(true)) {
		t.Error("configEqual=false for identical explicit-zero prefixes; want true")
	}
}
