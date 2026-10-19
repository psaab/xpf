package ra

// #15057 (A26-01): buildRA must compute the remaining PIO lifetime from
// the absolute expiry at send time — never more than remains under the
// send clock (RFC 9096 L-15) — while prefixes without an expiry keep the
// historical granted/default behavior.
//
// RED-on-revert: dropping the ValidExpiresAt branch makes the decaying
// cells emit the granted 7200/3600 verbatim at every pinned instant.

import (
	"net"
	"testing"
	"time"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

func pinRAClock15057(t *testing.T, now time.Time) {
	t.Helper()
	orig := timeNowForRA
	timeNowForRA = func() time.Time { return now }
	t.Cleanup(func() { timeNowForRA = orig })
}

func wirePIO15057(t *testing.T, pfx *config.RAPrefix) (valid, pref uint32, present bool) {
	t.Helper()
	s := newSender(&config.RAInterfaceConfig{
		Interface:      "trust0",
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
	for _, opt := range got.Options {
		if pi, ok := opt.(*ndp.PrefixInformation); ok {
			return uint32(pi.ValidLifetime / time.Second), uint32(pi.PreferredLifetime / time.Second), true
		}
	}
	return 0, 0, false
}

func TestBuildRA_15057_RemainingFromExpiryAtSendTime(t *testing.T) {
	obtained := time.Unix(1_700_000_000, 0)
	mk := func() *config.RAPrefix {
		return &config.RAPrefix{
			Prefix: "2606:4700:900d::/64", OnLink: true, Autonomous: true,
			Delegated: true, ValidLifetime: 7200, PreferredLife: 3600, PreferredLifeSet: true,
			ValidExpiresAt:     obtained.Add(7200 * time.Second).UnixNano(),
			PreferredExpiresAt: obtained.Add(3600 * time.Second).UnixNano(),
		}
	}
	for _, tc := range []struct {
		name       string
		now        time.Time
		wantValid  uint32
		wantPref   uint32
		wantAbsent bool
	}{
		{"at grant", obtained, 7200, 3600, false},
		{"60s later decays", obtained.Add(60 * time.Second), 7140, 3540, false},
		{"preferred expired stays deprecated", obtained.Add(4000 * time.Second), 3200, 0, false},
		{"valid expired omits PIO", obtained.Add(7200 * time.Second), 0, 0, true},
		{"past valid expiry omits PIO", obtained.Add(7300 * time.Second), 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinRAClock15057(t, tc.now)
			valid, pref, present := wirePIO15057(t, mk())
			if tc.wantAbsent {
				if present {
					t.Fatalf("PIO present with valid=%d, want omitted past expiry", valid)
				}
				return
			}
			if !present {
				t.Fatal("PIO missing, want present")
			}
			if valid != tc.wantValid || pref != tc.wantPref {
				t.Errorf("wire lifetimes valid=%d pref=%d, want %d/%d (remaining at %v)", valid, pref, tc.wantValid, tc.wantPref, tc.now)
			}
			if valid > 7200 {
				t.Errorf("valid=%d exceeds granted 7200", valid)
			}
		})
	}
}

// TestBuildRA_15057_NoExpiryKeepsGrantedAndDefaults is the control:
// prefixes without an expiry (operator, infinite, zero-obtained) are
// byte-identical to the pre-fix wire at any clock.
func TestBuildRA_15057_NoExpiryKeepsGrantedAndDefaults(t *testing.T) {
	pinRAClock15057(t, time.Unix(1_800_000_000, 0))
	for _, tc := range []struct {
		name      string
		pfx       *config.RAPrefix
		wantValid uint32
		wantPref  uint32
	}{
		{
			name:      "delegated granted without expiry",
			pfx:       &config.RAPrefix{Prefix: "2606:4700:900e::/64", OnLink: true, Autonomous: true, Delegated: true, ValidLifetime: 7200, PreferredLife: 3600, PreferredLifeSet: true},
			wantValid: 7200, wantPref: 3600,
		},
		{
			name:      "operator defaults",
			pfx:       &config.RAPrefix{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true},
			wantValid: defaultValidLifetime, wantPref: defaultPreferredLifetime,
		},
		{
			name:      "delegated deprecated without expiry",
			pfx:       &config.RAPrefix{Prefix: "2606:4700:900f::/64", OnLink: true, Autonomous: true, Delegated: true, ValidLifetime: 7200, PreferredLife: 0, PreferredLifeSet: true},
			wantValid: 7200, wantPref: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid, pref, present := wirePIO15057(t, tc.pfx)
			if !present {
				t.Fatal("PIO missing")
			}
			if valid != tc.wantValid || pref != tc.wantPref {
				t.Errorf("wire valid=%d pref=%d, want %d/%d", valid, pref, tc.wantValid, tc.wantPref)
			}
		})
	}
}

// TestConfigEqual_15057_ExpiryIsIdentity: the expiries are wire-affecting
// (they decide the send-time lifetimes), so moving one must restart the
// sender, while identical expiries must not.
func TestConfigEqual_15057_ExpiryIsIdentity(t *testing.T) {
	mk := func(ve, pe int64) *config.RAInterfaceConfig {
		return &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{{Prefix: "2001:db8::/64", OnLink: true, Autonomous: true,
				Delegated: true, ValidLifetime: 7200, PreferredLife: 3600, PreferredLifeSet: true,
				ValidExpiresAt: ve, PreferredExpiresAt: pe}},
		}
	}
	if !configEqual(mk(100, 50), mk(100, 50)) {
		t.Error("identical expiries reported unequal; sender would restart every reconcile")
	}
	if configEqual(mk(100, 50), mk(200, 50)) {
		t.Error("different ValidExpiresAt reported equal; renewed lifetime would never reach the wire")
	}
	if configEqual(mk(100, 50), mk(100, 60)) {
		t.Error("different PreferredExpiresAt reported equal; renewed preferred lifetime would never reach the wire")
	}
	if configEqual(mk(0, 0), mk(100, 50)) {
		t.Error("expiry added reported equal; send-time decay would never start")
	}
}
