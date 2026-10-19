package daemon

// #15057 (A26-01): decaying DHCPv6-PD lifetimes in the RA desired set
// restarted the cluster RA sender on every 2s reconcile pass.
//
// buildRAConfigs baked the decayed remaining lifetime into
// RAPrefix.ValidLifetime/PreferredLife, so raDesiredHash (JSON marshal
// including lifetimes) and ra.configEqual both saw a new value every
// second and Apply hard-restarted the sender (3-RA burst + new socket).
//
// Fix: buildRAConfigs carries the ABSOLUTE expiry (Obtained+granted) on
// RAPrefix.ValidExpiresAt/PreferredExpiresAt plus the granted lifetimes;
// pkg/ra buildRA computes the remaining lifetime at send time. The
// desired set, its hash, and configEqual are then stable as wall time
// advances, and a renewal that moves the expiry still restarts.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

func seedPD15057(t *testing.T, obtained time.Time, pref, valid time.Duration) (*Daemon, time.Time) {
	t.Helper()
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", []dhcp.DelegatedPrefix{{
		Interface:         "ge-0/0/3",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: pref,
		ValidLifetime:     valid,
		Obtained:          obtained,
	}})
	d := &Daemon{dhcp: mgr}
	// Pin the daemon clock to the seed's obtained instant so the
	// granted lifetimes and expiries are deterministic.
	orig := timeNowForRA
	timeNowForRA = func() time.Time { return obtained }
	t.Cleanup(func() { timeNowForRA = orig })
	return d, obtained
}

func onlyPrefix15057(t *testing.T, ras []*config.RAInterfaceConfig) *config.RAPrefix {
	t.Helper()
	for _, ra := range ras {
		if ra.Interface == "trust0" && len(ra.Prefixes) == 1 {
			return ra.Prefixes[0]
		}
	}
	t.Fatalf("want one trust0 prefix, got %+v", ras)
	return nil
}

// TestBuildRAConfigs15057_CarriesAbsoluteExpiry: the desired prefix
// carries Obtained+granted as absolute expiries plus the granted
// lifetimes — NOT a decayed remaining value.
func TestBuildRAConfigs15057_CarriesAbsoluteExpiry(t *testing.T) {
	obtained := time.Now().Add(-10 * time.Second)
	d, _ := seedPD15057(t, obtained, 3600*time.Second, 7200*time.Second)
	p := onlyPrefix15057(t, d.buildRAConfigs(&config.Config{}))
	if !p.Delegated {
		t.Error("PD prefix must remain Delegated")
	}
	if p.ValidLifetime != 7200 || p.PreferredLife != 3600 {
		t.Errorf("granted lifetimes = valid %d / pref %d, want 7200/3600 (not decayed)", p.ValidLifetime, p.PreferredLife)
	}
	if !p.PreferredLifeSet {
		t.Error("PreferredLifeSet=false, want true (#14606)")
	}
	if want := obtained.Add(7200 * time.Second).UnixNano(); p.ValidExpiresAt != want {
		t.Errorf("ValidExpiresAt=%d, want %d (Obtained+7200s)", p.ValidExpiresAt, want)
	}
	if want := obtained.Add(3600 * time.Second).UnixNano(); p.PreferredExpiresAt != want {
		t.Errorf("PreferredExpiresAt=%d, want %d (Obtained+3600s)", p.PreferredExpiresAt, want)
	}
}

// TestDesiredHash15057_StableAcrossDecayingPasses is the decisive RED:
// N reconcile passes 2s apart over a decaying PD must produce ONE hash
// (one apply). Pre-fix each pass decays by 2 more seconds so every hash
// differs and reconcileClusterRAServices applies (and restarts) every pass.
func TestDesiredHash15057_StableAcrossDecayingPasses(t *testing.T) {
	obtained := time.Now().Add(-10 * time.Second)
	d, _ := seedPD15057(t, obtained, 3600*time.Second, 7200*time.Second)
	orig := timeNowForRA
	defer func() { timeNowForRA = orig }()

	var first string
	for i := range 5 {
		now := obtained.Add(time.Duration(i) * 2 * time.Second)
		timeNowForRA = func() time.Time { return now }
		desired := d.buildRAConfigs(&config.Config{})
		h := raDesiredHash(desired)
		if h == "" {
			t.Fatalf("pass %d: empty hash for live PD", i)
		}
		if i == 0 {
			first = h
			continue
		}
		if h != first {
			t.Fatalf("pass %d: hash churned %q -> %q; the 2s reconcile would re-apply and restart the RA sender every pass (#15057)", i, first, h)
		}
	}
}

// TestBuildRAConfigs15057_RenewalMovesExpiry: a renewal (fresh Obtained)
// moves the expiry, so the hash MUST change — the fix must not latch a
// stale expiry forever.
func TestBuildRAConfigs15057_RenewalMovesExpiry(t *testing.T) {
	obtained := time.Now().Add(-10 * time.Second)
	d1, _ := seedPD15057(t, obtained, 3600*time.Second, 7200*time.Second)
	h1 := raDesiredHash(d1.buildRAConfigs(&config.Config{}))

	renewed := obtained.Add(time.Hour)
	d2, _ := seedPD15057(t, renewed, 3600*time.Second, 7200*time.Second)
	h2 := raDesiredHash(d2.buildRAConfigs(&config.Config{}))
	if h1 == h2 {
		t.Fatal("renewal with fresh Obtained produced identical hash; the renewed expiry would never be applied")
	}
	if h1 == "" || h2 == "" {
		t.Fatal("empty hash for live PD")
	}
}

// TestBuildRAConfigs15057_DecayedToZeroPreferredKeepsExpiryShape: a PD
// granted preferred 3600/valid 7200 obtained 4000s ago is already past
// its preferred expiry but still valid. It must still be carried (with
// PreferredLifeSet and both expiries) so buildRA emits preferred=0 at
// send time instead of the prefix vanishing or defaulting.
func TestBuildRAConfigs15057_DecayedToZeroPreferredKeepsExpiryShape(t *testing.T) {
	obtained := time.Now().Add(-4000 * time.Second)
	d, _ := seedPD15057(t, obtained, 3600*time.Second, 7200*time.Second)
	orig := timeNowForRA
	defer func() { timeNowForRA = orig }()
	timeNowForRA = func() time.Time { return obtained.Add(4000 * time.Second) }
	p := onlyPrefix15057(t, d.buildRAConfigs(&config.Config{}))
	if !p.PreferredLifeSet {
		t.Error("PreferredLifeSet=false for decayed-to-zero PD, want true")
	}
	if want := obtained.Add(7200 * time.Second).UnixNano(); p.ValidExpiresAt != want {
		t.Errorf("ValidExpiresAt=%d, want %d", p.ValidExpiresAt, want)
	}
	if want := obtained.Add(3600 * time.Second).UnixNano(); p.PreferredExpiresAt != want {
		t.Errorf("PreferredExpiresAt=%d, want %d", p.PreferredExpiresAt, want)
	}
}

// TestBuildRAConfigs15057_ZeroObtainedHasNoExpiry: a test-seeded PD with
// no clock (zero Obtained, granted valid 0) keeps the legacy sender-default
// sentinel: no expiry, lifetimes 0.
func TestBuildRAConfigs15057_ZeroObtainedHasNoExpiry(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", []dhcp.DelegatedPrefix{{
		Interface: "ge-0/0/3",
		Prefix:    netip.MustParsePrefix("2001:db8:1000::/48"),
	}})
	d := &Daemon{dhcp: mgr}
	p := onlyPrefix15057(t, d.buildRAConfigs(&config.Config{}))
	if p.ValidExpiresAt != 0 || p.PreferredExpiresAt != 0 {
		t.Errorf("expiries = %d/%d, want 0/0 for zero-obtained seed", p.ValidExpiresAt, p.PreferredExpiresAt)
	}
	if p.ValidLifetime != 0 {
		t.Errorf("ValidLifetime=%d, want 0 (sender default sentinel)", p.ValidLifetime)
	}
}
