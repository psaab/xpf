package daemon

// #14606: a DHCPv6-PD delegation with preferred lifetime 0 (deprecated,
// RFC 8415 §21.22) must stay preferred=0 through buildRAConfigs.
//
// Pre-fix daemon_ra.go copied lifetimes only when >0, so preferred 0
// collided with RAPrefix's "0 = unset/default" sentinel and pkg/ra
// re-advertised the dying prefix at the 7-day default (clamped to valid).
//
// RED-on-revert: dropping PreferredLifeSet from the PD construction (or
// reverting to the >0 guard) makes the deprecated cell report
// PreferredLifeSet=false.

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

func raPrefixesFor14606(t *testing.T, pds []dhcp.DelegatedPrefix) []*config.RAPrefix {
	t.Helper()
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "trust0", pds)
	d := &Daemon{dhcp: mgr}
	ras := d.buildRAConfigs(&config.Config{})
	for _, ra := range ras {
		if ra.Interface == "trust0" {
			return ra.Prefixes
		}
	}
	t.Fatalf("buildRAConfigs produced no RA config for trust0; got %d configs", len(ras))
	return nil
}

func TestBuildRAConfigs_14606_DeprecatedPDKeepsPreferredZero(t *testing.T) {
	pfxs := raPrefixesFor14606(t, []dhcp.DelegatedPrefix{
		{
			Interface:         "ge-0/0/3",
			Prefix:            netip.MustParsePrefix("2606:4700:900d::/64"),
			PreferredLifetime: 0,
			ValidLifetime:     7200 * time.Second,
		},
		{
			Interface:         "ge-0/0/3",
			Prefix:            netip.MustParsePrefix("2606:4700:900e::/64"),
			PreferredLifetime: 3600 * time.Second,
			ValidLifetime:     7200 * time.Second,
		},
	})
	byPrefix := map[string]*config.RAPrefix{}
	for _, p := range pfxs {
		byPrefix[p.Prefix] = p
	}
	dep := byPrefix["2606:4700:900d::/64"]
	if dep == nil {
		t.Fatalf("deprecated PD missing; got %v", pfxs)
	}
	if !dep.Delegated {
		t.Error("deprecated PD must remain Delegated")
	}
	if !dep.PreferredLifeSet {
		t.Error("PreferredLifeSet=false for IAPREFIX{preferred 0, valid 7200}: " +
			"the explicit deprecated 0 is lost and pkg/ra will substitute the 7-day default (#14606)")
	}
	if dep.PreferredLife != 0 {
		t.Errorf("PreferredLife=%d, want 0 (deprecated)", dep.PreferredLife)
	}
	if dep.ValidLifetime != 7200 {
		t.Errorf("ValidLifetime=%d, want 7200", dep.ValidLifetime)
	}
	// Positive control in the same run: a normal preferred lifetime is
	// carried verbatim and also marked explicit.
	ctl := byPrefix["2606:4700:900e::/64"]
	if ctl == nil {
		t.Fatalf("control PD missing; got %v", pfxs)
	}
	if !ctl.PreferredLifeSet || ctl.PreferredLife != 3600 || ctl.ValidLifetime != 7200 {
		t.Errorf("control = set=%v pref=%d valid=%d, want true/3600/7200",
			ctl.PreferredLifeSet, ctl.PreferredLife, ctl.ValidLifetime)
	}
}

// #14606 x #14598 x #15057: a prefix granted preferred 3600 / valid 7200
// whose preferred lifetime has fully decayed (elapsed 4000s) while valid
// remains must advertise as deprecated. Since #15057 the decay happens in
// pkg/ra buildRA at send time, so the daemon half carries the granted
// lifetimes with PreferredLifeSet and the absolute expiries; buildRA then
// emits preferred 0 / valid 3200 (pinned in pkg/ra sender_expiry tests).
func TestBuildRAConfigs_14606_DecayedToZeroPreferred(t *testing.T) {
	obtained := time.Now().Add(-4000 * time.Second)
	pfxs := raPrefixesFor14606(t, []dhcp.DelegatedPrefix{
		{
			Interface:         "ge-0/0/3",
			Prefix:            netip.MustParsePrefix("2606:4700:900d::/64"),
			PreferredLifetime: 3600 * time.Second,
			ValidLifetime:     7200 * time.Second,
			Obtained:          obtained,
		},
	})
	if len(pfxs) != 1 {
		t.Fatalf("got %d prefixes, want 1", len(pfxs))
	}
	p := pfxs[0]
	if !p.PreferredLifeSet {
		t.Errorf("decayed-to-zero PreferredLifeSet=false, want true (deprecated signal must survive, #14606)")
	}
	if p.PreferredLife != 3600 || p.ValidLifetime != 7200 {
		t.Errorf("carried lifetimes = pref %d / valid %d, want granted 3600/7200 (decay at send time, #15057)", p.PreferredLife, p.ValidLifetime)
	}
	if want := obtained.Add(3600 * time.Second).UnixNano(); p.PreferredExpiresAt != want {
		t.Errorf("PreferredExpiresAt=%d, want %d (Obtained+3600s)", p.PreferredExpiresAt, want)
	}
	if want := obtained.Add(7200 * time.Second).UnixNano(); p.ValidExpiresAt != want {
		t.Errorf("ValidExpiresAt=%d, want %d (Obtained+7200s)", p.ValidExpiresAt, want)
	}
}
