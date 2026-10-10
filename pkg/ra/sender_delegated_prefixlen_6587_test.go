// #6587 part B: pkg/ra had no prefix-length floor of its own, so a DELEGATED
// /0 that survived the upstream checks was advertised on-link + autonomous to
// the whole LAN.
//
// WHY THIS COULD NOT SIMPLY BE FILTERED, and why #6581 deliberately left it.
// #6581 closed the same class at the DHCPv6 DECODER (an IA_PD prefix-length of
// 0 or >128 is refused before it becomes a DelegatedPrefix), and its own test
// file records the reason it stopped there: by the time a prefix reaches
// pkg/ra it is "indistinguishable from an operator-authored
// `set interfaces <if> ipv6 router-advertisement prefix ::/0`" — which is
// legitimate configuration a naive floor would silently break.
//
// So the fix is not a floor, it is PROVENANCE. config.RAPrefix.Delegated is
// set only by buildRAConfigs on the PD path; the compiler leaves it false, so
// operator-authored prefixes are false by construction. buildRA then refuses
// exactly the population that can never be intentional.
//
// FAIL-ON-REVERT: delete the `pfx.Delegated && prefix.Bits() == 0` guard from
// buildRA and the delegated /0 reaches the wire again.
package ra

import (
	"testing"

	"github.com/mdlayher/ndp"

	"github.com/psaab/xpf/pkg/config"
)

// prefixInfosFor returns every PrefixInformation on the wire for the given
// prefixes, so a test can assert on ABSENCE as well as on content.
func prefixInfosFor(t *testing.T, prefixes ...*config.RAPrefix) []*ndp.PrefixInformation {
	t.Helper()
	s := newTestSender3895(&config.RAInterfaceConfig{
		Interface: "trust0",
		Prefixes:  prefixes,
	})
	b, err := ndp.MarshalMessage(s.buildRA())
	if err != nil {
		t.Fatalf("marshal RA: %v", err)
	}
	msg, err := ndp.ParseMessage(b)
	if err != nil {
		t.Fatalf("parse RA: %v", err)
	}
	ra, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		t.Fatalf("parsed message is %T, want *ndp.RouterAdvertisement", msg)
	}
	var out []*ndp.PrefixInformation
	for _, o := range ra.Options {
		if pi, ok := o.(*ndp.PrefixInformation); ok {
			out = append(out, pi)
		}
	}
	return out
}

func TestBuildRA_6587_DelegatedZeroPrefixIsRefused(t *testing.T) {
	got := prefixInfosFor(t, &config.RAPrefix{
		Prefix:     "::/0",
		OnLink:     true,
		Autonomous: true,
		Delegated:  true,
	})
	if len(got) != 0 {
		t.Fatalf("a DELEGATED /0 was advertised as PrefixLength %d (on-link=%v "+
			"autonomous=%v). Every SLAAC host on the segment would treat the entire "+
			"IPv6 address space as on-link and stop routing through this firewall "+
			"(#6587).", got[0].PrefixLength, got[0].OnLink,
			got[0].AutonomousAddressConfiguration)
	}
}

// The discrimination is the whole point, so it is asserted directly rather
// than left to two tests in different files. Same prefix, same flags, only the
// provenance differs — and only one of them is refused.
func TestBuildRA_6587_ProvenanceIsWhatDiscriminates(t *testing.T) {
	configured := prefixInfosFor(t, &config.RAPrefix{
		Prefix: "::/0", OnLink: true, Autonomous: true, Delegated: false,
	})
	delegated := prefixInfosFor(t, &config.RAPrefix{
		Prefix: "::/0", OnLink: true, Autonomous: true, Delegated: true,
	})
	if len(configured) != 1 {
		t.Fatalf("operator-authored ::/0 produced %d PrefixInformation options, want 1 — "+
			"the floor over-reached onto legitimate configuration", len(configured))
	}
	if len(delegated) != 0 {
		t.Fatalf("delegated ::/0 produced %d PrefixInformation options, want 0", len(delegated))
	}
}

// A delegated prefix of a NORMAL length must still be advertised: the floor is
// scoped to /0, not to delegated prefixes generally. Without this, a fix that
// dropped every delegated prefix would pass the two tests above.
func TestBuildRA_6587_DelegatedNormalPrefixStillAdvertised(t *testing.T) {
	got := prefixInfosFor(t, &config.RAPrefix{
		Prefix: "2606:4700:4700:1000::/64", OnLink: true, Autonomous: true, Delegated: true,
	})
	if len(got) != 1 {
		t.Fatalf("a delegated /64 produced %d PrefixInformation options, want 1 — "+
			"the floor is filtering delegated prefixes as a class rather than /0", len(got))
	}
	if got[0].PrefixLength != 64 {
		t.Errorf("PrefixLength = %d, want 64", got[0].PrefixLength)
	}
	if !got[0].OnLink || !got[0].AutonomousAddressConfiguration {
		t.Errorf("OnLink = %v, Autonomous = %v, want both true",
			got[0].OnLink, got[0].AutonomousAddressConfiguration)
	}
}

// TestConfigEqual_6587_DelegatedChangeRestartsTheSender pins the change
// detector. Delegated decides whether the PIO is emitted AT ALL, so it is
// wire-affecting; the #4307 comment in ra.go records what omitting a
// wire-affecting field from configEqual cost last time — a stale
// advertisement that kept going out after the config changed.
func TestConfigEqual_6587_DelegatedChangeRestartsTheSender(t *testing.T) {
	mk := func(delegated bool) *config.RAInterfaceConfig {
		return &config.RAInterfaceConfig{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{{
				Prefix: "2001:db8::/64", OnLink: true, Autonomous: true, Delegated: delegated,
			}},
		}
	}
	if configEqual(mk(false), mk(true)) {
		t.Fatal("configEqual reports two RA configs equal when only Delegated differs. " +
			"That field gates whether the prefix is advertised at all, so the sender " +
			"would keep running with the old decision (#6587)")
	}
	if !configEqual(mk(true), mk(true)) {
		t.Error("configEqual reports two identical configs unequal — the sender would " +
			"restart on every reconcile")
	}
}
