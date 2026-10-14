package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #8993: `policy-rematch extensive` must re-evaluate live sessions of a policy
// whose OWN TEXT DID NOT CHANGE when a referenced object's DEFINITION changed.
//
// Before this, policyMatchOrActionChanged compared address-book NAMES:
// `source-address trusted-hosts` is byte-identical before and after tightening
// what `trusted-hosts` resolves to, so the sessions of a host just removed from
// the set kept forwarding until idle timeout. The advisory said so in prose and
// nothing enforced it.
//
// RED ON REVERT: drop the policyReferencedObjectChanged arm and the first two
// cases detect no change and clear nothing.

// extensiveAddrConfig builds trust->untrust with p-first (which occupies the
// overloaded runtime id 0) and p-web, whose match names the address-SET
// `trusted-hosts`. The policy TEXT is identical across every config this
// returns; only the book behind it moves.
func extensiveAddrConfig(members []string, h1CIDR string, extensive bool, webAction config.PolicyAction) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: "p-first", Action: config.PolicyPermit},
			{Name: "p-web", Action: webAction, Match: config.PolicyMatch{
				SourceAddresses: []string{"trusted-hosts"},
			}},
		}},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"h1": {Name: "h1", Value: h1CIDR},
			"h2": {Name: "h2", Value: "10.0.0.2/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"trusted-hosts": {Name: "trusted-hosts", Addresses: members},
		},
	}
	cfg.Security.PolicyRematch = true
	cfg.Security.PolicyRematchExtensive = extensive
	return cfg
}

func TestPolicyRematchExtensive_ReferencedObjectChanged8993(t *testing.T) {
	base := extensiveAddrConfig([]string{"h1", "h2"}, "10.0.0.1/32", true, config.PolicyPermit)
	webID := dpuserspace.PolicyIDsByStableKey(base)["trust->untrust/p-web"]
	if webID == 0 {
		t.Fatalf("precondition: p-web id must be non-zero (0 is the overloaded wire value)")
	}

	t.Run("address-SET membership tightened (RED on revert)", func(t *testing.T) {
		// h2 removed from the set. Every policy's text is unchanged.
		newCfg := extensiveAddrConfig([]string{"h1"}, "10.0.0.1/32", true, config.PolicyPermit)
		got := changedPolicyRuntimeIDs(base, newCfg, nil, nil)
		if _, ok := got[webID]; !ok {
			t.Errorf("#8993: tightening `trusted-hosts` did not mark p-web changed; got %v.\n"+
				"Sessions of the removed host keep forwarding until idle timeout — the "+
				"`extensive` case the advisory promises and nothing enforced.", got)
		}
	})

	t.Run("address VALUE changed under a stable name (RED on revert)", func(t *testing.T) {
		// Membership identical; h1 now resolves to a different prefix. This is
		// the purest form: nothing about the policy OR the set moved.
		newCfg := extensiveAddrConfig([]string{"h1", "h2"}, "10.0.0.9/32", true, config.PolicyPermit)
		got := changedPolicyRuntimeIDs(base, newCfg, nil, nil)
		if _, ok := got[webID]; !ok {
			t.Errorf("#8993: redefining address `h1` did not mark p-web changed; got %v", got)
		}
	})

	// ── CONTROLS ────────────────────────────────────────────────────────
	//
	// THE LEVELLING CONTROL FIRST. A fingerprint that always differs — a map
	// iteration order leaking in, a timestamp, an unsorted slice — satisfies
	// BOTH cases above while clearing every session on every commit. That
	// failure is invisible without this, because "it detected the change" and
	// "it detects everything" look identical from the two tests above.
	t.Run("CONTROL nothing changed at all clears nothing", func(t *testing.T) {
		same := extensiveAddrConfig([]string{"h1", "h2"}, "10.0.0.1/32", true, config.PolicyPermit)
		if got := changedPolicyRuntimeIDs(base, same, nil, nil); len(got) != 0 {
			t.Errorf("#8993: an identical config reported %v changed. The fingerprint is "+
				"not stable across two builds of the same config, so `extensive` "+
				"would clear every session on every commit.", got)
		}
	})

	// Repeat-run stability: the same comparison must give the same answer.
	// A single run cannot distinguish a stable fingerprint from one that
	// happened to agree once.
	t.Run("CONTROL fingerprint is stable across repeated builds", func(t *testing.T) {
		for i := 0; i < 8; i++ {
			same := extensiveAddrConfig([]string{"h1", "h2"}, "10.0.0.1/32", true, config.PolicyPermit)
			if got := changedPolicyRuntimeIDs(base, same, nil, nil); len(got) != 0 {
				t.Fatalf("#8993: run %d reported %v changed for an identical config — "+
					"non-determinism (map order in the snapshot or the book table)", i, got)
			}
		}
	})

	t.Run("CONTROL plain policy-rematch does NOT get the extensive arm", func(t *testing.T) {
		// Same object change, `extensive` unset. Junos gates this behaviour on
		// the sub-mode, so a plain `policy-rematch` must behave as before.
		oldPlain := extensiveAddrConfig([]string{"h1", "h2"}, "10.0.0.1/32", false, config.PolicyPermit)
		newPlain := extensiveAddrConfig([]string{"h1"}, "10.0.0.1/32", false, config.PolicyPermit)
		if got := changedPolicyRuntimeIDs(oldPlain, newPlain, nil, nil); len(got) != 0 {
			t.Errorf("#8993: plain `policy-rematch` re-evaluated on an object-definition "+
				"change (%v). The extensive arm must be gated on the sub-mode.", got)
		}
	})

	t.Run("CONTROL a real match/action change still fires", func(t *testing.T) {
		// The pre-existing behaviour must survive: this is what #4234 shipped.
		newCfg := extensiveAddrConfig([]string{"h1", "h2"}, "10.0.0.1/32", true, config.PolicyDeny)
		got := changedPolicyRuntimeIDs(base, newCfg, nil, nil)
		if _, ok := got[webID]; !ok {
			t.Errorf("#8993: permit->deny on p-web no longer marks it changed; got %v", got)
		}
	})
}

func TestPolicyRematchExtensiveTracksStaticSiblingBesideLiveFeed12851(t *testing.T) {
	build := func(hostCIDR string) *config.Config {
		cfg := extensiveAddrConfig([]string{"h1", "feedref"}, hostCIDR, true, config.PolicyPermit)
		cfg.Security.AddressBook.Addresses["feedref"] = &config.Address{Name: "feedref", Value: "192.0.2.1/32"}
		cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
			"feedref": {Name: "feedref", FeedNames: []string{"test-feed"}},
		}
		return cfg
	}
	oldCfg := build("10.0.0.1/32")
	newCfg := build("10.0.9.9/32")
	webID := dpuserspace.PolicyIDsByStableKey(oldCfg)["trust->untrust/p-web"]
	if webID == 0 {
		t.Fatal("precondition: p-web id must be non-zero")
	}
	overlay := map[string][]string{"feedref": {"198.51.100.1/32"}}
	got := changedPolicyRuntimeIDs(oldCfg, newCfg, nil, nil, overlay, overlay)
	if _, swept := got[webID]; !swept {
		t.Fatalf("#12851: static sibling tightening beside a healthy live feed did not mark p-web for extensive rematch: %v", got)
	}
	if len(got) != 1 {
		t.Fatalf("#12851: unrelated policies were marked changed: %v", got)
	}
}
