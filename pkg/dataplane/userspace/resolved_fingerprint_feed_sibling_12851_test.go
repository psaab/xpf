package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12851 (D4-04): a policy side touching a dynamic-address binding must not
// collapse to the unsupported-address sentinel in the commit-time resolved
// fingerprints just because fingerprints are computed without a live feed
// overlay. With the binding absent, buildOneRuleSnapshot emitted
// ["__unsupported_address__"] for the WHOLE side, so changing a STATIC sibling
// inside the same address-set left PolicyResolvedFingerprints /
// PolicyResolvedIdentityStrippedFingerprints unchanged — masking a real
// referenced-object change from `policy-rematch extensive` (and from rename
// ancestry validation).

func fingerprintFeedSiblingConfig(hostCIDR string) *config.Config {
	cfg := newBookCfg(map[string]string{
		"host":    hostCIDR,
		"feedref": "192.0.2.1/32", // static alias shadowed by the declared binding
	})
	cfg.Security.AddressBook.AddressSets = map[string]*config.AddressSet{
		"mixed": {Name: "mixed", Addresses: []string{"host", "feedref"}},
	}
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"feedref": {Name: "feedref", FeedNames: []string{"some-feed"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name:   "mixed-policy",
			Match:  config.PolicyMatch{SourceAddresses: []string{"mixed"}},
			Action: config.PolicyPermit,
		}},
	}}
	return cfg
}

func TestResolvedFingerprintsTrackStaticSiblingBesideLiveFeed12851(t *testing.T) {
	feed := map[string][]string{"feedref": {"198.51.100.1/32"}}
	before := PolicyResolvedFingerprints(fingerprintFeedSiblingConfig("10.0.0.1/32"), feed)
	after := PolicyResolvedFingerprints(fingerprintFeedSiblingConfig("10.0.9.9/32"), feed)
	if len(before) != 1 || before["trust->untrust/mixed-policy"] == "" {
		t.Fatalf("precondition fingerprints = %v", before)
	}
	if after["trust->untrust/mixed-policy"] == before["trust->untrust/mixed-policy"] {
		t.Fatalf("#12851: static sibling change beside an absent dynamic-address binding "+
			"did not change PolicyResolvedFingerprints (sentinel collapse masked it): %v", before)
	}

	strippedBefore := PolicyResolvedIdentityStrippedFingerprints(fingerprintFeedSiblingConfig("10.0.0.1/32"), feed)
	strippedAfter := PolicyResolvedIdentityStrippedFingerprints(fingerprintFeedSiblingConfig("10.0.9.9/32"), feed)
	if strippedAfter["trust->untrust/mixed-policy"] == strippedBefore["trust->untrust/mixed-policy"] {
		t.Fatalf("#12851: static sibling change did not change identity-stripped fingerprints: %v", strippedBefore)
	}
	// Determinism control: identical configs must give identical fingerprints.
	if again := PolicyResolvedFingerprints(fingerprintFeedSiblingConfig("10.0.0.1/32"), feed); again["trust->untrust/mixed-policy"] != before["trust->untrust/mixed-policy"] {
		t.Fatalf("#12851: fingerprint not deterministic: %v vs %v", before, again)
	}
}
