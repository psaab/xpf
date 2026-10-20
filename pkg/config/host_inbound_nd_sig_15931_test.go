package config

import "testing"

// Triple-review F3/M1: the signature's ND component is the EFFECTIVE
// withdrawal bit, not the raw except list. Alias-equivalent non-ND
// exclusions with identical positives share a signature; a real
// ndp-withdrawn vs retained pair splits; a surviving positive ndp
// defeats a stale raw ndp except.
func TestHostInboundSigEffectiveND15931(t *testing.T) {
	igmp := CanonicalHostInboundTokenSigExcept([]string{"ssh"}, []string{"ospf"}, []string{"igmp"})
	dvmrp := CanonicalHostInboundTokenSigExcept([]string{"ssh"}, []string{"ospf"}, []string{"dvmrp"})
	if igmp != dvmrp {
		t.Fatalf("alias-equivalent excepts split signature: %q vs %q", igmp, dvmrp)
	}
	retained := CanonicalHostInboundTokenSigExcept([]string{"ssh"}, []string{"ospf"}, nil)
	withdrawn := CanonicalHostInboundTokenSigExcept([]string{"ssh"}, []string{"ospf"}, []string{"ndp"})
	if retained == withdrawn {
		t.Fatal("ndp-withdrawn must split from retained")
	}
	stale := CanonicalHostInboundTokenSigExcept([]string{"ssh"}, []string{"ndp"}, []string{"ndp"})
	if stale == withdrawn {
		t.Fatal("surviving positive ndp must defeat raw ndp except (not withdrawn)")
	}
	retainedNDP := CanonicalHostInboundTokenSigExcept([]string{"ssh"}, []string{"ndp"}, nil)
	if stale != retainedNDP {
		t.Fatalf("positive ndp + stale except must equal plain positive ndp: %q vs %q", stale, retainedNDP)
	}
}
