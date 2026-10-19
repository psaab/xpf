package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var renderBeltRe = regexp.MustCompile(`(?s)func validBGPNeighborAddress\(s string\) bool \{(.*?)\n\}`)

func bgpNeighborConfig6796(addr string) *Config {
	cfg := &Config{}
	cfg.Protocols.BGP = &BGPConfig{
		LocalAS:  65001,
		RouterID: "10.0.0.1",
		Neighbors: []*BGPNeighbor{
			{Address: addr, PeerAS: 65000},
		},
	}
	return cfg
}

// TestMultiTokenNeighborIsRejectedAtCommit6796 is the strict half, PAIRED: the
// same gate, an injecting identity and a legitimate one, opposite verdicts.
//
// #15184 supersedes the hostname acceptance: a BGP neighbor must now be a
// bare IP (netip.ParseAddr, no zone/prefix). Hostnames / peer-group names
// are moved to the rejected list in the #15184 tests; here the accepted
// rows are bare IPs only.
func TestMultiTokenNeighborIsRejectedAtCommit6796(t *testing.T) {
	rejected := []string{
		"1.1.1.1 remote-as 65000",
		"1.1.1.1\n neighbor 2.2.2.2",
		"1.1.1.1\tremote-as 65000",
		"",
	}
	for _, addr := range rejected {
		if err := validateBGPNeighborAddressStrict(bgpNeighborConfig6796(addr)); err == nil {
			t.Errorf("commit ACCEPTED a neighbor identity spanning more than one "+
				"FRR token (%q) — it renders as multiple frr.conf statements and "+
				"injects configuration the operator never wrote (#6796)", addr)
		}
	}

	accepted := []string{
		"10.0.0.2",
		"2001:db8::2",
	}
	for _, addr := range accepted {
		if err := validateBGPNeighborAddressStrict(bgpNeighborConfig6796(addr)); err != nil {
			t.Errorf("commit REJECTED the legitimate single-token neighbor %q: %v "+
				"— dropping a working peering is an outage, and it is the "+
				"direction a fail-closed gate gets wrong", addr, err)
		}
	}
}

// TestMultiTokenNeighborGateNamesTheNeighbor6796 pins the operator-facing half.
// A gate that rejects without saying WHICH neighbor leaves an operator grepping
// a large BGP config; the sibling peer-as gate names it, and so must this one.
func TestMultiTokenNeighborGateNamesTheNeighbor6796(t *testing.T) {
	cfg := bgpNeighborConfig6796("1.1.1.1 remote-as 65000")
	cfg.Protocols.BGP.Neighbors[0].GroupName = "upstream"

	err := validateBGPNeighborAddressStrict(cfg)
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if !strings.Contains(err.Error(), "upstream") {
		t.Fatalf("the error does not name the GROUP, so an operator cannot "+
			"locate the offending stanza: %v", err)
	}
	if !strings.Contains(err.Error(), "1.1.1.1") {
		t.Fatalf("the error does not quote the offending identity: %v", err)
	}
}

// TestMultiTokenNeighborGateIsLenientOnTheTolerantPath6796 pins #1960. A
// strict gate that also fired on the tolerant load / peer-sync path would brick
// a node whose already-persisted config carries such a neighbor — turning a
// render-time defect into a boot failure, which is strictly worse.
//
// RED-on-revert: unregister lenientBGPNeighborAddress from the tolerant opt set
// and the lenient compile returns an error instead of a warning.
func TestMultiTokenNeighborGateIsLenientOnTheTolerantPath6796(t *testing.T) {
	cfg := bgpNeighborConfig6796("1.1.1.1 remote-as 65000")
	if err := validateBGPNeighborAddressStrict(cfg); err == nil {
		t.Fatal("precondition: the fixture must be rejected by the STRICT gate, " +
			"or the lenient assertion below is vacuous")
	}
	if !lenientCompileOpts().lenientBGPNeighborAddress {
		t.Fatal("lenientBGPNeighborAddress is NOT registered in the tolerant " +
			"opt set — a leniently-loaded or peer-synced config carrying such a " +
			"neighbor would fail to compile and the node would not boot, turning " +
			"a render-time defect into a boot failure (#1960)")
	}
}

// rustlessTokenRe extracts the render-side belt's body so the two spellings of
// TestNeighborTokenGateAgreesWithTheRenderBelt6796 asserts the AGREEMENT
// between the commit gate and the render belt at the predicate level.
// #15184 changed both sides from single-token to bare-IP (netip.ParseAddr,
// no zone); the bodies now differ textually (config returns an error with
// messages, frr returns a bool) so the old textual-equality check is
// replaced by a behavioural one: both must still exist, and the config
// validator must accept exactly the bare-IP set the belt is documented to.
func TestNeighborTokenGateAgreesWithTheRenderBelt6796(t *testing.T) {
	beltSrc, err := os.ReadFile("../frr/render_validate.go")
	if err != nil {
		t.Fatalf("read the render belt: %v", err)
	}
	if renderBeltRe.FindStringSubmatch(string(beltSrc)) == nil {
		t.Fatal("validBGPNeighborAddress not found in pkg/frr — the render belt " +
			"was renamed or removed, so a committed bad neighbor would " +
			"reach frr.conf (#6796/#15184)")
	}
	if !strings.Contains(string(beltSrc), "netip.ParseAddr") {
		t.Fatal("render belt no longer uses netip.ParseAddr — it has diverged " +
			"from the #15184 bare-IP predicate")
	}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"192.0.2.1", true}, {"2001:db8::1", true},
		{"10.0.0.256", false}, {"192.0.2.0/24", false},
		{"peer-a", false}, {"peer.example.com", false},
		{"fe80::1%ge-0-0-1", false}, {"1.1.1.1 remote-as 65000", false}, {"", false},
	} {
		if got := ValidBGPNeighborAddress(tc.addr); got != tc.want {
			t.Errorf("ValidBGPNeighborAddress(%q)=%v want %v (must mirror frr belt)", tc.addr, got, tc.want)
		}
	}
}
