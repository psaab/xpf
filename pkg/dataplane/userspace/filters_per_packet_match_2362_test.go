package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2362: the firewall-filter compiler parses tcp-flags / is-fragment /
// icmp-type / icmp-code into config.FirewallFilterTerm, but the userspace
// snapshot builder previously dropped all four — so a term like
// `from { tcp-flags syn; }` silently matched broader than authored
// (discard-all-TCP instead of discard-SYN). These tests fail on the pre-fix
// builder (the fields never reach FirewallTermSnapshot) and pass after the
// wire-through fix.

// perPacketMatchCfg builds a config with one inet filter whose single term
// carries all four per-packet L4 match conditions.
func perPacketMatchCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {
			Name: "edge",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:       "syn-only",
					Protocols:  []string{"tcp"},
					TCPFlags:   []string{"syn"},
					IsFragment: false,
					Action:     config.FilterActionDiscard,
				},
			},
		},
	}
	return cfg
}

func TestFilterSnapshotTCPFlagsSerialized(t *testing.T) {
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(perPacketMatchCfg()))
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	term := snaps[0].Terms[0]
	if term.TCPFlags == nil {
		t.Fatal("tcp-flags syn was dropped from the snapshot (#2362)")
	}
	// SYN == 0x02; the mask must require exactly the SYN bit.
	if *term.TCPFlags != 0x02 {
		t.Errorf("tcp_flags mask = 0x%02x, want 0x02 (SYN)", *term.TCPFlags)
	}
}

// #3367 RED-on-revert: an unparseable tcp-flags expression (one rejected by
// ParseTCPFlagsExpression — e.g. a disjunction) must set the
// TCPFlagsUnparseable wire marker so the Rust filter compiler fails the snapshot
// CLOSED, instead of the pre-fix behavior of logging + leaving both masks nil
// (which the Rust matcher treats as "no tcp-flags constraint" → match every TCP
// segment, fail-WIDE). Reverting the filters.go change leaves the marker false
// and both masks nil, so this asserts the corrected behavior.
func TestFilterSnapshotTCPFlagsUnparseableSetsMarker(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "bad-flags",
			// A logical-OR expression is a disjunction the conjunctive dataplane
			// matcher cannot represent — ParseTCPFlagsExpression rejects it.
			Protocols: []string{"tcp"},
			TCPFlags:  []string{"syn", "|", "ack"},
			Action:    config.FilterActionDiscard,
		}}},
	}
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	term := snaps[0].Terms[0]
	if !term.TCPFlagsUnparseable {
		t.Fatal("unparseable tcp-flags expression must set TCPFlagsUnparseable (#3367)")
	}
	// The masks must stay nil — the term must NOT be emitted with a usable
	// (and necessarily wrong) constraint.
	if term.TCPFlags != nil || term.TCPFlagsForbidden != nil {
		t.Errorf("unparseable tcp-flags must leave both masks nil, got required=%v forbidden=%v",
			term.TCPFlags, term.TCPFlagsForbidden)
	}
}

// A representable tcp-flags expression must NOT set the unparseable marker.
func TestFilterSnapshotTCPFlagsRepresentableLeavesMarkerClear(t *testing.T) {
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(perPacketMatchCfg()))
	if snaps[0].Terms[0].TCPFlagsUnparseable {
		t.Error("a representable tcp-flags expression must not set TCPFlagsUnparseable")
	}
}

func TestFilterSnapshotTCPFlagsMultipleAreAnded(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocols: []string{"tcp"}, TCPFlags: []string{"syn", "ack"},
			Action: config.FilterActionDiscard,
		}}},
	}
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))
	term := snaps[0].Terms[0]
	if term.TCPFlags == nil {
		t.Fatal("tcp-flags dropped")
	}
	// SYN(0x02) | ACK(0x10) == 0x12.
	if *term.TCPFlags != 0x12 {
		t.Errorf("tcp_flags mask = 0x%02x, want 0x12 (SYN|ACK)", *term.TCPFlags)
	}
}

// TestFilterSnapshotTCPFlagsExpressionParsed is the #3076 FAIL-ON-REVERT guard
// at the snapshot layer. The Junos idiom `tcp-flags "(syn & !ack)"` (match
// SYN-not-ACK) arrives as a single token string. It MUST compile to a required
// mask of SYN (0x02) and a forbidden mask of ACK (0x10). Before #3076 the
// expression token missed the bare-name lookup, so both masks stayed nil and
// the TCP-flags constraint was silently dropped — the term matched regardless
// of flags (fail-open). REVERT (restoring the bare-name-only lookup) makes this
// assert FAIL because TCPFlags / TCPFlagsForbidden go nil.
func TestFilterSnapshotTCPFlagsExpressionParsed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocols: []string{"tcp"}, TCPFlags: []string{"(syn & !ack)"},
			Action: config.FilterActionDiscard,
		}}},
	}
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))
	term := snaps[0].Terms[0]
	if term.TCPFlags == nil {
		t.Fatal("required tcp-flags mask was dropped for \"(syn & !ack)\" (#3076 fail-open)")
	}
	if *term.TCPFlags != 0x02 {
		t.Errorf("required mask = 0x%02x, want 0x02 (SYN)", *term.TCPFlags)
	}
	if term.TCPFlagsForbidden == nil {
		t.Fatal("forbidden tcp-flags mask was dropped for \"(syn & !ack)\" (#3076 fail-open)")
	}
	if *term.TCPFlagsForbidden != 0x10 {
		t.Errorf("forbidden mask = 0x%02x, want 0x10 (ACK)", *term.TCPFlagsForbidden)
	}
}

// TestFilterSnapshotTCPFlagsNegationOnly checks a pure-negation expression
// (`!rst`) carries only the forbidden mask, leaving the required mask nil.
func TestFilterSnapshotTCPFlagsNegationOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocols: []string{"tcp"}, TCPFlags: []string{"!rst"},
			Action: config.FilterActionDiscard,
		}}},
	}
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))
	term := snaps[0].Terms[0]
	if term.TCPFlags != nil {
		t.Errorf("required mask should be nil for \"!rst\", got 0x%02x", *term.TCPFlags)
	}
	if term.TCPFlagsForbidden == nil || *term.TCPFlagsForbidden != 0x04 {
		t.Fatalf("forbidden mask = %v, want 0x04 (RST)", term.TCPFlagsForbidden)
	}
}

func TestFilterSnapshotIsFragmentSerialized(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", IsFragment: true, Action: config.FilterActionDiscard,
		}}},
	}
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))
	if !snaps[0].Terms[0].IsFragment {
		t.Error("is-fragment was dropped from the snapshot (#2362)")
	}
}

func TestFilterSnapshotICMPTypeCodeSerialized(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocols: []string{"icmp"}, ICMPTypes: []int{8}, ICMPCodes: []int{0}, Action: config.FilterActionDiscard,
		}}},
	}
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))
	term := snaps[0].Terms[0]
	if len(term.ICMPTypes) != 1 || term.ICMPTypes[0] != 8 {
		t.Errorf("icmp-types = %v, want [8] (echo-request) (#2362)", term.ICMPTypes)
	}
	if len(term.ICMPCodes) != 1 || term.ICMPCodes[0] != 0 {
		t.Errorf("icmp-codes = %v, want [0] (#2362)", term.ICMPCodes)
	}
}

func TestFilterSnapshotICMPUnsetStaysNil(t *testing.T) {
	// An unset icmp-type/code (empty slice on the typed term) must not
	// serialize a bogus 0 constraint — the wire vector stays empty.
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "t", Protocols: []string{"tcp"}, Action: config.FilterActionAccept,
		}}},
	}
	snaps := authoredFilterSnapshots18728(t, buildFirewallFilterSnapshots(cfg))
	term := snaps[0].Terms[0]
	if len(term.ICMPTypes) != 0 {
		t.Errorf("unset icmp-type should be empty, got %v", term.ICMPTypes)
	}
	if len(term.ICMPCodes) != 0 {
		t.Errorf("unset icmp-code should be empty, got %v", term.ICMPCodes)
	}
}
