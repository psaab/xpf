package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// lo0_proto_icmp_failclosed_6806_test.go is the daemon half of the #6806 proof.
// The nftables half (pkg/nftables/netlink_lo0_proto_icmp_6806_test.go) proves
// the production BUILDER fails closed; this half proves three things it cannot
// see:
//
//  1. reachability — the unresolvable token actually reaches that builder on the
//     production path (toNftLo0Spec -> InstallLo0), including the icmp markers
//     that have no other channel;
//  2. the TEXT oracle (buildLo0FilterPayload) fails the same input the same way;
//  3. the two renderers AGREE. That is the assertion that matters: before this
//     fix they agreed too — both DROPPED the token — so a parity test alone
//     could never have caught the defect. Agreement is asserted on the
//     PROPERTY (neither renderer may emit a term whose narrowing vanished), not
//     on a literal one of them happens to produce.
//
// Strict commit rejects these tokens (validateFilterMatchValuesStrict), so every
// fixture here is the tolerant shape: a leniently loaded / peer-synced /
// mixed-version config, which is precisely the live ingress #1960 keeps open.

func d6806() *Daemon { return &Daemon{} }

// lo0Cfg6806 builds a one-term inet lo0 filter config around the supplied term.
func lo0Cfg6806(term *config.FirewallFilterTerm) *config.Config {
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{term}},
	}
	return cfg
}

// lowerLo0Term6806 runs the production lowering and returns the single lowered
// term the netlink installer would receive.
func lowerLo0Term6806(t *testing.T, cfg *config.Config) xnft.Lo0FilterTerm {
	t.Helper()
	var got xnft.Lo0FilterSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(s xnft.Lo0FilterSpec) error { got = s; return nil },
	}
	defer func() { nftInstaller = orig }()

	if err := d6806().applyLo0Filter(cfg); err != nil {
		t.Fatalf("applyLo0Filter: %v", err)
	}
	if len(got.V4Terms) != 1 {
		t.Fatalf("want 1 lowered v4 term, got %d", len(got.V4Terms))
	}
	return got.V4Terms[0]
}

// TestUnresolvableProtocolReachesLo0Builder6806 pins the reachability half for
// protocol. The raw token must survive the lowering verbatim — that is what
// makes the builder's fail-closed possible at all.
func TestUnresolvableProtocolReachesLo0Builder6806(t *testing.T) {
	term := lowerLo0Term6806(t, lo0Cfg6806(&config.FirewallFilterTerm{
		Name: "admit-one", Protocols: []string{"tcp", "not-a-protocol"}, Action: config.FilterActionAccept,
	}))
	if !sliceContains(term.Protocols, "not-a-protocol") {
		t.Fatalf("the unresolvable protocol must reach the builder VERBATIM; Protocols = %v",
			term.Protocols)
	}
	if !sliceContains(term.Protocols, "tcp") {
		t.Fatalf("the resolvable token must reach it too — this is the PARTIAL shape; Protocols = %v",
			term.Protocols)
	}
}

// TestUnrepresentableICMPMarkerReachesLo0Builder6806 pins the reachability half
// for ICMP, which is the one the fix had to open. ICMPTypes/ICMPCodes carry only
// RESOLVED bytes, so without the markers the unresolvable token leaves no trace
// in the DTO at all and the builder is structurally unable to fail closed.
func TestUnrepresentableICMPMarkerReachesLo0Builder6806(t *testing.T) {
	term := lowerLo0Term6806(t, lo0Cfg6806(&config.FirewallFilterTerm{
		Name:             "admit-icmp",
		Protocols:        []string{"icmp"},
		UnknownICMPTypes: []string{"no-such-type"},
		UnknownICMPCodes: []string{"no-such-code"},
		Action:           config.FilterActionAccept,
	}))
	if len(term.ICMPTypes) != 0 || len(term.ICMPCodes) != 0 {
		t.Fatalf("setup: the unresolvable tokens must leave the resolved byte slices EMPTY "+
			"(that is the shape that widened the term); types=%v codes=%v",
			term.ICMPTypes, term.ICMPCodes)
	}
	if !term.ICMPTypeUnrepresentable {
		t.Error("#6806: UnknownICMPTypes must set ICMPTypeUnrepresentable — without it " +
			"the builder sees an unconstrained term and matches EVERY icmp type")
	}
	if !term.ICMPCodeUnrepresentable {
		t.Error("#6806: UnknownICMPCodes must set ICMPCodeUnrepresentable")
	}
}

// TestResolvedICMPDoesNotSetUnrepresentable6806 is the anti-over-fix control for
// the marker: a fully resolved term must NOT be marked, or every ordinary
// icmp-type filter would fail its lo0 install.
func TestResolvedICMPDoesNotSetUnrepresentable6806(t *testing.T) {
	term := lowerLo0Term6806(t, lo0Cfg6806(&config.FirewallFilterTerm{
		Name: "ok-icmp", Protocols: []string{"icmp"},
		ICMPTypes: []int{8}, ICMPCodes: []int{0}, Action: config.FilterActionAccept,
	}))
	if term.ICMPTypeUnrepresentable || term.ICMPCodeUnrepresentable {
		t.Fatalf("a fully resolved icmp term must not be marked unrepresentable "+
			"(type=%t code=%t)", term.ICMPTypeUnrepresentable, term.ICMPCodeUnrepresentable)
	}
}

// TestLo0TextOracleKeepsUnresolvableTokens6806 pins the text half. The oracle
// has no error channel — buildLo0FilterPayload returns a string — so its
// fail-closed idiom is to keep the raw token so `nft -f -` REJECTS the whole
// ruleset and the prior generation is retained (#6405 ports/DSCP, #6512
// addresses). Dropping it is what widened the rendered term.
func TestLo0TextOracleKeepsUnresolvableTokens6806(t *testing.T) {
	cases := []struct {
		name string
		term *config.FirewallFilterTerm
		want string
	}{
		{
			name: "protocol",
			term: &config.FirewallFilterTerm{
				Name: "admit-one", Protocols: []string{"not-a-protocol"}, Action: config.FilterActionAccept,
			},
			want: "not-a-protocol",
		},
		{
			name: "icmp_type",
			term: &config.FirewallFilterTerm{
				Name: "admit-icmp", UnknownICMPTypes: []string{"no-such-type"}, Action: config.FilterActionAccept,
			},
			want: "no-such-type",
		},
		{
			name: "icmp_code",
			term: &config.FirewallFilterTerm{
				Name: "admit-icmp-code", UnknownICMPCodes: []string{"no-such-code"}, Action: config.FilterActionAccept,
			},
			want: "no-such-code",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := buildLo0FilterPayload(lo0Cfg6806(tc.term), "protect-re", "")
			if !strings.Contains(payload, tc.want) {
				t.Fatalf("#6806: the oracle must keep %q VERBATIM so the nft load fails "+
					"closed; payload:\n%s", tc.want, payload)
			}
		})
	}
}

// TestLo0TextOracleUnchangedForResolvableTokens6806 is the no-regression half of
// the oracle change: a term whose tokens all resolve must render exactly as it
// did before, numerically. A fix that changed this would move every existing
// parity golden.
func TestLo0TextOracleUnchangedForResolvableTokens6806(t *testing.T) {
	payload := buildLo0FilterPayload(lo0Cfg6806(&config.FirewallFilterTerm{
		Name: "ok", Protocols: []string{"tcp"},
		ICMPTypes: []int{8}, ICMPCodes: []int{0}, Action: config.FilterActionAccept,
	}), "protect-re", "")
	if !strings.Contains(payload, "meta l4proto 6") {
		t.Errorf("a resolvable protocol must still render numerically; payload:\n%s", payload)
	}
	if !strings.Contains(payload, "icmp type 8") {
		t.Errorf("a resolved icmp type must still render as a bare byte; payload:\n%s", payload)
	}
	if !strings.Contains(payload, "icmp code 0") {
		t.Errorf("a resolved icmp code must still render as a bare byte; payload:\n%s", payload)
	}
}

// TestLo0RenderersAgreeOnUnresolvableTokens6806 is the assertion that makes the
// pair trustworthy, and it is deliberately NOT "the text output equals the
// netlink output". Before this fix the two renderers agreed PERFECTLY — both
// dropped the token — while both were fail-open, so an equality check between
// them could never have detected the defect. Equality is the wrong property.
//
// What must hold is that NEITHER mirror loses the refusal evidence at its own
// boundary, for the same input:
//
//   - text: the raw token survives into the payload, so `nft -f -` refuses the
//     whole ruleset and the prior generation is retained;
//   - netlink: the lowered DTO still carries what the builder needs to refuse —
//     the verbatim token for protocol, the marker for icmp. That the builder
//     then DOES refuse is proven in the nftables half
//     (TestLo0UnresolvableProtocolFailsClosed6806 /
//     TestLo0UnrepresentableICMPFailsClosed6806); this cell is the seam between
//     the two halves, which is where #6806 was actually broken for icmp.
//
// Break either side and this cell reds while the other side stays green, which
// is what makes it a localising assertion rather than a second copy of the
// halves it joins.
func TestLo0RenderersAgreeOnUnresolvableTokens6806(t *testing.T) {
	cases := []struct {
		name string
		term *config.FirewallFilterTerm
		raw  string
		// netlinkRefusable reports whether the lowered DTO carries the evidence
		// the netlink builder refuses on.
		netlinkRefusable func(xnft.Lo0FilterTerm) bool
	}{
		{
			name: "unresolvable_protocol",
			term: &config.FirewallFilterTerm{
				Name: "p", Protocols: []string{"not-a-protocol"}, Action: config.FilterActionAccept,
			},
			raw: "not-a-protocol",
			netlinkRefusable: func(lt xnft.Lo0FilterTerm) bool {
				return sliceContains(lt.Protocols, "not-a-protocol")
			},
		},
		{
			name: "unrepresentable_icmp_type",
			term: &config.FirewallFilterTerm{
				Name: "i", UnknownICMPTypes: []string{"no-such-type"}, Action: config.FilterActionAccept,
			},
			raw: "no-such-type",
			netlinkRefusable: func(lt xnft.Lo0FilterTerm) bool {
				return lt.ICMPTypeUnrepresentable
			},
		},
		{
			name: "unrepresentable_icmp_code",
			term: &config.FirewallFilterTerm{
				Name: "c", UnknownICMPCodes: []string{"no-such-code"}, Action: config.FilterActionAccept,
			},
			raw: "no-such-code",
			netlinkRefusable: func(lt xnft.Lo0FilterTerm) bool {
				return lt.ICMPCodeUnrepresentable
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lo0Cfg6806(tc.term)

			textKept := strings.Contains(buildLo0FilterPayload(cfg, "protect-re", ""), tc.raw)
			netlinkKept := tc.netlinkRefusable(lowerLo0Term6806(t, cfg))

			if !textKept {
				t.Errorf("text renderer LOST the refusal evidence %q — the rendered term "+
					"would install with its narrowing silently dropped", tc.raw)
			}
			if !netlinkKept {
				t.Errorf("netlink lowering LOST the refusal evidence for %q — the builder "+
					"is then structurally unable to fail closed", tc.raw)
			}
			if textKept != netlinkKept {
				t.Errorf("#6806: the two lo0 mirrors must not DIVERGE on the same term — "+
					"one refusing while the other installs a widened rule is the "+
					"mode-dependent fail-open this issue is about "+
					"(text_kept=%t netlink_kept=%t)", textKept, netlinkKept)
			}
		})
	}
}
