package dataplane

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2175 — the firewall-filter `from protocol <name>` resolution table was a
// fifth, independent copy of the protocol-name→IANA-number mapping that
// #2124 centralized onto appid.ProtocolNumber for the four policy-application
// sites. It only knew tcp/udp/icmp/icmpv6 + a silent numeric fallback, so a
// name added to the SSOT (e.g. sctp/esp/ah/vrrp) was silently unavailable to
// firewall filters even though the identical token resolved in a security
// policy. These tests pin the fold onto appid.ProtocolNumber: the broad named
// set now resolves, the L4 subset is unchanged, numeric tokens still work, and
// an unrepresentable name fails the commit with a clear error instead of the
// old silent "match protocol 0" surprise.

// recordingFilterDP is a no-op DataPlane that records the FilterRules a compile
// would have programmed, so a full compileFirewallFilters run can be exercised
// without a live dataplane.
type recordingFilterDP struct {
	DataPlane
	rules []FilterRule
}

func (d *recordingFilterDP) SetFilterRule(idx uint32, rule FilterRule) error {
	d.rules = append(d.rules, rule)
	return nil
}

func (d *recordingFilterDP) SetFilterConfig(id uint32, cfg FilterConfig) error { return nil }
func (d *recordingFilterDP) SetPolicerConfig(id uint32, cfg PolicerConfig) error {
	return nil
}
func (d *recordingFilterDP) DeleteStaleIfaceFilter(written map[IfaceFilterKey]bool) {}
func (d *recordingFilterDP) ZeroStaleFilterConfigs(startID uint32)                  {}

func filterCfgWithProtocol(family, proto string) *config.Config {
	cfg := &config.Config{}
	term := &config.FirewallFilterTerm{
		Name:      "t",
		Protocols: []string{proto},
		Action:    config.FilterActionAccept,
	}
	filter := &config.FirewallFilter{Name: "f", Terms: []*config.FirewallFilterTerm{term}}
	if family == "inet6" {
		cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{"f": filter}
	} else {
		cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{"f": filter}
	}
	return cfg
}

// TestExpandFilterTermProtocolSSOT verifies that firewall-filter protocol
// resolution now goes through appid.ProtocolNumber: the L4 subset is byte-for-
// byte unchanged AND the broader named protocols (#2124-added sctp/esp/ah/vrrp
// plus gre/ospf/igmp/pim) and numeric tokens all resolve. The sctp case is the
// acceptance assertion from #2175 — it would have hit the silent numeric
// fallback (protocol 0) before the fold.
func TestExpandFilterTermProtocolSSOT(t *testing.T) {
	cases := []struct {
		proto string
		want  uint8
	}{
		// L4 subset (must remain unchanged from the pre-fold table).
		{"tcp", 6},
		{"udp", 17},
		{"icmp", 1},
		{"icmpv6", 58},
		// #2124-added names that the firewall filter could NOT resolve before.
		{"sctp", 132},
		{"esp", 50},
		{"ah", 51},
		{"vrrp", 112},
		{"gre", 47},
		{"ospf", 89},
		{"igmp", 2},
		{"pim", 103},
		// Numeric tokens, including the deliberate HOPOPT "0".
		{"47", 47},
		{"0", 0},
		// Case-insensitive.
		{"SCTP", 132},
	}
	for _, tc := range cases {
		term := &config.FirewallFilterTerm{
			Name:      "proto-" + tc.proto,
			Protocols: []string{tc.proto},
			Action:    config.FilterActionAccept,
		}
		rules := expandFilterTerm(term, AFInet, nil, nil, nil)
		if len(rules) != 1 {
			t.Fatalf("protocol %q: expected 1 rule, got %d", tc.proto, len(rules))
		}
		r := rules[0]
		if r.MatchFlags&FilterMatchProtocol == 0 {
			t.Errorf("protocol %q: FilterMatchProtocol not set", tc.proto)
		}
		if r.Protocol != tc.want {
			t.Errorf("protocol %q: got %d, want %d", tc.proto, r.Protocol, tc.want)
		}
	}
}

// TestValidateFilterProtocolsRejectsUnknown verifies that an unrepresentable
// protocol token fails the compile with a clear, actionable error naming the
// family/filter/term/token — replacing the pre-#2175 silent degrade to
// "match protocol 0".
func TestValidateFilterProtocolsRejectsUnknown(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		cfg := filterCfgWithProtocol(family, "definitely-not-a-proto")
		err := validateFilterProtocols(cfg)
		if err == nil {
			t.Fatalf("family %s: expected error for unknown protocol, got nil", family)
		}
		msg := err.Error()
		for _, want := range []string{family, "filter f", "term t", "unknown protocol", "definitely-not-a-proto"} {
			if !strings.Contains(msg, want) {
				t.Errorf("family %s: error %q missing %q", family, msg, want)
			}
		}
	}
}

// TestValidateFilterProtocolsAcceptsRepresentable verifies the validation pass
// admits every protocol the SSOT can resolve (the L4 subset, #2124-added names,
// and numeric tokens including "0"), plus an empty token (no protocol match).
func TestValidateFilterProtocolsAcceptsRepresentable(t *testing.T) {
	good := []string{"", "tcp", "udp", "icmp", "icmpv6", "sctp", "esp", "ah", "vrrp", "gre", "ospf", "47", "0"}
	for _, proto := range good {
		cfg := filterCfgWithProtocol("inet", proto)
		if err := validateFilterProtocols(cfg); err != nil {
			t.Errorf("protocol %q: unexpected error: %v", proto, err)
		}
	}
}

// TestCompileFirewallFiltersUnknownProtocolReturnsDataplaneError drives the
// full compileFirewallFilters entry point to prove the dataplane defense-in-
// depth gate returns an error and programs NO rules for an unrepresentable
// protocol. NOTE: in production the daemon SWALLOWS this dataplane-layer error
// (compileErrorMustAbortApply == false — it is not in
// requiredProtocolGateSentinels), so this does NOT by itself refuse the
// operator commit. The operator-visible commit refusal is enforced one layer
// up by config.validateFilterProtocolsStrict — see
// pkg/config/compiler_filter_protocol_test.go
// (TestFilterProtocol_*_RejectsAtCommit). This test pins the dataplane gate as
// the strictly-more-fail-closed backstop.
func TestCompileFirewallFiltersUnknownProtocolReturnsDataplaneError(t *testing.T) {
	cfg := filterCfgWithProtocol("inet", "bogus-proto")
	dp := &recordingFilterDP{}
	result := &CompileResult{}
	err := compileFirewallFilters(dp, cfg, result)
	if err == nil {
		t.Fatal("expected commit-time error for unknown firewall-filter protocol, got nil")
	}
	if !strings.Contains(err.Error(), "bogus-proto") {
		t.Errorf("error %q does not name the offending protocol", err.Error())
	}
	if len(dp.rules) != 0 {
		t.Errorf("expected no rules programmed on validation failure, got %d", len(dp.rules))
	}
}

// TestCompileFirewallFiltersSCTPCompiles drives the full compileFirewallFilters
// entry point with an sctp term and asserts the programmed rule carries
// protocol 132 — the end-to-end #2175 acceptance: a #2124-added name now
// compiles in a firewall filter.
func TestCompileFirewallFiltersSCTPCompiles(t *testing.T) {
	cfg := filterCfgWithProtocol("inet", "sctp")
	dp := &recordingFilterDP{}
	result := &CompileResult{}
	if err := compileFirewallFilters(dp, cfg, result); err != nil {
		t.Fatalf("compileFirewallFilters: unexpected error: %v", err)
	}
	if len(dp.rules) != 1 {
		t.Fatalf("expected 1 programmed rule, got %d", len(dp.rules))
	}
	r := dp.rules[0]
	if r.MatchFlags&FilterMatchProtocol == 0 {
		t.Error("FilterMatchProtocol not set for sctp term")
	}
	if r.Protocol != 132 {
		t.Errorf("sctp rule protocol = %d, want 132", r.Protocol)
	}
}
