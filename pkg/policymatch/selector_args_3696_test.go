package policymatch

import (
	"strings"
	"testing"
)

// TestParseSelectorArgsFailsClosed is the #3696 SSOT guard for the strict
// selector parser shared by all four CLI surfaces + the gRPC test-policy
// bridge. Before it, each surface hand-copied a `for i := range args { switch
// args[i] {...} }` loop guarded by `if i+1 < len(args)` with no else and with
// no default arm. A missing value left its query dimension unspecified, so a
// constrained term never matched while an unconstrained term could still match;
// an unknown selector was dropped and a skipped deny could let a later permit
// match.
//
// FAIL-ON-REVERT: relaxing ParseSelectorArgs back to the loose "skip on
// missing value / ignore unknown token" behavior returns nil for malformed input,
// flipping the want-error cases red.
func TestParseSelectorArgsFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr string // substring; "" = want no error
	}{
		// H01-H10: a value-taking selector present without a value must ERROR.
		{"trailing from-zone", []string{"from-zone"}, "requires a value"},
		{"trailing to-zone", []string{"from-zone", "trust", "to-zone"}, "requires a value"},
		{"trailing destination-port", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port"}, "requires a value"},
		{"trailing source-port", []string{"from-zone", "trust", "to-zone", "untrust", "source-port"}, "requires a value"},
		{"trailing protocol", []string{"from-zone", "trust", "to-zone", "untrust", "protocol"}, "requires a value"},
		{"trailing source-ip", []string{"from-zone", "trust", "to-zone", "untrust", "source-ip"}, "requires a value"},
		{"trailing destination-ip", []string{"from-zone", "trust", "to-zone", "untrust", "destination-ip"}, "requires a value"},
		{"trailing icmp-type", []string{"from-zone", "trust", "to-zone", "untrust", "icmp-type"}, "requires a value"},
		{"trailing icmp-code", []string{"from-zone", "trust", "to-zone", "untrust", "icmp-code"}, "requires a value"},
		// M01: an explicit-empty typed value must ERROR, not read as omitted.
		{"empty destination-port", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", ""}, "requires a value"},
		{"empty protocol", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", ""}, "requires a value"},
		{"empty from-zone", []string{"from-zone", "", "to-zone", "untrust"}, "requires a value"},
		// Unknown / misspelled selector must ERROR, not silently drop.
		{"unknown protcol typo", []string{"from-zone", "trust", "to-zone", "untrust", "protcol", "tcp"}, "unknown selector"},
		{"unknown proto abbrev", []string{"from-zone", "trust", "to-zone", "untrust", "proto", "tcp"}, "unknown selector"},
		{"unknown leading garbage", []string{"garbage", "from-zone", "trust"}, "unknown selector"},
		// Value validators still fire through the parser.
		{"invalid port", []string{"from-zone", "trust", "to-zone", "untrust", "destination-port", "abc"}, "destination-port"},
		{"invalid protocol", []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcpp"}, "invalid protocol"},
		{"invalid source-ip", []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.999"}, "invalid source-ip"},
		{"invalid icmp-type", []string{"from-zone", "trust", "to-zone", "untrust", "icmp-type", "300"}, "icmp-type"},
		// Valid queries still work.
		{"empty args", nil, ""},
		{"only zones", []string{"from-zone", "trust", "to-zone", "untrust"}, ""},
		{"full valid", []string{
			"from-zone", "trust", "to-zone", "untrust",
			"source-ip", "10.0.1.1", "destination-ip", "10.0.2.1",
			"source-port", "1024", "destination-port", "443",
			"protocol", "tcp", "icmp-type", "8", "icmp-code", "0",
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSelectorArgs(tc.args)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ParseSelectorArgs(%v) err = %v, want nil", tc.args, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseSelectorArgs(%v) err = nil, want %q (silent widen / drop)", tc.args, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ParseSelectorArgs(%v) err = %v, want substring %q", tc.args, err, tc.wantErr)
			}
		})
	}
}

// TestParseSelectorArgsPopulatesQuery proves a valid selector vector populates
// every field and converts to a policymatch.Query with the IPs parsed and an
// omitted IP mapped to a nil net.IP (the match-any wildcard) — the invariant the
// four surfaces rely on when they route through the shared parser (#3696).
func TestParseSelectorArgsPopulatesQuery(t *testing.T) {
	sel, err := ParseSelectorArgs([]string{
		"from-zone", "trust", "to-zone", "untrust",
		"source-ip", "10.0.1.1", "destination-ip", "10.0.2.1",
		"source-port", "1024", "destination-port", "443",
		"protocol", "tcp", "icmp-type", "8", "icmp-code", "0",
	})
	if err != nil {
		t.Fatalf("ParseSelectorArgs(valid) err = %v", err)
	}
	if sel.FromZone != "trust" || sel.ToZone != "untrust" {
		t.Fatalf("zones = %q/%q, want trust/untrust", sel.FromZone, sel.ToZone)
	}
	if sel.SrcIP != "10.0.1.1" || sel.DstIP != "10.0.2.1" {
		t.Fatalf("ips = %q/%q", sel.SrcIP, sel.DstIP)
	}
	if sel.SrcPort != 1024 || sel.DstPort != 443 {
		t.Fatalf("ports = %d/%d, want 1024/443", sel.SrcPort, sel.DstPort)
	}
	if sel.Protocol != "tcp" {
		t.Fatalf("protocol = %q, want tcp", sel.Protocol)
	}
	if sel.ICMPType == nil || *sel.ICMPType != 8 || sel.ICMPCode == nil || *sel.ICMPCode != 0 {
		t.Fatalf("icmp = %v/%v, want 8/0", sel.ICMPType, sel.ICMPCode)
	}

	q := sel.Query()
	if q.SrcIP == nil || q.SrcIP.String() != "10.0.1.1" {
		t.Fatalf("Query SrcIP = %v, want 10.0.1.1", q.SrcIP)
	}
	if q.DstPort != 443 || q.Protocol != "tcp" {
		t.Fatalf("Query = %+v, want DstPort 443 / tcp", q)
	}

	// An omitted IP maps to a nil net.IP (wildcard), never a non-nil zero IP.
	empty, err := ParseSelectorArgs([]string{"from-zone", "trust", "to-zone", "untrust"})
	if err != nil {
		t.Fatalf("ParseSelectorArgs(zones only) err = %v", err)
	}
	if eq := empty.Query(); eq.SrcIP != nil || eq.DstIP != nil {
		t.Fatalf("omitted IP should map to nil net.IP, got %v/%v", eq.SrcIP, eq.DstIP)
	}
}
