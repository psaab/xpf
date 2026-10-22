// #6587 part A: `preferred-prefix-length` and `sub-prefix-length` were BOTH
// untyped `<length>` placeholders parsed with an unbounded strconv.Atoi whose
// error is DISCARDED (`, _ =`), so `abc` and `999` alike silently became a
// value the operator never typed.
//
// The issue frames the impact as "fail-closed, not fail-open". That holds for
// sub-prefix-length only: netip.PrefixFrom(addr, >128) yields an invalid
// Prefix which daemon_ra.go's IsValid() check rejects — the delegation is
// silently absent, with no commit-time error.
//
// preferred-prefix-length is NOT even that. net.CIDRMask(999, 128) returns
// nil, and dhcpv6.OptIAPrefix.ToBytes then writes `length, _ := Mask.Size()`
// = 0 — so the IA_PD hint EGRESSES to the upstream DHCPv6 server with wire
// prefix-length 0. No panic, no local error, a malformed request on the wire.
//
// Either way the guard was incidental: it depended on a downstream validity
// check noticing, not on the value being rejected where the operator typed it.
//
// FAIL-ON-REVERT: drop `valueType`/`validator` from either schema entry in
// schema_interfaces.go and that leaf's reject cases stop erroring.
package config

import (
	"strings"
	"testing"
)

func TestDHCPv6PrefixDelegatingLengthsAreRangeChecked6587(t *testing.T) {
	const base = "set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client prefix-delegating "

	for _, leaf := range []string{"preferred-prefix-length", "sub-prefix-length"} {
		t.Run(leaf, func(t *testing.T) {
			// Rejected: above the IPv6 prefix-length domain, negative, and
			// non-numeric. The Atoi that discarded its error accepted all
			// three by silently producing 0 or a nonsense length.
			for _, bad := range []string{"129", "999", "-1", "abc", "64x"} {
				tree := flatTreeFromSets(t, base+leaf+" "+bad)
				err := SchemaValidate(tree)
				if err == nil {
					t.Errorf("%s %q was ACCEPTED at commit-check; the operator gets no "+
						"error and the value is silently discarded or egressed malformed "+
						"(#6587)", leaf, bad)
					continue
				}
				// The operator has to be able to act on the message.
				if !strings.Contains(err.Error(), bad) {
					t.Errorf("%s %q: error does not name the offending value: %v", leaf, bad, err)
				}
				if !strings.Contains(err.Error(), leaf) {
					t.Errorf("%s %q: error does not name the leaf: %v", leaf, bad, err)
				}
			}

			// Accepted: the whole domain including BOTH boundaries. 0 is the
			// documented "not set" sentinel both fields already use, so a
			// validator that rejected it would break every config that omits
			// the value's effect by setting it explicitly.
			for _, ok := range []string{"0", "1", "48", "56", "64", "127", "128"} {
				tree := flatTreeFromSets(t, base+leaf+" "+ok)
				if err := SchemaValidate(tree); err != nil {
					t.Errorf("%s %q is in range and must commit clean, got: %v", leaf, ok, err)
				}
			}
		})
	}
}

// TestDHCPv6PrefixDelegatingLengthsStillCompile6587 is the over-reach control:
// the typed schema must not have changed what a VALID config compiles to.
func TestDHCPv6PrefixDelegatingLengthsStillCompile6587(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client prefix-delegating preferred-prefix-length 56",
		"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client prefix-delegating sub-prefix-length 64",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("a valid prefix-delegating stanza must pass schema validation: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	iface := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if iface == nil || len(iface.Units) == 0 {
		t.Fatalf("interface/unit not compiled: %+v", cfg.Interfaces.Interfaces)
	}
	dc := iface.Units[0].DHCPv6Client
	if dc == nil {
		t.Fatal("DHCPv6Client not compiled")
	}
	if dc.PrefixDelegatingPrefixLen != 56 {
		t.Errorf("PrefixDelegatingPrefixLen = %d, want 56", dc.PrefixDelegatingPrefixLen)
	}
	if dc.PrefixDelegatingSubPrefLen != 64 {
		t.Errorf("PrefixDelegatingSubPrefLen = %d, want 64", dc.PrefixDelegatingSubPrefLen)
	}
}
