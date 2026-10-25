package config

import (
	"strings"
	"testing"
)

// #16594: interface-level `mtu` is a Junos MEDIA MTU (counts the
// 14-byte Ethernet header, +4 tagged); compileInterfaces translates it
// to the L3 MTU stored in ifc.MTU. `mtu 1514` untagged must yield
// netdev 1500; tagged 1496. Family mtu is L3 and never translated.
//
// FAIL-ON-REVERT: drop translateInterfaceMediaMTU16594 from
// compileInterfaces and the untagged/tagged cells compile 1514 verbatim.

func TestMediaMTU1514UntaggedYields1500_16594(t *testing.T) {
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 mtu 1514",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	))
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.MTU != 1500 {
		t.Fatalf("mtu 1514 untagged: ifc.MTU = %+v, want 1500", ifc)
	}
	if got := ifc.NetdevMTU(); got != 1500 {
		t.Fatalf("NetdevMTU = %d, want 1500", got)
	}
}

func TestMediaMTU1514TaggedYields1496_16594(t *testing.T) {
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 mtu 1514",
		"set interfaces ge-0/0/0 unit 50 vlan-id 50",
		"set interfaces ge-0/0/0 unit 50 family inet address 10.0.50.1/24",
	))
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.MTU != 1496 {
		t.Fatalf("mtu 1514 tagged: ifc.MTU = %+v, want 1496 (1514-18)", ifc)
	}
}

func TestMediaMTUFlexibleTaggingYields1496_16594(t *testing.T) {
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 flexible-vlan-tagging",
		"set interfaces ge-0/0/0 mtu 1514",
		"set interfaces ge-0/0/0 unit 50 vlan-id 50",
		"set interfaces ge-0/0/0 unit 50 family inet address 10.0.50.1/24",
	))
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.MTU != 1496 {
		t.Fatalf("mtu 1514 flexible-tagging: ifc.MTU = %+v, want 1496", ifc)
	}
}

func TestMediaMTUFamilyMTUNotTranslated_16594(t *testing.T) {
	// Family (protocol) MTU is already L3: 1500 must stay 1500 while
	// the interface media 1514 becomes 1500; a smaller family value
	// stays exact.
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 mtu 1514",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet mtu 1400",
	))
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc.MTU != 1500 {
		t.Fatalf("interface MTU = %d, want 1500", ifc.MTU)
	}
	if got := ifc.Units[0].MTU; got != 1400 {
		t.Fatalf("family unit MTU = %d, want 1400 untranslated", got)
	}
}

func TestMediaMTUJumboTranslation_16594(t *testing.T) {
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 mtu 9014",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	))
	if got := cfg.Interfaces.Interfaces["ge-0/0/0"].MTU; got != 9000 {
		t.Fatalf("mtu 9014 untagged: MTU = %d, want 9000", got)
	}
	cfg = assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 mtu 9018",
		"set interfaces ge-0/0/0 unit 50 vlan-id 50",
		"set interfaces ge-0/0/0 unit 50 family inet address 10.0.50.1/24",
	))
	if got := cfg.Interfaces.Interfaces["ge-0/0/0"].MTU; got != 9000 {
		t.Fatalf("mtu 9018 tagged: MTU = %d, want 9000", got)
	}
}

func TestMediaMTUHiearchicalAndPacked_16594(t *testing.T) {
	cfg := assertCommitAccepts(t, hierTree(t, `interfaces {
    ge-0/0/0 {
        mtu 1514;
        unit 0 { family inet { address 10.0.0.1/24; } }
    }
}`))
	if got := cfg.Interfaces.Interfaces["ge-0/0/0"].MTU; got != 1500 {
		t.Fatalf("hierarchical mtu 1514: MTU = %d, want 1500", got)
	}
	cfg = compile14436(t, `interfaces { ge-0/0/0 mtu 1514; }`)
	if got := cfg.Interfaces.Interfaces["ge-0/0/0"].MTU; got != 1500 {
		t.Fatalf("packed mtu 1514: MTU = %d, want 1500", got)
	}
}

func TestMediaMTUUnsetStaysUnset_16594(t *testing.T) {
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	))
	if got := cfg.Interfaces.Interfaces["ge-0/0/0"].MTU; got != 0 {
		t.Fatalf("unset mtu: MTU = %d, want 0 (default materialised downstream)", got)
	}
}

func TestMediaMTUTinyClampsToOne_16594(t *testing.T) {
	// A media MTU at/below the header size must not collapse to the
	// 0 "unset" sentinel (which would materialise 1500 downstream).
	for _, authored := range []string{"1", "14"} {
		cfg := assertCommitAccepts(t, flatTreeFromSets(t,
			"set interfaces ge-0/0/0 mtu "+authored,
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		))
		if got := cfg.Interfaces.Interfaces["ge-0/0/0"].MTU; got != 1 {
			t.Fatalf("mtu %s: MTU = %d, want clamped 1", authored, got)
		}
	}
}

func TestMediaMTUExemptDevicesPassThrough_16594(t *testing.T) {
	cases := map[string][]string{
		"gre name": {
			"set interfaces gr-0/0/0 mtu 9000",
			"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/24",
		},
		"loopback": {
			"set interfaces lo0 mtu 9000",
			"set interfaces lo0 unit 0 family inet address 127.0.0.1/8",
		},
		"reth": {
			"set interfaces reth0 mtu 9000",
			"set interfaces reth0 unit 0 family inet address 10.0.0.1/24",
		},
		"ae": {
			"set interfaces ae0 mtu 9000",
			"set interfaces ae0 unit 0 family inet address 10.0.0.1/24",
		},
	}
	for name, sets := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := CompileConfig(flatTreeFromSets(t, sets...))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			found := false
			for _, ifc := range cfg.Interfaces.Interfaces {
				if ifc.MTU != 0 {
					found = true
					if ifc.MTU != 9000 {
						t.Fatalf("%s: MTU = %d, want 9000 pass-through", name, ifc.MTU)
					}
				}
			}
			if !found {
				t.Fatalf("%s: no interface carried the authored MTU: %+v", name, cfg.Interfaces.Interfaces)
			}
		})
	}
}

// The #16244 budget is an L3/frame budget: authored media 3580
// (== budget+14) is exactly at budget after translation and accepted;
// 3581 is one over and refused. FAIL-ON-REVERT for the gate ordering:
// without translation 3580 would refuse and 3566 would be the boundary.
func TestMediaMTU16244BoundaryIsAuthored3580_16594(t *testing.T) {
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 3580",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	))
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0/0/1 mtu 3581",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
	), "#16244")
}

// The #9837 gate must judge family (L3) against the translated parent:
// media 1418 tagged == L3 1400, so family 1400 is EQUAL and accepted,
// family 1401 refused. Without translation both would misjudge by 18.
func TestMediaMTU9837JudgesTranslatedParent_16594(t *testing.T) {
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1418",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
		"set interfaces ge-0-0-2 unit 50 family inet mtu 1400",
	))
	_, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1418",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet address 172.16.50.8/24",
		"set interfaces ge-0-0-2 unit 50 family inet mtu 1401",
	))
	if err == nil || !strings.Contains(err.Error(), "#9837") {
		t.Fatalf("family 1401 vs translated parent 1400: err = %v, want #9837 refusal", err)
	}
}

// The #13936 IPv6 floor judges the effective L3 MTU: media 1294
// untagged == L3 1280 exactly (accepted); media 1293 == 1279 refused.
func TestMediaMTU13936JudgesTranslatedMTU_16594(t *testing.T) {
	assertCommitAccepts(t, flatTreeFromSets(t,
		"set interfaces ge-0-0-0 mtu 1294",
		"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
	))
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0-0-0 mtu 1293",
		"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
	), "#13936")
}
