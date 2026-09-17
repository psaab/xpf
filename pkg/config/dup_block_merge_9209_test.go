package config

import (
	"fmt"
	"testing"
)

// Issue 9209: four more named containers silently lost configuration on a
// repeated block. They were never inspected — the #8436 census could not build
// a fixture for a container whose children are all containers, so all four left
// the population before any verdict was formed and the census reported
// "SILENT: 0" over a set that excluded them (#9024 widened it).
//
// Each cell compares the DUPLICATE spelling against the MERGED one and requires
// them to agree, with the merged arm asserted non-empty first — "both spellings
// produce nothing" would satisfy an equality check, which is the levelling-down
// shape.
func TestDuplicateBlocksMergeAtFourMoreSites9209(t *testing.T) {
	for _, tc := range []struct {
		name        string
		dup, merged string
		read        func(*Config) string
		wantNot     string
	}{
		{
			// The highest-consequence of the four: a policer is a CONTROL, and
			// this one silently became a no-op. `bandwidth-limit` was lost
			// entirely, so the policer admitted everything it was written to cap.
			name:    "firewall policer",
			dup:     `firewall { policer p1 { if-exceeding { bandwidth-limit 1000000; } } policer p1 { if-exceeding { burst-size-limit 15000; } } }`,
			merged:  `firewall { policer p1 { if-exceeding { bandwidth-limit 1000000; burst-size-limit 15000; } } }`,
			wantNot: "p1 bw=0",
			read: func(c *Config) string {
				for n, p := range c.Firewall.Policers {
					return fmt.Sprintf("%s bw=%d burst=%d", n, p.BandwidthLimit, p.BurstSizeLimit)
				}
				return ""
			},
		},
		{
			// A DIFFERENT SHAPE from the other three: nothing was discarded,
			// the area was DUPLICATED. Two `area 0.0.0.0` stanzas reached the
			// FRR managed section, where the tree's own doctrine is that one
			// rejected line costs the whole reload.
			name:    "protocols ospf area",
			dup:     `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0 { metric 5; } } area 0.0.0.0 { interface ge-0/0/1 { metric 7; } } } }`,
			merged:  `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0 { metric 5; } interface ge-0/0/1 { metric 7; } } } }`,
			wantNot: "areas=2",
			read: func(c *Config) string {
				if c.Protocols.OSPF == nil {
					return ""
				}
				s := fmt.Sprintf("areas=%d", len(c.Protocols.OSPF.Areas))
				for _, a := range c.Protocols.OSPF.Areas {
					s += fmt.Sprintf(" [%s ifaces=%d]", a.ID, len(a.Interfaces))
				}
				return s
			},
		},
		{
			// The `snmp trap-group` shape again: a gate DID fire, saying
			// `ipsec policy "p1" has no resolvable ipsec proposals` — true of
			// the SECOND block, which the operator never meant to exist alone,
			// and a description of a symptom rather than of the duplication.
			// Merging first lets that gate see the policy actually described.
			name:   "security ipsec policy",
			dup:    `security { ipsec { proposal pr1 { encryption-algorithm aes-256-cbc; authentication-algorithm hmac-sha-256-128; } policy p1 { proposals pr1; } policy p1 { perfect-forward-secrecy { keys group14; } } } }`,
			merged: `security { ipsec { proposal pr1 { encryption-algorithm aes-256-cbc; authentication-algorithm hmac-sha-256-128; } policy p1 { proposals pr1; perfect-forward-secrecy { keys group14; } } } }`,
			read: func(c *Config) string {
				for n, p := range c.Security.IPsec.Policies {
					return fmt.Sprintf("%s proposals=%v pfsGroup=%d", n, p.Proposals, p.PFSGroup)
				}
				return ""
			},
		},
		{
			name:   "system services dhcp-local-server group",
			dup:    `system { services { dhcp-local-server { group g1 { interface ge-0/0/0.0; } group g1 { overrides { always-broadcast; } } } } }`,
			merged: `system { services { dhcp-local-server { group g1 { interface ge-0/0/0.0; overrides { always-broadcast; } } } } }`,
			read: func(c *Config) string {
				d := c.System.DHCPServer.DHCPLocalServer
				if d == nil {
					return ""
				}
				for n, g := range d.Groups {
					return fmt.Sprintf("%s ifaces=%v", n, g.Interfaces)
				}
				return ""
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compile := func(text string) string {
				root, perrs := NewParser(text).Parse()
				if len(perrs) > 0 {
					t.Fatalf("parse: %v", perrs)
				}
				c, err := CompileConfig(&ConfigTree{Children: root.Children})
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
				return tc.read(c)
			}
			want := compile(tc.merged)
			if want == "" {
				t.Fatalf("the MERGED control compiled to nothing — the comparison below " +
					"would be between two empty readings and would prove nothing")
			}
			got := compile(tc.dup)
			if got != want {
				t.Errorf("the duplicate-block spelling does not match the merged one:\n"+
					"  duplicate %s\n  merged    %s", got, want)
			}
			// Name the pre-fix reading where it is known, so a regression that
			// reproduces the ORIGINAL defect is reported as that rather than as
			// a generic mismatch.
			if tc.wantNot != "" && got == tc.wantNot {
				t.Errorf("this is the ORIGINAL #9209 defect returning: %s", got)
			}
		})
	}
}

// TestSiblingContainerMergeIsScopedToFoldedBlocks9209 pins the bound on the
// second half of the fix. Merging sibling containers is only correct inside a
// block a duplicate was folded into; running it over a config with no repeats
// would re-answer questions the compilers already answer.
func TestSiblingContainerMergeIsScopedToFoldedBlocks9209(t *testing.T) {
	// No duplicate anywhere: two DIFFERENT policers, each with one
	// `if-exceeding`. Nothing may move.
	const text = `firewall { policer p1 { if-exceeding { bandwidth-limit 1000000; } } policer p2 { if-exceeding { burst-size-limit 15000; } } }`
	root, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	c, err := CompileConfig(&ConfigTree{Children: root.Children})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(c.Firewall.Policers) != 2 {
		t.Fatalf("two distinct policers compiled to %d — the fold reached a config with no "+
			"duplicate block", len(c.Firewall.Policers))
	}
	if p := c.Firewall.Policers["p1"]; p == nil || p.BandwidthLimit == 0 || p.BurstSizeLimit != 0 {
		t.Errorf("p1 = %+v, want only its own bandwidth-limit", p)
	}
	if p := c.Firewall.Policers["p2"]; p == nil || p.BurstSizeLimit == 0 || p.BandwidthLimit != 0 {
		t.Errorf("p2 = %+v, want only its own burst-size-limit", p)
	}
}
