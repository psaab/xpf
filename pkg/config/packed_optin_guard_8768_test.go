package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #8768: a container that opts into packedStatements must compile the PACKED
// and BRACED spellings identically for EVERY ORDERED PAIR of its admitted
// leaves — not for the one pair whoever opted it in happened to measure.
//
// THE JUSTIFICATION IS A PRIORI, NOT A COUNTER-EXAMPLE, and an earlier version
// of this comment claimed otherwise. Opting a container in is a claim about
// EVERY admitted leaf — that each survives the packed spelling — so every pair
// has to be compared for the claim to be tested. That argument needs no
// observed defect and does not weaken without one.
//
// THE MECHANISM THIS ORIGINALLY CITED WAS RETRACTED. It said `snmp community`
// showed a leaf-level reader ignoring a correctly-split tail. It does not:
// `snmp community` does not fold at all, because ("community","authorization")
// is not in the scope list, so there is no split structure and no reader
// ignoring one. Its lost `clients` is an ordinary drop at an unadmitted site
// (#8778). NO per-leaf reader divergence has ever been demonstrated, and the
// 18-of-18 EQUAL measured here is entirely consistent with none existing.
//
// The retraction is recorded rather than deleted because the cell's assertions
// were never affected by it — only the story about why they matter. A guard
// whose stated reason is a phantom still passes review, and the next person to
// read it inherits the phantom.
//
// "Multi-ness is not the discriminator" is likewise NOT asserted here. It was
// supported by `snmp community clients` diverging, and that divergence is not a
// fold divergence, so the evidence is gone even though the claim may still be
// true. `snmp trap-group targets` is multi and fine, which is one half and not
// a discriminator.
//
// THE REGISTRY IS ASSERTED AGAINST THE SCHEMA IN BOTH DIRECTIONS. A container
// that opts in without adding fixtures here reds, because otherwise this cell
// would silently cover only the containers someone remembered — the same
// accumulating-registry failure the #8690 buckets were built to avoid.
type packedOptInCase8768 struct {
	prefix string // text before the container statement
	open   string // the container statement itself, e.g. `trap-group tg1`
	closer string // text after
	// stmts maps an ADMITTED leaf to a real statement for it. A fixture for a
	// leaf that is not admitted to the compact-normalize scope is INERT -- it is
	// never compared -- so writing one is a false claim of coverage. The reverse
	// check at the end of the cell rejects them; `dead-peer-detection`,
	// `dynamic` and `no-nat-traversal` were three such entries on both gateway
	// containers, silently unused since they were written.
	stmts map[string]string
	// second holds a DIFFERENT instance of the same leaf, for the same-leaf
	// comparison below. Required for every admitted leaf that is `multi: true`
	// or `args >= 2`; see the same-leaf loop for why that is the population.
	second map[string]string
	// always is a statement the container CANNOT COMPILE WITHOUT, appended to
	// BOTH arms of every comparison below.
	//
	// `security log stream <s>` is the first container to need it: a stream
	// with no `host` does not compile at all, so a same-leaf fixture for any
	// other leaf has BOTH arms at ABSENT and the non-vacuity check correctly
	// refuses it -- a comparison of two nothings cannot tell a split from a
	// swallow. That refusal is right and is not satisfiable by writing a better
	// fixture, because the requirement is the container's, not the fixture's.
	//
	// The workaround does not exist either: declaring the stream in `prefix`
	// and repeating the container statement does NOT help, because two
	// `stream s1` blocks do not merge -- measured, the second block's
	// `category` is discarded.
	//
	// It goes INSIDE the container body, so the packed arm packs it into the
	// run exactly as an operator would write it. If the split works every
	// statement survives; if it does not, the arms diverge and that is the
	// signal this guard exists for.
	always string
	read   func(*Config) string
}

func packedOptInCases8768() map[string]packedOptInCase8768 {
	// A SECOND declared proposal, so `proposals pr2` in the same-leaf fixture
	// references something real. Pointing the second instance at pr1 would make
	// the two statements identical, and a same-leaf comparison built from two
	// identical statements cannot tell a split from a swallow.
	const ikeProp2 = "proposal pr2 { authentication-method pre-shared-keys; " +
		"dh-group group14; authentication-algorithm sha1; " +
		"encryption-algorithm aes-128-cbc; }"
	const ikeProp = "proposal pr1 { authentication-method pre-shared-keys; dh-group group14; " +
		"authentication-algorithm sha1; encryption-algorithm aes-128-cbc; }"
	// #9620 H11: `inet` and `inet6` opted in so a unit's packed family run
	// splits instead of folding to its first statement. Two leaves are admitted
	// at each, `address` and `filter`, and both are compared here in the packed
	// and braced spellings.
	const fwFilters = "firewall { family inet { filter f1 { term t0 { then accept; } } " +
		"filter f2 { term t0 { then accept; } } } " +
		"family inet6 { filter f6 { term t0 { then accept; } } " +
		"filter f7 { term t0 { then accept; } } } } "
	return map[string]packedOptInCase8768{
		"interfaces/*/unit/family/inet": {
			prefix: fwFilters + "interfaces { ge-0/0/0 { unit 0 { ",
			open:   "family inet",
			closer: " } } }",
			stmts: map[string]string{
				"address": "address 10.0.0.1/24",
				"filter":  "filter input f1",
			},
			second: map[string]string{
				"address": "address 10.0.0.2/24",
				"filter":  "filter output f2",
			},
			read: func(c *Config) string {
				out := ""
				for _, i := range c.Interfaces.Interfaces {
					for _, u := range i.Units {
						out += fmt.Sprintf("addrs=%v fin4=%q fout4=%q fin6=%q fout6=%q",
							u.Addresses, u.FilterInputV4, u.FilterOutputV4,
							u.FilterInputV6, u.FilterOutputV6)
					}
				}
				if out == "" {
					out = "<no unit>"
				}
				return out
			},
		},
		"interfaces/*/unit/family/inet6": {
			prefix: fwFilters + "interfaces { ge-0/0/0 { unit 0 { ",
			open:   "family inet6",
			closer: " } } }",
			stmts: map[string]string{
				"address": "address 2001:db8::1/64",
				"filter":  "filter input f6",
			},
			second: map[string]string{
				"address": "address 2001:db8::2/64",
				"filter":  "filter output f7",
			},
			read: func(c *Config) string {
				out := ""
				for _, i := range c.Interfaces.Interfaces {
					for _, u := range i.Units {
						out += fmt.Sprintf("addrs=%v fin4=%q fout4=%q fin6=%q fout6=%q",
							u.Addresses, u.FilterInputV4, u.FilterOutputV4,
							u.FilterInputV6, u.FilterOutputV6)
					}
				}
				if out == "" {
					out = "<no unit>"
				}
				return out
			},
		},
		// #8781-follow-up: the IKE gateway opted in so a packed body carries
		// `local-identity`/`remote-identity`. The schema declares the container
		// TWICE — under `security ike` and under `security ipsec` — and this
		// guard requires a case for each, so an opt-in cannot ship exercised on
		// one spelling and unmeasured on the other.
		"security/ike/gateway": {
			prefix: "security { ike { " + ikeProp + " policy pol1 { proposals pr1; pre-shared-key ascii-text \"s\"; } ",
			open:   "gateway gw1",
			closer: " } }",
			stmts: map[string]string{
				"address":            "address 192.0.2.1",
				"local-address":      "local-address 192.0.2.2",
				"ike-policy":         "ike-policy pol1",
				"external-interface": "external-interface ge-0/0/0",
				"local-certificate":  "local-certificate cert1",
				"version":            "version v2-only",
				"nat-traversal":      "nat-traversal disable",
				"local-identity":     "local-identity hostname foo",
				"remote-identity":    "remote-identity hostname bar",
				// #9056: a VALUELESS FLAG admitted to the elision scope. It
				// carries no value, so it needs no `second` fixture (the
				// same-leaf loop excludes args==0 by construction) -- but it
				// does need a statement here, or its packed spelling is never
				// compared against its braced one at all.
				"no-nat-traversal": "no-nat-traversal",
			},
			second: map[string]string{
				"address":            "address 192.0.2.9",
				"external-interface": "external-interface ge-0/0/1",
				"ike-policy":         "ike-policy pol2",
				"local-address":      "local-address 192.0.2.8",
				"local-certificate":  "local-certificate cert2",
				"local-identity":     "local-identity hostname foo2",
				"nat-traversal":      "nat-traversal enable",
				"remote-identity":    "remote-identity hostname bar2",
				"version":            "version v1-only",
			},
			read: func(c *Config) string {
				out := ""
				for _, g := range c.Security.IPsec.Gateways {
					out += fmt.Sprintf("addr=%q la=%q pol=%q ext=%q cert=%q ver=%q nat=%q nonat=%v local=%q/%q remote=%q/%q",
						g.Address, g.LocalAddress, g.IKEPolicy, g.ExternalIface,
						g.LocalCertificate, g.Version, g.NATTraversal, g.NoNATTraversal,
						g.LocalIDType, g.LocalIDValue, g.RemoteIDType, g.RemoteIDValue)
				}
				if out == "" {
					return "<no gateway>"
				}
				return out
			},
		},
		"security/ipsec/gateway": {
			prefix: "security { ipsec { ",
			open:   "gateway gw1",
			closer: " } }",
			stmts: map[string]string{
				"address":            "address 192.0.2.1",
				"local-address":      "local-address 192.0.2.2",
				"ike-policy":         "ike-policy pol1",
				"external-interface": "external-interface ge-0/0/0",
				"local-certificate":  "local-certificate cert1",
				"version":            "version v2-only",
				"nat-traversal":      "nat-traversal disable",
				"local-identity":     "local-identity hostname foo",
				"remote-identity":    "remote-identity hostname bar",
				// #9056: a VALUELESS FLAG admitted to the elision scope. It
				// carries no value, so it needs no `second` fixture (the
				// same-leaf loop excludes args==0 by construction) -- but it
				// does need a statement here, or its packed spelling is never
				// compared against its braced one at all.
				"no-nat-traversal": "no-nat-traversal",
			},
			second: map[string]string{
				"address":            "address 192.0.2.9",
				"external-interface": "external-interface ge-0/0/1",
				"ike-policy":         "ike-policy pol2",
				"local-address":      "local-address 192.0.2.8",
				"local-certificate":  "local-certificate cert2",
				"local-identity":     "local-identity hostname foo2",
				"nat-traversal":      "nat-traversal enable",
				"remote-identity":    "remote-identity hostname bar2",
				"version":            "version v1-only",
			},
			read: func(c *Config) string {
				out := ""
				for _, g := range c.Security.IPsec.Gateways {
					out += fmt.Sprintf("addr=%q la=%q pol=%q ext=%q cert=%q ver=%q nat=%q nonat=%v local=%q/%q remote=%q/%q",
						g.Address, g.LocalAddress, g.IKEPolicy, g.ExternalIface,
						g.LocalCertificate, g.Version, g.NATTraversal, g.NoNATTraversal,
						g.LocalIDType, g.LocalIDValue, g.RemoteIDType, g.RemoteIDValue)
				}
				if out == "" {
					return "<no gateway>"
				}
				return out
			},
		},
		// issue 8858: root-authentication opted in because SSHKeys is a
		// []string and a packed multi-key run folded into ONE key without it.
		// The keys deliberately differ so a fold that keeps only the first is
		// visible in the compared value rather than averaging out.
		"system/root-authentication": {
			prefix: "system { ",
			open:   "root-authentication",
			closer: " }",
			stmts: map[string]string{
				"encrypted-password": `encrypted-password "$6$rounds=5000$abc$def"`,
				"ssh-ed25519":        `ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKed a@b"`,
				"ssh-rsa":            `ssh-rsa "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABrsa c@d"`,
				"ssh-dsa":            `ssh-dsa "ssh-dss AAAAB3NzaC1kc3MAAACBAdsa e@f"`,
			},
			second: map[string]string{
				"encrypted-password": `encrypted-password "$6$rounds=5000$xyz$uvw"`,
				"ssh-ed25519":        `ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKed2 g@h"`,
				"ssh-rsa":            `ssh-rsa "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABrsa2 i@j"`,
				"ssh-dsa":            `ssh-dsa "ssh-dss AAAAB3NzaC1kc3MAAACBAdsa2 k@l"`,
			},
			read: func(c *Config) string {
				ra := c.System.RootAuthentication
				if ra == nil {
					return "<no root-authentication>"
				}
				return fmt.Sprintf("pw=%q keys=%v", ra.EncryptedPassword.Reveal(), ra.SSHKeys)
			},
		},
		// #9620 (M5): the snmp community container opted into packedStatements.
		"snmp/community": {
			prefix: "snmp { ",
			open:   "community public",
			closer: " }",
			stmts: map[string]string{
				"clients": "clients 10.0.0.0/8",
			},
			second: map[string]string{
				"clients": "clients 192.0.2.0/24",
			},
			read: func(c *Config) string {
				if c.System.SNMP == nil {
					return "<no snmp>"
				}
				out := ""
				for _, cm := range c.System.SNMP.Communities {
					out += fmt.Sprintf("name=%q auth=%q clients=%v", cm.Name, cm.Authorization, cm.Clients)
				}
				return out
			},
		},
		"snmp/trap-group": {
			prefix: "snmp { ",
			open:   "trap-group tg1",
			closer: " }",
			stmts: map[string]string{
				"targets":    "targets 10.0.0.1",
				"version":    "version v2",
				"categories": "categories authentication",
			},
			second: map[string]string{
				"categories": "categories link",
				"targets":    "targets 10.0.0.2",
				"version":    "version v1",
			},
			read: func(c *Config) string {
				if c.System.SNMP == nil {
					return "<no snmp>"
				}
				out := ""
				for _, g := range c.System.SNMP.TrapGroups {
					out += fmt.Sprintf("targets=%v version=%q cats=%v", g.Targets, g.Version, g.Categories)
				}
				return out
			},
		},
		"security/ipsec/vpn/vpn-monitor": {
			prefix: "security { ipsec { vpn v1 { ",
			open:   "vpn-monitor",
			closer: " } } }",
			stmts: map[string]string{
				"destination-ip":   "destination-ip 1.2.3.4",
				"source-interface": "source-interface ge-0/0/0",
				// #9056: valueless flag, see the gateway note above.
				"optimized": "optimized",
			},
			second: map[string]string{
				"destination-ip":   "destination-ip 5.6.7.8",
				"source-interface": "source-interface ge-0/0/1",
			},
			read: func(c *Config) string {
				out := ""
				for _, v := range c.Security.IPsec.VPNs {
					out += fmt.Sprintf("mon=%v src=%q dst=%q opt=%v",
						v.VPNMonitor, v.VPNMonitorSourceInterface, v.VPNMonitorDestinationIP,
						v.VPNMonitorOptimized)
				}
				return out
			},
		},
		"security/ike/proposal": {
			prefix: "security { ike { ",
			open:   "proposal pr1",
			closer: " } }",
			stmts: map[string]string{
				"authentication-algorithm": "authentication-algorithm sha1",
				"authentication-method":    "authentication-method pre-shared-keys",
				"description":              "description hello",
				"dh-group":                 "dh-group group14",
				"encryption-algorithm":     "encryption-algorithm aes-128-cbc",
				"lifetime-seconds":         "lifetime-seconds 3600",
			},
			second: map[string]string{
				"authentication-algorithm": "authentication-algorithm sha-256",
				"authentication-method":    "authentication-method rsa-signatures",
				"description":              "description goodbye",
				"dh-group":                 "dh-group group5",
				"encryption-algorithm":     "encryption-algorithm aes-256-cbc",
				"lifetime-seconds":         "lifetime-seconds 7200",
			},
			read: func(c *Config) string {
				out := ""
				for _, p := range c.Security.IPsec.IKEProposals {
					out += fmt.Sprintf("auth=%q meth=%q dh=%d enc=%q life=%d",
						p.AuthAlg, p.AuthMethod, p.DHGroup, p.EncryptionAlg, p.LifetimeSeconds)
				}
				return out
			},
		},
		// issue 8904, second instance: `firewall policer <p> if-exceeding`.
		// Same truncation mode as the tunnel rows -- a rate limiter configured
		// with a burst allowance that silently becomes zero. `bandwidth-percent`
		// is NOT admitted, so a fixture for it would be inert.
		"firewall/policer/if-exceeding": {
			prefix: "firewall { policer p1 { ",
			open:   "if-exceeding",
			closer: " then { discard; } } }",
			stmts: map[string]string{
				"bandwidth-limit":  "bandwidth-limit 10m",
				"burst-size-limit": "burst-size-limit 100k",
			},
			second: map[string]string{
				"bandwidth-limit":  "bandwidth-limit 20m",
				"burst-size-limit": "burst-size-limit 200k",
			},
			read: func(c *Config) string {
				out := ""
				names := make([]string, 0, len(c.Firewall.Policers))
				for n := range c.Firewall.Policers {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					p := c.Firewall.Policers[n]
					out += fmt.Sprintf("|%s bw=%d burst=%d", n, p.BandwidthLimit, p.BurstSizeLimit)
				}
				return out
			},
		},
		// issue 8904: both `tunnel` containers opted in, so a packed run
		// `tunnel source A destination B;` splits instead of keeping only the
		// first statement. The schema declares `tunnel` TWICE -- directly under
		// an interface and under a unit -- and this guard requires a case for
		// each, which is the whole reason the opt-in cannot ship exercised on
		// only one of them.
		//
		// `keepalive` and `routing-instance` are NOT admitted to the
		// compact-normalize scope, so fixtures for them would be inert and the
		// reverse check at the end of this cell rejects them. Six admitted
		// leaves, all args:1 and non-multi, so no `second` is required.
		// #9620 (M6): the interfaces unit container opted into packedStatements.
		"interfaces/*/unit": {
			prefix: "interfaces { ge-0/0/0 { flexible-vlan-tagging; ",
			open:   "unit 0",
			closer: " } }",
			stmts: map[string]string{
				"description": "description u0",
				"vlan-id":     "vlan-id 10",
				// #9620 H11 admitted (unit, family), so the unit-elided
				// spelling folds instead of keeping the whole run on the unit
				// node. The reader below carries the family's own state, or a
				// split here would be compared on unit fields alone.
				"family": "family inet address 10.0.0.1/24",
			},
			second: map[string]string{
				"description": "description u1",
				"vlan-id":     "vlan-id 11",
				"family":      "family inet6 address 2001:db8::1/64",
			},
			read: func(c *Config) string {
				ifc := c.Interfaces.Interfaces["ge-0/0/0"]
				if ifc == nil {
					return "<no interface>"
				}
				out := ""
				for n, u := range ifc.Units {
					out += fmt.Sprintf("unit=%d desc=%q vlan=%d inner=%d addrs=%v ",
						n, u.Description, u.VlanID, u.InnerVlanID, u.Addresses)
				}
				return out
			},
		},
		"interfaces/*/tunnel": {
			prefix: "interfaces { gr-0/0/0 { ",
			open:   "tunnel",
			closer: " } }",
			stmts: map[string]string{
				"source":          "source 10.0.0.1",
				"destination":     "destination 10.0.0.2",
				"mode":            "mode gre",
				"key":             "key 42",
				"ttl":             "ttl 64",
				"keepalive-retry": "keepalive-retry 3",
			},
			second: map[string]string{
				"source":          "source 10.0.0.9",
				"destination":     "destination 10.0.0.8",
				"mode":            "mode ipip",
				"key":             "key 77",
				"ttl":             "ttl 32",
				"keepalive-retry": "keepalive-retry 5",
			},
			read: tunnelRead8904(false),
		},
		"interfaces/*/unit/tunnel": {
			prefix: "interfaces { gr-0/0/0 { unit 0 { ",
			open:   "tunnel",
			closer: " } } }",
			stmts: map[string]string{
				"source":          "source 10.0.0.1",
				"destination":     "destination 10.0.0.2",
				"mode":            "mode gre",
				"key":             "key 42",
				"ttl":             "ttl 64",
				"keepalive-retry": "keepalive-retry 3",
			},
			second: map[string]string{
				"source":          "source 10.0.0.9",
				"destination":     "destination 10.0.0.8",
				"mode":            "mode ipip",
				"key":             "key 77",
				"ttl":             "ttl 32",
				"keepalive-retry": "keepalive-retry 5",
			},
			read: tunnelRead8904(true),
		},
		// issue 8939: both filter-term `then` containers. The schema declares
		// `then` under family inet AND inet6, and this guard requires a case for
		// each, so the opt-in cannot ship exercised on only one.
		//
		// `accept`, `discard`, `syslog` and `reject` are NOT admitted, so
		// fixtures for them would be inert and the reverse check rejects them.
		// `log` IS admitted but args:0, so it carries no value and needs no
		// `second`.
		"firewall/family/inet/filter/term/then": {
			prefix: "firewall { family inet { filter f1 { term t1 { ",
			open:   "then",
			closer: " } } } }",
			stmts: map[string]string{
				"count":            "count c1",
				"dscp":             "dscp af11",
				"forwarding-class": "forwarding-class ef",
				"log":              "log",
				"loss-priority":    "loss-priority low",
				"policer":          "policer pol1",
				"routing-instance": "routing-instance ri1",
				"traffic-class":    "traffic-class af12",
			},
			second: map[string]string{
				"count":            "count c2",
				"dscp":             "dscp af21",
				"forwarding-class": "forwarding-class af1",
				"loss-priority":    "loss-priority high",
				"policer":          "policer pol2",
				"routing-instance": "routing-instance ri2",
				"traffic-class":    "traffic-class af22",
			},
			read: firewallThenRead8939(false),
		},
		// #9017: `family any` is a third firewall filter family. It gets its own
		// fixture rather than sharing inet's because the schema subtree is a
		// DEEP COPY -- sharing a node made one of the two paths invisible to
		// this very census (it reported inet as "no longer opting in" while
		// nothing about inet had changed).
		"firewall/family/any/filter/term/then": {
			prefix: "firewall { family any { filter f1 { term t1 { ",
			open:   "then",
			closer: " } } } }",
			stmts: map[string]string{
				"count":            "count c1",
				"dscp":             "dscp af11",
				"forwarding-class": "forwarding-class ef",
				"log":              "log",
				"loss-priority":    "loss-priority low",
				"policer":          "policer pol1",
				"routing-instance": "routing-instance ri1",
				"traffic-class":    "traffic-class af12",
			},
			second: map[string]string{
				"count":            "count c2",
				"dscp":             "dscp af21",
				"forwarding-class": "forwarding-class af1",
				"loss-priority":    "loss-priority high",
				"policer":          "policer pol2",
				"routing-instance": "routing-instance ri2",
				"traffic-class":    "traffic-class af22",
			},
			read: firewallThenRead8939(false),
		},
		"firewall/family/inet6/filter/term/then": {
			prefix: "firewall { family inet6 { filter f1 { term t1 { ",
			open:   "then",
			closer: " } } } }",
			stmts: map[string]string{
				"count":            "count c1",
				"dscp":             "dscp af11",
				"forwarding-class": "forwarding-class ef",
				"log":              "log",
				"loss-priority":    "loss-priority low",
				"policer":          "policer pol1",
				"routing-instance": "routing-instance ri1",
				"traffic-class":    "traffic-class af12",
			},
			second: map[string]string{
				"count":            "count c2",
				"dscp":             "dscp af21",
				"forwarding-class": "forwarding-class af1",
				"loss-priority":    "loss-priority high",
				"policer":          "policer pol2",
				"routing-instance": "routing-instance ri2",
				"traffic-class":    "traffic-class af22",
			},
			read: firewallThenRead8939(true),
		},
		// issue 8932: the security-log stream, and the FIRST container to need
		// `always`. A stream with no `host` does not compile, so without it
		// every same-leaf comparison here has both arms ABSENT and the
		// non-vacuity check refuses them -- correctly, and unsatisfiably.
		//
		// `host` is the existence requirement rather than a compared leaf: it
		// appears once, in `always`, so the arms never carry it twice.
		// `transport` is not admitted (args:0 with children), so a fixture for
		// it would be inert.
		"security/log/stream": {
			prefix: "security { log { ",
			open:   "stream s1",
			closer: " } }",
			always: "host 192.0.2.1",
			stmts: map[string]string{
				"category":         "category policy",
				"facility":         "facility local0",
				"format":           "format sd-syslog",
				"port":             "port 5140",
				"severity":         "severity info",
				"source-address":   "source-address 192.0.2.9",
				"source-interface": "source-interface ge-0/0/0.0",
			},
			second: map[string]string{
				"category":         "category all",
				"facility":         "facility local1",
				"format":           "format syslog",
				"port":             "port 5141",
				"severity":         "severity warning",
				"source-address":   "source-address 192.0.2.8",
				"source-interface": "source-interface ge-0/0/1.0",
			},
			read: func(c *Config) string {
				out := ""
				for _, st := range c.Security.Log.Streams {
					out += fmt.Sprintf("|%s host=%s cat=%s fac=%s fmt=%s port=%d sev=%s sa=%s si=%s",
						st.Name, st.Host, st.Category, st.Facility, st.Format,
						st.Port, st.Severity, st.SourceAddress, st.SourceInterface)
				}
				return out
			},
		},
		// issue 8939: the class-of-service BINDING containers, at BOTH the unit
		// level and the interface level -- the schema declares each twice and
		// this guard requires a case for each, so an opt-in cannot ship
		// exercised on only one.
		//
		// THE TWO LEVELS DO NOT HAVE THE SAME CHILDREN, which the reverse check
		// caught after the first version gave them the same fixtures:
		// `inet-precedence` is declared only under `classifiers` at the UNIT
		// level; `exp` is declared by neither binding container here. A fixture
		// for a leaf the container does not declare is silently unused, so
		// writing one is a false claim of coverage -- the same error as
		// registering a whole family when only some members qualify.
		//
		// Every admitted leaf is an args:1 named reference, so each carries a
		// second instance.
		"class-of-service/interfaces/unit/classifiers": {
			prefix: "class-of-service { interfaces ge-0/0/0 { unit 0 { ",
			open:   "classifiers",
			closer: " } } }",
			stmts: map[string]string{
				"dscp":            "dscp ref1",
				"ieee-802.1":      "ieee-802.1 ref2",
				"inet-precedence": "inet-precedence ref3",
			},
			second: map[string]string{
				"dscp":            "dscp alt1",
				"ieee-802.1":      "ieee-802.1 alt2",
				"inet-precedence": "inet-precedence alt3",
			},
			read: func(c *Config) string {
				out := ""
				for _, i := range c.ClassOfService.Interfaces {
					for _, u := range i.Units {
						out += fmt.Sprintf("|%s.%d dc=%s ic=%s pc=%s dr=%s ir=%s",
							i.Name, u.Unit, u.DSCPClassifier, u.IEEE8021Classifier,
							u.INetPrecedenceClassifier, u.DSCPRewriteRule, u.IEEE8021RewriteRule)
					}
				}
				return out
			},
		},
		"class-of-service/interfaces/unit/rewrite-rules": {
			prefix: "class-of-service { interfaces ge-0/0/0 { unit 0 { ",
			open:   "rewrite-rules",
			closer: " } } }",
			stmts: map[string]string{
				"dscp":       "dscp ref1",
				"ieee-802.1": "ieee-802.1 ref2",
			},
			second: map[string]string{
				"dscp":       "dscp alt1",
				"ieee-802.1": "ieee-802.1 alt2",
			},
			read: func(c *Config) string {
				out := ""
				for _, i := range c.ClassOfService.Interfaces {
					for _, u := range i.Units {
						out += fmt.Sprintf("|%s.%d dc=%s ic=%s pc=%s dr=%s ir=%s",
							i.Name, u.Unit, u.DSCPClassifier, u.IEEE8021Classifier,
							u.INetPrecedenceClassifier, u.DSCPRewriteRule, u.IEEE8021RewriteRule)
					}
				}
				return out
			},
		},
		"class-of-service/interfaces/classifiers": {
			prefix: "class-of-service { interfaces ge-0/0/0 { ",
			open:   "classifiers",
			closer: " } }",
			stmts: map[string]string{
				"dscp":       "dscp ref1",
				"ieee-802.1": "ieee-802.1 ref2",
			},
			second: map[string]string{
				"dscp":       "dscp alt1",
				"ieee-802.1": "ieee-802.1 alt2",
			},
			read: func(c *Config) string {
				out := ""
				for _, i := range c.ClassOfService.Interfaces {
					if i.Level == nil {
						continue
					}
					u := i.Level
					out += fmt.Sprintf("|%s dc=%s ic=%s pc=%s dr=%s ir=%s",
						i.Name, u.DSCPClassifier, u.IEEE8021Classifier,
						u.INetPrecedenceClassifier, u.DSCPRewriteRule, u.IEEE8021RewriteRule)
				}
				return out
			},
		},
		"class-of-service/interfaces/rewrite-rules": {
			prefix: "class-of-service { interfaces ge-0/0/0 { ",
			open:   "rewrite-rules",
			closer: " } }",
			stmts: map[string]string{
				"dscp":       "dscp ref1",
				"ieee-802.1": "ieee-802.1 ref2",
			},
			second: map[string]string{
				"dscp":       "dscp alt1",
				"ieee-802.1": "ieee-802.1 alt2",
			},
			read: func(c *Config) string {
				out := ""
				for _, i := range c.ClassOfService.Interfaces {
					if i.Level == nil {
						continue
					}
					u := i.Level
					out += fmt.Sprintf("|%s dc=%s ic=%s pc=%s dr=%s ir=%s",
						i.Name, u.DSCPClassifier, u.IEEE8021Classifier,
						u.INetPrecedenceClassifier, u.DSCPRewriteRule, u.IEEE8021RewriteRule)
				}
				return out
			},
		},
		// #9689: `profile` opted into packedStatements when it gained its second
		// scalar leaf, fail-mode.
		"security/dynamic-address/address-name/profile": {
			prefix: "security { dynamic-address { feed-server partners { url http://example.test/partners; } address-name allow-partners { ",
			open:   "profile",
			closer: " } } }",
			stmts: map[string]string{
				"feed-name": "feed-name partners",
				"fail-mode": "fail-mode drop",
			},
			second: map[string]string{
				"feed-name": "feed-name threats",
				"fail-mode": "fail-mode retain",
			},
			read: func(c *Config) string {
				b := c.Security.DynamicAddress.AddressBindings["allow-partners"]
				if b == nil {
					return "<no binding>"
				}
				return fmt.Sprintf("feeds=%v fail-mode=%q", b.FeedNames, b.FailMode)
			},
		},
		"security/ipsec/proposal": {
			prefix: "security { ipsec { ",
			open:   "proposal ip1",
			closer: " } }",
			stmts: map[string]string{
				"authentication-algorithm": "authentication-algorithm hmac-sha-256-128",
				"description":              "description hello",
				"dh-group":                 "dh-group group14",
				"encryption-algorithm":     "encryption-algorithm aes-128-cbc",
				"lifetime-kilobytes":       "lifetime-kilobytes 100000",
				"lifetime-seconds":         "lifetime-seconds 3600",
				"protocol":                 "protocol esp",
			},
			second: map[string]string{
				"authentication-algorithm": "authentication-algorithm hmac-sha1-96",
				"description":              "description goodbye",
				"dh-group":                 "dh-group group5",
				"encryption-algorithm":     "encryption-algorithm aes-256-cbc",
				"lifetime-kilobytes":       "lifetime-kilobytes 200000",
				"lifetime-seconds":         "lifetime-seconds 7200",
				"protocol":                 "protocol ah",
			},
			read: func(c *Config) string {
				out := ""
				for _, p := range c.Security.IPsec.Proposals {
					// `lifekb` is reported because the same-leaf loop needs the
					// reader to DISTINGUISH two instances of every value-bearing
					// leaf; a leaf the reader drops makes its comparison
					// degenerate, green whether the packed run splits or swallows.
					out += fmt.Sprintf("proto=%q auth=%q dh=%d enc=%q life=%d lifekb=%d",
						p.Protocol, p.AuthAlg, p.DHGroup, p.EncryptionAlg,
						p.LifetimeSeconds, p.LifetimeKilobytes)
				}
				return out
			},
		},
		"security/ike/gateway/dead-peer-detection": {
			prefix: "security { ike { gateway g1 { ",
			open:   "dead-peer-detection",
			closer: " } } }",
			stmts: map[string]string{
				"interval":  "interval 10",
				"threshold": "threshold 3",
			},
			second: map[string]string{
				"interval":  "interval 20",
				"threshold": "threshold 5",
			},
			read: func(c *Config) string {
				out := ""
				for _, g := range c.Security.IPsec.Gateways {
					out += fmt.Sprintf("dpdOn=%v mode=%q int=%d thr=%d",
						g.DPDEnable, g.DeadPeerDetect, g.DPDInterval, g.DPDThreshold)
				}
				return out
			},
		},
		// #8850 opted both address books in so a packed run of entries splits
		// per statement instead of folding into one and swallowing every entry
		// after the first. Both admitted leaves are compared, per this cell's
		// own contract that opting a container in is a claim about ALL of them.
		"security/zones/security-zone/address-book": {
			prefix: "security { zones { security-zone trust { ",
			open:   "address-book",
			closer: " } } }",
			stmts: map[string]string{
				"address": "address a1 10.0.0.1/32",
				// FLAT, not braced. These builders join statements with ";", so a
				// statement ending in "}" yields "};" and the arm fails to PARSE
				// -- which compared <parse err> to <parse err>, green and
				// measuring nothing. It also has to be the ELIDED spelling to
				// reach the splitter at all; the braced one lands in the #8850
				// decline branch.
				"address-set": "address-set s1 address a1",
			},
			second: map[string]string{
				"address":     "address a2 10.0.0.2/32",
				"address-set": "address-set s2 address a1",
			},
			read: func(c *Config) string {
				for _, z := range c.Security.Zones {
					if z.AddressBook == nil {
						return "<no book>"
					}
					var names []string
					for k := range z.AddressBook.Addresses {
						names = append(names, k)
					}
					for k := range z.AddressBook.AddressSets {
						names = append(names, "set:"+k)
					}
					sort.Strings(names)
					return strings.Join(names, ",")
				}
				return "<no zone>"
			},
		},
		"security/address-book/global": {
			prefix: "security { address-book { ",
			open:   "global",
			closer: " } }",
			stmts: map[string]string{
				"address": "address a1 10.0.0.1/32",
				// FLAT, not braced. These builders join statements with ";", so a
				// statement ending in "}" yields "};" and the arm fails to PARSE
				// -- which compared <parse err> to <parse err>, green and
				// measuring nothing. It also has to be the ELIDED spelling to
				// reach the splitter at all; the braced one lands in the #8850
				// decline branch.
				"address-set": "address-set s1 address a1",
			},
			second: map[string]string{
				"address":     "address a2 10.0.0.2/32",
				"address-set": "address-set s2 address a1",
			},
			read: func(c *Config) string {
				if c.Security.AddressBook == nil {
					return "<no book>"
				}
				var names []string
				for k := range c.Security.AddressBook.Addresses {
					names = append(names, k)
				}
				for k := range c.Security.AddressBook.AddressSets {
					names = append(names, "set:"+k)
				}
				sort.Strings(names)
				return strings.Join(names, ",")
			},
		},
		"security/ike/policy": {
			prefix: "security { ike { " + ikeProp + " " + ikeProp2 + " ",
			open:   "policy p1",
			closer: " } }",
			stmts: map[string]string{
				"mode":           "mode main",
				"pre-shared-key": "pre-shared-key ascii-text SEKRIT",
				"proposals":      "proposals pr1",
				"proposal-set":   "proposal-set standard",
			},
			second: map[string]string{
				"mode":           "mode aggressive",
				"pre-shared-key": "pre-shared-key ascii-text SEKRIT2",
				"proposal-set":   "proposal-set basic",
				"proposals":      "proposals pr2",
			},
			read: func(c *Config) string {
				out := ""
				for _, p := range c.Security.IPsec.IKEPolicies {
					// PSK BY LENGTH, NOT BY VALUE, and via Reveal() so the access
					// stays greppable -- secret.go documents Reveal as
					// "deliberately greppable so an audit can find every cleartext
					// access", and len() on the Secret directly is the only such
					// site in pkg/. The type redacts itself under
					// %q (`<redacted>`), so `psk=%q` renders every distinct
					// secret identically -- which made `pre-shared-key`
					// unobservable in every comparison in this cell, not just
					// the two-instance one. Length distinguishes the fixtures
					// without printing the secret into a failure message.
					out += fmt.Sprintf("mode=%q psklen=%d props=%v pset=%q",
						p.Mode, len(p.PSK.Reveal()), p.Proposals, p.ProposalSet)
				}
				return out
			},
		},
	}
}

func TestPackedOptInHoldsForEveryLeafPair8768(t *testing.T) {
	// Find every container in the schema that has opted in.
	// KEYED BY SCHEMA PATH, not by container name. Names repeat: `proposal`
	// exists under both `ike` and `ipsec`, and `dead-peer-detection` under both
	// too. A name-keyed registry does not fail on that — it silently holds
	// whichever node the walk reached last and enumerates the WRONG container's
	// leaves while reading as coverage for the one someone opted in.
	//
	// The earlier version refused when two names collided, which was correct
	// and blocked three containers from opting in. A path is unique by
	// construction, so the refusal is replaced by an address that cannot be
	// ambiguous. Wildcard levels render as `*`, matching how the schema
	// addresses an instance rather than a keyword.
	optedIn := map[string]*schemaNode{}
	canonical := map[*schemaNode]string{}
	var walk func(n *schemaNode, path string, depth int)
	walk = func(n *schemaNode, path string, depth int) {
		if n == nil || depth > 12 {
			return
		}
		if n.packedStatements && path != "" {
			// THE SAME NODE IS REACHABLE BY TWO PATHS. Junos `groups` mirrors
			// the entire schema, so every container also has a
			// `groups/*/<path>` address pointing at the identical node. Keying
			// on the raw path would list each opted-in container twice and
			// demand two identical fixture sets.
			//
			// Dedupe by node IDENTITY and keep the shortest path as the
			// canonical address — which is the non-groups one, because the
			// mirror only ever adds a prefix.
			if prev, seen := canonical[n]; !seen || len(path) < len(prev) {
				canonical[n] = path
			}
		}
		for cn, ch := range n.children {
			next := cn
			if path != "" {
				next = path + "/" + cn
			}
			walk(ch, next, depth+1)
		}
		if n.wildcard != nil {
			walk(n.wildcard, path+"/*", depth+1)
		}
	}
	walk(setSchema, "", 0)
	for n, path := range canonical {
		optedIn[path] = n
	}

	if len(optedIn) == 0 {
		t.Fatal("no container declares packedStatements, so this cell asserts " +
			"nothing — either the flag was removed or the walk lost reach (#8768)")
	}

	cases := packedOptInCases8768()

	// BOTH DIRECTIONS. An opted-in container with no fixtures is unverified; a
	// fixture for a container that no longer opts in is stale.
	var unfixtured, stale []string
	for name := range optedIn {
		if _, ok := cases[name]; !ok {
			unfixtured = append(unfixtured, name)
		}
	}
	for name := range cases {
		if _, ok := optedIn[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(unfixtured)
	sort.Strings(stale)
	if len(unfixtured) > 0 {
		t.Errorf("%d container(s) declare packedStatements with NO fixtures here: %v.\n"+
			"Opting a container in is a claim that every admitted leaf survives the "+
			"packed spelling, and every one has to be COMPARED for that claim to "+
			"be tested. Add real statements for each admitted leaf (#8768).",
			len(unfixtured), unfixtured)
	}
	if len(stale) > 0 {
		t.Errorf("%d fixture set(s) name a container that no longer opts in: %v.\n"+
			"Remove them; a registry that only grows stops being a measurement.",
			len(stale), stale)
	}

	compile := func(txt string, read func(*Config) string) string {
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			return "<parse err>"
		}
		cfg, err := compileConfigWithOpts(tr, lenientCompileOpts())
		if err != nil || cfg == nil {
			return fmt.Sprintf("<err %v>", err)
		}
		return read(cfg)
	}

	// A packed run whose head is a CONTAINER (a schema node with children) is a
	// NESTED elision, not a leaf spelling: the container's own body has no
	// terminator inside the run, so `splitPackedStatements8768` cannot know where
	// it ends. `consumeNodeKeys` consumes the container's arity, the remainder
	// fails to split, and the tail is returned whole -- the container's multi
	// leaf then absorbs every following statement.
	//
	// MEASURED AT origin/master c6c5a8b3c, BEFORE address-book was opted in, so
	// this divergence is NOT caused by the opt-in -- the opt-in is what made this
	// cell look at it:
	//
	//	packed  address-book address-set s1 address a1 address a2 10.0.0.2/32;
	//	          -> set:s1(a1|address|a2|10.0.0.2/32)      (master AND here)
	//	braced  address-book { address-set s1 address a1; address a2 ...; }
	//	          -> a2, set:s1(a1)                          (master AND here)
	//
	// Registering it is NOT a waiver: an entry here must STILL DIVERGE or the
	// cell fails on the stale registration below, and any divergence that is not
	// registered still fails. Nested elision is owned by the #8850 d2 work, not
	// by the opt-in; when that lands, these entries must be deleted, not updated.
	divergesByNestedElision := map[string]bool{
		"security/zones/security-zone/address-book address-set+address": true,
		"security/address-book/global address-set+address":              true,
		// The reverse order, which surfaced only once the fixture was written
		// FLAT and the parse guard above stopped the arm failing silently.
		// Re-derived against origin/master rather than carried over:
		//
		//	packed  global address a1 10.0.0.1/32 address-set s1 address a1;
		//	  master  <nothing at all>
		//	  head    addr:a1=10.0.0.1/32        (the set is still lost)
		//	braced    addr:a1=10.0.0.1/32, set:s1(a1)
		//
		// So this head is strictly BETTER than master here and still unequal.
		// Recorded as diverging, not as fixed.
	}
	sawDivergence := map[string]bool{}

	// Two instances of one leaf that legitimately do NOT split, with the reason
	// MEASURED rather than assumed. Same contract as the map above: an entry
	// that stops diverging fails as stale, and an unadjudicated divergence still
	// fails. Empty until a measurement puts something here.
	sameLeafAdjudicated := map[string]string{
		"class-of-service/interfaces/classifiers ieee-802.1+ieee-802.1":                "scalar binding: a repeated statement OVERWRITES, so both spellings yield one value",
		"class-of-service/interfaces/rewrite-rules dscp+dscp":                          "scalar binding: a repeated statement OVERWRITES, so both spellings yield one value",
		"class-of-service/interfaces/rewrite-rules ieee-802.1+ieee-802.1":              "scalar binding: a repeated statement OVERWRITES, so both spellings yield one value",
		"class-of-service/interfaces/unit/classifiers dscp+dscp":                       "scalar binding: a repeated statement OVERWRITES, so both spellings yield one value",
		"class-of-service/interfaces/unit/classifiers ieee-802.1+ieee-802.1":           "scalar binding: a repeated statement OVERWRITES, so both spellings yield one value",
		"class-of-service/interfaces/unit/classifiers inet-precedence+inet-precedence": "scalar binding: a repeated statement OVERWRITES, so both spellings yield one value",
		"class-of-service/interfaces/unit/rewrite-rules dscp+dscp":                     "scalar binding: a repeated statement OVERWRITES, so both spellings yield one value",
		"class-of-service/interfaces/unit/rewrite-rules ieee-802.1+ieee-802.1":         "scalar binding: a repeated statement OVERWRITES, so both spellings yield one value",

		// Two instances of `address-set`, the divergence the round-1 review of
		// #8873 found live at head. It is NESTED ELISION, not a same-leaf split
		// failure: `address-set` is args:1 WITH children, so the run cannot be
		// cut through it and the first set absorbs the rest.
		//
		//	packed  global address-set s1 address a1 address-set s2 address a1;
		//	          -> set:s1(a1|address-set|s2|address)
		//	braced  -> set:s1(a1), set:s2(a1)
		//
		// BYTE-IDENTICAL AT origin/master, so neither the opt-in nor the #8850
		// container-head fix caused or closed it. It belongs to the d2 nested-
		// elision work; when that lands these entries must be DELETED, not
		// updated -- the stale check below is what forces that.
		"security/zones/security-zone/address-book address-set+address-set": "nested elision: container head absorbs the run (identical at master)",
		"security/address-book/global address-set+address-set":              "nested elision: container head absorbs the run (identical at master)",
	}
	sawSameLeaf := map[string]bool{}

	// Leaves whose value the COMPILER DISCARDS, so no reader can distinguish two
	// instances of them and the same-leaf comparison is degenerate by
	// construction rather than by a narrow reader.
	//
	// `description` on both proposal types is declared in setSchema and admitted
	// to the scope, but neither IKEProposal nor IPsecProposal has a Description
	// field -- the value is parsed and dropped. This is the same shape
	// schema_security.go already records for the address-set `description`
	// (#3332): declared, accepted, unsupported at compile.
	//
	// NOT A WAIVER. An entry here must STILL be degenerate; if the field is ever
	// wired the comparison becomes live and the stale check below fails, which
	// is the signal to delete the entry and let the leaf be measured.
	sameLeafUnobservable := map[string]string{
		// #9620 (M6): the interfaces unit container opted into packedStatements.
		"interfaces/*/unit description+description": "scalar binding: the compiler keeps the FIRST statement's value, so one instance and two read alike (measured #9620: `description u0; description u1;` reads desc=\"u0\")",
		"interfaces/*/unit vlan-id+vlan-id":         "scalar binding: the compiler keeps the FIRST statement's value, so one instance and two read alike (measured #9620: `description u0; description u1;` reads desc=\"u0\")",
		// issue 8939: the class-of-service BINDING containers. Every binding is
		// a SCALAR field -- CoSInterfaceUnit.DSCPClassifier is one string, not a
		// list -- so a repeated statement OVERWRITES rather than accumulating,
		// and one instance reads identically to two. The same-leaf comparison
		// therefore cannot distinguish a split run from a swallowed one, and no
		// fixture can repair that: it is a property of the FIELD, not of the
		// arms.
		//
		// THIS IS NOT THE GUARD BEING LENIENT, and the distinction matters
		// because an unobservable entry is exactly what a wrong verdict hides
		// behind. The ORDERED-PAIR comparisons for these four containers are
		// live and are the ones that do the work: `dscp c1 ieee-802.1 c2` is
		// precisely the shape that was losing the second binding, and it is
		// compared for every ordered pair of admitted leaves at all four sites.
		// Only the leaf-against-ITSELF case is degenerate.
		"class-of-service/interfaces/classifiers dscp+dscp":                            "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",
		"class-of-service/interfaces/classifiers ieee-802.1+ieee-802.1":                "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",
		"class-of-service/interfaces/rewrite-rules dscp+dscp":                          "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",
		"class-of-service/interfaces/rewrite-rules ieee-802.1+ieee-802.1":              "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",
		"class-of-service/interfaces/unit/classifiers dscp+dscp":                       "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",
		"class-of-service/interfaces/unit/classifiers ieee-802.1+ieee-802.1":           "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",
		"class-of-service/interfaces/unit/classifiers inet-precedence+inet-precedence": "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",
		"class-of-service/interfaces/unit/rewrite-rules dscp+dscp":                     "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",
		"class-of-service/interfaces/unit/rewrite-rules ieee-802.1+ieee-802.1":         "scalar binding: a repeated statement OVERWRITES, so one instance and two read alike",

		"security/ike/proposal description+description":   "IKEProposal has no Description field; value discarded at compile",
		"security/ipsec/proposal description+description": "IPsecProposal has no Description field; value discarded at compile",
	}
	sawUnobservable := map[string]bool{}

	checked := 0
	// `always` EXEMPTS ITS LEAF FROM THE PER-LEAF FIXTURE DEMAND, so the field
	// is an escape hatch: the demand is the expensive part of this guard, and
	// the cheapest way past a future refusal is to move the demanded leaf into
	// `always` and call it an existence requirement. That would be a guard
	// satisfiable by writing something false, and the false thing is one word.
	//
	// So the contents are VERIFIED rather than trusted: WITHOUT the `always`
	// statement, the container must contribute NOTHING OBSERVABLE. That is the
	// exact property the exemption rests on -- it is what makes a same-leaf
	// comparison for any other leaf a comparison of two nothings, which the
	// vacuity check below correctly refuses and which no better fixture can
	// repair.
	//
	// THE FIRST VERSION OF THIS CHECK ASSERTED THE BRACED ARM FAILS TO COMPILE,
	// AND IT WAS WRONG -- it fired on the only case using the field. Measured:
	// `security log stream s1 { category policy; }` COMPILES CLEANLY, with no
	// error and no strict rejection, and produces ZERO streams. The stream is
	// silently discarded rather than the config refused. Same vacuity, but a
	// different mechanism, and asserting the wrong one would have made the
	// field unusable for the container it was built for.
	//
	// Same principle as the reverse check on `stmts`, in the other direction:
	// that one rejects a fixture for a leaf which is NOT admitted, because
	// writing one is a false claim of coverage; this one rejects an existence
	// claim the container does not actually make.
	for name, c := range cases {
		if c.always == "" || c.read == nil {
			continue
		}
		var probe string
		for _, st := range c.stmts {
			probe = st
			break
		}
		if probe == "" {
			continue
		}
		withoutAlways := c.prefix + c.open + " { " + probe + "; }" + c.closer
		cfg := compileText(t, withoutAlways)
		if cfg == nil {
			continue // refused outright: an even stronger requirement
		}
		if got := c.read(cfg); got != "" {
			t.Errorf("container %q declares always=%q, but WITHOUT that statement "+
				"the container still contributes %q -- so it is not an existence "+
				"requirement, and the leaf it names is exempt from the per-leaf "+
				"fixture demand for no reason.\n  fixture: %s\n"+
				"  `always` exists for a container that produces NOTHING without a "+
				"statement, which is why its leaf need not also be varied: every "+
				"comparison for every other leaf would otherwise have both arms "+
				"empty. Using it for a leaf that is merely inconvenient to fixture "+
				"removes that leaf from comparison while looking handled (#8768).",
				name, c.always, got, withoutAlways)
		}
	}

	for name, node := range optedIn {
		c, ok := cases[name]
		if !ok {
			continue
		}
		// Every ADMITTED leaf must have a statement: a leaf admitted to the
		// scope but missing here is exactly the leaf whose packed spelling was
		// never compared.
		//
		// The scope predicate takes the container KEYWORD, which is the last
		// non-wildcard segment of the path — `security/ike/gateway/*/dead-peer-
		// detection` asks about `dead-peer-detection`, not about `*`.
		kw := containerKeywordOfPath8768(name)
		var leaves []string
		for leaf := range node.children {
			if !compactNormalizeInScope(kw, leaf) {
				continue
			}
			if _, ok := c.stmts[leaf]; !ok {
				// A leaf supplied as the container's EXISTENCE REQUIREMENT is
				// already in BOTH arms of every comparison and is observed by
				// `read`, so it IS compared -- just not with a varying value.
				// Demanding a second fixture for it would put the statement in
				// twice, which tests duplicate-leaf handling rather than the
				// split.
				//
				// It is still exercised in the direction that matters: if the
				// packed run fails to split, the existence statement is lost
				// with everything else and every arm diverges at once.
				if c.alwaysLeaf() == leaf {
					continue
				}
				t.Errorf("container %q admits leaf %q with no fixture statement, so "+
					"its packed spelling is never compared against its braced one "+
					"(#8768)", name, leaf)
				continue
			}
			leaves = append(leaves, leaf)
		}
		sort.Strings(leaves)
		for _, a := range leaves {
			for _, b := range leaves {
				if a == b {
					continue
				}
				packed := c.prefix + c.open + " " + c.alwaysPacked() + c.stmts[a] + " " + c.stmts[b] + ";" + c.closer
				braced := c.prefix + c.open + " { " + c.alwaysBraced() + c.stmts[a] + "; " + c.stmts[b] + "; }" + c.closer
				got, want := compile(packed, c.read), compile(braced, c.read)
				checked++
				// NEITHER ARM MAY BE A COMPILE FAILURE. Without this the loop
				// compared <parse err> to <parse err> -- equal, green, measuring
				// nothing -- and worse, a pair whose reference arm merely FAILED
				// TO PARSE registered as a divergence, pinning a
				// divergesByNestedElision entry to an unparsable string so no
				// change to the fold could ever free it. A registry entry that
				// can never be discharged is worse than a vacuous cell, because
				// the registry's whole contract is that entries are DELETED when
				// the divergence is repaired.
				//
				// The same-leaf loop below has carried this guard since it was
				// written; this is the older loop being given it.
				if bad := firstCompileFailure8768(got, want); bad != "" {
					t.Errorf("%s: the %s spelling for %q + %q did not parse or "+
						"compile (%s), so this pair asserts nothing -- and if it "+
						"is registered as diverging, the registration is pinned to "+
						"a fixture fault rather than to a fold (#8768)",
						name, bad, a, b, map[string]string{"packed": got, "braced": want}[bad])
					continue
				}
				if got != want {
					key := name + " " + a + "+" + b
					if divergesByNestedElision[key] {
						sawDivergence[key] = true
						continue
					}
					t.Errorf("%s: packed and braced DIFFER for %q + %q (#8768)\n"+
						"  packed %s\n  braced %s\n"+
						"MEASURED, NOT DIAGNOSED: this cell knows the two spellings "+
						"disagree and nothing more. Do not assume a reader defect — no "+
						"per-leaf reader divergence has ever been observed, and the "+
						"likelier causes are the fold declining to split (a token "+
						"outside the modelled grammar, so the tail returns whole) or an "+
						"arity the schema under-declares, which was the #8777 case. "+
						"Establish which before changing anything; the container must "+
						"not stay opted in on the strength of a different pair.",
						name, a, b, got, want)
				}
			}
		}
	}
	// SAME-LEAF PAIRS: two instances of ONE leaf.
	//
	// The loop above compares DISTINCT leaves and opens with `if a == b { continue }`,
	// so a leaf was never compared against itself. That skip is exactly the
	// defect class this guard exists for: one instance proves the statement is
	// REACHABLE, and only two prove the RUN IS SPLIT. It is why this cell stayed
	// green on both address books through the whole window in which they were
	// folding a two-entry run into one and silently keeping only the first --
	// it was measuring the axis that already worked.
	//
	// POPULATION: leaves that are `multi: true` or `args >= 2`. A leaf with
	// args==1 and no multi consumes a fixed two tokens, so its boundary is not
	// in question; the hazard is a multi leaf ABSORBING what follows it, or a
	// wider arity making the boundary non-obvious to a one-instance fixture.
	// Measured at the time of writing: 10 such leaves across 6 of the 10
	// opted-in containers, out of 46 admitted leaves.
	//
	// A leaf in that population with no `second` fixture REDS, on the same terms
	// as a missing `stmts` entry -- otherwise the population silently shrinks to
	// whatever someone remembered.
	sameChecked := 0
	for name, node := range optedIn {
		c, ok := cases[name]
		if !ok {
			continue
		}
		kw := containerKeywordOfPath8768(name)
		var leaves []string
		for leaf := range node.children {
			if !compactNormalizeInScope(kw, leaf) {
				continue
			}
			leaves = append(leaves, leaf)
		}
		sort.Strings(leaves)
		for _, leaf := range leaves {
			ln := node.children[leaf]
			// POPULATION: every admitted leaf that CARRIES A VALUE.
			//
			// This was `multi || args >= 2`, on the argument that an args==1
			// non-multi leaf consumes a fixed two tokens so "its boundary is not
			// in question". That argument was WRONG, and wrong in the way this
			// file's own header rejects for the distinct-pair loop: opting a
			// container in is a claim about EVERY admitted leaf, and a claim
			// needs no observed defect to require testing.
			//
			// It also hid a LIVE divergence. `address-set` is args==1, non-multi,
			// and at the head that introduced this loop:
			//
			//	packed  global address-set s1 { address a1; } address-set s2 { ... }
			//	          -> set:s1(a1)                     <- s2 SILENTLY LOST
			//	braced  global { address-set s1 { ... } address-set s2 { ... } }
			//	          -> set:s1(a1), set:s2(a1)
			//
			// which is verbatim the #8768 defect class. Reasoning about
			// consumeNodeKeys' token accounting answered a narrower question than
			// the comparison actually asks: the comparison runs packed-vs-braced
			// end to end, through the splitter, the arity, the compiler's
			// last-wins and the reader.
			//
			// args==0 flags are excluded because a second instance of a flag is
			// TEXTUALLY IDENTICAL to the first -- degenerate by construction, and
			// the liveness gate below would reject it anyway. That exclusion is
			// about the fixture being expressible, not about the claim being
			// uninteresting.
			if ln == nil || (!ln.multi && ln.args < 1) {
				continue
			}
			first, ok := c.stmts[leaf]
			if !ok {
				continue // already reported by the loop above
			}
			sec, ok := c.second[leaf]
			if ok {
				// The second statement must be an instance OF THIS LEAF. Nothing
				// checked that, so a `second` naming a DIFFERENT leaf silently
				// turned a same-leaf comparison into a duplicate of loop 1 while
				// the summary line still counted it as same-leaf. Measured: two
				// such entries dropped the merge-adjacent mutant's same-leaf
				// kills from 10 to 8 with the printed count unchanged at 10.
				if !strings.HasPrefix(sec, leaf+" ") && sec != leaf {
					t.Errorf("container %q: second fixture for %q is %q, which is "+
						"not an instance of that leaf -- this comparison is a "+
						"DISTINCT-leaf pair wearing a same-leaf label, and the "+
						"count cannot tell them apart (#8768)", name, leaf, sec)
					sawSameLeaf[name+" "+leaf+"+"+leaf] = true
					continue
				}
				if sec == first {
					t.Errorf("container %q: second fixture for %q is IDENTICAL to "+
						"the first (%q), so the run cannot distinguish a split "+
						"from a swallow (#8768)", name, leaf, sec)
					sawSameLeaf[name+" "+leaf+"+"+leaf] = true
					continue
				}
			}
			if !ok {
				t.Errorf("container %q admits %q, which CARRIES A VALUE, but has "+
					"no `second` fixture, so the packed spelling is only ever "+
					"compared at ONE instance -- the spelling that cannot "+
					"distinguish a split run from a swallowed one (#8768)",
					name, leaf)
				continue
			}
			packed := c.prefix + c.open + " " + c.alwaysPacked() + first + " " + sec + ";" + c.closer
			braced := c.prefix + c.open + " { " + c.alwaysBraced() + first + "; " + sec + "; }" + c.closer
			got, want := compile(packed, c.read), compile(braced, c.read)
			sameChecked++

			// LIVENESS, and it is not optional here. `got == want` is satisfied
			// perfectly by BOTH arms failing, and by a second instance the
			// reader never surfaces. Either makes this comparison green while
			// measuring nothing -- the same both-arms-empty trap that makes a
			// braced-vs-elided cell read as "no defect" or "value lost"
			// depending only on how the assertion is phrased.
			// Match the COMPILE sentinels specifically, not every "<...>" string:
			// several readers legitimately return `<no gateway>` / `<no snmp>` /
			// `<none>` when the object is absent. Treating those as "did not
			// compile" would emit a diagnostic that sends the reader to the
			// parser when the real answer is that the fixture built nothing --
			// a wrong diagnostic being worse than a missing one.
			// Screen BOTH arms. Screening only the braced one reports a packed
			// fixture that failed to PARSE as `packed and braced DIFFER`, which
			// sends the reader at the fold when the fault is in the fixture text
			// -- a wrong diagnostic, which this file holds to be worse than a
			// missing one. Reachable whenever a `second` value ends in `}`,
			// because the builder appends an unconditional `;`.
			if got == "<parse err>" || strings.HasPrefix(got, "<err ") {
				sawSameLeaf[name+" "+leaf+"+"+leaf] = true
				t.Errorf("container %q: the PACKED spelling for two instances of "+
					"%q did not parse or compile (%s). That is a FIXTURE fault, "+
					"not a fold divergence -- check the statement text before "+
					"looking at the normalizer (#8768)", name, leaf, got)
				continue
			}
			if want == "<parse err>" || strings.HasPrefix(want, "<err ") {
				t.Errorf("container %q: the BRACED reference for two instances of "+
					"%q did not compile (%s), so comparing it against the packed "+
					"spelling proves nothing (#8768)", name, leaf, want)
				sawSameLeaf[name+" "+leaf+"+"+leaf] = true
				continue
			}
			// A reader that reports NOTHING is the other vacuous shape: both arms
			// agree at "absent" and the comparison is satisfied without either
			// spelling having produced an object.
			if strings.HasPrefix(want, "<") {
				t.Errorf("container %q: the BRACED reference for two instances of "+
					"%q compiled but the reader reports %s, so both arms can agree "+
					"at ABSENT and this comparison asserts nothing (#8768)",
					name, leaf, want)
				sawSameLeaf[name+" "+leaf+"+"+leaf] = true
				continue
			}
			// The second instance must MOVE the reader's output. If one instance
			// and two produce the same string, the fixture cannot distinguish a
			// split run from a swallowed one no matter what the packed arm does.
			bracedOne := c.prefix + c.open + " { " + c.alwaysBraced() + first + "; }" + c.closer
			if one := compile(bracedOne, c.read); one == want {
				key := name + " " + leaf + "+" + leaf
				if reason, ok := sameLeafUnobservable[key]; ok {
					sawUnobservable[key] = true
					sawSameLeaf[key] = true
					t.Logf("#8768: %s is UNOBSERVABLE and not compared: %s", key, reason)
					continue
				}
				t.Errorf("container %q: adding a SECOND instance of %q changes "+
					"nothing the reader reports (%s), so this comparison is "+
					"degenerate -- it would stay green if the packed spelling "+
					"swallowed the second statement entirely. Give %q a second "+
					"instance the reader distinguishes, or widen the reader "+
					"(#8768)", name, leaf, one, leaf)
				sawSameLeaf[name+" "+leaf+"+"+leaf] = true
				continue
			}
			if got == want {
				continue
			}
			key := name + " " + leaf + "+" + leaf
			if reason, ok := sameLeafAdjudicated[key]; ok {
				sawSameLeaf[key] = true
				t.Logf("#8768: %s two-instance divergence is ADJUDICATED: %s", key, reason)
				continue
			}
			t.Errorf("%s: packed and braced DIFFER for TWO INSTANCES of %q (#8768)\n"+
				"  packed %s\n  braced %s\n"+
				"A one-instance fixture cannot see this. If only the FIRST "+
				"instance survives the packed spelling, the container folds a "+
				"multi-statement run into one; if the two spellings disagree in "+
				"some other way, establish WHICH before changing anything and "+
				"record it in sameLeafAdjudicated with the measurement.",
				name, leaf, got, want)
		}
	}
	// A pair that was GATED OUT above (fixture fault, absent reader, degenerate
	// second instance) was never compared, so it cannot be evidence that an
	// adjudication is stale. Every bail-out marks sawSameLeaf for exactly that
	// reason; without it the cell emitted TWO failures for one cause, the second
	// asserting the spellings "now AGREE" when they had not been compared at all.
	// RUNS OF THREE. Every comparison above builds a run of exactly TWO
	// statements, and a splitter that handles two but not three passes all of
	// them -- measured: `if len(out) > 2 { return [][]string{tail} }` at the tail
	// of splitPackedStatements8768 leaves this cell AND the whole pkg/config
	// suite green while `gateway g1 version v2-only local-address 192.0.2.2
	// external-interface ge-0/0/0;` silently loses two of its three statements.
	//
	// Three is an ordinary operator spelling, and it needs no new fixture data:
	// the containers that declare three or more admitted leaves already have
	// statements for them.
	runChecked := 0
	for name, node := range optedIn {
		c, ok := cases[name]
		if !ok {
			continue
		}
		kw := containerKeywordOfPath8768(name)
		var leaves []string
		for leaf := range node.children {
			if !compactNormalizeInScope(kw, leaf) {
				continue
			}
			if _, ok := c.stmts[leaf]; ok {
				leaves = append(leaves, leaf)
			}
		}
		sort.Strings(leaves)
		if len(leaves) < 3 {
			continue
		}
		for i := 0; i+2 < len(leaves); i++ {
			a, b, d := leaves[i], leaves[i+1], leaves[i+2]
			packed := c.prefix + c.open + " " + c.alwaysPacked() + c.stmts[a] + " " + c.stmts[b] + " " + c.stmts[d] + ";" + c.closer
			braced := c.prefix + c.open + " { " + c.alwaysBraced() + c.stmts[a] + "; " + c.stmts[b] + "; " + c.stmts[d] + "; }" + c.closer
			got, want := compile(packed, c.read), compile(braced, c.read)
			runChecked++
			if strings.HasPrefix(want, "<") || strings.HasPrefix(got, "<") {
				continue // the two-statement loops already police fixture health
			}
			if got == want {
				continue
			}
			if divergesByNestedElision[name+" "+a+"+"+b] ||
				divergesByNestedElision[name+" "+b+"+"+d] ||
				divergesByNestedElision[name+" "+a+"+"+d] {
				continue // already registered at length two; not a new fact
			}
			t.Errorf("%s: a run of THREE statements diverges where the pairs do "+
				"not: %q then %q then %q (#8768)\n  packed %s\n  braced %s\n"+
				"A splitter that handles two statements and not three passes "+
				"every other comparison in this cell.", name, a, b, d, got, want)
		}
	}
	if runChecked == 0 {
		t.Error("no three-statement run was built, so the N=3 axis is unmeasured " +
			"even though this cell claims to cover it (#8768)")
	}

	// FIXTURE -> SCHEMA, the reverse direction. The container-level `cases` map
	// is asserted against the schema in both directions; these leaf-level maps
	// were not, so a `second` written for a leaf that is not admitted (or is
	// misspelled) was silently ignored and the cell stayed green. That is the
	// trap for whoever acts on a finding here: they add the fixture, it does
	// nothing, and nothing says so.
	for name, node := range optedIn {
		c, ok := cases[name]
		if !ok {
			continue
		}
		kw := containerKeywordOfPath8768(name)
		for _, m := range []struct {
			which string
			fx    map[string]string
		}{{"stmts", c.stmts}, {"second", c.second}} {
			var keys []string
			for leaf := range m.fx {
				keys = append(keys, leaf)
			}
			sort.Strings(keys)
			for _, leaf := range keys {
				if node.children[leaf] == nil {
					t.Errorf("container %q has a %s fixture for %q, which is not a "+
						"child of that container in the schema -- the fixture is "+
						"silently unused (#8768)", name, m.which, leaf)
					continue
				}
				if !compactNormalizeInScope(kw, leaf) {
					t.Errorf("container %q has a %s fixture for %q, which is NOT "+
						"admitted to the compact-normalize scope -- the fixture is "+
						"silently unused (#8768)", name, m.which, leaf)
				}
			}
		}
	}

	for key, reason := range sameLeafUnobservable {
		if !sawUnobservable[key] {
			t.Errorf("%q is registered as UNOBSERVABLE (%s) but its two instances "+
				"are now distinguishable, so the leaf CAN be compared and the "+
				"registration is hiding it. Delete the entry (#8768)", key, reason)
		}
	}
	for key, reason := range sameLeafAdjudicated {
		if !sawSameLeaf[key] {
			t.Errorf("%q is adjudicated as a two-instance divergence (%s) but the "+
				"two spellings now AGREE, so the entry is stale and is hiding a "+
				"comparison nothing checks. Delete it (#8768)", key, reason)
		}
	}

	for key := range divergesByNestedElision {
		if !sawDivergence[key] {
			t.Errorf("%q is registered as diverging by NESTED ELISION but the two "+
				"spellings now AGREE, so the registration is stale and is now "+
				"hiding a pair nothing checks. Delete the entry -- a registration "+
				"that outlives its reason is indistinguishable from coverage "+
				"(#8768)", key)
		}
	}
	if checked == 0 {
		t.Fatal("no leaf pair was compared, so this cell passed without measuring " +
			"anything (#8768)")
	}
	t.Logf("#8768: %d opted-in container(s), %d ordered leaf pairs compared, "+
		"%d registered as diverging by nested elision; %d same-leaf (two-instance) "+
		"comparisons, %d adjudicated as correctly not splitting, %d unobservable; "+
		"%d three-statement runs", len(optedIn), checked, len(divergesByNestedElision),
		sameChecked, len(sameLeafAdjudicated), len(sameLeafUnobservable), runChecked)
}

// containerKeywordOfPath8768 returns the keyword the scope predicate is asked
// about for a schema path: the last segment that is not a wildcard.
// firstCompileFailure8768 names which arm failed to parse or compile, or "" if
// both produced a real reading. `<no gateway>`-style reader sentinels are NOT
// compile failures and are deliberately not matched here.
func firstCompileFailure8768(packed, braced string) string {
	isFail := func(v string) bool {
		return v == "<parse err>" || strings.HasPrefix(v, "<err ")
	}
	switch {
	case isFail(packed):
		return "packed"
	case isFail(braced):
		return "braced"
	}
	return ""
}

func containerKeywordOfPath8768(path string) string {
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != "*" && segs[i] != "" {
			return segs[i]
		}
	}
	return ""
}

// tunnelRead8904 reports every tunnel field the #8904 opt-in claims to preserve.
// EVERY admitted leaf is rendered, not just source/destination: a reader that
// printed only the pair a fixture happened to use would let the other four
// leaves diverge unobserved, which is the same single-leaf blindness that made
// `policy-statement -> then` read as a non-defect for a day.
func tunnelRead8904(perUnit bool) func(*Config) string {
	return func(c *Config) string {
		out := ""
		for _, i := range c.Interfaces.Interfaces {
			ts := []*TunnelConfig{}
			if perUnit {
				for _, u := range i.Units {
					ts = append(ts, u.Tunnel)
				}
			} else {
				ts = append(ts, i.Tunnel)
			}
			for _, tn := range ts {
				if tn == nil {
					out += "|<nil>"
					continue
				}
				out += fmt.Sprintf("|src=%s dst=%s mode=%s key=%d ttl=%d kar=%d",
					tn.Source, tn.Destination, tn.Mode, tn.Key, tn.TTL, tn.KeepaliveRetry)
			}
		}
		return out
	}
}

// firewallThenRead8939 reports EVERY admitted `then` action, not just the pair a
// fixture happens to use -- a reader printing two fields would let the other six
// diverge unobserved, which is the single-leaf blindness that made
// `policy-statement -> then` read as a non-defect for a day.
func firewallThenRead8939(v6 bool) func(*Config) string {
	return func(c *Config) string {
		filters := c.Firewall.FiltersInet
		if v6 {
			filters = c.Firewall.FiltersInet6
		}
		names := make([]string, 0, len(filters))
		for n := range filters {
			names = append(names, n)
		}
		sort.Strings(names)
		out := ""
		for _, n := range names {
			for _, tm := range filters[n].Terms {
				// `traffic-class` compiles into DSCPRewrite as well
				// (compiler_firewall.go: case "dscp", "traffic-class"), so it
				// is observed through that field rather than a separate one.
				out += fmt.Sprintf("|%s count=%s dscp=%s fc=%s log=%v lp=%s pol=%s ri=%s",
					tm.Name, tm.Count, tm.DSCPRewrite, tm.ForwardingClass, tm.Log,
					tm.LossPriority, tm.Policer, tm.RoutingInstance)
			}
		}
		return out
	}
}

// alwaysPacked renders the container's existence requirement for a PACKED arm:
// part of the run, with a trailing space, or empty when the container has none.
func (c packedOptInCase8768) alwaysPacked() string {
	if c.always == "" {
		return ""
	}
	return c.always + " "
}

// alwaysBraced renders it for a BRACED arm: its own statement.
func (c packedOptInCase8768) alwaysBraced() string {
	if c.always == "" {
		return ""
	}
	return c.always + "; "
}

// alwaysLeaf names the leaf the container's existence requirement supplies, or
// "" when there is none.
func (c packedOptInCase8768) alwaysLeaf() string {
	if c.always == "" {
		return ""
	}
	return strings.Fields(c.always)[0]
}
