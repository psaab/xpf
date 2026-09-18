package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// #8879 batch 1: four pairs admitted to compactNormalizeInScope, each after
// measuring that its elided spelling was SILENT.
//
// THE ADMISSION RULE IS PER PAIR AND THE GATE COLUMN DECIDES IT:
//
//	elided spelling REJECTED at strict  -> do NOT admit; the operator is already
//	                                      told, and admitting makes it quiet
//	elided spelling WARNS on lenient    -> same reasoning, weaker signal
//	elided spelling SILENT              -> admit; a silent drop becomes a
//	                                      correct compile
//
// #8868 is why the first row is not a formality: admitting `system login` would
// convert a LOUD #6662 commit rejection into a silent acceptance — a regression
// wearing the shape of a fix.
//
// Measured before admission, with these fixtures rather than the sweep's
// synthesized ones:
//
//	protocols bgp    braced as=65001 rid=10.0.0.1  ->  elided <nil>
//	security ike     braced proposals=1            ->  elided 0
//	security nat     braced pools=1                ->  elided 0
//	system syslog    braced hosts=1                ->  elided <nil>
//
// all four with strict accepting and lenient not warning on either arm: the
// whole stanza dropped, silently.
//
// Shipped-config sweep after the batch: 9 pass / 5 fail, identical to the
// pre-batch baseline and failing for the same pre-existing reasons (four
// historical evidence configs with no cluster authentication-key, one node-id
// mismatch). Confirming a rule catches its target says nothing about what else
// it catches, so the corpus is swept per batch rather than per campaign.
// admittedElisionCases8879 is the SINGLE source of the #8879 fixtures.
// It is package level so the guard below and the ratio re-derivation
// (TestAdmittedDropsAreReadSomewhere8879) measure the SAME fixtures. A
// second copy would drift, and a ratio derived from a drifted copy is a
// claim about the copy.
var admittedElisionCases8879 = []struct {
	pair, braced, elided string
	get                  func(*Config) string
}{
	{"protocols bgp",
		`protocols { bgp { local-as 65001; router-id 10.0.0.1; } }`,
		`protocols bgp { local-as 65001; router-id 10.0.0.1; }`,
		func(c *Config) string {
			if c.Protocols.BGP == nil {
				return "<nil>"
			}
			return fmt.Sprintf("as=%d rid=%s", c.Protocols.BGP.LocalAS, c.Protocols.BGP.RouterID)
		}},
	{"security ike",
		`security { ike { proposal pr { authentication-method pre-shared-keys; } } }`,
		`security ike { proposal pr { authentication-method pre-shared-keys; } }`,
		func(c *Config) string { return fmt.Sprintf("proposals=%d", len(c.Security.IPsec.IKEProposals)) }},
	{"security nat",
		`security { nat { source { pool P { address 10.0.0.1/32; } } } }`,
		`security nat { source { pool P { address 10.0.0.1/32; } } }`,
		func(c *Config) string { return fmt.Sprintf("pools=%d", len(c.Security.NAT.SourcePools)) }},
	// #8943 final — the remaining depth-2 drops. Per-row evidence, collision
	// counts and the dataplane-vs-compiler severity axis in
	// docs/log/8943-final.md.
	{"address-book global",
		`security { address-book { global { address a7717 203.0.113.7/32; } } }`,
		`security { address-book global { address a7717 203.0.113.7/32; } }`,
		func(c *Config) string {
			if c.Security.AddressBook == nil {
				return "<nil>"
			}
			return fmt.Sprintf("addrs=%d", len(c.Security.AddressBook.Addresses))
		}},
	{"archival configuration",
		`system { archival { configuration { transfer-interval 77; } } }`,
		`system { archival configuration { transfer-interval 77; } }`,
		func(c *Config) string {
			if c.System.Archival == nil {
				return "<nil>"
			}
			return fmt.Sprintf("iv=%d", c.System.Archival.TransferInterval)
		}},
	{"bgp damping",
		`protocols { bgp { damping { half-life 27; } } }`,
		`protocols { bgp damping { half-life 27; } }`,
		func(c *Config) string {
			if c.Protocols.BGP == nil {
				return "<nil>"
			}
			return fmt.Sprintf("damp=%v/%d", c.Protocols.BGP.Dampening, c.Protocols.BGP.DampeningHalfLife)
		}},
	{"bgp multipath",
		`protocols { bgp { multipath { multiple-as; } } }`,
		`protocols { bgp multipath { multiple-as; } }`,
		func(c *Config) string {
			if c.Protocols.BGP == nil {
				return "<nil>"
			}
			return fmt.Sprintf("mpAS=%v", c.Protocols.BGP.MultipathMultipleAS)
		}},
	{"dataplane coalescence",
		`system { dataplane { coalescence { rx-usecs 37; } } }`,
		`system { dataplane coalescence { rx-usecs 37; } }`,
		func(c *Config) string {
			if c.System.UserspaceDataplane == nil {
				return "<nil>"
			}
			return fmt.Sprintf("rx=%d", c.System.UserspaceDataplane.CoalescenceRXUsecs)
		}},
	{"dataplane shared-umem",
		`system { dataplane { shared-umem { mode cross-nic; } } }`,
		`system { dataplane shared-umem { mode cross-nic; } }`,
		func(c *Config) string {
			if c.System.UserspaceDataplane == nil || c.System.UserspaceDataplane.SharedUMEM == nil {
				return "<nil>"
			}
			return "umem=" + c.System.UserspaceDataplane.SharedUMEM.Mode
		}},
	{"flow-monitoring version9",
		`services { flow-monitoring { version9 { template t7717 { flow-active-timeout 313; } } } }`,
		`services { flow-monitoring version9 { template t7717 { flow-active-timeout 313; } } }`,
		func(c *Config) string {
			if c.Services.FlowMonitoring == nil || c.Services.FlowMonitoring.Version9 == nil {
				return "<nil>"
			}
			return fmt.Sprintf("v9=%d", len(c.Services.FlowMonitoring.Version9.Templates))
		}},
	{"flow-monitoring version-ipfix",
		`services { flow-monitoring { version-ipfix { template t7718 { flow-active-timeout 317; } } } }`,
		`services { flow-monitoring version-ipfix { template t7718 { flow-active-timeout 317; } } }`,
		func(c *Config) string {
			if c.Services.FlowMonitoring == nil || c.Services.FlowMonitoring.VersionIPFIX == nil {
				return "<nil>"
			}
			return fmt.Sprintf("ipfix=%d", len(c.Services.FlowMonitoring.VersionIPFIX.Templates))
		}},
	{"interface-routes rib-group",
		`routing-options { interface-routes { rib-group inet rg7717; } }`,
		`routing-options { interface-routes rib-group inet rg7717; }`,
		func(c *Config) string { return "rg=" + c.RoutingOptions.InterfaceRoutesRibGroup }},
	{"license autoupdate",
		`system { license { autoupdate { url https://lic7717.example.invalid/x; } } }`,
		`system { license autoupdate { url https://lic7717.example.invalid/x; } }`,
		func(c *Config) string { return "url=" + c.System.LicenseAutoUpdate }},
	{"policies policy-rematch",
		`security { policies { policy-rematch { extensive; } } }`,
		`security { policies policy-rematch { extensive; } }`,
		func(c *Config) string {
			return fmt.Sprintf("rematch=%v/%v", c.Security.PolicyRematch, c.Security.PolicyRematchExtensive)
		}},
	{"pre-id-default-policy then",
		`security { pre-id-default-policy { then { log { session-init; } } } }`,
		`security { pre-id-default-policy then { log { session-init; } } }`,
		func(c *Config) string {
			if c.Security.PreIDDefaultPolicy == nil {
				return "<nil>"
			}
			return fmt.Sprintf("init=%v", c.Security.PreIDDefaultPolicy.LogSessionInit)
		}},
	{"rib static",
		`routing-options { rib inet.0 { static { route 203.0.113.0/24 { next-hop 10.9.0.1; } } } }`,
		`routing-options { rib inet.0 static { route 203.0.113.0/24 { next-hop 10.9.0.1; } } }`,
		func(c *Config) string {
			return fmt.Sprintf("static=%d", len(c.RoutingOptions.StaticRoutes))
		}},
	// #8943 — the `syslog` destinations. The lost field reaches the RUNTIME:
	// applySyslogConfig builds the syslog clients from these, so an elided
	// destination means the operator has configured a log target and has none.
	{"syslog host",
		`system { syslog { host 198.51.100.44 { any warning; } } }`,
		`system { syslog host 198.51.100.44 { any warning; } }`,
		func(c *Config) string {
			if c.System.Syslog == nil {
				return "<nil>"
			}
			return fmt.Sprintf("hosts=%d", len(c.System.Syslog.Hosts))
		}},
	{"syslog file",
		`system { syslog { file trace7717.log { any info; } } }`,
		`system { syslog file trace7717.log { any info; } }`,
		func(c *Config) string {
			if c.System.Syslog == nil {
				return "<nil>"
			}
			return fmt.Sprintf("files=%d", len(c.System.Syslog.Files))
		}},
	{"syslog user",
		`system { syslog { user opsuser7717 { any critical; } } }`,
		`system { syslog user opsuser7717 { any critical; } }`,
		func(c *Config) string {
			if c.System.Syslog == nil {
				return "<nil>"
			}
			return fmt.Sprintf("users=%d", len(c.System.Syslog.Users))
		}},
	// #8943 — the `flow` family. Values chosen NOT to equal the compiled
	// defaults: udp-session and icmp-session both default to 60, so a fixture
	// using 60 would read clean while broken.
	//
	// The readers print the FIELD rather than a fingerprint, because a
	// difference tells you something was lost and not what the loss did --
	// and here that distinction reversed a verdict. `flow aging` LOOKS like
	// the worst row (its leaves compile to 0 and the schema says
	// `0 = disabled`), but the braced arm warns that pressure-based shedding
	// is accepted-only in the AF_XDP dataplane, so the feature is inert either
	// way and the elision costs the ADVISORY rather than behaviour. It is
	// registered in TestAdmittedDropsAreReadSomewhere8879's not-read set for
	// that reason. The other four lose live values.
	{"flow aging",
		`security { flow { aging { early-ageout 37; high-watermark 91; low-watermark 71; } } }`,
		`security { flow aging { early-ageout 37; high-watermark 91; low-watermark 71; } }`,
		func(c *Config) string {
			f := c.Security.Flow
			return fmt.Sprintf("early=%d hi=%d lo=%d",
				f.AgingEarlyAgeout, f.AgingHighWatermark, f.AgingLowWatermark)
		}},
	{"flow tcp-session",
		`security { flow { tcp-session { established-timeout 1777; } } }`,
		`security { flow tcp-session { established-timeout 1777; } }`,
		func(c *Config) string {
			if c.Security.Flow.TCPSession == nil {
				return "<nil>"
			}
			return fmt.Sprintf("est=%d", c.Security.Flow.TCPSession.EstablishedTimeout)
		}},
	{"flow udp-session",
		`security { flow { udp-session { timeout 77; } } }`,
		`security { flow udp-session { timeout 77; } }`,
		func(c *Config) string { return fmt.Sprintf("udp=%d", c.Security.Flow.UDPSessionTimeout) }},
	{"flow icmp-session",
		`security { flow { icmp-session { timeout 47; } } }`,
		`security { flow icmp-session { timeout 47; } }`,
		func(c *Config) string { return fmt.Sprintf("icmp=%d", c.Security.Flow.ICMPSessionTimeout) }},
	{"flow traceoptions",
		`security { flow { traceoptions { file ftrace7717.log; } } }`,
		`security { flow traceoptions { file ftrace7717.log; } }`,
		func(c *Config) string {
			if c.Security.Flow.Traceoptions == nil {
				return "<nil>"
			}
			return "trace=" + c.Security.Flow.Traceoptions.File
		}},
	// #8943 — the rest of the `nat` family, siblings of the #8929 `nat source`
	// pair. All five drop their whole body when the child's brace is elided.
	// #8921 collision check: one schema site each.
	{"nat destination",
		`security { nat { destination { pool dp1 { address 10.9.0.9/32; } } } }`,
		`security { nat destination { pool dp1 { address 10.9.0.9/32; } } }`,
		func(c *Config) string {
			if c.Security.NAT.Destination == nil {
				return "<nil>"
			}
			return fmt.Sprintf("dpools=%d", len(c.Security.NAT.Destination.Pools))
		}},
	{"nat static",
		`security { nat { static { rule-set rs1 { from zone trust; rule r1 { match { destination-address 10.9.0.0/24; } then { static-nat prefix 10.8.0.0/24; } } } } } }`,
		`security { nat static { rule-set rs1 { from zone trust; rule r1 { match { destination-address 10.9.0.0/24; } then { static-nat prefix 10.8.0.0/24; } } } } }`,
		func(c *Config) string { return fmt.Sprintf("static=%d", len(c.Security.NAT.Static)) }},
	{"nat nat64",
		`security { nat { nat64 { rule-set rs1 { from zone untrust; rule r1 { match { destination-address 64:ff9b::/96; } then { translate; } } } } } }`,
		`security { nat nat64 { rule-set rs1 { from zone untrust; rule r1 { match { destination-address 64:ff9b::/96; } then { translate; } } } } }`,
		func(c *Config) string { return fmt.Sprintf("nat64=%d", len(c.Security.NAT.NAT64)) }},
	{"nat natv6v4",
		`security { nat { natv6v4 { prefix 2001:db8::/96; } } }`,
		`security { nat natv6v4 { prefix 2001:db8::/96; } }`,
		func(c *Config) string {
			if c.Security.NAT.NATv6v4 == nil {
				return "<nil>"
			}
			return "natv6v4=set"
		}},
	{"nat proxy-arp",
		`security { nat { proxy-arp { interface ge-0/0/0.0 { address 10.9.0.9/32; } } } }`,
		`security { nat proxy-arp { interface ge-0/0/0.0 { address 10.9.0.9/32; } } }`,
		func(c *Config) string { return fmt.Sprintf("parp=%d", len(c.Security.NAT.ProxyARP)) }},
	// #8929 — a DEPTH-2 pair. `braced` is the fully braced spelling and
	// `elided` is the DOUBLY elided one: `security nat { ... }` folds because
	// (security, nat) is admitted, but whether `nat source { ... }` folds is a
	// separate decision answered by (nat, source). Before this admission the
	// doubly-elided spelling compiled to exactly what an EMPTY config
	// produces — the source NAT pool silently vanished.
	{"nat source",
		`security { nat { source { pool p1 { address 10.9.0.1; } } } }`,
		`security nat source { pool p1 { address 10.9.0.1; } }`,
		func(c *Config) string {
			return fmt.Sprintf("pools=%d", len(c.Security.NAT.SourcePools))
		}},
	// #8925 — found by SCHEMA WALK, not by the sweep. See
	// TestUnadmittedTopLevelPairsAreAdjudicated8925 for the instrument and
	// why the sweep could not see these.
	{"class-of-service forwarding-classes",
		`class-of-service { forwarding-classes { queue 3 my-ef; } }`,
		`class-of-service forwarding-classes { queue 3 my-ef; }`,
		func(c *Config) string {
			return fmt.Sprintf("fc=%d", len(c.ClassOfService.ForwardingClasses))
		}},
	{"policy-options as-path",
		`policy-options { as-path ap7717 ".* 65001"; }`,
		`policy-options as-path ap7717 ".* 65001";`,
		func(c *Config) string {
			return fmt.Sprintf("asp=%d", len(c.PolicyOptions.ASPaths))
		}},
	// The elided spelling turned DPI application detection OFF. Same shape as
	// `security policy-stats`: a feature disabled by the choice of spelling,
	// with no diagnostic.
	{"services application-identification",
		`services { application-identification { no-application-system-cache; } }`,
		`services application-identification { no-application-system-cache; }`,
		func(c *Config) string {
			return fmt.Sprintf("appid=%v", c.Services.ApplicationIdentification)
		}},
	{"system internet-options",
		`system { internet-options { no-ipv6-reject-zero-hop-limit; } }`,
		`system internet-options { no-ipv6-reject-zero-hop-limit; }`,
		func(c *Config) string {
			if c.System.InternetOptions == nil {
				return "<nil>"
			}
			return fmt.Sprintf("iopt=%v", c.System.InternetOptions.NoIPv6RejectZeroHopLimit)
		}},
	// #8879 batch 9 — the last of the population.
	//
	// Two fixtures here had to be repaired before they could answer, and
	// both failures were mine rather than the code's: `ssh-known-hosts`
	// with a bare `host` compiled to ZERO hosts on BOTH arms (a host with
	// no key is not stored), which is a dead comparison that would have
	// read as "no drop"; and `ip-monitoring` needs BOTH a defined rpm
	// probe and a `then preferred-route`, without which the braced
	// reference did not compile at all.
	{"forwarding-options port-mirroring",
		`forwarding-options { port-mirroring { instance pm1 { input { rate 313; } } } }`,
		`forwarding-options port-mirroring { instance pm1 { input { rate 313; } } }`,
		func(c *Config) string {
			if c.ForwardingOptions.PortMirroring == nil {
				return "<nil>"
			}
			return fmt.Sprintf("inst=%d", len(c.ForwardingOptions.PortMirroring.Instances))
		}},
	{"routing-options interface-routes",
		`routing-options { interface-routes { rib-group inet rg-7717; } }`,
		`routing-options interface-routes { rib-group inet rg-7717; }`,
		func(c *Config) string { return "rg=" + c.RoutingOptions.InterfaceRoutesRibGroup }},
	{"security ssh-known-hosts",
		`security { ssh-known-hosts { host h7717.example.invalid { rsa-key AAAAB3NzaC1yc2EAAAADAQABAAABgQxx; } } }`,
		`security ssh-known-hosts { host h7717.example.invalid { rsa-key AAAAB3NzaC1yc2EAAAADAQABAAABgQxx; } }`,
		func(c *Config) string { return fmt.Sprintf("hosts=%d", len(c.Security.SSHKnownHosts)) }},
	// 313, not 60/15 — those are the compiled defaults for the flow
	// timeouts and a fixture carrying one reads clean while broken.
	{"services flow-monitoring",
		`services { flow-monitoring { version9 { template tpl1 { flow-active-timeout 313; } } } }`,
		`services flow-monitoring { version9 { template tpl1 { flow-active-timeout 313; } } }`,
		func(c *Config) string {
			if c.Services.FlowMonitoring == nil || c.Services.FlowMonitoring.Version9 == nil {
				return "<nil>"
			}
			return fmt.Sprintf("tpl=%d", len(c.Services.FlowMonitoring.Version9.Templates))
		}},
	{"services ip-monitoring",
		`services { rpm { probe pr1 { test t1 { probe-type icmp-ping; target address 198.51.100.9; } } } ip-monitoring { policy ipm1 { match { rpm-probe pr1; } then { preferred-route { route 203.0.113.0/24 { next-hop 198.51.100.1; } } } } } }`,
		`services { rpm { probe pr1 { test t1 { probe-type icmp-ping; target address 198.51.100.9; } } } } services ip-monitoring { policy ipm1 { match { rpm-probe pr1; } then { preferred-route { route 203.0.113.0/24 { next-hop 198.51.100.1; } } } } }`,
		func(c *Config) string {
			if c.Services.IPMonitoring == nil {
				return "<nil>"
			}
			return fmt.Sprintf("pol=%d", len(c.Services.IPMonitoring.Policies))
		}},
	// #8879 batch 8.
	//
	// `forwarding-options family` uses mode `packet-based` and NOT
	// `flow-based`, which is the compiled default. A fixture carrying the
	// default value reads CLEAN WHILE BROKEN: losing it and keeping it
	// produce the same compiled answer, so the comparison can never fail.
	// This is the row where that trap was closest to being stepped in.
	{"forwarding-options family",
		`forwarding-options { family { inet6 { mode packet-based; } } }`,
		`forwarding-options family { inet6 { mode packet-based; } }`,
		func(c *Config) string { return "mode=" + c.ForwardingOptions.FamilyInet6Mode }},
	{"protocols ospf3",
		`protocols { ospf3 { area 0.0.0.9 { interface ge-0/0/0.0 { metric 33; } } } }`,
		`protocols ospf3 { area 0.0.0.9 { interface ge-0/0/0.0 { metric 33; } } }`,
		func(c *Config) string {
			if c.Protocols.OSPFv3 == nil {
				return "<nil>"
			}
			return fmt.Sprintf("areas=%d", len(c.Protocols.OSPFv3.Areas))
		}},
	{"security dynamic-address",
		`security { dynamic-address { feed-server fs1 { url https://feeds.example.invalid/x; } } }`,
		`security dynamic-address { feed-server fs1 { url https://feeds.example.invalid/x; } }`,
		func(c *Config) string {
			return fmt.Sprintf("feeds=%d", len(c.Security.DynamicAddress.FeedServers))
		}},
	{"system dataplane",
		`system { dataplane { binary /opt/xpf/dp-7717; workers 5; } }`,
		`system dataplane { binary /opt/xpf/dp-7717; workers 5; }`,
		func(c *Config) string {
			if c.System.UserspaceDataplane == nil {
				return "<nil>"
			}
			return fmt.Sprintf("bin=%s/w=%d",
				c.System.UserspaceDataplane.Binary, c.System.UserspaceDataplane.Workers)
		}},
	// #8879 batch 7. THE FIRST TWO ARE A CORRECTION OF MY OWN BATCH-5
	// WORK. Batch 5 re-checked the sweep's SAME rows by hand and cleared
	// `class-of-service classifiers` and `class-of-service rewrite-rules`
	// as "genuinely SAME". That was true of the ONE leaf I tried (`dscp`)
	// and false of the pair: via `inet-precedence` and `exp` both drop.
	//
	// It is precisely the error I had diagnosed in the sweep one batch
	// earlier -- a verdict derived from a single leaf, reported about the
	// pair -- committed by the person who wrote the diagnosis. The
	// fixtures below therefore use the DROPPING leaf, not the convenient
	// one.
	{"class-of-service classifiers",
		`class-of-service { classifiers { inet-precedence cl2 { forwarding-class expedited-forwarding { loss-priority low code-points 101; } } } }`,
		`class-of-service classifiers { inet-precedence cl2 { forwarding-class expedited-forwarding { loss-priority low code-points 101; } } }`,
		func(c *Config) string {
			return fmt.Sprintf("prec=%d", len(c.ClassOfService.INetPrecedenceClassifierDefs))
		}},
	// SEVERITY NOTE, so this row is not read as worse than it is: the
	// braced arm raises "rewrite-rules exp is accepted for compatibility
	// but inert" -- the value has no runtime effect either way. What the
	// elision actually costs here is the ADVISORY, not the behaviour. The
	// operator writing the elided spelling gets neither the (inert)
	// config nor the notice telling them it is inert.
	{"class-of-service rewrite-rules",
		`class-of-service { rewrite-rules { exp rw2 { forwarding-class expedited-forwarding { loss-priority low code-point 101; } } } }`,
		`class-of-service rewrite-rules { exp rw2 { forwarding-class expedited-forwarding { loss-priority low code-point 101; } } }`,
		func(c *Config) string {
			return fmt.Sprintf("exp=%d", len(c.ClassOfService.EXPRewriteRules))
		}},
	{"protocols lldp",
		`protocols { lldp { interface ge-0/0/6.0; transmit-interval 47; } }`,
		`protocols lldp { interface ge-0/0/6.0; transmit-interval 47; }`,
		func(c *Config) string {
			if c.Protocols.LLDP == nil {
				return "<nil>"
			}
			return fmt.Sprintf("if=%d/int=%d",
				len(c.Protocols.LLDP.Interfaces), c.Protocols.LLDP.Interval)
		}},
	// Same severity note as `rewrite-rules exp`: the braced arm warns that
	// pre-id session logging is inert in the userspace dataplane, so the
	// loss is the advisory rather than a live behaviour.
	{"security pre-id-default-policy",
		`security { pre-id-default-policy { then { log { session-init; } } } }`,
		`security pre-id-default-policy { then { log { session-init; } } }`,
		func(c *Config) string {
			if c.Security.PreIDDefaultPolicy == nil {
				return "<nil>"
			}
			return fmt.Sprintf("init=%v/close=%v",
				c.Security.PreIDDefaultPolicy.LogSessionInit,
				c.Security.PreIDDefaultPolicy.LogSessionClose)
		}},
	// #8879 batch 6. Read `routing-options forwarding-table` twice: the
	// elision was not only dropping a value, it was SUPPRESSING A COMMIT
	// CHECK. See TestElisionSuppressedAValidation8879 below.
	{"forwarding-options dhcp-relay",
		`forwarding-options { dhcp-relay { group g1 { active-server-group sg1; interface ge-0/0/4.0; } } }`,
		`forwarding-options dhcp-relay { group g1 { active-server-group sg1; interface ge-0/0/4.0; } }`,
		func(c *Config) string {
			if c.ForwardingOptions.DHCPRelay == nil {
				return "<nil>"
			}
			return fmt.Sprintf("groups=%d", len(c.ForwardingOptions.DHCPRelay.Groups))
		}},
	{"protocols rip",
		`protocols { rip { neighbor ge-0/0/5.0; redistribute static; } }`,
		`protocols rip { neighbor ge-0/0/5.0; redistribute static; }`,
		func(c *Config) string {
			if c.Protocols.RIP == nil {
				return "<nil>"
			}
			return fmt.Sprintf("if=%d/redist=%d",
				len(c.Protocols.RIP.Interfaces), len(c.Protocols.RIP.Redistribute))
		}},
	// The export policy is DEFINED in both arms on purpose. With an
	// undefined one the braced arm is rejected and the elided arm is not,
	// which is a real asymmetry but a different one -- it would make this
	// row measure the dangling-reference check rather than the drop.
	{"routing-options forwarding-table",
		`policy-options { policy-statement ecmp-policy-7717 { then accept; } } routing-options { forwarding-table { export ecmp-policy-7717; } }`,
		`policy-options { policy-statement ecmp-policy-7717 { then accept; } } routing-options forwarding-table { export ecmp-policy-7717; }`,
		func(c *Config) string { return "fte=" + c.RoutingOptions.ForwardingTableExport }},
	// #8879 batch 5. TWO OF THESE FOUR WERE PUBLISHED AS BENIGN.
	//
	// `class-of-service fairness` and `security policy-stats` came out of
	// the sweep's SAME column, not its SILENT column — the instrument
	// reported "elided delivers what braced delivers" for both. That
	// verdict was true of the single leaf the instrument synthesised and
	// false of the pair. With a hand-written fixture `fairness` drops its
	// entire expectation list and `policy-stats` silently flips
	// PolicyStatsEnabled from true to FALSE, which turns a security
	// feature off without telling anyone.
	//
	// Kept here as provenance, because it is the part that generalises: a
	// per-pair verdict derived from one synthesised leaf is a claim about
	// that leaf, and a SAME verdict is the one place where being wrong is
	// invisible — nobody re-opens a row the instrument already cleared.
	{"class-of-service fairness",
		`class-of-service { fairness { rss-expectation { interface ge-0/0/1 { queue 3 { at-least-active-workers 4; } } } } }`,
		`class-of-service fairness { rss-expectation { interface ge-0/0/1 { queue 3 { at-least-active-workers 4; } } } }`,
		func(c *Config) string {
			return fmt.Sprintf("fair=%d", len(c.ClassOfService.FairnessExpectations))
		}},
	{"security policy-stats",
		`security { policy-stats { system-wide enable; } }`,
		`security policy-stats { system-wide enable; }`,
		func(c *Config) string {
			return fmt.Sprintf("stats=%v", c.Security.PolicyStatsEnabled)
		}},
	{"security ipsec",
		`security { ipsec { proposal ip1 { encryption-algorithm aes-256-gcm; } } }`,
		`security ipsec { proposal ip1 { encryption-algorithm aes-256-gcm; } }`,
		func(c *Config) string {
			return fmt.Sprintf("ipsecprop=%d", len(c.Security.IPsec.Proposals))
		}},
	// The braced arm needs probe-type AND target to pass STRICT commit.
	// A reference that fails strict compile would put this row in the
	// same unanswerable third state the batch-4 cell exists to resolve.
	{"services rpm",
		`services { rpm { probe pr1 { test t1 { probe-type icmp-ping; target address 198.51.100.9; probe-count 7; } } } }`,
		`services rpm { probe pr1 { test t1 { probe-type icmp-ping; target address 198.51.100.9; probe-count 7; } } }`,
		func(c *Config) string {
			if c.Services.RPM == nil {
				return "<nil>"
			}
			return fmt.Sprintf("rpm=%d", len(c.Services.RPM.Probes))
		}},
	// #8879 batch 4. Mode-spanning again — a pointer struct reached
	// through a keyed sub-map (`sampling`), a slice
	// (`router-advertisement`), a map (`snmp v3`), and a struct whose
	// every OTHER field is a default (`archival`).
	//
	// `system archival` is the reason the liveness check compares against
	// an empty config rather than against nil: TransferOnCommit,
	// ArchiveDir and MaxArchives all come back at their defaults here, so
	// only TransferInterval carries the fixture's signal. Reading the
	// whole struct and asking "is it non-empty" would have been satisfied
	// entirely by defaults.
	{"forwarding-options sampling",
		`forwarding-options { sampling { instance si1 { input { rate 7717; } } } }`,
		`forwarding-options sampling { instance si1 { input { rate 7717; } } }`,
		func(c *Config) string {
			if c.ForwardingOptions.Sampling == nil {
				return "<nil>"
			}
			return fmt.Sprintf("inst=%d", len(c.ForwardingOptions.Sampling.Instances))
		}},
	{"protocols router-advertisement",
		`protocols { router-advertisement { interface ge-0/0/7.0 { link-mtu 1444; } } }`,
		`protocols router-advertisement { interface ge-0/0/7.0 { link-mtu 1444; } }`,
		func(c *Config) string {
			return fmt.Sprintf("ra=%d", len(c.Protocols.RouterAdvertisement))
		}},
	{"snmp v3",
		`snmp { v3 { usm { local-engine { user u7717 { authentication-sha { authentication-password sekritpw; } } } } } }`,
		`snmp v3 { usm { local-engine { user u7717 { authentication-sha { authentication-password sekritpw; } } } } }`,
		func(c *Config) string {
			if c.System.SNMP == nil {
				return "<no-snmp>"
			}
			return fmt.Sprintf("v3users=%d", len(c.System.SNMP.V3Users))
		}},
	{"system archival",
		`system { archival { configuration { transfer-interval 77; } } }`,
		`system archival { configuration { transfer-interval 77; } }`,
		func(c *Config) string {
			if c.System.Archival == nil {
				return "<nil>"
			}
			return fmt.Sprintf("interval=%d", c.System.Archival.TransferInterval)
		}},
	// #8879 batch 3, chosen to SPAN MODES: four subsystems and four
	// different compiled shapes — a pointer struct (`isis`), a slice
	// (`generate`), a scalar string (`license`) and a struct-of-scalars
	// (`log`). Picking the top four rows of the sweep table would have
	// sampled one region of the schema; picking the four most
	// consequential would have sampled the regions with the MOST
	// downstream validators, which is bias toward being caught rather
	// than bias toward being representative.
	//
	// `security log` is the shape that most needs the empty-config
	// liveness check below: Security.Log is a VALUE, not a pointer, so
	// the elided arm yields a zero struct rather than nil and a
	// nil-check would have called that "no drop".
	{"protocols isis",
		`protocols { isis { net 49.0001.1921.6800.1001.00; } }`,
		`protocols isis { net 49.0001.1921.6800.1001.00; }`,
		func(c *Config) string {
			if c.Protocols.ISIS == nil {
				return "<nil>"
			}
			return "net=" + c.Protocols.ISIS.NET
		}},
	{"routing-options generate",
		`routing-options { generate { route 203.0.113.0/24 { discard; } } }`,
		`routing-options generate { route 203.0.113.0/24 { discard; } }`,
		func(c *Config) string {
			return fmt.Sprintf("gen=%d", len(c.RoutingOptions.GenerateRoutes))
		}},
	{"system license",
		`system { license { autoupdate { url https://lic.example.invalid/x; } } }`,
		`system license { autoupdate { url https://lic.example.invalid/x; } }`,
		func(c *Config) string { return "url=" + c.System.LicenseAutoUpdate }},
	{"security log",
		`security { log { mode event; format binary; } }`,
		`security log { mode event; format binary; }`,
		func(c *Config) string {
			return fmt.Sprintf("mode=%s/fmt=%s", c.Security.Log.Mode, c.Security.Log.Format)
		}},
	// #8879 batch 2. Values are chosen NOT to equal any compiled default:
	// a fixture whose value IS the fallback reads CLEAN WHILE BROKEN, because
	// losing the value and keeping it produce the same compiled result. That
	// trap is invisible in exactly the way a dead reference arm is, and the
	// braced arm is LIVE throughout it.
	{"security address-book",
		`security { address-book { global { address a1 203.0.113.0/24; } } }`,
		`security address-book { global { address a1 203.0.113.0/24; } }`,
		func(c *Config) string {
			if c.Security.AddressBook == nil {
				return "<nil>"
			}
			return fmt.Sprintf("addrs=%d", len(c.Security.AddressBook.Addresses))
		}},
	{"protocols ospf",
		`protocols { ospf { area 0.0.0.7 { interface ge-0/0/0.0 { metric 42; } } } }`,
		`protocols ospf { area 0.0.0.7 { interface ge-0/0/0.0 { metric 42; } } }`,
		func(c *Config) string {
			if c.Protocols.OSPF == nil {
				return "<nil>"
			}
			return fmt.Sprintf("areas=%d", len(c.Protocols.OSPF.Areas))
		}},
	{"chassis device-map",
		`chassis { device-map { interface ge-0/0/5 { pci 0000:07:00.3; } } }`,
		`chassis device-map { interface ge-0/0/5 { pci 0000:07:00.3; } }`,
		func(c *Config) string {
			if c.Chassis.DeviceMap == nil {
				return "<nil>"
			}
			return fmt.Sprintf("entries=%d", len(c.Chassis.DeviceMap.Entries))
		}},
	{"system ntp",
		`system { ntp { server 198.51.100.23; } }`,
		`system ntp { server 198.51.100.23; }`,
		func(c *Config) string { return fmt.Sprintf("servers=%d", len(c.System.NTPServers)) }},
	{"system syslog",
		`system { syslog { host 10.0.0.9 { any any; } } }`,
		`system syslog { host 10.0.0.9 { any any; } }`,
		func(c *Config) string {
			if c.System.Syslog == nil {
				return "<nil>"
			}
			return fmt.Sprintf("hosts=%d", len(c.System.Syslog.Hosts))
		}},
}

func TestAdmittedPairsCompileLikeBraced8879(t *testing.T) {
	for _, c := range admittedElisionCases8879 {
		t.Run(c.pair, func(t *testing.T) {
			read := func(txt string) string {
				tree, perrs := NewParser(txt).Parse()
				if len(perrs) > 0 {
					t.Fatalf("fixture must parse (%q): %v", txt, perrs[0])
				}
				cfg, err := CompileConfigLenient(tree)
				if cfg == nil {
					t.Fatalf("fixture must compile (%q): %v", txt, err)
				}
				return c.get(cfg)
			}
			// LIVENESS, fatal: the braced reference must DELIVER something, or
			// "elided == braced" is agreement between two empty results.
			// LIVENESS, fatal — this is a FIXTURE check, not a property
			// assertion, so a fatal is correct here: nothing below can mean
			// anything if the reference delivered nothing.
			//
			// Asserted against an EMPTY config rather than merely non-nil. A
			// fixture whose value equals the compiled DEFAULT is live, its
			// comparison is real, and the row still reads clean while broken —
			// losing the value produces the same result as keeping it. The
			// values above are chosen so that cannot happen.
			braced := read(c.braced)
			if braced == "<nil>" || braced == "" {
				t.Fatalf("braced reference delivered %q — the comparison below "+
					"would be vacuous", braced)
			}
			if empty, _ := CompileConfigLenient(&ConfigTree{}); empty != nil && c.get(empty) == braced {
				t.Fatalf("%s: the braced reference compiles to %q, which is what an "+
					"EMPTY config produces. Losing the value would give the same "+
					"answer as keeping it, so this row cannot detect the drop it "+
					"exists to detect — pick a value that is not the default.",
					c.pair, braced)
			}
			if elided := read(c.elided); elided != braced {
				t.Errorf("%s: elided compiles to %q but braced compiles to %q. "+
					"The pair is admitted to compactNormalizeInScope, so the two "+
					"spellings must agree; a difference means the fold no longer "+
					"reaches this pair (#8879).", c.pair, elided, braced)
			}
		})
	}
}

// THE NEGATIVE CONTROL, and it is what makes the admissions above a measurement
// rather than an assertion. A pair whose elided spelling is ALREADY REJECTED
// must stay unadmitted: admitting it would silence a signal the operator gets
// today. `system login` is the #6662 case #8868 established.
//
// This cell fails if someone admits it — including as part of a "sweep the
// remaining rows" batch, which is exactly how a loud rejection becomes quiet.
func TestRejectedPairStaysUnadmitted8879(t *testing.T) {
	// Errorf, not Fatalf: a fatal here would stop the property assertion below
	// from running at all, so a mutant admitting the pair would prove only that
	// THIS assertion fires and leave the other untested.
	if compactNormalizeInScope("system", "login") {
		t.Errorf("`system login` has been ADMITTED to compactNormalizeInScope. " +
			"Its elided spelling is REJECTED at strict commit today (#6662), so " +
			"admitting it converts a loud rejection into a silent acceptance — a " +
			"regression wearing the shape of a fix (#8868). Admit only pairs whose " +
			"elided spelling is measured SILENT.")
	}
	// And the property behind the flag, asserted as an ASYMMETRY rather than
	// as a bare refusal.
	//
	// This is #8879's NEGATIVE CONTROL: the row that shows the instrument is
	// not simply calling everything a silent drop. #8917 reclassified the
	// sweep's `system login` row to BOTH-ARMS-REJECTED, which reads as the
	// control having dissolved -- if the BRACED spelling is refused too, the
	// row demonstrates nothing about elision.
	//
	// It has not dissolved. That verdict is a statement about the SYNTHESIZED
	// leaf, not about the pair; it is the leaf-contingency lesson pointed in
	// the opposite direction from where this campaign has been applying it. A
	// reclassification to BOTH-ARMS-REJECTED is evidence the SWEEP cannot
	// tell, not evidence the asymmetry is absent. Asked with a hand-written
	// fixture the asymmetry is intact, and both halves are asserted here so
	// no future reader has to take the sweep's word either way.
	compiles := func(txt string) bool {
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse (%q): %v", txt, perrs[0])
		}
		_, err := CompileConfig(tree)
		return err == nil
	}
	const braced = `system { login { user u1 { class super-user; } } }`
	const elided = `system login { user u1 { class super-user; } }`

	// Half one, and the half the sweep row lost: the BRACED spelling is
	// ACCEPTED. Without this the refusal below is consistent with the stanza
	// being invalid for reasons that have nothing to do with elision.
	if !compiles(braced) {
		t.Error("the BRACED `system login` spelling is refused at strict commit. " +
			"This cell is #8879's negative control and it only controls anything " +
			"while the two spellings DIFFER -- if both are refused it demonstrates " +
			"nothing about elision, which is exactly the state #8917 found the " +
			"sweep's synthesized fixture to be in.")
	}
	// Half two: the ELIDED spelling is REFUSED.
	if compiles(elided) {
		t.Error("the elided `system login` spelling is no longer refused at strict " +
			"commit. If that rejection was removed deliberately this cell should " +
			"move; if not, the operator has lost a signal (#8868).")
	}
}

// TestAdmittedDropsAreReadSomewhere8879 re-derives #8879's headline ratio
// against the CURRENT population, because the issue body's ratio rests on an
// argument that has since been withdrawn.
//
// The body justified "at least 37 of 38" by pointing at `system login` and
// `interfaces xpfname` reading STRICT-REJECTS -- "the reason the other rows
// mean something". #8917 reclassified both (BOTH-ARMS-REJECTED and
// LEAF-CONTINGENT). One survives when re-asked with a hand-written fixture
// (see the negative control above); the other does not -- with a real leaf
// `interfaces <name>` accepts on BOTH arms, so it was never a control. A
// number whose stated control has moved needs re-deriving rather than
// re-quoting.
//
// WHAT THIS MEASURES, and its bound. A drop matters when something READS the
// value. The signal is the compiler's own accepted-but-inert advisories: a
// stanza that raises one is declaring the value has no runtime effect, so
// losing it costs the ADVISORY rather than behaviour.
//
// The bound runs one way and must be stated: absence of an advisory is weaker
// evidence than presence of one. A stanza that is inert and says nothing would
// be counted READ. The project enforces advisory-firing only for
// class-of-service (#6850), so outside CoS this is an UPPER bound on READ.
// Six of the READ rows were additionally confirmed by hand to have consumers
// outside pkg/config (PolicyStatsEnabled, Protocols.LLDP, UserspaceDataplane,
// FairnessExpectations, IPMonitoring, SSHKnownHosts -- reaching daemon,
// grpcapi, cli and the userspace dataplane).
func TestAdmittedDropsAreReadSomewhere8879(t *testing.T) {
	// Named rather than counted. A bare count is satisfied by any three rows
	// going inert, which would silently swap one finding for another; naming
	// them means a MEMBERSHIP change reds this cell even when the total holds.
	knownNotRead := map[string]string{
		"forwarding-options family":      "inet6 mode packet-based is accepted-only; the dataplane is flow-based",
		"flow aging":                     "pressure-based shedding is accepted-only; the AF_XDP dataplane ages on per-session idle timeout only",
		"pre-id-default-policy then":     "pre-id session logging is inert; no pre-identification admit path exists (the depth-2 pair, same advisory as the depth-1 one above)",
		"class-of-service rewrite-rules": "exp rewrite is inert; the dataplane rewrites dscp on egress only",
		"security pre-id-default-policy": "pre-id session logging is inert; no pre-identification admit path exists",
	}
	inertMarkers := []string{
		"inert", "no runtime effect", "no effect", "accepted-only",
		"accepted but", "accepted for compatibility", "runtime no-op",
		"not yet enforced",
	}

	read, notRead := 0, 0
	got := map[string]bool{}
	for _, c := range admittedElisionCases8879 {
		tree, perrs := NewParser(c.braced).Parse()
		if len(perrs) > 0 {
			t.Fatalf("%s: fixture must parse: %v", c.pair, perrs[0])
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("%s: braced fixture must compile: %v", c.pair, err)
		}
		inert := false
		for _, w := range cfg.Warnings {
			ws := strings.ToLower(w)
			for _, m := range inertMarkers {
				if strings.Contains(ws, m) {
					inert = true
					break
				}
			}
			if inert {
				break
			}
		}
		if inert {
			notRead++
			got[c.pair] = true
		} else {
			read++
		}
	}

	for pair := range got {
		if _, ok := knownNotRead[pair]; !ok {
			t.Errorf("%q now raises an accepted-but-inert advisory and was not "+
				"one of the three rows #8879's re-derived ratio is built on. "+
				"Either a stanza became inert or a new advisory changed what "+
				"this measures -- the ratio must be re-derived, not adjusted.", pair)
		}
	}
	for pair, why := range knownNotRead {
		if !got[pair] {
			t.Errorf("%q no longer raises an accepted-but-inert advisory (%s). "+
				"If the value became live, the drop it used to suffer is worse "+
				"than recorded and #8879's ratio moves in the WORSE direction.",
				pair, why)
		}
	}
	if total := read + notRead; total != len(admittedElisionCases8879) {
		t.Errorf("accounted %d of %d cases", total, len(admittedElisionCases8879))
	}
	t.Logf("#8879 re-derived: %d of %d adjudicated drops lose a value something "+
		"reads; %d lose only an advisory. Upper bound on READ -- see the doc "+
		"comment.", read, read+notRead, notRead)
}

// The tolerant ingress must accept everything it accepts today. It DOES
// schema-validate and downgrade to a warning, so the property is "no new
// REJECTION", not "no new validation".
func TestAdmissionsIntroduceNoNewRejection8879(t *testing.T) {
	for _, txt := range []string{
		`protocols bgp { local-as 65001; router-id 10.0.0.1; }`,
		`security ike { proposal pr { authentication-method pre-shared-keys; } }`,
		`security nat { source { pool P { address 10.0.0.1/32; } } }`,
		`system syslog { host 10.0.0.9 { any any; } }`,
	} {
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse (%q): %v", txt, perrs[0])
		}
		if cfg, err := CompileConfigLenient(tree); err != nil || cfg == nil {
			t.Errorf("the tolerant ingress must still accept %q: %v — a config "+
				"already on disk must keep loading (#1960 no-brick)", txt, err)
		}
	}
}

// TestInstanceNamePairCannotBeAdmitted8879 records the one DECLINE in #8879
// batch 3, and records it for the reason that is actually true.
//
// `interfaces <name>` appears in the sweep as a CANDIDATE-DROP whose elided
// arm STRICT-REJECTS, which reads like "declined because the drop is loud".
// It is not that. With a hand-written leaf (`unit 0 family inet address ...`)
// BOTH arms compile strictly clean and both yield one interface, so that
// row's gate verdict is a property of the single synthesized leaf the sweep
// happened to pick, not of the pair. A per-row verdict derived from one
// synthesized leaf does not generalise to the pair it names.
//
// The real reason this pair is declined is STRUCTURAL and holds for every
// leaf: compactNormalizeInScope is keyed on a (container, head) pair of
// literal keywords, and here the head is an INSTANCE NAME chosen by the
// operator. There is no string to admit. This is a permanent bound of the
// pair-keyed design, not a backlog item, and it is asserted rather than
// written down so that a future redesign which removes the bound also
// removes this cell.
func TestInstanceNamePairCannotBeAdmitted8879(t *testing.T) {
	// The bound: an instance-named head is not a fixed keyword, so no
	// admission list can name it. Two arbitrary interface names must be
	// treated identically by the predicate — if they ever differ, the
	// predicate has started keying on instance names and this whole cell,
	// plus the reasoning above, needs revisiting.
	// Two containers, not one: `interfaces <name>` and `routing-instances
	// <name>` are BOTH instance-named heads in the #8879 population, and a
	// bound demonstrated on a single container is a claim about that
	// container. Asserting both makes it a claim about the shape.
	for _, ct := range []struct{ container, n1, n2 string }{
		{"interfaces", "ge-0/0/0", "xe-7/1/3"},
		{"routing-instances", "vrf-blue", "vrf-green"},
	} {
		a := compactNormalizeInScope(ct.container, ct.n1)
		b := compactNormalizeInScope(ct.container, ct.n2)
		if a != b {
			t.Errorf("compactNormalizeInScope treats `%s %s` (%v) differently "+
				"from `%s %s` (%v). The predicate is keyed on literal keyword "+
				"pairs, so an instance-named head must be indistinguishable "+
				"from any other (#8879).", ct.container, ct.n1, a, ct.container, ct.n2, b)
		}
		if a {
			t.Errorf("`%s <name>` is reported IN SCOPE. An instance name "+
				"cannot be a literal admission key, so this can only mean the "+
				"predicate matched something it should not have (#8879).",
				ct.container)
		}
	}
	// And the property the sweep's verdict was mistaken about: with a real
	// leaf, the elided spelling is NOT refused. Asserting this keeps the
	// decline honest — if someone later reads the sweep row and concludes
	// "declined because loud", this cell contradicts them.
	txt := `interfaces ge-0/0/0 { unit 0 { family inet { address 10.9.9.1/24; } } }`
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("the elided `interfaces <name>` spelling is now refused at "+
			"strict commit (%v). If that is deliberate the decline reason in "+
			"this cell should move to the gate; as measured for #8879 it was "+
			"accepted, and the decline rests on the instance-name bound "+
			"instead.", err)
	}
}

// TestSweepUnanswerableRowIsNotADefect8879 adjudicates the #8879 population's
// one NO-REFERENCE row, `firewall three-color-policer <name>`.
//
// The sweep reports it as "braced form does not compile — fixture cannot
// answer", which is an honest THIRD STATE rather than a verdict: the
// instrument is saying it did not measure, not that there is nothing to
// measure. That distinction is easy to lose, and a row parked in it is
// indistinguishable from an adjudicated one on any count of remaining work.
//
// Re-asked with a hand-written fixture the row answers cleanly. The
// synthesized fixture failed a COMPILER VALIDATION, not the elision:
// `three-color-policer requires positive excess-burst-size`. Supply one and
// both spellings compile strictly clean AND produce byte-identical configs.
//
// The reason they agree is NOT that the pair is naturally equivalent. It is
// that `firewall three-color-policer` is ALREADY ADMITTED to
// compactNormalizeInScope — this is the FOLD DOING THE WORK, which is a
// different label from "no defect here" and must not be recorded as the
// latter. Verified two-sided on sibling pairs: removing the admission for
// `firewall policer` and `snmp community` makes their two spellings DIFFER,
// so agreement in this family is caused by the admission rather than by the
// shape.
//
// The pair therefore needs no NEW admission, which is why it is a decline —
// but a reader must not conclude the elision is harmless here. The assertion
// below pins the actual cause, so the reason cannot rot into the wrong one.
func TestSweepUnanswerableRowIsNotADefect8879(t *testing.T) {
	const body = `single-rate { committed-information-rate 40m; ` +
		`committed-burst-size 100k; excess-burst-size 200k; } ` +
		`then { loss-priority high; }`
	braced := "firewall { three-color-policer tcp1 { " + body + " } }"
	elided := "firewall three-color-policer tcp1 { " + body + " }"

	dig := func(txt string) string {
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs[0])
		}
		// LIVENESS, fatal: if the reference stops compiling, this cell has
		// fallen back into exactly the unanswerable state it exists to
		// resolve, and every comparison below would be vacuous.
		if _, err := CompileConfig(tr); err != nil {
			t.Fatalf("fixture no longer compiles at STRICT commit (%v). This "+
				"cell adjudicates a row the sweep could not answer because "+
				"its fixture did not compile; if this one stops compiling "+
				"too, the row is unadjudicated again rather than clean.", err)
		}
		c, err := CompileConfigLenient(tr)
		if err != nil || c == nil {
			t.Fatalf("lenient compile failed: %v", err)
		}
		c.Warnings = nil
		b, _ := json.Marshal(c)
		return string(b)
	}

	// The CAUSE, pinned. If this pair ever leaves the admission list, the
	// identity asserted below would break for a reason the comment above
	// would no longer explain.
	if !compactNormalizeInScope("firewall", "three-color-policer") {
		t.Errorf("`firewall three-color-policer` is no longer admitted to " +
			"compactNormalizeInScope. This cell records the pair as declined " +
			"BECAUSE the fold already handles it; with the admission gone " +
			"that reason is false and the row needs re-adjudicating rather " +
			"than staying declined (#8879).")
	}
	if len(dig(braced)) == 0 {
		t.Fatal("braced reference produced nothing to compare")
	}
	if got, want := dig(elided), dig(braced); got != want {
		t.Errorf("`firewall three-color-policer <name>` was adjudicated NOT A "+
			"DEFECT for #8879 on the strength of the two spellings compiling "+
			"IDENTICALLY, and they no longer do (%d vs %d bytes). Either a "+
			"real drop has appeared here, or the decline recorded in this "+
			"cell is now wrong -- it must not stay declined by inertia.",
			len(got), len(want))
	}
}

// TestElisionSuppressedAValidation8879 pins the most consequential thing found
// in the whole #8879 population: an elision that did not merely lose a value
// but SUPPRESSED THE COMMIT CHECK that would have reported the loss.
//
// `routing-options forwarding-table export <policy>` is validated at strict
// commit -- naming an undefined policy-statement is refused, and the error says
// why it matters ("the expected ECMP / consistent-hash load-balancing would be
// silently disabled"). Before this pair was admitted, the ELIDED spelling
// dropped the export leaf before that check ran, so:
//
//	braced, undefined policy   -> REJECTED at commit (correct)
//	elided, undefined policy   -> COMMITTED CLEAN     (fail-open)
//
// The operator who wrote the elided spelling got no value AND no complaint.
// That is the worst of the three shapes this issue found: a silent drop is bad,
// a silent drop that also disarms its own detector is worse, and it inverts the
// usual intuition that the stricter-looking spelling is the risky one.
//
// Measured two-sided when it was found: removing the admission restores the
// fail-open, so the admission is what closes it.
func TestElisionSuppressedAValidation8879(t *testing.T) {
	// TWO instances, not one. The first (`forwarding-table`) was found in
	// batch 6 and read as a curiosity; the second (`ip-monitoring`) turned up
	// in batch 9 the moment a fixture happened to name a probe that did not
	// exist. Two independent instances in the two batches that looked make
	// this a CLASS, and a table is the honest shape for a class -- a
	// single-case cell would keep reading as an oddity.
	//
	// The shape: a container whose child carries a CROSS-REFERENCE that strict
	// commit validates. Elide the container and the child is dropped BEFORE
	// the check runs, so a dangling reference commits clean:
	//
	//	braced, bad reference  ->  REJECTED at commit  (correct)
	//	elided, bad reference  ->  COMMITTED CLEAN     (fail-open)
	//
	// The operator gets no value AND no complaint, and it inverts the usual
	// intuition that the more explicit spelling is the risky one.
	//
	// A FAIL-OPEN CLAIM NEEDS THREE ROWS, NOT TWO, AND THE THIRD IS THE ONE
	// EVERYONE REACHES PAST:
	//
	//	braced, BAD  reference  ->  REJECTED   (the validator exists)
	//	elided, BAD  reference  ->  ACCEPTED   (the finding)
	//	braced, GOOD reference  ->  ACCEPTED   (the CONTROL)
	//
	// Without the control, "elided accepts" is equally consistent with the
	// validator never firing on that path AT ALL -- in which case there is no
	// fail-open, just a validator that does not apply. That is not
	// hypothetical: `class-of-service forwarding-classes` looked exactly like
	// a fourth instance until the no-definition control came back ACCEPTED
	// too, and it would have been filed wrong.
	//
	// The control is therefore a REQUIRED FIELD of the table below rather than
	// a note here, so a fourth row cannot be added without one. A rule that
	// lives only in a comment is a rule the next person reads after they have
	// already written the row.
	//
	// THE MECHANISM IS NARROWER THAN "ELISION SUPPRESSED A VALIDATION", and
	// the refinement is what makes the class screenable:
	//
	//	REFERENCE-side elision  -> FAILS OPEN. The elided container holds the
	//	                           statement that NAMES something; dropping it
	//	                           removes the reference before the check runs,
	//	                           so nothing is left to complain about.
	//	DEFINITION-side elision -> FAILS LOUD. The elided container holds the
	//	                           DEFINITION; dropping it makes a reference
	//	                           elsewhere dangle, and the check fires.
	//
	// All three rows here are reference-side. Screened the remaining #8943
	// population against it: of the 16 un-admitted rows only `flow-monitoring
	// version9` and `flow-monitoring version-ipfix` are named by any
	// cross-reference validator, both are DEFINITION-side, and both were
	// measured fail-loud (eliding the templates makes the flow-server's
	// reference dangle and strict commit refuses, matching the no-definition
	// control exactly). So this class is closed at three among that
	// population rather than needing 16 individual adjudications.
	//
	// A near-miss worth keeping: the first version of that screen elided
	// `(services, flow-monitoring)` -- a pair admitted in #8879 batch 9, which
	// folds correctly -- and produced an apparent FOURTH instance. Checking
	// WHICH PAIR the fixture actually elides is the same discipline that the
	// #8938 correction turned on.
	for _, c := range []struct{ pair, braced, elided, control, costs string }{
		{"routing-options forwarding-table",
			`routing-options { forwarding-table { export no-such-policy-7717; } }`,
			`routing-options forwarding-table { export no-such-policy-7717; }`,
			`policy-options { policy-statement ok-policy-7717 { then accept; } } ` +
				`routing-options { forwarding-table { export ok-policy-7717; } }`,
			"ECMP / consistent-hash load-balancing is silently disabled"},
		// THIRD instance (#8943). Same shape, security-relevant: a
		// destination-NAT rule naming a pool that does not exist.
		{"security nat destination",
			`security { nat { destination { rule-set rs1 { from zone untrust; rule r1 { ` +
				`match { destination-address 10.9.0.0/24; } then { destination-nat pool no-such-pool-7717; } } } } } }`,
			`security { nat destination { rule-set rs1 { from zone untrust; rule r1 { ` +
				`match { destination-address 10.9.0.0/24; } then { destination-nat pool no-such-pool-7717; } } } } }`,
			`security { nat { destination { pool ok-pool-7717 { address 10.9.0.9/32; } ` +
				`rule-set rs1 { from zone untrust; rule r1 { match { destination-address 10.9.0.0/24; } ` +
				`then { destination-nat pool ok-pool-7717; } } } } } }`,
			"destination NAT silently does not translate"},
		{"services ip-monitoring",
			`services { ip-monitoring { policy ipm1 { match { rpm-probe no-such-probe-7717; } ` +
				`then { preferred-route { route 203.0.113.0/24 { next-hop 198.51.100.1; } } } } } }`,
			`services ip-monitoring { policy ipm1 { match { rpm-probe no-such-probe-7717; } ` +
				`then { preferred-route { route 203.0.113.0/24 { next-hop 198.51.100.1; } } } } }`,
			`services { rpm { probe ok-probe-7717 { test t1 { probe-type icmp-ping; target address 198.51.100.9; } } } ` +
				`ip-monitoring { policy ipm1 { match { rpm-probe ok-probe-7717; } ` +
				`then { preferred-route { route 203.0.113.0/24 { next-hop 198.51.100.1; } } } } } }`,
			"probe-driven WAN failover silently never arms"},
	} {
		t.Run(c.pair, func(t *testing.T) {
			refused := func(txt string) bool {
				tree, perrs := NewParser(txt).Parse()
				if len(perrs) > 0 {
					t.Fatalf("fixture must parse: %v", perrs[0])
				}
				_, err := CompileConfig(tree)
				return err != nil
			}
			// THE CONTROL, first and fatal. If the validator does not ACCEPT a
			// GOOD reference, it is not discriminating on the reference at
			// all, and "elided accepts" below says nothing about elision.
			// This is the row that stops a non-finding being filed as one.
			if refused(c.control) {
				t.Fatalf("%s: the CONTROL (braced spelling, VALID reference) is "+
					"REFUSED. Then the validator is not discriminating on the "+
					"reference, and the fail-open assertion below would be "+
					"evidence about the fixture rather than about elision "+
					"(#8879).", c.pair)
			}
			// LIVENESS, fatal: if the braced arm stops being refused, the
			// check this row is about no longer exists and the assertion
			// below would pass for the wrong reason -- both arms accepting.
			if !refused(c.braced) {
				t.Fatalf("%s: the BRACED spelling with a bad cross-reference is "+
					"no longer refused at strict commit. This row asserts the "+
					"ELIDED spelling is refused too; with the check gone it "+
					"would pass vacuously.", c.pair)
			}
			if !refused(c.elided) {
				t.Errorf("%s: the ELIDED spelling with a bad cross-reference "+
					"COMMITS CLEAN. The elision drops the child before the "+
					"validation can see it, so the operator gets neither the "+
					"configuration nor the error -- %s (#8879).", c.pair, c.costs)
			}
		})
	}
}

// TestSystemServicesStaysUnadmitted8879 records the #8879 batch-6 DECLINE, and
// the way it was found matters more than the decline itself.
//
// `system services` measures like a textbook admission candidate: gate SILENT,
// zero warnings, both spellings accepted at strict commit, braced arm live
// against an empty config, elided arm dropping the whole stanza. Every column
// this issue adjudicates on said "admit it". It was admitted, and the FULL
// package suite -- not the scoped run, not the #8879 cells -- went red on
// TestPackedLoginBehindAnotherSystemStatementIsRejected_6966.
//
// The reason: with `system services` folded, `system services ssh login user
// alice class ops;` parses into the services container, `login` is not a child
// of `ssh`, and the stanza is dropped -- but strict commit now ACCEPTS it.
// That is #6966 re-opened: the CLI then runs with an empty class. Admitting
// this pair converts a loud rejection into a silent acceptance, which is the
// #8868 shape exactly, and no measurement taken on the pair ITSELF could have
// seen it because the damage is to a DIFFERENT statement that happens to pack
// behind it.
//
// The general lesson, worth more than this one pair: a pair's own before/after
// columns cannot see a regression in a sibling statement. Only the whole suite
// can, which is why #8879 batches gate on the full package rather than on the
// cells they add.
func TestSystemServicesStaysUnadmitted8879(t *testing.T) {
	// Errorf, not Fatalf: the property assertion below must still run so a
	// mutant admitting the pair is caught by both, not just by this one.
	if compactNormalizeInScope("system", "services") {
		t.Errorf("`system services` has been ADMITTED to " +
			"compactNormalizeInScope. It measures like a clean silent-drop " +
			"candidate, but folding it makes `system services ssh login user " +
			"<u> class <c>;` strict-ACCEPT while still dropping the login " +
			"stanza, re-opening #6966 (the CLI runs with an empty class). " +
			"Admitting it trades a loud rejection for a silent acceptance " +
			"(#8868).")
	}
	// The property behind the flag. Asserting the flag alone would pass if the
	// rejection moved somewhere else or disappeared entirely.
	txt := `system services ssh login user alice class ops;`
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("`system services ssh login user alice class ops;` is now " +
			"ACCEPTED at strict commit. The login stanza is not modelled " +
			"there, so it is dropped and the CLI runs with an empty class -- " +
			"the operator must be told, not silently obeyed (#6966/#8879).")
	}
}

// TestUnadmittedTopLevelPairsAreAdjudicated8925 is the instrument #8879's
// population lacked, and it exists because of how that population was built.
//
// `TestSweepFull` enumerates sites by RUNNING the brace-elision pass
// (`collectCompactSites`). A `(container, head)` pair the pass never asks
// about produces no site, so it appears in no inventory and no census — and
// its absence there is INDISTINGUISHABLE from having been adjudicated and
// cleared. Four live silent drops sat outside that population for the whole
// #8879 campaign for exactly that reason (#8925): `class-of-service
// forwarding-classes`, `policy-options as-path`, `services
// application-identification` and `system internet-options`, the third of
// which silently turned DPI application detection OFF.
//
// This walks `setSchema` DIRECTLY instead — the declared grammar rather than
// the pass's behaviour — and pins the top-level pairs that are NOT admitted.
// Every one must be here with a reason, so a newly-added or newly-un-admitted
// pair cannot slip in silently the way those four did.
//
// It covers TOP-LEVEL pairs. It ORIGINALLY justified stopping there by arguing
// that "a deeper pair is reachable only through a parent that is itself either
// admitted or listed here" — and THAT ARGUMENT WAS FALSE (#8929). Elision is a
// per-level decision: an admitted parent gets you to the child's brace, it does
// not fold the child's brace. `security nat source { ... }` dropped its whole
// body while `(security, nat)` was admitted, compiling to exactly what an empty
// config produces.
//
// The depth-2 population is ratcheted separately by
// TestDepth2UnadmittedPopulation8929. This cell keeps the top-level scope
// because that is where a whole STANZA vanishes — but the stated bound no
// longer does work it cannot support.
func TestUnadmittedTopLevelPairsAreAdjudicated8925(t *testing.T) {
	// Reasons are re-derived where they can be. `no-body` is checked against
	// the schema every run rather than trusted: a pair that GAINS children
	// becomes droppable, and that is precisely the transition that would
	// re-open this class.
	const (
		reasonNoBody = "no-body: the head declares no children, so there is no body to strand"
		reasonLoud   = "declined: the elided spelling is REFUSED at strict commit, so the drop is loud (#8868)"
		reasonSame   = "declined: measured SAME — the elided spelling delivers what the braced one does"
		reason6966   = "declined: folding it makes a packed `login` behind it strict-ACCEPT while dropped (#6966)"
	)
	want := map[string]string{
		"forwarding-options allow-dataplane-sleep": reasonNoBody,
		"system dataplane-type":                    reasonNoBody,
		"system host-name":                         reasonNoBody,
		"system no-redirects":                      reasonNoBody,
		"system processes":                         reasonNoBody,
		"system login":                             reasonLoud,
		"system services":                          reason6966,
		"chassis cluster":                          reasonSame,
		// #9416: `snmp client-list <name> { <prefix>; }` declares no schema
		// CHILDREN — its body is a run of free-form CIDR prefixes carried by
		// `multi: true`, not modelled keywords — so there is no body to strand
		// and this reason is re-derived from the schema on every run, not
		// trusted. The prefixes themselves are not lost when the outer brace is
		// elided: compileSNMP reads the `snmp` stanza's own packed tail via
		// packedBodyChildren, which is what keeps `snmp client-list` out of the
		// #2419 divergence inventory.
		"snmp client-list": reasonNoBody,
	}

	got := map[string]string{}
	for stanza, sn := range setSchema.children {
		if sn == nil {
			continue
		}
		for head, hn := range sn.children {
			if compactNormalizeInScope(stanza, head) {
				continue
			}
			pair := stanza + " " + head
			// RE-DERIVED, not registered: does this head declare a body at all?
			if hn == nil || (len(hn.children) == 0 && hn.wildcard == nil) {
				got[pair] = reasonNoBody
				continue
			}
			got[pair] = "" // has a body — must be registered with a real reason
		}
	}

	for pair, derived := range got {
		reg, ok := want[pair]
		if !ok {
			t.Errorf("`%s` is NOT admitted to compactNormalizeInScope and is not "+
				"registered here. If its head declares a body, eliding the stanza "+
				"can silently drop it — that is #8925, and four such pairs sat "+
				"outside #8879's population undetected because the sweep only "+
				"sees what the pass already visits. Measure it (braced vs elided, "+
				"gate column FIRST, braced arm live against an EMPTY config) and "+
				"either admit it or register the reason it is declined.", pair)
			continue
		}
		if derived == reasonNoBody && reg != reasonNoBody {
			t.Errorf("`%s` is registered as %q but its schema head declares NO "+
				"children — the registration and the schema disagree.", pair, reg)
		}
		if derived == "" && reg == reasonNoBody {
			t.Errorf("`%s` is registered as %q but its schema head now DECLARES "+
				"A BODY. A pair that gains children becomes droppable, which is "+
				"exactly the transition that re-opens #8925 — measure it and give "+
				"it a real reason.", pair, reg)
		}
	}
	for pair := range want {
		if _, ok := got[pair]; !ok {
			t.Errorf("`%s` is registered as un-admitted but is no longer in that "+
				"set — it was admitted, or the schema no longer declares it. This "+
				"list must not outlive its reason; remove the entry.", pair)
		}
	}
	t.Logf("#8925: %d top-level pairs un-admitted, all adjudicated", len(got))
}

// TestDepth2UnadmittedPopulation8929 ratchets the DEPTH-2 population and
// records the pairs measured to DROP.
//
// The population: pairs (mid, head) where head declares a body, (mid, head) is
// NOT admitted, and mid sits under an ADMITTED top-level parent. A spelling
// that elides HEAD's brace under MID can drop any of their bodies.
//
// THIS CELL PREVIOUSLY CARRIED A FALSE SAMPLE, and the correction is the point
// (#8938). It reported "1 of 6 drop-tested" and named five pairs as
// measured-SAME. Those fixtures elided the WRONG BRACE: for `(flow,
// tcp-session)` they compared
//
//	security { flow { tcp-session { ... } } }  vs  security flow { tcp-session { ... } }
//
// which elides `(security, flow)` — an ADMITTED pair that folds correctly —
// and leaves tcp-session's brace intact. Five of the six rows tested a pair
// that was never in the population, which is why only `nat source` (the one
// fixture built correctly) came back DROPS.
//
// Re-measured against the right spellings, the population is 26 DROPS / 20
// SAME / 4 unanswerable, not 1 of 6.
//
// THE SAME COLUMN BOUNDS NOTHING, and there is direct evidence rather than
// caution: `policy-statement then` reads SAME under the census instrument and
// is KNOWN BROKEN (#8933 — the compiler consumes the packed token into the
// terminal-action slot, so the term stops terminating). One synthesised body
// statement per pair inherits the leaf-contingency defect this campaign has
// now found in three separate instruments, two of them mine. So 26 is a LOWER
// BOUND and a SAME verdict here is not evidence of health.
func TestDepth2UnadmittedPopulation8929(t *testing.T) {
	// MEASURED TO DROP (#8938). Named rather than counted so that fixing one
	// reds this cell and forces its removal — a list that outlives its reason
	// is the failure this campaign keeps finding.
	knownDropping := []string{}
	// UNIT: PAIRS, not sites. #8929 first said 51 by counting a slice that
	// double-counted `family inet6`, which appears under two different
	// top-level stanzas. The predicate is keyed on (mid, head) and knows
	// nothing about the stanza, so the same pair reached by two routes is ONE
	// pair — counting sites where the population is pairs is the unit mismatch
	// this campaign already hit on the 320-sites / 95-pairs reconciliation.
	//
	// The corrected figure was 50 UN-ADMITTED pairs. It is 24 now because the
	// `nat` and `flow` families and the batch-of-13 were admitted since; the
	// population SHRINKS as pairs are admitted, which is the direction that
	// means progress. (#8942: this comment said "50 UNIQUE pairs" beside a
	// constant reading 24 — a stale claim sitting next to the measurement that
	// contradicted it.)
	const // #9017 grew this by ONE: `family any` is a third firewall filter
	// family, declared so `set firewall family any filter ... then discard`
	// stops committing clean and minting zero filters. The pair was MEASURED
	// before this constant moved, as the ratchet's own message demands --
	// braced vs the spelling that elides HEAD's brace under MID:
	//
	//	(family, inet)   braced 1+0   HEAD-elided 1+0   baseline 0+0
	//	(family, inet6)  braced 0+1   HEAD-elided 0+1   baseline 0+0
	//	(family, any)    braced 1+1   HEAD-elided 1+1   baseline 0+0
	//
	// It reads SAME, exactly like both siblings, so it does not drop and does
	// not belong in knownDropping.
	// #8928 admitted `ip-monitoring policy`, which leaves the depth-2
	// UN-admitted population: 25 -> 24. A shrink here is the intended
	// direction — the ratchet reds on it precisely so an admission cannot
	// pass unremarked. Re-derived at this base.
	//
	// #9416 grew it by ONE: `(community, routing-instance)`, the per-routing-
	// instance spelling of the SNMP source restriction. The pair was MEASURED
	// before this constant moved, as this ratchet's own message demands —
	// braced vs the spelling that elides HEAD's brace under MID (not the
	// parent's), against a baseline with no restriction at all:
	//
	//	                     Clients            AllowsSource(203.0.113.9)
	//	braced               [10.0.0.0/8]       false
	//	HEAD-elided          [10.0.0.0/8]       false
	//	baseline (no body)   []                 true
	//
	//	braced, named list   [10.0.0.0/8] L     false
	//	HEAD-elided, named   [10.0.0.0/8] L     false
	//
	// It reads SAME in both its spellings — compileSNMP resolves the instance
	// body through packedBodyChildren for exactly this reason — so it does not
	// drop and does not belong in knownDropping. The baseline row is what makes
	// the SAME verdict non-vacuous: without it, "both spellings agree" would
	// also be satisfied by both compiling to nothing.
	// #10078 models the four ALG protocol kinds (`dns`, `ftp`, `sip`, and
	// `tftp`) beneath the newly closed security arm. Each now declares a
	// `disable` child, so the depth-2 census correctly gains one un-admitted
	// pair per protocol. A direct non-vacuous probe measured baseline
	// `disable=false`, then `disable=true` for both fully-braced and
	// doubly-elided spellings of every protocol (the wider #8823 cell covers
	// the two intermediate spellings too). These pairs therefore read SAME,
	// not drops, and belong in the population lower bound.
	wantPopulation = 30

	parentAdmitted := func(mid string) bool {
		for stanza := range setSchema.children {
			if compactNormalizeInScope(stanza, mid) {
				return true
			}
		}
		return false
	}

	pop := map[string]bool{}
	for _, sn := range setSchema.children {
		if sn == nil {
			continue
		}
		for mid, mn := range sn.children {
			if mn == nil || !parentAdmitted(mid) {
				continue
			}
			for head, hn := range mn.children {
				if compactNormalizeInScope(mid, head) {
					continue
				}
				if hn == nil || (len(hn.children) == 0 && hn.wildcard == nil) {
					continue
				}
				pop[mid+" "+head] = true
			}
		}
	}

	if !compactNormalizeInScope("nat", "source") {
		t.Error("`nat source` is no longer admitted. It was the first member of " +
			"this population measured to DROP silently: doubly elided it " +
			"compiled to what an EMPTY config produces, losing the source NAT " +
			"pool entirely (#8929).")
	}
	// COUNT ASSERTED, because the membership check below is one-sided: it
	// catches an entry that should have been REMOVED and is blind to one that
	// was removed silently (a bad merge, a tidy-up). Measured: deleting an
	// entry left this cell green until this assertion was added.
	if len(knownDropping) != 0 {
		t.Errorf("knownDropping has %d entries, want 0. #8938 measured 26 of the "+
			"50 dropping; the `nat` and `flow` families went in with #8943 and "+
			"the remaining 13 landed after, so the list is now EMPTY and every "+
			"measured drop has been admitted. ADDING one is only correct if a "+
			"pair was measured to drop and NOT admitted — in which case the "+
			"membership check below must also see it in the population, so both "+
			"move together. A count change on its own means the record was "+
			"edited without a measurement. (#8942: this message read \"want "+
			"13\" while the assertion beside it required 0 — the message "+
			"documented a state the code had already left.)", len(knownDropping))
	}
	// Every known-dropping pair must still be IN the population. One leaving it
	// means it was admitted — good news that must be reflected here, because a
	// stale entry turns this list into a claim nobody re-checked.
	for _, p := range knownDropping {
		if !pop[p] {
			t.Errorf("`%s` is recorded as a measured DROP but is no longer in the "+
				"depth-2 un-admitted population — it was admitted or the schema "+
				"changed. Remove it from knownDropping; this list must not "+
				"outlive its reason (#8938).", p)
		}
	}
	// #9553's dedicated shape test measures the new pair's two spellings.
	if got := len(pop); got != wantPopulation {
		verb := "GREW"
		if got < wantPopulation {
			verb = "SHRANK"
		}
		t.Errorf("depth-2 un-admitted population %s: got %d PAIRS, want %d PAIRS "+
			"(unit: distinct (mid, head) pairs — NOT sites; one pair reached "+
			"under two stanzas is ONE).\n"+
			"GREW means a new depth-2 pair declares a body and is not admitted, "+
			"so a spelling eliding its brace can drop it — measure it (braced "+
			"vs the spelling that elides HEAD's brace under MID, not the "+
			"parent's) before moving this constant. SHRANK means something was "+
			"admitted: tighten it, and drop any knownDropping entry it "+
			"resolves (#8938).", verb, got, wantPopulation)
	}
	t.Logf("#8938: %d depth-2 un-admitted pairs; %d MEASURED TO DROP, the rest "+
		"read SAME under a one-leaf instrument that is known to produce false "+
		"SAMEs — a lower bound, not a census of health",
		len(pop), len(knownDropping))
}
