package config

import (
	"os"
	"strings"
	"testing"
)

// #7490 — the zone-level `dhcp` / `bootp` authorization is WITHHELD from a DHCP
// server/relay interface and RETAINED everywhere else.
//
// Every cell below names the input that makes it fire before it asserts
// anything, because the two halves of this feature fail in OPPOSITE directions
// and a fixture that does not distinguish them proves nothing:
//
//   - the withheld half fails OPEN (the flip did not happen, Junos parity gap
//     stays);
//   - the retained half fails CLOSED, and closed here means an interface loses
//     its ADDRESS. That is the failure option 1 was rejected for, so the client
//     and both-roles cells are the ones that keep this implementation honest.

// flip7490Cfg compiles a one-zone config through the REAL compiler, so the P5
// derivation hook is exercised rather than the stamp being called directly.
//
// That matters more than convenience: hostInboundDHCPRolesFor and
// ZoneLevelSystemServicesFor can both be correct while nothing calls
// stampZoneDHCPScopeWithheld, and a test that stamped its own fixture would
// stay green through exactly that deletion. Every cell here goes through
// CompileConfig.
func flip7490Cfg(t *testing.T, extra ...string) *Config {
	t.Helper()
	lines := append([]string{
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.5.1/24",
		"set interfaces ge-0/0/9 unit 0 family inet address 10.0.9.1/24",
	}, extra...)
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// zoneSvcFor is the EFFECTIVE system-services set for ref, through the shared
// production resolver — the same call the nft view builder, the Rust snapshot
// stamp and every diagnostic surface reach.
func zoneSvcFor(t *testing.T, cfg *Config, zone, ref string) []string {
	t.Helper()
	z := cfg.Security.Zones[zone]
	if z == nil {
		t.Fatalf("zone %q missing", zone)
	}
	svc, _, _ := z.InterfaceHostInboundEffective(ref)
	return svc
}

func hasTok(toks []string, want string) bool {
	for _, s := range toks {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}

// serverZone: `ge-0/0/5.0` is a dhcp-local-server group member. The zone level
// names dhcp. FIRES IF: the flip is absent — dhcp is still in the effective set.
func serverZone(t *testing.T) *Config {
	t.Helper()
	return flip7490Cfg(t,
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
}

func TestZoneLevelDHCPIsWithheldFromAServer7490(t *testing.T) {
	svc := zoneSvcFor(t, serverZone(t), "trust", "ge-0/0/5.0")
	if hasTok(svc, "dhcp") {
		t.Errorf("a dhcp-local-server member must NOT inherit `dhcp` from the zone level — "+
			"that is the case the vendor sentence covers and the whole point of #7490. "+
			"effective = %v", svc)
	}
	if !hasTok(svc, "ssh") {
		t.Errorf("the flip must withdraw ONLY the DHCP-exception tokens; ssh is configurable "+
			"per zone in Junos and must survive. effective = %v", svc)
	}
}

// THE OPTION-1 DISCRIMINATOR. `ge-0/0/9.0` runs the firewall's OWN DHCPv4
// client and no server. FIRES IF: the flip is applied to every role — which is
// option 1, the choice #7490 rejected — because this interface then loses
// udp/68, its unicast lease renewals, and with them its address.
//
// A fixture using a SERVER interface passes under both options and would prove
// nothing about which one was implemented.
func TestZoneLevelDHCPIsRetainedForAClient7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set interfaces ge-0/0/3 unit 0 family inet dhcp",
		"set security zones security-zone untrust interfaces ge-0/0/3.0",
		"set security zones security-zone untrust host-inbound-traffic system-services dhcp",
	)
	svc := zoneSvcFor(t, cfg, "untrust", "ge-0/0/3.0")
	if !hasTok(svc, "dhcp") {
		t.Errorf("an interface running the firewall's OWN DHCP client must KEEP the "+
			"zone-level `dhcp`: the vendor rule is about a SERVER knowing its incoming "+
			"interface and does not reach the client, and withdrawing it costs this "+
			"interface its ADDRESS, not merely a service (#7490 rejected option 1 for "+
			"exactly this). effective = %v", svc)
	}
}

// THE CONJUNCTION CELL. `ge-0/0/5.0` is BOTH a dhcp-relay member AND runs the
// firewall's own client. FIRES IF: the predicate is simplified from
// `server && !client` to `server` — which reads like a harmless tidy-up and
// takes the address from the one configuration the client carve-out exists to
// protect.
func TestZoneLevelDHCPIsRetainedForABothRolesInterface7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set interfaces ge-0/0/5 unit 0 family inet dhcp",
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set forwarding-options dhcp-relay server-group sg 192.0.2.1",
		"set forwarding-options dhcp-relay group r active-server-group sg",
		"set forwarding-options dhcp-relay group r interface ge-0/0/5.0",
	)
	z := cfg.Security.Zones["trust"]
	roles := hostInboundDHCPRolesFor(cfg, hostInboundDHCPServerRefs(cfg), "ge-0/0/5.0")
	if !roles.server || !roles.client {
		t.Fatalf("fixture does not put the interface in BOTH roles (server=%v client=%v); "+
			"without both, this cell cannot distinguish `server` from `server && !client`",
			roles.server, roles.client)
	}
	if z.WithholdsZoneLevelDHCPFor("ge-0/0/5.0") {
		t.Error("a both-roles interface must not be withheld from at all — the derived stamp " +
			"is what every plane reads, so a wrong answer here narrows all of them")
	}
	if svc := zoneSvcFor(t, cfg, "trust", "ge-0/0/5.0"); !hasTok(svc, "dhcp") {
		t.Errorf("an interface that is BOTH a relay member and the firewall's own client "+
			"must KEEP the zone-level `dhcp` — the client half is what holds up its "+
			"address. effective = %v", svc)
	}
}

// FIRES IF: the flip is widened to the idle role. #7490 ruled server/relay ONLY.
// Removing the token there is safe (it authorizes udp/67-68 for nothing), but
// withholding it is a behaviour change the ruling did not make, and the
// advisory tells the operator to remove it themselves.
func TestZoneLevelDHCPIsRetainedForAnIdleInterface7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set security zones security-zone trust interfaces ge-0/0/9.0",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
	)
	if svc := zoneSvcFor(t, cfg, "trust", "ge-0/0/9.0"); !hasTok(svc, "dhcp") {
		t.Errorf("#7490 ruled the flip applies to the SERVER/RELAY role only; an interface "+
			"running neither keeps the zone-level token. effective = %v", svc)
	}
}

// FIRES IF: the `all` branch is missing. A zone-level `all` expands to the
// named-service union, which CONTAINS dhcp and bootp, and every plane expands
// it at the admission predicate rather than in the list — so leaving `all`
// verbatim re-authorizes both tokens through the back door and the flip is
// half-done. This is the case #6519's advisory calls out for the warning path.
func TestZoneLevelAllIsFilteredOnAServer7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services all",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	svc := zoneSvcFor(t, cfg, "trust", "ge-0/0/5.0")
	if hasTok(svc, "all") {
		t.Errorf("a withheld interface cannot keep the `all` token: `all` stands for the "+
			"named-service union, which contains dhcp and bootp, and every plane expands "+
			"it at the admission predicate — so `all` would re-admit exactly what was "+
			"withheld. effective = %v", svc)
	}
	for _, tok := range []string{"dhcp", "bootp"} {
		if hasTok(svc, tok) {
			t.Errorf("`all` must be expanded WITHOUT %q on a withheld interface; effective = %v",
				tok, svc)
		}
	}
	// And the expansion must still admit everything else `all` covered, or the
	// filter is a silent deny-most rather than a two-token withdrawal.
	if !hasTok(svc, "ssh") || !hasTok(svc, "ping") {
		t.Errorf("the `all` expansion must retain every non-exception service; effective = %v", svc)
	}
}

// FIRES IF: only `dhcp` is filtered. `bootp` is the OTHER token in the vendor
// sentence and rides the same udp/67-68.
func TestBootpIsWithheldToo7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services bootp",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	if svc := zoneSvcFor(t, cfg, "trust", "ge-0/0/5.0"); hasTok(svc, "bootp") {
		t.Errorf("bootp is the second token the vendor sentence names and must be withheld "+
			"with dhcp. effective = %v", svc)
	}
}

// FIRES IF: `dhcpv6` is added to the exception list. The vendor sentence names
// DHCP and BOOTP; extending it to the v6 token would be inference presented as
// citation, and it would cost a DHCPv6 server udp/547.
func TestDHCPv6IsNotWithheld7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set security zones security-zone trust host-inbound-traffic system-services dhcpv6",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	svc := zoneSvcFor(t, cfg, "trust", "ge-0/0/5.0")
	if !hasTok(svc, "dhcpv6") {
		t.Errorf("dhcpv6 is deliberately outside the vendor sentence and must survive the "+
			"flip on a server interface. effective = %v", svc)
	}
	if hasTok(svc, "dhcp") {
		t.Errorf("dhcp must still be withheld alongside a retained dhcpv6; effective = %v", svc)
	}
}

// THE MIGRATION PATH. FIRES IF: the filter is applied to the INTERFACE level
// too — in which case the remedy the advisory prints does not work and the
// operator has no way to admit DHCP at all.
func TestInterfaceLevelDHCPStillAdmitsOnAServer7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set security zones security-zone trust interfaces ge-0/0/5.0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/5.0 host-inbound-traffic system-services dhcp",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	if svc := zoneSvcFor(t, cfg, "trust", "ge-0/0/5.0"); !hasTok(svc, "dhcp") {
		t.Errorf("the flip withdraws the ZONE-level authorization only. An interface-level "+
			"`dhcp` is the migration the advisory tells the operator to author, and if it "+
			"did not admit there would be no way to run a DHCP server at all. "+
			"effective = %v", svc)
	}
}

// FIRES IF: the filter is applied to the protocols list. The vendor exception
// is about two SYSTEM-SERVICES tokens; `protocols` has no dhcp token and a
// filter that touched the list at all would be reaching past its own rule.
func TestProtocolsAreUntouchedByTheFlip7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set security zones security-zone trust interfaces ge-0/0/5.0",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set security zones security-zone trust host-inbound-traffic protocols router-discovery",
		"set system services dhcp-local-server group lan interface ge-0/0/5.0",
	)
	_, proto, _ := cfg.Security.Zones["trust"].InterfaceHostInboundEffective("ge-0/0/5.0")
	if !hasTok(proto, "router-discovery") {
		t.Errorf("the flip must not touch the protocols list; got %v", proto)
	}
}

// FIRES IF: the stamp records only the ref the zone's Interfaces list spells.
// A zone member is routinely a bare physical (`reth1`) while the enforcement
// path resolves per unit (`reth1.0`), so a one-spelling map withholds on one
// plane and not the other — the silent half-flip.
func TestWithholdingCoversBothRefSpellings7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set interfaces ge-0/0/7 unit 0 family inet address 10.0.7.1/24",
		"set security zones security-zone trust interfaces ge-0/0/7",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set system services dhcp-local-server group lan interface ge-0/0/7.0",
	)
	z := cfg.Security.Zones["trust"]
	for _, ref := range []string{"ge-0/0/7", "ge-0/0/7.0"} {
		if !z.WithholdsZoneLevelDHCPFor(ref) {
			t.Errorf("the zone-level authorization must be withheld from %q; the zone names "+
				"the physical and enforcement resolves the unit, and disagreeing between "+
				"the two spellings flips one plane only", ref)
		}
		if svc, _, _ := z.InterfaceHostInboundEffective(ref); hasTok(svc, "dhcp") {
			t.Errorf("%s still inherits dhcp from the zone level: %v", ref, svc)
		}
	}
}

// FIRES IF: the lifeline skip is dropped. A lifeline is excluded from
// host-inbound deny scoping entirely, so filtering its list changes what the
// DIAGNOSTIC surfaces render without changing what is admitted — inventing a
// divergence rather than closing one.
func TestLifelineIsNotWithheld7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set interfaces fxp0 unit 0 family inet address 10.1.1.1/24",
		"set security zones security-zone mgmt interfaces fxp0.0",
		"set security zones security-zone mgmt host-inbound-traffic system-services dhcp",
		"set system services dhcp-local-server group m interface fxp0.0",
	)
	if cfg.Security.Zones["mgmt"].WithholdsZoneLevelDHCPFor("fxp0.0") {
		t.Error("a lifeline must never be withheld from: it is exempt from host-inbound " +
			"deny scoping, so the filter could only move the diagnostic away from " +
			"enforcement")
	}
}

// THE UPGRADE NOTICE. FIRES IF: the advisory reads the EFFECTIVE set again —
// in which case it goes silent on exactly the interfaces the flip just
// narrowed, and an operator whose DHCP server stopped receiving DISCOVER is
// told nothing at all.
func TestAdvisoryKeepsFiringOnAWithheldInterface7490(t *testing.T) {
	got := validateHostInboundZoneLevelDHCPWarnings(serverZone(t))
	if len(got) != 1 {
		t.Fatalf("want exactly one advisory for a withheld server interface, got %d: %v",
			len(got), got)
	}
	for _, want := range []string{"NO LONGER authorizes", "ge-0/0/5.0 (DHCP server)", "#7490", "#8060"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the withheld advisory must contain %q so the operator knows the "+
				"authorization moved AND what the measured mechanism actually is. got: %s",
				want, got[0])
		}
	}
	if strings.Contains(got[0], "still authorizes") {
		t.Errorf("a withheld interface must not be described as still authorized: %s", got[0])
	}
	// THE FALSE-MECHANISM GUARD. #8060 measured that a DHCPv4 server's
	// DISCOVER/REQUEST never went through this token — Kea receives on an
	// AF_PACKET socket ahead of netfilter and the XDP shim passes the broadcast
	// to the kernel — and was filed to delete exactly that claim from this
	// project's own reference config. An advisory that re-asserted it would put
	// the deleted sentence in front of every operator instead of one config.
	//
	// Keyed on the CLAIM, not on the word: "DENIED" alone would be defeated by
	// any paraphrase, so this asserts the two nouns the false mechanism needs.
	low := strings.ToLower(got[0])
	if strings.Contains(low, "discover") && strings.Contains(low, "denied") {
		t.Errorf("the advisory must not tell an operator that client DISCOVER is denied — "+
			"#8060 measured that DISCOVER bypasses host-inbound entirely, and that "+
			"sentence is the defect it was filed to remove: %s", got[0])
	}
}

// And the mirror: a RETAINED interface must be described as a live deviation,
// in the words #7490 requires, not as a narrowing that already happened.
func TestAdvisoryDescribesARetainedInterfaceAsADeviation7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set interfaces ge-0/0/3 unit 0 family inet dhcp",
		"set security zones security-zone untrust interfaces ge-0/0/3.0",
		"set security zones security-zone untrust host-inbound-traffic system-services dhcp",
	)
	got := validateHostInboundZoneLevelDHCPWarnings(cfg)
	if len(got) != 1 {
		t.Fatalf("want one advisory, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "still authorizes") ||
		!strings.Contains(got[0], "xpf deviation from Junos, not Junos behaviour") {
		t.Errorf("a retained interface must be named as a LIVE xpf deviation in those words, "+
			"so an operator does not carry it away as vendor behaviour: %s", got[0])
	}
	if strings.Contains(got[0], "NO LONGER authorizes") {
		t.Errorf("a retained interface must not draw the upgrade notice: %s", got[0])
	}
}

// TestShippedConfigsMigratedAndBehaviourPreserved7490 walks the five configs
// #7490 names and asserts BOTH halves of the migration at once.
//
// This is the cell that protects the HA smoke. Two of these files are what
// `make test-failover` deploys, and the `lan` zone's reth1 runs the
// dhcp-local-server the cluster LAN host gets its lease from. A migration that
// dropped a token would not fail any unit test — it would fail on hardware,
// as a LAN host with no address.
//
// Both arms are needed and they catch opposite mistakes:
//
//   - "still admits" catches a migration that dropped a token. Note #6515: the
//     interface stanza REPLACES the zone stanza, so every token has to be
//     restated, and forgetting one is the easy error.
//   - "no advisory" catches a migration that was not done at all — the flip
//     would then have silently withdrawn dhcp from reth1 and the DHCP server
//     would stop answering.
func TestShippedConfigsMigratedAndBehaviourPreserved7490(t *testing.T) {
	// The pre-migration effective set for reth1, written as a literal because
	// the point is that the migration did not change it. Deriving it from the
	// file under test would compare the file with itself.
	wantSvc := []string{"ssh", "ping", "dhcp", "dhcpv6"}
	wantProto := []string{"router-discovery"}

	for _, path := range []string{
		"../../test/incus/xpf-cluster-fw0.conf",
		"../../test/incus/xpf-cluster-fw1.conf",
		"../../docs/ha-cluster.conf",
		"../../docs/ha-cluster-loss.conf",
		"../../docs/ha-cluster-userspace.conf",
	} {
		t.Run(path, func(t *testing.T) {
			cfg := compileConfFile7490(t, path)
			zone := cfg.Security.Zones["lan"]
			if zone == nil {
				t.Fatalf("%s has no `lan` zone; the fixture this test walks has moved", path)
			}
			svc, proto, overridden := zone.InterfaceHostInboundEffective("reth1")
			if !overridden {
				t.Fatalf("reth1 must declare an interface-level host-inbound stanza after the "+
					"#7490 migration — without one the flip withdraws `dhcp` and the "+
					"dhcp-local-server stops receiving DISCOVER. effective = %v", svc)
			}
			for _, tok := range wantSvc {
				if !hasTok(svc, tok) {
					t.Errorf("reth1 lost system-service %q in the migration. A per-interface "+
						"stanza REPLACES the zone stanza (#6515), so every zone token has to "+
						"be restated. effective = %v", tok, svc)
				}
			}
			for _, tok := range wantProto {
				if !hasTok(proto, tok) {
					t.Errorf("reth1 lost protocol %q in the migration. effective = %v", tok, proto)
				}
			}
			if got := validateHostInboundZoneLevelDHCPWarnings(cfg); len(got) != 0 {
				t.Errorf("a migrated config must draw no #6519/#7490 zone-level DHCP "+
					"advisory; got: %v", got)
			}
		})
	}
}

func compileConfFile7490(t *testing.T, path string) *Config {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	cfg, err := CompileConfig(goldenParseHier(t, string(b)))
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return cfg
}

// TestSiblingUnitIsNotWithheldFromByItsPhysical7490 pins the exact over-match
// hostInboundSameInterface exists to prevent, one level up.
//
// The zone names the BARE PHYSICAL `ge-0/0/7`, and `ge-0/0/7.0` runs the DHCP
// server. `ge-0/0/7.50` is a sibling unit with no DHCP role at all. The role
// classifier already refuses to treat two distinct units as the same interface
// — "basing both sides on the physical would leak a sibling unit's DHCP role
// onto an interface that has none" — and this asserts the withholding lookup
// does not reintroduce that leak by falling back to the physical.
//
// Found by mutation: deleting a physical-parent fallback from
// WithholdsZoneLevelDHCPFor changed NO test outcome, because the stamp already
// records every spelling it should. Probing why showed the fallback was not
// merely redundant — it withheld from sibling units too, which would deny DHCP
// on an unrelated VLAN unit. The fallback is gone and this is the cell that
// keeps it gone.
func TestSiblingUnitIsNotWithheldFromByItsPhysical7490(t *testing.T) {
	cfg := flip7490Cfg(t,
		"set interfaces ge-0/0/7 unit 0 family inet address 10.0.7.1/24",
		"set interfaces ge-0/0/7 unit 50 vlan-id 50",
		"set interfaces ge-0/0/7 unit 50 family inet address 10.0.57.1/24",
		"set security zones security-zone trust interfaces ge-0/0/7",
		"set security zones security-zone trust host-inbound-traffic system-services dhcp",
		"set system services dhcp-local-server group lan interface ge-0/0/7.0",
	)
	z := cfg.Security.Zones["trust"]
	if !z.WithholdsZoneLevelDHCPFor("ge-0/0/7.0") {
		t.Fatal("fixture precondition: the SERVER unit must be withheld from, or this cell " +
			"cannot distinguish a correct answer from a blanket no")
	}
	if z.WithholdsZoneLevelDHCPFor("ge-0/0/7.50") {
		t.Error("a sibling unit with no DHCP role must NOT be withheld from because its " +
			"PHYSICAL parent hosts a server on a different unit — that is the leak " +
			"hostInboundSameInterface refuses at the role level, and it would deny DHCP " +
			"on an unrelated VLAN unit")
	}
	if svc, _, _ := z.InterfaceHostInboundEffective("ge-0/0/7.50"); !hasTok(svc, "dhcp") {
		t.Errorf("the sibling unit must keep the zone-level dhcp: %v", svc)
	}
}
