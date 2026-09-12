package daemon

import (
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/policymatch"
)

// junosHostDenyTestConfig builds a config with an `untrust` ingress zone (netdev
// ge-0-0-1) that coarse-admits ssh, plus a static address book, so #4146
// `to-zone junos-host` DENY projection + kernel nft emission can be exercised
// end to end without a live dataplane. Callers append the policy set.
func junosHostDenyTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.2.10/24"}},
		}},
		// fxp0 is a lifeline — a junos-host deny must NEVER scope to it.
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.10/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"ge-0/0/1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		"mgmt": {
			Name:               "mgmt",
			Interfaces:         []string{"fxp0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}},
		},
	}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"bad-host":  {Name: "bad-host", Value: "10.0.0.5/32"},
			"good-host": {Name: "good-host", Value: "10.0.0.6/32"},
			"bad-net":   {Name: "bad-net", Value: "10.0.0.0/8"},
		},
	}
	return cfg
}

func zonePairDeny(from, name string, matches ...string) []*config.Policy {
	return []*config.Policy{denyPolicy(name, matches...)}
}

func denyPolicy(name string, matches ...string) *config.Policy {
	p := &config.Policy{Name: name, Action: config.PolicyDeny}
	applyMatches(&p.Match, matches...)
	return p
}

func permitPolicy(name string, matches ...string) *config.Policy {
	p := &config.Policy{Name: name, Action: config.PolicyPermit}
	applyMatches(&p.Match, matches...)
	return p
}

// applyMatches is a tiny DSL: "src:bad-host", "srcx:bad-net" (excluded),
// "dst:wan-ip", "dstx:wan-ip" (destination-address-excluded), "app:junos-ssh",
// "app:any".
func applyMatches(m *config.PolicyMatch, matches ...string) {
	for _, spec := range matches {
		kind, val, _ := strings.Cut(spec, ":")
		switch kind {
		case "src":
			m.SourceAddresses = append(m.SourceAddresses, val)
		case "srcx":
			m.SourceAddresses = append(m.SourceAddresses, val)
			m.SourceAddressExcluded = true
		case "dst":
			m.DestinationAddresses = append(m.DestinationAddresses, val)
		case "dstx":
			m.DestinationAddresses = append(m.DestinationAddresses, val)
			m.DestinationAddressExcluded = true
		case "app":
			m.Applications = append(m.Applications, val)
		}
	}
}

func junosHostPayload(t *testing.T, cfg *config.Config) (string, []dpuserspace.JunosHostProgram) {
	t.Helper()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	programs := dpuserspace.BuildJunosHostPrograms(cfg)
	return buildHostInboundFilterPayload(views, nil, nil, programs, nil), programs
}

// junosHostSection returns the payload lines from the junos-host window of the
// INPUT chain — everything between the reply-direction established accept and
// the ND accepts. Since #9504 that window holds the exemption shields and the
// iifname-scoped jump; the zone's rules live in its subchain
// (junosHostChainLines).
func junosHostSection(payload string) []string {
	lines := strings.Split(payload, "\n")
	var out []string
	in := false
	for _, l := range lines {
		if strings.Contains(l, "ct direction reply accept") {
			in = true
			continue
		}
		if in && strings.Contains(l, "icmpv6 type { 1, 2, 3, 4 }") {
			break
		}
		if in {
			out = append(out, l)
		}
	}
	return out
}

// junosHostChainLines returns the rule lines inside the rendered junos-host
// subchains (#9504): everything between a `chain junos_host_...` header and its
// closing brace. A zone's projected rules moved there when the program became a
// first-match chain the input chain jumps to.
func junosHostChainLines(payload string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(payload, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "chain junos_host_"):
			in = true
		case in && t == "}":
			in = false
		case in:
			out = append(out, l)
		}
	}
	return out
}

// TestJunosHostDenyRendersDropScopedByIifname is the core #4146 enforcement
// guard: a representable `to-zone junos-host` DENY renders an iifname-scoped
// jump into the zone's subchain, whose silent DROP (no fine accept) carries the
// authored source, placed in coarse-then-fine order and NOT scoped by
// destination address.
func TestJunosHostDenyRendersDropScopedByIifname(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
	}
	payload, programs := junosHostPayload(t, cfg)

	if len(programs) != 1 {
		t.Fatalf("want 1 junos-host program, got %d: %+v", len(programs), programs)
	}
	p := programs[0]
	if p.Zone != "untrust" {
		t.Fatalf("program zone = %q, want untrust", p.Zone)
	}
	if got := strings.Join(p.IngressIfnames, ","); got != "ge-0-0-1" {
		t.Fatalf("IngressIfnames = %q, want ge-0-0-1 (lifeline fxp0 excluded, iifname not daddr)", got)
	}

	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	// #9504: the ZONE scope is the jump's iifname; the rule itself carries only
	// the authored match, inside the zone's subchain.
	wantJump := `iifname "ge-0-0-1" jump ` + xnft.HostInboundJunosHostChainName(0, "untrust")
	if !strings.Contains(payload, wantJump) {
		t.Fatalf("payload missing the iifname-scoped jump %q:\n%s", wantJump, payload)
	}
	wantDrop := `meta nfproto ipv4 ip saddr 10.0.0.5/32 counter name "` + cn + `" drop`
	if !strings.Contains(payload, wantDrop) {
		t.Fatalf("payload missing the junos-host drop %q:\n%s", wantDrop, payload)
	}
	// The counter must be DECLARED (unquoted) so nft never references an
	// undeclared object.
	if !strings.Contains(payload, "counter "+cn+" {") {
		t.Fatalf("payload missing junos-host counter declaration for %q:\n%s", cn, payload)
	}
	// The ZONE scope is `iifname`, never `daddr` (a daddr-only zone scope both
	// under- and over-denies across zones — plan §3.2). This policy matches
	// `destination-address any`, so no daddr predicate may appear at all. (An
	// EXPLICIT `match destination-address` does render a narrowing daddr — see
	// host_inbound_junos_host_dst_4146_test.go — but it is always ON TOP of the
	// iifname scope, never a replacement for it.)
	sec := append(junosHostSection(payload), junosHostChainLines(payload)...)
	for _, l := range sec {
		if strings.Contains(l, "daddr") {
			t.Errorf("junos-host section must not scope by daddr: %q", l)
		}
		// DROP-only: no fine accept in the junos-host section (except the reply
		// established already excluded and the exemption shields, which this test
		// has none of).
		if strings.Contains(l, "drop") && strings.Contains(l, "accept") {
			t.Errorf("junos-host drop line must not carry accept: %q", l)
		}
	}

	// Coarse-then-fine ordering: ESP/AH accept, then reply-established, then the
	// fine DROP, then the ND accepts, then the residual established accept and
	// the coarse per-zone ssh accept.
	assertOrder(t, payload,
		"meta l4proto { 50, 51 } accept",
		"ct state established,related ct direction reply accept",
		wantJump,
		"icmpv6 type { 1, 2, 3, 4 }",
		"ct state established,related accept",
		"tcp dport 22 accept",
	)
}

// TestJunosHostPermitRendersAReturnAheadOfTheDeny9504 proves an earlier permit
// carves a later deny by RETURNING from the zone's subchain ahead of it, in
// first-match order, and NEVER emits a fine accept (the coarse gate stays the
// sole admit authority). Before #9504 the carve was a `saddr !=` subtraction on
// the deny, which could not express a permit narrowed on any other dimension.
func TestJunosHostPermitRendersAReturnAheadOfTheDeny9504(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("allow-good", "src:good-host", "app:any"),
			denyPolicy("block-net", "src:bad-net", "app:any"),
		}},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d", len(programs))
	}
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	wantReturn := `meta nfproto ipv4 ip saddr 10.0.0.6/32 return`
	wantDrop := `meta nfproto ipv4 ip saddr 10.0.0.0/8 counter name "` + cn + `" drop`
	assertOrder(t, payload, wantReturn, wantDrop)
	// No fine accept anywhere in the zone's subchain (a permit returns to the
	// coarse gate; it must never re-admit anything itself).
	for _, l := range junosHostChainLines(payload) {
		if strings.Contains(l, "accept") {
			t.Errorf("permit must not emit a fine accept in the junos-host subchain: %q", l)
		}
	}
}

// TestJunosHostDenyIKEExemption proves the fine-eligible-L4 domain: an
// `application any` deny in an ike-admitting zone emits the IKE 500/4500
// exemption shield ahead of the drop (so coarse-admitted IKE survives).
func TestJunosHostDenyIKEExemption(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ike"}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 || !programs[0].CoarseAdmitsIKE {
		t.Fatalf("expected 1 program with CoarseAdmitsIKE, got %+v", programs)
	}
	shield := `iifname "ge-0-0-1" udp dport { 500, 4500 } accept`
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	// The shield must precede the JUMP: once the packet is in the subchain the
	// drop is unconditional for that source, so a shield after it never runs.
	assertOrder(t, payload, shield, `iifname "ge-0-0-1" jump `+xnft.HostInboundJunosHostChainName(0, "untrust"))
	drop := `meta nfproto ipv4 ip saddr 10.0.0.5/32 counter name "` + cn + `" drop`
	if !strings.Contains(payload, drop) {
		t.Fatalf("payload missing the junos-host drop %q:\n%s", drop, payload)
	}
}

// TestJunosHostDenyAppScopedToExemptTupleWarns: a deny explicitly scoped to an
// IKE application is un-representable (the IPsec path owns it) so it emits NO
// kernel rule.
func TestJunosHostDenyAppScopedToExemptTupleUnrepresentable(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Applications.Applications = map[string]*config.Application{
		"my-ike": {Name: "my-ike", Protocol: "udp", DestinationPort: "500"},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-ike", "src:bad-host", "app:my-ike")},
	}
	_, programs := junosHostPayload(t, cfg)
	if len(programs) != 0 {
		t.Fatalf("a deny scoped to an IKE tuple must be un-representable (no program), got %+v", programs)
	}
}

// TestJunosHostAnyExcludedEmitsNoDropLine is the #5828 projection-to-nft
// fail-on-revert guard: `match source-address any` + `source-address-excluded`
// + `then deny` is an EMPTY source match ("every source except every source"),
// so it must render NO junos-host drop line for either family. The pre-fix
// projection mis-classified `any`'s empty concrete set as `SrcAny` and emitted
// an UNCONDITIONAL, source-predicate-less drop
// (`iifname "ge-0-0-1" counter name "<cn>" drop`) — an over-deny that locks out
// all direct host-bound traffic on the ingress zone.
//
// RED on revert: restoring the `len(src)==0 => SrcAny` behavior emits the
// unconditional drop for both families, so the `counter name "<cn>" drop`
// substring reappears and these assertions fail.
func TestJunosHostAnyExcludedEmitsNoDropLine(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-all", "srcx:any", "app:any")},
	}
	payload, programs := junosHostPayload(t, cfg)
	// The term is inert: it projects zero rules, so BuildJunosHostPrograms
	// filters the (representable) program out entirely — no kernel program, no
	// drop line. On revert the any+excluded term emits an unconditional
	// all-source drop for both families, so a program with rules reappears.
	if len(programs) != 0 {
		t.Fatalf("any+excluded must yield no junos-host program (inert term), got %d: %+v", len(programs), programs)
	}
	for _, fam := range []string{"ip", "ip6"} {
		cn := xnft.HostInboundJunosHostDenyCounterName("untrust", fam)
		if strings.Contains(payload, `counter name "`+cn+`" drop`) {
			t.Errorf("junos-host %s drop line emitted for any+excluded (the #5828 over-deny); counter %q:\n%s", fam, cn, payload)
		}
	}
	// No junos-host drop line at all in the section window (xpfjh_ tags every
	// junos-host named counter).
	for _, l := range junosHostChainLines(payload) {
		if strings.Contains(l, "drop") && strings.Contains(l, "xpfjh_") {
			t.Errorf("unexpected junos-host drop line for an inert any+excluded term: %q", l)
		}
	}
}

// TestJunosHostSubchainRulesCarryTheirFamily9504 pins the guard that makes
// first-match order safe across families.
//
// A rule with no address predicate — an `application any` deny, or a permit
// narrowed only on application — carries no family of its own. Without a
// `meta nfproto` guard an IPv4 rule would also match an IPv6 packet, and that is
// not cosmetic here: the v4 list is emitted before the v6 list, so a v6 packet
// could meet a LATER term's v4 rule before its own term's v6 rule, and be dropped
// by a deny that its own permit precedes. Under the pre-#9504 DROP-only model
// every rule was a drop, so family bleed changed no verdict and no cell covered
// it.
func TestJunosHostSubchainRulesCarryTheirFamily9504(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("allow-good", "src:good-host", "app:any"),
			denyPolicy("block-all", "src:any", "app:any"),
		}},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %+v", programs)
	}
	lines := junosHostChainLines(payload)
	if len(lines) == 0 {
		t.Fatal("no subchain rules rendered, so this cell checks nothing")
	}
	for _, l := range lines {
		if !strings.Contains(l, "meta nfproto ipv4") && !strings.Contains(l, "meta nfproto ipv6") {
			t.Errorf("subchain rule carries no family guard, so it can match the other "+
				"family ahead of that family's own earlier term: %q", l)
		}
	}
}

// TestJunosHostVerdictsRenderAsTheRuntimeAnswers9504 pins the two verdicts #9504
// added to the kernel path, in the text the daemon installs.
//
// Both split TCP from everything else, because the runtime does: a `reject`
// answers TCP with a RST and every other protocol with an ICMP administratively
// prohibited, and a deny on a `tcp-rst` zone answers TCP with a RST and drops the
// rest silently (enqueue_deny_reply, reject_reply.rs). Rendering either as a
// plain drop would be invisible to a rule-count assertion and wrong on the wire.
func TestJunosHostVerdictsRenderAsTheRuntimeAnswers9504(t *testing.T) {
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	for _, tc := range []struct {
		name  string
		build func() *config.Config
		want  []string
	}{
		{
			name: "then reject",
			build: func() *config.Config {
				cfg := junosHostDenyTestConfig()
				p := &config.Policy{Name: "rej", Action: config.PolicyReject}
				applyMatches(&p.Match, "src:bad-host", "app:any")
				cfg.Security.Policies = []*config.ZonePairPolicies{
					{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{p}},
				}
				return cfg
			},
			want: []string{
				`meta nfproto ipv4 meta l4proto tcp ip saddr 10.0.0.5/32 counter name "` + cn + `" reject with tcp reset`,
				`meta nfproto ipv4 ip saddr 10.0.0.5/32 counter name "` + cn + `" reject with icmpx type admin-prohibited`,
			},
		},
		{
			name: "deny on a tcp-rst ingress zone",
			build: func() *config.Config {
				cfg := junosHostDenyTestConfig()
				cfg.Security.Zones["untrust"].TCPRst = true
				cfg.Security.Policies = []*config.ZonePairPolicies{
					{FromZone: "untrust", ToZone: "junos-host",
						Policies: zonePairDeny("untrust", "blk", "src:bad-host", "app:any")},
				}
				return cfg
			},
			want: []string{
				`meta nfproto ipv4 meta l4proto tcp ip saddr 10.0.0.5/32 counter name "` + cn + `" reject with tcp reset`,
				`meta nfproto ipv4 ip saddr 10.0.0.5/32 counter name "` + cn + `" drop`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, programs := junosHostPayload(t, tc.build())
			if len(programs) != 1 {
				t.Fatalf("want 1 program, got %+v", programs)
			}
			// Ordered: the TCP answer must precede the catch-all, or TCP never
			// reaches it.
			assertOrder(t, payload, tc.want...)
		})
	}
}

// TestJunosHostDenyNftParses feeds a representable junos-host DENY payload
// through `nft -c -f -` so the rendered iifname / saddr / counter lines are
// validated against the real nft parser (v1.1.6). nft absent => skip; a
// non-syntax (netlink/permission) error => pass.
func TestJunosHostDenyNftParses(t *testing.T) {
	nftPath := findNft()
	if nftPath == "" {
		t.Skip("nft not found")
	}
	cfg := junosHostDenyTestConfig()
	cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{"ike"}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("allow-good", "src:good-host", "app:any"),
			denyPolicy("block-net", "src:bad-net", "app:any"),
		}},
	}
	payload, _ := junosHostPayload(t, cfg)
	cmd := exec.Command(nftPath, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	if strings.Contains(string(out), "syntax error") {
		t.Fatalf("nft -c rejected junos-host payload:\n%s\npayload:\n%s", out, payload)
	}
	t.Logf("nft -c parsed (non-syntax error expected without CAP_NET_ADMIN): %v\n%s", err, out)
}

// TestJunosHostNftMatchesRustOracle is the #4146 cross-language parity fixture:
// for the representable ordered DENY class, the kernel nft projection must DROP
// exactly the sources the authoritative Rust junos-host semantics
// (policymatch.Match, the oracle pinned to userspace-dp evaluate_junos_host_
// policy) evaluate to a DENY, and never a permitted-exception source.
func TestJunosHostNftMatchesRustOracle(t *testing.T) {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("allow-good", "src:good-host", "app:any"),
			denyPolicy("block-net", "src:bad-net", "app:any"),
		}},
	}
	programs := dpuserspace.BuildJunosHostPrograms(cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d", len(programs))
	}

	cases := []struct {
		ip       string
		wantDrop bool // nft drop == Rust deny
	}{
		{"10.0.0.6", false},    // permitted exception (good-host) — carved out
		{"10.0.0.5", true},     // in bad-net, not the permitted host — denied
		{"10.1.2.3", true},     // in bad-net — denied
		{"192.168.1.1", false}, // outside bad-net — no host rule matches
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		// Rust oracle.
		res := policymatch.Match(cfg, policymatch.Query{
			FromZone: "untrust", ToZone: policymatch.JunosHostZone,
			SrcIP: ip, DstIP: net.ParseIP("10.0.2.10"),
			Protocol: "tcp", DstPort: 22,
		})
		oracleDeny := res.Matched && res.Action == config.PolicyDeny
		// nft projection verdict.
		nftDrop := junosHostProgramDrops(programs[0], ip)
		if oracleDeny != tc.wantDrop || nftDrop != tc.wantDrop {
			t.Errorf("src %s: nftDrop=%v oracleDeny=%v want=%v (res=%+v)",
				tc.ip, nftDrop, oracleDeny, tc.wantDrop, res)
		}
	}
}

// TestJunosHostExemptTupleParity documents the fine-eligible-L4 exemptions as
// parity cells the naive `policymatch.Match` oracle CANNOT express. For an
// IKE-admitting / ident-resetting zone, a `match source BAD application any then
// deny` STILL admits BAD's IKE (udp 500/4500) and STILL RSTs BAD's ident (tcp
// 113) — because the Rust IPsec-passthrough / ident-reset stages run BEFORE the
// fine junos-host policy (Stage 11 returns pre-fine; ident-reset is a coarse
// terminal). The pure-fine oracle returns DENY for those tuples (it models only
// the fine layer), so the kernel nft ADMIT/RST is FAITHFUL to the Rust runtime,
// NOT a divergence — the exemption shields the codegen emits ahead of the jump
// into the zone's subchain encode exactly that pre-fine behaviour. Only the
// fine-eligible tuples (e.g. tcp/22) are actually dropped.
func TestJunosHostExemptTupleParity(t *testing.T) {
	mkPayload := func(svc string) (string, dpuserspace.JunosHostProgram) {
		cfg := junosHostDenyTestConfig()
		cfg.Security.Zones["untrust"].HostInboundTraffic.SystemServices = []string{svc}
		cfg.Security.Policies = []*config.ZonePairPolicies{
			{FromZone: "untrust", ToZone: "junos-host",
				Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
		}
		payload, programs := junosHostPayload(t, cfg)
		if len(programs) != 1 {
			t.Fatalf("want 1 program for svc %q, got %d", svc, len(programs))
		}
		return payload, programs[0]
	}
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")

	// oracle: the pure-fine junos-host semantics DENY BAD on every app (incl. the
	// exempt tuples) — but that is NOT what the runtime does for IKE/ident.
	oracleDenies := func(proto string, port int) bool {
		res := policymatch.Match(junosHostDenyTestConfig4146Oracle(), policymatch.Query{
			FromZone: "untrust", ToZone: policymatch.JunosHostZone,
			SrcIP: net.ParseIP("10.0.0.5"), DstIP: net.ParseIP("10.0.2.10"),
			Protocol: proto, DstPort: port,
		})
		return res.Matched && res.Action == config.PolicyDeny
	}

	t.Run("IKE 500/4500 admitted despite deny (Stage-11 pre-fine)", func(t *testing.T) {
		payload, p := mkPayload("ike")
		if !p.CoarseAdmitsIKE {
			t.Fatal("zone should coarse-admit ike")
		}
		// The IKE shield precedes the application-any drop, so BAD's 500/4500 is
		// admitted before the drop can silence it.
		assertOrder(t, payload,
			`iifname "ge-0-0-1" udp dport { 500, 4500 } accept`,
			`iifname "ge-0-0-1" jump `+xnft.HostInboundJunosHostChainName(0, "untrust"),
		)
		// The naive fine oracle would DENY BAD's 500 — nft's admit is the faithful
		// runtime behaviour, not a bug.
		if !oracleDenies("udp", 500) {
			t.Fatal("sanity: the pure-fine oracle should DENY BAD's udp/500 (documents the intended nft divergence)")
		}
	})

	t.Run("ident 113 RST despite deny (coarse-terminal pre-fine)", func(t *testing.T) {
		payload, p := mkPayload("ident-reset")
		if !p.CoarseIdentResets {
			t.Fatal("zone should coarse-reset ident")
		}
		assertOrder(t, payload,
			`iifname "ge-0-0-1" tcp dport 113 reject with tcp reset`,
			`iifname "ge-0-0-1" jump `+xnft.HostInboundJunosHostChainName(0, "untrust"),
		)
		if !oracleDenies("tcp", 113) {
			t.Fatal("sanity: the pure-fine oracle should DENY BAD's tcp/113 (documents the intended nft divergence)")
		}
	})

	t.Run("fine-eligible tcp/22 still dropped", func(t *testing.T) {
		payload, _ := mkPayload("ike")
		// The drop is application-any (no L4 match), so it catches BAD's tcp/22.
		if !strings.Contains(payload, `meta nfproto ipv4 ip saddr 10.0.0.5/32 counter name "`+cn+`" drop`) {
			t.Fatalf("fine-eligible traffic from BAD must still be dropped:\n%s", payload)
		}
	})
}

// junosHostDenyTestConfig4146Oracle rebuilds the deny config for the oracle
// query (the zone's coarse services do not affect the fine junos-host verdict).
func junosHostDenyTestConfig4146Oracle() *config.Config {
	cfg := junosHostDenyTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "block-bad", "src:bad-host", "app:any")},
	}
	return cfg
}

// junosHostProgramDrops simulates the nft verdict of a program's v4 rules for a
// source IP in first-match order (#9504): the first rule whose source matches
// decides, a return (a permit) admitting and every other verdict denying.
// Application-any only (the fixture uses app any).
func junosHostProgramDrops(p dpuserspace.JunosHostProgram, ip net.IP) bool {
	for _, r := range p.RulesV4 {
		var matched bool
		switch {
		case r.SrcExcluded:
			matched = !ipInAny(ip, r.Src)
		case r.SrcAny:
			matched = true
		default:
			matched = ipInAny(ip, r.Src)
		}
		if matched {
			return r.Verdict != config.JunosHostReturn
		}
	}
	return false
}

func ipInAny(ip net.IP, cidrs []string) bool {
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// assertOrder asserts the given substrings appear in the payload in the given
// relative order (each strictly after the previous).
func assertOrder(t *testing.T, payload string, subs ...string) {
	t.Helper()
	idx := 0
	for _, s := range subs {
		found := strings.Index(payload[idx:], s)
		if found < 0 {
			t.Fatalf("payload missing %q at/after offset %d (or out of order):\n%s", s, idx, payload)
		}
		idx += found + len(s)
	}
}
