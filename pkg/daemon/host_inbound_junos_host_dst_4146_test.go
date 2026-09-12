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

// host_inbound_junos_host_dst_4146_test.go is the VERDICT gate for the #4146
// destination slice: a `to-zone junos-host` DENY that carries an explicit
// `match destination-address` must be ENFORCED on the DIRECT host-bound path
// (the kernel `xpf_hostinbound` chain), not merely warned about.
//
// Before this slice `junosHostProjectTerm` marked ANY term with a scoped
// destination un-representable, and the WHOLE-PROGRAM gate then emitted nothing
// for the ingress zone — so the deny was silently unenforced on the path that
// actually delivers the packet (the kernel; the XDP shim shunts local-destined
// packets to it before userspace-dp sees them). Worse, one destination-scoped
// deny disabled kernel enforcement of every OTHER junos-host deny on that zone
// (TestJunosHostDstScopedDenyDoesNotDisableSiblingDeny below).
//
// Every test here asserts the packet-level VERDICT — drop vs deliver for a
// concrete 5-tuple — and cross-checks it against policymatch.Match, the Go
// mirror of the authoritative Rust `evaluate_junos_host_policy` semantics (which
// already matched destination-address on the junos-host path via
// `rule_l3_matches(rule, state, src_ip, dst_ip)`). The kernel projection was the
// only surface dropping that dimension.

// junosHostVerdictQuery is one concrete host-bound packet.
type junosHostVerdictQuery struct {
	src, dst string
	proto    string
	dport    uint16
}

// junosHostKernelDrops evaluates the projected kernel DROP rules of the ingress
// zone's program against a concrete host-bound packet and reports whether the
// kernel would DROP it. It walks the rules in first-match order applying the
// SAME predicates the nft codegen renders: family, source (any / positive /
// excluded), destination (any / positive / excluded), and the L4 fragment. The
// first matching rule decides, and a return (a permit) admits (#9504). This is a
// verdict evaluation of the emitted ruleset, not a structural assertion about it.
//
// It takes the whole program SLICE deliberately: when the projection emits NO
// program for the zone — which is exactly what the pre-fix code did for a
// destination-scoped deny — the kernel drops nothing, so a revert surfaces as a
// VERDICT failure ("drop:false, want drop:true") naming the fail-open, not as a
// structural "no program" fatal that stops before the verdicts are checked.
func junosHostKernelDrops(programs []dpuserspace.JunosHostProgram, zone string, q junosHostVerdictQuery) bool {
	src, dst := net.ParseIP(q.src), net.ParseIP(q.dst)
	for _, p := range programs {
		if p.Zone != zone {
			continue
		}
		rules := p.RulesV4
		if dst.To4() == nil {
			rules = p.RulesV6
		}
		for _, r := range rules {
			if !junosHostAddrMatches(src, r.SrcAny, r.SrcExcluded, r.Src) {
				continue
			}
			if !junosHostAddrMatches(dst, r.DstAny, r.DstExcluded, r.Dst) {
				continue
			}
			if !junosHostL4Matches(r.L4, q.proto, q.dport) {
				continue
			}
			return r.Verdict != config.JunosHostReturn
		}
	}
	return false
}

// junosHostAddrMatches mirrors junosHostSrcPredicate / junosHostDstPredicate:
// `any` (or an excluded set with no prefix of this family) matches everything,
// an excluded set matches every address OUTSIDE it, a positive set matches
// inside it.
func junosHostAddrMatches(ip net.IP, matchAny, excluded bool, set []string) bool {
	switch {
	case excluded && len(set) > 0:
		return !ipInAny(ip, set)
	case matchAny || (excluded && len(set) == 0):
		return true
	default:
		return ipInAny(ip, set)
	}
}

// junosHostL4Matches mirrors renderJunosHostL4 for the tcp/udp fragments these
// tests use. An empty fragment list is `application any` (every protocol).
func junosHostL4Matches(l4 []config.JunosHostDenyL4, proto string, dport uint16) bool {
	if len(l4) == 0 {
		return true
	}
	want := config.HostInboundProtoTCP
	if proto == "udp" {
		want = config.HostInboundProtoUDP
	}
	for _, f := range l4 {
		if f.Proto != want {
			continue
		}
		if len(f.Ports) == 0 {
			return true
		}
		for _, pr := range f.Ports {
			if dport >= pr.Lo && dport <= pr.Hi {
				return true
			}
		}
	}
	return false
}

// junosHostOracleDenies evaluates the authoritative fine junos-host semantics
// (policymatch.Match, the Go mirror of Rust evaluate_junos_host_policy).
func junosHostOracleDenies(cfg *config.Config, zone string, q junosHostVerdictQuery) bool {
	res := policymatch.Match(cfg, policymatch.Query{
		FromZone: zone, ToZone: policymatch.JunosHostZone,
		SrcIP: net.ParseIP(q.src), DstIP: net.ParseIP(q.dst),
		Protocol: q.proto, DstPort: int(q.dport),
	})
	return res.Matched && res.Action == config.PolicyDeny
}

// junosHostDstTestConfig extends the shared #4146 fixture with the firewall's
// own addresses in the address book so a policy can scope by destination, plus
// an IPv6 address on the untrust netdev.
func junosHostDstTestConfig() *config.Config {
	cfg := junosHostDenyTestConfig()
	cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].Addresses = append(
		cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].Addresses, "2001:db8:2::10/64")
	ab := cfg.Security.AddressBook.Addresses
	ab["wan-ip"] = &config.Address{Name: "wan-ip", Value: "10.0.2.10/32"}
	ab["wan-ip6"] = &config.Address{Name: "wan-ip6", Value: "2001:db8:2::10/128"}
	ab["mgmt-ip"] = &config.Address{Name: "mgmt-ip", Value: "192.0.2.10/32"}
	return cfg
}

// TestJunosHostDstScopedDenyIsEnforced is the core #4146 destination-slice
// gate. A `from-zone untrust to-zone junos-host { match destination-address
// wan-ip; match application junos-ssh; then deny; }` MUST make the kernel DROP a
// host-bound TCP/22 packet addressed to the WAN IP — and must NOT touch the same
// flow addressed to a DIFFERENT firewall address (the deny is scoped).
//
// RED before the fix: junosHostProjectTerm marked the destination-scoped term
// un-representable, so BuildJunosHostPrograms returned NO program and the drop
// verdict was false while the oracle said DENY — the fail-open in #4146.
func TestJunosHostDstScopedDenyIsEnforced(t *testing.T) {
	cfg := junosHostDstTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "deny-ssh-to-wan", "src:bad-host", "dst:wan-ip", "app:junos-ssh")},
	}
	payload, programs := junosHostPayload(t, cfg)

	cases := []struct {
		name string
		q    junosHostVerdictQuery
		drop bool
	}{
		// The authored flow: denied source, denied destination, denied app.
		{"denied source to the scoped firewall address", junosHostVerdictQuery{"10.0.0.5", "10.0.2.10", "tcp", 22}, true},
		// Same source+app to a DIFFERENT firewall address: out of the deny's
		// destination scope, so it must still be delivered (over-deny guard).
		{"denied source to an unscoped firewall address", junosHostVerdictQuery{"10.0.0.5", "192.0.2.10", "tcp", 22}, false},
		// A different source to the scoped address: outside the source set.
		{"other source to the scoped address", junosHostVerdictQuery{"10.0.0.6", "10.0.2.10", "tcp", 22}, false},
		// A different application to the scoped address: outside the L4 scope.
		{"denied source, other application", junosHostVerdictQuery{"10.0.0.5", "10.0.2.10", "tcp", 443}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kernel := junosHostKernelDrops(programs, "untrust", tc.q)
			oracle := junosHostOracleDenies(cfg, "untrust", tc.q)
			if kernel != tc.drop {
				t.Errorf("kernel verdict for %s -> %s tcp/%d = drop:%v, want drop:%v",
					tc.q.src, tc.q.dst, tc.q.dport, kernel, tc.drop)
			}
			if oracle != tc.drop {
				t.Errorf("oracle (Rust junos-host semantics) for %s -> %s tcp/%d = deny:%v, want deny:%v",
					tc.q.src, tc.q.dst, tc.q.dport, oracle, tc.drop)
			}
		})
	}

	// The rendered nft line, checked after the verdicts so a regression reports
	// the packet-level consequence first.
	if len(programs) != 1 {
		t.Fatalf("a destination-scoped junos-host DENY must render a kernel program, got %d: %+v",
			len(programs), programs)
	}
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	want := `meta nfproto ipv4 tcp dport 22 ip saddr 10.0.0.5/32 ip daddr 10.0.2.10/32 counter name "` + cn + `" drop`
	if !strings.Contains(payload, want) {
		t.Fatalf("payload missing the destination-scoped drop %q:\n%s", want, payload)
	}
}

// TestJunosHostDstScopedDenyIsEnforcedV6 mirrors the surface on IPv6: the same
// destination-scoped deny authored against the firewall's IPv6 address must
// render an ip6 daddr drop and produce the same verdicts.
func TestJunosHostDstScopedDenyIsEnforcedV6(t *testing.T) {
	cfg := junosHostDstTestConfig()
	cfg.Security.AddressBook.Addresses["bad-host6"] = &config.Address{Name: "bad-host6", Value: "2001:db8:bad::5/128"}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "deny-ssh-to-wan6", "src:bad-host6", "dst:wan-ip6", "app:junos-ssh")},
	}
	payload, programs := junosHostPayload(t, cfg)
	for _, tc := range []struct {
		q    junosHostVerdictQuery
		drop bool
	}{
		{junosHostVerdictQuery{"2001:db8:bad::5", "2001:db8:2::10", "tcp", 22}, true},
		{junosHostVerdictQuery{"2001:db8:bad::6", "2001:db8:2::10", "tcp", 22}, false},
	} {
		kernel := junosHostKernelDrops(programs, "untrust", tc.q)
		oracle := junosHostOracleDenies(cfg, "untrust", tc.q)
		if kernel != tc.drop || oracle != tc.drop {
			t.Errorf("v6 %s -> %s: kernel drop=%v oracle deny=%v, want %v",
				tc.q.src, tc.q.dst, kernel, oracle, tc.drop)
		}
	}
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d: %+v", len(programs), programs)
	}
	if len(programs[0].RulesV4) != 0 {
		t.Errorf("a v6-only source/destination must emit no IPv4 rule, got %+v", programs[0].RulesV4)
	}
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip6")
	want := `meta nfproto ipv6 tcp dport 22 ip6 saddr 2001:db8:bad::5/128 ip6 daddr 2001:db8:2::10/128 counter name "` + cn + `" drop`
	if !strings.Contains(payload, want) {
		t.Fatalf("payload missing the v6 destination-scoped drop %q:\n%s", want, payload)
	}
}

// TestJunosHostDstScopedDenyDoesNotDisableSiblingDeny is the amplification
// regression guard. The whole-program representability gate means ONE
// un-representable term silences the ENTIRE ingress zone — so before this slice,
// adding a single destination-scoped junos-host policy silently disabled kernel
// enforcement of every other (perfectly representable) junos-host deny on that
// zone. Both denies must now render and both must enforce.
func TestJunosHostDstScopedDenyDoesNotDisableSiblingDeny(t *testing.T) {
	cfg := junosHostDstTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			denyPolicy("block-net", "src:bad-net", "app:any"),
			denyPolicy("deny-ssh-to-wan", "dst:wan-ip", "app:junos-ssh"),
		}},
	}
	_, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d: %+v", len(programs), programs)
	}
	if got := len(programs[0].RulesV4); got != 2 {
		t.Fatalf("want both denies rendered as IPv4 rules, got %d: %+v", got, programs[0].RulesV4)
	}
	// The plain source deny still enforces (it must not have been silenced).
	if !junosHostKernelDrops(programs, "untrust", junosHostVerdictQuery{"10.1.2.3", "192.0.2.10", "tcp", 443}) {
		t.Error("the sibling source-scoped deny must still DROP a source in bad-net")
	}
	// The destination-scoped deny enforces for a source OUTSIDE bad-net.
	if !junosHostKernelDrops(programs, "untrust", junosHostVerdictQuery{"203.0.113.9", "10.0.2.10", "tcp", 22}) {
		t.Error("the destination-scoped deny must DROP ssh to the scoped firewall address")
	}
	// And a flow matched by neither still reaches the box.
	if junosHostKernelDrops(programs, "untrust", junosHostVerdictQuery{"203.0.113.9", "192.0.2.10", "tcp", 443}) {
		t.Error("a flow matched by neither deny must NOT be dropped (over-deny guard)")
	}
	// Both policies must have their #4168 warning suppressed — each renders.
	rendered := config.BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys
	for _, name := range []string{"block-net", "deny-ssh-to-wan"} {
		if !rendered[config.JunosHostZonePairPolicyKey("untrust", name)] {
			t.Errorf("policy %q renders a kernel rule but is not in RenderedPolicyKeys", name)
		}
	}
}

// TestJunosHostDstScopedPermitRendersAReturn9504 is the over-reach guard on the
// permit side, re-pointed by #9504.
//
// The hazard is unchanged: rendering the following deny while dropping the
// permit's destination dimension would DENY traffic the operator explicitly
// permitted. What changed is the remedy. A permit used to be projectable only as
// a `saddr !=` subtraction of later denies, which cannot carry a destination, so
// the projection refused the whole program. It now renders as a RETURN carrying
// the permit's own daddr, ahead of the deny, in first-match order — so the carve
// is expressed rather than refused, and the deny stays as wide as authored.
func TestJunosHostDstScopedPermitRendersAReturn9504(t *testing.T) {
	cfg := junosHostDstTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			permitPolicy("allow-good-to-mgmt", "src:good-host", "dst:mgmt-ip", "app:any"),
			denyPolicy("block-net", "src:bad-net", "app:any"),
		}},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want one program for the ingress zone, got %+v", programs)
	}
	v4 := programs[0].RulesV4
	if len(v4) != 2 {
		t.Fatalf("want the permit's return then the deny's drop in v4, got %+v", v4)
	}
	if r := v4[0]; r.Verdict != config.JunosHostReturn || r.DstAny || len(r.Dst) != 1 {
		t.Errorf("first v4 rule = %+v, want a return still scoped to the permit's destination", r)
	}
	if r := v4[1]; r.Verdict != config.JunosHostDrop || !r.DstAny {
		t.Errorf("second v4 rule = %+v, want the deny's drop for every destination", r)
	}
	// The rendered subchain must carry the permit's daddr on the return: a return
	// that lost it would admit the permitted source to every firewall address, and
	// one that never rendered would deny it at the address the operator permitted.
	var sawScopedReturn bool
	for _, l := range junosHostChainLines(payload) {
		if strings.Contains(l, "return") && strings.Contains(l, "daddr") {
			sawScopedReturn = true
		}
	}
	if !sawScopedReturn {
		t.Errorf("no destination-scoped return rendered in the zone's subchain:\n%s", payload)
	}
	// The deny is enforced, so its warning is suppressed; the permit is never
	// suppressed, because the half that would refuse what it does not match is
	// enforced on no path (#9504).
	rendered := config.BuildJunosHostDenyProjection(cfg).RenderedPolicyKeys
	if !rendered[config.JunosHostZonePairPolicyKey("untrust", "block-net")] {
		t.Errorf("the deny renders a rule yet is not marked rendered: %+v", rendered)
	}
	if rendered[config.JunosHostZonePairPolicyKey("untrust", "allow-good-to-mgmt")] {
		t.Errorf("a permit must never be marked rendered: %+v", rendered)
	}
}

// TestJunosHostDstAnyExcludedEmitsNoDropLine is the #5828 degenerate case on the
// DESTINATION dimension: `destination-address any` + `destination-address-
// excluded` is "every destination EXCEPT every destination" = the empty set, so
// it must render NO drop line. Classifying its empty concrete set as the "any"
// arm would emit an UNCONDITIONAL drop and lock out all direct host-bound
// traffic on the ingress zone — the exact over-deny #5828 fixed for sources.
func TestJunosHostDstAnyExcludedEmitsNoDropLine(t *testing.T) {
	cfg := junosHostDstTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "blk", "src:bad-host", "dstx:any", "app:any")},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 0 {
		t.Fatalf("destination any+excluded is inert and must emit no program, got %+v", programs)
	}
	for _, l := range junosHostChainLines(payload) {
		if strings.Contains(l, "drop") && strings.Contains(l, "xpfjh_") {
			t.Errorf("unexpected junos-host drop line for an inert destination any+excluded term: %q", l)
		}
	}
}

// TestJunosHostDstExcludedDropsEverythingElse covers the constrained exclusion
// arm on the destination: `destination-address mgmt-ip` + excluded drops the
// flow to every firewall address EXCEPT the management one.
func TestJunosHostDstExcludedDropsEverythingElse(t *testing.T) {
	cfg := junosHostDstTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host",
			Policies: zonePairDeny("untrust", "blk", "src:bad-host", "dstx:mgmt-ip", "app:junos-ssh")},
	}
	payload, programs := junosHostPayload(t, cfg)
	if len(programs) != 1 {
		t.Fatalf("want 1 program, got %d: %+v", len(programs), programs)
	}
	cn := xnft.HostInboundJunosHostDenyCounterName("untrust", "ip")
	want := `meta nfproto ipv4 tcp dport 22 ip saddr 10.0.0.5/32 ip daddr != 192.0.2.10/32 counter name "` + cn + `" drop`
	if !strings.Contains(payload, want) {
		t.Fatalf("payload missing the excluded-destination drop %q:\n%s", want, payload)
	}
	for _, tc := range []struct {
		q    junosHostVerdictQuery
		drop bool
	}{
		{junosHostVerdictQuery{"10.0.0.5", "10.0.2.10", "tcp", 22}, true},   // not the excluded address
		{junosHostVerdictQuery{"10.0.0.5", "192.0.2.10", "tcp", 22}, false}, // the excluded address
	} {
		kernel := junosHostKernelDrops(programs, "untrust", tc.q)
		oracle := junosHostOracleDenies(cfg, "untrust", tc.q)
		if kernel != tc.drop || oracle != tc.drop {
			t.Errorf("%s -> %s: kernel drop=%v oracle deny=%v, want %v",
				tc.q.src, tc.q.dst, kernel, oracle, tc.drop)
		}
	}
}

// TestJunosHostDstScopedDenyKeepsLifelineReachable is the management-availability
// guard. The `mgmt` zone's only interface is the fxp0 LIFELINE, so it never gets
// an iifname scope and never renders a junos-host program — a destination-scoped
// deny on a DATA zone can therefore never suppress management ingress on fxp0,
// regardless of which firewall address it names. The deny still applies to the
// data zone's own ingress.
func TestJunosHostDstScopedDenyKeepsLifelineReachable(t *testing.T) {
	cfg := junosHostDstTestConfig()
	// A deliberately broad deny on BOTH zones naming the management address.
	deny := func() []*config.Policy {
		return []*config.Policy{denyPolicy("blk", "srcx:any-ipv6", "dst:mgmt-ip", "app:any")}
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: deny()},
		{FromZone: "mgmt", ToZone: "junos-host", Policies: deny()},
	}
	_, programs := junosHostPayload(t, cfg)
	for _, p := range programs {
		if p.Zone == "mgmt" {
			t.Fatalf("the lifeline-only mgmt zone must never render a junos-host program: %+v", p)
		}
		for _, iif := range p.IngressIfnames {
			if iif == "fxp0" {
				t.Fatalf("a junos-host DROP must never be scoped to the fxp0 lifeline: %+v", p)
			}
		}
	}
}

// TestJunosHostDstScopedNftParses feeds a destination-scoped payload through the
// real nft parser so the rendered `daddr` / `daddr !=` lines are validated
// against nft(8). nft absent => skip; a non-syntax (netlink/permission) error =>
// pass.
func TestJunosHostDstScopedNftParses(t *testing.T) {
	nftPath := findNft()
	if nftPath == "" {
		t.Skip("nft not found")
	}
	cfg := junosHostDstTestConfig()
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*config.Policy{
			denyPolicy("deny-ssh-to-wan", "src:bad-host", "dst:wan-ip", "app:junos-ssh"),
			denyPolicy("deny-else", "src:bad-net", "dstx:mgmt-ip", "app:any"),
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
		t.Fatalf("nft -c rejected the destination-scoped junos-host payload:\n%s\npayload:\n%s", out, payload)
	}
	t.Logf("nft -c parsed (non-syntax error expected without CAP_NET_ADMIN): %v\n%s", err, out)
}
