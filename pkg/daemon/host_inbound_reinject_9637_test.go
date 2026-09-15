package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/networkd"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/psaab/xpf/pkg/vrrp"
)

// reinjectViews9637 is two addressed views shaped like the loss cluster's lan
// and wan plus one addressed-but-unzoned interface: lan admits ssh and ping,
// wan admits ping, the unzoned address admits nothing (the #4420 catch-all).
func reinjectViews9637() ([]dpuserspace.ZoneHostInboundView, []string, []string) {
	views := []dpuserspace.ZoneHostInboundView{
		{Zone: "lan", SystemServices: []string{"ssh", "ping"}, V4Addrs: []string{"10.0.61.1"}, V6Addrs: []string{"2001:db8:61::1"}, IngressNetdevs: []string{"fwlan"}},
		{Zone: "wan", SystemServices: []string{"ping"}, V4Addrs: []string{"172.16.80.8"}, IngressNetdevs: []string{"fwwan"}},
	}
	return views, []string{"10.0.99.1"}, []string{"2001:db8:99::1"}
}

// reinjectAcceptLines returns the rendered reinject-accept rule lines.
func reinjectAcceptLines(t *testing.T, payload string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(payload, "\n") {
		if strings.Contains(l, `"xpf-usp0"`) {
			out = append(out, l)
		}
	}
	return out
}

// TestHostInboundReinjectAcceptShape9637 pins the fresh-render shape, in both
// chain shapes (with and without junos-host programs):
//   - one accept per addressed family, scoped to iifname xpf-usp0 AND the
//     per-family VIEW addresses, carrying the named accept counter;
//   - placed AFTER the global accepts and the program jumps and BEFORE the
//     first ingress-zone rule.
func TestHostInboundReinjectAcceptShape9637(t *testing.T) {
	views, unzonedV4, unzonedV6 := reinjectViews9637()
	_, _, _, programs, wg := parityHostInboundInputs()
	for _, tc := range []struct {
		name     string
		programs []dpuserspace.JunosHostProgram
	}{
		{"no-programs", nil},
		{"with-programs", programs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, tc.programs, wg, true)
			cn := xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptReinject)
			wantV4 := `    iifname "xpf-usp0" ip daddr ` + nftAddrSet([]string{"10.0.61.1", "172.16.80.8"}) + ` counter name "` + cn + `" accept`
			wantV6 := `    iifname "xpf-usp0" ip6 daddr 2001:db8:61::1 counter name "` + cn + `" accept`
			if !strings.Contains(payload, wantV4) {
				t.Errorf("missing v4 reinject accept:\n%s\npayload:\n%s", wantV4, payload)
			}
			if !strings.Contains(payload, wantV6) {
				t.Errorf("missing v6 reinject accept:\n%s\npayload:\n%s", wantV6, payload)
			}
			lines := strings.Split(payload, "\n")
			acceptIdx, firstIngressIdx := -1, -1
			for i, l := range lines {
				s := strings.TrimSpace(l)
				if strings.Contains(l, `"xpf-usp0"`) {
					acceptIdx = i
				}
				// Program jumps also carry iifname but no daddr; the first
				// ingress-zone rule is the first iifname+daddr line that is
				// not the reinject accept.
				if firstIngressIdx < 0 && strings.HasPrefix(s, "iifname ") && strings.Contains(l, "daddr") && !strings.Contains(l, `"xpf-usp0"`) {
					firstIngressIdx = i
				}
			}
			if acceptIdx < 0 {
				t.Fatalf("no reinject accept rendered\npayload:\n%s", payload)
			}
			if firstIngressIdx < 0 || acceptIdx > firstIngressIdx {
				t.Errorf("reinject accept (line %d) must precede the first ingress-zone rule (line %d)", acceptIdx, firstIngressIdx)
			}
			// The global accepts precede the reinject accept in both shapes.
			for _, global := range []string{"ct state established,related accept", "meta l4proto { 50, 51 } accept"} {
				if idx := strings.Index(payload, global); idx < 0 || strings.Index(payload, `"xpf-usp0"`) < idx {
					t.Errorf("global %q must precede the reinject accept", global)
				}
			}
			if tc.name == "with-programs" && !strings.Contains(payload, "jump") {
				t.Error("with-programs shape must render program jumps ahead of the accept")
			}
		})
	}
}

// TestHostInboundReinjectStaleOmitsAccept9637 is the D1 fail-closed pin (and
// the M3 staged-failure render assertion): a render from a generation the
// dataplane does not run (dataplaneFresh=false — the #5679 deferred-error
// shape: nft at N+1, dataplane at N) contains NO reinject accept and NO
// reinject counter, while the fresh address still meets the destination-only
// deny. Packet verdicts through failure/recovery stay lock-cell-measured; the
// render pin is what makes the window unopenable.
func TestHostInboundReinjectStaleOmitsAccept9637(t *testing.T) {
	views, unzonedV4, unzonedV6 := reinjectViews9637()
	// The N+1 generation: a fresh view address the stale dataplane never saw.
	views[1].V4Addrs = append(views[1].V4Addrs, "172.16.80.9")
	stale := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, false)
	if strings.Contains(stale, "xpf-usp0") {
		t.Errorf("stale render must not name the reinject device:\n%s", stale)
	}
	if strings.Contains(stale, xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptReinject)) {
		t.Errorf("stale render must not declare the reinject counter:\n%s", stale)
	}
	// The fresh address still meets the owner-zone destination deny.
	wanDeny := "ip daddr " + nftAddrSet([]string{"172.16.80.8", "172.16.80.9"})
	found := false
	for _, l := range strings.Split(stale, "\n") {
		if strings.Contains(l, wanDeny) && strings.HasSuffix(strings.TrimSpace(l), "drop") {
			found = true
		}
	}
	if !found {
		t.Errorf("stale render must still deny the fresh address by destination:\n%s", stale)
	}
	// The fresh twin renders the accept for exactly the view set.
	fresh := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, true)
	if got := reinjectAcceptLines(t, fresh); len(got) != 2 {
		t.Errorf("fresh render must carry exactly the v4+v6 reinject accepts, got %q", got)
	}
}

// TestHostInboundReinjectViewsScoped9637 pins why the accept is views-scoped,
// not blanket: the unzoned address is judged by the unchanged #4420 catch-all
// in BOTH designs, and the accept set carries no unzoned value. It also pins
// the builder-disjointness invariant the scoping relies on: union(view addrs)
// ∩ union(unzoned addrs) = ∅.
func TestHostInboundReinjectViewsScoped9637(t *testing.T) {
	views, unzonedV4, unzonedV6 := reinjectViews9637()
	viewV4, viewV6 := hostInboundReinjectDestinations(views)
	for _, u := range unzonedV4 {
		for _, v := range viewV4 {
			if u == v {
				t.Errorf("builder-disjointness violated: %q in both view and unzoned v4 sets", u)
			}
		}
	}
	for _, u := range unzonedV6 {
		for _, v := range viewV6 {
			if u == v {
				t.Errorf("builder-disjointness violated: %q in both view and unzoned v6 sets", u)
			}
		}
	}
	payload := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, true)
	for _, l := range reinjectAcceptLines(t, payload) {
		for _, u := range append(append([]string{}, unzonedV4...), unzonedV6...) {
			if strings.Contains(l, u) {
				t.Errorf("reinject accept must not carry unzoned address %q:\n%s", u, l)
			}
		}
	}
	// The unzoned catch-all still drops the unzoned address.
	unzonedDeny := `ip daddr 10.0.99.1 counter name "` + xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, "ip") + `" drop`
	if !strings.Contains(payload, unzonedDeny) {
		t.Errorf("unzoned catch-all must be byte-identical:\n%s\npayload:\n%s", unzonedDeny, payload)
	}
}

// TestHostInboundReinjectCounterDeclared9637 pins the counter discipline: the
// reinject counter is declared exactly when the accept rules render (fresh +
// addressed views), and never otherwise. An undeclared reference (or a
// reference without a rule) rejects the whole atomic load or lies in the
// table.
func TestHostInboundReinjectCounterDeclared9637(t *testing.T) {
	views, unzonedV4, unzonedV6 := reinjectViews9637()
	cn := xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptReinject)
	decl := "  counter " + cn + " {"
	fresh := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, true)
	if !strings.Contains(fresh, decl) {
		t.Errorf("fresh render must declare the reinject counter:\n%s", fresh)
	}
	stale := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, false)
	if strings.Contains(stale, decl) || strings.Contains(stale, cn) {
		t.Errorf("stale render must declare nothing reinject-related:\n%s", stale)
	}
	// Addressless views render no accept and declare no counter, fresh or not.
	empty := []dpuserspace.ZoneHostInboundView{{Zone: "lan", SystemServices: []string{"ssh"}}}
	for _, freshFlag := range []bool{true, false} {
		p := buildHostInboundFilterPayload(empty, nil, nil, nil, nil, freshFlag)
		if strings.Contains(p, cn) {
			t.Errorf("addressless render (fresh=%v) must not reference the reinject counter:\n%s", freshFlag, p)
		}
	}
}

// TestHostInboundReinjectChainPolicyAccept9637 pins the load-bearing
// chain-policy invariant the common-skew equivalence leg depends on: an
// address in NEITHER the views nor the unzoned set falls through to `policy
// accept` in both designs. If a later change flips the policy to drop, the
// common-skew row must be re-proved.
func TestHostInboundReinjectChainPolicyAccept9637(t *testing.T) {
	views, unzonedV4, unzonedV6 := reinjectViews9637()
	for _, freshFlag := range []bool{true, false} {
		payload := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, freshFlag)
		if !strings.Contains(payload, "type filter hook input priority") || !strings.Contains(payload, "policy accept;") {
			t.Errorf("fresh=%v: chain must keep the accept fall-through policy:\n%s", freshFlag, payload)
		}
	}
}

// TestHostInboundReinjectTunName9637 pins the cross-language name contracts:
// the Go accept scope MUST equal the Rust DEFAULT_SLOW_PATH_TUN, and the Go
// delegated-device name MUST equal the Rust DELEGATED_SLOW_PATH_TUN. A rename
// on either side without the other orphans the accept (dead rule, residual
// unclosed) or strands delegated reinjects off-kernel (silent blackhole) —
// this test reds first. It also pins that NO render surface references the
// delegated device (the narrowing proof: delegated frames must fall through
// to destination judgment, never an accept).
func TestHostInboundReinjectTunName9637(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "userspace-dp", "src", "afxdp", "mod.rs"))
	if err != nil {
		t.Fatalf("reading Rust slow-path TUN name: %v", err)
	}
	m := regexp.MustCompile(`const DEFAULT_SLOW_PATH_TUN:\s*&str\s*=\s*"([^"]+)"`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("DEFAULT_SLOW_PATH_TUN declaration not found in userspace-dp/src/afxdp/mod.rs")
	}
	if got, want := xnft.HostInboundReinjectIfname, string(m[1]); got != want {
		t.Errorf("Go HostInboundReinjectIfname %q != Rust DEFAULT_SLOW_PATH_TUN %q", got, want)
	}
	d := regexp.MustCompile(`pub\(crate\) const DELEGATED_SLOW_PATH_TUN:\s*&str\s*=\s*"([^"]+)"`).FindSubmatch(raw)
	if d == nil {
		t.Fatal("DELEGATED_SLOW_PATH_TUN declaration not found in userspace-dp/src/afxdp/mod.rs")
	}
	if got, want := xnft.HostInboundDelegatedIfname, string(d[1]); got != want {
		t.Errorf("Go HostInboundDelegatedIfname %q != Rust DELEGATED_SLOW_PATH_TUN %q", got, want)
	}
	views, unzonedV4, unzonedV6 := reinjectViews9637()
	for _, freshFlag := range []bool{true, false} {
		payload := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, freshFlag)
		if strings.Contains(payload, xnft.HostInboundDelegatedIfname) {
			t.Errorf("fresh=%v: no render surface may reference the delegated device:\n%s", freshFlag, payload)
		}
	}
	// networkd keeps its copy of the delegated name as a literal (importing
	// the SSOT would cycle); pin that it still spells the SSOT value.
	nwd, err := os.ReadFile(filepath.Join("..", "networkd", "networkd.go"))
	if err != nil {
		t.Fatalf("reading networkd.go for the delegated TUN literal: %v", err)
	}
	if !strings.Contains(string(nwd), `"`+xnft.HostInboundDelegatedIfname+`"`) {
		t.Errorf("pkg/networkd/networkd.go must spell the delegated TUN %q (rp_filter restore)", xnft.HostInboundDelegatedIfname)
	}
}

// TestHostInboundReinjectFreshGateWiring9637 drives the daemon choke point:
// applyHostInboundFilter installs the spec with DataplaneFresh following the
// flag — set (post-ApplyConfig success) renders the accept, clear (deferred
// #5679 error, abort-class failure, or never-applied) omits it. The flag
// setters live at the single ApplyConfig call site; this test pins the render
// side of that contract.
func TestHostInboundReinjectFreshGateWiring9637(t *testing.T) {
	origInst := nftInstaller
	defer func() { nftInstaller = origInst }()
	var got []xnft.HostInboundSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			got = append(got, spec)
			return nil
		},
	}
	d := &Daemon{}
	d.hostInboundDataplaneFresh.Store(true)
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("fresh apply: %v", err)
	}
	d.hostInboundDataplaneFresh.Store(false)
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("stale apply: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two installs, got %d", len(got))
	}
	if !got[0].DataplaneFresh {
		t.Error("fresh daemon must install with DataplaneFresh=true")
	}
	if got[1].DataplaneFresh {
		t.Error("stale daemon must install with DataplaneFresh=false (D1 fail-closed)")
	}
}

// TestHostInboundReinjectDispositionMatrix9637 is the binding enumeration
// gate (b): one row per §5.2 reinject disposition, each asserting the
// RENDERED verdict for that disposition's kernel-observable shape — string
// checks on the payload, nothing more. Operator narrowing: ONLY
// userspace-gated LocalDelivery rides the trusted TUN (accept); every
// delegation path (NoRoute incl. capped, transit MissingNeighbor,
// ForwardCandidate fallback, synthetic IPsec) rides the delegated TUN and
// meets the destination rules — rows for those classes pin the
// destination-deny presence, while the outlet proof is Rust-side
// (reinject_host_authorized mapping + per-site flags) plus lock-cell
// wire/counter evidence. No row proves non-arrival: non-arrival claims
// live Rust-side.
func TestHostInboundReinjectDispositionMatrix9637(t *testing.T) {
	views, unzonedV4, unzonedV6 := reinjectViews9637()
	fresh := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, true)
	stale := buildHostInboundFilterPayload(views, unzonedV4, unzonedV6, nil, nil, false)
	cn := xnft.HostInboundAcceptCounterName(xnft.HostInboundAcceptReinject)
	v4accept := `    iifname "xpf-usp0" ip daddr ` + nftAddrSet([]string{"10.0.61.1", "172.16.80.8"}) + ` counter name "` + cn + `" accept`
	v6accept := `    iifname "xpf-usp0" ip6 daddr 2001:db8:61::1 counter name "` + cn + `" accept`
	denyUnzonedV4 := `ip daddr 10.0.99.1 counter name "` + xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, "ip") + `" drop`
	rows := []struct {
		name string
		// disposition names the §5.2 row this kernel verdict answers.
		disposition string
		payloads    map[string]string
		want        []string
		absent      []string
	}{
		{
			name:        "localdelivery-hit/view-v4",
			disposition: "LocalDelivery session-hit (per-hit host-inbound + junos-host re-eval): ADJUDICATED, reinject accepted",
			payloads:    map[string]string{"fresh": fresh},
			want:        []string{v4accept},
		},
		{
			name:        "localdelivery-miss-iface-nat/view-v4",
			disposition: "LocalDelivery session-miss incl. the interface-NAT miss path: ADJUDICATED, reinject accepted — the residual fix itself",
			payloads:    map[string]string{"fresh": fresh},
			want:        []string{v4accept},
		},
		{
			name:        "flowless-localdelivery/view-v6",
			disposition: "LocalDelivery flowless (#3292 fragments/no-L4, flowless_local_delivery_verdict): ADJUDICATED, reinject accepted",
			payloads:    map[string]string{"fresh": fresh},
			want:        []string{v6accept},
		},
		{
			name:        "ipsec-synthetic/delegated",
			disposition: "IPsec synthetic LocalDelivery (new/seeded IKE, ESP/AH, ESP-in-UDP/NAT-T): DELEGATED outlet — rides the unfiltered passthrough site, so the destination judges on the same token set with identical verdicts (no flip; the old SA-design flip is closed by narrowing).",
			payloads:    map[string]string{"fresh": fresh, "stale": stale},
			want:        []string{"meta l4proto { 50, 51 } accept"},
		},
		{
			name:        "tunnel-nat-uncapped-deny/zoned-anchor",
			disposition: "Tunnel-interface-NAT leg (i) uncapped default-deny: PolicyDenied, NO TUN enqueue (Rust three-state fixture). Were it to reinject it would ride the DELEGATED outlet (untrusted) and meet the owner-zone destination deny — the render carries no delegated accept (TunName pin).",
			payloads:    map[string]string{"fresh": fresh, "stale": stale},
			want:        []string{xnft.HostInboundDenyCounterName("wan", "ip")},
		},
		{
			name:        "tunnel-nat-default-permit/zoned-anchor",
			disposition: "Tunnel-interface-NAT leg (ii) default-PERMIT (unresolved-egress NoRoute falls to the default action, PD:5155-5160): DELEGATED outlet — the kernel destination rules judge (deny where the owner zone denies). The scoped accept never sees it (iifname xpf-usp0 only). Rust device proof + lock-cell counters; no approval flip remains.",
			payloads:    map[string]string{"fresh": fresh, "stale": stale},
			want:        []string{xnft.HostInboundDenyCounterName("wan", "ip")},
		},
		{
			name:        "tunnel-nat-capped/zoned-anchor",
			disposition: "Tunnel-interface-NAT leg (iii) capped-delegate: DELEGATED outlet while capped — destination-judged, no flip (the capped set-revocation follow-up is moot: there is no delegated accept to revoke).",
			payloads:    map[string]string{"fresh": fresh, "stale": stale},
			want:        []string{xnft.HostInboundDenyCounterName("wan", "ip")},
		},
		{
			name:        "missingneighbor-nonowning/D4a-delegated",
			disposition: "MissingNeighbor via a NON-OWNING resolving table (fib.rs:250-253) with a transit permit: DELEGATED outlet (Rust: reinject_host_authorized false for non-LocalDelivery). Kernel destination judgment applies; the owning-table path resolves LocalDelivery FIRST (gated, trusted). This row pins the destination-deny presence; the outlet proof is Rust-side.",
			payloads:    map[string]string{"fresh": fresh, "stale": stale},
			want:        []string{xnft.HostInboundDenyCounterName("wan", "ip")},
		},
		{
			name:        "unzoned-catch-all/both-designs",
			disposition: "Unzoned-interface dst: the #4420 catch-all DROP judges in BOTH designs (views-scoping preserves it)",
			payloads:    map[string]string{"fresh": fresh, "stale": stale},
			want:        []string{denyUnzonedV4},
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			for pname, p := range r.payloads {
				for _, w := range r.want {
					if !strings.Contains(p, w) {
						t.Errorf("%s: disposition %q: missing %q", pname, r.disposition, w)
					}
				}
				for _, a := range r.absent {
					if strings.Contains(p, a) {
						t.Errorf("%s: disposition %q: forbidden %q present", pname, r.disposition, a)
					}
				}
			}
		})
	}
	// The rows below need structural assertions beyond substring presence.
	t.Run("nat-t-delegated/service-agnostic-accept-shape", func(t *testing.T) {
		// ESP-in-UDP / NAT-T keepalive to a non-ike zone NO LONGER flips:
		// the synthetic passthrough rides the DELEGATED outlet, so the
		// destination judges (deny without an ike token). This pins the
		// remaining breadth honestly: the trusted accept carries NO service
		// qualifier (any gated service rides it), and a delegated arrival
		// can never match it (iifname xpf-usp0 only). Lock-cell UDP/4500
		// probe + wan-deny counter is the wire proof of destination denial.
		for _, l := range reinjectAcceptLines(t, fresh) {
			for _, q := range []string{"dport", " tcp ", " udp ", "meta l4proto"} {
				if strings.Contains(l, q) {
					t.Errorf("reinject accept must be service-agnostic, found %q in:\n%s", q, l)
				}
			}
		}
	})
	t.Run("forwardcandidate-buildfailure/D4b-delegated", func(t *testing.T) {
		// D4b: the non-owning-table forward lookup INTENTIONALLY yields
		// ForwardCandidate when a neighbor exists (fib.rs:455-473), and the
		// forward-build-failure fallback to the slow path is INTENTIONAL
		// (tx/dispatch/mod.rs:516-517,530-531; slow_path.rs:91-104,
		// unfiltered except FabricRedirect) — routed DELEGATED (Rust:
		// explicit `false` at the fallback site). No flip: the kernel
		// destination rules judge. This row pins defense-in-depth on the
		// render side: even a misrouted reinject matches ONLY view addresses
		// (exactly the v4+v6 accepts, exact view set), while
		// unzoned/lifeline/unknown dsts fall through.
		got := reinjectAcceptLines(t, fresh)
		if len(got) != 2 {
			t.Fatalf("fresh render must carry exactly the v4+v6 accepts, got %q", got)
		}
		if !strings.Contains(got[0]+got[1], v4accept[strings.Index(v4accept, "ip daddr"):]) {
			t.Errorf("v4 accept set must equal the view set exactly:\n%q", got)
		}
	})
	t.Run("fabricredirect-hainactive/not-input", func(t *testing.T) {
		// Both dispositions are slow-path-ineligible in the Rust eligibility
		// enum, so neither is ever enqueued to the TUN (that non-arrival is
		// the proof, pinned Rust-side). Belt-and-braces, every accept line
		// is additionally iifname-scoped to xpf-usp0, so no forward-path
		// packet (physical iifname) could match even a mis-enqueued one.
		for _, l := range reinjectAcceptLines(t, fresh) {
			if !strings.Contains(l, `iifname "xpf-usp0"`) {
				t.Errorf("reinject accept must be TUN-scoped, got:\n%s", l)
			}
		}
		if len(reinjectAcceptLines(t, fresh)) == 0 {
			t.Fatal("expected fresh reinject accepts to scope-check")
		}
	})
	t.Run("post-decap-inner/arrival-agnostic", func(t *testing.T) {
		// Decapsulated-inner dsts traverse the same arms: the accept
		// carries NO outer-tunnel qualifier (no tunnel-endpoint, GRE, or
		// WireGuard condition) — inner and outer arrivals share the rule.
		for _, l := range reinjectAcceptLines(t, fresh) {
			for _, q := range []string{"tunnel", "gre", "wireguard", "51820", "47"} {
				if strings.Contains(strings.ToLower(l), q) {
					t.Errorf("reinject accept must be arrival-agnostic, found %q in:\n%s", q, l)
				}
			}
		}
	})
	t.Run("lifeline/fall-through-both-designs", func(t *testing.T) {
		// Lifeline dsts are in NEITHER the view set nor the unzoned set
		// (#3718): no rule may name them in either design — they fall
		// through exactly as today.
		for pname, p := range map[string]string{"fresh": fresh, "stale": stale} {
			for _, a := range []string{"10.0.0.1", "192.0.2.9"} {
				if strings.Contains(p, a) {
					t.Errorf("%s: neither-set address %q must appear in no rule", pname, a)
				}
			}
		}
	})
	t.Run("unzoned-v6-catch-all/both-designs", func(t *testing.T) {
		// The v6 twin of the unzoned catch-all, both designs.
		for pname, p := range map[string]string{"fresh": fresh, "stale": stale} {
			found := false
			for _, l := range strings.Split(p, "\n") {
				if strings.Contains(l, "ip6 daddr 2001:db8:99::1") && strings.HasSuffix(strings.TrimSpace(l), "drop") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: v6 unzoned catch-all DROP missing", pname)
			}
		}
	})
	t.Run("f3-fresh-view-addr/stale-denies", func(t *testing.T) {
		// The F3 opposite-skew row with a generation dial: the N+1 view
		// address meets the owner-zone destination deny while stale and
		// the exemption while fresh.
		n1 := append([]dpuserspace.ZoneHostInboundView(nil), views...)
		n1[1].V4Addrs = append(append([]string(nil), views[1].V4Addrs...), "172.16.80.9")
		staleN1 := buildHostInboundFilterPayload(n1, unzonedV4, unzonedV6, nil, nil, false)
		freshN1 := buildHostInboundFilterPayload(n1, unzonedV4, unzonedV6, nil, nil, true)
		if strings.Contains(staleN1, "xpf-usp0") {
			t.Error("stale N+1 render must not name the reinject device")
		}
		wanDeny := "ip daddr " + nftAddrSet([]string{"172.16.80.8", "172.16.80.9"})
		found := false
		for _, l := range strings.Split(staleN1, "\n") {
			if strings.Contains(l, wanDeny) && strings.HasSuffix(strings.TrimSpace(l), "drop") {
				found = true
			}
		}
		if !found {
			t.Error("stale N+1 render must deny the fresh address by destination")
		}
		if got := reinjectAcceptLines(t, freshN1); len(got) != 2 {
			t.Errorf("fresh N+1 render must carry the v4+v6 accepts, got %q", got)
		}
	})
}

// TestHostInboundReinjectReapplySetsFreshGate9637 pins the second writer of
// the D1 gate: a #5134 same-config worker-arm re-apply that SUCCEEDS
// publishes this commit's snapshot, so the flag must be set even when the
// first ApplyConfig failed (flag clear). A failed re-apply leaves the flag
// untouched (the first-apply outcome stands) and records worker-arm debt.
func TestHostInboundReinjectReapplySetsFreshGate9637(t *testing.T) {
	t.Run("success-after-first-failure-sets", func(t *testing.T) {
		d := &Daemon{}
		d.setDataplane(&deferredMACReapplyTestDP{})
		d.hostInboundDataplaneFresh.Store(false)
		d.reapplyAfterDeferredMAC(&config.Config{})
		if !d.hostInboundDataplaneFresh.Load() {
			t.Error("successful worker-arm re-apply must set the D1 gate (dataplane runs this snapshot)")
		}
	})
	t.Run("failure-leaves-clear-and-records-debt", func(t *testing.T) {
		dp := &deferredMACReapplyTestDP{applyErr: errors.New("helper rejected apply_snapshot")}
		d := &Daemon{}
		d.setDataplane(dp)
		d.reapplyAfterDeferredMAC(&config.Config{})
		if d.hostInboundDataplaneFresh.Load() {
			t.Error("failed worker-arm re-apply must not set the D1 gate")
		}
		if dp.debtRecords != 1 {
			t.Errorf("failed re-apply must record worker-arm debt, got %d", dp.debtRecords)
		}
	})
}

// reinjectProductionHarness9637 drives the REAL applyConfigLocked (not the
// helper) with a hermetic netlink installer seam, capturing every installed
// HostInboundSpec. It mirrors the #3333/#5643 harnesses: fake networkctl,
// in-dir networkd, temp config store, and a runtimeOnlyApplyTestDP published
// through the cell.
func reinjectProductionHarness9637(t *testing.T, dp *runtimeOnlyApplyTestDP) (*Daemon, *[]xnft.HostInboundSpec) {
	t.Helper()
	installFakeNetworkctl(t)
	orig := nftInstaller
	var got []xnft.HostInboundSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(s xnft.HostInboundSpec) error {
			got = append(got, s)
			return nil
		},
	}
	t.Cleanup(func() { nftInstaller = orig })
	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(dp)
	return d, &got
}

// reinjectEnforceableConfig9637 is a minimal enforceable host-inbound config
// proven through applyConfigLocked by the #3333 harness: a non-lifeline zone
// with a static address and an ssh stanza.
func reinjectEnforceableConfig9637() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.7.7.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	return cfg
}

// TestHostInboundReinjectOrdinaryFailureRendersAcceptless9637 is the F1
// production-path pin for the #5679 shape: an ordinary ApplyConfig failure
// fails the commit but still runs the tail, which must install WITHOUT the
// accept — removing a previously installed one. RED-on-revert: remove the
// Store(false) at the ApplyConfig call site and the captured install carries
// DataplaneFresh=true.
func TestHostInboundReinjectOrdinaryFailureRendersAcceptless9637(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{applyErr: errors.New("helper rejected apply_snapshot")}
	d, got := reinjectProductionHarness9637(t, dp)
	d.hostInboundDataplaneFresh.Store(true) // previous success installed the accept
	err := d.applyConfigLocked(context.Background(), reinjectEnforceableConfig9637())
	if err == nil {
		t.Fatal("failed dataplane apply must fail the commit (deferred #5679), got nil")
	}
	if len(*got) == 0 {
		t.Fatal("failed apply must still run the tail (ordinary error): no host-inbound install captured")
	}
	for _, s := range *got {
		if s.DataplaneFresh {
			t.Error("failed apply must install accept-less (D1 fail-closed removal of the previous accept)")
		}
	}
	if d.hostInboundDataplaneFresh.Load() {
		t.Error("flag must be clear after an ApplyConfig failure")
	}
}

// TestHostInboundReinjectCancelCloseoutRendersAcceptless9637 is the F1-A
// production-path pin: a pre-dataplane cancel (C1/C2) runs the
// cancellation closeout, which renders the INCOMING config while the
// dataplane still runs the previous snapshot. The closeout must install
// WITHOUT the accept even though the flag was set by the previous success.
// RED-on-revert: remove the closeout-entry Store(false) and the captured
// install carries DataplaneFresh=true (incoming-config accept against the
// previous snapshot — the bypass).
func TestHostInboundReinjectCancelCloseoutRendersAcceptless9637(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{}
	d, got := reinjectProductionHarness9637(t, dp)
	d.hostInboundDataplaneFresh.Store(true) // previous success installed the accept
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // daemon-stop before the dataplane apply (C1/C2)
	err := d.applyConfigLocked(ctx, reinjectEnforceableConfig9637())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled apply must bail with context.Canceled, got %v", err)
	}
	if dp.applyCalls != 0 {
		t.Fatalf("dataplane apply ran %d times: the cancel was not pre-dataplane, the test is not exercising F1-A", dp.applyCalls)
	}
	if len(*got) == 0 {
		t.Fatal("cancel closeout must still install host-inbound (M35): no install captured")
	}
	for _, s := range *got {
		if s.DataplaneFresh {
			t.Error("cancel closeout must install accept-less: the dataplane never saw this config (F1-A bypass)")
		}
	}
	if d.hostInboundDataplaneFresh.Load() {
		t.Error("flag must be clear after a cancel closeout")
	}
}

// TestHostInboundReinjectSuccessRendersAccept9637 is the production-path pin
// for the set side: a successful ApplyConfig through applyConfigLocked
// installs WITH the accept. RED-on-revert: remove the Store(true) at the
// call site and the captured install carries DataplaneFresh=false.
func TestHostInboundReinjectSuccessRendersAccept9637(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{}
	d, got := reinjectProductionHarness9637(t, dp)
	if err := d.applyConfigLocked(context.Background(), reinjectEnforceableConfig9637()); err != nil {
		t.Fatalf("successful apply must commit clean, got %v", err)
	}
	if dp.applyCalls == 0 {
		t.Fatal("dataplane apply did not run: not exercising the success path")
	}
	if len(*got) == 0 {
		t.Fatal("successful apply must install host-inbound: no install captured")
	}
	last := (*got)[len(*got)-1]
	if !last.DataplaneFresh {
		t.Error("successful apply must install WITH the accept (dataplane runs this snapshot)")
	}
	if !d.hostInboundDataplaneFresh.Load() {
		t.Error("flag must be set after a successful ApplyConfig")
	}
}

// TestHostInboundReinjectBuilderDisjointness9637 is the M2 pin Codex demanded:
// union(view addrs) ∩ union(unzoned addrs) = ∅ asserted over the REAL builder
// outputs (BuildZoneHostInboundViews vs BuildUnzonedHostInboundAddrs, which
// subtracts zoned values and withholds lifeline-shared values) — not over
// hand-authored fixtures — plus the accept set asserted free of unzoned
// values on that same builder-derived input. Non-vacuous: both sets must be
// non-empty, and the lifeline address must be in NEITHER set.
func TestHostInboundReinjectBuilderDisjointness9637(t *testing.T) {
	cfg := hostInboundUnzonedTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	u4, u6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	var viewAddrs []string
	for _, v := range views {
		viewAddrs = append(viewAddrs, v.V4Addrs...)
		viewAddrs = append(viewAddrs, v.V6Addrs...)
	}
	unzoned := append(append([]string{}, u4...), u6...)
	if len(viewAddrs) == 0 || len(unzoned) == 0 {
		t.Fatalf("non-vacuous pin requires addressed views AND unzoned addrs, got %d view + %d unzoned", len(viewAddrs), len(unzoned))
	}
	inView := map[string]bool{}
	for _, a := range viewAddrs {
		inView[a] = true
	}
	for _, u := range unzoned {
		if inView[u] {
			t.Errorf("builder-disjointness violated: %q produced by both builders", u)
		}
	}
	for _, lifeline := range []string{"10.5.5.5"} {
		if inView[lifeline] {
			t.Errorf("lifeline %q must not be in any view", lifeline)
		}
		for _, u := range unzoned {
			if u == lifeline {
				t.Errorf("lifeline %q must not be in the unzoned set", lifeline)
			}
		}
	}
	payload := buildHostInboundFilterPayload(views, u4, u6, nil, nil, true)
	for _, l := range reinjectAcceptLines(t, payload) {
		for _, u := range unzoned {
			if strings.Contains(l, u) {
				t.Errorf("reinject accept must not carry builder-derived unzoned address %q:\n%s", u, l)
			}
		}
	}
}

// TestHostInboundReinjectSubtractionRegression9637 pins the address-value
// subtraction the views-scoping relies on: an address present on BOTH a
// zoned unit and an unzoned interface must land in the views ONLY
// (zones_host_inbound.go:532-540) — the unzoned catch-all must not judge
// it, and the reinject accept must carry it exactly once via the view set.
func TestHostInboundReinjectSubtractionRegression9637(t *testing.T) {
	cfg := hostInboundUnzonedTestConfig()
	const shared = "192.0.2.1/24"
	reth1 := cfg.Interfaces.Interfaces["reth1"].Units[0]
	reth1.Addresses = append(reth1.Addresses, shared) // now zoned (lan) AND unzoned (ge-0/0/9)
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	u4, u6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	for _, u := range u4 {
		if u == "192.0.2.1" {
			t.Errorf("subtraction violated: shared address 192.0.2.1 kept in the unzoned set %q", u4)
		}
	}
	inViews := false
	for _, v := range views {
		for _, a := range v.V4Addrs {
			if a == "192.0.2.1" {
				inViews = true
			}
		}
	}
	if !inViews {
		t.Error("shared address 192.0.2.1 must stay in the (lan) view set")
	}
	payload := buildHostInboundFilterPayload(views, u4, u6, nil, nil, true)
	total := 0
	for _, l := range reinjectAcceptLines(t, payload) {
		total += strings.Count(l, "192.0.2.1")
	}
	if total != 1 {
		t.Errorf("shared address must appear exactly once via the view set, got %d:\n%s", total, payload)
	}
}

// TestHostInboundReinjectDeferredPublishRendersAcceptless9637 is the F1-B
// production-path pin: an ApplyConfig SUCCESS that deferred its helper
// publish (XSK-startup: SnapshotPublishDeferred) must install WITHOUT the
// accept — the helper still serves the previous snapshot. RED-on-revert:
// drop the `!SnapshotPublishDeferred` condition at the call site and the
// captured install carries DataplaneFresh=true.
func TestHostInboundReinjectDeferredPublishRendersAcceptless9637(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{SnapshotPublishDeferred: true}}
	d, got := reinjectProductionHarness9637(t, dp)
	d.hostInboundDataplaneFresh.Store(true) // previous success installed the accept
	if err := d.applyConfigLocked(context.Background(), reinjectEnforceableConfig9637()); err != nil {
		t.Fatalf("deferred publish still commits clean, got %v", err)
	}
	if len(*got) == 0 {
		t.Fatal("deferred-publish apply must still install host-inbound: no install captured")
	}
	for _, s := range *got {
		if s.DataplaneFresh {
			t.Error("deferred-publish apply must install accept-less (helper runs the previous snapshot)")
		}
	}
	if d.hostInboundDataplaneFresh.Load() {
		t.Error("flag must be clear after a deferred-publish success")
	}
}

// TestHostInboundReinjectVersionRefusalAbortsAcceptless9637 is the GPT-1
// mixed-version cell: a pre-narrowing (v17) helper under this daemon
// refuses the v18 snapshot (exact-equality gate), which surfaces as an
// abort-class apply error. The commit must abort (loud, operator-visible),
// the flag must be clear, and NO install may run — the kernel retains its
// previous table instead of installing the narrowed exemption against a
// helper that funnels every reinject through `xpf-usp0`. RED-on-revert:
// stop clearing the flag before the abort check and a retained-true flag
// would authorize a later accept against the old helper.
func TestHostInboundReinjectVersionRefusalAbortsAcceptless9637(t *testing.T) {
	dp := &runtimeOnlyApplyTestDP{applyErr: dpuserspace.ErrEgressZoneProtocolIncompatible}
	d, got := reinjectProductionHarness9637(t, dp)
	d.hostInboundDataplaneFresh.Store(true) // previous success installed the accept
	err := d.applyConfigLocked(context.Background(), reinjectEnforceableConfig9637())
	if !errors.Is(err, dpuserspace.ErrEgressZoneProtocolIncompatible) {
		t.Fatalf("version refusal must abort the commit with the gate error, got %v", err)
	}
	if len(*got) != 0 {
		t.Fatalf("aborted apply must install nothing (tail skipped), got %d installs", len(*got))
	}
	if d.hostInboundDataplaneFresh.Load() {
		t.Error("flag must be clear after a version-refusal abort")
	}
}
