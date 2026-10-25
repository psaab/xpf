package flowexport

import (
	"errors"
	"net"
	"testing"
	"time"
)

// assignedCIDRAddrs builds the address view the real net.InterfaceAddrs
// returns: each entry is a *net.IPNet carrying the host IP together with
// its on-link mask (e.g. 192.0.2.2/24), NOT a host mask. This is the
// shape the #15073 fixture (host masks via CIDRMask(bits,bits)) missed
// and the shape that made prefix containment look like assignment.
func assignedCIDRAddrs(cidrs ...string) func() ([]net.Addr, error) {
	return func() ([]net.Addr, error) {
		out := make([]net.Addr, 0, len(cidrs))
		for _, s := range cidrs {
			ip, ipnet, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			out = append(out, &net.IPNet{IP: ip, Mask: ipnet.Mask})
		}
		if len(out) == 0 {
			out = append(out, &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 8)})
		}
		return out, nil
	}
}

func setupGraceAndProbe16757(t *testing.T) {
	t.Helper()
	origProbe := unhealthyProbeInterval
	unhealthyProbeInterval = 30 * time.Second
	t.Cleanup(func() { unhealthyProbeInterval = origProbe })
	origGrace := staleSourceGrace
	staleSourceGrace = 0
	t.Cleanup(func() { staleSourceGrace = origGrace })
}

// TestAddrIsAssigned_SamePrefix16757 pins the predicate directly: an
// assigned address with an on-link mask only counts for its own IP.
// Same-prefix neighbours (the DHCP/SLAAC renumber shape) are NOT
// assigned; the exact address under the same mask still is.
func TestAddrIsAssigned_SamePrefix16757(t *testing.T) {
	cases := []struct {
		name     string
		assigned []string
		needle   string
		want     bool
	}{
		{"v4 exact under on-link mask", []string{"192.0.2.1/24"}, "192.0.2.1", true},
		{"v4 same-prefix renumber", []string{"192.0.2.2/24"}, "192.0.2.1", false},
		{"v6 exact under on-link mask", []string{"2001:db8::1/64"}, "2001:db8::1", true},
		{"v6 same-prefix renumber", []string{"2001:db8::2/64"}, "2001:db8::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withLocalAddrs(t, assignedCIDRAddrs(tc.assigned...))
			if got := addrIsAssigned(tc.needle); got != tc.want {
				t.Fatalf("addrIsAssigned(%q) with assigned %v = %v, want %v (#16757)", tc.needle, tc.assigned, got, tc.want)
			}
		})
	}
}

// TestCollectorRedial_SamePrefixRenumberV4_16757 is the #16757 IPv4
// leg: the source was renumbered within the same subnet
// (192.0.2.1 -> 192.0.2.2, both /24). The next write must re-dial and
// deliver from S2 instead of parking on the dead socket.
//
// RED pre-fix: prefix containment (192.0.2.2/24 contains 192.0.2.1)
// reports the dead source still assigned, so neither the canary nor
// the write-failure path re-dials — dials stays 1 and writeAll fails.
func TestCollectorRedial_SamePrefixRenumberV4_16757(t *testing.T) {
	setupGraceAndProbe16757(t)

	withLocalAddrs(t, assignedCIDRAddrs("192.0.2.2/24"))
	dials, made := withDialSeams15073(t, []string{"192.0.2.1:40001", "192.0.2.2:40002"})

	cc, err := dialCollectors([]CollectorConfig{{Address: "192.0.2.99:2055"}})
	if err != nil {
		t.Fatalf("dialCollectors: %v", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials after build = %d, want 1", got)
	}
	oldConn := made()[0]
	oldConn.setErr(errors.New("write udp 192.0.2.1:40001->192.0.2.99:2055: sendto: cannot assign requested address"))

	if ok := cc.writeAll([]byte("pkt"), "send"); !ok {
		t.Fatal("writeAll = false after same-prefix renumber; want redial + delivery from S2 on the same flush (#16757)")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials after same-prefix renumber = %d, want 2 (one re-dial onto the live source)", got)
	}
	if !oldConn.closed.Load() {
		t.Fatal("old (stale-source) conn was not closed after the re-dial swap")
	}
	if got := made()[1].writes.Load(); got != 1 {
		t.Fatalf("fresh conn writes = %d, want 1 (this packet retried on the new source)", got)
	}
	if h := cc.health(); len(h) != 1 || !h[0].Healthy {
		t.Fatalf("health after redial = %+v, want the collector healthy on S2", h)
	}
}

// TestCollectorRedial_SamePrefixRenumberV6_16757 is the #16757 IPv6
// leg: the source was renumbered within the same prefix
// (2001:db8::1 -> 2001:db8::2, both /64) and writes keep succeeding
// from the removed address. Health must read unhealthy and the next
// writeAll must re-dial onto S2.
//
// RED pre-fix: 2001:db8::2/64 contains 2001:db8::1, so health reads
// healthy and writeAll never re-dials (dials stays 1, packet from S1).
func TestCollectorRedial_SamePrefixRenumberV6_16757(t *testing.T) {
	setupGraceAndProbe16757(t)

	withLocalAddrs(t, assignedCIDRAddrs("2001:db8::2/64"))
	dials, made := withDialSeams15073(t, []string{"[2001:db8::1]:40001", "[2001:db8::2]:40002"})

	cc, err := dialCollectors([]CollectorConfig{{Address: "[2001:db8::99]:4739"}})
	if err != nil {
		t.Fatalf("dialCollectors: %v", err)
	}
	h := cc.health()
	if len(h) != 1 {
		t.Fatalf("health entries = %d, want 1", len(h))
	}
	if h[0].Healthy {
		t.Fatalf("same-prefix stale-source collector reads healthy (source 2001:db8::1 renumbered to 2001:db8::2/64); health = %+v (#16757 v6 leg)", h[0])
	}
	if h[0].LastError == "" {
		t.Fatal("stale-source health carries no error; want the not-assigned reason surfaced")
	}
	if ok := cc.writeAll([]byte("pkt"), "send"); !ok {
		t.Fatal("writeAll = false; want re-dial onto S2 and delivery (#16757)")
	}
	if got := dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want 2 (canary re-dial onto the live source)", got)
	}
	if !made()[0].closed.Load() {
		t.Fatal("stale-source conn not closed after canary re-dial")
	}
	if got := made()[1].writes.Load(); got != 1 {
		t.Fatalf("S2 conn writes = %d, want 1 (packet sent from the new source)", got)
	}
	if h := cc.health(); !h[0].Healthy {
		t.Fatalf("health after canary redial = %+v, want healthy on S2", h[0])
	}
}

// TestCollectorRedial_ExactAddrOnLinkMaskNoChurn16757 is the control:
// the source is still assigned exactly, only reported with its real
// on-link mask (192.0.2.1/24). It must never be re-dialed — neither by
// the canary nor after an ordinary write failure. This control is
// green both pre- and post-fix; the defect arms above are what flip.
func TestCollectorRedial_ExactAddrOnLinkMaskNoChurn16757(t *testing.T) {
	setupGraceAndProbe16757(t)

	withLocalAddrs(t, assignedCIDRAddrs("192.0.2.1/24"))
	dials, made := withDialSeams15073(t, []string{"192.0.2.1:40001", "192.0.2.2:40002"})

	cc, err := dialCollectors([]CollectorConfig{{Address: "192.0.2.99:2055"}})
	if err != nil {
		t.Fatalf("dialCollectors: %v", err)
	}
	if ok := cc.writeAll([]byte("a"), "send"); !ok {
		t.Fatal("writeAll = false with a live source; want success")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1 (no canary churn while source still assigned)", got)
	}
	if h := cc.health(); !h[0].Healthy {
		t.Fatalf("health = %+v, want healthy", h[0])
	}

	made()[0].setErr(errors.New("write udp: connection refused"))
	if ok := cc.writeAll([]byte("b"), "send"); ok {
		t.Fatal("writeAll = true on a refused write; want false")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials after live-source failure = %d, want 1 (no redial churn)", got)
	}
	if made()[0].closed.Load() {
		t.Fatal("live-source conn closed on an ordinary failure; want it retained")
	}
	if h := cc.health(); h[0].Healthy {
		t.Fatalf("health = %+v, want unhealthy after refused write", h[0])
	}
}
