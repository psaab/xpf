package daemon

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

type neighborCounts15952 struct {
	linkByIndex map[int]int
	listNeigh   map[neighborFamilyKey]int
	probed      []string // "ip@iface" in probe order
}

func newNeighborCounts15952() *neighborCounts15952 {
	return &neighborCounts15952{
		linkByIndex: make(map[int]int),
		listNeigh:   make(map[neighborFamilyKey]int),
	}
}

func (c *neighborCounts15952) ops(
	linkErr map[int]error,
	tables map[neighborFamilyKey][]netlink.Neigh,
) neighborResolveOps {
	return neighborResolveOps{
		linkByIndex: func(ifindex int) (netlink.Link, error) {
			c.linkByIndex[ifindex]++
			if err := linkErr[ifindex]; err != nil {
				return nil, err
			}
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
				Name:  fmt.Sprintf("if-%d", ifindex),
				Index: ifindex,
			}}, nil
		},
		listNeigh: func(ifindex, family int) ([]netlink.Neigh, error) {
			key := neighborFamilyKey{linkIndex: ifindex, family: family}
			c.listNeigh[key]++
			return tables[key], nil
		},
		probe: func(ip net.IP, iface string) {
			c.probed = append(c.probed, ip.String()+"@"+iface)
		},
	}
}

func v4targets15952(linkIndex, n int) []neighborProbeTarget {
	targets := make([]neighborProbeTarget, 0, n)
	for i := range n {
		targets = append(targets, neighborProbeTarget{
			neighborIP: net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1)).To4(),
			linkIndex:  linkIndex,
		})
	}
	return targets
}

// T targets on one (linkIndex, family) must dump LinkByIndex/NeighList at
// most once per unique pair, and every target missing from the usable
// snapshot must be probed (#15952).
func TestResolveNeighborTargetsDumpsOncePerLinkFamily15952(t *testing.T) {
	const linkIndex = 7
	targets := v4targets15952(linkIndex, 200)
	// One usable entry mid-range: it alone is skipped.
	tables := map[neighborFamilyKey][]netlink.Neigh{
		{linkIndex: linkIndex, family: netlink.FAMILY_V4}: {
			{LinkIndex: linkIndex, IP: net.ParseIP("192.0.2.100").To4(), State: netlink.NUD_REACHABLE},
		},
	}
	counts := newNeighborCounts15952()
	resolved := resolveNeighborTargets(targets, counts.ops(nil, tables))

	if counts.linkByIndex[linkIndex] != 1 || len(counts.linkByIndex) != 1 {
		t.Fatalf("LinkByIndex calls = %v, want exactly one call for link %d", counts.linkByIndex, linkIndex)
	}
	key := neighborFamilyKey{linkIndex: linkIndex, family: netlink.FAMILY_V4}
	if counts.listNeigh[key] != 1 || len(counts.listNeigh) != 1 {
		t.Fatalf("NeighList calls = %v, want exactly one call for %v", counts.listNeigh, key)
	}
	if resolved != 199 {
		t.Fatalf("resolved = %d, want 199 (all but the usable 192.0.2.100)", resolved)
	}
	if len(counts.probed) != 199 {
		t.Fatalf("probed = %d, want 199: %v", len(counts.probed), counts.probed)
	}
	for _, p := range counts.probed {
		if p == "192.0.2.100@if-7" {
			t.Fatalf("usable-at-pass-start target was probed: %v", counts.probed)
		}
	}
}

// Skip/probe decisions must match the per-target semantics: usable states
// (REACHABLE/STALE/PERMANENT) skip, other states probe, and errors from
// NeighList leave every target probed (the pre-fix code ignored the error
// and scanned an empty table) (#15952).
func TestResolveNeighborTargetsSkipStates15952(t *testing.T) {
	const linkIndex = 3
	mk := func(s string) net.IP { return net.ParseIP(s).To4() }
	targets := []neighborProbeTarget{
		{neighborIP: mk("10.0.0.1"), linkIndex: linkIndex}, // REACHABLE -> skip
		{neighborIP: mk("10.0.0.2"), linkIndex: linkIndex}, // STALE -> skip
		{neighborIP: mk("10.0.0.3"), linkIndex: linkIndex}, // PERMANENT -> skip
		{neighborIP: mk("10.0.0.4"), linkIndex: linkIndex}, // FAILED -> probe
		{neighborIP: mk("10.0.0.5"), linkIndex: linkIndex}, // absent -> probe
	}
	tables := map[neighborFamilyKey][]netlink.Neigh{
		{linkIndex: linkIndex, family: netlink.FAMILY_V4}: {
			{LinkIndex: linkIndex, IP: mk("10.0.0.1"), State: netlink.NUD_REACHABLE},
			{LinkIndex: linkIndex, IP: mk("10.0.0.2"), State: netlink.NUD_STALE},
			{LinkIndex: linkIndex, IP: mk("10.0.0.3"), State: netlink.NUD_PERMANENT},
			{LinkIndex: linkIndex, IP: mk("10.0.0.4"), State: netlink.NUD_FAILED},
		},
	}
	counts := newNeighborCounts15952()
	if resolved := resolveNeighborTargets(targets, counts.ops(nil, tables)); resolved != 2 {
		t.Fatalf("resolved = %d, want 2", resolved)
	}
	want := []string{"10.0.0.4@if-3", "10.0.0.5@if-3"}
	if fmt.Sprint(counts.probed) != fmt.Sprint(want) {
		t.Fatalf("probed = %v, want %v", counts.probed, want)
	}
}

// Distinct links and families are dumped separately; a LinkByIndex failure
// skips only that link's targets and is attempted once per link (#15952).
func TestResolveNeighborTargetsDistinctPairsAndLinkFailure15952(t *testing.T) {
	mk4 := func(s string) net.IP { return net.ParseIP(s).To4() }
	targets := []neighborProbeTarget{
		{neighborIP: mk4("10.1.0.1"), linkIndex: 1},
		{neighborIP: mk4("10.1.0.2"), linkIndex: 1},
		{neighborIP: net.ParseIP("2001:db8::1"), linkIndex: 1}, // same link, v6
		{neighborIP: mk4("10.2.0.1"), linkIndex: 2},
		{neighborIP: mk4("10.3.0.1"), linkIndex: 9}, // LinkByIndex fails
		{neighborIP: mk4("10.3.0.2"), linkIndex: 9}, // LinkByIndex fails
	}
	counts := newNeighborCounts15952()
	ops := counts.ops(map[int]error{9: errors.New("no such link")}, nil)
	if resolved := resolveNeighborTargets(targets, ops); resolved != 4 {
		t.Fatalf("resolved = %d, want 4 (link-9 targets skipped)", resolved)
	}
	if len(counts.linkByIndex) != 3 {
		t.Fatalf("LinkByIndex distinct links = %v, want links 1, 2, 9 once each", counts.linkByIndex)
	}
	for idx, n := range counts.linkByIndex {
		if n != 1 {
			t.Fatalf("LinkByIndex[%d] = %d, want 1", idx, n)
		}
	}
	wantLists := map[neighborFamilyKey]int{
		{linkIndex: 1, family: netlink.FAMILY_V4}: 1,
		{linkIndex: 1, family: netlink.FAMILY_V6}: 1,
		{linkIndex: 2, family: netlink.FAMILY_V4}: 1,
	}
	if fmt.Sprint(counts.listNeigh) != fmt.Sprint(wantLists) {
		t.Fatalf("NeighList calls = %v, want %v", counts.listNeigh, wantLists)
	}
	for _, p := range counts.probed {
		if p == "10.3.0.1@if-9" || p == "10.3.0.2@if-9" {
			t.Fatalf("target on failed link was probed: %v", counts.probed)
		}
	}
}

// An entry that becomes usable only after the snapshot was taken (here the
// fake table gains it on a hypothetical second dump, which must never
// happen) may draw one harmless extra probe; the snapshot is authoritative
// for the whole pass (#15952).
func TestResolveNeighborTargetsSnapshotIsPassAuthoritative15952(t *testing.T) {
	const linkIndex = 5
	targets := v4targets15952(linkIndex, 3)
	counts := newNeighborCounts15952()
	ops := counts.ops(nil, nil)
	dumps := 0
	ops.listNeigh = func(ifindex, family int) ([]netlink.Neigh, error) {
		counts.listNeigh[neighborFamilyKey{linkIndex: ifindex, family: family}]++
		dumps++
		if dumps > 1 {
			// Mid-pass appearance: would make 192.0.2.1 usable if re-dumped.
			return []netlink.Neigh{{LinkIndex: ifindex, IP: net.ParseIP("192.0.2.1").To4(), State: netlink.NUD_REACHABLE}}, nil
		}
		return nil, nil
	}
	if resolved := resolveNeighborTargets(targets, ops); resolved != 3 {
		t.Fatalf("resolved = %d, want 3 (snapshot taken once, before probes)", resolved)
	}
	if dumps != 1 {
		t.Fatalf("NeighList dumps = %d, want 1", dumps)
	}
}
