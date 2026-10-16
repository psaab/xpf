package userspace

import (
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// prepopulateIngressRows writes ifindex rows straight into the injected
// userspace_ingress_ifaces map, WITHOUT going through the Manager. That is the
// point: it models rows left in the PINNED map by a previous xpfd process, which
// the current Manager never wrote and has no inventory for.
func prepopulateIngressRows(t *testing.T, ifaceMap *ebpf.Map, ifindexes ...uint32) {
	t.Helper()
	for _, idx := range ifindexes {
		if err := ifaceMap.Update(idx, uint8(userspaceIngressIfaceFlagAdjudicated), ebpf.UpdateAny); err != nil {
			t.Fatalf("prepopulate userspace_ingress_ifaces %d: %v", idx, err)
		}
	}
}

// ingressRowsPresent returns the ifindex keys currently in the map, sorted.
func ingressRowsPresent(t *testing.T, ifaceMap *ebpf.Map) []uint32 {
	t.Helper()
	var (
		key uint32
		val uint8
	)
	var out []uint32
	iter := ifaceMap.Iterate()
	for iter.Next(&key, &val) {
		out = append(out, key)
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate userspace_ingress_ifaces: %v", err)
	}
	slices.Sort(out)
	return out
}

// TestFreshManagerReapsPrepopulatedIngressRows6784 is the #6784 fail-on-revert
// test, and it is the test the issue's own fix direction asked for: "test a new
// manager against stale prepopulated pins".
//
// userspace_ingress_ifaces is PinByName-pinned at /sys/fs/bpf/xpf, so its rows
// outlive xpfd. m.lastIngressIfaces does not — it is an ordinary Manager field
// that starts nil. Before #6784 the reap loop in syncIngressIfaceMapLocked
// scanned that empty inventory, so the FIRST sync after a daemon restart
// deleted nothing and every row the previous process left behind survived. The
// row is not inert: the XDP shim reads this map on every packet and a present
// non-zero row is what diverts traffic away from cpumap_or_pass into the AF_XDP
// redirect path, so a stale row keeps steering a de-configured interface.
//
// Both cases below start from a FRESH Manager (New(), inventory nil) against a
// map that already holds rows, exactly as a restart finds it.
//
//   - overlap: some prepopulated rows are still in the config and some are not.
//     This is the case that needs the reap to be SELECTIVE — it fails a fix that
//     adopts and then deletes everything, as well as one that reaps nothing.
//   - no-overlap: nothing prepopulated is still configured. This is the
//     interface-deleted-while-xpfd-was-down / ifindex-reused shape.
//
// FAIL-ON-REVERT: dropping the adoptIngressInventoryLocked call (or making it a
// no-op) leaves `prior` empty on the first pass, so the stale rows survive and
// the "must be gone" assertion goes RED with the stale ifindex named.
//
// PRIVILEGE NOTE: like the #6537 tests it extends, this needs real BPF maps and
// SKIPs unprivileged. The #6784 mutation matrix was run under sudo so these
// cells actually executed; a SKIP here is not a pass.
func TestFreshManagerReapsPrepopulatedIngressRows6784(t *testing.T) {
	tests := []struct {
		name string
		// prepopulated models the rows the pinned map carried across the restart.
		prepopulated []uint32
		// configured is the ingress set the new snapshot adjudicates.
		configured []int
		// want is the exact row set the map must hold after the sync.
		want []uint32
		// gone names the stale rows whose survival is the defect.
		gone []uint32
	}{
		{
			name:         "overlap",
			prepopulated: []uint32{10, 11, 99},
			configured:   []int{10, 11},
			want:         []uint32{10, 11},
			gone:         []uint32{99},
		},
		{
			name:         "no-overlap",
			prepopulated: []uint32{7, 8},
			configured:   []int{21},
			want:         []uint32{21},
			gone:         []uint32{7, 8},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ifaceMap := newIngressManager(t, ebpf.Hash, 16)

			// Premise: the Manager is FRESH — it has no inventory naming any of
			// these rows, which is the whole reason the pre-#6784 reap was a
			// no-op. Assert it rather than assuming it.
			if len(m.lastIngressIfaces) != 0 {
				t.Fatalf("premise broken: a fresh Manager must have an empty ingress inventory, got %v",
					m.lastIngressIfaces)
			}
			if m.ingressInventoryAdopted {
				t.Fatal("premise broken: a fresh Manager must not be marked as having adopted the pinned map")
			}

			prepopulateIngressRows(t, ifaceMap, tc.prepopulated...)

			if err := m.syncIngressIfaceMapLocked(ingressSnapshot(tc.configured...)); err != nil {
				t.Fatalf("syncIngressIfaceMapLocked: %v", err)
			}

			got := ingressRowsPresent(t, ifaceMap)
			for _, stale := range tc.gone {
				if slices.Contains(got, stale) {
					t.Errorf("ifindex %d was left in the PINNED userspace_ingress_ifaces map by a "+
						"previous process and is NOT in the new config, but the first sync of a fresh "+
						"Manager did not reap it: rows=%v. The XDP shim reads this map per packet, so "+
						"the shim keeps steering that interface's traffic into the AF_XDP path (#6784)",
						stale, got)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("userspace_ingress_ifaces = %v, want exactly %v "+
					"(the reap must be SELECTIVE — configured rows must survive it)", got, tc.want)
			}
		})
	}
}

// TestIngressAdoptionFailureIsFatal6784 binds the fail-direction choice. If the
// pinned map cannot be enumerated, the rows it holds are UNKNOWN, so the reap
// below cannot be trusted and the sync must NOT report success — the caller
// (syncUserspaceClassifierMapsFailClosedLocked) drives ctrl to Enabled=0 so the
// shim stops redirecting transit rather than running against a classifier no
// one can account for. This matches how syncLocalAddressMapsLocked and
// syncInterfaceNATAddressMapsLocked already treat an iteration failure.
//
// The failure is injected by CLOSING the map, which makes every subsequent map
// operation fail — so the assertion checks the error names the ADOPTION step,
// not merely that some error occurred.
//
// FAIL-ON-REVERT: swallowing the adoption error (logging and continuing) makes
// the sync return nil, and the "must fail" assertion goes RED.
func TestIngressAdoptionFailureIsFatal6784(t *testing.T) {
	m, ifaceMap := newIngressManager(t, ebpf.Hash, 16)
	prepopulateIngressRows(t, ifaceMap, 42)

	if err := ifaceMap.Close(); err != nil {
		t.Fatalf("close userspace_ingress_ifaces: %v", err)
	}

	err := m.syncIngressIfaceMapLocked(ingressSnapshot(10))
	if err == nil {
		t.Fatal("an unreadable userspace_ingress_ifaces map must FAIL the classifier sync " +
			"(the caller then drives ctrl to Enabled=0); got nil, so the reap silently ran " +
			"against an unknown map (#6784)")
	}
	if !strings.Contains(err.Error(), "adopt userspace_ingress_ifaces inventory") {
		t.Errorf("the error must name the adoption step so the fail-closed cause is attributable; got %q", err)
	}
	if m.ingressInventoryAdopted {
		t.Error("a FAILED enumeration must not mark the inventory adopted — the next pass has to retry, " +
			"otherwise a single transient scan failure permanently disables the restart reap (#6784)")
	}
}

// TestIngressAdoptionRunsOncePerManager6784 is the tightening control: adoption
// is a RESTART-RECOVERY step, not a standing authority grab over the map.
//
// Within a live process the Manager is the sole writer of
// userspace_ingress_ifaces (the Rust helper never touches it; the shim only
// reads it), and #6537 established m.lastIngressIfaces as the record of what
// this process installed. Re-enumerating on every pass would quietly widen the
// reap to rows the Manager never installed and never recorded, which is a
// different contract from the one #6537 tests pin.
//
// The discriminator: a row injected BETWEEN two syncs is not in the config and
// not in the inventory. A once-per-Manager adoption leaves it alone; a
// per-pass adoption reaps it.
//
// FAIL-ON-REVERT: removing the `if m.ingressInventoryAdopted { return nil }`
// early return makes the second sync re-enumerate and delete ifindex 77, and
// the "must survive" assertion goes RED.
func TestIngressAdoptionRunsOncePerManager6784(t *testing.T) {
	m, ifaceMap := newIngressManager(t, ebpf.Hash, 16)

	if err := m.syncIngressIfaceMapLocked(ingressSnapshot(10)); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if !m.ingressInventoryAdopted {
		t.Fatal("premise broken: the first sync must have adopted the pinned map")
	}

	// A row appears that this Manager did not install and did not record.
	prepopulateIngressRows(t, ifaceMap, 77)

	if err := m.syncIngressIfaceMapLocked(ingressSnapshot(10)); err != nil {
		t.Fatalf("second sync: %v", err)
	}

	got := ingressRowsPresent(t, ifaceMap)
	if !slices.Contains(got, uint32(77)) {
		t.Errorf("adoption must run ONCE per Manager (restart recovery), not on every pass: "+
			"ifindex 77 was injected after the first sync, so it is neither configured nor in the "+
			"#6537 inventory, and a per-pass re-enumeration reaped it. rows=%v (#6784)", got)
	}
	if !slices.Contains(got, uint32(10)) {
		t.Errorf("the configured ifindex 10 must still be present; rows=%v", got)
	}
}
