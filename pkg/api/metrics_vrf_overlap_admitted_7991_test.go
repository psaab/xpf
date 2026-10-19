package api

import (
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// vrfOverlapStore builds a store whose ACTIVE config a tolerant load accepts but
// the strict commit gate would REJECT (#7924): two routing-instances carrying
// overlapping L3, plus a PBR `then routing-instance` term.
//
// Seeded via a persisted DB + tolerant Load() rather than Commit(), because
// Commit runs the strict path and refuses it. That is the whole point — this
// models a config persisted before #7927 and loaded at upgrade, or one arriving
// by HA peer-sync, which is exactly the population the metric exists to surface.
//
// `strictReject` lets the caller build the NEGATIVE fixture (overlap, no PBR
// term) through the same helper, so the two differ in one stanza and nothing
// else — the difference the metric is supposed to key on.
func vrfOverlapStore(t *testing.T, withPBRSteering bool) *configstore.Store {
	t.Helper()
	dir := t.TempDir()
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.9.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.1/24",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/0.0",
		"set routing-instances tenant-b instance-type virtual-router",
		"set routing-instances tenant-b interface ge-0/0/1.0",
	}
	if withPBRSteering {
		lines = append(lines,
			"set firewall family inet filter steer term t1 from source-address 10.9.9.0/24",
			"set firewall family inet filter steer term t1 then routing-instance tenant-b",
			"set interfaces ge-0/0/2 unit 0 family inet address 192.168.9.1/24",
			"set interfaces ge-0/0/2 unit 0 family inet filter input steer",
		)
	}
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	// The preconditions are the fixture's whole claim, so assert them rather
	// than assume: WITH the PBR term the strict path must refuse and the
	// tolerant path must accept; WITHOUT it both must accept. If the strict
	// gate ever stopped refusing, this test would still pass on a metric that
	// fires for a config nobody is in — and that is the failure a fixture
	// cannot report about itself unless it checks.
	_, strictErr := config.CompileConfig(tree)
	if withPBRSteering && strictErr == nil {
		t.Fatal("precondition: overlap + PBR steering compiled cleanly on the STRICT path; " +
			"the #7924 gate must reject it, or this fixture is not the tolerant-admitted state")
	}
	if !withPBRSteering && strictErr != nil {
		t.Fatalf("precondition: plain VRF overlap must still COMMIT on the strict path "+
			"(only the combination is refused): %v", strictErr)
	}
	if _, err := config.CompileConfigLenient(tree); err != nil {
		t.Fatalf("precondition: the config must compile on the tolerant path: %v", err)
	}

	db, err := configstore.NewDB(filepath.Join(dir, ".configdb"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	db.SetWriterVersion("test-1.0")
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	if err := store.Load(); err != nil {
		t.Fatalf("tolerant Load() of the seeded DB must succeed: %v", err)
	}
	if store.ActiveConfig() == nil {
		t.Fatal("ActiveConfig() nil after tolerant Load of a lenient-compilable config")
	}
	return store
}

func gatherVRFOverlapSeries(t *testing.T, store *configstore.Store) map[[3]string]float64 {
	t.Helper()
	s := &Server{store: store} // dp intentionally nil.
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(newCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[[3]string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "xpf_vrf_overlap_pbr_admitted" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var k [3]string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "instance_a":
					k[0] = l.GetValue()
				case "instance_b":
					k[1] = l.GetValue()
				case "prefix":
					k[2] = l.GetValue()
				}
			}
			got[k] = m.GetGauge().GetValue()
		}
	}
	return got
}

// TestVRFOverlapAdmittedEmittedWhenDataplaneUnloaded is the fail-on-revert
// proof, and it mirrors the #3718 cell deliberately: the condition is a
// config-derived control-plane signal that can be open in a config-only /
// degraded boot AND is NOT self-healing, so the series must be emitted with the
// dataplane nil. Moving collectVRFOverlapPBRAdmitted below the
// `dp == nil || !dp.IsLoaded()` gate makes this RED.
func TestVRFOverlapAdmittedEmittedWhenDataplaneUnloaded_7991(t *testing.T) {
	got := gatherVRFOverlapSeries(t, vrfOverlapStore(t, true))
	if len(got) != 1 {
		t.Fatalf("xpf_vrf_overlap_pbr_admitted series = %v, want exactly one "+
			"(config-only boot; the collector must run BEFORE the dataplane gate)", got)
	}
	for k, v := range got {
		if v != 1 {
			t.Errorf("gauge value = %v, want 1", v)
		}
		if k[0] != "tenant-a" || k[1] != "tenant-b" {
			t.Errorf("instances = (%q, %q), want (tenant-a, tenant-b) in the detector's "+
				"deterministic sorted order", k[0], k[1])
		}
		if k[2] != "10.9.9.0/24" {
			t.Errorf("prefix label = %q, want the MASKED overlapping prefix 10.9.9.0/24 — "+
				"an unmasked host address would make two boxes with the same overlap "+
				"report different series", k[2])
		}
	}
}

// THE PAIRED CELL. Plain VRF overlap with no PBR steering COMMITS on the strict
// path, so it is not the tolerant-admitted state and must emit nothing.
//
// Without this, a collector that reported every overlap would satisfy the cell
// above while firing on configurations that are perfectly legal — overlapping
// address space across VRFs is the primary reason VRFs exist, and a metric that
// fires on it is one operators learn to ignore.
func TestVRFOverlapWithoutPBRSteeringEmitsNothing_7991(t *testing.T) {
	if got := gatherVRFOverlapSeries(t, vrfOverlapStore(t, false)); len(got) != 0 {
		t.Fatalf("xpf_vrf_overlap_pbr_admitted fired for plain VRF overlap with no PBR "+
			"steering: %v — that configuration commits on the strict path and is not "+
			"the tolerant-admitted state", got)
	}
}
