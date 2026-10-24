package api

import (
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// #16202: three-way agreement between the descriptor table, Describe,
// and the struct fields assigned by each family's init. Collect-side
// agreement (every emitted Desc is described) stays with the #1726
// pedantic canary, which drives the real Collect; this test covers
// the surfaces the table now owns and cannot be checked by Gather
// alone: a field assigned by an init but missing from its family row
// would never be described (a checked-collector scrape error the
// moment Collect emits it), and a row naming a field its init does
// not assign would describe a nil or stale Desc.
//
// MUTATION (each must red):
//   - remove one entry from a collectorDesc<Family> slice -> the
//     "missing from its family row" check fails (and Describe loses it).
//   - add a collector field's index to the wrong family, or a second
//     copy to another family -> the duplicate check fails.
//   - drop one fam.init call path by emptying a family's init in the
//     table (name a no-op) -> its fields stay nil and the nil check
//     fails.
func TestCollectorDescriptorTableAgreement16202(t *testing.T) {
	// (a) Table hygiene: every row has a name and an init, every field
	// index resolves to a distinct *prometheus.Desc struct field, and
	// together the rows cover every *prometheus.Desc field exactly once.
	collectorType := reflect.TypeOf(xpfCollector{})
	descType := reflect.TypeOf((*prometheus.Desc)(nil))
	structFields := map[int]string{}
	for i := range collectorType.NumField() {
		if collectorType.Field(i).Type == descType {
			structFields[i] = collectorType.Field(i).Name
		}
	}
	if len(structFields) == 0 {
		t.Fatal("no *prometheus.Desc fields found on xpfCollector — fixture broken")
	}
	seen := map[int]string{} // field index -> family name
	for _, fam := range collectorDescFamilies {
		if fam.name == "" {
			t.Error("collectorDescFamilies row with empty name")
		}
		if fam.init == nil {
			t.Errorf("family %q has nil init", fam.name)
		}
		if len(fam.fields) == 0 {
			t.Errorf("family %q has no fields", fam.name)
		}
		for _, idx := range fam.fields {
			name, ok := structFields[idx]
			if !ok {
				t.Errorf("family %q names field index %d, which is not a *prometheus.Desc field", fam.name, idx)
				continue
			}
			if prev, dup := seen[idx]; dup {
				t.Errorf("descriptor field %s is listed in both family %q and family %q", name, prev, fam.name)
			}
			seen[idx] = fam.name
		}
	}
	for idx, name := range structFields {
		if _, ok := seen[idx]; !ok {
			t.Errorf("descriptor field %s (index %d) is in no collectorDescFamilies row — "+
				"it will never be described", name, idx)
		}
	}

	// (b) Init agreement: run each family's init on a fresh collector
	// and require that it assigns exactly the fields its row names —
	// no assigned-but-unlisted field (invisible to Describe) and no
	// listed-but-unassigned field (nil in Describe).
	for _, fam := range collectorDescFamilies {
		fresh := &xpfCollector{}
		fam.init(fresh)
		fv := reflect.ValueOf(fresh).Elem()
		listed := map[int]bool{}
		for _, idx := range fam.fields {
			listed[idx] = true
		}
		for idx, name := range structFields {
			assigned := !fv.Field(idx).IsNil()
			switch {
			case assigned && !listed[idx]:
				t.Errorf("family %q init assigns descriptor field %s, but its table row does not list it — "+
					"Describe will omit it (checked-collector scrape error when Collect emits it)", fam.name, name)
			case !assigned && listed[idx]:
				t.Errorf("family %q table row lists descriptor field %s, but its init does not assign it — "+
					"Describe will send a nil Desc", fam.name, name)
			}
		}
	}

	// (c) Describe agreement: a fully initialized collector describes
	// exactly the struct's descriptor fields, by pointer identity, with
	// no nils and no duplicates — the registry side of the three-way
	// check (registry + Collect are exercised by the #1726 canary).
	c := newCollector(nil)
	described := describedSet(c)
	if len(described) != len(structFields) {
		t.Errorf("Describe sent %d distinct descriptors, want %d (one per struct field)",
			len(described), len(structFields))
	}
	for idx, name := range structFields {
		desc := collectorDescField(c, idx)
		if desc == nil {
			t.Errorf("descriptor field %s is nil after newCollector", name)
			continue
		}
		if _, ok := described[desc]; !ok {
			t.Errorf("descriptor field %s (%s) is missing from Describe output", name, descName(desc))
		}
	}
	// Duplicate sends collapse in the set above, so count raw sends too.
	ch := make(chan *prometheus.Desc, 4096)
	c.Describe(ch)
	close(ch)
	raw := 0
	names := map[string]int{}
	for d := range ch {
		raw++
		if d == nil {
			t.Error("Describe sent a nil *prometheus.Desc")
			continue
		}
		names[descName(d)]++
	}
	if raw != len(structFields) {
		t.Errorf("Describe sent %d descriptors, want exactly %d", raw, len(structFields))
	}
	for name, n := range names {
		if n != 1 {
			t.Errorf("descriptor %s described %d times, want 1", name, n)
		}
	}
	if names["xpf_packets_total"] != 1 {
		t.Error("sanity: xpf_packets_total not among described names — name extraction broken")
	}
}

// TestDescribeDoesNotAllocate16202 pins the issue's static-allocation
// requirement: Describe must not allocate per call (the table is a
// package-level var; a version rebuilt per Describe would show up here).
func TestDescribeDoesNotAllocate16202(t *testing.T) {
	c := newCollector(nil)
	// Warm up, then measure steady-state allocations.
	for i := 0; i < 3; i++ {
		dch := make(chan *prometheus.Desc, 4096)
		go func() { c.Describe(dch); close(dch) }()
		for range dch {
		}
	}
	allocs := testing.AllocsPerRun(10, func() {
		dch := make(chan *prometheus.Desc, 4096)
		go func() { c.Describe(dch); close(dch) }()
		for range dch {
		}
	})
	// Channel + goroutine plumbing dominates; the table iteration
	// itself must be allocation-free, so allow only plumbing slack.
	if allocs > 8 {
		t.Errorf("Describe allocates %.1f per run, want near-zero (table must stay static, #16202)", allocs)
	}
}
