package cluster

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/psaab/xpf/pkg/config"
)

// #8435: an RG's incarnation boundary must purge EVERY per-RG authority map.
//
// `UpdateConfig`'s removal loop purged holdTimer, degradedTimer,
// monitorWeights, garpCounts and groups — but not transferOverrides. A
// stale override survived an RG being removed and re-added under the same id,
// and the subject then SELF-PROMOTED TO PRIMARY. Reproduced at master, with a
// control (identical remove + re-add without the override stays secondary)
// that makes it a defect rather than an observation.
//
// THIS IS THE FOURTH OF THESE. The loop's own comment calls garpCounts "the
// third same-id-re-add map-lifecycle gap in this loop after #5990", so #5990
// and #6027 are the first two. Both added a map to the loop and a test naming
// that map — and a cell naming three maps cannot see the fourth. That is
// exactly how this one survived them.
//
// So the guard here does not name maps. It ENUMERATES THEM FROM THE STRUCT by
// reflection, and fails on any RG-keyed map the removal loop leaves populated.
// A fifth map added to Manager is covered on the next run whether or not
// anyone remembers this file exists.

// rgKeyedMapFields returns every Manager field that is a map keyed by
// redundancy-group id, as (fieldName, keyForRG) pairs.
//
// Two key shapes are recognised: a bare `int` id, and a struct carrying an
// `rgID` field (monitorKey). Anything else is NOT silently skipped — the
// caller fails on it. A map shape this cannot classify is a map this guard
// cannot check, and skipping it quietly would reproduce the exact failure the
// file exists to prevent: a per-RG map nobody noticed was unpurged.
func rgKeyedMapFields(t *testing.T, rg int) []rgMapField8435 {
	t.Helper()
	rt := reflect.TypeOf(Manager{})
	var out []rgMapField8435
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Type.Kind() != reflect.Map {
			continue
		}
		if reason := notLocalRGAuthority8435[f.Name]; reason != "" {
			t.Logf("skipping Manager.%s: %s", f.Name, reason)
			continue
		}
		kt := f.Type.Key()
		switch {
		case kt.Kind() == reflect.Int:
			// `groups` is the RG table itself; it is purged by the same loop
			// and is not a satellite authority map, but including it costs
			// nothing and asserting it is purged is correct.
			out = append(out, rgMapField8435{name: f.Name, key: reflect.ValueOf(rg)})
		case kt.Kind() == reflect.Struct:
			// Reflection cannot SET an unexported field even inside the
			// declaring package, so struct keys need an explicit constructor.
			// That is deliberate rather than a workaround: a new RG-keyed map
			// with a new key struct fails here until someone classifies it,
			// which is precisely the "do not silently skip" property this guard
			// exists for. Enumeration stays reflective — the self-maintaining
			// half — while key construction is explicit and type-checked.
			key, ok := rgKeyForStruct8435(kt, rg)
			if !ok {
				if !structKeyMentionsRG8435(kt) {
					continue // struct-keyed map about something else
				}
				t.Fatalf("Manager.%s is keyed by %s, which carries an rgID but has no "+
					"constructor in rgKeyForStruct8435. Add one — do not let the guard "+
					"skip it. A per-RG map this cell cannot check is a per-RG map "+
					"nobody is checking, which is how #8435 survived #5990 and #6027.",
					f.Name, kt.Name())
			}
			out = append(out, rgMapField8435{name: f.Name, key: key})
		}
	}
	return out
}

// newManagerForRGPurge8435 builds a Manager with RG0 and the subject RG
// configured. RG0 stays present in both configs so the removal is of ONE
// incarnation rather than of the whole cluster — which is the shape the defect
// occurs in (remove + re-add under the same id, RG0 unaffected).
func newManagerForRGPurge8435(t *testing.T, rg int) *Manager {
	t.Helper()
	m := NewManager(0, 1)
	m.UpdateConfig(clusterConfigWithRG8435(rg))
	if _, ok := m.groups[rg]; !ok {
		t.Fatalf("precondition: RG%d must exist after UpdateConfig", rg)
	}
	return m
}

func clusterConfigWithRG8435(rg int) *config.ClusterConfig {
	return makeConfig(
		makeRG(0, false, map[int]int{0: 200}),
		makeRG(rg, false, map[int]int{0: 100}),
	)
}

func emptyClusterConfig8435() *config.ClusterConfig {
	return makeConfig(makeRG(0, false, map[int]int{0: 200}))
}

// rgKeyForStruct8435 builds a struct map key for `rg`. One arm per RG-keyed
// struct key type on Manager.
// notLocalRGAuthority8435 is the EXCLUSION list, and every entry is a claim
// that owes a justification. It is deliberately tiny: an exclusion is how a map
// stops being checked, so the bar for adding one is that the map is not local
// authority at all — not that purging it seemed unnecessary.
var notLocalRGAuthority8435 = map[string]string{
	"peerGroups": "an OBSERVATION, not local authority. The heartbeat handler " +
		"replaces the whole map (`m.peerGroups = newPeerGroups`, " +
		"heartbeat_manager.go), so it is refreshed wholesale every 200 ms and " +
		"carries what the PEER reports rather than anything this node decided. " +
		"Purging one entry on a local config change would be overwritten within " +
		"one heartbeat and would misrepresent the map as ours to reset.",
}

func rgKeyForStruct8435(kt reflect.Type, rg int) (reflect.Value, bool) {
	switch kt {
	case reflect.TypeOf(monitorKey{}):
		// The iface is left empty: the removal loop deletes every monitorWeights
		// entry whose rgID matches, regardless of interface, so one entry is
		// enough to detect a loop that stopped doing that.
		return reflect.ValueOf(monitorKey{rgID: rg}), true
	}
	return reflect.Value{}, false
}

// structKeyMentionsRG8435 reports whether a struct key type carries an rgID
// field — i.e. whether it is per-RG at all. Used only to decide between
// "skip, not our concern" and "fail, classify it".
func structKeyMentionsRG8435(kt reflect.Type) bool {
	_, ok := kt.FieldByName("rgID")
	return ok
}

// settable8435 returns an addressable, WRITABLE Value for an unexported field.
//
// reflect refuses to write an unexported field even inside the declaring
// package, and this guard's whole point is that it must not need a per-field
// accessor someone remembers to add. `reflect.NewAt` over the field's address
// is the standard same-package idiom for that, and it is confined to this test.
//
// The alternative — an explicit accessor per map — would reintroduce exactly
// the failure mode #8435 is: a list of maps someone maintains by hand, which
// stops covering the next one.
func settable8435(v reflect.Value) reflect.Value {
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}

type rgMapField8435 struct {
	name string
	key  reflect.Value
}

// TestEveryRGKeyedMapIsPurgedOnRemoval8435 is the guard.
func TestEveryRGKeyedMapIsPurgedOnRemoval8435(t *testing.T) {
	const rg = 1
	m := newManagerForRGPurge8435(t, rg)

	fields := rgKeyedMapFields(t, rg)

	// POSITIVE CONTROL on the enumeration itself. If reflection stops matching
	// — a renamed field, a changed key type, a Manager that stopped being a
	// struct — this returns nothing and every assertion below passes while
	// checking nothing. The three known RG-keyed maps must all be found, BY
	// NAME, here and only here: naming them in the assertion loop is what the
	// previous three cells did and is what let the fourth through.
	found := map[string]bool{}
	for _, f := range fields {
		found[f.name] = true
	}
	for _, want := range []string{"groups", "monitorWeights", "garpCounts", "transferOverrides"} {
		if !found[want] {
			t.Fatalf("the reflection enumeration did not find Manager.%s, which IS "+
				"an RG-keyed map. The scan is broken, not the tree — a clean result "+
				"from it would mean nothing. Found: %v", want, found)
		}
	}

	// Populate every enumerated map for this RG.
	mv := reflect.ValueOf(m).Elem()
	for _, f := range fields {
		mp := settable8435(mv.FieldByName(f.name))
		if mp.IsNil() {
			mp.Set(reflect.MakeMap(mp.Type()))
		}
		// Only where absent. `groups` is already populated by UpdateConfig with
		// a real *rgState, and overwriting it with a zero value (a NIL pointer)
		// makes the removal loop dereference nil — the guard would then be
		// testing its own fixture rather than the loop.
		if !mp.MapIndex(f.key).IsValid() {
			mp.SetMapIndex(f.key, reflect.New(mp.Type().Elem()).Elem())
		}
	}

	// The incarnation boundary: a config that no longer contains this RG.
	m.UpdateConfig(emptyClusterConfig8435())

	for _, f := range fields {
		mp := settable8435(mv.FieldByName(f.name))
		if mp.MapIndex(f.key).IsValid() {
			t.Errorf("Manager.%s still holds an entry for RG %d after it was removed "+
				"from the config.\n\n"+
				"Every per-RG authority map must be purged at the incarnation "+
				"boundary, or a same-id re-add inherits this incarnation's state. "+
				"For transferOverrides that inheritance is a DUAL-PRIMARY "+
				"(#8435); for garpCounts it was a stale ARP count (#6027); for the "+
				"ip-monitor maps it was #5990. This is the fourth. Add the delete to "+
				"the removal loop in group_state.go.", f.name, rg)
		}
	}
}

// TestARetainedRGKeepsItsMaps8435 is the control, and without it every
// assertion above passes against a loop that purges every map unconditionally
// — which would drop the state of RGs that are still configured.
func TestARetainedRGKeepsItsMaps8435(t *testing.T) {
	const rg = 1
	m := newManagerForRGPurge8435(t, rg)

	mv := reflect.ValueOf(m).Elem()
	fields := rgKeyedMapFields(t, rg)
	for _, f := range fields {
		mp := settable8435(mv.FieldByName(f.name))
		if mp.IsNil() {
			mp.Set(reflect.MakeMap(mp.Type()))
		}
		// Only where absent. `groups` is already populated by UpdateConfig with
		// a real *rgState, and overwriting it with a zero value (a NIL pointer)
		// makes the removal loop dereference nil — the guard would then be
		// testing its own fixture rather than the loop.
		if !mp.MapIndex(f.key).IsValid() {
			mp.SetMapIndex(f.key, reflect.New(mp.Type().Elem()).Elem())
		}
	}

	// The SAME RG is still in the config.
	m.UpdateConfig(clusterConfigWithRG8435(rg))

	kept := 0
	for _, f := range fields {
		if settable8435(mv.FieldByName(f.name)).MapIndex(f.key).IsValid() {
			kept++
		}
	}
	if kept == 0 {
		t.Fatal("a config that still contains the RG purged EVERY per-RG map. The " +
			"removal loop must key on the RG being absent, not run unconditionally " +
			"— otherwise it drops live state on every commit.")
	}
}
