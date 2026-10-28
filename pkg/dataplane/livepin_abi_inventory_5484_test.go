package dataplane

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// TestUserspaceABICheckedPinnedMapsCoversAllRequiredPins is the #5484 core:
// the live-pin ABI pre-flight inventory (userspaceABICheckedPinnedMaps) must
// cover every required pin — both the shim-declared PinByName maps
// (userspacePinnedShimMaps) and the Go-created/replaced shared maps
// (userspaceShimSharedMapSpecs) — minus only maps whose contents are rebuilt
// before the new dataplane is activated.
//
// Before the fix the set was userspacePinnedShimMaps() minus rebuilt maps only,
// so the state-bearing shared maps the shim does not declare — sessions_v6,
// and the HA/per-CPU maps (rg_active, ha_watchdog,
// session_id_gen, the *_counters) — were never ABI-checked. An incompatible
// live pin for one of those passed the deploy pre-flight and then failed
// ErrMapIncompatible in loadUserspaceShimSharedMaps AFTER the old daemon was
// stopped, stranding the node fail-closed. RED-on-revert: the pre-fix inventory
// omits every shared-spec-only name asserted below.
func TestUserspaceABICheckedPinnedMapsCoversAllRequiredPins(t *testing.T) {
	t.Parallel()

	got := userspaceABICheckedPinnedMaps()

	set := make(map[string]int, len(got))
	for _, n := range got {
		set[n]++
	}

	// No duplicates.
	for n, c := range set {
		if c != 1 {
			t.Fatalf("map %q appears %d times, want deduplicated single entry", n, c)
		}
	}

	// Rebuilt maps are reconciled before collection loading rather than refused
	// by the read-only live-pin pre-flight.
	for _, name := range userspaceRebuiltCollectionPinMapNames {
		if _, ok := set[name]; ok {
			t.Fatalf("ABI-checked set must exclude rebuilt map %s", name)
		}
	}

	// Spot-check the previously-omitted state-bearing shared maps that the #5484
	// stranding scenario turns on.
	for _, want := range []string{
		"sessions_v6", "ha_watchdog", "rg_active",
		"session_id_gen", "interface_counters", "nat_rule_counters",
	} {
		if _, ok := set[want]; !ok {
			t.Fatalf("ABI-checked set omits %q (would strand node fail-closed on an incompatible live pin)", want)
		}
	}

	// Completeness: the set must equal the union of both required-pin sources
	// minus maps intentionally rebuilt on load — the exact invariant enforced
	// by userspaceRequiredShimPins.
	want := make(map[string]struct{})
	for _, n := range userspacePinnedShimMaps() {
		if !isUserspaceRebuiltCollectionPinMap(n) {
			want[n] = struct{}{}
		}
	}
	for _, s := range userspaceShimSharedMapSpecs() {
		if !isUserspaceRebuiltCollectionPinMap(s.Name) {
			want[s.Name] = struct{}{}
		}
	}
	if len(set) != len(want) {
		t.Fatalf("ABI-checked set has %d maps, want %d (union of both required-pin sources minus rebuilt maps)", len(set), len(want))
	}
	for n := range want {
		if _, ok := set[n]; !ok {
			t.Fatalf("ABI-checked set omits required pin %q", n)
		}
	}
}

// TestABICheckedMapProvenance documents HOW each newly covered map is confirmed
// embedded+pinned, and that abiCheckedRefSpec resolves it to the right shape:
//
//   - sessions_v6 and the HA/counter maps are Go-created shared maps (present in
//     userspaceShimSharedMapSpecs, ABSENT from the shim ELF), so their reference
//     is the Go SSOT spec — the shape loadUserspaceShimSharedMaps creates+pins.
//
// This is the production-accurate resolution: in production the shim never
// declares sessions_v6/HA maps, so the fix MUST fall back to the Go SSOT.
func TestABICheckedMapProvenance(t *testing.T) {
	t.Parallel()

	spec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load Rust userspace XDP spec: %v", err)
	}

	shared := make(map[string]bool)
	for _, s := range userspaceShimSharedMapSpecs() {
		shared[s.Name] = true
	}
	// sessions_v6 + HA/counter maps: Go-created shared maps, NOT shim-declared.
	for _, name := range []string{"sessions_v6", "rg_active", "ha_watchdog", "session_id_gen", "global_counters", "nat_port_counters"} {
		if !shared[name] {
			t.Errorf("%s not in userspaceShimSharedMapSpecs (Go SSOT)", name)
		}
		if spec.Maps[name] != nil {
			t.Errorf("%s unexpectedly declared by the shim ELF; expected Go-created only", name)
		}
		// abiCheckedRefSpec must fall back to the Go SSOT (value-equal to
		// sharedShimMapSpecByName; userspaceShimSharedMapSpecs rebuilds fresh
		// pointers each call, so compare by name + ABI shape, not identity).
		got := abiCheckedRefSpec(spec, name)
		wantSpec := sharedShimMapSpecByName(name)
		if got == nil || wantSpec == nil || got.Name != name || mapABIFromSpec(got) != mapABIFromSpec(wantSpec) {
			t.Errorf("abiCheckedRefSpec(%s) must resolve to the Go SSOT shared spec (got %+v)", name, got)
		}
	}
}

// sharedMapLivePinReader returns a fake live-pin reader that reports one target
// shared map's pinned shape as `drift` (exists=true) and every other map as its
// base-spec shape (or absent for maps not in the base spec). It models a running
// daemon whose shared-map pin drifted from the new dataplane's Go SSOT shape —
// the production scenario, where the target map is NOT in the shim spec and so
// abiCheckedRefSpec must fall back to the Go SSOT to find its reference shape.
func sharedMapLivePinReader(base *ebpf.CollectionSpec, target string, drift userspaceMapABI) userspacePinnedMapABIReader {
	return func(path string) (userspaceMapABI, bool, error) {
		name := filepath.Base(path)
		if name == target {
			return drift, true, nil
		}
		if ms, ok := base.Maps[name]; ok {
			return mapABIFromSpec(ms), true, nil
		}
		return userspaceMapABI{}, false, nil
	}
}

// TestValidateUserspaceShimSpecSharedMapLivePinABI proves the Part-1 fix on the
// production-accurate path: a Go-created shared map the shim does NOT declare
// (sessions_v6, sessions, the HA maps, a per-CPU counter) whose live pin drifts
// from the new dataplane's Go SSOT shape is now rejected at the pre-flight —
// before the old daemon is stopped — instead of failing ErrMapIncompatible in
// loadUserspaceShimSharedMaps AFTER the stop. The target map is deliberately
// absent from the (synthetic) shim spec, so abiCheckedRefSpec resolves it via
// the Go SSOT fallback, exactly as in production. A matching pin passes (no
// false failure). RED-on-revert: the pre-#5484 inventory never iterates these
// names, so the drifted pin is never read and the deploy passes.
func TestValidateUserspaceShimSpecSharedMapLivePinABI(t *testing.T) {
	t.Parallel()

	targets := []string{
		"sessions_v6",
		"sessions",
		"rg_active",
		"ha_watchdog",
		"session_id_gen",
		"nat_port_counters",
		"global_counters",
		"interface_counters",
	}
	for _, target := range targets {
		target := target
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			base := validABIBaseSpec()
			ref := sharedShimMapSpecByName(target)
			if ref == nil {
				t.Fatalf("no Go SSOT spec for %s", target)
			}
			// The target is NOT in the shim (base) spec — the production reality.
			if base.Maps[target] != nil {
				t.Fatalf("test invariant: %s must be absent from the base shim spec", target)
			}
			correct := mapABIFromSpec(ref)

			// RED-on-revert guard: the pre-#5484 validator accepts the base spec, so
			// the ONLY reject signal is the new shared-map live-pin comparison.
			if err := legacyPresenceMaxEntriesValidate(base); err != nil {
				t.Fatalf("legacy validator rejected base (%v); cannot prove RED-on-revert", err)
			}

			// A matching live pin passes (fail-safe: healthy deploy, no false fail).
			if err := validateUserspaceShimSpecWith(base, sharedMapLivePinReader(base, target, correct)); err != nil {
				t.Fatalf("matching %s live pin must pass, got: %v", target, err)
			}

			// A drifted live pin (MaxEntries bumped) is rejected, naming the map.
			drift := correct
			drift.MaxEntries++
			err := validateUserspaceShimSpecWith(base, sharedMapLivePinReader(base, target, drift))
			if err == nil {
				t.Fatalf("want %s live-pin ABI mismatch, got nil (would brick post-stop after ErrMapIncompatible)", target)
			}
			// #5363: the live pin is always the STALE side (the running daemon's
			// pin predates this build's shim ABI), so the remediation is a full
			// reload, not `make generate`.
			for _, want := range []string{target, "MaxEntries", "ABI-incompatible", userspaceShimStalePinRemediation} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want substring %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "make generate-userspace-xdp") {
				t.Fatalf("err = %v, live-pin mismatch must NOT tell the operator to rebuild the shim", err)
			}
		})
	}
}
