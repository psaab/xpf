// Package dataplane: retained Rust AF_XDP shim loader.
//
// This file holds the loader graph that survived the #1476
// mechanical source removal of the legacy XDP/TC eBPF dataplane.
// Before #1476 this graph lived alongside the legacy
// loadAllObjects() bpf2go bootstrap in loader_ebpf.go; that file
// is gone now. The retained shim is owned by the Rust
// userspace-xdp/ crate, compiled via build-userspace-xdp.sh and
// embedded into the Go binary by userspace_xdp_rust.go.
//
// Manager.LoadUserspaceShim() and Manager.CompileUserspaceShim()
// in loader.go are the production entry points; everything below
// is their plumbing.
package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	bpfPinPath                       = "/sys/fs/bpf/xpf"
	userspaceShimGenerateRemediation = "Re-run `make generate-userspace-xdp`."
	// userspaceShimStalePinRemediation is the remediation for a GENUINE LIVE-PIN
	// ABI mismatch (validateUserspaceShimLivePins): the running daemon's pinned
	// map predates this build's shim-map ABI. That is NOT an embedded-vs-Go SSOT
	// drift — the embedded shim is the intended deploy target and is not broken
	// — so `make generate` is the WRONG action.
	//
	// Whether a restart clears the pin is MODE-DEPENDENT, and this message has
	// now been wrong in BOTH directions (#6928). It said "a reload" until r5,
	// which never releases a pin at all. r5 replaced that with the opposite
	// categorical claim — that restarting NEVER releases it and only `xpfd
	// cleanup` does — and that is also false: `Cleanup()` (loader.go) does
	// `os.RemoveAll(bpfPinPath)` and has TWO production reference sites, the
	// `xpfd cleanup` subcommand AND `Manager.Teardown` (indirectly since
	// #6743, through the `teardownCleanupFn` seam var). `daemon_run_shutdown.go`
	// calls `Teardown` on every NON-hitless shutdown ("HA shutdown: tearing
	// down BPF state"), so on that path the pins are already gone and a plain
	// restart is sufficient. Only a HITLESS shutdown takes `Manager.Close`,
	// which deliberately leaves the pins for the next daemon to reuse — that is
	// the path where a restart hits this identical refusal.
	//
	// The message must therefore state the dependency rather than either
	// categorical, and must lead with the TARGETED recovery (unlink the one
	// named pin, docs/operations/userspace-shim-pin-recovery.md) rather than
	// `xpfd cleanup`, which additionally GCs every other pinned dataplane map
	// and clears the FRR managed routes (cmd/xpfd/main.go). Getting this wrong
	// is worse than an inaccurate comment: it is what an operator follows
	// mid-upgrade with the dataplane down, and the r5 form pointed at a
	// destructive action, understated what it destroys, and did so in a mode
	// where a restart would have sufficed.
	//
	// #5364: this message is NOT reachable for a userspace_cpumap MaxEntries
	// gap. That map is a BPF_MAP_TYPE_CPUMAP whose MaxEntries the kernel/loader
	// clamps to nr_possible_cpus (the shim's `CpuMap::with_max_entries(256, 0)`
	// is only a template max), so a fresh daemon ALWAYS pins it at
	// nr_possible_cpus, never 256. livePinRefABI applies the identical clamp to
	// the reference shape, so the old "cpumap=16 pin vs embedded cpumap=256
	// shim" diff that #5363 mischaracterized as a stale pin (and that blocked
	// EVERY rolling cluster-deploy) is no longer produced. This remediation now
	// fires only for a real cross-version ABI break of a NON-cpumap map, or a
	// genuine cpumap Type/KeySize/ValueSize/Flags change.
	userspaceShimStalePinRemediation = "The RUNNING daemon's pinned map predates " +
		"this build's shim-map ABI. A rolling deploy cannot cross a shim-map ABI " +
		"change while the old pin is still present: a bpffs pin outlives the " +
		"process that made it. Whether a restart is enough DEPENDS ON HOW xpfd " +
		"LAST STOPPED — a hitless shutdown preserves the pins on purpose, so a " +
		"restart hits this same refusal; a non-hitless HA shutdown tears them " +
		"down, so a restart already suffices. TARGETED RECOVERY (try this " +
		"first): stop xpfd, unlink ONLY the pin path named above, start xpfd — " +
		"see docs/operations/userspace-shim-pin-recovery.md. `xpfd cleanup` also " +
		"clears it but is far broader: it removes EVERY pinned dataplane map " +
		"(sessions, DNAT and all compatibility state) and clears the FRR managed " +
		"routes. Either way brief downtime is unavoidable. Do NOT `make " +
		"generate` (the embedded shim is the intended target, not broken). See " +
		"pkg/dataplane/README.md (#1864)."
	userspaceBindingsMapName           = "userspace_bindings"
	userspaceIngressIfacesMapName      = "userspace_ingress_ifaces"
	userspaceHeartbeatMapName          = "userspace_heartbeat"
	userspaceXskMapName                = "userspace_xsk_map"
	userspaceShimCompatibilityDNATName = "dnat_table"
	// userspaceShimCompatibilityDNATV6Name is the IPv6 reverse-NAT steering
	// table. Like dnat_table it is BOTH declared by the shim ELF and replaced at
	// load (opts.MapReplacements["dnat_table_v6"]); #5484 pulls it into the same
	// ABI arms dnat_table already had.
	userspaceShimCompatibilityDNATV6Name = "dnat_table_v6"
	// userspaceFallbackStatsMapName is the internal mixed-version compatibility
	// name for the degraded-path counter map (operator surface:
	// degraded_path_counters). #4113 changed its BPF type from Array to
	// PerCpuArray; it is a collection-pinned map, so a stale incompatible pin
	// must be reconciled on upgrade (see reconcileDisposableCollectionPin).
	userspaceFallbackStatsMapName = "userspace_fallback_stats"
)

// pinnedMaps lists maps that survive daemon restarts via BPF
// filesystem pins. Config-derived maps are repopulated from config
// on every Compile(). Infrastructure maps (per-CPU scratch,
// counters) are recreated fresh each time.
//
// After #1476 this set is narrowed to the userspace shim's shared
// maps only. The legacy PROG_ARRAY pins (xdp_progs, tc_progs) and
// the legacy per-CPU policer_states pin are dropped — they no
// longer exist as kernel objects because no legacy program loads
// them. cleanupUserspaceShimLegacyOnlyMapPins() in shim_pins.go
// removes the stale pins from disk on first boot after upgrade.
var pinnedMaps = map[string]bool{
	"sessions":          true,
	"sessions_v6":       true,
	"dnat_table":        true,
	"dnat_table_v6":     true,
	"nat64_state":       true,
	"nat_port_counters": true, // retained shim shared state (loader_ebpf.go used to also list this — kept here)
}

// loadUserspaceShimObjects loads the retained Rust AF_XDP shim
// collection and pins the shared maps that the userspace runtime
// still exchanges with Go.
func (m *Manager) loadUserspaceShimObjects() error {
	if err := os.MkdirAll(bpfPinPath, 0700); err != nil {
		return fmt.Errorf("create pin path %s: %w", bpfPinPath, err)
	}

	if err := m.loadUserspaceShimObjectsOnce(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) loadUserspaceShimObjectsOnce() (err error) {
	sharedMaps, err := loadUserspaceShimSharedMaps()
	if err != nil {
		return err
	}
	keepShared := false
	defer func() {
		if keepShared {
			return
		}
		closeUniqueMaps(sharedMaps)
	}()

	userspaceSpec, err := loadRustUserspaceXDP()
	if err != nil {
		return fmt.Errorf("load Rust xdp_userspace spec: %w", err)
	}
	if err := validateUserspaceShimSpec(userspaceSpec); err != nil {
		return err
	}
	for _, name := range userspacePinnedShimMaps() {
		if ms, ok := userspaceSpec.Maps[name]; ok {
			ms.Pinning = ebpf.PinByName
		}
	}

	// #4113 upgrade migration: userspace_fallback_stats changed from Array to
	// PerCpuArray. It is pinned by the collection load below (PinByName), whose
	// compatibility check rejects a stale Array pin from a previous daemon with
	// ErrMapIncompatible — aborting the whole shim load and bricking a rolling
	// upgrade (#1917/#1960 class). Drop the incompatible pin first so the load
	// recreates it fresh. Safe because it is a DISPOSABLE degraded-path counter
	// (resets on every reload); DATA maps are never reset here.
	if spec, ok := userspaceSpec.Maps[userspaceFallbackStatsMapName]; ok {
		pinPath := filepath.Join(bpfPinPath, userspaceFallbackStatsMapName)
		if err := reconcileDisposableCollectionPin(pinPath, spec); err != nil {
			return err
		}
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpfPinPath,
		},
		MapReplacements: map[string]*ebpf.Map{},
	}
	if dnat := sharedMaps["dnat_table"]; dnat != nil {
		opts.MapReplacements["dnat_table"] = dnat
	}
	// #2406: bind the shim's dnat_table_v6 reader to the Go-created/pinned
	// shared map so SNAT66-return entries published by the userspace-dp
	// helper (publish_dnat_table_entry v6 arm) are visible to the shim's
	// GRE-inner v6 classify (dnat_lookup_v6). Mirrors the v4 binding above.
	if dnatV6 := sharedMaps["dnat_table_v6"]; dnatV6 != nil {
		opts.MapReplacements["dnat_table_v6"] = dnatV6
	}
	userspaceCollection, err := ebpf.NewCollectionWithOptions(userspaceSpec, opts)
	if err != nil {
		return fmt.Errorf("load Rust xdp_userspace collection: %w", err)
	}

	userspaceProg, ok := userspaceCollection.Programs[userspaceShimEntryProg]
	if !ok {
		userspaceCollection.Close()
		return fmt.Errorf("Rust %s not found", userspaceShimEntryProg)
	}
	for _, pin := range userspaceRequiredShimPins() {
		umap := userspaceCollection.Maps[pin.name]
		if umap == nil {
			if shared := sharedMaps[pin.name]; shared != nil {
				umap = shared
			}
		}
		if err := ensureUserspaceMapPinned(pin.name, umap, pin.path); err != nil {
			userspaceCollection.Close()
			return err
		}
	}

	// #2114 A3: the registry assignments (program + both map loops) AND
	// the armed flag publish as ONE whole-batch critical section —
	// acquisition above (collection construction, program lookup,
	// pinning) stays unlocked, the publication is the short locked
	// publisher body.
	m.publishShimRegistryLocked(userspaceProg, userspaceCollection.Maps, sharedMaps)
	keepShared = true
	return nil
}

// validateUserspaceShimSpec is the deploy pre-flight ABI gate. It runs from
// three call sites: the build-time verifier (cmd/shimverify), the deploy
// pre-flight (xpfd verify-dataplane, which runs BEFORE the old daemon is
// stopped — README #1864 §3), and the daemon's own shim load. It rejects a
// shim whose maps drift from the Go-side contract OR from the RUNNING daemon's
// live pinned maps, so an ABI incompatibility is caught HERE — while the old
// dataplane still forwards — instead of surfacing as ErrMapIncompatible at
// NewCollectionWithOptions AFTER the old daemon has been stopped (which strands
// the node fail-closed; #5307).
func validateUserspaceShimSpec(userspaceSpec *ebpf.CollectionSpec) error {
	return validateUserspaceShimSpecWith(userspaceSpec, readPinnedShimMapABI)
}

// validateUserspaceShimSpecWith is validateUserspaceShimSpec with an injectable
// live-pin reader, so the ABI comparison can be exercised without root/bpffs.
func validateUserspaceShimSpecWith(userspaceSpec *ebpf.CollectionSpec, readPin userspacePinnedMapABIReader) error {
	if ms, ok := userspaceSpec.Maps[userspaceBindingsMapName]; !ok {
		return fmt.Errorf("Rust xdp_userspace spec missing map userspace_bindings")
	} else if ms.MaxEntries != BindingArrayMaxEntries {
		return userspaceBindingsMaxEntriesDriftError(ms.MaxEntries)
	}
	if ms, ok := userspaceSpec.Maps[userspaceIngressIfacesMapName]; !ok {
		return fmt.Errorf("Rust xdp_userspace spec missing map userspace_ingress_ifaces")
	} else if ms.MaxEntries != MaxInterfaces {
		return userspaceIngressIfacesMaxEntriesDriftError(ms.MaxEntries)
	}
	for _, name := range []string{userspaceHeartbeatMapName, userspaceXskMapName} {
		ms, ok := userspaceSpec.Maps[name]
		if !ok {
			return fmt.Errorf("Rust xdp_userspace spec missing map %s", name)
		}
		if ms.MaxEntries != BindingSlotMapMaxEntries {
			return userspaceSlotMapMaxEntriesDriftError(name, ms.MaxEntries)
		}
	}
	if ms, ok := userspaceSpec.Maps[userspaceShimCompatibilityDNATName]; !ok {
		return fmt.Errorf("Rust xdp_userspace spec missing map dnat_table")
	} else if ms.MaxEntries != userspaceShimMaxSessions {
		return fmt.Errorf(
			"dnat_table max_entries drift: embedded=%d, expected=%d (userspace shim compatibility map). %s",
			ms.MaxEntries, userspaceShimMaxSessions, userspaceShimGenerateRemediation,
		)
	} else if ms.Flags&unix.BPF_F_NO_PREALLOC == 0 {
		return fmt.Errorf(
			"dnat_table flags drift: embedded=%d, expected BPF_F_NO_PREALLOC (userspace shim compatibility map). %s",
			ms.Flags, userspaceShimGenerateRemediation,
		)
	} else if err := validateSharedMapExpectedABI(ms, userspaceShimCompatibilityDNATName); err != nil {
		return err
	}
	// #5484: dnat_table_v6 is declared by the shim AND replaced at load, exactly
	// like dnat_table, but was omitted from every expected-shape arm — so an
	// embedded v6 DNAT ABI drift was invisible on a fresh node (no live pin to
	// compare against). Validate its embedded shape against the Go SSOT
	// (userspaceShimSharedMapSpecs). Guarded on presence rather than mandatory so
	// a synthetic/partial spec that omits the v6 table still exercises the other
	// arms; the real embedded shim always declares dnat_table_v6 (#2406). The
	// running-daemon case is covered by the live-pin arm below, which now
	// includes dnat_table_v6 in its ABI-checked set.
	if ms, ok := userspaceSpec.Maps[userspaceShimCompatibilityDNATV6Name]; ok {
		if ms.MaxEntries != userspaceShimMaxSessions {
			return fmt.Errorf(
				"dnat_table_v6 max_entries drift: embedded=%d, expected=%d (userspace shim compatibility map). %s",
				ms.MaxEntries, userspaceShimMaxSessions, userspaceShimGenerateRemediation,
			)
		}
		if ms.Flags&unix.BPF_F_NO_PREALLOC == 0 {
			return fmt.Errorf(
				"dnat_table_v6 flags drift: embedded=%d, expected BPF_F_NO_PREALLOC (userspace shim compatibility map). %s",
				ms.Flags, userspaceShimGenerateRemediation,
			)
		}
		if err := validateSharedMapExpectedABI(ms, userspaceShimCompatibilityDNATV6Name); err != nil {
			return err
		}
	}
	// #5307/#5484: compare the embedded shim's map ABI against the RUNNING
	// daemon's live pins so ErrMapIncompatible is caught pre-stop, not post-stop.
	return validateUserspaceShimLivePins(userspaceSpec, readPin)
}

// userspaceMapABI carries exactly the fields cilium/ebpf's MapSpec.Compatible
// compares at a PinByName load (Type, KeySize, ValueSize, MaxEntries, Flags) —
// i.e. the set an ErrMapIncompatible flags. See cilium/ebpf map.go
// MapSpec.Compatible.
type userspaceMapABI struct {
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

func mapABIFromSpec(ms *ebpf.MapSpec) userspaceMapABI {
	return userspaceMapABI{
		Type:       ms.Type,
		KeySize:    ms.KeySize,
		ValueSize:  ms.ValueSize,
		MaxEntries: ms.MaxEntries,
		Flags:      ms.Flags,
	}
}

// livePinRefABI is the reference ABI shape the live-pin comparison diffs against
// the RUNNING daemon's pinned map. For every map except a BPF_MAP_TYPE_CPUMAP it
// is the reference spec's shape verbatim (mapABIFromSpec). For a CPUMAP it
// applies the SAME nr_possible_cpus MaxEntries clamp cilium/ebpf's
// MapSpec.fixupMagicFields runs before it creates OR ABI-compares the map: a
// CPUMAP's MaxEntries is clamped to PossibleCPU() (the shim's
// `CpuMap::with_max_entries(256, 0)` is only a template max cap), so the map is
// created — and pinned — at nr_possible_cpus, never the .o's 256. MapSpec.Compatible
// (the exact ErrMapIncompatible check this pre-flight predicts) runs the identical
// fixup, so without this clamp the pre-flight rejects EVERY rolling deploy on a
// phantom "MaxEntries embedded=256 pinned=<nr_possible_cpus>" diff even though the
// real PinByName load compares <nr_possible_cpus>==<nr_possible_cpus> and succeeds
// (#5364). The relaxation is scoped to CPUMAP: no other ABI-checked shim map is
// CPU-count-sized — per-CPU ARRAY/HASH maps keep their declared MaxEntries and
// replicate the VALUE per-CPU, and XskMap keeps its declared size — so every other
// map keeps a strict MaxEntries check. A genuine cpumap ABI change still diffs on
// Type/KeySize/ValueSize/Flags (and on MaxEntries when the pin drops below
// nr_possible_cpus).
func livePinRefABI(ref *ebpf.MapSpec) userspaceMapABI {
	abi := mapABIFromSpec(ref)
	if ref.Type == ebpf.CPUMap {
		abi.MaxEntries = cpuMapFixupMaxEntries(abi.MaxEntries)
	}
	return abi
}

// cpuMapFixupMaxEntries mirrors the CPUMap arm of cilium/ebpf
// MapSpec.fixupMagicFields: clamp MaxEntries to nr_possible_cpus when the
// declared value is 0 or exceeds the CPU count. This is the shape the loader
// actually creates+pins and the shape MapSpec.Compatible compares against, so
// the live-pin pre-flight must use it to avoid a false MaxEntries rejection.
func cpuMapFixupMaxEntries(declared uint32) uint32 {
	n := uint32(ebpf.MustPossibleCPU())
	if declared == 0 || declared > n {
		return n
	}
	return declared
}

// userspaceMapABIDiff reports the first ABI field in which the embedded shim map
// spec differs from a reference shape (the Go expected shape or the live pinned
// map), or "" when compatible. It mirrors cilium/ebpf MapSpec.Compatible: Type,
// KeySize, ValueSize, MaxEntries, Flags — the exact set an ErrMapIncompatible
// flags at PinByName load. None of the shim's ABI-checked pinned maps is a
// DevMap/DevMapHash, so Compatible's BPF_F_RDONLY_PROG flag exception does not
// apply here.
func userspaceMapABIDiff(embedded, ref userspaceMapABI) string {
	switch {
	case embedded.Type != ref.Type:
		return fmt.Sprintf("Type embedded=%s pinned=%s", embedded.Type, ref.Type)
	case embedded.KeySize != ref.KeySize:
		return fmt.Sprintf("KeySize embedded=%d pinned=%d", embedded.KeySize, ref.KeySize)
	case embedded.ValueSize != ref.ValueSize:
		return fmt.Sprintf("ValueSize embedded=%d pinned=%d", embedded.ValueSize, ref.ValueSize)
	case embedded.MaxEntries != ref.MaxEntries:
		return fmt.Sprintf("MaxEntries embedded=%d pinned=%d", embedded.MaxEntries, ref.MaxEntries)
	case embedded.Flags != ref.Flags:
		return fmt.Sprintf("Flags embedded=%#x pinned=%#x", embedded.Flags, ref.Flags)
	}
	return ""
}

// validateSharedMapExpectedABI checks an embedded shim map (named by `name`)
// against the Go-side single source of truth (userspaceShimSharedMapSpecs) for
// the ABI fields cilium/ebpf compares beyond MaxEntries/Flags already asserted
// by the caller: Type, KeySize, ValueSize. This catches an embedded-vs-Go ABI
// drift even on a fresh node that has no live pin to compare against (#5307
// expected-value arm; #5484 generalized so the v6 DNAT steering table gets the
// same fresh-node protection as v4). Only maps with a Go-side expected shape
// (dnat_table / dnat_table_v6) are validated here; the other pinned shim maps
// are Rust-defined and are guarded by the live-pin comparison. A name with no
// Go SSOT spec returns nil (nothing to compare against).
func validateSharedMapExpectedABI(embedded *ebpf.MapSpec, name string) error {
	want := sharedShimMapSpecByName(name)
	if want == nil {
		return nil
	}
	if embedded.Type != want.Type {
		return fmt.Errorf(
			"%s type drift: embedded=%s, expected=%s (userspace shim compatibility map). %s",
			name, embedded.Type, want.Type, userspaceShimGenerateRemediation,
		)
	}
	if embedded.KeySize != want.KeySize {
		return fmt.Errorf(
			"%s key_size drift: embedded=%d, expected=%d (userspace shim compatibility map). %s",
			name, embedded.KeySize, want.KeySize, userspaceShimGenerateRemediation,
		)
	}
	if embedded.ValueSize != want.ValueSize {
		return fmt.Errorf(
			"%s value_size drift: embedded=%d, expected=%d (userspace shim compatibility map). %s",
			name, embedded.ValueSize, want.ValueSize, userspaceShimGenerateRemediation,
		)
	}
	return nil
}

func sharedShimMapSpecByName(name string) *ebpf.MapSpec {
	for _, s := range userspaceShimSharedMapSpecs() {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// userspaceABICheckedPinnedMaps is the full set of maps whose live pin must be
// ABI-compatible with the new dataplane before the collection load — the ONE
// production replacement inventory the #5484 fix consolidates. It is the union
// of:
//
//   - the shim-declared PinByName maps (userspacePinnedShimMaps), which the
//     shim ELF creates+pins via the collection load; and
//   - the Go-created shared maps (userspaceShimSharedMapSpecs), which the Go
//     loader creates+pins itself (loadUserspaceShimSharedMaps) and, for some,
//     hands to the shim via MapReplacements.
//
// The pre-#5484 inventory covered only the first group, so state-bearing shared
// maps the shim does NOT declare — sessions_v6, the HA maps (rg_active,
// ha_watchdog, session_id_gen), and the per-CPU counter maps — were never
// pre-flighted. An incompatible live pin for one of those passed the deploy
// gate and then failed ErrMapIncompatible in loadUserspaceShimSharedMaps AFTER
// the old daemon was stopped, stranding the node fail-closed (#5484). Adding
// them here catches the drift pre-stop while the old dataplane still forwards.
//
// The DISPOSABLE counter map (userspace_fallback_stats) is excluded: it is
// deliberately reset on an intended shape change by
// reconcileDisposableCollectionPin (#4113), so ABI-checking it here would
// re-brick the very upgrade that reconcile was written to unblock.
func userspaceABICheckedPinnedMaps() []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(userspacePinnedShimMaps())+len(userspaceShimSharedMapSpecs()))
	add := func(n string) {
		if n == userspaceFallbackStatsMapName || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range userspacePinnedShimMaps() {
		add(n)
	}
	for _, s := range userspaceShimSharedMapSpecs() {
		add(s.Name)
	}
	return out
}

// validateUserspaceShimLivePins compares the embedded shim's ABI-relevant map
// shape against the RUNNING daemon's live pinned maps. A mismatch means the
// PinByName collection load would fail ErrMapIncompatible — but at the deploy
// pre-flight the old daemon is still up and its pins still exist, so catching
// it here refuses the deploy with the current dataplane still forwarding,
// instead of bricking the node after the old daemon has been stopped (#5307).
//
// A map with no pin yet (fresh node / first load) is skipped, so this never
// produces a false failure on a clean node. A map the new dataplane does not
// create/pin at all (neither shim-declared nor a Go shared map) is skipped,
// since nothing would ever fail ErrMapIncompatible for it.
//
// The reference shape is resolved per map by abiCheckedRefSpec: the embedded
// shim's own MapSpec for a shim-declared map (dnat_table, dnat_table_v6, the
// userspace_* maps), else the Go-side SSOT spec for a shared map the loader
// creates itself (sessions_v6, the HA/counter family). The reference ABI is
// spec-derived via livePinRefABI — never a hardcoded live shape — so a healthy
// deploy where live pin == the shape that created it yields no diff and only a
// real cross-version ABI break is caught (#5484). livePinRefABI applies the
// nr_possible_cpus MaxEntries clamp cilium/ebpf uses for a CPUMAP
// (userspace_cpumap), so the CPU-count-sized live pin is not mistaken for an
// ABI break on a rolling deploy (#5364).
func validateUserspaceShimLivePins(userspaceSpec *ebpf.CollectionSpec, readPin userspacePinnedMapABIReader) error {
	if readPin == nil {
		return nil
	}
	for _, name := range userspaceABICheckedPinnedMaps() {
		ref := abiCheckedRefSpec(userspaceSpec, name)
		if ref == nil {
			continue // new dataplane never creates/pins it: no ErrMapIncompatible risk
		}
		pinPath := filepath.Join(bpfPinPath, name)
		live, exists, err := readPin(pinPath)
		if err != nil {
			return fmt.Errorf("userspace shim ABI pre-flight: inspect live pin %s: %w", name, err)
		}
		if !exists {
			continue // fresh node / first load: nothing pinned yet
		}
		if diff := userspaceMapABIDiff(livePinRefABI(ref), live); diff != "" {
			return fmt.Errorf(
				"userspace shim map %s is ABI-incompatible with the live pinned map at %s: %s. "+
					"Loading the new dataplane would fail with ErrMapIncompatible AFTER the running "+
					"daemon is stopped, stranding the node fail-closed; refusing so the current "+
					"dataplane keeps forwarding. %s",
				name, pinPath, diff, userspaceShimStalePinRemediation,
			)
		}
	}
	return nil
}

// abiCheckedRefSpec resolves the authoritative ABI reference shape for a
// live-pin comparison. A shim-declared map is compared against the embedded
// shim's own MapSpec (the shape the collection load would pin by name); a
// Go-created shared map the shim does NOT declare is compared against the Go
// SSOT spec (userspaceShimSharedMapSpecs), the shape loadUserspaceShimSharedMaps
// creates+pins it with. Returns nil when neither owns the name, so the caller
// skips it — the new dataplane never loads such a map, so it can never fail
// ErrMapIncompatible (fail-safe).
func abiCheckedRefSpec(userspaceSpec *ebpf.CollectionSpec, name string) *ebpf.MapSpec {
	if ms, ok := userspaceSpec.Maps[name]; ok {
		return ms
	}
	return sharedShimMapSpecByName(name)
}

// userspacePinnedMapABIReader reads the ABI-relevant shape of a live pinned map
// at path. It returns exists=false with a nil error when there is no pin to
// compare against (a fresh node, or a pin directory this process cannot search
// — unprivileged unit tests: /sys/fs/bpf is mode 700), so the live-pin
// comparison is skipped without a false failure. The real deploy pre-flight and
// daemon load run as root and can read the pins.
type userspacePinnedMapABIReader func(path string) (shape userspaceMapABI, exists bool, err error)

// readPinnedShimMapABI is the production reader. It inspects the pinned map
// READ-ONLY: open a handle, read its shape, close it. It never unpins,
// attaches, or otherwise mutates the map, so the running daemon keeps
// forwarding throughout the pre-flight (#1864 verify-path spirit).
func readPinnedShimMapABI(path string) (userspaceMapABI, bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrPermission) {
			return userspaceMapABI{}, false, nil
		}
		return userspaceMapABI{}, false, fmt.Errorf("stat pinned shim map %s: %w", path, err)
	}
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return userspaceMapABI{}, false, fmt.Errorf("inspect pinned shim map %s: %w", path, err)
	}
	defer m.Close()
	return userspaceMapABI{
		Type:       m.Type(),
		KeySize:    m.KeySize(),
		ValueSize:  m.ValueSize(),
		MaxEntries: m.MaxEntries(),
		Flags:      m.Flags(),
	}, true, nil
}

func userspaceBindingsMaxEntriesDriftError(got uint32) error {
	return fmt.Errorf(
		"userspace_bindings max_entries drift: embedded=%d, expected=%d (MaxInterfaces=%d * BindingQueuesPerIface=%d in bpf/headers/xpf_common.h). %s",
		got, BindingArrayMaxEntries, MaxInterfaces, BindingQueuesPerIface, userspaceShimGenerateRemediation,
	)
}

// userspaceSlotMapMaxEntriesDriftError reports a slot-keyed map whose embedded
// max_entries disagrees with BindingSlotMapMaxEntries.
//
// This is a separate arm from the userspace_bindings check on purpose (#7497).
// The two maps are on different axes, and a shim that resized ONLY the
// slot-keyed maps would leave the bindings check green while the helper's
// plan-time cap (MAX_BINDING_SLOTS in userspace-dp) went on admitting slots the
// XSK map can no longer address — a silent regression to the failure this cap
// exists to prevent: an unregisterable binding whose RX queue drops all transit.
func userspaceSlotMapMaxEntriesDriftError(name string, got uint32) error {
	return fmt.Errorf(
		"%s max_entries drift: embedded=%d, expected=%d (BINDING_SLOT_MAP_MAX_ENTRIES in userspace-xdp/src/binding_index.rs, mirrored by MAX_BINDING_SLOTS in userspace-dp/src/server/helpers/planning.rs). %s",
		name, got, BindingSlotMapMaxEntries, userspaceShimGenerateRemediation,
	)
}

func userspaceIngressIfacesMaxEntriesDriftError(got uint32) error {
	return fmt.Errorf(
		"userspace_ingress_ifaces max_entries drift: embedded=%d, expected=%d (MaxInterfaces in bpf/headers/xpf_common.h). %s",
		got, MaxInterfaces, userspaceShimGenerateRemediation,
	)
}

func userspacePinnedShimMaps() []string {
	return []string{
		"dnat_table",
		// #5484: dnat_table_v6 is the IPv6 twin of dnat_table — declared by the
		// shim ELF and replaced at load (MapReplacements["dnat_table_v6"]) — but
		// was omitted from this inventory, so the live-pin ABI arm never checked
		// it. Listed here for parity with dnat_table (both replaced maps are
		// re-pinned idempotently via userspaceRequiredShimPins).
		"dnat_table_v6",
		"userspace_ctrl",
		"userspace_bindings",
		"userspace_ingress_ifaces",
		"userspace_heartbeat",
		"userspace_xsk_map",
		"userspace_local_v4",
		"userspace_local_v6",
		"userspace_interface_nat_v4",
		"userspace_interface_nat_v6",
		"userspace_sessions",
		"userspace_trace",
		"userspace_fallback_stats",
		"userspace_cpumap",
	}
}

func userspaceRequiredShimPins() []struct {
	name string
	path string
} {
	names := userspacePinnedShimMaps()
	out := make([]struct {
		name string
		path string
	}, 0, len(names)+len(userspaceShimSharedMapSpecs()))
	for _, name := range names {
		out = append(out, struct {
			name string
			path string
		}{name: name, path: filepath.Join(bpfPinPath, name)})
	}
	for _, spec := range userspaceShimSharedMapSpecs() {
		out = append(out, struct {
			name string
			path string
		}{name: spec.Name, path: filepath.Join(bpfPinPath, spec.Name)})
	}
	return out
}

func loadUserspaceShimSharedMaps() (map[string]*ebpf.Map, error) {
	maps := make(map[string]*ebpf.Map)
	for _, spec := range userspaceShimSharedMapSpecs() {
		loaded, err := loadOrCreatePinnedShimMap(spec)
		if err != nil {
			closeUniqueMaps(maps)
			return nil, err
		}
		maps[spec.Name] = loaded
	}
	return maps, nil
}

func loadOrCreatePinnedShimMap(spec *ebpf.MapSpec) (*ebpf.Map, error) {
	return loadOrCreatePinnedShimMapWith(spec, bpfPinPath, ebpf.NewMapWithOptions)
}

type userspaceShimMapLoader func(*ebpf.MapSpec, ebpf.MapOptions) (*ebpf.Map, error)

func loadOrCreatePinnedShimMapWith(
	spec *ebpf.MapSpec,
	pinPath string,
	load userspaceShimMapLoader,
) (*ebpf.Map, error) {
	spec = spec.Copy()
	spec.Pinning = ebpf.PinByName
	m, err := load(spec, ebpf.MapOptions{PinPath: pinPath})
	if err == nil {
		return m, nil
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		return nil, fmt.Errorf("load userspace shim shared map %s: %w", spec.Name, err)
	}
	return nil, fmt.Errorf(
		"refusing to reset incompatible userspace shim map %s at %s: %w",
		spec.Name, filepath.Join(pinPath, spec.Name), err,
	)
}

func closeUniqueMaps(maps map[string]*ebpf.Map) {
	seen := make(map[*ebpf.Map]struct{}, len(maps))
	for _, m := range maps {
		if m == nil {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		_ = m.Close()
	}
}

func userspaceShimSharedMapSpecs() []*ebpf.MapSpec {
	return []*ebpf.MapSpec{
		// Register the conntrack maps at the on-map C/Rust ABI size
		// (ConntrackSessionValueSize{,V6}), NOT sizeOf[SessionValue].
		// SessionValue carries the sync-only Generation field (#2170) which
		// is intentionally absent from the BPF C struct; using its size would
		// inflate value_size by 8 bytes and cause an OOB copy into the Rust
		// helper's smaller lookup buffer (#2360). These constants are the
		// single source of truth shared with the test fixtures.
		hashMapSpec("sessions", sizeOf[SessionKey](), ConntrackSessionValueSize, userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("sessions_v6", sizeOf[SessionKeyV6](), ConntrackSessionValueSizeV6, userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("dnat_table", sizeOf[DNATKey](), sizeOf[DNATValue](), userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		hashMapSpec("dnat_table_v6", sizeOf[DNATKeyV6](), sizeOf[DNATValueV6](), userspaceShimMaxSessions, unix.BPF_F_NO_PREALLOC),
		arrayMapSpec("fib_gen_map", sizeOf[uint32](), 1),
		arrayMapSpec("fabric_fwd", sizeOf[FabricFwdInfo](), 2),
		arrayMapSpec("rg_active", sizeOf[uint8](), MaxRedundancyGroups),
		arrayMapSpec("ha_watchdog", sizeOf[uint64](), MaxRedundancyGroups),
		perCPUArrayMapSpec("session_id_gen", sizeOf[uint64](), 1),
		perCPUArrayMapSpec("global_counters", sizeOf[uint64](), GlobalCtrMax),
		perCPUArrayMapSpec("flood_counters", sizeOf[FloodState](), MaxZones),
		perCPUArrayMapSpec("policy_counters", sizeOf[CounterValue](), userspaceShimMaxPolicies),
		perCPUArrayMapSpec("zone_counters", sizeOf[CounterValue](), MaxZones*2),
		perCPUArrayMapSpec("filter_counters", sizeOf[CounterValue](), MaxFilterRules),
		perCPUHashMapSpec("interface_counters", sizeOf[uint32](), sizeOf[InterfaceCounterValue](), MaxInterfaces, unix.BPF_F_NO_PREALLOC),
		perCPUArrayMapSpec("nat_port_counters", sizeOf[NATPortCounter](), userspaceShimMaxNATPools),
		perCPUArrayMapSpec("nat_rule_counters", sizeOf[CounterValue](), MaxNATRuleCounters),
	}
}

const (
	userspaceShimMaxSessions uint32 = 10000000
	userspaceShimMaxPolicies uint32 = 4096
	userspaceShimMaxNATPools uint32 = 32
)

func hashMapSpec(name string, keySize, valueSize, maxEntries, flags uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		Flags:      flags,
	}
}

func perCPUHashMapSpec(name string, keySize, valueSize, maxEntries, flags uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.PerCPUHash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		Flags:      flags,
	}
}

func arrayMapSpec(name string, valueSize, maxEntries uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Array,
		KeySize:    sizeOf[uint32](),
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}
}

func perCPUArrayMapSpec(name string, valueSize, maxEntries uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.PerCPUArray,
		KeySize:    sizeOf[uint32](),
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}
}

func sizeOf[T any]() uint32 {
	var zero T
	return uint32(unsafe.Sizeof(zero))
}

// reconcileDisposableCollectionPin removes a stale pinned map whose on-disk
// shape no longer matches the spec the collection is about to load with
// PinByName, so NewCollectionWithOptions recreates it fresh instead of failing
// with ErrMapIncompatible and bricking the shim load on a daemon upgrade.
//
// This is SAFE ONLY for DISPOSABLE maps — counters that reset to zero on every
// reload anyway (userspace_fallback_stats / degraded_path_counters). DATA maps
// (sessions, conntrack, dnat) must NEVER be silently reset; those go through
// loadOrCreatePinnedShimMapWith, which deliberately REFUSES to reset an
// incompatible pin (#2360). #4113 changed this counter's BPF type from Array to
// PerCpuArray; without this reconcile, the stale Array pin from a previous
// daemon is incompatible with the new PerCpuArray spec, PinByName's
// compatibility check fails, and the whole collection load aborts (#1917/#1960
// upgrade-brick class).
//
// A missing pin (fresh boot) or a shape-compatible pin (already migrated) is
// left untouched, so accumulated counters survive an ordinary restart.
func reconcileDisposableCollectionPin(pinPath string, spec *ebpf.MapSpec) error {
	if spec == nil {
		return nil
	}
	if _, err := os.Stat(pinPath); err != nil {
		if os.IsNotExist(err) {
			return nil // fresh boot: nothing pinned yet
		}
		return fmt.Errorf("stat disposable pin %s: %w", pinPath, err)
	}
	existing, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return fmt.Errorf("inspect disposable pin %s: %w", pinPath, err)
	}
	defer existing.Close()
	if disposablePinShapeMatches(existing.Type(), existing.KeySize(),
		existing.ValueSize(), existing.MaxEntries(), spec) {
		return nil
	}
	slog.Info("resetting incompatible disposable shim map pin on upgrade",
		"path", pinPath,
		"pinned_type", existing.Type().String(),
		"pinned_value_size", existing.ValueSize(),
		"pinned_max_entries", existing.MaxEntries(),
		"want_type", spec.Type.String(),
		"want_value_size", spec.ValueSize,
		"want_max_entries", spec.MaxEntries)
	if err := existing.Unpin(); err != nil {
		return fmt.Errorf("unpin incompatible disposable pin %s: %w", pinPath, err)
	}
	return nil
}

// disposablePinShapeMatches reports whether an on-disk pinned map's shape
// matches the spec closely enough that the PinByName collection load will
// accept it. It compares the discriminating fields for the #4113 migration
// (type is the changed field; key/value/entries are compared so a future shape
// change also triggers a reset). Flags are intentionally excluded: this counter
// is created with flags 0 on both sides, and a disposable map errs toward
// resetting rather than bricking.
func disposablePinShapeMatches(
	pinnedType ebpf.MapType,
	pinnedKeySize, pinnedValueSize, pinnedMaxEntries uint32,
	spec *ebpf.MapSpec,
) bool {
	return pinnedType == spec.Type &&
		pinnedKeySize == spec.KeySize &&
		pinnedValueSize == spec.ValueSize &&
		pinnedMaxEntries == spec.MaxEntries
}

func ensureUserspaceMapPinned(name string, m *ebpf.Map, path string) error {
	if m == nil {
		return fmt.Errorf("nil map for %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s pin path %s: %w", name, path, err)
		}
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pin %s at %s: %w", name, path, err)
		}
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s pin missing at %s after load: %w", name, path, err)
	}
	return nil
}
