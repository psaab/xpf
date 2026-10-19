package userspace

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

// #15789: per-ingress-zone LAND screen disposition for the XDP shim.
//
// The shim's kernel-pass arms are terminal — the worker's profile-gated
// check_land never sees those packets — so the LAND verdict for them
// must be decided at the shim. #13953 decided it unconditionally (drop),
// which bypassed ScreenProfile.land and alarm-without-drop. The Go
// control plane now publishes the resolved disposition per zone into
// userspace_land_screen and the shim honours it:
//   - landScreenPass (0): the zone's resolved profile has the LAND check
//     disabled — published as an explicit row so the shim can tell a
//     resolved LAND-off zone from an unresolved one;
//   - landScreenDrop (1): LAND enabled, drop-enforcing;
//   - landScreenAlarm (2): LAND enabled under alarm-without-drop — the
//     shim counts land_alarm and passes the packet to the kernel.
//
// An unresolved ingress zone (no WG ingress-zone row, or zone 0) fails
// closed to DROP at the shim regardless of any row. That preserves the
// #13953 guarantee for unscreened zones and for a pre-#15789 control
// plane that never publishes the map (version skew degrades to the
// #13953 behaviour, never fail-open).
//
// The zone key is the StableZoneID (config.StableZoneID) — the same
// namespace buildZoneSnapshots stamps and the WG ingress-zone map uses.
const (
	landScreenPass  uint8 = 0
	landScreenDrop  uint8 = 1
	landScreenAlarm uint8 = 2
)

// userspaceLandScreenMapCapacity mirrors the shim map's max_entries.
const userspaceLandScreenMapCapacity = 65536

// buildUserspaceLandScreenEntries derives the desired
// userspace_land_screen rows from the snapshot's resolved screen state.
//
// The resolution mirrors the worker's ScreenState exactly:
//
//   - a zone whose screen snapshot was published (a defined profile
//     enforcing at least one check): DROP when the snapshot's Land is
//     set (ALARM when AlarmWithoutDrop is also set), explicit PASS (0)
//     when Land is clear — the row's presence marks the zone resolved;
//   - a zone referencing an UNDEFINED profile: the worker substitutes
//     ScreenProfile::conservative_default(), which enables LAND, so
//     DROP (no audit flag exists to read — the missing ref carries
//     none);
//   - a zone whose defined profile enforces nothing (inert): the same
//     substituted default applies, with the profile's AlarmWithoutDrop
//     carried on the inert ref — ALARM when set, DROP otherwise;
//   - a zone with no screen configured, a quarantined zone, or a
//     dropped enforcement child: no row (absent = shim fail-closed
//     DROP, the #13953 posture for unscreened zones).
//
// Rows are keyed by StableZoneID. A zone id claimed by two zone names
// with different dispositions is poisoned to DROP (fail-closed) rather
// than letting map iteration order pick a winner; the StableZoneID
// quarantine normally prevents collisions from reaching the published
// set at all.
func buildUserspaceLandScreenEntries(snapshot *ConfigSnapshot) map[uint16]uint8 {
	entries := make(map[uint16]uint8)
	if snapshot == nil {
		return entries
	}
	put := func(zone string, disposition uint8) {
		id := config.StableZoneID(zone)
		if prior, exists := entries[id]; exists && prior != disposition {
			entries[id] = landScreenDrop
			return
		}
		entries[id] = disposition
	}
	// Copy before sorting: the snapshot's Screens slice is shared with
	// other readers and must not be reordered in place. Deterministic
	// order so a poisoned collision resolves identically on every build.
	screens := append([]ScreenProfileSnapshot(nil), snapshot.Screens...)
	sort.Slice(screens, func(i, j int) bool { return screens[i].Zone < screens[j].Zone })
	for _, snap := range screens {
		// Every screened zone publishes an explicit row: PASS (0) when
		// LAND is disabled — the row's PRESENCE is what distinguishes
		// "resolved zone, LAND off" from an unresolved zone at the
		// shim, where absent must fail closed.
		disposition := landScreenPass
		if snap.Land {
			if snap.AlarmWithoutDrop {
				disposition = landScreenAlarm
			} else {
				disposition = landScreenDrop
			}
		}
		put(snap.Zone, disposition)
	}
	for _, ref := range snapshot.ScreenMissingProfiles {
		put(ref.Zone, landScreenDrop)
	}
	for _, ref := range snapshot.ScreenInertProfiles {
		if ref.AlarmWithoutDrop {
			put(ref.Zone, landScreenAlarm)
		} else {
			put(ref.Zone, landScreenDrop)
		}
	}
	return entries
}

func checkLandScreenCapacity(desired int) error {
	if desired > userspaceLandScreenMapCapacity {
		return fmt.Errorf("%d land screen entries exceed the %s map capacity of %d (#15789); the classifier maps and userspace_ctrl are left on the previous plan",
			desired, mapNameUserspaceLandScreen, userspaceLandScreenMapCapacity)
	}
	return nil
}

// syncUserspaceLandScreenMapLocked reconciles userspace_land_screen to
// the desired set by iterating the live map (the WG-zone-map pattern),
// so rows left by a previous daemon in the pinned map are reaped even
// though no in-process inventory names them.
func (m *Manager) syncUserspaceLandScreenMapLocked(landMap *ebpf.Map, desired map[uint16]uint8) error {
	current := make(map[uint16]uint8)
	var key uint16
	var value uint8
	iter := landMap.Iterate()
	for iter.Next(&key, &value) {
		current[key] = value
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_land_screen: %w", err)
	}
	same := len(current) == len(desired)
	if same {
		for k, v := range current {
			if got, ok := desired[k]; !ok || got != v {
				same = false
				break
			}
		}
	}
	if same {
		return nil
	}
	for k, v := range desired {
		if err := landMap.Update(k, v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_land_screen zone=%d: %w", k, err)
		}
	}
	for k := range current {
		if _, keep := desired[k]; keep {
			continue
		}
		if err := landMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale userspace_land_screen zone=%d: %w", k, err)
		}
	}
	return nil
}

func (m *Manager) syncUserspaceLandScreenLocked(snapshot *ConfigSnapshot) error {
	desired := buildUserspaceLandScreenEntries(snapshot)
	if err := checkLandScreenCapacity(len(desired)); err != nil {
		return err
	}
	landMap := m.bpfShim.Map(mapNameUserspaceLandScreen)
	if landMap == nil {
		return errors.New("userspace_land_screen map not loaded")
	}
	return m.syncUserspaceLandScreenMapLocked(landMap, desired)
}
