package userspace

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

// #16009: per-ingress-zone stateless-malformed screen mask for the XDP
// shim's kernel-pass arms.
//
// The shim's kernel-pass arms are terminal — the worker's screen
// stage 10 never sees those packets — so the stateless malformed
// verdicts (ping-of-death, teardrop, icmp-fragment, syn-frag,
// ip-source-route, TCP SYN+FIN / no-flag / fin-no-ack / winnuke) for
// host-bound traffic must be decided at the shim. #15789 did this for
// LAND alone; this publishes the remaining stateless family. The Go
// control plane packs the zone's enabled checks plus the profile-wide
// alarm-without-drop bit into userspace_host_screen and the shim
// honours it:
//
//   - a tripped check that is enabled for the zone: DROP at the shim
//     (host_screen_drop counter), or ALARM (host_screen_alarm counter,
//     packet passes) when the profile sets alarm-without-drop;
//   - a tripped check that is disabled for the zone: pass;
//   - an unresolved ingress zone (no WG ingress-zone row, or zone 0):
//     the shim fails closed to DROP for any tripped packet regardless
//     of any row, preserving the fail-closed posture for unscreened
//     zones and for a pre-#16009 control plane that never publishes
//     the map (version skew degrades to dropping malformed packets,
//     never to passing them unscreened).
//
// Deliberately NOT published: port-scan / ip-sweep (stateful
// per-source trackers gated on the worker's new-flow decision),
// SYN-cookie challenge semantics, true fragment-overlap detection,
// and the rate-based flood counters (already replicated in the
// kernel by pkg/nftables/host_inbound_screens.go). See
// userspace-xdp/src/host_screen.rs.
//
// The mask bits mirror the HOST_SCREEN_* constants in
// userspace-xdp/src/host_screen.rs. The zone key is the StableZoneID
// (config.StableZoneID) — the same namespace the LAND screen and the
// WG ingress-zone map use. Bit 5 is SYN+FIN; bit 6 is the shared
// no-flag / fin-no-ack / winnuke family (the worker carries them as
// separate bools, the shim verdict tests one family bit).
const (
	hostScreenPingDeath    uint8 = 1 << 0
	hostScreenTeardrop     uint8 = 1 << 1
	hostScreenICMPFragment uint8 = 1 << 2
	hostScreenSynFrag      uint8 = 1 << 3
	hostScreenSourceRoute  uint8 = 1 << 4
	hostScreenSynFin       uint8 = 1 << 5
	hostScreenTCPFlags     uint8 = 1 << 6
	hostScreenAlarmBit     uint8 = 1 << 7
	hostScreenAllChecks    uint8 = hostScreenPingDeath | hostScreenTeardrop | hostScreenICMPFragment | hostScreenSynFrag | hostScreenSourceRoute | hostScreenSynFin | hostScreenTCPFlags
)

// userspaceHostScreenMapCapacity mirrors the shim map's max_entries.
const userspaceHostScreenMapCapacity = 65536

// hostScreenMaskFor packs one resolved screen profile's stateless
// malformed checks (plus alarm-without-drop) into the shim byte.
// synFin maps to bit 5; noFlag/finNoAck/winnuke share bit 6.
func hostScreenMaskFor(pingDeath, teardrop, icmpFragment, synFrag, sourceRoute, synFin, tcpFlags, alarmWithoutDrop bool) uint8 {
	var mask uint8
	if pingDeath {
		mask |= hostScreenPingDeath
	}
	if teardrop {
		mask |= hostScreenTeardrop
	}
	if icmpFragment {
		mask |= hostScreenICMPFragment
	}
	if synFrag {
		mask |= hostScreenSynFrag
	}
	if sourceRoute {
		mask |= hostScreenSourceRoute
	}
	if synFin {
		mask |= hostScreenSynFin
	}
	if tcpFlags {
		mask |= hostScreenTCPFlags
	}
	if alarmWithoutDrop {
		mask |= hostScreenAlarmBit
	}
	return mask
}

// buildUserspaceHostScreenEntries derives the desired
// userspace_host_screen rows from the snapshot's resolved screen
// state.
//
// The resolution mirrors the worker's ScreenState exactly (the
// #15789 LAND builder's posture):
//
//   - a zone whose screen snapshot was published: its checks packed
//     as-is — a zero mask (no malformed check enabled) still publishes
//     an explicit row marking the zone resolved;
//   - a zone referencing an UNDEFINED profile: the worker substitutes
//     ScreenProfile::conservative_default(), which enables
//     ping-death / teardrop / syn-frag / source-route (NOT
//     icmp-fragment), with no audit flag to read — drop posture;
//   - a zone whose defined profile enforces nothing (inert): the same
//     substituted default applies, with the profile's
//     AlarmWithoutDrop carried on the inert ref;
//   - a zone with no screen configured, a quarantined zone, or a
//     dropped enforcement child: no row (absent = unresolved at the
//     shim only when the zone itself does not resolve; a resolved zone
//     with no row reads checks-off).
//
// Rows are keyed by StableZoneID. A zone id claimed by two zone names
// with different masks is poisoned to all-checks-drop (fail-closed)
// rather than letting map iteration order pick a winner; the
// StableZoneID quarantine normally prevents collisions from reaching
// the published set at all.
func buildUserspaceHostScreenEntries(snapshot *ConfigSnapshot) map[uint32]uint8 {
	entries := make(map[uint32]uint8)
	if snapshot == nil {
		return entries
	}
	put := func(zone string, mask uint8) {
		id := config.StableZoneID(zone)
		if prior, exists := entries[id]; exists && prior != mask {
			entries[id] = hostScreenAllChecks
			return
		}
		entries[id] = mask
	}
	// Copy before sorting: the snapshot's Screens slice is shared with
	// other readers and must not be reordered in place. Deterministic
	// order so a poisoned collision resolves identically on every build.
	screens := append([]ScreenProfileSnapshot(nil), snapshot.Screens...)
	sort.Slice(screens, func(i, j int) bool { return screens[i].Zone < screens[j].Zone })
	for _, snap := range screens {
		put(snap.Zone, hostScreenMaskFor(
			snap.PingDeath, snap.Teardrop, snap.ICMPFragment, snap.SynFrag, snap.SourceRoute,
			snap.SynFin, snap.NoFlag || snap.FinNoAck || snap.WinNuke,
			snap.AlarmWithoutDrop,
		))
	}
	// conservative_default() enables syn-fin and the TCP-flag family
	// plus ping-death / teardrop / syn-frag / source-route — not
	// icmp-fragment (see ScreenProfile::conservative_default).
	conservative := hostScreenMaskFor(true, true, false, true, true, true, true, false)
	for _, ref := range snapshot.ScreenMissingProfiles {
		put(ref.Zone, conservative)
	}
	for _, ref := range snapshot.ScreenInertProfiles {
		mask := conservative
		if ref.AlarmWithoutDrop {
			mask |= hostScreenAlarmBit
		}
		put(ref.Zone, mask)
	}
	return entries
}

func checkHostScreenCapacity(desired int) error {
	if desired > userspaceHostScreenMapCapacity {
		return fmt.Errorf("%d host screen entries exceed the %s map capacity of %d (#16009); the classifier maps and userspace_ctrl are left on the previous plan",
			desired, mapNameUserspaceHostScreen, userspaceHostScreenMapCapacity)
	}
	return nil
}

// syncUserspaceHostScreenMapLocked reconciles userspace_host_screen
// to the desired set by iterating the live map (the LAND-screen
// pattern), so rows left by a previous daemon in the pinned map are
// reaped even though no in-process inventory names them.
func (m *Manager) syncUserspaceHostScreenMapLocked(hostMap *ebpf.Map, desired map[uint32]uint8) error {
	current := make(map[uint32]uint8)
	var key uint32
	var value uint8
	iter := hostMap.Iterate()
	for iter.Next(&key, &value) {
		current[key] = value
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate userspace_host_screen: %w", err)
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
		if err := hostMap.Update(k, v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update userspace_host_screen zone=%d: %w", k, err)
		}
	}
	for k := range current {
		if _, keep := desired[k]; keep {
			continue
		}
		if err := hostMap.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale userspace_host_screen zone=%d: %w", k, err)
		}
	}
	return nil
}

func (m *Manager) syncUserspaceHostScreenLocked(snapshot *ConfigSnapshot) error {
	desired := buildUserspaceHostScreenEntries(snapshot)
	if err := checkHostScreenCapacity(len(desired)); err != nil {
		return err
	}
	hostMap := m.bpfShim.Map(mapNameUserspaceHostScreen)
	if hostMap == nil {
		return errors.New("userspace_host_screen map not loaded")
	}
	return m.syncUserspaceHostScreenMapLocked(hostMap, desired)
}
