package dataplane

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/psaab/xpf/pkg/config"
)

// #2114 A3 armed-gate runtime legs (the plan's FIVE-leg oracle set plus the
// named Detach/ownership/continuation legs). The oracle honestly splits:
// the ALWAYS-ON legs prove classification + blocking for every manifest
// entry with sentinel/absent registries (no BPF privileges needed); the
// PRIVILEGED semantic-mutation legs run where BPF map creation works and
// skip elsewhere (the repo's skipIfBPFUnavailable idiom).

// armMuProbeArrival arms the muAcquireProbeHook seam (Codex PR #6743
// r3-8) to close the returned channel the FIRST time a contended m.mu
// surface is entered while armed — the blocking legs' arrival proof.
// Arm it AFTER the holding party is parked (the holder's own pre-hook
// fire happens before its park), start the probe goroutine, and wait on
// the channel: the goroutine is then PROVABLY at the contended m.mu
// acquisition, so the following non-completion window cannot pass
// vacuously the way a signal-before-call handshake can (the goroutine
// could previously be descheduled between signal and call for the whole
// window). The returned disarm restores the nil production value.
func armMuProbeArrival() (arrived <-chan struct{}, disarm func()) {
	ch := make(chan struct{})
	var once sync.Once
	muAcquireProbeHook = func(site string) { once.Do(func() { close(ch) }) }
	return ch, func() { muAcquireProbeHook = nil }
}

// armedGateDirectLockSet pins the invoke-table members that block on a
// DIRECT m.mu acquisition BEFORE reaching any probed surface (the
// class-3 counter/offset methods take m.mu for the offset maps ahead
// of — or instead of — a lookup helper), so the muAcquireProbeHook
// pre-lock seam never fires for them during the hold (Codex PR #6743
// r3-8). The blocking legs COMPUTE the set by serialized per-member
// attribution and require it to equal this pin: any drift means a
// member changed its contention path and the arrival proof no longer
// covers what the author believes. Direct-first members still get the
// in-hold non-completion check and the post-release outcome assertion;
// the per-goroutine arrival proof covers the helper-routed majority.
var armedGateDirectLockSet = map[string]bool{
	"ClearAllCounters":     true, // composes the raw counter clears under its own m.mu section
	"ClearGlobalCounters":  true, // class 3: offset-map section precedes the registry work
	"ClearNATRuleCounters": true, // class 3: same direct-lock shape
	"ClearZoneCounters":    true, // class 3: same direct-lock shape
}

// startArmedGateInvoke starts every invoke-table member against m
// (whose publisher is parked mid-hold) ONE AT A TIME, waiting for each
// member's pre-lock probe fire before starting the next — the
// per-member arrival proof of Codex PR #6743 r3-8. A signal-before-call
// handshake can pass the silence window with the goroutine descheduled
// for its whole length; the in-call pre-lock fire proves the goroutine
// reached the contended acquisition. Members that never fire block on
// a direct m.mu acquisition ahead of any probed surface; they are
// named and checked against armedGateDirectLockSet. Arm the probe ONLY
// after the publisher parked: the publisher's own pre-lock fire
// precedes its park and would corrupt the attribution.
func startArmedGateInvoke(t *testing.T, m *Manager, invoke map[string]func(*Manager) error) []armedGatePendingCall {
	t.Helper()
	var arrived atomic.Int32
	muAcquireProbeHook = func(site string) { arrived.Add(1) }
	t.Cleanup(func() { muAcquireProbeHook = nil })

	var pending []armedGatePendingCall
	var preLockBlockers []string
	for name, call := range invoke {
		before := arrived.Load()
		p := armedGatePendingCall{name: name, done: make(chan error, 1)}
		go func(c func(m *Manager) error, p armedGatePendingCall) {
			p.done <- c(m)
		}(call, p)
		pending = append(pending, p)
		deadline := time.Now().Add(2 * time.Second)
		for arrived.Load() == before && time.Now().Before(deadline) {
			select {
			case err := <-p.done:
				t.Fatalf("%s completed (%v) during the hold before any probe fire — it neither blocked nor reached a contended surface", name, err)
			default:
			}
			time.Sleep(time.Millisecond)
		}
		if arrived.Load() == before {
			preLockBlockers = append(preLockBlockers, name)
		}
	}
	if len(preLockBlockers) != len(armedGateDirectLockSet) {
		t.Fatalf("direct-first-lock set %v drifted from the pin %v", preLockBlockers, armedGateDirectLockSet)
	}
	for _, name := range preLockBlockers {
		if !armedGateDirectLockSet[name] {
			t.Fatalf("direct-first-lock set %v drifted from the pin %v", preLockBlockers, armedGateDirectLockSet)
		}
	}
	return pending
}

// armedGatePendingCall tracks one in-flight invoke-table member.
type armedGatePendingCall struct {
	name string
	done chan error
}

// armedGateSentinel seeds the registry into the retained classification
// (nonempty m.maps, loaded=false) without providing any map a method
// actually looks up: every method's own lookup returns present=false, so
// master's armed/retained + ABSENT outcome is exercised without touching
// the kernel.
func armedGateSentinel(m *Manager) {
	m.maps["sentinel_unused"] = nil
}

// armedGateInvoke drives every registry-consuming exported method with a
// benign zero-ish argument set and returns its error (nil for void /
// neutral-value methods). Methods that would touch the kernel or netlink
// past an armed+absent lookup (the attach family) are NOT here — they are
// covered by the carve-out assertions below. The map keys are the method
// names from managerMethodClasses.
func armedGateInvoke() map[string]func(m *Manager) error {
	return map[string]func(m *Manager) error{
		// class 1
		"SetZone":           func(m *Manager) error { return m.SetZone(1, 0, 1, 0, 0, 0, 0) },
		"SetVlanIfaceInfo":  func(m *Manager) error { return m.SetVlanIfaceInfo(2, 1, 10) },
		"ClearIfaceZoneMap": func(m *Manager) error { return m.ClearIfaceZoneMap() },
		"ClearVlanIfaceMap": func(m *Manager) error { return m.ClearVlanIfaceMap() },
		"AddTxPort":         func(m *Manager) error { return m.AddTxPort(1) },
		"SwapToUserspaceXDPShimEntryProgram": func(m *Manager) error {
			return m.SwapToUserspaceXDPShimEntryProgram()
		},
		"ReadGlobalCounter":      func(m *Manager) error { _, err := m.ReadGlobalCounter(0); return err },
		"ReadInterfaceCounters":  func(m *Manager) error { _, err := m.ReadInterfaceCounters(1); return err },
		"ClearInterfaceCounters": func(m *Manager) error { return m.ClearInterfaceCounters() },
		"UpdateFabricFwd":        func(m *Manager) error { return m.UpdateFabricFwd(FabricFwdInfo{}) },
		"UpdateFabricFwd1":       func(m *Manager) error { return m.UpdateFabricFwd1(FabricFwdInfo{}) },
		"UpdateRGActive":         func(m *Manager) error { return m.UpdateRGActive(0, true) },
		"UpdateHAWatchdog":       func(m *Manager) error { return m.UpdateHAWatchdog(0, 1) },
		"BumpFIBGeneration":      func(m *Manager) error { _, err := m.BumpFIBGeneration(); return err },
		"SetIfaceFilter":         func(m *Manager) error { return m.SetIfaceFilter(IfaceFilterKey{}, 1) },
		"ClearIfaceFilterMap":    func(m *Manager) error { return m.ClearIfaceFilterMap() },
		"SetFilterConfig":        func(m *Manager) error { return m.SetFilterConfig(1, FilterConfig{}) },
		"ReadFilterConfig":       func(m *Manager) error { _, err := m.ReadFilterConfig(1); return err },
		"SetFilterRule":          func(m *Manager) error { return m.SetFilterRule(0, FilterRule{}) },
		"SetPolicerConfig":       func(m *Manager) error { return m.SetPolicerConfig(1, PolicerConfig{}) },
		"ClearPolicerConfigs":    func(m *Manager) error { return m.ClearPolicerConfigs() },
		"ClearFilterConfigs":     func(m *Manager) error { return m.ClearFilterConfigs() },
		"ReadFilterCounters":     func(m *Manager) error { _, err := m.ReadFilterCounters(0); return err },
		"ClearFilterCounters":    func(m *Manager) error { return m.ClearFilterCounters() },
		"SetFlowTimeout":         func(m *Manager) error { return m.SetFlowTimeout(0, 30) },
		"SetFlowConfig":          func(m *Manager) error { return m.SetFlowConfig(FlowConfigValue{}) },
		"SetMirrorConfig":        func(m *Manager) error { return m.SetMirrorConfig(1, 2, 100) },
		"ClearMirrorConfigs":     func(m *Manager) error { return m.ClearMirrorConfigs() },
		"SetDNATEntry":           func(m *Manager) error { return m.SetDNATEntry(DNATKey{}, DNATValue{}) },
		"DeleteDNATEntry":        func(m *Manager) error { return m.DeleteDNATEntry(DNATKey{}) },
		"SetDNATEntryV6":         func(m *Manager) error { return m.SetDNATEntryV6(DNATKeyV6{}, DNATValueV6{}) },
		"DeleteDNATEntryV6":      func(m *Manager) error { return m.DeleteDNATEntryV6(DNATKeyV6{}) },
		"ReadNATPortCounter":     func(m *Manager) error { _, err := m.ReadNATPortCounter(0); return err },
		"SetZoneConfig":          func(m *Manager) error { return m.SetZoneConfig(1, ZoneConfig{}) },
		"SetZonePairPolicy":      func(m *Manager) error { return m.SetZonePairPolicy(1, 1, PolicySet{}) },
		"SetPolicyRule":          func(m *Manager) error { return m.SetPolicyRule(0, 0, PolicyRule{}) },
		"SetAddressBookEntry":    func(m *Manager) error { return m.SetAddressBookEntry("10.0.0.0/8", 1) },
		"SetAddressMembership":   func(m *Manager) error { return m.SetAddressMembership(1, 1) },
		"ClearAddressBookV4":     func(m *Manager) error { return m.ClearAddressBookV4() },
		"ClearAddressBookV6":     func(m *Manager) error { return m.ClearAddressBookV6() },
		"ClearAddressMembership": func(m *Manager) error { return m.ClearAddressMembership() },
		"SetApplication":         func(m *Manager) error { return m.SetApplication(6, 80, 1, 0, 0, 0, 0) },
		"SetAppRange":            func(m *Manager) error { return m.SetAppRange(0, AppRangeEntry{}) },
		"ClearAppRanges":         func(m *Manager) error { return m.ClearAppRanges() },
		"ClearZonePairPolicies":  func(m *Manager) error { return m.ClearZonePairPolicies() },
		"ClearApplications":      func(m *Manager) error { return m.ClearApplications() },
		"SetDefaultPolicy":       func(m *Manager) error { return m.SetDefaultPolicy(1) },
		"ReadPolicyCounters":     func(m *Manager) error { _, err := m.ReadPolicyCounters(0); return err },
		"ClearPolicyCounters":    func(m *Manager) error { return m.ClearPolicyCounters() },
		"SetScreenConfig":        func(m *Manager) error { return m.SetScreenConfig(0, ScreenConfig{}) },
		"ClearScreenConfigs":     func(m *Manager) error { return m.ClearScreenConfigs() },
		"UpdateSessionCountSrc":  func(m *Manager) error { return m.UpdateSessionCountSrc(SessionCountKey{}, 1) },
		"UpdateSessionCountDst":  func(m *Manager) error { return m.UpdateSessionCountDst(SessionCountKey{}, 1) },
		"IterateSessions":        func(m *Manager) error { return m.IterateSessions(func(SessionKey, SessionValue) bool { return false }) },
		"DeleteSession":          func(m *Manager) error { return m.DeleteSession(SessionKey{}) },
		"SetSessionV4":           func(m *Manager) error { return m.SetSessionV4(SessionKey{}, SessionValue{}) },
		"GetSessionV4":           func(m *Manager) error { _, err := m.GetSessionV4(SessionKey{}); return err },
		"GetSessionV6":           func(m *Manager) error { _, err := m.GetSessionV6(SessionKeyV6{}); return err },
		"IterateSessionsV6": func(m *Manager) error {
			return m.IterateSessionsV6(func(SessionKeyV6, SessionValueV6) bool { return false })
		},
		"IterateSessionsFrom": func(m *Manager) error {
			return m.IterateSessionsFrom(nil, func(SessionKey, SessionValue) bool { return false })
		},
		"IterateSessionsV6From": func(m *Manager) error {
			return m.IterateSessionsV6From(nil, func(SessionKeyV6, SessionValueV6) bool { return false })
		},
		"BatchIterateSessions": func(m *Manager) error {
			return m.BatchIterateSessions(func(SessionKey, SessionValue) bool { return false })
		},
		"BatchIterateSessionsV6": func(m *Manager) error {
			return m.BatchIterateSessionsV6(func(SessionKeyV6, SessionValueV6) bool { return false })
		},
		"BatchDeleteSessions":   func(m *Manager) error { _, err := m.BatchDeleteSessions(nil); return err },
		"BatchDeleteSessionsV6": func(m *Manager) error { _, err := m.BatchDeleteSessionsV6(nil); return err },
		"DeleteSessionV6":       func(m *Manager) error { return m.DeleteSessionV6(SessionKeyV6{}) },
		"SetSessionV6":          func(m *Manager) error { return m.SetSessionV6(SessionKeyV6{}, SessionValueV6{}) },
		"ClearAllSessions":      func(m *Manager) error { _, _, err := m.ClearAllSessions(); return err },
		"ClearAllSessionsChunked": func(m *Manager) error {
			_, _, err := m.ClearAllSessionsChunked(nil, nil)
			return err
		},

		// class 2 (neutral; error-returning members return nil on fresh)
		"SessionCount":       func(m *Manager) error { m.SessionCount(); return nil },
		"GetMapStats":        func(m *Manager) error { m.GetMapStats(); return nil },
		"ClearSessionCounts": func(m *Manager) error { return m.ClearSessionCounts() },
		"UpdatePolicyScheduleState": func(m *Manager) error {
			return m.UpdatePolicyScheduleState(nil, map[string]bool{})
		},
		"SeedNATPortCounters":  func(m *Manager) error { m.SeedNATPortCounters(); return nil },
		"SeedSessionIDCounter": func(m *Manager) error { m.SeedSessionIDCounter(0); return nil },
		"DeleteStaleIfaceZone": func(m *Manager) error { m.DeleteStaleIfaceZone(nil); return nil },
		"DeleteStaleVlanIface": func(m *Manager) error { m.DeleteStaleVlanIface(nil); return nil },
		"DeleteStaleZonePairPolicies": func(m *Manager) error {
			m.DeleteStaleZonePairPolicies(nil)
			return nil
		},
		"DeleteStaleApplications": func(m *Manager) error { m.DeleteStaleApplications(nil); return nil },
		"DeleteStaleDNATStatic":   func(m *Manager) error { m.DeleteStaleDNATStatic(nil); return nil },
		"DeleteStaleDNATStaticV6": func(m *Manager) error { m.DeleteStaleDNATStaticV6(nil); return nil },
		"DeleteStaleStaticNAT":    func(m *Manager) error { m.DeleteStaleStaticNAT(nil, nil); return nil },
		"ZeroStaleScreenConfigs":  func(m *Manager) error { m.ZeroStaleScreenConfigs(0); return nil },
		"DeleteStaleIfaceFilter":  func(m *Manager) error { m.DeleteStaleIfaceFilter(nil); return nil },
		"ZeroStaleFilterConfigs":  func(m *Manager) error { m.ZeroStaleFilterConfigs(0); return nil },

		// class 3 (hybrids: pinned side-effect + legacy outcome in every state)
		"ClearNATRuleCounters": func(m *Manager) error { return m.ClearNATRuleCounters() },
		"ClearGlobalCounters":  func(m *Manager) error { return m.ClearGlobalCounters() },
		"ClearZoneCounters":    func(m *Manager) error { return m.ClearZoneCounters() },
		"ClearAllCounters":     func(m *Manager) error { return m.ClearAllCounters() },
	}
}

// armedGateClass1Hosts returns the helper-consuming class-1 method names
// (everything in armedGateInvoke that the manifest marks class1).
func armedGateClass1Hosts() map[string]bool {
	out := map[string]bool{}
	for name, class := range managerMethodClasses {
		if class == "class1" {
			out[name] = true
		}
	}
	return out
}

// TestManager_ArmedGate_FreshOutcomes is the quiescent FRESH leg (plan leg
// 1): on a never-armed manager every class-1 method returns the typed
// ErrDataplaneNotArmed (replacing master's per-map not-found error), the
// carve-out set keeps master's own pre-registry rejection, class-2 keeps
// master's neutral outcome byte-for-byte, class-3 keeps the pinned legacy
// behavior (ClearAllCounters surfaces the tolerated "interface_counters map
// not found" through the raw composition), and the class-4 getters return
// nil (NewEventSource: the typed error — its signature carries one).
func TestManager_ArmedGate_FreshOutcomes(t *testing.T) {
	m := New()
	invoke := armedGateInvoke()
	class1 := armedGateClass1Hosts()

	for name, call := range invoke {
		err := call(m)
		switch {
		case class1[name]:
			if !errors.Is(err, ErrDataplaneNotArmed) {
				t.Errorf("fresh %s = %v, want errors.Is ErrDataplaneNotArmed", name, err)
			}
		default:
			// class 2: neutral (nil). class 3 handled below.
			if name == "ClearAllCounters" {
				// Pinned legacy text through the raw composition.
				if err == nil || !strings.Contains(err.Error(), "interface_counters map not found") {
					t.Errorf("fresh ClearAllCounters = %v, want the pinned legacy interface_counters text", err)
				}
				if errors.Is(err, ErrDataplaneNotArmed) {
					t.Errorf("fresh ClearAllCounters must NOT surface the typed gate error (nested-call rule)")
				}
				continue
			}
			if managerMethodClasses[name] == "class3" || managerMethodClasses[name] == "class2" {
				if err != nil {
					t.Errorf("fresh %s (%s) = %v, want nil (neutral/pinned)", name, managerMethodClasses[name], err)
				}
			}
		}
	}

	// Carve-out set: master's own pre-registry rejections on the fresh
	// state; the typed error never fires for them.
	if err := m.AttachXDP(1, false); err == nil || err.Error() != "eBPF programs not loaded" {
		t.Errorf("fresh AttachXDP = %v, want master's loaded rejection", err)
	}
	if err := m.AttachTC(1); err == nil || err.Error() != "eBPF programs not loaded" {
		t.Errorf("fresh AttachTC = %v, want master's loaded rejection", err)
	}
	if _, err := m.Compile(nil); err == nil || err.Error() != "nil config" {
		t.Errorf("fresh Compile(nil) = %v, want the nil-config validation error (pure validation precedes the gate)", err)
	}

	// The CompileConfig path's own loaded rejection (the carve-out):
	// fires on the fresh state with master's text.
	if _, err := m.Compile(&config.Config{}); err == nil || err.Error() != "dataplane not loaded" {
		t.Errorf("fresh Compile(empty) = %v, want master's CompileConfig loaded rejection", err)
	}

	// Class 4 getters.
	if got := m.Map("sessions"); got != nil {
		t.Errorf("fresh Map(sessions) = %v, want nil", got)
	}
	if got := m.Program("xdp_userspace_prog"); got != nil {
		t.Errorf("fresh Program = %v, want nil", got)
	}
	if _, err := m.NewEventSource(); !errors.Is(err, ErrDataplaneNotArmed) {
		t.Errorf("fresh NewEventSource = %v, want errors.Is ErrDataplaneNotArmed", err)
	}
}

// TestManager_ArmedGate_RetainedOutcomes is the quiescent RETAINED leg
// (plan leg 2): a seeded-but-unarmed registry (loaded=false, maps present
// — the armed-Close/Teardown-retain shape) makes every class proceed
// EXACTLY as master: class-1 methods return master's per-map not-found
// error (never the typed error), class-2 keep the neutral outcome, class-3
// keep the pinned legacy behavior, the carve-out set still rejects via its
// own loaded check, and the class-4 getters keep master's nil/text
// outcomes.
func TestManager_ArmedGate_RetainedOutcomes(t *testing.T) {
	m := New()
	armedGateSentinel(m)
	m.loaded.Store(false)

	invoke := armedGateInvoke()
	class1 := armedGateClass1Hosts()
	for name, call := range invoke {
		err := call(m)
		switch {
		case class1[name]:
			if errors.Is(err, ErrDataplaneNotArmed) {
				t.Errorf("retained %s = %v, must NOT be the typed gate error (retained proceeds as master)", name, err)
			}
			if err == nil || !strings.Contains(err.Error(), "not found") {
				t.Errorf("retained %s = %v, want master's per-map not-found error", name, err)
			}
		default:
			if name == "ClearAllCounters" {
				if err == nil || !strings.Contains(err.Error(), "interface_counters map not found") {
					t.Errorf("retained ClearAllCounters = %v, want the pinned legacy interface_counters text", err)
				}
				continue
			}
			if managerMethodClasses[name] == "class3" || managerMethodClasses[name] == "class2" {
				if err != nil {
					t.Errorf("retained %s (%s) = %v, want nil (neutral/pinned)", name, managerMethodClasses[name], err)
				}
			}
		}
	}

	// Carve-out set rejects on the retained state too (loaded==false).
	if err := m.AttachXDP(1, false); err == nil || err.Error() != "eBPF programs not loaded" {
		t.Errorf("retained AttachXDP = %v, want master's loaded rejection", err)
	}
	if _, err := m.Compile(&config.Config{}); err == nil || err.Error() != "dataplane not loaded" {
		t.Errorf("retained Compile(empty) = %v, want master's CompileConfig loaded rejection", err)
	}

	// Class 4: master's missing outcomes.
	if got := m.Map("sessions"); got != nil {
		t.Errorf("retained Map(sessions) = %v, want nil", got)
	}
	if _, err := m.NewEventSource(); err == nil || err.Error() != "events map not loaded" || errors.Is(err, ErrDataplaneNotArmed) {
		t.Errorf("retained NewEventSource = %v, want master's events-map text (not the typed error)", err)
	}
}

// runSyntheticStart drives LoadUserspaceShim with the acquisition seam
// replaced by a synthetic registry (the publisher still runs the
// production code path). Returns a channel receiving the Start result.
// The seam restore is the CALLER's job (defer restoreShimPrePublishLoad)
// and must run only after the Start result is received — an asynchronous
// restore races the next test's seam read (the -race gate caught exactly
// that here).
func runSyntheticStart(t *testing.T, m *Manager, registry map[string]*ebpf.Map) chan error {
	t.Helper()
	shimPrePublishLoad = func(m *Manager) error {
		m.publishShimRegistryLocked(nil, registry, nil)
		return nil
	}
	done := make(chan error, 1)
	go func() {
		done <- m.LoadUserspaceShim()
	}()
	return done
}

// productionShimPrePublishLoad captures the production loader at package
// init so the restore below can never drift from the loader.go body.
var productionShimPrePublishLoad = shimPrePublishLoad

// restoreShimPrePublishLoad puts the production loader back. Pair with
// runSyntheticStart via defer BEFORE the Start result is consumed.
func restoreShimPrePublishLoad() {
	shimPrePublishLoad = productionShimPrePublishLoad
}

// TestManager_ArmedGate_BlockedStart is the blocked FRESH-Start
// lock-ownership leg (plan leg 3): the whole-batch publication hold
// contains the test hook; helper-consuming readers from every class BLOCK
// until the hold releases, then observe the ARMED state (the in-hold
// Store(true) is the batch's final step).
func TestManager_ArmedGate_BlockedStart(t *testing.T) {
	m := New()
	invoke := armedGateInvoke()

	entered := make(chan struct{})
	release := make(chan struct{})
	shimRegistryPublishHook = func() {
		close(entered)
		<-release
	}
	defer func() { shimRegistryPublishHook = nil }()

	defer restoreShimPrePublishLoad()
	startDone := runSyntheticStart(t, m, map[string]*ebpf.Map{"sentinel_unused": nil})
	<-entered // the publisher holds m.mu, pre-Store(true)

	// Readers from every helper-consuming class block on the hold. Codex
	// PR #6743 r3-8: prove EVERY reader arrived at its contended m.mu
	// acquisition before the silence window — the previous
	// signal-before-call handshake plus sleep could pass with a goroutine
	// descheduled for the whole window (a false-green "it blocked"). The
	// starter waits for every helper-routed member's pre-lock probe fire
	// (the publisher's own fire preceded its park); the calibrated
	// direct-lock members are exempt per the pin.
	pending := startArmedGateInvoke(t, m, invoke)

	// None may complete during the hold.
	for _, p := range pending {
		select {
		case err := <-p.done:
			t.Fatalf("%s completed (%v) during the publication hold — the lookup did not block", p.name, err)
		default:
		}
	}
	if m.IsLoaded() {
		t.Fatal("IsLoaded() = true before the in-hold Store(true) — flag published outside the batch")
	}

	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("synthetic Start: %v", err)
	}
	if !m.IsLoaded() {
		t.Fatal("IsLoaded() = false after the publication batch")
	}

	// After release every reader observed the ARMED state: class-1 hosts
	// return master's per-map not-found error (never the fresh typed
	// error); class-2/3 keep their neutral/pinned outcomes.
	class1 := armedGateClass1Hosts()
	for _, p := range pending {
		err := <-p.done
		if class1[p.name] && errors.Is(err, ErrDataplaneNotArmed) {
			t.Errorf("post-release %s = %v, must not be the fresh gate error (armed observed)", p.name, err)
		}
	}
}

// TestManager_ArmedGate_PassThenBlock arms the post-Store seam (the plan's
// pass-then-block shape, Codex PR #6743 M4): a loaded-check method invoked
// DURING the pre-Store barrier rejects immediately with master's
// pre-registry rejection; a NEW invocation AFTER the in-hold Store(true)
// but BEFORE the unlock passes its loaded precheck and blocks at registry
// selection — and after release it returns the armed+absent outcome
// ("tc_main_prog not found"), proving the reader observed the ARMED state,
// not retained and not fresh. This is the leg that pins the in-hold
// Store(true) ordering: moving the Store after the unlock flips the second
// invocation's outcome and fails here. The probe is AttachTC deliberately:
// its tc_main_prog key is never written by the shim publisher, so the
// post-release lookup is a clean armed+absent miss (AttachXDP's
// xdp_userspace_prog IS written — a present-but-nil handle would proceed
// into link.AttachXDP and nil-deref, which is master's own fixture-only
// behavior and not what this leg measures).
func TestManager_ArmedGate_PassThenBlock(t *testing.T) {
	m := New()
	defer restoreShimPrePublishLoad()

	preStoreEntered := make(chan struct{})
	preStoreRelease := make(chan struct{})
	postStoreEntered := make(chan struct{})
	postStoreRelease := make(chan struct{})
	shimRegistryPublishHook = func() {
		close(preStoreEntered)
		<-preStoreRelease
	}
	shimRegistryPublishPostStoreHook = func() {
		close(postStoreEntered)
		<-postStoreRelease
	}
	defer func() {
		shimRegistryPublishHook = nil
		shimRegistryPublishPostStoreHook = nil
	}()

	startDone := runSyntheticStart(t, m, map[string]*ebpf.Map{"sentinel_unused": nil})
	<-preStoreEntered // in-hold, BEFORE Store(true)

	// Pre-Store: the loaded-check carve-out rejects immediately (loaded is
	// still false), never reaching the registry.
	if err := m.AttachTC(1); err == nil || err.Error() != "eBPF programs not loaded" {
		t.Fatalf("pre-Store AttachTC = %v, want the pre-registry loaded rejection", err)
	}

	close(preStoreRelease)
	<-postStoreEntered // in-hold, AFTER Store(true), before unlock

	// Post-Store: a NEW invocation passes the loaded precheck and blocks at
	// registry selection (the publisher still holds m.mu). The arrival
	// signal fires from the muAcquireProbeHook seam INSIDE the contended
	// call (Codex PR #6743 r3-8) — a pre-call handshake could pass the
	// timeout below without the goroutine ever reaching m.mu.
	probeArrived, disarmProbe := armMuProbeArrival()
	defer disarmProbe()
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- m.AttachTC(1)
	}()
	<-probeArrived
	select {
	case err := <-attachDone:
		t.Fatalf("post-Store AttachTC completed (%v) while the publisher held m.mu — did not block at registry selection", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(postStoreRelease)
	if err := <-startDone; err != nil {
		t.Fatalf("synthetic Start: %v", err)
	}
	// After release the invocation observes ARMED + absent: master's
	// not-found text (never the fresh typed error, never the loaded
	// rejection).
	err := <-attachDone
	if err == nil || err.Error() != "tc_main_prog not found" {
		t.Fatalf("post-release AttachTC = %v, want armed+absent master's text", err)
	}
	if errors.Is(err, ErrDataplaneNotArmed) {
		t.Fatal("post-release AttachTC returned the fresh gate error — the in-hold Store ordering is broken")
	}
}

// TestManager_ArmedGate_RetainedReStartOverlap is the blocked
// RETAINED-re-Start leg (plan leg 4): the retained fixture (registry
// populated, loaded=false — the bootstrap/hitless-restart posture) driven
// through the blocked re-Start; every class's readers block until the hold
// releases and observe the ARMED state after it.
func TestManager_ArmedGate_RetainedReStartOverlap(t *testing.T) {
	m := New()
	armedGateSentinel(m)
	m.loaded.Store(false)

	invoke := armedGateInvoke()
	entered := make(chan struct{})
	release := make(chan struct{})
	shimRegistryPublishHook = func() {
		close(entered)
		<-release
	}
	defer func() { shimRegistryPublishHook = nil }()

	// The re-Start publishes only sentinel names nothing looks up: readers
	// released from the hold observe the ARMED state with their own maps
	// ABSENT (master's not-found outcomes), never a present-but-nil handle
	// — production never publishes nil maps, so no method may proceed
	// against one here.
	defer restoreShimPrePublishLoad()
	startDone := runSyntheticStart(t, m, map[string]*ebpf.Map{"sentinel_restart": nil})
	<-entered

	// Codex PR #6743 r3-8: same arrival proof as the fresh blocked-Start
	// leg — every helper-routed reader must PROVABLY reach its contended
	// m.mu acquisition before the silence window.
	pending := startArmedGateInvoke(t, m, invoke)
	for _, p := range pending {
		select {
		case err := <-p.done:
			t.Fatalf("%s completed (%v) during the retained re-Start hold — the lookup did not block", p.name, err)
		default:
		}
	}
	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("synthetic re-Start: %v", err)
	}
	class1 := armedGateClass1Hosts()
	for _, p := range pending {
		err := <-p.done
		if class1[p.name] && errors.Is(err, ErrDataplaneNotArmed) {
			t.Errorf("post-release %s = %v, must not be the fresh gate error", p.name, err)
		}
	}
}

// TestManager_ArmedGate_CloseWindowIsLoaded is the ISLOADED-WINDOW leg
// (plan leg 5): an armed manager's Close() is held at the test hook
// immediately AFTER the entry Store(false) and BEFORE the link-handle
// closes; a concurrent IsLoaded() read observes false DURING the window,
// where master (flip at the exit) would still report true. The registry
// stays populated (retained) across Close.
func TestManager_ArmedGate_CloseWindowIsLoaded(t *testing.T) {
	m := New()
	armedGateSentinel(m)
	m.loaded.Store(true)

	entered := make(chan struct{})
	release := make(chan struct{})
	closeWindowHook = func() {
		close(entered)
		<-release
	}
	defer func() { closeWindowHook = nil }()

	closeDone := make(chan error, 1)
	go func() { closeDone <- m.Close() }()
	<-entered

	// Inside the window: the externally visible surface already reports
	// unarmed (the intended early-report semantics), and the registry is
	// still populated.
	if m.IsLoaded() {
		t.Fatal("IsLoaded() = true during the Close window — the entry Store(false) did not land first")
	}
	if len(m.maps) == 0 {
		t.Fatal("Close cleared the registry — the hitless-restart retain posture broke")
	}

	close(release)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if m.IsLoaded() {
		t.Fatal("IsLoaded() = true after Close")
	}
	// Post-Close the manager classifies RETAINED: a class-1 method keeps
	// master's not-found outcome rather than the fresh typed error.
	if err := m.UpdateRGActive(0, true); err == nil ||
		!strings.Contains(err.Error(), "rg_active map not found") || errors.Is(err, ErrDataplaneNotArmed) {
		t.Fatalf("post-Close UpdateRGActive = %v, want master's retained not-found", err)
	}
}

// TestManager_ArmedGate_LookupOwnership exercises BOTH typed helpers' lock
// ownership directly (the reverse-schedule guard): while a helper's own
// section holds the test hook, a racing publisher attempt blocks until the
// hold releases — proving the classification + handle selection and the
// publication batch are mutually exclusive under m.mu.
func TestManager_ArmedGate_LookupOwnership(t *testing.T) {
	for _, which := range []string{"map", "program"} {
		t.Run(which, func(t *testing.T) {
			m := New()
			armedGateSentinel(m)

			entered := make(chan struct{})
			release := make(chan struct{})
			registryLookupHook = func() {
				select {
				case <-entered:
				default:
					close(entered)
					<-release
				}
			}
			defer func() { registryLookupHook = nil }()

			lookupDone := make(chan struct{})
			go func() {
				defer close(lookupDone)
				if which == "map" {
					m.lookupMapLocked("sessions")
				} else {
					m.lookupProgramLocked("xdp_userspace_prog")
				}
			}()
			<-entered // the helper holds m.mu

			probeArrived, disarmProbe := armMuProbeArrival()
			defer disarmProbe()
			pubDone := make(chan struct{})
			go func() {
				defer close(pubDone)
				m.publishShimRegistryLocked(nil, map[string]*ebpf.Map{"sessions": nil}, nil)
			}()
			<-probeArrived // the publisher provably reached the contended m.mu acquisition (r3-8)
			select {
			case <-pubDone:
				t.Fatal("publisher completed while the lookup helper held m.mu")
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			<-lookupDone
			<-pubDone
			if !m.IsLoaded() {
				t.Fatal("publisher did not run after the lookup released m.mu")
			}
		})
	}
}

// TestManager_ArmedGate_SwapXDPEntryProgOwnership pins the entry-program
// swap's field-write lock DIRECTLY: a direct swapXDPEntryProg call with a
// seeded distinct test program (retained fixture: nonempty m.maps AND
// m.programs — a nonempty programs registry alone does NOT classify
// retained) drives the write section while the hook holds it; a concurrent
// XDPEntryProgram() getter blocks until release.
func TestManager_ArmedGate_SwapXDPEntryProgOwnership(t *testing.T) {
	m := New()
	m.maps["sentinel_unused"] = nil // retained classification reads m.maps emptiness
	m.programs["test_prog"] = nil   // present-but-nil: the swap's lookup passes
	m.xdpEntryProg = "other"        // distinct from the target so the early exits fail
	m.loaded.Store(false)

	entered := make(chan struct{})
	release := make(chan struct{})
	swapXDPEntryProgHook = func() {
		close(entered)
		<-release
	}
	defer func() { swapXDPEntryProgHook = nil }()

	swapDone := make(chan error, 1)
	go func() { swapDone <- m.swapXDPEntryProg("test_prog") }()
	<-entered // the :632 write section holds m.mu

	probeArrived, disarmProbe := armMuProbeArrival()
	defer disarmProbe()
	getterDone := make(chan string, 1)
	go func() {
		getterDone <- m.XDPEntryProgram()
	}()
	<-probeArrived // the getter provably reached the contended m.mu acquisition (r3-8)
	select {
	case got := <-getterDone:
		t.Fatalf("XDPEntryProgram() = %q during the swap write hold — the getter did not block", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-swapDone; err != nil {
		t.Fatalf("swapXDPEntryProg: %v", err)
	}
	if got := <-getterDone; got != "test_prog" {
		t.Fatalf("XDPEntryProgram() after release = %q, want test_prog", got)
	}
}

// TestManager_ArmedGate_XDPSelectorTwoSided drives the LoadUserspaceShim
// selector write (the :154 arm) with getter/predicate driven across it:
// while the selector's m.mu section holds the hook, the public getter
// blocks; after release the getter and the predicate observe the userspace
// shim selection.
func TestManager_ArmedGate_XDPSelectorTwoSided(t *testing.T) {
	m := New()

	entered := make(chan struct{})
	release := make(chan struct{})
	xdpEntryProgSelectorHook = func() {
		select {
		case <-entered:
		default:
			close(entered)
			<-release
		}
	}
	defer func() { xdpEntryProgSelectorHook = nil }()

	defer restoreShimPrePublishLoad()
	shimPrePublishLoad = func(m *Manager) error {
		m.publishShimRegistryLocked(nil, map[string]*ebpf.Map{"sentinel_unused": nil}, nil)
		return nil
	}
	startDone := make(chan error, 1)
	go func() {
		startDone <- m.LoadUserspaceShim()
	}()
	<-entered // the selector write section holds m.mu

	probeArrived, disarmProbe := armMuProbeArrival()
	defer disarmProbe()
	getterDone := make(chan string, 1)
	go func() {
		getterDone <- m.XDPEntryProgram()
	}()
	<-probeArrived // the getter provably reached the contended m.mu acquisition (r3-8)
	select {
	case got := <-getterDone:
		t.Fatalf("XDPEntryProgram() = %q during the selector write hold — did not block", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("LoadUserspaceShim: %v", err)
	}
	if got := <-getterDone; got != userspaceShimEntryProg {
		t.Fatalf("XDPEntryProgram() after Start = %q, want %q", got, userspaceShimEntryProg)
	}
	if !m.UsingUserspaceXDPShimEntryProgram() {
		t.Fatal("UsingUserspaceXDPShimEntryProgram() = false after Start")
	}
}

// TestManager_ArmedGate_DetachRetainedClaims is the named Detach leg: a
// package-local fake link (overriding Unpin/Close), xdpLinks AND
// xdpFlagClaims seeded, and a usable iface_zone_map seeded; the detach's
// setXDPAttachedFlag(false) delegation target runs the claim cleanup on
// the retained registry (no gate) — claims are deleted and the fake link
// is unpinned+closed, race-free against the concurrent population actor.
// "Cleanup always runs" excludes master's absent-iface_zone_map early-boot
// no-op and any discovery-failure path (those preserve claims for retry).
//
// UNPROVEN WITHOUT BPF PRIVILEGE (Codex PR #6743 r6-F6). This leg needs a
// REAL ebpf.Hash map: the claim it makes is about setXDPAttachedFlag's
// registry lookup blocking on a concurrent publisher, and Manager.maps is
// typed map[string]*ebpf.Map, so there is no seam to substitute a fake
// through. Without CAP_BPF (or a sufficient MEMLOCK rlimit) the map
// creation fails and this test SKIPS — and a skipped cell is UNKNOWN, not
// a pass: on such a host NOTHING here is verified, and a regression in the
// detach claim-cleanup path would go unnoticed. Do not count this leg as
// covered unless the run log shows it EXECUTING. Making it privilege-free
// requires introducing a map interface in Manager (its own change), which
// #6743 deliberately does not attempt.
func TestManager_ArmedGate_DetachRetainedClaims(t *testing.T) {
	zoneMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "iface_zone_map",
		Type:       ebpf.Hash,
		KeySize:    uint32(sizeOf[IfaceZoneKey]()),
		ValueSize:  uint32(sizeOf[IfaceZoneValue]()),
		MaxEntries: 16,
	})
	if err != nil {
		skipIfBPFUnavailable(t, "new iface_zone_map", err)
		return
	}
	defer zoneMap.Close()

	m := New()
	m.maps["iface_zone_map"] = zoneMap
	m.loaded.Store(false) // retained

	fake := &armedGateFakeLink{}
	const ifindex = 42
	m.xdpLinks[ifindex] = fake
	key := IfaceZoneKey{Ifindex: ifindex, VlanID: 0}
	m.xdpFlagClaims[key] = map[int]bool{ifindex: true}

	// The concurrent population actor (the blocked re-Start seam): the
	// publisher holds m.mu mid-detach; the detach's setXDPAttachedFlag
	// registry lookup must BLOCK on the hold and complete after release —
	// race-clean (a raw lookup slipped into the flag path would race the
	// publisher's writes and trip -race here).
	entered := make(chan struct{})
	release := make(chan struct{})
	shimRegistryPublishHook = func() {
		close(entered)
		<-release
	}
	defer func() { shimRegistryPublishHook = nil }()
	defer restoreShimPrePublishLoad()
	startDone := runSyntheticStart(t, m, map[string]*ebpf.Map{"sentinel_restart": nil})
	<-entered

	probeArrived, disarmProbe := armMuProbeArrival()
	defer disarmProbe()
	detachDone := make(chan error, 1)
	go func() {
		detachDone <- m.DetachXDP(ifindex)
	}()
	// #9337: BOUNDED. This wait was bare, and when the probed surface stopped
	// being the detach's first contended acquisition it stopped firing — the
	// cell then hung for the package's whole 15-minute budget and voided every
	// later cell in pkg/dataplane rather than failing. A hang leaves no trace;
	// a named failure does.
	select {
	case <-probeArrived: // the detach provably reached a contended m.mu acquisition (r3-8)
	case <-time.After(30 * time.Second):
		t.Fatal("DetachXDP never fired muAcquireProbeHook: its first contended m.mu " +
			"acquisition is not one of the probed surfaces, so the arrival proof below " +
			"is vacuous. Add the pre-lock fire to the surface it actually blocks on " +
			"(see the hook's doc comment in armed_gate.go).")
	}
	select {
	case err := <-detachDone:
		t.Fatalf("DetachXDP completed (%v) during the publication hold — its registry lookup did not block", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-startDone; err != nil {
		t.Fatalf("synthetic re-Start: %v", err)
	}
	if err := <-detachDone; err != nil {
		t.Fatalf("DetachXDP: %v", err)
	}
	if _, still := m.xdpFlagClaims[key]; still {
		t.Fatal("DetachXDP left the stale claim behind (the retained-registry cleanup did not run)")
	}
	if _, still := m.xdpLinks[ifindex]; still {
		t.Fatal("DetachXDP left the link in xdpLinks")
	}
	if !fake.unpinned || !fake.closed {
		t.Fatalf("fake link lifecycle = unpinned:%v closed:%v, want both", fake.unpinned, fake.closed)
	}
}

// TestManager_ArmedGate_DetachAbsentLinkNoRegistryAccess is the absent-link
// oracle (Codex PR #6743 M6): DetachXDP on an ifindex with NO attached link
// returns nil at the category-G early return and must NOT touch the
// registry at all — the registryLookupHook tripwire fails the test if any
// lookup helper fires.
func TestManager_ArmedGate_DetachAbsentLinkNoRegistryAccess(t *testing.T) {
	m := New()
	m.maps["sentinel_unused"] = nil // retained; irrelevant to the absent-link path

	var tripwire atomic.Int32
	registryLookupHook = func() { tripwire.Add(1) }
	defer func() { registryLookupHook = nil }()

	if err := m.DetachXDP(4242); err != nil {
		t.Fatalf("DetachXDP(absent link) = %v, want nil (master's category-G early return)", err)
	}
	if got := tripwire.Load(); got != 0 {
		t.Fatalf("absent-link DetachXDP touched the registry %d times — the early return must not reach a lookup helper", got)
	}
}

// armedGateFakeLink embeds link.Link (the interface carries an unexported
// marker, so it cannot be implemented externally) and overrides exactly the
// two methods DetachXDP invokes.
type armedGateFakeLink struct {
	link.Link
	unpinned bool
	closed   bool
}

func (l *armedGateFakeLink) Unpin() error { l.unpinned = true; return nil }
func (l *armedGateFakeLink) Close() error { l.closed = true; return nil }

// TestManagerTeardownClearsLinkMembership is the Codex PR #6743 r3-1
// regression leg: Teardown (Close + Cleanup) destroys the kernel links,
// so the xdpLinks/tcLinks membership it leaves behind must be EMPTY —
// otherwise a same-process re-Start (the commit-confirmed rollback →
// bootstrap-exit re-arm) hits AttachXDP's stale-membership short-circuit,
// attachUserspaceShimXDP swallows the "already attached" error, and the
// corrected commit reports success with no AF_XDP ingress. Fail-on-
// revert: without the Teardown clear the memberships survive and the
// assertions fail. The filesystem sweep is neutralized through the
// teardownCleanupFn seam (the real Cleanup unpins and removes the
// production /sys/fs/bpf/xpf tree). The second half pins the Close-only
// polarity: Close keeps the membership because its pinned kernel links
// stay live for hitless restart — a "clear in Close too" simplification
// would make a post-Close AttachXDP double-attach over a live link.
func TestManagerTeardownClearsLinkMembership(t *testing.T) {
	defer func(fn func() error) { teardownCleanupFn = fn }(teardownCleanupFn)
	teardownCleanupFn = func() error { return nil }

	xdpFake := &armedGateFakeLink{}
	tcFake := &armedGateFakeLink{}
	m := New()
	m.xdpLinks[7] = xdpFake
	m.tcLinks[9] = tcFake

	if err := m.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if !xdpFake.closed || !tcFake.closed {
		t.Fatalf("Teardown did not close the link handles (xdp:%v tc:%v)", xdpFake.closed, tcFake.closed)
	}
	if len(m.xdpLinks) != 0 || len(m.tcLinks) != 0 {
		t.Fatalf("Teardown left stale link membership (xdp:%d tc:%d) — a re-Start would skip re-attach on the destroyed links",
			len(m.xdpLinks), len(m.tcLinks))
	}

	// Close-only polarity: the hitless path keeps the pinned kernel links
	// live, so the membership must survive Close. #9847: Close reports a
	// degraded shutdown when a registered link has no pin, so the fixture
	// provides one — an unpinned registered link is the degraded shape,
	// covered by TestCloseReportsDegradedOnUnpinnedXDPLink_9847.
	pinDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pinDir, "xdp_11"), []byte{}, 0600); err != nil {
		t.Fatalf("seed pin: %v", err)
	}
	oldPinPath := linkPinPath
	linkPinPath = pinDir
	defer func() { linkPinPath = oldPinPath }()
	m2 := New()
	m2.xdpLinks[11] = &armedGateFakeLink{}
	if err := m2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(m2.xdpLinks) != 1 {
		t.Fatal("Close cleared the xdpLinks membership — a post-Close AttachXDP would double-attach over the live pinned link")
	}
}

// TestManager_ArmedGate_AbsentIfaceZoneMapNoOp is continuation leg (iii):
// with iface_zone_map ABSENT (armed or retained), setXDPAttachedFlag
// returns master's early-boot no-op NIL and does NOT touch the claims —
// distinct from the Detach leg's map-present cleanup. Always-on (no BPF
// needed: the early return precedes any map use).
func TestManager_ArmedGate_AbsentIfaceZoneMapNoOp(t *testing.T) {
	for _, armed := range []bool{false, true} {
		m := New()
		armedGateSentinel(m) // retained classification (registry nonempty, map absent)
		m.loaded.Store(armed)
		key := IfaceZoneKey{Ifindex: 7, VlanID: 0}
		m.xdpFlagClaims[key] = map[int]bool{7: true}
		if err := m.setXDPAttachedFlag(7, false); err != nil {
			t.Fatalf("armed=%v: setXDPAttachedFlag = %v, want master's early-boot no-op nil", armed, err)
		}
		if _, still := m.xdpFlagClaims[key]; !still {
			t.Fatalf("armed=%v: absent-iface_zone_map path must not touch the claims", armed)
		}
	}
}

// TestManager_ArmedGate_SeedInterfaceCounterNilGuard is continuation leg
// (ii), absent half (always-on): with interface_counters ABSENT,
// AddTxPort's seed skips silently (master's nil-guard return), NOT a
// spurious error — here on an armed manager with a real tx_ports map so
// the post-seed success is observable. The present half (the seed writes)
// needs a real PERCPU_HASH and joins the privileged set below.
func TestManager_ArmedGate_SeedInterfaceCounterNilGuard(t *testing.T) {
	txPorts, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "tx_ports",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: MaxInterfaces,
	})
	if err != nil {
		skipIfBPFUnavailable(t, "new tx_ports map", err)
		return
	}
	defer txPorts.Close()

	m := New()
	m.maps["tx_ports"] = txPorts // interface_counters deliberately ABSENT
	m.loaded.Store(true)

	if err := m.AddTxPort(1); err != nil {
		t.Fatalf("AddTxPort with absent interface_counters = %v, want nil (the seed's nil-guard skip)", err)
	}
}

// TestManager_ArmedGate_ContinuationLegsPrivileged is the privileged
// semantic-mutation set (plan's oracle split): real-map fixtures assert
// the mixed-method CONTINUATION behavior that a premature optional-miss
// return would break. Skips where BPF map creation is unavailable.
//
// Coverage note (Codex PR #6743 r2-6 — the r1 production-coverage
// disposition was REBUTTED and is corrected here): root
// (*dataplane.Manager).Compile is DEAD IN PRODUCTION — the daemon's
// runtime dataplane is always the userspace adapter, whose compile path
// runs CompileUserspaceShim (userspace/manager_compile.go), never the
// root Compile (compiler.go:316). The root Compile remains only as a
// retired-DataPlane interface obligation, so its :353 continuation
// outcome is a dead-surface property; reaching :353 in a unit test would
// require a full successful zone compile (every required map seeded)
// plus netlink interface mutation, which no test environment may perform
// safely. What IS pinned: (a) the :353 read goes through the scoped
// registry helper, so even a hypothetical live call is race-safe; (b)
// the daemon-constructor pin in pkg/daemon
// (TestRuntimeDataplaneNeverBareRootManager) fails if the root Manager
// ever becomes the daemon's dataplane again — which would make :353
// live and REQUIRE a continuation leg at that time; (c) Compile's
// fresh/retained outcomes (the CompileConfig loaded rejection on both
// unarmed states) are asserted directly in the fresh/retained legs above.
func TestManager_ArmedGate_ContinuationLegsPrivileged(t *testing.T) {
	newArray := func(st *testing.T, name string, valueSize, maxEntries uint32) *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name: name, Type: ebpf.Array, KeySize: 4,
			ValueSize: valueSize, MaxEntries: maxEntries,
		})
		if err != nil {
			skipIfBPFUnavailable(st, "new "+name, err)
		}
		st.Cleanup(func() { m.Close() })
		return m
	}
	newHash := func(st *testing.T, name string, keySize, valueSize, maxEntries uint32) *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name: name, Type: ebpf.Hash, KeySize: keySize,
			ValueSize: valueSize, MaxEntries: maxEntries,
		})
		if err != nil {
			skipIfBPFUnavailable(st, "new "+name, err)
		}
		st.Cleanup(func() { m.Close() })
		return m
	}
	newPerCPUHash := func(st *testing.T, name string, keySize, valueSize, maxEntries uint32) *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name: name, Type: ebpf.PerCPUHash, KeySize: keySize,
			ValueSize: valueSize, MaxEntries: maxEntries,
		})
		if err != nil {
			skipIfBPFUnavailable(st, "new "+name, err)
		}
		st.Cleanup(func() { m.Close() })
		return m
	}
	// newPerCPUArray matches the production nat_port_counters shape
	// (perCPUArrayMapSpec, loader_userspace_shim.go) — a plain ARRAY
	// rejects the per-CPU slice Update/Lookup the seed path uses (Codex
	// PR #6743 m1).
	newPerCPUArray := func(st *testing.T, name string, valueSize, maxEntries uint32) *ebpf.Map {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name: name, Type: ebpf.PerCPUArray, KeySize: 4,
			ValueSize: valueSize, MaxEntries: maxEntries,
		})
		if err != nil {
			skipIfBPFUnavailable(st, "new "+name, err)
		}
		st.Cleanup(func() { m.Close() })
		return m
	}

	for _, armed := range []bool{true, false} {
		name := "retained"
		if armed {
			name = "armed"
		}

		t.Run(name+"_SessionCount_absent_first_family_continues", func(t *testing.T) {
			// Discriminating continuation (Codex PR #6743 M5): sessions is
			// ABSENT, sessions_v6 present with an entry — the v4-absent path
			// must CONTINUE to the v6 count (a premature first-miss return
			// reports (0,0) and fails).
			m := New()
			v6 := newHash(t, "sessions_v6", uint32(sizeOf[SessionKeyV6]()), ConntrackSessionValueSizeV6, 8)
			m.maps["sessions_v6"] = v6
			m.loaded.Store(armed)

			k6 := SessionKeyV6{Protocol: 6}
			if err := v6.Update(k6, make([]byte, ConntrackSessionValueSizeV6), ebpf.UpdateAny); err != nil {
				t.Fatalf("seed sessions_v6: %v", err)
			}
			got4, got6 := m.SessionCount()
			if got4 != 0 || got6 != 1 {
				t.Fatalf("SessionCount = (%d,%d), want (0,1) — the absent v4 lookup must continue to v6", got4, got6)
			}
		})

		t.Run(name+"_SessionCount_both_present", func(t *testing.T) {
			// Both-present complement of the absent-first leg (Codex PR
			// #6743 r2-7): the continuation leg alone would pass if the
			// first map's count were dropped entirely.
			m := New()
			v4 := newHash(t, "sessions", uint32(sizeOf[SessionKey]()), ConntrackSessionValueSize, 8)
			v6 := newHash(t, "sessions_v6", uint32(sizeOf[SessionKeyV6]()), ConntrackSessionValueSizeV6, 8)
			m.maps["sessions"] = v4
			m.maps["sessions_v6"] = v6
			m.loaded.Store(armed)

			if err := v4.Update(SessionKey{Protocol: 6}, make([]byte, ConntrackSessionValueSize), ebpf.UpdateAny); err != nil {
				t.Fatalf("seed sessions: %v", err)
			}
			if err := v6.Update(SessionKeyV6{Protocol: 6}, make([]byte, ConntrackSessionValueSizeV6), ebpf.UpdateAny); err != nil {
				t.Fatalf("seed sessions_v6: %v", err)
			}
			got4, got6 := m.SessionCount()
			if got4 != 1 || got6 != 1 {
				t.Fatalf("SessionCount = (%d,%d), want (1,1) — both families counted", got4, got6)
			}
		})

		t.Run(name+"_ClearSessionCounts_absent_first_map_continues", func(t *testing.T) {
			// session_count_src ABSENT, dst present with an entry — the
			// loop's first-miss continue must reach the second map.
			m := New()
			dst := newHash(t, "session_count_dst", uint32(sizeOf[SessionCountKey]()), uint32(sizeOf[SessionCountValue]()), 8)
			m.maps["session_count_dst"] = dst
			m.loaded.Store(armed)

			k := SessionCountKey{}
			if err := dst.Update(k, SessionCountValue{Count: 4}, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed dst: %v", err)
			}
			if err := m.ClearSessionCounts(); err != nil {
				t.Fatalf("ClearSessionCounts = %v", err)
			}
			var out SessionCountValue
			if err := dst.Lookup(k, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("dst entry survives (err=%v) — the loop's first-miss continue did not reach the second map", err)
			}
		})

		t.Run(name+"_ClearSessionCounts_both_present", func(t *testing.T) {
			// Both-present complement (r2-7): dropping the source map's
			// clear must fail here even though the absent-first leg passes.
			m := New()
			srcM := newHash(t, "session_count_src", uint32(sizeOf[SessionCountKey]()), uint32(sizeOf[SessionCountValue]()), 8)
			dstM := newHash(t, "session_count_dst", uint32(sizeOf[SessionCountKey]()), uint32(sizeOf[SessionCountValue]()), 8)
			m.maps["session_count_src"] = srcM
			m.maps["session_count_dst"] = dstM
			m.loaded.Store(armed)

			k := SessionCountKey{}
			if err := srcM.Update(k, SessionCountValue{Count: 3}, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed src: %v", err)
			}
			if err := dstM.Update(k, SessionCountValue{Count: 4}, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed dst: %v", err)
			}
			if err := m.ClearSessionCounts(); err != nil {
				t.Fatalf("ClearSessionCounts = %v", err)
			}
			var out SessionCountValue
			if err := srcM.Lookup(k, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("src entry survives (err=%v) — the first map was not cleared", err)
			}
			if err := dstM.Lookup(k, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("dst entry survives (err=%v) — the second map was not cleared", err)
			}
		})

		t.Run(name+"_GetMapStats_all_descriptors_reported", func(t *testing.T) {
			// Two descriptor maps present (one countable hash, one
			// non-countable array), the rest absent — both must be reported
			// and the absent descriptors skipped without aborting the loop.
			m := New()
			m.maps["sessions"] = newHash(t, "sessions", uint32(sizeOf[SessionKey]()), ConntrackSessionValueSize, 8)
			m.maps["zone_configs"] = newArray(t, "zone_configs", uint32(sizeOf[ZoneConfig]()), 8)
			m.loaded.Store(armed)

			stats := m.GetMapStats()
			var sawSessions, sawZoneConfigs bool
			for _, ms := range stats {
				if ms.Name == "sessions" {
					sawSessions = true
				}
				if ms.Name == "zone_configs" {
					sawZoneConfigs = true
				}
			}
			if !sawSessions || !sawZoneConfigs {
				t.Fatalf("GetMapStats = %+v, want sessions AND zone_configs reported (the descriptor loop must continue past absent maps)", stats)
			}
		})

		t.Run(name+"_DeleteStaleStaticNAT_absent_v4_continues", func(t *testing.T) {
			// static_nat_v4 ABSENT, v6 present with a stale entry — the
			// absent-v4 path must continue and delete the v6 entry.
			m := New()
			v6 := newHash(t, "static_nat_v6", uint32(sizeOf[StaticNATKeyV6]()), uint32(sizeOf[StaticNATValueV6]()), 8)
			m.maps["static_nat_v6"] = v6
			m.loaded.Store(armed)

			stale := StaticNATKeyV6{Direction: 9}
			if err := v6.Update(stale, StaticNATValueV6{}, ebpf.UpdateAny); err != nil {
				t.Fatalf("seed static_nat_v6: %v", err)
			}
			m.DeleteStaleStaticNAT(nil, nil) // nothing written => everything stale
			var out StaticNATValueV6
			if err := v6.Lookup(stale, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("stale v6 entry survives (err=%v) — the absent-v4 path did not continue", err)
			}
		})

		t.Run(name+"_AddTxPort_seeds_interface_counter_when_present", func(t *testing.T) {
			// Leg (ii) present half: interface_counters present (real
			// PERCPU_HASH) + tx_ports present — AddTxPort succeeds AND the
			// seed entry exists, distinguishing the seed's write from the
			// nil-guard skip.
			m := New()
			ic := newPerCPUHash(t, "interface_counters", 4, uint32(sizeOf[InterfaceCounterValue]()), MaxInterfaces)
			m.maps["interface_counters"] = ic
			m.maps["tx_ports"] = newArray(t, "tx_ports", 8, MaxInterfaces)
			m.loaded.Store(armed)

			if err := m.AddTxPort(1); err != nil {
				t.Fatalf("AddTxPort = %v", err)
			}
			var vals []InterfaceCounterValue
			if err := ic.Lookup(uint32(1), &vals); err != nil {
				t.Fatalf("interface_counters[1] missing after AddTxPort: %v — the seed did not write", err)
			}
		})

		t.Run(name+"_SeedNATPortCounters_writes_when_present", func(t *testing.T) {
			// Leg (ii) present half: nat_port_counters present ⇒ the seed
			// writes (distinguishing the nil-guard skip from a spurious
			// error or a silent no-op).
			m := New()
			npc := newPerCPUArray(t, "nat_port_counters", uint32(sizeOf[NATPortCounter]()), 32)
			m.maps["nat_port_counters"] = npc
			m.loaded.Store(armed)

			m.SeedNATPortCounters()
			var vals []NATPortCounter
			if err := npc.Lookup(uint32(0), &vals); err != nil {
				t.Fatalf("read back nat_port_counters[0]: %v", err)
			}
			// A fresh PERCPU_ARRAY reads back zero-per-CPU before the seed;
			// the seed writes a random offset on CPU 0 (may theoretically be
			// 0 with probability 2^-64 — acceptable).
			nonzero := false
			for _, v := range vals {
				if v.Counter != 0 {
					nonzero = true
				}
			}
			if !nonzero {
				t.Fatal("nat_port_counters[0] all-zero after the seed — the present-map seed did not write")
			}
		})
	}
}
