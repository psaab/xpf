package userspace

import (
	"errors"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// Test-only observability hooks. Both are nil in production, so the only
// runtime cost is a nil check on the 1/15s counter-read path.
//
//   - policyRuleCounterIndexBuildObserver fires each time the ruleID->counter
//     index is built. A bulk ReadAllPolicyCounters builds it EXACTLY ONCE
//     (O(P+C)); a test asserts the read did not regress to the per-policy
//     rebuild the pre-#3965 ReadPolicyCounters loop performed (O(P*(P+C))).
//   - policyCounterResolveObserver fires AFTER ReadAllPolicyCounters releases
//     the snapshot lock, during the lock-free resolution phase. A test uses it
//     to assert the policy mutex is not held across the whole read
//     (snapshot-and-release), so a concurrent commit/apply is not starved.
var (
	policyRuleCounterIndexBuildObserver func()
	policyCounterResolveObserver        func()
)

func buildPolicyRuleCounterIndex(status *ProcessStatus) map[string]PolicyRuleCounterStatus {
	if policyRuleCounterIndexBuildObserver != nil {
		policyRuleCounterIndexBuildObserver()
	}
	index := make(map[string]PolicyRuleCounterStatus)
	if status == nil {
		return index
	}
	for _, counter := range status.PolicyRuleCounters {
		if counter.RuleID == "" {
			continue
		}
		index[counter.RuleID] = counter
	}
	return index
}

// policyRuleIDForCounter translates the numeric policy-counter handle used by
// the per-policy hit-count read callers into the stable rule ID that the
// userspace helper reports counters by.
//
// IMPORTANT — two distinct numeric namespaces coexist by design, and this
// resolver intentionally lives in the SLICE-INDEX one, NOT the span-accumulated
// snapshot-PolicyID one:
//
//   - The dataplane snapshot's PolicyRuleSnapshot.PolicyID (assigned by
//     walkPolicyRuleSlots / buildPolicySnapshots) is span-accumulated:
//     policySetID*MaxRulesPerPolicy + ruleIndex, where ruleIndex advances by the
//     application-set expansion count. That namespace serves the dataplane and
//     the RT_FLOW/event path.
//   - The per-policy COUNTER read path is name-keyed: the helper reports each
//     rule's packets/bytes under its stable RuleID string
//     (`from->to/name`, see PolicyRuleSnapshot.RuleID and
//     buildPolicyRuleCounterIndex). The numeric policyID passed to
//     ReadPolicyCounters is ONLY a handle the callers use to identify which
//     policy they want a name for. EVERY production caller
//     (pkg/api/metrics_counters.go, pkg/api/security.go,
//     pkg/cli/cli_show_security*.go, pkg/grpcapi/server_show_*.go) computes that
//     handle as policySetID*MaxRulesPerPolicy + sliceIndex, where sliceIndex is
//     the raw position in zpp.Policies — NOT the expanded ruleIndex.
//
// Therefore this resolver MUST decode the remainder as a direct slice index to
// agree with the callers. Decoding it as a span-accumulated index (mapping the
// handle into the preceding policy's expansion span) would mis-resolve the
// counter of every policy that follows a multi-application policy to the
// preceding policy. The counter store never indexes by the span-accumulated id
// (the helper is name-keyed; the legacy bpfShim policy_counters array is not
// incremented in userspace mode), so there is nothing to "round-trip" against —
// the only requirement is caller/resolver agreement, and both use slice index.
func policyRuleIDForCounter(cfg *config.Config, policyID uint32) string {
	// #3363: the reserved sentinel doubles as the read handle for the IMPLICIT
	// default-policy hit counter. The userspace helper reports that counter
	// under the stable rule id dataplane.DefaultPolicyName ("default-policy",
	// the same name rendered in RT_FLOW logs), so resolving the sentinel here
	// lets EVERY existing counter surface (CLI, gRPC text, REST, Prometheus)
	// read it via the unchanged ReadPolicyCounters(DefaultPolicySentinelID)
	// path — no new dataplane interface method. The sentinel can never collide
	// with a configured policy's computed id (see DefaultPolicySentinelID).
	if policyID == dataplane.DefaultPolicySentinelID {
		return dataplane.DefaultPolicyName
	}
	if cfg == nil {
		return ""
	}
	policySetID := policyID / dataplane.MaxRulesPerPolicy
	ruleIndex := policyID % dataplane.MaxRulesPerPolicy

	var currentSet uint32
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			// #3474: a nil zone-pair slot still consumes a policy-set ID. The
			// SSOT walker (walkPolicyRuleSlots) and EVERY production counter
			// caller (pkg/api/security.go, pkg/api/metrics_counters.go) do
			// `policySetID++` for a nil element of cfg.Security.Policies, so this
			// resolver advances currentSet in lockstep — it was the lone consumer
			// that skipped a nil slot WITHOUT incrementing, diverging from the
			// walker + all callers. This is DEFENSIVE SSOT-alignment, not a
			// reachable-bug fix: a nil cfg.Security.Policies slot is not produced
			// by any production config path today (strict and tolerant compile
			// share a non-nil-only builder; HA ships recompiled config text;
			// persistence round-trips the tree). Aligning it here matches the
			// #3476/#3494 defensive nil-guards so the resolver/walker/callers can
			// never drift if a nil slot ever does arise.
			currentSet++
			continue
		}
		if currentSet == policySetID {
			if int(ruleIndex) >= len(zpp.Policies) || zpp.Policies[ruleIndex] == nil {
				return ""
			}
			return stablePolicyRuleID(zpp.FromZone, zpp.ToZone, zpp.Policies[ruleIndex].Name)
		}
		currentSet++
	}
	if currentSet == policySetID {
		if int(ruleIndex) >= len(cfg.Security.GlobalPolicies) || cfg.Security.GlobalPolicies[ruleIndex] == nil {
			return ""
		}
		return stablePolicyRuleID("junos-global", "junos-global", cfg.Security.GlobalPolicies[ruleIndex].Name)
	}
	return ""
}

func (m *Manager) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	// The public DataPlane API is still indexed by legacy policy ID, while the
	// userspace helper reports counters by stable policy identity. Keep the
	// translation config-derived so scheduled-rule counters survive delete/re-add
	// and app-term slot expansion without callers recomputing Rust map slots.
	var total dataplane.CounterValue
	var innerErr error
	if m.bpfShim != nil {
		total, innerErr = m.bpfShim.ReadPolicyCounters(policyID)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cfg := (*config.Config)(nil)
	if m.lastSnapshot != nil {
		cfg = m.lastSnapshot.Config
	}
	ruleID := policyRuleIDForCounter(cfg, policyID)
	if ruleID == "" {
		if innerErr != nil {
			return dataplane.CounterValue{}, innerErr
		}
		return total, nil
	}
	counter, ok := buildPolicyRuleCounterIndex(&m.lastStatus)[ruleID]
	if !ok {
		if innerErr != nil {
			return dataplane.CounterValue{}, innerErr
		}
		if total == (dataplane.CounterValue{}) {
			return dataplane.CounterValue{}, ErrPolicyCounterUnpublished
		}
		return total, nil
	}
	total.Packets += counter.Packets
	total.Bytes += counter.Bytes
	return total, nil
}

// ErrPolicyCounterUnpublished is returned by the reader NewPolicyCounterReader
// builds for a policy whose per-rule counter the helper has not published. It
// mirrors the error the per-policy ReadPolicyCounters returned in userspace mode
// for the same case (the retired bpfShim map-not-found error surfaced when the
// helper counter was absent), so callers keep their existing degraded-read
// handling (Prometheus skip-and-bump, REST HTTP 500).
var ErrPolicyCounterUnpublished = errors.New("policy counter not published")

// ReadAllPolicyCounters returns every published per-policy counter keyed by the
// numeric policy-counter handle the read callers compute
// (policySetID*MaxRulesPerPolicy + sliceIndex, plus DefaultPolicySentinelID for
// the implicit default policy). It is the O(P+C), snapshot-and-release bulk read
// that replaces looping the per-policy ReadPolicyCounters on the observability
// paths (#3965).
//
// The pre-#3965 pattern — a Prometheus scrape (every ~15s) calling
// ReadPolicyCounters once per policy — was O(P*(P+C)) AND held the policy mutex
// m.mu for the ENTIRE read: each call rebuilt the whole ruleID->counter index
// (O(C)) and rescanned the config (O(P)) under the lock, so a firewall with many
// policies periodically starved commit/apply and session classification for the
// duration of the scrape. This method instead:
//
//   - takes m.mu only briefly to COPY the helper-published counter slice
//     (and, if the caller passes a nil config, the last snapshot config), then
//     releases it before doing any resolution/formatting;
//   - builds the ruleID->counter index EXACTLY ONCE (O(C));
//   - walks the config ONCE (O(P)), resolving each policy's handle -> ruleID ->
//     counter.
//
// The caller SHOULD pass the same config it walks for labels (the active
// config), so the returned handles line up with the caller's computed handles.
// A nil config falls back to the last published snapshot config.
//
// The retired-eBPF bpfShim policy_counters array is intentionally NOT consulted:
// it is never incremented in userspace mode (the only runtime forwarding path),
// so it contributes zero. The single-policy ReadPolicyCounters retains the
// bpfShim add solely for legacy API parity.
func (m *Manager) ReadAllPolicyCounters(cfg *config.Config) (map[uint32]dataplane.CounterValue, error) {
	m.mu.Lock()
	if cfg == nil && m.lastSnapshot != nil {
		cfg = m.lastSnapshot.Config
	}
	counters := append([]PolicyRuleCounterStatus(nil), m.lastStatus.PolicyRuleCounters...)
	m.mu.Unlock()

	if policyCounterResolveObserver != nil {
		policyCounterResolveObserver()
	}

	result := make(map[uint32]dataplane.CounterValue)
	if cfg == nil {
		return result, nil
	}
	index := buildPolicyRuleCounterIndex(&ProcessStatus{PolicyRuleCounters: counters})

	put := func(policyID uint32, ruleID string) {
		if c, ok := index[ruleID]; ok {
			result[policyID] = dataplane.CounterValue{Packets: c.Packets, Bytes: c.Bytes}
		}
	}

	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			// A nil zone-pair slot still consumes a policy-set ID, matching
			// policyRuleIDForCounter and every counter caller.
			policySetID++
			continue
		}
		for i, rule := range zpp.Policies {
			if rule == nil {
				continue
			}
			put(policySetID*dataplane.MaxRulesPerPolicy+uint32(i),
				stablePolicyRuleID(zpp.FromZone, zpp.ToZone, rule.Name))
		}
		policySetID++
	}
	for i, rule := range cfg.Security.GlobalPolicies {
		if rule == nil {
			continue
		}
		put(policySetID*dataplane.MaxRulesPerPolicy+uint32(i),
			stablePolicyRuleID("junos-global", "junos-global", rule.Name))
	}
	// #3363: the implicit default-policy hit counter is published under the
	// stable rule id dataplane.DefaultPolicyName and read via the reserved
	// sentinel handle.
	put(dataplane.DefaultPolicySentinelID, dataplane.DefaultPolicyName)

	return result, nil
}

// NewPolicyCounterReader returns a per-policy counter reader that the
// observability surfaces (Prometheus collector, REST inventory) use in place of
// looping ReadPolicyCounters. When dp provides the bulk ReadAllPolicyCounters
// snapshot (the userspace Manager), the whole policy set is read O(P+C) with a
// single brief lock: the reader closes over the snapshot map and does O(1)
// lookups, returning ErrPolicyCounterUnpublished for a policy the helper has not
// published (the same skip/error signal the per-policy read produced). Otherwise
// (the retired eBPF Manager, test fakes) it returns fallback unchanged — the
// per-policy read path, bit-for-bit as before.
//
// cfg should be the config the caller walks for labels/handles so the snapshot's
// handles line up. dp is taken as any so callers can pass their narrow runtime
// interface without a shared type.
//
// #2114 / Codex PR #6743 r7-N2: the probe resolves through dataplane.Unwrap
// FIRST. Every one of the seven callers (pkg/api's metrics + security
// inventory, pkg/cli's show-security paths, pkg/grpcapi's policies-text and
// zones renders) passes the handle the daemon filled with its live
// indirection, whose method set is exactly the mandatory management surface
// — so the bare assertion answered "no bulk provider" for a perfectly
// healthy userspace helper and every one of them silently dropped to the
// O(P*(P+C)) per-policy fallback. Same capability-erasure class as the
// missing Prometheus families, with a performance cliff instead of a
// missing metric as the symptom. Unwrap is the identity for a plain
// backend (every test and every pre-#2114 caller) and nil once the daemon
// has disowned one, in which case the fallback is the correct answer.
func NewPolicyCounterReader(dp any, cfg *config.Config, fallback func(uint32) (dataplane.CounterValue, error)) func(uint32) (dataplane.CounterValue, error) {
	provider, ok := dataplane.Unwrap(dp).(interface {
		ReadAllPolicyCounters(*config.Config) (map[uint32]dataplane.CounterValue, error)
	})
	if !ok {
		return fallback
	}
	bulk, err := provider.ReadAllPolicyCounters(cfg)
	if err != nil {
		// Surface the read failure through the same per-policy error channel so
		// callers keep their existing degraded-read handling.
		return func(uint32) (dataplane.CounterValue, error) {
			return dataplane.CounterValue{}, err
		}
	}
	return func(policyID uint32) (dataplane.CounterValue, error) {
		if v, ok := bulk[policyID]; ok {
			return v, nil
		}
		return dataplane.CounterValue{}, ErrPolicyCounterUnpublished
	}
}

func (m *Manager) ClearPolicyCounters() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	if m.bpfShim != nil {
		if err := m.bpfShim.ClearPolicyCounters(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := m.clearHelperPolicyCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (m *Manager) ClearAllCounters() error {
	var errs []error

	// #5098 (review fold): hold the userspace m.mu across the ENTIRE method so
	// the global-counter offset reset (inside bpfShim.ClearAllCounters) and the
	// delta-baseline rebase (m.prevBindingCounters, at the end) land in ONE
	// critical section that the 1/s status poll cannot interleave with. The poll
	// (statusLoop) holds this SAME userspace m.mu across its whole cycle and only
	// near the end calls syncBPFCountersLocked -> IncrementGlobalCounter, which
	// ACCUMULATES cur-prevBindingCounters into the offset map. Before this fold
	// the offset reset ran OUTSIDE the userspace lock (bpfShim.ClearAllCounters
	// takes only the DATAPLANE m.mu), so a poll mid-cycle could re-add a
	// stale-baseline delta into the freshly-zeroed offset AFTER the reset but
	// BEFORE the baseline rebase — the rebase does not re-zero the offset, so the
	// cleared global RX/TX/drop/session totals kept a small constant residual
	// (bounded by ~1 poll interval of pre-clear traffic) until the next clear.
	// Serializing the whole method under m.mu makes that interleaving impossible:
	// the poll either fully completes before the clear starts, or runs entirely
	// after it (offset already 0, baseline already rebased), so the next delta
	// measures strictly post-clear traffic.
	//
	// Lock order is userspace m.mu -> dataplane m.mu: bpfShim.ClearAllCounters
	// (via ClearGlobalCounters) and the poll's IncrementGlobalCounter both take
	// the dataplane m.mu only while the userspace m.mu is held, matching the
	// poll's order, so this cannot deadlock. Nothing reached under the userspace
	// m.mu here re-takes it — the clearHelper*Locked helpers assume it is held
	// and never re-lock; the bpfShim methods touch only the dataplane m.mu.
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.bpfShim != nil {
		// bpfShim.ClearAllCounters() zeroes the BPF per-CPU counter arrays AND,
		// via ClearGlobalCounters, the in-memory global counter offset map
		// (userspaceCounterOffsets) that ReadGlobalCounter merges on top of the
		// array (#5098). Before #5098 only the array was zeroed, so a cleared
		// global RX/TX/drop/session total snapped straight back to its pre-clear
		// value because the accumulated offset half survived. It also drops the
		// per-zone (#3643) and flood offset maps.
		if err := m.bpfShim.ClearAllCounters(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := m.clearHelperPolicyCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	// #2218: a clear-all must also reset the helper NAT translation hit store,
	// otherwise the per-rule NAT totals snap back on the next status poll (the
	// helper reports cumulative-since-start and syncBPFCountersLocked overwrites
	// the offset absolutely). This sends the clear_nat_counters IPC so the helper
	// store resets and the next poll re-mirrors 0 onto the offset.
	if err := m.clearHelperNATCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	// #3651: a clear-all must also reset the helper per-zone traffic store,
	// otherwise the per-zone totals snap back on the next status poll (the
	// helper reports cumulative-since-start and syncBPFCountersLocked overwrites
	// the offset absolutely). bpfShim.ClearAllCounters() already zeroed the Go
	// zone offset map (via ClearZoneCounters); this sends the clear_zone_counters
	// IPC so the helper store resets too.
	if err := m.clearHelperZoneCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	// #3651: and the helper per-zone FLOOD-event store, for the same reason.
	// bpfShim.ClearAllCounters() already dropped the Go flood offset map (via
	// ClearFloodCounterOffsets); without this IPC the helper's cumulative counts
	// are re-mirrored onto that map by the next 1/s poll and the cleared value
	// snaps back.
	if err := m.clearHelperFloodCountersLocked(); err != nil {
		errs = append(errs, err)
	}
	// #15107: a clear-all must also reset the helper filter term counters
	// (and the per-colour policer counters), for the same reason as the
	// flood store above: the helper reports cumulative totals every poll
	// and the Go surfaces mirror them, so without this IPC a route through
	// `clear security counters` would leave `show firewall` hit counts at
	// their pre-clear values. bpfShim.ClearAllCounters already zeroed the
	// retired filter_counters array; this resets the live helper counters.
	if err := m.clearHelperFilterCountersLocked(); err != nil {
		errs = append(errs, err)
	}

	// #5098: restart the global-counter delta epoch. syncBPFCountersLocked
	// ACCUMULATES each 1/s helper delta (cur - prevBindingCounters) into the
	// global offset map that bpfShim.ClearAllCounters() just reset to zero —
	// unlike the NAT/zone stores above, which overwrite absolutely. Rebase the
	// baseline to the last-recorded cumulative so the next poll measures traffic
	// strictly AFTER the clear; leaving prevBindingCounters below the current
	// cumulative would fold the pre-clear span back in as one large delta on the
	// next poll. Done last so it captures the freshest helper status, and under
	// the m.mu held here — the same lock syncBPFCountersLocked mutates it under.
	// Because the offset reset above (bpfShim.ClearAllCounters) now runs under
	// this SAME m.mu (see the method header), the reset and this rebase form one
	// atomic epoch restart: the poll cannot slip an IncrementGlobalCounter delta
	// between them, so no residual survives.
	m.prevBindingCounters = sumBindingCounters(&m.lastStatus)
	return errors.Join(errs...)
}

func (m *Manager) clearHelperPolicyCountersLocked() error {
	if m.proc == nil || m.proc.Process == nil {
		// Preserve previously published status snapshots: callers retain
		// shallow copies of these slices.
		counters := append([]PolicyRuleCounterStatus(nil), m.lastStatus.PolicyRuleCounters...)
		for i := range counters {
			counters[i].Packets = 0
			counters[i].Bytes = 0
		}
		m.lastStatus.PolicyRuleCounters = counters
		m.republishLastStatusLocked()
		return nil
	}

	var status ProcessStatus
	if err := m.requestLocked(ControlRequest{Type: "clear_policy_counters"}, &status); err != nil {
		return err
	}
	m.recordHelperStatusLocked(&status)
	return nil
}
