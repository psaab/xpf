package monitoriface

import (
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"
)

// InterfaceCounters is the monitor-interface package's local counter shape.
// Callers adapt broader dataplane implementations to this struct so this
// package stays independent of root dataplane telemetry types.
type InterfaceCounters struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
}

// RuntimeDataPlane is the small dataplane surface ReadSnapshot needs.
// It is intentionally narrower than the legacy root dataplane.DataPlane
// interface.
type RuntimeDataPlane interface {
	IsLoaded() bool
	ReadInterfaceCounters(ifindex int) (InterfaceCounters, error)
}

// CounterReader is kept as the older name for callers and docs that describe
// the monitor package's interface-counter dependency.
type CounterReader = RuntimeDataPlane

type StatusReader func() (dpuserspace.ProcessStatus, error)

type SummaryMode int

const (
	SummaryModeCombined SummaryMode = iota
	SummaryModePackets
	SummaryModeBytes
	SummaryModeDelta
	SummaryModeRate
)

type Snapshot struct {
	RxBytes, TxBytes   uint64
	RxPkts, TxPkts     uint64
	RxErrors, TxErrors uint64
	RxDrops, TxDrops   uint64
	RxFrame, TxCarrier uint64
	Collisions         uint64
	Userspace          *UserspaceSnapshot
	Timestamp          time.Time

	// #7422 row 10: per-counter-group validity. Two INDEPENDENT reads populate
	// this snapshot and each could fail silently — the dataplane counter read
	// (RxBytes/TxBytes/RxPkts/TxPkts) and the kernel link statistics
	// (errors/drops/frame/carrier/collisions, and the byte/packet FALLBACK).
	// Before this, both were `if err == nil { ... }` with no else, so a failed
	// read left the fields at zero and the renderer printed 0 — a value
	// indistinguishable from a genuinely idle interface. The Userspace group 15
	// lines below already carried a StatusNote on failure; these two did not,
	// and that asymmetry is what the row names.
	//
	// DELIBERATELY TWO FIELDS, NOT ONE. The two groups are read from different
	// epochs — the dataplane's own counters and the kernel's link stats — and a
	// single note spanning both would tell an operator that "the counters" are
	// unavailable when one source is fine. That is the epoch-mixing this row
	// exists to flag, reproduced in the fix.
	//
	// Empty means the group was read successfully (or was not attempted, which
	// the renderer distinguishes by the reader being absent).
	DataplaneCountersNote string
	KernelStatsNote       string
}

type trafficDeltas struct {
	rxPkts, txPkts, rxBytes, txBytes                     uint64
	rxPktsReset, txPktsReset, rxBytesReset, txBytesReset bool
	userspaceDropped                                     bool
}

type trafficRates struct {
	rxPps, txPps, rxBytesPerSec, txBytesPerSec           uint64
	rxPktsReset, txPktsReset, rxBytesReset, txBytesReset bool
}

func formatCounterValue(value string, reset bool) string {
	if reset {
		return "n/a"
	}
	return value
}

func writeCounterRate(w io.Writer, value uint64, unit string, reset bool) {
	if reset {
		_, _ = io.WriteString(w, "n/a")
		return
	}
	fmt.Fprintf(w, "%d %s", value, unit)
}

func writeCounterDelta(w io.Writer, value uint64, reset bool) {
	if reset {
		_, _ = io.WriteString(w, "n/a")
		return
	}
	fmt.Fprintf(w, "%d", value)
}

func writeSummaryCounterDelta(w io.Writer, value uint64, reset bool) {
	if reset {
		fmt.Fprintf(w, "%16s", "n/a")
		return
	}
	fmt.Fprintf(w, "%16d", value)
}

func writeRateDeltaLine(w io.Writer, format string, counter, rate, delta uint64, unit string, rateReset, deltaReset bool) {
	fmt.Fprintf(w, format, counter)
	writeCounterRate(w, rate, unit, rateReset)
	_, _ = io.WriteString(w, ")    [")
	writeCounterDelta(w, delta, deltaReset)
	_, _ = io.WriteString(w, "]\n")
}

func writeDeltaLine(w io.Writer, format string, counter, delta uint64, reset bool) {
	fmt.Fprintf(w, format, counter)
	writeCounterDelta(w, delta, reset)
	_, _ = io.WriteString(w, "]\n")
}

// deltaU64 marks a decreasing cumulative counter as reset instead of treating
// it as a measured zero delta.
func deltaU64(curr, prev uint64) (uint64, bool) {
	if curr < prev {
		return 0, true
	}
	return curr - prev, false
}

func deltaU64Rebase(curr uint64, baseline *uint64) (uint64, bool) {
	delta, reset := deltaU64(curr, *baseline)
	if reset {
		*baseline = curr
	}
	return delta, reset
}

// Rebaseline only the kernel counters that actually decreased. A reset in the
// userspace component must not erase the kernel baseline.
func rebaselineInterfaceTrafficCounters(curr, baseline *Snapshot) {
	if curr.RxPkts < baseline.RxPkts {
		baseline.RxPkts = curr.RxPkts
	}
	if curr.TxPkts < baseline.TxPkts {
		baseline.TxPkts = curr.TxPkts
	}
	if curr.RxBytes < baseline.RxBytes {
		baseline.RxBytes = curr.RxBytes
	}
	if curr.TxBytes < baseline.TxBytes {
		baseline.TxBytes = curr.TxBytes
	}
}

type trafficCounters struct {
	rxBytes uint64
	txBytes uint64
	rxPkts  uint64
	txPkts  uint64
}

type UserspaceSnapshot struct {
	StatusNote                        string
	HelperEnabled                     bool
	ForwardingArmed                   bool
	NeighborGeneration                uint64
	LastSnapshotGen                   uint64
	Bindings                          int
	ReadyBindings                     int
	BoundBindings                     int
	XSKRegistered                     int
	ZeroCopyBindings                  int
	RxPackets                         uint64
	RxBytes                           uint64
	TxPackets                         uint64
	TxBytes                           uint64
	DirectTXPackets                   uint64
	CopyTXPackets                     uint64
	InPlaceTXPackets                  uint64
	DirectTXNoFrameFallbackPackets    uint64
	DirectTXBuildFallbackPackets      uint64
	DirectTXDisallowedFallbackPackets uint64
	TxCompletions                     uint64
	KernelRXDropped                   uint64
	KernelRXInvalidDescs              uint64
	DebugPendingFillFrames            uint64
	DebugSpareFillFrames              uint64
	DebugFreeTXFrames                 uint64
	DebugPendingTXPrepared            uint64
	DebugPendingTXLocal               uint64
	DebugOutstandingTX                uint64
	DebugInFlightRecycles             uint64
	SessionMisses                     uint64
	NeighborMissPackets               uint64
	RouteMissPackets                  uint64
	PolicyDeniedPackets               uint64
	ExceptionPackets                  uint64
	SlowPathPackets                   uint64
	SlowPathLocalDeliveryPackets      uint64
	SlowPathMissingNeighborPackets    uint64
	SlowPathNoRoutePackets            uint64
	SlowPathNextTablePackets          uint64
	SlowPathForwardBuildPackets       uint64
	LastErrors                        []string
	RecentExceptions                  []string
}

func hasUserspaceTrafficSource(snap *UserspaceSnapshot) bool {
	if snap == nil {
		return false
	}
	return snap.Bindings > 0 ||
		snap.ReadyBindings > 0 ||
		snap.BoundBindings > 0 ||
		snap.XSKRegistered > 0 ||
		snap.ZeroCopyBindings > 0 ||
		snap.RxPackets > 0 ||
		snap.RxBytes > 0 ||
		snap.TxPackets > 0 ||
		snap.TxBytes > 0
}

func displayTrafficCounters(snap *Snapshot) trafficCounters {
	if snap == nil {
		return trafficCounters{}
	}
	counters := trafficCounters{
		rxBytes: snap.RxBytes,
		txBytes: snap.TxBytes,
		rxPkts:  snap.RxPkts,
		txPkts:  snap.TxPkts,
	}
	if !hasUserspaceTrafficSource(snap.Userspace) {
		return counters
	}
	// Userspace/XSK forwarding is accounted in the helper bindings rather than
	// the kernel/BPF interface snapshots that back monitor output, so fold both
	// directions into the displayed totals.
	counters.rxBytes += snap.Userspace.RxBytes
	counters.txBytes += snap.Userspace.TxBytes
	counters.rxPkts += snap.Userspace.RxPackets
	counters.txPkts += snap.Userspace.TxPackets
	return counters
}

// snapshotTrafficDeltas returns the per-window deltas and reports whether the
// USERSPACE component had to be left out of them.
//
// #9047: the both-samples gate below is correct and must stay -- these are
// CUMULATIVE counters, so treating a missing side as zero would attribute the
// entire cumulative total to one window and render a spike that never
// happened. What was wrong is that declining was SILENT.
//
// The window that drops it is not rare: hasUserspaceTrafficSource is false at
// the first sample after helper start, after a helper restart, and whenever the
// status read failed -- that path sets Userspace to a struct carrying only a
// StatusNote, with no bindings and no counters, so the gate declines.
//
// AND THE SAME RENDER DISAGREES WITH ITSELF. displayTrafficCounters gates on
// `curr` ALONE, so in any window where prev lacks a source and curr has one,
// the displayed TOTAL includes userspace bytes while the displayed RATE does
// not. The two gates are NOT reconciled to match, deliberately: they answer
// different questions. A total is a single-sample fact and is right to include
// userspace as soon as curr has it; a rate needs two samples and cannot be
// computed without both. Forcing the total to drop userspace whenever prev
// lacked a source would make the TOTAL wrong to fix a cosmetic disagreement.
// The honest reconciliation is to say so, which is what the flag is for.
//
// That is #7422 row 10's doctrine applied to the path that reintroduced the
// shape it fixed: a counter group that could not be contributed must carry a
// NOTE rather than silently render 0, because 0 is indistinguishable from a
// genuinely idle interface. #7422 fixed the two sibling groups on the strength
// of the userspace group already having a note -- and then the RATE path went
// on dropping that same group silently.
func snapshotTrafficDeltas(curr, prev *Snapshot) trafficDeltas {
	var deltas trafficDeltas
	if curr == nil || prev == nil {
		return deltas
	}

	deltas.rxPkts, deltas.rxPktsReset = deltaU64(curr.RxPkts, prev.RxPkts)
	deltas.txPkts, deltas.txPktsReset = deltaU64(curr.TxPkts, prev.TxPkts)
	deltas.rxBytes, deltas.rxBytesReset = deltaU64(curr.RxBytes, prev.RxBytes)
	deltas.txBytes, deltas.txBytesReset = deltaU64(curr.TxBytes, prev.TxBytes)

	if hasUserspaceTrafficSource(curr.Userspace) && hasUserspaceTrafficSource(prev.Userspace) {
		userDelta, reset := deltaU64(curr.Userspace.RxPackets, prev.Userspace.RxPackets)
		deltas.rxPkts += userDelta
		deltas.rxPktsReset = deltas.rxPktsReset || reset
		userDelta, reset = deltaU64(curr.Userspace.TxPackets, prev.Userspace.TxPackets)
		deltas.txPkts += userDelta
		deltas.txPktsReset = deltas.txPktsReset || reset
		userDelta, reset = deltaU64(curr.Userspace.RxBytes, prev.Userspace.RxBytes)
		deltas.rxBytes += userDelta
		deltas.rxBytesReset = deltas.rxBytesReset || reset
		userDelta, reset = deltaU64(curr.Userspace.TxBytes, prev.Userspace.TxBytes)
		deltas.txBytes += userDelta
		deltas.txBytesReset = deltas.txBytesReset || reset
		return deltas
	}

	// Dropped. Report it ONLY when the interface actually has a userspace
	// source to contribute in the current sample -- otherwise every
	// kernel-only interface would carry a permanent note about a component it
	// never has, which is the false-positive that makes operators stop reading
	// notes.
	deltas.userspaceDropped = hasUserspaceTrafficSource(curr.Userspace)
	return deltas
}

func ResolvePhysicalParent(name string) string {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return name
	}
	if ipv, ok := link.(*netlink.IPVlan); ok {
		parent, err := netlink.LinkByIndex(ipv.Attrs().ParentIndex)
		if err == nil {
			return parent.Attrs().Name
		}
	}
	return name
}

// FormatDeviceChangeNote renders the shared device-change annotation for
// single-interface monitoring (#10838), or "" when the device did not move.
//
// A display name such as reth0 can re-resolve to a different kernel device
// mid-stream (RG failover, member change, config commit). Both transports
// call this on every tick: a non-empty return means the prev/baseline held
// for the old device must be dropped and the note rendered. One helper for
// both transports so the reset/annotate contract cannot drift.
func FormatDeviceChangeNote(displayName, oldKernel, newKernel string) string {
	if oldKernel == newKernel {
		return ""
	}
	return fmt.Sprintf("Note: %s device changed %s -> %s (possible RG failover) — baseline reset; rates and deltas restart from the new device",
		displayName, oldKernel, newKernel)
}

// ResetOnDeviceChange drops rate and delta baselines when a display name
// resolves to a different kernel device. The non-empty note is intended to
// remain visible for the rest of the monitor session.
func ResetOnDeviceChange(displayName string, trackedKernel *string, newKernel string, prev, baseline **Snapshot) string {
	if *trackedKernel == newKernel {
		return ""
	}
	note := FormatDeviceChangeNote(displayName, *trackedKernel, newKernel)
	*trackedKernel = newKernel
	*prev = nil
	*baseline = nil
	return note
}

func ListTrafficInterfaces() ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}
	names := make([]string, 0, len(links))
	seen := make(map[string]struct{}, len(links))
	for _, link := range links {
		name := link.Attrs().Name
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

type summaryDisplayChoice struct {
	name     string
	priority int
}

// TrafficSummaryInterfaces returns the display names and backing kernel
// interfaces for summary-mode monitoring. It prefers configured names such as
// fab*/reth* when they resolve to a live physical counter source, while still
// falling back to raw kernel links when no config alias exists.
func TrafficSummaryInterfaces(cfg *config.Config) ([]string, map[string]string) {
	if liveNames, err := ListTrafficInterfaces(); err == nil && len(liveNames) > 0 {
		if names, kernelNames := buildTrafficSummaryInterfaces(cfg, liveNames, ResolvePhysicalParent); len(names) > 0 {
			return names, kernelNames
		}
	}
	return configuredTrafficSummaryInterfaces(cfg, ResolvePhysicalParent)
}

func buildTrafficSummaryInterfaces(cfg *config.Config, liveNames []string, canonicalize func(string) string) ([]string, map[string]string) {
	liveKernels := canonicalTrafficKernels(liveNames, canonicalize)
	if len(liveKernels) == 0 {
		return configuredTrafficSummaryInterfaces(cfg, canonicalize)
	}
	choices := make(map[string]summaryDisplayChoice, len(liveKernels))
	for _, kernel := range liveKernels {
		choices[kernel] = summaryDisplayChoice{name: kernel}
	}
	applyConfiguredSummaryChoices(cfg, liveKernels, choices, canonicalize)
	return finalizeTrafficSummaryInterfaces(liveKernels, choices)
}

func configuredTrafficSummaryInterfaces(cfg *config.Config, canonicalize func(string) string) ([]string, map[string]string) {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil, nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	displayNames := make([]string, 0, len(names))
	kernelNames := make(map[string]string, len(names))
	for _, name := range names {
		kernelName := resolveConfiguredTrafficKernel(cfg, name, canonicalize)
		if kernelName == "" {
			continue
		}
		displayNames = append(displayNames, name)
		kernelNames[name] = kernelName
	}
	return displayNames, kernelNames
}

func canonicalTrafficKernels(liveNames []string, canonicalize func(string) string) []string {
	if canonicalize == nil {
		canonicalize = func(name string) string { return name }
	}
	kernels := make([]string, 0, len(liveNames))
	seen := make(map[string]struct{}, len(liveNames))
	for _, name := range liveNames {
		kernelName := canonicalize(name)
		if kernelName == "" {
			continue
		}
		if _, ok := seen[kernelName]; ok {
			continue
		}
		seen[kernelName] = struct{}{}
		kernels = append(kernels, kernelName)
	}
	sort.Strings(kernels)
	return kernels
}

func applyConfiguredSummaryChoices(cfg *config.Config, liveKernels []string, choices map[string]summaryDisplayChoice, canonicalize func(string) string) {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return
	}
	liveSet := make(map[string]struct{}, len(liveKernels))
	for _, kernelName := range liveKernels {
		liveSet[kernelName] = struct{}{}
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		kernelName := resolveConfiguredTrafficKernel(cfg, name, canonicalize)
		if kernelName == "" {
			continue
		}
		if _, ok := liveSet[kernelName]; !ok {
			continue
		}
		current := choices[kernelName]
		priority := summaryDisplayPriority(name)
		if priority > current.priority || (priority == current.priority && name < current.name) {
			choices[kernelName] = summaryDisplayChoice{name: name, priority: priority}
		}
	}
}

func finalizeTrafficSummaryInterfaces(liveKernels []string, choices map[string]summaryDisplayChoice) ([]string, map[string]string) {
	names := make([]string, 0, len(liveKernels))
	kernelNames := make(map[string]string, len(liveKernels))
	usedDisplayNames := make(map[string]struct{}, len(liveKernels))
	for _, kernelName := range liveKernels {
		displayName := choices[kernelName].name
		if displayName == "" {
			displayName = kernelName
		}
		if _, ok := usedDisplayNames[displayName]; ok {
			displayName = kernelName
		}
		usedDisplayNames[displayName] = struct{}{}
		names = append(names, displayName)
		kernelNames[displayName] = kernelName
	}
	sort.Strings(names)
	return names, kernelNames
}

func resolveConfiguredTrafficKernel(cfg *config.Config, name string, canonicalize func(string) string) string {
	if canonicalize == nil {
		canonicalize = func(value string) string { return value }
	}
	parts := strings.SplitN(name, ".", 2)
	base := parts[0]
	suffix := ""
	if len(parts) == 2 {
		suffix = "." + parts[1]
	}
	if cfg != nil && cfg.Interfaces.Interfaces != nil {
		// #5886: LookupInterface returns ok only for a present, NON-nil slot, so
		// `ifc.LocalFabricMember` cannot nil-deref on a present-but-nil value
		// (which tolerant load / HA config-sync can leave). This is a read-only
		// operator path (CLI `show interfaces` traffic summary + gRPC
		// MonitorInterface), so a raw map-index deref here panicked xpfd.
		if ifc, ok := config.LookupInterface(cfg, base); ok && ifc.LocalFabricMember != "" {
			resolved := ifc.LocalFabricMember
			if suffix != "" && !strings.Contains(resolved, ".") {
				resolved += suffix
			}
			return canonicalize(config.LinuxIfName(resolved))
		}
	}
	resolved := name
	if cfg != nil {
		resolved = cfg.ResolveReth(name)
	}
	return canonicalize(config.LinuxIfName(resolved))
}

func summaryDisplayPriority(name string) int {
	base := strings.SplitN(name, ".", 2)[0]
	switch {
	case strings.HasPrefix(base, "fab"):
		return 30
	case strings.HasPrefix(base, "reth"):
		return 20
	default:
		return 10
	}
}

func ParseSummaryMode(value string) (SummaryMode, bool) {
	switch strings.ToLower(value) {
	case "", "combined", "all", "both":
		return SummaryModeCombined, true
	case "packets", "packet":
		return SummaryModePackets, true
	case "bytes", "byte":
		return SummaryModeBytes, true
	case "delta":
		return SummaryModeDelta, true
	case "rate", "rates":
		return SummaryModeRate, true
	default:
		return SummaryModeCombined, false
	}
}

func SummaryModeLabel(mode SummaryMode) string {
	switch mode {
	case SummaryModePackets:
		return "packets"
	case SummaryModeBytes:
		return "bytes"
	case SummaryModeDelta:
		return "delta"
	case SummaryModeRate:
		return "rate"
	default:
		return "combined"
	}
}

func AggregateUserspaceSnapshot(kernelName string, status dpuserspace.ProcessStatus) *UserspaceSnapshot {
	snap := &UserspaceSnapshot{
		HelperEnabled:      status.Enabled,
		ForwardingArmed:    status.ForwardingArmed,
		NeighborGeneration: status.NeighborGeneration,
		LastSnapshotGen:    status.LastSnapshotGeneration,
	}
	errorSet := map[string]struct{}{}
	for _, binding := range status.Bindings {
		if binding.Interface != kernelName {
			continue
		}
		snap.Bindings++
		if binding.Ready {
			snap.ReadyBindings++
		}
		if binding.Bound {
			snap.BoundBindings++
		}
		if binding.XSKRegistered {
			snap.XSKRegistered++
		}
		if binding.ZeroCopy {
			snap.ZeroCopyBindings++
		}
		snap.RxPackets += binding.RXPackets
		snap.RxBytes += binding.RXBytes
		snap.TxPackets += binding.TXPackets
		snap.TxBytes += binding.TXBytes
		snap.DirectTXPackets += binding.DirectTXPackets
		snap.CopyTXPackets += binding.CopyTXPackets
		snap.InPlaceTXPackets += binding.InPlaceTXPackets
		snap.DirectTXNoFrameFallbackPackets += binding.DirectTXNoFrameFallbackPackets
		snap.DirectTXBuildFallbackPackets += binding.DirectTXBuildFallbackPackets
		snap.DirectTXDisallowedFallbackPackets += binding.DirectTXDisallowedFallbackPackets
		snap.TxCompletions += binding.TXCompletions
		snap.KernelRXDropped += binding.KernelRXDropped
		snap.KernelRXInvalidDescs += binding.KernelRXInvalidDescs
		snap.DebugPendingFillFrames += uint64(binding.DebugPendingFillFrames)
		snap.DebugSpareFillFrames += uint64(binding.DebugSpareFillFrames)
		snap.DebugFreeTXFrames += uint64(binding.DebugFreeTXFrames)
		snap.DebugPendingTXPrepared += uint64(binding.DebugPendingTXPrepared)
		snap.DebugPendingTXLocal += uint64(binding.DebugPendingTXLocal)
		snap.DebugOutstandingTX += uint64(binding.DebugOutstandingTX)
		snap.DebugInFlightRecycles += uint64(binding.DebugInFlightRecycles)
		snap.SessionMisses += binding.SessionMisses
		snap.NeighborMissPackets += binding.NeighborMissPackets
		snap.RouteMissPackets += binding.RouteMissPackets
		snap.PolicyDeniedPackets += binding.PolicyDeniedPackets
		snap.ExceptionPackets += binding.ExceptionPackets
		snap.SlowPathPackets += binding.SlowPathPackets
		snap.SlowPathLocalDeliveryPackets += binding.SlowPathLocalDeliveryPackets
		snap.SlowPathMissingNeighborPackets += binding.SlowPathMissingNeighborPackets
		snap.SlowPathNoRoutePackets += binding.SlowPathNoRoutePackets
		snap.SlowPathNextTablePackets += binding.SlowPathNextTablePackets
		snap.SlowPathForwardBuildPackets += binding.SlowPathForwardBuildPackets
		if binding.LastError != "" {
			errorSet[binding.LastError] = struct{}{}
		}
	}
	for _, exc := range status.RecentExceptions {
		if exc.Interface != kernelName {
			continue
		}
		snap.RecentExceptions = append(snap.RecentExceptions, formatUserspaceException(exc))
	}
	for msg := range errorSet {
		snap.LastErrors = append(snap.LastErrors, msg)
	}
	sort.Strings(snap.LastErrors)
	if len(snap.RecentExceptions) > 3 {
		snap.RecentExceptions = snap.RecentExceptions[:3]
	}
	if snap.Bindings == 0 && len(snap.RecentExceptions) == 0 {
		snap.StatusNote = fmt.Sprintf("no userspace bindings or exceptions matched %s", kernelName)
	}
	return snap
}

func ReadSnapshot(counterReader CounterReader, statusReader StatusReader, kernelName string) (Snapshot, error) {
	iface, err := net.InterfaceByName(kernelName)
	if err != nil {
		return Snapshot{}, fmt.Errorf("interface %s: %w", kernelName, err)
	}
	snap := Snapshot{Timestamp: time.Now()}

	if counterReader != nil && counterReader.IsLoaded() {
		if ctrs, err := counterReader.ReadInterfaceCounters(iface.Index); err == nil {
			snap.RxBytes = ctrs.RxBytes
			snap.TxBytes = ctrs.TxBytes
			snap.RxPkts = ctrs.RxPackets
			snap.TxPkts = ctrs.TxPackets
		} else {
			// #7422 row 10: without this the fields stay 0 and render as a
			// genuinely idle interface.
			snap.DataplaneCountersNote = err.Error()
		}
	}

	link, err := netlink.LinkByName(kernelName)
	if err != nil {
		// #7422 row 10: a failed link lookup left every error/drop counter at
		// zero, which reads as a healthy interface rather than an unread one.
		snap.KernelStatsNote = err.Error()
	}
	if err == nil {
		if stats := link.Attrs().Statistics; stats != nil {
			snap.RxErrors = stats.RxErrors
			snap.TxErrors = stats.TxErrors
			snap.RxDrops = stats.RxDropped
			snap.TxDrops = stats.TxDropped
			snap.RxFrame = stats.RxFrameErrors
			snap.TxCarrier = stats.TxCarrierErrors
			snap.Collisions = stats.Collisions
			if snap.RxBytes == 0 && snap.TxBytes == 0 {
				snap.RxBytes = stats.RxBytes
				snap.TxBytes = stats.TxBytes
				snap.RxPkts = stats.RxPackets
				snap.TxPkts = stats.TxPackets
			}
		} else {
			// The link resolved but carries no statistics block. Distinct from
			// a failed lookup and equally invisible in the rendered zeros.
			snap.KernelStatsNote = "link carries no statistics"
		}
	}

	if statusReader != nil {
		status, err := statusReader()
		if err != nil {
			snap.Userspace = &UserspaceSnapshot{StatusNote: err.Error()}
		} else {
			snap.Userspace = AggregateUserspaceSnapshot(kernelName, status)
		}
	}

	return snap, nil
}

func ReadLinkState(name string) string {
	if data, err := os.ReadFile("/sys/class/net/" + name + "/operstate"); err == nil {
		if strings.TrimSpace(string(data)) == "up" {
			return "Up"
		}
	}
	return "Down"
}

// formatLinkSpeed renders an integer-Mbps sysfs speed for the operator display
// (#9917 F-138). Exact multiples of 1000 render as integer gbps; any other
// gigabit-plus speed renders one decimal — computed with integer math and
// truncated, never float-rounded — so 2500 Mbps reads 2.5gbps instead of the
// mbps/1000 truncation 2gbps. The rule is uniform at all magnitudes (no >=10G
// integer tier that would reintroduce the truncation one tier up), and every
// real Ethernet rate renders exactly. Non-positive input renders unknown.
func formatLinkSpeed(mbps int) string {
	if mbps <= 0 {
		return "unknown"
	}
	if mbps < 1000 {
		return fmt.Sprintf("%dmbps", mbps)
	}
	if mbps%1000 == 0 {
		return fmt.Sprintf("%dgbps", mbps/1000)
	}
	return fmt.Sprintf("%d.%dgbps", mbps/1000, (mbps%1000)/100)
}

func ReadLinkSpeed(name string) string {
	raw, err := os.ReadFile("/sys/class/net/" + name + "/speed")
	if err != nil {
		return "unknown"
	}
	var mbps int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d", &mbps); err != nil {
		return "unknown"
	}
	return formatLinkSpeed(mbps)
}

func RenderSingleInterface(w io.Writer, hostname, displayName, kernelName string, snap, prev, baseline *Snapshot, startTime time.Time, deviceNote string) {
	seconds := int(time.Since(startTime).Seconds())
	now := time.Now().Format("15:04:05")
	linkState := ReadLinkState(kernelName)
	speed := ReadLinkSpeed(kernelName)

	fmt.Fprintf(w, "%-40s Seconds: %-10d Time: %s\n", hostname, seconds, now)
	fmt.Fprintf(w, "Interface: %s, Enabled, Link is %s\n", displayName, linkState)
	fmt.Fprintf(w, "Encapsulation: Ethernet, Speed: %s\n", speed)
	if deviceNote != "" {
		fmt.Fprintf(w, "  %s\n", deviceNote)
	}

	var rxBps, txBps, rxPps, txPps uint64
	var windowDeltas trafficDeltas
	var userspaceRateDropped bool
	if prev != nil {
		windowDeltas = snapshotTrafficDeltas(snap, prev)
		userspaceRateDropped = windowDeltas.userspaceDropped
		dt := snap.Timestamp.Sub(prev.Timestamp).Seconds()
		if dt > 0 {
			rxBps = uint64(float64(windowDeltas.rxBytes) * 8 / dt)
			txBps = uint64(float64(windowDeltas.txBytes) * 8 / dt)
			rxPps = uint64(float64(windowDeltas.rxPkts) / dt)
			txPps = uint64(float64(windowDeltas.txPkts) / dt)
		}
	}

	var baselineDeltas trafficDeltas
	if baseline != nil {
		baselineDeltas = snapshotTrafficDeltas(snap, baseline)
		if snap.DataplaneCountersNote == "" {
			rebaselineInterfaceTrafficCounters(snap, baseline)
		}
	}
	currCounters := displayTrafficCounters(snap)

	fmt.Fprintf(w, "Traffic statistics (interface counters + userspace XSK traffic): Current delta\n")
	// #7422 row 10: annotate the group whose read FAILED, so a rendered 0 is
	// not read as an idle interface. Per group, because the dataplane counters
	// and the kernel link stats are separate reads from separate epochs and one
	// note for both would misreport a healthy source as unavailable.
	if snap.DataplaneCountersNote != "" {
		fmt.Fprintf(w, "  Note: dataplane counters unavailable (%s) — byte/packet values below are NOT a measurement\n",
			snap.DataplaneCountersNote)
	}
	// #9047: the rate below excludes userspace forwarding for this window while
	// the TOTAL beside it includes it. Say so rather than render a rate that
	// under-reports with no indication -- `monitor` is a live-diagnosis
	// surface, and a silently-wrong rate on it is worse than no rate.
	if userspaceRateDropped {
		fmt.Fprintf(w, "  Note: rate EXCLUDES userspace/XSK forwarding this window "+
			"(no userspace counters in the previous sample — helper start, restart, or a "+
			"failed status read); the totals below DO include it, so bps/pps under-reports\n")
	}
	writeRateDeltaLine(w, "  Input  bytes:         %20d (", currCounters.rxBytes, rxBps,
		baselineDeltas.rxBytes, "bps", windowDeltas.rxBytesReset, baselineDeltas.rxBytesReset)
	writeRateDeltaLine(w, "  Output bytes:         %20d (", currCounters.txBytes, txBps,
		baselineDeltas.txBytes, "bps", windowDeltas.txBytesReset, baselineDeltas.txBytesReset)
	writeRateDeltaLine(w, "  Input  packets:       %20d (", currCounters.rxPkts, rxPps,
		baselineDeltas.rxPkts, "pps", windowDeltas.rxPktsReset, baselineDeltas.rxPktsReset)
	writeRateDeltaLine(w, "  Output packets:       %20d (", currCounters.txPkts, txPps,
		baselineDeltas.txPkts, "pps", windowDeltas.txPktsReset, baselineDeltas.txPktsReset)
	fmt.Fprintf(w, "\n")

	var (
		rxErrDelta, txErrDelta, rxDropDelta, txDropDelta, rxFrameDelta, txCarrierDelta, colDelta uint64
		rxErrReset, txErrReset, rxDropReset, txDropReset, rxFrameReset, txCarrierReset, colReset bool
	)
	if baseline != nil && snap.KernelStatsNote == "" {
		rxErrDelta, rxErrReset = deltaU64Rebase(snap.RxErrors, &baseline.RxErrors)
		txErrDelta, txErrReset = deltaU64Rebase(snap.TxErrors, &baseline.TxErrors)
		rxDropDelta, rxDropReset = deltaU64Rebase(snap.RxDrops, &baseline.RxDrops)
		txDropDelta, txDropReset = deltaU64Rebase(snap.TxDrops, &baseline.TxDrops)
		rxFrameDelta, rxFrameReset = deltaU64Rebase(snap.RxFrame, &baseline.RxFrame)
		txCarrierDelta, txCarrierReset = deltaU64Rebase(snap.TxCarrier, &baseline.TxCarrier)
		colDelta, colReset = deltaU64Rebase(snap.Collisions, &baseline.Collisions)
	}

	fmt.Fprintf(w, "Error statistics:                                  Current delta\n")
	// #7422 row 10: the kernel link statistics feed EVERY line in this block,
	// plus the byte/packet fallback above, so a failed read renders a clean
	// interface rather than an unread one.
	if snap.KernelStatsNote != "" {
		fmt.Fprintf(w, "  Note: kernel link statistics unavailable (%s) — the zeros below are NOT a measurement\n",
			snap.KernelStatsNote)
	}
	writeDeltaLine(w, "  Input  errors:        %20d          [", snap.RxErrors, rxErrDelta, rxErrReset)
	writeDeltaLine(w, "  Output errors:        %20d          [", snap.TxErrors, txErrDelta, txErrReset)
	writeDeltaLine(w, "  Input  drops:         %20d          [", snap.RxDrops, rxDropDelta, rxDropReset)
	writeDeltaLine(w, "  Output drops:         %20d          [", snap.TxDrops, txDropDelta, txDropReset)
	writeDeltaLine(w, "  Input  frame errors:  %20d          [", snap.RxFrame, rxFrameDelta, rxFrameReset)
	writeDeltaLine(w, "  Output carrier:       %20d          [", snap.TxCarrier, txCarrierDelta, txCarrierReset)
	writeDeltaLine(w, "  Collisions:           %20d          [", snap.Collisions, colDelta, colReset)
	fmt.Fprintf(w, "\n")
	if snap.Userspace != nil {
		var (
			usRxBps, usTxBps, usRxPps, usTxPps                                           uint64
			usRxBytesDelta, usTxBytesDelta, usRxPktsDelta, usTxPktsDelta                 uint64
			usDirectDelta, usCopyDelta, usInPlaceDelta                                   uint64
			usDirectNoFrameDelta, usDirectBuildDelta, usDirectDisallowedDelta            uint64
			usTxCompletionsDelta, usKernelRXDroppedDelta, usKernelRXInvalidDelta         uint64
			usPendingFillDelta, usSpareFillDelta, usFreeTXDelta                          uint64
			usPendingPreparedDelta, usPendingLocalDelta                                  uint64
			usOutstandingTXDelta, usInFlightRecycleDelta                                 uint64
			usSessionMissDelta, usNeighborMissDelta, usRouteMissDelta                    uint64
			usPolicyDeniedDelta, usExceptionDelta, usSlowPathDelta                       uint64
			usSlowPathLocalDelta, usSlowPathMissingNeighborDelta                         uint64
			usSlowPathNoRouteDelta, usSlowPathNextTableDelta, usSlowPathBuildDelta       uint64
			usRxBytesReset, usTxBytesReset, usRxPktsReset, usTxPktsReset                 bool
			usDirectReset, usCopyReset, usInPlaceReset                                   bool
			usDirectNoFrameReset, usDirectBuildReset, usDirectDisallowedReset            bool
			usTxCompletionsReset, usKernelRXDroppedReset, usKernelRXInvalidReset         bool
			usPendingFillReset, usSpareFillReset, usFreeTXReset                          bool
			usPendingPreparedReset, usPendingLocalReset                                  bool
			usOutstandingTXReset, usInFlightRecycleReset                                 bool
			usSessionMissReset, usNeighborMissReset, usRouteMissReset                    bool
			usPolicyDeniedReset, usExceptionReset, usSlowPathReset                       bool
			usSlowPathLocalReset, usSlowPathMissingNeighborReset                         bool
			usSlowPathNoRouteReset, usSlowPathNextTableReset, usSlowPathBuildReset       bool
			usRxBytesRateReset, usTxBytesRateReset, usRxPktsRateReset, usTxPktsRateReset bool
		)
		if prev != nil && prev.Userspace != nil {
			dt := snap.Timestamp.Sub(prev.Timestamp).Seconds()
			delta, reset := deltaU64(snap.Userspace.RxBytes, prev.Userspace.RxBytes)
			usRxBytesRateReset = reset
			if dt > 0 {
				usRxBps = uint64(float64(delta) * 8 / dt)
			}
			delta, reset = deltaU64(snap.Userspace.TxBytes, prev.Userspace.TxBytes)
			usTxBytesRateReset = reset
			if dt > 0 {
				usTxBps = uint64(float64(delta) * 8 / dt)
			}
			delta, reset = deltaU64(snap.Userspace.RxPackets, prev.Userspace.RxPackets)
			usRxPktsRateReset = reset
			if dt > 0 {
				usRxPps = uint64(float64(delta) / dt)
			}
			delta, reset = deltaU64(snap.Userspace.TxPackets, prev.Userspace.TxPackets)
			usTxPktsRateReset = reset
			if dt > 0 {
				usTxPps = uint64(float64(delta) / dt)
			}
		}
		if baseline != nil && baseline.Userspace != nil && snap.Userspace.StatusNote == "" {
			usRxBytesDelta, usRxBytesReset = deltaU64Rebase(snap.Userspace.RxBytes, &baseline.Userspace.RxBytes)
			usTxBytesDelta, usTxBytesReset = deltaU64Rebase(snap.Userspace.TxBytes, &baseline.Userspace.TxBytes)
			usRxPktsDelta, usRxPktsReset = deltaU64Rebase(snap.Userspace.RxPackets, &baseline.Userspace.RxPackets)
			usTxPktsDelta, usTxPktsReset = deltaU64Rebase(snap.Userspace.TxPackets, &baseline.Userspace.TxPackets)
			usDirectDelta, usDirectReset = deltaU64Rebase(snap.Userspace.DirectTXPackets, &baseline.Userspace.DirectTXPackets)
			usCopyDelta, usCopyReset = deltaU64Rebase(snap.Userspace.CopyTXPackets, &baseline.Userspace.CopyTXPackets)
			usInPlaceDelta, usInPlaceReset = deltaU64Rebase(snap.Userspace.InPlaceTXPackets, &baseline.Userspace.InPlaceTXPackets)
			usDirectNoFrameDelta, usDirectNoFrameReset = deltaU64Rebase(snap.Userspace.DirectTXNoFrameFallbackPackets, &baseline.Userspace.DirectTXNoFrameFallbackPackets)
			usDirectBuildDelta, usDirectBuildReset = deltaU64Rebase(snap.Userspace.DirectTXBuildFallbackPackets, &baseline.Userspace.DirectTXBuildFallbackPackets)
			usDirectDisallowedDelta, usDirectDisallowedReset = deltaU64Rebase(snap.Userspace.DirectTXDisallowedFallbackPackets, &baseline.Userspace.DirectTXDisallowedFallbackPackets)
			usTxCompletionsDelta, usTxCompletionsReset = deltaU64Rebase(snap.Userspace.TxCompletions, &baseline.Userspace.TxCompletions)
			usKernelRXDroppedDelta, usKernelRXDroppedReset = deltaU64Rebase(snap.Userspace.KernelRXDropped, &baseline.Userspace.KernelRXDropped)
			usKernelRXInvalidDelta, usKernelRXInvalidReset = deltaU64Rebase(snap.Userspace.KernelRXInvalidDescs, &baseline.Userspace.KernelRXInvalidDescs)
			usPendingFillDelta, usPendingFillReset = deltaU64Rebase(snap.Userspace.DebugPendingFillFrames, &baseline.Userspace.DebugPendingFillFrames)
			usSpareFillDelta, usSpareFillReset = deltaU64Rebase(snap.Userspace.DebugSpareFillFrames, &baseline.Userspace.DebugSpareFillFrames)
			usFreeTXDelta, usFreeTXReset = deltaU64Rebase(snap.Userspace.DebugFreeTXFrames, &baseline.Userspace.DebugFreeTXFrames)
			usPendingPreparedDelta, usPendingPreparedReset = deltaU64Rebase(snap.Userspace.DebugPendingTXPrepared, &baseline.Userspace.DebugPendingTXPrepared)
			usPendingLocalDelta, usPendingLocalReset = deltaU64Rebase(snap.Userspace.DebugPendingTXLocal, &baseline.Userspace.DebugPendingTXLocal)
			usOutstandingTXDelta, usOutstandingTXReset = deltaU64Rebase(snap.Userspace.DebugOutstandingTX, &baseline.Userspace.DebugOutstandingTX)
			usInFlightRecycleDelta, usInFlightRecycleReset = deltaU64Rebase(snap.Userspace.DebugInFlightRecycles, &baseline.Userspace.DebugInFlightRecycles)
			usSessionMissDelta, usSessionMissReset = deltaU64Rebase(snap.Userspace.SessionMisses, &baseline.Userspace.SessionMisses)
			usNeighborMissDelta, usNeighborMissReset = deltaU64Rebase(snap.Userspace.NeighborMissPackets, &baseline.Userspace.NeighborMissPackets)
			usRouteMissDelta, usRouteMissReset = deltaU64Rebase(snap.Userspace.RouteMissPackets, &baseline.Userspace.RouteMissPackets)
			usPolicyDeniedDelta, usPolicyDeniedReset = deltaU64Rebase(snap.Userspace.PolicyDeniedPackets, &baseline.Userspace.PolicyDeniedPackets)
			usExceptionDelta, usExceptionReset = deltaU64Rebase(snap.Userspace.ExceptionPackets, &baseline.Userspace.ExceptionPackets)
			usSlowPathDelta, usSlowPathReset = deltaU64Rebase(snap.Userspace.SlowPathPackets, &baseline.Userspace.SlowPathPackets)
			usSlowPathLocalDelta, usSlowPathLocalReset = deltaU64Rebase(snap.Userspace.SlowPathLocalDeliveryPackets, &baseline.Userspace.SlowPathLocalDeliveryPackets)
			usSlowPathMissingNeighborDelta, usSlowPathMissingNeighborReset = deltaU64Rebase(snap.Userspace.SlowPathMissingNeighborPackets, &baseline.Userspace.SlowPathMissingNeighborPackets)
			usSlowPathNoRouteDelta, usSlowPathNoRouteReset = deltaU64Rebase(snap.Userspace.SlowPathNoRoutePackets, &baseline.Userspace.SlowPathNoRoutePackets)
			usSlowPathNextTableDelta, usSlowPathNextTableReset = deltaU64Rebase(snap.Userspace.SlowPathNextTablePackets, &baseline.Userspace.SlowPathNextTablePackets)
			usSlowPathBuildDelta, usSlowPathBuildReset = deltaU64Rebase(snap.Userspace.SlowPathForwardBuildPackets, &baseline.Userspace.SlowPathForwardBuildPackets)
		}

		fmt.Fprintf(w, "Userspace dataplane:\n")
		if snap.Userspace.StatusNote != "" {
			fmt.Fprintf(w, "  Note:                 %s\n", snap.Userspace.StatusNote)
		}
		fmt.Fprintf(w, "  Helper state:         enabled=%t armed=%t snapshot_gen=%d neighbor_gen=%d\n",
			snap.Userspace.HelperEnabled, snap.Userspace.ForwardingArmed, snap.Userspace.LastSnapshotGen, snap.Userspace.NeighborGeneration)
		fmt.Fprintf(w, "  Binding state:        bindings=%d ready=%d bound=%d xsk=%d zc=%d\n",
			snap.Userspace.Bindings, snap.Userspace.ReadyBindings, snap.Userspace.BoundBindings, snap.Userspace.XSKRegistered, snap.Userspace.ZeroCopyBindings)
		writeRateDeltaLine(w, "  RX bytes:             %20d (", snap.Userspace.RxBytes, usRxBps,
			usRxBytesDelta, "bps", usRxBytesRateReset, usRxBytesReset)
		writeRateDeltaLine(w, "  TX bytes:             %20d (", snap.Userspace.TxBytes, usTxBps,
			usTxBytesDelta, "bps", usTxBytesRateReset, usTxBytesReset)
		writeRateDeltaLine(w, "  RX packets:           %20d (", snap.Userspace.RxPackets, usRxPps,
			usRxPktsDelta, "pps", usRxPktsRateReset, usRxPktsReset)
		writeRateDeltaLine(w, "  TX packets:           %20d (", snap.Userspace.TxPackets, usTxPps,
			usTxPktsDelta, "pps", usTxPktsRateReset, usTxPktsReset)
		writeDeltaLine(w, "  Direct TX packets:    %20d          [", snap.Userspace.DirectTXPackets, usDirectDelta, usDirectReset)
		writeDeltaLine(w, "  Copy TX packets:      %20d          [", snap.Userspace.CopyTXPackets, usCopyDelta, usCopyReset)
		writeDeltaLine(w, "  In-place TX packets:  %20d          [", snap.Userspace.InPlaceTXPackets, usInPlaceDelta, usInPlaceReset)
		writeDeltaLine(w, "  TX completions:       %20d          [", snap.Userspace.TxCompletions, usTxCompletionsDelta, usTxCompletionsReset)
		writeDeltaLine(w, "  Kernel RX dropped:    %20d          [", snap.Userspace.KernelRXDropped, usKernelRXDroppedDelta, usKernelRXDroppedReset)
		writeDeltaLine(w, "  Kernel RX invalid:    %20d          [", snap.Userspace.KernelRXInvalidDescs, usKernelRXInvalidDelta, usKernelRXInvalidReset)
		writeDeltaLine(w, "  Direct TX no-frame:   %20d          [", snap.Userspace.DirectTXNoFrameFallbackPackets, usDirectNoFrameDelta, usDirectNoFrameReset)
		writeDeltaLine(w, "  Direct TX build-none: %20d          [", snap.Userspace.DirectTXBuildFallbackPackets, usDirectBuildDelta, usDirectBuildReset)
		writeDeltaLine(w, "  Direct TX disallowed: %20d          [", snap.Userspace.DirectTXDisallowedFallbackPackets, usDirectDisallowedDelta, usDirectDisallowedReset)
		writeDeltaLine(w, "  Pending fill frames:  %20d          [", snap.Userspace.DebugPendingFillFrames, usPendingFillDelta, usPendingFillReset)
		writeDeltaLine(w, "  Spare fill frames:    %20d          [", snap.Userspace.DebugSpareFillFrames, usSpareFillDelta, usSpareFillReset)
		writeDeltaLine(w, "  Free TX frames:       %20d          [", snap.Userspace.DebugFreeTXFrames, usFreeTXDelta, usFreeTXReset)
		writeDeltaLine(w, "  Pending TX prepared:  %20d          [", snap.Userspace.DebugPendingTXPrepared, usPendingPreparedDelta, usPendingPreparedReset)
		writeDeltaLine(w, "  Pending TX local:     %20d          [", snap.Userspace.DebugPendingTXLocal, usPendingLocalDelta, usPendingLocalReset)
		writeDeltaLine(w, "  Outstanding TX:       %20d          [", snap.Userspace.DebugOutstandingTX, usOutstandingTXDelta, usOutstandingTXReset)
		writeDeltaLine(w, "  In-flight recycles:   %20d          [", snap.Userspace.DebugInFlightRecycles, usInFlightRecycleDelta, usInFlightRecycleReset)
		writeDeltaLine(w, "  Session misses:       %20d          [", snap.Userspace.SessionMisses, usSessionMissDelta, usSessionMissReset)
		writeDeltaLine(w, "  Neighbor misses:      %20d          [", snap.Userspace.NeighborMissPackets, usNeighborMissDelta, usNeighborMissReset)
		writeDeltaLine(w, "  Route misses:         %20d          [", snap.Userspace.RouteMissPackets, usRouteMissDelta, usRouteMissReset)
		writeDeltaLine(w, "  Policy denied:        %20d          [", snap.Userspace.PolicyDeniedPackets, usPolicyDeniedDelta, usPolicyDeniedReset)
		writeDeltaLine(w, "  Exception packets:    %20d          [", snap.Userspace.ExceptionPackets, usExceptionDelta, usExceptionReset)
		fmt.Fprintf(w, "  Slow path packets:    %20d          [", snap.Userspace.SlowPathPackets)
		writeCounterDelta(w, usSlowPathDelta, usSlowPathReset)
		fmt.Fprintf(w, "]  local=%d[", snap.Userspace.SlowPathLocalDeliveryPackets)
		writeCounterDelta(w, usSlowPathLocalDelta, usSlowPathLocalReset)
		fmt.Fprintf(w, "] neigh=%d[", snap.Userspace.SlowPathMissingNeighborPackets)
		writeCounterDelta(w, usSlowPathMissingNeighborDelta, usSlowPathMissingNeighborReset)
		fmt.Fprintf(w, "] route=%d[", snap.Userspace.SlowPathNoRoutePackets)
		writeCounterDelta(w, usSlowPathNoRouteDelta, usSlowPathNoRouteReset)
		fmt.Fprintf(w, "] next=%d[", snap.Userspace.SlowPathNextTablePackets)
		writeCounterDelta(w, usSlowPathNextTableDelta, usSlowPathNextTableReset)
		fmt.Fprintf(w, "] build=%d[", snap.Userspace.SlowPathForwardBuildPackets)
		writeCounterDelta(w, usSlowPathBuildDelta, usSlowPathBuildReset)
		fmt.Fprintf(w, "]\n")
		if len(snap.Userspace.LastErrors) > 0 {
			fmt.Fprintf(w, "  Binding errors:\n")
			for _, msg := range snap.Userspace.LastErrors {
				fmt.Fprintf(w, "    %s\n", msg)
			}
		}
		if len(snap.Userspace.RecentExceptions) > 0 {
			fmt.Fprintf(w, "  Recent exceptions:\n")
			for _, msg := range snap.Userspace.RecentExceptions {
				fmt.Fprintf(w, "    %s\n", msg)
			}
		}
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "Keys: q=quit  n=next interface  f=freeze  t=thaw  c=clear baseline\n")
}

func RenderTrafficSummary(w io.Writer, hostname string, names []string, kernelNames map[string]string, snaps, prevSnaps map[string]*Snapshot, mode SummaryMode, startTime time.Time) {
	seconds := int(time.Since(startTime).Seconds())
	now := time.Now().Format("15:04:05")

	fmt.Fprintf(w, "  xpf %s monitor interface traffic (probing every 1.000s), mode: %s\n", hostname, SummaryModeLabel(mode))
	fmt.Fprintf(w, "  elapsed: %ds  time: %s\n\n", seconds, now)

	switch mode {
	case SummaryModePackets:
		fmt.Fprintf(w, "  %-16s %16s %16s %16s\n", "iface", "Rx pps", "Tx pps", "Total pps")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 70))
		var totalRxPps, totalTxPps uint64
		var totalRxReset, totalTxReset bool
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			rates := snapshotRates(snap, prevSnaps[name])
			totalRxPps += rates.rxPps
			totalTxPps += rates.txPps
			totalRxReset = totalRxReset || rates.rxPktsReset
			totalTxReset = totalTxReset || rates.txPktsReset
			fmt.Fprintf(w, "  %-16s %16s %16s %16s\n",
				name+":",
				formatCounterValue(formatPacketRate(rates.rxPps), rates.rxPktsReset),
				formatCounterValue(formatPacketRate(rates.txPps), rates.txPktsReset),
				formatCounterValue(formatPacketRate(rates.rxPps+rates.txPps), rates.rxPktsReset || rates.txPktsReset))
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 70))
		fmt.Fprintf(w, "  %-16s %16s %16s %16s\n",
			"total:",
			formatCounterValue(formatPacketRate(totalRxPps), totalRxReset),
			formatCounterValue(formatPacketRate(totalTxPps), totalTxReset),
			formatCounterValue(formatPacketRate(totalRxPps+totalTxPps), totalRxReset || totalTxReset))
	case SummaryModeBytes:
		fmt.Fprintf(w, "  %-16s %20s %20s %20s\n", "iface", "Rx", "Tx", "Total")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 82))
		var totalRxBytesPerSec, totalTxBytesPerSec uint64
		var totalRxReset, totalTxReset bool
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			rates := snapshotRates(snap, prevSnaps[name])
			totalRxBytesPerSec += rates.rxBytesPerSec
			totalTxBytesPerSec += rates.txBytesPerSec
			totalRxReset = totalRxReset || rates.rxBytesReset
			totalTxReset = totalTxReset || rates.txBytesReset
			fmt.Fprintf(w, "  %-16s %20s %20s %20s\n",
				name+":",
				formatCounterValue(formatBytesRate(rates.rxBytesPerSec), rates.rxBytesReset),
				formatCounterValue(formatBytesRate(rates.txBytesPerSec), rates.txBytesReset),
				formatCounterValue(formatBytesRate(rates.rxBytesPerSec+rates.txBytesPerSec), rates.rxBytesReset || rates.txBytesReset))
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 82))
		fmt.Fprintf(w, "  %-16s %20s %20s %20s\n",
			"total:",
			formatCounterValue(formatBytesRate(totalRxBytesPerSec), totalRxReset),
			formatCounterValue(formatBytesRate(totalTxBytesPerSec), totalTxReset),
			formatCounterValue(formatBytesRate(totalRxBytesPerSec+totalTxBytesPerSec), totalRxReset || totalTxReset))
	case SummaryModeDelta:
		fmt.Fprintf(w, "  %-16s %16s %16s %16s\n", "iface", "Rx delta", "Tx delta", "Total")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 70))
		var totalRxDelta, totalTxDelta uint64
		var totalRxReset, totalTxReset bool
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			var deltas trafficDeltas
			if prev := prevSnaps[name]; prev != nil {
				deltas = snapshotTrafficDeltas(snap, prev)
			}
			totalRxDelta += deltas.rxPkts
			totalTxDelta += deltas.txPkts
			totalRxReset = totalRxReset || deltas.rxPktsReset
			totalTxReset = totalTxReset || deltas.txPktsReset
			fmt.Fprintf(w, "  %-16s ", name+":")
			writeSummaryCounterDelta(w, deltas.rxPkts, deltas.rxPktsReset)
			_, _ = io.WriteString(w, " ")
			writeSummaryCounterDelta(w, deltas.txPkts, deltas.txPktsReset)
			_, _ = io.WriteString(w, " ")
			writeSummaryCounterDelta(w, deltas.rxPkts+deltas.txPkts, deltas.rxPktsReset || deltas.txPktsReset)
			_, _ = io.WriteString(w, "\n")
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 70))
		fmt.Fprintf(w, "  %-16s ", "total:")
		writeSummaryCounterDelta(w, totalRxDelta, totalRxReset)
		_, _ = io.WriteString(w, " ")
		writeSummaryCounterDelta(w, totalTxDelta, totalTxReset)
		_, _ = io.WriteString(w, " ")
		writeSummaryCounterDelta(w, totalRxDelta+totalTxDelta, totalRxReset || totalTxReset)
		_, _ = io.WriteString(w, "\n")
	case SummaryModeRate:
		fmt.Fprintf(w, "  %-16s %16s %16s %16s %12s %12s %12s\n", "iface", "Rx b/s", "Tx b/s", "Total b/s", "Rx pps", "Tx pps", "Total")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 106))
		var totalRxPps, totalTxPps, totalRxBitsPerSec, totalTxBitsPerSec uint64
		var totalRxPktsReset, totalTxPktsReset, totalRxBytesReset, totalTxBytesReset bool
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			rates := snapshotRates(snap, prevSnaps[name])
			rxBitsPerSec := rates.rxBytesPerSec * 8
			txBitsPerSec := rates.txBytesPerSec * 8
			totalRxPps += rates.rxPps
			totalTxPps += rates.txPps
			totalRxBitsPerSec += rxBitsPerSec
			totalTxBitsPerSec += txBitsPerSec
			totalRxPktsReset = totalRxPktsReset || rates.rxPktsReset
			totalTxPktsReset = totalTxPktsReset || rates.txPktsReset
			totalRxBytesReset = totalRxBytesReset || rates.rxBytesReset
			totalTxBytesReset = totalTxBytesReset || rates.txBytesReset
			fmt.Fprintf(w, "  %-16s %16s %16s %16s %12s %12s %12s\n",
				name+":",
				formatCounterValue(formatBitsRate(rxBitsPerSec), rates.rxBytesReset),
				formatCounterValue(formatBitsRate(txBitsPerSec), rates.txBytesReset),
				formatCounterValue(formatBitsRate(rxBitsPerSec+txBitsPerSec), rates.rxBytesReset || rates.txBytesReset),
				formatCounterValue(formatPacketRate(rates.rxPps), rates.rxPktsReset),
				formatCounterValue(formatPacketRate(rates.txPps), rates.txPktsReset),
				formatCounterValue(formatPacketRate(rates.rxPps+rates.txPps), rates.rxPktsReset || rates.txPktsReset))
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 106))
		fmt.Fprintf(w, "  %-16s %16s %16s %16s %12s %12s %12s\n",
			"total:",
			formatCounterValue(formatBitsRate(totalRxBitsPerSec), totalRxBytesReset),
			formatCounterValue(formatBitsRate(totalTxBitsPerSec), totalTxBytesReset),
			formatCounterValue(formatBitsRate(totalRxBitsPerSec+totalTxBitsPerSec), totalRxBytesReset || totalTxBytesReset),
			formatCounterValue(formatPacketRate(totalRxPps), totalRxPktsReset),
			formatCounterValue(formatPacketRate(totalTxPps), totalTxPktsReset),
			formatCounterValue(formatPacketRate(totalRxPps+totalTxPps), totalRxPktsReset || totalTxPktsReset))
	default:
		fmt.Fprintf(w, "  %-16s %20s %20s %20s %12s %12s %12s\n", "iface", "Rx", "Tx", "Total", "Rx pps", "Tx pps", "Total")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 108))
		var totalRxPps, totalTxPps, totalRxBytesPerSec, totalTxBytesPerSec uint64
		var totalRxPktsReset, totalTxPktsReset, totalRxBytesReset, totalTxBytesReset bool
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			rates := snapshotRates(snap, prevSnaps[name])
			totalRxPps += rates.rxPps
			totalTxPps += rates.txPps
			totalRxBytesPerSec += rates.rxBytesPerSec
			totalTxBytesPerSec += rates.txBytesPerSec
			totalRxPktsReset = totalRxPktsReset || rates.rxPktsReset
			totalTxPktsReset = totalTxPktsReset || rates.txPktsReset
			totalRxBytesReset = totalRxBytesReset || rates.rxBytesReset
			totalTxBytesReset = totalTxBytesReset || rates.txBytesReset
			fmt.Fprintf(w, "  %-16s %20s %20s %20s %12s %12s %12s\n",
				name+":",
				formatCounterValue(formatBytesRate(rates.rxBytesPerSec), rates.rxBytesReset),
				formatCounterValue(formatBytesRate(rates.txBytesPerSec), rates.txBytesReset),
				formatCounterValue(formatBytesRate(rates.rxBytesPerSec+rates.txBytesPerSec), rates.rxBytesReset || rates.txBytesReset),
				formatCounterValue(formatPacketRate(rates.rxPps), rates.rxPktsReset),
				formatCounterValue(formatPacketRate(rates.txPps), rates.txPktsReset),
				formatCounterValue(formatPacketRate(rates.rxPps+rates.txPps), rates.rxPktsReset || rates.txPktsReset))
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 108))
		fmt.Fprintf(w, "  %-16s %20s %20s %20s %12s %12s %12s\n",
			"total:",
			formatCounterValue(formatBytesRate(totalRxBytesPerSec), totalRxBytesReset),
			formatCounterValue(formatBytesRate(totalTxBytesPerSec), totalTxBytesReset),
			formatCounterValue(formatBytesRate(totalRxBytesPerSec+totalTxBytesPerSec), totalRxBytesReset || totalTxBytesReset),
			formatCounterValue(formatPacketRate(totalRxPps), totalRxPktsReset),
			formatCounterValue(formatPacketRate(totalTxPps), totalTxPktsReset),
			formatCounterValue(formatPacketRate(totalRxPps+totalTxPps), totalRxPktsReset || totalTxPktsReset))
	}

	fmt.Fprintf(w, "\nKeys: q=quit  c=combined  p=packets  b=bytes  d=delta  r=rate\n")
}

func snapshotRates(curr, prev *Snapshot) trafficRates {
	var rates trafficRates
	if curr == nil || prev == nil {
		return rates
	}
	deltas := snapshotTrafficDeltas(curr, prev)
	rates.rxPktsReset = deltas.rxPktsReset
	rates.txPktsReset = deltas.txPktsReset
	rates.rxBytesReset = deltas.rxBytesReset
	rates.txBytesReset = deltas.txBytesReset
	dt := curr.Timestamp.Sub(prev.Timestamp).Seconds()
	if dt <= 0 {
		return rates
	}
	rates.rxPps = uint64(float64(deltas.rxPkts) / dt)
	rates.txPps = uint64(float64(deltas.txPkts) / dt)
	rates.rxBytesPerSec = uint64(float64(deltas.rxBytes) / dt)
	rates.txBytesPerSec = uint64(float64(deltas.txBytes) / dt)
	return rates
}

func formatPacketRate(v uint64) string {
	switch {
	case v >= 1_000_000_000:
		return fmt.Sprintf("%.2fG", float64(v)/1_000_000_000)
	case v >= 1_000_000:
		return fmt.Sprintf("%.2fM", float64(v)/1_000_000)
	case v >= 1_000:
		return fmt.Sprintf("%.2fK", float64(v)/1_000)
	default:
		return fmt.Sprintf("%.2f", float64(v))
	}
}

func formatBytesRate(v uint64) string {
	value := float64(v)
	unit := "B/s"
	switch {
	case v >= 1_000_000_000:
		value = value / 1_000_000_000
		unit = "GB/s"
	case v >= 1_000_000:
		value = value / 1_000_000
		unit = "MB/s"
	case v >= 1_000:
		value = value / 1_000
		unit = "KB/s"
	}
	return fmt.Sprintf("%.2f %s", value, unit)
}

func formatBitsRate(v uint64) string {
	value := float64(v)
	unit := "b/s"
	switch {
	case v >= 1_000_000_000:
		value = value / 1_000_000_000
		unit = "Gb/s"
	case v >= 1_000_000:
		value = value / 1_000_000
		unit = "Mb/s"
	case v >= 1_000:
		value = value / 1_000
		unit = "Kb/s"
	}
	return fmt.Sprintf("%.2f %s", value, unit)
}

func formatUserspaceException(exc dpuserspace.ExceptionStatus) string {
	fields := []string{exc.Reason}
	if exc.SrcIP != "" || exc.DstIP != "" {
		flow := exc.SrcIP
		if exc.SrcPort != 0 {
			flow = fmt.Sprintf("%s:%d", flow, exc.SrcPort)
		}
		flow += " -> " + exc.DstIP
		if exc.DstPort != 0 {
			flow += fmt.Sprintf(":%d", exc.DstPort)
		}
		fields = append(fields, flow)
	}
	if exc.FromZone != "" || exc.ToZone != "" {
		fields = append(fields, fmt.Sprintf("%s->%s", exc.FromZone, exc.ToZone))
	}
	return strings.Join(fields, " | ")
}
