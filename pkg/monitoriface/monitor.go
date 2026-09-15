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
func snapshotTrafficDeltas(curr, prev *Snapshot) (rxPktsDelta, txPktsDelta, rxBytesDelta, txBytesDelta uint64, userspaceDropped bool) {
	if curr == nil || prev == nil {
		return 0, 0, 0, 0, false
	}

	rxPktsDelta = deltaU64(curr.RxPkts, prev.RxPkts)
	txPktsDelta = deltaU64(curr.TxPkts, prev.TxPkts)
	rxBytesDelta = deltaU64(curr.RxBytes, prev.RxBytes)
	txBytesDelta = deltaU64(curr.TxBytes, prev.TxBytes)

	if hasUserspaceTrafficSource(curr.Userspace) && hasUserspaceTrafficSource(prev.Userspace) {
		rxPktsDelta += deltaU64(curr.Userspace.RxPackets, prev.Userspace.RxPackets)
		txPktsDelta += deltaU64(curr.Userspace.TxPackets, prev.Userspace.TxPackets)
		rxBytesDelta += deltaU64(curr.Userspace.RxBytes, prev.Userspace.RxBytes)
		txBytesDelta += deltaU64(curr.Userspace.TxBytes, prev.Userspace.TxBytes)
		return rxPktsDelta, txPktsDelta, rxBytesDelta, txBytesDelta, false
	}

	// Dropped. Report it ONLY when the interface actually has a userspace
	// source to contribute in the current sample -- otherwise every
	// kernel-only interface would carry a permanent note about a component it
	// never has, which is the false-positive that makes operators stop reading
	// notes.
	return rxPktsDelta, txPktsDelta, rxBytesDelta, txBytesDelta,
		hasUserspaceTrafficSource(curr.Userspace)
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

func RenderSingleInterface(w io.Writer, hostname, displayName, kernelName string, snap, prev, baseline *Snapshot, startTime time.Time) {
	seconds := int(time.Since(startTime).Seconds())
	now := time.Now().Format("15:04:05")
	linkState := ReadLinkState(kernelName)
	speed := ReadLinkSpeed(kernelName)

	fmt.Fprintf(w, "%-40s Seconds: %-10d Time: %s\n", hostname, seconds, now)
	fmt.Fprintf(w, "Interface: %s, Enabled, Link is %s\n", displayName, linkState)
	fmt.Fprintf(w, "Encapsulation: Ethernet, Speed: %s\n", speed)

	var rxBps, txBps, rxPps, txPps uint64
	var userspaceRateDropped bool
	if prev != nil {
		dt := snap.Timestamp.Sub(prev.Timestamp).Seconds()
		if dt > 0 {
			rxPktsDelta, txPktsDelta, rxBytesDeltaStep, txBytesDeltaStep, dropped := snapshotTrafficDeltas(snap, prev)
			userspaceRateDropped = dropped
			rxBps = uint64(float64(rxBytesDeltaStep) * 8 / dt)
			txBps = uint64(float64(txBytesDeltaStep) * 8 / dt)
			rxPps = uint64(float64(rxPktsDelta) / dt)
			txPps = uint64(float64(txPktsDelta) / dt)
		}
	}

	var rxBytesDelta, txBytesDelta, rxPktsDelta, txPktsDelta uint64
	if baseline != nil {
		rxPktsDelta, txPktsDelta, rxBytesDelta, txBytesDelta, _ = snapshotTrafficDeltas(snap, baseline)
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
	fmt.Fprintf(w, "  Input  bytes:         %20d (%d bps)    [%d]\n", currCounters.rxBytes, rxBps, rxBytesDelta)
	fmt.Fprintf(w, "  Output bytes:         %20d (%d bps)    [%d]\n", currCounters.txBytes, txBps, txBytesDelta)
	fmt.Fprintf(w, "  Input  packets:       %20d (%d pps)    [%d]\n", currCounters.rxPkts, rxPps, rxPktsDelta)
	fmt.Fprintf(w, "  Output packets:       %20d (%d pps)    [%d]\n", currCounters.txPkts, txPps, txPktsDelta)
	fmt.Fprintf(w, "\n")

	var rxErrDelta, txErrDelta, rxDropDelta, txDropDelta, rxFrameDelta, txCarrierDelta, colDelta uint64
	if baseline != nil {
		rxErrDelta = deltaU64(snap.RxErrors, baseline.RxErrors)
		txErrDelta = deltaU64(snap.TxErrors, baseline.TxErrors)
		rxDropDelta = deltaU64(snap.RxDrops, baseline.RxDrops)
		txDropDelta = deltaU64(snap.TxDrops, baseline.TxDrops)
		rxFrameDelta = deltaU64(snap.RxFrame, baseline.RxFrame)
		txCarrierDelta = deltaU64(snap.TxCarrier, baseline.TxCarrier)
		colDelta = deltaU64(snap.Collisions, baseline.Collisions)
	}

	fmt.Fprintf(w, "Error statistics:                                  Current delta\n")
	// #7422 row 10: the kernel link statistics feed EVERY line in this block,
	// plus the byte/packet fallback above, so a failed read renders a clean
	// interface rather than an unread one.
	if snap.KernelStatsNote != "" {
		fmt.Fprintf(w, "  Note: kernel link statistics unavailable (%s) — the zeros below are NOT a measurement\n",
			snap.KernelStatsNote)
	}
	fmt.Fprintf(w, "  Input  errors:        %20d          [%d]\n", snap.RxErrors, rxErrDelta)
	fmt.Fprintf(w, "  Output errors:        %20d          [%d]\n", snap.TxErrors, txErrDelta)
	fmt.Fprintf(w, "  Input  drops:         %20d          [%d]\n", snap.RxDrops, rxDropDelta)
	fmt.Fprintf(w, "  Output drops:         %20d          [%d]\n", snap.TxDrops, txDropDelta)
	fmt.Fprintf(w, "  Input  frame errors:  %20d          [%d]\n", snap.RxFrame, rxFrameDelta)
	fmt.Fprintf(w, "  Output carrier:       %20d          [%d]\n", snap.TxCarrier, txCarrierDelta)
	fmt.Fprintf(w, "  Collisions:           %20d          [%d]\n", snap.Collisions, colDelta)
	fmt.Fprintf(w, "\n")

	if snap.Userspace != nil {
		var (
			usRxBps, usTxBps, usRxPps, usTxPps                                     uint64
			usRxBytesDelta, usTxBytesDelta, usRxPktsDelta, usTxPktsDelta           uint64
			usDirectDelta, usCopyDelta, usInPlaceDelta                             uint64
			usDirectNoFrameDelta, usDirectBuildDelta, usDirectDisallowedDelta      uint64
			usTxCompletionsDelta, usKernelRXDroppedDelta, usKernelRXInvalidDelta   uint64
			usPendingFillDelta, usSpareFillDelta, usFreeTXDelta                    uint64
			usPendingPreparedDelta, usPendingLocalDelta                            uint64
			usOutstandingTXDelta, usInFlightRecycleDelta                           uint64
			usSessionMissDelta, usNeighborMissDelta, usRouteMissDelta              uint64
			usPolicyDeniedDelta, usExceptionDelta, usSlowPathDelta                 uint64
			usSlowPathLocalDelta, usSlowPathMissingNeighborDelta                   uint64
			usSlowPathNoRouteDelta, usSlowPathNextTableDelta, usSlowPathBuildDelta uint64
		)
		if prev != nil && prev.Userspace != nil {
			dt := snap.Timestamp.Sub(prev.Timestamp).Seconds()
			if dt > 0 {
				usRxBps = uint64(float64(deltaU64(snap.Userspace.RxBytes, prev.Userspace.RxBytes)) * 8 / dt)
				usTxBps = uint64(float64(deltaU64(snap.Userspace.TxBytes, prev.Userspace.TxBytes)) * 8 / dt)
				usRxPps = uint64(float64(deltaU64(snap.Userspace.RxPackets, prev.Userspace.RxPackets)) / dt)
				usTxPps = uint64(float64(deltaU64(snap.Userspace.TxPackets, prev.Userspace.TxPackets)) / dt)
			}
		}
		if baseline != nil && baseline.Userspace != nil {
			usRxBytesDelta = deltaU64(snap.Userspace.RxBytes, baseline.Userspace.RxBytes)
			usTxBytesDelta = deltaU64(snap.Userspace.TxBytes, baseline.Userspace.TxBytes)
			usRxPktsDelta = deltaU64(snap.Userspace.RxPackets, baseline.Userspace.RxPackets)
			usTxPktsDelta = deltaU64(snap.Userspace.TxPackets, baseline.Userspace.TxPackets)
			usDirectDelta = deltaU64(snap.Userspace.DirectTXPackets, baseline.Userspace.DirectTXPackets)
			usCopyDelta = deltaU64(snap.Userspace.CopyTXPackets, baseline.Userspace.CopyTXPackets)
			usInPlaceDelta = deltaU64(snap.Userspace.InPlaceTXPackets, baseline.Userspace.InPlaceTXPackets)
			usDirectNoFrameDelta = deltaU64(snap.Userspace.DirectTXNoFrameFallbackPackets, baseline.Userspace.DirectTXNoFrameFallbackPackets)
			usDirectBuildDelta = deltaU64(snap.Userspace.DirectTXBuildFallbackPackets, baseline.Userspace.DirectTXBuildFallbackPackets)
			usDirectDisallowedDelta = deltaU64(snap.Userspace.DirectTXDisallowedFallbackPackets, baseline.Userspace.DirectTXDisallowedFallbackPackets)
			usTxCompletionsDelta = deltaU64(snap.Userspace.TxCompletions, baseline.Userspace.TxCompletions)
			usKernelRXDroppedDelta = deltaU64(snap.Userspace.KernelRXDropped, baseline.Userspace.KernelRXDropped)
			usKernelRXInvalidDelta = deltaU64(snap.Userspace.KernelRXInvalidDescs, baseline.Userspace.KernelRXInvalidDescs)
			usPendingFillDelta = deltaU64(snap.Userspace.DebugPendingFillFrames, baseline.Userspace.DebugPendingFillFrames)
			usSpareFillDelta = deltaU64(snap.Userspace.DebugSpareFillFrames, baseline.Userspace.DebugSpareFillFrames)
			usFreeTXDelta = deltaU64(snap.Userspace.DebugFreeTXFrames, baseline.Userspace.DebugFreeTXFrames)
			usPendingPreparedDelta = deltaU64(snap.Userspace.DebugPendingTXPrepared, baseline.Userspace.DebugPendingTXPrepared)
			usPendingLocalDelta = deltaU64(snap.Userspace.DebugPendingTXLocal, baseline.Userspace.DebugPendingTXLocal)
			usOutstandingTXDelta = deltaU64(snap.Userspace.DebugOutstandingTX, baseline.Userspace.DebugOutstandingTX)
			usInFlightRecycleDelta = deltaU64(snap.Userspace.DebugInFlightRecycles, baseline.Userspace.DebugInFlightRecycles)
			usSessionMissDelta = deltaU64(snap.Userspace.SessionMisses, baseline.Userspace.SessionMisses)
			usNeighborMissDelta = deltaU64(snap.Userspace.NeighborMissPackets, baseline.Userspace.NeighborMissPackets)
			usRouteMissDelta = deltaU64(snap.Userspace.RouteMissPackets, baseline.Userspace.RouteMissPackets)
			usPolicyDeniedDelta = deltaU64(snap.Userspace.PolicyDeniedPackets, baseline.Userspace.PolicyDeniedPackets)
			usExceptionDelta = deltaU64(snap.Userspace.ExceptionPackets, baseline.Userspace.ExceptionPackets)
			usSlowPathDelta = deltaU64(snap.Userspace.SlowPathPackets, baseline.Userspace.SlowPathPackets)
			usSlowPathLocalDelta = deltaU64(snap.Userspace.SlowPathLocalDeliveryPackets, baseline.Userspace.SlowPathLocalDeliveryPackets)
			usSlowPathMissingNeighborDelta = deltaU64(snap.Userspace.SlowPathMissingNeighborPackets, baseline.Userspace.SlowPathMissingNeighborPackets)
			usSlowPathNoRouteDelta = deltaU64(snap.Userspace.SlowPathNoRoutePackets, baseline.Userspace.SlowPathNoRoutePackets)
			usSlowPathNextTableDelta = deltaU64(snap.Userspace.SlowPathNextTablePackets, baseline.Userspace.SlowPathNextTablePackets)
			usSlowPathBuildDelta = deltaU64(snap.Userspace.SlowPathForwardBuildPackets, baseline.Userspace.SlowPathForwardBuildPackets)
		}

		fmt.Fprintf(w, "Userspace dataplane:\n")
		if snap.Userspace.StatusNote != "" {
			fmt.Fprintf(w, "  Note:                 %s\n", snap.Userspace.StatusNote)
		}
		fmt.Fprintf(w, "  Helper state:         enabled=%t armed=%t snapshot_gen=%d neighbor_gen=%d\n",
			snap.Userspace.HelperEnabled, snap.Userspace.ForwardingArmed, snap.Userspace.LastSnapshotGen, snap.Userspace.NeighborGeneration)
		fmt.Fprintf(w, "  Binding state:        bindings=%d ready=%d bound=%d xsk=%d zc=%d\n",
			snap.Userspace.Bindings, snap.Userspace.ReadyBindings, snap.Userspace.BoundBindings, snap.Userspace.XSKRegistered, snap.Userspace.ZeroCopyBindings)
		fmt.Fprintf(w, "  RX bytes:             %20d (%d bps)    [%d]\n", snap.Userspace.RxBytes, usRxBps, usRxBytesDelta)
		fmt.Fprintf(w, "  TX bytes:             %20d (%d bps)    [%d]\n", snap.Userspace.TxBytes, usTxBps, usTxBytesDelta)
		fmt.Fprintf(w, "  RX packets:           %20d (%d pps)    [%d]\n", snap.Userspace.RxPackets, usRxPps, usRxPktsDelta)
		fmt.Fprintf(w, "  TX packets:           %20d (%d pps)    [%d]\n", snap.Userspace.TxPackets, usTxPps, usTxPktsDelta)
		fmt.Fprintf(w, "  Direct TX packets:    %20d          [%d]\n", snap.Userspace.DirectTXPackets, usDirectDelta)
		fmt.Fprintf(w, "  Copy TX packets:      %20d          [%d]\n", snap.Userspace.CopyTXPackets, usCopyDelta)
		fmt.Fprintf(w, "  In-place TX packets:  %20d          [%d]\n", snap.Userspace.InPlaceTXPackets, usInPlaceDelta)
		fmt.Fprintf(w, "  TX completions:       %20d          [%d]\n", snap.Userspace.TxCompletions, usTxCompletionsDelta)
		fmt.Fprintf(w, "  Kernel RX dropped:    %20d          [%d]\n", snap.Userspace.KernelRXDropped, usKernelRXDroppedDelta)
		fmt.Fprintf(w, "  Kernel RX invalid:    %20d          [%d]\n", snap.Userspace.KernelRXInvalidDescs, usKernelRXInvalidDelta)
		fmt.Fprintf(w, "  Direct TX no-frame:   %20d          [%d]\n", snap.Userspace.DirectTXNoFrameFallbackPackets, usDirectNoFrameDelta)
		fmt.Fprintf(w, "  Direct TX build-none: %20d          [%d]\n", snap.Userspace.DirectTXBuildFallbackPackets, usDirectBuildDelta)
		fmt.Fprintf(w, "  Direct TX disallowed: %20d          [%d]\n", snap.Userspace.DirectTXDisallowedFallbackPackets, usDirectDisallowedDelta)
		fmt.Fprintf(w, "  Pending fill frames:  %20d          [%d]\n", snap.Userspace.DebugPendingFillFrames, usPendingFillDelta)
		fmt.Fprintf(w, "  Spare fill frames:    %20d          [%d]\n", snap.Userspace.DebugSpareFillFrames, usSpareFillDelta)
		fmt.Fprintf(w, "  Free TX frames:       %20d          [%d]\n", snap.Userspace.DebugFreeTXFrames, usFreeTXDelta)
		fmt.Fprintf(w, "  Pending TX prepared:  %20d          [%d]\n", snap.Userspace.DebugPendingTXPrepared, usPendingPreparedDelta)
		fmt.Fprintf(w, "  Pending TX local:     %20d          [%d]\n", snap.Userspace.DebugPendingTXLocal, usPendingLocalDelta)
		fmt.Fprintf(w, "  Outstanding TX:       %20d          [%d]\n", snap.Userspace.DebugOutstandingTX, usOutstandingTXDelta)
		fmt.Fprintf(w, "  In-flight recycles:   %20d          [%d]\n", snap.Userspace.DebugInFlightRecycles, usInFlightRecycleDelta)
		fmt.Fprintf(w, "  Session misses:       %20d          [%d]\n", snap.Userspace.SessionMisses, usSessionMissDelta)
		fmt.Fprintf(w, "  Neighbor misses:      %20d          [%d]\n", snap.Userspace.NeighborMissPackets, usNeighborMissDelta)
		fmt.Fprintf(w, "  Route misses:         %20d          [%d]\n", snap.Userspace.RouteMissPackets, usRouteMissDelta)
		fmt.Fprintf(w, "  Policy denied:        %20d          [%d]\n", snap.Userspace.PolicyDeniedPackets, usPolicyDeniedDelta)
		fmt.Fprintf(w, "  Exception packets:    %20d          [%d]\n", snap.Userspace.ExceptionPackets, usExceptionDelta)
		fmt.Fprintf(w, "  Slow path packets:    %20d          [%d]  local=%d[%d] neigh=%d[%d] route=%d[%d] next=%d[%d] build=%d[%d]\n",
			snap.Userspace.SlowPathPackets,
			usSlowPathDelta,
			snap.Userspace.SlowPathLocalDeliveryPackets,
			usSlowPathLocalDelta,
			snap.Userspace.SlowPathMissingNeighborPackets,
			usSlowPathMissingNeighborDelta,
			snap.Userspace.SlowPathNoRoutePackets,
			usSlowPathNoRouteDelta,
			snap.Userspace.SlowPathNextTablePackets,
			usSlowPathNextTableDelta,
			snap.Userspace.SlowPathForwardBuildPackets,
			usSlowPathBuildDelta)
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
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			rxPps, txPps, _, _ := snapshotRates(snap, prevSnaps[name])
			totalRxPps += rxPps
			totalTxPps += txPps
			fmt.Fprintf(w, "  %-16s %16s %16s %16s\n",
				name+":", formatPacketRate(rxPps), formatPacketRate(txPps), formatPacketRate(rxPps+txPps))
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 70))
		fmt.Fprintf(w, "  %-16s %16s %16s %16s\n",
			"total:", formatPacketRate(totalRxPps), formatPacketRate(totalTxPps), formatPacketRate(totalRxPps+totalTxPps))
	case SummaryModeBytes:
		fmt.Fprintf(w, "  %-16s %20s %20s %20s\n", "iface", "Rx", "Tx", "Total")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 82))
		var totalRxBytesPerSec, totalTxBytesPerSec uint64
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			_, _, rxBytesPerSec, txBytesPerSec := snapshotRates(snap, prevSnaps[name])
			totalRxBytesPerSec += rxBytesPerSec
			totalTxBytesPerSec += txBytesPerSec
			fmt.Fprintf(w, "  %-16s %20s %20s %20s\n",
				name+":", formatBytesRate(rxBytesPerSec), formatBytesRate(txBytesPerSec), formatBytesRate(rxBytesPerSec+txBytesPerSec))
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 82))
		fmt.Fprintf(w, "  %-16s %20s %20s %20s\n",
			"total:", formatBytesRate(totalRxBytesPerSec), formatBytesRate(totalTxBytesPerSec), formatBytesRate(totalRxBytesPerSec+totalTxBytesPerSec))
	case SummaryModeDelta:
		fmt.Fprintf(w, "  %-16s %16s %16s %16s\n", "iface", "Rx delta", "Tx delta", "Total")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 70))
		var totalRxDelta, totalTxDelta uint64
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			var rxDelta, txDelta uint64
			if prev := prevSnaps[name]; prev != nil {
				rxDelta, txDelta, _, _, _ = snapshotTrafficDeltas(snap, prev)
			}
			totalRxDelta += rxDelta
			totalTxDelta += txDelta
			fmt.Fprintf(w, "  %-16s %16d %16d %16d\n",
				name+":", rxDelta, txDelta, rxDelta+txDelta)
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 70))
		fmt.Fprintf(w, "  %-16s %16d %16d %16d\n",
			"total:", totalRxDelta, totalTxDelta, totalRxDelta+totalTxDelta)
	case SummaryModeRate:
		fmt.Fprintf(w, "  %-16s %16s %16s %16s %12s %12s %12s\n", "iface", "Rx b/s", "Tx b/s", "Total b/s", "Rx pps", "Tx pps", "Total")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 106))
		var totalRxPps, totalTxPps, totalRxBitsPerSec, totalTxBitsPerSec uint64
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			rxPps, txPps, rxBytesPerSec, txBytesPerSec := snapshotRates(snap, prevSnaps[name])
			rxBitsPerSec := rxBytesPerSec * 8
			txBitsPerSec := txBytesPerSec * 8
			totalRxPps += rxPps
			totalTxPps += txPps
			totalRxBitsPerSec += rxBitsPerSec
			totalTxBitsPerSec += txBitsPerSec
			fmt.Fprintf(w, "  %-16s %16s %16s %16s %12s %12s %12s\n",
				name+":",
				formatBitsRate(rxBitsPerSec),
				formatBitsRate(txBitsPerSec),
				formatBitsRate(rxBitsPerSec+txBitsPerSec),
				formatPacketRate(rxPps),
				formatPacketRate(txPps),
				formatPacketRate(rxPps+txPps))
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 106))
		fmt.Fprintf(w, "  %-16s %16s %16s %16s %12s %12s %12s\n",
			"total:",
			formatBitsRate(totalRxBitsPerSec),
			formatBitsRate(totalTxBitsPerSec),
			formatBitsRate(totalRxBitsPerSec+totalTxBitsPerSec),
			formatPacketRate(totalRxPps),
			formatPacketRate(totalTxPps),
			formatPacketRate(totalRxPps+totalTxPps))
	default:
		fmt.Fprintf(w, "  %-16s %20s %20s %20s %12s %12s %12s\n", "iface", "Rx", "Tx", "Total", "Rx pps", "Tx pps", "Total")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("=", 108))
		var totalRxPps, totalTxPps, totalRxBytesPerSec, totalTxBytesPerSec uint64
		for _, name := range names {
			snap := snaps[name]
			if snap == nil {
				continue
			}
			rxPps, txPps, rxBytesPerSec, txBytesPerSec := snapshotRates(snap, prevSnaps[name])
			totalRxPps += rxPps
			totalTxPps += txPps
			totalRxBytesPerSec += rxBytesPerSec
			totalTxBytesPerSec += txBytesPerSec
			fmt.Fprintf(w, "  %-16s %20s %20s %20s %12s %12s %12s\n",
				name+":",
				formatBytesRate(rxBytesPerSec),
				formatBytesRate(txBytesPerSec),
				formatBytesRate(rxBytesPerSec+txBytesPerSec),
				formatPacketRate(rxPps),
				formatPacketRate(txPps),
				formatPacketRate(rxPps+txPps))
		}
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 108))
		fmt.Fprintf(w, "  %-16s %20s %20s %20s %12s %12s %12s\n",
			"total:",
			formatBytesRate(totalRxBytesPerSec),
			formatBytesRate(totalTxBytesPerSec),
			formatBytesRate(totalRxBytesPerSec+totalTxBytesPerSec),
			formatPacketRate(totalRxPps),
			formatPacketRate(totalTxPps),
			formatPacketRate(totalRxPps+totalTxPps))
	}

	fmt.Fprintf(w, "\nKeys: q=quit  c=combined  p=packets  b=bytes  d=delta  r=rate\n")
}

func snapshotRates(curr, prev *Snapshot) (rxPps, txPps, rxBytesPerSec, txBytesPerSec uint64) {
	if curr == nil || prev == nil {
		return 0, 0, 0, 0
	}
	dt := curr.Timestamp.Sub(prev.Timestamp).Seconds()
	if dt <= 0 {
		return 0, 0, 0, 0
	}
	rxPktsDelta, txPktsDelta, rxBytesDelta, txBytesDelta, _ := snapshotTrafficDeltas(curr, prev)
	return uint64(float64(rxPktsDelta) / dt),
		uint64(float64(txPktsDelta) / dt),
		uint64(float64(rxBytesDelta) / dt),
		uint64(float64(txBytesDelta) / dt)
}

func deltaU64(curr, prev uint64) uint64 {
	if curr < prev {
		return 0
	}
	return curr - prev
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
