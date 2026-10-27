package cluster

import "fmt"

// renderMode selects the operator-surface posture of a sync-stats field
// (#17107). Exported for the completeness test's allowlist audit.
type RenderMode int

const (
	// RenderAlways renders on every statistics surface, even at zero.
	RenderAlways RenderMode = iota
	// RenderNonzero renders only when the value is nonzero (true for bools).
	RenderNonzero
	// RenderNever is the explicit decision to keep a field out of the
	// statistics render; it MUST carry a reason in syncStatNotRendered.
	RenderNever
)

// syncStatField is one descriptor for a SyncStatsSnapshot field (#17107).
// One ordered slice (syncStatFields) drives both Stats() and the status.go
// statistics render, so adding an atomic without a rendering decision
// fails TestSyncStatsSnapshotComplete instead of silently dropping.
type syncStatField struct {
	name  string // snapshot field name (== SyncStats field name for counters)
	get   func(*SessionSync, *SyncStatsSnapshot) uint64
	label string // operator label on the statistics surface; "" iff RenderNever
	mode  RenderMode
}

// u64 adapts a snapshot uint64 field to the descriptor getter shape.
func u64(get func(*SyncStatsSnapshot) uint64) func(*SessionSync, *SyncStatsSnapshot) uint64 {
	return func(_ *SessionSync, snap *SyncStatsSnapshot) uint64 { return get(snap) }
}

// syncStatFields is the single ordered descriptor slice for every
// SyncStatsSnapshot field (#17107). Stats() loads each counter through
// the descriptors keyed by name; status.go renders through this order.
// Descriptor order is statistics-render order: always-rendered service
// rows first, then conditional diagnostic counters, then the not-rendered
// tail (whose order only matters to Stats()).
var syncStatFields = []syncStatField{
	{name: "SessionsSent", label: "Sessions sent", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.SessionsSent })},
	{name: "SweepSessionsSent", label: "Sessions sent (mirror sweep)", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.SweepSessionsSent })},
	{name: "SessionsReceived", label: "Sessions received", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.SessionsReceived })},
	{name: "SessionsInstalled", label: "Sessions installed", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.SessionsInstalled })},
	{name: "DeletesSent", label: "Deletes sent", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DeletesSent })},
	{name: "DeletesReceived", label: "Deletes received", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DeletesReceived })},
	{name: "BulkSyncs", label: "Bulk syncs", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.BulkSyncs })},
	{name: "ConfigsSent", label: "Configs sent", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigsSent })},
	{name: "ConfigsReceived", label: "Configs received", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigsReceived })},
	{name: "ConfigsSentCleartext", label: "Configs sent cleartext", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigsSentCleartext })},
	{name: "ConfigsReceivedCleartext", label: "Configs received cleartext", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigsReceivedCleartext })},
	{name: "CleartextSyncAlarmLatched", label: "Cleartext sync alarm latched", mode: RenderNonzero, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 {
		if s.CleartextSyncAlarmLatched {
			return 1
		}
		return 0
	}},
	{name: "ConfigsStaleIgnored", label: "Configs stale-dropped", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigsStaleIgnored })},
	{name: "BulkPrimesWithoutIncarnation", label: "Primes without incarnation", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.BulkPrimesWithoutIncarnation })},
	{name: "ConfigsDeadIncarnationDropped", label: "Configs dead-incarnation-dropped", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigsDeadIncarnationDropped })},
	{name: "BulkEndsDeadIncarnationDropped", label: "Bulk ends dead-incarnation-dropped", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.BulkEndsDeadIncarnationDropped })},
	{name: "ClockSyncsRefused", label: "Clock syncs refused", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ClockSyncsRefused })},
	{name: "RebaseSaturations", label: "Rebase saturations", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.RebaseSaturations })},
	{name: "BulkEndsForeignConnDropped", label: "Bulk ends foreign-connection-dropped", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.BulkEndsForeignConnDropped })},
	{name: "BulkEndsEpochOnlyMatched", label: "Bulk ends matched on epoch alone", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.BulkEndsEpochOnlyMatched })},
	{name: "BulkRecvCapped", label: "Bulk receive keys capped", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.BulkRecvCapped })},
	{name: "BulkRecvAborted", label: "Bulk receive windows aborted", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.BulkRecvAborted })},
	{name: "ConfigsApplyFailed", label: "Configs apply-failed", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigsApplyFailed })},
	{name: "ImportsRefusedByHelper", label: "Imports refused by helper", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ImportsRefusedByHelper })},
	{name: "ImportsRejectedByHelper", label: "Imports rejected by helper", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ImportsRejectedByHelper })},
	{name: "ConfigsQueueFullDropped", label: "Configs queue-full-dropped", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigsQueueFullDropped })},
	{name: "ConfigApplyNacksReceived", label: "Config apply-nacks received", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.ConfigApplyNacksReceived })},
	{name: "IPsecSASent", label: "IPsec SAs sent", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.IPsecSASent })},
	{name: "IPsecSAReceived", label: "IPsec SAs received", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.IPsecSAReceived })},
	{name: "IPsecSAStaleIgnored", label: "IPsec SAs stale-ignored", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.IPsecSAStaleIgnored })},
	{name: "IPsecSAMalformedIgnored", label: "IPsec SAs malformed-ignored", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.IPsecSAMalformedIgnored })},
	{name: "IPsecSAOversizeAlarmLatched", label: "IPsec SA oversize alarm latched", mode: RenderNonzero, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 {
		if s.IPsecSAOversizeAlarmLatched {
			return 1
		}
		return 0
	}},
	{name: "IPsecSAOverCapSets", label: "IPsec SA over-cap sets", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.IPsecSAOverCapSets })},
	{name: "DHCPLeasesSent", label: "DHCP leases sent", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DHCPLeasesSent })},
	{name: "DHCPLeasesReceived", label: "DHCP leases received", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DHCPLeasesReceived })},
	{name: "DHCPLeasesStaleIgnored", label: "DHCP leases stale-ignored", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DHCPLeasesStaleIgnored })},
	{name: "DHCPLeasesSeeded", label: "DHCP leases seeded", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DHCPLeasesSeeded })},
	{name: "DHCPLeasesDroppedNoIdentity", label: "DHCP leases dropped (no identity)", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DHCPLeasesDroppedNoIdentity })},
	{name: "FencesSent", label: "Fences sent", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.FencesSent })},
	{name: "FencesReceived", label: "Fences received", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.FencesReceived })},
	{name: "FenceAcksSent", label: "Fence acks sent", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.FenceAcksSent })},
	{name: "FenceAcksReceived", label: "Fence acks received", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.FenceAcksReceived })},
	{name: "FenceAcksTimedOut", label: "Fence acks timed out", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.FenceAcksTimedOut })},
	{name: "Errors", label: "Errors", mode: RenderAlways, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.Errors })},
	{name: "DeletesDropped", label: "Deletes dropped", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DeletesDropped })},
	{name: "PreKeyAuthEvictions", label: "Pre-key authentication evictions", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.PreKeyAuthEvictions })},
	{name: "DeletesSuppressedPeerIncapable", label: "Deletes suppressed for incapable peer", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DeletesSuppressedPeerIncapable })},
	{name: "DeletesSuppressedPurgeRetirement", label: "Purge-retirement deletes suppressed", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DeletesSuppressedPurgeRetirement })},
	{name: "DeletesSuppressedScopedPolicy", label: "Scoped-policy deletes suppressed", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DeletesSuppressedScopedPolicy })},
	{name: "InstallsSuppressedNoPeerInstallTable", label: "Installs suppressed (peer lacks install-table support)", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.InstallsSuppressedNoPeerInstallTable })},
	{name: "DeletesStaleIgnored", label: "Deletes stale-ignored", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.DeletesStaleIgnored })},
	{name: "InstallsStaleIgnored", label: "Installs stale-ignored", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.InstallsStaleIgnored })},
	{name: "SessionsStaleConfigIgnored", label: "Sessions stale-config-ignored", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.SessionsStaleConfigIgnored })},
	{name: "GenMapOverflow", label: "Generation-guard map overflows", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.GenMapOverflow })},
	{name: "GenTombstonesEvicted", label: "Generation-guard tombstones evicted", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.GenTombstonesEvicted })},
	{name: "GenCapGrown", label: "Generation-guard cap growths", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.GenCapGrown })},
	{name: "GenCapShrunk", label: "Generation-guard cap shrinks", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.GenCapShrunk })},
	{name: "AuthUpgradeIdentityErrors", label: "Auth upgrade identity errors", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.AuthUpgradeIdentityErrors })},
	{name: "PreAuthRejected", label: "Pre-auth rejected", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.PreAuthRejected })},
	{name: "PreAuthHandshakeFailed", label: "Pre-auth handshake failed", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.PreAuthHandshakeFailed })},
	{name: "OversizeFramesRefused", label: "Oversize frames refused (per-type cap)", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.OversizeFramesRefused })},
	{name: "MalformedRecordsDropped", label: "Malformed records dropped", mode: RenderNonzero, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.MalformedRecordsDropped })},

	// Derived / non-counter snapshot fields: in the snapshot because the
	// Manager only holds the SyncStatsProvider interface, but not counters
	// and not rows of the statistics counter table.
	{name: "PeerBootIncarnation", mode: RenderNever, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 { return 0 }},
	{name: "GenGuardSessionCap", mode: RenderNever, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.GenGuardSessionCap })},
	{name: "Connected", mode: RenderNever, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 {
		if s.Connected {
			return 1
		}
		return 0
	}},
	{name: "ActiveFabric", mode: RenderNever, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 {
		if s.ActiveFabric < 0 {
			return 0
		}
		return uint64(s.ActiveFabric)
	}},
	{name: "BulkSyncStartTime", mode: RenderNever, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 { return uint64(s.BulkSyncStartTime) }},
	{name: "BulkSyncEndTime", mode: RenderNever, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 { return uint64(s.BulkSyncEndTime) }},
	{name: "BulkSyncSessions", mode: RenderNever, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.BulkSyncSessions })},
	{name: "LastConfigSyncTime", mode: RenderNever, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 { return uint64(s.LastConfigSyncTime) }},
	{name: "LastConfigSyncSize", mode: RenderNever, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.LastConfigSyncSize })},
	{name: "LastFenceSeq", mode: RenderNever, get: u64(func(s *SyncStatsSnapshot) uint64 { return s.LastFenceSeq })},
	{name: "LastFenceAckAt", mode: RenderNever, get: func(_ *SessionSync, s *SyncStatsSnapshot) uint64 { return uint64(s.LastFenceAckAt) }},
}

// syncStatNotRendered is the explicit not-rendered allowlist (#17107
// acceptance): every RenderNever snapshot field appears here with the
// reason it stays off `show chassis cluster statistics`. Adding a field
// here — or to syncStatFields as RenderNever without an entry — fails
// TestSyncStatsSnapshotComplete.
var syncStatNotRendered = map[string]string{
	"PeerBootIncarnation": "rendered always as its own line in FormatInformation (status.go), not a counter row",
	"GenGuardSessionCap":  "wired helper capacity input to guard sizing, not an event counter; consumed via Stats() by guard-capacity readers",
	"Connected":           "rendered as sync Status Up/Down in FormatInformation/FormatDataPlaneInterfaces, not a counter row",
	"ActiveFabric":        "fabric identity (0/1/-1) exposed via Stats()/ActiveFabric(), not a counter row",
	"BulkSyncStartTime":   "timestamp rendered in the Cold synchronization block of FormatInformation",
	"BulkSyncEndTime":     "timestamp rendered in the Cold synchronization block of FormatInformation",
	"BulkSyncSessions":    "rendered beside the bulk timestamps in the Cold synchronization block of FormatInformation",
	"LastConfigSyncTime":  "timestamp rendered in the Configuration synchronization block of FormatInformation",
	"LastConfigSyncSize":  "rendered beside LastConfigSyncTime in FormatInformation",
	"LastFenceSeq":        "rendered in the Install fence block of FormatInformation and the statistics fence-seq row",
	"LastFenceAckAt":      "timestamp rendered in the Install fence block of FormatInformation",
}

// loadSyncStat loads one SyncStats counter by snapshot field name. It is
// the Stats() half of the descriptor: the field set Stats() can populate
// is exactly the descriptor set, so a counter absent from the descriptors
// cannot reach the snapshot. Types it does not handle (the derived
// string/bool/int/int64 snapshot fields) are populated explicitly in
// Stats() after the counter loop.
func loadSyncStat(s *SessionSync, name string) uint64 {
	switch name {
	case "SessionsSent":
		return s.stats.SessionsSent.Load()
	case "SweepSessionsSent":
		return s.stats.SweepSessionsSent.Load()
	case "SessionsReceived":
		return s.stats.SessionsReceived.Load()
	case "SessionsInstalled":
		return s.stats.SessionsInstalled.Load()
	case "DeletesSent":
		return s.stats.DeletesSent.Load()
	case "DeletesReceived":
		return s.stats.DeletesReceived.Load()
	case "BulkSyncs":
		return s.stats.BulkSyncs.Load()
	case "ConfigsSent":
		return s.stats.ConfigsSent.Load()
	case "ConfigsReceived":
		return s.stats.ConfigsReceived.Load()
	case "ConfigsSentCleartext":
		return s.stats.ConfigsSentCleartext.Load()
	case "ConfigsReceivedCleartext":
		return s.stats.ConfigsReceivedCleartext.Load()
	case "ConfigsStaleIgnored":
		return s.stats.ConfigsStaleIgnored.Load()
	case "BulkPrimesWithoutIncarnation":
		return s.stats.BulkPrimesWithoutIncarnation.Load()
	case "ConfigsDeadIncarnationDropped":
		return s.stats.ConfigsDeadIncarnationDropped.Load()
	case "BulkEndsDeadIncarnationDropped":
		return s.stats.BulkEndsDeadIncarnationDropped.Load()
	case "ClockSyncsRefused":
		return s.stats.ClockSyncsRefused.Load()
	case "RebaseSaturations":
		return s.stats.RebaseSaturations.Load()
	case "BulkEndsForeignConnDropped":
		return s.stats.BulkEndsForeignConnDropped.Load()
	case "BulkEndsEpochOnlyMatched":
		return s.stats.BulkEndsEpochOnlyMatched.Load()
	case "BulkRecvCapped":
		return s.stats.BulkRecvCapped.Load()
	case "BulkRecvAborted":
		return s.stats.BulkRecvAborted.Load()
	case "ConfigsApplyFailed":
		return s.stats.ConfigsApplyFailed.Load()
	case "ImportsRefusedByHelper":
		return s.stats.ImportsRefusedByHelper.Load()
	case "ImportsRejectedByHelper":
		return s.stats.ImportsRejectedByHelper.Load()
	case "ConfigsQueueFullDropped":
		return s.stats.ConfigsQueueFullDropped.Load()
	case "ConfigApplyNacksReceived":
		return s.stats.ConfigApplyNacksReceived.Load()
	case "IPsecSASent":
		return s.stats.IPsecSASent.Load()
	case "IPsecSAReceived":
		return s.stats.IPsecSAReceived.Load()
	case "IPsecSAStaleIgnored":
		return s.stats.IPsecSAStaleIgnored.Load()
	case "IPsecSAMalformedIgnored":
		return s.stats.IPsecSAMalformedIgnored.Load()
	case "IPsecSAOverCapSets":
		return s.stats.IPsecSAOverCapSets.Load()
	case "DHCPLeasesSent":
		return s.stats.DHCPLeasesSent.Load()
	case "DHCPLeasesReceived":
		return s.stats.DHCPLeasesReceived.Load()
	case "DHCPLeasesStaleIgnored":
		return s.stats.DHCPLeasesStaleIgnored.Load()
	case "DHCPLeasesSeeded":
		return s.stats.DHCPLeasesSeeded.Load()
	case "DHCPLeasesDroppedNoIdentity":
		return s.stats.DHCPLeasesDroppedNoIdentity.Load()
	case "GenGuardSessionCap":
		return s.genState.genGuardSessionCap.Load()
	case "FencesSent":
		return s.stats.FencesSent.Load()
	case "FencesReceived":
		return s.stats.FencesReceived.Load()
	case "FenceAcksSent":
		return s.stats.FenceAcksSent.Load()
	case "FenceAcksReceived":
		return s.stats.FenceAcksReceived.Load()
	case "FenceAcksTimedOut":
		return s.stats.FenceAcksTimedOut.Load()
	case "Errors":
		return s.stats.Errors.Load()
	case "DeletesDropped":
		return s.stats.DeletesDropped.Load()
	case "PreKeyAuthEvictions":
		return s.stats.PreKeyAuthEvictions.Load()
	case "DeletesSuppressedPeerIncapable":
		return s.stats.DeletesSuppressedPeerIncapable.Load()
	case "DeletesSuppressedPurgeRetirement":
		return s.stats.DeletesSuppressedPurgeRetirement.Load()
	case "DeletesSuppressedScopedPolicy":
		return s.stats.DeletesSuppressedScopedPolicy.Load()
	case "InstallsSuppressedNoPeerInstallTable":
		return s.stats.InstallsSuppressedNoPeerInstallTable.Load()
	case "DeletesStaleIgnored":
		return s.stats.DeletesStaleIgnored.Load()
	case "InstallsStaleIgnored":
		return s.stats.InstallsStaleIgnored.Load()
	case "SessionsStaleConfigIgnored":
		return s.stats.SessionsStaleConfigIgnored.Load()
	case "GenMapOverflow":
		return s.stats.GenMapOverflow.Load()
	case "GenTombstonesEvicted":
		return s.stats.GenTombstonesEvicted.Load()
	case "GenCapGrown":
		return s.stats.GenCapGrown.Load()
	case "GenCapShrunk":
		return s.stats.GenCapShrunk.Load()
	case "AuthUpgradeIdentityErrors":
		return s.stats.AuthUpgradeIdentityErrors.Load()
	case "PreAuthRejected":
		return s.stats.PreAuthRejected.Load()
	case "PreAuthHandshakeFailed":
		return s.stats.PreAuthHandshakeFailed.Load()
	case "OversizeFramesRefused":
		return s.stats.OversizeFramesRefused.Load()
	case "MalformedRecordsDropped":
		return s.stats.MalformedRecordsDropped.Load()
	case "BulkSyncSessions":
		return s.stats.BulkSyncSessions.Load()
	case "LastConfigSyncSize":
		return s.stats.LastConfigSyncSize.Load()
	case "LastFenceSeq":
		return s.stats.LastFenceSeq.Load()
	}
	return 0
}

// boolSyncStat loads one SyncStats bool by snapshot field name.
func boolSyncStat(s *SessionSync, name string) bool {
	switch name {
	case "CleartextSyncAlarmLatched":
		return s.stats.CleartextSyncAlarmLatched.Load()
	case "IPsecSAOversizeAlarmLatched":
		return s.stats.IPsecSAOversizeAlarmLatched.Load()
	case "Connected":
		return s.stats.Connected.Load()
	}
	return false
}

// int64SyncStat loads one SyncStats int64 by snapshot field name.
func int64SyncStat(s *SessionSync, name string) int64 {
	switch name {
	case "BulkSyncStartTime":
		return s.stats.BulkSyncStartTime.Load()
	case "BulkSyncEndTime":
		return s.stats.BulkSyncEndTime.Load()
	case "LastConfigSyncTime":
		return s.stats.LastConfigSyncTime.Load()
	case "LastFenceAckAt":
		return s.stats.LastFenceAckAt.Load()
	}
	return 0
}

// setSyncStatUint assigns one uint64 snapshot field by descriptor name.
// It is the write half of Stats()'s descriptor loop: only fields with a
// descriptor can be assigned, so the snapshot cannot gain a hand-mirrored
// field the render never decided on.
func setSyncStatUint(snap *SyncStatsSnapshot, name string, v uint64) {
	switch name {
	case "SessionsSent":
		snap.SessionsSent = v
	case "SweepSessionsSent":
		snap.SweepSessionsSent = v
	case "SessionsReceived":
		snap.SessionsReceived = v
	case "MalformedRecordsDropped":
		snap.MalformedRecordsDropped = v
	case "SessionsInstalled":
		snap.SessionsInstalled = v
	case "DeletesSent":
		snap.DeletesSent = v
	case "DeletesReceived":
		snap.DeletesReceived = v
	case "BulkSyncs":
		snap.BulkSyncs = v
	case "ConfigsSent":
		snap.ConfigsSent = v
	case "ConfigsReceived":
		snap.ConfigsReceived = v
	case "ConfigsSentCleartext":
		snap.ConfigsSentCleartext = v
	case "ConfigsReceivedCleartext":
		snap.ConfigsReceivedCleartext = v
	case "ConfigsStaleIgnored":
		snap.ConfigsStaleIgnored = v
	case "BulkPrimesWithoutIncarnation":
		snap.BulkPrimesWithoutIncarnation = v
	case "ConfigsDeadIncarnationDropped":
		snap.ConfigsDeadIncarnationDropped = v
	case "BulkEndsDeadIncarnationDropped":
		snap.BulkEndsDeadIncarnationDropped = v
	case "ClockSyncsRefused":
		snap.ClockSyncsRefused = v
	case "RebaseSaturations":
		snap.RebaseSaturations = v
	case "BulkEndsForeignConnDropped":
		snap.BulkEndsForeignConnDropped = v
	case "BulkEndsEpochOnlyMatched":
		snap.BulkEndsEpochOnlyMatched = v
	case "BulkRecvCapped":
		snap.BulkRecvCapped = v
	case "BulkRecvAborted":
		snap.BulkRecvAborted = v
	case "ConfigsApplyFailed":
		snap.ConfigsApplyFailed = v
	case "ImportsRefusedByHelper":
		snap.ImportsRefusedByHelper = v
	case "ImportsRejectedByHelper":
		snap.ImportsRejectedByHelper = v
	case "ConfigsQueueFullDropped":
		snap.ConfigsQueueFullDropped = v
	case "ConfigApplyNacksReceived":
		snap.ConfigApplyNacksReceived = v
	case "IPsecSASent":
		snap.IPsecSASent = v
	case "IPsecSAReceived":
		snap.IPsecSAReceived = v
	case "IPsecSAStaleIgnored":
		snap.IPsecSAStaleIgnored = v
	case "IPsecSAMalformedIgnored":
		snap.IPsecSAMalformedIgnored = v
	case "IPsecSAOverCapSets":
		snap.IPsecSAOverCapSets = v
	case "DHCPLeasesSent":
		snap.DHCPLeasesSent = v
	case "DHCPLeasesReceived":
		snap.DHCPLeasesReceived = v
	case "DHCPLeasesStaleIgnored":
		snap.DHCPLeasesStaleIgnored = v
	case "DHCPLeasesSeeded":
		snap.DHCPLeasesSeeded = v
	case "DHCPLeasesDroppedNoIdentity":
		snap.DHCPLeasesDroppedNoIdentity = v
	case "GenGuardSessionCap":
		snap.GenGuardSessionCap = v
	case "FencesSent":
		snap.FencesSent = v
	case "FencesReceived":
		snap.FencesReceived = v
	case "FenceAcksSent":
		snap.FenceAcksSent = v
	case "FenceAcksReceived":
		snap.FenceAcksReceived = v
	case "FenceAcksTimedOut":
		snap.FenceAcksTimedOut = v
	case "Errors":
		snap.Errors = v
	case "DeletesDropped":
		snap.DeletesDropped = v
	case "PreKeyAuthEvictions":
		snap.PreKeyAuthEvictions = v
	case "DeletesSuppressedPeerIncapable":
		snap.DeletesSuppressedPeerIncapable = v
	case "DeletesSuppressedPurgeRetirement":
		snap.DeletesSuppressedPurgeRetirement = v
	case "DeletesSuppressedScopedPolicy":
		snap.DeletesSuppressedScopedPolicy = v
	case "InstallsSuppressedNoPeerInstallTable":
		snap.InstallsSuppressedNoPeerInstallTable = v
	case "DeletesStaleIgnored":
		snap.DeletesStaleIgnored = v
	case "InstallsStaleIgnored":
		snap.InstallsStaleIgnored = v
	case "SessionsStaleConfigIgnored":
		snap.SessionsStaleConfigIgnored = v
	case "GenMapOverflow":
		snap.GenMapOverflow = v
	case "GenTombstonesEvicted":
		snap.GenTombstonesEvicted = v
	case "GenCapGrown":
		snap.GenCapGrown = v
	case "GenCapShrunk":
		snap.GenCapShrunk = v
	case "AuthUpgradeIdentityErrors":
		snap.AuthUpgradeIdentityErrors = v
	case "PreAuthRejected":
		snap.PreAuthRejected = v
	case "PreAuthHandshakeFailed":
		snap.PreAuthHandshakeFailed = v
	case "OversizeFramesRefused":
		snap.OversizeFramesRefused = v
	case "BulkSyncSessions":
		snap.BulkSyncSessions = v
	case "LastConfigSyncSize":
		snap.LastConfigSyncSize = v
	case "LastFenceSeq":
		snap.LastFenceSeq = v
	}
}

// fabricStr17107 renders an ActiveFabric snapshot value as the fabric
// string the deleted FormatStats used ("none"/"fab0"/"fab1"); kept so the
// #13544 preferred-incarnation test asserts the same operator string
// without the deleted fourth renderer (#17107).
func fabricStr17107(activeFabric int) string {
	if activeFabric < 0 {
		return "none"
	}
	return fmt.Sprintf("fab%d", activeFabric)
}
