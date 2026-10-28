package daemon

import (
	"log/slog"
	"sync"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/wireschema"
)

// The wire-name extraction itself is the single production extractor
// wireschema.WireNamesOf applied to dpuserspace.SessionDeltaInfo
// (#17137). It cannot live beside the struct in
// pkg/dataplane/userspace because the #1476 retirement-boundary
// canary (TestUserspaceManagerDoesNotImportReflectOrUnsafe) forbids
// `reflect` anywhere under that package (the walk is recursive);
// pkg/wireschema is outside that tree and reflect-allowed. Until #17137 a
// second copy lived here in pkg/daemon and no test compared it with
// anything, so a one-token drift would have flipped the fail-closed
// gate below to MISMATCH against every helper while every pkg/daemon
// test stayed green. The canonicalisation and hash stay next to the
// wire types; only the extraction moved, and now it is shared.

var (
	localDeltaSchemaOnce sync.Once
	localDeltaSchemaFP   uint64
)

// localSessionDeltaSchemaFingerprint is this daemon's session-delta schema
// identity. Computed once: the shape cannot change at runtime.
func localSessionDeltaSchemaFingerprint() uint64 {
	localDeltaSchemaOnce.Do(func() {
		localDeltaSchemaFP = dpuserspace.SessionDeltaSchemaFingerprintOf(wireschema.WireNamesOf(dpuserspace.SessionDeltaInfo{}))
	})
	return localDeltaSchemaFP
}

// #7194: fail-closed admission for HA session-open deltas.
//
// The problem this closes. `ConfigSnapshotProtocolVersion` gates the config
// snapshot; the session-delta schema shared the same helper/daemon pair with no
// identity of its own. Five fields (#5865) and `rt_flow_session_id` (#5212 ->
// #6312) each existed on one transport and not the other, and each shipped,
// because there was no version to bump. On the JSON leg `serde(default)`
// decodes a field the producer never sent as 0, and at the consumer a
// `policy_id` of 0 means BOTH "no policy attribution" and "the producer does
// not carry this field". Installing that zero as identity is the failure mode.
//
// Helper/daemon skew is not hypothetical here: #6722's
// ErrEgressZoneProtocolIncompatible exists precisely because a RUNNING helper
// can advertise a version that is not this binary's, and that gate's severity
// was measured on the reference cluster.
//
// WHY IT IS LOUD. "Withhold the sync" done quietly would trade a silent
// zero-fill for a silently dead HA sync — the standby would simply stop
// receiving sessions, and a failover would find nothing there. That is a worse
// failure than the one being fixed, so a refusal warns once per episode and
// increments a counter that `show` surfaces.
//
// WHY UNKNOWN IS PERMITTED. Three states, not two, mirroring
// noHelperVersionObservedLocked (#1960): a helper that advertises NOTHING
// predates the field and is already fenced by the snapshot-protocol gates.
// Refusing on absence would brick HA against an older helper on the strength of
// a reading that never happened — a brick, not a fence.

// recordUserspaceDeltaSchema stores the fingerprint advertised by the running
// helper. Called from the drain loop, which already receives ProcessStatus.
//
// A transition back to a MATCHING (or unknown) fingerprint re-arms the
// one-shot warning, so a second episode after a helper restart is reported
// again instead of being swallowed by the first episode's dampener.
func (d *Daemon) recordUserspaceDeltaSchema(advertised uint64) {
	prev := d.userspaceDeltaSchemaFP.Swap(advertised)
	if prev == advertised {
		return
	}
	if verdict, _ := dpuserspace.CompareSessionDeltaSchema(advertised, localSessionDeltaSchemaFingerprint()); verdict != dpuserspace.SessionDeltaSchemaMismatch {
		d.userspaceDeltaSchemaLogged.Store(false)
	}
}

// userspaceDeltaSchemaAdmits reports whether a batch of session deltas may be
// converted and queued for the peer. batchLen is used only for the log line.
func (d *Daemon) userspaceDeltaSchemaAdmits(batchLen int) bool {
	advertised := d.userspaceDeltaSchemaFP.Load()
	verdict, reason := dpuserspace.CompareSessionDeltaSchema(advertised, localSessionDeltaSchemaFingerprint())
	if verdict != dpuserspace.SessionDeltaSchemaMismatch {
		return true
	}
	d.userspaceDeltaSchemaWithheld.Add(1)
	// Once per episode: the drain runs at 100ms while the stream is down, so
	// an undampened warning here would bury itself.
	if d.userspaceDeltaSchemaLogged.CompareAndSwap(false, true) {
		slog.Warn("ha: withholding session-delta sync — helper delta schema mismatch",
			"reason", reason,
			"helper_fingerprint", advertised,
			"daemon_fingerprint", localSessionDeltaSchemaFingerprint(),
			"deltas_withheld_in_batch", batchLen,
			"daemon_schema", dpuserspace.SessionDeltaSchemaCanonicalOf(wireschema.WireNamesOf(dpuserspace.SessionDeltaInfo{})))
	}
	return false
}

// UserspaceDeltaSchemaWithheldCount is the observable for the gate: how many
// delta batches have been refused. Non-zero means HA session sync is being
// withheld and a failover would find an incomplete session table on the peer.
func (d *Daemon) UserspaceDeltaSchemaWithheldCount() uint64 {
	return d.userspaceDeltaSchemaWithheld.Load()
}
