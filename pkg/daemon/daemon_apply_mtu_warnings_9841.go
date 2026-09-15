package daemon

import (
	"context"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #9841 — surfacing unconverged interface MTUs as commit warnings.
//
// The dataplane records MTUs it could not read or write into
// ApplyResult.UnconvergedMTUs; this file projects the commit's own records
// onto its commit warnings. The mechanism is deliberately narrow:
//
// ONLY operator-commit applies project, via applyConfigLockedForCommit,
// called from exactly one site: applyAndSyncCommitted (which both
// commitAndApply and commitConfirmedAndApply funnel through — pinned by
// TestApplyAndSyncCommittedSyncsMTUWarnings9841). Peer-sync, rollback,
// feed, debt and boot applies never project: no response exists to carry
// the lines, and no future reader exists to consume them.
//
// WHY A RESPONSE-ONLY COPY. The commit's compiled config is ALREADY
// published when the apply returns: the userspace snapshot builder
// retains the applied pointer (builder.go Config: cfg), the last-apply
// publication is out while transmission may still be deferred
// (manager_compile.go deferred-publish path), and the status loop keeps
// reading the retained snapshot under the userspace mutex
// (process_status.go syncSnapshotLocked) while the control path marshals
// under that same mutex — neither of which the committing goroutine
// holds. Mutating cfg.Warnings post-apply therefore races those readers,
// however narrow the writer set is: restricting writers to the commit's
// own apply kills the ownership bug (no foreign apply replaces the lines)
// but NOT the race (the mutation targets an already-published object).
//
// So the wrapper never mutates: it returns the object the response
// projects — the applied pointer itself when there is nothing to warn
// about, else a shallow copy carrying the synced lines
// (dataplane.WithMTUWarningsForResponse9841). The copy shares every
// sub-object (read-only post-commit) and owns its Warnings storage; the
// applied original is never written, so snapshot readers race with
// nothing. Every commit surface projects the returned object, never
// store-active. Pinned by TestMTUWarningsAliasedSerializationRace9841:
// serializers read the applied object while the wrapper projects, and
// -race trips iff the wrapper writes through the alias.
//
// The projection fires iff the apply SUCCEEDED and the last-apply
// generation ADVANCED past its entry snapshot. The generation guard is
// what makes a skipped/NoDataplane apply project nothing: warning then
// would cite a stale apply's records. Generations strictly increase per
// recorded apply on each backend (pinned on the real publishers by
// TestRecordApplyResultAdvancesGeneration9841 and
// TestBumpGenerationMonotonic9841); both captures read the same probe, and
// a backend swap mid-commit coincides with teardown, whose #2926 abort
// fails the apply and skips the projection anyway.
//
// READER AUDIT (every production `.Warnings` touch outside pkg/config,
// verified 2026-09-14): gRPC configWarnings and REST configCommitResponse
// (commit responses — the intended consumers, both reading the returned
// object), the four local-CLI printConfigWarnings call sites (commit
// paths, same shape via the CLI's own response copy), the pre-apply log
// loop (same goroutine, before the apply — validation lines only), and
// wire copies downstream. Digests hash TEXT (configTextDigest over the
// tree, never the compiled object), HA-sync compares text+generation,
// export renders text, alarms recompute ValidateConfig — warnings
// participate in none, so the projection cannot perturb identity, diff,
// or resync (pinned by TestCommittedDigestStableAcrossMTUSync9841).
//
// Failed applies project nothing: the commit reports the error, and the
// MTU lines recur on the next attempt while the host stays unconverged.
func (d *Daemon) applyConfigLockedForCommit(ctx context.Context, cfg *config.Config) (*config.Config, error) {
	before, beforeOK := dataplane.LastApplyGenerationOf(d.dataplane())
	if err := d.applyConfigLocked(ctx, cfg); err != nil {
		return nil, err
	}
	after := dataplane.LastApplyResultOf(d.dataplane())
	if after == nil {
		return cfg, nil
	}
	if beforeOK && after.Generation == before {
		return cfg, nil
	}
	return dataplane.WithMTUWarningsForResponse9841(cfg, after.UnconvergedMTUs), nil
}
