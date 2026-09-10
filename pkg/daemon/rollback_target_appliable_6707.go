package daemon

import (
	"errors"
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// errRollbackTargetUnappliable is the #6707 sentinel: `commit confirmed` was
// asked to arm a rollback timer whose TARGET the dataplane is guaranteed to
// refuse.
var errRollbackTargetUnappliable = errors.New("commit confirmed rollback target cannot be applied")

// rollbackTargetAppliablePreflight refuses to ARM a `commit confirmed` whose
// rollback target — the currently-active config, restored when the confirm
// timer expires — is one the dataplane is guaranteed to refuse as a WHOLE
// policy snapshot, and therefore cannot become the running dataplane snapshot.
//
// WHY THIS IS A PRE-FLIGHT AND NOT A ROLLBACK-TIME ABORT. The rollback path
// applies its target UNCONDITIONALLY and deliberately: by then
// PromoteRollback has already reverted the STORE, so aborting the dataplane
// apply would leave the store and the dataplane disagreeing — a split-brain
// strictly worse than applying the target (#1956 OQ-15.2,
// daemon_apply_commit.go). That reasoning holds, which is exactly why the
// decision has to be made BEFORE the store is committed to. The existing
// device-map, cluster-topology and cluster-identity gates already validate the
// rollback target for the same reason; this extends "KNOWN-safe" from
// "will not strand management on next boot" to "can actually be applied".
//
// WHAT MAKES THE PREDICTION SOUND. The predicate is
// dpuserspace.PolicyContentRejectionReasons, the Go single source of truth for
// "the helper refuses this whole snapshot" — the same function `show security
// match-policies` gates on. #6707 first keyed on config.LenientDroppedPolicyLocator
// alone, the #5575 poison. The mirror reproduces that arm AND every refusal
// class added since: the #3261 sentinels (undefined or unrepresentable
// addresses and applications, including #9524's mixed address forms and
// #9525's changed application matches), #9410's unresolvable zones, #9570's
// zone-pair `junos-global`, and #9584's duplicate rule identity. A gate that
// kept its own list would miss the next class; consulting the mirror means a
// class added there reaches this gate with no edit here (#9588). It stays a
// local, Go-side prediction: no round trip, and no dependence on helper
// liveness at arm time.
//
// feedOverlay must be the daemon's LIVE dynamic-address overlay for the target
// (feedSnapshotsForConfig). Address representability is feed-aware: with a nil
// overlay a declared dynamic-address binding reads as unrepresentable, so this
// gate would refuse a healthy feed-backed config.
//
// Almost everything it fires on is content a strict commit already rejects
// outright, so such a target can only have arrived by a route that does not
// strict-compile: a lenient boot load of a persisted config, a peer-sync
// SyncApply, or an upgrade whose new gates now refuse an old config. That is
// precisely the #6707 sequence — boot from such an active config A, correct it
// in candidate B, and `commit confirmed` B — where the safety net silently
// could not fire.
//
// The one strict-valid refusal is a dynamic-address binding with a feed that
// has no installed snapshot yet. SnapshotForBindings omits such a binding, and
// the mirror fails it closed (#5645), exactly as the helper would refuse that
// snapshot at this moment. The gate agrees with the mirror rather than
// predicting that the feed will be ready when the timer fires, so `commit
// confirmed` waits for the feed; a plain `commit` is unaffected.
//
// The refusal is deliberately narrow. A plain `commit` of B is unaffected and
// remains the way forward: it makes B permanent, which is what an operator
// correcting a broken active config wants. Only the CONFIRMED variant is
// refused, and only because its promise — "this reverts cleanly if I lose
// contact" — would be false.
func rollbackTargetAppliablePreflight(rollbackTarget *config.Config, feedOverlay map[string][]string) error {
	// A nil target is the first-commit case: there is nothing to roll back to,
	// which the timeout path already handles by reverting to bootstrap mode
	// (daemon_apply_commit.go's nil-prevCfg branch). Not this gate's business.
	if rollbackTarget == nil {
		return nil
	}
	reasons := dpuserspace.PolicyContentRejectionReasons(rollbackTarget, feedOverlay)
	if len(reasons) == 0 {
		return nil
	}
	more := ""
	if len(reasons) > 1 {
		more = fmt.Sprintf(" (and %d more)", len(reasons)-1)
	}
	return fmt.Errorf(
		"%w: the active configuration (which `commit confirmed` would restore when the "+
			"timer expires) is one the dataplane refuses as a WHOLE policy snapshot — %s%s — "+
			"so the rollback would revert the configuration store without reverting "+
			"forwarding, leaving the store and the dataplane disagreeing. Use a plain "+
			"`commit` to make this change permanent, or repair the active configuration "+
			"first (a strict `commit` reports the exact leaf)",
		errRollbackTargetUnappliable, reasons[0], more)
}
