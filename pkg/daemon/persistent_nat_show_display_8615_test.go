package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #8615: the persistent-NAT SHOW table must be able to show a binding that
// still has LIVE flows, and must not render it as expired while doing so.
//
// #8607 filled the table from the helper's IDLE export, so a binding was
// observable only once its sessions were gone. These cells bind the display
// half: the record that carries a live-flow count, and the rendering rule that
// count exists to drive.

const showTimeout = 300 * time.Second

func displayLease(activeFlows uint32, remaining time.Duration) dpuserspace.DisplayLeaseWire {
	return dpuserspace.DisplayLeaseWire{
		Pool:           "p1",
		Protocol:       6,
		SrcIP:          "10.0.61.102",
		SrcPort:        40000,
		RoutingScope:   persistentNatLeaseScopeDaemon(0),
		TranslatedIP:   "172.16.80.7",
		TranslatedPort: 51400,
		RemainingNs:    uint64(remaining),
		TimeoutNs:      uint64(showTimeout),
		ActiveFlows:    activeFlows,
	}
}

// A binding with LIVE flows must not render as expired.
//
// THE TRAP THIS GUARDS. While flows are live the allocator does not refresh
// expires_at_ns — it is rewritten only when the LAST flow closes
// (allocator.rs:2246-2250) — so a perfectly healthy long-lived binding
// routinely reports RemainingNs == 0. Back-dating LastSeen by (timeout -
// remaining), which is correct for an IDLE lease, would place LastSeen a full
// timeout in the past and render the binding as already expired.
//
// That is a worse failure than the empty table #8607 fixed, because it looks
// like data: the operator sees the binding they asked about, with a number
// saying it is gone.
func TestALiveBindingDoesNotRenderAsExpired8615(t *testing.T) {
	now := time.Now()
	// The realistic shape: live flows, and a deadline that went stale long ago.
	bindings := persistentNatBindingsFromDisplayLeases(
		[]dpuserspace.DisplayLeaseWire{displayLease(3, 0)}, now)

	if len(bindings) != 1 {
		t.Fatalf("expected the live binding to be shown at all, got %d", len(bindings))
	}
	remaining := time.Until(bindings[0].LastSeen.Add(bindings[0].Timeout))
	if remaining <= 0 {
		t.Fatalf("a binding with 3 live flows rendered as EXPIRED (remaining %v). "+
			"While flows are live the allocator does not refresh the deadline, so "+
			"RemainingNs is routinely 0 for a healthy binding; back-dating LastSeen "+
			"by (timeout-remaining) shows it as gone. The operator sees the binding "+
			"they asked about with a number saying it no longer exists (#8615).",
			remaining)
	}
	if remaining < showTimeout-time.Second {
		t.Errorf("a binding with live flows should render the FULL timeout as its "+
			"floor — it does not begin expiring until its last flow closes — got %v, "+
			"want ~%v", remaining, showTimeout)
	}
}

// CONTROL for the cell above. An IDLE binding must still count down from its
// reported remaining, which is the #8607 behaviour this must not break.
//
// Without this control, "always render the full timeout" passes the cell above
// and silently discards the remaining-time column for every idle binding — the
// column that is the whole point of persistent-nat-table.
func TestAnIdleBindingStillCountsDownFromItsRemaining8615(t *testing.T) {
	now := time.Now()
	const remainingLeft = 30 * time.Second
	bindings := persistentNatBindingsFromDisplayLeases(
		[]dpuserspace.DisplayLeaseWire{displayLease(0, remainingLeft)}, now)

	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	remaining := time.Until(bindings[0].LastSeen.Add(bindings[0].Timeout))
	if remaining > remainingLeft+time.Second || remaining < remainingLeft-time.Second {
		t.Errorf("an IDLE binding must render the helper's own remaining lifetime, "+
			"got %v want ~%v. Rendering the full timeout here would discard the "+
			"remaining-time column for every idle binding — the column "+
			"persistent-nat-table exists to answer (#8607).", remaining, remainingLeft)
	}
}

// An error must leave the previous snapshot standing, never replace it with an
// emptiness nobody observed — the #8607 rule, restated for the display path
// because it is a second refresher and the rule is not inherited by proximity.
func TestADisplayRefreshErrorKeepsThePreviousSnapshot8615(t *testing.T) {
	table := dataplane.NewPersistentNATTable()
	table.ReplaceAll([]*dataplane.PersistentNATBinding{{
		PoolName: "p1", Timeout: showTimeout, LastSeen: time.Now(),
		Permit: config.PersistentNATPermitAnyRemoteHost,
	}})
	before := len(table.All())
	if before == 0 {
		t.Fatal("setup: the table must start non-empty or this proves nothing")
	}

	if applyPersistentNatShowRefreshDisplay(table, nil, errors.New("helper restarting"), time.Now()) {
		t.Error("a failed refresh must report that it did NOT replace the table")
	}
	if got := len(table.All()); got != before {
		t.Errorf("a failed refresh emptied the table (%d -> %d). That renders as "+
			"\"No persistent NAT bindings\" — the exact false statement #8607 "+
			"removed — for a helper that is merely restarting (#8615).", before, got)
	}
}
