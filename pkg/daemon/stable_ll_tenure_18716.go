package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// #18716 fold 3: one owner for the stable RETH router link-local.
//
// The stable link-local is the shared IPv6 default-router identity, and in
// legacy VRRP mode it is also the VRRP IPv6 advert source (it sorts below the
// per-node link-locals) and therefore the master source the peer learned. A
// forced resign's priority-0 burst must go out from it, so it may leave this
// node only after that burst. Before fold 3 three paths could remove it during
// the burst: the cluster handler's barrier wrapper (correctly after it), and,
// independently, the VRRP BACKUP arm and the reconcile tick, because the
// BACKUP event is published before the burst. A delayed remover could also
// delete the address a NEWER MASTER tenure had just added.
//
// stableLLTenure fixes both:
//   - Every add and every remove of the address runs under mu.
//   - Every add bumps the RG's tenure, so a removal that captured the tenure
//     at resign start sees a re-promotion, and the check and the delete
//     happen under the lock the add takes: no promotion can land between
//     them.
//   - A forced resign registers itself as pending for its RG. While any
//     resign is pending, removeStableRethLinkLocal (the BACKUP arm, the
//     reconcile tick) defers: the pending resign removes the address once
//     its burst barrier settles.
type stableLLTenure struct {
	mu      sync.Mutex
	gen     map[int]uint64              // per RG; bumped by every add
	pending map[int]map[uint64]struct{} // per RG; forced resigns awaiting their burst
	nextID  uint64
}

// errStableLLSuperseded: the RG was re-activated after the resign began. The
// stable link-local now belongs to the new tenure and was kept.
var errStableLLSuperseded = errors.New("the RG was re-activated since the resign began; the stable router link-local belongs to the new tenure and was kept")

// errStableLLHandedOn: another forced resign of the same RG is still waiting
// for its burst; it removes the stable link-local after that burst.
var errStableLLHandedOn = errors.New("a later resign of the RG still owns the stable router link-local's removal")

// bumpLocked records a new tenure for rgID. Caller holds mu.
func (t *stableLLTenure) bumpLocked(rgID int) {
	if t.gen == nil {
		t.gen = make(map[int]uint64)
	}
	t.gen[rgID]++
}

// beginResign registers a pending forced resign for rgID and returns the
// tenure it captured and its id.
func (t *stableLLTenure) beginResign(rgID int) (tenure, id uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pending == nil {
		t.pending = make(map[int]map[uint64]struct{})
	}
	if t.pending[rgID] == nil {
		t.pending[rgID] = make(map[uint64]struct{})
	}
	t.nextID++
	t.pending[rgID][t.nextID] = struct{}{}
	return t.gen[rgID], t.nextID
}

// pendingLocked reports whether a forced resign of rgID still owns the
// removal. Caller holds mu.
func (t *stableLLTenure) pendingLocked(rgID int) bool {
	return len(t.pending[rgID]) > 0
}

// resignRethRGReleasingLL starts rgID's forced RETH VRRP resign and gives the
// stable link-local's removal to that resign's burst barrier. It returns the
// VRRP barrier itself (inner) and one that settles only after the link-local
// was removed and confirmed absent (withLL). Every daemon-initiated forced
// resign goes through here, so the BACKUP arm and the reconcile tick never
// remove the address while a burst is pending.
func (d *Daemon) resignRethRGReleasingLL(rgID int, resign func(int) vipReleaseBarrier) (inner, withLL vipReleaseBarrier) {
	tenure, id := d.stableLL.beginResign(rgID)
	inner = resign(rgID)
	if inner == nil {
		// No VRRP instance to resign, so no burst: release at once.
		if err := d.releaseStableLL(rgID, tenure, id); err != nil {
			slog.Info("cluster: stable router link-local kept after a resign with no RETH VRRP instance",
				"rg", rgID, "reason", err)
		}
		return nil, nil
	}
	return inner, d.stableLLReleaseBarrier(rgID, inner, tenure, id)
}

// stableLLReleaseBarrier waits for the forced resign's VRRP barrier, which
// settles after the priority-0 burst's send attempts (fold 2: a nil verdict
// means the VIPs were removed and the sends were attempted, not that each
// reached the wire), then releases the stable link-local (releaseStableLL).
// The wrapper settles only after that, so a failover fence waiting on it also
// covers the IPv6 default-router address.
//
// Timeout: if the VRRP barrier has not settled within the release bound, the
// run loop is wedged. The link-local is then released anyway, under the same
// tenure check, and the wrapper reports the timeout. A delayed burst can still
// resume after that deletion; its adverts then go out from a per-node source
// that the peer's #16018 gate drops, and the peer takes over on master-down
// expiry instead.
func (d *Daemon) stableLLReleaseBarrier(rgID int, inner vipReleaseBarrier, tenure, id uint64) vipReleaseBarrier {
	timeout := d.rethVIPReleaseTimeout
	if timeout <= 0 {
		timeout = rethVIPReleaseTimeout
	}
	b := &stableLLBarrier{done: make(chan struct{})}
	go func() {
		defer close(b.done)
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		var timedOut error
		select {
		case <-inner.Done():
			b.err = inner.Err()
		case <-timer.C:
			timedOut = fmt.Errorf("RETH VRRP release not complete after %s", timeout)
		}
		rel := d.releaseStableLL(rgID, tenure, id)
		switch {
		case timedOut != nil:
			b.err = errors.Join(timedOut, rel)
			slog.Warn("cluster: RETH VRRP resign did not settle; stable router link-local released without its burst",
				"rg", rgID, "err", b.err)
		case errors.Is(rel, errStableLLSuperseded):
			b.err = rel
			slog.Info("cluster: stable router link-local kept: the RG was re-activated during its resign", "rg", rgID)
		case b.err == nil:
			b.err = rel
		}
	}()
	return b
}

// releaseStableLL is the resign side of the single remover. It drops this
// resign's pending mark and, under the same lock every add takes, removes the
// stable link-local only if (a) no add happened since the resign captured
// tenure, and (b) no other resign of the RG is still pending. It confirms the
// address absent before releasing the lock.
func (d *Daemon) releaseStableLL(rgID int, tenure, id uint64) error {
	if d.stableLLReleaseHoldFn != nil {
		d.stableLLReleaseHoldFn(rgID) // unit-test seam: park before the check
	}
	t := &d.stableLL
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending[rgID], id)
	if len(t.pending[rgID]) == 0 {
		delete(t.pending, rgID)
	}
	if t.gen[rgID] != tenure {
		return errStableLLSuperseded
	}
	if t.pendingLocked(rgID) {
		return errStableLLHandedOn
	}
	d.deleteStableRethLinkLocalLocked(rgID)
	return d.stableLinkLocalConfirmedAbsent(rgID)
}

type stableLLBarrier struct {
	done chan struct{}
	err  error // written before done closes
}

func (b *stableLLBarrier) Done() <-chan struct{} { return b.done }

// Err is the VRRP release verdict, then the link-local's release; valid once
// Done has closed.
func (b *stableLLBarrier) Err() error { return b.err }
