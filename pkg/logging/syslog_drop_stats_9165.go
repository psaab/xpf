package logging

import "sort"

// SyslogDropStat is one remote syslog collector's drop accounting, snapshotted
// for an operator-facing surface.
//
// #9165: `DroppedWrites`/`DroppedDials`/`DroppedCooldown` existed with ZERO
// production readers. Every counted drop reached an operator through exactly
// one channel — the ≤1/s `slog.Warn` inside the package — and a warning that
// has already been rate-limited away leaves nothing behind. A counter nobody
// reads is indistinguishable from no counter, which is why the missing reader
// is half of the defect rather than a follow-up.
//
// #16769: the counters are CUMULATIVE per destination. A commit that rebuilds
// the client set closes the old clients and installs fresh ones with zeroed
// counters; folding each retired client's final counts into a per-(sink,
// addr, protocol) accumulator keeps the exported Prometheus counter monotonic
// per destination instead of resetting to zero on every rebuild. Counters of
// clients still installed are read live; the accumulator carries only the
// retired generations, so a live client is never double-counted.
type SyslogDropStat struct {
	// Sink is "security" for security-log stream clients (EventReader set)
	// or "system" for `system syslog host` clients (slog handler set).
	Sink string
	// RemoteAddr is the collector's host:port, as configured.
	RemoteAddr string
	// Protocol is "udp", "tcp" or "tls" — the label that makes a UDP-only
	// silence visible as a transport property rather than a mystery.
	Protocol string
	// Writes counts messages dropped because the write itself failed.
	Writes uint64
	// Dials counts messages dropped because the post-failure reconnect dial
	// failed. Stream transports only; a datagram socket never reconnects.
	Dials uint64
	// Cooldown counts messages dropped because a reconnect was suppressed by
	// the cooldown window. Stream transports only.
	Cooldown uint64
}

// syslogDropKey identifies one collector destination within one sink.
type syslogDropKey struct {
	sink     string
	addr     string
	protocol string
}

// syslogDropsFromClient snapshots one client's counters as a SyslogDropStat.
func syslogDropsFromClient(sink string, c *SyslogClient) SyslogDropStat {
	return SyslogDropStat{
		Sink:       sink,
		RemoteAddr: c.RemoteAddr(),
		Protocol:   c.Protocol(),
		Writes:     c.DroppedWrites(),
		Dials:      c.DroppedDials(),
		Cooldown:   c.DroppedCooldown(),
	}
}

// syslogDropAccumulator folds retired clients' drop counters per destination
// so the exported counters survive client rebuilds (#16769). All methods
// require the caller to hold the owning mutex; the zero value is ready.
type syslogDropAccumulator struct {
	byKey map[syslogDropKey]*SyslogDropStat
	// foldedByClient tracks each retired client's folded contribution so
	// a (hypothetical) reinstall of the same pointer can subtract it:
	// its counters would otherwise be read live AND sit in byKey
	// (#17855 reinstall double-count). Keyed by client pointer.
	foldedByClient map[*SyslogClient]SyslogDropStat
}

// retire folds a client that is about to be closed/replaced into the
// accumulator, snapshotting its pre-Close counts. The Close-discard
// remainder is folded separately and exactly once via the owner's
// retired-pending set (#17855); retire itself stays a pre-Close snapshot.
func (a *syslogDropAccumulator) retire(sink string, c *SyslogClient) {
	if c == nil {
		return
	}
	st := syslogDropsFromClient(sink, c)
	if st.Writes == 0 && st.Dials == 0 && st.Cooldown == 0 {
		return
	}
	a.foldFor(c, st)
}

func (a *syslogDropAccumulator) foldFor(c *SyslogClient, st SyslogDropStat) {
	a.fold(st)
	if a.foldedByClient == nil {
		a.foldedByClient = make(map[*SyslogClient]SyslogDropStat)
	}
	cur := a.foldedByClient[c]
	cur.Sink, cur.RemoteAddr, cur.Protocol = st.Sink, st.RemoteAddr, st.Protocol
	cur.Writes += st.Writes
	cur.Dials += st.Dials
	cur.Cooldown += st.Cooldown
	a.foldedByClient[c] = cur
}

// forgetClient subtracts a reinstalled client's folded contribution:
// the client is live again, so its counters are read from the client
// itself and must not also remain in the retired totals. No-op when
// nothing was folded for it. Owners call it when (re)installing.
func (a *syslogDropAccumulator) forgetClient(c *SyslogClient) {
	st, ok := a.foldedByClient[c]
	if !ok {
		return
	}
	k := syslogDropKey{sink: st.Sink, addr: st.RemoteAddr, protocol: st.Protocol}
	if cur, ok := a.byKey[k]; ok {
		cur.Writes -= st.Writes
		cur.Dials -= st.Dials
		cur.Cooldown -= st.Cooldown
		if cur.Writes == 0 && cur.Dials == 0 && cur.Cooldown == 0 {
			delete(a.byKey, k)
		}
	}
	delete(a.foldedByClient, c)
}

func (a *syslogDropAccumulator) fold(st SyslogDropStat) {
	if a.byKey == nil {
		a.byKey = make(map[syslogDropKey]*SyslogDropStat)
	}
	k := syslogDropKey{sink: st.Sink, addr: st.RemoteAddr, protocol: st.Protocol}
	cur, ok := a.byKey[k]
	if !ok {
		cp := st
		a.byKey[k] = &cp
		return
	}
	cur.Writes += st.Writes
	cur.Dials += st.Dials
	cur.Cooldown += st.Cooldown
}

// retiredPending tracks, per retired client, the snapshot retire()
// took, so the post-Close remainder can be folded exactly once at stats
// time (#17855). Owners guard it with the same mutex as the accumulator.
type retiredPending map[*SyslogClient]SyslogDropStat

// record remembers a just-retired client's snapshot under its sink.
func (p *retiredPending) record(sink string, c *SyslogClient) {
	if c == nil {
		return
	}
	if *p == nil {
		*p = make(retiredPending)
	}
	(*p)[c] = syslogDropsFromClient(sink, c)
}

// recordForget drops c's pending entry: a reinstalled client is live,
// so nothing about it is retired anymore.
func (p *retiredPending) recordForget(c *SyslogClient) {
	delete(*p, c)
}

// foldInto folds each pending client's post-retire counter growth (its
// Close discards) into acc. A client's pending entry is cleared only
// once its counters are FINAL (CountsFinal: writer goroutine exited
// after Close, so no drop can land later) and STABLE (no movement
// since the previous stats call). The finality flag is read BEFORE
// the counters so a completing Close cannot straddle the read. A still-open client (retired but not yet closed
// by its owner, or being drained) folds what it has counted so far and
// its snapshot ADVANCES by the folded amount, so the remainder folds
// at a later call: every drop is counted exactly once across any
// number of interleaved stats calls (#17855).
func (p *retiredPending) foldInto(acc *syslogDropAccumulator) {
	for c, snap := range *p {
		// Read finality BEFORE the counters (#17855 fold 4): CountsFinal
		// is stored only after Close's counting completes, so observing
		// it first makes every pre-Store increment visible to the read
		// below. Reading counters first and the flag second could
		// straddle a completing Close and delete the entry mid-drain.
		finalClaimed := c.CountsFinal()
		now := syslogDropsFromClient(snap.Sink, c)
		sub := func(now, before uint64) uint64 {
			if now <= before {
				return 0
			}
			return now - before
		}
		delta := SyslogDropStat{
			Sink:       snap.Sink,
			RemoteAddr: snap.RemoteAddr,
			Protocol:   snap.Protocol,
			Writes:     sub(now.Writes, snap.Writes),
			Dials:      sub(now.Dials, snap.Dials),
			Cooldown:   sub(now.Cooldown, snap.Cooldown),
		}
		if delta.Writes != 0 || delta.Dials != 0 || delta.Cooldown != 0 {
			acc.foldFor(c, delta)
		}
		// Delete only when Close claims finality AND the counters did
		// not move since the previous snapshot (delta zero): Close
		// raises its flag before the bounded-join writer's last drop
		// can be counted for non-interrupting conns, so flag-alone
		// would still race one in-flight record (#17855 fold 3).
		stable := delta.Writes == 0 && delta.Dials == 0 && delta.Cooldown == 0
		if finalClaimed && stable {
			delete(*p, c)
		} else {
			// Not final yet: advance the snapshot so the remainder is
			// folded later, never twice, never lost.
			(*p)[c] = now
		}
	}
}

// merge adds this accumulator's retired totals into out, keyed by
// destination, and returns the extended slice. Live rows already in out for
// the same destination absorb their retired totals instead of producing a
// duplicate series; destinations with only retired clients get a row so
// their drops stay visible after the client set is torn down.
func (a *syslogDropAccumulator) merge(out []SyslogDropStat) []SyslogDropStat {
	if len(a.byKey) == 0 {
		return out
	}
	index := make(map[syslogDropKey]int, len(out))
	for i, st := range out {
		index[syslogDropKey{sink: st.Sink, addr: st.RemoteAddr, protocol: st.Protocol}] = i
	}
	var extra []SyslogDropStat
	for k, retired := range a.byKey {
		if i, ok := index[k]; ok {
			out[i].Writes += retired.Writes
			out[i].Dials += retired.Dials
			out[i].Cooldown += retired.Cooldown
			continue
		}
		extra = append(extra, *retired)
	}
	sort.Slice(extra, func(i, j int) bool {
		if extra[i].Sink != extra[j].Sink {
			return extra[i].Sink < extra[j].Sink
		}
		if extra[i].RemoteAddr != extra[j].RemoteAddr {
			return extra[i].RemoteAddr < extra[j].RemoteAddr
		}
		return extra[i].Protocol < extra[j].Protocol
	})
	return append(out, extra...)
}

// SyslogDropStats snapshots the drop counters of every installed syslog client
// (goroutine-safe), folded with the retired generations' totals so the
// counters are cumulative per destination across rebuilds (#16769).
//
// The returned slice is a copy taken under the write lock that guards
// the client set (the lock serializes the retired-pending fold), so a
// concurrent ReplaceSyslogClients cannot be observed half-applied. The counters themselves are atomics read individually: a
// snapshot is not a consistent instant across all three, which is correct for
// monotonic counters scraped by Prometheus and is why they are exported as
// counters rather than as a rate computed here.
func (er *EventReader) SyslogDropStats() []SyslogDropStat {
	er.syslogMu.Lock()
	defer er.syslogMu.Unlock()
	// #17855: fold retired clients' Close discards exactly once.
	er.syslogRetiredPending.foldInto(&er.syslogRetired)
	out := make([]SyslogDropStat, 0, len(er.syslogClients))
	for _, c := range er.syslogClients {
		if c == nil {
			continue
		}
		out = append(out, syslogDropsFromClient("security", c))
	}
	out = er.syslogRetired.merge(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
