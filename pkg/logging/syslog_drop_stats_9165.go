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
}

// retire folds a client that is about to be closed/replaced into the
// accumulator. Must be called BEFORE Close: Close stops the event writer,
// which counts its discarded queue into DroppedWrites.
func (a *syslogDropAccumulator) retire(sink string, c *SyslogClient) {
	if c == nil {
		return
	}
	st := syslogDropsFromClient(sink, c)
	if st.Writes == 0 && st.Dials == 0 && st.Cooldown == 0 {
		return
	}
	a.fold(st)
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
// The returned slice is a copy taken under the same RLock that guards the
// client set, so a concurrent ReplaceSyslogClients cannot be observed
// half-applied. The counters themselves are atomics read individually: a
// snapshot is not a consistent instant across all three, which is correct for
// monotonic counters scraped by Prometheus and is why they are exported as
// counters rather than as a rate computed here.
func (er *EventReader) SyslogDropStats() []SyslogDropStat {
	er.syslogMu.RLock()
	defer er.syslogMu.RUnlock()
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

