package snmp

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// snmpServeRatePerSource is the sustained request budget per source IP on
	// the Serve loop (#9917 F-139). Legitimate polling (seconds to minutes
	// between polls) and walk bursts pass untouched; a lone source flooding
	// cheap polls throttles here.
	snmpServeRatePerSource = 100
	// snmpServeBurstPerSource is the per-source bucket capacity: a cold
	// source may fire a walk-sized burst instantly before throttling to the
	// sustained rate.
	snmpServeBurstPerSource = 200
	// snmpServeServiceFactor is the minimum post-handling service charge:
	// each admitted request is debited its loop time at rate x factor, so a
	// source saturating the loop converges to ~1/factor of the loop share.
	// The factor grows with the number of active expensive sources below.
	snmpServeServiceFactor = 10
	// snmpServeExpensiveThreshold separates normal polling from a request
	// whose service time must participate in fair-share accounting. A
	// millisecond is far above the normal microsecond-scale SNMP path while
	// remaining below the ~33ms max-size ifXTable walk.
	snmpServeExpensiveThreshold = time.Millisecond
	// snmpServeExpensiveIdle is the quiet interval after which an expensive
	// contender no longer reserves a fair-share slot. Expiry is checked by a
	// bounded map sweep at most once per second, not on every packet.
	snmpServeExpensiveIdle       = time.Second
	snmpServeExpirySweepInterval = time.Second
	// snmpServeMaxSources bounds tracked sources. Past the cap a newcomer
	// displaces a random incumbent (O(1), no scan) -- admission is certain,
	// so a spoofed-source flood refreshing entries can never lock legitimate
	// newcomers out. Expensive and pending state use a bounded expiry sweep;
	// displacement remains the only map reclamation.
	snmpServeMaxSources = 1024
	// snmpServeGlobalRate / snmpServeGlobalBurst bound AGGREGATE admissions
	// across all sources: the backstop a rotating-spoof flood (fresh bucket
	// per packet) cannot evade. Sized far above any legitimate aggregate so
	// only floods bind here.
	snmpServeGlobalRate  = 2000
	snmpServeGlobalBurst = 4000
	// snmpServeGlobalFactor scales the aggregate service charge for every
	// admitted request, preserving the #9917 global backstop while the
	// independent per-source factor below provides fair-share ordering.
	snmpServeGlobalFactor = 2
)

func snmpServeFairFactor(active int) float64 {
	if active <= 0 {
		return snmpServeServiceFactor
	}
	factor := 2 * active
	if factor < snmpServeServiceFactor {
		return snmpServeServiceFactor
	}
	return float64(factor)
}

// snmpSourceBucket is one source's token bucket, with separate timestamps for
// measured expensive service and a pending newcomer. expensiveSeen is written
// only by account after measured expensive service; cheap traffic must not
// retain a fair-share contender slot indefinitely. everExpensive lets a
// previously measured source re-enter the pending set if it keeps demanding
// during a global dip.
type snmpSourceBucket struct {
	tokens        float64
	last          time.Time
	expensiveSeen time.Time
	pendingSeen   time.Time
	expensive     bool
	everExpensive bool
	pending       bool
	admitted      bool
}

// snmpServeBudget is the Serve loop's request budget (#9917 F-139). The loop
// stays strictly serial -- which is what keeps the lastPacket auth pattern
// safe -- and fairness comes from shedding before any MIB work plus debiting
// loop time consumed, instead of from concurrency. now is injectable (time.Now
// in production; a fake in tests) so refill and service charge are
// deterministic without sleeping, mirroring the dhcprelay #5670 token bucket.
type snmpServeBudget struct {
	mu        sync.Mutex
	now       func() time.Time
	perSource map[[16]byte]*snmpSourceBucket
	// activeExpensive is the number of source buckets currently marked
	activeExpensive int
	lastExpirySweep time.Time
	// pendingSources are sources that reached userspace while the global
	// bucket was empty. Previously admitted sources yield future global
	// credits to these onboarding contenders, preventing FIFO starvation.
	pendingSources int
	// Global backstop, refilled lazily (globalLast.IsZero means unstarted, so
	// hand-built test budgets behave like constructed ones).
	globalTokens float64
	globalLast   time.Time
	// shed counts requests denied at the call site (per-source exhausted,
	// globally exhausted, or -- unreachable while displacement holds -- table
	// pressure). Tests observe enforcement through it instead of inferring
	// drops from missing UDP datagrams.
	shed atomic.Uint64
}

func newSNMPServeBudget() *snmpServeBudget {
	return &snmpServeBudget{now: time.Now, perSource: make(map[[16]byte]*snmpSourceBucket)}
}

// clock returns the budget's clock, tolerating a nil budget or nil clock so
// bare-struct agents stay unbudgeted without nil checks at the call site.
func (b *snmpServeBudget) clock() time.Time {
	if b == nil || b.now == nil {
		return time.Now()
	}
	return b.now()
}

// expireExpensiveLocked releases quiet expensive demand and pending newcomers.
// The sweep is bounded by snmpServeMaxSources and runs at most once per
// interval, so the serial Serve hot path never scans the table per packet.
// expensiveSeen changes only after measured expensive service; pendingSeen
// tracks a newcomer independently.
func (b *snmpServeBudget) expireExpensiveLocked(now time.Time) {
	if !b.lastExpirySweep.IsZero() &&
		now.Sub(b.lastExpirySweep) < snmpServeExpirySweepInterval {
		return
	}
	b.lastExpirySweep = now
	for _, bkt := range b.perSource {
		if bkt.expensive && now.Sub(bkt.expensiveSeen) >= snmpServeExpensiveIdle {
			bkt.expensive = false
			if b.activeExpensive > 0 {
				b.activeExpensive--
			}
		}
		if bkt.pending && now.Sub(bkt.pendingSeen) >= snmpServeExpensiveIdle {
			bkt.pending = false
			if b.pendingSources > 0 {
				b.pendingSources--
			}
		}
	}
}

// allow reports whether a request from srcIP may be served, consuming one
// request token from both the global and the per-source bucket. It is O(1)
// between bounded expiry sweeps: the map holds at most snmpServeMaxSources
// entries and a full table displaces one random incumbent. Sources key on
// normalized IP only (never UDP port); nil/unparseable IPs and nil budgets
// bypass the budget for non-UDP/direct test callers.
func (b *snmpServeBudget) allow(srcIP net.IP) bool {
	if b == nil || srcIP == nil {
		return true
	}
	raw := srcIP.To16()
	if raw == nil {
		return true
	}
	var key [16]byte
	copy(key[:], raw)
	now := b.clock()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.perSource == nil {
		b.perSource = make(map[[16]byte]*snmpSourceBucket)
	}
	bkt, ok := b.perSource[key]
	if !ok {
		if len(b.perSource) >= snmpServeMaxSources {
			// Go map iteration is randomized, so the first key is a
			// constant-time random incumbent. A displaced expensive
			// contender or pending newcomer releases its slot.
			for victim, incumbent := range b.perSource {
				if incumbent.expensive && b.activeExpensive > 0 {
					b.activeExpensive--
				}
				if incumbent.pending && b.pendingSources > 0 {
					b.pendingSources--
				}
				delete(b.perSource, victim)
				break
			}
		}
		bkt = &snmpSourceBucket{tokens: snmpServeBurstPerSource, last: now, pendingSeen: now}
		b.perSource[key] = bkt
	} else {
		if bkt.pending {
			bkt.pendingSeen = now
		}
		// Refill the per-source bucket before the global bucket. The token
		// check below still prevents a depleted source from spending a
		// global credit, while an expired source can reserve a one-shot
		// probe before that check.
		if elapsed := now.Sub(bkt.last).Seconds(); elapsed > 0 {
			bkt.tokens += elapsed * snmpServeRatePerSource
			if bkt.tokens > snmpServeBurstPerSource {
				bkt.tokens = snmpServeBurstPerSource
			}
			bkt.last = now
		}
	}
	b.expireExpensiveLocked(now)

	// Global backstop first for every request that reaches admission: no
	// per-source token is consumed for a request the aggregate budget refuses.
	if b.globalLast.IsZero() {
		b.globalTokens = snmpServeGlobalBurst
		b.globalLast = now
	} else if elapsed := now.Sub(b.globalLast).Seconds(); elapsed > 0 {
		b.globalTokens += elapsed * snmpServeGlobalRate
		if b.globalTokens > snmpServeGlobalBurst {
			b.globalTokens = snmpServeGlobalBurst
		}
		b.globalLast = now
	}
	// A previously measured source that keeps arriving while the global
	// bucket is empty is a real contender even if its old expensive slot
	// expired. Re-enroll it as a pending probe so a global refill cannot
	// starve it; the probe does not change N until its next request is
	// measured expensive. Cheap keepalives therefore cannot inflate N.
	if b.globalTokens < 1 && bkt.admitted && !bkt.expensive &&
		bkt.everExpensive && !bkt.pending {
		bkt.pending = true
		bkt.pendingSeen = now
		b.pendingSources++
	}
	// The reservation is scarce only when admitting this request would leave
	// fewer than one whole global token per pending source. Surplus credits
	// remain work-conserving, so a silent newcomer cannot stall managers after
	// a flood ends.
	if b.globalTokens < float64(b.pendingSources+1) && b.pendingSources > 0 &&
		bkt.admitted && !bkt.pending {
		b.shed.Add(1)
		return false
	}
	if b.globalTokens < 1 {
		if !bkt.admitted && !bkt.pending {
			bkt.pending = true
			bkt.pendingSeen = now
			b.pendingSources++
		}
		b.shed.Add(1)
		return false
	}
	if bkt.tokens < 1 {
		b.shed.Add(1)
		return false
	}
	b.globalTokens--
	bkt.tokens--
	wasExpensiveProbe := bkt.pending && bkt.admitted && bkt.everExpensive
	if bkt.pending {
		bkt.pending = false
		if wasExpensiveProbe {
			bkt.everExpensive = false
		}
		if b.pendingSources > 0 {
			b.pendingSources--
		}
	}
	bkt.admitted = true
	return true
}

// account debits the loop time an admitted request consumed, scaled by the
// service factors. A request above snmpServeExpensiveThreshold joins the
// active contender set. For N >= 5 active expensive sources, each source's
// independent token bucket is charged at 2N, converging to an equal ~1/(2N)
// share of the loop (1/N of the global half). For N <= 5, the 10x floor
// preserves the single-source behavior. Every admitted request still
// receives the #9917 global backstop charge. A missing bucket is skipped.
func (b *snmpServeBudget) account(srcIP net.IP, elapsed time.Duration) {
	if b == nil || srcIP == nil || elapsed <= 0 {
		return
	}
	raw := srcIP.To16()
	if raw == nil {
		return
	}
	var key [16]byte
	copy(key[:], raw)
	secs := elapsed.Seconds()
	now := b.clock()

	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.globalLast.IsZero() {
		b.globalTokens -= secs * snmpServeGlobalRate * snmpServeGlobalFactor
	}
	bkt, ok := b.perSource[key]
	if !ok {
		return
	}
	expensive := elapsed >= snmpServeExpensiveThreshold
	factor := float64(snmpServeServiceFactor)
	if expensive {
		bkt.everExpensive = true
		if !bkt.expensive {
			bkt.expensive = true
			b.activeExpensive++
		}
		bkt.expensiveSeen = now
		factor = snmpServeFairFactor(b.activeExpensive)
	}
	bkt.tokens -= secs * snmpServeRatePerSource * factor
}
