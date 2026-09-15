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
	// snmpServeServiceFactor scales the post-handling service charge: each
	// admitted request is debited its loop time at rate x factor, so a source
	// saturating the loop with expensive PDUs converges to ~1/factor of loop
	// share instead of replenishing its admission token while the loop is
	// busy with its own request. Cheap polls (microseconds) are barely
	// charged and throttle on the admission token instead.
	snmpServeServiceFactor = 10
	// snmpServeMaxSources bounds tracked sources. Past the cap a newcomer
	// displaces a random incumbent (O(1), no scan) -- admission is certain,
	// so a spoofed-source flood refreshing entries can never lock legitimate
	// newcomers out. There is no idle sweep: displacement is the only
	// reclamation, and it runs only on the full-table path.
	snmpServeMaxSources = 1024
	// snmpServeGlobalRate / snmpServeGlobalBurst bound AGGREGATE admissions
	// across all sources: the backstop a rotating-spoof flood (fresh bucket
	// per packet) cannot evade. Sized far above any legitimate aggregate so
	// only floods bind here.
	snmpServeGlobalRate  = 2000
	snmpServeGlobalBurst = 4000
	// snmpServeGlobalFactor scales the aggregate service charge the same way
	// per-source factor does: sustained expensive load from all sources
	// combined converges to ~1/factor of loop share.
	snmpServeGlobalFactor = 2
)

// snmpSourceBucket is one source's token bucket: request tokens, sustained
// refill rate, and the last refill point.
type snmpSourceBucket struct {
	tokens float64
	last   time.Time
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

// allow reports whether a request from srcIP may be served, consuming one
// request token from both the global and the per-source bucket. It is O(1):
// the map holds at most snmpServeMaxSources entries and a full table displaces
// one random incumbent instead of scanning. Sources key on the normalized IP
// only (never the UDP port, which would hand every request a fresh bucket); a
// nil IP (non-IP transports, direct handlePacket callers) bypasses the budget,
// as does a nil budget (bare-struct test agents).
//
// Neither bucket is consumed unless BOTH admit: a per-source-shed packet must
// not burn the shared global budget for everyone else.
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
	// Global backstop first: no per-source state is touched for a request the
	// aggregate budget already refuses.
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
	if b.globalTokens < 1 {
		b.shed.Add(1)
		return false
	}
	bkt, ok := b.perSource[key]
	if !ok {
		if len(b.perSource) >= snmpServeMaxSources {
			// Displace a random incumbent: Go map iteration order is
			// randomized, so the first key ranged is a uniform pick. The
			// newcomer is ALWAYS admitted -- no set of refreshed entries
			// can lock it out, and the scan-per-packet a sweep would cost
			// under spoofed-source flood never happens.
			for victim := range b.perSource {
				delete(b.perSource, victim)
				break
			}
		}
		bkt = &snmpSourceBucket{tokens: snmpServeBurstPerSource, last: now}
		b.perSource[key] = bkt
	}
	// Refill for time passed since the last request from this source. Elapsed
	// <= 0 (frozen test clock, wall-clock step backward) refills nothing, and
	// the burst cap bounds any refill after a forward jump -- a clock jump
	// can neither grant unbounded tokens nor stall the bucket.
	if elapsed := now.Sub(bkt.last).Seconds(); elapsed > 0 {
		bkt.tokens += elapsed * snmpServeRatePerSource
		if bkt.tokens > snmpServeBurstPerSource {
			bkt.tokens = snmpServeBurstPerSource
		}
		bkt.last = now
	}
	if bkt.tokens < 1 {
		b.shed.Add(1)
		return false
	}
	b.globalTokens--
	bkt.tokens--
	return true
}

// account debits the loop time an admitted request consumed, scaled by the
// service factors. Without it the refill during handling would replenish the
// admission token of every request slower than 1/rate -- a source feeding
// back-to-back expensive PDUs would never deplete and would hold the serial
// loop forever. With it, sustained expensive load converges to ~1/factor of
// loop share per source (and ~1/globalFactor aggregate), while cheap requests
// are dominated by the admission token instead. A missing bucket (unit tests
// calling account without allow) is silently skipped.
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

	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.globalLast.IsZero() {
		b.globalTokens -= secs * snmpServeGlobalRate * snmpServeGlobalFactor
	}
	if bkt, ok := b.perSource[key]; ok {
		bkt.tokens -= secs * snmpServeRatePerSource * snmpServeServiceFactor
	}
}
