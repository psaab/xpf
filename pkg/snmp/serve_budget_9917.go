package snmp

import (
	"net"
	"sync"
	"time"
)

const (
	// snmpServeRatePerSource is the sustained request budget per source IP on
	// the Serve loop (#9917 F-139). Typical polls cost microseconds (bounded
	// per-PDU work per #4013/#4918/#6551/#6597), so 100/s holds one source to
	// single-digit loop share for typical shapes while legitimate polling
	// (seconds to minutes between polls) and walk bursts pass untouched.
	snmpServeRatePerSource = 100
	// snmpServeBurstPerSource is the per-source bucket capacity: a cold
	// source may fire a walk-sized burst instantly before throttling to the
	// sustained rate.
	snmpServeBurstPerSource = 200
	// snmpServeMaxSources bounds tracked sources so a spoofed-source flood
	// cannot grow memory without limit. Past the cap, unknown sources are
	// shed untracked until an amortized sweep frees idle entries.
	snmpServeMaxSources = 1024
	// snmpServeSourceIdleTTL reclaims a source idle this long on the next
	// sweep. SNMP managers poll on second/minute cadences; an idle minute
	// means gone.
	snmpServeSourceIdleTTL = 60 * time.Second
	// snmpServeSweepInterval throttles full-table expiry scans: at most one
	// O(sources) sweep per interval, so a rotating-spoof flood pays O(1)
	// per packet plus one amortized scan per second -- never a scan per
	// packet inside the serial loop.
	snmpServeSweepInterval = time.Second
)

// snmpSourceBucket is one source's token bucket: rate tokens/second sustained,
// burst capacity, last refill point, and last-seen point for idle expiry.
type snmpSourceBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

// snmpServeBudget is the Serve loop's per-source request budget (#9917 F-139).
// The loop stays strictly serial -- which is what keeps the lastPacket auth
// pattern safe -- and fairness comes from shedding over-budget sources before
// any MIB work instead of from concurrency. now is injectable (time.Now in
// production; a fake in tests) so refill/expiry are deterministic without
// sleeping, mirroring the dhcprelay #5670 token bucket.
type snmpServeBudget struct {
	mu        sync.Mutex
	now       func() time.Time
	perSource map[[16]byte]*snmpSourceBucket
	lastSweep time.Time
}

func newSNMPServeBudget() *snmpServeBudget {
	return &snmpServeBudget{now: time.Now, perSource: make(map[[16]byte]*snmpSourceBucket)}
}

// allow reports whether a request from srcIP may be served, consuming one
// token. It is O(1): the map holds at most snmpServeMaxSources entries and the
// expiry sweep runs at most once per snmpServeSweepInterval. Sources key on
// the normalized IP only (never the UDP port, which would hand every request a
// fresh bucket); a nil IP (non-IP transports, direct handlePacket callers)
// bypasses the budget, as does a nil budget (bare-struct test agents).
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
	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.perSource == nil {
		b.perSource = make(map[[16]byte]*snmpSourceBucket)
	}
	bkt, ok := b.perSource[key]
	if !ok {
		if len(b.perSource) >= snmpServeMaxSources {
			b.sweepLocked(now)
			if len(b.perSource) >= snmpServeMaxSources {
				return false
			}
		}
		bkt = &snmpSourceBucket{tokens: snmpServeBurstPerSource, last: now, lastSeen: now}
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
	bkt.lastSeen = now
	if bkt.tokens < 1 {
		return false
	}
	bkt.tokens--
	return true
}

// sweepLocked evicts sources idle past snmpServeSourceIdleTTL. Call with mu
// held, only from the full-table path; runs at most once per
// snmpServeSweepInterval so flood packets between sweeps shed in O(1).
func (b *snmpServeBudget) sweepLocked(now time.Time) {
	if now.Sub(b.lastSweep) < snmpServeSweepInterval {
		return
	}
	b.lastSweep = now
	for k, v := range b.perSource {
		if now.Sub(v.lastSeen) >= snmpServeSourceIdleTTL {
			delete(b.perSource, k)
		}
	}
}
