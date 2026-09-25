package dhcprelay

import (
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// Outstanding-request binding for relayed server replies (#6562).
//
// PROBLEM. The server-facing socket is bound (not connect()-ed) to giaddr:67,
// so it accepts datagrams from ANY host that can route there. #4163 added a
// source-IP allow-list, but a source IP is spoofable: an off-path attacker who
// forges the configured server's address can inject an OFFER/ACK (hostile
// gateway/DNS) or a NAK (forced client restart) at a client, because the relay
// forwards any well-formed BOOTREPLY without ever asking whether it answers a
// request the relay actually sent.
//
// FIX. Every request the relay forwards upstream records an entry here; a
// reply is forwarded only if it matches one. That adds a 32-bit xid the
// attacker must guess on top of the spoofed source IP, and pins the reply to
// the client identity (chaddr) the request carried.
//
// KEYING — xid + chaddr, and deliberately nothing else. RFC 2131 §2 defines
// 'xid' as "Transaction ID, a random number chosen by the client", and §4.1
// gives its purpose: "The 'xid' field is used by the client to match incoming
// DHCP messages with pending requests." That is precisely the association this
// table needs, applied one hop earlier. The §4.3.1 Table 3 (fields in DHCP
// messages sent by a server) then pins both halves of the key as server-echoed:
// for DHCPOFFER/DHCPACK/DHCPNAK alike, 'xid' is "'xid' from client
// DHCPDISCOVER/DHCPREQUEST message" and 'chaddr' is "'chaddr' from client
// DHCPDISCOVER/DHCPREQUEST message". Both are therefore present on the request
// AND echoed on the reply, which is exactly what a binding needs.
//
// Option 61 (client-identifier) is deliberately NOT part of the key even
// though it is a stronger identity. RFC 6842 §2 records why: "[RFC2131] also
// specifies that the server MUST NOT return the 'client identifier' option in
// DHCPOFFER and DHCPACK messages", and only RFC 6842 §3 (2013) reversed that
// to "the server MUST return the 'client identifier' option, unaltered, in its
// response message". A server still on the original RFC 2131 behavior echoes
// no option 61, so keying on it would drop every reply from that server — a
// silent, total DHCP outage on the segment. xid+chaddr is the subset that
// every conformant server echoes under BOTH revisions.
//
// A client with no valid hardware address may legitimately send an all-zero
// chaddr (RFC 6842 §2 notes this case). Such clients still bind correctly:
// the server echoes the zero chaddr, so the key round-trips. They simply lean
// entirely on the xid for uniqueness, which is the pre-existing RFC 2131
// matching rule and no weaker than what the client itself relies on.
//
// FAIL DIRECTION. This table gates live DHCP for real clients, so every path
// that can drop a legitimate reply is counted and logged on interfaceRelay
// (repliesDroppedNoRequest, pendingEvicted) — an over-strict binding must be
// visible in `show services dhcp relay`, never silent.
//
// SHARED CORE (#10699). The table is generic over its key: v4 instantiates
// pendingTable (pendingKey: xid+chaddr, below) and DHCPv6 instantiates
// pendingTableOf[pending6Key] (xid+DUID+IAID, see pending6.go). One ring, one
// expiry/eviction discipline, one set of O(1) pins — a second copy would
// re-learn every lesson in these comments the hard way.

const (
	// pendingTTL is the NOMINAL reply-binding window: how long a forwarded
	// request stays bindable. It bounds the window in which a spoofed reply
	// carrying a guessed xid would be accepted, so shorter is safer; it must
	// still cover the worst-case server response time, because an entry that
	// expires early drops a LEGITIMATE reply.
	//
	// 30s is chosen against RFC 2131 §4.1's client retransmission schedule:
	// "the delay before the first retransmission SHOULD be 4 seconds
	// randomized by the value of a uniform random number chosen from the range
	// -1 to +1... The delay before the next retransmission SHOULD be 8
	// seconds... The retransmission delay SHOULD be doubled with subsequent
	// retransmissions up to a maximum of 64 seconds." 30s spans the 4s, 8s and
	// 16s retransmissions, so a server slow enough to outrun the window has
	// already prompted at least one client retransmission.
	//
	// That retransmission is what makes a too-short TTL self-healing, and it
	// works whichever xid the client picks. §4.1 is explicit that the choice is
	// open — "Selecting a new 'xid' for each retransmission is an
	// implementation decision. A client may choose to reuse the same 'xid' or
	// select a new 'xid' for each retransmitted message" — but either way the
	// retransmission itself traverses this relay and inserts an entry under
	// whatever xid it carries, and the server's answer to it echoes that same
	// xid (§4.3.1 Table 3). The failure mode of a too-short TTL is therefore a
	// bounded retry, not a stuck client.
	//
	// The window is only NOMINAL when the memory ceiling binds; see
	// pendingCapacityFor.
	pendingTTL = 30 * time.Second

	// pendingCapMin is the floor on table capacity. At the default 100 pps the
	// derivation below wants 100*30 + 200 = 3200 entries; the floor rounds that
	// up so a default relay has headroom and never evicts.
	pendingCapMin = 4096

	// pendingCapMax is the memory ceiling on table capacity. The derivation is
	// rate-driven and `overrides maximum-packet-rate` accepts up to 1000000, so
	// an UNCLAMPED derivation would itself be the memory-exhaustion vector this
	// table exists not to be: 1e6 pps x 30 s is 3e7 entries, on the order of
	// gigabytes. 131072 entries is ~6 MB of ring plus the map — a bounded cost
	// per relay interface — and it covers the full 30s window for every rate up
	// to ~4096 pps, which spans realistic large campus/access deployments.
	//
	// Above that rate the ceiling binds and the EFFECTIVE window shrinks to
	// capacity/rate seconds. That is unavoidable — window x rate IS memory —
	// but it is made explicit rather than emergent: pendingCapacityFor reports
	// the clamp, Apply logs a startup Warn naming the reduced window, and
	// PendingSize/PendingEvicted expose the runtime truth.
	pendingCapMax = 131072

	// maxDrainPerInsert bounds how many expired slots one insert reclaims.
	//
	// insert needs exactly ONE free slot, so draining more than a small
	// constant per call buys nothing and only lengthens the time the mutex is
	// held on the client-facing packet path. Leftover expired slots are inert
	// (matches re-checks the expiry, occupancy excludes them) and are reclaimed
	// by subsequent inserts: each drains up to this many and then adds one, so
	// the raw ring count falls by 63 per admitted packet. (NOT 65 — after any
	// positive drain `count < capacity`, so the eviction loop below cannot run
	// and frees nothing; see its early return.) A full 131072-slot ring still
	// clears inside a few seconds at the default rate, without ever stalling a
	// single packet.
	maxDrainPerInsert = 64
)

// pendingCapacityFor sizes the outstanding-request table from the interface's
// #5670 ingress packet-rate limit, and reports whether the memory ceiling
// clamped the result.
//
// WHY THIS IS RATE-DERIVED (#6603 review F1). A fixed capacity is wrong because
// the fill rate is configurable: steady-state occupancy is rate x pendingTTL,
// so a hardcoded 8192 was cap-bound above ~273 pps and the binding window
// silently collapsed from 30s to 8192/rate seconds. That is an availability
// regression in exactly the direction this file declares worse than the attack
// it prevents — and the relay's own README recommends raising
// `maximum-packet-rate` on a busy segment, steering operators straight into it.
// A boot storm on a segment provisioned for 3000 pps would collapse the window
// to 2.7s; a saturated server whose RTT exceeds that then has every reply
// dropped at the relay, turning a storm that previously COMPLETED into a
// permanent retry storm.
//
// Capacity therefore tracks the rate: rate x TTL covers the sustained window,
// and + relayBurstFor(rate) covers the token bucket's 2-second burst allowance,
// so every packet the limiter can admit within one TTL has a slot.
// maxPacketRate participates in relaySpec.equal(), so a day-2 rate change
// restarts the session and re-derives this.
func pendingCapacityFor(maxPacketRate int) (capacity int, clamped bool) {
	rate := resolveMaxPacketRate(maxPacketRate)
	// Any rate at or above the ceiling saturates it anyway. Short-circuiting
	// here also keeps the arithmetic below overflow-free on 32-bit int, so a
	// nonsense rate from a hand-edited active.json cannot wrap.
	if rate >= pendingCapMax {
		return pendingCapMax, true
	}
	want := rate*int(pendingTTL/time.Second) + relayBurstFor(rate)
	switch {
	case want > pendingCapMax:
		return pendingCapMax, true
	case want < pendingCapMin:
		return pendingCapMin, false
	default:
		return want, false
	}
}

// pendingWindow reports the EFFECTIVE reply-binding window a table of the given
// capacity provides at the given packet rate: the table can only hold
// capacity/rate seconds' worth of requests. Used for the startup Warn when the
// memory ceiling clamps capacity below the nominal pendingTTL.
func pendingWindow(capacity, maxPacketRate int) time.Duration {
	rate := resolveMaxPacketRate(maxPacketRate)
	w := time.Duration(capacity) * time.Second / time.Duration(rate)
	if w > pendingTTL {
		return pendingTTL
	}
	return w
}

// pendingKey identifies one outstanding client transaction. It is an
// all-array, comparable struct so it can be a map key with no allocation and
// no string building on the per-packet path.
type pendingKey struct {
	// xid is the RFC 2131 'xid' field. dhcpv4.TransactionID is [4]byte, so it
	// is comparable as-is.
	xid dhcpv4.TransactionID
	// hlen is the significant length of chaddr. It participates in the key so a
	// 6-byte Ethernet address cannot collide with a longer address that shares
	// its first 6 bytes.
	hlen uint8
	// chaddr is the BOOTP client hardware address, zero-padded. dhcpv4.FromBytes
	// clamps the parsed length to 16 (MaxHWAddrLen), which this array matches.
	chaddr [16]byte
}

// pendingKeyFor derives the binding key from a DHCP message. It reads only
// fields that RFC 2131 requires a server to echo, so the key computed from a
// forwarded request equals the key computed from the reply that answers it.
// The relay's own mutations (hops, giaddr, Option 82) do not touch either
// field, so stamping a request does not change its key.
func pendingKeyFor(pkt *dhcpv4.DHCPv4) pendingKey {
	k := pendingKey{xid: pkt.TransactionID}
	// Defensive cap: dhcpv4.FromBytes already clamps hwAddrLen to 16, but a
	// packet built in-process (tests, future callers) is not bound by that.
	n := len(pkt.ClientHWAddr)
	if n > len(k.chaddr) {
		n = len(k.chaddr)
	}
	copy(k.chaddr[:], pkt.ClientHWAddr[:n])
	k.hlen = uint8(n)
	return k
}

// pendingSlotOf is one insertion in the expiry-ordered ring. pendingSlot is
// the v4 instantiation; the v6 relay uses pendingSlotOf[pending6Key].
type pendingSlotOf[K comparable] struct {
	key K
	exp time.Time
	// gen identifies WHICH insertion of this key the slot represents. When a
	// key is re-inserted, the map moves to the new generation and every older
	// slot becomes stale. See pendingEntry.gen.
	gen uint64
}

// pendingSlot is the v4 pending key's ring slot. Alias, not a copy: every
// method below is defined once on pendingTableOf[K].
type pendingSlot = pendingSlotOf[pendingKey]

// pendingEntry is the live state for one key: its expiry, and the generation
// of the ring slot that owns it.
type pendingEntry struct {
	exp time.Time
	gen uint64
}

// pendingTableOf is a bounded, expiring set of outstanding relayed requests,
// generic over the key so the v4 and DHCPv6 relays share one ring, one
// expiry/eviction discipline, and one set of O(1) pins. pendingTable is the
// v4 instantiation (key pendingKey, below); the v6 relay instantiates
// pendingTableOf[pending6Key] (see pending6.go).
//
// It is written by the client-facing read loop and read by the server-facing
// reply loop — two different goroutines within one relay session — so it is
// mutex-guarded. The table lives on the relay struct (interfaceRelay /
// dhcpV6Relay) rather than on the session, so a session rebuild (#2347 ifindex
// drift / #3960 re-address) does NOT wipe in-flight bindings and strand a
// client mid-transaction.
//
// STRUCTURE. A map for O(1) lookup, plus a fixed-size ring of insertions for
// O(1) expiry and eviction. The ring works because EVERY entry is inserted with
// the SAME ttl, so insertion order IS expiry order — the oldest slot is always
// at the head, and finding it needs no scan. The earlier implementation ranged
// the whole map to find the minimum expiry, which cost two full O(capacity)
// scans per admitted packet once the table was full: at a raised packet rate
// that was hundreds of microseconds per packet on the single client-facing read
// goroutine, saturating a core in the exact overload the table is meant to
// survive (#6603 review F1).
//
// A key re-inserted before its previous slot expires (a client retransmitting,
// or the SELECTING REQUEST reusing the DISCOVER's xid) simply gets a NEW slot;
// the older slot becomes stale because the map now holds a later expiry, and it
// is discarded for free when it reaches the head. Because the ring length is
// the capacity and a slot is always freed before a push, len(entries) <= count
// <= capacity holds — the ring bounds the map, so duplicate inserts cannot grow
// either structure past the cap.
type pendingTableOf[K comparable] struct {
	mu      sync.Mutex
	entries map[K]pendingEntry   // key -> expiry + owning generation
	ring    []pendingSlotOf[K]   // fixed length == capacity; expiry-ordered
	head    int                   // index of the oldest slot
	count   int                   // slots in use
	ttl     time.Duration
	now     func() time.Time

	// nextGen hands out slot generations. It makes slot identity EXACT
	// rather than inferring it from the expiry: two inserts of the same key
	// can receive the SAME expiry (time.Now() is not guaranteed to advance
	// between two calls, and a frozen test clock never does), and comparing
	// expiries would then treat the older slot as the live one — popping it at
	// capacity would delete a binding that a newer slot still owns, silently
	// losing a legitimate reply. Generations cannot collide.
	nextGen uint64

	// evicted counts entries removed by CAP PRESSURE (not by ordinary expiry).
	// It is surfaced as RelayStats.PendingEvicted; a nonzero value means the
	// table is full and a legitimate reply may now be dropped.
	evicted uint64

	// slotScans counts ring slots examined by the expiry/eviction path. It
	// exists to pin the O(1) invariant deterministically in tests
	// (TestPendingTable_AtCapInsertIsConstantTime) without timing: if the
	// eviction path ever regresses to a scan, scans-per-insert grows with
	// capacity instead of staying a small constant.
	slotScans uint64
}

// pendingTable is the v4 instantiation of pendingTableOf. Alias, not a copy.
type pendingTable = pendingTableOf[pendingKey]

// newPendingTableOf builds a table for any comparable key. A nil clock
// defaults to time.Now; a non-positive capacity or ttl falls back to the
// package defaults so a mis-wired caller cannot silently create an unbounded
// or never-expiring table. Production sizes capacity with pendingCapacityFor.
func newPendingTableOf[K comparable](capacity int, ttl time.Duration, now func() time.Time) *pendingTableOf[K] {
	if now == nil {
		now = time.Now
	}
	if capacity <= 0 {
		capacity, _ = pendingCapacityFor(defaultMaxPacketRate)
	}
	if ttl <= 0 {
		ttl = pendingTTL
	}
	return &pendingTableOf[K]{
		entries: make(map[K]pendingEntry),
		ring:    make([]pendingSlotOf[K], capacity),
		ttl:     ttl,
		now:     now,
	}
}

// newPendingTable builds the v4 table. It is newPendingTableOf[pendingKey],
// kept so every v4 caller and test reads unchanged.
func newPendingTable(capacity int, ttl time.Duration, now func() time.Time) *pendingTable {
	return newPendingTableOf[pendingKey](capacity, ttl, now)
}

// insert records a forwarded request as bindable for ttl.
//
// It MUST be called BEFORE the request is written upstream: the reply loop
// runs in a different goroutine, and a fast server on a local segment can
// deliver its OFFER before a post-send insert has run — which would drop the
// legitimate first reply of every exchange.
//
// A nil receiver is a no-op (see matches for the fail-closed rationale).
func (t *pendingTableOf[K]) insert(k K) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()

	// FULL-DRAIN FAST PATH. The ring is expiry-ordered, so if even the NEWEST
	// slot has expired then EVERY slot has. Without this, the loop below would
	// pop the whole ring one slot at a time — up to pendingCapMax (131072)
	// iterations, each with a map lookup and delete, all under the mutex and on
	// the client-facing packet path — on the first insert after an idle period.
	// That is a ~10ms stall that also blocks the reply loop. Detecting it costs
	// one slot read, and the reset itself is O(1): head/count go to zero and the
	// map is replaced wholesale rather than deleted key by key.
	//
	// Slots at or beyond count are never read (pushLocked overwrites a slot
	// before count covers it, and snapshot bounds its walk by count), so leaving
	// the stale contents in place is safe and keeps this genuinely constant-time.
	if t.count > 0 && !now.Before(t.ring[(t.head+t.count-1)%len(t.ring)].exp) {
		t.slotScans++ // the one probe read above
		t.head = 0
		t.count = 0
		t.entries = make(map[K]pendingEntry)
	}

	// Reclaim expired slots from the head, BOUNDED. The ring is expiry-ordered,
	// so this stops at the first unexpired slot — but the fast path above only
	// covers the case where EVERY slot has expired. The adjacent case it does
	// not cover is the expensive one: capacity-1 slots expired with the newest
	// still live (a quiet period followed by a single late request). There the
	// probe fails and an unbounded loop would pop ~131071 slots one at a time,
	// each with a map lookup and delete, under the mutex on the packet path —
	// the same multi-millisecond stall, just behind a narrower trigger.
	//
	// insert needs exactly ONE free slot, so reclaiming more than a small
	// constant per call buys nothing. Whatever is left stays expired-but-inert
	// (matches re-checks the expiry, occupancy excludes it) and is reclaimed by
	// later inserts, which drain maxDrainPerInsert each while the eviction loop
	// below frees one more. Per-call work is therefore bounded by a constant,
	// and the backlog still clears promptly.
	drained := 0
	for t.count > 0 && drained < maxDrainPerInsert && !now.Before(t.ring[t.head].exp) {
		t.popHeadLocked()
		drained++
	}

	// Make room if still full. EVICTION POLICY — evict the OLDEST, do not
	// refuse the NEW request.
	//
	// The alternative (drop new requests at the cap) is strictly worse here:
	// an attacker who fills the table would lock out every NEW client until
	// entries aged out, i.e. a total DHCP outage on the segment. Evicting the
	// oldest degrades gracefully instead — new clients keep being served, and
	// only the entries closest to expiry anyway lose their binding.
	//
	// Crucially, the choice does not trade away the security property.
	// Eviction can only cause a legitimate reply to be DROPPED; it can never
	// cause an unsolicited reply to be ACCEPTED. Both policies fail in the
	// availability direction only, so the tie-break is which outage is smaller
	// — and "new clients still work" beats "no client works". A client whose
	// entry was evicted recovers on its next retransmission (RFC 2131 §4.1).
	//
	// This loop pops exactly one slot (count is at most the ring length, and
	// one pop drops it below), so the at-cap path stays O(1).
	//
	// Every pop here displaces an UNEXPIRED binding, so counting each one as a
	// cap-pressure eviction is exact — no expiry re-check is needed, and adding
	// one would be dead code. Proof, given the two reclaim steps above:
	//
	//	this loop needs count >= capacity to run at all
	//	  - fast path fired      -> count == 0            -> loop is a no-op
	//	  - drain popped d > 0   -> count = cap-d < cap   -> loop is a no-op
	//	  - drain popped d == 0  -> the head is UNEXPIRED (that is why it stopped)
	//
	// The bound cannot change this: stopping at d == maxDrainPerInsert would
	// need cap-64 >= cap. So whenever this loop runs, the head is unexpired by
	// construction. If either reclaim step above is ever removed, that ceases to
	// hold and PendingEvicted — an alarm an operator is told to read as damage
	// in progress — would start firing on a merely idle relay.
	for t.count >= len(t.ring) {
		if t.popHeadLocked() {
			t.evicted++
		}
	}

	t.pushLocked(k, now.Add(t.ttl))
}

// pushLocked records one key with an explicit expiry, assigning it a fresh
// generation. Callers MUST push in non-decreasing expiry order so the ring
// stays expiry-ordered, and MUST have already made room. Caller holds mu.
func (t *pendingTableOf[K]) pushLocked(k K, exp time.Time) {
	gen := t.nextGen
	t.nextGen++
	t.entries[k] = pendingEntry{exp: exp, gen: gen}
	t.ring[(t.head+t.count)%len(t.ring)] = pendingSlotOf[K]{key: k, exp: exp, gen: gen}
	t.count++
}

// popHeadLocked removes the oldest ring slot and reports whether it removed a
// LIVE map entry. A slot is stale (and its removal frees nothing in the map)
// when the key was re-inserted after it: the map then holds a LATER GENERATION
// than the slot.
//
// Identity is the generation, NOT the expiry. Two inserts of the same key can
// carry identical expiries (nothing guarantees time.Now() advances between two
// calls, and a frozen test clock never does); comparing expiries would then
// match the OLDER slot and delete a binding the newer slot still owns — a
// silently lost reply. Caller holds mu.
func (t *pendingTableOf[K]) popHeadLocked() bool {
	s := t.ring[t.head]
	t.ring[t.head] = pendingSlotOf[K]{} // drop the time.Time reference
	t.head = (t.head + 1) % len(t.ring)
	t.count--
	t.slotScans++
	if e, ok := t.entries[s.key]; ok && e.gen == s.gen {
		delete(t.entries, s.key)
		return true
	}
	return false
}

// matches reports whether a reply binds to an unexpired outstanding request.
//
// The entry is deliberately NOT consumed. One relayed request legitimately
// draws MULTIPLE replies: the relay fans each request out to EVERY server in
// the group, so an N-server group answers one v4 DISCOVER with N OFFERs — and
// likewise one v6 Solicit with N Advertises. On top of that, RFC 2131 §4.4.1
// states "The DHCPREQUEST message contains the same 'xid' as the DHCPOFFER
// message", so the whole v4 SELECTING exchange (DISCOVER/OFFER/REQUEST/ACK)
// shares one xid and the same binding must also admit the ACK/NAK. Consuming
// on first match would drop every reply after the first and silently break
// multi-server redundancy.
//
// A nil receiver returns false (fail-closed). Production wires the table where
// the relay struct is built (interfaceRelay / dhcpV6Relay), so nil means a
// caller was mis-wired; failing closed makes that a loud, counted, immediately
// visible outage rather than a silent loss of the binding this file exists to
// enforce — the same posture as the #4163 empty-allow-set rule.
func (t *pendingTableOf[K]) matches(k K) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[k]
	if !ok {
		return false
	}
	return t.now().Before(e.exp)
}

// snapshot returns the live, unexpired bindings in expiry order (oldest
// first), for migration into a replacement table.
//
// WHY THIS EXISTS (#6603 re-review). maxPacketRate — and every other field in
// relaySpec — participates in relaySpec.equal(), so ANY day-2 config change to
// a relay group stops the relay and builds a replacement with a brand-new
// table. Without migration every outstanding binding is destroyed at that
// instant, and because the replacement rebinds the SAME giaddr:67, replies for
// pre-reload requests still arrive — and are then dropped by the binding gate.
// Pre-#6562 those replies were forwarded, so that is a straight availability
// regression.
//
// It is sharpest for maximum-packet-rate: raising it is the documented remedy
// for a busy segment, so an operator following the docs DURING a boot storm
// would flush every in-flight binding and trigger the retry storm this file
// exists to prevent.
//
// Expired entries are excluded, and each entry keeps its ORIGINAL expiry when
// adopted — a config reload must not extend the binding window, which would
// hand an attacker a longer guessing window for free.
func (t *pendingTableOf[K]) snapshot() []pendingSlotOf[K] {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	live := make([]pendingSlotOf[K], 0, t.count)
	for i := 0; i < t.count; i++ {
		s := t.ring[(t.head+i)%len(t.ring)]
		// Skip stale slots (a newer generation owns the key) and expired ones.
		if e, ok := t.entries[s.key]; !ok || e.gen != s.gen {
			continue
		}
		if !now.Before(s.exp) {
			continue
		}
		live = append(live, s)
	}
	return live
}

// adopt installs migrated bindings into a freshly-built table, preserving each
// one's original expiry. Slots MUST arrive in expiry order (snapshot's output
// is), which keeps the ring's expiry ordering intact.
//
// If the replacement is SMALLER — the operator lowered maximum-packet-rate —
// the excess cannot be kept. The OLDEST are dropped (the same policy the
// steady-state path uses, and the ones closest to expiry anyway) and each is
// COUNTED as an eviction, so a shrink shows up in PendingEvicted instead of
// silently discarding bindings.
//
// The destination MUST be empty — see the assertion in the body. adopt appends
// rather than merging, so it cannot preserve expiry ordering against
// pre-existing entries, and every other operation depends on that ordering.
func (t *pendingTableOf[K]) adopt(slots []pendingSlotOf[K]) {
	if t == nil || len(slots) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// PRECONDITION: the destination must be EMPTY.
	//
	// adopt appends; it does not merge. Migrated expiries are whatever the old
	// table held, so appending them onto a non-empty ring can place an EARLIER
	// expiry after a later one and break the expiry ordering every other
	// operation depends on — the full-drain probe would read a stale-but-newer
	// tail slot and wrongly conclude the whole ring had expired, wiping live
	// destination bindings, and both the head drain and occupancy's binary
	// search would mis-locate the boundary.
	//
	// This is a programmer-error assertion, not a runtime condition: the
	// production callers (the v4/v6 apply phase-2.5 migrations) adopt into
	// tables built moments earlier and never launched, so it cannot fire.
	// Failing loudly here is deliberate — the alternative is silent corruption
	// of the structure that decides which replies reach clients. An ordered
	// merge would make the general case work, but no caller needs it and it is
	// not worth the complexity on a security-relevant path.
	if t.count != 0 {
		panic("dhcprelay: pendingTable.adopt requires an empty destination " +
			"(appending would break the ring's expiry ordering)")
	}
	if capacity := len(t.ring); len(slots) > capacity {
		t.evicted += uint64(len(slots) - capacity)
		slots = slots[len(slots)-capacity:] // keep the NEWEST (longest-lived)
	}
	for _, s := range slots {
		t.pushLocked(s.key, s.exp)
	}
}

// evictions returns the cap-pressure eviction count.
func (t *pendingTableOf[K]) evictions() uint64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evicted
}

// occupancy returns the number of RING SLOTS in use — the quantity that is
// actually compared against capacity, and therefore the one that predicts
// eviction. Surfaced as RelayStats.PendingSize.
//
// It is deliberately NOT len(entries), which diverges from ring pressure in
// both directions and would make the gauge lie:
//
//   - too LOW under ordinary duplicate inserts: a retransmission consumes a
//     ring slot without adding a map entry, so a capacity-4 ring holding
//     A,B,B,B reports len(entries)==2 while the very next insert must evict
//     live A. Eviction would begin while the displayed ratio still looked
//     comfortable — the exact opposite of the documented contract.
//   - too HIGH on an idle relay: expired entries are reclaimed lazily.
//
// The raw ring `count` is not right either, and for the SAME false-high
// reason: expired slots stay counted until some later insert reclaims them, so
// an idle full table would report capacity/capacity even though the very next
// insert reclaims the lot and evicts nothing. An operator told to alert on the
// ratio would be paged by a relay that is simply quiet.
//
// So: unexpired ring slots. The expired ones form a contiguous PREFIX (the ring
// is expiry-ordered), so the boundary is a binary search rather than a walk —
// O(log capacity) under the mutex, which matters because this is read by
// Stats() while the packet path is running.
//
// Use liveEntries for the count of distinct bindable keys.
func (t *pendingTableOf[K]) occupancy() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count - t.expiredPrefixLocked(t.now())
}

// expiredPrefixLocked returns how many slots at the head have expired. The ring
// is expiry-ordered, so expired slots are a contiguous prefix and the first
// unexpired index can be found by binary search. Caller holds mu.
func (t *pendingTableOf[K]) expiredPrefixLocked(now time.Time) int {
	lo, hi := 0, t.count
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if now.Before(t.ring[(t.head+mid)%len(t.ring)].exp) {
			hi = mid // unexpired: the boundary is at or before mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

// liveEntries returns the number of distinct keys currently in the map. Expired
// entries are reclaimed lazily (on the next insert), so on an idle relay this
// can include entries past their expiry; they are inert either way because
// matches re-checks the expiry. Diagnostic/test accessor — the operator-facing
// gauge is occupancy.
func (t *pendingTableOf[K]) liveEntries() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// capacity returns the table's fixed entry ceiling.
func (t *pendingTableOf[K]) capacity() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ring)
}

// scans returns the number of ring slots examined by the expiry/eviction path.
// Test probe for the O(1) invariant; see slotScans.
func (t *pendingTableOf[K]) scans() uint64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.slotScans
}
