package authz

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// peer.go answers "who is on the other end of this connection" from the
// kernel's own socket table (#5561).
//
// # Why not SO_PEERCRED
//
// SO_PEERCRED answers exactly this, but only for AF_UNIX. The management API is
// an AF_INET listener (`system services web-management` binds host:port), so it
// returns nothing here. Moving the surface to a Unix socket would answer it too,
// at the cost of a new transport, a new config knob, packaging changes and a
// client migration — for an identity the kernel already exposes on the socket we
// have.
//
// # Why not SOCK_DIAG / netlink
//
// The first version of this file asked INET_DIAG via netlink.SocketGet, on the
// assumption that a request carrying a full 4-tuple is answered for that
// 4-tuple. **It is not, and the resulting lookup was spoofable.**
//
// netlink.SocketGet (v1.3.1) issues SOCK_DIAG_BY_FAMILY with NLM_F_DUMP. The
// kernel's inet_diag_dump_icsk filters a dump on family, states, idiag_sport and
// idiag_dport — the ADDRESSES in the request's id are ignored. The library then
// returns msgs[0] whenever two or fewer sockets matched, without comparing the
// reply's SocketID against what was asked. Identity was therefore decided by
// (family, source port, destination port) alone.
//
// Demonstrated: with a single real socket at 127.0.0.2:35591 -> 127.0.0.1:38849,
// a query for 127.0.0.9:35591 -> 127.0.0.1:38849 — an address with no socket at
// all — returned uid 1000, and the raw reply's id carried source 127.0.0.2. All
// of 127/8 is bindable by any local user, so an unprivileged caller that binds
// the source port of an existing root-owned connection is reported as root.
//
// The /proc parser below matched the full local AND remote address from the
// start, so it was correct — but it ran second, as a fallback, and so never ran.
// It is now the single source of truth. A "fast path" whose reply must be
// re-verified against the request buys nothing on a surface that answers a
// handful of operator actions per second, and every line of it is another place
// to assume the kernel filtered something it did not.
//
// # The three-state answer
//
// A boolean "did we get a UID" is not enough to authorize safely, because "no
// UID" has two very different meanings:
//
//   - There is no socket for this 4-tuple on this host, so the peer is a REMOTE
//     administrator, and an api-auth credential is the intended way to identify
//     it (#4047 requires one for any off-loopback bind).
//   - There IS a local caller, but it could not be attributed — its socket left
//     ESTABLISHED, or the socket table could not be read. Letting THAT fall
//     through to a credential is precisely the escalation a restricted local
//     account would engineer, so it must deny.
//
// PeerIdentity therefore reports Local separately from OK. See the type.
//
// # What "not local" is allowed to mean
//
// Absence from THIS namespace's socket table is not evidence that a caller is
// off-box: a peer in another network namespace on this same host appears in
// neither /proc/net/tcp nor net.InterfaceAddrs() here, and calling that "remote"
// would hand it the credential path — the same unsound "not found means remote"
// inference that made the half-close bypass possible.
//
// So "remote" is never inferred from a failed lookup alone. It is bounded by the
// DELIVERY address instead: a connection delivered on a loopback address is
// treated as local. Under a default configuration that is also true — martian
// filtering drops packets carrying loopback addresses that arrive on a real
// interface — but it is a CONSERVATIVE rule, not a guarantee: route_localnet=1,
// IP_TRANSPARENT and DNAT-to-loopback each defeat that filtering.
//
// The rule still fails SAFE under all three, which is why it is the one we lean
// on: each of them classifies a REMOTE caller as local, and a local caller with
// no socket row is denied. THAT RULE over-denies; it never inverts. (Scoped to
// the loopback rule — it is not a claim about the classification as a whole, two
// of whose residuals do grant; see pkg/api/README.md.)
// (The cost is a real availability residual for a remote admin behind a
// DNAT-to-loopback redirect — see pkg/api/README.md.)
//
// For a connection delivered on a routable address the distinction is genuinely
// unobservable — a container's veth peer and a remote administrator are
// indistinguishable from the socket table — and that surface is the one #4047
// requires an api-auth credential for. The residual is stated in
// pkg/api/README.md rather than papered over.
//
// # The state requirement, and the race it closes
//
// Only a socket in TCP_ESTABLISHED yields a UID.
//
// This is load-bearing. The kernel reports UID 0 for a TIME_WAIT mini-socket, so
// accepting any state would let a caller who closes its socket immediately after
// writing the request be reported as root. Requiring ESTABLISHED turns that into
// "local but unattributable" — a denial — instead of a privilege escalation.
// With the state requirement, at most one socket can be ESTABLISHED on a given
// 4-tuple and it is the caller's own, so there is nothing to substitute.

// tcpEstablished is TCP_ESTABLISHED from the kernel's include/net/tcp_states.h,
// the value /proc/net/tcp{,6} reports in its state column. It is spelled out
// here rather than imported because neither netlink nor x/sys exports the TCP
// state enum under a name that means "TCP state".
const tcpEstablished = 1

// tcpSynRecv is TCP_SYN_RECV (include/net/tcp_states.h). LookupPeer never
// attributes a row in this state; it only flags it (PeerIdentity.synRecv) so the
// CLIENT half of #14581 can wait for the server half of a connection it just
// dialed to finish its handshake (#19125, client.go).
const tcpSynRecv = 3

// procNetTCPPath and procNetTCP6Path are the socket-table sources. They are
// variables so a test can point the parser at a fixture; production never
// changes them.
var (
	procNetTCPPath  = "/proc/net/tcp"
	procNetTCP6Path = "/proc/net/tcp6"
)

// localAddrsFn lists this host's interface addresses. It is a variable so a test
// can drive the "is the peer one of our own addresses" decision deterministically
// instead of depending on the machine's interfaces.
var localAddrsFn = net.InterfaceAddrs

// localAddrTTL bounds how long a cached interface-address snapshot is reused by
// the ACCEPT-time classification below.
//
// The snapshot exists so connection churn from a routable peer cannot force one
// interface enumeration per connection. Refreshes are rate-limited to one per
// TTL regardless of hit or miss, so a flood cannot amplify through it either.
//
// # What the staleness costs, stated correctly
//
// An earlier version of this comment argued the staleness was safe on its own.
// IT WAS NOT, and the direction it named was backwards. For up to one TTL after
// an address is ADDED to this host, a caller arriving from that brand-new
// address is classified as off-box — and "off-box" is precisely the row an
// api-auth credential is allowed to speak for. The old shape of LookupPeer made
// that decisive: it asked couldBeLocal FIRST and returned "not on this host"
// without reading the socket table, so such a caller did not merely lose its
// attribution, it skipped attribution and landed on the credential row, which
// authorizes as a full-power principal. A local account that watches
// `ip monitor address` — unprivileged — and connects from a freshly added VRRP
// VIP, DHCP lease or RA-derived address inside that window escaped its login
// class through a shared secret. That is the escalation #5561 exists to
// prevent, not a residual of it.
//
// Two changes bound it, and neither is this cache:
//
//   - LookupPeer now reads the socket table FIRST and consults this
//     classification only where the table has nothing to say. A row hit proves
//     locality from the kernel, so for any caller that HAS a socket — which is
//     every caller that can read a response — a stale negative decides nothing.
//   - The one case the table cannot answer is "no row at all", and there a
//     stale negative can still say off-box. PeerCouldBeLocalNow re-derives the
//     rule from an enumeration started at the moment of use, and the credential
//     row consults it before honoring a credential.
//
// What remains is an over-denial: for at most one TTL a local caller with no
// socket row is denied rather than resolved to its class.
//
// Connections delivered on a loopback address never consult this cache at all —
// couldBeLocal short-circuits on the loopback clause — so the default
// management posture is provably unaffected either way.
const localAddrTTL = time.Second

var localAddrCache struct {
	mu      sync.Mutex
	addrs   []net.Addr
	fetched time.Time
	err     error
}

// isLocalAddr reports whether ip is assigned to an interface of this host,
// through a snapshot refreshed at most once per localAddrTTL.
//
// The refresh is rate-limited for BOTH hits and misses. An earlier version
// refreshed on every miss, which meant a connect flood from a routable address
// — the case that never matches — drove one interface enumeration per
// connection, exactly the amplification the cache exists to prevent. (The
// comment claimed otherwise; the comment was wrong.)
//
// A NEGATIVE answer from here is therefore not authoritative; see localAddrTTL
// for what that costs and PeerCouldBeLocalNow for the check that bounds it.
//
// A failure to enumerate interfaces answers true — fail closed, so an
// unenumerable host does not classify a local caller as remote and hand it the
// credential path.
func isLocalAddr(ip net.IP) bool {
	localAddrCache.mu.Lock()
	defer localAddrCache.mu.Unlock()

	if localAddrCache.fetched.IsZero() || time.Since(localAddrCache.fetched) > localAddrTTL {
		localAddrCache.addrs, localAddrCache.err = localAddrsFn()
		localAddrCache.fetched = time.Now()
	}
	if localAddrCache.err != nil {
		return true
	}
	return addrsContain(localAddrCache.addrs, ip)
}

// addrsContain reports whether ip appears in an interface-address list.
func addrsContain(addrs []net.Addr, ip net.IP) bool {
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP.Equal(ip) {
				return true
			}
		case *net.IPAddr:
			if v.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// resetLocalAddrCacheForTest drops the cached snapshot so a test that swaps
// localAddrsFn observes the new value immediately.
func resetLocalAddrCacheForTest() {
	localAddrCache.mu.Lock()
	defer localAddrCache.mu.Unlock()
	localAddrCache.fetched = time.Time{}
	localAddrCache.addrs, localAddrCache.err = nil, nil
}

// hostAddrScan is the single-flight scheduler for AUTHORITATIVE interface
// enumerations — the ones whose answer may ADMIT a caller rather than deny one.
//
// It is deliberately NOT the localAddrTTL cache. That cache serves the
// accept-time classification, where a stale answer costs at most an
// attribution; this one serves the credential row, where a stale answer costs
// the security property, so it never reuses an observation older than the call
// that asked for it.
//
// The batching argument is socketscan.go's, applied to the address table for
// the same reason: the waiter set is taken under the same lock it was appended
// under, and the enumeration begins after that swap — so no caller is ever
// answered from an observation older than its own arrival. See now() for the
// cost that buys and, precisely, the promise it does NOT make.
type hostAddrScanner struct {
	mu      sync.Mutex
	waiters []chan hostAddrs
	running bool
}

// hostAddrs is one completed enumeration.
type hostAddrs struct {
	addrs []net.Addr
	err   error
}

var hostAddrScan hostAddrScanner

// hostAddrScans counts completed authoritative enumerations, so a test can
// assert the COST property (N concurrent confirmations must not cost N
// enumerations) rather than merely that the answer is fresh.
var hostAddrScans atomic.Uint64

// HostAddrScansForTest returns the number of authoritative interface
// enumerations performed so far. Test-only; dep-free, so no test-only import
// leaks into the production binary.
func HostAddrScansForTest() uint64 { return hostAddrScans.Load() }

// maxHostAddrWaiters caps the enumeration queue, for the same reason
// socketscan.go caps its own: every waiter is a goroutine blocked in
// PeerCouldBeLocalNow, and a wedged enumeration would otherwise accumulate them
// without limit. Past the cap the caller is answered with an error, which
// PeerCouldBeLocalNow turns into "local" — a DENIAL, so saturation cannot admit.
//
// Reaching it requires a VALID credential (the call is made after s.credential),
// so this is not an uncredentialed amplification; it is a bound on a queue that
// otherwise had none.
const maxHostAddrWaiters = 4096

// now returns an enumeration that STARTED after this call began.
//
// A caller that arrives while a scan is in flight is NOT served by that scan —
// run() took its batch before the scan started — so it waits for the NEXT one.
// The promise is therefore "callers that overlap a scan share the scan after
// it", i.e. enumerations are bounded by elapsed time over scan duration rather
// than by caller count. It is NOT "N callers cost one scan": N callers arriving
// one per scan really do cost N sequential scans. That is the price of the
// freshness guarantee — an answer may never come from an observation older than
// its own arrival — and it is why this path sits behind the credential check.
func (h *hostAddrScanner) now() hostAddrs {
	ch := make(chan hostAddrs, 1)
	h.mu.Lock()
	if len(h.waiters) >= maxHostAddrWaiters {
		h.mu.Unlock()
		slog.Warn("authz: refusing locality re-derivation, enumeration queue saturated",
			"waiters", maxHostAddrWaiters)
		return hostAddrs{err: errHostAddrQueueFull}
	}
	h.waiters = append(h.waiters, ch)
	if !h.running {
		h.running = true
		go h.run()
	}
	h.mu.Unlock()
	return <-ch
}

// errHostAddrQueueFull is returned when the enumeration queue is at its cap.
var errHostAddrQueueFull = errors.New("interface-enumeration queue is saturated")

// run drains batches until none are pending. Each iteration takes the whole
// waiter set BEFORE enumerating, so every waiter in it arrived strictly before
// that enumeration began.
func (h *hostAddrScanner) run() {
	for {
		h.mu.Lock()
		waiters := h.waiters
		h.waiters = nil
		if len(waiters) == 0 {
			h.running = false
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()

		addrs, err := localAddrsFn()
		hostAddrScans.Add(1)
		snap := hostAddrs{addrs: addrs, err: err}
		for _, ch := range waiters {
			ch <- snap
		}
	}
}

// PeerCouldBeLocalNow re-derives couldBeLocal's verdict for an accepted
// connection from an interface enumeration STARTED BY THIS CALL.
//
// # Why a second check exists at all
//
// LookupPeer reads the socket table first, so a caller that has a socket is
// answered by the kernel and the cached snapshot decides nothing for it. One
// case is left over: NO ROW AT ALL. There the classification is all we have, its
// snapshot lags an address ADD by up to localAddrTTL, and the answer it can give
// — "not on this host" — is the sole row an api-auth credential may speak for.
//
// That case is reachable: a local caller from a brand-new address that reset its
// own socket before the read has no row. It cannot read a response, but the
// handler still runs, so a fire-and-forget mutation is a real outcome. A caller
// must therefore never be admitted through that row on the strength of a cached
// observation — hence this call, which the credential path makes at the moment
// the credential is about to be honored (pkg/api's principal()).
//
// # Why it cannot itself become a bypass
//
// It is a ONE-WAY narrowing. LookupPeer already denied everything it classified
// as local, so this check can only turn an admission into a denial; there is no
// input for which it turns a denial into an admission. Its own failure modes —
// an address pair we cannot classify, an unusable address list, a saturated
// queue — answer true (local, deny), so a broken enumeration costs availability,
// never authority.
//
// # What FALSE means, and what it does NOT mean
//
// False means "this host is not holding that address at this instant". It is NOT
// proof the caller is off-box, and the difference is not academic on this
// product.
//
// Errors fail closed; successful OMISSIONS cannot. A clean no-match is
// indistinguishable between "genuinely remote", "in another network namespace"
// (both halves of the lookup are namespace-scoped — see pkg/api/README.md), and
// "was on this host a moment ago and is not now". The last one is reachable
// without the caller doing anything privileged: it can ride address churn the
// SYSTEM performs. A VRRP VIP moves on every failover, DHCP renews, RAs come and
// go. A caller need only be adjudicated while its source address is between
// owners.
//
// Both observations are used rather than one. The accept-time verdict is still
// consulted — pkg/api's principal() denies on id.Local BEFORE it reaches the
// credential row — so a caller this host could place at accept is denied no
// matter what a later enumeration says, and this check adds denials for callers
// that only became placeable afterwards. What neither observation covers is an
// address that appeared AND vanished between them; closing that would need
// address-change notification (RTM_NEWADDR) rather than two point samples, and
// is not attempted here.
//
// So the honest statement of the bound is not "a caller that gets past this is
// off-box". It is: a caller this host cannot place is governed by the api-auth
// credential, which is exactly what #4047 makes that credential for.
//
// # Why re-checking here is sound when re-checking the SOCKET TABLE would not be
//
// The socket-table answer is caller-controlled: a caller can destroy its own
// socket between accept and request (which is why LookupPeer resolves identity
// at accept, not at request time). Host addresses are not caller-controlled —
// adding or removing one needs CAP_NET_ADMIN, i.e. a principal that is already
// authorized — so asking this question later cannot be gamed by the caller.
//
// # Cost
//
// Measured at ~32 µs per enumeration on a box carrying 14 addresses, against
// 4.3-10.1 ms for one /proc/net/tcp read. It runs only for a request that
// presented a VALID credential on a connection already classified off-box: a
// caller with no credential — the flooding population — forces none at all, and
// concurrent ones collapse into a single enumeration through hostAddrScan.
func PeerCouldBeLocalNow(client, server net.Addr) bool {
	ct, cok := client.(*net.TCPAddr)
	st, sok := server.(*net.TCPAddr)
	if !cok || !sok || ct.IP == nil || st.IP == nil {
		// Not a shape we classify; LookupPeer reports every one of these as
		// local already, so agree rather than admit.
		return true
	}
	if loopbackDelivery(ct, st) {
		return true
	}
	snap := hostAddrScan.now()
	if snap.err != nil {
		return true
	}
	return addrsContain(snap.addrs, ct.IP)
}

// PeerIdentity is what the kernel could tell us about the far end of an accepted
// connection.
//
//	OK     Local  meaning                              caller must
//	-----  -----  -----------------------------------  ---------------------------
//	true   true   attributed local caller              use UID
//	false  true   local, but not attributable          DENY — never substitute a
//	                                                   credential for it
//	false  false  no socket here; the peer is off-box  a credential may identify it
//
// The (false, false) row is the ONLY one in which an api-auth credential may
// speak for the caller.
type PeerIdentity struct {
	// UID owns the peer socket. Meaningful only when OK.
	UID uint32
	// OK reports that UID was read from a socket in TCP_ESTABLISHED whose local
	// and remote addresses both matched this connection exactly.
	OK bool
	// Local reports that the caller is on THIS host — either its socket was
	// found (in any state), or its address is one of ours. When Local is set and
	// OK is not, the caller is present but unattributable and must be denied.
	Local bool
	// Detail explains a missing or unusable identity, for the denial message and
	// the audit log. Never carries a secret.
	Detail string
	// synRecv reports that the matching row was found in TCP_SYN_RECV (never
	// with OK). Only the client half reads it, to re-read the table for a
	// bounded time (#19125, client.go); it attributes nothing.
	synRecv bool
}

// LookupPeer identifies the peer end of an accepted TCP connection, where
// `client` is the connection's remote address (as seen by this server) and
// `server` is its local address.
//
// It never returns an error: every outcome is one of the three rows in
// PeerIdentity, and the caller's obligation differs per row. Failing to read the
// socket table is reported as Local (deny), not as "remote" — an unreadable
// table is a reason to refuse, not a reason to believe the caller is elsewhere.
func LookupPeer(client, server net.Addr) PeerIdentity {
	ct, ok := client.(*net.TCPAddr)
	if !ok {
		// A non-TCP peer (e.g. a future Unix socket) is on this host by
		// construction, and this function cannot attribute it.
		return PeerIdentity{Local: true, Detail: fmt.Sprintf("peer address %v is not TCP", client)}
	}
	st, ok := server.(*net.TCPAddr)
	if !ok {
		return PeerIdentity{Local: true, Detail: fmt.Sprintf("local address %v is not TCP", server)}
	}
	if ct.IP == nil || st.IP == nil {
		return PeerIdentity{Local: true, Detail: "connection has no address"}
	}
	// Refuse a query whose two endpoints are identical: such a 4-tuple matches
	// OUR OWN socket as readily as a peer's, and ours is owned by the daemon's
	// UID (root), so it would report the daemon as the caller. A TCP self-connect
	// on the management port is not reachable in practice (the listener holds the
	// port), but a guard that costs one comparison is cheaper than the argument
	// that it cannot happen.
	if ct.Port == st.Port && ct.IP.Equal(st.IP) {
		return PeerIdentity{Local: true, Detail: "peer and local addresses are identical"}
	}
	// A ZONED (scope-qualified) peer address cannot be ATTRIBUTED. /proc/net/tcp6
	// prints only the 128 address bits, never the scope id, so two link-local
	// callers on different interfaces render the identical key and the first
	// established row would win — an order-dependent identity, the same defect
	// class as matching on ports alone. Refuse to guess: no scoped peer is ever
	// given a UID, whatever the table says.
	//
	// The table is still READ. Refusing to attribute is not a reason to skip the
	// observation — a matching row proves a socket exists on this host for those
	// 128 bits and ports even though it names nobody, and answering from the
	// cached address classification alone was a zero-observation fail-open (see
	// the block below). An earlier version of this header said "skip the table
	// entirely and decide locality from the addresses", which is what the code
	// did before that fail-open was closed; it is stated here because a reviewer
	// who reads this preamble and stops is the way that early-out gets
	// reinstated.
	//
	// The refusal to attribute must NOT become a blanket denial. A scoped peer
	// that is not on this host is a remote administrator reaching an IPv6
	// link-local management bind, and denying it locked out every credentialed
	// remote on such a bind. So only a scoped peer we would otherwise have to
	// attribute is refused. The SERVER's zone is not disqualifying on its own —
	// the client column still selects the row.
	if ct.Zone != "" {
		// Consult the table anyway. We cannot ATTRIBUTE from it — /proc carries
		// no scope id — but a matching row still PROVES a socket exists on this
		// host for those 128 bits and ports, and that is evidence of locality
		// even when it names nobody. Skipping the read and answering from the
		// cached classification alone was the same zero-observation fail-open
		// this function's error path was corrected for one branch up: a scoped
		// caller the snapshot did not recognise went off-box — the credential
		// row — without anything ever being read.
		_, _, found, malformed, err := findPeerSocket(ct, st)
		switch {
		case err != nil:
			return PeerIdentity{Local: true, Detail: "socket table unreadable: " + err.Error()}
		case found || malformed:
			return PeerIdentity{
				Local:  true,
				Detail: fmt.Sprintf("peer address %v is scope-qualified and cannot be attributed from the socket table", ct),
			}
		}
		// No row, and the table was readable: the observation was actually made.
		// Only now may the address classification decide, and a scoped peer that
		// is not one of ours is a remote administrator reaching an IPv6
		// link-local management bind — denying it there locked out every
		// credentialed remote on such a bind.
		if couldBeLocal(ct, st) {
			// A DIFFERENT state from the row-found case above, and it gets a
			// different Detail (#5561 round 9, MINOR-5). Both deny, but the 403
			// body and the audit line are an operator's only handle on WHY: there
			// the kernel proved a socket exists and the scope id is what stops us
			// naming its owner; here the table was read and held nothing, and the
			// denial rests entirely on the address classification. Different
			// diagnosis, different remedy — emitting one string for both loses
			// that.
			return PeerIdentity{
				Local:  true,
				Detail: fmt.Sprintf("peer address %v is scope-qualified, has no socket-table row, and is assigned to this host", ct),
			}
		}
		return PeerIdentity{Detail: fmt.Sprintf("peer %v is not on this host", ct.IP)}
	}

	// Read the socket table FIRST, and consult the address classification only
	// where the table has nothing to say.
	//
	// The previous shape asked couldBeLocal up front and returned "not on this
	// host" without reading the table at all. That made a NEGATIVE address answer
	// decisive — and the address snapshot behind it is cached (localAddrTTL), so
	// for up to a TTL after an address was added to this host a caller arriving
	// from it did not merely lose its attribution, it SKIPPED attribution and
	// landed on the credential row. Reading the table first removes the negative
	// from that decision entirely for any caller that has a socket: a row hit
	// proves locality on its own, and it proves it from the kernel rather than
	// from a snapshot.
	//
	// The early-out existed to keep connection churn from a routable address off
	// the socket table. The single-flight batcher in socketscan.go already
	// removed that argument — measured, 120 concurrent fresh connections cost 3
	// table reads in 82 ms — so the cost it bought is no longer worth the
	// authority it gave away.
	uid, state, found, malformed, err := findPeerSocket(ct, st)
	if err != nil {
		// A failed table read is UNKNOWN, and unknown must deny (#5561 round 7).
		//
		// This used to fall back to the address classification in both
		// directions, so a caller the cached snapshot did not recognise was
		// reported off-box — credential-eligible — on the strength of an
		// observation we never actually made. The caller's row may be in exactly
		// the file that failed: tcp and tcp6 are alternatives, not duplicates,
		// and a partial failure is half an observation rather than a small one.
		//
		// The cost is real and is the right trade: while /proc/net/tcp{,6} is
		// unreadable, a remote administrator holding a valid credential is denied
		// too. That is an outage on a box whose /proc is broken, against handing
		// a local caller the credential path — and only the second one is a
		// privilege boundary. An ABSENT table is not a failure (scanBatch), so
		// an IPv6-less kernel does not take this path.
		return PeerIdentity{Local: true, Detail: "socket table unreadable: " + err.Error()}
	}
	if malformed {
		// A row matched this 4-tuple but its state or uid column would not parse.
		// A socket exists here, so the caller is LOCAL; we just cannot say who it
		// is. Reporting "no row" instead would route it through the address
		// classification and, on a stale negative, to the credential.
		return PeerIdentity{Local: true, Detail: "peer socket row could not be parsed"}
	}
	if found && state == tcpEstablished {
		return PeerIdentity{UID: uid, OK: true, Local: true}
	}
	if found {
		return PeerIdentity{
			Local:   true,
			Detail:  fmt.Sprintf("peer socket is in TCP state %d, not established", state),
			synRecv: state == tcpSynRecv,
		}
	}
	// No row at all. This is the ONLY place the address classification still
	// decides, and the only place its cached NEGATIVE can still reach the
	// credential row: a local caller that destroyed its own socket (an SO_LINGER-0
	// reset) before the read, from an address added within the last TTL, is
	// reported off-box. Such a caller cannot read a response, but the handler
	// still runs, so the residual is real rather than cosmetic. PeerCouldBeLocalNow
	// narrows it one layer up — it catches such a caller whenever the address is
	// STILL on this host when the credential is adjudicated, and cannot when the
	// address has since moved (see that function's "What FALSE means").
	if couldBeLocal(ct, st) {
		return PeerIdentity{Local: true, Detail: "local peer has no established socket"}
	}
	return PeerIdentity{Detail: fmt.Sprintf("peer %v is not on this host", ct.IP)}
}

// couldBeLocal reports whether the peer of an accepted connection is on THIS
// host, decided from addresses alone.
//
// The loopback clause is the load-bearing one: a connection DELIVERED on a
// loopback address is treated as local, which covers the entire default
// management posture — a caller reaching the default bind is local no matter
// what the socket table says, and no credential can speak for it. It is a
// conservative rule rather than a kernel guarantee (see the file comment), and
// its failure mode is over-denial, not admission.
//
// For a routable delivery address the answer falls back to "is the peer one of
// OUR addresses", which is sound in the positive direction and admits the netns
// residual documented in pkg/api/README.md in the negative one.
//
// The address fallback reads a CACHED snapshot, so its negative answer is not
// authoritative — see localAddrTTL. PeerCouldBeLocalNow re-derives the same rule
// from a fresh enumeration for the one caller that acts on the negative.
func couldBeLocal(client, server *net.TCPAddr) bool {
	if loopbackDelivery(client, server) {
		return true
	}
	return isLocalAddr(client.IP)
}

// loopbackDelivery is the address-only half of couldBeLocal, factored out so the
// cached classifier and the authoritative re-derivation cannot drift apart on
// it. It depends on nothing that can go stale.
func loopbackDelivery(client, server *net.TCPAddr) bool {
	return server.IP.IsLoopback() || client.IP.IsLoopback()
}

// LoopbackDeliveryCannotEnumerate reports whether a connection between these two
// addresses is answered WITHOUT consulting the interface-address cache — i.e.
// without ever reaching localAddrsFn and the mutex it holds.
//
// It exists for one caller: pkg/api's accept-time admission budget (#6974),
// which bounds exactly that enumeration. A connection this returns true for
// cannot reach the wedge the budget is defending, so it does not need to spend
// that budget.
//
// SINGLE-SOURCED WITH THE SHORT-CIRCUIT ON PURPOSE. couldBeLocal returns before
// isLocalAddr for precisely these connections, and the api-side split is only
// sound while the two agree. Written as a second copy of the predicate they
// would agree until someone edited one of them, and the failure would be
// silent: connections that CAN wedge would stop spending the budget. Both call
// this function, so the agreement is structural rather than remembered.
//
// A non-TCP address answers FALSE — the conservative direction. LookupPeer
// returns early for those without consulting the cache, so a false here only
// costs a budget slot that was not needed; a true would skip the budget on a
// path this function has not actually reasoned about.
func LoopbackDeliveryCannotEnumerate(client, server net.Addr) bool {
	ct, ok := client.(*net.TCPAddr)
	if !ok {
		return false
	}
	st, ok := server.(*net.TCPAddr)
	if !ok {
		return false
	}
	if ct.IP == nil || st.IP == nil {
		return false
	}
	return loopbackDelivery(ct, st)
}

// findPeerSocket looks for the row whose LOCAL address is the client and whose
// REMOTE address is the server — the mirror of the connection this server
// accepted.
//
// Both /proc/net/tcp and /proc/net/tcp6 are consulted. Which file holds a given
// connection depends on the address family of the CLIENT's socket, which this
// server cannot observe: a caller that opened an AF_INET6 socket and connected
// to ::ffff:127.0.0.1 lands in tcp6 even though Go reports its address as plain
// 127.0.0.1. Scanning only the file implied by the Go-side address would miss
// that row and report the caller as off-box — which, under the precedence rule
// in LookupPeer's doc, hands it the credential path. The miss is therefore a
// security question, not just a robustness one, and both files are consulted.
//
// The read itself is single-flighted through socketscan.go: concurrent lookups
// share one table read, which is what keeps a connect flood from costing 6-9 ms
// of daemon CPU per connection. The batching does not weaken the guarantee that
// a connection is answered only from a read that started after it was accepted.
//
// found=false means no row matched in either file. malformed=true means a row
// DID match but its state or uid column would not parse, which proves a socket
// exists without saying who owns it. err is non-nil only when NO table could be
// read at all (an absent tcp6 alongside a readable tcp is not an error) or when
// the batcher is saturated.
func findPeerSocket(client, server *net.TCPAddr) (uid uint32, state uint64, found, malformed bool, err error) {
	q := &socketQuery{res: make(chan socketResult, 1)}
	if l, lok := procAddr4(client); lok {
		if r, rok := procAddr4(server); rok {
			q.keys = append(q.keys, scanKey{procNetTCPPath, l, r})
		}
	}
	if l, lok := procAddr6(client); lok {
		if r, rok := procAddr6(server); rok {
			q.keys = append(q.keys, scanKey{procNetTCP6Path, l, r})
		}
	}
	if len(q.keys) == 0 {
		return 0, 0, false, false, fmt.Errorf("cannot render %v -> %v for a socket-table lookup", client, server)
	}
	res := batcher.lookup(q)
	return res.uid, res.state, res.found, res.malformed, res.err
}

// procAddr4 renders a TCPAddr the way /proc/net/tcp does. ok=false when the
// address is not IPv4-representable and so cannot appear in that file.
func procAddr4(a *net.TCPAddr) (string, bool) {
	v4 := a.IP.To4()
	if v4 == nil {
		return "", false
	}
	return procAddrHex(v4, a.Port), true
}

// procAddr6 renders a TCPAddr the way /proc/net/tcp6 does — 16 bytes, so an IPv4
// address renders in its ::ffff:a.b.c.d mapped form, which is how the kernel
// reports a v4 connection made on an AF_INET6 socket.
func procAddr6(a *net.TCPAddr) (string, bool) {
	v6 := a.IP.To16()
	if v6 == nil {
		return "", false
	}
	return procAddrHex(v6, a.Port), true
}

// procAddrHex renders address bytes + port the way /proc/net/tcp{,6} does: each
// 4-byte group read back as a NATIVE-endian u32 and printed %08X, then a colon,
// then the port as %04X.
//
// That is literally what the kernel does — it prints `__be32` address words with
// %08X, so on a little-endian host the printed word is the byte-reversed
// address. 127.0.0.1:8080 becomes "0100007F:1F90"; [::1]:8080 becomes
// "00000000000000000000000001000000:1F90". Expressing it as "re-read the same
// bytes as a native u32" rather than "reverse the bytes" keeps it correct on a
// big-endian host, where the kernel prints "7F000001" instead.
func procAddrHex(ip net.IP, port int) string {
	var sb strings.Builder
	for i := 0; i+4 <= len(ip); i += 4 {
		fmt.Fprintf(&sb, "%08X", binary.NativeEndian.Uint32(ip[i:i+4]))
	}
	fmt.Fprintf(&sb, ":%04X", port)
	return sb.String()
}
