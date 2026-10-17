package ddns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// #1387 inc-2 live RFC 2136 backend tests. The key to keeping the LIVE
// backend lab-free is an in-process miekg/dns server bound on 127.0.0.1:0
// (UDP+TCP) with a real TSIG secret map: it parses real DNS UPDATE
// messages, verifies real TSIG, and records every received UPDATE so the
// test asserts the EXACT wire adds/deletes. The production *dns.Client path
// is exercised — not stubbed — so this proves the wire format end to end.

// recordedUpdate is one UPDATE the fake server received, decomposed into the
// adds (Insert) and exact-RR deletes (CLASS=NONE) the backend sent.
type recordedUpdate struct {
	zone    string
	adds    []dns.RR
	deletes []dns.RR // CLASS=NONE exact-RR deletes
	prereqs []dns.RR // Answer-section prerequisites
}

// fakeDNSServer is an in-process authoritative responder for UPDATEs.
type fakeDNSServer struct {
	t   *testing.T
	udp *dns.Server
	tcp *dns.Server

	mu      sync.Mutex
	updates []recordedUpdate

	// rcodeForZone overrides the response rcode for an UPDATE whose zone
	// (Question[0].Name, canonical) matches — used to simulate NOTAUTH on a
	// reverse zone, or a conflict (YXRRSET) on a prerequisite.
	rcodeForZone map[string]int
	// conflictPrereq, when true, answers a prerequisite-bearing UPDATE for a
	// zone in conflictZones with YXRRSET (collision). Empty conflictZones
	// means "all zones" when conflictPrereq is set.
	conflictPrereq bool
	conflictZones  map[string]bool

	// stateful, when true, makes the server maintain an in-memory zone and
	// evaluate RFC 2136 prerequisites + apply Insert/Remove against it (used by
	// the #2648 DHCID ownership tests, which need realistic NameNotUsed /
	// DHCID-match prerequisite evaluation across an add/delete sequence).
	// zone[name] is the set of RRs currently present at that owner name; the
	// value key is the RR's textual form for set semantics.
	stateful bool
	zone     map[string]map[string]dns.RR

	// truncateUDP, when set, marks every UDP reply Truncated so the client
	// retries over TCP (used to exercise the TCP-retry path).
	truncateUDP bool
	// tcpReplyDelay stalls the TCP reply so the client's read deadline (derived
	// from the caller ctx, post-fix) bounds the retry before the reply lands.
	tcpReplyDelay time.Duration

	addrUDP string
	addrTCP string
	tsig    map[string]string
}

// listenDNSPair returns a UDP PacketConn and a TCP Listener bound to the SAME
// 127.0.0.1 ephemeral port, which is what a real DNS server looks like and what
// the truncation→TCP-retry path needs to reach one address for both.
//
// UDP and TCP are independent port namespaces, so there is no portable way to
// reserve a port number in both at once; the only sound approach is to draw a
// candidate, try to complete the pair, and DRAW AGAIN on conflict (#6709).
// Every attempt uses a fresh port, so attempts are independent rather than a
// retry against a busy port.
func listenDNSPair() (net.PacketConn, net.Listener, error) {
	var lastErr error
	for i := 0; i < dnsPairAttempts; i++ {
		pc, l, err := dnsPairAttempt()
		if err == nil {
			return pc, l, nil
		}
		lastErr = err
	}
	return nil, nil, fmt.Errorf("no free udp+tcp port pair after %d attempts: %w", dnsPairAttempts, lastErr)
}

// dnsPairAttempts bounds the resample. Attempts are INDEPENDENT (each draws a
// fresh port), so the residual failure probability is the per-attempt collision
// rate raised to this power — at a measured ~0.2% that is ~1e-22.
const dnsPairAttempts = 8

// dnsPairAttempt draws ONE candidate ephemeral port and tries to complete the
// UDP+TCP pair on it. It is indirected through a var so the resample loop can
// be tested against a CONFLICTING candidate deterministically. The alternative
// — occupying a large slice of the host's real ephemeral TCP range to force a
// collision — would manufacture, for every other test process on this box,
// exactly the flake #6709/#7009 exist to remove.
var dnsPairAttempt = realDNSPairAttempt

func realDNSPairAttempt() (net.PacketConn, net.Listener, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("udp listen: %w", err)
	}
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		// That port number is taken on TCP by something else on the host.
		// Release the UDP side so the next attempt draws a different port.
		addr := pc.LocalAddr()
		_ = pc.Close()
		return nil, nil, fmt.Errorf("tcp listen on udp-assigned %s: %w", addr, err)
	}
	return pc, l, nil
}

func newFakeDNSServer(t *testing.T, tsig map[string]string) *fakeDNSServer {
	t.Helper()
	s := &fakeDNSServer{t: t, rcodeForZone: map[string]int{}, tsig: tsig}

	// Handle every message directly (no ServeMux name routing — an UPDATE's
	// "question" is the zone, and the default mux answers NOTIMP for the
	// UPDATE opcode unless a handler is registered for the exact zone name).
	handler := dns.HandlerFunc(s.handle)

	// Bind TCP on the SAME host:port the UDP socket got (UDP and TCP are
	// independent port namespaces), so a client that retries-over-TCP against
	// the single configured server address reaches this server's TCP listener
	// too — mirroring a real DNS server (UDP+TCP on :53). This makes the
	// truncation→TCP-retry path testable end to end.
	//
	// #6709/#7009: because the two namespaces are independent, the kernel
	// handing out a free UDP port says NOTHING about whether that port number
	// is free for TCP — another process on the host (a second `go test`, of
	// which this repo routinely runs a dozen) may hold it. Binding UDP once and
	// then asserting the TCP bind succeeds therefore failed ~7% of full-package
	// runs with "bind: address already in use", on a RANDOM test each time.
	//
	// RESAMPLE the pair rather than retrying a contended port. Each attempt
	// draws a FRESH ephemeral port, so this is not the retry-on-EADDRINUSE loop
	// #7009 rejects — that one re-attempts the SAME port and converts a fast
	// deterministic failure into a slow flaky one. Redrawing makes attempts
	// independent: at a measured ~0.2% per-attempt collision rate, 8 attempts
	// leave a residual around 1e-22, and the loop still fails FAST and loudly
	// if the host genuinely cannot supply a dual-stack port pair.
	pc, l, err := listenDNSPair()
	if err != nil {
		t.Fatalf("listen udp+tcp pair: %v", err)
	}
	s.addrUDP = pc.LocalAddr().String()
	s.addrTCP = l.Addr().String()

	// DefaultMsgAcceptFunc rejects the UPDATE opcode with NOTIMP; accept all
	// opcodes so the handler sees the UPDATE.
	acceptAll := func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }
	s.udp = &dns.Server{PacketConn: pc, Handler: handler, TsigSecret: tsig, MsgAcceptFunc: acceptAll}
	s.tcp = &dns.Server{Listener: l, Handler: handler, TsigSecret: tsig, MsgAcceptFunc: acceptAll}

	started := make(chan struct{}, 2)
	s.udp.NotifyStartedFunc = func() { started <- struct{}{} }
	s.tcp.NotifyStartedFunc = func() { started <- struct{}{} }
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	<-started
	<-started
	t.Cleanup(func() {
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
	})
	return s
}

func (s *fakeDNSServer) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	zone := ""
	if len(r.Question) > 0 {
		zone = dns.CanonicalName(r.Question[0].Name)
	}

	rec := recordedUpdate{zone: zone}
	for _, rr := range r.Ns {
		switch rr.Header().Class {
		case dns.ClassNONE:
			rec.deletes = append(rec.deletes, rr)
		case dns.ClassANY:
			// delete-RRset / delete-name (the backend must NEVER send these).
			rec.deletes = append(rec.deletes, rr)
		default:
			rec.adds = append(rec.adds, rr)
		}
	}
	rec.prereqs = append(rec.prereqs, r.Answer...)

	overTCP := w.RemoteAddr() != nil && strings.HasPrefix(w.RemoteAddr().Network(), "tcp")

	s.mu.Lock()
	s.updates = append(s.updates, rec)
	override, hasOverride := s.rcodeForZone[zone]
	conflict := s.conflictPrereq && (len(s.conflictZones) == 0 || s.conflictZones[zone])
	truncate := s.truncateUDP && !overTCP
	tcpDelay := s.tcpReplyDelay
	statefulRcode := 0
	statefulSet := false
	// A real authoritative server that answers an error rcode (SERVFAIL,
	// NOTAUTH, REFUSED, ...) does NOT apply the update. An explicit error
	// override therefore SUPPRESSES the stateful apply, so a re-attempt of a
	// failed update sees the record as still-absent (the #2661 PTR-retry path
	// depends on this: a PTR that SERVFAILed must not silently land in the
	// zone, or the retry's name-not-in-use prerequisite would falsely collide).
	overrideIsError := hasOverride && override != dns.RcodeSuccess
	if s.stateful && !overrideIsError {
		statefulRcode = s.evalStatefulLocked(r)
		statefulSet = true
	}
	s.mu.Unlock()
	// Mark a UDP reply Truncated to drive the client into the TCP-retry path.
	if truncate {
		m.Truncated = true
	}
	// Stall the TCP reply so the client's (caller-derived) read deadline can
	// bound the retry before the reply lands.
	if overTCP && tcpDelay > 0 {
		time.Sleep(tcpDelay)
	}

	// TSIG: when the request is signed and verification FAILED, reject with
	// NOTAUTH and an unsigned reply so the client surfaces an error (a wrong
	// shared secret must not silently succeed).
	signed := r.IsTsig() != nil
	tsigBad := signed && w.TsigStatus() != nil
	switch {
	case tsigBad:
		m.Rcode = dns.RcodeNotAuth
	case hasOverride:
		m.Rcode = override
	case conflict && len(r.Answer) > 0:
		// A prerequisite present + conflict flag → simulate a collision.
		m.Rcode = dns.RcodeYXRrset
	case statefulSet:
		m.Rcode = statefulRcode
	default:
		m.Rcode = dns.RcodeSuccess
	}

	// Sign the reply only when the request TSIG verified, so the client's
	// reply-verification succeeds on the happy path.
	if signed && !tsigBad && len(s.tsig) > 0 {
		t := r.IsTsig()
		m.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
	}
	_ = w.WriteMsg(m)
}

// rrKey is the set-membership key for an RR within a name (type + rdata).
func rrKey(rr dns.RR) string {
	h := rr.Header()
	// String() includes the full rdata; strip the leading header text so the
	// key is type+rdata (TTL/class differences must not split a logical RR).
	return dns.TypeToString[h.Rrtype] + "|" + rrRdataString(rr)
}

// rrRdataString returns the rdata portion of an RR's text form (everything
// after the standard header fields name/ttl/class/type).
func rrRdataString(rr dns.RR) string {
	full := rr.String()
	// dns RR String() is "<name>\t<ttl>\t<class>\t<type>\t<rdata>"; take the
	// 5th tab-separated field onward as rdata.
	parts := strings.SplitN(full, "\t", 5)
	if len(parts) == 5 {
		return parts[4]
	}
	return full
}

// evalStatefulLocked evaluates RFC 2136 prerequisites against the in-memory
// zone and, on success, applies the update section (Insert / exact-RR Remove).
// It supports exactly the prerequisite kinds the backend uses:
//   - NameNotUsed  (ANY type, ClassNONE)      — name must have NO records.
//   - RRsetNotUsed (specific type, ClassNONE) — that RRset must not exist.
//   - Used         (value-dependent, ClassINET w/ rdata) — that exact RR must
//     exist (DHCID-match).
//
// Returns the rcode the server should answer with. Caller holds s.mu.
func (s *fakeDNSServer) evalStatefulLocked(r *dns.Msg) int {
	if s.zone == nil {
		s.zone = map[string]map[string]dns.RR{}
	}
	// 1) Check prerequisites (Answer section).
	for _, pre := range r.Answer {
		h := pre.Header()
		name := dns.CanonicalName(h.Name)
		set := s.zone[name]
		switch h.Class {
		case dns.ClassNONE:
			if h.Rrtype == dns.TypeANY {
				// NameNotUsed: the name must have no records.
				if len(set) > 0 {
					return dns.RcodeYXDomain
				}
			} else {
				// RRsetNotUsed: no RR of this type may exist.
				for _, rr := range set {
					if rr.Header().Rrtype == h.Rrtype {
						return dns.RcodeYXRrset
					}
				}
			}
		case dns.ClassINET:
			// Used (value-dependent RRset exists): this exact RR must exist.
			if _, ok := set[rrKey(pre)]; !ok {
				return dns.RcodeNXRrset
			}
		}
	}
	// 2) Apply the update section (Ns).
	for _, rr := range r.Ns {
		h := rr.Header()
		name := dns.CanonicalName(h.Name)
		switch h.Class {
		case dns.ClassNONE:
			// Exact-RR delete.
			if set := s.zone[name]; set != nil {
				delete(set, rrKey(rr))
				if len(set) == 0 {
					delete(s.zone, name)
				}
			}
		case dns.ClassANY:
			// CLASS=ANY: delete-name (Rrtype ANY) OR delete-RRset (a specific
			// Rrtype). The lease path never sends these, but the #2691 P2
			// self-owned forward replace (sendAddSelfOwned) sends a delete-RRset
			// of OUR forward type in the SAME message as the Insert (atomic
			// in-place replace). Honor the RFC 2136 §2.5.1/§2.5.2 distinction so
			// the test verifies the delete is scoped to OUR type and never harms a
			// co-resident RR of a DIFFERENT type at the name.
			if h.Rrtype == dns.TypeANY {
				delete(s.zone, name)
			} else if set := s.zone[name]; set != nil {
				for k, rr := range set {
					if rr.Header().Rrtype == h.Rrtype {
						delete(set, k)
					}
				}
				if len(set) == 0 {
					delete(s.zone, name)
				}
			}
		default:
			// Insert.
			if s.zone[name] == nil {
				s.zone[name] = map[string]dns.RR{}
			}
			s.zone[name][rrKey(rr)] = dns.Copy(rr)
		}
	}
	return dns.RcodeSuccess
}

// seedRR injects a record into the stateful zone as if a third party (or a
// prior xpf add) had published it.
func (s *fakeDNSServer) seedRR(rr dns.RR) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.zone == nil {
		s.zone = map[string]map[string]dns.RR{}
	}
	name := dns.CanonicalName(rr.Header().Name)
	if s.zone[name] == nil {
		s.zone[name] = map[string]dns.RR{}
	}
	s.zone[name][rrKey(rr)] = dns.Copy(rr)
}

// zoneHas reports whether the stateful zone currently holds an RR equal to the
// given one (type + rdata) at its name.
func (s *fakeDNSServer) zoneHas(rr dns.RR) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := dns.CanonicalName(rr.Header().Name)
	set := s.zone[name]
	if set == nil {
		return false
	}
	_, ok := set[rrKey(rr)]
	return ok
}

func (s *fakeDNSServer) recorded() []recordedUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]recordedUpdate, len(s.updates))
	copy(out, s.updates)
	return out
}

// The setters below mutate handler-read fields under s.mu so tests configuring
// the server cannot race a lingering in-flight handler goroutine (the handler
// reads every such field under s.mu). All test configuration of the server
// MUST go through these rather than touching the fields directly.

func (s *fakeDNSServer) setRcode(zone string, rcode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rcodeForZone[dns.CanonicalName(zone)] = rcode
}

func (s *fakeDNSServer) clearRcode(zone string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rcodeForZone, dns.CanonicalName(zone))
}

func (s *fakeDNSServer) setConflict(prereq bool, zones map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conflictPrereq = prereq
	s.conflictZones = zones
}

func (s *fakeDNSServer) setStateful(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateful = on
	if on && s.zone == nil {
		s.zone = map[string]map[string]dns.RR{}
	}
}

func (s *fakeDNSServer) setTruncate(truncate bool, tcpDelay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.truncateUDP = truncate
	s.tcpReplyDelay = tcpDelay
}

// testUpdater builds an rfc2136Updater pointed at the fake server, using a
// real *dns.Client (UDP). Counters are captured into the returned closures.
func testUpdater(t *testing.T, srv *fakeDNSServer, c *config.DHCPDynamicDNSConfig, ptrNotAuth, conflict *int) *rfc2136Updater {
	t.Helper()
	c.UpdateServer = srv.addrUDP
	pol := policyFromConfig(c)
	u, err := newRFC2136Updater(pol, c, nil,
		func() { *ptrNotAuth++ },
		func() { *conflict++ })
	if err != nil {
		t.Fatalf("newRFC2136Updater: %v", err)
	}
	// Point the real client at our server; UDP only (the fake never
	// truncates). Keep TSIG from the constructor.
	if cl, ok := u.client.(*dns.Client); ok {
		cl.Timeout = 3 * time.Second
	}
	return u
}

func recV4(fqdn, addr string, ttl int) LeaseDNSRecord {
	a := netip.MustParseAddr(addr)
	return LeaseDNSRecord{FQDN: fqdn, Addr: a, TTL: ttl, ForwardType: "A", PTRName: reversePTRName(a)}
}

func recV6(fqdn, addr string, ttl int) LeaseDNSRecord {
	a := netip.MustParseAddr(addr)
	return LeaseDNSRecord{FQDN: fqdn, Addr: a, TTL: ttl, ForwardType: "AAAA", PTRName: reversePTRName(a)}
}

func TestRFC2136UpsertV4AddsForwardAndReverse(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	if err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	ups := srv.recorded()
	if len(ups) != 2 {
		t.Fatalf("want 2 UPDATEs (forward + reverse), got %d", len(ups))
	}
	// Forward: an A add in zone example.com., NO delete.
	fwd := ups[0]
	if fwd.zone != "example.com." {
		t.Errorf("forward zone = %q, want example.com.", fwd.zone)
	}
	if len(fwd.deletes) != 0 {
		t.Errorf("forward upsert must NOT delete-RRset; got %d deletes (R1 cardinal sin)", len(fwd.deletes))
	}
	if len(fwd.adds) != 1 {
		t.Fatalf("want 1 forward add, got %d", len(fwd.adds))
	}
	a, ok := fwd.adds[0].(*dns.A)
	if !ok || a.A.String() != "10.0.1.5" || a.Hdr.Name != "laptop.example.com." {
		t.Errorf("forward add wrong: %+v", fwd.adds[0])
	}
	if a.Hdr.Ttl != 300 {
		t.Errorf("forward TTL = %d, want 300", a.Hdr.Ttl)
	}
	// Reverse: a PTR add in 1.0.10.in-addr.arpa.
	rev := ups[1]
	if rev.zone != "1.0.10.in-addr.arpa." {
		t.Errorf("reverse zone = %q, want 1.0.10.in-addr.arpa.", rev.zone)
	}
	if len(rev.adds) != 1 {
		t.Fatalf("want 1 reverse add, got %d", len(rev.adds))
	}
	ptrRR, ok := rev.adds[0].(*dns.PTR)
	if !ok || ptrRR.Ptr != "laptop.example.com." {
		t.Errorf("reverse PTR wrong: %+v", rev.adds[0])
	}
}

func TestRFC2136UpsertV6AddsAAAAAndIP6Arpa(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	if err := u.UpsertLease(context.Background(), recV6("server6.example.com", "2001:db8::5", 600)); err != nil {
		t.Fatalf("UpsertLease v6: %v", err)
	}
	ups := srv.recorded()
	if len(ups) != 2 {
		t.Fatalf("want 2 UPDATEs, got %d", len(ups))
	}
	if _, ok := ups[0].adds[0].(*dns.AAAA); !ok {
		t.Errorf("forward add is not AAAA: %+v", ups[0].adds[0])
	}
	if !strings.HasSuffix(ups[1].zone, ".ip6.arpa.") {
		t.Errorf("reverse zone %q is not ip6.arpa", ups[1].zone)
	}
}

func TestRFC2136DeleteIsExactRRNotRRset(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	if err := u.DeleteLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("DeleteLease: %v", err)
	}
	ups := srv.recorded()
	if len(ups) != 2 {
		t.Fatalf("want 2 UPDATEs (forward + reverse delete), got %d", len(ups))
	}
	fwd := ups[0]
	if len(fwd.adds) != 0 {
		t.Errorf("delete must not add; got %d adds", len(fwd.adds))
	}
	if len(fwd.deletes) != 1 {
		t.Fatalf("want 1 forward delete, got %d", len(fwd.deletes))
	}
	d := fwd.deletes[0]
	// EXACT-RR delete: CLASS=NONE, TTL=0, carries the exact rdata (an A, not
	// an ANY/delete-RRset). This is the R1 cardinal-sin guard.
	if d.Header().Class != dns.ClassNONE {
		t.Errorf("delete class = %d, want NONE (exact-RR delete, not delete-RRset)", d.Header().Class)
	}
	if d.Header().Ttl != 0 {
		t.Errorf("delete TTL = %d, want 0 (RFC 2136 §2.5.4)", d.Header().Ttl)
	}
	a, ok := d.(*dns.A)
	if !ok {
		t.Fatalf("delete RR is not an exact A (got %T) — a co-resident record on the same name would be collateral", d)
	}
	if a.A.String() != "10.0.1.5" {
		t.Errorf("delete rdata = %s, want 10.0.1.5", a.A.String())
	}
}

func TestRFC2136UpsertNeverSendsDeleteRRset(t *testing.T) {
	// The other half of R1: an UPSERT must be an exact ADD only — a
	// manually-added co-resident A on the same name survives.
	srv := newFakeDNSServer(t, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)
	if err := u.UpsertLease(context.Background(), recV4("shared.example.com", "10.0.1.9", 300)); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	for _, up := range srv.recorded() {
		for _, d := range up.deletes {
			t.Errorf("upsert sent a delete (%v) — would clobber co-resident records", d)
		}
		// A delete-RRset/delete-name would be a ClassANY ANY RR.
		for _, rr := range up.adds {
			if rr.Header().Class == dns.ClassANY {
				t.Errorf("upsert sent a ClassANY (delete-RRset/name) RR: %v", rr)
			}
		}
	}
}

func TestRFC2136TSIGSignedAndVerified(t *testing.T) {
	const keyName = "xpf-ddns."
	const secret = "c2VjcmV0LWtleS1iYXNlNjQtZW5jb2RlZA==" // arbitrary valid base64
	srv := newFakeDNSServer(t, map[string]string{keyName: secret})
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled:       true,
		Domain:        "example.com",
		TSIGKeyName:   keyName,
		TSIGAlgorithm: "hmac-sha256",
		TSIGSecret:    config.Secret(secret),
	}, &ptr, &conf)

	if err := u.UpsertLease(context.Background(), recV4("tsig.example.com", "10.0.1.7", 300)); err != nil {
		t.Fatalf("signed UpsertLease should succeed: %v", err)
	}
}

func TestRFC2136TSIGWrongSecretRejectedNoLeak(t *testing.T) {
	const keyName = "xpf-ddns."
	const serverSecret = "c2VydmVyLXNlY3JldC1iYXNlNjQ="
	const clientSecret = "Y2xpZW50LXdyb25nLXNlY3JldA==" // different → verify fails
	srv := newFakeDNSServer(t, map[string]string{keyName: serverSecret})
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled:       true,
		Domain:        "example.com",
		TSIGKeyName:   keyName,
		TSIGAlgorithm: "hmac-sha256",
		TSIGSecret:    config.Secret(clientSecret),
	}, &ptr, &conf)

	err := u.UpsertLease(context.Background(), recV4("bad.example.com", "10.0.1.8", 300))
	if err == nil {
		t.Fatal("wrong TSIG secret must produce an error")
	}
	if strings.Contains(err.Error(), clientSecret) || strings.Contains(err.Error(), serverSecret) {
		t.Errorf("error message leaks a TSIG secret: %q (R6)", err.Error())
	}
}

func TestRFC2136PTRNotAuthIsCountedSkipNotFatal(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeNotAuth)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	// Forward succeeds, reverse NOTAUTH → the whole upsert still succeeds.
	if err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
		t.Fatalf("PTR NOTAUTH must not fail the lease (plan §11 Q6): %v", err)
	}
	if ptr != 1 {
		t.Errorf("ptr-notauth skip counter = %d, want 1", ptr)
	}
}

// TestRFC2136ForwardPublishedPTRFailReturnsPendingSentinel proves the #2661
// updater contract: when the forward A publishes but the reverse PTR add fails
// with a NON-skippable error (SERVFAIL — not NOTAUTH/REFUSED), UpsertLease
// returns the errDDNSPTRPending sentinel (so the manager records ownership of
// the live forward instead of orphaning it). The forward A is on the wire.
func TestRFC2136ForwardPublishedPTRFailReturnsPendingSentinel(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	srv.setRcode("1.0.10.in-addr.arpa.", dns.RcodeServerFailure)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)

	err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300))
	if !errors.Is(err, errDDNSPTRPending) {
		t.Fatalf("a non-skippable PTR failure after a forward success must return the "+
			"PTR-pending sentinel (#2661); got %v", err)
	}
	// The non-skippable PTR error is NOT counted as a NOTAUTH skip.
	if ptr != 0 {
		t.Errorf("ptr-notauth skip counter = %d, want 0 (SERVFAIL is not a NOTAUTH skip)", ptr)
	}
	// The forward A is live (the orphan-risk record the manager must now own).
	if !srv.zoneHas(&dns.A{Hdr: dns.RR_Header{Name: "laptop.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}) {
		t.Errorf("forward A was not published")
	}
}

func TestRFC2136SkipExistingConflictSkips(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	// Scope the collision to the forward zone so the skip count is
	// deterministic (the reverse zone add succeeds).
	srv.setConflict(true, map[string]bool{"example.com.": true})
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "skip-existing",
	}, &ptr, &conf)

	// skip-existing on a collision must REFUSE with the errDDNSConflictRefused
	// sentinel (#2660) — not a silent nil success (which would let the manager
	// record phantom ownership and a later release delete the third party's RR)
	// and not a hard transport error.
	err := u.UpsertLease(context.Background(), recV4("exists.example.com", "10.0.1.5", 300))
	if !errors.Is(err, errDDNSConflictRefused) {
		t.Fatalf("skip-existing on a collision must return the refusal sentinel; got %v", err)
	}
	if conf != 1 {
		t.Errorf("conflict skip counter = %d, want 1", conf)
	}
	// The add carried a prerequisite (NameNotUsed → an Answer RR, #14604:
	// a name-level guard, not the per-type RRsetNotUsed that let a client
	// plant one family at a name holding only the other type).
	ups := srv.recorded()
	if len(ups) == 0 || len(ups[0].prereqs) == 0 {
		t.Errorf("skip-existing must send a no-name prerequisite")
	} else if pre := ups[0].prereqs[0]; pre.Header().Class != dns.ClassNONE || pre.Header().Rrtype != dns.TypeANY {
		t.Errorf("skip-existing prereq = class %d type %s, want NameNotUsed (ClassNONE ANY) (#14604)",
			pre.Header().Class, dns.TypeToString[pre.Header().Rrtype])
	}
}

func TestRFC2136StrictFailConflictErrors(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setConflict(true, nil)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "strict-fail",
	}, &ptr, &conf)

	err := u.UpsertLease(context.Background(), recV4("exists.example.com", "10.0.1.5", 300))
	if err == nil {
		t.Fatal("strict-fail on a collision must error")
	}
}

// recV4ID is recV4 with a client identity (the DHCID input).
func recV4ID(fqdn, addr, clientID string, ttl int) LeaseDNSRecord {
	r := recV4(fqdn, addr, ttl)
	r.ClientID = clientID
	return r
}

// TestRFC2136ReplaceOwnedFreshNameUsesNameNotUsedPrereq proves the #2648 fix:
// replace-owned no longer sends a BARE Insert. A fresh-name add carries a
// "name not in use" prerequisite (so it can never adopt a pre-existing RR) and
// publishes the A + a DHCID ownership marker.
func TestRFC2136ReplaceOwnedFreshNameUsesNameNotUsedPrereq(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)
	if err := u.UpsertLease(context.Background(), recV4ID("r.example.com", "10.0.1.5", "cid:0102", 300)); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	// The forward add must carry a prerequisite (NameNotUsed) — NOT a bare add.
	fwd := srv.recorded()[0]
	if len(fwd.prereqs) == 0 {
		t.Fatalf("replace-owned fresh add must carry a name-not-in-use prerequisite (#2648); got none")
	}
	pre := fwd.prereqs[0]
	if pre.Header().Class != dns.ClassNONE || pre.Header().Rrtype != dns.TypeANY {
		t.Errorf("fresh-add prereq = class %d type %s, want NameNotUsed (ClassNONE ANY)",
			pre.Header().Class, dns.TypeToString[pre.Header().Rrtype])
	}
	// xpf now owns the A AND a DHCID marker at the name.
	if !srv.zoneHas(&dns.A{Hdr: dns.RR_Header{Name: "r.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.5")}) {
		t.Errorf("A record was not published")
	}
	dhcid, ok := dhcidRR("cid:0102", "r.example.com", 300)
	if !ok || !srv.zoneHas(dhcid) {
		t.Errorf("DHCID ownership marker was not published")
	}
}

// TestRFC2136ReplaceOwnedDoesNotAdoptThirdPartyRR is the #2648 boundary proof:
// a third party has already published the IDENTICAL A record (no DHCID). Under
// replace-owned, xpf's add must be REFUSED (name-not-in-use fails, no DHCID of
// ours to match), so xpf records NO ownership — and a later release therefore
// does NOT delete the third party's record.
//
// fail-on-revert: reverting sendAdd to a bare Insert makes the add idempotently
// succeed against the pre-existing RR, xpf records ownership, and the delete
// path then removes the third party's record → this test goes red.
func TestRFC2136ReplaceOwnedDoesNotAdoptThirdPartyRR(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	// Third party pre-publishes the exact A (no DHCID).
	thirdParty := &dns.A{
		Hdr: dns.RR_Header{Name: "host.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("10.0.1.5"),
	}
	srv.seedRR(thirdParty)

	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)

	// The upsert must REFUSE with the errDDNSConflictRefused sentinel (the
	// signal the manager uses to record NO ownership, #2648 MAJOR-1) — not a
	// silent nil success (which would let the manager record phantom ownership)
	// and not a hard transport error.
	err := u.UpsertLease(context.Background(), recV4ID("host.example.com", "10.0.1.5", "cid:aabb", 300))
	if !errors.Is(err, errDDNSConflictRefused) {
		t.Fatalf("UpsertLease on a third-party-owned name must return the refusal sentinel; got %v", err)
	}
	if conf == 0 {
		t.Errorf("expected the third-party collision to be counted")
	}
	// xpf must not have written a DHCID for this name (no ownership claimed).
	ours, _ := dhcidRR("cid:aabb", "host.example.com", 300)
	if srv.zoneHas(ours) {
		t.Errorf("xpf wrote a DHCID for a name it does not own — it ADOPTED a third-party RR (#2648 boundary breach)")
	}

	// A later release/delete (as the reconciler would issue) must leave the
	// third party's record intact: its DHCID-match prerequisite fails.
	if err := u.DeleteLease(context.Background(), recV4ID("host.example.com", "10.0.1.5", "cid:aabb", 300)); err != nil {
		t.Fatalf("DeleteLease should be a counted skip on a non-owned name, not an error: %v", err)
	}
	if !srv.zoneHas(thirdParty) {
		t.Fatalf("#2648 BOUNDARY BREACH: xpf deleted a third-party A record it did not create")
	}
}

// TestRFC2136ReplaceOwnedFullLifecycleOwnsAndDeletes proves the safe path: a
// normal add on an unused name claims ownership (A + DHCID), and a later
// release deletes exactly those records (DHCID-match prerequisite holds).
func TestRFC2136ReplaceOwnedFullLifecycleOwnsAndDeletes(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)

	rec := recV4ID("mine.example.com", "10.0.1.7", "cid:1234", 300)
	if err := u.UpsertLease(context.Background(), rec); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "mine.example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("10.0.1.7")}
	dhcid, _ := dhcidRR("cid:1234", "mine.example.com", 300)
	if !srv.zoneHas(a) || !srv.zoneHas(dhcid) {
		t.Fatalf("after add, xpf should own the A and DHCID")
	}
	if err := u.DeleteLease(context.Background(), rec); err != nil {
		t.Fatalf("DeleteLease: %v", err)
	}
	if srv.zoneHas(a) {
		t.Errorf("after release, the owned A should be deleted")
	}
	if srv.zoneHas(dhcid) {
		t.Errorf("after release, the owned DHCID should be deleted")
	}
}

// TestRFC2136ReplaceOwnedAdoptsOwnNameOnReadd proves the RFC 4703 §5.3.2
// second attempt: when a name already exists with OUR DHCID (e.g. a lease
// refresh after a restart re-derives the same record), the add succeeds via
// the DHCID-match prerequisite rather than being refused.
func TestRFC2136ReplaceOwnedAdoptsOwnNameOnReadd(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)

	// Pre-seed OUR own A + DHCID (as if a prior add already ran).
	a := &dns.A{Hdr: dns.RR_Header{Name: "self.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.1.9")}
	dhcid, _ := dhcidRR("cid:5678", "self.example.com", 300)
	srv.seedRR(a)
	srv.seedRR(dhcid)

	if err := u.UpsertLease(context.Background(), recV4ID("self.example.com", "10.0.1.9", "cid:5678", 300)); err != nil {
		t.Fatalf("re-add of our own name must succeed via the DHCID-match prereq: %v", err)
	}
	if conf != 0 {
		t.Errorf("re-adding our OWN name must not be counted as a conflict; got %d", conf)
	}
	if !srv.zoneHas(a) || !srv.zoneHas(dhcid) {
		t.Errorf("our records should remain after a self re-add")
	}
}

// TestRFC2136ReplaceOwnedRefusesNameOwnedByDifferentDHCID proves a name owned
// by a DIFFERENT client (a DHCID that is not ours) is never touched: the add
// is refused and a later delete is skipped, leaving the other owner's records.
func TestRFC2136ReplaceOwnedRefusesNameOwnedByDifferentDHCID(t *testing.T) {
	srv := newFakeDNSServer(t, nil)
	srv.setStateful(true)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
		Enabled: true, Domain: "example.com", ConflictPolicy: "replace-owned",
	}, &ptr, &conf)

	// A different client owns shared.example.com (its own A + DHCID).
	otherA := &dns.A{Hdr: dns.RR_Header{Name: "shared.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("10.0.1.50")}
	otherDHCID, _ := dhcidRR("cid:OTHER", "shared.example.com", 300)
	srv.seedRR(otherA)
	srv.seedRR(otherDHCID)

	if err := u.UpsertLease(context.Background(), recV4ID("shared.example.com", "10.0.1.51", "cid:MINE", 300)); !errors.Is(err, errDDNSConflictRefused) {
		t.Fatalf("add against a different owner's name must return the refusal sentinel; got %v", err)
	}
	if conf == 0 {
		t.Errorf("collision with a different DHCID owner must be counted")
	}
	if !srv.zoneHas(otherA) || !srv.zoneHas(otherDHCID) {
		t.Errorf("the other owner's records must be untouched by a refused add")
	}

	// And a delete must not remove the other owner's records.
	if err := u.DeleteLease(context.Background(), recV4ID("shared.example.com", "10.0.1.51", "cid:MINE", 300)); err != nil {
		t.Fatalf("delete against a different owner's name must be a counted skip: %v", err)
	}
	if !srv.zoneHas(otherA) || !srv.zoneHas(otherDHCID) {
		t.Fatalf("#2648 BOUNDARY BREACH: xpf deleted records owned by a different DHCID")
	}
}

// TestDHCIDDeterministicAndBound proves the DHCID digest is a deterministic
// function of (client-id, name) and changes when either changes.
func TestDHCIDDeterministicAndBound(t *testing.T) {
	a, _ := dhcidRR("cid:1", "host.example.com", 300)
	b, _ := dhcidRR("cid:1", "host.example.com", 300)
	if a.Digest != b.Digest {
		t.Errorf("DHCID not deterministic for the same (id,name)")
	}
	c, _ := dhcidRR("cid:2", "host.example.com", 300)
	if a.Digest == c.Digest {
		t.Errorf("DHCID must change with a different client id")
	}
	d, _ := dhcidRR("cid:1", "other.example.com", 300)
	if a.Digest == d.Digest {
		t.Errorf("DHCID must change with a different name")
	}
	if _, ok := dhcidRR("", "host.example.com", 300); ok {
		t.Errorf("DHCID must be omitted when there is no client identity")
	}
}

func TestRFC2136Timeout(t *testing.T) {
	// Point at an unroutable discard address so the exchange times out.
	pol := policyFromConfig(&config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com", UpdateServer: "192.0.2.1:53"})
	u, err := newRFC2136Updater(pol, &config.DHCPDynamicDNSConfig{UpdateServer: "192.0.2.1:53"}, nil, func() {}, func() {})
	if err != nil {
		t.Fatalf("newRFC2136Updater: %v", err)
	}
	u.timeout = 200 * time.Millisecond
	if cl, ok := u.client.(*dns.Client); ok {
		cl.Timeout = 200 * time.Millisecond
	}
	start := time.Now()
	err = u.UpsertLease(context.Background(), recV4("t.example.com", "10.0.1.5", 300))
	if err == nil {
		t.Fatal("a non-responding server must error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("timeout not bounded: took %v", elapsed)
	}
}

func TestCanonicalTSIGAlgorithm(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", dns.HmacSHA256, false},
		{"hmac-sha256", dns.HmacSHA256, false},
		{"HMAC-SHA256", dns.HmacSHA256, false},
		{"hmac-sha256.", dns.HmacSHA256, false},
		{"hmac-sha1", dns.HmacSHA1, false},
		{"hmac-sha512", dns.HmacSHA512, false},
		{"hmac-md5", "", true}, // deprecated/insecure → rejected (plan §11 Q5)
		{"bogus-alg", "", true},
	}
	for _, c := range cases {
		got, err := canonicalTSIGAlgorithm(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("canonicalTSIGAlgorithm(%q) want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("canonicalTSIGAlgorithm(%q) error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("canonicalTSIGAlgorithm(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeUpdateServer(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"192.0.2.53", "192.0.2.53:53", false},
		{"192.0.2.53:5353", "192.0.2.53:5353", false},
		{"dns.example.com", "dns.example.com:53", false},
		{"dns.example.com:53", "dns.example.com:53", false},
		// IPv6: bare literal gets bracketed exactly once; a bracketed literal
		// with no port must NOT be double-wrapped ("[[...]]:53"); host:port
		// forms pass through unchanged.
		{"2001:db8::1", "[2001:db8::1]:53", false},
		{"[2001:db8::1]", "[2001:db8::1]:53", false},
		{"[2001:db8::1]:5353", "[2001:db8::1]:5353", false},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := normalizeUpdateServer(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeUpdateServer(%q) want error", c.in)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("normalizeUpdateServer(%q) = %q,%v want %q", c.in, got, err, c.want)
		}
	}
}

func TestCanonicalReverseZone(t *testing.T) {
	cases := []struct{ in, want string }{
		{"5.1.0.10.in-addr.arpa", "1.0.10.in-addr.arpa."},
		{reversePTRName(netip.MustParseAddr("10.0.1.5")), "1.0.10.in-addr.arpa."},
	}
	for _, c := range cases {
		if got := canonicalReverseZone(c.in); got != c.want {
			t.Errorf("canonicalReverseZone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// ip6.arpa: the parent (drop one nibble).
	v6ptr := reversePTRName(netip.MustParseAddr("2001:db8::5"))
	gotV6 := canonicalReverseZone(v6ptr)
	if !strings.HasSuffix(gotV6, ".ip6.arpa.") {
		t.Errorf("canonicalReverseZone(v6) = %q, want a *.ip6.arpa. zone", gotV6)
	}
	if gotV6 == dns.Fqdn(v6ptr) {
		t.Errorf("canonicalReverseZone(v6) must drop a nibble, got the full name %q", gotV6)
	}
}

func TestLongestZoneSuffix(t *testing.T) {
	zones := []string{"example.com", "dept.example.com"}
	if got := longestZoneSuffix("host.dept.example.com", zones); got != "dept.example.com." {
		t.Errorf("longestZoneSuffix = %q, want dept.example.com.", got)
	}
	if got := longestZoneSuffix("host.other.com", zones); got != "" {
		t.Errorf("longestZoneSuffix non-match = %q, want empty", got)
	}
}

func TestResolveForwardZone(t *testing.T) {
	// defaultDomain is the configured Domain; the forward zone may only be the
	// domain when the FQDN is actually UNDER it. An out-of-domain FQDN must
	// derive its OWN parent zone, not be misrouted into the domain.
	u := &rfc2136Updater{defaultDomain: "example.com"}
	cases := []struct {
		fqdn string
		want string
	}{
		// Under the domain → the domain zone.
		{"laptop.example.com", "example.com."},
		{"laptop.example.com.", "example.com."},
		// The domain name itself → the domain zone.
		{"example.com", "example.com."},
		// OUTSIDE the domain → the FQDN's own parent (NOT example.com.).
		{"host.other.org", "other.org."},
		{"a.b.other.org", "b.other.org."},
	}
	for _, c := range cases {
		if got := u.resolveForwardZone(c.fqdn); got != c.want {
			t.Errorf("resolveForwardZone(%q) = %q, want %q", c.fqdn, got, c.want)
		}
	}

	// No domain configured at all → always the FQDN's parent.
	un := &rfc2136Updater{}
	if got := un.resolveForwardZone("host.example.com"); got != "example.com." {
		t.Errorf("resolveForwardZone (no domain) = %q, want example.com.", got)
	}
}

func TestExchangeTCPRetryHonorsCallerCancellation(t *testing.T) {
	// The truncation→TCP retry must derive its context from the CALLER's ctx,
	// so a deadline'd reconcile pass actually bounds the in-flight retry rather
	// than running it on a fresh context.Background() that ignores the caller's
	// deadline.
	//
	// The fake server truncates the first (UDP) reply to drive the client into
	// the *dns.Client TCP-retry branch, then STALLS the TCP reply for 2s. The
	// caller passes a SHORT-deadline ctx (300ms). Post-fix the TCP retry's
	// read deadline derives from the caller (miekg clamps the read deadline to
	// ctx.Deadline()), so the retry aborts at ~300ms with an i/o timeout. Pre-
	// fix the TCP ctx is context.Background()+u.timeout (10s), which ignores
	// the caller deadline, so the retry waits out the 2s stall and SUCCEEDS
	// (nil error) — the test fails pre-fix.
	srv := newFakeDNSServer(t, nil)
	srv.setTruncate(true, 2*time.Second)
	var ptr, conf int
	u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)
	// Per-exchange budget large enough that, pre-fix, the stalled TCP reply
	// lands within u.timeout (so pre-fix returns success, not a timeout — the
	// caller-deadline difference is the only thing the assertion observes).
	u.timeout = 10 * time.Second
	if cl, ok := u.client.(*dns.Client); ok {
		cl.Timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := u.UpsertLease(ctx, recV4("laptop.example.com", "10.0.1.5", 300))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("TCP retry ignored the caller deadline: returned success after the 2s stall " +
			"(pre-fix it runs on context.Background()+u.timeout)")
	}
	// The caller's 300ms deadline must bound the retry well before the 2s stall.
	if elapsed > time.Second {
		t.Errorf("caller deadline was not honored: took %v (stall is 2s) — err=%v", elapsed, err)
	}
}

// TestRFC2136UnsignedUpdateWarnsOncePerProvider is the #4483 runtime-warn
// fail-on-revert proof: an updater with NO TSIG key must emit a single WARN,
// the first time it sends an unsigned UPDATE to a given server, that the update
// is unauthenticated and the response rcode is forgeable. The warning is
// deduped per update server (keyed by host:port) across the per-cycle backend
// rebuilds, so a second UpsertLease to the same server stays silent. An updater
// WITH a TSIG key must NOT warn.
func TestRFC2136UnsignedUpdateWarnsOncePerProvider(t *testing.T) {
	t.Run("no tsig warns exactly once", func(t *testing.T) {
		srv := newFakeDNSServer(t, nil) // no TSIG on the server side either
		var ptr, conf int
		u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{Enabled: true, Domain: "example.com"}, &ptr, &conf)
		if u.tsigKeyName != "" {
			t.Fatalf("precondition: updater must have no TSIG key, got %q", u.tsigKeyName)
		}

		// #6709: unsignedUpdateWarned is a PROCESS-GLOBAL dedup keyed by server
		// host:port, and ephemeral ports ARE recycled inside a single test
		// binary (measured: ~1 reuse per 550 binds, so ~8% of full-package
		// runs). If an earlier test warned for the port this server happens to
		// draw, LoadOrStore reports "already warned", warnUnsignedOnce returns
		// silently, and this assertion observes ZERO warns with an EMPTY log —
		// the exact reported symptom, on a test that passes in isolation.
		//
		// SEED the poisoned state explicitly, then clear it. Seeding makes the
		// hostile precondition deterministic instead of an ~8% lottery: without
		// the Delete below this subtest fails EVERY run rather than rarely, so
		// the reset is pinned by a mutation that reds reliably.
		unsignedUpdateWarned.LoadOrStore(u.server, struct{}{})
		unsignedUpdateWarned.Delete(u.server)

		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(prev)

		// First upsert sends a forward + reverse UPDATE (two unsigned
		// exchanges); the once-per-provider dedup must collapse them to one WARN.
		if err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
			t.Fatalf("UpsertLease #1: %v", err)
		}
		// A second upsert to the SAME server must not re-warn.
		if err := u.UpsertLease(context.Background(), recV4("phone.example.com", "10.0.1.6", 300)); err != nil {
			t.Fatalf("UpsertLease #2: %v", err)
		}

		out := buf.String()
		n := strings.Count(out, "UNSIGNED DNS UPDATE")
		if n != 1 {
			t.Fatalf("want exactly one unsigned-update WARN across two upserts, got %d; log=%q", n, out)
		}
		if !strings.Contains(out, "forgeable") || !strings.Contains(out, "server="+srv.addrUDP) {
			t.Fatalf("the WARN must name the forgeable posture and the server; log=%q", out)
		}
	})

	t.Run("tsig-signed updater does not warn", func(t *testing.T) {
		secret := map[string]string{"k1.": "c2VjcmV0"}
		srv := newFakeDNSServer(t, secret)
		var ptr, conf int
		u := testUpdater(t, srv, &config.DHCPDynamicDNSConfig{
			Enabled:       true,
			Domain:        "example.com",
			TSIGKeyName:   "k1",
			TSIGAlgorithm: "hmac-sha256",
			TSIGSecret:    config.Secret("c2VjcmV0"),
		}, &ptr, &conf)
		if u.tsigKeyName == "" {
			t.Fatal("precondition: updater must have a TSIG key")
		}

		// #6709: this is a NEGATIVE assertion, so a stale global dedup entry
		// for this server's address would silence warnUnsignedOnce and make it
		// pass VACUOUSLY — green even if the TSIG gate regressed and the signed
		// path started warning. Clear the slot so the only reason no warn
		// appears is the TSIG gate itself.
		unsignedUpdateWarned.Delete(u.server)

		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(prev)

		if err := u.UpsertLease(context.Background(), recV4("laptop.example.com", "10.0.1.5", 300)); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
		if strings.Contains(buf.String(), "UNSIGNED DNS UPDATE") {
			t.Fatalf("a TSIG-signed updater must not warn unsigned; log=%q", buf.String())
		}
	})
}
