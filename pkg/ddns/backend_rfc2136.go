package ddns

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/psaab/xpf/pkg/config"
)

// backend_rfc2136.go was moved verbatim from pkg/dhcpserver/ddns_rfc2136.go in
// #2691 P1a (the pkg/ddns spine extraction). Logic is unchanged.

// ddns_rfc2136.go: the LIVE RFC 2136 DNS-update backend (#1387 increment 2,
// docs/research/1387-inc2-ddns-backend/plan.md §4.1). It implements the
// Inc-1 DNSUpdater interface (ddns_dns.go) so it slots in behind the same
// two-method contract the reconciler already drives — the diff/transition
// algorithm, the ownership state store, and deleteOwnedLocked-as-sole-
// delete-authority are unchanged; this backend only puts the exact wire
// adds/deletes the reconciler asks for onto the network.
//
// Exact-RR discipline (plan §4.1 / risk R1, the cardinal sin): the backend
// NEVER issues a delete-RRset or delete-name. Every wire op targets ONE
// exact RR (name + type + rdata). UpsertLease is an idempotent exact ADD;
// DeleteLease is an exact RFC 2136 §2.5.4 RR delete (TTL=0 / CLASS=NONE).
// A manually-added co-resident record on the same name is therefore never
// collateral. Re-adding an identical RR is a harmless idempotent no-op at
// the server, and Inc-1's recordsEqual short-circuit means a stable lease
// is not even re-upserted.
//
// Zone surface (plan §11 Q1): Inc-2 ships a Domain-derived forward zone +
// the canonical reverse zone (in-addr.arpa / ip6.arpa) derived from the
// PTR name. Explicit forward-zone/reverse-zone config leaves are the
// additive follow-up; resolveForwardZone/resolveReverseZone take an
// OPTIONAL explicit zone list so that follow-up wires straight into an
// existing parameter with no rewrite (today the lists are always empty).
//
// PTR NOTAUTH (plan §11 Q6): a NOTAUTH/REFUSED on the reverse-zone UPDATE
// is a COUNTED SKIP (skippedPTRNotAuth), NOT a blocking error — the forward
// A/AAAA add still succeeds and the lease's reconcile is not marked failed,
// so a reverse zone we do not own (delegated to an ISP) cannot drive a
// retry storm or fail the whole lease.

// defaultDDNSTimeout bounds one DNS UPDATE exchange (dial + write + read).
// The reconcile loop runs on a slow cadence and is a guarded phase, so a
// stuck server only delays DNS, never DHCP (plan risk R4).
const defaultDDNSTimeout = 5 * time.Second

// errDDNSConflictRefused is the sentinel an add returns when it REFUSES to
// claim a name owned by someone else. Two policies raise it:
//
//   - replace-owned (#2648): the name exists and its DHCID is not ours, or
//     there is no DHCID and the name pre-exists.
//   - skip-existing (#2660, name-level since #14604): the NameNotUsed
//     prerequisite failed (a record of ANY type already exists at the
//     name), so a third party owns it.
//
// It is neither a success nor a hard transport error — it means "another party
// owns this name". The manager (upsertLocked) classifies it like the nop-skip
// so it records NO ownership: recording phantom ownership for a name xpf does
// not own on the wire would let a LATER release delete a third party's record
// (#2648/#2659/#2660 MAJOR) — directly for a no-identity lease (whose delete
// has no DHCID-match guard) and for EVERY skip-existing record (which never
// writes a DHCID, so its delete always takes the plain exact-RR branch), and
// as broad phantom-state pollution for every refused identity-bearing
// replace-owned add. Returning a DISTINCT error keeps the reverse PTR add from
// running on a refused forward and signals the manager not to put().
var errDDNSConflictRefused = errors.New("ddns: replace-owned add refused (name owned by another party)")

// errDDNSPTRPending is the sentinel UpsertLease returns when the forward
// A/AAAA add SUCCEEDED but the reverse PTR add failed with a NON-skippable
// error (timeout, SERVFAIL, etc.). The forward RR is already LIVE in DNS, so
// the manager (upsertLocked) MUST record ownership of it — otherwise the
// forward is orphaned: live in the authoritative zone but absent from the
// ownership store, so no later release can withdraw it (#2661, the exact
// stale-record class #1387 set out to prevent). It is a PARTIAL success:
// ownership IS recorded (the forward is tracked + cleanable) but with the
// PTRPending flag set so the NEXT reconcile re-attempts the PTR (the forward
// re-add is an idempotent no-op; only the still-missing PTR is published).
// The wrapped cause carries the underlying PTR error so the manager can log
// and count it. Distinct from errDDNSConflictRefused (which records NO
// ownership) and from a NOTAUTH/REFUSED skip (which records ownership with no
// pending retry, because that reverse zone is permanently not ours).
var errDDNSPTRPending = errors.New("ddns: forward published but reverse PTR add failed (pending retry)")

// dnsExchanger is the seam the backend uses to talk to the authoritative
// server. *dns.Client satisfies it; tests inject a recorder so the wire
// adds/deletes can be asserted without a real socket (though the test
// suite drives a real in-process miekg/dns server on 127.0.0.1:0, so the
// production *dns.Client path is itself exercised).
type dnsExchanger interface {
	ExchangeContext(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, time.Duration, error)
}

// rfc2136Updater is the live DNSUpdater backend. It is STATELESS beyond
// its resolved config — all ownership/state lives in the Manager store
// (unchanged from Inc-1). A new one is built per reconcile from the current
// policy (plan §6 fork 1: resolve-per-Reconcile), so a backend-config
// change at commit takes effect on the next cycle with no swap race.
type rfc2136Updater struct {
	server         string // host:port of the authoritative DNS
	defaultDomain  string // policy.Domain — forward-zone fallback
	conflictPolicy string // replace-owned | skip-existing | strict-fail

	tsigKeyName string // canonical (lowercase, trailing-dot) key name; "" = no TSIG
	tsigAlgo    string // canonical miekg algorithm name (hmac-sha256. etc)
	tsigSecret  string // revealed base64 secret
	// requireTSIG (#15992): when true and no TSIG key is configured, the
	// updater refuses every non-loopback exchange instead of trusting an
	// unsigned rcode; loopback servers are exempt, matching the commit gate.
	requireTSIG bool

	// optional explicit zone lists (plan §11 Q1 follow-up). Always empty in
	// Inc-2; carried so the additive follow-up wires new leaves in here.
	forwardZones []string
	reverseZones []string

	timeout time.Duration

	// dhcidClientID is the client identity (from the LeaseDNSRecord) for the
	// record currently being upserted/deleted. It seeds the RFC 4701 DHCID
	// ownership marker under replace-owned. It is set at the top of each
	// UpsertLease / DeleteLease call (the manager serializes all reconcile
	// work under its mutex, so per-call mutation of this stateless-config
	// backend is safe). Empty ⇒ no DHCID (name-not-in-use guard only).
	dhcidClientID string

	// selfOwnedPrevAddr is the PREVIOUS published rdata for the self-owned
	// forward record currently being upserted (#3739), carried alongside the
	// record like dhcidClientID. sendAddSelfOwned uses it to do a VALUE-SPECIFIC
	// replace — an exact-RR delete of xpf's OWN prior value paired with the
	// insert of the new one, in ONE atomic UPDATE — so a co-resident FOREIGN
	// A/AAAA at a shared name survives (instead of the old delete-RRset that
	// destroyed every same-type record at the name). Invalid ⇒ first publish or
	// unknown prior value ⇒ Insert-only (additive, coexists with any foreign RR).
	// Set at the top of UpsertLease and only consulted on the self-owned A/AAAA
	// path; ignored by the DHCP-lease path (selfOwned=false) and by PTR adds.
	selfOwnedPrevAddr netip.Addr
	// selfOwnedPrevAddrs is the full ambiguous candidate set (#15225
	// A40-02); when non-empty it supersedes selfOwnedPrevAddr.
	selfOwnedPrevAddrs []netip.Addr
	// zoneCache memoizes SOA-discovered zones per updater (#15225 A40-05).
	// No lock: the manager serializes all calls on one updater (the same
	// discipline the per-call fields above already rely on).
	zoneCache map[string]string

	// siblingFamilyOwned is retained only as the wire-side record of
	// rec.SiblingFamilyOwned for test/debug inspection (#15072): the
	// RFC 2136 add paths deliberately NEVER consult it — authorization
	// is the wire DHCID proof via siblingClientID/pairedClientID
	// (siblingDHCIDRR + proveSiblingDHCID), so a stamped flag alone
	// cannot downgrade any guard.
	siblingFamilyOwned bool

	// siblingClientID is the client identity of the manager-owned
	// opposite-family sibling record for the forward add in flight
	// (#14995). dhcidForSibling digests it into the sibling's RFC 4701
	// DHCID; the cross-family add paths require that exact DHCID on
	// the wire before downgrading any guard, so the store flag alone
	// never authorizes a claim. Set at the top of UpsertLease from
	// rec.SiblingClientID; empty ⇒ no proven sibling.
	siblingClientID string

	// pairedClientID is the client identity of the same-device
	// opposite-family lease desired in THIS pass (#14995), threaded
	// as rec.PairedClientID. Pairing candidate for the cross-family
	// proof when SiblingClientID is empty (first pass).
	pairedClientID string
	// siblingMarkerRR is the DHCID-shaped proof marker whose last publish
	// SUCCEEDED under skip-existing/strict-fail in THIS pass (#14995/#16597)
	// at the current updater lifetime's active name and not yet observed to
	// be withdrawn by a same-device last-family delete (which clears it so
	// a later re-claim is not refused). The manager consults namedMarker
	// (a snapshot of this value) to learn which marker, if any, a pass
	// actually published, so marker cleanup is driven by ownership state
	// rather than per-updater lifetime alone. Ghost (unprovoked) marker
	// deletes are exact-match no-ops, so a delete attempted when no marker
	// was published is harmless. Nil when no marker has been published in
	// this updater's lifetime, after the last last-family withdraw cleared
	// it, or after a name switch in UpsertLease.
	siblingMarkerRR *dns.DHCID

	// selfOwned marks a backend that publishes the FIREWALL'S OWN records
	// (Surface A router/interface-address publish, #2691 P2), as opposed to a
	// DHCP-lease record claimed on behalf of a client. A self-owned record has
	// no DHCID (the firewall IS the authoritative owner of its configured FQDN),
	// so the forward ADD is an atomic IN-PLACE REPLACE of OUR record type at OUR
	// name — `sendAddSelfOwned` — rather than the lease path's name-not-in-use /
	// DHCID-match prerequisite. This is what makes an address change and a
	// forced-refresh of an existing self-record succeed (the lease path would
	// refuse the pre-existing name, since with no DHCID it has no "matches our
	// prior value" branch). A self-owned add NEVER touches a co-resident record
	// of a DIFFERENT type at the name, and NEVER issues a delete-RRset/delete-
	// name for anything but its own forward type (exact-RR discipline preserved).
	selfOwned bool

	client dnsExchanger // *dns.Client in production; recorder in tests

	// counters surfaced to the manager via the reason-tagged skip path.
	onPTRNotAuth func()
	onConflict   func()
}

// supportedTSIGAlgorithms maps an operator-facing algorithm name (with or
// without the trailing dot, case-insensitive) to the canonical miekg/dns
// constant. hmac-md5 is deliberately ABSENT — it is deprecated/insecure and
// miekg/dns no longer signs with it (plan §11 Q5); an md5 key is rejected.
var supportedTSIGAlgorithms = map[string]string{
	"hmac-sha1":   dns.HmacSHA1,
	"hmac-sha224": dns.HmacSHA224,
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

// canonicalTSIGAlgorithm normalizes an operator algorithm string to the
// canonical miekg name, defaulting to hmac-sha256 when unset. Returns an
// error for an unsupported/insecure algorithm (hmac-md5).
func canonicalTSIGAlgorithm(algo string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(algo))
	a = strings.TrimSuffix(a, ".")
	if a == "" {
		return dns.HmacSHA256, nil
	}
	if canon, ok := supportedTSIGAlgorithms[a]; ok {
		return canon, nil
	}
	return "", fmt.Errorf("ddns: unsupported TSIG algorithm %q (supported: "+
		"hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512)", algo)
}

// updateServerHasUserinfo reports whether s carries URL userinfo — an
// '@' in the authority (the whole value here: an update-server is a bare
// host[:port], so any '@' is userinfo). RFC 2136 has no credential slot:
// TSIG is the authentication mechanism, so userinfo can never work. It
// must be REJECTED, not redacted-and-dialed: dialing the redacted form
// would silently target a different string than the operator wrote, and
// keeping the raw form leaks the credential into every dial error,
// LastError and journald line that embeds the server (#16440, residual
// of #15174). The LAST '@' bounds the host, matching RedactURL; an '@'
// with an empty user or host part is still userinfo-shaped and refused.
func updateServerHasUserinfo(s string) bool {
	return strings.Contains(s, "@")
}

// redactedUpdateServer renders an update-server for errors/logs through
// config.RedactURL (#16440). Host:port has no scheme, so RedactURL's
// authority scan covers the whole value: "user:s3cr3t@host:53" renders
// "<redacted>@host:53" and a clean "host:53" renders unchanged. Used for
// values that reach an error/log site WITHOUT passing the constructor
// gate (directly-built updaters, querySOA) as defence in depth.
func redactedUpdateServer(server string) string {
	return config.RedactURL(server)
}

// scrubServerError returns err with any verbatim occurrence of the raw
// server string replaced by its RedactURL render. Dial errors from
// miekg/dns / net embed the dial address ("dial udp: lookup
// user:s3cr3t@host:53: ..."), so formatting %s of the server is not the
// only leak: the wrapped transport error itself must be scrubbed before
// it reaches LastError or journald (#16440). A clean server is absent
// from most errors (or present harmlessly), so the replace is a no-op
// for working configs. Returns nil for nil.
func (u *rfc2136Updater) scrubServerError(err error) error {
	if err == nil || u.server == "" {
		return err
	}
	redacted := redactedUpdateServer(u.server)
	if redacted == u.server {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), u.server, redacted)
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

// normalizeUpdateServer turns a host or host:port into a host:port. A bare
// host gets the default DNS port 53.
func normalizeUpdateServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("ddns: update-server is empty")
	}
	if updateServerHasUserinfo(s) {
		// #16440: never dial, log or status-render a credential. The
		// error names only the REDACTED form so the rejection itself
		// cannot leak into a commit warning / journald.
		return "", fmt.Errorf("ddns: update-server %q carries URL userinfo; "+
			"RFC 2136 update-server is a bare host[:port] with no credential "+
			"slot — remove the userinfo (use tsig-key/tsig-secret for "+
			"authentication)", config.RedactURL(s))
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s, nil
	}
	// No port. A bracketed IPv6 literal without a port ("[2001:db8::1]")
	// would be double-bracketed by JoinHostPort ("[[2001:db8::1]]:53"), so
	// strip an existing surrounding bracket pair first and let JoinHostPort
	// re-bracket the bare host exactly once. A bare IPv6 literal without
	// brackets ("2001:db8::1") and an IPv4/hostname both pass through to
	// JoinHostPort unchanged.
	host := s
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return net.JoinHostPort(host, "53"), nil
}

// updateServerIsLoopback reports whether a normalized host:port's host is
// loopback (127.0.0.0/8, ::1, or "localhost"). A non-literal hostname is
// non-loopback: xpf cannot prove it resolves only to loopback (#15992).
func updateServerIsLoopback(server string) bool {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		host = server
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}

// ddnsUnsignedNonLoopback reports whether an enabled rfc2136 policy with
// this config currently trusts unsigned rcodes from a non-loopback server.
func ddnsUnsignedNonLoopback(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) bool {
	if c == nil || !pol.enabled || pol.backend != "rfc2136" {
		return false
	}
	return ddnsConfigUnsignedNonLoopback(c)
}

// ddnsConfigUnsignedNonLoopback reports whether this config's UPDATE target
// is a non-loopback server with no TSIG key. It deliberately does NOT check
// Enabled: a disabled family still sends unsigned cleanup UPDATEs for owned
// records, so the gauge must stay set while that cleanup authority exists.
func ddnsConfigUnsignedNonLoopback(c *config.DHCPDynamicDNSConfig) bool {
	if c == nil {
		return false
	}
	return endpointUnsignedNonLoopback(c.RFC2136Endpoint, c.Backend)
}

// endpointUnsignedNonLoopback is the single *UnsignedNonLoopback config
// predicate in this package (#17237): whether an endpoint targeting a
// non-loopback server with no TSIG key trusts unsigned rcodes. Both the
// DHCP per-family shape and the Surface A provider shape resolve to it
// through their embedded RFC2136Endpoint, so the twin predicates cannot
// diverge again.
func endpointUnsignedNonLoopback(ep config.RFC2136Endpoint, backend string) bool {
	if ep.UpdateServer == "" || ep.TSIGKeyName != "" {
		return false
	}
	if backend == "" {
		backend = "rfc2136"
	}
	if backend != "rfc2136" {
		return false
	}
	server, err := normalizeUpdateServer(ep.UpdateServer)
	if err != nil {
		return false
	}
	return !updateServerIsLoopback(server)
}

// providerUnsignedNonLoopback is the Surface A entry to the shared
// endpointUnsignedNonLoopback predicate (#17237).
func providerUnsignedNonLoopback(p *config.DDNSProvider) bool {
	if p == nil {
		return false
	}
	return endpointUnsignedNonLoopback(p.RFC2136Endpoint, p.Backend)
}

// updaterUnsignedNonLoopback reports whether a resolved backend will send
// unsigned UPDATEs to a non-loopback server. Used for cleanup-path posture:
// the updater retained for withdrawals carries the endpoint that published
// the owned records, even after the config that created it is disabled or
// removed. Non-RFC2136 / nop backends report false.
func updaterUnsignedNonLoopback(u DNSUpdater) bool {
	server, keyed, ok := updaterEndpointPosture(u)
	if !ok || keyed {
		return false
	}
	return !updateServerIsLoopback(server)
}

// updaterEndpointPosture reports a resolved backend's UPDATE target and
// whether it signs with TSIG. It unwraps the per-reconcile backend the
// managers retain for withdrawals. ok=false for nop/non-RFC2136 backends.
func updaterEndpointPosture(u DNSUpdater) (server string, keyed bool, ok bool) {
	if u == nil || isNopUpdater(u) {
		return "", false, false
	}
	if pu, isPosture := u.(interface{ DDNSUpdaterEndpoint() (string, bool) }); isPosture {
		srv, k := pu.DDNSUpdaterEndpoint()
		return srv, k, true
	}
	ru, isRFC := u.(*rfc2136Updater)
	if !isRFC || ru == nil {
		return "", false, false
	}
	return ru.server, ru.tsigKeyName != "", true
}

// newRFC2136Updater builds the live backend from a resolved policy plus the
// shared RFC2136Endpoint (for the TSIG/server fields the policy struct does
// not carry) (#17237).
// onPTRNotAuth/onConflict are the manager's skip counters. A nil client
// seam means a real *dns.Client is used. Returns an error when the policy
// is structurally unusable (no update-server / bad TSIG) so the caller can
// fall back to a no-op and count it rather than emit broken UPDATEs.
//
// resolveIf is the OPTIONAL committed-config Junos→kernel interface-name
// resolver (cfg.ResolveKernelIfName) threaded from the daemon so a
// destination-interface binding resolves to the real kernel device before
// SO_BINDTODEVICE (#5070). Omitted / nil ⇒ the leaf slash-substitution fallback
// (direct + test callers with no committed config).
func newRFC2136Updater(pol ddnsPolicy, ep config.RFC2136Endpoint, client dnsExchanger, onPTRNotAuth, onConflict func(), resolveIf ...func(string) string) (*rfc2136Updater, error) {
	// #14432: fail closed on a garbage conflict-policy. Pre-fix, any value
	// other than "replace-owned" took sendRemoveForward's UNGUARDED plain
	// exact-RR delete branch, so a typo (skip-existng, none, ...) that
	// reached the backend via the tolerant load / peer-sync path (which
	// downgrades the strict schema-enum reject to a warning) could delete
	// a third party's record on lease release. The strict commit path
	// already rejects such values via the schema enum; this gate covers
	// the tolerant path and direct callers. Returning an error here makes
	// resolveFamilyUpdater fall back to the no-op updater for the cycle,
	// so no UPDATE is emitted and no ownership is recorded. Empty is
	// allowed: Surface A builds the backend from a policy literal that
	// sets it explicitly, and policyFromConfig has already defaulted an
	// unset config value to replace-owned — but a non-empty value outside
	// the valid set is never honoured. (The add side shares this gate;
	// #14429 is its audit owner.)
	if pol.conflictPolicy != "" && !validConflictPolicy(pol.conflictPolicy) {
		return nil, fmt.Errorf("ddns: invalid conflict-policy %q (valid: replace-owned, skip-existing, strict-fail); refusing to publish or withdraw DNS records", pol.conflictPolicy)
	}
	server, err := normalizeUpdateServer(ep.UpdateServer)
	if err != nil {
		return nil, err
	}
	u := &rfc2136Updater{
		server:         server,
		defaultDomain:  pol.domain,
		conflictPolicy: pol.conflictPolicy,
		forwardZones:   pol.forwardZones,
		reverseZones:   pol.reverseZones,
		timeout:        defaultDDNSTimeout,
		client:         client,
		onPTRNotAuth:   onPTRNotAuth,
		onConflict:     onConflict,
		requireTSIG:    ep.RequireTSIG,
	}
	if ep.TSIGKeyName != "" {
		algo, err := canonicalTSIGAlgorithm(ep.TSIGAlgorithm)
		if err != nil {
			return nil, err
		}
		u.tsigKeyName = dns.CanonicalName(ep.TSIGKeyName)
		u.tsigAlgo = algo
		u.tsigSecret = ep.TSIGSecret.Reveal()
	}
	// #2691 P1b / #2665: resolve the source / interface / VRF binding. An
	// invalid source-address is a hard error (the caller falls back to no-op +
	// counts it) so a misconfigured bind never emits UPDATEs from the wrong
	// source.
	bind, err := resolveBindConfig(ep, firstResolver(resolveIf))
	if err != nil {
		return nil, err
	}
	// #5070: fail construction with a clear error when the resolved bind device
	// (kernel interface or vrf-<name> master) does not exist, rather than
	// leaking a cryptic SO_BINDTODEVICE failure into every UPDATE dial later.
	if err := bind.validateDevice(); err != nil {
		return nil, err
	}
	if u.client == nil {
		cl := &dns.Client{
			Timeout:    u.timeout,
			TsigSecret: u.tsigSecretMap(),
		}
		// Apply the custom dialer (source-address LocalAddr + interface/VRF
		// SO_BINDTODEVICE) when any binding is requested; otherwise leave the
		// *dns.Client's default dialer (today's behaviour byte-for-byte).
		if d := bind.dialer(u.timeout); d != nil {
			cl.Dialer = d
			// #5327: when a source-address is configured, PIN the UDP dial to its
			// family (cl.Net drives the network miekg passes to the dialer). Without
			// this, a dual-stack update-server hostname lets Go pick the other family
			// and the family gate silently skips the source bind, so the UPDATE
			// egresses from a kernel-chosen source on the wrong WAN. A device-only
			// bind leaves cl.Net empty (byte-for-byte unchanged). The TCP truncation
			// retry (exchange) carries the same family pin off cl.Net.
			if suffix, ok := bind.sourceDialFamily(); ok {
				cl.Net = "udp" + suffix
			}
		}
		u.client = cl
	}
	return u, nil
}

// tsigSecretMap returns the miekg TsigSecret map (key name → base64 secret)
// when TSIG is configured, else nil. The secret is read via Reveal() only
// here at construction; it never appears in an error message (plan risk R6).
func (u *rfc2136Updater) tsigSecretMap() map[string]string {
	if u.tsigKeyName == "" {
		return nil
	}
	return map[string]string{u.tsigKeyName: u.tsigSecret}
}

// resolveForwardZone returns the zone the forward UPDATE targets. With no
// explicit list (Inc-2), the zone is the configured Domain (the operator's
// authoritative zone) — failing that, the parent of the FQDN. The optional
// explicit list is the additive follow-up's input; longest matching suffix
// wins so a delegated cut is honored when configured.
func (u *rfc2136Updater) resolveForwardZone(fqdn string) string {
	if z := longestZoneSuffix(fqdn, u.forwardZones); z != "" {
		return z
	}
	// Use the configured Domain only when the name is actually UNDER it. A
	// name outside the domain (an explicit ClientFQDN in a different zone)
	// must not be sent to the domain's zone — the server would answer NOTAUTH
	// (or, worse, accept it into the wrong zone). Derive that name's own
	// parent zone instead.
	if u.defaultDomain != "" {
		if z := longestZoneSuffix(fqdn, []string{u.defaultDomain}); z != "" {
			return z
		}
	}
	// No (matching) domain configured: fall back to the parent label of the
	// name.
	return parentZone(dns.Fqdn(fqdn))
}

// resolveReverseZone returns the zone the PTR UPDATE targets. With no
// explicit list (Inc-2), the canonical in-addr.arpa/ip6.arpa parent of the
// PTR name is used.
func (u *rfc2136Updater) resolveReverseZone(ptrName string) string {
	if z := longestZoneSuffix(ptrName, u.reverseZones); z != "" {
		return z
	}
	return canonicalReverseZone(ptrName)
}

// discoverZone returns the UPDATE zone for name (#15225 A40-05). Explicit
// leaves and a matching configured domain win without any query; otherwise
// the enclosing zone is discovered by walking SOA queries toward the root
// against the update server itself. Any failure falls back to the legacy
// guessed zone (the caller's NOTAUTH handling then applies, unchanged).
func (u *rfc2136Updater) discoverZone(ctx context.Context, name string, reverse bool) string {
	guessed := u.resolveForwardZone(name)
	if reverse {
		guessed = u.resolveReverseZone(name)
	}
	// Explicit/default already authoritative-shaped: no walk needed when
	// an explicit leaf or (forward) configured domain matched.
	if reverse {
		if longestZoneSuffix(name, u.reverseZones) != "" {
			return guessed
		}
	} else if longestZoneSuffix(name, u.forwardZones) != "" ||
		(u.defaultDomain != "" && longestZoneSuffix(name, []string{u.defaultDomain}) != "") {
		return guessed
	}
	if u.client == nil || u.server == "" {
		return guessed
	}
	key := "f:"
	if reverse {
		key = "r:"
	}
	key += dns.CanonicalName(name)
	if z, ok := u.zoneCache[key]; ok {
		return z
	}
	if z := u.soaWalk(ctx, name); z != "" {
		if u.zoneCache == nil {
			u.zoneCache = map[string]string{}
		}
		u.zoneCache[key] = z
		return z
	}
	return guessed
}

// soaWalk queries SOA for name and each parent until the server answers
// with an SOA in the answer section, returning that owner name. Bounded
// and best-effort: any error/empty walk returns "".
func (u *rfc2136Updater) soaWalk(ctx context.Context, name string) string {
	cur := dns.Fqdn(name)
	for cur != "." && cur != "" {
		m := new(dns.Msg)
		m.SetQuestion(cur, dns.TypeSOA)
		m.RecursionDesired = false
		resp, err := u.querySOA(ctx, m)
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			for _, rr := range resp.Answer {
				if _, ok := rr.(*dns.SOA); ok {
					return dns.Fqdn(rr.Header().Name)
				}
			}
		}
		parent := parentZone(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return ""
}

// querySOA sends one SOA query. dnsExchanger only carries UPDATEs, so a
// real *dns.Client is used directly when available; a bare exchanger
// seam (unit-test recorders without SOA support) fails the walk and the
// caller falls back to the guessed zone.
func (u *rfc2136Updater) querySOA(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if dc, ok := u.client.(*dns.Client); ok {
		c := *dc
		if u.timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, u.timeout)
			defer cancel()
		}
		resp, _, err := c.ExchangeContext(ctx, m, u.server)
		return resp, u.scrubServerError(err)
	}
	// Test/recorder seams implement ExchangeContext for any message; try it.
	resp, _, err := u.client.ExchangeContext(ctx, m, u.server)
	return resp, u.scrubServerError(err)
}

// longestZoneSuffix returns the longest configured zone that is a suffix of
// name (both compared canonically), or "" if none match. This is the seam
// the additive forward-zone/reverse-zone follow-up uses.
func longestZoneSuffix(name string, zones []string) string {
	cn := dns.CanonicalName(dns.Fqdn(name))
	best := ""
	for _, z := range zones {
		cz := dns.CanonicalName(dns.Fqdn(z))
		if cn == cz || strings.HasSuffix(cn, "."+cz) {
			if len(cz) > len(best) {
				best = dns.Fqdn(z)
			}
		}
	}
	return best
}

// parentZone returns the parent zone of a name (everything after the first
// label). A name with a single label returns the root ".".
func parentZone(fqdn string) string {
	fqdn = dns.Fqdn(fqdn)
	if i := strings.IndexByte(fqdn, '.'); i >= 0 && i+1 < len(fqdn) {
		return fqdn[i+1:]
	}
	return "."
}

// canonicalReverseZone derives the canonical reverse zone for a PTR name:
// the /24 in-addr.arpa for IPv4 (drop the host octet) or the parent
// ip6.arpa for IPv6 (drop the leading nibble). The PTR names are produced
// by Inc-1's reversePTRName, so this is the inverse of that construction.
func canonicalReverseZone(ptrName string) string {
	p := dns.Fqdn(ptrName)
	lower := strings.ToLower(p)
	switch {
	case strings.HasSuffix(lower, ".in-addr.arpa."):
		// "<d>.<c>.<b>.<a>.in-addr.arpa." -> "<c>.<b>.<a>.in-addr.arpa."
		// (drop the host octet to name the /24 the server is authoritative
		// for; if the server delegates a different boundary it answers
		// NOTAUTH, which the PTR path degrades to a counted skip).
		return parentZone(p)
	case strings.HasSuffix(lower, ".ip6.arpa."):
		// Drop the leading nibble to name the immediate parent.
		return parentZone(p)
	default:
		// Not a recognized reverse name: name its parent (best effort).
		return parentZone(p)
	}
}

// siblingProofIdentity returns the sibling client identity whose
// DHCID the cross-family add must prove on the wire (#14995): the
// durable store sibling (SiblingClientID) when present, else the
// same-pass paired lease (PairedClientID). "" when neither was
// threaded.
func (u *rfc2136Updater) siblingProofIdentity() string {
	if u.siblingClientID != "" {
		return u.siblingClientID
	}
	return u.pairedClientID
}

// siblingDHCIDRR returns the RFC 4701 DHCID the SIBLING family's
// publish wrote at this name, digested from the sibling identity
// (siblingProofIdentity). ok=false when no sibling identity was
// threaded, it yields no DHCID, or the sibling and claimant
// identities do not pair to the same device (#14995): the wire
// DHCIDs only coincide for a same-device pair (both digests are
// device-canonicalized), so proof is only meaningful — and only
// attempted — for such a pair.
func (u *rfc2136Updater) siblingDHCIDRR(rr dns.RR) (*dns.DHCID, bool) {
	sibID := u.siblingProofIdentity()
	if sibID == "" || !sameDeviceClient(u.dhcidClientID, sibID) {
		return nil, false
	}
	if d, ok := dhcidRR(sibID, rr.Header().Name, rr.Header().Ttl); ok {
		return d, true
	}
	if u.siblingMarkerRR != nil && dns.CanonicalName(u.siblingMarkerRR.Hdr.Name) == dns.CanonicalName(rr.Header().Name) {
		return u.siblingMarkerRR, true
	}
	return nil, false
}

// siblingCandidate reports whether this forward add carries a
// cross-family sibling claim worth a wire proof attempt: the manager
// flagged a store sibling OR a same-device sibling is desired this
// pass. The claim still earns nothing until proveSiblingDHCID holds.
func (u *rfc2136Updater) siblingCandidate(rr dns.RR) bool {
	if !(rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA) {
		return false
	}
	return u.siblingProofIdentity() != ""
}

// namedMarker returns the retained proof marker for name, or nil
// (#16597). The manager consults it after a pass to learn which
// device marker (if any) was actually published under
// skip-existing/strict-fail in that pass, so marker cleanup can be
// driven by ownership state rather than per-updater lifetime alone.
// UpsertLease resets the retained marker on a name switch so a
// multi-name updater never leaks name A's proof into name B's
// siblingDHCIDRR fallback or delete; a same-name different-device
// delete still recomputes its marker value-specifically from the
// deleting record's own identity.
func (u *rfc2136Updater) namedMarker(name string) *dns.DHCID {
	if u == nil || u.siblingMarkerRR == nil {
		return nil
	}
	if dns.CanonicalName(u.siblingMarkerRR.Hdr.Name) != dns.CanonicalName(name) {
		return nil
	}
	return dns.Copy(u.siblingMarkerRR).(*dns.DHCID)
}

// UpsertLease publishes the forward A/AAAA and reverse PTR for a lease
// (plan §4.1). The forward add is the operation whose success governs the
// lease's reconcile result; a PTR NOTAUTH/REFUSED is a counted skip.
func (u *rfc2136Updater) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	// #16597: a name switch in the updater's lifetime resets the
	// retained marker so multi-name updater lifetimes never leak
	// name A's proof into name B's siblingDHCIDRR fallback or delete.
	if u.siblingMarkerRR != nil && dns.CanonicalName(u.siblingMarkerRR.Hdr.Name) != dns.CanonicalName(rec.FQDN) {
		u.siblingMarkerRR = nil
	}
	u.dhcidClientID = rec.ClientID
	u.selfOwnedPrevAddr = rec.PrevAddr // #3739: value-specific self-owned replace
	u.selfOwnedPrevAddrs = rec.PrevAddrs
	u.siblingFamilyOwned = rec.SiblingFamilyOwned
	u.siblingClientID = rec.SiblingClientID
	u.pairedClientID = rec.PairedClientID
	forwardRR, err := u.forwardRR(rec)
	if err != nil {
		return err
	}
	// Forward zone add (#15225 A40-05: SOA-discovered zone, explicit
	// leaves and configured domain take precedence inside the resolver).
	zone := u.discoverZone(ctx, rec.FQDN, false)
	if err := u.sendAdd(ctx, zone, forwardRR); err != nil {
		// A conflict refusal (the name is owned by another party) — from
		// replace-owned (#2648) OR skip-existing (#2660) — is propagated
		// UNWRAPPED so the manager's errors.Is check sees the sentinel and
		// records no ownership. Do NOT add the reverse PTR for a forward we did
		// not publish.
		if errors.Is(err, errDDNSConflictRefused) {
			return errDDNSConflictRefused
		}
		return fmt.Errorf("ddns: forward upsert %s %s: %w", rec.ForwardType, rec.FQDN, err)
	}
	// Reverse zone PTR add — NOTAUTH/REFUSED is a counted skip, not fatal.
	if rec.PTRName != "" {
		ptrRR := u.ptrRR(rec)
		rzone := u.discoverZone(ctx, rec.PTRName, true)
		if err := u.sendAdd(ctx, rzone, ptrRR); err != nil {
			if isPTRSkippable(err) {
				if u.onPTRNotAuth != nil {
					u.onPTRNotAuth()
				}
				return nil
			}
			// PTR-side CONFLICT REFUSAL (#2676): the reverse RRset already exists
			// and is owned by another party (replace-owned DHCID mismatch, or
			// skip-existing RRsetNotUsed prereq failure). This is a PERMANENT
			// condition for the reverse name — exactly like a NOTAUTH skip, not a
			// transient failure to retry. The forward A/AAAA is already LIVE, so
			// we must NOT propagate errDDNSConflictRefused (the manager would then
			// take its no-ownership branch and ORPHAN the live forward, the #2661
			// class on the PTR-conflict path). Treat it as a counted, permanent
			// PTR skip: the forward is owned (tracked + cleanable) with NO PTR
			// pending (nothing to retry — the reverse is not ours and never will
			// be). Do NOT double-wrap the two sentinels into one chain (the wrap
			// that confused upsertLocked's errors.Is ordering). sendAdd already
			// counted the conflict (its onConflict hook fired on the YX refusal),
			// so do NOT count it again here — just swallow the refusal as a
			// permanent skip and return nil so the manager keeps the forward
			// owned-not-pending.
			if errors.Is(err, errDDNSConflictRefused) {
				return nil
			}
			// The forward A/AAAA is already LIVE in DNS but the reverse PTR add
			// failed with a non-skippable, TRANSIENT error (timeout, SERVFAIL).
			// Returning a plain error here would make the manager record NO
			// ownership, ORPHANING the live forward (#2661). Instead, return the
			// errDDNSPTRPending sentinel wrapping the cause: the manager records
			// ownership of the forward (so it is tracked + cleanable) with
			// PTRPending set, and the next reconcile re-runs UpsertLease — the
			// forward re-add is an idempotent no-op and only the still-missing PTR
			// is published.
			return fmt.Errorf("ddns: reverse upsert PTR %s: %w: %w", rec.PTRName, err, errDDNSPTRPending)
		}
	}
	return nil
}

// DeleteLease removes the exact forward and reverse RRs the firewall
// published (plan §4.1). Both are exact RFC 2136 §2.5.4 deletes (the
// miekg Remove path forces TTL=0 / CLASS=NONE), so a co-resident record on
// the same name is never collateral. A PTR NOTAUTH/REFUSED on delete is the
// same counted skip as on add.
func (u *rfc2136Updater) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	u.dhcidClientID = rec.ClientID
	forwardRR, err := u.forwardRR(rec)
	if err != nil {
		return err
	}
	zone := u.discoverZone(ctx, rec.FQDN, false)
	// rec.KeepForwardDHCID (#2700): another owned record still shares this
	// FQDN+ClientID (a dual-stack client's surviving family), so delete the
	// forward A/AAAA but keep the shared DHCID — the surviving record stays
	// DHCID-protected and its later delete still satisfies the DHCID-match
	// prerequisite. rec.KeepSiblingMarker (#16597) is the skip-existing/
	// strict-fail analogue: keep the device proof marker while a same-device
	// sibling survives; the last family's delete removes it value-specifically.
	if err := u.sendRemoveForward(ctx, zone, forwardRR, rec.KeepForwardDHCID, rec.KeepSiblingMarker); err != nil {
		return fmt.Errorf("ddns: forward delete %s %s: %w", rec.ForwardType, rec.FQDN, err)
	}
	if rec.PTRName != "" {
		ptrRR := u.ptrRR(rec)
		rzone := u.discoverZone(ctx, rec.PTRName, true)
		if err := u.sendRemove(ctx, rzone, ptrRR); err != nil {
			if isPTRSkippable(err) {
				if u.onPTRNotAuth != nil {
					u.onPTRNotAuth()
				}
				return nil
			}
			return fmt.Errorf("ddns: reverse delete PTR %s: %w", rec.PTRName, err)
		}
	}
	return nil
}

// forwardRR builds the A or AAAA RR for a record.
func (u *rfc2136Updater) forwardRR(rec LeaseDNSRecord) (dns.RR, error) {
	name := dns.Fqdn(rec.FQDN)
	ttl := uint32(rec.TTL) //nolint:gosec // TTL is a small positive config value
	if rec.Addr.Is4() {
		a4 := rec.Addr.As4()
		ip := net.IP(a4[:])
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip,
		}, nil
	}
	if rec.Addr.Is6() {
		a16 := rec.Addr.As16()
		ip := net.IP(a16[:])
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: ip,
		}, nil
	}
	return nil, fmt.Errorf("ddns: record %q has an unspecified address", rec.FQDN)
}

// ptrRR builds the PTR RR for a record's reverse name.
func (u *rfc2136Updater) ptrRR(rec LeaseDNSRecord) dns.RR {
	return &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(rec.PTRName),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    uint32(rec.TTL), //nolint:gosec // TTL is a small positive config value
		},
		Ptr: dns.Fqdn(rec.FQDN),
	}
}

// RFC 4701 §3.3 "identifier type codes" carried in the first 2 octets of the
// DHCID RDATA. They tell a reader WHICH client-identity form the digest was
// computed over, so a shared zone with another DHCID writer (ISC Kea, Windows
// DHCP) can interoperate. xpf maps them from the lease-parser identity prefix:
//
//   - 0x0000 — the 1-octet htype followed by the hardware address (the
//     DHCPv4 "htype+chaddr" form). xpf uses this for the hwaddr fallback
//     (identity4's "mac:" prefix, used only when no client-id option exists).
//   - 0x0001 — the data octets of the DHCPv4 Client Identifier option (RFC
//     2132 option 61). xpf uses this for identity4's "cid:" prefix.
//   - 0x0002 — the DHCPv6 DUID. xpf uses this for identity6's "duid:" prefix.
//
// RESIDUAL (documented): the DIGEST input below is xpf's canonical identity
// STRING (the prefixed, colon-hex form the Kea memfile parser produces), not
// the raw option byte stream RFC 4701 §3.5 specifies. So the identifier-TYPE
// is now RFC-correct, but the DIGEST is not guaranteed byte-identical to what
// ISC Kea / Windows would compute for the same client — cross-vendor DHCID
// MATCH on a shared name is therefore best-effort, not guaranteed. xpf is
// internally consistent (the same lease always yields the same DHCID across an
// add/delete pair, which is what the ownership boundary requires), and a
// non-matching foreign DHCID is treated as "owned by another party" and left
// untouched — the SAFE direction. Computing the digest over the raw option
// bytes would require threading the un-mangled DHCP option through the lease
// parser, deferred as an interop enhancement.
const (
	dhcidIDTypeHTypeChaddr = 0x0000 // "mac:" — htype+chaddr
	dhcidIDTypeClientID    = 0x0001 // "cid:" — DHCPv4 client-identifier option
	dhcidIDTypeDUID        = 0x0002 // "duid:" — DHCPv6 DUID
)

// dhcidIdentifierType returns the RFC 4701 §3.3 identifier-type code for an
// xpf lease identity, keyed on the prefix the lease parser (identity4 /
// identity6) attached. An unrecognized form falls back to htype+chaddr
// (0x0000) — it only affects the marker's self-description; xpf compares its
// own DHCID against itself, so the fallback is harmless.
func dhcidIdentifierType(clientID string) int {
	switch {
	case strings.HasPrefix(clientID, "duid:"):
		return dhcidIDTypeDUID
	case strings.HasPrefix(clientID, "cid:"):
		return dhcidIDTypeClientID
	case strings.HasPrefix(clientID, "mac:"):
		return dhcidIDTypeHTypeChaddr
	default:
		return dhcidIDTypeHTypeChaddr
	}
}

// dhcidDigestTypeSHA256 is the RFC 4701 §3.4 digest type code for SHA-256.
const dhcidDigestTypeSHA256 = 0x01

// dnsCanonicalFQDN returns the canonical (lowercased, trailing-dot) form of a
// name, matching exactly how dhcidRR canonicalizes the FQDN before folding it
// into the DHCID digest. The manager (dhcidSharedWithOther, #2700) uses it to
// decide whether two owned records would compute the SAME DHCID, so this must
// stay in lockstep with dhcidRR's `dns.CanonicalName(dns.Fqdn(fqdn))`.
func dnsCanonicalFQDN(fqdn string) string {
	return dns.CanonicalName(dns.Fqdn(fqdn))
}

// dhcidDigestClientID returns the identity bytes folded into the
// RFC 4701 DHCID digest for a lease client identity (#14995). When
// the identity has a device-pairing key (pairedIdentityKey —
// "mac:<MAC>" for a MAC-based DUID or the v4 hwaddr fallback, or an
// exact "cid:<client-id>"), the digest is computed over the DEVICE
// ("dev:"+key), so the SAME device produces ONE DHCID across both
// families no matter which family-shaped form it presented — one
// DHCID RR per owner name, as RFC 4701 §3.5 intends. An identity
// with no pairing key digests verbatim (fail closed: it can only
// ever match itself). Add and delete both go through dhcidRR, so
// the canonicalization is symmetric and cannot orphan a record.
func dhcidDigestClientID(clientID string) string {
	if key := pairedIdentityKey(clientID); key != "" {
		return "dev:" + key
	}
	return clientID
}

// legacyDHCIDDigestClientID returns the identity bytes the pre-#14995
// dhcidRR folded into the digest (#16591): the raw clientID verbatim,
// including the IAID-bearing v6 form ("duid:.../<IAID>").
func legacyDHCIDDigestClientID(clientID string) string {
	return clientID
}

// dhcidDigest returns the SHA-256 over identityBytes || canonical
// FQDN wire form (RFC 4701 §3.5) for one digest flavour.
func dhcidDigest(identity, name string, wire []byte, off int) []byte {
	h := sha256.New()
	h.Write([]byte(identity))
	h.Write(wire[:off])
	return h.Sum(nil)
}

// dhcidRRFromDigest builds a DHCID RR from a precomputed digest.
func dhcidRRFromDigest(name string, ttl uint32, idType int, digest []byte) *dns.DHCID {
	rdata := make([]byte, 0, 3+len(digest))
	rdata = append(rdata, byte(idType>>8), byte(idType&0xff))
	rdata = append(rdata, byte(dhcidDigestTypeSHA256))
	rdata = append(rdata, digest...)
	return &dns.DHCID{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeDHCID,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Digest: base64.StdEncoding.EncodeToString(rdata),
	}
}

// dhcidIdentifierTypeForDigest mirrors dhcidRR's idType selection for
// a digest flavour: the device digest stamps the htype+chaddr form
// for a MAC pairing (#14995); the legacy digest keeps the presenting
// identity's own form, exactly as the pre-#14995 dhcidRR did.
func dhcidIdentifierTypeForDigest(clientID string, legacy bool) int {
	idType := dhcidIdentifierType(clientID)
	if !legacy && strings.HasPrefix(pairedIdentityKey(clientID), "mac:") {
		idType = dhcidIDTypeHTypeChaddr
	}
	return idType
}

// dhcidRRWithDigest builds the DHCID for clientID under one digest
// flavour: legacy=false is the current device digest (dhcidRR);
// legacy=true is the pre-#14995 per-identity digest (#16591).
func dhcidRRWithDigest(clientID, fqdn string, ttl uint32, legacy bool) (*dns.DHCID, bool) {
	if clientID == "" {
		return nil, false
	}
	name := dns.CanonicalName(dns.Fqdn(fqdn))
	wire := make([]byte, len(name)+1)
	off, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil {
		return nil, false
	}
	identity := dhcidDigestClientID(clientID)
	if legacy {
		identity = legacyDHCIDDigestClientID(clientID)
	}
	digest := dhcidDigest(identity, name, wire, off)
	return dhcidRRFromDigest(name, ttl, dhcidIdentifierTypeForDigest(clientID, legacy), digest), true
}

// legacyDHCIDRR builds the pre-#14995 DHCID (#16591), or ok=false
// when the legacy digest coincides with the current device digest
// (identity has no pairing key, so the two flavours are identical
// and there is no distinct legacy RR to match).
func legacyDHCIDRR(clientID, fqdn string, ttl uint32) (*dns.DHCID, bool) {
	if pairedIdentityKey(clientID) == "" {
		return nil, false
	}
	return dhcidRRWithDigest(clientID, fqdn, ttl, true)
}

// legacyDHCIDForRR is legacyDHCIDRR for this updater's forward RR.
func (u *rfc2136Updater) legacyDHCIDForRR(rr dns.RR) (*dns.DHCID, bool) {
	if rr.Header().Rrtype != dns.TypeA && rr.Header().Rrtype != dns.TypeAAAA {
		return nil, false
	}
	return legacyDHCIDRR(u.dhcidClientID, rr.Header().Name, rr.Header().Ttl)
}

// legacyProbe exhausts the sequential used-DHCID proof attempts
// against the wire: it tries each candidate DHCID as a Used
// prerequisite probe (no update section) in order and returns the
// index of the first that holds, or -1 when none holds. A transport
// error aborts immediately. Candidates must be non-nil.
func (u *rfc2136Updater) legacyProbe(ctx context.Context, zone string, candidates []*dns.DHCID) (int, error) {
	for i, cand := range candidates {
		proven, err := u.proveSiblingDHCID(ctx, zone, cand)
		if err != nil {
			return -1, err
		}
		if proven {
			return i, nil
		}
	}
	return -1, nil
}

// dhcidRR builds the RFC 4701 DHCID resource record that proves xpf owns a
// forward name. The RDATA is: 2-byte identifier-type || 1-byte digest-type
// || SHA-256(client-identity || canonical-FQDN-in-wire-form) (RFC 4701
// §3.5). miekg's DHCID.Digest is the base64 of that whole RDATA blob.
//
// The FQDN is folded into the digest in DNS wire form (canonical, lowercased)
// so the marker is bound to BOTH the client identity and the exact name —
// the same (identity, name) pair always produces the same DHCID, and a
// different name or client cannot collide onto it. Returns ok=false when the
// lease has no stable client identity (the caller then omits the DHCID and
// uses the name-not-in-use prerequisite instead).
//
// #14995: the folded identity is the DEVICE identity
// (dhcidDigestClientID), not the raw family-shaped string, so a
// dual-stack device carries ONE DHCID across its A and AAAA instead
// of two per-family DHCIDs. The identifier-TYPE octets still
// describe the presenting identity's form (RFC 4701 §3.3).
func dhcidRR(clientID, fqdn string, ttl uint32) (*dns.DHCID, bool) {
	return dhcidRRWithDigest(clientID, fqdn, ttl, false)
}

// sendAdd issues an exact-RR ADD honoring the conflict policy.
//
//   - replace-owned (the SAFE default, #2648): xpf claims a name only when it
//     can PROVE ownership. It computes the RFC 4701 DHCID for (client-id,
//     name) and runs RFC 4703 §5.3 DHCID conflict resolution: first try to
//     add the A/AAAA + DHCID with a "name not in use" prerequisite (a fresh
//     name we are free to claim); if that collides (YXDOMAIN), retry with a
//     "DHCID matches OURS" prerequisite so we only adopt/update a name WE
//     already own. If neither holds — a third party owns the name (a
//     different or absent DHCID) — the add is REFUSED and counted, so xpf
//     never records ownership of, and therefore never later deletes, a
//     record it did not create. When the lease has no stable client identity
//     the DHCID is omitted and the name-not-in-use prerequisite alone guards
//     the claim (still never adopting a pre-existing third-party RR).
//   - skip-existing: precede the Insert with a "name not in use"
//     prerequisite (RFC 2136 §2.4.5 `NameNotUsed`, ANY/NONE) and REFUSE on a
//     YX collision (the name already exists in ANY type = a third party owns
//     it) by returning errDDNSConflictRefused so the manager records NO
//     ownership. #14604: previously this used the per-type RRsetNotUsed
//     prerequisite, so a v6-only or MX/TXT-only foreign name was still
//     claimable for A/AAAA. A name xpf itself already owns across the other
//     address family (or any owned sibling Family at the name) is NOT
//     third-party: the manager threads `SiblingFamilyOwned` through
//     `UpsertLease` in those cases and the cross-family allow-lists are
//     re-proven per cycle for the remaining sibling state locally.
//     skip-existing never writes a DHCID, so phantom ownership here would
//     let a later release take the plain exact-RR delete and remove the
//     third party's RR (#2660).
//   - strict-fail: same prerequisite, surface the collision as an error.
func (u *rfc2136Updater) sendAdd(ctx context.Context, zone string, rr dns.RR) error {
	// #2691 P2: a self-owned forward record (Surface A) is published as an
	// atomic in-place replace of OUR record type, so an address change or a
	// forced-refresh of an EXISTING name succeeds (the DHCID/name-not-in-use
	// prerequisites below would refuse the pre-existing name). Only the forward
	// A/AAAA add is self-owned; a PTR add (rare for Surface A) falls through to
	// the normal path.
	if u.selfOwned && (rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA) {
		return u.sendAddSelfOwned(ctx, zone, rr)
	}
	if u.conflictPolicy == "replace-owned" {
		return u.sendAddOwned(ctx, zone, rr)
	}
	// #14429 defense-in-depth: an updater built outside newRFC2136Updater
	// (struct literal) with a garbage policy must still refuse the ADD
	// rather than fall through to the bare Insert below.
	if u.conflictPolicy != "skip-existing" && u.conflictPolicy != "strict-fail" {
		return fmt.Errorf("ddns: invalid conflict-policy %q (valid: replace-owned, skip-existing, strict-fail); refusing ADD of %s", u.conflictPolicy, rr.Header().Name)
	}
	// #14995 sibling proof: when the manager claims a cross-family
	// sibling, first prove the sibling's DHCID is on the wire with a
	// dedicated prerequisite-only probe. Only a proven sibling earns
	// the per-type guard below; an unproven claim (foreign client,
	// stale intent) keeps the name-level guard and is refused.
	siblingProven := false
	if u.siblingCandidate(rr) {
		if sib, ok := u.siblingDHCIDRR(rr); ok {
			proven, perr := u.proveSiblingDHCID(ctx, zone, sib)
			if perr != nil {
				return perr
			}
			siblingProven = proven
			if !siblingProven {
				// #16591: sibling may carry only its legacy DHCID.
				if sibID := u.siblingProofIdentity(); sibID != "" {
					if legacySib, lok := legacyDHCIDRR(sibID, rr.Header().Name, rr.Header().Ttl); lok {
						lproven, lerr := u.legacyProbe(ctx, zone, []*dns.DHCID{legacySib})
						if lerr != nil {
							return lerr
						}
						siblingProven = lproven >= 0
					}
				}
			}
		}
	}
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	// #14604/#14995: client-claimed forward adds are guarded
	// name-level: NameNotUsed (ANY/NONE) refuses the add when ANY
	// record exists at the name. Only a sibling whose DHCID was just
	// proven on the wire keeps the per-type RRsetNotUsed guard.
	switch {
	case siblingProven:
		m.RRsetNotUsed([]dns.RR{rr})
	default:
		m.NameNotUsed([]dns.RR{rr})
	}
	m.Insert([]dns.RR{rr})
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// #14995/#16597: under skip-existing/strict-fail the forward
		// add wrote no DHCID, so a same-device sibling desired in
		// this same pass has nothing on the wire to prove against.
		// Publish the device proof marker now — once, in this
		// updater's lifetime — so the sibling family's add present
		// in this same pass can prove it. Only a SUCCESSFUL marker
		// exchange is retained; on exchange error the forward add
		// has already succeeded, so surface the error (the forward
		// stays owned and the marker is re-attempted next cycle)
		// rather than recording ownership of a marker never
		// published. On last-family withdrawal the manager drives
		// a value-specific delete of this marker when it is the
		// last same-name family of that device (#16597), so the
		// marker cannot burn the name after the owned A/AAAA are
		// gone.
		if u.siblingCandidate(rr) {
			if sib, ok := u.siblingDHCIDRR(rr); ok && u.siblingMarkerRR == nil {
				mark := new(dns.Msg)
				mark.SetUpdate(dns.Fqdn(zone))
				mark.Insert([]dns.RR{sib})
				if _, merr := u.exchange(ctx, mark); merr != nil {
					return merr
				}
				u.siblingMarkerRR = sib
			}
		}
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain:
		// Prerequisite failed: a record already exists — a third party owns
		// this name. Refuse to claim it (count the conflict) and signal the
		// refusal with errDDNSConflictRefused, NOT nil. A nil return is a
		// SUCCESS to upsertLocked, which would then record phantom ownership
		// for a name xpf did not create; skip-existing never writes a DHCID, so
		// a later release would take sendRemoveForward's plain exact-RR delete
		// branch and DELETE the third party's RR (#2660, the skip-existing
		// sibling of the #2648/#2659 boundary breach). The sentinel tells the
		// manager to record NO ownership — exactly the replace-owned mechanism
		// (#2648), extended to skip-existing.
		if u.conflictPolicy == "skip-existing" {
			if u.onConflict != nil {
				u.onConflict()
			}
			return errDDNSConflictRefused
		}
		return fmt.Errorf("ddns: conflict on %s (rcode %s)", rr.Header().Name, dns.RcodeToString[resp.Rcode])
	default:
		return rcodeError(resp.Rcode)
	}
}

// dhcidForRR returns the DHCID RR that should accompany an A/AAAA add under
// replace-owned, derived from the client identity carried alongside the
// record. Reverse PTR adds get no DHCID (RFC 4701 binds the marker to the
// forward owner name only). ok=false means no DHCID applies (a reverse name,
// or a forward name with no stable client identity).
func (u *rfc2136Updater) dhcidForRR(rr dns.RR) (*dns.DHCID, bool) {
	if rr.Header().Rrtype != dns.TypeA && rr.Header().Rrtype != dns.TypeAAAA {
		return nil, false
	}
	return dhcidRR(u.dhcidClientID, rr.Header().Name, rr.Header().Ttl)
}

// ownDHCIDRR returns the DHCID this updater's current client identity
// would publish at rr's name — the device marker the skip-existing/
// strict-fail marker cleanup deletes value-specifically (#16597).
// Because the digest is device-canonicalized, either family's
// publishing identity recomputes the same marker.
func (u *rfc2136Updater) ownDHCIDRR(rr dns.RR) (*dns.DHCID, bool) {
	return u.dhcidForRR(rr)
}

// sendAddOwned implements the replace-owned ownership-proving add via RFC 4703
// DHCID conflict resolution. The two-condition "DHCID matches OR name unused"
// guard cannot be a single RFC 2136 prerequisite (prerequisites are AND-ed),
// so it is two sequential attempts (RFC 4703 §5.3.2):
//
//  1. Attempt A — add A/AAAA (+ DHCID, when there is a client identity) with a
//     NAME-NOT-IN-USE prerequisite. Success ⇒ a fresh name we now own.
//  2. On YXDOMAIN/YXRRSET (the name already exists) — Attempt B — add the same
//     records with a DHCID-MATCHES-OURS prerequisite (a value-dependent RRset-
//     exists prereq, RFC 2136 §2.4.2). Success ⇒ a name WE already own,
//     refreshed. Another YX ⇒ a third party owns the name: REFUSE by returning
//     the errDDNSConflictRefused sentinel (and counting the conflict). The
//     manager classifies that sentinel as a skip — NOT a hard failure and NOT
//     a success — so upsertLocked records NO ownership for the refused name.
//     Recording phantom ownership would let a later release delete a record
//     xpf did not create (#2648 MAJOR-1).
//
// When the lease has no client identity there is no DHCID to match, so the
// name-not-in-use prerequisite alone gates the claim: a pre-existing name (by
// anyone) is refused (same sentinel) and never adopted.
func (u *rfc2136Updater) sendAddOwned(ctx context.Context, zone string, rr dns.RR) error {
	// #14602/#14995: a manager-owned sibling forward record already
	// occupies this name (the other family's A/AAAA — the manager
	// threads SiblingFamilyOwned + SiblingClientID from its store,
	// #14604). The sibling's DHCID was digested from a
	// production-shaped identity string (`cid:`/`mac:` v4 vs `duid:` v6)
	// that THIS family's identity can never reproduce, so Attempt B
	// below could never match it. The store flag alone is NOT proof
	// (#14995: any client that merely REQUESTED the hostname entered
	// the store): prove the sibling's exact DHCID on the wire first.
	// Only a proven sibling earns the per-type add below; an unproven
	// claim falls through to Attempts A/B, whose name-level and
	// own-DHCID guards refuse it without touching the victim.
	if u.siblingCandidate(rr) {
		if sib, ok := u.siblingDHCIDRR(rr); ok {
			proven, perr := u.proveSiblingDHCID(ctx, zone, sib)
			if perr != nil {
				return perr
			}
			if proven {
				return u.sendAddSiblingProven(ctx, zone, rr)
			}
			// #16591: the sibling may still carry its pre-#14995
			// legacy DHCID (published before the device digest).
			// siblingDHCIDRR digests from the SIBLING identity, so
			// the legacy candidate is that identity's legacy RR.
			if sibID := u.siblingProofIdentity(); sibID != "" {
				if legacySib, lok := legacyDHCIDRR(sibID, rr.Header().Name, rr.Header().Ttl); lok {
					lproven, lerr := u.legacyProbe(ctx, zone, []*dns.DHCID{legacySib})
					if lerr != nil {
						return lerr
					}
					if lproven >= 0 {
						return u.sendAddSiblingProvenLegacy(ctx, zone, rr, legacySib)
					}
				}
			}
		}
	}
	dhcid, hasDHCID := u.dhcidForRR(rr)

	// Attempt A: fresh-name claim (name not in use).
	mA := new(dns.Msg)
	mA.SetUpdate(dns.Fqdn(zone))
	mA.NameNotUsed([]dns.RR{rr})
	if hasDHCID {
		mA.Insert([]dns.RR{rr, dhcid})
	} else {
		mA.Insert([]dns.RR{rr})
	}
	resp, err := u.exchange(ctx, mA)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain:
		// Name already exists — fall through to the ownership-proving retry.
	default:
		return rcodeError(resp.Rcode)
	}

	if !hasDHCID {
		// No ownership proof available and the name already exists: this is a
		// pre-existing record we cannot claim as ours. Refuse (count + skip)
		// rather than adopt it — adopting would let a later release delete a
		// record xpf did not create (#2648). Signal the refusal with the
		// sentinel so the manager records NO ownership (a no-identity lease's
		// delete has no DHCID guard, so phantom ownership here would delete the
		// third party's record on release).
		if u.onConflict != nil {
			u.onConflict()
		}
		return errDDNSConflictRefused
	}

	// Attempt B: adopt/refresh a name whose existing DHCID matches OURS.
	// Use a SEPARATE copy of the DHCID for the prerequisite vs the update
	// section: miekg's Used()/Insert() mutate the RR header class in place, so
	// sharing one pointer would let Insert (CLASS=INET) clobber the
	// prerequisite's value-dependent class and corrupt the ownership check.
	mB := new(dns.Msg)
	mB.SetUpdate(dns.Fqdn(zone))
	mB.Used([]dns.RR{dns.Copy(dhcid)}) // value-dependent: our exact DHCID must exist
	mB.Insert([]dns.RR{rr, dhcid})
	resp, err = u.exchange(ctx, mB)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain, dns.RcodeNXRrset, dns.RcodeNameError:
		// The existing DHCID is NOT ours under the current device
		// digest — but it may be the pre-#14995 legacy per-identity
		// digest of the SAME client (#16591). Probe it before
		// refusing: on a legacy match, adopt the name AND migrate it
		// onto the device DHCID in the same UPDATE.
		if legacy, ok := u.legacyDHCIDForRR(rr); ok {
			proven, perr := u.legacyProbe(ctx, zone, []*dns.DHCID{legacy})
			if perr != nil {
				return perr
			}
			if proven >= 0 {
				return u.sendAddOwnedLegacy(ctx, zone, rr, dhcid, legacy)
			}
		}
		// The existing DHCID is NOT ours (or absent): a third party owns this
		// name. Refuse to claim it — record NO ownership (the sentinel tells
		// the manager not to put()), so a later release cannot delete it
		// (#2648).
		if u.onConflict != nil {
			u.onConflict()
		}
		return errDDNSConflictRefused
	default:
		return rcodeError(resp.Rcode)
	}
}

// sendAddOwnedLegacy adopts a name proven (by legacyProbe) to carry
// the pre-#14995 DHCID of this same client (#16591): one UPDATE that
// requires the legacy DHCID, publishes the new forward RR + the
// current device DHCID, and removes the legacy DHCID, so the name
// converges onto the device digest. When keepSiblingDHCID holds
// (the other family's record still shares the name), the caller —
// sendAddSiblingProvenLegacy — has already rewritten the message;
// this entry point always migrates (removes the legacy RR).
func (u *rfc2136Updater) sendAddOwnedLegacy(ctx context.Context, zone string, rr dns.RR, dhcid, legacy *dns.DHCID) error {
	return u.sendAddOwnedLegacyKeep(ctx, zone, rr, dhcid, legacy, false)
}

// sendAddOwnedLegacyKeep is sendAddOwnedLegacy with the migration
// conditional: keepSibling=true publishes the new family RR +
// device DHCID but RETAINS the legacy DHCID, which is still the
// surviving sibling family's only wire proof (its delete replays
// its own identity, and its Attempt B can only match its legacy
// digest until it too migrates — removing the legacy RR here would
// strand the sibling exactly as #16591 strands the primary).
func (u *rfc2136Updater) sendAddOwnedLegacyKeep(ctx context.Context, zone string, rr dns.RR, dhcid, legacy *dns.DHCID, keepSibling bool) error {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	m.Used([]dns.RR{dns.Copy(legacy)})
	m.Insert([]dns.RR{rr, dhcid})
	if !keepSibling {
		m.Remove([]dns.RR{dns.Copy(legacy)})
	}
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain, dns.RcodeNXRrset, dns.RcodeNameError:
		if u.onConflict != nil {
			u.onConflict()
		}
		return errDDNSConflictRefused
	default:
		return rcodeError(resp.Rcode)
	}
}

// sendAddSiblingProvenLegacy publishes this family's forward RR at a
// name whose sibling DHCID was proven only under the pre-#14995
// legacy digest (#16591): the sibling's presence is proven, but the
// legacy DHCID is RETAINED (see sendAddOwnedLegacyKeep) and the
// device DHCID is added alongside it — RFC 4701 §3.5 caps DHCID at
// one RR per owner, but the two RRs here are ONE logical owner's
// migration bridge: the sibling's own refresh migrates it (removes
// the legacy RR) and the last delete removes the device RR, so the
// name ends with exactly one DHCID again. A same-type RRset that
// predates the sibling still refuses via RRsetNotUsed.
func (u *rfc2136Updater) sendAddSiblingProvenLegacy(ctx context.Context, zone string, rr dns.RR, legacy *dns.DHCID) error {
	dhcid, hasDHCID := u.dhcidForRR(rr)
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	m.RRsetNotUsed([]dns.RR{rr})
	m.Used([]dns.RR{dns.Copy(legacy)})
	if hasDHCID {
		m.Insert([]dns.RR{rr, dhcid})
	} else {
		m.Insert([]dns.RR{rr})
	}
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain, dns.RcodeNXRrset, dns.RcodeNameError:
		if u.onConflict != nil {
			u.onConflict()
		}
		return errDDNSConflictRefused
	default:
		return rcodeError(resp.Rcode)
	}
}

// proveSiblingDHCID reports whether the sibling's exact DHCID is
// present on the wire at its name (#14995). It sends a
// prerequisite-only RFC 2136 UPDATE (no update section): NOERROR
// means the value-dependent Used prerequisite held; NXRRSET /
// YXRRSET / YXDOMAIN / NXDOMAIN mean it did not. Any other rcode is
// a transport-level failure. This is the wire proof the store flag
// alone cannot provide — a write-ahead intent whose add never
// landed, or a foreign client's store row, has no DHCID on the wire
// and proves nothing.
func (u *rfc2136Updater) proveSiblingDHCID(ctx context.Context, zone string, sib *dns.DHCID) (bool, error) {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	m.Used([]dns.RR{dns.Copy(sib)})
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return false, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return true, nil
	case dns.RcodeNXRrset, dns.RcodeYXRrset, dns.RcodeYXDomain, dns.RcodeNameError:
		return false, nil
	default:
		return false, rcodeError(resp.Rcode)
	}
}

// sendAddSiblingProven publishes this family's forward RR + its OWN
// DHCID at a name whose sibling DHCID was just proven on the wire
// (#14602/#14995). The per-type RRsetNotUsed prerequisite refuses a
// same-type RRset that predates the sibling (foreign or stale); the
// sibling's forward RR and DHCID are left untouched. Each family's
// delete later removes only its own forward RR + its own DHCID
// (sendRemoveForward replays the publishing identity — real deletes
// never carry a sibling signal).
func (u *rfc2136Updater) sendAddSiblingProven(ctx context.Context, zone string, rr dns.RR) error {
	dhcid, hasDHCID := u.dhcidForRR(rr)
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	m.RRsetNotUsed([]dns.RR{rr})
	if hasDHCID {
		m.Insert([]dns.RR{rr, dhcid})
	} else {
		m.Insert([]dns.RR{rr})
	}
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeYXRrset, dns.RcodeYXDomain, dns.RcodeNXRrset, dns.RcodeNameError:
		if u.onConflict != nil {
			u.onConflict()
		}
		return errDDNSConflictRefused
	default:
		return rcodeError(resp.Rcode)
	}
}

// sendAddSelfOwned publishes a SELF-OWNED forward record (Surface A router /
// interface-address publish, #2691 P2) as an ATOMIC IN-PLACE REPLACE: a single
// RFC 2136 UPDATE that, in one message, deletes the existing RRset OF OUR TYPE
// at our name (RFC 2136 §2.5.2 delete-RRset, CLASS=ANY, no rdata) and then
// inserts the new rdata. Because both ops are in the SAME UPDATE, the server
// applies them atomically — there is NO withdraw-then-add blackhole window, and
// the new address is live the instant the old one is gone.
//
// Why this (vs the DHCID/name-not-in-use path): a router record has no DHCID
// (the firewall is the authoritative owner of its OWN configured FQDN), so the
// lease path's two prerequisites both REFUSE a pre-existing name — which would
// pin the record at its first address forever (the bug this fixes). The
// firewall owns the NAME, so an in-place replace of its own forward type is the
// correct, idempotent self-ownership mechanism: a same-address re-publish
// (forced-refresh) deletes-then-re-adds the identical RR (a no-op net change
// that SUCCEEDS), and an address change replaces the rdata atomically.
//
// Exact-RR / co-resident safety (#3739): the replace is now VALUE-SPECIFIC. When
// the previous published value is known (u.selfOwnedPrevAddr, threaded from the
// manager) and differs from the new one, the message pairs an EXACT-RR delete of
// xpf's OWN prior rdata (RFC 2136 §2.5.4, CLASS=NONE) with the insert of the new
// rdata — so a CO-RESIDENT FOREIGN A/AAAA at a shared name SURVIVES (the old
// whole-RRset delete destroyed every same-type record at the name). Both ops are
// in the SAME UPDATE, so the replace stays atomic and no-blackhole. When the
// prior value is unknown (first publish) or equal to the new one, the message is
// Insert-only — additive, coexisting with any foreign RR (a same-value re-publish
// is an idempotent no-op). It never touches a different RR type at the name and
// never issues a delete-name/delete-RRset. The third-party case: if an operator
// points two firewalls' Surface-A FQDNs at the SAME name their records now
// COEXIST (each only manages its own value) rather than fighting — non-destructive
// by design; the per-RG HA gate still prevents the in-cluster two-writer case.
func (u *rfc2136Updater) sendAddSelfOwned(ctx context.Context, zone string, rr dns.RR) error {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	// Value-specific replace: remove ONLY xpf's own prior rdata (exact-RR delete)
	// when it is known and differs from the new value. Skipped on a first publish
	// (invalid prev) or a same-value re-publish (Insert is idempotent).
	prevs := u.selfOwnedPrevAddrs
	if len(prevs) == 0 && u.selfOwnedPrevAddr.IsValid() {
		prevs = []netip.Addr{u.selfOwnedPrevAddr}
	}
	for _, p := range prevs {
		if prev := p.Unmap(); prev.IsValid() {
			if cur, ok := rrAddr(rr); !ok || cur != prev {
				if prevRR, ok := prevSelfOwnedRR(prev, rr); ok {
					m.Remove([]dns.RR{prevRR})
				}
			}
		}
	}
	m.Insert([]dns.RR{rr})
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return nil
	default:
		return rcodeError(resp.Rcode)
	}
}

// rrAddr extracts the netip.Addr rdata from an A/AAAA RR (ok=false for any other
// type or an unparseable address). Used by the self-owned value-specific replace
// to compare xpf's previous value against the new one.
func rrAddr(rr dns.RR) (netip.Addr, bool) {
	switch v := rr.(type) {
	case *dns.A:
		if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
			return a.Unmap(), true
		}
	case *dns.AAAA:
		if a, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// prevSelfOwnedRR builds the exact-RR-delete RR for xpf's PREVIOUS self-owned
// value (#3739), matching the name/TTL and the forward TYPE of the record being
// published. ok=false when prev's family does not match cur's type — a
// cross-family delete is never emitted (a Surface A scope is family-fixed, so
// this is belt-and-suspenders, never a normal case).
func prevSelfOwnedRR(prev netip.Addr, cur dns.RR) (dns.RR, bool) {
	prev = prev.Unmap()
	if !prev.IsValid() {
		return nil, false
	}
	name := cur.Header().Name
	ttl := cur.Header().Ttl
	switch cur.(type) {
	case *dns.A:
		if !prev.Is4() {
			return nil, false
		}
		a4 := prev.As4()
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.IP(a4[:]),
		}, true
	case *dns.AAAA:
		if !prev.Is6() {
			return nil, false
		}
		a16 := prev.As16()
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: net.IP(a16[:]),
		}, true
	}
	return nil, false
}

// sendRemove issues an exact-RR delete (RFC 2136 §2.5.4 via miekg Remove,
// which forces TTL=0 / CLASS=NONE). An NXRRSET/NXDOMAIN-style "nothing to
// delete" is benign and treated as success (idempotent delete).
func (u *rfc2136Updater) sendRemove(ctx context.Context, zone string, rr dns.RR) error {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	m.Remove([]dns.RR{rr})
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNXRrset, dns.RcodeNameError:
		return nil
	default:
		return rcodeError(resp.Rcode)
	}
}

// sendRemoveForward deletes the forward A/AAAA record. Under replace-owned
// (#2648) it is OWNERSHIP-GUARDED: when the record carries a client identity,
// it prepends a "DHCID matches OURS" prerequisite (RFC 2136 §2.4.2 value-
// dependent RRset-exists) and deletes the A/AAAA AND the DHCID together, so
// xpf removes a name ONLY when the on-wire DHCID proves xpf created it. If the
// DHCID does not match (a third party re-published the name, or there is no
// DHCID at all = a manual record), the prerequisite fails and the delete is
// SKIPPED + counted — xpf never deletes a record it does not own.
//
// The state store already prevents constructing a delete for a tuple xpf
// never recorded; this adds a SECOND, on-wire guard against the narrow race
// where a third party adopted the exact name+address between xpf's add and
// release. Without a client identity (no DHCID was ever written) the delete is
// the plain exact-RR delete — still only the firewall's own (name,type,rdata)
// tuple, never a delete-RRset.
//
// keepDHCID (#2700): when ANOTHER owned record still shares this FQDN+ClientID
// (a dual-stack client whose A and AAAA carry the SAME shared DHCID), the DHCID
// must SURVIVE this delete so the remaining family's record stays
// DHCID-protected (RFC 4703) and its eventual delete still satisfies the
// DHCID-match prerequisite. In that case the DHCID-match PREREQUISITE is still
// sent (the delete stays ownership-guarded — xpf removes the A/AAAA only when
// the on-wire DHCID proves xpf created it) but the DHCID itself is OMITTED from
// the Remove section, so only the specific A/AAAA is removed. When this is the
// LAST owned record under the name (keepDHCID=false) the DHCID is removed with
// it (the pre-#2700 behaviour), so a fully-released name leaves no orphan DHCID.
// keepSiblingMarker (#16597): when OTHER same-device owned records
// still share this FQDN, the device proof marker stays so the
// surviving family's next-cycle add can prove its sibling on the
// wire. When this is the last family (#16597 false), the marker is
// removed value-specifically so the name is not burned for a later
// single-family or foreign claim.
func (u *rfc2136Updater) sendRemoveForward(ctx context.Context, zone string, rr dns.RR, keepDHCID bool, keepSiblingMarker ...bool) error {
	// #14429/#14432: a garbage policy must not take any delete branch.
	// Valid non-replace-owned policies keep the plain exact-RR delete;
	// an invalid value (only reachable via a directly-built updater,
	// since newRFC2136Updater refuses it) fails closed.
	if u.conflictPolicy != "replace-owned" {
		if u.conflictPolicy != "skip-existing" && u.conflictPolicy != "strict-fail" {
			return fmt.Errorf("ddns: invalid conflict-policy %q (valid: replace-owned, skip-existing, strict-fail); refusing DELETE of %s", u.conflictPolicy, rr.Header().Name)
		}
		keep := len(keepSiblingMarker) > 0 && keepSiblingMarker[0]
		if keep {
			return u.sendRemove(ctx, zone, rr)
		}
		// #16597: withdraw the device proof marker with the last
		// family. Two steps: first the device DHCID (a ghost when
		// never published — an exact-match no-op), then the
		// exact-RR forward delete. A preceding marker delete must
		// not strand the forward RR when the caller already decided
		// this is the last family (the forward tuple is already owned
		// and proven by state, not by the marker which is never
		// replayed as a prerequisite under these policies). A failed
		// marker delete surfaces after the forward delete is still
		// attempted so a transient marker error cannot wedge the
		// forward delete forever; the marker retry is driven by the
		// retained siblingMarkerRR on the next delete cycle.
		var markErr error
		if marker, ok := u.ownDHCIDRR(rr); ok {
			markErr = u.sendRemove(ctx, zone, marker)
			if markErr == nil && u.namedMarker(rr.Header().Name) != nil &&
				dns.CanonicalName(u.siblingMarkerRR.Hdr.Name) == dns.CanonicalName(rr.Header().Name) {
				u.siblingMarkerRR = nil
			}
		}
		if err := u.sendRemove(ctx, zone, rr); err != nil {
			return err
		}
		return markErr
	}
	dhcid, hasDHCID := u.dhcidForRR(rr)
	if !hasDHCID {
		// No DHCID was ever published for this record (no client identity):
		// fall back to the plain exact-RR delete of the firewall's own tuple.
		return u.sendRemove(ctx, zone, rr)
	}
	// #16591: probe device first, then legacy (same order as Attempt
	// B). A single AND-ed Used(device,legacy) can never hold — the
	// name carries at most one of the two RRs in the common case.
	matchedLegacy := false
	if legacy, ok := u.legacyDHCIDForRR(rr); ok {
		idx, perr := u.legacyProbe(ctx, zone, []*dns.DHCID{dhcid, legacy})
		if perr != nil {
			return perr
		}
		if idx < 0 {
			if u.onConflict != nil {
				u.onConflict()
			}
			return nil
		}
		matchedLegacy = idx == 1
	}
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	// Separate DHCID copies for the prerequisite vs the delete: Remove() sets
	// CLASS=NONE in place, which would otherwise corrupt the value-dependent
	// Used() prerequisite that proves we own the record.
	if matchedLegacy {
		legacy, _ := u.legacyDHCIDForRR(rr)
		m.Used([]dns.RR{dns.Copy(legacy)})
		if keepDHCID {
			m.Remove([]dns.RR{rr})
		} else {
			// Last owner: remove the legacy DHCID AND sweep any
			// device DHCID left by a sibling's legacy migration.
			m.Remove([]dns.RR{rr, legacy, dhcid})
		}
	} else {
		m.Used([]dns.RR{dns.Copy(dhcid)}) // prerequisite: our exact DHCID must exist
		if keepDHCID {
			// A sibling family's record still shares this DHCID (#2700): remove only
			// the A/AAAA, leave the shared DHCID so the survivor stays protected.
			m.Remove([]dns.RR{rr})
		} else {
			m.Remove([]dns.RR{rr, dhcid})
			// #16591: also sweep a co-resident legacy DHCID of the
			// SAME identity (left by a sibling migration) so the
			// last delete leaves no orphan. Exact-RR remove of an
			// absent RR is a no-op.
			if legacy, ok := u.legacyDHCIDForRR(rr); ok {
				m.Remove([]dns.RR{legacy})
			}
		}
	}
	resp, err := u.exchange(ctx, m)
	if err != nil {
		return err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// Prerequisite held (our DHCID is present): the delete applied.
		return nil
	case dns.RcodeNXRrset, dns.RcodeYXRrset, dns.RcodeYXDomain, dns.RcodeNameError:
		// The DHCID prerequisite failed between probe and delete
		// (or, with no distinct legacy, the device prerequisite
		// failed): the name's DHCID is not ours. Skip + count.
		if u.onConflict != nil {
			u.onConflict()
		}
		return nil
	default:
		return rcodeError(resp.Rcode)
	}
}

// unsignedUpdateWarned dedups the #4483 once-per-provider runtime warning
// emitted the first time this process sends an UNSIGNED (no-TSIG) DNS UPDATE to
// a given update server. It is keyed by the server host:port because the
// manager rebuilds the rfc2136Updater every Reconcile cycle
// (NewProductionManager resolves the backend from the policy at the start of
// each pass), so a per-updater sync.Once would re-warn every cycle. The map
// only ever grows by the small, bounded number of distinct update servers
// configured across DHCP DDNS + Surface A providers.
var unsignedUpdateWarned sync.Map // server string -> struct{}

// warnUnsignedOnce logs a single WARN — the first time this process sends an
// unsigned update to u.server — that the update is unauthenticated and the
// server's response rcode is forgeable (#4483). Subsequent unsigned updates to
// the same server are silent. Configuring tsig-key/tsig-secret authenticates
// updates (exchange requires a TSIG-signed response, #14603), so the message
// points the operator there.
func (u *rfc2136Updater) warnUnsignedOnce() {
	if _, loaded := unsignedUpdateWarned.LoadOrStore(u.server, struct{}{}); loaded {
		return
	}
	slog.Warn("ddns: sending UNSIGNED DNS UPDATE (no tsig-key configured); "+
		"the update is unauthenticated and the server's response rcode is "+
		"forgeable — a spoofed NOERROR records a name as published though the "+
		"server wrote nothing (silent blackhole) and a spoofed REFUSED "+
		"suppresses a legitimate publish. Configure tsig-key/tsig-secret to "+
		"authenticate updates.",
		"server", redactedUpdateServer(u.server))
}

// validateTSIGResponse enforces the #14603 contract: when TSIG is
// configured, a response is only trustworthy if it carries a TSIG
// record for the configured key name and algorithm. miekg/dns only
// verifies the MAC when a TSIG RR is present (client.go ReadMsg: it
// verifies if IsTsig()!=nil and otherwise returns err=nil), so an
// UNSIGNED reply to a signed UPDATE would otherwise be accepted and
// its forgeable rcode would set the publish/ownership verdict — the
// residual #4483 gap for exactly the deployments that configured
// TSIG. A signed reply with a bad MAC already fails inside miekg and
// never reaches here. The error never carries the secret.
func (u *rfc2136Updater) validateTSIGResponse(resp *dns.Msg, proto string) error {
	if u.tsigKeyName == "" {
		return nil
	}
	t := resp.IsTsig()
	suffix := ""
	if proto != "" {
		suffix = " (" + proto + ")"
	}
	if t == nil {
		return fmt.Errorf("ddns: unsigned response to TSIG-signed update from %s%s: "+
			"refusing to trust its rcode", redactedUpdateServer(u.server), suffix)
	}
	if !strings.EqualFold(dns.CanonicalName(t.Hdr.Name), dns.CanonicalName(u.tsigKeyName)) {
		return fmt.Errorf("ddns: TSIG response from %s%s signed with unexpected key %q (want %q): "+
			"refusing to trust its rcode", redactedUpdateServer(u.server), suffix, t.Hdr.Name, u.tsigKeyName)
	}
	if !strings.EqualFold(dns.CanonicalName(t.Algorithm), dns.CanonicalName(u.tsigAlgo)) {
		return fmt.Errorf("ddns: TSIG response from %s%s uses unexpected algorithm %q (want %q): "+
			"refusing to trust its rcode", redactedUpdateServer(u.server), suffix, t.Algorithm, u.tsigAlgo)
	}
	return nil
}

// exchange signs (when TSIG configured) and sends a message UDP-first,
// retrying over TCP on a truncated response. When TSIG is configured
// the response MUST be TSIG-signed with the configured key/algorithm
// (#14603); an unsigned, wrong-key, or wrong-algorithm reply is a
// transport error on BOTH legs and never reaches the rcode verdict.
// The per-call context bounds the network I/O.
func (u *rfc2136Updater) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if u.tsigKeyName != "" {
		m.SetTsig(u.tsigKeyName, u.tsigAlgo, 300, time.Now().Unix())
	} else if u.requireTSIG && !updateServerIsLoopback(u.server) {
		// #15992 runtime backstop: a require-tsig config that reached the
		// backend without a key (tolerant load) must never trust an
		// unsigned rcode from a non-loopback server — the same loopback
		// exemption the strict commit gate applies. Refuse before any
		// UPDATE is sent (exchange only carries RFC 2136 UPDATEs; the
		// SOA zone-discovery query in querySOA is a separate path), so
		// no durable ownership is recorded on a forgeable verdict.
		return nil, fmt.Errorf("ddns: require-tsig is set but no tsig-key is configured for %s; refusing unsigned update", redactedUpdateServer(u.server))
	} else {
		// #4483: no TSIG key configured. The UPDATE is sent unsigned and the
		// publish/ownership verdict below keys on an UNAUTHENTICATED, forgeable
		// response rcode. Warn once per update server so the operator sees the
		// weakened posture (the commit-time check already warned; this catches
		// the runtime path too).
		u.warnUnsignedOnce()
	}
	if u.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, u.timeout)
		defer cancel()
	}
	resp, _, err := u.client.ExchangeContext(ctx, m, u.server)
	if err != nil {
		return nil, u.scrubServerError(err)
	}
	if resp == nil {
		return nil, errors.New("ddns: nil response from update server")
	}
	if err := u.validateTSIGResponse(resp, "udp"); err != nil {
		return nil, err
	}
	if resp.Truncated {
		// Retry over TCP. A dns.Client honors Net="tcp"; the test recorder
		// never truncates, so this path is production-only.
		if tc, ok := u.client.(*dns.Client); ok {
			tcpClient := *tc
			// #5327: keep the source-family pin on the TCP retry. If the UDP dial
			// was pinned to a family (cl.Net "udp4"/"udp6" for a configured
			// source-address), the retry must dial "tcp4"/"tcp6" so the source bind
			// still applies; an unpinned client (empty/"udp") retries plain "tcp".
			tcpClient.Net = "tcp" + networkFamilySuffix(tc.Net)
			// Derive the TCP retry context from the CALLER's ctx (not
			// context.Background()) so a canceled/deadline'd reconcile pass
			// actually cancels the retry. The per-exchange timeout is still
			// applied on top, so the retry is bounded even when the caller has
			// no deadline of its own.
			if u.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, u.timeout)
				defer cancel()
			}
			resp, _, err = tcpClient.ExchangeContext(ctx, m, u.server)
			if err != nil {
				return nil, u.scrubServerError(err)
			}
			if resp == nil {
				return nil, errors.New("ddns: nil response from update server (tcp)")
			}
			if err := u.validateTSIGResponse(resp, "tcp"); err != nil {
				return nil, err
			}
		} else if u.tsigKeyName != "" {
			// A truncated TSIG-signed exchange that cannot retry over TCP
			// (non-*dns.Client seam) must not fall through with an
			// unverifiable verdict.
			return nil, errors.New("ddns: truncated TSIG-signed response cannot be retried over TCP")
		}
	}
	return resp, nil
}

// rcodeErr is the typed non-NOERROR update-rcode error. It carries the
// numeric rcode so isPTRSkippable can match NOTAUTH/REFUSED exactly via
// errors.As (no string sniffing), and it NEVER includes the TSIG secret
// (plan risk R6) — only the rcode string.
type rcodeErr struct{ rcode int }

func (e *rcodeErr) Error() string {
	name, ok := dns.RcodeToString[e.rcode]
	if !ok {
		name = fmt.Sprintf("rcode%d", e.rcode)
	}
	return fmt.Sprintf("ddns: update rejected (%s)", name)
}

// rcodeError turns a non-NOERROR update rcode into a typed error.
func rcodeError(rcode int) error { return &rcodeErr{rcode: rcode} }

// isPTRSkippable reports whether a reverse-zone error is a NOTAUTH/REFUSED
// that the PTR path degrades to a counted skip (plan §11 Q6) rather than a
// blocking failure. The forward/reverse senders wrap rcodeErr with
// fmt.Errorf, so errors.As unwraps to the typed cause.
func isPTRSkippable(err error) bool {
	if err == nil {
		return false
	}
	var re *rcodeErr
	if errors.As(err, &re) {
		return re.rcode == dns.RcodeNotAuth || re.rcode == dns.RcodeRefused
	}
	return false
}
