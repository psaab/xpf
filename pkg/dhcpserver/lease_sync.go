package dhcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// lease_sync.go: the read/seed half of #2239 HA DHCP-server lease
// synchronization (PATH C — xpf-managed replication over the existing
// pkg/cluster session-sync channel, re-instantiating the IPsec-SA-sync
// pattern). The cluster wire + standby-hold + takeover-orchestration live in
// pkg/cluster and pkg/daemon; this file owns ONLY the Kea side:
//
//   - GetSyncLeases4/6 — read the live, active lease set, preferring the Kea
//     lease_cmds control socket (lease{4,6}-get-all) and falling back to the
//     authoritative memfile parser (parseSyncLeases4/6) when the socket is not
//     yet up. Used by the MASTER's periodic + on-grant push.
//   - SeedSyncLeases4/6 — write held peer leases into a just-started Kea via
//     lease_cmds (lease{4,6}-add, falling back to lease{4,6}-update on an
//     "already exists" collision). Used on MASTER takeover (the
//     reinitiateIPsecSAs precedent).
//   - WaitControlSocket4/6 — bounded wait for the family's control socket to
//     accept a connection, so SeedSyncLeases runs after Kea is answering.
//
// CRITICAL (CLAUDE.md control-socket rule): these helpers talk ONLY to Kea's
// OWN unix control socket (and, as a fallback, read the memfile). They NEVER
// touch the userspace-helper control socket, so they cannot starve session
// installs or status polls.
//
// CLOCK INVARIANT (#2239 §6, the <60s answer): a SyncLease carries the lease's
// REMAINING LIFETIME, not an absolute wall-clock expiry. The peer's wall clock
// never enters the promoting node's computation — the absolute Kea `expire`
// epoch is recomputed at SEED time on the LOCAL clock (now + Remaining). This
// makes the design immune to peer wall-clock skew (the IPsec hazard PATH A
// inherits), the cluster channel only carrying a monotonic offset.

// Kea control-socket paths (one per family). The lease_cmds hook is loaded and
// a unix control-socket pointed here by generateKea{4,6}Config when lease sync
// is enabled. /run/kea is created by the kea packages (owned by _kea); xpfd
// runs as root and can connect.
const (
	keaControlSocket4 = "/run/kea/kea4-ctrl-socket"
	keaControlSocket6 = "/run/kea/kea6-ctrl-socket"
)

// keaControlTimeout bounds a single control-socket exchange (connect + write +
// read-to-EOF). Kept short: a lease read/seed must never wedge the periodic
// push loop or the takeover path. The seed path runs async post-start like
// reinitiateIPsecSAs, so a slow Kea only delays the seed, never the takeover.
const keaControlTimeout = 5 * time.Second

// keaDHCPDisableMaxPeriod bounds a takeover that dies after disabling DHCP but
// before the queued Kea restart. The normal restart happens immediately after
// the memfile pre-seed; this is only the fail-open recovery.
const keaDHCPDisableMaxPeriod = 300

// maxKeaResponseBytes bounds a single Kea control-socket response (#9003).
//
// The exchange was DEADLINE-bounded and byte-UNBOUNDED: keaControlTimeout caps
// how long the peer may stream, not how much, and over AF_UNIX 5 s at memory
// bandwidth is GB-scale. The decoded value is retained (lease4-get-all /
// lease6-get-all return every lease), so this is retention, not transient
// buffering.
//
// 64 MiB is far above a real answer — a lease row is ~200 B of JSON, so this
// admits ~300k leases, well past what Kea holds on this appliance — while
// removing the unbounded case. The sizing rule is the same one
// MaxControlRequestBytes follows: a cap that can reject a legitimate answer is a
// self-inflicted outage, so bound the pathological case, not the headroom.
const maxKeaResponseBytes = 64 << 20

// SyncLease is ONE DHCP-server lease (active or declined) in the cluster-portable form
// replicated to the peer. It is deliberately a flat, family-tagged record (no
// pointers, copy-by-value) so it can be encoded on the sync wire and held in
// the standby's process memory exactly like peerIPsecSAs.
//
// Remaining is the SECONDS of valid lifetime left at the moment the SENDER read
// the lease (Expire - now_sender). The receiver re-anchors it to fresh absolute
// time at seed (now_local + Remaining) — see the clock invariant above.
type SyncLease struct {
	Family int // 4 or 6

	Address  string // v4 dotted / v6 colon address (or PD prefix base for IA_PD)
	SubnetID int    // Kea subnet-id the lease belongs to

	// v4 identity. At least one of HWAddress / ClientID is set.
	HWAddress string // "aa:bb:cc:dd:ee:ff"
	ClientID  string // RFC 2131 client identifier, Kea hex form ("01:..")

	// v6 identity (DUID/IAID) + lease kind. Type is "IA_NA", "IA_TA", or "IA_PD".
	DUID      string
	IAID      uint32
	LeaseType string // v6: "IA_NA"/"IA_TA" (address) or "IA_PD" (prefix delegation)
	PrefixLen int    // v6 IA_PD: delegated prefix length (0 for IA_NA / IA_TA)

	Hostname  string
	FQDNFwd   bool // client requested forward DNS update
	FQDNRev   bool // client requested reverse DNS update
	ValidLife int  // the lease's configured valid-lifetime (seconds)
	Remaining int  // seconds of lifetime left at read time (clock-skew-safe)

	// PreferredRemaining is the SECONDS of PREFERRED lifetime left at the moment
	// the SENDER read the lease. For DHCPv6 the preferred lifetime is a SEPARATE
	// deadline from the valid lifetime: a DEPRECATED binding has preferred=0 with
	// a still-positive valid lifetime (the client must stop using the address for
	// new connections but the lease is not yet expired). It is re-anchored to the
	// receiver's local clock at seed exactly like Remaining (the #2239 clock
	// invariant) and the invariant 0 <= PreferredRemaining <= Remaining always
	// holds (#5073). A value of 0 means DEPRECATED. For DHCPv4 (no preferred
	// concept) and for leases synced from an OLDER peer that predates this field,
	// PreferredRemaining defaults to Remaining (preferred==valid), preserving the
	// pre-#5073 behavior.
	PreferredRemaining int

	State int // Kea lease state (0=default/active, 1=declined; 2 never synced)
}

// LeaseScopeAuthority proves which RG serves a canonical pool subnet in a lease
// snapshot. CIDR is the identity, not SyncLease.SubnetID: Kea may resolve a
// hash collision against the current rendered set, while ownership is defined
// by address membership in the configured pool. A scope is emitted only when
// the sender can attribute every pool in the DHCP group to one RG; mixed-RG
// groups intentionally remain unattributed and retain conservative whole-union
// behavior on takeover.
type LeaseScopeAuthority struct {
	Family     int
	CIDR       string
	RGID       int
	Generation uint64
	Served     bool
	Applied    bool
}

// LeaseSyncSnapshot is a full-set peer lease snapshot plus the ownership
// authority that was true when the sender read it. Received is explicit so a
// valid empty snapshot is distinguishable from never having received one.
type LeaseSyncSnapshot struct {
	Leases     []SyncLease
	Generation uint64
	Scopes     []LeaseScopeAuthority
	Received   bool
}

// LeaseSyncAuthority is the receiver's local proof state. It describes the
// canonical scopes this node currently serves; the peer snapshot supplies the
// sender-side Applied proof for a scope before negative exclusion is allowed.
type LeaseSyncAuthority struct {
	Scopes []LeaseScopeAuthority
}

// clampPreferredRemaining enforces the #5073 invariant 0 <= pref <= remaining.
// The preferred lifetime can never outlive the valid lifetime (RFC 8415 §6.3),
// and a negative computed remainder (a deprecated lease whose preferred deadline
// has already passed) floors to 0 (deprecated), never revives.
func clampPreferredRemaining(pref, remaining int) int {
	if pref < 0 {
		return 0
	}
	if pref > remaining {
		return remaining
	}
	return pref
}

// maxSyncLeaseLifetime caps a synced lease's Remaining/ValidLife (#10893). The
// wire carries lifetimes as uint32 seconds, so a buggy or compromised
// authenticated peer (or a legacy peer with no auth at all) can pin an address
// for ~136 years with one full-set push. Five years is ~1800x the rendered
// 1-day default and past any sane operator lease-time, while periodic
// full-set pushes refresh legitimately long leases long before the cap
// matters; the clamp direction is fail-safe (a shorter seeded lifetime only
// costs the client a renewal). It is also int32-safe for downstream consumers.
const maxSyncLeaseLifetime = 5 * 365 * 24 * 60 * 60 // 5 years, in seconds

// SanitizeSyncLeaseForFamily enforces the semantic contract a SyncLease must
// meet before it is trusted (#10893): the row's family matches the outer
// message family, the address parses as a servable unicast address of that
// family, an IA_PD row carries an in-range delegated prefix length, and
// lifetimes are clamped to [0, maxSyncLeaseLifetime] with the #5073
// preferred<=valid invariant preserved. It returns the sanitized row and
// whether the row is keepable; a false row must be dropped, never seeded.
//
// All three sinks call it — the cluster receive filter (framing-then-semantics,
// so one bad row cannot poison the held set or any consumer), the control-
// socket seed, and the memfile pre-seed — so the decode/seed boundary cannot
// drift. Lifetimes clamp rather than drop: an expired row (Remaining<=0) still
// reaches the #4871 guards, which own the drop-vs-revive disposition.
// IsDeclined reports whether the lease is a Kea declined (state=1) row.
func (l SyncLease) IsDeclined() bool { return l.State == keaStateDeclined }

func SanitizeSyncLeaseForFamily(family int, l SyncLease) (SyncLease, bool) {
	if l.Family != family {
		return l, false
	}
	if !validSyncLeaseAddressForFamily(family, l.Address) {
		return l, false
	}
	if !validSyncLeasePrefixLen(l) {
		return l, false
	}
	if l.State != keaStateDefault && l.State != keaStateDeclined {
		return l, false
	}
	l.Hostname = stripLeaseControlChars(l.Hostname)
	l.HWAddress = stripLeaseControlChars(l.HWAddress)
	l.ClientID = stripLeaseControlChars(l.ClientID)
	l.DUID = stripLeaseControlChars(l.DUID)
	l.ValidLife = clampSyncLeaseLifetime(l.ValidLife)
	l.Remaining = clampSyncLeaseLifetime(l.Remaining)
	if l.ValidLife > 0 && l.Remaining > l.ValidLife {
		l.Remaining = l.ValidLife
	}
	l.PreferredRemaining = clampPreferredRemaining(clampSyncLeaseLifetime(l.PreferredRemaining), l.Remaining)
	return l, true
}

// stripLeaseControlChars removes ASCII control characters (including CR/LF)
// from a client- or peer-supplied lease string field (#14730). A bare CR in
// a hostname breaks Go encoding/csv parsing of the memfile (9-field row ->
// DDNS halt) and Kea's own CSV loader; stripping at the shared sanitize
// boundary protects the memfile writer, socket seed, and cluster hold.
func stripLeaseControlChars(s string) string {
	if !strings.ContainsAny(s, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f\r\n\t") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// validSyncLeaseAddressForFamily reports whether address parses as an IP of the
// given family in that family's textual form and is a plausible served
// address: global-scope unicast, never unspecified/loopback/multicast/
// link-local/broadcast. DHCP never assigns those, so a peer row carrying one
// is corrupt or hostile.
func validSyncLeaseAddressForFamily(family int, address string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	switch family {
	case 4:
		// Dotted-quad form only: a v6 rendering (including v4-mapped) is not
		// a v4 lease Kea could install. 0/8 and 240/4 are reserved, not
		// assignable unicast lease space.
		v4 := ip.To4()
		if v4 == nil || strings.Contains(address, ":") || v4[0] == 0 || v4[0] >= 240 {
			return false
		}
	case 6:
		// Colon form only, and never a v4 address in disguise.
		if ip.To4() != nil || !strings.Contains(address, ":") {
			return false
		}
	default:
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

// validSyncLeasePrefixLen bounds the delegated prefix of a v6 IA_PD row to the
// protocol range 1..128 (#10893): a PrefixLen of 0 (or beyond 128) delegates
// nothing (or is unrepresentable) and must not seed. Non-PD rows carry no
// prefix — both seed paths force /128 or ignore the field — so any value is
// accepted rather than dropping a lease over an ignored column. v4 rows carry
// no prefix at all.
func validSyncLeasePrefixLen(l SyncLease) bool {
	if l.Family != 6 || l.LeaseType != "IA_PD" {
		return true
	}
	return l.PrefixLen >= 1 && l.PrefixLen <= 128
}

// clampSyncLeaseLifetime bounds one lifetime to the seedable range (#10893).
// Negatives floor to 0 (the #4871 guards drop the row downstream); over-long
// values clamp to maxSyncLeaseLifetime instead of pinning the address.
func clampSyncLeaseLifetime(v int) int {
	if v < 0 {
		return 0
	}
	if v > maxSyncLeaseLifetime {
		return maxSyncLeaseLifetime
	}
	return v
}

// IdentityKey returns a stable per-lease identity used for dedup/diff on the
// sender (on-grant change detection) and as the seed idempotency key. It mirrors
// the DDNS identity functions but is keyed on the address + identity so two
// renewals of the same binding compare equal except for Remaining.
func (l SyncLease) IdentityKey() string {
	if l.IsDeclined() {
		if l.Family == 6 {
			return fmt.Sprintf("6|declined|%s|%s|%d", l.Address, l.LeaseType, l.PrefixLen)
		}
		return "4|declined|" + l.Address
	}
	if l.Family == 6 {
		return fmt.Sprintf("6|%s|%s|%d|%s", l.Address, l.DUID, l.IAID, l.LeaseType)
	}
	id := l.ClientID
	if id == "" {
		id = l.HWAddress
	}
	return fmt.Sprintf("4|%s|%s", l.Address, id)
}

// keaCommand is one Kea control-socket request.
type keaCommand struct {
	Command   string `json:"command"`
	Arguments any    `json:"arguments,omitempty"`
}

// keaResponse is the generic Kea control-socket response envelope. result==0 is
// success; result==3 is "empty" (e.g. no leases) which lease{4,6}-get-all
// returns and which we treat as a successful empty set.
type keaResponse struct {
	Result    int             `json:"result"`
	Text      string          `json:"text"`
	Arguments json.RawMessage `json:"arguments"`
}

const (
	keaResultSuccess  = 0
	keaResultError    = 1
	keaResultEmpty    = 3
	keaResultConflict = 2 // lease already exists (lease-add) etc.
)

// keaLeaseJSON is the lease shape lease{4,6}-get-all returns and lease{4,6}-add
// accepts. Kea uses "valid-lft" + "cltt" (client-last-transaction-time epoch);
// the absolute expiry is cltt+valid-lft. On add we send an absolute "expire".
type keaLeaseJSON struct {
	IPAddress string  `json:"ip-address"`
	HWAddress string  `json:"hw-address,omitempty"`
	ClientID  string  `json:"client-id,omitempty"`
	DUID      string  `json:"duid,omitempty"`
	IAID      *uint32 `json:"iaid,omitempty"`
	Type      string  `json:"type,omitempty"`       // v6: IA_NA / IA_PD
	PrefixLen int     `json:"prefix-len,omitempty"` // v6 IA_PD
	SubnetID  int     `json:"subnet-id,omitempty"`
	ValidLft  int     `json:"valid-lft,omitempty"`
	// PreferredLft is a POINTER so an absent field (nil, an older Kea or a v4
	// lease) is distinguishable from an explicit preferred-lft:0 (a DEPRECATED
	// v6 binding). omitempty only drops a nil pointer, so a &0 still emits
	// "preferred-lft":0 on the add path — the deprecation must reach Kea (#5073).
	PreferredLft *int   `json:"preferred-lft,omitempty"`
	CLTT         int64  `json:"cltt,omitempty"`   // client-last-transaction-time epoch (get)
	Expire       int64  `json:"expire,omitempty"` // absolute expiry epoch (add)
	State        int    `json:"state"`
	Hostname     string `json:"hostname,omitempty"`
	FQDNFwd      bool   `json:"fqdn-fwd,omitempty"`
	FQDNRev      bool   `json:"fqdn-rev,omitempty"`
}

// keaLease4AddArguments preserves an explicitly empty hw-address for declined
// IPv4 adds. Kea's lease4 parser requires the member, while an empty HWAddr is
// the representation Kea itself stores for a declined lease.
type keaLease4AddArguments struct {
	keaLeaseJSON
	HWAddress string `json:"hw-address"`
}

// AppliedGeneration returns the daemon lease-authority generation of the most
// recent APPLIED authority-bearing apply for family (0 if none). #16855: the
// post-start lease-add backstop polls this so it only seeds the process that
// loaded the takeover config, not a still-running pre-restart Kea.
func (m *Manager) AppliedGeneration(family int) uint64 {
	if family != 4 && family != 6 {
		return 0
	}
	m.authorityMu.Lock()
	defer m.authorityMu.Unlock()
	r := m.authorityResults[authorityResultIndex(family)]
	if !r.applied {
		return 0
	}
	return r.generation
}

type keaLeaseGetAllArgs struct {
	Leases []keaLeaseJSON `json:"leases"`
}

// errUntrustedKeaPeer marks a control-socket connection whose peer is
// not the Kea runtime user (nor this process). It is a sentinel so
// callers and tests can tell a hostile/squatted socket apart from an
// ordinary dial failure.
var errUntrustedKeaPeer = errors.New("untrusted Kea control-socket peer")

// keaPeerUIDResolver reports the uid a Kea control-socket peer must
// carry (the resolved _kea/kea runtime user), or ok=false when neither
// Kea user exists on this host. It is a package seam so tests can pin
// the expected uid without a real _kea account. Production resolves
// the same user database names the memfile pre-seed uses (#2450),
// uncached: the lookup runs once per dial, never on a packet path,
// and caching it here would couple the peer check to a Manager the
// dialer does not hold.
var keaPeerUIDResolver = func() (int, bool) {
	uid, _, ok := lookupKeaOwner()
	return uid, ok
}

// keaPeerTrustError is the DECISION half of the peer check, split from
// the syscall shell so every arm is reachable from a test on any
// machine (a non-root test binary cannot manufacture a connection
// from a foreign uid; see #9003). peerUID is trusted when it is:
//
//   - the resolved Kea runtime uid (_kea/kea): the production case —
//     Kea runs as _kea, xpfd as root;
//   - root or this process's own euid, mirroring the reinject fix
//     (#16052, reinjectPeerTrustError16052) and the helper-socket
//     check (#9003): the root arm covers a Kea packaged to run as
//     root, and the euid arm lets a non-root test binary drive the
//     real production dialer against a stub server it holds itself
//     (in production xpfd is root, so the two arms coincide).
//
// Everything else — a foreign local user that won the pathname — is
// refused. A missing credential (nil) never reads as trusted.
func keaPeerTrustError(socketPath string, peerUID int) error {
	return keaPeerTrustErrorAs(socketPath, peerUID, os.Geteuid())
}

// keaPeerTrustErrorAs is keaPeerTrustError with the daemon euid made
// explicit, so a test can state the daemon/squatter relationship
// deterministically whatever uid the test binary itself runs as.
func keaPeerTrustErrorAs(socketPath string, peerUID, selfUID int) error {
	if peerUID == 0 || peerUID == selfUID {
		return nil
	}
	if keaUID, ok := keaPeerUIDResolver(); ok && peerUID == keaUID {
		return nil
	}
	return fmt.Errorf("%w: %s is held by uid %d, not the Kea runtime user; refusing to trust its leases",
		errUntrustedKeaPeer, socketPath, peerUID)
}

// keaGetsockoptUcred is the SO_PEERCRED syscall, seamed so a test can
// force a read failure (see TestKeaPeerUIDReadFailsClosed16058).
var keaGetsockoptUcred = unix.GetsockoptUcred

// readKeaPeerUID is the syscall shell: it asks the kernel who is on the
// other end of an AF_UNIX connection. It NEVER substitutes a zero
// value for a failed read — a zeroed unix.Ucred has Uid 0, which
// keaPeerTrustError accepts as root, so swallowing the error here
// would convert the guard into a fail-open (the #9003 lesson).
func readKeaPeerUID(socketPath string, conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("%w: %s is not an AF_UNIX connection (%T), so its peer cannot be identified",
			errUntrustedKeaPeer, socketPath, conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("%w: %s: obtain raw connection: %v", errUntrustedKeaPeer, socketPath, err)
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = keaGetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("%w: %s: read peer credentials: %v", errUntrustedKeaPeer, socketPath, err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("%w: %s: read peer credentials: %v", errUntrustedKeaPeer, socketPath, credErr)
	}
	if cred == nil {
		return 0, fmt.Errorf("%w: %s: kernel returned no peer credentials", errUntrustedKeaPeer, socketPath)
	}
	return int(cred.Uid), nil
}

// verifyKeaPeer reads SO_PEERCRED from a freshly dialed control-socket
// connection and refuses any peer that is not the Kea runtime user,
// root, or this process. It runs before a single command byte is
// written, so a squatter on the pathname can neither feed fabricated
// leases into HA sync nor receive lease-add commands.
func verifyKeaPeer(socketPath string, conn net.Conn) error {
	uid, err := readKeaPeerUID(socketPath, conn)
	if err != nil {
		return err
	}
	return keaPeerTrustError(socketPath, uid)
}

// keaPeerVerify is the peer check defaultKeaDialer applies to every
// connection it returns. It is a seam so a test can substitute a
// foreign-credential decision — a non-root test binary cannot
// manufacture a connection from a foreign uid, so the squatter's
// kernel credential cannot be produced directly (the #16052 shape).
// Production always runs verifyKeaPeer.
var keaPeerVerify = verifyKeaPeer

// keaSocketDialer abstracts the unix-socket dial for tests (a stub server can
// implement the lease_cmds wire). Production uses net.Dial.
type keaSocketDialer func(ctx context.Context, socketPath string) (net.Conn, error)

func defaultKeaDialer(ctx context.Context, socketPath string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := keaPeerVerify(socketPath, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// keaControl sends one command to the family control socket and decodes the
// response envelope. Kea answers a single JSON object and closes (or keeps
// open); we read to the first complete JSON value.
func keaControl(ctx context.Context, dial keaSocketDialer, socketPath string, cmd keaCommand) (*keaResponse, error) {
	if dial == nil {
		dial = defaultKeaDialer
	}
	dctx, cancel := context.WithTimeout(ctx, keaControlTimeout)
	defer cancel()
	conn, err := dial(dctx, socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial kea control socket %s: %w", socketPath, err)
	}
	defer conn.Close()
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	payload, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write kea command %s: %w", cmd.Command, err)
	}
	// Read the single JSON response. Kea writes one object; decode the first
	// value from the stream so a kept-open socket does not hang us.
	dec := json.NewDecoder(io.LimitReader(conn, maxKeaResponseBytes))
	var resp keaResponse
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode kea response for %s: %w", cmd.Command, err)
	}
	return &resp, nil
}

// readSyncLeasesViaSocket reads active leases for a family from the Kea control
// socket via lease{4,6}-get-all.
func readSyncLeasesViaSocket(ctx context.Context, dial keaSocketDialer, socketPath string, family int, now time.Time) ([]SyncLease, error) {
	cmd := keaCommand{Command: fmt.Sprintf("lease%d-get-all", family)}
	resp, err := keaControl(ctx, dial, socketPath, cmd)
	if err != nil {
		return nil, err
	}
	if resp.Result == keaResultEmpty {
		return nil, nil
	}
	if resp.Result != keaResultSuccess {
		return nil, fmt.Errorf("lease%d-get-all: result=%d text=%q", family, resp.Result, resp.Text)
	}
	var args keaLeaseGetAllArgs
	if len(resp.Arguments) > 0 {
		if err := json.Unmarshal(resp.Arguments, &args); err != nil {
			return nil, fmt.Errorf("lease%d-get-all decode args: %w", family, err)
		}
	}
	out := make([]SyncLease, 0, len(args.Leases))
	for _, kl := range args.Leases {
		l := keaLeaseRowFromSocket(kl, family).toSync(now)
		if l.State != keaStateDefault && l.State != keaStateDeclined {
			continue
		}
		if l.Remaining <= 0 {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// readSyncLeasesViaMemfile is the fallback reader. It decodes authoritative
// Kea rows through the destructive-safe parser and uses the same SyncLease
// projection as the socket path.
func readSyncLeasesViaMemfile(path string, family int, now time.Time) ([]SyncLease, error) {
	rows, err := parseSyncLeases(path, family, now)
	if err != nil {
		return nil, err
	}
	out := make([]SyncLease, 0, len(rows))
	for _, row := range rows {
		if family == 6 {
			if !row.IAIDOK {
				_, idErr := strconv.ParseUint(row.IAIDRaw, 10, 32)
				slog.Warn("dhcpserver: skipping v6 memfile lease with unparseable IAID",
					"address", row.Address, "identity", identity6(row.DUID, row.IAIDRaw), "error", idErr)
				continue
			}
			if !row.LeaseTypeOK {
				slog.Warn("dhcpserver: skipping v6 memfile lease with unparseable lease_type",
					"address", row.Address, "duid", row.DUID, "iaid", row.IAID)
				continue
			}
			if _, ok := stringToKeaLeaseType(row.LeaseType); !ok {
				slog.Warn("dhcpserver: skipping v6 memfile lease with unknown lease_type",
					"address", row.Address, "lease_type", row.LeaseType)
				continue
			}
		}
		lease := row.toSync(now)
		if lease.Remaining <= 0 {
			// Without an expire epoch there is no safe remaining lifetime.
			continue
		}
		out = append(out, lease)
	}
	return out, nil
}

// keaLeaseTypeToString maps the numeric Kea memfile lease_type column to the
// string form the control-socket path reports (and SeedSyncLeases6 consumes):
// 0 → IA_NA, 1 → IA_TA, 2 → IA_PD. ok is false for any other value so the
// caller skips a row it cannot faithfully type rather than mis-seeding it
// (#2262). IA_TA is passed through for parity with the socket path, which
// reports whatever kind Kea returns.
//
// keaLeaseTypeToString and stringToKeaLeaseType are a single total inverse
// pair: every value one accepts, the other round-trips back, and neither has a
// branch the other lacks. The memfile WRITE path (writeMemfile6) and the
// control-socket add path (syncLeaseToKea) both go through stringToKeaLeaseType
// so the read↔write lease-type mapping cannot drift to re-introduce the #2268
// IA_TA downgrade (a synced IA_TA lease read as IA_TA but written back as
// IA_NA).
func keaLeaseTypeToString(t int) (string, bool) {
	switch t {
	case keaLeaseTypeIANA:
		return "IA_NA", true
	case keaLeaseTypeIATA:
		return "IA_TA", true
	case keaLeaseTypeIAPD:
		return "IA_PD", true
	}
	return "", false
}

// stringToKeaLeaseType is the exact inverse of keaLeaseTypeToString: it maps the
// SyncLease.LeaseType string back to the numeric Kea memfile lease_type column.
// An empty string defaults to IA_NA (an address lease) — the historical
// behavior for a lease whose kind the read side could not determine. ok is false
// for any other non-empty value so the WRITE path never silently emits a
// mis-typed row; the caller falls back to IA_NA and logs.
func stringToKeaLeaseType(s string) (int, bool) {
	switch s {
	case "", "IA_NA":
		return keaLeaseTypeIANA, true
	case "IA_TA":
		return keaLeaseTypeIATA, true
	case "IA_PD":
		return keaLeaseTypeIAPD, true
	}
	return keaLeaseTypeIANA, false
}

// GetSyncLeases4 returns the active v4 leases this node is serving, preferring
// the control socket and falling back to the memfile. now is injectable for
// tests (production passes time.Now()).
func (m *Manager) GetSyncLeases4(ctx context.Context, now time.Time) ([]SyncLease, error) {
	return m.getSyncLeases(ctx, 4, now)
}

// GetSyncLeases6 returns the active v6 leases this node is serving.
func (m *Manager) GetSyncLeases6(ctx context.Context, now time.Time) ([]SyncLease, error) {
	return m.getSyncLeases(ctx, 6, now)
}

func (m *Manager) getSyncLeases(ctx context.Context, family int, now time.Time) ([]SyncLease, error) {
	leases, _, err := m.getSyncLeasesWithSource(ctx, family, now)
	return leases, err
}

// getSyncLeasesWithSource reads one family's active leases and reports whether
// the result came from Kea's live control socket. A memfile fallback is safe
// only when systemd definitively reports Kea inactive; an active unit whose
// socket read failed may still be serving, so publishing its stale memfile
// would erase the peer's last good snapshot (#17886).
func (m *Manager) getSyncLeasesWithSource(ctx context.Context, family int, now time.Time) ([]SyncLease, bool, error) {
	socket := m.controlSocket(family)
	leases, socketErr := readSyncLeasesViaSocket(ctx, m.keaDial, socket, family, now)
	if socketErr == nil {
		return leases, true, nil
	}
	unit := kea4Svc
	if family == 6 {
		unit = kea6Svc
	}
	active, stateErr := m.unitActive(unit)
	if stateErr != nil {
		return nil, false, fmt.Errorf("kea v%d lease read: socket=%v; query %s state: %w", family, socketErr, unit, stateErr)
	}
	if active {
		return nil, false, fmt.Errorf("kea v%d lease read: socket=%v; %s is active, refusing memfile fallback", family, socketErr, unit)
	}
	// A definitively stopped Kea cannot serve the persisted rows; retain the
	// memfile fallback only for this non-serving case.
	memfile := m.leaseFile(family)
	mem, memErr := readSyncLeasesViaMemfile(memfile, family, now)
	if memErr != nil {
		return nil, false, fmt.Errorf("kea v%d lease read: socket=%v memfile=%v", family, socketErr, memErr)
	}
	return mem, false, nil
}

// SeedSyncLeases4 writes held peer v4 leases into the just-started Kea via
// lease4-add (lease4-update on collision). It re-anchors each lease's Remaining
// to fresh absolute time on the LOCAL clock. Returns the number successfully
// seeded and a joined error of any failures (fail-open: the caller logs+counts;
// a seed failure never blocks serving).
func (m *Manager) SeedSyncLeases4(ctx context.Context, leases []SyncLease, now time.Time) (int, error) {
	return m.seedSyncLeases(ctx, 4, leases, now)
}

// SeedSyncLeases6 writes held peer v6 leases into the just-started Kea.
func (m *Manager) SeedSyncLeases6(ctx context.Context, leases []SyncLease, now time.Time) (int, error) {
	return m.seedSyncLeases(ctx, 6, leases, now)
}

// GetSyncLeases4WithSource is GetSyncLeases4 plus the live-socket proof: it
// reports whether the rows came from Kea's live control socket (true) or the
// persisted memfile fallback (false). A sender whose Kea is stopped must not
// present memfile rows as its serving set (#16854).
func (m *Manager) GetSyncLeases4WithSource(ctx context.Context, now time.Time) ([]SyncLease, bool, error) {
	return m.getSyncLeasesWithSource(ctx, 4, now)
}

// GetSyncLeases6WithSource is the v6 counterpart of GetSyncLeases4WithSource.
func (m *Manager) GetSyncLeases6WithSource(ctx context.Context, now time.Time) ([]SyncLease, bool, error) {
	return m.getSyncLeasesWithSource(ctx, 6, now)
}

func (m *Manager) seedSyncLeases(ctx context.Context, family int, leases []SyncLease, now time.Time) (int, error) {
	socket := m.controlSocket(family)
	var seeded int
	var errs []string
	for _, l := range leases {
		// #10893: reject rows no honest peer serves (wrong family, unparsable
		// or non-unicast address, IA_PD prefix out of range) and clamp
		// lifetimes before the row reaches Kea's lease DB. Mirrors the
		// memfile pre-seed guard and the cluster receive filter.
		sanitized, ok := SanitizeSyncLeaseForFamily(family, l)
		if !ok {
			continue
		}
		l = sanitized
		if l.Remaining <= 0 {
			// #4871: an aged-out lease must be DROPPED, never re-anchored to
			// now_local+Remaining at seed (which would resurrect it past its
			// true expiry). The standby-residence subtraction upstream
			// (PeerDHCPLeases) normally removes these; this is the fail-safe.
			continue
		}
		if err := m.seedOneLease(ctx, socket, family, l, now); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		seeded++
	}
	if len(errs) > 0 {
		return seeded, fmt.Errorf("seed v%d leases: %d/%d failed: %s",
			family, len(errs), len(leases), strings.Join(errs, "; "))
	}
	return seeded, nil
}

// seedOneLease issues lease{4,6}-add for one lease; on a "conflict" (already
// exists) it retries lease{4,6}-update so a lease already in the promoting
// node's own persisted memfile is harmlessly refreshed (idempotent).
func (m *Manager) seedOneLease(ctx context.Context, socket string, family int, l SyncLease, now time.Time) error {
	kl := syncLeaseToKea(l, now)
	var arguments any = kl
	if family == 4 && l.IsDeclined() && kl.HWAddress == "" {
		arguments = keaLease4AddArguments{keaLeaseJSON: kl}
	}
	addCmd := keaCommand{Command: fmt.Sprintf("lease%d-add", family), Arguments: arguments}
	resp, err := keaControl(ctx, m.keaDial, socket, addCmd)
	if err != nil {
		return err
	}
	if resp.Result == keaResultSuccess {
		return nil
	}
	// Conflict / already-exists → update in place (newer of the two wins;
	// the local persisted lease keeps the in-use binding either way).
	if resp.Result == keaResultConflict || strings.Contains(strings.ToLower(resp.Text), "exist") {
		updCmd := keaCommand{Command: fmt.Sprintf("lease%d-update", family), Arguments: arguments}
		uresp, uerr := keaControl(ctx, m.keaDial, socket, updCmd)
		if uerr != nil {
			return uerr
		}
		if uresp.Result == keaResultSuccess {
			return nil
		}
		return fmt.Errorf("lease%d-update %s: result=%d text=%q", family, l.Address, uresp.Result, uresp.Text)
	}
	return fmt.Errorf("lease%d-add %s: result=%d text=%q", family, l.Address, resp.Result, resp.Text)
}

// syncLeaseToKea re-anchors a SyncLease to fresh absolute time at seed (the
// clock-skew-immunity step: expire = now_local + Remaining) and renders the Kea
// lease{4,6}-add argument record. valid-lft is set to Remaining so a renewing
// client sees the correct remaining time, and the absolute expire matches.
func syncLeaseToKea(l SyncLease, now time.Time) keaLeaseJSON {
	// #4871: expired leases are DROPPED upstream (seedSyncLeases skips
	// Remaining<=0), so rem is a genuinely-positive remaining lifetime here.
	// The floor is now only a last-resort guard against a sub-second positive
	// value producing a zero valid-lft (which Kea rejects) — it never revives
	// an aged-out lease.
	rem := l.Remaining
	if rem < 1 {
		rem = 1
	}
	kl := keaLeaseJSON{
		IPAddress: l.Address,
		SubnetID:  l.SubnetID,
		ValidLft:  rem,
		Expire:    now.Unix() + int64(rem),
		State:     l.State,
		Hostname:  l.Hostname,
		FQDNFwd:   l.FQDNFwd,
		FQDNRev:   l.FQDNRev,
	}
	if l.Family == 6 {
		kl.DUID = l.DUID
		kl.IAID = &l.IAID // pointer: IAID 0 must still emit (#16855)
		// #5073: carry the PREFERRED remaining onto the socket add/update path so
		// a DEPRECATED binding (PreferredRemaining=0) is seeded deprecated rather
		// than revived. Clamp to [0, rem] (rem is the floored valid-lft) so the
		// invariant preferred<=valid holds; the pointer emits "preferred-lft":0
		// for a deprecated lease (omitempty only drops nil). A lease from an
		// older peer defaults PreferredRemaining=Remaining, so preferred==valid.
		prefRem := clampPreferredRemaining(l.PreferredRemaining, rem)
		kl.PreferredLft = &prefRem
		// Normalize the lease kind through the shared inverse so the socket-add
		// path and the memfile pre-seed path agree on every type (#2268). An
		// unknown string falls back to IA_NA, matching writeMemfile6.
		lt, ok := stringToKeaLeaseType(l.LeaseType)
		if !ok {
			slog.Warn("dhcpserver: seed v6 lease with unknown lease_type, sending as IA_NA",
				"address", l.Address, "lease_type", l.LeaseType)
		}
		s, _ := keaLeaseTypeToString(lt)
		kl.Type = s
		// Only IA_PD carries a delegated prefix length; IA_NA / IA_TA are address
		// bindings (Kea infers /128), so prefix-len stays unset for them.
		if lt == keaLeaseTypeIAPD {
			kl.PrefixLen = l.PrefixLen
		}
	} else {
		kl.HWAddress = l.HWAddress
		kl.ClientID = l.ClientID
	}
	return kl
}

// WaitControlSocket4 blocks until the v4 control socket accepts a connection or
// the deadline passes. Used post-Kea-start before seeding (Q3 backstop).
func (m *Manager) WaitControlSocket4(ctx context.Context, within time.Duration) bool {
	return m.waitControlSocket(ctx, 4, within)
}

// WaitControlSocket6 blocks until the v6 control socket is ready.
func (m *Manager) WaitControlSocket6(ctx context.Context, within time.Duration) bool {
	return m.waitControlSocket(ctx, 6, within)
}

func (m *Manager) waitControlSocket(ctx context.Context, family int, within time.Duration) bool {
	socket := m.controlSocket(family)
	deadline := time.Now().Add(within)
	dial := m.keaDial
	if dial == nil {
		dial = defaultKeaDialer
	}
	for {
		if ctx.Err() != nil {
			return false
		}
		dctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		conn, err := dial(dctx, socket)
		cancel()
		if err == nil {
			// #16058: a connectable squatter is not Kea. The production
			// dialer already verified; verify again here so a custom
			// dialer cannot make a squatted socket look ready — the seed
			// that follows this wait would otherwise trust it.
			if m.keaDial != nil {
				err = verifyKeaPeer(socket, conn)
			}
			if err == nil {
				conn.Close()
				return true
			}
			conn.Close()
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// controlSocket returns the family's control-socket path (overridable in tests
// via m.ctrlSocket4/6).
func (m *Manager) controlSocket(family int) string {
	if family == 6 {
		if m.ctrlSocket6 != "" {
			return m.ctrlSocket6
		}
		return keaControlSocket6
	}
	if m.ctrlSocket4 != "" {
		return m.ctrlSocket4
	}
	return keaControlSocket4
}

// PreSeedMemfileMerged4WithAuthority is the v4 authority-aware takeover
// pre-seed. Matching current-generation apply proof filters peer rows to
// eligible scopes and removes stale local rows only where authority is known.
// Missing or mismatched proof retains a conservative union, except peer rows
// excluded by explicit negative scope authority.
func (m *Manager) PreSeedMemfileMerged4WithAuthority(ctx context.Context, peer LeaseSyncSnapshot, now time.Time, stillMastering bool, authority LeaseSyncAuthority) error {
	return m.withQuiescedPreSeed(ctx, 4, now, func(local []SyncLease, live bool) error {
		if !live && !stillMastering {
			return m.writeMemfile4ReplacingLFC(
				m.leaseFile(4), mergeLeasesByAuthority(nil, peer, 4, authority, stillMastering), now)
		}
		return m.writeMemfile4ReplacingLFC(
			m.leaseFile(4), mergeLeasesByAuthority(local, peer, 4, authority, stillMastering), now)
	})
}

// PreSeedMemfileMerged6WithAuthority is the #10170 authority-aware v6 twin.
func (m *Manager) PreSeedMemfileMerged6WithAuthority(ctx context.Context, peer LeaseSyncSnapshot, now time.Time, stillMastering bool, authority LeaseSyncAuthority) error {
	return m.withQuiescedPreSeed(ctx, 6, now, func(local []SyncLease, live bool) error {
		if !live && !stillMastering {
			return m.writeMemfile6ReplacingLFC(
				m.leaseFile(6), mergeLeasesByAuthority(nil, peer, 6, authority, stillMastering), now)
		}
		return m.writeMemfile6ReplacingLFC(
			m.leaseFile(6), mergeLeasesByAuthority(local, peer, 6, authority, stillMastering), now)
	})
}

// withQuiescedPreSeed serializes takeover installation against this manager's
// Apply calls and, when Kea is active, disables packet handling before reading
// its live lease set. Successful quiescing remains in effect until ApplyAsync
// restarts Kea on takeover; Kea's max-period is a fail-open recovery if that
// restart never arrives. It invalidates the applied-config cache so an otherwise
// unchanged configuration cannot suppress the required restart (#10896).
func (m *Manager) withQuiescedPreSeed(ctx context.Context, family int, now time.Time, install func(local []SyncLease, live bool) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	socket := m.controlSocket(family)
	resp, disableErr := keaControl(ctx, m.keaDial, socket, keaCommand{
		Command: "dhcp-disable",
		Arguments: map[string]int{
			"max-period": keaDHCPDisableMaxPeriod,
		},
	})
	quiesced := disableErr == nil && resp.Result == keaResultSuccess

	// A config-identical ApplyAsync may otherwise skip its restart (#10896).
	// The installed memfile requires a fresh Kea process, and a restart must
	// also clear DHCP-disable when a later read/write step fails.
	if quiesced {
		if family == 6 {
			m.appliedConfig6 = nil
		} else {
			m.appliedConfig4 = nil
		}
	}
	if !quiesced {
		if disableErr == nil {
			disableErr = fmt.Errorf("dhcp-disable: result=%d text=%q", resp.Result, resp.Text)
		}
		unit := kea4Svc
		if family == 6 {
			unit = kea6Svc
		}
		active, err := m.unitActive(unit)
		if err != nil {
			return fmt.Errorf("pre-seed v%d: check Kea state after dhcp-disable failure: %w", family, err)
		}
		if active {
			return fmt.Errorf("pre-seed v%d: cannot quiesce active Kea before memfile replacement: %w", family, disableErr)
		}
	}

	local, live, err := m.getSyncLeasesWithSource(ctx, family, now)
	if err != nil {
		return fmt.Errorf("pre-seed v%d: local lease read failed, not overwriting memfile: %w", family, err)
	}
	if live != quiesced {
		return fmt.Errorf("pre-seed v%d: live lease source and Kea quiesce state disagree; refusing memfile replacement", family)
	}
	return install(local, live)
}

// mergeLeasesByIdentity returns the lease set the takeover pre-seed writes for
// one family (#5040), with ONE owner per address (#9791).
//
// Two passes:
//  1. Union by SyncLease.IdentityKey (address + client identity). The LOCAL
//     row wins an identity conflict: the same binding held on both sides is
//     this node's live copy, and it must not be displaced by a peer copy.
//  2. One row per address (leaseAddressKey9791). The same address bound to two
//     DIFFERENT clients keeps the binding with the most recent grant
//     (moreRecentGrant9791); a tie keeps the local row. Pass 1 alone kept both
//     rows, local first. #9729's run 6 left a promoted node's memfile holding
//     three rows for a reused address, all naming the client that had released
//     it, and the client holding it now was refused its renewal. A memfile load
//     does not arbitrate between two clients for one address, so the writer
//     must.
//
// The peer set is as old as its last sync, so the recency comparison can be off
// by that much. A re-grant to a new client follows the old lease's release or
// expiry, which puts the two grants much further apart. The result is a fresh
// slice; inputs are not mutated.
func mergeLeasesByIdentity(local, peer []SyncLease, family int) []SyncLease {
	seen := make(map[string]struct{}, len(local)+len(peer))
	union := make([]SyncLease, 0, len(local)+len(peer))
	for _, l := range local {
		if l.Family != family {
			continue
		}
		union = append(union, l)
		seen[l.IdentityKey()] = struct{}{}
	}
	for _, l := range peer {
		if l.Family != family {
			continue
		}
		if _, dup := seen[l.IdentityKey()]; dup {
			continue // local live binding wins
		}
		union = append(union, l)
		seen[l.IdentityKey()] = struct{}{}
	}
	return oneOwnerPerAddress9791(union)
}

// familyRowsOf returns the rows of one family as a fresh slice, safe to
// filter in place.
func familyRowsOf(rows []SyncLease, family int) []SyncLease {
	out := make([]SyncLease, 0, len(rows))
	for _, lease := range rows {
		if lease.Family == family {
			out = append(out, lease)
		}
	}
	return out
}

// peerScopesForReceiver returns every peer scope of this family at the
// snapshot generation with an RG identity, split by proof kind. A peer that
// explicitly reports Served:false for a scope proves it is NOT serving that
// scope (#16854): its rows in that scope are stale memfile-fallback residue,
// not live leases, so the receiver must exclude them. Served:true without
// Applied keeps the conservative whole-union behavior (#10170).
func peerScopesForReceiver(peer LeaseSyncSnapshot, family int) (proven, negative []LeaseScopeAuthority) {
	for _, scope := range peer.Scopes {
		if scope.Family != family || scope.CIDR == "" || scope.Generation != peer.Generation {
			continue
		}
		switch {
		case scope.Served && scope.Applied:
			proven = append(proven, scope)
		case !scope.Served:
			negative = append(negative, scope)
		}
	}
	return proven, negative
}

// excludePeerRowsInNegativeScopes drops peer rows whose address falls in a
// scope the peer explicitly reported as not served (#16854). The peer's Kea
// is stopped for that scope, so any row it still carries there came from the
// surviving memfile, never from a live server. Rows is a freshly built slice
// in every caller; it is filtered in place.
func excludePeerRowsInNegativeScopes(rows []SyncLease, negative []LeaseScopeAuthority, localScopes []LeaseScopeAuthority) []SyncLease {
	if len(negative) == 0 || len(rows) == 0 {
		return rows
	}
	matched, _ := partitionPeerScopes(negative, localScopes)
	if len(matched) == 0 {
		return rows
	}
	out := rows[:0]
	for _, lease := range rows {
		if leaseInAnyScope(lease.Address, matched) {
			continue
		}
		out = append(out, lease)
	}
	return out
}

// PeerLeasesForAuthority returns the peer rows eligible for this receiver's
// family and served-scope authority. It is shared by memfile and post-start
// seeding so both takeover paths make the same conservative decision.
func PeerLeasesForAuthority(peer LeaseSyncSnapshot, family int, authority LeaseSyncAuthority) []SyncLease {
	familyRows := func(rows []SyncLease) []SyncLease {
		out := make([]SyncLease, 0, len(rows))
		for _, lease := range rows {
			if lease.Family == family {
				out = append(out, lease)
			}
		}
		return out
	}
	localScopes := make([]LeaseScopeAuthority, 0, len(authority.Scopes))
	for _, scope := range authority.Scopes {
		if scope.Family == family && scope.CIDR != "" {
			localScopes = append(localScopes, scope)
		}
	}
	if !peer.Received || peer.Generation == 0 {
		return familyRows(peer.Leases)
	}
	peerScopes, negativeScopes := peerScopesForReceiver(peer, family)
	if len(peerScopes) == 0 || len(localScopes) == 0 {
		return excludePeerRowsInNegativeScopes(familyRows(peer.Leases), negativeScopes, localScopes)
	}
	matched, eligible := partitionPeerScopes(peerScopes, localScopes)
	if len(matched) == 0 {
		return excludePeerRowsInNegativeScopes(familyRows(peer.Leases), negativeScopes, localScopes)
	}
	return excludePeerRowsInNegativeScopes(
		peerLeasesForScopes(peer, family, matched, eligible), negativeScopes, localScopes)
}
func partitionPeerScopes(peerScopes, localScopes []LeaseScopeAuthority) (matched, eligible []LeaseScopeAuthority) {
	for _, peerScope := range peerScopes {
		var exact *LeaseScopeAuthority
		conflict := false
		for i := range localScopes {
			localScope := &localScopes[i]
			if !scopeCIDREqual(peerScope.CIDR, localScope.CIDR) {
				continue
			}
			if localScope.RGID != peerScope.RGID || exact != nil {
				conflict = true
				break
			}
			exact = localScope
		}
		if conflict || exact == nil {
			continue
		}
		matched = append(matched, peerScope)
		if exact.Served {
			eligible = append(eligible, peerScope)
		}
	}
	return matched, eligible
}

func peerLeasesForScopes(peer LeaseSyncSnapshot, family int, known, eligible []LeaseScopeAuthority) []SyncLease {
	out := make([]SyncLease, 0, len(peer.Leases))
	for _, lease := range peer.Leases {
		if lease.Family != family {
			continue
		}
		if !leaseInAnyScope(lease.Address, known) ||
			leaseInAnyScope(lease.Address, eligible) {
			out = append(out, lease)
		}
	}
	return out
}

// mergeLeasesByAuthority applies the #10170 scope/generation gate before the
// existing identity/address arbitration. Unknown scopes, unreceived snapshots,
// generation mismatches, unapplied sender state, and ambiguous groups retain
// the old whole-union behavior — except that a peer scope explicitly reported
// Served:false is negative proof (#16854): the peer is not serving it, so its
// rows there are stale memfile residue and are excluded even without positive
// proof. Explicit authority proof narrows both local stale rows and peer rows
// during staggered multi-RG takeover.
//
// Contract ruling (see docs/log/10170.md): NO ordinal stale<current comparison.
// Generation values are independent per-node counters, so cross-node age
// ordering is meaningless; narrowing stays proof-gated (successful
// current-generation peer proof + exact CIDR+RG match). Do not reintroduce
// age ordering here.
func mergeLeasesByAuthority(local []SyncLease, peer LeaseSyncSnapshot, family int, authority LeaseSyncAuthority, _ bool) []SyncLease {
	if !peer.Received || peer.Generation == 0 {
		return mergeLeasesByIdentity(local, peer.Leases, family)
	}

	peerScopes, negativeScopes := peerScopesForReceiver(peer, family)
	localScopes := make([]LeaseScopeAuthority, 0, len(authority.Scopes))
	for _, scope := range authority.Scopes {
		if scope.Family == family && scope.CIDR != "" {
			localScopes = append(localScopes, scope)
		}
	}
	if len(peerScopes) == 0 || len(localScopes) == 0 {
		return mergeLeasesByIdentity(local,
			excludePeerRowsInNegativeScopes(familyRowsOf(peer.Leases, family), negativeScopes, localScopes), family)
	}

	matchedPeerScopes, eligiblePeerScopes := partitionPeerScopes(peerScopes, localScopes)
	if len(matchedPeerScopes) == 0 {
		return mergeLeasesByIdentity(local,
			excludePeerRowsInNegativeScopes(familyRowsOf(peer.Leases, family), negativeScopes, localScopes), family)
	}
	filteredLocal := make([]SyncLease, 0, len(local))
	for _, lease := range local {
		if lease.Family != family {
			continue
		}
		served, known := localLeaseState(lease.Address, localScopes)
		if served || !known || !leaseInAnyScope(lease.Address, matchedPeerScopes) {
			filteredLocal = append(filteredLocal, lease)
		}
	}
	return mergeLeasesByIdentity(filteredLocal,
		excludePeerRowsInNegativeScopes(
			peerLeasesForScopes(peer, family, matchedPeerScopes, eligiblePeerScopes), negativeScopes, localScopes), family)
}

func localLeaseState(address string, scopes []LeaseScopeAuthority) (served, known bool) {
	ip := net.ParseIP(address)
	if ip == nil {
		return false, false
	}
	bestPrefix := -1
	ambiguous := false
	for _, scope := range scopes {
		_, network, err := net.ParseCIDR(scope.CIDR)
		if err != nil || !network.Contains(ip) {
			continue
		}
		prefix, _ := network.Mask.Size()
		switch {
		case prefix > bestPrefix:
			bestPrefix = prefix
			served = scope.Served
			ambiguous = false
		case prefix == bestPrefix:
			ambiguous = true
		}
	}
	return served && !ambiguous, bestPrefix >= 0 && !ambiguous
}

func leaseInAnyScope(address string, scopes []LeaseScopeAuthority) bool {
	for _, scope := range scopes {
		if leaseAddressInCIDR(address, scope.CIDR) {
			return true
		}
	}
	return false
}

func scopeCIDREqual(left, right string) bool {
	_, leftNet, leftErr := net.ParseCIDR(left)
	_, rightNet, rightErr := net.ParseCIDR(right)
	return leftErr == nil && rightErr == nil && leftNet.String() == rightNet.String()
}

func leaseAddressInCIDR(address, cidr string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	return err == nil && network.Contains(ip)
}

// oneOwnerPerAddress9791 keeps, for each address, the row with the most recent
// grant. Rows arrive local-first, so a tie keeps the local row. Order is
// otherwise preserved: a winning later row takes the earlier row's position.
func oneOwnerPerAddress9791(rows []SyncLease) []SyncLease {
	at := make(map[string]int, len(rows))
	out := make([]SyncLease, 0, len(rows))
	for _, l := range rows {
		k := leaseAddressKey9791(l)
		i, dup := at[k]
		if !dup {
			at[k] = len(out)
			out = append(out, l)
			continue
		}
		if declinedBeatsActive16856(l, out[i]) {
			out[i] = l
			continue
		}
		if out[i].IsDeclined() && !l.IsDeclined() {
			// Incumbent declined: only a provably later active grant displaces it.
			if l.ValidLife > 0 && out[i].ValidLife > 0 && (l.ValidLife-l.Remaining) < (out[i].ValidLife-out[i].Remaining) {
				out[i] = l
			}
			continue
		}
		if l.IsDeclined() {
			continue
		}
		if moreRecentGrant9791(l, out[i]) {
			out[i] = l
		}
	}
	return out
}

// declinedBeatsActive16856: a declined occupancy beats an active row for the
// same address unless the active row is provably a later grant (both carry
// ValidLife and its grant age is strictly smaller). Without lifetime proof
// the declined row wins — fail-closed against re-offering a conflicting
// address (#16856).
func declinedBeatsActive16856(candidate, incumbent SyncLease) bool {
	if !candidate.IsDeclined() || incumbent.IsDeclined() {
		return false
	}
	if candidate.ValidLife > 0 && incumbent.ValidLife > 0 {
		candidateAge := candidate.ValidLife - candidate.Remaining
		incumbentAge := incumbent.ValidLife - incumbent.Remaining
		if incumbentAge < candidateAge {
			return false
		}
	}
	return true
}

func leaseAddressKey9791(l SyncLease) string {
	if l.Family == 6 {
		return fmt.Sprintf("6|%s|%s|%d", l.Address, l.LeaseType, l.PrefixLen)
	}
	return "4|" + l.Address
}

func moreRecentGrant9791(a, b SyncLease) bool {
	if a.ValidLife > 0 && b.ValidLife > 0 {
		return a.ValidLife-a.Remaining < b.ValidLife-b.Remaining
	}
	return a.Remaining > b.Remaining
}

// keaMemfileHeader4 is Kea's canonical DHCPv4 memfile CSV header (Kea 2.x/3.x).
const keaMemfileHeader4 = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id"

// keaMemfileHeader6 is Kea's canonical DHCPv6 memfile CSV header (Kea 2.x/3.x).
const keaMemfileHeader6 = "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id"

func boolCSV(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (m *Manager) writeMemfile4(path string, leases []SyncLease, now time.Time) error {
	var b strings.Builder
	b.WriteString(keaMemfileHeader4)
	b.WriteByte('\n')
	for _, l := range leases {
		// #10893: reject rows no honest peer serves (wrong family, unparsable
		// or non-unicast address, IA_PD prefix out of range) and clamp
		// lifetimes before the row reaches Kea's lease DB. Mirrors the
		// socket-seed guard and the cluster receive filter.
		sanitized, ok := SanitizeSyncLeaseForFamily(4, l)
		if !ok {
			continue
		}
		l = sanitized
		if l.Remaining <= 0 {
			continue // #4871: drop an aged-out lease rather than reviving it
		}
		rem := l.Remaining
		expire := now.Unix() + int64(rem)
		// address,hwaddr,client_id,valid_lifetime,expire,subnet_id,
		// fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
		fmt.Fprintf(&b, "%s,%s,%s,%d,%d,%d,%s,%s,%s,%d,,0\n",
			csvField(l.Address), csvField(l.HWAddress), csvField(l.ClientID),
			rem, expire, l.SubnetID,
			boolCSV(l.FQDNFwd), boolCSV(l.FQDNRev), csvField(l.Hostname),
			l.State)
	}
	return m.writeMemfileAtomic(path, b.String())
}

func (m *Manager) writeMemfile6(path string, leases []SyncLease, now time.Time) error {
	var b strings.Builder
	b.WriteString(keaMemfileHeader6)
	b.WriteByte('\n')
	for _, l := range leases {
		// #10893: reject rows no honest peer serves (wrong family, unparsable
		// or non-unicast address, IA_PD prefix out of range) and clamp
		// lifetimes before the row reaches Kea's lease DB. Mirrors the
		// socket-seed guard and the cluster receive filter.
		sanitized, ok := SanitizeSyncLeaseForFamily(6, l)
		if !ok {
			continue
		}
		l = sanitized
		if l.Remaining <= 0 {
			continue // #4871: drop an aged-out lease rather than reviving it
		}
		rem := l.Remaining
		expire := now.Unix() + int64(rem)
		// #5073: the pref_lifetime column must carry the PREFERRED remaining, not
		// the valid remaining. Writing `rem` here revived a DEPRECATED binding
		// (preferred=0) as fully preferred on takeover. Clamp defensively to
		// [0, rem] so the invariant preferred<=valid holds even if an upstream
		// producer left PreferredRemaining unset (0 → deprecated, safe) or larger
		// than rem (an older-peer default equals rem, so the clamp is a no-op).
		prefRem := clampPreferredRemaining(l.PreferredRemaining, rem)
		// Encode the v6 lease kind symmetrically with the read path
		// (keaLeaseTypeToString) via the shared inverse so IA_NA / IA_TA / IA_PD
		// all round-trip (#2268). An unknown string falls back to IA_NA (an
		// address lease) and is logged rather than silently mis-typed.
		leaseType, ok := stringToKeaLeaseType(l.LeaseType)
		if !ok {
			slog.Warn("dhcpserver: pre-seed v6 lease with unknown lease_type, writing as IA_NA",
				"address", l.Address, "lease_type", l.LeaseType)
		}
		// IA_PD carries a delegated prefix length; IA_NA and IA_TA are full /128
		// address bindings (no prefix concept), so their prefix_len column is 128.
		prefixLen := l.PrefixLen
		if leaseType != keaLeaseTypeIAPD {
			prefixLen = 128
		}
		// address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,
		// lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,
		// state,user_context,hwtype,hwaddr_source,pool_id
		fmt.Fprintf(&b, "%s,%s,%d,%d,%d,%d,%d,%d,%d,%s,%s,%s,%s,%d,,,,0\n",
			csvField(l.Address), csvField(l.DUID),
			rem, expire, l.SubnetID, prefRem,
			leaseType, l.IAID, prefixLen,
			boolCSV(l.FQDNFwd), boolCSV(l.FQDNRev), csvField(l.Hostname),
			csvField(l.HWAddress), l.State)
	}
	return m.writeMemfileAtomic(path, b.String())
}

// writeMemfileAtomic writes the rendered memfile durably so a Kea start cannot
// read a torn pre-seed. Pre-seed runs on the takeover path (not a hot path) so
// the fsync cost is acceptable, and durability matters: the pre-seed exists to
// survive a crash-failover, the worst case being a torn file Kea then rejects.
//
// OWNERSHIP (#2450, HIGH): xpfd runs as root, but distro Kea (`kea-dhcp4`/
// `kea-dhcp6`) runs as the unprivileged `_kea` (Debian/Ubuntu) or `kea`
// (RHEL-family) user and opens its memfile lease DB for READ+WRITE at startup.
// A root-owned 0640 file is unreadable/unwritable by that user, so Kea fails to
// start (EACCES) on the node that just took over — a DHCP outage at the worst
// possible moment. We therefore install the file already owned by the resolved
// Kea runtime user (0640 + owner=_kea ⇒ owner can RW). The chown rides on the
// fsatomic temp fd (fsatomic.WithOwner does fchown BEFORE the rename), so the
// FINAL visible inode at `path` is _kea-owned atomically — there is no
// post-rename window where the renamed-into-place file is root-owned, and no
// orphaned root-owned temp survives the rename.
//
// ROBUSTNESS: when NEITHER Kea user exists (a dev host, or Kea simply not
// installed) the takeover must NOT abort — chown is best-effort. The file is
// written without an owner override and the write itself still succeeds; one
// warning is logged (once per process, in resolveKeaOwner's cached lookup —
// not per pre-seed) so an absent-user takeover does not warn twice for v4+v6
// or again on every subsequent takeover. The daemon is root, so when the user
// DOES exist the chown cannot fail for lack of privilege.
func (m *Manager) writeMemfileAtomic(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	uid, gid, ok := m.resolveKeaOwner(true)
	return writeMemfileFile(path, []byte(content), 0640, uid, gid, ok)
}

// writeMemfile4ReplacingLFC writes an active+declined current file and then
// removes prior LFC generations. Every merged/plain pre-seed uses it
// (#14730/#16856): stale generations would resurrect state=2 rows the
// snapshot dropped.
func (m *Manager) writeMemfile4ReplacingLFC(path string, leases []SyncLease, now time.Time) error {
	if err := m.writeMemfile4(path, leases, now); err != nil {
		return err
	}
	return removeLFCGenerations(path)
}

func (m *Manager) writeMemfile6ReplacingLFC(path string, leases []SyncLease, now time.Time) error {
	if err := m.writeMemfile6(path, leases, now); err != nil {
		return err
	}
	return removeLFCGenerations(path)
}

func removeLFCGenerations(path string) error {
	// The current file alone is not the effective Kea lease set while LFC
	// generations exist. Remove them after the durable current-file rename so a
	// stale backup row cannot be replayed from .1/.2 on the promoted start.
	//
	// .completed is removed too: it is kea-lfc's finished compaction output
	// (lease-bearing, one row per active lease), and Kea's startup loader
	// reads it INSTEAD of .2/.1 when present (memfile_lease_mgr.cc
	// loadLeasesFromFiles). An interrupted-LFC orphan would otherwise
	// resurrect stale rows despite the peer-only current file (#9853 M1).
	var errs []error
	for _, generation := range []string{path + ".2", path + ".1", path + ".completed"} {
		if err := os.Remove(generation); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove stale Kea LFC generation %s: %w", generation, err))
		}
	}
	// The current-file write fsyncs the directory before these unlinks. Sync it
	// again so a power loss cannot restore the removed generation names. This is
	// deliberately after ALL removal attempts, including when any failed.
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil {
		errs = append(errs, fmt.Errorf("sync Kea LFC generation cleanup directory: %w", err))
	}
	return errors.Join(errs...)
}

// writeMemfileFile installs the pre-seeded memfile. It is a package var so a
// test can record the resolved owner (uid/gid + whether the chown is applied)
// and the final path without needing root to perform a real fchown. Production
// rides the chown on the fsatomic temp fd via WithOwner, so the FINAL renamed
// inode is _kea-owned atomically (no post-rename root-owned window).
var writeMemfileFile = func(path string, data []byte, perm os.FileMode, uid, gid int, applyOwner bool) error {
	var opts []fsatomic.Option
	if applyOwner {
		opts = append(opts, fsatomic.WithOwner(uid, gid))
	}
	return fsatomic.WriteFileDurable(path, data, perm, opts...)
}

// Kea runtime user names, in resolution order. Debian/Ubuntu (the appliance
// base) package Kea to run as `_kea`; the RHEL-family packaging uses `kea`.
const (
	keaPrimaryUser  = "_kea"
	keaFallbackUser = "kea"
)

// resolveKeaOwner returns the uid/gid the Kea memfile must be owned by so the
// unprivileged Kea process can open it RW, and ok=false when neither candidate
// user exists (chown then becomes best-effort — see writeMemfileAtomic). The
// lookup runs exactly once per process (cached behind keaOwnerOnce, a
// sync.Once) so the takeover path does not hit /etc/passwd per pre-seed. The
// resolver is seam-injectable for tests (keaOwnerLookup; nil selects the real
// os/user lookup).
//
// The absent-user warning is PER-PURPOSE (#16101 fold): it is keyed off
// the resolution OUTCOME at a warnMissing (pre-seed) call, guarded by
// its own keaOwnerWarnOnce — NOT off which caller populated the lookup
// cache. A config render (#16062) resolves silently and may populate
// the cache first; a later pre-seed on the same manager must still warn
// exactly once, because a root-owned 0640 memfile is Kea-UNREADABLE
// (EACCES at failover) and that absence is operator-actionable there.
// Render-only managers never warn (an unresolved group only means the
// config lands plain 0640 root:root instead of root:_kea), and repeated
// pre-seeds (v4+v6, retries) warn once total.
func (m *Manager) resolveKeaOwner(warnMissing ...bool) (uid, gid int, ok bool) {
	m.keaOwnerOnce.Do(func() {
		lookup := m.keaOwnerLookup
		if lookup == nil {
			lookup = lookupKeaOwner
		}
		m.keaOwnerUID, m.keaOwnerGID, m.keaOwnerOK = lookup()
	})
	if !m.keaOwnerOK && len(warnMissing) > 0 && warnMissing[0] {
		m.keaOwnerWarnOnce.Do(func() {
			m.warnf("dhcpserver: no %s/%s runtime user found; pre-seeding Kea "+
				"memfiles as root — Kea may be unable to open them (EACCES) if it "+
				"runs unprivileged", keaPrimaryUser, keaFallbackUser)
		})
	}
	return m.keaOwnerUID, m.keaOwnerGID, m.keaOwnerOK
}

// lookupKeaOwner resolves the first existing Kea runtime user (_kea, then kea)
// to its numeric uid/gid via the OS user database. It returns ok=false when
// neither exists.
func lookupKeaOwner() (uid, gid int, ok bool) {
	for _, name := range []string{keaPrimaryUser, keaFallbackUser} {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		ui, err := strconv.Atoi(u.Uid)
		if err != nil {
			continue
		}
		gi, err := strconv.Atoi(u.Gid)
		if err != nil {
			continue
		}
		return ui, gi, true
	}
	return 0, 0, false
}

// warnf routes a pre-seed warning through the manager's warn sink (the test
// seam, default slog.Warn) using printf-style formatting so the message is one
// human-readable line rather than slog key/value pairs.
func (m *Manager) warnf(format string, args ...any) {
	if m.warn != nil {
		m.warn(fmt.Sprintf(format, args...))
		return
	}
	slog.Warn(fmt.Sprintf(format, args...))
}

// csvField escapes a memfile CSV field. Kea memfile values (addresses,
// hex-encoded identities, hostnames) do not normally contain commas, but a
// hostname could; quote-escape per RFC 4180 to stay safe.
func csvField(s string) string {
	s = stripLeaseControlChars(s)
	if strings.ContainsAny(s, ",\"\r\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// leaseFile returns the family's memfile path (overridable in tests).
func (m *Manager) leaseFile(family int) string {
	if family == 6 {
		if m.leaseFile6 != "" {
			return m.leaseFile6
		}
		return keaLeaseFile6
	}
	if m.leaseFile4 != "" {
		return m.leaseFile4
	}
	return keaLeaseFile4
}
