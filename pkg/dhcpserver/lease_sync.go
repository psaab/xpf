package dhcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
//     append-only memfile parser (parseActiveLeases4/6) when the socket is not
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

// SyncLease is ONE active DHCP-server lease in the cluster-portable form
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

	State int // Kea lease state (0=default/active)
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

// IdentityKey returns a stable per-lease identity used for dedup/diff on the
// sender (on-grant change detection) and as the seed idempotency key. It mirrors
// the DDNS identity functions but is keyed on the address + identity so two
// renewals of the same binding compare equal except for Remaining.
func (l SyncLease) IdentityKey() string {
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
	IPAddress string `json:"ip-address"`
	HWAddress string `json:"hw-address,omitempty"`
	ClientID  string `json:"client-id,omitempty"`
	DUID      string `json:"duid,omitempty"`
	IAID      uint32 `json:"iaid,omitempty"`
	Type      string `json:"type,omitempty"`       // v6: IA_NA / IA_PD
	PrefixLen int    `json:"prefix-len,omitempty"` // v6 IA_PD
	SubnetID  int    `json:"subnet-id,omitempty"`
	ValidLft  int    `json:"valid-lft,omitempty"`
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

type keaLeaseGetAllArgs struct {
	Leases []keaLeaseJSON `json:"leases"`
}

// keaSocketDialer abstracts the unix-socket dial for tests (a stub server can
// implement the lease_cmds wire). Production uses net.Dial.
type keaSocketDialer func(ctx context.Context, socketPath string) (net.Conn, error)

func defaultKeaDialer(ctx context.Context, socketPath string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", socketPath)
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
	dec := json.NewDecoder(conn)
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
		l := keaLeaseToSync(kl, family, now)
		if l.State != keaStateDefault {
			continue // only active leases are synced
		}
		if l.Remaining <= 0 {
			continue // already expired at read time
		}
		out = append(out, l)
	}
	return out, nil
}

// keaLeaseToSync converts a get-all lease record into the clock-skew-safe
// SyncLease (computing Remaining from cltt+valid-lft on the SENDER clock).
func keaLeaseToSync(kl keaLeaseJSON, family int, now time.Time) SyncLease {
	l := SyncLease{
		Family:    family,
		Address:   kl.IPAddress,
		SubnetID:  kl.SubnetID,
		HWAddress: kl.HWAddress,
		ClientID:  kl.ClientID,
		DUID:      kl.DUID,
		IAID:      kl.IAID,
		LeaseType: kl.Type,
		PrefixLen: kl.PrefixLen,
		Hostname:  kl.Hostname,
		FQDNFwd:   kl.FQDNFwd,
		FQDNRev:   kl.FQDNRev,
		ValidLife: kl.ValidLft,
		State:     kl.State,
	}
	// Remaining = (cltt + valid-lft) - now, computed on the sender's clock.
	expire := kl.Expire
	if expire == 0 {
		expire = kl.CLTT + int64(kl.ValidLft)
	}
	rem := expire - now.Unix()
	if rem < 0 {
		rem = 0
	}
	l.Remaining = int(rem)
	// #5073: preferred remaining is anchored to the SAME expire epoch as the
	// valid remaining. Both lifetimes count from cltt, so
	//   preferred_remaining = valid_remaining - (valid-lft - preferred-lft).
	// A DEPRECATED lease (preferred-lft=0) yields a negative remainder that
	// clamps to 0; a lease with preferred==valid yields exactly Remaining. When
	// Kea reports no preferred-lft (nil — an older Kea or a v4 lease) default to
	// preferred==valid (PreferredRemaining=Remaining), the pre-#5073 behavior.
	if kl.PreferredLft != nil {
		l.PreferredRemaining = clampPreferredRemaining(l.Remaining-(kl.ValidLft-*kl.PreferredLft), l.Remaining)
	} else {
		l.PreferredRemaining = l.Remaining
	}
	return l
}

// readSyncLeasesViaMemfile is the fallback read path: parse the append-only
// memfile via the destructive-safe parser and convert to SyncLeases. Used when
// the control socket is not (yet) up. The memfile holds an absolute Expire
// epoch (Kea writes cltt+valid-lft); Remaining is computed from it on the
// local clock, same as the socket path.
func readSyncLeasesViaMemfile(path string, family int, now time.Time) ([]SyncLease, error) {
	active, err := parseActiveLeases(path, family, now)
	if err != nil {
		return nil, err
	}
	out := make([]SyncLease, 0, len(active))
	for _, a := range active {
		l := SyncLease{
			Family:   family,
			Address:  a.Address,
			Hostname: a.HostName,
			State:    keaStateDefault,
		}
		if a.ClientFQDN != "" {
			l.Hostname = a.ClientFQDN
			l.FQDNFwd = true
		}
		if a.SubnetID != "" {
			// #6218 item 11: strconv.Atoi parses with the PLATFORM int
			// bit-size (bitSize=0 -> 64-bit on amd64/arm64, but 32-bit on a
			// 32-bit target), so a Kea subnet-id near keaSubnetIDMax
			// (0xFFFFFFFE, dhcpserver.go) would silently fail to parse (and
			// so silently drop the subnet-id) on a 32-bit build even though
			// it is a perfectly valid Kea subnet-id. ParseUint(...,32) is
			// exact and portable: it accepts every value up to 2^32-1
			// regardless of the host's native int width.
			if sid, e := strconv.ParseUint(a.SubnetID, 10, 32); e == nil {
				l.SubnetID = int(sid)
			}
		}
		if family == 6 {
			duid, iaid, idErr := splitV6Identity(a.Identity)
			if idErr != nil {
				// #2379: a PRESENT but unparseable IAID would silently seed
				// IAID 0 into the peer's Kea lease DB on takeover. Skip the
				// lease (logged) rather than mis-seed it — fail-closed, the
				// same posture as the unparseable lease_type / missing expire
				// rows below.
				slog.Warn("dhcpserver: skipping v6 memfile lease with unparseable IAID",
					"address", a.Address, "identity", a.Identity, "error", idErr)
				continue
			}
			l.DUID = duid
			l.IAID = iaid
			// #2262: preserve the v6 lease kind from the memfile instead of
			// hardcoding IA_NA, which mis-seeded an IA_PD (prefix-delegation)
			// lease as an address lease on the peer. A PRESENT but unparseable
			// lease_type column flips LeaseTypeOK=false: skip (logged) rather
			// than mis-type — fail-closed, mirroring the socket path which
			// reports the kind faithfully.
			if !a.LeaseTypeOK {
				slog.Warn("dhcpserver: skipping v6 memfile lease with unparseable lease_type",
					"address", a.Address, "duid", duid, "iaid", iaid)
				continue
			}
			lt, ok := keaLeaseTypeToString(a.LeaseType)
			if !ok {
				slog.Warn("dhcpserver: skipping v6 memfile lease with unknown lease_type",
					"address", a.Address, "lease_type", a.LeaseType)
				continue
			}
			l.LeaseType = lt
			if a.LeaseType == keaLeaseTypeIAPD {
				l.PrefixLen = a.PrefixLen
			}
		} else {
			hw, cid := splitV4Identity(a.Identity)
			l.HWAddress = hw
			l.ClientID = cid
		}
		rem := a.Expire - now.Unix()
		if a.Expire == 0 {
			// memfile lacked an expire column; treat as full lifetime unknown,
			// skip (cannot compute a safe remaining).
			continue
		}
		if rem <= 0 {
			continue
		}
		l.Remaining = int(rem)
		// #5073: preferred remaining, re-anchored the SAME way as Remaining. The
		// memfile expire epoch is cltt+valid_lifetime, so the preferred deadline
		// is expire-valid_lifetime+pref_lifetime and
		//   preferred_remaining = Remaining - (valid_lifetime - pref_lifetime),
		// clamped [0, Remaining]. A DEPRECATED binding (pref_lifetime=0) floors
		// to 0 and is not revived. When the pref_lifetime/valid_lifetime columns
		// are absent (v4, or an old memfile) default preferred==valid.
		l.PreferredRemaining = l.Remaining
		if family == 6 && a.PrefLifetimeOK && a.ValidLifetime > 0 {
			l.PreferredRemaining = clampPreferredRemaining(l.Remaining-(a.ValidLifetime-a.PrefLifetime), l.Remaining)
		}
		out = append(out, l)
	}
	return out, nil
}

// splitV4Identity inverts identity4 ("cid:.."/"mac:..") back into the Kea
// fields. The memfile parser collapsed client-id/hwaddr into one keyed string;
// we recover whichever was present so lease4-add gets a usable identity.
func splitV4Identity(identity string) (hwaddr, clientID string) {
	switch {
	case strings.HasPrefix(identity, "cid:"):
		return "", strings.TrimPrefix(identity, "cid:")
	case strings.HasPrefix(identity, "mac:"):
		return strings.TrimPrefix(identity, "mac:"), ""
	}
	return "", ""
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

// splitV6Identity inverts identity6 ("duid:DUID/IAID") back into DUID + IAID.
//
// The "no slash / no IAID" form ("duid:DUID") is a legitimate identity and
// returns iaid=0 with a nil error. When the "/IAID" portion IS present it must
// parse as a decimal uint32: a parse failure returns a non-nil error rather
// than silently swallowing to iaid=0. Because 0 is a valid IAID, swallowing
// would make a malformed identity indistinguishable from a real zero IAID and
// would seed the peer's Kea lease DB with the wrong IAID on takeover, so a
// non-zero-IAID client could fail to renew with nothing logged (#2379). The
// callers (memfile takeover-seed loop) log+skip the lease on error, matching
// how they already handle an unparseable lease_type / missing expire.
func splitV6Identity(identity string) (duid string, iaid uint32, err error) {
	s := strings.TrimPrefix(identity, "duid:")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		duid = s[:i]
		v, perr := strconv.ParseUint(s[i+1:], 10, 32)
		if perr != nil {
			return duid, 0, fmt.Errorf("unparseable IAID %q in v6 identity %q: %w", s[i+1:], identity, perr)
		}
		return duid, uint32(v), nil
	}
	return s, 0, nil
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
	socket := m.controlSocket(family)
	leases, err := readSyncLeasesViaSocket(ctx, m.keaDial, socket, family, now)
	if err == nil {
		return leases, nil
	}
	// Fallback: read the memfile (socket not up yet, or hook unavailable).
	memfile := m.leaseFile(family)
	mem, memErr := readSyncLeasesViaMemfile(memfile, family, now)
	if memErr != nil {
		return nil, fmt.Errorf("kea v%d lease read: socket=%v memfile=%v", family, err, memErr)
	}
	return mem, nil
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

func (m *Manager) seedSyncLeases(ctx context.Context, family int, leases []SyncLease, now time.Time) (int, error) {
	socket := m.controlSocket(family)
	var seeded int
	var errs []string
	for _, l := range leases {
		if l.Family != family {
			continue
		}
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
	addCmd := keaCommand{Command: fmt.Sprintf("lease%d-add", family), Arguments: kl}
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
		updCmd := keaCommand{Command: fmt.Sprintf("lease%d-update", family), Arguments: kl}
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
		State:     keaStateDefault,
		Hostname:  l.Hostname,
		FQDNFwd:   l.FQDNFwd,
		FQDNRev:   l.FQDNRev,
	}
	if l.Family == 6 {
		kl.DUID = l.DUID
		kl.IAID = l.IAID
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
			conn.Close()
			return true
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

// PreSeedMemfile4 writes the held peer v4 leases into the Kea v4 memfile CSV
// BEFORE Kea is (re)started on takeover (#2239 Q3). A starting Kea loads its
// memfile at boot, so pre-seeding the in-use bindings means it can NEVER answer
// a DISCOVER with an in-use address even in the window before the post-start
// lease-add seed runs — this fully closes the duplicate-allocation window. The
// Remaining lifetime is re-anchored to fresh absolute time on the LOCAL clock
// (now + Remaining) so peer wall-clock skew never enters the seeded expiry.
//
// The file is written atomically (fsatomic) with Kea's canonical v4 memfile
// header so Kea parses it cleanly. It OVERWRITES any existing memfile: on
// takeover the held peer set is the authoritative serving state, and Kea's own
// LFC will compact going forward.
func (m *Manager) PreSeedMemfile4(leases []SyncLease, now time.Time) error {
	return m.writeMemfile4(m.leaseFile(4), leases, now)
}

// PreSeedMemfile6 writes the held peer v6 leases into the Kea v6 memfile CSV
// before Kea start (#2239 Q3). See PreSeedMemfile4.
func (m *Manager) PreSeedMemfile6(leases []SyncLease, now time.Time) error {
	return m.writeMemfile6(m.leaseFile(6), leases, now)
}

// PreSeedMemfileMerged4 pre-seeds the Kea v4 memfile with the UNION of this
// node's CURRENT local active leases and the held peer leases (#5040), instead
// of overwriting it with the peer-only set.
//
// On a per-RG active-active takeover this node is ALREADY MASTER for one or
// more RGs whose leases are live in the local Kea (and its persisted memfile).
// The takeover then restarts Kea under the union config (already-mastered RG +
// newly-taken RG). A peer-ONLY pre-seed (the pre-#5040 behavior) atomically
// OVERWROTE the shared memfile, wiping this node's own still-mastered RG rows;
// the restarted Kea then had no record of those in-use bindings and could
// re-allocate their addresses to new clients (duplicate allocation). The
// invariant: restarting Kea during one RG transition must preserve the lease
// union for every RG that remains locally MASTER.
//
// The local set is read via the same socket-preferred, memfile-fallback path
// GetSyncLeases4 uses. FAIL-CLOSED: if that read errors (an untrusted/corrupt
// local source), we do NOT overwrite the memfile with peer-only leases — we
// return the error and leave the existing memfile intact so the restarting Kea
// reloads its own persisted rows, and the async post-start lease-add seed still
// adds the peer set. A genuinely MISSING memfile with Kea down is a trusted
// empty (a cold node with nothing to preserve), so the union degenerates to the
// peer set and the pre-seed proceeds.
func (m *Manager) PreSeedMemfileMerged4(ctx context.Context, peer []SyncLease, now time.Time) error {
	local, err := m.getSyncLeases(ctx, 4, now)
	if err != nil {
		return fmt.Errorf("pre-seed v4: local lease read failed, not overwriting memfile: %w", err)
	}
	return m.writeMemfile4(m.leaseFile(4), mergeLeasesByIdentity(local, peer, 4), now)
}

// PreSeedMemfileMerged6 is the v6 counterpart of PreSeedMemfileMerged4 (#5040).
func (m *Manager) PreSeedMemfileMerged6(ctx context.Context, peer []SyncLease, now time.Time) error {
	local, err := m.getSyncLeases(ctx, 6, now)
	if err != nil {
		return fmt.Errorf("pre-seed v6: local lease read failed, not overwriting memfile: %w", err)
	}
	return m.writeMemfile6(m.leaseFile(6), mergeLeasesByIdentity(local, peer, 6), now)
}

// mergeLeasesByIdentity returns the union of the local and peer lease sets for
// one family, keyed by SyncLease.IdentityKey (address + client identity). The
// LOCAL lease WINS a conflict: for an RG this node still masters, its live
// binding is the authoritative in-use lease, so it must never be displaced by a
// peer copy. Peer-only identities (the RG being taken over) are appended. The
// result is a fresh slice; inputs are not mutated.
func mergeLeasesByIdentity(local, peer []SyncLease, family int) []SyncLease {
	seen := make(map[string]struct{}, len(local)+len(peer))
	out := make([]SyncLease, 0, len(local)+len(peer))
	for _, l := range local {
		if l.Family != family {
			continue
		}
		out = append(out, l)
		seen[l.IdentityKey()] = struct{}{}
	}
	for _, l := range peer {
		if l.Family != family {
			continue
		}
		if _, dup := seen[l.IdentityKey()]; dup {
			continue // local live binding wins
		}
		out = append(out, l)
		seen[l.IdentityKey()] = struct{}{}
	}
	return out
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
		if l.Family != 4 {
			continue
		}
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
			keaStateDefault)
	}
	return m.writeMemfileAtomic(path, b.String())
}

func (m *Manager) writeMemfile6(path string, leases []SyncLease, now time.Time) error {
	var b strings.Builder
	b.WriteString(keaMemfileHeader6)
	b.WriteByte('\n')
	for _, l := range leases {
		if l.Family != 6 {
			continue
		}
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
			csvField(l.HWAddress), keaStateDefault)
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
	uid, gid, ok := m.resolveKeaOwner()
	return writeMemfileFile(path, []byte(content), 0640, uid, gid, ok)
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
// os/user lookup). When the lookup FAILS, the absent-user warning is emitted
// HERE — inside the once-guarded closure — so it fires exactly once per
// process rather than on every pre-seed (an operator who installs the Kea
// package mid-process restarts xpfd anyway, which re-runs the lookup).
func (m *Manager) resolveKeaOwner() (uid, gid int, ok bool) {
	m.keaOwnerOnce.Do(func() {
		lookup := m.keaOwnerLookup
		if lookup == nil {
			lookup = lookupKeaOwner
		}
		m.keaOwnerUID, m.keaOwnerGID, m.keaOwnerOK = lookup()
		if !m.keaOwnerOK {
			m.warnf("dhcpserver: no %s/%s runtime user found; pre-seeding Kea "+
				"memfiles as root — Kea may be unable to open them (EACCES) if it "+
				"runs unprivileged", keaPrimaryUser, keaFallbackUser)
		}
	})
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
	if strings.ContainsAny(s, ",\"\n") {
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
