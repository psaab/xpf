package dhcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// lease_source.go completes the Kea LFC lease-source invariants #5796/#5936
// deferred (#5938): the live `lease_cmds` socket is preferred over the memfile
// snapshot for the DISPLAY path (Invariant 2), and a degraded lease source is
// surfaced to `show dhcp server leases` via a banner (Invariant 8). The
// crash-interrupted-cleanup safety argument (Invariant 3) is documented at
// keaLFCLeaseFilePaths (lease_lfc.go) and pinned by a test.
//
// This is the DHCP server's display read path. GetLeasesWithSource4/6 prefer
// the live lease DB when available and fall back to the memfile while carrying
// source degradation through to the `show dhcp server` handlers.

// Lease-source origin labels (human-readable, shown in logs / the degraded
// banner detail).
const (
	leaseSourceLiveSocket      = "live lease_cmds control socket"
	leaseSourceMemfile         = "memfile LFC file-set"
	leaseSourceMemfileFallback = "memfile LFC file-set (socket fallback)"
)

// LeaseSource describes WHERE a displayed lease set came from and whether that
// source is DEGRADED (the shown set may be incomplete). It is threaded from the
// lease read to the show handler so the operator is never silently shown a
// best-effort fallback as if it were authoritative (#5938 Invariant 8).
type LeaseSource struct {
	Origin   string // human label of the source actually used
	Degraded bool   // true ⇒ the displayed lease set may be incomplete
	Detail   string // one-line reason for the degradation (banner text)
}

// Banner returns the one-line operator banner for a degraded source, or "" when
// the source is healthy (no banner). The show handlers print this above the
// lease table so a degraded read is visually distinct from a healthy empty set.
func (s LeaseSource) Banner() string {
	if !s.Degraded {
		return ""
	}
	return "WARNING: DHCP lease display is DEGRADED — " + s.Detail +
		"; the lease set shown below may be incomplete"
}

// DegradedBanners returns the operator banner line(s) for a combined v4+v6
// lease display — one line per DEGRADED family, in v4-then-v6 order, with an
// exact-duplicate collapsed to a single line (#5967).
//
// #5938 introduced the per-source banner but the show handlers rendered it as
// `if src4.Banner() else if src6.Banner()`, so when BOTH families were degraded
// only the v4 detail printed and a v6-specific reason (e.g. a DIFFERENT
// unreadable sibling file) was silently suppressed — the operator was alerted
// but lost the v6 detail. Centralizing the selection here keeps the authoritative
// gRPC `show dhcp server` handler and the in-process interactive CLI in lockstep
// (they were divergent before #5967): both call this and render every distinct
// degraded-family detail. The exact-duplicate collapse avoids printing the same
// line twice when both families fell back to the memfile for the identical
// reason (identical Detail). A healthy source contributes no line.
func DegradedBanners(src4, src6 LeaseSource) []string {
	var out []string
	if b := src4.Banner(); b != "" {
		out = append(out, b)
	}
	if b := src6.Banner(); b != "" && (len(out) == 0 || out[0] != b) {
		out = append(out, b)
	}
	return out
}

// skippedDetail renders the "N sibling(s) unreadable" degradation reason.
func skippedDetail(paths []string) string {
	return fmt.Sprintf("%d Kea lease file(s) unreadable and skipped: %s",
		len(paths), strings.Join(paths, ", "))
}

// GetLeasesWithSource4 returns the active DHCPv4 leases for display PLUS the
// source they were read from (#5938). It prefers the live lease DB when the
// lease_cmds hook is available and falls back to the memfile LFC file set,
// annotating the source degraded on fallback or on an unreadable sibling.
func (m *Manager) GetLeasesWithSource4() ([]Lease, LeaseSource) {
	return m.getDisplayLeases(4, time.Now())
}

// GetLeasesWithSource6 is the DHCPv6 counterpart of GetLeasesWithSource4.
func (m *Manager) GetLeasesWithSource6() ([]Lease, LeaseSource) {
	return m.getDisplayLeases(6, time.Now())
}

// getDisplayLeases resolves the active display lease set for a family, preferring
// the live lease_cmds socket when it is EXPECTED (Invariant 2) and degrading to
// the memfile LFC file set otherwise, tracking the source (Invariant 8).
func (m *Manager) getDisplayLeases(family int, now time.Time) ([]Lease, LeaseSource) {
	// Invariant 2: the running Kea lease DB (queried via lease{4,6}-get-all over
	// the control socket) is the AUTHORITATIVE source. Prefer it — but ONLY when
	// the lease_cmds hook is expected to be present (lease-sync enabled injects
	// the control socket + hook, see SetLeaseSyncEnabled). On a box WITHOUT the
	// hook the memfile is the normal authoritative source, so a memfile read
	// there is NOT a degradation and must not raise the banner.
	if m.leaseSyncEnabled.Load() {
		ctx, cancel := context.WithTimeout(context.Background(), keaControlTimeout)
		defer cancel()
		leases, err := m.readDisplayLeasesViaSocket(ctx, family, now)
		if err == nil {
			return leases, LeaseSource{Origin: leaseSourceLiveSocket}
		}
		// The EXPECTED socket failed (Kea not up yet, hook missing, timeout).
		// Fall back to the memfile file set and flag the display degraded — the
		// snapshot is complete for the LFC phases (#5796) but may lag the live DB.
		slog.Debug("dhcpserver: live lease_cmds query failed; display falling back to memfile",
			"family", family, "err", err)
		fallback, skipped := parseLeaseCSVDegradable(m.leaseFile(family), now)
		detail := "live lease_cmds control socket unavailable — showing memfile snapshot"
		if len(skipped) > 0 {
			detail += "; " + skippedDetail(skipped)
		}
		return fallback, LeaseSource{Origin: leaseSourceMemfileFallback, Degraded: true, Detail: detail}
	}

	// No hook expected: the memfile LFC file set is the normal source. Still
	// surface a banner if a sibling file was present but unreadable (Invariant 8
	// mangled-sibling half) so a partial display is never mistaken for complete.
	leases, skipped := parseLeaseCSVDegradable(m.leaseFile(family), now)
	if len(skipped) > 0 {
		return leases, LeaseSource{Origin: leaseSourceMemfile, Degraded: true, Detail: skippedDetail(skipped)}
	}
	return leases, LeaseSource{Origin: leaseSourceMemfile}
}

// readDisplayLeasesViaSocket queries the live Kea lease DB for a family via
// lease{4,6}-get-all on the control socket and maps each active lease to the
// display Lease shape. It mirrors the memfile display filters (only Kea's
// default/active state; drop leases whose expiry has lapsed) so the socket and
// memfile displays agree. Reuses the HA-sync socket plumbing (keaControl +
// keaLeaseGetAllArgs). Any transport / result error is returned so the caller
// falls back to the memfile.
func (m *Manager) readDisplayLeasesViaSocket(ctx context.Context, family int, now time.Time) ([]Lease, error) {
	socket := m.controlSocket(family)
	resp, err := keaControl(ctx, m.keaDial, socket, keaCommand{Command: fmt.Sprintf("lease%d-get-all", family)})
	if err != nil {
		return nil, err
	}
	if resp.Result == keaResultEmpty {
		return nil, nil // no leases (a successful empty set)
	}
	if resp.Result != keaResultSuccess {
		return nil, fmt.Errorf("lease%d-get-all: result=%d text=%q", family, resp.Result, resp.Text)
	}
	var args keaLeaseGetAllArgs
	if len(resp.Arguments) > 0 {
		if err := json.Unmarshal(resp.Arguments, &args); err != nil {
			return nil, fmt.Errorf("lease%d-get-all decode: %w", family, err)
		}
	}
	nowUnix := now.Unix()
	out := make([]Lease, 0, len(args.Leases))
	for _, kl := range args.Leases {
		if kl.State != keaStateDefault {
			continue // only active leases (mirrors the display memfile filter)
		}
		// Kea get-all returns cltt + valid-lft; the absolute expiry is their sum
		// (matching the memfile's `expire` column). Drop a lapsed lease.
		expire := kl.Expire
		if expire == 0 {
			expire = kl.CLTT + int64(kl.ValidLft)
		}
		if expire > 0 && nowUnix >= expire {
			continue
		}
		out = append(out, Lease{
			Address:    kl.IPAddress,
			HWAddress:  kl.HWAddress,
			Hostname:   kl.Hostname,
			ValidLife:  strconv.Itoa(kl.ValidLft),
			ExpireTime: strconv.FormatInt(expire, 10),
			SubnetID:   strconv.Itoa(kl.SubnetID),
		})
	}
	return out, nil
}

// parseLeaseCSVDegradable reads the full Kea LFC file set using the display
// semantics. It is DEGRADE-tolerant (#5938 Invariant 8): instead of ABORTING
// the whole read when one sibling file cannot be opened (a non-IsNotExist error
// — a mangled / permission-broken .2 / .1 / current), it SKIPS that file,
// records its path, and continues, so a single unreadable sibling shows the
// remaining leases plus a banner rather than blanking `show dhcp server leases`.
// A genuinely-absent file (IsNotExist) is handled inside parseLeaseCSVFileInto
// (returns nil) and is NOT a degradation — it is the common no-LFC steady state.
// Returns the merged active leases and the list of skipped (unreadable) paths.
func parseLeaseCSVDegradable(path string, now time.Time) ([]Lease, []string) {
	acc := &leaseCSVAccum{
		latest: make(map[string]Lease),
		seen:   make(map[string]struct{}),
	}
	var skipped []string
	for _, f := range keaLFCLeaseFilePaths(path) {
		if err := parseLeaseCSVFileInto(f, now, acc); err != nil {
			slog.Debug("dhcpserver: skipping unreadable Kea lease file for display",
				"path", f, "err", err)
			skipped = append(skipped, f)
			continue
		}
	}
	leases := make([]Lease, 0, len(acc.order))
	for _, addr := range acc.order {
		if l := acc.latest[addr]; l.Address != "" {
			leases = append(leases, l)
		}
	}
	return leases, skipped
}
