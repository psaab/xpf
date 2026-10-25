package dhcp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// lease_persist.go holds the durable DHCP lease store (#16566).
//
// Before this, a graceful restart survived only as a kernel address:
// Manager.New started with empty lease state, the startup apply rendered
// the managed FRR section / DNS / PD-RA from an empty Leases(), and the
// client restarted at DISCOVER/SOLICIT. A restart during an upstream
// DHCP outage therefore withdrew the DHCP-learned routes for the whole
// outage even though the old lease was still valid.
//
// The fix persists every committed lease (plus its delegated prefixes)
// durably at commit time. Manager.New re-adopts an unexpired persisted
// lease when the kernel still holds its address, so the startup apply
// renders it immediately; the run loop then resumes in the renewal cycle
// (v4 RENEWING REQUEST / v6 RENEW) instead of DISCOVER/SOLICIT, falling
// back to full acquisition on NAK/NoBinding, refusal, or expiry.

// leaseStateVersion is the on-disk schema version. A file with any other
// version is discarded (leases are re-acquired; the DUID store is
// separate and untouched).
const leaseStateVersion = 1

type persistedLease struct {
	Version      int              `json:"version"`
	Interface    string           `json:"interface"`
	Family       int              `json:"family"`
	Address      string           `json:"address,omitempty"`
	Gateway      string           `json:"gateway,omitempty"`
	DNS          []string         `json:"dns,omitempty"`
	DomainSearch []string         `json:"domain_search,omitempty"`
	LeaseTimeNs  int64            `json:"lease_time_ns"`
	ObtainedUnix int64            `json:"obtained_unix"`
	RenewAtNs    int64            `json:"renew_at_ns,omitempty"`
	RebindAtNs   int64            `json:"rebind_at_ns,omitempty"`
	Routes       []persistedRoute `json:"routes,omitempty"`
	ServerID     string           `json:"server_id,omitempty"`
	ServerDUID   string           `json:"server_duid,omitempty"`
	PDs          []persistedPD    `json:"pds,omitempty"`
}

type persistedRoute struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
}

type persistedPD struct {
	Prefix       string `json:"prefix"`
	PreferredNs  int64  `json:"preferred_ns"`
	ValidNs      int64  `json:"valid_ns"`
	ObtainedUnix int64  `json:"obtained_unix"`
	RenewAtNs    int64  `json:"renew_at_ns,omitempty"`
	RebindAtNs   int64  `json:"rebind_at_ns,omitempty"`
	Pinned       bool   `json:"pinned,omitempty"`
}

// leaseStatePath returns the durable lease-state file for a client key.
// Reuses the DUID path validation (traversal-safe interface names, direct
// child of stateDir, #4857).
func (m *Manager) leaseStatePath(ifaceName string, af AddressFamily) (string, error) {
	if !validInterfaceName(ifaceName) {
		return "", fmt.Errorf("invalid interface name %q for lease-state path", ifaceName)
	}
	suffix := "4"
	if af == AFInet6 {
		suffix = "6"
	}
	p := filepath.Join(m.stateDir, "dhcp-lease-"+ifaceName+"-v"+suffix)
	if filepath.Dir(p) != filepath.Clean(m.stateDir) {
		return "", fmt.Errorf("refusing lease-state path outside state dir for interface %q", ifaceName)
	}
	return p, nil
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

func (l *Lease) toPersisted(pds []DelegatedPrefix) persistedLease {
	pl := persistedLease{
		Version:      leaseStateVersion,
		Interface:    l.Interface,
		Family:       int(l.Family),
		Address:      prefixString(l.Address),
		Gateway:      addrString(l.Gateway),
		LeaseTimeNs:  int64(l.LeaseTime),
		ObtainedUnix: l.Obtained.Unix(),
		RenewAtNs:    int64(l.RenewAt),
		RebindAtNs:   int64(l.RebindAt),
		DomainSearch: append([]string(nil), l.DomainSearch...),
		ServerID:     addrString(l.serverID),
	}
	for _, d := range l.DNS {
		pl.DNS = append(pl.DNS, d.String())
	}
	for _, r := range l.ClasslessRoutes {
		pl.Routes = append(pl.Routes, persistedRoute{Destination: prefixString(r.Destination), Gateway: addrString(r.Gateway)})
	}
	if l.v6ServerDUID != nil {
		pl.ServerDUID = hex.EncodeToString(l.v6ServerDUID.ToBytes())
	}
	for _, pd := range pds {
		pl.PDs = append(pl.PDs, persistedPD{
			Prefix:       prefixString(pd.Prefix),
			PreferredNs:  int64(pd.PreferredLifetime),
			ValidNs:      int64(pd.ValidLifetime),
			ObtainedUnix: pd.Obtained.Unix(),
			RenewAtNs:    int64(pd.RenewAt),
			RebindAtNs:   int64(pd.RebindAt),
			Pinned:       pd.Pinned,
		})
	}
	return pl
}

func (pl persistedLease) toLease() (*Lease, []DelegatedPrefix, error) {
	if pl.Version != leaseStateVersion {
		return nil, nil, fmt.Errorf("lease-state version %d, want %d", pl.Version, leaseStateVersion)
	}
	lease := &Lease{
		Interface:    pl.Interface,
		Family:       AddressFamily(pl.Family),
		LeaseTime:    time.Duration(pl.LeaseTimeNs),
		Obtained:     time.Unix(pl.ObtainedUnix, 0),
		RenewAt:      time.Duration(pl.RenewAtNs),
		RebindAt:     time.Duration(pl.RebindAtNs),
		DomainSearch: append([]string(nil), pl.DomainSearch...),
	}
	if pl.Address != "" {
		p, err := netip.ParsePrefix(pl.Address)
		if err != nil {
			return nil, nil, err
		}
		lease.Address = p
	}
	if pl.Gateway != "" {
		a, err := netip.ParseAddr(pl.Gateway)
		if err != nil {
			return nil, nil, err
		}
		lease.Gateway = a
	}
	for _, s := range pl.DNS {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, nil, err
		}
		lease.DNS = append(lease.DNS, a)
	}
	for _, r := range pl.Routes {
		d, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			return nil, nil, err
		}
		g, err := netip.ParseAddr(r.Gateway)
		if err != nil {
			return nil, nil, err
		}
		lease.ClasslessRoutes = append(lease.ClasslessRoutes, LeaseRoute{Destination: d, Gateway: g})
	}
	if pl.ServerID != "" {
		a, err := netip.ParseAddr(pl.ServerID)
		if err != nil {
			return nil, nil, err
		}
		lease.serverID = a
	}
	if pl.ServerDUID != "" {
		b, err := hex.DecodeString(pl.ServerDUID)
		if err != nil {
			return nil, nil, err
		}
		d, err := dhcpv6.DUIDFromBytes(b)
		if err != nil {
			return nil, nil, err
		}
		lease.v6ServerDUID = d
	}
	lease.leaseExpiryApplies = true
	var pds []DelegatedPrefix
	for _, pp := range pl.PDs {
		p, err := netip.ParsePrefix(pp.Prefix)
		if err != nil {
			return nil, nil, err
		}
		pds = append(pds, DelegatedPrefix{
			Interface:         pl.Interface,
			Prefix:            p,
			PreferredLifetime: time.Duration(pp.PreferredNs),
			ValidLifetime:     time.Duration(pp.ValidNs),
			Obtained:          time.Unix(pp.ObtainedUnix, 0),
			RenewAt:           time.Duration(pp.RenewAtNs),
			RebindAt:          time.Duration(pp.RebindAtNs),
			Pinned:            pp.Pinned,
		})
	}
	return lease, pds, nil
}

// persistLease durably stores the committed lease for key (DurableState,
// #1894). Called from commitLease AFTER the in-memory store. Errors are
// logged, never returned: a persist failure must not fail the commit or
// drop a live lease — the worst case degrades to the pre-#16566 restart
// behavior for that lease.
// Every committed lease is persisted, including address-less v6 leases.
func (m *Manager) persistLease(key clientKey, lease *Lease) {
	if lease == nil || m.stateDir == "" {
		return
	}
	m.mu.Lock()
	var pds []DelegatedPrefix
	if key.family == AFInet6 {
		pds = append(pds, m.delegatedPDs[key.iface]...)
	}
	m.mu.Unlock()

	path, err := m.leaseStatePath(key.iface, key.family)
	if err != nil {
		slog.Warn("DHCP: lease-state path", "interface", key.iface, "err", err)
		return
	}
	data, err := json.Marshal(lease.toPersisted(pds))
	if err != nil {
		slog.Warn("DHCP: marshal lease state", "interface", key.iface, "err", err)
		return
	}
	if err := fsatomic.MkdirAllDurable(m.stateDir, 0755); err != nil {
		slog.Warn("DHCP: lease-state mkdir", "interface", key.iface, "err", err)
		return
	}
	if err := fsatomic.WriteFileDurable(path, data, 0644); err != nil {
		slog.Warn("DHCP: persist lease state failed (restart will re-acquire)",
			"interface", key.iface, "family", key.family, "err", err)
	}
}

// deletePersistedLease removes the durable lease state for key. Used on
// terminal teardown (expiry/NAK/finish/Renew deconfigure). Best-effort.
func (m *Manager) deletePersistedLease(key clientKey) {
	if m.stateDir == "" {
		return
	}
	path, err := m.leaseStatePath(key.iface, key.family)
	if err != nil {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		slog.Warn("DHCP: remove lease state", "interface", key.iface, "err", err)
		return
	}
	if err == nil {
		_ = fsatomic.SyncDir(m.stateDir)
	}
}

// loadPersistedLease reads and validates one persisted lease. ok=false
// (with the file removed) when absent, corrupt, expired, or not yet
// valid; now is passed for testability.
func (m *Manager) loadPersistedLease(key clientKey, now time.Time) (*Lease, []DelegatedPrefix, bool) {
	if m.stateDir == "" {
		return nil, nil, false
	}
	path, err := m.leaseStatePath(key.iface, key.family)
	if err != nil {
		return nil, nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false
	}
	var pl persistedLease
	if err := json.Unmarshal(data, &pl); err != nil {
		slog.Warn("DHCP: discarding corrupt lease state", "interface", key.iface, "err", err)
		m.deletePersistedLease(key)
		return nil, nil, false
	}
	lease, pds, err := pl.toLease()
	if err != nil {
		slog.Warn("DHCP: discarding invalid lease state", "interface", key.iface, "err", err)
		m.deletePersistedLease(key)
		return nil, nil, false
	}
	if lease.Interface != key.iface || lease.Family != key.family {
		m.deletePersistedLease(key)
		return nil, nil, false
	}
	if lease.LeaseTime <= 0 && key.family != AFInet6 {
		m.deletePersistedLease(key)
		return nil, nil, false
	}
	// Expired finite leases are never re-adopted.
	if exp := lease.ExpiresAt(); !exp.IsZero() && !now.Before(exp) {
		m.deletePersistedLease(key)
		return nil, nil, false
	}
	// Drop already-expired PDs.
	live := pds[:0]
	for _, pd := range pds {
		if !pd.Expired(now) {
			live = append(live, pd)
		}
	}
	return lease, live, true
}

// kernelHasAddress reports whether the kernel still holds the lease
// address on ifaceName. Tests without a netlink handle (nlHandle==nil)
// or with the seam set report true so the re-adoption path is exercised
// without a live interface; production queries AddrList.
func (m *Manager) kernelHasAddress(ifaceName string, lease *Lease) bool {
	if lease == nil || !lease.Address.IsValid() {
		// Address-less (PD-only / stateless) leases need no kernel check.
		return true
	}
	if m.kernelHasAddressForTest != nil {
		return m.kernelHasAddressForTest(ifaceName, lease)
	}
	if m.nlHandle == nil {
		return true
	}
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return false
	}
	addrs, err := m.nlHandle.AddrList(link, 0)
	if err != nil {
		return false
	}
	want := lease.Address.Addr()
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		if got, ok := netip.AddrFromSlice(a.IPNet.IP); ok && got.Unmap() == want.Unmap() {
			return true
		}
	}
	return false
}

// adoptPersistedLease re-adopts the persisted lease for key when it is
// unexpired and (for addressed leases) the kernel still holds the
// address. On success the lease (+PDs) is installed into the in-memory
// maps so Leases()/DelegatedPrefixesForRA() render it in the startup
// apply, and it is returned for the run loop to resume renewal from.
// On any failure the persisted file is removed so a stale address is
// never resurrected after its kernel lifetime ended.
func (m *Manager) adoptPersistedLease(key clientKey) (*Lease, []DelegatedPrefix) {
	lease, pds, ok := m.loadPersistedLease(key, time.Now())
	if !ok {
		return nil, nil
	}
	if !m.kernelHasAddress(key.iface, lease) {
		slog.Info("DHCP: persisted lease address not in kernel, discarding",
			"interface", key.iface, "family", key.family, "address", lease.Address)
		m.deletePersistedLease(key)
		return nil, nil
	}
	m.mu.Lock()
	m.leases[key] = lease
	if key.family == AFInet6 {
		if len(pds) > 0 {
			m.delegatedPDs[key.iface] = pds
		} else {
			delete(m.delegatedPDs, key.iface)
		}
	}
	m.mu.Unlock()
	slog.Info("DHCP: re-adopted persisted lease after restart",
		"interface", key.iface, "family", key.family,
		"address", lease.Address, "expires", lease.ExpiresAt())
	return lease, pds
}

// adoptedLease returns the lease Start already re-adopted for key (plus
// its PDs), so run loops can resume in the renewal cycle. Nil when no
// lease was adopted.
func (m *Manager) adoptedLease(key clientKey) (*Lease, []DelegatedPrefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	lease := m.leases[key]
	if lease == nil {
		return nil, nil
	}
	var pds []DelegatedPrefix
	if key.family == AFInet6 {
		pds = append(pds, m.delegatedPDs[key.iface]...)
	}
	return lease, pds
}
