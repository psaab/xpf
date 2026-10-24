package dhcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// ClientSpec describes one desired DHCP client, derived purely from the
// committed configuration. It carries config identity only — never
// lease, address, or other runtime state.
type ClientSpec struct {
	Iface    string
	Family   AddressFamily
	DUIDType string         // DHCPv6 only; "" defaults to duid-ll
	V4       *DHCPv4Options // DHCPv4 only; nil = defaults
	V6       *DHCPv6Options // DHCPv6 only; nil = defaults
}

// fingerprintV4 encodes the config identity of a DHCPv4 client.
func fingerprintV4(o *DHCPv4Options) string {
	if o == nil {
		return "v4"
	}
	return fmt.Sprintf("v4|lt=%d|ra=%d|ri=%d|fd=%t",
		o.LeaseTime, o.RetransmissionAttempt,
		o.RetransmissionInterval, o.ForceDiscover)
}

// fingerprintV6 encodes the config identity of a DHCPv6 client,
// including the DUID type and the Stateless flag (both captured by the
// run goroutine at start, so a change requires a restart).
func fingerprintV6(duidType string, o *DHCPv6Options) string {
	if duidType == "" {
		duidType = "duid-ll"
	}
	if o == nil {
		return "v6|duid=" + duidType
	}
	// #12533: pins are part of config identity — adding/removing a pin
	// restarts the client so the next exchange re-decodes delegations
	// against the new pin set instead of silently retaining a now-
	// unpinned (or newly pinned) delegation until expiry.
	return fmt.Sprintf("v6|duid=%s|sl=%t|ia=%s|pl=%d|sub=%d|req=%s|ra=%s|pin=%s",
		duidType, o.Stateless, strings.Join(o.IATypes, ","),
		o.PDPrefLen, o.PDSubLen, strings.Join(o.ReqOptions, ","),
		o.RAIface, strings.Join(o.PinnedPrefixes, ","))
}

// configFingerprintLocked computes the config-identity fingerprint for
// a client key from the manager's currently installed option state.
// Caller must hold m.mu.
func (m *Manager) configFingerprintLocked(key clientKey) string {
	if key.family == AFInet {
		return fingerprintV4(m.v4opts[key.iface])
	}
	return fingerprintV6(m.duidTypes[key.iface], m.v6opts[key.iface])
}

// Reconcile diffs the desired client set against running clients and
// converges: clients removed from config are stopped (stop renewing +
// remove the leased address; no protocol RELEASE — matching interface
// deconfiguration semantics elsewhere), clients whose option identity
// changed are restarted, and missing clients are started.
//
// The diff keys STRICTLY on config identity (interface, family,
// options/DUID type). It must never key on lease or address state:
// lease changes fire the onAddressChange callback, which re-enters the
// daemon's applyConfig and thus this Reconcile — keying on lease state
// would restart the client on every lease event and loop forever
// (#1793, plan §5.4).
func (m *Manager) Reconcile(specs []ClientSpec) {
	desired := make(map[clientKey]ClientSpec, len(specs))
	for _, s := range specs {
		desired[clientKey{iface: s.Iface, family: s.Family}] = s
	}

	type stopEntry struct {
		key    clientKey
		dc     *dhcpClient
		reason string
	}
	var stops []stopEntry

	m.mu.Lock()
	// Install the desired option state first so fingerprint comparison
	// below sees the new config identity. Running clients re-read the
	// option maps mid-cycle, but any client observing changed options
	// is about to be restarted by the fingerprint mismatch anyway.
	for key, s := range desired {
		switch key.family {
		case AFInet:
			m.v4opts[key.iface] = s.V4
		case AFInet6:
			dt := s.DUIDType
			if dt == "" {
				dt = "duid-ll"
			}
			// #5855: on a DUID-type ROTATION (duid-ll<->duid-llt), drop the
			// cached DUID so the restarted client cannot be handed the retired
			// identity — getDUID re-resolves the requested type (regenerating +
			// persisting it). The persisted file is left in place as getDUID's
			// fail-safe fallback until a successful rotation overwrites it.
			if prev, ok := m.duidTypes[key.iface]; ok && normalizeDUIDType(prev) != dt {
				delete(m.duids, key.iface)
			}
			m.duidTypes[key.iface] = dt
			m.v6opts[key.iface] = s.V6
		}
	}
	for key, dc := range m.clients {
		if _, ok := desired[key]; !ok {
			stops = append(stops, stopEntry{key, dc, "removed from config"})
			continue
		}
		if dc.fingerprint != m.configFingerprintLocked(key) {
			stops = append(stops, stopEntry{key, dc, "client options changed"})
		}
	}
	// Prune option state for every key absent from desired, regardless
	// of whether a client is currently registered. Renew's membership
	// guard treats these maps as the desired-config signal, and a
	// renewing client may already be deregistered (cancel +
	// finishClient) by the time this Reconcile runs — pruning only for
	// registered clients would leave a stale entry that lets Renew
	// resurrect the removed client (Codex review on PR #1815, round 4).
	for iface := range m.v4opts {
		if _, ok := desired[clientKey{iface: iface, family: AFInet}]; !ok {
			delete(m.v4opts, iface)
		}
	}
	for iface := range m.v6opts {
		if _, ok := desired[clientKey{iface: iface, family: AFInet6}]; !ok {
			delete(m.v6opts, iface)
			delete(m.duidTypes, iface)
		}
	}
	m.mu.Unlock()

	for _, s := range stops {
		slog.Info("DHCP: stopping client",
			"interface", s.key.iface, "family", s.key.family,
			"reason", s.reason)
		s.dc.cancel()
		// finishClient (the goroutine's defer) deregisters the entry and
		// removes the leased address before done closes.
		<-s.dc.done
	}

	for key := range desired {
		// No-op for clients still running with an unchanged fingerprint;
		// starts new and option-changed (just stopped) clients.
		m.Start(context.Background(), key.iface, key.family)
	}
}
