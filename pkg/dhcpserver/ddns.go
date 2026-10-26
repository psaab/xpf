package dhcpserver

import (
	"time"

	"github.com/psaab/xpf/pkg/ddns"
)

// ddns.go: the thin glue between pkg/dhcpserver and the pkg/ddns spine
// (#2691 P1a). The RFC 2136 backend, the ownership state store, the reconcile
// engine, the sentinels, the write-ahead durability, and the DHCID/ownership
// model were moved VERBATIM to pkg/ddns; this file keeps pkg/dhcpserver a
// CALLER of that spine without changing any external API:
//
//   - It re-exports the cross-package DDNS types (DDNSManager, DNSUpdater,
//     LeaseDNSRecord, DDNSStats, DDNSOwnedRecordView) as type aliases so
//     pkg/daemon / pkg/grpcapi / pkg/cli / pkg/api compile unchanged.
//   - It injects the Kea-memfile lease parser (which STAYS in this package —
//     ddns_leases.go, entangled with the lease-sync fallback) into the engine
//     via the ddns.LeaseParser seam, inverting the dependency (pkg/ddns owns
//     the engine + Lease type; pkg/dhcpserver supplies the parser). This
//     avoids an import cycle: pkg/ddns never imports pkg/dhcpserver.
//
// No behavior changed in P1a — this is a pure code-motion refactor.

// DDNSManager is the DHCP dynamic-DNS reconcile manager. Moved to pkg/ddns in
// #2691 P1a; aliased here so existing callers (pkg/daemon's d.ddns field, etc.)
// need no change.
type DDNSManager = ddns.Manager

// DNSUpdater is the pluggable DNS-update backend interface (moved to pkg/ddns).
type DNSUpdater = ddns.DNSUpdater

// LeaseDNSRecord is the forward+reverse record set the reconciler operates on
// (moved to pkg/ddns).
type LeaseDNSRecord = ddns.LeaseDNSRecord

// DDNSStats is the observable counter snapshot (moved to pkg/ddns).
type DDNSStats = ddns.Stats

// DDNSOwnedRecordView is the read-only owned-record projection (moved to
// pkg/ddns).
type DDNSOwnedRecordView = ddns.OwnedRecordView

// keaLeaseParser adapts the package-local Kea-memfile parser
// (parseActiveLeases, in ddns_leases.go) to the ddns.LeaseParser seam,
// converting each authoritative keaLeaseRow into the reconcile-relevant
// ddns.Lease view. HA-only fields never enter ddnsLease; the DDNS contract
// has no prefix-len field. The v6 lease_type discriminator (#5072) is carried
// through so the reconciler distinguishes an IA_PD delegated-prefix base
// from an address lease and never publishes AAAA/PTR for a delegated network
// base. A present-but-unparseable lease_type maps to ddns.LeaseTypeUnknown
// and is rejected fail-closed rather than defaulting to an address type.
func keaLeaseParser(path string, family int, now time.Time) ([]ddns.Lease, error) {
	leases, err := parseActiveLeases(path, family, now)
	if err != nil {
		return nil, err
	}
	out := make([]ddns.Lease, 0, len(leases))
	for _, l := range leases {
		leaseType := ddns.LeaseTypeIANA // v4 and v6-without-column: address lease
		if l.Family == 6 {
			if l.LeaseTypeOK {
				// keaLeaseType{IANA,IATA,IAPD} share Kea's numeric values with
				// ddns.LeaseType{IANA,IATA,IAPD}; carry the raw type. An
				// unrecognized numeric value fails the reconciler's allowlist.
				leaseType = l.LeaseType
			} else {
				leaseType = ddns.LeaseTypeUnknown
			}
		}
		out = append(out, ddns.Lease{
			Family:     l.Family,
			Address:    l.Address,
			Identity:   l.Identity,
			SubnetID:   l.SubnetID,
			HostName:   l.HostName,
			ClientFQDN: l.ClientFQDN,
			LeaseType:  leaseType,
		})
	}
	return out, nil
}

// NewProductionDDNSManager constructs the always-on production manager
// (#1387 increment 2), wiring the package-local Kea-memfile lease parser.
func NewProductionDDNSManager(nodeID string) *DDNSManager {
	return ddns.NewProductionManager(keaLeaseParser, nodeID)
}
