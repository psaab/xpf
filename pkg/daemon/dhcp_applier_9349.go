package daemon

import (
	"context"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// dhcpApplier is the DHCP-server surface the daemon drives (#9349).
//
// WHY AN INTERFACE. Daemon.dhcpServer was a concrete *dhcpserver.Manager whose
// test seams (runSystemctl, unitActive, confPath4/confPath6, warn) are
// unexported, so a pkg/daemon test could not construct a harmless one. The
// consequence was measured with mutation testing during #9141: BOTH DHCP
// derivation calls in applyServicesReconcile could be severed —
//
//	desired := cfg.System.DHCPServer          // instead of desiredStandaloneDHCPConfig(cfg)
//	dhcpCfg := &cfg.System.DHCPServer         // instead of d.desiredClusterDHCPConfig(cfg)
//
// — and the ENTIRE Go suite stayed green. Neither is a subtle regression:
// standalone, Kea is handed RETH LOGICAL names (`reth1.0`), which are not kernel
// devices, so DHCP fails on every RETH-backed segment; clustered, Kea is handed
// the unfiltered config, so BOTH nodes serve every group regardless of
// redundancy-group mastership — dual-DHCP, the exact failure the #1835 F3 /
// #6520 design exists to prevent.
//
// The functions BELOW those call sites are well covered (#6520/#4647 on the
// filter, #9141 on the resolver, #6535 on the converger); what had no cell was
// the WIRING between the apply and the applier. This interface is the smallest
// change that makes it drivable.
//
// It is deliberately the FULL set the daemon calls rather than just the appliers:
// a partial interface would leave the field a concrete type for the rest, which
// is what made this untestable in the first place.
type dhcpApplier interface {
	Apply(cfg *config.DHCPServerConfig) error
	ApplyWithLeaseAuthority(cfg *config.DHCPServerConfig, authority dhcpserver.LeaseApplyAuthority) error
	ApplyClusterCommit(cfg *config.DHCPServerConfig) error
	ApplyClusterCommitWithLeaseAuthority(cfg *config.DHCPServerConfig, authority dhcpserver.LeaseApplyAuthority) error
	ApplyAsync(cfg *config.DHCPServerConfig, reason string)
	ApplyAsyncWithLeaseAuthority(cfg *config.DHCPServerConfig, reason string, authority dhcpserver.LeaseApplyAuthority)
	ClaimApplyRetry(now time.Time) bool
	SetLeaseSyncEnabled(enabled bool)
	Shutdown() error

	GetSyncLeases4(ctx context.Context, now time.Time) ([]dhcpserver.SyncLease, error)
	GetSyncLeases6(ctx context.Context, now time.Time) ([]dhcpserver.SyncLease, error)
	SeedSyncLeases4(ctx context.Context, leases []dhcpserver.SyncLease, now time.Time) (int, error)
	SeedSyncLeases6(ctx context.Context, leases []dhcpserver.SyncLease, now time.Time) (int, error)
	PreSeedMemfileMerged4(ctx context.Context, peer []dhcpserver.SyncLease, now time.Time, stillMastering bool) error
	PreSeedMemfileMerged6(ctx context.Context, peer []dhcpserver.SyncLease, now time.Time, stillMastering bool) error
	WaitControlSocket4(ctx context.Context, within time.Duration) bool
	WaitControlSocket6(ctx context.Context, within time.Duration) bool

	// The read surface pkg/grpcapi's `show dhcp server` needs. It is here, on
	// the daemon's field type, so d.dhcpServer can be handed to grpcapi.Config
	// as its own narrower interface without a type assertion — Go widens
	// interface to interface when the method set is a superset, and an
	// assertion back to the concrete Manager would reintroduce exactly the
	// coupling this removes.
	IsRunning() bool
	GetLeasesWithSource4() ([]dhcpserver.Lease, dhcpserver.LeaseSource)
	GetLeasesWithSource6() ([]dhcpserver.Lease, dhcpserver.LeaseSource)

	// ApplyFailedForTesting is read by the #6535 converger's own cells. It is
	// part of the interface because the field is the interface — leaving it out
	// would mean those cells could not observe the production Manager they are
	// written against.
	ApplyFailedForTesting() bool
}

// The production implementation must satisfy it. A signature drift here is a
// compile error rather than a silently unimplemented interface.
var _ dhcpApplier = (*dhcpserver.Manager)(nil)
