package nftables

// netlink_installer.go defines the concrete injection interface (#6387 plan
// §12.4) covering EVERY kernel-touching host-inbound / lo0 / fence operation
// that today goes through the exec-`nft` package vars nftApplyPayload /
// nftDeleteTable in pkg/daemon/daemon_nft.go, plus its netlink implementation.
//
// PR-2 only DEFINES + implements + parity-tests this interface. PR-3 wires the
// daemon apply path to it and ports the 14 fail-closed tests onto its single
// failure-injection seam (a fake Installer that returns an error).

import (
	"errors"
	"fmt"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// HostInboundGapTableName is the kernel nftables table for the #5789 additive
// coverage-gap fence (a distinct input-hook base chain at a later priority than
// the main host-inbound table).
const HostInboundGapTableName = "xpf_hostinbound_gap"

// Base-chain hook-input priorities, mirroring the pkg/daemon constants
// nftLo0FilterPriority (0) < nftHostInboundPriority (10) <
// nftHostInboundGapPriority (11). The spread is a determinism invariant
// (nft_chain_priority_test.go): the operator's explicit lo0 filter evaluates
// before the zone default-deny backstop, and the coverage-gap fence last.
const (
	lo0FilterPriority      = 0
	hostInboundPriority    = 10
	hostInboundGapPriority = 11
)

// Installer is the netlink host-inbound / lo0 / fence installer seam. Each
// method is one atomic kernel transaction. A fake implementation returning an
// error drives the fail-closed regression tests without a live kernel (PR-3).
type Installer interface {
	// InstallHostInbound installs the real host-inbound table (#3070/#3333).
	InstallHostInbound(spec HostInboundSpec) error
	// InstallColdBootFence installs the #5644 cold-boot fail-closed fence
	// (the xpf_hostinbound table reduced to mandatory admits + address drops).
	InstallColdBootFence(spec FenceSpec) error
	// InstallLo0ColdBootFence installs the #6476 lo0 cold-boot fail-closed fence:
	// the SAME fence body as InstallColdBootFence (mandatory admits + firewall-
	// local address drops) but in the xpf_lo0 table at the lo0 filter priority, so
	// a failed boot-time InstallLo0 does not leave the RE-protection input path
	// open. A later successful InstallLo0 atomically replaces it (same table).
	InstallLo0ColdBootFence(spec FenceSpec) error
	// InstallGapFence installs the #5789 additive coverage-gap fence.
	InstallGapFence(spec GapFenceSpec) error
	// InstallLo0 installs the lo0 loopback input filter (#3445/#3392) and
	// reports how many kernel rules the spec lowered to. ZERO rules means the
	// installed table is an empty `policy accept` shell that enforces NOTHING —
	// a filter name that resolves to no filter, a filter with no terms, or one
	// whose every term lowers to zero rules (a Junos match-nothing scope). The
	// caller must not record such an install as a real operator filter being
	// loaded (#6529); a bare "the install succeeded" boolean cannot tell the two
	// apart.
	InstallLo0(spec Lo0FilterSpec) (rules int, err error)
	// DeleteTable idempotently removes a table (absent -> nil; a genuine
	// kernel/permission failure -> error, preserving the fail-closed teardown
	// contract #5790).
	DeleteTable(name string) error
	// InstallTransitBarrier installs the #7191 forward-hook DROP in the inet and
	// bridge families. Idempotent. The daemon installs it ONLY while kernel
	// transit is closed (its transitOpen, #9725) -- see the scoping argument in
	// transit_barrier.go.
	InstallTransitBarrier() error
	// RemoveTransitBarrier removes it from both families. Idempotent; a genuine
	// failure is returned because a barrier that survives the gate opening would
	// drop transit the kernel forwards (IPsec plaintext, SNAT'd frames, #7409
	// reinject).
	RemoveTransitBarrier() error
}

// netlinkInstaller is the production Installer: it renders each ruleset into a
// single google/nftables batch and Flushes it as one nf_tables transaction.
type netlinkInstaller struct {
	// newConn returns a fresh *nftables.Conn. Overridable so tests can bind the
	// installer to a private network namespace (WithNetNSFd).
	newConn func() (*nftables.Conn, error)
}

// NewNetlinkInstaller returns an Installer that talks to the host's default
// network namespace via netlink (no `nft` binary).
func NewNetlinkInstaller() Installer {
	return &netlinkInstaller{newConn: func() (*nftables.Conn, error) { return nftables.New() }}
}

// newNetlinkInstallerConn constructs a netlinkInstaller with a custom conn
// factory (used by the kernel-gated parity tests to target a private netns).
func newNetlinkInstallerConn(newConn func() (*nftables.Conn, error)) *netlinkInstaller {
	return &netlinkInstaller{newConn: newConn}
}

func (in *netlinkInstaller) InstallHostInbound(spec HostInboundSpec) error {
	_, err := in.replaceTable(HostInboundTableName, hostInboundPriority, func(p *nlPlan) {
		buildHostInboundNetlink(p, spec)
	})
	return err
}

func (in *netlinkInstaller) InstallColdBootFence(spec FenceSpec) error {
	_, err := in.replaceTable(HostInboundTableName, hostInboundPriority, func(p *nlPlan) {
		buildHostInboundFenceNetlink(p, spec)
	})
	return err
}

// InstallLo0ColdBootFence installs the #6476 lo0 cold-boot fence: the SAME fence
// body as InstallColdBootFence (buildHostInboundFenceNetlink — mandatory admits
// plus firewall-local address DROPs) but into the xpf_lo0 table at the lo0 filter
// priority. Reusing the shared fence builder keeps the two fences bit-identical
// in rule shape; only the table wrapper (name + priority, produced generically by
// replaceTable) differs, so a later successful InstallLo0 atomically replaces the
// fence with the operator's real RE-protection filter.
func (in *netlinkInstaller) InstallLo0ColdBootFence(spec FenceSpec) error {
	_, err := in.replaceTable(Lo0TableName, lo0FilterPriority, func(p *nlPlan) {
		buildHostInboundFenceNetlink(p, spec)
	})
	return err
}

func (in *netlinkInstaller) InstallGapFence(spec GapFenceSpec) error {
	_, err := in.replaceTable(HostInboundGapTableName, hostInboundGapPriority, func(p *nlPlan) {
		buildHostInboundGapFenceNetlink(p, spec)
	})
	return err
}

// InstallLo0 returns the rendered rule count alongside the error so the caller
// can tell a real operator filter from an empty `policy accept` shell (#6529).
// The count comes from the ACTUAL build — nlPlan.rules, populated as each rule
// is batched — so it can never drift from the lowering the way a second,
// daemon-side "does this spec enforce anything?" predicate would.
func (in *netlinkInstaller) InstallLo0(spec Lo0FilterSpec) (int, error) {
	return in.replaceTable(Lo0TableName, lo0FilterPriority, func(p *nlPlan) {
		buildLo0FilterNetlink(p, spec)
	})
}

// replaceTable performs the atomic delete-then-recreate of one inet table +
// `input` base chain in a SINGLE Flush (plan §12.2). Cold-boot safe: the table
// is deleted only when it already exists, so an absent table does NOT abort the
// batch (the unconditional-DelTable v1 bug). On any error the kernel aborts the
// whole transaction and the PREVIOUS table is retained untouched — the exact
// atomicity `nft -f -` gave (invariant H4). Each ruleset is its own transaction;
// xpf_lo0 / xpf_hostinbound / xpf_hostinbound_gap are never cross-coupled.
func (in *netlinkInstaller) replaceTable(name string, priority nftables.ChainPriority, build func(p *nlPlan)) (int, error) {
	c, err := in.newConn()
	if err != nil {
		return 0, fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExists(c, name)
	if err != nil {
		return 0, err
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: name}
	if exists {
		c.DelTable(tbl)
	}
	tbl = c.AddTable(tbl)
	prio := priority
	policy := nftables.ChainPolicyAccept
	chain := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &prio,
		Policy:   &policy,
	})
	p := &nlPlan{c: c, table: tbl, chain: chain}
	build(p)
	if p.err != nil {
		return 0, p.err
	}
	if err := c.Flush(); err != nil {
		return 0, fmt.Errorf("nftables flush %s: %w", name, err)
	}
	return len(p.rules), nil
}

func (in *netlinkInstaller) DeleteTable(name string) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExists(c, name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables delete table %s: %w", name, err)
	}
	return nil
}

// tableExists reports whether an inet table of the given name is installed.
func tableExists(c *nftables.Conn, name string) (bool, error) {
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables list tables: %w", err)
	}
	for _, t := range tables {
		if t != nil && t.Name == name {
			return true, nil
		}
	}
	return false, nil
}
