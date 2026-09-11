package nftables

import (
	"errors"
	"fmt"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// TransitBarrierTableName is the table installed on BOTH the inet and bridge
// families while kernel transit is closed (#7191; the daemon's transitOpen,
// #9725).
const TransitBarrierTableName = "xpf_transit_barrier"

// #7191: the nftables half of the transit barrier.
//
// WHY IT EXISTS. PR #7189 shipped the `ip_forward=0` leg of the barrier
// specified in docs/research/5275-arm-failclosed/plan.md §6. That leaves a
// single sysctl as the only thing between an unarmed box and kernel routing —
// and a sysctl can be raised by a `sysctl.d` drop-in, a systemd unit, an
// operator, or any future code path, none of which this daemon controls. Before
// this change the repo had ZERO `hook forward` chains, verified on a live node:
// `nft list ruleset | grep -c "hook forward"` returned 0.
//
// WHY IT IS SCOPED STRICTLY TO THE CLOSED-TRANSIT WINDOW. This is the
// constraint that makes the barrier safe, and getting it wrong is the difference
// between defence-in-depth and a black hole. Several ARMED paths deliberately
// rely on the kernel forward path being OPEN and UNFILTERED while transit is
// open, and daemon_transit_gate.go names them: route-based-VPN plaintext leaving
// an xfrm interface (which is excluded from AF_XDP binding, so nothing
// adjudicates it in userspace), SNAT'd frames passed up for kernel routing (the
// reason `accept_local` is set), and the #7409 slow-path reinject. A forward
// drop that is live while transit is open breaks all three. The daemon installs
// the barrier exactly while its transitOpen is false (#9725): unarmed, or armed
// with no shim XDP link attached.
//
// Closing installs the barrier first and then writes `ip_forward=0`. Once both
// have landed, the inet leg is belt to the sysctl's braces for ROUTED transit.
// The bridge leg is different: bridged frames ignore `ip_forward`, so it is the
// only thing that closes them. That
// bounds the blast radius: the worst case of a bug here is that the barrier
// fails to install (no worse than without it), not that transit is dropped while
// open.
//
// WHY BOTH FAMILIES. `ip_forward` does not govern bridged frames at all, and
// this repo creates Linux bridge domains (compiler_iface.go), so an inet
// forward-hook drop alone leaves a bridged topology uncovered. The two families
// are installed and removed independently so a kernel without bridge netfilter
// still gets the inet leg.
//
// FLOWTABLE: plan §6 also calls for a flowtable disable. That leg is a NO-OP
// today and no code is written for it deliberately: xpf creates no flowtable
// anywhere (zero hits for `flowtable` outside prose), so there is nothing to
// flush. Building machinery to disable a flowtable that is never created would
// be inert code that reads as coverage. TestNoFlowtableIsEverCreated7191 pins
// the assumption so this comment cannot rot into a false claim.

// transitBarrierFamilies is the family set the barrier covers. inet carries
// routed transit; bridge carries frames that never traverse the inet forward
// hook at all.
func transitBarrierFamilies() []nftables.TableFamily {
	return []nftables.TableFamily{nftables.TableFamilyINet, nftables.TableFamilyBridge}
}

// InstallTransitBarrier installs an unconditional forward-hook DROP in every
// barrier family. It is idempotent: an existing table is replaced in the same
// transaction, so a re-assert on the apply tail cannot accumulate chains.
//
// A per-family failure is returned joined rather than short-circuited: the inet
// leg must still install when a kernel lacks bridge netfilter support.
func (in *netlinkInstaller) InstallTransitBarrier() error {
	var errs []error
	for _, family := range transitBarrierFamilies() {
		if err := in.installBarrierFamily(family); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", familyName(family), err))
		}
	}
	return errors.Join(errs...)
}

func (in *netlinkInstaller) installBarrierFamily(family nftables.TableFamily) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExistsInFamily(c, family, TransitBarrierTableName)
	if err != nil {
		return err
	}
	tbl := &nftables.Table{Family: family, Name: TransitBarrierTableName}
	if exists {
		c.DelTable(tbl)
	}
	tbl = c.AddTable(tbl)
	prio := *nftables.ChainPriorityFilter
	// Policy DROP with no rules: every forwarded packet falls through the empty
	// chain to the policy. There is deliberately no management exemption —
	// management is INPUT, not FORWARD (plan §6), so nothing reachable by an
	// operator traverses this chain.
	policy := nftables.ChainPolicyDrop
	c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: &prio,
		Policy:   &policy,
	})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", TransitBarrierTableName, err)
	}
	return nil
}

// RemoveTransitBarrier removes the barrier from every family. Idempotent:
// absent -> nil. A genuine kernel failure IS returned, because a barrier that
// could not be removed leaves the box transit-closed while the gate is open —
// the black hole this design exists to avoid — and the caller must be able to
// see it.
func (in *netlinkInstaller) RemoveTransitBarrier() error {
	var errs []error
	for _, family := range transitBarrierFamilies() {
		if err := in.removeBarrierFamily(family); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", familyName(family), err))
		}
	}
	return errors.Join(errs...)
}

func (in *netlinkInstaller) removeBarrierFamily(family nftables.TableFamily) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExistsInFamily(c, family, TransitBarrierTableName)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	c.DelTable(&nftables.Table{Family: family, Name: TransitBarrierTableName})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables delete %s: %w", TransitBarrierTableName, err)
	}
	return nil
}

// tableExistsInFamily is the family-aware twin of tableExists, which is pinned
// to inet. A missing family (no bridge netfilter) reads as "absent", not as an
// error, so removal on such a kernel is a clean no-op.
func tableExistsInFamily(c *nftables.Conn, family nftables.TableFamily, name string) (bool, error) {
	tables, err := c.ListTablesOfFamily(family)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EAFNOSUPPORT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyBridge:
		return "bridge"
	default:
		return fmt.Sprintf("family(%d)", f)
	}
}
