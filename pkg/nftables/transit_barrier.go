package nftables

import (
	"errors"
	"fmt"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// TransitBarrierTableName is the table installed on BOTH the inet and bridge
// families while the dataplane is UNARMED (#7191).
const TransitBarrierTableName = "xpf_transit_barrier"

// ErrTransitBarrierBridgeUnsupported marks a kernel that does not provide the
// bridge nf_tables family. The inet barrier remains useful on that kernel, so
// callers may treat this sentinel as a documented degraded-success condition
// only when it is the sole InstallTransitBarrier error.
var ErrTransitBarrierBridgeUnsupported = errors.New("bridge nftables family unsupported")

type transitBarrierBridgeUnsupportedError struct {
	err error
}

func (e *transitBarrierBridgeUnsupportedError) Error() string {
	return fmt.Sprintf("%s: %v", ErrTransitBarrierBridgeUnsupported, e.err)
}

func (e *transitBarrierBridgeUnsupportedError) Unwrap() error {
	return e.err
}

func (e *transitBarrierBridgeUnsupportedError) Is(target error) bool {
	return target == ErrTransitBarrierBridgeUnsupported
}

// IsTransitBarrierBridgeUnsupportedOnly reports whether err is exactly the
// bridge-family unsupported degradation from InstallTransitBarrier, with no
// inet or other family failure joined alongside it.
func IsTransitBarrierBridgeUnsupportedOnly(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) != 1 {
			return false
		}
		err = children[0]
	}
	for err != nil {
		if err == ErrTransitBarrierBridgeUnsupported {
			return true
		}
		if _, ok := err.(*transitBarrierBridgeUnsupportedError); ok {
			return true
		}
		if _, ok := err.(interface{ Unwrap() []error }); ok {
			return false
		}
		unwrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapped.Unwrap()
	}
	return false
}

func transitBarrierFamilyUnsupported(err error) bool {
	return errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EAFNOSUPPORT)
}

// #7191: the nftables half of the unarmed transit barrier.
//
// WHY IT EXISTS. PR #7189 shipped the `ip_forward=0` leg of the barrier
// specified in docs/research/5275-arm-failclosed/plan.md §6. That leaves a
// single sysctl as the only thing between an unarmed box and kernel routing —
// and a sysctl can be raised by a `sysctl.d` drop-in, a systemd unit, an
// operator, or any future code path, none of which this daemon controls. Before
// this change the repo had ZERO `hook forward` chains, verified on a live node:
// `nft list ruleset | grep -c "hook forward"` returned 0.
//
// WHY IT IS SCOPED STRICTLY TO THE UNARMED WINDOW. This is the constraint that
// makes the barrier safe, and getting it wrong is the difference between
// defence-in-depth and a black hole. Several ARMED paths deliberately rely on
// the kernel forward path being OPEN and UNFILTERED, and daemon_transit_gate.go
// names them: route-based-VPN plaintext leaving an xfrm interface (which is
// excluded from AF_XDP binding, so nothing adjudicates it in userspace), SNAT'd
// frames passed up for kernel routing (the reason `accept_local` is set), and
// the #7409 slow-path reinject. A forward drop that is live while ARMED breaks
// all three.
//
// Because the barrier is installed only while unarmed — exactly the window in
// which `ip_forward` is already 0 — it CLOSES NOTHING THAT WAS OPEN. It is belt
// to the sysctl's braces over the same interval, not a new reject surface. That
// bounds the blast radius: the worst case of a bug here is that the barrier
// fails to install (no worse than today), not that armed transit is dropped.
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
// leg must still install when a kernel lacks bridge netfilter support. A bridge
// family-unsupported error carries ErrTransitBarrierBridgeUnsupported so a
// caller can report that documented degradation without hiding other failures.
func (in *netlinkInstaller) InstallTransitBarrier() error {
	var errs []error
	for _, family := range transitBarrierFamilies() {
		if err := in.installBarrierFamily(family); err != nil {
			if family == nftables.TableFamilyBridge && transitBarrierFamilyUnsupported(err) {
				err = &transitBarrierBridgeUnsupportedError{err: err}
			}
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
// could not be removed leaves the box transit-closed while armed — the black
// hole this design exists to avoid — and the caller must be able to see it.
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
