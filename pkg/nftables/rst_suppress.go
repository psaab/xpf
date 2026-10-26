// Package nftables manages nftables rules via the kernel netlink API.
// It does NOT shell out to the nft binary.
package nftables

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const rstTableName = "xpf_dp_rst"

type rstSuppressionPlan struct {
	deleteTable bool
	v4Addrs     []netip.Addr
	v6Addrs     []netip.Addr
}

// InstallRSTSuppression creates nftables rules to DROP outgoing TCP RSTs
// from interface-NAT (SNAT) addresses, but ONLY for packets the kernel
// reports as ct state invalid at OUTPUT with no live full socket behind
// them -- its no-conntrack-entry, no-socket signature (see rstDropExprs,
// #14949 as corrected by #15727 and #16839). These addresses are owned
// by the userspace dataplane; the kernel has no sockets for them and
// should never emit RSTs for the flows the dataplane owns.
// Conntrack-tracked RSTs from the same addresses -- nft
// reject-with-tcp-reset (policy reject / ident-reset) and local
// control-plane socket RSTs -- are legitimate and must survive, as are
// RSTs from live local sockets on those addresses even though no
// conntrack entry exists yet when the raw-priority chain runs (#16839,
// #17868).
//
// When the table already exists, delete + create is performed in a single
// atomic netlink batch to eliminate the race window where no rules exist
// between the old table deletion and new table creation. This is critical
// for HA failover: during the microseconds of RG demotion, the kernel may
// generate RSTs for connections it doesn't own (#450).
func InstallRSTSuppression(v4Addrs []netip.Addr, v6Addrs []netip.Addr) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	tableExists, err := rstTableExists(c)
	if err != nil {
		return err
	}
	plan := buildRSTSuppressionPlan(tableExists, v4Addrs, v6Addrs)
	if !queueRSTSuppression(c, plan) {
		return nil
	}

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}

	slog.Info("RST suppression: installed nftables rules via netlink",
		"v4", len(v4Addrs), "v6", len(v6Addrs))
	return nil
}

// RemoveRSTSuppression was removed in #7171: it had zero production callers
// and swallowed the outcome of its own teardown (`_ = c.Flush()`), so had a
// caller ever appeared it would have reported success for a table that was
// still installed. removeRSTTable below is the live teardown, used by the
// install path's rebuild. A future explicit teardown entry point should return
// an error rather than restore this shape.

func removeRSTTable(c *nftables.Conn) {
	c.DelTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   rstTableName,
	})
}

func rstTableExists(c *nftables.Conn) (bool, error) {
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables list tables: %w", err)
	}
	for _, table := range tables {
		if table != nil && table.Name == rstTableName {
			return true, nil
		}
	}
	return false, nil
}

func buildRSTSuppressionPlan(tableExists bool, v4Addrs []netip.Addr, v6Addrs []netip.Addr) rstSuppressionPlan {
	return rstSuppressionPlan{
		deleteTable: tableExists,
		v4Addrs:     slices.Clone(v4Addrs),
		v6Addrs:     slices.Clone(v6Addrs),
	}
}

func queueRSTSuppression(c *nftables.Conn, plan rstSuppressionPlan) bool {
	if plan.deleteTable {
		removeRSTTable(c)
	}
	if len(plan.v4Addrs) == 0 && len(plan.v6Addrs) == 0 {
		return plan.deleteTable
	}

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   rstTableName,
	})
	// Priority raw (-300) is load-bearing (#15727): OUTPUT conntrack
	// runs at -200, so at raw the RST still reads INVALID. That alone
	// is not sufficient (#16839), because live-socket RSTs also read
	// INVALID before conntrack attaches an entry. IPv4 uses the
	// wildcard-bound control mini-socket predicate to spare full
	// sockets. IPv6's socketless kernel RST has no skb->sk, so its
	// socket expression BREAKs; the ordered rules instead return
	// address-bound live sockets before dropping socketless RSTs.
	// Reject-synthesized RSTs are emitted from the ingress hook and do
	// not reach OUTPUT as a fresh socketless packet from these addresses.
	chain := c.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityRaw,
		Policy:   ptrPolicy(nftables.ChainPolicyAccept),
	})

	for _, addr := range plan.v4Addrs {
		addRSTDropRule(c, table, chain, addr)
	}
	for _, addr := range plan.v6Addrs {
		// nft_socket_eval BREAKs on the IPv6 kernel's socketless RST
		// skb before the wildcard comparison can run. First return
		// live full-socket RSTs, then drop matching socketless RSTs.
		addRSTLiveSocketReturnRule(c, table, chain, addr)
		addRSTDropRule(c, table, chain, addr)
	}
	return true
}

// addRSTDropRule adds the conntrack-less TCP RST drop rule for one protected
// source address.
func addRSTDropRule(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addr netip.Addr) {
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: rstDropExprs(addr),
	})
}

// addRSTLiveSocketReturnRule lets live full-socket RSTs from a protected
// IPv6 source continue through the output hook. For a socketless RST,
// nft_socket_eval BREAKs this rule; the following drop rule then matches it.
func addRSTLiveSocketReturnRule(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addr netip.Addr) {
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: rstLiveSocketReturnExprs(addr),
	})
}

// rstDropExprs builds the expressions that drop a conntrack-less RST from
// addr. IPv4 RSTs use the wildcard-bound tcp_rst_sock control mini-socket,
// so the wildcard==1 predicate protects live sockets. The socketless IPv6
// reset skb has no skb->sk: nft_socket_eval BREAKs instead of returning a
// wildcard value. IPv6 therefore uses a preceding live-socket exception
// rule and this drop rule intentionally has no socket expression.
func rstDropExprs(addr netip.Addr) []expr.Any {
	exprs := rstCommonMatchExprs(addr)
	if addr.Is4() {
		exprs = append(exprs,
			&expr.Socket{Key: expr.SocketKeyWildcard, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		)
	}
	exprs = appendRSTPacketMatch(exprs)
	return append(exprs, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
}

// rstLiveSocketReturnExprs matches a live, address-bound socket's RST.
// Socketless IPv6 RSTs BREAK at the Socket expression and continue to the
// following socketless drop rule.
func rstLiveSocketReturnExprs(addr netip.Addr) []expr.Any {
	exprs := rstCommonMatchExprs(addr)
	exprs = append(exprs,
		&expr.Socket{Key: expr.SocketKeyWildcard, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
	)
	exprs = appendRSTPacketMatch(exprs)
	return append(exprs, &expr.Verdict{Kind: expr.VerdictReturn})
}

// rstCommonMatchExprs matches the source family/address and ct state INVALID.
// At raw OUTPUT, conntrack has not attached an entry yet, so both spurious
// kernel RSTs and live-socket RSTs need the socket-specific handling above.
func rstCommonMatchExprs(addr netip.Addr) []expr.Any {
	var (
		addrBytes   net.IP
		addrLen     uint32
		saddrOffset uint32
		family      byte
	)
	if addr.Is4() {
		v4 := addr.As4()
		addrBytes, addrLen, saddrOffset, family = net.IP(v4[:]), 4, 12, unix.NFPROTO_IPV4
	} else {
		v6 := addr.As16()
		addrBytes, addrLen, saddrOffset, family = net.IP(v6[:]), 16, 8, unix.NFPROTO_IPV6
	}
	exprs := make([]expr.Any, 0, 16)
	return append(exprs,
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       saddrOffset,
			Len:          addrLen,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addrBytes},
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID),
		},
	)
}

// appendRSTPacketMatch appends the TCP protocol and RST-flag predicates.
func appendRSTPacketMatch(exprs []expr.Any) []expr.Any {
	return append(exprs,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13,
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x04},
			Xor:            []byte{0x00},
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00}},
	)
}

func ptrPolicy(p nftables.ChainPolicy) *nftables.ChainPolicy {
	return &p
}
