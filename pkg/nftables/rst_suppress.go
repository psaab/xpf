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
// conntrack entry exists yet when the raw-priority chain runs (#16839).
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
	// Priority raw (-300) is load-bearing (#15727): the output
	// conntrack hook runs at -200 and attaches an entry (ctinfo NEW)
	// to the kernel's locally generated RST before a filter-priority
	// (0) chain sees it, so at filter priority the packet reads
	// `new`, never `invalid`, and no INVALID predicate can match it.
	// Verified live: the same rule counts the RST at priority raw and
	// counts nothing at priority filter. At raw the RST still carries
	// no entry, so nft_ct reports INVALID -- the signature rstDropExprs
	// matches. That signature alone is NOT sufficient (#16839): a
	// local socket's RST also carries no nfct at raw (conntrack has
	// not run yet on OUTPUT), so it too reads INVALID even though its
	// connection is tracked once conntrack runs. rstDropExprs
	// therefore additionally requires that no live full socket owns
	// the packet (socket wildcard == 1 via the kernel's timewait/
	// request-socket control socket), which only the spurious
	// no-socket RST satisfies. A reject-synthesized RST is emitted
	// from the ingress hook itself, never reaches OUTPUT as a fresh
	// socket-less packet, and in any case is not emitted from an
	// interface-NAT source address owned by the dataplane.
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
		addRSTDropRule(c, table, chain, addr)
	}
	return true
}

// addRSTDropRule adds: meta nfproto <family> ip/ip6 saddr <addr> ct state invalid socket wildcard 1 tcp flags & rst != 0 counter drop
func addRSTDropRule(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, addr netip.Addr) {
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: rstDropExprs(addr),
	})
}

// rstDropExprs builds the expression list for one conntrack-less RST-drop
// rule, deriving the nfproto byte, the source-address payload offset and
// the address length from the address itself.
//
// Taking a netip.Addr rather than (bytes, len, offset, family) is what makes
// the rule shape testable AND removes a defect class (#7171). Previously the
// three per-family constants were passed in by addRSTDropRuleV4/V6, so the
// binding between a family and ITS offset lived at the call site. A test could
// then only assert that this function copies the arguments it was handed --
// true however the constants are paired -- so transposing v4's saddr offset to
// v6's was invisible to it. That is not a hypothetical: it is the first
// mutation run against the earlier version of this split, and it escaped.
// Deriving the constants here puts the binding in the one place a test calls.
//
// It also retires the As4() conversion the callers used to make, which panics
// on a v6 address. That panic was unreachable -- the only production caller
// builds its v4 slice with netip.AddrFrom4 -- but the guarantee now comes from
// the type rather than from an invariant each future caller has to know.
//
// The fields below are all silently wrong rather than loudly wrong: nftables
// accepts a rule with the wrong offset, mask or family, the install reports
// success, and the only symptom is that the RST this exists to suppress is not
// suppressed.
func rstDropExprs(addr netip.Addr) []expr.Any {
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
	return []expr.Any{
		// meta nfproto ipv4/ipv6
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{family},
		},
		// ip/ip6 saddr == addr
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       saddrOffset,
			Len:          addrLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addrBytes,
		},
		// ct state invalid -- no conntrack entry yet at OUTPUT
		// (#14949 scoping, corrected by #15727). Linux
		// nft_ct_get_eval (net/netfilter/nft_ct.c, NFT_CT_STATE)
		// never writes 0: it writes NF_CT_STATE_BIT(ctinfo) for a
		// tracked packet, NF_CT_STATE_UNTRACKED_BIT (0x40) when
		// ctinfo is IP_CT_UNTRACKED, and NF_CT_STATE_INVALID_BIT
		// (0x01) otherwise. The pre-#15727 predicate
		// `state & 0x4f == 0` was therefore unsatisfiable and the
		// rule never fired.
		//
		// INVALID alone does not prove the packet is socket-less
		// (#16839): this chain runs at raw priority (-300), BEFORE
		// the OUTPUT conntrack hook (-200), so a live local
		// socket's abortive RST (tcp_send_active_reset ->
		// ip_local_out, skb->sk set, no nfct attached yet) also
		// reads INVALID here and only becomes ESTABLISHED after
		// conntrack. The premise in the pre-#16839 comment -- "a
		// local socket's RST carries its socket conntrack entry
		// (attached before OUTPUT)" -- is false at raw priority;
		// it was measured live (witness counters, kernel 7.2.8):
		// a server-abort RST sourced from the protected address
		// counted as ct-invalid at raw and ct-established at
		// filter. The socket-wildcard predicate below is what
		// separates the two classes.
		//
		// UNTRACKED is deliberately not matched: it requires a
		// NOTRACK decision (ingress raw table) that the kernel's own
		// locally generated RST never carries, so it cannot occur on
		// this path. Widening to it would drop a class with no
		// evidence it occurs here.
		//
		// Residual: with the host default tcp_loose=1 a bare
		// non-RST segment may be picked up mid-stream on ingress;
		// it still cannot attach to the locally generated RST
		// (nf_reset_ct detaches it; a lone RST creates none), so
		// the INVALID signature holds. Recorded in docs/log/15727.md.
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
		// socket wildcard == 1 -- no live full socket owns this
		// packet (#16839). nft_socket_eval (net/netfilter/
		// nft_socket.c, NFT_SOCKET_WILDCARD) BREAKs (rule does not
		// match) when there is no socket at all or the socket is
		// not a full socket, and otherwise stores whether the
		// socket is bound to a wildcard address
		// (inet_rcv_saddr == 0 / ipv6_addr_any(rcv_saddr)). A live
		// local socket's RST reaches OUTPUT with skb->sk set to
		// that full socket, bound to the specific interface-NAT
		// address, so wildcard == 0 and the rule does not drop it
		// -- regardless of whether conntrack has attached an
		// entry yet. The spurious RST this table exists to
		// suppress is emitted by tcp_v4_send_reset /
		// tcp_v6_send_response via tcp_rst_sock, a per-cpu control
		// socket (a request/timewait-class mini-socket, not a
		// full socket) bound to the wildcard address, so
		// wildcard == 1. Measured live (kernel 7.2.8, witness
		// counters at raw OUTPUT): spurious RSTs counted
		// wildcard==1 3/3 and wildcard==0 0/3; a live server
		// socket's abortive RST sourced from the protected
		// address counted wildcard==0 1/1 and wildcard==1 0/1.
		//
		// Deliberate scope: a live socket bound to the wildcard
		// address (0.0.0.0 / ::) whose source is rewritten to the
		// protected address only by a later NAT hook would read
		// wildcard == 1 here; at raw priority no such rewrite has
		// happened, its on-wire source is not the protected
		// address yet, and the saddr predicate above has already
		// excluded it. Sockets bound to the protected address
		// itself -- the #16839 cell -- read wildcard == 0.
		&expr.Socket{Key: expr.SocketKeyWildcard, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{1},
		},
		// meta l4proto tcp
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		// tcp flags & RST != 0
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13, // TCP flags byte
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x04}, // RST flag
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0x00},
		},
		// counter
		&expr.Counter{},
		// drop
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

func ptrPolicy(p nftables.ChainPolicy) *nftables.ChainPolicy {
	return &p
}
