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
// reports as ct state invalid at OUTPUT -- its no-conntrack-entry
// signature (see rstDropExprs, #14949 as corrected by #15727). These
// addresses are owned by the userspace dataplane; the kernel has no
// sockets for them and should never emit RSTs for the flows the
// dataplane owns. Conntrack-tracked RSTs from the same addresses --
// nft reject-with-tcp-reset (policy reject / ident-reset) and local
// control-plane socket RSTs -- are legitimate and must survive.
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
	// matches. Legitimate tracked RSTs keep their tracked bit at raw
	// too: a local socket's RST carries its socket conntrack entry
	// (attached before OUTPUT), and a reject-synthesized RST is
	// emitted from the ingress hook itself, never reaches OUTPUT as
	// a fresh socket-less packet, and in any case is not emitted
	// from an interface-NAT source address owned by the dataplane.
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

// addRSTDropRule adds: meta nfproto <family> ip/ip6 saddr <addr> ct state invalid tcp flags & rst != 0 counter drop
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
		// ct state invalid -- no conntrack entry at OUTPUT (#14949
		// scoping, corrected by #15727). Linux nft_ct_get_eval
		// (net/netfilter/nft_ct.c, NFT_CT_STATE) never writes 0: it
		// writes NF_CT_STATE_BIT(ctinfo) for a tracked packet,
		// NF_CT_STATE_UNTRACKED_BIT (0x40) when ctinfo is
		// IP_CT_UNTRACKED, and NF_CT_STATE_INVALID_BIT (0x01)
		// otherwise. The pre-#15727 predicate `state & 0x4f == 0`
		// was therefore unsatisfiable and the rule never fired.
		//
		// INVALID is the only conntrack-less signature a locally
		// generated RST presents at OUTPUT: tcp_v4_send_reset emits
		// it via a fresh control socket with no nfct attached (any
		// ingress-created entry is detached by nf_reset_ct), and
		// the OUTPUT conntrack hook creates no entry for it -- with
		// nf_conntrack_tcp_loose=0 tcp_new rejects a non-SYN, and a
		// lone RST in TCP_CONNTRACK_NONE maps to TCP_CONNTRACK_MAX
		// so the hook drops the entry and reports invalid. Every
		// legitimate RST from these addresses carries a confirmed
		// entry and reports its tracked ctinfo bit instead: an nft
		// reject-with-tcp-reset creates the entry before its
		// synthesized RST traverses OUTPUT, and a local socket RST
		// belongs to a tracked connection. Matching INVALID alone
		// therefore drops the spurious RSTs and lets both legitimate
		// classes through.
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
