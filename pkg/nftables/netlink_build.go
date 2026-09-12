package nftables

// netlink_build.go is the low-level, security-critical rendering layer of the
// #6387 PR-2 netlink host-inbound / lo0 / fence installer. It lowers the
// construct-by-construct nft-text -> netlink expr mapping from
// docs/pr/6387-hostinbound-netlink/plan.md §5.1 into google/nftables
// expressions, mirroring what the exec-`nft` payload builders in
// pkg/daemon/daemon_nft.go (the parity ORACLE) emit for the SAME rule.
//
// Register discipline: every match loads into register 1 and compares register
// 1, exactly like nft's own compilation.
//
// Dependency dedup: nft attaches an implicit `meta nfproto <fam>` ahead of a
// family-specific payload (`ip`/`ip6`/`icmp`/`icmpv6`/`ip dscp`/`ip frag-off`/
// `exthdr`) and an implicit `meta l4proto <proto>` ahead of a transport match
// (`tcp`/`udp`/`icmp`/`icmpv6`/`tcp flags`), but only ONCE per rule — a second
// predicate needing the same dependency does not re-emit the guard. The ruleAsm
// accumulator below tracks the established nfproto/l4proto so the netlink build
// dedups exactly as nft does, which is what keeps a combined rule
// (`ip daddr X icmp type Y`) bit-equivalent to the oracle text.

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// nftObjTypeCounter is NFT_OBJECT_COUNTER, the object type an expr.Objref must
// carry to reference a named `counter` object (plan §5.1 "counter name" row).
const nftObjTypeCounter = 1

// nlFamily captures the per-family constants a network-header match needs.
type nlFamily struct {
	v6       bool
	nfproto  byte
	saddrOff uint32
	daddrOff uint32
	addrLen  uint32
	setKey   nftables.SetDatatype
}

var (
	famV4 = nlFamily{v6: false, nfproto: unix.NFPROTO_IPV4, saddrOff: 12, daddrOff: 16, addrLen: 4, setKey: nftables.TypeIPAddr}
	famV6 = nlFamily{v6: true, nfproto: unix.NFPROTO_IPV6, saddrOff: 8, daddrOff: 24, addrLen: 16, setKey: nftables.TypeIP6Addr}
)

func famFor(family string) nlFamily {
	if family == "ip6" {
		return famV6
	}
	return famV4
}

// nlPort is a normalized transport-port match value: a single port when lo==hi,
// a contiguous range otherwise.
type nlPort struct {
	lo uint16
	hi uint16
}

func (p nlPort) isRange() bool { return p.lo != p.hi }

// nlPlan accumulates one nft table's worth of netlink operations against a
// single *nftables.Conn batch. It carries the sticky first error from any
// set-allocation helper so rule assembly stays linear.
type nlPlan struct {
	c     *nftables.Conn
	table *nftables.Table
	chain *nftables.Chain
	err   error

	// rules records every emitted rule's expr list (in order) so the pure-unit
	// golden (T1b) and mutation-sensitivity tests can inspect the build without a
	// live kernel. It is populated alongside the AddRule batch call.
	rules [][]expr.Any
	// counters records every declared counter-object name (in order) for the
	// counter-declaration parity check.
	counters []string
	// sets records each anonymous set's elements by allocated set ID, so the
	// canonical rule dump (T1b golden / mutation tests) can render set CONTENTS
	// inline — otherwise a widened lookup set (a fail-open) would be invisible in
	// the expr stream (the Lookup expr is identical; only the elements differ).
	sets map[uint32][]nftables.SetElement
}

func (p *nlPlan) fail(err error) {
	if p.err == nil {
		p.err = err
	}
}

// counterObj declares a named counter object in the table body (plan §5.1
// "counter <name> {} declaration" row). It must precede any objref reference.
func (p *nlPlan) counterObj(name string) {
	if p.err != nil {
		return
	}
	p.counters = append(p.counters, name)
	p.c.AddObj(&nftables.CounterObj{Table: p.table, Name: name})
}

// rule starts a new rule assembler bound to this plan's chain.
func (p *nlPlan) rule() *ruleAsm { return &ruleAsm{p: p} }

// regularChain declares a regular (non-base) chain in the plan's table: no hook,
// reachable only by a jump (#9504).
func (p *nlPlan) regularChain(name string) *nftables.Chain {
	if p.err != nil {
		return nil
	}
	return p.c.AddChain(&nftables.Chain{Name: name, Table: p.table})
}

// inChain emits the rules fn builds into ch rather than the plan's base chain.
func (p *nlPlan) inChain(ch *nftables.Chain, fn func()) {
	base := p.chain
	p.chain = ch
	defer func() { p.chain = base }()
	fn()
}

// ruleAsm accumulates one rule's []expr.Any, tracking the established nfproto /
// l4proto dependencies for nft-faithful guard dedup.
type ruleAsm struct {
	p     *nlPlan
	exprs []expr.Any
	nfSet bool
	nfVal byte
	l4Set bool
	l4Val uint8
}

func (a *ruleAsm) add(e ...expr.Any) *ruleAsm { a.exprs = append(a.exprs, e...); return a }

// needNfproto emits `meta nfproto <fam>` unless the SAME family is already
// established this rule (nft dedups an identical dependency, but emits a fresh
// guard for a different value).
func (a *ruleAsm) needNfproto(f nlFamily) {
	if a.nfSet && a.nfVal == f.nfproto {
		return
	}
	a.nfSet = true
	a.nfVal = f.nfproto
	a.add(nfprotoGuard(f)...)
}

// needL4proto emits `meta l4proto <proto>` unless the SAME proto is already
// established this rule.
func (a *ruleAsm) needL4proto(proto uint8) {
	if a.l4Set && a.l4Val == proto {
		return
	}
	a.l4Set = true
	a.l4Val = proto
	a.add(l4protoGuard(proto)...)
}

// emit finalizes the rule with its trailing verdict/reject exprs.
func (a *ruleAsm) emit(tail ...expr.Any) {
	if a.p.err != nil {
		return
	}
	a.add(tail...)
	a.p.rules = append(a.p.rules, a.exprs)
	a.p.c.AddRule(&nftables.Rule{Table: a.p.table, Chain: a.p.chain, Exprs: a.exprs})
}

// --- high-level ruleAsm match composition -----------------------------------

// daddr / saddr append a family-scoped network-address match with its nfproto
// dependency (plan §5.1 daddr / saddr rows).
func (a *ruleAsm) daddr(f nlFamily, addrs []string, except bool) *ruleAsm {
	m := a.p.pfxAddrMatch("daddr", f, addrs, except)
	if len(m) == 0 {
		return a
	}
	a.needNfproto(f)
	return a.add(m...)
}

func (a *ruleAsm) saddr(f nlFamily, addrs []string, except bool) *ruleAsm {
	m := a.p.pfxAddrMatch("saddr", f, addrs, except)
	if len(m) == 0 {
		return a
	}
	a.needNfproto(f)
	return a.add(m...)
}

// l4protoSet appends `meta l4proto <n>` / `meta l4proto { .. }`. A single value
// establishes the l4proto dependency (so a later transport match dedups against
// it); a multi-value set does not (nft keeps it independent).
func (a *ruleAsm) l4protoSet(protos []uint8) *ruleAsm {
	if len(protos) == 0 {
		return a
	}
	if len(protos) == 1 {
		a.needL4proto(protos[0])
		return a
	}
	m := a.p.l4protoSetMatch(protos)
	return a.add(m...)
}

// tcpDport / udpDport / tcpSport / udpSport append a guarded transport-port
// match (plan §5.1 tcp/udp dport rows).
func (a *ruleAsm) l4Port(proto uint8, dir string, ports []nlPort, except bool) *ruleAsm {
	off := uint32(2)
	if dir == "sport" {
		off = 0
	}
	m := a.p.portMatch(off, ports, except)
	if len(m) == 0 {
		return a
	}
	a.needL4proto(proto)
	return a.add(m...)
}

// thPort appends a transport-agnostic `th sport|dport [!=] <spec>` match (lo0,
// no l4proto guard — plan §5.1 "th sport/dport" row).
func (a *ruleAsm) thPort(dir string, ports []nlPort, except bool) *ruleAsm {
	off := uint32(2)
	if dir == "sport" {
		off = 0
	}
	m := a.p.portMatch(off, ports, except)
	return a.add(m...)
}

// icmpType appends `icmp|icmpv6 type <spec>` with its nfproto + l4proto deps.
func (a *ruleAsm) icmpType(f nlFamily, vals []uint8) *ruleAsm {
	m := a.p.icmpByteMatch(0, vals, icmpTypeSetKey(f))
	if len(m) == 0 {
		return a
	}
	a.needNfproto(f)
	a.needL4proto(icmpProto(f))
	return a.add(m...)
}

// icmpCode appends `icmp|icmpv6 code <spec>` with its nfproto + l4proto deps
// (deduped against a preceding type match in the same rule).
func (a *ruleAsm) icmpCode(f nlFamily, vals []uint8) *ruleAsm {
	m := a.p.icmpByteMatch(1, vals, icmpCodeSetKey(f))
	if len(m) == 0 {
		return a
	}
	a.needNfproto(f)
	a.needL4proto(icmpProto(f))
	return a.add(m...)
}

// dscp appends `ip|ip6 dscp <spec>` with its nfproto dep (plan §5.1 dscp rows).
func (a *ruleAsm) dscp(f nlFamily, vals []uint8) *ruleAsm {
	m := a.p.dscpMatch(f, vals)
	if len(m) == 0 {
		return a
	}
	a.needNfproto(f)
	return a.add(m...)
}

// tcpFlags appends `tcp flags & (mask) == req` with its l4proto(6) dep.
func (a *ruleAsm) tcpFlags(required, forbidden uint8) *ruleAsm {
	a.needL4proto(unix.IPPROTO_TCP)
	return a.add(tcpFlagsMatch(required, forbidden)...)
}

// fragV4 appends `ip frag-off & 0x1fff != 0` with its nfproto(ipv4) dep.
func (a *ruleAsm) fragV4() *ruleAsm {
	a.needNfproto(famV4)
	return a.add(fragV4Match()...)
}

// flexMatch appends a `flexible-match-range` predicate (#6804): load BitLength
// bits at ByteOffset from the LAYER-3 header, mask, and compare.
//
// No nfproto/l4proto dep is added, deliberately. `layer-3` means "from the start
// of the network header", which is well-defined in both families, and adding an
// nfproto dep would narrow the term to one family — silently dropping the
// predicate's effect in the other pass, which is the widening this exists to
// prevent.
func (a *ruleAsm) flexMatch(fm Lo0FlexMatch) *ruleAsm {
	return a.add(flexMatchExprs(fm)...)
}

// exthdrFragV6 appends `exthdr frag exists` with its nfproto(ipv6) dep.
func (a *ruleAsm) exthdrFragV6() *ruleAsm {
	a.needNfproto(famV6)
	return a.add(exthdrFragV6Match()...)
}

// iifname appends `iifname "<n>"` / `iifname { .. }` (no nfproto/l4proto dep).
func (a *ruleAsm) iifname(names []string) *ruleAsm {
	return a.add(a.p.iifnameMatch(names)...)
}

// ct appends a conntrack state / direction predicate (no deps).
func (a *ruleAsm) ctEstablishedRelated() *ruleAsm { return a.add(ctEstablishedRelated()...) }
func (a *ruleAsm) ctDirectionReply() *ruleAsm     { return a.add(ctDirectionReply()...) }

// logPrefix appends `log prefix "<prefix>"` (non-terminating modifier).
func (a *ruleAsm) logPrefix(prefix string) *ruleAsm { return a.add(logPrefix(prefix)...) }

// counterRef appends `counter name "<n>"` (objref; object declared separately).
func (a *ruleAsm) counterRef(name string) *ruleAsm { return a.add(counterRef(name)...) }

// --- low-level dep-free fragments -------------------------------------------

func nfprotoGuard(f nlFamily) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{f.nfproto}},
	}
}

func l4protoGuard(proto uint8) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func ctEstablishedRelated() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

func ctDirectionReply() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x01}},
	}
}

// l4protoSetMatch renders `meta l4proto { a, b }` (multi-value; single-value is
// handled by ruleAsm.needL4proto).
func (p *nlPlan) l4protoSetMatch(protos []uint8) []expr.Any {
	els := make([]nftables.SetElement, len(protos))
	for i, pr := range protos {
		els[i] = nftables.SetElement{Key: []byte{pr}}
	}
	set := p.addAnonSet(nftables.TypeInetProto, false, els)
	if set == nil {
		return nil
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
	}
}

// pfxAddrMatch renders the network-address payload+comparison for
// `<fam> <field> [!=] <spec>` WITHOUT the nfproto guard (ruleAsm adds it):
//
//   - 1 host / full-length prefix -> Payload + Cmp
//   - 1 non-full prefix           -> Payload + Bitwise(mask) + Cmp(network)
//   - many, all hosts             -> exact anonymous set + Lookup
//   - many, any prefix present    -> interval anonymous set + Lookup
func (p *nlPlan) pfxAddrMatch(field string, f nlFamily, addrs []string, except bool) []expr.Any {
	off := f.daddrOff
	if field == "saddr" {
		off = f.saddrOff
	}
	pfxs := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if pfx, err := netip.ParsePrefix(a); err == nil {
			pfxs = append(pfxs, pfx.Masked())
			continue
		}
		if ip, err := netip.ParseAddr(a); err == nil {
			pfxs = append(pfxs, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
	}
	if len(pfxs) == 0 {
		return nil
	}
	load := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: f.addrLen}
	op := expr.CmpOpEq
	if except {
		op = expr.CmpOpNeq
	}
	if len(pfxs) == 1 {
		pfx := pfxs[0]
		if pfx.Bits() == int(f.addrLen)*8 {
			return []expr.Any{load, &expr.Cmp{Op: op, Register: 1, Data: addrBytes(pfx.Addr(), f)}}
		}
		return []expr.Any{
			load,
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: f.addrLen, Mask: prefixMask(pfx.Bits(), f.addrLen), Xor: zeroBytes(f.addrLen)},
			&expr.Cmp{Op: op, Register: 1, Data: addrBytes(pfx.Addr(), f)},
		}
	}
	interval := false
	for _, pfx := range pfxs {
		if pfx.Bits() != int(f.addrLen)*8 {
			interval = true
			break
		}
	}
	var els []nftables.SetElement
	if interval {
		for _, pfx := range pfxs {
			els = append(els, nftables.SetElement{Key: addrBytes(pfx.Addr(), f)})
			// #8597: a prefix reaching the top of the key space has no
			// "first address not covered", so it gets NO end element and the
			// interval runs open to the end of the range. Emitting a wrapped
			// end put the marker at the BOTTOM of the key space instead — see
			// prefixNext for the two encodings that produced, and what the
			// kernel stored for each.
			if end, ok := prefixNext(pfx); ok {
				els = append(els, nftables.SetElement{Key: addrBytes(end, f), IntervalEnd: true})
			}
		}
	} else {
		for _, pfx := range pfxs {
			els = append(els, nftables.SetElement{Key: addrBytes(pfx.Addr(), f)})
		}
	}
	set := p.addAnonSet(f.setKey, interval, els)
	if set == nil {
		return nil
	}
	return []expr.Any{load, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID, Invert: except}}
}

// portMatch renders the transport-header port comparison at the given offset
// (0=sport, 2=dport) WITHOUT any l4proto guard (ruleAsm adds it for tcp/udp;
// `th` omits it): scalar -> Cmp; range -> Range; multiple -> anonymous set.
func (p *nlPlan) portMatch(off uint32, ports []nlPort, except bool) []expr.Any {
	if len(ports) == 0 {
		return nil
	}
	load := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: off, Len: 2}
	op := expr.CmpOpEq
	if except {
		op = expr.CmpOpNeq
	}
	if len(ports) == 1 {
		pt := ports[0]
		if !pt.isRange() {
			return []expr.Any{load, &expr.Cmp{Op: op, Register: 1, Data: binaryutil.BigEndian.PutUint16(pt.lo)}}
		}
		return []expr.Any{load, &expr.Range{
			Op:       op,
			Register: 1,
			FromData: binaryutil.BigEndian.PutUint16(pt.lo),
			ToData:   binaryutil.BigEndian.PutUint16(pt.hi),
		}}
	}
	interval := false
	for _, pt := range ports {
		if pt.isRange() {
			interval = true
			break
		}
	}
	var els []nftables.SetElement
	if interval {
		for _, pt := range ports {
			els = append(els, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(pt.lo)})
			// #9005, the port twin of #8597: a range reaching the top of the
			// key space has no "first port not covered", so it gets NO end
			// element and the interval runs open to the end of the range.
			// Emitting the wrapped end put the marker at the BOTTOM of the key
			// space (`0000!end`) instead — the same encoding #8597 measured and
			// rejected for addresses, on the same kernel representation.
			if end, ok := portNext(pt.hi); ok {
				els = append(els, nftables.SetElement{Key: end, IntervalEnd: true})
			}
		}
	} else {
		for _, pt := range ports {
			els = append(els, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(pt.lo)})
		}
	}
	set := p.addAnonSet(nftables.TypeInetService, interval, els)
	if set == nil {
		return nil
	}
	return []expr.Any{load, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID, Invert: except}}
}

// icmpByteMatch renders a single-byte transport-header comparison (ICMP type at
// offset 0, code at offset 1) WITHOUT guards (ruleAsm adds nfproto+l4proto). The
// anonymous set uses the 1-byte icmp_type/icmp_code datatype (matching nft), so
// the lookup register width (1 byte) equals the set key width — a 2-byte key
// (inet_service) here is a hard kernel EINVAL.
func (p *nlPlan) icmpByteMatch(off uint32, vals []uint8, setKey nftables.SetDatatype) []expr.Any {
	if len(vals) == 0 {
		return nil
	}
	load := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: off, Len: 1}
	if len(vals) == 1 {
		return []expr.Any{load, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{vals[0]}}}
	}
	els := make([]nftables.SetElement, len(vals))
	for i, v := range vals {
		els[i] = nftables.SetElement{Key: []byte{v}}
	}
	set := p.addAnonSet(setKey, false, els)
	if set == nil {
		return nil
	}
	return []expr.Any{load, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}}
}

func icmpProto(f nlFamily) uint8 {
	if f.v6 {
		return unix.IPPROTO_ICMPV6
	}
	return unix.IPPROTO_ICMP
}

func icmpTypeSetKey(f nlFamily) nftables.SetDatatype {
	if f.v6 {
		return nftables.TypeICMP6Type
	}
	return nftables.TypeICMPType
}

func icmpCodeSetKey(f nlFamily) nftables.SetDatatype {
	if f.v6 {
		return nftables.TypeICMPV6Code
	}
	return nftables.TypeICMPCode
}

// dscpMatch renders the DSCP payload+bitwise+comparison WITHOUT the nfproto
// guard (ruleAsm adds it). See the plan §12.3 IPv6 correction encoded below.
func (p *nlPlan) dscpMatch(f nlFamily, vals []uint8) []expr.Any {
	if len(vals) == 0 {
		return nil
	}
	if f.v6 {
		load := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 0, Len: 2}
		bw := &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2, Mask: []byte{0x0f, 0xc0}, Xor: []byte{0x00, 0x00}}
		return append([]expr.Any{load, bw}, p.dscpCompare(vals, dscpV6Bytes, nftables.TypeInetService)...)
	}
	load := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 1, Len: 1}
	bw := &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0xfc}, Xor: []byte{0x00}}
	return append([]expr.Any{load, bw}, p.dscpCompare(vals, dscpV4Bytes, nftables.TypeInetProto)...)
}

func (p *nlPlan) dscpCompare(vals []uint8, enc func(uint8) []byte, setKey nftables.SetDatatype) []expr.Any {
	if len(vals) == 1 {
		return []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: enc(vals[0])}}
	}
	els := make([]nftables.SetElement, len(vals))
	for i, v := range vals {
		els[i] = nftables.SetElement{Key: enc(v)}
	}
	set := p.addAnonSet(setKey, false, els)
	if set == nil {
		return nil
	}
	return []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}}
}

func dscpV4Bytes(v uint8) []byte { return []byte{v << 2} }

func dscpV6Bytes(v uint8) []byte { return []byte{(v >> 2) & 0x0f, (v & 0x03) << 6} }

func tcpFlagsMatch(required, forbidden uint8) []expr.Any {
	mask := required | forbidden
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{mask}, Xor: []byte{0x00}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{required}},
	}
}

func fragV4Match() []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 2, Mask: []byte{0x1f, 0xff}, Xor: []byte{0x00, 0x00}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x00}},
	}
}

// flexMatchByteLen is the payload load width for a bit length: ceil(bits/8),
// matching the userspace snapshot builder (pkg/dataplane/userspace/filters.go),
// which derives its own load width the same way. The compiler constrains
// BitLength to 1..32, so the result is 1..4.
// It mirrors the userspace snapshot builder EXACTLY, including its two edge
// rules (pkg/dataplane/userspace/filters.go): a zero bit-length defaults to 4
// (32-bit), and an oversized width is NOT capped to 4 — capping would compare
// only the truncated window and BROADEN the match, the #3406 fail-open. An
// oversized width is reported here as unrepresentable instead, which is the same
// direction userspace takes (it rejects the snapshot outright).
func flexMatchByteLen(bits uint8) uint32 {
	if bits == 0 {
		return 4
	}
	return uint32((uint16(bits) + 7) / 8)
}

// flexMatchRepresentable reports whether a resolved predicate can be rendered
// as an nft payload load. Only the width can fail: the commit gate bounds
// bit-length to 1..32, so a width outside 1..4 arrives only on a corrupt /
// version-drifted tolerant-load snapshot.
func flexMatchRepresentable(fm Lo0FlexMatch) bool {
	n := flexMatchByteLen(fm.BitLength)
	return n >= 1 && n <= 4
}

// flexMatchExprs renders `@nh,<off*8>,<bits> & mask == value` as
// payload + bitwise + cmp, the same three-expression shape fragV4Match uses.
//
// Value and Mask are emitted BIG-ENDIAN over the load width, because a payload
// load returns network-order bytes and the compiler stores both as host-order
// integers over that same width (config.FlexMatchConfig). Truncating from the
// low end of a big-endian encoding is what keeps a 1-byte match comparing the
// byte the operator wrote rather than the top byte of a 32-bit word.
func flexMatchExprs(fm Lo0FlexMatch) []expr.Any {
	n := flexMatchByteLen(fm.BitLength)
	if !flexMatchRepresentable(fm) {
		return nil
	}
	var val, mask [4]byte
	binary.BigEndian.PutUint32(val[:], fm.Value)
	binary.BigEndian.PutUint32(mask[:], fm.Mask)
	v := append([]byte(nil), val[4-n:]...)
	m := append([]byte(nil), mask[4-n:]...)
	// Apply the mask to the expected value too. nft's own `& mask == value`
	// lowering compares the MASKED load, so an operator value carrying bits
	// outside the mask would otherwise never match — a silent never-match is a
	// different fail direction from the widening this fixes, and just as quiet.
	for i := range v {
		v[i] &= m[i]
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: uint32(fm.ByteOffset), Len: n},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: n, Mask: m, Xor: make([]byte, n)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: v},
	}
}

func exthdrFragV6Match() []expr.Any {
	// `exthdr frag exists`: the presence load returns 1 when the fragment ext
	// header is present; nft's canonical form is `== 1` (rendered `exists`), NOT
	// `!= 0` (which nft renders `!= missing`).
	return []expr.Any{
		&expr.Exthdr{DestRegister: 1, Type: 44, Offset: 0, Len: 1, Op: expr.ExthdrOpIpv6, Flags: unix.NFT_EXTHDR_F_PRESENT},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x01}},
	}
}

func (p *nlPlan) iifnameMatch(names []string) []expr.Any {
	if len(names) == 0 {
		return nil
	}
	load := &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}
	if len(names) == 1 {
		return []expr.Any{load, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname16(names[0])}}
	}
	els := make([]nftables.SetElement, len(names))
	for i, n := range names {
		els[i] = nftables.SetElement{Key: ifname16(n)}
	}
	set := p.addAnonSet(nftables.TypeIFName, false, els)
	if set == nil {
		return nil
	}
	return []expr.Any{load, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}}
}

func ifname16(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

func logPrefix(prefix string) []expr.Any {
	return []expr.Any{&expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte(prefix)}}
}

func counterRef(name string) []expr.Any {
	return []expr.Any{&expr.Objref{Type: nftObjTypeCounter, Name: name}}
}

func verdictAccept() []expr.Any { return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}} }
func verdictDrop() []expr.Any   { return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}} }
func verdictReturn() []expr.Any { return []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}} }

func verdictJump(chain string) []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: chain}}
}

func rejectTCPReset() []expr.Any {
	return []expr.Any{&expr.Reject{Type: unix.NFT_REJECT_TCP_RST}}
}

func rejectICMPXAdminProhibited() []expr.Any {
	return []expr.Any{&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED}}
}

// --- set allocation ---------------------------------------------------------

func (p *nlPlan) addAnonSet(keyType nftables.SetDatatype, interval bool, elements []nftables.SetElement) *nftables.Set {
	if p.err != nil {
		return nil
	}
	set := &nftables.Set{
		Table:     p.table,
		Anonymous: true,
		Constant:  true,
		Interval:  interval,
		// AutoMerge lets the kernel merge overlapping/adjacent intervals (a lo0
		// filter set like { 10.0.0.0/8, 10.0.1.0/24 } has overlapping members),
		// mirroring nft's own anonymous-interval-set handling. Without it the
		// kernel rejects overlapping elements with EEXIST — a false fail-closed.
		AutoMerge: interval,
		KeyType:   keyType,
	}
	if err := p.c.AddSet(set, elements); err != nil {
		p.fail(fmt.Errorf("nftables add anonymous set: %w", err))
		return nil
	}
	if p.sets == nil {
		p.sets = map[uint32][]nftables.SetElement{}
	}
	p.sets[set.ID] = elements
	return set
}

// --- byte helpers -----------------------------------------------------------

func addrBytes(a netip.Addr, f nlFamily) []byte {
	if f.v6 {
		b := a.As16()
		return b[:]
	}
	b := a.As4()
	return b[:]
}

func zeroBytes(n uint32) []byte { return make([]byte, n) }

func prefixMask(bits int, addrLen uint32) []byte {
	mask := make([]byte, addrLen)
	for i := 0; i < int(addrLen); i++ {
		switch {
		case bits >= 8:
			mask[i] = 0xff
			bits -= 8
		case bits > 0:
			mask[i] = byte(0xff << (8 - bits))
			bits = 0
		default:
			mask[i] = 0
		}
	}
	return mask
}

// prefixNext returns the first address NOT covered by the prefix — the interval
// END for an anonymous interval set — and whether such an address EXISTS.
//
// #8597 (muse-004 K06): it does not exist for a prefix whose last address is
// the top of the key space (0.0.0.0/0, ::/0, 128.0.0.0/1, ...), and this used
// to fall back to the UNSPECIFIED address, which is the BOTTOM. Measured by
// installing the set and reading it back from the kernel:
//
//	{0.0.0.0/0, 10.0.0.0/8}
//	  -> 00000000 start, 00000000 END, 0a000000 start, 0b000000 END
//	     the /0 member is a ZERO-WIDTH interval: a term that must match
//	     everything matches nothing. Fail-CLOSED.
//
//	{128.0.0.0/1, 10.0.0.0/8}
//	  -> 00000000 END, 0a000000 start, 0b000000 END, 80000000 start
//	     the wrapped end sorts to the BOTTOM of the key space, an end marker
//	     with no start before it, while 128.0.0.0 is left open to the top.
//	     Fail-OPEN at the bottom.
//
// Two wrong encodings in opposite directions from one fallback. Returning
// ok=false lets the caller OMIT the end element, which is the representation
// for an interval that runs to the top of the range.
func prefixNext(pfx netip.Prefix) (netip.Addr, bool) {
	next := lastAddr(pfx).Next()
	if !next.IsValid() {
		return netip.Addr{}, false
	}
	return next, true
}

func lastAddr(pfx netip.Prefix) netip.Addr {
	a := pfx.Masked().Addr()
	if a.Is4() {
		v := a.As4()
		orLastBits(v[:], 32-pfx.Bits())
		return netip.AddrFrom4(v)
	}
	v := a.As16()
	orLastBits(v[:], 128-pfx.Bits())
	return netip.AddrFrom16(v)
}

// orLastBits sets the low `hostBits` bits of the big-endian byte slice to 1.
func orLastBits(b []byte, hostBits int) {
	for i := len(b) - 1; i >= 0 && hostBits > 0; i-- {
		if hostBits >= 8 {
			b[i] = 0xff
			hostBits -= 8
		} else {
			b[i] |= byte(0xff >> (8 - hostBits))
			hostBits = 0
		}
	}
}

// portNext returns the big-endian interval end for a port range upper bound —
// the first port NOT covered — and false when there is none because the range
// reaches the top of the key space (#9005).
//
// It replaces portEnd, which returned a WRAPPED 0x0000 for hi == 0xffff. That
// is not an end marker at the top; it is an end marker at the BOTTOM, and the
// kernel stores it as such. The address side reached the same conclusion in
// #8597 and its `prefixNext` has the identical shape and contract, which is why
// this returns (value, ok) rather than a sentinel: a caller cannot forget to
// check, and the two key types now answer the question the same way.
func portNext(hi uint16) ([]byte, bool) {
	if hi == 0xffff {
		return nil, false
	}
	return binaryutil.BigEndian.PutUint16(hi + 1), true
}
