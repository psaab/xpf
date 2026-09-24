package nftables

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// isTransitFenceWitnessMark identifies the one q0 mark conjunction whose
// counter is a product-owned downstream-of-TUN witness. q0 is shared with the
// transit MissingNeighbor adjudication path, so the counter remains a superset
// and is only a valid S5 witness during a quiesced S5 window.
func isTransitFenceWitnessMark(mark ForwardFenceMark) bool {
	return mark.Ifname == HostInboundDelegatedIfname &&
		mark.Mark == AdjudicatedTransitMark &&
		mark.Mask == AdjudicatedTransitMarkMask
}

func forwardFenceSpecHasWitness(spec ForwardFenceSpec) bool {
	for _, mark := range spec.AllowedMarks {
		if isTransitFenceWitnessMark(mark) {
			return true
		}
	}
	return false
}

func cloneForwardFenceSpec(spec ForwardFenceSpec) ForwardFenceSpec {
	return ForwardFenceSpec{
		AllowedIfnames: append([]string(nil), spec.AllowedIfnames...),
		AllowedMarks:   append([]ForwardFenceMark(nil), spec.AllowedMarks...),
	}
}

// forwardFenceSpecsEqual is deliberately order-sensitive. The armed resolver
// canonicalizes its inputs before handing them to the installer; an unexpected
// order change is therefore a live-shape doubt and must take the old replace
// path rather than silently skipping it.
func forwardFenceSpecsEqual(a, b ForwardFenceSpec) bool {
	if len(a.AllowedIfnames) != len(b.AllowedIfnames) || len(a.AllowedMarks) != len(b.AllowedMarks) {
		return false
	}
	for i := range a.AllowedIfnames {
		if a.AllowedIfnames[i] != b.AllowedIfnames[i] {
			return false
		}
	}
	for i := range a.AllowedMarks {
		if a.AllowedMarks[i] != b.AllowedMarks[i] {
			return false
		}
	}
	return true
}

type transitFenceRuleShape struct {
	ifnames []string
	mark    *ForwardFenceMark
	counter string
	// hasEther/ether is the #10641 bridge-leg ethertype conjunction. Inet and
	// marked shapes never carry it (hasEther=false).
	hasEther bool
	ether    uint16
}

type transitFenceLiveShape struct {
	chain   *gnft.Chain
	rules   []*gnft.Rule
	objects []gnft.Obj
	sets    map[string][]string
}

func desiredTransitFenceRuleShapes(spec ForwardFenceSpec, family gnft.TableFamily) []transitFenceRuleShape {
	out := make([]transitFenceRuleShape, 0, len(spec.AllowedIfnames)+len(spec.AllowedMarks))
	if len(spec.AllowedIfnames) > 0 {
		if family == gnft.TableFamilyBridge {
			// #10641: the desired bridge shape is three ether-qualified
			// rules in emission order, so a live table that lost the
			// qualification reads back UNEQUAL and takes the replace path.
			names := canonicalFenceNames(spec.AllowedIfnames)
			for _, ether := range bridgeTransitFenceEtherTypes {
				out = append(out, transitFenceRuleShape{ifnames: names, hasEther: true, ether: ether})
			}
		} else {
			out = append(out, transitFenceRuleShape{ifnames: canonicalFenceNames(spec.AllowedIfnames)})
		}
	}
	for _, mark := range spec.AllowedMarks {
		counter := ""
		if family == gnft.TableFamilyINet && isTransitFenceWitnessMark(mark) {
			counter = TransitFenceDeliveredCounterName
		}
		out = append(out, transitFenceRuleShape{
			ifnames: []string{mark.Ifname},
			mark:    &ForwardFenceMark{Ifname: mark.Ifname, Mark: mark.Mark, Mask: mark.Mask},
			counter: counter,
		})
	}
	return out
}

func canonicalFenceNames(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}

func (in *netlinkInstaller) readForwardFenceLiveEqual(spec ForwardFenceSpec) (bool, error) {
	conn, err := in.newConn()
	if err != nil {
		return false, fmt.Errorf("nftables fence read: %w", err)
	}
	for _, family := range transitBarrierFamilies() {
		tables, err := conn.ListTablesOfFamily(family)
		if err != nil {
			if family == gnft.TableFamilyBridge && in.forwardFenceBridgeUnsupported && transitBarrierFamilyUnsupported(err) {
				continue
			}
			return false, fmt.Errorf("nftables list fence tables %s: %w", familyName(family), err)
		}
		var table *gnft.Table
		for _, candidate := range tables {
			if candidate != nil && candidate.Name == TransitBarrierTableName {
				table = candidate
				break
			}
		}
		if table == nil {
			return false, nil
		}
		chain, err := conn.ListChain(table, "forward")
		if err != nil {
			return false, fmt.Errorf("nftables read fence chain %s: %w", familyName(family), err)
		}
		rules, err := conn.GetRules(table, chain)
		if err != nil {
			return false, fmt.Errorf("nftables read fence rules %s: %w", familyName(family), err)
		}
		objects, err := conn.GetObjects(table)
		if err != nil {
			return false, fmt.Errorf("nftables read fence objects %s: %w", familyName(family), err)
		}
		sets, err := conn.GetSets(table)
		if err != nil {
			return false, fmt.Errorf("nftables read fence sets %s: %w", familyName(family), err)
		}
		setValues := make(map[string][]string, len(sets))
		for _, set := range sets {
			if set == nil {
				return false, errors.New("nftables read fence: nil set")
			}
			elements, err := conn.GetSetElements(set)
			if err != nil {
				return false, fmt.Errorf("nftables read fence set %q: %w", set.Name, err)
			}
			values := make([]string, 0, len(elements))
			for _, element := range elements {
				if len(element.KeyEnd) != 0 || element.IntervalEnd || element.Val != nil || element.VerdictData != nil {
					return false, fmt.Errorf("nftables read fence set %q has unsupported element shape", set.Name)
				}
				values = append(values, string(bytes.TrimRight(element.Key, "\x00")))
			}
			setValues[set.Name] = canonicalFenceNames(values)
		}
		if !forwardFenceLiveShapeEqual(spec, family, transitFenceLiveShape{
			chain: chain, rules: rules, objects: objects, sets: setValues,
		}) {
			return false, nil
		}
	}
	return true, nil
}

func forwardFenceLiveShapeEqual(spec ForwardFenceSpec, family gnft.TableFamily, live transitFenceLiveShape) bool {
	if live.chain == nil || live.chain.Name != "forward" || live.chain.Hooknum == nil ||
		live.chain.Priority == nil || live.chain.Policy == nil ||
		*live.chain.Hooknum != *gnft.ChainHookForward ||
		*live.chain.Priority != *gnft.ChainPriorityFilter ||
		live.chain.Type != gnft.ChainTypeFilter || *live.chain.Policy != gnft.ChainPolicyDrop {
		return false
	}
	want := desiredTransitFenceRuleShapes(spec, family)
	if len(live.rules) != len(want) {
		return false
	}
	usedSets := make(map[string]struct{})
	for i, rule := range live.rules {
		got, setName, ok := decodeTransitFenceRule(rule, live.sets)
		if !ok || !transitFenceRuleShapeEqual(got, want[i]) {
			return false
		}
		if setName != "" {
			usedSets[setName] = struct{}{}
		}
	}
	// The set check is reference-closure, not cardinality. The bridge leg
	// allocates one anonymous iifname set per ether rule (#10641), but
	// pre-flush anonymous sets share the literal "__set%d" name the kernel
	// substitutes on install, so a synthetic live shape may collapse them to
	// one map entry while the kernel reads back three. Both are the same
	// policy: every rule's set VALUES are verified against the desired names
	// by the decoder above, so it suffices that every live set is referenced
	// (no junk) and every referenced set exists with the right values (a gap
	// already failed the decode).
	for name := range live.sets {
		if _, ok := usedSets[name]; !ok {
			return false
		}
	}
	wantCounter := ""
	if family == gnft.TableFamilyINet && forwardFenceSpecHasWitness(spec) {
		wantCounter = TransitFenceDeliveredCounterName
	}
	seenCounter := ""
	for _, object := range live.objects {
		counter, ok := object.(*gnft.CounterObj)
		if !ok || counter.Name != wantCounter || seenCounter != "" {
			return false
		}
		seenCounter = counter.Name
	}
	if seenCounter != wantCounter {
		return false
	}
	return true
}

func transitFenceRuleShapeEqual(a, b transitFenceRuleShape) bool {
	if len(a.ifnames) != len(b.ifnames) || a.counter != b.counter ||
		a.hasEther != b.hasEther || (a.hasEther && a.ether != b.ether) {
		return false
	}
	for i := range a.ifnames {
		if a.ifnames[i] != b.ifnames[i] {
			return false
		}
	}
	if (a.mark == nil) != (b.mark == nil) {
		return false
	}
	return a.mark == nil || *a.mark == *b.mark
}

func decodeTransitFenceRule(rule *gnft.Rule, sets map[string][]string) (transitFenceRuleShape, string, bool) {
	if rule == nil || len(rule.Exprs) < 3 {
		return transitFenceRuleShape{}, "", false
	}
	var out transitFenceRuleShape
	idx := 0
	meta, ok := rule.Exprs[idx].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyIIFNAME || meta.SourceRegister || meta.Register == 0 {
		return transitFenceRuleShape{}, "", false
	}
	reg := meta.Register
	idx++
	if idx >= len(rule.Exprs) {
		return transitFenceRuleShape{}, "", false
	}
	switch match := rule.Exprs[idx].(type) {
	case *expr.Cmp:
		if match.Op != expr.CmpOpEq || match.Register != reg {
			return transitFenceRuleShape{}, "", false
		}
		out.ifnames = []string{string(bytes.TrimRight(match.Data, "\x00"))}
	case *expr.Lookup:
		if match.SourceRegister != reg {
			return transitFenceRuleShape{}, "", false
		}
		values, exists := sets[match.SetName]
		if !exists || len(values) == 0 {
			return transitFenceRuleShape{}, "", false
		}
		out.ifnames = canonicalFenceNames(values)
		idx++
		goto afterIfname
	default:
		return transitFenceRuleShape{}, "", false
	}
	idx++

afterIfname:
	if len(out.ifnames) == 0 || len(out.ifnames) > 1 && !sort.StringsAreSorted(out.ifnames) {
		return transitFenceRuleShape{}, "", false
	}
	setName := ""
	if lookup, ok := rule.Exprs[1].(*expr.Lookup); ok {
		setName = lookup.SetName
	}
	// #10641: the bridge-leg unmarked pinhole carries an ethertype
	// conjunction (LL payload load @12/2 + equality) between the ingress
	// match and the verdict. Fence rules contain no other payload expr, so a
	// Payload here is always that load: any other base/offset/len/register
	// is an unknown shape and fails the comparison toward reinstall. The
	// value is wire-order (BigEndian); the mark path below stays NativeEndian
	// (host-order skb mark, #10410 P0).
	if pay, ok := rule.Exprs[idx].(*expr.Payload); ok {
		if pay.Base != expr.PayloadBaseLLHeader || pay.Offset != 12 || pay.Len != 2 ||
			pay.DestRegister != 1 || idx+2 > len(rule.Exprs)-1 {
			return transitFenceRuleShape{}, "", false
		}
		ecmp, ok := rule.Exprs[idx+1].(*expr.Cmp)
		if !ok || ecmp.Op != expr.CmpOpEq || ecmp.Register != 1 || len(ecmp.Data) != 2 {
			return transitFenceRuleShape{}, "", false
		}
		out.hasEther = true
		out.ether = binaryutil.BigEndian.Uint16(ecmp.Data)
		idx += 2
	}
	if idx < len(rule.Exprs)-1 {
		markMeta, ok := rule.Exprs[idx].(*expr.Meta)
		if !ok || markMeta.Key != expr.MetaKeyMARK || markMeta.SourceRegister || markMeta.Register == 0 {
			return transitFenceRuleShape{}, "", false
		}
		markReg := markMeta.Register
		idx++
		if idx >= len(rule.Exprs) {
			return transitFenceRuleShape{}, "", false
		}
		bitwise, ok := rule.Exprs[idx].(*expr.Bitwise)
		if !ok || bitwise.SourceRegister != markReg || bitwise.DestRegister != markReg || bitwise.Len != 4 || len(bitwise.Mask) != 4 || len(bitwise.Xor) != 4 || !bytes.Equal(bitwise.Xor, []byte{0, 0, 0, 0}) {
			return transitFenceRuleShape{}, "", false
		}
		idx++
		if idx >= len(rule.Exprs) {
			return transitFenceRuleShape{}, "", false
		}
		cmp, ok := rule.Exprs[idx].(*expr.Cmp)
		if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != markReg || len(cmp.Data) != 4 {
			return transitFenceRuleShape{}, "", false
		}
		idx++
		var mark ForwardFenceMark
		mark.Ifname = out.ifnames[0]
		mark.Mark = binaryutil.NativeEndian.Uint32(cmp.Data)
		mark.Mask = binaryutil.NativeEndian.Uint32(bitwise.Mask)
		out.mark = &mark
		if idx < len(rule.Exprs)-1 {
			obj, ok := rule.Exprs[idx].(*expr.Objref)
			if !ok || obj.Type != nftObjTypeCounter {
				return transitFenceRuleShape{}, "", false
			}
			out.counter = obj.Name
			idx++
		}
	}
	// #10641: the ether conjunction above can consume the trailing exprs of
	// a truncated live rule; without this guard the verdict read indexes
	// past the end. (The pre-existing marked path shares the exposure for a
	// verdict-less live rule; this closes both.)
	if idx >= len(rule.Exprs) {
		return transitFenceRuleShape{}, "", false
	}
	verdict, ok := rule.Exprs[idx].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictAccept || idx != len(rule.Exprs)-1 {
		return transitFenceRuleShape{}, "", false
	}
	return out, setName, true
}
