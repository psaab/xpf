package nftables

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// SO_RCVBUF and SO_SNDBUF values are doubled by Linux. Requesting 2 MiB gives
// each socket a bounded 4 MiB effective buffer, matching the maximum reported
// on the affected hosts without changing namespace or host-wide sysctls.
const netlinkSocketBufferRequest = 2 << 20
const netlinkSocketBufferEffective = 4 << 20

func newBoundedNetlinkConn() (*nftables.Conn, error) {
	return nftables.New(nftables.WithSockOptions(configureNetlinkSocket))
}

func configureNetlinkSocket(conn *netlink.Conn) error {
	if err := conn.SetReadBuffer(netlinkSocketBufferRequest); err != nil {
		return fmt.Errorf("set nftables netlink receive buffer: %w", err)
	}
	if err := conn.SetWriteBuffer(netlinkSocketBufferRequest); err != nil {
		return fmt.Errorf("set nftables netlink send buffer: %w", err)
	}
	readBuffer, writeBuffer, err := netlinkSocketBuffers(conn)
	if err != nil {
		return fmt.Errorf("read nftables netlink socket buffers: %w", err)
	}
	if readBuffer < netlinkSocketBufferEffective || writeBuffer < netlinkSocketBufferEffective {
		return fmt.Errorf("nftables netlink buffers are too small: receive=%d send=%d, require at least %d bytes",
			readBuffer, writeBuffer, netlinkSocketBufferEffective)
	}
	return nil
}

func netlinkSocketBuffers(conn *netlink.Conn) (readBuffer, writeBuffer int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		readBuffer, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if socketErr != nil {
			return
		}
		writeBuffer, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		return 0, 0, err
	}
	if socketErr != nil {
		return 0, 0, socketErr
	}
	return readBuffer, writeBuffer, nil
}

func (in *netlinkInstaller) tableMatchesPlan(name string, plan *nlPlan) (bool, error) {
	c, err := in.newConn()
	if err != nil {
		return false, fmt.Errorf("nftables readback conn: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("list inet tables: %w", err)
	}
	var table *nftables.Table
	for _, candidate := range tables {
		if candidate != nil && candidate.Name == name {
			table = candidate
			break
		}
	}
	if table == nil {
		return false, nil
	}
	if len(plan.rules) != len(plan.ruleChains) {
		return false, fmt.Errorf("incomplete planned rule-chain mapping: %d rules, %d chains", len(plan.rules), len(plan.ruleChains))
	}

	plannedChains := make(map[string]*nftables.Chain, len(plan.chains))
	for _, chain := range plan.chains {
		if chain == nil || chain.Name == "" {
			return false, errors.New("incomplete planned chain")
		}
		if _, exists := plannedChains[chain.Name]; exists {
			return false, fmt.Errorf("duplicate planned chain %q", chain.Name)
		}
		plannedChains[chain.Name] = chain
	}
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, fmt.Errorf("list inet chains: %w", err)
	}
	installedChains := make(map[string]*nftables.Chain)
	for _, chain := range chains {
		if chain != nil && chain.Table != nil && chain.Table.Name == name {
			installedChains[chain.Name] = chain
		}
	}
	if len(installedChains) != len(plannedChains) {
		return false, fmt.Errorf("installed table has %d chains, planned %d", len(installedChains), len(plannedChains))
	}
	setNames, setsMatch, err := setsMatchPlan(c, table, plan)
	if err != nil {
		return false, err
	}
	if !setsMatch {
		return false, errors.New("installed table sets differ from plan")
	}
	for chainName, wantChain := range plannedChains {
		gotChain := installedChains[chainName]
		if !chainsMatch(gotChain, wantChain) {
			return false, fmt.Errorf("installed chain %s differs from plan", chainName)
		}
		rules, err := c.GetRules(table, &nftables.Chain{Name: chainName, Table: table})
		if errors.Is(err, unix.ENOENT) {
			return false, fmt.Errorf("installed chain %s is absent", chainName)
		}
		if err != nil {
			return false, fmt.Errorf("read chain %s rules: %w", chainName, err)
		}
		wantRules := make([][]expr.Any, 0)
		for i, plannedChain := range plan.ruleChains {
			if plannedChain == chainName {
				wantRules = append(wantRules, plan.rules[i])
			}
		}
		if len(rules) != len(wantRules) {
			return false, fmt.Errorf("installed chain %s has %d rules, planned %d", chainName, len(rules), len(wantRules))
		}
		for i, rule := range rules {
			matches, err := expressionsMatch(byte(nftables.TableFamilyINet), wantRules[i], rule.Exprs, setNames)
			if err != nil {
				return false, fmt.Errorf("compare chain %s rule %d: %w", chainName, i, err)
			}
			if !matches {
				return false, fmt.Errorf("installed chain %s rule %d differs from plan", chainName, i)
			}
		}
	}

	objectsMatch, err := countersMatchPlan(c, table, plan)
	if err != nil {
		return false, err
	}
	if !objectsMatch {
		return false, errors.New("installed table objects differ from plan")
	}
	return true, nil
}

func chainsMatch(got, want *nftables.Chain) bool {
	if got == nil || want == nil || got.Name != want.Name || got.Type != want.Type || got.Device != want.Device {
		return false
	}
	if got.Table == nil || want.Table == nil || got.Table.Name != want.Table.Name || got.Table.Family != want.Table.Family {
		return false
	}
	return optionalChainHookEqual(got.Hooknum, want.Hooknum) &&
		optionalChainPriorityEqual(got.Priority, want.Priority) &&
		optionalChainPolicyEqual(got.Policy, want.Policy)
}

func optionalChainHookEqual(a, b *nftables.ChainHook) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func optionalChainPriorityEqual(a, b *nftables.ChainPriority) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func optionalChainPolicyEqual(a, b *nftables.ChainPolicy) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func expressionsMatch(family byte, want, got []expr.Any, setNames map[uint32]string) (bool, error) {
	if len(want) != len(got) {
		return false, nil
	}
	for i := range want {
		normalized, ok := normalizeSetReference(want[i], got[i], setNames)
		if !ok {
			return false, nil
		}
		wantBytes, err := expr.Marshal(family, normalized)
		if err != nil {
			return false, fmt.Errorf("marshal planned expression %d: %w", i, err)
		}
		gotBytes, err := expr.Marshal(family, got[i])
		if err != nil {
			return false, fmt.Errorf("marshal installed expression %d: %w", i, err)
		}
		if !bytes.Equal(wantBytes, gotBytes) {
			return false, nil
		}
	}
	return true, nil
}

func normalizeSetReference(want, got expr.Any, setNames map[uint32]string) (expr.Any, bool) {
	switch want := want.(type) {
	case *expr.Lookup:
		got, ok := got.(*expr.Lookup)
		if !ok || setNames[want.SetID] == "" || setNames[want.SetID] != got.SetName {
			return nil, false
		}
		normalized := *want
		normalized.SetID = got.SetID
		normalized.SetName = got.SetName
		return &normalized, true
	case *expr.Dynset:
		got, ok := got.(*expr.Dynset)
		if !ok || setNames[want.SetID] == "" || setNames[want.SetID] != got.SetName {
			return nil, false
		}
		normalized := *want
		normalized.SetID = got.SetID
		normalized.SetName = got.SetName
		return &normalized, true
	default:
		return want, reflect.TypeOf(want) == reflect.TypeOf(got)
	}
}

func setsMatchPlan(c *nftables.Conn, table *nftables.Table, plan *nlPlan) (map[uint32]string, bool, error) {
	sets, err := c.GetSets(table)
	expectedCount := len(plan.setDefs) + len(plan.screenFloodSets)
	if errors.Is(err, unix.ENOENT) && expectedCount == 0 {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read table sets: %w", err)
	}
	if len(sets) != expectedCount {
		return nil, false, fmt.Errorf("installed table has %d sets, planned %d", len(sets), expectedCount)
	}

	wantAnonymous := make([]*nftables.Set, 0, len(plan.setDefs))
	for _, set := range plan.setDefs {
		wantAnonymous = append(wantAnonymous, set)
	}
	sort.Slice(wantAnonymous, func(i, j int) bool { return wantAnonymous[i].ID < wantAnonymous[j].ID })
	gotAnonymous := make([]*nftables.Set, 0, len(plan.setDefs))
	setNames := make(map[uint32]string, len(sets))
	for _, got := range sets {
		if got.Anonymous {
			gotAnonymous = append(gotAnonymous, got)
			continue
		}
		want := plan.screenFloodSets[got.Name]
		if !setsMatch(got, want) {
			return nil, false, fmt.Errorf("installed named set %q differs from plan", got.Name)
		}
		setNames[want.ID] = got.Name
	}
	if len(gotAnonymous) != len(wantAnonymous) {
		return nil, false, fmt.Errorf("installed table has %d anonymous sets, planned %d", len(gotAnonymous), len(wantAnonymous))
	}
	sort.Slice(gotAnonymous, func(i, j int) bool {
		leftPrefix, leftIndex := anonymousSetOrder(gotAnonymous[i].Name)
		rightPrefix, rightIndex := anonymousSetOrder(gotAnonymous[j].Name)
		if leftPrefix != rightPrefix {
			return leftPrefix < rightPrefix
		}
		return leftIndex < rightIndex
	})
	for i, want := range wantAnonymous {
		got := gotAnonymous[i]
		if !setsMatch(got, want) {
			return nil, false, fmt.Errorf("installed anonymous set %q differs from planned set id %d: got=%#v want=%#v", got.Name, want.ID, got, want)
		}
		gotElements, err := c.GetSetElements(got)
		if err != nil {
			return nil, false, fmt.Errorf("read anonymous set %q elements: %w", got.Name, err)
		}
		if !setElementsMatch(plan.sets[want.ID], gotElements) {
			return nil, false, fmt.Errorf("installed anonymous set %q elements differ from plan", got.Name)
		}
		setNames[want.ID] = got.Name
	}
	return setNames, true, nil
}

func anonymousSetOrder(name string) (string, int) {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	index, _ := strconv.Atoi(name[i:])
	return name[:i], index
}

func setsMatch(got, want *nftables.Set) bool {
	if got == nil || want == nil ||
		got.Anonymous != want.Anonymous || got.Constant != want.Constant ||
		got.Interval != want.Interval || got.AutoMerge != want.AutoMerge ||
		got.IsMap != want.IsMap || got.HasTimeout != want.HasTimeout ||
		got.Timeout != want.Timeout ||
		got.KeyType.Name != want.KeyType.Name || got.KeyType.Bytes != want.KeyType.Bytes ||
		got.KeyType.GetNFTMagic() != want.KeyType.GetNFTMagic() ||
		got.DataType.Name != want.DataType.Name || got.DataType.Bytes != want.DataType.Bytes ||
		got.DataType.GetNFTMagic() != want.DataType.GetNFTMagic() {
		return false
	}
	if !want.Anonymous && (got.Name != want.Name || got.Size != want.Size) {
		return false
	}
	return got.Table != nil && want.Table != nil && got.Table.Name == want.Table.Name && got.Table.Family == want.Table.Family
}

func setElementsMatch(want, got []nftables.SetElement) bool {
	if len(want) != len(got) {
		return false
	}
	want = append([]nftables.SetElement(nil), want...)
	got = append([]nftables.SetElement(nil), got...)
	sort.Slice(want, func(i, j int) bool { return setElementLess(want[i], want[j]) })
	sort.Slice(got, func(i, j int) bool { return setElementLess(got[i], got[j]) })
	return reflect.DeepEqual(want, got)
}

func setElementLess(a, b nftables.SetElement) bool {
	if cmp := bytes.Compare(a.Key, b.Key); cmp != 0 {
		return cmp < 0
	}
	if cmp := bytes.Compare(a.KeyEnd, b.KeyEnd); cmp != 0 {
		return cmp < 0
	}
	if cmp := bytes.Compare(a.Val, b.Val); cmp != 0 {
		return cmp < 0
	}
	if a.IntervalEnd != b.IntervalEnd {
		return !a.IntervalEnd
	}
	if a.Timeout != b.Timeout {
		return a.Timeout < b.Timeout
	}
	if a.Expires != b.Expires {
		return a.Expires < b.Expires
	}
	return a.Comment < b.Comment
}

func countersMatchPlan(c *nftables.Conn, table *nftables.Table, plan *nlPlan) (bool, error) {
	objects, err := c.GetNamedObjects(table)
	if errors.Is(err, unix.ENOENT) && len(plan.counters) == 0 {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read table objects: %w", err)
	}
	want := make(map[string]struct{}, len(plan.counters))
	for _, name := range plan.counters {
		want[name] = struct{}{}
	}
	if len(objects) != len(want) {
		return false, fmt.Errorf("installed table has %d named objects, planned %d", len(objects), len(want))
	}
	for _, object := range objects {
		named, ok := object.(*nftables.NamedObj)
		if !ok || named.Type != nftables.ObjTypeCounter {
			return false, fmt.Errorf("installed table has unexpected object %T", object)
		}
		if _, exists := want[named.Name]; !exists {
			return false, fmt.Errorf("installed table has unexpected counter %q", named.Name)
		}
		delete(want, named.Name)
	}
	return len(want) == 0, nil
}
