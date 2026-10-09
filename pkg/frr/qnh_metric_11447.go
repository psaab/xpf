package frr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// qnhMetricRoute11447 is one renderable static route / qualified-next-hop
// metric pair. Matching both the destination and the configured next hop is
// essential: plain and qualified next hops for one prefix coexist while the
// plain next hop is active, and a prefix-only map would assign the backup's
// metric to the primary route as well.
type qnhMetricRoute11447 struct {
	destination     string
	destinationList string
	nextHop         string
	nextHopList     string
	interfaceName   string
	metric          int
	ipv6            bool
}

type qnhMetricScope11447 struct {
	key        string
	staticMap  string
	policyMaps map[string]string
	routes     []qnhMetricRoute11447
}

type qnhMetricSet11447 struct {
	global    *qnhMetricScope11447
	instances []*qnhMetricScope11447
}

// qnhMetricMatchCaps11447 records the match commands installed by each
// protocol daemon. A generated metric sequence is useful only when its
// destination and configured next-hop discriminators both survive evaluation.
type qnhMetricMatchCaps11447 struct {
	ipv4Destination bool
	ipv6Destination bool
	ipv4NextHop     bool
	ipv6NextHop     bool
	interfaceMatch  bool
}

var qnhMetricMatchCapabilities11447 = map[string]qnhMetricMatchCaps11447{
	"ospf":  {ipv4Destination: true, ipv4NextHop: true, interfaceMatch: true},
	"rip":   {ipv4Destination: true, ipv4NextHop: true, interfaceMatch: true},
	"ospf6": {ipv6Destination: true, interfaceMatch: true},
	"isis":  {ipv4Destination: true, ipv6Destination: true},
}

func qnhMetricRouteMatchesWithCaps11447(route qnhMetricRoute11447, caps qnhMetricMatchCaps11447) bool {
	if route.ipv6 {
		if !caps.ipv6Destination || (route.nextHop != "" && !caps.ipv6NextHop) {
			return false
		}
	} else if !caps.ipv4Destination || (route.nextHop != "" && !caps.ipv4NextHop) {
		return false
	}
	if route.interfaceName != "" && !caps.interfaceMatch {
		return false
	}
	return route.nextHop != "" || route.interfaceName != ""
}

// The static QNH map is shared by ospfd and ripd. Keep only rules both
// daemons can evaluate so either attachment sees the same fully-qualified
// IPv4 match sequence; neither FRR 10.6 daemon supports IPv6 redistribution.
func qnhMetricRouteSafeForSharedMap11447(route qnhMetricRoute11447) bool {
	return qnhMetricRouteMatchesWithCaps11447(route, qnhMetricMatchCapabilities11447["ospf"]) &&
		qnhMetricRouteMatchesWithCaps11447(route, qnhMetricMatchCapabilities11447["rip"])
}

func qnhMetricScopeForDaemon11447(scope *qnhMetricScope11447, daemon string) *qnhMetricScope11447 {
	if scope == nil || len(scope.routes) == 0 {
		return nil
	}
	caps, ok := qnhMetricMatchCapabilities11447[daemon]
	if !ok {
		return nil
	}
	for _, route := range scope.routes {
		if !qnhMetricRouteMatchesWithCaps11447(route, caps) {
			return nil
		}
	}
	return scope
}

func qnhMetricName11447(kind, identity string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + identity))
	return "xpf-qnh-" + kind + "-" + hex.EncodeToString(sum[:])[:16] + config.ReservedRedistSuffix
}

func qnhMetricPrefixListName11447(kind, identity string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + identity))
	return "xpf-qnh-" + kind + "-" + hex.EncodeToString(sum[:])[:16]
}

func qnhMetricScopeKey11447(index int, inst InstanceConfig) string {
	if inst.Name != "" {
		return fmt.Sprintf("instance:%d:%s", index, inst.Name)
	}
	if inst.VRFName != "" {
		return fmt.Sprintf("instance:%d:%s", index, inst.VRFName)
	}
	return fmt.Sprintf("instance:%d:table:%d", index, inst.TableID)
}

func qnhMetricCandidate11447(routeSets ...[]*config.StaticRoute) bool {
	for _, routes := range routeSets {
		for _, route := range routes {
			if route == nil || route.NoInstall || route.NextTable != "" {
				continue
			}
			for _, nh := range route.NextHops {
				if nh.HasMetric {
					return true
				}
			}
		}
	}
	return false
}

func buildQNHMetricScope11447(key string, resolveIfName func(string) string, routeSets ...[]*config.StaticRoute) *qnhMetricScope11447 {
	byMatcher := make(map[string]qnhMetricRoute11447)
	for _, routes := range routeSets {
		for _, route := range routes {
			if route == nil || route.NoInstall || route.NextTable != "" || !validFRRRoutePrefix(route.Destination) {
				continue
			}
			dst, err := netip.ParsePrefix(route.Destination)
			if err != nil {
				addr, parseErr := netip.ParseAddr(route.Destination)
				if parseErr != nil || addr.Is4In6() {
					continue
				}
				bits := 128
				if addr.Is4() {
					bits = 32
				}
				dst = netip.PrefixFrom(addr, bits)
			}
			destination := dst.Masked().String()
			for _, nh := range route.NextHops {
				if !nh.HasMetric || nh.Metric < 0 || uint64(nh.Metric) > uint64(^uint32(0)) {
					continue
				}
				entry := qnhMetricRoute11447{destination: destination, metric: nh.Metric, ipv6: dst.Addr().Is6()}
				if nh.Address != "" {
					gateway, err := netip.ParseAddr(nh.Address)
					if err != nil || gateway.Is4In6() || gateway.Is6() != entry.ipv6 {
						continue
					}
					entry.nextHop = gateway.String()
					entry.nextHopList = qnhMetricPrefixListName11447("nh", key+"\x00"+destination+"\x00"+entry.nextHop+"\x00"+nh.Interface)
				}
				if nh.Interface != "" {
					entry.interfaceName = nh.Interface
					if resolveIfName != nil {
						entry.interfaceName = resolveIfName(entry.interfaceName)
					}
					if strings.HasSuffix(entry.interfaceName, ".0") {
						entry.interfaceName = strings.TrimSuffix(entry.interfaceName, ".0")
					}
					if !validFRRInterfaceOperand(entry.interfaceName) {
						continue
					}
				}
				if entry.nextHop == "" && entry.interfaceName == "" {
					continue
				}
				if !qnhMetricRouteSafeForSharedMap11447(entry) {
					continue
				}
				entry.destinationList = qnhMetricPrefixListName11447("dst", key+"\x00"+route.Destination+"\x00"+entry.nextHop+"\x00"+entry.interfaceName)
				matcher := route.Destination + "\x00" + entry.nextHop + "\x00" + entry.interfaceName
				byMatcher[matcher] = entry
			}
		}
	}
	if len(byMatcher) == 0 {
		return nil
	}
	scope := &qnhMetricScope11447{
		key:       key,
		staticMap: qnhMetricName11447("static", key),
	}
	for _, route := range byMatcher {
		scope.routes = append(scope.routes, route)
	}
	sort.Slice(scope.routes, func(i, j int) bool {
		a, b := scope.routes[i], scope.routes[j]
		if a.destination != b.destination {
			return a.destination < b.destination
		}
		if a.nextHop != b.nextHop {
			return a.nextHop < b.nextHop
		}
		if a.interfaceName != b.interfaceName {
			return a.interfaceName < b.interfaceName
		}
		return a.metric < b.metric
	})
	return scope
}

func buildQNHMetricSet11447(fc *FullConfig, po *config.PolicyOptionsConfig) *qnhMetricSet11447 {
	if fc == nil {
		return nil
	}
	hasCandidates := qnhMetricCandidate11447(fc.StaticRoutes, fc.Inet6StaticRoutes)
	for _, inst := range fc.Instances {
		hasCandidates = hasCandidates || qnhMetricCandidate11447(inst.StaticRoutes, inst.Inet6StaticRoutes)
	}
	if !hasCandidates {
		return nil
	}
	resolveIfName := fc.ifNameResolver()
	set := &qnhMetricSet11447{
		global:    buildQNHMetricScope11447("global", resolveIfName, fc.StaticRoutes, fc.Inet6StaticRoutes),
		instances: make([]*qnhMetricScope11447, len(fc.Instances)),
	}
	for i, inst := range fc.Instances {
		set.instances[i] = buildQNHMetricScope11447(qnhMetricScopeKey11447(i, inst), resolveIfName, inst.StaticRoutes, inst.Inet6StaticRoutes)
	}
	if po != nil {
		for _, scope := range set.scopes() {
			scope.policyMaps = make(map[string]string)
			for name, ps := range po.PolicyStatements {
				if policyHasStaticSource11447(ps) {
					scope.policyMaps[name] = qnhMetricName11447("policy", scope.key+"\x00"+name)
				}
			}
		}
	}
	if set.global == nil {
		any := false
		for _, scope := range set.instances {
			any = any || scope != nil
		}
		if !any {
			return nil
		}
	}
	return set
}

func (s *qnhMetricSet11447) scopes() []*qnhMetricScope11447 {
	if s == nil {
		return nil
	}
	out := make([]*qnhMetricScope11447, 0, len(s.instances)+1)
	if s.global != nil {
		out = append(out, s.global)
	}
	for _, scope := range s.instances {
		if scope != nil {
			out = append(out, scope)
		}
	}
	return out
}

func policyHasStaticSource11447(ps *config.PolicyStatement) bool {
	if ps == nil {
		return false
	}
	for _, term := range ps.Terms {
		for _, source := range term.FromProtocols {
			if source == "static" {
				return true
			}
		}
	}
	return false
}

func (s *qnhMetricSet11447) renderPrefixLists() string {
	var b strings.Builder
	for _, scope := range s.scopes() {
		for _, route := range scope.routes {
			prefixKind := "ip"
			if route.ipv6 {
				prefixKind = "ipv6"
			}
			fmt.Fprintf(&b, "%s prefix-list %s seq 5 permit %s\n", prefixKind, frrName(route.destinationList), sanitizeFRRValue(route.destination))
			if route.nextHop != "" {
				gateway, _ := netip.ParseAddr(route.nextHop)
				bits := 32
				if gateway.Is6() {
					bits = 128
				}
				fmt.Fprintf(&b, "%s prefix-list %s seq 5 permit %s/%d\n", prefixKind, frrName(route.nextHopList), gateway.String(), bits)
			}
		}
	}
	if b.Len() > 0 {
		b.WriteString("!\n")
	}
	return b.String()
}

func renderQNHMetricTerms11447(scope *qnhMetricScope11447, routeMap string, start int) (string, int) {
	var b strings.Builder
	seq := start
	for _, route := range scope.routes {
		fmt.Fprintf(&b, "route-map %s permit %d\n", frrName(routeMap), seq)
		family := "ip"
		if route.ipv6 {
			family = "ipv6"
		}
		// This route-map is attached only to `redistribute static`, so the
		// source protocol is selected by the attachment, not a daemon-specific
		// match clause.
		fmt.Fprintf(&b, " match %s address prefix-list %s\n", family, frrName(route.destinationList))
		if route.nextHop != "" {
			fmt.Fprintf(&b, " match %s next-hop prefix-list %s\n", family, frrName(route.nextHopList))
		}
		if route.interfaceName != "" {
			fmt.Fprintf(&b, " match interface %s\n", sanitizeFRRValue(route.interfaceName))
		}
		b.WriteString(" on-match next\nexit\n")
		seq += 10
	}
	return b.String(), seq
}

func qualifiedNextHopMetricCollision11447(po *config.PolicyOptionsConfig, set *qnhMetricSet11447) error {
	if set == nil {
		return nil
	}
	policyNames := make(map[string]string)
	prefixListNames := make(map[string]string)
	if po != nil {
		for name := range po.PolicyStatements {
			policyNames[frrName(name)] = name
		}
		for name := range po.PrefixLists {
			prefixListNames[frrName(name)] = name
		}
	}
	generatedMaps := make(map[string]string)
	generatedLists := make(map[string]string)
	for _, scope := range set.scopes() {
		for _, mapName := range append([]string{scope.staticMap}, mapValues11447(scope.policyMaps)...) {
			final := frrName(mapName)
			if operator, ok := policyNames[final]; ok {
				return fmt.Errorf("qualified-next-hop metric route-map %q collides with policy-statement %q after FRR name normalization", mapName, operator)
			}
			if previous, ok := generatedMaps[final]; ok && previous != mapName {
				return fmt.Errorf("qualified-next-hop metric route-maps %q and %q collide after FRR name normalization", previous, mapName)
			}
			generatedMaps[final] = mapName
		}
		for _, route := range scope.routes {
			for _, listName := range []string{route.destinationList, route.nextHopList} {
				if listName == "" {
					continue
				}
				final := frrName(listName)
				if operator, ok := prefixListNames[final]; ok {
					return fmt.Errorf("qualified-next-hop metric prefix-list %q collides with policy-options prefix-list %q after FRR name normalization", listName, operator)
				}
				if previous, ok := generatedLists[final]; ok && previous != listName {
					return fmt.Errorf("qualified-next-hop metric prefix-lists %q and %q collide after FRR name normalization", previous, listName)
				}
				generatedLists[final] = listName
			}
		}
	}
	return nil
}
func (m *Manager) renderQNHMetricPolicyMap11447(po *config.PolicyOptionsConfig, routeMap string, ps *config.PolicyStatement, scope *qnhMetricScope11447) string {
	policy := redistPolicyForProtocol(ps, "static")
	if uint64(len(scope.routes))+config.RouteMapSequenceCount(po, policy) > config.MaxRouteMapSequences {
		slog.Warn("frr: qualified-next-hop metric and policy route-map exceed FRR sequence limit; rendering a deny map",
			"route_map", routeMap, "metric_rules", len(scope.routes), "policy", ps.Name)
		m.noteQuarantined(routeMap)
		return renderQuarantineDenyRouteMap(routeMap)
	}
	rules, next := renderQNHMetricTerms11447(scope, routeMap, 10)
	definitions, body, seq := m.renderPolicyTermSequencesWithDefinitions(po, routeMap, routeMap, policy, next)
	hasNextPolicy := policyHasNextPolicyTerm(policy)
	if hasNextPolicy {
		nextPolicySequence := seq
		if policy.DefaultAction == "accept" || policy.DefaultAction == "reject" {
			nextPolicySequence += 10
		}
		body = renderNextPolicyTarget(body, nextPolicySequence)
	}
	var b strings.Builder
	b.WriteString(definitions)
	b.WriteString(rules)
	b.WriteString(body)
	trailingAction := "deny"
	switch policy.DefaultAction {
	case "accept":
		trailingAction = "permit"
	case "reject":
		trailingAction = "deny"
	}
	fmt.Fprintf(&b, "route-map %s %s %d\nexit\n", frrName(routeMap), trailingAction, seq)
	if hasNextPolicy && (policy.DefaultAction == "accept" || policy.DefaultAction == "reject") {
		fmt.Fprintf(&b, "route-map %s deny %d\nexit\n", frrName(routeMap), seq+10)
	}
	return b.String()
}

func mapValues11447(m map[string]string) []string {
	values := make([]string, 0, len(m))
	for _, value := range m {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func renderQNHMetricSetOverlay11447(scope *qnhMetricScope11447, routeMap string) string {
	var b strings.Builder
	seq := 10
	for _, route := range scope.routes {
		fmt.Fprintf(&b, "route-map %s permit %d\n set metric %d\nexit\n",
			frrName(routeMap), seq, route.metric)
		seq += 10
	}
	return b.String()
}

// qnhMetricDaemonOverlays11447 emits metric actions only for QNH maps attached
// to the daemons whose route-map match hooks preserve both discriminators.
// The integrated map bodies remain metric-free in every daemon's copy.
func (m *Manager) qnhMetricDaemonOverlays11447(fc *FullConfig, set *qnhMetricSet11447) map[string]string {
	if fc == nil || set == nil {
		return nil
	}
	targets := map[string]map[string]*qnhMetricScope11447{
		"ospfd": {},
		"ripd":  {},
	}
	addExport := func(daemon, self, export string, scope *qnhMetricScope11447) {
		if qnhMetricScopeForDaemon11447(scope, self) == nil {
			return
		}
		for _, entry := range m.redistributeEntries(export, fc.PolicyOptions, self, scope) {
			if entry.proto == "static" && entry.routeMap != "" {
				targets[daemon][entry.routeMap] = scope
			}
		}
	}
	addProtocols := func(ospf *config.OSPFConfig, rip *config.RIPConfig, scope *qnhMetricScope11447) {
		if ospf != nil {
			for _, export := range ospf.Export {
				addExport("ospfd", "ospf", export, scope)
			}
		}
		if rip != nil {
			for _, export := range rip.Redistribute {
				addExport("ripd", "rip", export, scope)
			}
		}
	}
	addProtocols(fc.OSPF, fc.RIP, set.global)
	for i, inst := range fc.Instances {
		if i < len(set.instances) {
			addProtocols(inst.OSPF, inst.RIP, set.instances[i])
		}
	}

	overlays := make(map[string]string, len(targets))
	for daemon, maps := range targets {
		mapNames := make([]string, 0, len(maps))
		for routeMap := range maps {
			mapNames = append(mapNames, routeMap)
		}
		sort.Strings(mapNames)
		var b strings.Builder
		for _, routeMap := range mapNames {
			scope := maps[routeMap]
			switch {
			case routeMap == scope.staticMap:
				if len(scope.routes) <= config.MaxRouteMapSequences {
					b.WriteString(renderQNHMetricSetOverlay11447(scope, routeMap))
				}
			case fc.PolicyOptions != nil:
				for name, policyMap := range scope.policyMaps {
					if policyMap != routeMap {
						continue
					}
					policy := redistPolicyForProtocol(fc.PolicyOptions.PolicyStatements[name], "static")
					if uint64(len(scope.routes))+config.RouteMapSequenceCount(fc.PolicyOptions, policy) <= config.MaxRouteMapSequences {
						b.WriteString(renderQNHMetricSetOverlay11447(scope, routeMap))
					}
					break
				}
			}
		}
		if b.Len() > 0 {
			overlays[daemon] = b.String()
		}
	}
	return overlays
}

type qnhMetricSequenceSet11447 map[string]map[int]struct{}

// These daemons may hold a previous integrated QNH map copy. Clear only the
// known generated sequences there; metric overlays themselves target ospfd/ripd.
var qnhMetricCleanupDaemons11447 = []string{"ospfd", "ospf6d", "ripd", "isisd", "bgpd"}

func newQNHMetricSequenceSet11447() qnhMetricSequenceSet11447 {
	return make(qnhMetricSequenceSet11447)
}

func (s qnhMetricSequenceSet11447) add(routeMap string, sequence int) {
	if s[routeMap] == nil {
		s[routeMap] = make(map[int]struct{})
	}
	s[routeMap][sequence] = struct{}{}
}

func mergeQNHMetricSequenceSets11447(sets ...qnhMetricSequenceSet11447) qnhMetricSequenceSet11447 {
	merged := newQNHMetricSequenceSet11447()
	for _, set := range sets {
		for routeMap, sequences := range set {
			for sequence := range sequences {
				merged.add(routeMap, sequence)
			}
		}
	}
	return merged
}

// qnhMetricSequencesFromConfig11447 identifies generated QNH route-map
// sequences by their reserved destination and next-hop/interface match lists.
// It deliberately excludes policy-action sequences in QNH policy aliases.
func qnhMetricSequencesFromConfig11447(text string) qnhMetricSequenceSet11447 {
	sequences := newQNHMetricSequenceSet11447()
	var routeMap string
	var sequence int
	hasQNHDestination, hasQNHDiscriminator := false, false
	flush := func() {
		if routeMap != "" && hasQNHDestination && hasQNHDiscriminator {
			sequences.add(routeMap, sequence)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "route-map" {
			flush()
			routeMap = ""
			sequence = 0
			hasQNHDestination, hasQNHDiscriminator = false, false
			if len(fields) != 4 || fields[2] != "permit" || !strings.HasPrefix(fields[1], "xpf-qnh-") {
				continue
			}
			parsed, err := strconv.Atoi(fields[3])
			if err != nil {
				continue
			}
			routeMap, sequence = fields[1], parsed
			continue
		}
		if routeMap == "" {
			continue
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "match ip address prefix-list xpf-qnh-dst-") {
			hasQNHDestination = true
		}
		if strings.HasPrefix(line, "match ip next-hop prefix-list xpf-qnh-nh-") ||
			strings.HasPrefix(line, "match interface ") {
			hasQNHDiscriminator = true
		}
	}
	flush()
	return sequences
}

func qnhMetricSequencesFromOverlay11447(overlays map[string]string) qnhMetricSequenceSet11447 {
	sequences := newQNHMetricSequenceSet11447()
	var routeMap string
	var sequence int
	hasMetric := false
	flush := func() {
		if routeMap != "" && hasMetric {
			sequences.add(routeMap, sequence)
		}
	}
	for _, overlay := range overlays {
		for _, line := range strings.Split(overlay, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "route-map" {
				flush()
				routeMap = ""
				sequence = 0
				hasMetric = false
				if len(fields) != 4 || fields[2] != "permit" || !strings.HasPrefix(fields[1], "xpf-qnh-") {
					continue
				}
				parsed, err := strconv.Atoi(fields[3])
				if err != nil {
					continue
				}
				routeMap, sequence = fields[1], parsed
				continue
			}
			if routeMap != "" && strings.HasPrefix(strings.TrimSpace(line), "set metric ") {
				hasMetric = true
			}
		}
		flush()
	}
	return sequences
}

func qnhMetricSequencesFromManagedConfig11447(text string) qnhMetricSequenceSet11447 {
	start := strings.Index(text, markerBegin)
	if start < 0 {
		return newQNHMetricSequenceSet11447()
	}
	start += len(markerBegin)
	if start < len(text) && text[start] == '\n' {
		start++
	}
	section := text[start:]
	if end := strings.Index(section, markerEnd); end >= 0 {
		section = section[:end]
	}
	return qnhMetricSequencesFromConfig11447(section)
}

func renderQNHMetricSequenceClears11447(sequences qnhMetricSequenceSet11447) string {
	routeMaps := make([]string, 0, len(sequences))
	for routeMap := range sequences {
		routeMaps = append(routeMaps, routeMap)
	}
	sort.Strings(routeMaps)
	var b strings.Builder
	for _, routeMap := range routeMaps {
		seqs := make([]int, 0, len(sequences[routeMap]))
		for sequence := range sequences[routeMap] {
			seqs = append(seqs, sequence)
		}
		sort.Ints(seqs)
		for _, sequence := range seqs {
			fmt.Fprintf(&b, "route-map %s permit %d\n no set metric\nexit\n!\n",
				frrName(routeMap), sequence)
		}
	}
	return b.String()
}

func (m *Manager) generateQNHMetricStaticMaps11447(set *qnhMetricSet11447) string {
	if set == nil {
		return ""
	}
	var b strings.Builder
	for _, scope := range set.scopes() {
		if len(scope.routes) > config.MaxRouteMapSequences {
			slog.Warn("frr: too many qualified-next-hop metric rules; static redistribution is denied rather than emitting an invalid route-map", "count", len(scope.routes))
			b.WriteString(renderQuarantineDenyRouteMap(scope.staticMap))
			b.WriteString("!\n")
			continue
		}
		rules, next := renderQNHMetricTerms11447(scope, scope.staticMap, 10)
		b.WriteString(rules)
		fmt.Fprintf(&b, "route-map %s permit %d\nexit\n!\n", frrName(scope.staticMap), next)
	}
	return b.String()
}
