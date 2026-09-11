// Package flowexport implements NetFlow v9 and IPFIX (NetFlow v10) flow
// data export. Session-close events are turned into flow records and
// shipped to remote collectors over UDP, with per-zone direction
// filtering and 1-in-N session sampling.
//
// The package is split by responsibility:
//   - manager.go   — resolved export config, sampling scheduler, the
//     shared FlowRecord shape, and the BuildExportConfig family of
//     config resolvers.
//   - netflow.go   — NetFlow v9 template/record encoding and the
//     Exporter that drives it.
//   - ipfix.go     — IPFIX (v10) template/record encoding and the
//     IPFIXExporter that drives it.
//   - transport.go — collector connection management and per-family
//     batch accumulation shared by both exporters.
package flowexport

import (
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// SamplingDir tracks per-zone sampling direction flags.
type SamplingDir struct {
	Input  bool
	Output bool
}

// ExportConfig holds the resolved NetFlow export configuration for a
// single template group: the collectors that referenced one template (or
// the default-template collectors that referenced none), the timeouts and
// v9 field options resolved from THAT template, plus the per-instance
// sampling state.
//
// #2461: before this change a single ExportConfig was built per family
// from the FIRST Go-map-iteration template and broadcast to every
// collector, so a per-flow-server template reference was silently ignored
// and the chosen template flipped across restarts. The resolver now emits
// one ExportConfig per referenced template — the group key is
// (instance, version, template_name); source-address is a deterministic
// sort tiebreak, NOT part of the key, so collectors that share a template
// but pin different source-addresses land in ONE group and each still gets
// its own source-pinned UDP connection from dialCollectors (see
// ResolveV9TemplateGroups / ResolveIPFIXTemplateGroups).
//
// #2462: sampling-instance identity is now first-class. Each sampling
// instance resolves to its OWN ExportConfig(s) carrying its OWN InputRate
// and its OWN sampleCounter, so a flow eligible for instance A exports ONLY
// to instance A's collectors at instance A's rate (1-in-N is independent
// per instance) and NEVER crosses to instance B. The template groups of one
// instance share that instance's sampleCounter (pointer below) so 1-in-N
// stays a single cadence across the instance's templates, but two instances
// never share a counter. Attribution to an instance is by address family:
// ServesInet / ServesInet6 record which families the instance configured a
// collector for, and ServesFamily gates a record so an IPv6 flow is
// not exported by an instance that configured only inet collectors. Two
// instances claiming the SAME (version, family) are genuinely ambiguous (no
// per-interface instance selector exists to attribute a flow) and are
// rejected at commit — see validateSamplingInstanceConflictsStrict.
type ExportConfig struct {
	Collectors          []CollectorConfig
	InstanceName        string // sampling instance this config belongs to (#2462)
	TemplateName        string // referenced template ("" = default group)
	FlowActiveTimeout   time.Duration
	FlowInactiveTimeout time.Duration
	TemplateRefreshRate time.Duration
	SamplingZones       map[uint16]SamplingDir // zone ID -> sampling directions
	SamplingRate        int                    // 1-in-N sampling (0 = export all)
	// ServesInet / ServesInet6 record which address families this instance
	// has a SURVIVING collector group for (#2462, narrowed by #9172): a family
	// whose only group names an undefined template is not served, because
	// nothing would export its records. ServesFamily uses them to
	// attribute a flow to the right instance: an instance with only inet
	// collectors must not export an IPv6 flow. An instance that configured
	// neither (no flow-servers for this version) produces no ExportConfig at
	// all, so both true-everywhere defaults are never observed.
	ServesInet  bool
	ServesInet6 bool
	// GroupIsV6 is the address family of THIS group's collectors (#6811).
	//
	// It is deliberately NOT the same thing as ServesInet/ServesInet6, which
	// stay per-INSTANCE and keep their #2462 meaning ("does this instance serve
	// this family at all"). The instance-level flags gate the single sampling
	// DECISION — a record of a family the instance does not serve must not
	// consume a 1-in-N slot — while GroupIsV6 gates which groups that decision
	// then fans out to. Collapsing the two would either re-open the cross-fan or
	// change the sampling denominator.
	GroupIsV6      bool
	V9TemplateOpts V9TemplateOptions // optional v9 template field control
	// IncludeFlowDir is the resolved `export-extension flow-dir` knob for THIS
	// template group (#3270). When set, the NetFlow v9 / IPFIX template
	// advertises flowDirection (IE 61) and the encoder writes the per-flow
	// direction derived from the per-zone sampling-direction (see
	// FlowDirection). It is opt-in: a group whose template did not request
	// flow-dir leaves IE 61 absent so a collector never ingests a synthetic
	// zero (the #2613 regression). For NetFlow v9 this mirrors
	// V9TemplateOpts.IncludeFlowDir (the v9 template builder reads the latter);
	// the IPFIX exporter, which has no V9TemplateOptions, reads this field.
	IncludeFlowDir bool
	// sampleCounter is the monotonic 1-in-N counter. It is a POINTER so all
	// ExportConfig template groups of one INSTANCE share a single counter
	// (the sampling rate is a per-instance property; #2462). Two different
	// instances each get their own counter. A nil pointer is lazily
	// allocated on first use so a hand-built ExportConfig (tests, the
	// singular Build* helpers) still samples correctly. json.Marshal skips
	// the unexported field, so the reconcile config-hash is unaffected.
	sampleCounter *atomic.Uint64
	counterOnce   sync.Once
}

// CollectorConfig defines a single NetFlow collector destination.
type CollectorConfig struct {
	Address       string // "host:port"
	SourceAddress string // local bind address (empty = auto)
	// Template is the per-flow-server template the collector referenced
	// ("" = none → default group). It is HALF the grouping key for #2461 and is
	// NOT serialized into the dialed connection; it only steers which
	// ExportConfig (template context) the collector is placed under.
	Template string `json:"-"`
	// IsV6 records the address family the flow-server was configured under
	// (#6811). Before it, family was collapsed to two per-INSTANCE booleans the
	// moment the two families were merged into one collector slice, so an
	// instance carrying `family inet { flow-server A }` AND
	// `family inet6 { flow-server B }` had both booleans true and exported IPv4
	// flows to B and IPv6 flows to A. Carrying family per collector is what lets
	// the grouping partition it back out at BUILD time, so the hot path stays a
	// gate on a precomputed group rather than a per-record collector search.
	IsV6 bool `json:"-"`
}

// resolveFlowServerVersion returns the export protocol a single
// flow-server is bound to, given the per-server selector and which
// global flow-monitoring version stanzas are configured. Junos binds
// each flow-server to exactly one export version + template; xpf
// honours that binding so a collector never receives both a NetFlow v9
// and an IPFIX datagram for the same flow (#2136).
//
// Resolution:
//   - An explicit per-server selector (`version9` / `version-ipfix`
//     nested under the flow-server) wins outright — but only if the
//     matching global `services flow-monitoring` stanza is configured
//     (the global stanza supplies the template timeouts/fields). A
//     server bound to a version whose global stanza is absent exports
//     nothing (it has no template), matching the existing global gates.
//   - With no per-server selector, the server inherits the single
//     configured global version. When BOTH global versions are set the
//     unbound server resolves to IPFIX (documented precedence): IPFIX
//     (v10) is the IETF-standard superset of NetFlow v9, so an operator
//     who turned on both and did not pin the collector gets the modern
//     protocol — and, critically, exactly ONE datagram stream rather
//     than the pre-#2136 double-export.
//
// Returns "" when the server resolves to no configured version (it is
// then skipped by both collector builders).
func resolveFlowServerVersion(fs *config.FlowServer, hasV9, hasIPFIX bool) string {
	switch fs.Version {
	case config.FlowServerVersion9:
		if hasV9 {
			return config.FlowServerVersion9
		}
		return ""
	case config.FlowServerVersionIPFIX:
		if hasIPFIX {
			return config.FlowServerVersionIPFIX
		}
		return ""
	}
	// Unbound: inherit the single configured global version. IPFIX wins
	// when both are configured (documented precedence — see above).
	switch {
	case hasIPFIX:
		return config.FlowServerVersionIPFIX
	case hasV9:
		return config.FlowServerVersion9
	default:
		return ""
	}
}

// collectInstanceVersionCollectors walks ONE sampling instance's
// flow-servers and returns the deduplicated collector set for the requested
// export version, skipping flow-servers resolved to the other version. It
// also reports which address families (inet / inet6) the instance
// configured a collector for under this version, so the caller can scope the
// resulting ExportConfig to those families (#2462 attribution). This is the
// per-flow-server version binding that prevents double-export (#2136): the
// v9 resolver calls it with version=version9, the IPFIX resolver with
// version=version-ipfix, and a server appears in at most one of the two
// sets.
//
// #2462: this is now per-INSTANCE (was a global walk over every instance,
// which merged distinct instances into one collector set — the defect).
func collectInstanceVersionCollectors(inst *config.SamplingInstance, version string, hasV9, hasIPFIX bool) (collectors []CollectorConfig, servesInet, servesInet6 bool) {
	families := []struct {
		fam  *config.SamplingFamily
		isV6 bool
	}{
		{inst.FamilyInet, false},
		{inst.FamilyInet6, true},
	}
	for _, fe := range families {
		fam := fe.fam
		if fam == nil {
			continue
		}
		for _, fs := range fam.FlowServers {
			// A nil entry cannot be version-resolved (resolveFlowServerVersion
			// dereferences fs.Version), so guard before it rather than relying
			// on the compiler's collection never holding one.
			if fs == nil {
				continue
			}
			if resolveFlowServerVersion(fs, hasV9, hasIPFIX) != version {
				continue
			}
			// #8163: drop a flow-server that can never receive a record HERE,
			// where the collector list is BUILT — not downstream where the
			// failure is caught.
			//
			// dialCollectors treats a dial failure as fatal for the whole
			// group (it closes every socket opened so far and returns the
			// error), NewExporter propagates it out of the constructor, and
			// Daemon.reconcileFlowExporter's build loop `return`s on the FIRST
			// constructor error. So a single unusable flow-server disabled
			// NetFlow/IPFIX export for EVERY template/family group, not just
			// its own siblings — and on a boot with nothing previously running
			// it published the empty bundle, leaving export simply off.
			//
			// Catching it further down would not do. Making the daemon loop
			// `continue` would rescue the OTHER groups while still dropping
			// this collector's healthy siblings, and tolerating dial failures
			// inside dialCollectors would also swallow a well-formed collector
			// that is merely unreachable — a transient the #3742
			// build-before-swap design deliberately keeps fatal so the old
			// exporters stay up instead of being replaced by a degraded set.
			// The collectors excluded here are decidable from config and can
			// never succeed later, which is exactly what makes dropping them
			// safe.
			//
			// The verdict is the SHARED config.FlowServerExcludedReason, the
			// same predicate `show security flow monitoring` and
			// `show forwarding-options` annotate NOT INSTALLED (#7422), so the
			// exporter and the show surfaces cannot disagree about which
			// collectors are live. Two spellings would drift in opposite
			// directions: an exporter skipping what the renderer calls active
			// lies to the operator, and one dialling what the renderer calls
			// dead cries wolf.
			if reason := config.FlowServerExcludedReason(fs); reason != "" {
				slog.Warn("flowexport: skipping flow-server that cannot receive records",
					"instance", inst.Name, "address", fs.Address, "port", fs.Port,
					"version", version, "reason", reason)
				continue
			}
			addr := fs.Address
			if fs.Port > 0 {
				// net.JoinHostPort brackets an IPv6 literal
				// ([2001:db8::9]:4739) so net.ResolveUDPAddr /
				// net.Dial in transport.go can parse it. A plain
				// "%s:%d" leaves an IPv6 address unbracketed
				// (2001:db8::9:4739), which they cannot parse, so
				// IPv6 flow collectors never dial (#2183).
				addr = net.JoinHostPort(fs.Address, strconv.Itoa(fs.Port))
			}
			// Effective per-collector source-address (#3745): a
			// flow-server-nested source-address (fs.SourceAddress) is the
			// per-collector override and wins; else the family output-level
			// default (fam.SourceAddress); else the inline-jflow default.
			// Resolving here — instead of applying one family-wide value to
			// every collector — lets two same-family collectors each bind
			// their own configured source (the pre-#3745 last-writer-wins
			// bug bound all collectors to the last nested source).
			srcAddr := fs.SourceAddress
			if srcAddr == "" {
				srcAddr = fam.SourceAddress
			}
			if srcAddr == "" {
				srcAddr = fam.InlineJflowSourceAddress
			}
			tmpl := fs.Version9Template
			if version == config.FlowServerVersionIPFIX {
				tmpl = fs.VersionIPFIXTemplate
			}
			collectors = append(collectors, CollectorConfig{
				Address:       addr,
				SourceAddress: srcAddr,
				Template:      tmpl,
				IsV6:          fe.isV6,
			})
			if fe.isV6 {
				servesInet6 = true
			} else {
				servesInet = true
			}
		}
	}
	return dedupeCollectors(collectors), servesInet, servesInet6
}

// dedupeCollectors removes duplicate collector destinations (same
// address + source-address + referenced template — see collectorKey)
// in-place, preserving first-seen order. This is the dedup key, NOT the
// grouping key: grouping is by template name alone (groupCollectorsByTemplate).
func dedupeCollectors(collectors []CollectorConfig) []CollectorConfig {
	seen := make(map[string]bool)
	deduped := collectors[:0]
	for _, c := range collectors {
		key := collectorKey(c)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, c)
		}
	}
	return deduped
}

// templateContext is the resolved per-template export parameters (the
// timeouts and the v9 field options) carried into every ExportConfig built
// for the collectors that referenced that template. #2461.
type templateContext struct {
	activeTimeout   time.Duration
	inactiveTimeout time.Duration
	refreshRate     time.Duration
	v9opts          V9TemplateOptions
	// includeFlowDir is the resolved `export-extension flow-dir` knob (#3270).
	// It is family-agnostic (set by both the v9 and IPFIX template-context
	// resolvers); the v9 path also mirrors it into v9opts.IncludeFlowDir for
	// the existing v9 template builder.
	includeFlowDir bool
}

// defaultTemplateContext is the timeout/refresh fallback used for a
// collector that referenced no template and when a referenced template
// name has no matching definition that overrides a field.
// #6769: the accepted range for the flow-export `seconds` knobs is
// config.MaxDurationSeconds — the same constant the schema typed leaves and the
// commit-time gate (validateFlowExportSecondsStrict) use, so no two layers can
// disagree about where the ceiling is.
//
// The defect the bound exists for: the compiler stores these as a plain `int`
// from `strconv.Atoi` with NO range check, and this file computed
// `time.Duration(n) * time.Second`. For a large enough n that multiply overflows
// int64 and WRAPS, and the wrapped value can be small and POSITIVE — which is
// the dangerous half, because `templateRefreshInterval` only rejects `<= 0`.
//
// gcd(1e9, 2^64) = 512, so the wrapped residues are multiples of 512 ns and the
// smallest positive one is exactly 512 ns: `template-refresh-rate seconds
// 20211507185753197` yields a 512 ns ticker, and 18446744074 yields 290 ms. The
// exporter then re-emits its templates thousands of times a second at every
// collector — a self-inflicted flood, and the reason this is a security issue
// rather than a cosmetic one.

// secondsToDuration converts a config `seconds` value, falling back for
// anything outside the accepted range.
//
// It replaces `if n > 0 { d = time.Duration(n) * time.Second }` at all three
// sites. Behaviour for a sane value is identical; what changes is that an
// out-of-range value now yields the DEFAULT instead of an overflowed one.
//
// Falling back rather than clamping to the maximum is deliberate: a value this
// far out of range is not an operator asking for 24h, it is a typo or a hostile
// config, and silently honouring it as "the largest thing we allow" would be
// inventing an intent. The default is what an absent knob already means.
func secondsToDuration(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 || int64(seconds) > config.MaxDurationSeconds {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func defaultTemplateContext() templateContext {
	return templateContext{
		activeTimeout:   60 * time.Second,
		inactiveTimeout: 15 * time.Second,
		refreshRate:     60 * time.Second,
	}
}

// v9TemplateContext resolves one NetFlow v9 template definition into a
// templateContext. A zero/absent field keeps the default.
func v9TemplateContext(tmpl *config.NetFlowV9Template) templateContext {
	tc := defaultTemplateContext()
	if tmpl == nil {
		return tc
	}
	// #6769: range-checked. An untyped seconds value large enough to overflow
	// `time.Duration(n) * time.Second` used to wrap into a sub-second ticker.
	tc.activeTimeout = secondsToDuration(tmpl.FlowActiveTimeout, tc.activeTimeout)
	tc.inactiveTimeout = secondsToDuration(tmpl.FlowInactiveTimeout, tc.inactiveTimeout)
	tc.refreshRate = secondsToDuration(tmpl.TemplateRefreshRate, tc.refreshRate)
	for _, ext := range tmpl.ExportExtensions {
		if ext == "flow-dir" {
			// #3270: flow-dir is applied again, derived in Go from the per-zone
			// sampling-direction (see ExportConfig.FlowDirection). Set both the
			// v9 template toggle and the family-agnostic flag.
			tc.v9opts.IncludeFlowDir = true
			tc.includeFlowDir = true
		}
	}
	return tc
}

// ipfixTemplateContext resolves one IPFIX template definition into a
// templateContext. IPFIX has no v9 field options, but it honours the
// `export-extension flow-dir` knob (#3270) the same way version9 does.
func ipfixTemplateContext(tmpl *config.NetFlowIPFIXTemplate) templateContext {
	tc := defaultTemplateContext()
	if tmpl == nil {
		return tc
	}
	// #6769: range-checked. An untyped seconds value large enough to overflow
	// `time.Duration(n) * time.Second` used to wrap into a sub-second ticker.
	tc.activeTimeout = secondsToDuration(tmpl.FlowActiveTimeout, tc.activeTimeout)
	tc.inactiveTimeout = secondsToDuration(tmpl.FlowInactiveTimeout, tc.inactiveTimeout)
	tc.refreshRate = secondsToDuration(tmpl.TemplateRefreshRate, tc.refreshRate)
	for _, ext := range tmpl.ExportExtensions {
		if ext == "flow-dir" {
			tc.includeFlowDir = true
		}
	}
	return tc
}

// sortedInstanceNames returns the sampling-instance names in deterministic
// (lexical) order so the resolved exporter wiring is restart-stable (#2462).
// Killing the Go-map-iteration order is half of the determinism fix; the
// other half is per-instance rate selection (no more first-nonzero
// map-order-dependent global rate).
func sortedInstanceNames(fo *config.ForwardingOptionsConfig) []string {
	names := make([]string, 0, len(fo.Sampling.Instances))
	for name := range fo.Sampling.Instances {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// collectorGroupKey is the grouping identity of an ExportConfig: the template
// a collector referenced AND the address family it was configured under
// (#2461 + #6811).
//
// Family belongs in the key because it is what makes the hot path a GATE
// rather than a SEARCH. With family in the key every group is single-family by
// construction, so the per-record work is one comparison against a precomputed
// group flag; keeping template-only groups and filtering conns per record
// would put a collector scan on the export path for every flow.
type collectorGroupKey struct {
	Template string
	IsV6     bool
}

// groupCollectorsByTemplateAndFamily partitions the deduplicated collector list
// into one slice per (template, address-family) pair, returning the group keys
// sorted deterministically. The empty Template holds collectors that referenced
// no template (the default group).
//
// Determinism (#2461): the group order and the per-group collector order are
// stable across process restarts, killing the Go-map-iteration nondeterminism
// that let a collector silently flip between templates. IsV6 is the secondary
// sort key so the ordering stays total.
//
// #6811: this used to key on template alone. Both families were merged into one
// collector slice before grouping, so a single instance configured with
// `family inet { flow-server A }` and `family inet6 { flow-server B }` produced
// ONE group holding A and B, and every export to that group reached both — IPv4
// records to the IPv6-only collector and vice versa.
// narrowToSurvivingFamilies9172 narrows an instance's family flags to the
// families that still have a template group AFTER the undefined-template drop
// in both resolvers (#9172, V076).
//
// collectInstanceVersionCollectors derives ServesInet / ServesInet6 from every
// eligible flow-server, and the resolvers then drop a group whose template is
// not defined. So an instance whose only inet6 group named an undefined
// template still claimed ServesInet6: an IPv6 record passed the instance-level
// gate, consumed a 1-in-N slot on the instance's shared counter, found no inet6
// group, and was exported nowhere. The surviving inet group's effective rate
// was diluted below the configured 1-in-N -- the rate an IPFIX collector is
// told by the #3748 sampler Options record and uses to scale volume (NetFlow v9
// carries no such record, but its records were diluted the same way) --
// exactly what the ServesInet/ServesInet6 contract exists to prevent
// ("a record of a family the instance does not serve must not consume a 1-in-N
// sampling slot"). Reachable on the tolerant load / peer-sync population; the
// strict commit gate rejects an undefined template reference.
func narrowToSurvivingFamilies9172(keys []collectorGroupKey, servesInet, servesInet6 bool, defined func(string) bool) (bool, bool) {
	var inet, inet6 bool
	for _, k := range keys {
		if k.Template != "" && !defined(k.Template) {
			continue
		}
		if k.IsV6 {
			inet6 = true
		} else {
			inet = true
		}
	}
	return servesInet && inet, servesInet6 && inet6
}

func groupCollectorsByTemplateAndFamily(collectors []CollectorConfig) ([]collectorGroupKey, map[collectorGroupKey][]CollectorConfig) {
	groups := make(map[collectorGroupKey][]CollectorConfig)
	for _, c := range collectors {
		k := collectorGroupKey{Template: c.Template, IsV6: c.IsV6}
		groups[k] = append(groups[k], c)
	}
	keys := make([]collectorGroupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Template != keys[j].Template {
			return keys[i].Template < keys[j].Template
		}
		return !keys[i].IsV6 && keys[j].IsV6
	})
	for _, k := range keys {
		cs := groups[k]
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].Address != cs[j].Address {
				return cs[i].Address < cs[j].Address
			}
			return cs[i].SourceAddress < cs[j].SourceAddress
		})
		groups[k] = cs
	}
	return keys, groups
}

// ResolveV9TemplateGroups resolves the NetFlow v9 export configuration into
// one ExportConfig per referenced template (#2461). Each group carries the
// timeouts / field options of the template its collectors actually
// referenced, instead of broadcasting the first map-iteration template to
// every collector. A collector referencing no template lands in the default
// group, which uses the lone configured template's parameters when there is
// exactly one (the common single-template case, unchanged behavior), else
// the built-in defaults. A collector referencing a template that is not
// defined is DROPPED (the strict commit-time gate
// validateFlowServerTemplateReferencesStrict rejects it on commit; this is
// the lenient-load backstop — export nothing for that collector rather than
// the wrong template). All groups share one sampleCounter so 1-in-N
// sampling stays global. Returns nil when no v9 export is configured.
func ResolveV9TemplateGroups(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) []*ExportConfig {
	if fo == nil || fo.Sampling == nil || len(fo.Sampling.Instances) == 0 {
		return nil
	}
	// #2129: a NetFlow v9 exporter must only start when `services
	// flow-monitoring version9` is configured.
	if svc == nil || svc.FlowMonitoring == nil || svc.FlowMonitoring.Version9 == nil {
		return nil
	}

	hasIPFIX := svc.FlowMonitoring.VersionIPFIX != nil
	defined := svc.FlowMonitoring.Version9.Templates
	// defaultCtx: when exactly one template is defined, an unreferenced
	// collector inherits it (preserves the pre-#2461 single-template case);
	// with zero or multiple templates it uses the built-in defaults.
	defaultCtx := defaultTemplateContext()
	if len(defined) == 1 {
		for _, tmpl := range defined {
			defaultCtx = v9TemplateContext(tmpl)
		}
	}

	var out []*ExportConfig
	// #2462: iterate instances in deterministic order; each instance is an
	// independent export policy (own collectors, own rate, own counter).
	for _, instName := range sortedInstanceNames(fo) {
		inst := fo.Sampling.Instances[instName]
		if inst == nil {
			continue
		}
		// #2136 per-flow-server version binding: collect only THIS instance's
		// flow-servers bound to NetFlow v9.
		collectors, servesInet, servesInet6 := collectInstanceVersionCollectors(inst, config.FlowServerVersion9, true, hasIPFIX)
		if len(collectors) == 0 {
			continue
		}
		rate := inst.InputRate
		shared := &atomic.Uint64{} // per-INSTANCE counter (#2462)
		keys, groups := groupCollectorsByTemplateAndFamily(collectors)
		servesInet, servesInet6 = narrowToSurvivingFamilies9172(keys, servesInet, servesInet6,
			func(name string) bool { _, ok := defined[name]; return ok })
		for _, key := range keys {
			name := key.Template
			ctx := defaultCtx
			if name != "" {
				tmpl, ok := defined[name]
				if !ok {
					// Undefined reference: drop (the strict gate rejects on
					// commit; lenient load exports nothing for these collectors).
					continue
				}
				ctx = v9TemplateContext(tmpl)
			}
			out = append(out, &ExportConfig{
				Collectors:          groups[key],
				InstanceName:        instName,
				TemplateName:        name,
				GroupIsV6:           key.IsV6,
				FlowActiveTimeout:   ctx.activeTimeout,
				FlowInactiveTimeout: ctx.inactiveTimeout,
				TemplateRefreshRate: ctx.refreshRate,
				V9TemplateOpts:      ctx.v9opts,
				IncludeFlowDir:      ctx.includeFlowDir,
				SamplingRate:        rate,
				ServesInet:          servesInet,
				ServesInet6:         servesInet6,
				sampleCounter:       shared,
			})
		}
	}
	return out
}

// ResolveIPFIXTemplateGroups is the IPFIX equivalent of
// ResolveV9TemplateGroups (#2461). Returns nil when no IPFIX export is
// configured.
func ResolveIPFIXTemplateGroups(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) []*ExportConfig {
	if fo == nil || fo.Sampling == nil || len(fo.Sampling.Instances) == 0 {
		return nil
	}
	if svc == nil || svc.FlowMonitoring == nil || svc.FlowMonitoring.VersionIPFIX == nil {
		return nil
	}

	hasV9 := svc.FlowMonitoring.Version9 != nil
	defined := svc.FlowMonitoring.VersionIPFIX.Templates
	defaultCtx := defaultTemplateContext()
	if len(defined) == 1 {
		for _, tmpl := range defined {
			defaultCtx = ipfixTemplateContext(tmpl)
		}
	}

	var out []*ExportConfig
	for _, instName := range sortedInstanceNames(fo) {
		inst := fo.Sampling.Instances[instName]
		if inst == nil {
			continue
		}
		collectors, servesInet, servesInet6 := collectInstanceVersionCollectors(inst, config.FlowServerVersionIPFIX, hasV9, true)
		if len(collectors) == 0 {
			continue
		}
		rate := inst.InputRate
		shared := &atomic.Uint64{} // per-INSTANCE counter (#2462)
		keys, groups := groupCollectorsByTemplateAndFamily(collectors)
		servesInet, servesInet6 = narrowToSurvivingFamilies9172(keys, servesInet, servesInet6,
			func(name string) bool { _, ok := defined[name]; return ok })
		for _, key := range keys {
			name := key.Template
			ctx := defaultCtx
			if name != "" {
				tmpl, ok := defined[name]
				if !ok {
					continue
				}
				ctx = ipfixTemplateContext(tmpl)
			}
			out = append(out, &ExportConfig{
				Collectors:          groups[key],
				InstanceName:        instName,
				TemplateName:        name,
				GroupIsV6:           key.IsV6,
				FlowActiveTimeout:   ctx.activeTimeout,
				FlowInactiveTimeout: ctx.inactiveTimeout,
				TemplateRefreshRate: ctx.refreshRate,
				IncludeFlowDir:      ctx.includeFlowDir,
				SamplingRate:        rate,
				ServesInet:          servesInet,
				ServesInet6:         servesInet6,
				sampleCounter:       shared,
			})
		}
	}
	return out
}

// BuildExportConfig resolves config types into a single NetFlow v9
// ExportConfig. It returns the FIRST group (deterministically the
// default/empty-template group, else the lowest template name; and within a
// template, inet before inet6) and is retained for TESTS that want a single
// aggregate config — it has no production callers. The daemon uses
// ResolveV9TemplateGroups so each collector gets its referenced template
// (#2461). Returns nil if no flow export is configured.
//
// #6811: groups are keyed on template AND address family, so for a
// multi-family instance this returns only ONE family's collectors. A caller
// that needs every collector must iterate ResolveV9TemplateGroups.
func BuildExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig {
	groups := ResolveV9TemplateGroups(svc, fo)
	if len(groups) == 0 {
		return nil
	}
	return groups[0]
}

// BuildIPFIXExportConfig is the IPFIX equivalent of BuildExportConfig,
// including the #6811 single-family caveat.
func BuildIPFIXExportConfig(svc *config.ServicesConfig, fo *config.ForwardingOptionsConfig) *ExportConfig {
	groups := ResolveIPFIXTemplateGroups(svc, fo)
	if len(groups) == 0 {
		return nil
	}
	return groups[0]
}

// BuildSamplingZones builds a map of zone ID to sampling direction flags.
// For each zone, it checks whether any interface in that zone has
// sampling input or output enabled on its unit.
func BuildSamplingZones(cfg *config.Config, zoneIDs map[string]uint16) map[uint16]SamplingDir {
	result := make(map[uint16]SamplingDir)
	for zoneName, zone := range cfg.Security.Zones {
		// A nil zone value is reachable on the tolerant/programmatic/
		// HA-peer-sync config path (the same nil-slot invariant the
		// dataplane SSOT defends). Skip it, otherwise the zone.Interfaces
		// deref below panics the flow-export apply path (#3492).
		if zone == nil {
			continue
		}
		zid, ok := zoneIDs[zoneName]
		if !ok {
			continue
		}
		var dir SamplingDir
		for _, ifaceRef := range zone.Interfaces {
			physName, unitNum, ok := parseIfaceRef(ifaceRef)
			if !ok {
				// A malformed unit suffix (non-numeric, signed, empty, or
				// trailing junk) used to be silently coerced to the wrong
				// unit (or unit 0). Warn once and skip rather than enable
				// sampling on a bogus unit (#2463).
				slog.Warn("flowexport: skipping malformed sampling-interface reference",
					"zone", zoneName, "interface", ifaceRef)
				continue
			}
			ifCfg, ok := cfg.Interfaces.Interfaces[physName]
			if !ok || ifCfg == nil {
				// comma-ok checks key-presence, not value-non-nil; a
				// (nil, true) entry would panic on ifCfg.Units below.
				continue
			}
			unit, ok := ifCfg.Units[unitNum]
			if !ok {
				continue
			}
			if unit.SamplingInput {
				dir.Input = true
			}
			if unit.SamplingOutput {
				dir.Output = true
			}
		}
		if dir.Input || dir.Output {
			result[zid] = dir
		}
	}
	return result
}

// ShouldExport checks whether a session close event should be exported based
// on the ingress/egress zone sampling configuration and sampling rate.
// A session is exported if the ingress zone has sampling input enabled OR
// the egress zone has sampling output enabled. If no SamplingZones are
// configured, all sessions are eligible. When SamplingRate > 0, only
// 1-in-N eligible sessions are actually exported.
func (ec *ExportConfig) ShouldExport(inZone, outZone uint16) bool {
	if len(ec.SamplingZones) > 0 {
		eligible := false
		if d, ok := ec.SamplingZones[inZone]; ok && d.Input {
			eligible = true
		}
		if d, ok := ec.SamplingZones[outZone]; ok && d.Output {
			eligible = true
		}
		if !eligible {
			return false
		}
	}
	// Apply 1-in-N sampling rate
	if ec.SamplingRate > 1 {
		n := ec.counter().Add(1)
		return n%uint64(ec.SamplingRate) == 0
	}
	return true
}

// FlowDirection derives the NetFlow/IPFIX flowDirection (IE 61) for a flow
// from the per-zone sampling-direction configuration (#3270). RFC 5102:
// 0 = ingress (observed at the ingress observation point), 1 = egress.
//
// xpf exports one record per bidirectional session anchored at the initiator
// tuple, so the direction is the OBSERVATION anchor, derived from which
// sampling direction selected the flow for export — exactly the signal
// ShouldExport already consults:
//
//   - the INGRESS zone has `sampling input`  -> 0 (ingress)
//   - else the EGRESS zone has `sampling output` -> 1 (egress)
//   - neither (or no sampling configured) -> 0 (default ingress)
//
// Ingress wins ties (both directions sampled): it matches the record's
// initiator-tuple anchor and Junos SRX inline active-flow-monitoring, which
// applies input sampling first. The result is a pure function of the flow's
// two zone IDs and the static sampling config; it is meaningful only when the
// group advertises IE 61 (IncludeFlowDir) — the encoder writes it only then,
// and a commit-time warning fires when flow-dir is enabled with no
// sampling-direction configured (the field would always read 0).
func (ec *ExportConfig) FlowDirection(inZone, outZone uint16) uint8 {
	if d, ok := ec.SamplingZones[inZone]; ok && d.Input {
		return 0
	}
	if d, ok := ec.SamplingZones[outZone]; ok && d.Output {
		return 1
	}
	return 0
}

// ServesFamily reports whether this instance's ExportConfig should handle a
// flow of the given address family (#2462). An instance that configured only
// inet collectors must not export an IPv6 flow (and vice versa) — that is the
// control-plane attribution that keeps two family-disjoint instances
// isolated. An ExportConfig is only ever built for a version the instance has
// at least one collector for, so at least one of ServesInet / ServesInet6 is
// always true here.
func (ec *ExportConfig) ServesFamily(isIPv6 bool) bool {
	if isIPv6 {
		return ec.ServesInet6
	}
	return ec.ServesInet
}

// counter returns the shared 1-in-N counter, lazily allocating a private
// one for a hand-built ExportConfig that the resolver did not wire. The
// sync.Once converges a concurrent first-call race on a single counter.
func (ec *ExportConfig) counter() *atomic.Uint64 {
	ec.counterOnce.Do(func() {
		if ec.sampleCounter == nil {
			ec.sampleCounter = &atomic.Uint64{}
		}
	})
	return ec.sampleCounter
}

// parseIfaceRef splits an interface reference into its physical name and
// logical unit, returning ok=false for a malformed unit suffix.
//
// A bare reference with no dot (e.g. "ge-0/0/0", "enp6s0") is a legitimate
// config form and maps to the implicit unit 0 — the parser stores zone
// interface tokens verbatim and a unit-less reference is valid Junos
// grammar, so it returns (ref, 0, true).
//
// A reference WITH a dot splits on the FINAL dot and the suffix after it
// must be a clean decimal unit number parsed by strconv.Atoi. Anything
// strconv.Atoi rejects — a non-numeric suffix ("foo"), trailing junk
// ("1abc2"), an empty suffix ("ge-0/0/0."), a sign or leading/trailing
// space ("-1", " 1") — returns ok=false so the caller can warn and skip
// rather than silently sample the wrong unit. The previous
// digit-accumulation scan accepted all of these: "1abc2" became unit 12,
// "foo" became unit 0, "-1" became unit 1.
func parseIfaceRef(ref string) (name string, unit int, ok bool) {
	dot := strings.LastIndexByte(ref, '.')
	if dot < 0 {
		// No unit suffix — implicit unit 0 (valid bare-name form).
		return ref, 0, true
	}
	suffix := ref[dot+1:]
	// Reject an empty suffix and any leading sign or space up front:
	// strconv.Atoi would accept "+1"/"-1" and return a signed value, but a
	// Junos unit number is an unsigned decimal with no sign or whitespace.
	if suffix == "" || suffix[0] < '0' || suffix[0] > '9' {
		return ref[:dot], 0, false
	}
	u, err := strconv.Atoi(suffix)
	if err != nil || u < 0 {
		return ref[:dot], 0, false
	}
	return ref[:dot], u, true
}

// FlowRecord holds the data for a single flow, shared by the NetFlow v9
// and IPFIX encoders.
type FlowRecord struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TOS       uint8
	TCPFlags  uint8
	Direction uint8
	InIf      uint32
	OutIf     uint32
	Packets   uint64
	Bytes     uint64
	// #3746: RFC 5103 biflow reverse (server→client) volume. Encoded ONLY by
	// the IPFIX exporter as the reverse Information Elements
	// reversePacketDeltaCount / reverseOctetDeltaCount under PEN 29305; NetFlow
	// v9 has no standard reverse element and leaves these unused (v9 exports the
	// initiator-direction volume only — see pkg/flowexport/README.md).
	RevPackets uint64
	RevBytes   uint64
	StartTime  time.Time
	EndTime    time.Time
	SrcMask    uint8
	DstMask    uint8
	IsIPv6     bool
	// #2526: post-NAT (translated) tuple — RFC 5103 / RFC 8158. These are
	// ALWAYS populated by ExportSessionClose: when the flow carried no NAT
	// the converter copies the pre-NAT tuple here (post == pre), matching
	// Junos/vSRX behaviour where the post-NAT IPFIX/NetFlow fields are
	// non-optional template fields present in every record.
	NATSrcIP   net.IP
	NATDstIP   net.IP
	NATSrcPort uint16
	NATDstPort uint16
}

// SessionCloseData holds parsed session data for flow export.
type SessionCloseData struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	IsIPv6   bool
	// #2526: post-NAT translated tuple parsed from the SESSION_CLOSE event's
	// NATSrcAddr/NATDstAddr by the daemon callback. A nil/unspecified NAT IP
	// (or zero port) means the dataplane reported no translation for that
	// half of the tuple; ExportSessionClose then falls back to the pre-NAT
	// value so the exported post-NAT field equals the pre-NAT field.
	NATSrcIP   net.IP
	NATDstIP   net.IP
	NATSrcPort uint16
	NATDstPort uint16
	// #2749: ingress ifindex (SNMP ifIndex) carried on the SESSION_CLOSE
	// wire frame ([128:132], stamped by the dataplane in #2615). The
	// exporter writes it into the re-introduced NetFlow IE 10 / IPFIX
	// ingressInterface field. 0 means the dataplane could not attribute an
	// ingress interface (the collector then sees ifIndex 0, the
	// conventional "unknown interface" value).
	InIf uint32
	// #2749: class-of-service / egress-interface attribution carried on the
	// SESSION_CLOSE wire frame's [144:152] block. TOS is the IP ToS byte
	// (DSCP<<2) observed on the forward direction → NetFlow srcTos (IE 5) /
	// IPFIX ipClassOfService. TCPFlags is the cumulative TCP control bits →
	// NetFlow tcpFlags (IE 6) / IPFIX tcpControlBits. OutIf is the egress SNMP
	// ifIndex → NetFlow OutputSNMP (IE 14) / IPFIX egressInterface. 0 means the
	// dataplane reported no value (collector "unknown" sentinel).
	TOS      uint8
	TCPFlags uint8
	OutIf    uint32
	// Direction is the NetFlow/IPFIX flowDirection (IE 61) derived in the
	// daemon callback from the per-zone sampling-direction via
	// ExportConfig.FlowDirection (#3270): 0 = ingress, 1 = egress. It is
	// always computed but only encoded by a group whose template enabled
	// `export-extension flow-dir` (IncludeFlowDir).
	Direction uint8
}

// flowStartTime resolves the flow record StartTime for a session-close event.
//
// #2465: when the close event carries a real session-creation timestamp
// (rec.Created, absolute Unix seconds stamped by the dataplane at session
// install), the StartTime is that exact instant — an accurate flow age for
// billing / audit / DDoS reconstruction / duration analytics. Only when the
// timestamp is absent (0 — an old-format frame or a synthesized close that
// carried no creation instant, e.g. the explicit clear-session / HA-purge
// paths) does it fall back to the legacy packet-count heuristic
// (estimateSessionDuration), subtracting the estimate from the record EndTime.
//
// The bool return reports whether the heuristic fallback was used, so callers
// can bump an "estimated-duration-used" counter for operator visibility.
func flowStartTime(rec logging.EventRecord, proto uint8) (time.Time, bool) {
	if rec.Created > 0 {
		// #2853: combine the integer Unix second (rec.Created) with the
		// sub-second nanosecond remainder (rec.CreatedNanos, carried on the
		// [44:48] wire slot) so the StartTime keeps millisecond resolution.
		// Pre-#2853 this truncated to the whole second, collapsing every flow
		// opened in the same second onto one start instant and flattening
		// IPFIX flowStartMilliseconds for short flows.
		created := time.Unix(int64(rec.Created), int64(rec.CreatedNanos))
		// Guard against a created stamp at or after the close time (clock skew
		// across the monotonic→wall conversion): clamp to the EndTime so the
		// flow never reports a negative duration.
		if created.After(rec.Time) {
			return rec.Time, false
		}
		return created, false
	}
	// Packet-count fallback. estimateSessionDuration saturates (#4923) so the
	// estimate is always bounded and non-negative, which keeps `start` at or
	// before the EndTime. Clamp explicitly anyway — mirroring the rec.Created
	// skew clamp above — so the StartTime <= EndTime invariant holds no matter
	// how the heuristic evolves and the flow never reports a negative duration.
	start := rec.Time.Add(-estimateSessionDuration(rec.SessionPkts, proto))
	if start.After(rec.Time) {
		return rec.Time, true
	}
	return start, true
}

// resolvePostNAT returns the post-NAT tuple for a flow record, falling back
// to the pre-NAT 5-tuple for any half the dataplane did not translate
// (#2526). The post-NAT IPFIX/NetFlow fields are non-optional template
// fields, so every record MUST carry them; when no NAT applied we export
// post == pre (Junos/vSRX behaviour) rather than zeros, so a collector
// always sees a usable translated tuple and a NAT'd flow is distinguishable
// from a non-NAT'd flow by post != pre.
//
// A NAT IP is treated as "absent" when it is nil or the unspecified address
// (the dataplane fills 0.0.0.0 / :: when it has no translation to report); a
// NAT port is treated as absent when zero. The address and port fall back
// independently so a flow with only address translation (or only port
// translation) reports the translated half and the pre-NAT other half.
func resolvePostNAT(srcIP, dstIP net.IP, srcPort, dstPort uint16,
	natSrcIP, natDstIP net.IP, natSrcPort, natDstPort uint16,
) (rSrcIP, rDstIP net.IP, rSrcPort, rDstPort uint16) {
	rSrcIP = srcIP
	if !natIPAbsent(natSrcIP) {
		rSrcIP = natSrcIP
	}
	rDstIP = dstIP
	if !natIPAbsent(natDstIP) {
		rDstIP = natDstIP
	}
	rSrcPort = srcPort
	if natSrcPort != 0 {
		rSrcPort = natSrcPort
	}
	rDstPort = dstPort
	if natDstPort != 0 {
		rDstPort = natDstPort
	}
	return
}

// natIPAbsent reports whether a parsed NAT IP carries no usable translation:
// nil, or the unspecified address (0.0.0.0 / ::), which the dataplane emits
// when the flow was not address-translated on that half.
func natIPAbsent(ip net.IP) bool {
	return ip == nil || ip.IsUnspecified()
}

// maxEstimatedSessionAge bounds the packet-count StartTime heuristic
// (estimateSessionDuration). It is a defensible ceiling on a session age no
// real flow exceeds, and — crucially (#4923) — it is ~9e12 below the int64
// nanosecond ceiling, so multiplying the per-packet estimate can never wrap
// time.Duration negative.
const maxEstimatedSessionAge = 366 * 24 * time.Hour

// estimateSessionDuration provides a rough duration estimate based on packet count.
func estimateSessionDuration(pkts uint64, proto uint8) time.Duration {
	if pkts == 0 {
		return 0
	}
	// Use a heuristic: TCP sessions ~100ms per packet average,
	// UDP/ICMP ~50ms per packet
	perPkt := 50 * time.Millisecond
	if proto == 6 { // TCP
		perPkt = 100 * time.Millisecond
	}
	// #4923: saturate before the multiply overflows int64. A SessionPkts count
	// beyond maxEstimatedSessionAge/perPkt (~92.2B TCP / ~184.5B non-TCP at the
	// int64 ceiling, well above this cap) would wrap the signed time.Duration
	// negative; the caller subtracts that from the record EndTime, moving
	// StartTime *after* EndTime. Cap the coarse estimate so the result is
	// always bounded, non-negative, and keeps StartTime <= EndTime.
	if pkts >= uint64(maxEstimatedSessionAge/perPkt) {
		return maxEstimatedSessionAge
	}
	return time.Duration(pkts) * perPkt
}

func collectorKey(c CollectorConfig) string {
	// #6811: family is part of the identity. The same address+source+template
	// configured under BOTH families is two distinct destinations-with-family,
	// not one duplicate: collapsing them would silently drop one family's
	// export to a collector the operator explicitly configured for both.
	fam := "4"
	if c.IsV6 {
		fam = "6"
	}
	return c.Address + "\x00" + c.SourceAddress + "\x00" + c.Template + "\x00" + fam
}
