package dataplane

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	repoRootForBoundaryCanary       = "../.."
	rootDataplaneImportForCanary    = "github.com/psaab/xpf/pkg/dataplane"
	ciliumEBPFImportForCanary       = "github.com/cilium/ebpf"
	makefileForCanary               = "../../Makefile"
	retirementBoundaryDocsForCanary = "../../docs/pr/1373-retire-ebpf-dataplane/README.md"
	userspaceXDPEntryProgForCanary  = "xdp_userspace_prog"
)

var legacyDataplaneImportAllowlist = map[string]string{
	"cmd/shimverify/main.go":                         "#1864 build-time verifier gate: thin wrapper over dataplane.VerifyUserspaceShimObject (verify-only, no production load path)",
	"cmd/shim-manifest/main.go":                      "#4977 build-time freshness gate: thin wrapper over dataplane.WriteUserspaceXDPManifest (regenerates the source→object manifest during make generate; no production load path)",
	"cmd/xpfd/main.go":                               "cleanup entry point (backend registration removed in #1527)",
	"pkg/api/metrics_userspace.go":                   "#2114 r6-F1: the userspace Status() probe resolves through dataplane.Unwrap so the daemon's live indirection does not erase the capability; probe-routing only, no legacy enforcement path",
	"pkg/cli/cli_show_chassis.go":                    "#2114 r2-B7: `show chassis forwarding` binds dataplane.Unwrap(dp) to a local so an empty cell yields a nil fwdstatus accessor; the old `dp == nil` gate is permanently false under the live indirection, and falling past it produced BufferKnown=true with BufferPercent=0 (peer of pkg/grpcapi/server_show_forwarding.go); render-only, no legacy enforcement path",
	"pkg/cli/cli_show_security_wireguard.go":         "#2114 r2-B4: the WireGuard renders bind dataplane.Unwrap(dp) to a local so an empty cell reports \"Dataplane not loaded\" instead of naming a backend KIND for a daemon with no backend (peer of pkg/grpcapi/server_show_security_text.go); render-only, no legacy enforcement path",
	"pkg/cli/top_talkers_bound_8597.go":              "#8597 K05: top-talkers collection SPLIT OUT of cli_show_flow.go (d93263fe5, -89 lines there, +236 here); same legacy session key/value types as its parent entry, no new dataplane surface. A relocation, not a new capability — the allowlist is keyed by FILENAME, so extracting code from an allowlisted file trips the canary while the boundary posture is unchanged",
	"pkg/cli/cli_show_system.go":                     "#2114 r6-F3: `show system buffers` binds dataplane.Unwrap(dp) to a local instead of asking `dp != nil`, so an empty cell reports \"Dataplane not loaded\" rather than a claim about a loaded backend's maps, and ONE resolution feeds both the publication check and the capability probe (r7); render-only, no legacy enforcement path",
	"pkg/grpcapi/server_diag_system_action.go":       "#2114 r6-F2/F3: clear-persistent-nat binds dataplane.PersistentNATTable to a LOCAL (one resolution per operation) and dataplaneActionError maps dataplane.ErrNotPublished to codes.Unavailable; control-plane only, no legacy enforcement path",
	"pkg/grpcapi/server_show_forwarding.go":          "#2114 r2-B7: `show chassis forwarding` binds dataplane.Unwrap(dp) to a local so an empty cell yields a nil fwdstatus accessor; the old `dp == nil` gate is permanently false under the live indirection, and falling past it made fwdstatus.Build set BufferKnown=true with BufferPercent=0 — a zero every downstream consumer is told to trust (peer of pkg/cli/cli_show_chassis.go); render-only, no legacy enforcement path",
	"pkg/grpcapi/server_show_system.go":              "#2114 r6-F3: `show system buffers` binds dataplane.Unwrap(dp) to a local instead of asking `dp != nil`, with ONE resolution feeding both decisions (r7) (peer of pkg/cli/cli_show_system.go); render-only, no legacy enforcement path",
	"pkg/api/api.go":                                 "shared REST helpers still reference legacy dataplane counters and types (#1540 split entry: apiRuntimeDataPlane interface, applyResult adapter)",
	"pkg/api/metrics.go":                             "Prometheus telemetry still reads legacy counters and metadata",
	"pkg/api/metrics_counters.go":                    "Prometheus map-counter collectors still call legacy dataplane reads (#1540 metrics split)",
	"pkg/api/metrics_nat.go":                         "Prometheus NAT pool collector still reads legacy dataplane (#1540 metrics split)",
	"pkg/api/metrics_sessions.go":                    "Prometheus session gauge collector still iterates legacy session tables (#1540 metrics split)",
	"pkg/api/nat.go":                                 "REST NAT handlers still read legacy NAT counters and metadata (#1540 handlers split)",
	"pkg/api/security.go":                            "REST security handlers still reference legacy policy/screen counter types (#1540 handlers split)",
	"pkg/api/sessions.go":                            "REST session reads still use legacy session types (#1540 rename of handlers_sessions.go)",
	"pkg/api/stats.go":                               "REST statistics handlers still read legacy global/interface/zone counters (#1540 handlers split)",
	"pkg/cli/cli.go":                                 "embedded CLI constructor still stores the legacy bridge",
	"pkg/cli/cli_clear.go":                           "clear commands still delete legacy session entries",
	"pkg/cli/cli_config.go":                          "#9841: commitApply syncs the just-published unconverged-MTU records onto the committed config via dataplane.LastApplyGenerationOf/LastApplyResultOf/SyncMTUUnconvergedWarnings (peer of the daemon wrapper); commit-warning projection only, no legacy enforcement path",
	"pkg/cli/runtime.go":                             "#1517 cliRuntime interface declares the narrow CLI surface; still depends on root pkg/dataplane type names (SessionKey, CounterValue, etc.) until those types move to a domain package",
	"pkg/cli/cli_show_cluster.go":                    "#1444: fabric redirect counters relocated from cli.go; still reads legacy GlobalCtrFabric* counter indices via dataplane.Telemetry",
	"pkg/cli/cli_show_flow.go":                       "flow display still uses legacy session keys and values",
	"pkg/cli/cli_show_interfaces.go":                 "#9841: show interfaces annotates unconverged MTUs via dataplane.LastApplyResultOf plus the shared Annotate/Render helpers (peer of pkg/grpcapi/server_show_interfaces.go); render-only, no legacy enforcement path",
	"pkg/cli/cli_show_nat.go":                        "NAT display still uses legacy NAT/session metadata",
	"pkg/cli/cli_show_security.go":                   "security display still uses legacy counters and filter types",
	"pkg/cli/cli_show_security_dispatch.go":          "#1444: handleShowSecurity dispatcher relocated from cli.go; still uses legacy MaxRulesPerPolicy + counter accessors",
	"pkg/cli/cli_show_security_filters.go":           "#7422: `show firewall` resolves a `then dscp` / `then traffic-class` rewrite through dataplane.ResolveFilterDSCP — the SAME resolver the snapshot builder uses — so the renderer cannot claim a CoS marking the builder dropped (mirrors daemon_nft.go's #3436 and netlink_lo0.go's #6387 use of the dataplane.DSCPValues SSOT); render-only, no legacy enforcement path",
	"pkg/cli/cli_show_security_log.go":               "#2158: split from cli_show_security.go; still reads legacy screen GlobalCtr* counter constants",
	"pkg/cli/cli_show_security_screen.go":            "#2158: split from cli_show_security.go; still reads legacy screen GlobalCtr* counter constants",
	"pkg/cli/cli_show_security_zones.go":             "#3643: `show security zones` distinguishes dataplane.ErrCounterNotPopulated (per-zone counters HIDE) from a genuine read error; still names root dataplane counter types",
	"pkg/cli/proto.go":                               "#1444: shared session/proto helpers relocated from cli.go; still names dataplane.SessState* enum and ProtoICMPv6 sentinel",
	"pkg/cli/session_filter.go":                      "#1444: session filter type + RPC fetchers relocated from cli.go; still uses legacy session key/value types and SessFlag*",
	"pkg/cluster/runtime.go":                         "clusterRuntime interface still names dataplane.SessionStore/Telemetry domain types from pkg/dataplane (#1518)",
	"pkg/cluster/sync.go":                            "session sync still installs sessions through the legacy bridge",
	"pkg/cluster/sync_bulk.go":                       "bulk sync still serializes legacy session entries",
	"pkg/cluster/sync_conn_gen.go":                   "#5661 pure-motion split of sync_conn.go: session-gen guards still reference legacy session types",
	"pkg/cluster/sync_conn_read.go":                  "#5661 pure-motion split of sync_conn.go: receive/dispatch path still references legacy session types",
	"pkg/cluster/sync_conn_sweep.go":                 "#5661 pure-motion split of sync_conn.go: incremental sync sweep still references legacy session types",
	"pkg/cluster/sync_conn_write.go":                 "#5661 pure-motion split of sync_conn.go: send/queue/journal path still references legacy session types",
	"pkg/cluster/sync_install_table_9752.go":         "#9752 round 5: install-table send/recv memos name legacy session key/value types for the cluster sync path (same types as sync_conn_gen.go guards); membership helpers only, no legacy enforcement path",
	"pkg/cluster/sync_protocol.go":                   "wire protocol still carries legacy session records",
	"pkg/conntrack/gc.go":                            "GC still uses root session-domain types until those move out of pkg/dataplane",
	"pkg/daemon/daemon.go":                           "daemon owns dataplane.RuntimeDataPlane; legacyDP() accessor was deleted in #1519 — only the RuntimeDataPlane field + LastApplyResultOf adapter remain",
	"pkg/daemon/daemon_apply_dataplane.go":           "#5661 pure-motion split of daemon_apply.go: dataplane+HA core apply still adapts legacy compile/apply metadata",
	"pkg/daemon/daemon_apply_tail.go":                "#5661 pure-motion split of daemon_apply.go: tail reconcile still names legacy dataplane types",
	"pkg/daemon/daemon_apply_mtu_warnings_9841.go":   "#9841: the commit wrapper syncs the just-published unconverged-MTU records onto the committed config via dataplane.LastApplyGenerationOf/SyncMTUUnconvergedWarnings; commit-warning projection only, no legacy enforcement path",
	"pkg/daemon/daemon_persistent_nat_show_8607.go":  "#8607 persistent-NAT SHOW refresh names dataplane.PersistentNATTable / PersistentNATBinding and resolves the published backend through dataplane.Unwrap, to fill the table `show security nat source persistent-nat-table` reads. It exists BECAUSE the legacy path is dead here: daemon_run.go sets gc.SkipSweep on the userspace backend, so the preserve hook on SessionStore.DeleteBatchKnown* (the table's only writer) and pnat.GC() are both unreachable. Display-only, no legacy enforcement path",
	"pkg/daemon/daemon_policy_invalidate.go":         "#4234 commit-time deletion-clear names root dataplane session types (SessionEntryV4/V6, DeleteReasonPolicyDeleted) to invalidate a deleted policy's live sessions via SessionStore.DeleteBatchKnown*; control-plane session lifecycle, no legacy enforcement path",
	"pkg/daemon/daemon_policy_invalidate_capture.go": "#6948 pre-publication invalidation capture names root dataplane session types (SessionEntryV4/V6, SessionKey/Value, DefaultPolicySentinelID) to snapshot the candidate sessions through SessionStore.ForEach* before the new policy snapshot is published; control-plane session lifecycle, no legacy enforcement path",
	"pkg/daemon/daemon_proxyarp.go":                  "#2197: extracted proxy-ARP/NDP reconcile + periodic re-assert still call dataplane.ReconcileProxyARP (control-plane kernel responder reconcile relocated from daemon_apply.go)",
	"pkg/daemon/daemon_flow.go":                      "flow logging still names legacy dataplane.GlobalCtr* counter indices via dataplane.Telemetry",
	"pkg/daemon/daemon_nft.go":                       "#3436: lo0/host-inbound nft generation resolves DSCP names through the dataplane.DSCPValues SSOT to emit numeric nft (avoids unloadable Junos DSCP tokens); generation-only, no legacy enforcement path",
	"pkg/daemon/rss_indirection.go":                  "#7497: RSS indirection reshaping bounds its fed queue set by dataplane.BindingQueuesPerIface, the binding-array stride SSOT, so RSS never steers to a queue index the planner cannot bind. The exemption is for a CONSTANT-ONLY import: one compile-time constant, no dataplane call and no legacy type. That limit is NOT ENFORCED — this canary is file-scoped and sees only THAT the package is imported, never WHAT is imported, so widening this file to a call or a type would keep this entry green while making its justification false. Do not cite it as precedent for a wider import without re-reading the file. Importing rather than re-spelling is deliberate: the stride already has three spellings pinned to each other (shim source, userspace-dp, pkg/dataplane), and a fourth literal in pkg/daemon would inherit none of that pin",
	"pkg/daemon/daemon_ha.go":                        "HA state updates still call legacy bridge methods",
	"pkg/daemon/daemon_ha_fabric.go":                 "fabric HA updates still call legacy bridge methods",
	"pkg/daemon/daemon_ha_userspace_convert.go":      "#4659 split of daemon_ha_userspace.go by concern: HA session (de)serialization names root dataplane session-domain types (SessionKey/SessionKeyV6/SessionValue/SessionValueV6) and SessFlag*/LogFlag* wire constants when crossing the legacy bridge",
	"pkg/daemon/daemon_ha_userspace_readiness.go":    "#4659 split of daemon_ha_userspace.go by concern: userspace HA readiness gate reads dataplane.EffectiveType/TypeUserspace to confirm the runtime forwarding path",
	"pkg/daemon/daemon_ha_userspace_stream.go":       "#4659 split of daemon_ha_userspace.go by concern: userspace HA session-delta streaming names dataplane.AFInet/AFInet6 address-family constants when crossing the legacy bridge",
	"pkg/daemon/daemon_run.go":                       "runtime wiring still uses legacy dataplane.ErrDPDKBackendRetired sentinel handling and constructs api/grpcapi/cli configs against the daemon-local probes in runtime_probes.go (#1519 capstone)",
	"pkg/daemon/daemon_run_bringup.go":               "#5661 pure-motion split of daemon_run.go: manager/config bring-up names dataplane.ErrDPDKBackendRetired/ErrEBPFBackendRetired/Manager",
	"pkg/daemon/daemon_run_naming.go":                "#5661 pure-motion split of daemon_run.go: interface naming reads dataplane.EffectiveType/TypeUserspace",
	"pkg/daemon/daemon_run_routehelpers.go":          "#5661 pure-motion split of daemon_run.go: applied-tunnel/route helpers read dataplane.EffectiveType/TypeUserspace",
	"pkg/daemon/runtime_probes.go":                   "#1519 daemon-local typed probes (apiDataPlane/grpcDataPlane/cliDataPlane/...) mirror downstream package-private interfaces; still name root dataplane types (SessionKey, CounterValue, etc.) until those move to a domain package",
	"pkg/daemon/daemon_dp_live.go":                   "#2114 r4 live management-surface indirection: forwards the UNION of the runtime_probes.go probes, so it names the same root dataplane types those probes do (SessionKey, CounterValue, ...) and moves with them",
	"pkg/logging/ringbuf.go":                         "#3057: RT_FLOW policy-name resolution references the shared wire-contract constants dataplane.DefaultPolicySentinelID + dataplane.DefaultPolicyName (the implicit default-policy sentinel ID, kept in lockstep with userspace-dp/src/policy.rs); display-only, no legacy enforcement path",
	"pkg/nftables/netlink_lo0.go":                    "#6387 PR-2: the additive netlink lo0-filter builder resolves DSCP names through the dataplane.DSCPValues SSOT to emit numeric nft-equivalent matches (mirrors daemon_nft.go's #3436 lo0/host-inbound DSCP resolution); ruleset-generation-only, no legacy enforcement path",
	"pkg/policymatch/zone_detail_summary.go":         "#3684: the shared `show security zones detail` policy-summary presenter renders the same wire-contract constants dataplane.DefaultPolicyName + dataplane.DefaultPolicySentinelID on the default-policy catch-all row (M13); display-only, no legacy enforcement path (peer of pkg/logging/ringbuf.go)",
	"pkg/grpcapi/apply_result.go":                    "gRPC apply metadata still adapts legacy apply results",
	"pkg/grpcapi/server_nat.go":                      "#2218 GetNATRuleStats keys NAT translation-hit counters with dataplane.NATCounterKey (type-namespaced ruleset/rule) so same-named SNAT/DNAT/static rules do not collide; shares the compiler's single key formatter",
	"pkg/grpcapi/runtime.go":                         "#1516 grpcRuntime interface declares the narrow gRPC dataplane surface; still depends on root pkg/dataplane type names (SessionKey, CounterValue, etc.) until those types move to a domain package",
	"pkg/grpcapi/server_helpers.go":                  "gRPC helpers still format legacy dataplane types and bridge runtime accessors",
	"pkg/grpcapi/server_sessions.go":                 "gRPC session RPCs still use legacy session types",
	"pkg/grpcapi/server_show_cluster_text.go":        "cluster text output still reads legacy dataplane state",
	"pkg/grpcapi/server_show_flow.go":                "flow text output still uses legacy session keys and values",
	"pkg/grpcapi/server_show_policies_text.go":       "policy text output still uses legacy counters",
	"pkg/grpcapi/server_show_security_text.go":       "security text output still uses legacy counters and filter types",
	"pkg/grpcapi/server_show_status.go":              "status output still reads legacy dataplane state",
	"pkg/grpcapi/server_show_zones.go":               "zone output still uses legacy dataplane types",
	"pkg/grpcapi/server_show_zones_text.go":          "#3643: zone text output distinguishes dataplane.ErrCounterNotPopulated (per-zone counters HIDE) from a genuine read error; still names root dataplane counter types",
	"pkg/grpcapi/server_show_interfaces.go":          "#9841: the ShowInterfacesDetail text twin annotates unconverged MTUs via the shared Annotate/Render helpers (peer of pkg/cli/cli_show_interfaces.go); render-only, no legacy enforcement path",
	"pkg/natshow/natshow.go":                         "#1687 shared NAT presenter Reader interface names root pkg/dataplane session/counter types (SessionKey, CounterValue, PersistentNATTable); net-neutral consolidation of the import that previously lived in server_show_nat.go + cli_show_nat.go",
	"pkg/natshow/source.go":                          "#1687 shared source-NAT rule-detail renderer iterates legacy SessionKey/Value via the Reader",
	"pkg/natshow/dest.go":                            "#1687 shared dest-NAT rule-detail renderer iterates legacy SessionKey/Value via the Reader",
	"pkg/natshow/persistent.go":                      "#1687 shared persistent-NAT renderers iterate legacy SessionKey/Value and read PersistentNATTable via the Reader",
	"pkg/natshow/walk.go":                            "#7315 the single cancellable session-walk authority the three walking NAT renderers route through; names the same legacy SessionKey/Value the per-renderer copies it replaced already named (net-neutral — walk.go took those iterations OUT of persistent.go/source.go/dest.go, it did not add a new consumer)",
}

// retainedShimBoundaryBuildTagAllowlist enumerates files that may
// carry non-default Go build constraints inside the retained shim
// boundary. Pre-#1476 this listed the 14 bpf2go-generated
// xpf{Xdp,Tc}*_x86_bpfel.go wrappers and the //go:build ignore
// `loader_stub.go` placeholder. #1476 deleted all of those, so the
// allowlist is now empty by intent — no retained file legitimately
// needs a non-default build constraint. The empty map is preserved
// (rather than the variable being deleted) because canary tests
// in this file still consult it and rely on the iteration shape;
// a nil map and an empty map are not identical for those callers.
var retainedShimBoundaryBuildTagAllowlist = map[string][]string{}

var userspaceShimAllowedMapTypes = map[string]ebpf.MapType{
	"dnat_table":    ebpf.Hash,
	"dnat_table_v6": ebpf.Hash, // #2406 SNAT66-return reverse-NAT steering

	"userspace_bindings":       ebpf.Array,
	"userspace_cpumap":         ebpf.CPUMap,
	"userspace_ctrl":           ebpf.Array,
	"userspace_fallback_stats": ebpf.PerCPUArray, // #4113 (F13): per-CPU, lost-update-free
	// #8249: per-CPU, and required to be so — native XDP runs one program
	// instance per RX queue on distinct CPUs, so a shared array would let one
	// CPU's fragment sighting decide another CPU's packet.
	"userspace_v6frag_scratch": ebpf.PerCPUArray,

	"userspace_heartbeat":        ebpf.Array,
	"userspace_ingress_ifaces":   ebpf.Hash,
	"userspace_interface_nat_v4": ebpf.Hash,
	"userspace_interface_nat_v6": ebpf.Hash,
	"userspace_local_v4":         ebpf.Hash,
	"userspace_local_v6":         ebpf.Hash,
	"userspace_sessions":         ebpf.Hash,
	"userspace_trace":            ebpf.Hash,
	"userspace_xsk_map":          ebpf.XSKMap,
}

var userspaceShimAllowedProgramTypes = map[string]ebpf.ProgramType{
	userspaceXDPEntryProgForCanary: ebpf.XDP,
}

var (
	rustMapAnnotationRE = regexp.MustCompile(`#\[\s*map\s*\([^)]*\bname\s*=\s*"([^"]+)"[^)]*\)\s*\]`)
	rustXDPFunctionRE   = regexp.MustCompile(`#\[\s*xdp\s*\]\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

func TestOperatorPackagesOnlyUseDocumentedLegacyDataplaneImports(t *testing.T) {
	t.Parallel()

	found := map[string]bool{}
	var unexpected []string
	for _, path := range productionGoFilesUnder(t, operatorRuntimeBoundaryRoots(t)) {
		for _, imp := range importPaths(t, path) {
			if imp != rootDataplaneImportForCanary {
				continue
			}
			rel := repoRelativePath(t, path)
			found[rel] = true
			if _, ok := legacyDataplaneImportAllowlist[rel]; !ok {
				unexpected = append(unexpected, rel)
			}
		}
	}

	var stale []string
	for rel := range legacyDataplaneImportAllowlist {
		if !found[rel] {
			stale = append(stale, rel)
		}
	}

	if len(unexpected) > 0 || len(stale) > 0 {
		sort.Strings(unexpected)
		sort.Strings(stale)
		t.Fatalf(
			"legacy pkg/dataplane import allowlist drift\nunexpected imports: %v\nstale allowlist entries: %v\nupdate legacyDataplaneImportAllowlist and the #1451 docs table with any intentional change",
			unexpected,
			stale,
		)
	}
}

func TestOperatorPackagesDoNotImportBPFArtifactsDirectly(t *testing.T) {
	t.Parallel()

	var violations []string
	for _, path := range productionGoFilesUnder(t, operatorRuntimeBoundaryRoots(t)) {
		rel := repoRelativePath(t, path)
		for _, imp := range importPaths(t, path) {
			if imp == ciliumEBPFImportForCanary || strings.HasPrefix(imp, ciliumEBPFImportForCanary+"/") {
				violations = append(violations, rel+" imports "+imp)
			}
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("operator packages must stay behind RuntimeDataPlane/BPF artifact boundaries: %v", violations)
	}
}

// TestDPDKBackendImportStaysBackendLocal was deleted in #1528 along
// with the pkg/dataplane/dpdk package itself. With the backend
// package gone, the Go compiler enforces the "no DPDK import"
// invariant directly — any operator-runtime file that tried to
// import the deleted path would fail to build. The remaining
// defense-in-depth canary lives at
// pkg/dataplane/runtime/import_canary_test.go:47 which keeps
// `github.com/psaab/xpf/pkg/dataplane/dpdk` in the forbidden-import
// list for the runtime package, blocking accidental revival.

// TestDPDKEBPFArtifactImportsStayAtLegacyAdapter was deleted in
// #1528. The canary policed a package (pkg/dataplane/dpdk) that no
// longer exists.

func TestUserspaceXDPGenerateTargetStaysDecoupledFromLegacyBPF(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(makefileForCanary)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	prereqs, recipe := makeTargetDefinition(t, string(data), "generate-userspace-xdp")
	if strings.TrimSpace(prereqs) != "" {
		t.Fatalf("generate-userspace-xdp must not depend on other Make targets, got prerequisites %q", prereqs)
	}
	if len(recipe) == 0 {
		t.Fatal("generate-userspace-xdp has no recipe")
	}
	body := strings.Join(recipe, "\n")
	for _, token := range []string{"generate", "-run", "build-userspace-xdp"} {
		if !strings.Contains(body, token) {
			t.Fatalf("generate-userspace-xdp recipe %q missing required token %q", body, token)
		}
	}
	for _, token := range []string{
		"bpf2go",
		"xdp_main",
		"tc_main",
		"bpf/xdp",
		"bpf/tc",
		"./pkg/dataplane/...",
		"generate-legacy-bpf",
		"$(MAKE)",
	} {
		if strings.Contains(body, token) {
			t.Fatalf("generate-userspace-xdp must not invoke legacy dataplane generation; recipe %q contains %q", body, token)
		}
	}
}

func TestUserspaceXDPGoGenerateRunSelectsOnlyShim(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("go", "generate", "-n", "-run", "^//go:generate bash build-userspace-xdp\\.sh$", "./pkg/dataplane")
	cmd.Dir = repoRootForBoundaryCanary
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go generate dry-run failed: %v\n%s", err, out)
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if len(lines) != 1 || lines[0] != "bash build-userspace-xdp.sh" {
		t.Fatalf("go generate shim dry-run selected %v, want only build-userspace-xdp.sh", lines)
	}
}

func TestUserspaceShimCompileAdapterCoversCompilerDataplaneCalls(t *testing.T) {
	t.Parallel()

	compilerCalls := compilerDataplaneCalls(t)
	adapterMethods := receiverMethods(t, "loader.go", "userspaceShimCompileDataplane")
	allowedRealMethods := map[string]bool{
		"BumpFIBGeneration": true, // uses the shim-owned fib_gen_map
		"GetPersistentNAT":  true, // in-memory compatibility table
		"IsLoaded":          true, // lifecycle state only
	}

	var missing []string
	for name := range compilerCalls {
		if allowedRealMethods[name] || adapterMethods[name] {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("userspaceShimCompileDataplane must explicitly no-op or allow compiler DataPlane calls: %v", missing)
	}
}

func TestUserspaceShimSharedMapsAreExplicitCompatibilitySet(t *testing.T) {
	t.Parallel()

	specs := userspaceShimSharedMapSpecs()
	names := make(map[string]bool, len(specs))
	for _, spec := range specs {
		names[spec.Name] = true
	}
	for _, name := range []string{
		"sessions",
		"sessions_v6",
		"dnat_table",
		"dnat_table_v6",
		"fib_gen_map",
		"fabric_fwd",
		"rg_active",
		"ha_watchdog",
		"session_id_gen",
		"global_counters",
		"flood_counters",
		"policy_counters",
		"zone_counters",
		"filter_counters",
		"interface_counters",
		"nat_port_counters",
		"nat_rule_counters",
	} {
		if !names[name] {
			t.Fatalf("userspace shim shared map %q missing from explicit compatibility set", name)
		}
	}
	for _, forbidden := range []string{
		"xdp_progs",
		"tc_progs",
		"iface_zone_map",
		"zone_configs",
		"policy_rules",
		"tx_ports",
		"redirect_capable",
	} {
		if names[forbidden] {
			t.Fatalf("userspace shim shared maps must not retain legacy pipeline map %q", forbidden)
		}
	}
}

func TestUserspaceXDPShimSourceMatchesRetainedObjectAllowlist(t *testing.T) {
	t.Parallel()

	foundMaps := map[string]string{}
	foundPrograms := map[string]string{}
	var forbidden []string

	for _, path := range rustSourceFilesUnder(t, filepath.Join(repoRootForBoundaryCanary, "userspace-xdp", "src")) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read userspace XDP shim source %s: %v", path, err)
		}
		text := string(data)
		rel := repoRelativePath(t, path)
		for _, token := range []string{
			"ProgramArray",
			".tail_call(",
			"bpf_tail_call",
		} {
			if strings.Contains(text, token) {
				forbidden = append(forbidden, fmt.Sprintf("%s contains %q", rel, token))
			}
		}
		for _, match := range rustMapAnnotationRE.FindAllStringSubmatchIndex(text, -1) {
			name := text[match[2]:match[3]]
			foundMaps[name] = fmt.Sprintf("%s at %s:%d", name, rel, lineForOffset(text, match[0]))
		}
		for _, match := range rustXDPFunctionRE.FindAllStringSubmatchIndex(text, -1) {
			name := text[match[2]:match[3]]
			foundPrograms[name] = fmt.Sprintf("%s at %s:%d", name, rel, lineForOffset(text, match[0]))
		}
	}

	unexpectedMaps, missingMaps := compareStringSetToAllowed(foundMaps, keysOfMapTypeAllowlist(userspaceShimAllowedMapTypes))
	unexpectedPrograms, missingPrograms := compareStringSetToAllowed(foundPrograms, keysOfProgramTypeAllowlist(userspaceShimAllowedProgramTypes))
	if len(forbidden) > 0 || len(unexpectedMaps) > 0 || len(missingMaps) > 0 ||
		len(unexpectedPrograms) > 0 || len(missingPrograms) > 0 {
		sort.Strings(forbidden)
		sort.Strings(unexpectedMaps)
		sort.Strings(missingMaps)
		sort.Strings(unexpectedPrograms)
		sort.Strings(missingPrograms)
		t.Fatalf(
			"userspace XDP shim source allowlist drift\nforbidden tail-call tokens: %v\nunexpected maps: %v\nmissing maps: %v\nunexpected programs: %v\nmissing programs: %v",
			forbidden,
			unexpectedMaps,
			missingMaps,
			unexpectedPrograms,
			missingPrograms,
		)
	}
}

func TestUserspaceXDPShimObjectMatchesRetainedCollectionAllowlist(t *testing.T) {
	t.Parallel()

	spec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load userspace XDP shim object: %v", err)
	}

	foundMaps := map[string]string{}
	var wrongMaps []string
	for name, mapSpec := range spec.Maps {
		foundMaps[name] = name
		if want, ok := userspaceShimAllowedMapTypes[name]; ok && mapSpec.Type != want {
			wrongMaps = append(wrongMaps, fmt.Sprintf("%s type %s, want %s", name, mapSpec.Type, want))
		}
	}
	foundPrograms := map[string]string{}
	var wrongPrograms []string
	for name, programSpec := range spec.Programs {
		foundPrograms[name] = name
		if want, ok := userspaceShimAllowedProgramTypes[name]; ok && programSpec.Type != want {
			wrongPrograms = append(wrongPrograms, fmt.Sprintf("%s type %s, want %s", name, programSpec.Type, want))
		}
	}

	unexpectedMaps, missingMaps := compareStringSetToAllowed(foundMaps, keysOfMapTypeAllowlist(userspaceShimAllowedMapTypes))
	unexpectedPrograms, missingPrograms := compareStringSetToAllowed(foundPrograms, keysOfProgramTypeAllowlist(userspaceShimAllowedProgramTypes))
	if len(wrongMaps) > 0 || len(unexpectedMaps) > 0 || len(missingMaps) > 0 ||
		len(wrongPrograms) > 0 || len(unexpectedPrograms) > 0 || len(missingPrograms) > 0 {
		sort.Strings(wrongMaps)
		sort.Strings(unexpectedMaps)
		sort.Strings(missingMaps)
		sort.Strings(wrongPrograms)
		sort.Strings(unexpectedPrograms)
		sort.Strings(missingPrograms)
		t.Fatalf(
			"userspace XDP shim object allowlist drift\nwrong map types: %v\nunexpected maps: %v\nmissing maps: %v\nwrong program types: %v\nunexpected programs: %v\nmissing programs: %v",
			wrongMaps,
			unexpectedMaps,
			missingMaps,
			wrongPrograms,
			unexpectedPrograms,
			missingPrograms,
		)
	}
}

func TestUserspaceDegradedPathCounterStatusStructAvoidsFallbackField(t *testing.T) {
	t.Parallel()

	tags := processStatusJSONTags(t)
	if !tags["degraded_path_counters"] {
		t.Fatal("ProcessStatus JSON tags missing degraded_path_counters")
	}
	if tags["fallback_counters"] {
		t.Fatal("ProcessStatus must not expose fallback_counters as a primary status field")
	}
}

func TestActiveDocsDescribeRetainedShimCountersAsDegradedPath(t *testing.T) {
	t.Parallel()

	docs := []string{
		filepath.Join(repoRootForBoundaryCanary, "docs", "afxdp-packet-processing.md"),
		filepath.Join(repoRootForBoundaryCanary, "docs", "userspace-xdp-pass-bootstrap-and-ipv6.md"),
		filepath.Join(repoRootForBoundaryCanary, "docs", "userspace-dataplane-architecture.md"),
		filepath.Join(repoRootForBoundaryCanary, "docs", "userspace-dataplane-gaps.md"),
		filepath.Join(repoRootForBoundaryCanary, "docs", "xpf-userspace-fw-deploy-verification.md"),
		retirementBoundaryDocsForCanary,
	}
	for _, path := range docs {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		lines := strings.Split(string(data), "\n")
		for idx, line := range lines {
			lower := strings.ToLower(line)
			switch {
			case strings.Contains(line, "fallback_counters") &&
				!lineWindowContains(lines, idx, "compatibility"):
				t.Fatalf("%s:%d exposes legacy fallback_counters JSON name", repoRelativePath(t, path), idx+1)
			case strings.Contains(lower, "xdp fallback stats"),
				strings.Contains(lower, "fallback counters"),
				strings.Contains(lower, "fallback reason"),
				strings.Contains(lower, "went via fallback"):
				t.Fatalf("%s:%d describes retained-shim counters with fallback wording: %s",
					repoRelativePath(t, path), idx+1, strings.TrimSpace(line))
			case strings.Contains(line, "userspace_fallback_stats") &&
				!lineWindowContains(lines, idx, "compatibility"):
				t.Fatalf("%s:%d mentions userspace_fallback_stats without compatibility context: %s",
					repoRelativePath(t, path), idx+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram(t *testing.T) {
	t.Parallel()

	violations := userspaceXDPEntryProgramViolations(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	})
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("userspace manager production code must only select userspaceXDPEntryProg: %v", violations)
	}
}

func TestUserspaceLinkCycleDoesNotReenterLegacyLoader(t *testing.T) {
	t.Parallel()

	violations, missing := linkCycleLegacyLoaderTargetViolations(t, productionLinkCycleLegacyLoaderTargets())
	if len(missing) > 0 {
		t.Fatalf("userspace link-cycle methods not found: %v", missing)
	}
	if len(violations) > 0 {
		t.Fatalf("userspace link-cycle code must not reference legacy loader or xdp_main_prog controls: %v", violations)
	}
}

type linkCycleLegacyLoaderTarget struct {
	path     string
	receiver string
	methods  map[string]bool
}

func productionLinkCycleLegacyLoaderTargets() []linkCycleLegacyLoaderTarget {
	return []linkCycleLegacyLoaderTarget{
		{
			// #4462 split moved the Manager link-cycle methods
			// (PrepareLinkCycle/NotifyLinkCycle) out of process.go into
			// process_linkcycle.go.
			path:     filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace", "process_linkcycle.go"),
			receiver: "Manager",
			methods: map[string]bool{
				"PrepareLinkCycle": false,
				"NotifyLinkCycle":  false,
			},
		},
		{
			// #2158 split moved the userspaceLinkController link-cycle methods
			// from manager.go into controllers.go.
			path:     filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace", "controllers.go"),
			receiver: "userspaceLinkController",
			methods: map[string]bool{
				"PrepareLinkCycle": false,
				"NotifyLinkCycle":  false,
			},
		},
		{
			path:     filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace", "legacy_dataplane.go"),
			receiver: "LegacyDataPlaneAdapter",
			methods: map[string]bool{
				"PrepareLinkCycle": false,
				"NotifyLinkCycle":  false,
			},
		},
	}
}

func linkCycleLegacyLoaderTargetViolations(
	t *testing.T,
	targets []linkCycleLegacyLoaderTarget,
) ([]string, []string) {
	t.Helper()

	var violations []string
	var missing []string
	for _, target := range targets {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, target.path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", target.path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || receiverTypeName(fn.Recv.List[0].Type) != target.receiver {
				continue
			}
			if _, ok := target.methods[fn.Name.Name]; !ok {
				continue
			}
			target.methods[fn.Name.Name] = true
			violations = append(violations, linkCycleLegacyLoaderFunctionViolations(
				t,
				fset,
				target.path,
				target.receiver,
				fn,
			)...)
		}
		for method, found := range target.methods {
			if !found {
				missing = append(missing, repoRelativePath(t, target.path)+":"+method)
			}
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
	}
	sort.Strings(violations)
	return violations, missing
}

func linkCycleLegacyLoaderFunctionViolations(
	t *testing.T,
	fset *token.FileSet,
	path string,
	receiver string,
	fn *ast.FuncDecl,
) []string {
	t.Helper()

	aliases := linkCycleLegacyLoaderRootAliases(receiver, receiverValueName(fn.Recv.List[0]))
	var violations []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if i < len(node.Lhs) {
					linkCycleRecordLegacyLoaderAlias(node.Lhs[i], rhs, aliases)
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range node.Values {
				if i < len(node.Names) {
					linkCycleRecordLegacyLoaderAlias(node.Names[i], rhs, aliases)
				}
			}
		case *ast.SelectorExpr:
			if !linkCycleLegacyLoaderSelector(node, aliases) {
				return true
			}
			pos := fset.Position(node.Pos())
			violations = append(violations, fmt.Sprintf(
				"%s:%d %s references %s.%s during userspace link-cycle handling",
				repoRelativePath(t, path),
				pos.Line,
				fn.Name.Name,
				linkCycleSelectorReceiverString(node.X),
				node.Sel.Name,
			))
		}
		return true
	})
	return violations
}

func receiverValueName(recv *ast.Field) string {
	if recv != nil && len(recv.Names) > 0 {
		return recv.Names[0].Name
	}
	return ""
}

func linkCycleLegacyLoaderRootAliases(receiver, name string) map[string]bool {
	aliases := map[string]bool{}
	if name == "" {
		return aliases
	}
	switch receiver {
	case "Manager":
		aliases[name] = true
		aliases[name+".bpfShim"] = true
	case "userspaceLinkController":
		aliases[name+".manager"] = true
		aliases[name+".manager.bpfShim"] = true
	case "LegacyDataPlaneAdapter":
		aliases[name] = true
		aliases[name+".DataPlane"] = true
	}
	return aliases
}

func linkCycleRecordLegacyLoaderAlias(lhs ast.Expr, rhs ast.Expr, aliases map[string]bool) {
	id, ok := lhs.(*ast.Ident)
	if !ok || id.Name == "_" {
		return
	}
	if linkCycleLegacyLoaderExpr(rhs, aliases) {
		aliases[id.Name] = true
		aliases[id.Name+".bpfShim"] = true
		aliases[id.Name+".DataPlane"] = true
	}
}

func linkCycleLegacyLoaderSelector(sel *ast.SelectorExpr, aliases map[string]bool) bool {
	if !linkCycleLegacyLoaderMethod(sel.Sel.Name) {
		return false
	}
	return linkCycleLegacyLoaderExpr(sel.X, aliases) || linkCycleLegacyManagerTypeExpr(sel.X)
}

func linkCycleLegacyLoaderMethod(name string) bool {
	switch name {
	case "Load", "Compile",
		"LoadUserspaceShim", "CompileUserspaceShim",
		"AttachXDP", "SelectUserspaceXDPShimEntryProgram",
		"SwapToUserspaceXDPShimEntryProgram", "SwapXDPEntryProg":
		return true
	default:
		return false
	}
}

func linkCycleLegacyLoaderExpr(expr ast.Expr, aliases map[string]bool) bool {
	expr = unparenCanaryExpr(expr)
	if aliases[canaryExprString(expr)] {
		return true
	}
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		switch e.Sel.Name {
		case "bpfShim", "DataPlane":
			return linkCycleLegacyLoaderExpr(e.X, aliases)
		default:
			return false
		}
	case *ast.TypeAssertExpr:
		return linkCycleLegacyLoaderExpr(e.X, aliases) && linkCycleLegacyManagerTypeExpr(e.Type)
	case *ast.CallExpr:
		sel, ok := unparenCanaryExpr(e.Fun).(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "managerOrErr" && linkCycleLegacyLoaderExpr(sel.X, aliases)
	default:
		return false
	}
}

func linkCycleLegacyManagerTypeExpr(expr ast.Expr) bool {
	expr = unparenCanaryExpr(expr)
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "Manager"
	case *ast.SelectorExpr:
		return canaryExprString(e) == "dataplane.Manager"
	case *ast.StarExpr:
		return linkCycleLegacyManagerTypeExpr(e.X)
	default:
		return false
	}
}

func linkCycleSelectorReceiverString(expr ast.Expr) string {
	if got := canaryExprString(unparenCanaryExpr(expr)); got != "" {
		return got
	}
	return fmt.Sprintf("%T", expr)
}

func unparenCanaryExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

func TestLinkCycleLegacyLoaderSelectorCatchesLegacyReceivers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expr string
		want bool
	}{
		{expr: "m.Load", want: true},
		{expr: "c.manager.CompileUserspaceShim", want: true},
		{expr: "a.Load", want: true},
		{expr: "m.bpfShim.LoadUserspaceShim", want: true},
		{expr: "c.manager.bpfShim.SelectUserspaceXDPShimEntryProgram", want: true},
		{expr: "a.DataPlane.Load", want: true},
		{expr: "mgr.Load", want: true},
		{expr: "shim.AttachXDP", want: true},
		{expr: "(*Manager).Load", want: true},
		{expr: "atomic.Load", want: false},
		{expr: "m.rgTransitionInFlight.Load", want: false},
		{expr: "m.somethingNew.Load", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			expr, err := parser.ParseExpr(tt.expr)
			if err != nil {
				t.Fatalf("parse %s: %v", tt.expr, err)
			}
			sel, ok := expr.(*ast.SelectorExpr)
			if !ok {
				t.Fatalf("%s parsed as %T, want *ast.SelectorExpr", tt.expr, expr)
			}
			aliases := map[string]bool{
				"m":                 true,
				"m.bpfShim":         true,
				"c.manager":         true,
				"c.manager.bpfShim": true,
				"a":                 true,
				"a.DataPlane":       true,
				"mgr":               true,
				"mgr.bpfShim":       true,
				"shim":              true,
				"dp":                true,
				"dp.DataPlane":      true,
			}
			if got := linkCycleLegacyLoaderSelector(sel, aliases); got != tt.want {
				t.Fatalf("linkCycleLegacyLoaderSelector(%s) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestUserspaceLinkCycleCanaryRejectsLegacyLoaderFixtures(t *testing.T) {
	t.Parallel()

	root := writeUserspaceEntryProgramFixture(t, map[string]string{
		"link_cycle.go": `
package userspace

import "github.com/psaab/xpf/pkg/dataplane"

type Manager struct {
	bpfShim shim
	rgTransitionInFlight counter
	somethingNew counter
}
type shim struct{}
type counter struct{}

func (m *Manager) PrepareLinkCycle() {
	m.somethingNew.Load()
}

func (m *Manager) NotifyLinkCycle() {
	mgr := m
	mgr.Load()
	m.bpfShim.LoadUserspaceShim()
	(*Manager).Load(m)
}

type userspaceLinkController struct {
	manager *Manager
}

func (c userspaceLinkController) PrepareLinkCycle() {
	mgr := c.manager
	mgr.Compile()
	shim := c.manager.bpfShim
	shim.CompileUserspaceShim(nil)
}

func (c userspaceLinkController) NotifyLinkCycle() {}

type LegacyDataPlaneAdapter struct {
	DataPlane any
}

func (a *LegacyDataPlaneAdapter) PrepareLinkCycle() {
	dp := a.DataPlane
	dp.Compile(nil)
	a.DataPlane.(*dataplane.Manager).Load()
}

func (a *LegacyDataPlaneAdapter) NotifyLinkCycle() {
	a.DataPlane.Load()
}
`,
	})
	path := filepath.Join(root, "link_cycle.go")
	targets := []linkCycleLegacyLoaderTarget{
		{
			path:     path,
			receiver: "Manager",
			methods: map[string]bool{
				"PrepareLinkCycle": false,
				"NotifyLinkCycle":  false,
			},
		},
		{
			path:     path,
			receiver: "userspaceLinkController",
			methods: map[string]bool{
				"PrepareLinkCycle": false,
				"NotifyLinkCycle":  false,
			},
		},
		{
			path:     path,
			receiver: "LegacyDataPlaneAdapter",
			methods: map[string]bool{
				"PrepareLinkCycle": false,
				"NotifyLinkCycle":  false,
			},
		},
	}
	violations, missing := linkCycleLegacyLoaderTargetViolations(t, targets)
	if len(missing) > 0 {
		t.Fatalf("fixture link-cycle methods not found: %v", missing)
	}
	assertCanaryViolationContains(t, violations, "NotifyLinkCycle", "mgr.Load")
	assertCanaryViolationContains(t, violations, "NotifyLinkCycle", "m.bpfShim.LoadUserspaceShim")
	assertCanaryViolationContains(t, violations, "NotifyLinkCycle", "*Manager.Load")
	assertCanaryViolationContains(t, violations, "PrepareLinkCycle", "mgr.Compile")
	assertCanaryViolationContains(t, violations, "PrepareLinkCycle", "shim.CompileUserspaceShim")
	assertCanaryViolationContains(t, violations, "PrepareLinkCycle", "dp.Compile")
	assertCanaryViolationContains(t, violations, "PrepareLinkCycle", "*ast.TypeAssertExpr.Load")
	assertCanaryViolationContains(t, violations, "NotifyLinkCycle", "a.DataPlane.Load")
}

func TestBPFShimEntryProgramStateIsNotJSONMutable(t *testing.T) {
	t.Parallel()

	if userspaceShimEntryProg != userspaceXDPEntryProgForCanary {
		t.Fatalf(
			"userspace shim entry-program constant = %q, want %q",
			userspaceShimEntryProg,
			userspaceXDPEntryProgForCanary,
		)
	}

	managerType := reflect.TypeOf(Manager{})
	if _, ok := managerType.FieldByName("XDPEntryProg"); ok {
		t.Fatal("dataplane.Manager must not export XDPEntryProg")
	}
	field, ok := managerType.FieldByName("xdpEntryProg")
	if !ok {
		t.Fatal("dataplane.Manager lost xdpEntryProg state field")
	}
	if field.PkgPath == "" {
		t.Fatal("dataplane.Manager.xdpEntryProg must stay unexported")
	}

	managerPtrType := reflect.TypeOf((*Manager)(nil))
	if _, ok := managerPtrType.MethodByName("SwapXDPEntryProg"); ok {
		t.Fatal("dataplane.Manager must not expose arbitrary SwapXDPEntryProg")
	}
	if _, ok := managerPtrType.MethodByName("SwapToUserspaceXDPShimEntryProgram"); !ok {
		t.Fatal("dataplane.Manager lost narrow userspace shim swap method")
	}

	data, err := json.Marshal(&Manager{xdpEntryProg: "xdp_bypassed"})
	if err != nil {
		t.Fatalf("marshal Manager: %v", err)
	}
	if strings.Contains(string(data), "xdp_bypassed") ||
		strings.Contains(string(data), "XDPEntryProg") ||
		strings.Contains(string(data), "xdpEntryProg") {
		t.Fatalf("xdpEntryProg leaked into JSON: %s", data)
	}

	var decoded Manager
	if err := json.Unmarshal(
		[]byte(`{"XDPEntryProg":"xdp_bypassed","xdpEntryProg":"xdp_bypassed"}`),
		&decoded,
	); err != nil {
		t.Fatalf("unmarshal Manager: %v", err)
	}
	if got := decoded.XDPEntryProgram(); got == "xdp_bypassed" {
		t.Fatalf("JSON mutated xdpEntryProg to %q", got)
	}
}

func TestUserspaceManagerDoesNotImportReflectOrUnsafe(t *testing.T) {
	t.Parallel()

	var violations []string
	for _, path := range productionGoFilesUnder(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	}) {
		rel := repoRelativePath(t, path)
		for _, imp := range importPaths(t, path) {
			switch imp {
			case "reflect", "unsafe":
				violations = append(violations, rel+" imports "+imp)
			}
		}
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("userspace production code must not use reflection/unsafe to bypass entry-program canaries: %v", violations)
	}
}

func TestRetainedUserspaceShimBoundaryCanaryRejectsExoticEscapes(t *testing.T) {
	t.Parallel()

	violations := retainedUserspaceShimBoundaryViolations(t, retainedUserspaceShimBoundaryPackageRoots(), true)
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("retained userspace shim boundary has exotic escape paths: %v", violations)
	}
}

func TestUserspaceXDPEntryProgramConstantNamesRetainedShim(t *testing.T) {
	t.Parallel()

	found, violations := userspaceXDPEntryProgramConstantDrift(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	})
	if len(found) != 1 || len(violations) > 0 {
		sort.Strings(found)
		sort.Strings(violations)
		t.Fatalf("userspaceXDPEntryProg constant drift\nfound: %v\nviolations: %v", found, violations)
	}
}

func TestRetainedUserspaceShimBoundaryCanaryRejectsExoticEscapeFixtures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			name: "positional_dataplane_manager_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

func hostile() *Manager {
	return &Manager{false, nil, "xdp_main_prog"}
}
`,
			},
			want: []string{"positional dataplane.Manager literal", "xdpEntryProg", "xdp_main_prog"},
		},
		{
			name: "positional_dataplane_manager_alias_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

type managerAlias = Manager

func hostileAlias() managerAlias {
	return managerAlias{false, nil, "xdp_main_prog"}
}
`,
			},
			want: []string{"positional dataplane.Manager literal", "xdpEntryProg", "xdp_main_prog"},
		},
		{
			name: "positional_dataplane_manager_defined_type_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

type managerCopy Manager

func hostileDefinedType() Manager {
	return Manager(managerCopy{false, nil, "xdp_main_prog"})
}
`,
			},
			want: []string{"positional dataplane.Manager literal", "xdpEntryProg", "xdp_main_prog"},
		},
		{
			name: "positional_dataplane_manager_in_slice_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

func hostileSlice() []Manager {
	return []Manager{{false, nil, "xdp_main_prog"}}
}
`,
			},
			want: []string{"positional dataplane.Manager literal", "xdpEntryProg", "xdp_main_prog"},
		},
		{
			name: "positional_dataplane_manager_in_array_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

func hostileArray() [1]Manager {
	return [1]Manager{{false, nil, "xdp_main_prog"}}
}
`,
			},
			want: []string{"positional dataplane.Manager literal", "xdpEntryProg", "xdp_main_prog"},
		},
		{
			name: "positional_dataplane_manager_in_map_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

func hostileMap() map[string]Manager {
	return map[string]Manager{"k": {false, nil, "xdp_main_prog"}}
}
`,
			},
			want: []string{"positional dataplane.Manager literal", "xdpEntryProg", "xdp_main_prog"},
		},
		{
			name: "cgo_import",
			files: map[string]string{
				"cgo.go": `
package userspace

import "C"
`,
			},
			want: []string{`imports "C"`},
		},
		{
			name: "go_linkname",
			files: map[string]string{
				"linkname.go": `
package userspace

//go:linkname hostile github.com/psaab/xpf/pkg/dataplane.(*Manager).xdpEntryProg
func hostile()
`,
			},
			want: []string{"uses //go:linkname"},
		},
		{
			name: "assembly_file",
			files: map[string]string{
				"escape.s": `
TEXT ·hostile(SB),$0-0
	RET
`,
			},
			want: []string{"has assembly file"},
		},
		{
			name: "precompiled_object_file",
			files: map[string]string{
				"escape.syso": "opaque object bytes",
			},
			want: []string{"has precompiled object file"},
		},
		{
			name: "go_cgo_compiler_directive",
			files: map[string]string{
				"directive.go": `
package userspace

//go:cgo_import_dynamic libc_malloc malloc "libc.so"
func hostile()
`,
			},
			want: []string{"uses //go:cgo_ compiler directive"},
		},
		{
			name: "go_build_tagged_file",
			files: map[string]string{
				"hidden.go": `
//go:build linux

package userspace
`,
			},
			want: []string{"has unallowlisted build constraint", "//go:build linux"},
		},
		{
			name: "legacy_build_tagged_file",
			files: map[string]string{
				"hidden_legacy.go": `
// +build legacy

package userspace
`,
			},
			want: []string{"has unallowlisted build constraint", "// +build legacy"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeBoundaryFixture(t, tc.files)
			violations := retainedUserspaceShimBoundaryViolations(t, []string{root}, false)
			assertCanaryViolationContains(t, violations, tc.want...)
		})
	}
}

func TestPositionalDataplaneManagerLiteralCanaryAllowsKeyedFixtures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		files map[string]string
	}{
		{
			name: "fully_keyed_dataplane_manager_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

func keyedFull() Manager {
	return Manager{loaded: true, programs: nil, xdpEntryProg: "xdp_userspace_prog"}
}
`,
			},
		},
		{
			name: "mixed_keyed_xdp_entry_prog_keyed_dataplane_manager_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

func keyedSparse() Manager {
	return Manager{loaded: true, xdpEntryProg: "xdp_userspace_prog"}
}
`,
			},
		},
		{
			name: "keyed_dataplane_manager_in_slice_literal",
			files: map[string]string{
				"manager.go": `
package dataplane

type Manager struct {
	loaded bool
	programs map[string]any
	xdpEntryProg string
}

func keyedSlice() []Manager {
	return []Manager{{loaded: true, programs: nil, xdpEntryProg: "xdp_userspace_prog"}}
}
`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeBoundaryFixture(t, tc.files)
			violations := retainedUserspaceShimBoundaryViolations(t, []string{root}, false)
			for _, v := range violations {
				if strings.Contains(v, "positional dataplane.Manager literal") {
					t.Fatalf("keyed Manager literal produced positional canary violation: %s\nall violations:\n%s",
						v, strings.Join(violations, "\n"))
				}
			}
		})
	}
}

func TestUserspaceEntryProgramCanaryAllowsCrossFileConstantFixture(t *testing.T) {
	t.Parallel()

	root := writeUserspaceEntryProgramFixture(t, map[string]string{
		"const.go": `
package userspace

const userspaceXDPEntryProg = "xdp_userspace_prog"

type shim struct{}
func (s *shim) SelectUserspaceXDPShimEntryProgram() {}
func (s *shim) SwapToUserspaceXDPShimEntryProgram() error { return nil }
type manager struct { bpfShim *shim }
`,
		"use.go": `
package userspace

func valid(m *manager) {
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	_ = m.bpfShim.SwapToUserspaceXDPShimEntryProgram()
}
`,
	})

	if got := userspaceXDPEntryProgramViolations(t, []string{root}); len(got) > 0 {
		t.Fatalf("valid cross-file constant fixture produced violations: %v", got)
	}
	found, drift := userspaceXDPEntryProgramConstantDrift(t, []string{root})
	if len(found) != 1 || len(drift) > 0 {
		t.Fatalf("valid cross-file constant drift\nfound: %v\nviolations: %v", found, drift)
	}
}

func TestUserspaceEntryProgramCanaryRejectsBypassFixtures(t *testing.T) {
	t.Parallel()

	base := `
package userspace

const userspaceXDPEntryProg = "xdp_userspace_prog"

type shim struct { XDPEntryProg string }
func (s *shim) SwapXDPEntryProg(name string) error { return nil }
type manager struct { bpfShim *shim }
func consume(v interface{}) {}
`

	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "literal_assignment",
			body: `
package userspace

func literalAssign(m *manager) {
	m.bpfShim.XDPEntryProg = "xdp_main_prog"
}
`,
			want: []string{"assigns XDPEntryProg from", "xdp_main_prog"},
		},
		{
			name: "shadowed_constant_name",
			body: `
package userspace

func shadowedConstName(m *manager) {
	userspaceXDPEntryProg := "xdp_main_prog"
	m.bpfShim.XDPEntryProg = userspaceXDPEntryProg
}
`,
			want: []string{"assigns XDPEntryProg from \"userspaceXDPEntryProg\""},
		},
		{
			name: "pointer_alias",
			body: `
package userspace

func pointerAlias(m *manager) {
	p := &m.bpfShim.XDPEntryProg
	_ = p
}
`,
			want: []string{"takes XDPEntryProg address"},
		},
		{
			name: "method_value_capture",
			body: `
package userspace

func methodValueCapture(m *manager) {
	swap := m.bpfShim.SwapXDPEntryProg
	_ = swap
}
`,
			want: []string{"captures SwapXDPEntryProg method value"},
		},
		{
			name: "method_value_pass",
			body: `
package userspace

func methodValuePass(m *manager) {
	consume(m.bpfShim.SwapXDPEntryProg)
}
`,
			want: []string{"passes SwapXDPEntryProg method value"},
		},
		{
			name: "method_value_return",
			body: `
package userspace

func methodValueReturn(m *manager) func(string) error {
	return m.bpfShim.SwapXDPEntryProg
}
`,
			want: []string{"returns SwapXDPEntryProg method value"},
		},
		{
			name: "direct_bad_call",
			body: `
package userspace

func directBadCall(m *manager) {
	_ = m.bpfShim.SwapXDPEntryProg("xdp_main_prog")
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "parenthesized_bad_call",
			body: `
package userspace

func parenBadCall(m *manager) {
	_ = (m.bpfShim.SwapXDPEntryProg)("xdp_main_prog")
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "method_expression_bad_call",
			body: `
package userspace

func methodExprBadCall(m *manager) {
	_ = ((*shim).SwapXDPEntryProg)(m.bpfShim, "xdp_main_prog")
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "raw_string_bad_call",
			body: `
package userspace

func rawStringBadCall(m *manager) {
	_ = m.bpfShim.SwapXDPEntryProg(` + "`xdp_main_prog`" + `)
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "slice_index_bad_call",
			body: `
package userspace

func sliceIndexBadCall(m *manager) {
	_ = ([]func(string) error{m.bpfShim.SwapXDPEntryProg})[0]("xdp_main_prog")
}
`,
			want: []string{"calls through SwapXDPEntryProg method value"},
		},
		{
			name: "double_parenthesized_bad_call",
			body: `
package userspace

func doubleParenBadCall(m *manager) {
	_ = ((m.bpfShim.SwapXDPEntryProg))("xdp_main_prog")
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "wrapped_method_value_callee",
			body: `
package userspace

func wrap(fn func(string) error) func(string) error { return fn }
func wrappedMethodValueCallee(m *manager) {
	_ = wrap(m.bpfShim.SwapXDPEntryProg)(userspaceXDPEntryProg)
}
`,
			want: []string{"calls through SwapXDPEntryProg method value"},
		},
		{
			name: "send_stmt_method_value",
			body: `
package userspace

func sendStmtBypass(m *manager) {
	ch := make(chan func(string) error, 1)
	ch <- m.bpfShim.SwapXDPEntryProg
}
`,
			want: []string{"sends SwapXDPEntryProg method value"},
		},
		{
			name: "range_stmt_method_value",
			body: `
package userspace

func rangeStmtBypass(m *manager) {
	for _, fn := range []func(string) error{m.bpfShim.SwapXDPEntryProg} {
		_ = fn(userspaceXDPEntryProg)
	}
}
`,
			want: []string{"ranges over SwapXDPEntryProg method value"},
		},
		{
			name: "map_key_method_value",
			body: `
package userspace

func mapKeyBypass(m *manager) {
	mapOfFuncs := make(map[any]bool)
	mapOfFuncs[m.bpfShim.SwapXDPEntryProg] = true
}
`,
			want: []string{"uses SwapXDPEntryProg method value"},
		},
		{
			name: "switch_tag_method_value",
			body: `
package userspace

func switchTagBypass(m *manager) {
	switch m.bpfShim.SwapXDPEntryProg {
	case nil:
	default:
	}
}
`,
			want: []string{"switches on SwapXDPEntryProg method value"},
		},
		{
			name: "json_unmarshal_bpf_shim",
			body: `
package userspace

import "encoding/json"

func jsonBypass(m *manager) {
	_ = json.Unmarshal([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_dot_import_unmarshal_bpf_shim",
			body: `
package userspace

import . "encoding/json"

func jsonDotImportBypass(m *manager) {
	_ = Unmarshal([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_new_decoder_decode_bpf_shim",
			body: `
package userspace

import (
	"encoding/json"
	"strings"
)

func jsonDecoderBypass(m *manager) {
	_ = json.NewDecoder(strings.NewReader(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `)).Decode(m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_dot_import_new_decoder_decode_bpf_shim",
			body: `
package userspace

import (
	. "encoding/json"
	"strings"
)

func jsonDotDecoderBypass(m *manager) {
	_ = NewDecoder(strings.NewReader(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `)).Decode(m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_unmarshal_alias_bpf_shim",
			body: `
package userspace

import "encoding/json"

func jsonUnmarshalAliasBypass(m *manager) {
	alias := m.bpfShim
	_ = json.Unmarshal([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), alias)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_new_decoder_alias_bpf_shim",
			body: `
package userspace

import (
	"encoding/json"
	"strings"
)

func jsonDecodeAliasBypass(m *manager) {
	alias := m.bpfShim
	_ = json.NewDecoder(strings.NewReader(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `)).Decode(alias)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_stored_decoder_decode_bpf_shim",
			body: `
package userspace

import (
	"encoding/json"
	"strings"
)

func jsonStoredDecoderBypass(m *manager) {
	dec := json.NewDecoder(strings.NewReader(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `))
	_ = dec.Decode(m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_func_var_unmarshal_bpf_shim",
			body: `
package userspace

import "encoding/json"

func jsonFuncVarBypass(m *manager) {
	decode := json.Unmarshal
	_ = decode([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_tuple_spread_bpf_shim",
			body: `
package userspace

import "encoding/json"

func tupleDecodeArgs(m *manager) ([]byte, *bpfShim) {
	return []byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim
}

func jsonTupleSpreadBypass(m *manager) {
	_ = json.Unmarshal(tupleDecodeArgs(m))
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_v2_unmarshal_bpf_shim",
			body: `
package userspace

import "encoding/json/v2"

func jsonV2Bypass(m *manager) {
	_ = json.Unmarshal([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "reflection_field_name",
			body: `
package userspace

func reflectionName() {
	_ = "XDPEntryProg"
}
`,
			want: []string{"uses XDPEntryProg string literal"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeUserspaceEntryProgramFixture(t, map[string]string{
				"base.go":   base,
				"bypass.go": tc.body,
			})
			violations := userspaceXDPEntryProgramViolations(t, []string{root})
			assertCanaryViolationContains(t, violations, tc.want...)
		})
	}
}

func TestDaemonRuntimeEntryPointUsesRuntimeDataPlane(t *testing.T) {
	t.Parallel()

	assertDaemonDPFieldIsRuntimeDataPlane(t)

	daemonRun := filepath.Join("..", "daemon", "daemon_run.go")
	if hasDaemonRuntimeConstructorCall(t, daemonRun, "NewDataPlane") {
		t.Fatal("daemon runtime startup must call NewRuntimeDataPlane, not NewDataPlane")
	}
	if !hasDaemonRuntimeConstructorCall(t, daemonRun, "NewRuntimeDataPlane") {
		t.Fatal("daemon runtime startup no longer calls dataplane.NewRuntimeDataPlane")
	}
}

// TestRetirementBoundaryDocsMentionDPDKPolicy was deleted in #1528.
// The canary pinned a "DPDK remains a separately supported backend"
// policy that is no longer true after the umbrella retirement in
// #1525. The associated section in
// docs/pr/1373-retire-ebpf-dataplane/README.md is rewritten as a
// retirement note pointing at #1525.

func TestRetirementBoundaryDocsMentionShimEscapeAssumptions(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(retirementBoundaryDocsForCanary)
	if err != nil {
		t.Fatalf("read retirement boundary docs: %v", err)
	}
	text := string(data)

	want := []string{
		"## #1504 Userspace Shim Boundary Escape Assumptions",
		"does not recurse",
		"positional `dataplane.Manager`",
		"`import \"C\"`",
		"`//go:linkname`",
		"`//go:cgo_*`",
		"`.s` / `.S`",
		"`.syso`",
		// `*_bpfel.go` and the bpf2go x86 build-tag stayed pinned
		// pre-#1476 to call out the legacy generated wrappers'
		// architecture constraint. After #1476 those files are gone.
		// `pkg/dataplane/loader_stub.go` and `//go:build ignore`
		// likewise referred to a deleted file; the canary now policed
		// emptiness rather than presence, so the tokens are dropped
		// from the want list.
	}
	for _, root := range retainedUserspaceShimBoundaryPackageRoots() {
		want = append(want, "`"+repoRelativePath(t, root)+"`")
	}
	var allowlistPaths []string
	for rel := range retainedShimBoundaryBuildTagAllowlist {
		allowlistPaths = append(allowlistPaths, rel)
	}
	sort.Strings(allowlistPaths)
	for _, rel := range allowlistPaths {
		want = append(want, "`"+rel+"`")
		for _, constraint := range retainedShimBoundaryBuildTagAllowlist[rel] {
			want = append(want, "`"+constraint+"`")
		}
	}
	var missing []string
	for _, token := range want {
		if !strings.Contains(text, token) {
			missing = append(missing, token)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("retirement docs do not mention shim escape assumptions: %v", missing)
	}
}

func TestRetirementBoundaryDocsMentionLegacyImportAllowlist(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(retirementBoundaryDocsForCanary)
	if err != nil {
		t.Fatalf("read retirement boundary docs: %v", err)
	}
	text := string(data)

	var missing []string
	for rel := range legacyDataplaneImportAllowlist {
		if !strings.Contains(text, rel) {
			missing = append(missing, rel)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("retirement docs do not mention allowlisted legacy imports: %v", missing)
	}
}

type canaryParsedGoFile struct {
	path string
	file *ast.File
}

func retainedUserspaceShimBoundaryPackageRoots() []string {
	return []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane"),
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	}
}

func retainedUserspaceShimBoundaryViolations(t *testing.T, roots []string, checkAllowlists bool) []string {
	t.Helper()

	fset := token.NewFileSet()
	var parsedFiles []canaryParsedGoFile
	var violations []string
	foundBuildTagAllowlist := map[string]bool{}

	for _, path := range retainedUserspaceShimBoundaryFilesUnder(t, roots) {
		rel := repoRelativePath(t, path)
		if isGoAssemblyFile(path) {
			violations = append(violations, rel+" has assembly file")
			continue
		}
		if isGoObjectFile(path) {
			violations = append(violations, rel+" has precompiled object file")
			continue
		}
		if !strings.HasSuffix(path, ".go") {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(data)
		buildConstraints := buildConstraintLines(text)
		if len(buildConstraints) > 0 {
			if _, ok := retainedShimBoundaryBuildTagAllowlist[rel]; ok {
				foundBuildTagAllowlist[rel] = true
			}
			if !buildConstraintLinesAllowed(rel, buildConstraints) {
				violations = append(violations, fmt.Sprintf(
					"%s has unallowlisted build constraint %q",
					rel,
					strings.Join(buildConstraints, "; "),
				))
			}
		}
		for _, line := range goCompilerDirectiveLines(text) {
			violations = append(violations, fmt.Sprintf("%s uses %s compiler directive %q", rel, goCompilerDirectiveKind(line), line))
		}

		file, err := parser.ParseFile(fset, path, data, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		parsedFiles = append(parsedFiles, canaryParsedGoFile{path: path, file: file})
		for _, imp := range file.Imports {
			if importPathLiteral(imp) == "C" {
				pos := fset.Position(imp.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d imports \"C\"", rel, pos.Line))
			}
		}
	}

	violations = append(violations, positionalDataplaneManagerLiteralViolations(t, fset, parsedFiles)...)

	if checkAllowlists {
		for rel := range retainedShimBoundaryBuildTagAllowlist {
			if !foundBuildTagAllowlist[rel] {
				violations = append(violations, rel+" stale retained shim boundary build-tag allowlist entry")
			}
		}
	}

	sort.Strings(violations)
	return violations
}

func retainedUserspaceShimBoundaryFilesUnder(t *testing.T, roots []string) []string {
	t.Helper()

	var files []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("read boundary dir %s: %v", root, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			if strings.HasSuffix(name, ".go") || isGoAssemblyFile(name) || isGoObjectFile(name) {
				files = append(files, filepath.Join(root, name))
			}
		}
	}
	sort.Strings(files)
	return files
}

func isGoAssemblyFile(path string) bool {
	return strings.HasSuffix(path, ".s") || strings.HasSuffix(path, ".S")
}

func isGoObjectFile(path string) bool {
	return strings.HasSuffix(path, ".syso")
}

func buildConstraintLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build") || strings.HasPrefix(trimmed, "// +build") {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

func buildConstraintLinesAllowed(rel string, got []string) bool {
	allowed, ok := retainedShimBoundaryBuildTagAllowlist[rel]
	if !ok || len(allowed) != len(got) {
		return false
	}
	for i := range allowed {
		if allowed[i] != got[i] {
			return false
		}
	}
	return true
}

func goCompilerDirectiveLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:linkname") || strings.HasPrefix(trimmed, "//go:cgo_") {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

func goCompilerDirectiveKind(line string) string {
	switch {
	case strings.HasPrefix(line, "//go:linkname"):
		return "//go:linkname"
	case strings.HasPrefix(line, "//go:cgo_"):
		return "//go:cgo_"
	default:
		return "//go:"
	}
}

func importPathLiteral(imp *ast.ImportSpec) string {
	if imp == nil || imp.Path == nil {
		return ""
	}
	path, err := strconv.Unquote(imp.Path.Value)
	if err != nil {
		return ""
	}
	return path
}

func positionalDataplaneManagerLiteralViolations(t *testing.T, fset *token.FileSet, files []canaryParsedGoFile) []string {
	t.Helper()

	xdpEntryProgIndex := dataplaneManagerFieldIndex(files, "xdpEntryProg")
	if xdpEntryProgIndex < 0 {
		return nil
	}
	managerTypeNames := packageLocalDataplaneManagerTypeNames(files)

	var violations []string
	for _, parsed := range files {
		if parsed.file.Name == nil || parsed.file.Name.Name != "dataplane" {
			continue
		}
		rel := repoRelativePath(t, parsed.path)
		var walk func(node ast.Node, inferredManager bool)
		walk = func(node ast.Node, inferredManager bool) {
			if node == nil {
				return
			}
			lit, isLit := node.(*ast.CompositeLit)
			if !isLit {
				ast.Inspect(node, func(n ast.Node) bool {
					if n == node {
						return true
					}
					if inner, ok := n.(*ast.CompositeLit); ok {
						walk(inner, false)
						return false
					}
					return true
				})
				return
			}

			// Decide whether this CompositeLit's element type is a
			// package-local dataplane.Manager. The explicit lit.Type form
			// covers the common `Manager{...}` and `aliasManager{...}`
			// shape; the inferred form covers nested literals inside a
			// slice / array / map container whose element / value type is
			// Manager, e.g. `[]Manager{{false, nil, "..."}}`. In the
			// inferred case Go omits the inner literal's type and we have
			// to propagate it from the enclosing container.
			isManagerLit := false
			switch {
			case lit.Type != nil && isPackageLocalDataplaneManagerLiteralType(lit.Type, managerTypeNames):
				isManagerLit = true
			case lit.Type == nil && inferredManager:
				isManagerLit = true
			}

			// Compute the inferred element / value type for nested literals
			// inside this CompositeLit so the recursive walk can decide
			// whether they should be treated as Manager literals.
			childInferred := false
			if lit.Type != nil {
				switch ty := lit.Type.(type) {
				case *ast.ArrayType:
					childInferred = isPackageLocalDataplaneManagerLiteralType(ty.Elt, managerTypeNames)
				case *ast.MapType:
					childInferred = isPackageLocalDataplaneManagerLiteralType(ty.Value, managerTypeNames)
				}
			}

			if isManagerLit && len(lit.Elts) > xdpEntryProgIndex {
				target := lit.Elts[xdpEntryProgIndex]
				// Only positional elements at xdpEntryProgIndex can leak
				// the program name. A keyed element at that slot is by
				// definition not setting xdpEntryProg positionally; if it
				// is the xdpEntryProg= keyed form the per-field canary in
				// userspaceXDPEntryProgramViolations catches it. Skipping
				// here avoids confusing empty-string violations on mixed
				// keyed / positional literals.
				if _, keyed := target.(*ast.KeyValueExpr); !keyed {
					pos := fset.Position(lit.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d uses positional dataplane.Manager literal that can set xdpEntryProg from %q",
						rel,
						pos.Line,
						canaryExprString(target),
					))
				}
			}

			for _, elt := range lit.Elts {
				switch e := elt.(type) {
				case *ast.CompositeLit:
					walk(e, childInferred)
				case *ast.KeyValueExpr:
					// Map-keyed: `"k": {...}` — value inherits container
					// value type; key does not.
					walk(e.Key, false)
					walk(e.Value, childInferred)
				default:
					walk(elt, false)
				}
			}
		}
		walk(parsed.file, false)
	}
	return violations
}

func dataplaneManagerFieldIndex(files []canaryParsedGoFile, fieldName string) int {
	for _, parsed := range files {
		if parsed.file.Name == nil || parsed.file.Name.Name != "dataplane" {
			continue
		}
		for _, decl := range parsed.file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != "Manager" {
					continue
				}
				st, ok := typeSpec.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				index := 0
				for _, field := range st.Fields.List {
					names := field.Names
					if len(names) == 0 {
						if fieldName == canaryExprString(field.Type) {
							return index
						}
						index++
						continue
					}
					for _, name := range names {
						if name.Name == fieldName {
							return index
						}
						index++
					}
				}
			}
		}
	}
	return -1
}

func packageLocalDataplaneManagerTypeNames(files []canaryParsedGoFile) map[string]bool {
	names := map[string]bool{"Manager": true}
	for changed := true; changed; {
		changed = false
		for _, parsed := range files {
			if parsed.file.Name == nil || parsed.file.Name.Name != "dataplane" {
				continue
			}
			for _, decl := range parsed.file.Decls {
				genDecl, ok := decl.(*ast.GenDecl)
				if !ok || genDecl.Tok != token.TYPE {
					continue
				}
				for _, spec := range genDecl.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if !ok || names[typeSpec.Name.Name] {
						continue
					}
					if names[typeIdentName(typeSpec.Type)] {
						names[typeSpec.Name.Name] = true
						changed = true
					}
				}
			}
		}
	}
	return names
}

func typeIdentName(expr ast.Expr) string {
	ident, ok := unparenExpr(expr).(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

func isPackageLocalDataplaneManagerLiteralType(expr ast.Expr, managerTypeNames map[string]bool) bool {
	return managerTypeNames[typeIdentName(expr)]
}

func userspaceXDPEntryProgramViolations(t *testing.T, roots []string) []string {
	t.Helper()

	fset, files := productionGoPackageFilesUnder(t, roots)
	var violations []string
	for _, parsed := range files {
		rel := repoRelativePath(t, parsed.path)
		parents := astParentMap(parsed.file)
		jsonImports, jsonDotImport := importNamesForPath(parsed.file, "encoding/json")
		jsonV2Imports, jsonV2DotImport := importNamesForPath(parsed.file, "encoding/json/v2")
		for name := range jsonV2Imports {
			jsonImports[name] = true
		}
		jsonDotImport = jsonDotImport || jsonV2DotImport
		ast.Inspect(parsed.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if !isXDPEntryProgField(lhs) {
						continue
					}
					var rhs ast.Expr
					if len(node.Rhs) == len(node.Lhs) {
						rhs = node.Rhs[i]
					}
					pos := fset.Position(lhs.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d assigns XDPEntryProg from %q",
						rel,
						pos.Line,
						canaryExprString(rhs),
					))
				}
			case *ast.CompositeLit:
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok || !isXDPEntryProgField(kv.Key) {
						continue
					}
					pos := fset.Position(kv.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d initializes XDPEntryProg from %q",
						rel,
						pos.Line,
						canaryExprString(kv.Value),
					))
				}
			case *ast.CallExpr:
				if isJSONDecoderIntoBPFShim(node, jsonImports, jsonDotImport) {
					pos := fset.Position(node.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d encoding/json decode into bpfShim can mutate XDPEntryProg",
						rel,
						pos.Line,
					))
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND && containsXDPEntryProgField(node.X) {
					pos := fset.Position(node.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d takes XDPEntryProg address",
						rel,
						pos.Line,
					))
				}
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(node.Value)
				if err == nil && value == "XDPEntryProg" {
					pos := fset.Position(node.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d uses XDPEntryProg string literal",
						rel,
						pos.Line,
					))
				}
			case *ast.SelectorExpr:
				if node.Sel.Name != "SwapXDPEntryProg" {
					return true
				}
				if violation := swapXDPEntryProgSelectorViolation(node, parents, fset, rel); violation != "" {
					violations = append(violations, violation)
				}
			}
			return true
		})
	}
	sort.Strings(violations)
	return violations
}

func userspaceXDPEntryProgramConstantDrift(t *testing.T, roots []string) ([]string, []string) {
	t.Helper()

	fset, files := productionGoPackageFilesUnder(t, roots)
	var found []string
	var violations []string
	for _, parsed := range files {
		ast.Inspect(parsed.file, func(n ast.Node) bool {
			valueSpec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range valueSpec.Names {
				if name.Name != "userspaceXDPEntryProg" {
					continue
				}
				pos := fset.Position(name.Pos())
				location := fmt.Sprintf("%s:%d", repoRelativePath(t, parsed.path), pos.Line)
				found = append(found, location)
				if len(valueSpec.Values) != len(valueSpec.Names) {
					violations = append(violations, location+" uses implicit or tuple value")
					continue
				}
				lit, ok := valueSpec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || lit.Value != strconv.Quote(userspaceXDPEntryProgForCanary) {
					violations = append(violations, fmt.Sprintf(
						"%s sets userspaceXDPEntryProg to %q, want %q",
						location,
						canaryExprString(valueSpec.Values[i]),
						userspaceXDPEntryProgForCanary,
					))
				}
			}
			return true
		})
	}
	sort.Strings(found)
	sort.Strings(violations)
	return found, violations
}

func TestConntrackGCConstructorDoesNotAcceptLegacyDataPlane(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "conntrack", "gc.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse conntrack/gc.go: %v", err)
	}

	var foundNewGC bool
	var legacyRefs []string
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && canaryExprString(sel) == "dataplane.DataPlane" {
			legacyRefs = append(legacyRefs, fset.Position(sel.Pos()).String())
		}

		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "NewGC" {
			return true
		}
		foundNewGC = true
		if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
			t.Fatal("conntrack.NewGC has no provider parameter")
		}
		if got := canaryExprString(fn.Type.Params.List[0].Type); got != "RuntimeDomainProvider" {
			t.Fatalf("conntrack.NewGC provider = %s, want RuntimeDomainProvider", got)
		}
		return true
	})

	if !foundNewGC {
		t.Fatal("conntrack.NewGC not found")
	}
	if len(legacyRefs) > 0 {
		t.Fatalf("conntrack GC must not reference dataplane.DataPlane: %v", legacyRefs)
	}
}

func compilerDataplaneCalls(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("compiler*.go")
	if err != nil {
		t.Fatalf("glob compiler files: %v", err)
	}
	out := make(map[string]bool)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "dp" {
				return true
			}
			out[sel.Sel.Name] = true
			return true
		})
	}
	return out
}

func receiverMethods(t *testing.T, path, receiverName string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if receiverTypeName(fn.Recv.List[0].Type) == receiverName {
			out[fn.Name.Name] = true
		}
	}
	return out
}

func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	default:
		return ""
	}
}

func productionGoPackageFilesUnder(t *testing.T, roots []string) (*token.FileSet, []canaryParsedGoFile) {
	t.Helper()

	fset := token.NewFileSet()
	packageFiles := map[string]*ast.File{}
	var files []canaryParsedGoFile
	for _, path := range productionGoFilesUnder(t, roots) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		packageFiles[path] = file
		files = append(files, canaryParsedGoFile{path: path, file: file})
	}
	resolveUserspaceXDPEntryProgramIdents(packageFiles)
	return fset, files
}

func astParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

func importNamesForPath(file *ast.File, importPath string) (map[string]bool, bool) {
	names := map[string]bool{}
	dotImport := false
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "." {
				dotImport = true
			}
			if imp.Name.Name != "_" && imp.Name.Name != "." {
				names[imp.Name.Name] = true
			}
			continue
		}
		names[defaultImportName(importPath)] = true
	}
	return names, dotImport
}

func defaultImportName(importPath string) string {
	last := importPath
	if idx := strings.LastIndex(last, "/"); idx >= 0 {
		last = last[idx+1:]
	}
	if strings.HasPrefix(last, "v") && len(last) > 1 {
		allDigits := true
		for _, r := range last[1:] {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			trimmed := strings.TrimSuffix(importPath, "/"+last)
			if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
				return trimmed[idx+1:]
			}
			return trimmed
		}
	}
	if idx := strings.LastIndex(importPath, "/"); idx >= 0 {
		return importPath[idx+1:]
	}
	return importPath
}

func resolveUserspaceXDPEntryProgramIdents(files map[string]*ast.File) {
	var packageConst *ast.Object
	for _, file := range files {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.CONST {
				continue
			}
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range valueSpec.Names {
					if name.Name == "userspaceXDPEntryProg" && name.Obj != nil && name.Obj.Kind == ast.Con {
						packageConst = name.Obj
					}
				}
			}
		}
	}
	if packageConst == nil {
		return
	}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if ok && ident.Name == "userspaceXDPEntryProg" && ident.Obj == nil {
				ident.Obj = packageConst
			}
			return true
		})
	}
}

func writeUserspaceEntryProgramFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	return writeBoundaryFixture(t, files)
}

func writeBoundaryFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
	}
	return root
}

func assertCanaryViolationContains(t *testing.T, violations []string, needles ...string) {
	t.Helper()

	for _, violation := range violations {
		matches := true
		for _, needle := range needles {
			if !strings.Contains(violation, needle) {
				matches = false
				break
			}
		}
		if matches {
			return
		}
	}
	t.Fatalf("no violation contains all of %q\nall violations:\n%s", needles, strings.Join(violations, "\n"))
}

func rustSourceFilesUnder(t *testing.T, root string) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".rs") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk Rust source under %s: %v", root, err)
	}
	sort.Strings(files)
	return files
}

func compareStringSetToAllowed(found map[string]string, allowed map[string]bool) ([]string, []string) {
	var unexpected []string
	for name, location := range found {
		if !allowed[name] {
			unexpected = append(unexpected, location)
		}
	}
	var missing []string
	for name := range allowed {
		if _, ok := found[name]; !ok {
			missing = append(missing, name)
		}
	}
	return unexpected, missing
}

func keysOfMapTypeAllowlist(values map[string]ebpf.MapType) map[string]bool {
	keys := make(map[string]bool, len(values))
	for name := range values {
		keys[name] = true
	}
	return keys
}

func keysOfProgramTypeAllowlist(values map[string]ebpf.ProgramType) map[string]bool {
	keys := make(map[string]bool, len(values))
	for name := range values {
		keys[name] = true
	}
	return keys
}

func lineForOffset(text string, offset int) int {
	if offset > len(text) {
		offset = len(text)
	}
	return strings.Count(text[:offset], "\n") + 1
}

func lineWindowContains(lines []string, idx int, needle string) bool {
	start := idx - 2
	if start < 0 {
		start = 0
	}
	end := idx + 2
	if end >= len(lines) {
		end = len(lines) - 1
	}
	needle = strings.ToLower(needle)
	for i := start; i <= end; i++ {
		if strings.Contains(strings.ToLower(lines[i]), needle) {
			return true
		}
	}
	return false
}

func processStatusJSONTags(t *testing.T) map[string]bool {
	t.Helper()

	path := filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace", "protocol_status.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "ProcessStatus" {
				continue
			}
			st, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("ProcessStatus in %s is not a struct", path)
			}
			tags := map[string]bool{}
			for _, field := range st.Fields.List {
				if field.Tag == nil {
					continue
				}
				rawTag, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					t.Fatalf("unquote ProcessStatus tag %s: %v", field.Tag.Value, err)
				}
				jsonTag := reflect.StructTag(rawTag).Get("json")
				name, _, _ := strings.Cut(jsonTag, ",")
				if name != "" && name != "-" {
					tags[name] = true
				}
			}
			return tags
		}
	}
	t.Fatalf("ProcessStatus not found in %s", path)
	return nil
}

func isXDPEntryProgField(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "XDPEntryProg"
	case *ast.SelectorExpr:
		return e.Sel.Name == "XDPEntryProg"
	default:
		return false
	}
}

func isUserspaceXDPEntryProgExpr(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok || ident.Name != "userspaceXDPEntryProg" {
		return false
	}
	return ident.Obj != nil && ident.Obj.Kind == ast.Con
}

func containsXDPEntryProgField(expr ast.Expr) bool {
	return containsExpr(expr, isXDPEntryProgField)
}

func isJSONDecoderIntoBPFShim(call *ast.CallExpr, jsonImports map[string]bool, jsonDotImport bool) bool {
	if (len(jsonImports) == 0 && !jsonDotImport) || len(call.Args) == 0 {
		return false
	}

	if isJSONUnmarshalCallee(call.Fun, jsonImports, jsonDotImport) {
		switch len(call.Args) {
		case 0:
			return false
		case 1:
			return callReturnsBPFShimTuple(call.Args[0], map[*ast.Object]bool{})
		default:
			return containsBPFShimReference(call.Args[1])
		}
	}

	if len(call.Args) != 1 {
		return false
	}
	if sel, ok := unparenExpr(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Decode" {
		if !isJSONNewDecoderReceiver(sel.X, jsonImports, jsonDotImport, map[*ast.Object]bool{}) {
			return false
		}
		return containsBPFShimReference(call.Args[0])
	}
	return false
}

func isJSONUnmarshalCallee(expr ast.Expr, jsonImports map[string]bool, jsonDotImport bool) bool {
	switch fun := unparenExpr(expr).(type) {
	case *ast.SelectorExpr:
		pkg, ok := unparenExpr(fun.X).(*ast.Ident)
		return ok && fun.Sel.Name == "Unmarshal" && jsonImports[pkg.Name]
	case *ast.Ident:
		if jsonDotImport && fun.Name == "Unmarshal" {
			return true
		}
		return identResolvesToJSONUnmarshal(fun, jsonImports, jsonDotImport, map[*ast.Object]bool{})
	default:
		return false
	}
}

func identResolvesToJSONUnmarshal(ident *ast.Ident, jsonImports map[string]bool, jsonDotImport bool, seen map[*ast.Object]bool) bool {
	if ident == nil || ident.Obj == nil {
		return false
	}
	obj := ident.Obj
	if seen[obj] {
		return false
	}
	seen[obj] = true
	defer delete(seen, obj)

	switch decl := obj.Decl.(type) {
	case *ast.AssignStmt:
		if len(decl.Rhs) != len(decl.Lhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			lhsIdent, ok := lhs.(*ast.Ident)
			if ok && lhsIdent.Obj == obj {
				return isJSONUnmarshalCallee(decl.Rhs[i], jsonImports, jsonDotImport)
			}
		}
	case *ast.ValueSpec:
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, name := range decl.Names {
			if name.Obj == obj {
				return isJSONUnmarshalCallee(decl.Values[i], jsonImports, jsonDotImport)
			}
		}
	}
	return false
}

func isJSONNewDecoderReceiver(expr ast.Expr, jsonImports map[string]bool, jsonDotImport bool, seen map[*ast.Object]bool) bool {
	switch e := unparenExpr(expr).(type) {
	case *ast.CallExpr:
		return isJSONNewDecoderCall(e, jsonImports, jsonDotImport)
	case *ast.Ident:
		return identResolvesToJSONNewDecoder(e, jsonImports, jsonDotImport, seen)
	default:
		return false
	}
}

func isJSONNewDecoderCall(call *ast.CallExpr, jsonImports map[string]bool, jsonDotImport bool) bool {
	if call == nil {
		return false
	}
	switch fun := unparenExpr(call.Fun).(type) {
	case *ast.SelectorExpr:
		pkg, ok := unparenExpr(fun.X).(*ast.Ident)
		return ok && fun.Sel.Name == "NewDecoder" && jsonImports[pkg.Name]
	case *ast.Ident:
		return jsonDotImport && fun.Name == "NewDecoder"
	default:
		return false
	}
}

func identResolvesToJSONNewDecoder(ident *ast.Ident, jsonImports map[string]bool, jsonDotImport bool, seen map[*ast.Object]bool) bool {
	if ident == nil || ident.Obj == nil {
		return false
	}
	obj := ident.Obj
	if seen[obj] {
		return false
	}
	seen[obj] = true
	defer delete(seen, obj)

	switch decl := obj.Decl.(type) {
	case *ast.AssignStmt:
		if len(decl.Rhs) != len(decl.Lhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			lhsIdent, ok := lhs.(*ast.Ident)
			if ok && lhsIdent.Obj == obj {
				return isJSONNewDecoderReceiver(decl.Rhs[i], jsonImports, jsonDotImport, seen)
			}
		}
	case *ast.ValueSpec:
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, name := range decl.Names {
			if name.Obj == obj {
				return isJSONNewDecoderReceiver(decl.Values[i], jsonImports, jsonDotImport, seen)
			}
		}
	}
	return false
}

func callReturnsBPFShimTuple(expr ast.Expr, seen map[*ast.Object]bool) bool {
	call, ok := unparenExpr(expr).(*ast.CallExpr)
	if !ok {
		return false
	}

	switch fun := unparenExpr(call.Fun).(type) {
	case *ast.FuncLit:
		return blockReturnsBPFShimTuple(fun.Body, seen)
	case *ast.Ident:
		return identReturnsBPFShimTuple(fun, seen)
	default:
		return false
	}
}

func identReturnsBPFShimTuple(ident *ast.Ident, seen map[*ast.Object]bool) bool {
	if ident == nil || ident.Obj == nil {
		return false
	}
	obj := ident.Obj
	if seen[obj] {
		return false
	}
	seen[obj] = true
	defer delete(seen, obj)

	switch decl := obj.Decl.(type) {
	case *ast.FuncDecl:
		return blockReturnsBPFShimTuple(decl.Body, seen)
	case *ast.AssignStmt:
		if len(decl.Rhs) != len(decl.Lhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			lhsIdent, ok := lhs.(*ast.Ident)
			if ok && lhsIdent.Obj == obj {
				return callReturnsBPFShimTuple(decl.Rhs[i], seen)
			}
		}
	case *ast.ValueSpec:
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, name := range decl.Names {
			if name.Obj == obj {
				return callReturnsBPFShimTuple(decl.Values[i], seen)
			}
		}
	}
	return false
}

func blockReturnsBPFShimTuple(block *ast.BlockStmt, seen map[*ast.Object]bool) bool {
	if block == nil {
		return false
	}
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, result := range ret.Results {
			if containsBPFShimReferenceExpr(result, seen) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func containsBPFShimSelector(expr ast.Expr) bool {
	return containsExpr(expr, func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "bpfShim"
	})
}

func containsBPFShimReference(expr ast.Expr) bool {
	return containsBPFShimReferenceExpr(expr, map[*ast.Object]bool{})
}

func containsBPFShimReferenceExpr(expr ast.Expr, seen map[*ast.Object]bool) bool {
	if expr == nil {
		return false
	}
	if containsBPFShimSelector(expr) {
		return true
	}

	switch e := unparenExpr(expr).(type) {
	case *ast.Ident:
		return containsBPFShimFromIdent(e, seen)
	case *ast.SelectorExpr:
		return containsBPFShimReferenceExpr(e.X, seen)
	case *ast.StarExpr:
		return containsBPFShimReferenceExpr(e.X, seen)
	case *ast.UnaryExpr:
		return containsBPFShimReferenceExpr(e.X, seen)
	case *ast.IndexExpr:
		return containsBPFShimReferenceExpr(e.X, seen) || containsBPFShimReferenceExpr(e.Index, seen)
	case *ast.IndexListExpr:
		if containsBPFShimReferenceExpr(e.X, seen) {
			return true
		}
		for _, idx := range e.Indices {
			if containsBPFShimReferenceExpr(idx, seen) {
				return true
			}
		}
	}

	return false
}

func containsBPFShimFromIdent(ident *ast.Ident, seen map[*ast.Object]bool) bool {
	if ident == nil || ident.Obj == nil {
		return false
	}
	obj := ident.Obj
	if seen[obj] {
		return false
	}
	seen[obj] = true
	defer delete(seen, obj)

	switch decl := obj.Decl.(type) {
	case *ast.AssignStmt:
		if len(decl.Rhs) != len(decl.Lhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			lhsIdent, ok := lhs.(*ast.Ident)
			if ok && lhsIdent.Obj == obj {
				return containsBPFShimReferenceExpr(decl.Rhs[i], seen)
			}
		}
	case *ast.ValueSpec:
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, name := range decl.Names {
			if name.Obj == obj {
				return containsBPFShimReferenceExpr(decl.Values[i], seen)
			}
		}
	}

	return false
}

func swapXDPEntryProgSelectorViolation(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node, fset *token.FileSet, rel string) string {
	if call, methodExpr, ok := enclosingDirectSwapXDPEntryProgCall(sel, parents); ok {
		argIndex := 0
		if methodExpr {
			argIndex = 1
		}
		var got string
		if len(call.Args) > argIndex {
			got = canaryExprString(call.Args[argIndex])
		}
		pos := fset.Position(call.Pos())
		return fmt.Sprintf("%s:%d calls SwapXDPEntryProg with %q", rel, pos.Line, got)
	}

	pos := fset.Position(sel.Pos())
	return fmt.Sprintf("%s:%d %s", rel, pos.Line, swapXDPEntryProgMethodValueContext(sel, parents))
}

func enclosingDirectSwapXDPEntryProgCall(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node) (*ast.CallExpr, bool, bool) {
	var expr ast.Node = sel
	for {
		parent := parents[expr]
		if paren, ok := parent.(*ast.ParenExpr); ok && paren.X == expr {
			expr = paren
			continue
		}
		call, ok := parent.(*ast.CallExpr)
		if !ok || call.Fun != expr {
			return nil, false, false
		}
		return call, isSwapXDPEntryProgMethodExpression(sel), true
	}
}

func isSwapXDPEntryProgMethodExpression(sel *ast.SelectorExpr) bool {
	_, ok := unparenExpr(sel.X).(*ast.StarExpr)
	return ok
}

func swapXDPEntryProgMethodValueContext(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node) string {
	if selectorInsideCallFun(sel, parents) {
		return "calls through SwapXDPEntryProg method value"
	}

	for child := ast.Node(sel); child != nil; {
		parent := parents[child]
		switch node := parent.(type) {
		case *ast.AssignStmt:
			if exprListContainsNode(node.Rhs, child) {
				return "captures SwapXDPEntryProg method value"
			}
		case *ast.ValueSpec:
			if exprListContainsNode(node.Values, child) {
				return "stores SwapXDPEntryProg method value"
			}
		case *ast.ReturnStmt:
			if exprListContainsNode(node.Results, child) {
				return "returns SwapXDPEntryProg method value"
			}
		case *ast.CallExpr:
			if exprListContainsNode(node.Args, child) {
				return "passes SwapXDPEntryProg method value"
			}
		case *ast.SendStmt:
			if node.Value == child {
				return "sends SwapXDPEntryProg method value"
			}
		case *ast.RangeStmt:
			if node.X == child {
				return "ranges over SwapXDPEntryProg method value"
			}
		case *ast.SwitchStmt:
			if node.Tag == child {
				return "switches on SwapXDPEntryProg method value"
			}
		}
		child = parent
	}
	return "uses SwapXDPEntryProg method value"
}

func selectorInsideCallFun(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node) bool {
	for child := ast.Node(sel); child != nil; {
		parent := parents[child]
		if call, ok := parent.(*ast.CallExpr); ok && call.Fun == child {
			return true
		}
		child = parent
	}
	return false
}

func exprListContainsNode(exprs []ast.Expr, node ast.Node) bool {
	for _, expr := range exprs {
		if expr == node {
			return true
		}
	}
	return false
}

func unparenExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

func containsExpr(expr ast.Expr, match func(ast.Expr) bool) bool {
	if expr == nil {
		return false
	}
	var found bool
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		if match(expr) {
			found = true
			return false
		}
		return true
	})
	return found
}

func operatorRuntimeBoundaryRoots(t *testing.T) []string {
	t.Helper()

	var roots []string
	for _, pattern := range []string{
		filepath.Join(repoRootForBoundaryCanary, "cmd", "*"),
		filepath.Join(repoRootForBoundaryCanary, "pkg", "*"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", path, err)
			}
			if !info.IsDir() {
				continue
			}
			if repoRelativePath(t, path) == "pkg/dataplane" {
				continue
			}
			roots = append(roots, path)
		}
	}
	sort.Strings(roots)
	return roots
}

func makeTargetDefinition(t *testing.T, makefile, target string) (string, []string) {
	t.Helper()

	lines := strings.Split(makefile, "\n")
	for i, line := range lines {
		targets, prereqs, ok := parseMakeTargetLine(line)
		if !ok {
			continue
		}
		found := false
		for _, name := range targets {
			if name == target {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		var recipe []string
		for _, next := range lines[i+1:] {
			trimmed := strings.TrimSpace(next)
			switch {
			case strings.HasPrefix(next, "\t"):
				recipe = append(recipe, strings.TrimSpace(next))
			case trimmed == "" || strings.HasPrefix(trimmed, "#"):
				if len(recipe) == 0 {
					continue
				}
				return prereqs, recipe
			default:
				return prereqs, recipe
			}
		}
		return prereqs, recipe
	}
	t.Fatalf("Makefile target %q not found", target)
	return "", nil
}

func parseMakeTargetLine(line string) ([]string, string, bool) {
	if strings.HasPrefix(line, "\t") {
		return nil, "", false
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, "", false
	}
	idx := strings.Index(trimmed, ":")
	if idx < 0 {
		return nil, "", false
	}
	targets := strings.Fields(strings.TrimSpace(trimmed[:idx]))
	if len(targets) == 0 || targets[0] == ".PHONY" {
		return nil, "", false
	}
	return targets, strings.TrimSpace(trimmed[idx+1:]), true
}

func productionGoFilesUnder(t *testing.T, roots []string) []string {
	t.Helper()

	var files []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Strings(files)
	return files
}

func importPaths(t *testing.T, path string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse imports for %s: %v", path, err)
	}

	imports := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		imports = append(imports, strings.Trim(imp.Path.Value, `"`))
	}
	return imports
}

func repoRelativePath(t *testing.T, path string) string {
	t.Helper()

	root, err := filepath.Abs(repoRootForBoundaryCanary)
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs path for %s: %v", path, err)
	}
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		t.Fatalf("rel path for %s: %v", path, err)
	}
	return filepath.ToSlash(rel)
}

func hasDaemonRuntimeConstructorCall(t *testing.T, path, name string) bool {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	want := "dataplane." + name
	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if canaryExprString(call.Fun) == want {
			found = true
			return false
		}
		return true
	})
	return found
}

func assertDaemonDPFieldIsRuntimeDataPlane(t *testing.T) {
	t.Helper()

	if err := checkDaemonDPFieldShape(filepath.Join("..", "daemon", "daemon.go")); err != nil {
		t.Fatal(err)
	}
}

// checkDaemonDPFieldShape verifies the #2114 dataplane-publication shape:
// the Daemon struct carries the runtime dataplane ONLY as the
// `dpCell atomic.Pointer[dpSlot]` publication cell, and the `dpSlot`
// payload struct's `v` field is a `dataplane.RuntimeDataPlane`. The
// pre-#2114 raw `dp dataplane.RuntimeDataPlane` field raced the
// bootstrap-exit writer against the sampler/HA-watcher readers, so its
// reappearance (or a dpSlot payload of any other type) fails here.
func checkDaemonDPFieldShape(path string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return fmt.Errorf("parse %s: %v", path, err)
	}

	var foundCell, foundSlot bool
	var inspectErr error
	ast.Inspect(file, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return true
		}
		switch typeSpec.Name.Name {
		case "Daemon":
			for _, field := range st.Fields.List {
				fieldType := canaryExprString(field.Type)
				for _, name := range field.Names {
					if name.Name == "dpCell" {
						foundCell = true
						if fieldType != "atomic.Pointer[dpSlot]" {
							inspectErr = fmt.Errorf("Daemon.dpCell = %s, want atomic.Pointer[dpSlot]", fieldType)
						}
						continue
					}
					// Codex PR #6743 r3-6: reject the raw interface field
					// under ANY name — a renamed `fallback dataplane.
					// RuntimeDataPlane` recreates the exact unsynchronized
					// publication path this shape pins.
					if fieldType == "dataplane.RuntimeDataPlane" {
						inspectErr = fmt.Errorf("Daemon.%s is a raw dataplane.RuntimeDataPlane field; #2114 publishes the dataplane through dpCell (atomic.Pointer[dpSlot])", name.Name)
					}
				}
			}
		case "dpSlot":
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					if name.Name != "v" {
						continue
					}
					foundSlot = true
					if got := canaryExprString(field.Type); got != "dataplane.RuntimeDataPlane" {
						inspectErr = fmt.Errorf("dpSlot.v = %s, want dataplane.RuntimeDataPlane", got)
					}
				}
			}
		}
		return true
	})
	if inspectErr != nil {
		return inspectErr
	}
	if !foundCell {
		return fmt.Errorf("Daemon.dpCell field not found (want dpCell atomic.Pointer[dpSlot])")
	}
	if !foundSlot {
		return fmt.Errorf("dpSlot struct with a v dataplane.RuntimeDataPlane field not found")
	}
	return nil
}

// TestDaemonDPFieldShapeSelfTest feeds synthetic fixtures through
// checkDaemonDPFieldShape in BOTH directions (#2114): the redesign must
// reject the pre-#2114 raw field shape and accept the cell shape, so a
// revert trips the boundary canary above.
func TestDaemonDPFieldShapeSelfTest(t *testing.T) {
	t.Parallel()

	good := `package daemon

type dpSlot struct{ v dataplane.RuntimeDataPlane }

type Daemon struct {
	dpCell atomic.Pointer[dpSlot]
}
`
	rawField := `package daemon

type Daemon struct {
	dp dataplane.RuntimeDataPlane
}
`
	wrongCellType := `package daemon

type dpSlot struct{ v dataplane.RuntimeDataPlane }

type Daemon struct {
	dpCell atomic.Pointer[int]
}
`
	missingSlot := `package daemon

type Daemon struct {
	dpCell atomic.Pointer[dpSlot]
}
`
	wrongSlotPayload := `package daemon

type dpSlot struct{ v int }

type Daemon struct {
	dpCell atomic.Pointer[dpSlot]
}
`
	renamedRaw := `package daemon

type dpSlot struct{ v dataplane.RuntimeDataPlane }

type Daemon struct {
	dpCell   atomic.Pointer[dpSlot]
	fallback dataplane.RuntimeDataPlane
}
`

	cases := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{"cell shape accepted", good, false},
		{"raw field rejected", rawField, true},
		{"wrong cell type rejected", wrongCellType, true},
		{"missing dpSlot rejected", missingSlot, true},
		{"wrong slot payload rejected", wrongSlotPayload, true},
		// Codex PR #6743 r3-6: the raw field under a DIFFERENT name must
		// fail too — the name-literal check used to pass it.
		{"renamed raw field rejected", renamedRaw, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "daemon.go")
			if err := os.WriteFile(path, []byte(tc.src), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			err := checkDaemonDPFieldShape(path)
			if tc.wantErr && err == nil {
				t.Fatal("checkDaemonDPFieldShape accepted a bad shape")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkDaemonDPFieldShape rejected the cell shape: %v", err)
			}
		})
	}
}

func canaryExprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return canaryExprString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + canaryExprString(e.X)
	case *ast.BasicLit:
		return e.Value
	case *ast.IndexExpr:
		// Generic instantiation with one type argument, e.g.
		// atomic.Pointer[dpSlot] (#2114).
		return canaryExprString(e.X) + "[" + canaryExprString(e.Index) + "]"
	case *ast.IndexListExpr:
		parts := make([]string, 0, len(e.Indices))
		for _, idx := range e.Indices {
			parts = append(parts, canaryExprString(idx))
		}
		return canaryExprString(e.X) + "[" + strings.Join(parts, ", ") + "]"
	default:
		return ""
	}
}
