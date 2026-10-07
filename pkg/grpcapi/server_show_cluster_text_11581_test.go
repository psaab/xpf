package grpcapi

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #11581 (plan v3 §1, review m6): full-renderer fixtures for the two HA
// dataplane CLI transcripts consumed by the shell parsers in
// scripts/userspace-ha-failover-validation.sh and their reached successors in
// test/incus/ha-assurance-lib.sh (assertion-groups slice of
// test/incus/ha-assurance-selftest.sh).
//
// Unlike pkg/dataplane/userspace/format/testdata/status_summary.golden — which
// pins only FormatStatusSummary — these goldens pin the FULL production CLI
// rendering path: Server.showChassisClusterDataPlaneStatistics (cluster
// FormatDataPlaneStatistics sync table + appended userspace summary) and
// Server.showChassisClusterDataPlaneInterfaces (cluster sync/fabric header +
// appended queues/fabric/bindings). The shell parser tests consume these
// transcripts; no incus/cli stubs echo hand-written expected output.
//
// Server construction mirrors server_show_cluster_vrrp_10844_test.go
// (newConfigStore + cluster.NewManager + &Server{store, cluster}); the status
// seam is Server.userspaceDataplaneStatus() via dpProbe() (runtime.go,
// server.go) fed by a fake userspaceStatusProvider below. NO production Go
// change.
//
// Regenerate with `go test ./pkg/grpcapi/ -run 11581 -update-11581` after a
// deliberate, reviewed change to either renderer. The flag is 11581-scoped so
// it cannot collide with the format package's bare `-update` flag.
var update11581 = flag.Bool("update-11581", false, "regenerate #11581 full-renderer golden fixtures")

// fakeSyncStats11581 is a cluster.SyncStatsProvider fixture: connected sync
// with idle session counters (Sent == Received) so the sync-idle predicate
// sees a quiesced pair.
type fakeSyncStats11581 struct {
	snapshot  cluster.SyncStatsSnapshot
	connected bool
}

func (f fakeSyncStats11581) Stats() cluster.SyncStatsSnapshot { return f.snapshot }
func (f fakeSyncStats11581) IsConnected() bool                { return f.connected }
func (f fakeSyncStats11581) PeerSessionSyncWireVersion() uint16 {
	return 0
}
func (f fakeSyncStats11581) UnauthenticatedSessionConns() []string { return nil }

// fakeUserspaceDP11581 is the userspaceStatusProvider seam fake: it embeds the
// mandatory grpcRuntime surface (*dataplane.Manager) and serves a populated
// ProcessStatus from Status(), following the firewallFilterShowUserspaceDP
// precedent in server_show_firewall_test.go. dataplane.Unwrap is the identity
// for a plain backend, so dpProbe() resolves to this value directly.
type fakeUserspaceDP11581 struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (f *fakeUserspaceDP11581) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

// clusterManager11581 builds a connected-sync Manager whose formatted output
// covers the sync-table and sync/fabric-header census labels.
func clusterManager11581() *cluster.Manager {
	manager := cluster.NewManager(0, 1)
	manager.SetSyncTransport("fabric")
	manager.SetSyncStats(fakeSyncStats11581{
		snapshot: cluster.SyncStatsSnapshot{
			SessionsSent:     321,
			SessionsReceived: 321,
			SessionsInstalled: 321,
			DeletesSent:      8,
			DeletesReceived:  8,
			ConfigsSent:      12,
			ConfigsReceived:  12,
		},
		connected: true,
	})
	return manager
}

// processStatus11581 builds the userspace ProcessStatus fixture. Shape follows
// goldenStatusSummaryFixture in
// pkg/dataplane/userspace/format/status_golden_test.go; every conditional
// section the shell parsers need is populated, and everything renders
// deterministically (no LastSnapshotAt, no non-zero WorkerHeartbeats — those
// durations depend on time.Now()).
//
// Fixture extensions over the format fixture, each driven by a parser need:
//   - ForwardingSupported:true (the format fixture pins false + blocked-by;
//     the legacy owner predicate at :208-211 greps `Forwarding supported: true`).
//   - rg1 active=false + rg0 active=true: the standby slice greps
//     `rg1 active=false` (:644), the owner slice greps `rg0 active=true` (:210).
//   - Three bindings on ge-0-0-0 (fabric), ge-0-0-1 (LAN), ge-0-0-2 (WAN) so
//     the interface regexes ge-[0-9]+-0-0/-0-1/-0-2 each match, with RX/TX
//     counters in columns 10/11 (0-based) of the 20-column bindings table.
//   - Fabric parent ge-0-0-0 so status_fabric_tx_packets (:483-538) joins the
//     fabric-links table against bindings column 19.
//   - Session delta pending=0 with sent==received above: a sync-idle fixture.
func processStatus11581() dpuserspace.ProcessStatus {
	return dpuserspace.ProcessStatus{
		PID:                   4242,
		HelperMode:            "rust-native",
		Enabled:               true,
		ForwardingArmed:       true,
		Workers:               2,
		RingEntries:           4096,
		SessionTableEntries:   321,
		MaxSessions:           1000,
		Capabilities:          dpuserspace.UserspaceCapabilities{ForwardingSupported: true},
		HAGroups: []dpuserspace.HAGroupStatus{
			{RGID: 0, Active: true, WatchdogTimestamp: 100},
			{RGID: 1, Active: false, WatchdogTimestamp: 0},
		},
		Fabrics: []dpuserspace.FabricSnapshot{
			{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7, OverlayLinux: "fab0", OverlayIfindex: 17, RXQueues: 4, PeerAddress: "10.99.1.2"},
		},
		Queues: []dpuserspace.QueueStatus{
			{QueueID: 0, WorkerID: 0, Interfaces: []string{"ge-0-0-0", "ge-0-0-1", "ge-0-0-2"}, Registered: true, Armed: true, Ready: true},
			{QueueID: 1, WorkerID: 1, Registered: true, Armed: false, Ready: false},
		},
		Bindings: []dpuserspace.BindingStatus{
			{
				Slot: 0, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-0", Ifindex: 7,
				Registered: true, Armed: true, Ready: true, Bound: true,
				XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, HugepageBacked: true,
				SharedUMEMMode: "cross-nic", SharedUMEMSocketRole: "owner",
				RXPackets: 5000, TXPackets: 4800,
				DirectTXPackets: 4700, CopyTXPackets: 80, InPlaceTXPackets: 20,
				SlowPathPackets: 6, ExceptionPackets: 3, RouteMissPackets: 2,
				SessionHits: 50, SessionMisses: 12, SessionCreates: 8, SessionExpires: 4,
				SessionDeltaPending: 0, SessionDeltaGenerated: 6, SessionDeltaDrained: 5,
				PolicyDeniedPackets: 7, NeighborMissPackets: 1,
				KernelRXDropped: 9, DirectTXNoFrameFallbackPackets: 3,
				DebugPendingTXLocal: 14, DebugOutstandingTX: 15,
				DebugPendingFillFrames: 10, DebugSpareFillFrames: 11, DebugFreeTXFrames: 12,
				DebugPendingTXPrepared: 13, DebugInFlightRecycles: 16,
			},
			{
				Slot: 1, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-1", Ifindex: 8,
				Registered: true, Armed: true, Ready: true, Bound: true,
				XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, HugepageBacked: true,
				SharedUMEMMode: "cross-nic", SharedUMEMSocketRole: "member",
				RXPackets: 9000, TXPackets: 120,
				DirectTXPackets: 100, CopyTXPackets: 15, InPlaceTXPackets: 5,
				SessionHits: 30, SessionMisses: 4,
			},
			{
				Slot: 2, QueueID: 0, WorkerID: 0, Interface: "ge-0-0-2", Ifindex: 9,
				Registered: true, Armed: true, Ready: true, Bound: true,
				XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, HugepageBacked: true,
				SharedUMEMMode: "cross-nic", SharedUMEMSocketRole: "member",
				RXPackets: 300, TXPackets: 2600,
				DirectTXPackets: 2500, CopyTXPackets: 70, InPlaceTXPackets: 30,
				SessionHits: 20, SessionMisses: 2,
			},
		},
	}
}

// server11581 builds the full Server under test: config-store + cluster
// manager + fake userspace backend, per the 10844 constructor pattern.
func server11581(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(strings.Join([]string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-11581",
		"set chassis cluster reth-count 2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
	}, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Server{
		store:   store,
		cluster: clusterManager11581(),
		dp: &fakeUserspaceDP11581{
			Manager: dataplane.New(),
			status:  processStatus11581(),
		},
	}
}

// Statistics census: every label the statistics-transcript parsers require.
// Each entry names its consumer in scripts/userspace-ha-failover-validation.sh
// (line numbers at base 507a9cafe); the reached ha-assurance-lib.sh parsers
// share these predicates per plan v3 §1.
//
// sync_stats_value (:390-434) needs the exact `Services Synchronized:` section
// line plus a `Session create` row with sent/received numerics; it stops at
// the first blank line, so the golden MUST keep the table contiguous.
// status_summary_value (:337-366) and sample_window_value (:915-962) match
// lines starting with two spaces + `<label>:` and take the first integer after
// the colon — hence the `  <label>:` prefix form below. The readiness greps
// (:207-211 owner, :637-646 standby) match `Enabled: true`,
// `Forwarding supported: true` / `Forwarding armed: true`, `rg<N> active=…`,
// and a nonzero `Ready bindings: n/m` numerator.
var statisticsCensus11581 = []string{
	// Sync table (sync_stats_value :390-434; sync-idle :442-481).
	"Services Synchronized:",
	"Service name",
	"Sent",
	"Received",
	"Session create",
	// Session-delta labels (sync-idle :457-462; Group 9 §6.1).
	"  Session delta pending:",
	"  Session delta drained:",
	// Miss/policy labels (Groups 1–4 :697-771; Group 8 :988-1042).
	"  Session misses:",
	"  Neighbor misses:",
	"  Route misses:",
	"  Policy denied packets:",
	"  Kernel RX dropped:",
	"  Direct TX no-frame fb:",
	"  Pending TX local:",
	"  Outstanding TX:",
	// Readiness predicates (owner :207-211; standby :637-646; Group 7 §5.3).
	"Enabled:",
	"Forwarding armed:",
	"Forwarding supported:",
	"rg0 active=true",
	"rg1 active=false",
	"Ready bindings:",
}

// Interfaces census: every label the interfaces-transcript parsers require.
// status_fabric_tx_packets (:483-538) needs the exact `Userspace fabric links:`
// section + `Userspace bindings:` table with ≥20 whitespace columns, TX in
// column 11 (0-based) and interface in column 19. interface_packets_value
// (:540-616) and sample_window_interface_packets (:831-913) need the bindings
// table with RX/TX in columns 10/11 and fullmatch-able interface names
// (STANDBY_WAN_IFACE_REGEX=ge-[0-9]+-0-2 at :56; Group 8 sampler regexes
// ge-[0-9]+-0-0/-0-1/-0-2 at :1012-1058). The cluster sync/fabric header opens
// the transcript (FormatDataPlaneInterfaces).
var interfacesCensus11581 = []string{
	// Cluster sync/fabric header (FormatDataPlaneInterfaces).
	"Fabric link:",
	"  Status: Up",
	"  Errors:",
	// Userspace sections (FormatBindings).
	"Userspace queues:",
	"Userspace fabric links:",
	"Userspace bindings:",
	// Fabric-join parent + bindings-table column header row.
	"ge-0-0-0",
	"TXPkts",
	// Interface regex populations (Group 5 WAN, Group 8 LAN/fabric/WAN).
	"ge-0-0-1",
	"ge-0-0-2",
}

// goldenHeader11581 records the producing method and shell selftest consumer.
// It is prepended to the golden file but is NOT part of the renderer output:
// the comparator strips it before the byte comparison, so the golden pins the
// production bytes exactly while remaining self-describing. Shell consumers
// source the transcript body (parsers grep for content labels; `#` comment
// lines never match a `  <label>:` prefix or section header).
func goldenHeader11581(method, transcript string) string {
	return "# #11581 full-renderer fixture: " + method + "\n" +
		"# transcript: " + transcript + "\n" +
		"# consumer: test/incus/ha-assurance-selftest.sh (assertion-groups slice)\n"
}

// assertCensus11581 checks the fail-closed label list plus the structural
// fields used by the shell parsers. It is applied to renderer output and the
// golden body, so deleting a required label from a golden COPY fails with a
// label-specific diagnostic before the byte comparison.
func assertCensus11581(t *testing.T, method, output string, census []string) {
	t.Helper()
	for _, label := range census {
		if !strings.Contains(output, label) {
			t.Fatalf("%s transcript missing parser-required label %q:\n%s", method, label, output)
		}
	}
	if method == "Server.showChassisClusterDataPlaneStatistics" {
		for _, pattern := range []string{
			`(?m)^    Session create[ \t]+[0-9]+[ \t]+[0-9]+[ \t]*$`,
			`(?m)^  Enabled:[ \t]+true$`,
			`(?m)^  Forwarding armed:[ \t]+true$`,
			`(?m)^  Forwarding supported:[ \t]+true$`,
			`(?m)^  Ready bindings:[ \t]*[1-9][0-9]*/[0-9]+$`,
			`(?m)^  Session delta pending:[ \t]*[0-9]+$`,
			`(?m)^  Session delta drained:[ \t]*[0-9]+$`,
		} {
			if !regexp.MustCompile(pattern).MatchString(output) {
				t.Fatalf("%s transcript does not satisfy parser shape %q:\n%s", method, pattern, output)
			}
		}
		for _, group := range []string{"rg0 active=true", "rg1 active=false"} {
			if !strings.Contains(output, group) {
				t.Fatalf("%s transcript missing HA readiness state %q:\n%s", method, group, output)
			}
		}
		return
	}

	// Pin the full table shape used by the scripts' fixed [10]/[11]/[19]
	// columns, not only the `Userspace bindings:` section heading.
	_, bindings, found := strings.Cut(output, "Userspace bindings:\n")
	if !found {
		t.Fatalf("%s transcript has no bindings table:\n%s", method, output)
	}
	table, _, _ := strings.Cut(bindings, "\n\n")
	rows := strings.Split(table, "\n")
	if len(rows) < 2 {
		t.Fatalf("%s transcript bindings table has no header/data rows:\n%s", method, table)
	}
	wantColumns := []string{
		"Slot", "Queue", "Worker", "Registered", "Armed", "Ready", "Bound", "XSK",
		"Mode", "Ifindex", "RXPkts", "TXPkts", "DirTx", "CopyTx", "InPlTx",
		"SessHit", "SlowPkts", "ExcPkts", "RtMiss", "Interface",
	}
	gotColumns := strings.Fields(rows[0])
	if len(gotColumns) < len(wantColumns) {
		t.Fatalf("%s transcript bindings header has %d columns, want at least %d: %q",
			method, len(gotColumns), len(wantColumns), rows[0])
	}
	for i, want := range wantColumns {
		if gotColumns[i] != want {
			t.Fatalf("%s transcript bindings column %d = %q, want %q",
				method, i, gotColumns[i], want)
		}
	}
	wantInterfaces := map[string]bool{"ge-0-0-0": false, "ge-0-0-1": false, "ge-0-0-2": false}
	for _, row := range rows[1:] {
		fields := strings.Fields(row)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 20 {
			t.Fatalf("%s transcript has a short bindings row (%d columns): %q", method, len(fields), row)
		}
		for _, index := range []int{10, 11} {
			if _, err := strconv.ParseUint(fields[index], 10, 64); err != nil {
				t.Fatalf("%s transcript bindings counter column %d is not an integer: %q", method, index, fields[index])
			}
		}
		if _, ok := wantInterfaces[fields[19]]; ok {
			wantInterfaces[fields[19]] = true
		}
	}
	for iface, found := range wantInterfaces {
		if !found {
			t.Fatalf("%s transcript bindings table lacks parser interface %q:\n%s", method, iface, table)
		}
	}
	if !regexp.MustCompile(`(?m)^  fab0[ \t]+ge-0-0-0[ \t]+[0-9]+[ \t]+fab0[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[^[:space:]]+`).MatchString(output) {
		t.Fatalf("%s transcript fabric table lacks a parseable fab0 parent row:\n%s", method, output)
	}
}


// checkGolden11581 compares renderer output against the checked-in golden
// (writing it under -update-11581) and asserts the fail-closed label census
// against both the live output and checked-in golden body.
func checkGolden11581(t *testing.T, method, goldenName, transcript, got string, census []string) {
	t.Helper()
	assertCensus11581(t, method, got, census)
	goldenPath := filepath.Join("testdata", goldenName)
	if *update11581 {
		content := goldenHeader11581(method, transcript) + got
		if err := os.WriteFile(goldenPath, []byte(content), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update-11581 to generate): %v", err)
	}
	want := string(wantBytes)
	if header := goldenHeader11581(method, transcript); !strings.HasPrefix(want, header) {
		t.Fatalf("golden %s missing header comment (want prefix %q)", goldenPath, header)
	} else {
		want = strings.TrimPrefix(want, header)
	}
	assertCensus11581(t, method, want, census)
	if got != want {
		t.Fatalf("%s output diverged from golden.\n--- got ---\n%s\n--- want ---\n%s", method, got, want)
	}
}

func TestShowChassisClusterDataPlaneStatistics11581(t *testing.T) {
	s := server11581(t)
	var buf strings.Builder
	s.showChassisClusterDataPlaneStatistics(&buf)
	checkGolden11581(t,
		"Server.showChassisClusterDataPlaneStatistics",
		"show_chassis_cluster_data_plane_statistics_11581.golden",
		"show chassis cluster data-plane statistics",
		buf.String(), statisticsCensus11581)
}

func TestShowChassisClusterDataPlaneInterfaces11581(t *testing.T) {
	s := server11581(t)
	var buf strings.Builder
	s.showChassisClusterDataPlaneInterfaces(&buf)
	checkGolden11581(t,
		"Server.showChassisClusterDataPlaneInterfaces",
		"show_chassis_cluster_data_plane_interfaces_11581.golden",
		"show chassis cluster data-plane interfaces",
		buf.String(), interfacesCensus11581)
}
