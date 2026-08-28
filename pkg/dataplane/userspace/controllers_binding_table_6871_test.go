package userspace

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

// #6871 round 8 B3: the adapter layer cannot be severed silently, BY
// CONSTRUCTION.
//
// THE HISTORY IS THE ARGUMENT. Codex found two unbound adapter methods. The
// round-7 sweep that answered it found six. Codex then found a SEVENTH
// (RecordDeferredWorkerArmDebt) that the sweep had missed. Each round produced a
// number and each number was a lower bound, because every one of them was
// somebody enumerating by hand and stopping when they ran out of things they
// could see.
//
// An eighth hand-written test would have exactly the same property. So this file
// does not enumerate: it DERIVES the surface from the source and fails if any
// method of any controller type lacks an entry. Adding a method to controllers.go
// without answering for it here is a compile-green test failure, which is the
// only form of coverage that survives the next person who does not read this
// comment.
//
// WHAT THE DERIVATION COVERS, exactly. adapterMethodsFromSource parses every
// non-test file of this package and collects methods whose RECEIVER is one of
// the four controller types. Parsing the package rather than "controllers.go"
// specifically is deliberate — moving a method to another file must not silently
// shrink the required set (it would look like a stale entry, not a missing one).
//
// WHAT IT DOES NOT COVER, stated rather than left to be discovered:
//
//   - PROMOTED methods. userspaceSessionStore embeds dataplane.SessionStore, so
//     its method set includes that interface's methods. They are not declared on
//     the controller and are not adapters — the embedded value IS the
//     implementation, with no forwarder to sever — so a source-declaration scan
//     is the right boundary and this is why it is drawn there.
//   - The two OTHER production seams that are not in controllers.go:
//     LegacyDataPlaneAdapter (bound in runtime_adapter_binding_6871_test.go) and
//     the eBPF-backed dataPlaneLinkController in pkg/dataplane.
//
// This file does not replace runtime_adapter_binding_6871_test.go. That file's
// cells were each measured against a real severance, and a table that subsumed
// them would be a table that could retire one of them by accident. The two
// overlap on purpose.

// adapterControllerTypes is the set of receiver type names this file governs.
// It is the ONE hand-maintained list here, and a new controller type added to
// controllers.go without being listed is the residual gap — narrower than the
// per-method gap it replaces, because a new TYPE is a new production seam that
// gets reviewed, while a new METHOD on an existing type is a two-line forwarder
// that does not.
var adapterControllerTypes = map[string]bool{
	"userspaceLinkController": true,
	"managerHAOps":            true,
	"userspaceHAController":   true,
	"userspaceSessionStore":   true,
}

// adapterMethodsFromSource returns "Type.Method" for every method DECLARED on a
// controller type anywhere in this package's non-test sources.
func adapterMethodsFromSource(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package sources: %v", err)
	}
	// PASS 1 — expand the governed set through type ALIASES (#6871 round 9, F5).
	//
	// `type aliasEscape = userspaceLinkController` plus a method on aliasEscape
	// puts that method in userspaceLinkController's method set — confirmed by a
	// compile-time assertion — while a receiver-name match against the literal
	// list above misses it entirely. Measured: such a method stayed GREEN.
	//
	// INCLUDED rather than rejected. Refusing an alias would also be sound, but
	// resolving it means the alias's methods are BOUND rather than merely
	// forbidden, and an alias is a legitimate thing to write. `ts.Assign != 0`
	// is what distinguishes `type A = B` from `type A B`; the latter is a
	// distinct type with its own method set and is correctly not governed.
	//
	// Fixed-point loop because an alias may name another alias.
	governed := map[string]string{} // type name -> canonical controller name
	for name := range adapterControllerTypes {
		governed[name] = name
	}
	for changed := true; changed; {
		changed = false
		for _, pkg := range pkgs {
			for _, file := range pkg.Files {
				for _, decl := range file.Decls {
					gd, ok := decl.(*ast.GenDecl)
					if !ok || gd.Tok != token.TYPE {
						continue
					}
					for _, spec := range gd.Specs {
						ts, ok := spec.(*ast.TypeSpec)
						if !ok || ts.Assign == 0 {
							continue // `type A B` defines a NEW type, not an alias
						}
						rhs, ok := ts.Type.(*ast.Ident)
						if !ok {
							continue
						}
						canon, isGoverned := governed[rhs.Name]
						if !isGoverned {
							continue
						}
						if _, already := governed[ts.Name.Name]; already {
							continue
						}
						governed[ts.Name.Name] = canon
						changed = true
					}
				}
			}
		}
	}

	// TWO ESCAPES THAT DO NOT WORK, recorded so nobody spends time re-deriving
	// them (#6871 round 9):
	//
	//   - BUILD TAGS: parser.ParseDir ignores //go:build, so a method hidden
	//     behind a tag is still SEEN here. That over-includes rather than
	//     under-includes — a tagged-out method fails loudly as an unbound row
	//     instead of escaping — which is the safe direction.
	//   - POINTER vs VALUE receivers: covered by the StarExpr unwrap below.
	//     `func (c *userspaceLinkController) M()` keys identically to the value
	//     form.

	// PASS 2 — collect the methods.
	out := map[string]bool{}
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
					continue
				}
				recv := fn.Recv.List[0].Type
				if star, ok := recv.(*ast.StarExpr); ok {
					recv = star.X
				}
				id, ok := recv.(*ast.Ident)
				if !ok {
					continue
				}
				canon, isGoverned := governed[id.Name]
				if !isGoverned {
					continue
				}
				if !fn.Name.IsExported() {
					// Unexported helpers on a controller are not part of any
					// production interface, so severing one cannot silently
					// remove behaviour from a caller outside this package.
					continue
				}
				out[canon+"."+fn.Name.Name] = true
				_ = path
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("derived ZERO controller methods from source: the scan is broken, and a " +
			"broken scan makes this whole file vacuously green")
	}
	return out
}

// adapterBinding is one row: either a driver that proves the method reaches the
// real Manager, or an explicit statement that it cannot be driven and why.
type adapterBinding struct {
	setup func(t *testing.T, m *Manager)
	drive func(t *testing.T, m *Manager, srv *leaseControlServer)
	// cannotDrive is the REASON there is no behavioural cell. Non-empty entries
	// are visible gaps rather than absent ones — the failure mode this file
	// exists to prevent is a method with no row at all.
	cannotDrive string
}

// adapterBindingTable answers for every method of every controller type.
func adapterBindingTable() map[string]adapterBinding {
	return map[string]adapterBinding{
		"userspaceLinkController.SetDeferWorkers": {
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				m.Link().SetDeferWorkers(true)
				m.mu.Lock()
				defer m.mu.Unlock()
				if !m.deferWorkers {
					t.Error("deferWorkers is still false: a RETH apply that must not spawn " +
						"workers before the MAC is correct would spawn them")
				}
			},
		},
		"userspaceLinkController.RecordDeferredWorkerArmDebt": {
			// Codex's SEVENTH adapter, and the one the round-7 sweep missed.
			//
			// REACHABILITY, corrected by measurement. Codex placed this on the
			// live path via the link fallback in recordDataplaneWorkerArmDebt
			// (pkg/daemon/daemon_apply_dataplane.go). It is NOT reached there
			// today: production d.dp is *LegacyDataPlaneAdapter (Boot() ->
			// NewLegacyDataPlaneAdapter, manager.go), which satisfies the
			// debtRecorder assertion itself, so the fallback is dead for that
			// caller. The finding stands anyway — this is a method on a
			// production type reachable through Manager.Link() by any holder of
			// a *Manager, it is the documented fallback for exactly the case
			// where d.dp does NOT carry the method, and it was unbound — but the
			// harm is a latent fallback rather than a live one, and saying so is
			// the difference between a fix and a fix plus a false claim.
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				// Asserted off Link(), exactly as Daemon.recordDataplaneWorkerArmDebt
				// does: this method is deliberately NOT on dataplane.LinkController,
				// so the assertion IS the production reach and a failed assertion is
				// itself the severance.
				type debtRecorder interface{ RecordDeferredWorkerArmDebt() }
				r, ok := m.Link().(debtRecorder)
				if !ok {
					t.Fatal("Manager.Link() no longer satisfies the debtRecorder assertion " +
						"the daemon reaches this through; the fallback in " +
						"recordDataplaneWorkerArmDebt is now dead for every caller")
				}
				r.RecordDeferredWorkerArmDebt()
				m.mu.Lock()
				defer m.mu.Unlock()
				if !m.pendingWorkerArm {
					t.Error("pendingWorkerArm is still false: the #5134 deferred-MAC " +
						"worker-arm debt never reached the manager. Nothing then retries " +
						"the DeferWorkers=false publish, so the workerless snapshot stays " +
						"published and status reconciliation replays it indefinitely — " +
						"forwarding silently down on this node under a successful commit")
				}
			},
		},
		"userspaceLinkController.PrepareLinkCycle": {
			drive: func(t *testing.T, m *Manager, srv *leaseControlServer) {
				if err := m.Link().PrepareLinkCycle(); err != nil {
					t.Fatalf("PrepareLinkCycle: %v", err)
				}
				if n := countRequests(srv.requests(), "stop_workers"); n != 1 {
					t.Errorf("stop_workers requests = %d, want 1: the AF_XDP worker join "+
						"never reached the helper, so the link would cycle with workers "+
						"still touching UMEM. Requests: %v", n, srv.requests())
				}
			},
		},
		"userspaceLinkController.NotifyLinkCycle": {
			setup: func(t *testing.T, _ *Manager) { skipLinkCycleRebindSleep(t) },
			drive: func(t *testing.T, m *Manager, srv *leaseControlServer) {
				if err := m.Link().NotifyLinkCycle(); err != nil {
					t.Fatalf("NotifyLinkCycle: %v", err)
				}
				if n := countRequests(srv.requests(), "rebind"); n != 1 {
					t.Errorf("rebind requests = %d, want 1: the inverse of stop_workers "+
						"never reached the helper, so the workers stay joined and the node "+
						"forwards nothing. Requests: %v", n, srv.requests())
				}
			},
		},
		// #7007: the repair-WITHOUT-release variant. The driver asserts BOTH
		// halves, because either alone would pass against a severed forwarder:
		// a body replaced with `return nil` sends no rebind, and a body that
		// forwarded to the RELEASING NotifyLinkCycle would send the rebind but
		// drop the lease — which is precisely the bug this method exists to fix.
		"userspaceLinkController.NotifyLinkCycleKeepingLease": {
			setup: func(t *testing.T, _ *Manager) { skipLinkCycleRebindSleep(t) },
			drive: func(t *testing.T, m *Manager, srv *leaseControlServer) {
				m.acquireLinkCycleLease()
				t.Cleanup(m.releaseLinkCycleLease)
				if err := m.Link().NotifyLinkCycleKeepingLease(); err != nil {
					t.Fatalf("NotifyLinkCycleKeepingLease: %v", err)
				}
				if n := countRequests(srv.requests(), "rebind"); n != 1 {
					t.Errorf("rebind requests = %d, want 1: the repair never reached the "+
						"helper, so an aborted RETH member's workers stay joined and that "+
						"member forwards nothing. Requests: %v", n, srv.requests())
				}
				if !m.linkCycleInFlight() {
					t.Error("the lease was RELEASED by the keep-lease repair (#7007). On a " +
						"multi-member RETH apply that ends a lease an already-cycled " +
						"sibling still depends on, and every renewal after it becomes a " +
						"no-op against the 0 sentinel")
				}
			},
		},
		"userspaceLinkController.RenewLinkCycle": {
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				advance := fakeLinkCycleClock(t)
				m.acquireLinkCycleLease()
				t.Cleanup(m.releaseLinkCycleLease)
				advance(linkCycleLeaseTTL - time.Second)
				m.Link().RenewLinkCycle()
				advance(2 * time.Second)
				if !m.linkCycleInFlight() {
					t.Error("the lease expired on schedule despite a renewal through Link(): " +
						"with this adapter severed there are no production renewals at all")
				}
			},
		},
		"userspaceLinkController.AbandonLinkCycle": {
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				fakeLinkCycleClock(t)
				m.acquireLinkCycleLease()
				if !m.Link().AbandonLinkCycle() {
					t.Error("AbandonLinkCycle through Link() reported no lease while one was " +
						"held: the daemon's deferred release is the only thing that ends a " +
						"leaked lease now that the lease renews itself, so a severed adapter " +
						"turns a leak into a permanently suppressed reconcile loop")
				}
				if m.linkCycleInFlight() {
					t.Error("the lease survived AbandonLinkCycle through the production adapter")
				}
			},
		},

		// managerHAOps is the INNER hop. Production reaches every one of these
		// through userspaceHAController, so each is driven that way — driving
		// the struct directly would leave the outer forwarder unguarded, which
		// is the defect class this whole file answers.
		"managerHAOps.UpdateRGActive": {
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				err := m.HA().SetRGActive(context.Background(), 1, true)
				assertReachedManagerMap6871(t, err, "rg_active", "SetRGActive",
					"the kernel-visible RG ownership state was never written, so a standby "+
						"would keep forwarding as if it still owned the group")
			},
		},
		"managerHAOps.UpdateHAWatchdog": {
			drive: func(t *testing.T, m *Manager, srv *leaseControlServer) {
				if err := m.HA().SetHAWatchdog(context.Background(), 1, 4242); err != nil {
					t.Logf("SetHAWatchdog: %v", err) // map-free tail, request already sent
				}
				if n := countRequests(srv.requests(), "update_ha_state"); n != 1 {
					t.Fatalf("update_ha_state requests = %d, want 1: the daemon's 500ms "+
						"heartbeat is the ONLY refresh of the helper's per-RG forwarding "+
						"lease (10s), so a severed hop expires it and STOPS FORWARDING for "+
						"the group. Requests: %v", n, srv.requests())
				}
				m.mu.Lock()
				defer m.mu.Unlock()
				if got := m.haGroups[1].WatchdogTimestamp; got != 4242 {
					t.Errorf("WatchdogTimestamp = %d, want 4242: a forwarder is dropping or "+
						"rewriting its argument rather than merely being present", got)
				}
			},
		},
		"managerHAOps.UpdateFabricFwd": {
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				err := m.HA().SetFabricForwarding(context.Background(), 0, dataplane.FabricFwdInfo{})
				assertFabricMapComplaint6871(t, err, "fabric0")
			},
		},
		"managerHAOps.UpdateFabricFwd1": {
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				err := m.HA().SetFabricForwarding(context.Background(), 1, dataplane.FabricFwdInfo{})
				assertFabricMapComplaint6871(t, err, "fabric1")
			},
		},
		"managerHAOps.SyncFabricState": {
			setup: func(_ *testing.T, m *Manager) {
				m.lastSnapshot = &ConfigSnapshot{}
				m.fabricSnapshotBuilder = func(*config.Config) []FabricSnapshot {
					return []FabricSnapshot{{Name: "fab0"}}
				}
			},
			drive: func(t *testing.T, m *Manager, srv *leaseControlServer) {
				if err := m.HA().SyncFabricState(context.Background()); err != nil {
					t.Fatalf("SyncFabricState: %v", err)
				}
				if n := countRequests(srv.requests(), "update_fabrics"); n != 1 {
					t.Errorf("update_fabrics requests = %d, want 1: the freshly resolved "+
						"fabric peer MACs never reached the helper, so cross-chassis redirect "+
						"keeps using the stale set during exactly the HA window it exists to "+
						"cover. Requests: %v", n, srv.requests())
				}
			},
		},

		// userspaceHAController is the OUTER hop.
		"userspaceHAController.SetRGActive": {
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := m.HA().SetRGActive(ctx, 1, true); err == nil {
					t.Error("SetRGActive on a cancelled context returned nil; the ctx.Err() " +
						"check is behaviour that lives ONLY in the outer adapter, so without " +
						"it a fix that deleted this hop and wired managerHAOps straight into " +
						"the interface would look identical")
				}
			},
		},
		"userspaceHAController.SetHAWatchdog": {
			drive: func(t *testing.T, m *Manager, srv *leaseControlServer) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := m.HA().SetHAWatchdog(ctx, 1, 4242); err == nil {
					t.Error("SetHAWatchdog on a cancelled context returned nil")
				}
				if n := countRequests(srv.requests(), "update_ha_state"); n != 0 {
					t.Errorf("update_ha_state requests after a cancelled context = %d, want "+
						"0: the refusal must happen BEFORE the control socket. Requests: %v",
						n, srv.requests())
				}
			},
		},
		"userspaceHAController.SetFabricForwarding": {
			// TWO entry points, because this method has two and testing one
			// binds neither reliably (Codex, round 8). Its body calls
			// managerHAOps.SyncFabricState DIRECTLY rather than going through
			// userspaceHAController.SyncFabricState — so the "always push helper
			// fabric state after a successful update" contract is invisible to
			// the fabric-set cells above: map-free, UpdateFabricFwd fails and
			// the method returns BEFORE the tail. A fake userspaceHAOps is the
			// only way to reach it, and userspaceHAOps being an interface is
			// what makes that possible.
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				err := m.HA().SetFabricForwarding(context.Background(), 0, dataplane.FabricFwdInfo{})
				assertFabricMapComplaint6871(t, err, "fabric0")

				for _, id := range []dataplane.FabricID{0, 1} {
					ops := &recordingHAOps6871{}
					c := userspaceHAController{manager: ops}
					if err := c.SetFabricForwarding(context.Background(), id, dataplane.FabricFwdInfo{}); err != nil {
						t.Fatalf("SetFabricForwarding(fabric%d) on a succeeding ops: %v", id, err)
					}
					if ops.syncCalls != 1 {
						t.Errorf("fabric%d: SyncFabricState calls after a SUCCESSFUL fabric "+
							"update = %d, want 1. The map write is committed at that point "+
							"and the helper's fabric view is not, so cross-chassis redirect "+
							"runs on the stale peer MAC until some other caller happens to "+
							"push — during the HA window this exists to cover", id, ops.syncCalls)
					}
					if ops.fwdCalls+ops.fwd1Calls != 1 {
						t.Errorf("fabric%d: routed to %d fabric0 and %d fabric1 updates, want "+
							"exactly one", id, ops.fwdCalls, ops.fwd1Calls)
					}
				}
			},
		},
		"userspaceHAController.SyncFabricState": {
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := m.HA().SyncFabricState(ctx); err == nil {
					t.Error("SyncFabricState on a cancelled context returned nil; the outer " +
						"adapter's ctx.Err() check is the only cancellation this path honours")
				}
			},
		},

		"userspaceSessionStore.SessionDeltas": {
			// Production consumer: SessionSync.sweepIntervals
			// (pkg/cluster/sync_conn_sweep.go) calls s.sessions.SessionDeltas()
			// and falls back to the hard-coded 1s/10s cadence on nil, so a
			// severed forwarder silently runs incremental session sync at the
			// wrong rate instead of the helper-profiled one.
			drive: func(t *testing.T, m *Manager, _ *leaseControlServer) {
				got := m.Sessions().SessionDeltas()
				if got == nil {
					t.Fatal("SessionDeltas() through the production Sessions() constructor is " +
						"nil: the cluster session-sync sweep loses the helper's own sweep " +
						"profile and silently falls back to the default cadence")
				}
				if want := m.RuntimeSessionDeltaSource(); got != want {
					t.Errorf("SessionDeltas() = %#v, want the manager's own source %#v: the "+
						"store is answering with something other than the live manager",
						got, want)
				}
				var _ dpruntime.SessionDeltaSource = got
			},
		},
	}
}

// recordingHAOps6871 is a userspaceHAOps whose fabric updates SUCCEED, which is
// the only way to reach userspaceHAController.SetFabricForwarding's tail.
type recordingHAOps6871 struct {
	fwdCalls  int
	fwd1Calls int
	syncCalls int
}

func (o *recordingHAOps6871) UpdateRGActive(int, bool) error     { return nil }
func (o *recordingHAOps6871) UpdateHAWatchdog(int, uint64) error { return nil }
func (o *recordingHAOps6871) UpdateFabricFwd(dataplane.FabricFwdInfo) error {
	o.fwdCalls++
	return nil
}
func (o *recordingHAOps6871) UpdateFabricFwd1(dataplane.FabricFwdInfo) error {
	o.fwd1Calls++
	return nil
}
func (o *recordingHAOps6871) SyncFabricState() { o.syncCalls++ }

// assertReachedManagerMap6871 checks that a call reached the real manager by the
// specific complaint a missing BPF map produces. A nil return means the adapter
// answered on its own.
func assertReachedManagerMap6871(t *testing.T, err error, mapName, call, harm string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s returned nil with no %s map loaded. The real manager writes that map "+
			"and fails when it is absent, so a nil means the adapter is not forwarding: %s",
			call, mapName, harm)
		return
	}
	if !strings.Contains(err.Error(), mapName) {
		t.Errorf("%s error = %q, want it to name %s: some other layer refused before the "+
			"manager's own map write was attempted", call, err, mapName)
	}
}

// TestEveryControllerAdapterMethodIsBound_6871 is the structural half: the table
// above must answer for exactly the methods the source declares.
//
// This is the cell that makes a NEW adapter method bound by construction. Adding
// one to controllers.go and forgetting to test it fails here by name, which is
// the outcome three hand-written sweeps in a row did not produce.
func TestEveryControllerAdapterMethodIsBound_6871(t *testing.T) {
	declared := adapterMethodsFromSource(t)
	table := adapterBindingTable()

	var missing, stale []string
	for name := range declared {
		if _, ok := table[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range table {
		if !declared[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)

	if len(missing) > 0 {
		t.Errorf("controller adapter methods with NO entry in adapterBindingTable: %v.\n"+
			"Every method of every type in adapterControllerTypes is a two-line production "+
			"forwarder whose body can be replaced with `return nil` invisibly to both "+
			"packages — that is how the first two, then four more, then a seventh were "+
			"found. Add a row with a driver, or a row with cannotDrive stating why not, so "+
			"the gap is VISIBLE rather than absent (#6871 round 8 B3)", missing)
	}
	if len(stale) > 0 {
		t.Errorf("adapterBindingTable entries naming methods that no longer exist: %v. "+
			"Either the method was renamed (update the row) or removed (delete it) — a "+
			"stale row is a row that proves nothing while looking like coverage", stale)
	}
}

// TestControllerAdapterMethodsReachTheManager_6871 is the behavioural half:
// every row actually runs, against the real Manager, through the production
// constructor the daemon uses.
func TestControllerAdapterMethodsReachTheManager_6871(t *testing.T) {
	for name, binding := range adapterBindingTable() {
		t.Run(strings.ReplaceAll(name, ".", "/"), func(t *testing.T) {
			if binding.cannotDrive != "" {
				if binding.drive != nil {
					t.Fatal("a row must have a driver OR a cannotDrive reason, not both")
				}
				t.Skipf("NOT DRIVEN: %s", binding.cannotDrive)
			}
			if binding.drive == nil {
				t.Fatal("row has neither a driver nor a cannotDrive reason; an empty row is " +
					"coverage that does not exist")
			}
			m, srv := newAdapterBindingManager(t)
			if binding.setup != nil {
				binding.setup(t, m)
			}
			binding.drive(t, m, srv)
		})
	}
}
