package dataplane

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #2114 A3 enforcement surface. Three mechanical nets, per the converged
// plan (docs/research/2114-nat-pool-alarm-dp-race/plan.md v99):
//
//  1. TestManager_PreArmMethodMatrix — every exported *Manager method is
//     assigned to exactly ONE armed-gate class by the handwritten manifest
//     below. The AST inventory enforces TOTALITY (an unassigned or
//     double-assigned method fails); the per-class OUTCOMES are enforced by
//     the runtime legs in armed_gate_legs_test.go; each label's CORRECTNESS
//     comes from the handwritten access audit reviewed in the PR (the
//     matrix cannot prove semantic disjointness and does not claim to).
//  2. TestManagerRegistryAccessAllowlist — the registry canary: no direct
//     m.maps / m.programs access outside the exactly-named allowlist (the
//     two lookup helpers + the publisher), with the domination/escape shape
//     rules, the stale-allowlist self-check, and synthetic negatives.
//  3. TestManagerRegistryCallsiteManifest — the stale-checked
//     helper-callsite manifest: every lookupMapLocked/lookupProgramLocked
//     callsite maps to its required/optional/raw outcome bit; a callsite
//     added, removed, or moved fails the build until the manifest and the
//     leg mapping are updated.

// managerMethodClasses is the handwritten class manifest: every exported
// *Manager method, exactly once. Classification is by the method's DIRECT
// Start-state access under the plan's escape-first precedence: a method
// that ESCAPES a Start-state reference is class 4; else a method touching
// Start-state with required pre-error Go-side side effects is class 3;
// else a method whose EVERY registry access is neutral-on-absent is
// class 2; else a method with at least one REQUIRED access is class 1.
// Methods touching only m.mu-protected Go state are category G; lifecycle
// and facade methods are categories L/F. A method that only DELEGATES into
// an already-classed internal is classed by that delegation target.
var managerMethodClasses = map[string]string{
	// --- class 1: fallible map-required (fresh -> ErrDataplaneNotArmed at
	// each REQUIRED access; armed/retained absent -> master's text) ---
	"AddTxPort": "class1", "AttachTC": "class1-carveout", "AttachXDP": "class1-carveout",
	"SetZone": "class1", "SetVlanIfaceInfo": "class1",
	"ClearIfaceZoneMap": "class1", "ClearVlanIfaceMap": "class1",
	"SwapToUserspaceXDPShimEntryProgram": "class1",
	"ReadGlobalCounter":                  "class1", "ReadInterfaceCounters": "class1", "ClearInterfaceCounters": "class1",
	"UpdateFabricFwd": "class1", "UpdateFabricFwd1": "class1",
	"UpdateRGActive": "class1", "UpdateHAWatchdog": "class1", "BumpFIBGeneration": "class1",
	"SetIfaceFilter": "class1", "ClearIfaceFilterMap": "class1",
	"SetFilterConfig": "class1", "ReadFilterConfig": "class1", "SetFilterRule": "class1",
	"SetPolicerConfig": "class1", "ClearPolicerConfigs": "class1",
	"ClearFilterConfigs": "class1", "ReadFilterCounters": "class1", "ClearFilterCounters": "class1",
	"SetFlowTimeout": "class1", "SetFlowConfig": "class1",
	"SetMirrorConfig": "class1", "ClearMirrorConfigs": "class1",
	"SetDNATEntry": "class1", "DeleteDNATEntry": "class1",
	"ReadNATPortCounter": "class1", "SetDNATEntryV6": "class1", "DeleteDNATEntryV6": "class1", "SetZoneConfig": "class1", "SetZonePairPolicy": "class1", "SetPolicyRule": "class1",
	"SetAddressBookEntry": "class1", "SetAddressMembership": "class1",
	"ClearAddressBookV4": "class1", "ClearAddressBookV6": "class1", "ClearAddressMembership": "class1",
	"SetApplication": "class1", "SetAppRange": "class1", "ClearAppRanges": "class1",
	"ClearZonePairPolicies": "class1", "ClearApplications": "class1", "SetDefaultPolicy": "class1",
	"ReadPolicyCounters": "class1", "ClearPolicyCounters": "class1",
	"SetScreenConfig": "class1", "ClearScreenConfigs": "class1",
	"UpdateSessionCountSrc": "class1", "UpdateSessionCountDst": "class1",
	"IterateSessions": "class1", "DeleteSession": "class1", "SetSessionV4": "class1",
	"GetSessionV4": "class1", "GetSessionV6": "class1", "IterateSessionsV6": "class1",
	"IterateSessionsFrom": "class1", "IterateSessionsV6From": "class1",
	"BatchIterateSessions": "class1", "BatchIterateSessionsV6": "class1",
	"BatchDeleteSessions": "class1", "BatchDeleteSessionsV6": "class1",
	"DeleteSessionV6": "class1", "SetSessionV6": "class1",
	// class 1 by delegation: the chunked clear delegates into the class-1
	// batch iterate/delete internals and surfaces their gate error.
	"ClearAllSessions": "class1", "ClearAllSessionsChunked": "class1",

	// --- class 2: neutral-outcome, any signature, WITH the uniform
	// synchronization rule (fresh outcome == master's missing-map outcome,
	// byte-for-byte) ---
	"Compile":                     "class2", // redirect_capable optional skip-and-continue
	"SessionCount":                "class2",
	"GetMapStats":                 "class2",
	"ClearSessionCounts":          "class2",
	"UpdatePolicyScheduleState":   "class2", // the #3780 deliberate nil
	"SeedNATPortCounters":         "class2",
	"SeedSessionIDCounter":        "class2",
	"DeleteStaleIfaceZone":        "class2",
	"DeleteStaleVlanIface":        "class2",
	"DeleteStaleZonePairPolicies": "class2",
	"DeleteStaleApplications":     "class2",
	"DeleteStaleDNATStatic":       "class2",
	"DeleteStaleDNATStaticV6":     "class2",
	"DeleteStaleStaticNAT":        "class2",
	"ZeroStaleScreenConfigs":      "class2",
	"DeleteStaleIfaceFilter":      "class2",
	"ZeroStaleFilterConfigs":      "class2",

	// --- class 3: required-side-effect hybrids, UNGATED (pinned legacy
	// behavior in every state; scoped lookups; ClearAllCounters composes
	// through the raw internals — the nested-call rule) ---
	"ClearNATRuleCounters": "class3",
	"ClearGlobalCounters":  "class3",
	"ClearZoneCounters":    "class3",
	"ClearAllCounters":     "class3",

	// --- class 4: escaping getters of Start-populated state ---
	"Map":            "class4",
	"Program":        "class4",
	"NewEventSource": "class4", // error signature: fresh -> the typed error

	// --- category L: lifecycle (arming/teardown path itself; ungated by
	// construction) + the retired-path no-op stubs ---
	"Load":                 "catL",
	"LoadUserspaceShim":    "catL",
	"Start":                "catL",
	"CompileUserspaceShim": "catL",
	"Close":                "catL",
	"Teardown":             "catL",
	"StartFIBSync":         "catL",
	"NotifyLinkCycle":      "catL",
	"SyncFabricState":      "catL",

	// --- category F: facade/domain accessors ---
	"Link":              "catF",
	"HA":                "catF",
	"Sessions":          "catF",
	"SessionDeltas":     "catF",
	"Telemetry":         "catF",
	"ApplyConfig":       "catF", // delegates Compile (classed) then LastApplyResult
	"LastApplyResult":   "catF",
	"LastCompileResult": "catF",

	// --- category G: ungated Go-state helpers (m.mu-protected offset state,
	// construction-time handles, the loaded bit read itself) ---
	"IncrementGlobalCounter":     "catG",
	"ReadUserspaceCounterOffset": "catG",
	"ReadZoneCounters":           "catG",
	"SetZoneCounterOffset":       "catG",
	// #6743 r4: master's #3643/#5275 work landed two exported *Manager
	// methods after this census was written, and neither touches the map
	// registry — the merge left the package's TEST BUILD red (159 vs 157)
	// until they were classified. ReplaceZoneCounterOffsets swaps the
	// m.mu-protected zoneCounterOffsets map wholesale (the plural sibling
	// of SetZoneCounterOffset); ProveArmCoverage (armproof.go) reads only
	// m.attachedInstance.
	"ReplaceZoneCounterOffsets": "catG",
	"ProveArmCoverage":          "catG",
	// #7191: ArmCoverageSummary reads only the armCoverage cell (its own RWMutex),
	// touches no map registry, and cannot arm or disarm anything on its own — the
	// daemon-side gate decides. Same class as the proof it reports.
	"ArmCoverageSummary": "catG",
	// #9725, the same shape twice. AttachedXDPLinkCount ranges the m.mu-protected
	// xdpLinks SNAPSHOT and asks the kernel whether each link is still attached;
	// SetAttachedLinksObserver stores one callback in an atomic cell. Neither
	// touches the map registry, and neither can arm or disarm anything — the
	// daemon-side transit gate decides on what they report. The first of the two
	// landed on this branch without being classified, which left the package's
	// TEST BUILD red at 141 vs 140 exactly as #6743 r4 records for its own pair.
	"AttachedXDPLinkCount":     "catG",
	"SetAttachedLinksObserver": "catG",
	"ClearZoneCounterOffsets":  "catG",
	"ReadFloodCounters":        "catG",
	"SetFloodCounterOffset":    "catG",
	// #3651 flood half: the plural sibling of SetFloodCounterOffset, and the
	// only production writer of the flood offset map. Same shape as
	// ReplaceZoneCounterOffsets above — it takes m.mu, rebuilds the
	// m.mu-protected floodCounterOffsets map from the caller's rows (nil on an
	// empty set) and returns; it touches neither m.maps nor m.programs, so its
	// behaviour is identical fresh, armed, and retained.
	"ReplaceFloodCounterOffsets": "catG",
	"ClearFloodCounterOffsets":   "catG",
	"ReadNATRuleCounter":         "catG",
	"SetNATRuleCounterOffset":    "catG",
	"ClearNATRuleCounterOffsets": "catG",
	"IsLoaded":                   "catG", // the gate read itself
	"GetPersistentNAT":           "catG",
	"XDPLinks":                   "catG",
	"TCLinks":                    "catG",
	// #6740: the guarded siblings of XDPLinks/TCLinks — pure reads of link
	// membership under m.mu, same class as the accessors they replace on the
	// 1 Hz status path. SetLinkForTest is a test seam (see its doc comment) and
	// touches no kernel state, so it classifies the same way.
	"XDPEntryPrograms":   "catG",
	"IsVLANSubInterface": "catG",
	"SetLinkForTest":     "catG",
	// #6741: a pure read of the observability counter under m.mu. It changes no
	// behaviour and needs no armed state, so it classifies with the other
	// registry-state reads.
	"ObsoleteRegistryAccesses": "catG",
	"DetachTC":                 "catG", // reads only the construction link map
	// DetachXDP's single label is category G (its direct access is the
	// construction link map) with the class-3-LIKE delegation target
	// setXDPAttachedFlag: scoped lookups, cleanup always runs, NO gate.
	"DetachXDP": "catG",
	// The xdpEntryProg trio: the field is m.mu-protected (locked-helper
	// scheme), so the accessors touch only m.mu-protected Go state.
	"XDPEntryProgram":                    "catG",
	"SelectUserspaceXDPShimEntryProgram": "catG",
	"UsingUserspaceXDPShimEntryProgram":  "catG",
}

// TestManager_PreArmMethodMatrix assigns every exported *Manager method to
// exactly one armed-gate class via the manifest above and the generated AST
// inventory: an unassigned or double-assigned method fails. It also asserts
// the class-3 raw-helper composition shape: ClearAllCounters must call the
// ungated raw internals and NOT the public gated Clear{Interface,Policy,
// Filter}Counters (whose fresh typed error would otherwise surface through
// the composition and break the pinned legacy texts).
func TestManager_PreArmMethodMatrix(t *testing.T) {
	t.Parallel()

	// AST inventory of exported *Manager methods across production files.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	inventory := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			ident, ok := star.X.(*ast.Ident)
			if !ok || ident.Name != "Manager" {
				continue
			}
			if fn.Name.IsExported() {
				inventory[fn.Name.Name] = true
			}
		}
	}

	if len(inventory) != 142 {
		t.Fatalf("exported *Manager method inventory = %d, want 142 (the 164 census minus the 23 NAT write methods retired in #7268, plus ArmCoverageSummary added in #7191, minus DeleteStaleNAT64 and ZeroStaleNATPoolConfigs retired in #7804 — the writers for snat_rules, static_nat_*, nptv6_rules, nat_pool_*, snat_egress_ips and nat64_* maps, none of which the AF_XDP shim declares — plus the two #9725 additions: AttachedXDPLinkCount, the live count the transit gate opens on, and SetAttachedLinksObserver, the registration the gate needs on the runtime the daemon publishes. This census was already red at 141 on the first #9725 commit, which added the first of those without reconciling it; the #9725 test helpers are deliberately unexported and live in test files so they do not enter this census); reconcile the count or the plan", len(inventory))
	}
	for name := range inventory {
		if _, ok := managerMethodClasses[name]; !ok {
			t.Errorf("exported *Manager method %s is UNASSIGNED in managerMethodClasses", name)
		}
	}
	for name := range managerMethodClasses {
		if !inventory[name] {
			t.Errorf("managerMethodClasses names %s, which is not an exported *Manager method (stale entry)", name)
		}
	}

	// Invoke-table coextensiveness (Codex PR #6743 self-audit hardened):
	// every class-1/2/3 manifest member must be driven by the
	// armedGateInvoke driver or named in the exemption set — a method
	// silently absent from BOTH is untested by the fresh/retained/blocked
	// legs and fails here.
	invoke := armedGateInvoke()
	for name, class := range managerMethodClasses {
		if class != "class1" && class != "class2" && class != "class3" && class != "class1-carveout" {
			continue
		}
		_, driven := invoke[name]
		_, exempt := armedGateInvokeExemptions[name]
		if !driven && !exempt {
			t.Errorf("manifest member %s (%s) is neither driven by armedGateInvoke nor exempted — the outcome legs do not cover it", name, class)
		}
		if driven && exempt {
			t.Errorf("manifest member %s is both driven and exempted — remove one", name)
		}
	}
	for name := range armedGateInvokeExemptions {
		if _, ok := managerMethodClasses[name]; !ok {
			t.Errorf("exemption %s is not a manifest member (stale)", name)
		}
	}

	// Class-3 raw-helper composition shape: ClearAllCounters' body must
	// reference the raw internals and must NOT call the public gated
	// ClearInterfaceCounters/ClearPolicyCounters/ClearFilterCounters.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "maps_counters.go", nil, 0)
	if err != nil {
		t.Fatalf("parse maps_counters.go: %v", err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ClearAllCounters" || fn.Body == nil {
			return true
		}
		calls := map[string]bool{}
		ast.Inspect(fn.Body, func(n2 ast.Node) bool {
			call, ok := n2.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				calls[sel.Sel.Name] = true
			}
			return true
		})
		for _, want := range []string{"clearInterfaceCountersRaw", "clearPolicyCountersRaw", "clearFilterCountersRaw"} {
			if !calls[want] {
				t.Errorf("ClearAllCounters does not compose through %s (class-3 nested-call rule)", want)
			}
		}
		for _, banned := range []string{"ClearInterfaceCounters", "ClearPolicyCounters", "ClearFilterCounters"} {
			if calls[banned] {
				t.Errorf("ClearAllCounters calls the public gated %s — its fresh typed error would replace the pinned legacy text in the composition", banned)
			}
		}
		return false
	})
}

// armedGateInvokeExemptions names the class-1/2/3 manifest members that
// legitimately CANNOT join the armedGateInvoke driver, with the reason —
// the matrix asserts the invoke table plus this set is coextensive with
// the manifest (a missing entry fails either side).
var armedGateInvokeExemptions = map[string]string{
	// The carve-out pair reject at their own pre-registry loaded check on
	// both unarmed states and attach netlink links when armed — they are
	// asserted directly in the fresh/retained/pass-then-block legs.
	"AttachXDP": "carve-out: asserted directly (fresh+retained+pass-then-block legs)",
	"AttachTC":  "carve-out: asserted directly (pass-then-block leg)",
	// Compile's only direct registry access (redirect_capable) runs past
	// CompileConfig's loaded check, so it never blocks pre-arm and cannot
	// join the blocked legs; its fresh/retained outcomes are asserted
	// directly and its armed continuation maps to production smoke (the
	// shim registry never carries redirect_capable).
	"Compile": "carve-out path: fresh/retained loaded-rejection asserted directly; armed continuation via production smoke",
}

// registryAccessAllowlist names the ONLY functions permitted to touch
// m.maps / m.programs: the two scoped lookup helpers (uniform registry
// rule) and the whole-batch publisher. Everything else routes through the
// helpers. The stale-allowlist self-check below fails if an allowlisted
// function is renamed or removed without updating the canary.
var registryAccessAllowlist = map[string]bool{
	"lookupMapLocked":           true,
	"lookupProgramLocked":       true,
	"publishShimRegistryLocked": true,
	// #7755: the Teardown FD-close snapshot. Added as a HELPER rather than
	// by allowlisting Teardown itself — the canary defends "registry access
	// lives only in a small reviewable set of functions", and naming the
	// caller would have widened that set instead of preserving it.
	"takeRegistryHandles": true,
}

// unwrapOwnerIdent strips any parenthesization and pointer-dereference
// layers to reach the underlying owner identifier (Codex PR #6743 r3-2):
// m, (*m), and ((*m)) all resolve to the same ident; anything more
// complex (calls, selector chains) yields nil so it cannot claim credit.
func unwrapOwnerIdent(expr ast.Expr) *ast.Ident {
	for {
		switch x := expr.(type) {
		case *ast.ParenExpr:
			expr = x.X
		case *ast.StarExpr:
			expr = x.X
		case *ast.Ident:
			return x
		default:
			return nil
		}
	}
}

// registryCanaryViolations parses every production .go file under root and
// reports: (a) any m.maps/m.programs reference outside the allowlisted
// functions; (b) inside an allowlisted function, any registry reference NOT
// dominated by the m.mu acquisition (an explicit Unlock before the access
// fails — the Lock -> hook -> Unlock -> access anti-pattern), any access
// that is not an index read/write or len() (the container is never
// returned, aliased, assigned, closed over, or passed as an argument), and
// (c) for the publisher, that its writes are followed by EXACTLY ONE
// in-lock loaded.Store(true) positioned AFTER the last registry write.
//
// Receiver handling (Codex PR #6743 M2): the registry owner is identified
// by TYPE, not by the identifier spelling — the *Manager receiver (whatever
// it is named), any *Manager-typed parameter, and one-level local aliases
// (`x := m`) all resolve, so `mgr.maps["x"]` or `alias.maps["x"]` cannot
// slip past by renaming.
func registryCanaryViolations(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var violations []string

	// Parse every production file ONCE, up front (Codex PR #6743 r3-2):
	// type aliases resolve PACKAGE-wide, so the alias set must be
	// collected across all files before any per-file check runs — an
	// alias declared in another file used to produce no owner at all.
	type parsedFile struct {
		name string
		fset *token.FileSet
		file *ast.File
	}
	var parsed []parsedFile
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(root, name)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		parsed = append(parsed, parsedFile{name, fset, file})
	}

	// The Manager-alias set, package-wide and to a fixpoint (Codex PR
	// #6743 r3-2): direct `type X = Manager`, chained `type B = A`
	// where A is itself an alias, and pointer-RHS `type P = *Manager`
	// (a pointer alias cannot be a receiver base type, but it CAN type
	// a parameter whose registry access aliases the shared maps).
	managerAliases := map[string]bool{"Manager": true}
	for changed := true; changed; {
		changed = false
		for _, pf := range parsed {
			for _, decl := range pf.file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, spec := range gd.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || ts.Assign == token.NoPos || managerAliases[ts.Name.Name] {
						continue
					}
					switch rhs := ts.Type.(type) {
					case *ast.Ident:
						if managerAliases[rhs.Name] {
							managerAliases[ts.Name.Name] = true
							changed = true
						}
					case *ast.StarExpr:
						if id, ok := rhs.X.(*ast.Ident); ok && managerAliases[id.Name] {
							managerAliases[ts.Name.Name] = true
							changed = true
						}
					}
				}
			}
		}
	}

	// isManagerStar recognizes *Manager and Manager-typed (or
	// package-aliased) receivers/params — including value params of
	// an aliased struct type, whose map field copy still aliases the
	// shared registry (Codex PR #6743 r2-3).
	var isManagerStar func(ast.Expr) bool
	isManagerStar = func(expr ast.Expr) bool {
		switch t := expr.(type) {
		case *ast.StarExpr:
			id, ok := t.X.(*ast.Ident)
			return ok && managerAliases[id.Name]
		case *ast.Ident:
			return managerAliases[t.Name]
		case *ast.ParenExpr:
			return isManagerStar(t.X)
		}
		return false
	}

	for _, pf := range parsed {
		name := pf.name
		fset := pf.fset
		file := pf.file
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			allowed := registryAccessAllowlist[fn.Name.Name]

			// The registry-owner identifier set: the *Manager receiver,
			// *Manager-typed parameters, and one-level local aliases.
			owners := map[string]bool{}
			if fn.Recv != nil {
				for _, rf := range fn.Recv.List {
					if isManagerStar(rf.Type) {
						for _, n := range rf.Names {
							owners[n.Name] = true
						}
					}
				}
			}
			if fn.Type.Params != nil {
				for _, pf := range fn.Type.Params.List {
					if isManagerStar(pf.Type) {
						for _, n := range pf.Names {
							owners[n.Name] = true
						}
					}
				}
			}
			// The lock-credit set is the RECEIVER's own alias closure only —
			// locking a *Manager PARAMETER (possibly a different object)
			// must not count as holding this registry's lock (Codex PR
			// #6743 r2-3).
			lockOwners := map[string]bool{}
			if fn.Recv != nil {
				for _, rf := range fn.Recv.List {
					if isManagerStar(rf.Type) {
						for _, n := range rf.Names {
							lockOwners[n.Name] = true
						}
					}
				}
			}
			if len(owners) > 0 {
				// Alias propagation to a fixpoint: `x := <owner>` or
				// `var x = <owner>` makes x an owner; iterate so a := m;
				// b := a resolves (r2-3). The ValueSpec shape is covered
				// too — a var-declared alias propagates identically
				// (Codex PR #6743 r3-2).
				propagate := func(set map[string]bool) {
					for changed := true; changed; {
						changed = false
						pair := func(l, r ast.Expr) {
							id, ok := r.(*ast.Ident)
							if !ok || !set[id.Name] {
								return
							}
							if lid, ok := l.(*ast.Ident); ok && !set[lid.Name] {
								set[lid.Name] = true
								changed = true
							}
						}
						ast.Inspect(fn.Body, func(n ast.Node) bool {
							switch as := n.(type) {
							case *ast.AssignStmt:
								if len(as.Lhs) == len(as.Rhs) {
									for i := range as.Lhs {
										pair(as.Lhs[i], as.Rhs[i])
									}
								}
							case *ast.ValueSpec:
								if len(as.Names) == len(as.Values) {
									for i := range as.Names {
										pair(as.Names[i], as.Values[i])
									}
								}
							}
							return true
						})
					}
				}
				propagate(owners)
				propagate(lockOwners)
			}

			// Lock/unlock positions and the receiver-scoped loaded.Store(true).
			var lockPos token.Pos
			var directUnlocks []token.Pos
			storeTrueCount := 0
			var storeTruePos token.Pos
			var shapeViolations []string
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.DeferStmt:
					return false // deferred calls run at function end
				case *ast.FuncLit:
					// Codex PR #6743 r3-3: a lock inside a closure runs at
					// closure-CALL time (possibly never), so it must not
					// credit a lexically-later access with the hold.
					return false
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					recvSel, ok := sel.X.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					recvID := unwrapOwnerIdent(recvSel.X)
					if recvID == nil || !lockOwners[recvID.Name] {
						return true
					}
					switch {
					case recvSel.Sel.Name == "mu" && sel.Sel.Name == "Lock":
						if lockPos == token.NoPos {
							lockPos = node.Pos()
						}
					case recvSel.Sel.Name == "mu" && sel.Sel.Name == "Unlock":
						directUnlocks = append(directUnlocks, node.Pos())
					case recvSel.Sel.Name == "loaded" && sel.Sel.Name == "Store":
						if len(node.Args) > 0 {
							if id, ok := node.Args[0].(*ast.Ident); ok && id.Name == "true" {
								storeTrueCount++
								storeTruePos = node.Pos()
							}
						}
					}
				}
				return true
			})

			// Method-value lock/unlock aliases (Codex PR #6743 r2-5a):
			// `u := m.mu.Unlock; u()` releases the hold invisible to the
			// direct-call scan — flag the method-value assignment itself.
			// The var-decl shape `var u = m.mu.Unlock` escapes identically
			// (Codex PR #6743 r3-5a), so ValueSpec values are scanned too.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				var rhss []ast.Expr
				var stmtPos token.Pos
				switch st := n.(type) {
				case *ast.AssignStmt:
					rhss = st.Rhs
					stmtPos = st.Pos()
				case *ast.ValueSpec:
					rhss = st.Values
					stmtPos = st.Pos()
				default:
					return true
				}
				for _, rhs := range rhss {
					sel, ok := rhs.(*ast.SelectorExpr)
					if !ok || (sel.Sel.Name != "Unlock" && sel.Sel.Name != "Lock") {
						continue
					}
					muSel, ok := sel.X.(*ast.SelectorExpr)
					if !ok || muSel.Sel.Name != "mu" {
						continue
					}
					recvID := unwrapOwnerIdent(muSel.X)
					if recvID == nil || !lockOwners[recvID.Name] {
						continue
					}
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: m.mu.%s taken as a method value in %s — the lock operation escapes the lexical scan", name, fset.Position(stmtPos), sel.Sel.Name, fn.Name.Name))
				}
				return true
			})

			// Lookup-helper method-value escapes (Codex PR #6743 r3-5b):
			// `lookup := m.lookupMapLocked; lookup("sessions")` adds an
			// unmanifested, potentially ungated callsite the direct-call
			// collectors (and their 135-row manifest) cannot see. Flag
			// any helper reference that is not in call position.
			var mvStack []ast.Node
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if n == nil {
					if len(mvStack) > 0 {
						mvStack = mvStack[:len(mvStack)-1]
					}
					return true
				}
				mvStack = append(mvStack, n)
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "lookupMapLocked" && sel.Sel.Name != "lookupProgramLocked") {
					return true
				}
				if len(mvStack) >= 2 {
					if call, ok := mvStack[len(mvStack)-2].(*ast.CallExpr); ok && call.Fun == sel {
						return true // direct call — the callsite collectors cover it
					}
				}
				shapeViolations = append(shapeViolations,
					fmt.Sprintf("%s:%s: lookup helper %s referenced as a method value in %s — an unmanifested callsite the gate manifest cannot key", name, fset.Position(sel.Pos()), sel.Sel.Name, fn.Name.Name))
				return true
			})

			// Registry references with shape + domination classification.
			var lastWritePos token.Pos
			var stack []ast.Node
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if n == nil {
					if len(stack) > 0 {
						stack = stack[:len(stack)-1]
					}
					return true
				}
				stack = append(stack, n)
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "maps" && sel.Sel.Name != "programs") {
					return true
				}
				// m.maps / (*m).maps / ((*m)).maps all resolve to m
				// (Codex PR #6743 r3-2: the one-layer unwrap used to
				// stop at the first paren).
				recv := unwrapOwnerIdent(sel.X)
				if recv == nil || !owners[recv.Name] {
					return true
				}
				pos := fset.Position(sel.Pos())
				if !allowed {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: raw %s.%s access in %s (outside the allowlist)", name, pos, recv.Name, sel.Sel.Name, fn.Name.Name))
					return true
				}
				// Codex PR #6743 r3-3: the lock credit belongs to the
				// RECEIVER's own alias closure — an allowlisted access
				// through a *Manager PARAMETER (possibly a different
				// object) is not guarded by the receiver's m.mu hold.
				if !lockOwners[recv.Name] {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: registry access through %s in allowlisted %s is not covered by the receiver's own m.mu hold (a locked *Manager parameter can be a different object)", name, pos, recv.Name, fn.Name.Name))
					return true
				}
				var parent ast.Node
				if len(stack) >= 2 {
					parent = stack[len(stack)-2]
				}
				shapeOK := false
				switch p := parent.(type) {
				case *ast.IndexExpr:
					if p.X == sel {
						shapeOK = true
						// Track the last registry index-WRITE for the
						// publisher's Store-ordering rule.
						if len(stack) >= 3 {
							if as, ok := stack[len(stack)-3].(*ast.AssignStmt); ok {
								for _, lhs := range as.Lhs {
									if lhs == ast.Expr(p) {
										lastWritePos = sel.Pos()
									}
								}
							}
						}
					}
				case *ast.CallExpr:
					if id, ok := p.Fun.(*ast.Ident); ok && id.Name == "len" {
						shapeOK = true
					}
				case *ast.RangeStmt:
					// #7755: iterating the registry is NOT an alias escape, and
					// this check's own stated hazard is aliasing — "container
					// returned/aliased/assigned/passed". A `range` COPIES each
					// key and value into fresh locals; the container reference
					// does not outlive the statement, so nothing can read it
					// after the lock is dropped. The rule was broader than its
					// rationale, which is why it caught a safe operation
					// (Teardown enumerating handles to CLOSE their FDs, where
					// map names are dynamic so there is nothing to index by).
					//
					// This does NOT weaken the lock requirement: the domination
					// check below is separate and still demands the access
					// follow an m.mu.Lock in this function with no direct
					// unlock, so `range` without the lock is still a violation.
					// Nor does it widen the ALLOWLIST — only allowlisted
					// functions reach this switch at all.
					//
					// The negatives test drives every real aliasing shape
					// (assign, struct field, return, argument) plus
					// range-without-lock, and each must still fail.
					if p.X == sel {
						shapeOK = true
					}
				}
				if !shapeOK {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: %s.%s escapes as a non-indexed reference in %s (container returned/aliased/assigned/passed)", name, pos, recv.Name, sel.Sel.Name, fn.Name.Name))
				}
				// Domination: an allowlisted function MUST hold the lock;
				// the access must follow the first lock and no direct unlock.
				if lockPos == token.NoPos {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: %s.%s access in allowlisted %s without any m.mu.Lock", name, pos, recv.Name, sel.Sel.Name, fn.Name.Name))
				} else if sel.Pos() < lockPos {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s:%s: %s.%s access precedes the m.mu.Lock in %s", name, pos, recv.Name, sel.Sel.Name, fn.Name.Name))
				}
				for _, up := range directUnlocks {
					if sel.Pos() > up {
						shapeViolations = append(shapeViolations,
							fmt.Sprintf("%s:%s: %s.%s access follows a direct m.mu.Unlock in %s (unlock-before-access)", name, pos, recv.Name, sel.Sel.Name, fn.Name.Name))
					}
				}
				return true
			})

			if fn.Name.Name == "publishShimRegistryLocked" {
				if storeTrueCount != 1 {
					shapeViolations = append(shapeViolations,
						fmt.Sprintf("%s: publishShimRegistryLocked has %d loaded.Store(true) calls, want exactly 1", name, storeTrueCount))
				} else {
					// The armed flag is the batch's FINAL in-hold step: the
					// Store must follow the lock, follow the last registry
					// write, and precede any direct unlock.
					if lockPos == token.NoPos || storeTruePos < lockPos {
						shapeViolations = append(shapeViolations,
							fmt.Sprintf("%s: publishShimRegistryLocked's Store(true) is not inside the m.mu hold", name))
					}
					if lastWritePos != token.NoPos && storeTruePos < lastWritePos {
						shapeViolations = append(shapeViolations,
							fmt.Sprintf("%s: publishShimRegistryLocked's Store(true) precedes a registry write — the batch must publish population BEFORE the flag", name))
					}
					for _, up := range directUnlocks {
						if storeTruePos > up {
							shapeViolations = append(shapeViolations,
								fmt.Sprintf("%s: publishShimRegistryLocked's Store(true) follows a direct Unlock — outside the hold", name))
						}
					}
				}
			}
			violations = append(violations, shapeViolations...)
		}
	}
	return violations
}

// TestManagerRegistryAccessAllowlist is the registry canary (#2114 A3):
// every m.maps/m.programs access in the package goes through the scoped
// lookup helpers or the whole-batch publisher — anything else fails here,
// so a future raw access (which would race the publication batch) cannot
// land silently.
func TestManagerRegistryAccessAllowlist(t *testing.T) {
	t.Parallel()

	if violations := registryCanaryViolations(t, "."); len(violations) > 0 {
		t.Fatalf("registry-access canary violations:\n%s", strings.Join(violations, "\n"))
	}

	// Stale-allowlist self-check: every allowlisted function must exist as
	// a *Manager method in the package (a rename without a canary update
	// fails here rather than silently widening the surface).
	fset := token.NewFileSet()
	found := map[string]bool{}
	files, _ := filepath.Glob("*.go")
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && registryAccessAllowlist[fn.Name.Name] {
				found[fn.Name.Name] = true
			}
		}
	}
	for name := range registryAccessAllowlist {
		if !found[name] {
			t.Errorf("allowlisted function %s not found in the package (stale allowlist entry)", name)
		}
	}
}

// TestManagerRegistryAccessAllowlistNegatives drives the canary over
// synthetic fixtures in every failure direction: a raw access outside the
// allowlist, a container alias escape inside an allowlisted-shaped
// function, and an unlock-before-access anti-pattern must each be caught;
// the well-formed helpers/publisher shapes must pass.
func TestManagerRegistryAccessAllowlistNegatives(t *testing.T) {
	t.Parallel()

	good := `package dataplane

func (m *Manager) lookupMapLocked(name string) (h *ebpf.Map, present bool, st registryState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, present = m.maps[name]
	return h, present, m.classifyRegistryLocked()
}

func (m *Manager) publishShimRegistryLocked(prog *ebpf.Program, collMaps, sharedMaps map[string]*ebpf.Map) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.programs[userspaceShimEntryProg] = prog
	for name, umap := range collMaps {
		m.maps[name] = umap
	}
	m.loaded.Store(true)
}

func (m *Manager) takeRegistryHandles() []*ebpf.Map {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*ebpf.Map, 0, len(m.maps))
	for _, h := range m.maps {
		out = append(out, h)
	}
	return out
}
`
	// #7755: the range refinement must not have loosened the LOCK requirement.
	// The good fixture above ranges the registry under m.mu and is clean; this
	// is the identical shape with the lock removed and it must still fail. It
	// is the negative the refinement owes -- without it, "range is permitted"
	// would be indistinguishable from "range is permitted anywhere".
	rangeNoLock := `package dataplane

func (m *Manager) takeRegistryHandles() []*ebpf.Map {
	out := make([]*ebpf.Map, 0, len(m.maps))
	for _, h := range m.maps {
		out = append(out, h)
	}
	return out
}
`
	rawAccess := `package dataplane

func (m *Manager) sneaky(name string) *ebpf.Map {
	return m.maps[name]
}
`
	aliasEscape := `package dataplane

func (m *Manager) lookupMapLocked(name string) map[string]*ebpf.Map {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.maps
}
`
	unlockBeforeAccess := `package dataplane

func (m *Manager) lookupProgramLocked(name string) *ebpf.Program {
	m.mu.Lock()
	m.mu.Unlock()
	return m.programs[name]
}
`
	renamedReceiver := `package dataplane

func (mgr *Manager) sneakyRenamed(name string) *ebpf.Map {
	return mgr.maps[name]
}
`
	aliasReceiver := `package dataplane

func (m *Manager) sneakyAlias(name string) *ebpf.Map {
	alias := m
	return alias.maps[name]
}
`
	noLockAllowlisted := `package dataplane

func (m *Manager) lookupMapLocked(name string) *ebpf.Map {
	return m.maps[name]
}
`
	storeAfterUnlock := `package dataplane

func (m *Manager) publishShimRegistryLocked(prog *ebpf.Program, collMaps map[string]*ebpf.Map) {
	m.mu.Lock()
	m.programs["x"] = prog
	m.mu.Unlock()
	m.loaded.Store(true)
}
`
	parenReceiver := `package dataplane

func (m *Manager) sneakyParen(name string) *ebpf.Map {
	return (*m).maps[name]
}
`
	twoHopAlias := `package dataplane

func (m *Manager) sneakyTwoHop(name string) *ebpf.Map {
	a := m
	b := a
	return b.maps[name]
}
`
	typeAliasParam := `package dataplane

type managerAlias = Manager

func sneakyAliasParam(mgr managerAlias, name string) *ebpf.Map {
	return mgr.maps[name]
}
`
	methodValueUnlock := `package dataplane

func (m *Manager) lookupMapLocked(name string) (h *ebpf.Map, present bool, st registryState) {
	m.mu.Lock()
	u := m.mu.Unlock
	u()
	h, present = m.maps[name]
	return h, present, registryFresh
}
`
	paramLockNotCredited := `package dataplane

func (m *Manager) lookupMapLocked(other *Manager, name string) *ebpf.Map {
	other.mu.Lock()
	defer other.mu.Unlock()
	return m.maps[name]
}
`
	// Codex PR #6743 r3-2 negatives: the alias shapes that used to produce
	// NO owner (and therefore no violation) — cross-file aliases, chained
	// aliases, pointer-RHS aliases, and multi-layer parenthesized access.
	crossFileAliasDecl := `package dataplane

type managerCrossAlias = Manager
`
	crossFileAliasUse := `package dataplane

func sneakyCrossFile(mgr managerCrossAlias, name string) *ebpf.Map {
	return mgr.maps[name]
}
`
	chainedAlias := `package dataplane

type managerChainA = Manager
type managerChainB = managerChainA

func sneakyChained(mgr managerChainB, name string) *ebpf.Map {
	return mgr.maps[name]
}
`
	pointerAliasParam := `package dataplane

type managerPtrAlias = *Manager

func sneakyPtrAlias(mgr managerPtrAlias, name string) *ebpf.Map {
	return mgr.maps[name]
}
`
	multiParen := `package dataplane

func (m *Manager) sneakyMultiParen(name string) *ebpf.Map {
	return ((*m)).maps[name]
}
`
	// Codex PR #6743 r3-3 negatives: locking the receiver while reading
	// THROUGH A PARAMETER (possibly a different object), and a lock inside
	// a never-called closure — both used to credit the access.
	crossObjectLock := `package dataplane

func (m *Manager) lookupMapLocked(other *Manager, name string) *ebpf.Map {
	m.mu.Lock()
	defer m.mu.Unlock()
	return other.maps[name]
}
`
	closureLock := `package dataplane

func (m *Manager) lookupMapLocked(name string) *ebpf.Map {
	f := func() { m.mu.Lock() }
	_ = f
	return m.maps[name]
}
`
	// Codex PR #6743 r3-5 negatives: the var-declared lock method value,
	// and a lookup helper referenced as a method value (an unmanifested
	// callsite).
	varMethodValue := `package dataplane

func (m *Manager) lookupMapLocked(name string) (h *ebpf.Map, present bool, st registryState) {
	m.mu.Lock()
	var u = m.mu.Unlock
	u()
	h, present = m.maps[name]
	return h, present, registryFresh
}
`
	helperMethodValue := `package dataplane

func (m *Manager) sneakyHelperValue(name string) *ebpf.Map {
	lookup := m.lookupMapLocked
	h, _, _ := lookup(name)
	return h
}
`

	dir := t.TempDir()
	write := func(n, src string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}

	write("good.go", good)
	if violations := registryCanaryViolations(t, dir); len(violations) > 0 {
		t.Fatalf("well-formed fixture reported violations: %v", violations)
	}

	write("bad_rangenolock.go", rangeNoLock)
	write("bad_raw.go", rawAccess)
	write("bad_alias.go", aliasEscape)
	write("bad_unlock.go", unlockBeforeAccess)
	write("bad_recv.go", renamedReceiver)
	write("bad_recv_alias.go", aliasReceiver)
	write("bad_nolock.go", noLockAllowlisted)
	write("bad_store_order.go", storeAfterUnlock)
	write("bad_paren.go", parenReceiver)
	write("bad_twohop.go", twoHopAlias)
	write("bad_typealias.go", typeAliasParam)
	write("bad_methodvalue.go", methodValueUnlock)
	write("bad_paramlock.go", paramLockNotCredited)
	write("bad_crossfile_decl.go", crossFileAliasDecl)
	write("bad_crossfile_use.go", crossFileAliasUse)
	write("bad_chained.go", chainedAlias)
	write("bad_ptralias.go", pointerAliasParam)
	write("bad_multiparen.go", multiParen)
	write("bad_crossobject.go", crossObjectLock)
	write("bad_closurelock.go", closureLock)
	write("bad_varmethodvalue.go", varMethodValue)
	write("bad_helpermethodvalue.go", helperMethodValue)
	violations := registryCanaryViolations(t, dir)
	saw := map[string]bool{}
	for _, v := range violations {
		switch {
		case strings.Contains(v, "in sneaky ") && strings.Contains(v, "outside the allowlist"):
			saw["raw"] = true
		case strings.Contains(v, "in sneakyCrossFile ") && strings.Contains(v, "outside the allowlist"):
			saw["crossfilealias"] = true
		case strings.Contains(v, "in sneakyChained ") && strings.Contains(v, "outside the allowlist"):
			saw["chainedalias"] = true
		case strings.Contains(v, "in sneakyPtrAlias ") && strings.Contains(v, "outside the allowlist"):
			saw["ptralias"] = true
		case strings.Contains(v, "in sneakyMultiParen ") && strings.Contains(v, "outside the allowlist"):
			saw["multiparen"] = true
		case strings.Contains(v, "in sneakyHelperValue ") && strings.Contains(v, "unmanifested callsite"):
			saw["helpermethodvalue"] = true
		case strings.Contains(v, "not covered by the receiver's own m.mu hold"):
			saw["crossobject"] = true
		case strings.Contains(v, "in sneakyAliasParam ") && strings.Contains(v, "outside the allowlist"):
			saw["typealias"] = true
		case strings.Contains(v, "in sneakyAlias ") && strings.Contains(v, "outside the allowlist"):
			saw["recvAlias"] = true
		case strings.Contains(v, "sneakyRenamed") && strings.Contains(v, "outside the allowlist"):
			saw["renamedRecv"] = true
		case strings.Contains(v, "escapes as a non-indexed reference"):
			saw["alias"] = true
		case strings.Contains(v, "unlock-before-access"):
			saw["unlock"] = true
		case strings.Contains(v, "bad_rangenolock.go") && strings.Contains(v, "without any m.mu.Lock"):
			saw["rangenolock"] = true
		case strings.Contains(v, "bad_paramlock.go") && strings.Contains(v, "without any m.mu.Lock"):
			saw["paramlock"] = true
		case strings.Contains(v, "bad_closurelock.go") && strings.Contains(v, "without any m.mu.Lock"):
			saw["closurelock"] = true
		case strings.Contains(v, "without any m.mu.Lock"):
			saw["nolock"] = true
		case strings.Contains(v, "Store(true) follows a direct Unlock"):
			saw["storeOrder"] = true
		case strings.Contains(v, "sneakyParen"):
			saw["paren"] = true
		case strings.Contains(v, "sneakyTwoHop"):
			saw["twohop"] = true
		case strings.Contains(v, "bad_varmethodvalue.go") && strings.Contains(v, "method value"):
			saw["varmethodvalue"] = true
		case strings.Contains(v, "method value"):
			saw["methodvalue"] = true
		}
	}
	for _, k := range []string{"raw", "recvAlias", "renamedRecv", "alias", "unlock", "nolock", "storeOrder", "paren", "twohop", "typealias", "methodvalue", "paramlock", "crossfilealias", "chainedalias", "ptralias", "multiparen", "crossobject", "closurelock", "varmethodvalue", "helpermethodvalue", "rangenolock"} {
		if !saw[k] {
			t.Errorf("canary missed synthetic negative %q; violations:\n%s", k, strings.Join(violations, "\n"))
		}
	}
}

// registryCallsiteManifestEntry pins one lookupMapLocked/lookupProgramLocked
// callsite: file, enclosing function, registry kind, the literal name
// argument ("<ident:x>"/"<dynamic>" when not a literal), and the outcome
// role — "required" (the fresh gate follows the call), "optional"
// (master's per-site neutral outcome), or "raw" (a class-3 ungated
// composition leg). The manifest is STALE-CHECKED by
// TestManagerRegistryCallsiteManifest: a callsite added, removed, or moved
// fails the build until the manifest and its leg mapping are updated.
// The 17 mixed sites carry their named §9 continuation leg in a comment.
type registryCallsiteManifestEntry struct {
	file, fn, kind, arg, role string
}

var registryCallsiteManifest = []registryCallsiteManifestEntry{
	{"compiler.go", "Compile", "map", `"redirect_capable"`, "optional"}, // leg: Compile continuation (absent redirect_capable skips AND CONTINUES into attachment work)
	{"loader.go", "AddTxPort", "map", `"tx_ports"`, "required"},
	{"loader.go", "AttachTC", "prog", `"tc_main_prog"`, "carveout"}, // carve-out: the pre-registry loaded rejection fires first on both unarmed states; the lookup keeps master's not-found text
	{"loader.go", "ClearIfaceZoneMap", "map", `"iface_zone_map"`, "required"},
	{"loader.go", "ClearVlanIfaceMap", "map", `"vlan_iface_map"`, "required"},
	{"loader.go", "Map", "map", "<ident:name>", "optional"},        // class 4: nil outcome
	{"loader.go", "NewEventSource", "map", `"events"`, "required"}, // class 4 with error signature: fresh -> typed error
	{"loader.go", "Program", "prog", "<ident:name>", "optional"},   // class 4: nil outcome
	{"loader.go", "SetVlanIfaceInfo", "map", `"vlan_iface_map"`, "required"},
	{"loader.go", "SetZone", "map", `"iface_zone_map"`, "required"},
	{"loader.go", "clearNativeXDPFlags", "map", `"iface_zone_map"`, "optional"},
	{"loader.go", "clearNativeXDPFlagsForIfindexes", "map", `"iface_zone_map"`, "optional"},
	{"loader.go", "setXDPAttachedFlag", "map", `"iface_zone_map"`, "optional"}, // leg (iii): absent -> master's early-boot no-op NIL, claims untouched
	{"loader.go", "setXDPAttachedFlag", "map", `"vlan_iface_map"`, "optional"}, // leg: absent vlan_iface_map CONTINUES into the physical-interface processing
	// #9725: moved out of loader.go with the XDP attach/detach lifecycle when the
	// #7253 modularity audit required that split. Same callsites, new file.
	{"loader_xdp_links.go", "AttachXDP", "prog", "<ident:entryProg>", "carveout"},              // carve-out
	{"loader_xdp_links.go", "seedInterfaceCounter", "map", `"interface_counters"`, "optional"}, // leg (ii): absent skips the seed (AttachXDP/AddTxPort still succeed); present asserts the seed wrote
	{"loader_xdp_links.go", "swapXDPEntryProg", "prog", "<ident:name>", "required"},
	{"maps_counters.go", "ClearGlobalCounters", "map", `"global_counters"`, "optional"}, // class 3: pinned legacy behavior
	{"maps_counters.go", "ClearInterfaceCounters", "map", `"interface_counters"`, "required"},
	{"maps_counters.go", "ClearZoneCounters", "map", `"zone_counters"`, "optional"}, // class 3
	{"maps_counters.go", "ReadGlobalCounter", "map", `"global_counters"`, "required"},
	{"maps_counters.go", "ReadInterfaceCounters", "map", `"interface_counters"`, "required"},
	{"maps_counters.go", "clearInterfaceCountersRaw", "map", `"interface_counters"`, "raw"}, // class-3 nested-call composition leg (legacy text preserved)
	{"maps_fabric.go", "BumpFIBGeneration", "map", `"fib_gen_map"`, "required"},
	{"maps_fabric.go", "UpdateFabricFwd", "map", `"fabric_fwd"`, "required"},
	{"maps_fabric.go", "UpdateFabricFwd1", "map", `"fabric_fwd"`, "required"},
	{"maps_fabric.go", "UpdateHAWatchdog", "map", `"ha_watchdog"`, "required"},
	{"maps_fabric.go", "UpdateRGActive", "map", `"rg_active"`, "required"},
	{"maps_filter.go", "ClearFilterConfigs", "map", `"filter_configs"`, "required"},
	{"maps_filter.go", "ClearFilterCounters", "map", `"filter_counters"`, "required"},
	{"maps_filter.go", "ClearIfaceFilterMap", "map", `"iface_filter_map"`, "required"},
	{"maps_filter.go", "ClearPolicerConfigs", "map", `"policer_configs"`, "required"},
	{"maps_filter.go", "ReadFilterConfig", "map", `"filter_configs"`, "required"},
	{"maps_filter.go", "ReadFilterCounters", "map", `"filter_counters"`, "required"},
	{"maps_filter.go", "SetFilterConfig", "map", `"filter_configs"`, "required"},
	{"maps_filter.go", "SetFilterRule", "map", `"filter_rules"`, "required"},
	{"maps_filter.go", "SetIfaceFilter", "map", `"iface_filter_map"`, "required"},
	{"maps_filter.go", "SetPolicerConfig", "map", `"policer_configs"`, "required"},
	{"maps_filter.go", "clearFilterCountersRaw", "map", `"filter_counters"`, "raw"},
	{"maps_flow.go", "SetFlowConfig", "map", `"flow_config_map"`, "required"},
	{"maps_flow.go", "SetFlowTimeout", "map", `"flow_timeouts"`, "required"},
	{"maps_mirror.go", "ClearMirrorConfigs", "map", `"mirror_config"`, "required"},
	{"maps_mirror.go", "SetMirrorConfig", "map", `"mirror_config"`, "required"},
	{"maps_nat.go", "ClearNATRuleCounters", "map", `"nat_rule_counters"`, "optional"}, // class 3
	{"maps_nat.go", "DeleteDNATEntry", "map", `"dnat_table"`, "required"},
	{"maps_nat.go", "DeleteDNATEntryV6", "map", `"dnat_table_v6"`, "required"},
	{"maps_nat.go", "ReadNATPortCounter", "map", `"nat_port_counters"`, "required"},
	{"maps_nat.go", "SeedNATPortCounters", "map", `"nat_port_counters"`, "optional"},
	{"maps_nat.go", "SetDNATEntry", "map", `"dnat_table"`, "required"},
	{"maps_nat.go", "SetDNATEntryV6", "map", `"dnat_table_v6"`, "required"},
	{"maps_policy.go", "ClearAddressBookV4", "map", `"address_book_v4"`, "required"},
	{"maps_policy.go", "ClearAddressBookV6", "map", `"address_book_v6"`, "required"},
	{"maps_policy.go", "ClearAddressMembership", "map", `"address_membership"`, "required"},
	{"maps_policy.go", "ClearAppRanges", "map", `"app_ranges"`, "required"},
	{"maps_policy.go", "ClearApplications", "map", `"applications"`, "required"},
	{"maps_policy.go", "ClearPolicyCounters", "map", `"policy_counters"`, "required"},
	{"maps_policy.go", "ClearZonePairPolicies", "map", `"zone_pair_policies"`, "required"},
	{"maps_policy.go", "ReadPolicyCounters", "map", `"policy_counters"`, "required"},
	{"maps_policy.go", "SetAddressBookEntry", "map", `"address_book_v4"`, "required"},
	{"maps_policy.go", "SetAddressBookEntry", "map", `"address_book_v6"`, "required"},
	{"maps_policy.go", "SetAddressMembership", "map", `"address_membership"`, "required"},
	{"maps_policy.go", "SetAppRange", "map", `"app_ranges"`, "required"},
	{"maps_policy.go", "SetApplication", "map", `"applications"`, "required"},
	{"maps_policy.go", "SetDefaultPolicy", "map", `"default_policy"`, "required"},
	{"maps_policy.go", "SetPolicyRule", "map", `"policy_rules"`, "required"},
	{"maps_policy.go", "SetZoneConfig", "map", `"zone_configs"`, "required"},
	{"maps_policy.go", "SetZonePairPolicy", "map", `"zone_pair_policies"`, "required"},
	{"maps_policy.go", "UpdatePolicyScheduleState", "map", `"policy_rules"`, "optional"}, // the #3780 deliberate nil
	{"maps_policy.go", "clearPolicyCountersRaw", "map", `"policy_counters"`, "raw"},
	{"maps_screen.go", "ClearScreenConfigs", "map", `"screen_configs"`, "required"},
	{"maps_screen.go", "ClearSessionCounts", "map", "<ident:name>", "optional"}, // leg: BOTH looped maps cleared (continuation)
	{"maps_screen.go", "SetScreenConfig", "map", `"screen_configs"`, "required"},
	{"maps_screen.go", "UpdateSessionCountDst", "map", `"session_count_dst"`, "required"},
	{"maps_screen.go", "UpdateSessionCountSrc", "map", `"session_count_src"`, "required"},
	{"maps_session.go", "BatchDeleteSessions", "map", `"sessions"`, "required"},
	{"maps_session.go", "BatchDeleteSessionsV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "BatchIterateSessions", "map", `"sessions"`, "required"},
	{"maps_session.go", "BatchIterateSessionsV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "DeleteSession", "map", `"sessions"`, "required"},
	{"maps_session.go", "DeleteSessionV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "GetSessionV4", "map", `"sessions"`, "required"},
	{"maps_session.go", "GetSessionV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "IterateSessions", "map", `"sessions"`, "required"},
	{"maps_session.go", "IterateSessionsFrom", "map", `"sessions"`, "required"},
	{"maps_session.go", "IterateSessionsV6", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "IterateSessionsV6From", "map", `"sessions_v6"`, "required"},
	{"maps_session.go", "SeedSessionIDCounter", "map", `"session_id_gen"`, "optional"},
	{"maps_session.go", "SessionCount", "map", `"sessions"`, "optional"}, // leg: v4 AND v6 both reported (continuation)
	{"maps_session.go", "SessionCount", "map", `"sessions_v6"`, "optional"},
	{"maps_session.go", "SetSessionV4", "map", `"sessions"`, "required"},
	{"maps_session.go", "SetSessionV6", "map", `"sessions_v6"`, "required"},
	{"maps_stale.go", "DeleteStaleApplications", "map", `"applications"`, "optional"},
	{"maps_stale.go", "DeleteStaleDNATStatic", "map", `"dnat_table"`, "optional"},
	{"maps_stale.go", "DeleteStaleDNATStaticV6", "map", `"dnat_table_v6"`, "optional"},
	{"maps_stale.go", "DeleteStaleIfaceFilter", "map", `"iface_filter_map"`, "optional"},
	{"maps_stale.go", "DeleteStaleIfaceZone", "map", `"iface_zone_map"`, "optional"},
	{"maps_stale.go", "DeleteStaleStaticNAT", "map", `"static_nat_v4"`, "optional"}, // (same continuation pattern)
	{"maps_stale.go", "DeleteStaleStaticNAT", "map", `"static_nat_v6"`, "optional"},
	{"maps_stale.go", "DeleteStaleVlanIface", "map", `"vlan_iface_map"`, "optional"},
	{"maps_stale.go", "DeleteStaleZonePairPolicies", "map", `"zone_pair_policies"`, "optional"},
	{"maps_stale.go", "ZeroStaleFilterConfigs", "map", `"filter_configs"`, "optional"},
	{"maps_stale.go", "ZeroStaleScreenConfigs", "map", `"screen_configs"`, "optional"},
	{"maps_stats.go", "GetMapStats", "map", "<dynamic>", "optional"}, // leg: every descriptor reported (continuation)
}

// collectRegistryCallsites walks every production .go file under root and
// returns the set of lookup-helper callsites as "file|fn|kind|arg" plus the
// AST-derived gated bit (does a registryFresh check follow in the same
// function body).
func collectRegistryCallsites(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		type fnSpan struct {
			name string
			body *ast.BlockStmt
		}
		var fns []fnSpan
		for _, d := range file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				fns = append(fns, fnSpan{fd.Name.Name, fd.Body})
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "lookupMapLocked" && sel.Sel.Name != "lookupProgramLocked") {
				return true
			}
			arg := "<dynamic>"
			if len(call.Args) == 1 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					arg = lit.Value
				} else if id, ok := call.Args[0].(*ast.Ident); ok {
					arg = "<ident:" + id.Name + ">"
				}
			}
			encl := "<none>"
			for _, g := range fns {
				if g.body.Pos() <= call.Pos() && call.Pos() < g.body.End() {
					encl = g.name
					break
				}
			}
			kind := "map"
			if sel.Sel.Name == "lookupProgramLocked" {
				kind = "prog"
			}
			key := fmt.Sprintf("%s|%s|%s|%s", name, encl, kind, arg)
			if out[key] {
				// A second IDENTICAL call in the same function collapses
				// the manifest key — refuse to collapse it silently
				// (Codex PR #6743 M3): the reviewer must disambiguate the
				// manifest entry (or the code) deliberately.
				t.Fatalf("duplicate helper callsite %s in %s — the manifest cannot key it; rename or restructure so each callsite is distinct", key, name)
			}
			out[key] = true
			return true
		})
	}
	return out
}

// collectRegistryGatedCallsites returns the per-callsite gate-consumption
// evidence (same "file|fn|kind|arg" key form): the name of the identifier
// the registryState return is bound to ("" when blanked), and whether the
// enclosing function compares that identifier against registryFresh. The
// manifest test requires "required" callsites to BIND non-blank AND
// COMPARE — binding st and ignoring it must not pass (Codex PR #6743 M3).
func collectRegistryGatedCallsites(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := gatedCallsiteEvidence(t, root)
	result := map[string]bool{}
	for key, ev := range out {
		result[key] = ev.bound && ev.compared
	}
	return result
}

type gatedEvidence struct {
	bound bool // third result bound non-blank
	// compared: that identifier is the EQL operand of an `if` condition
	// against registryFresh whose body returns (r4-F3 — a bare comparison
	// expression or an empty if body is not a gate).
	compared bool
}

// blockReturns reports whether blk contains a return statement at any
// depth outside a nested function literal. It is the "this if actually
// rejects the call" half of the gate-shape check (r4-F3).
func blockReturns(blk *ast.BlockStmt) bool {
	if blk == nil {
		return false
	}
	found := false
	ast.Inspect(blk, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.FuncLit:
			return false // a return inside a closure returns from the closure
		case *ast.ReturnStmt:
			found = true
			return false
		}
		return true
	})
	return found
}

func gatedCallsiteEvidence(t *testing.T, root string) map[string]gatedEvidence {
	t.Helper()
	out := map[string]gatedEvidence{}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		type fnSpan struct {
			name string
			body *ast.BlockStmt
		}
		var fns []fnSpan
		for _, d := range file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				fns = append(fns, fnSpan{fd.Name.Name, fd.Body})
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "lookupMapLocked" && sel.Sel.Name != "lookupProgramLocked") {
				return true
			}
			arg := "<dynamic>"
			if len(call.Args) == 1 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					arg = lit.Value
				} else if id, ok := call.Args[0].(*ast.Ident); ok {
					arg = "<ident:" + id.Name + ">"
				}
			}
			encl := "<none>"
			for _, g := range fns {
				if g.body.Pos() <= call.Pos() && call.Pos() < g.body.End() {
					encl = g.name
					break
				}
			}
			kind := "map"
			if sel.Sel.Name == "lookupProgramLocked" {
				kind = "prog"
			}
			key := fmt.Sprintf("%s|%s|%s|%s", name, encl, kind, arg)
			// The call sits inside an AssignStmt's Rhs; find the bound
			// third-LHS identifier by re-walking the enclosing body, then
			// look for an `<ident> == registryFresh` comparison in it.
			for _, g := range fns {
				if g.name != encl {
					continue
				}
				ev := out[key]
				ast.Inspect(g.body, func(n2 ast.Node) bool {
					as, ok := n2.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for _, rhs := range as.Rhs {
						rc, ok := rhs.(*ast.CallExpr)
						if !ok || rc.Pos() != call.Pos() {
							continue
						}
						if len(as.Lhs) == 3 {
							if id, ok := as.Lhs[2].(*ast.Ident); ok && id.Name != "_" {
								ev.bound = true
								boundName := id.Name
								// Codex PR #6743 r3-4: a comparison only
								// evidences THIS callsite's gate when it
								// evaluates the value THIS binding produced.
								// Find the first reassignment of the bound
								// identifier after the binding — comparisons
								// at or past it evaluate a LATER lookup's
								// value (the ClearNATPoolIPs two-lookup
								// shape reuses st; the second comparison
								// must not satisfy the first callsite).
								reassignPos := token.NoPos
								ast.Inspect(g.body, func(n4 ast.Node) bool {
									mark := func(p token.Pos) {
										if p > as.Pos() && (reassignPos == token.NoPos || p < reassignPos) {
											reassignPos = p
										}
									}
									switch node := n4.(type) {
									case *ast.AssignStmt:
										for _, lhs := range node.Lhs {
											if lid, ok := lhs.(*ast.Ident); ok && lid.Name == boundName {
												mark(node.Pos())
											}
										}
									case *ast.ValueSpec:
										for _, nm := range node.Names {
											if nm.Name == boundName {
												mark(node.Pos())
											}
										}
									case *ast.IncDecStmt:
										if xid, ok := node.X.(*ast.Ident); ok && xid.Name == boundName {
											mark(node.Pos())
										}
									}
									return true
								})
								// Codex PR #6743 r2-4: the comparison must
								// reference THIS callsite's binding, appear
								// AFTER the assignment, and NOT inside a
								// nested closure — a comparison anywhere
								// else in the function must not satisfy the
								// gate evidence for this callsite.
								// Codex PR #6743 r4-F3: the comparison must be
								// the CONDITION of an if whose body RETURNS.
								// Matching a bare *ast.BinaryExpr accepted an
								// inert `_ = st == registryFresh` and an
								// `if st == registryFresh {}` with an empty
								// body — both of which read as a gate to this
								// collector while admitting the call.
								ast.Inspect(g.body, func(n3 ast.Node) bool {
									switch node := n3.(type) {
									case *ast.FuncLit:
										return false // comparisons inside closures do not count
									case *ast.IfStmt:
										cond, ok := node.Cond.(*ast.BinaryExpr)
										if !ok {
											return true
										}
										if cond.Pos() <= as.Pos() {
											return true // must come after the binding
										}
										if reassignPos != token.NoPos && cond.Pos() >= reassignPos {
											return true // past the reassignment: evaluates a later value (r3-4)
										}
										if cond.Op != token.EQL {
											return true
										}
										var leftName, rightName string
										if id, ok := cond.X.(*ast.Ident); ok {
											leftName = id.Name
										}
										if id, ok := cond.Y.(*ast.Ident); ok {
											rightName = id.Name
										}
										if (leftName != boundName || rightName != "registryFresh") &&
											(leftName != "registryFresh" || rightName != boundName) {
											return true
										}
										if !blockReturns(node.Body) {
											return true // an empty / fall-through body is not a gate
										}
										ev.compared = true
									}
									return true
								})
							}
						}
					}
					return true
				})
				out[key] = ev
			}
			return true
		})
	}
	return out
}

// TestManagerRegistryGateEvidenceSelfTest drives the gate-evidence collector
// over synthetic fixtures: bind-and-COMPARE yields gated=true;
// bind-and-ignore yields gated=false (the M3 hole); blanking yields
// gated=false.
func TestManagerRegistryGateEvidenceSelfTest(t *testing.T) {
	t.Parallel()

	compared := `package dataplane

func (m *Manager) good(name string) error {
	zm, present, st := m.lookupMapLocked(name)
	if st == registryFresh {
		return ErrDataplaneNotArmed
	}
	if !present {
		return nil
	}
	_ = zm
	return nil
}
`
	bindIgnore := `package dataplane

func (m *Manager) bad(name string) error {
	zm, present, st := m.lookupMapLocked(name)
	_ = st
	if !present {
		return nil
	}
	_ = zm
	return nil
}
`
	closureCompare := `package dataplane

func (m *Manager) closureBad(name string) error {
	zm, present, st := m.lookupMapLocked(name)
	_ = zm
	_ = present
	f := func() bool { return st == registryFresh } // never called
	_ = f
	return nil
}
`
	earlyCompare := `package dataplane

func (m *Manager) earlyBad(name string) error {
	var st registryState
	if st == registryFresh { // compares st BEFORE the lookup assignment reuses it
		return ErrDataplaneNotArmed
	}
	zm, present, st := m.lookupMapLocked(name)
	_, _ = zm, present
	return nil
}
`
	blanked := `package dataplane

func (m *Manager) blank(name string) error {
	zm, present, _ := m.lookupMapLocked(name)
	if !present {
		return nil
	}
	_ = zm
	return nil
}
`
	// Codex PR #6743 r4-F3 negatives: the two shapes that read as a gate
	// to a bare-comparison matcher but admit the call anyway.
	inertCompare := `package dataplane

func (m *Manager) inertBad(name string) error {
	zm, present, st := m.lookupMapLocked(name)
	_ = st == registryFresh // evaluated and thrown away — not a gate
	if !present {
		return nil
	}
	_ = zm
	return nil
}
`
	emptyIfCompare := `package dataplane

func (m *Manager) emptyIfBad(name string) error {
	zm, present, st := m.lookupMapLocked(name)
	if st == registryFresh {
	}
	if !present {
		return nil
	}
	_ = zm
	return nil
}
`
	crossCredit := `package dataplane

func (m *Manager) reused(name string) error {
	v4, present, st := m.lookupMapLocked("nat_pool_ips_v4")
	if !present {
		return nil
	}
	_ = v4
	v6, present, st := m.lookupMapLocked("nat_pool_ips_v6")
	if st == registryFresh {
		return ErrDataplaneNotArmed
	}
	if !present {
		return nil
	}
	_ = v6
	return nil
}
`

	dir := t.TempDir()
	write := func(n, s string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(s), 0o644); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	write("a.go", compared)
	write("b.go", bindIgnore)
	write("c.go", blanked)
	write("d.go", closureCompare)
	write("e.go", earlyCompare)
	write("f.go", crossCredit)
	write("g.go", inertCompare)
	write("h.go", emptyIfCompare)

	ev := gatedCallsiteEvidence(t, dir)
	if got := ev["a.go|good|map|<ident:name>"].bound && ev["a.go|good|map|<ident:name>"].compared; !got {
		t.Error("bind-and-compare fixture must yield bound+compared")
	}
	if ev["b.go|bad|map|<ident:name>"].compared {
		t.Error("bind-and-ignore fixture must NOT yield compared (the M3 hole)")
	}
	if !ev["b.go|bad|map|<ident:name>"].bound {
		t.Error("bind-and-ignore fixture should still register the non-blank binding")
	}
	if ev["c.go|blank|map|<ident:name>"].bound {
		t.Error("blanked fixture must not register a binding")
	}
	// Codex PR #6743 r2-4 negatives: a comparison inside a never-called
	// closure and a comparison positioned BEFORE the binding must NOT
	// satisfy the gate evidence.
	if ev["d.go|closureBad|map|<ident:name>"].compared {
		t.Error("closure comparison must not count as gate evidence")
	}
	if got := ev["e.go|earlyBad|map|<ident:name>"]; got.compared {
		t.Error("pre-binding comparison must not count as gate evidence")
	}
	// Codex PR #6743 r3-4: the reused-identifier shape (the ClearNATPoolIPs
	// pattern) — the SECOND lookup's comparison must not satisfy the FIRST
	// callsite's evidence; the first callsite here has NO check of its own.
	if got := ev[`f.go|reused|map|"nat_pool_ips_v4"`]; got.compared {
		t.Error("a comparison after the identifier's reassignment must not count for the earlier callsite (the ClearNATPoolIPs cross-credit)")
	}
	if got := ev[`f.go|reused|map|"nat_pool_ips_v6"`]; !got.compared {
		t.Error("the second callsite's own comparison must still count")
	}
	// Codex PR #6743 r4-F3 negatives: a comparison that is not an if
	// condition, and an if whose body does not reject, are NOT gates.
	if got := ev["g.go|inertBad|map|<ident:name>"]; got.compared {
		t.Error("an inert `_ = st == registryFresh` must not count as gate evidence")
	}
	if got := ev["g.go|inertBad|map|<ident:name>"]; !got.bound {
		t.Error("the inert fixture should still register the non-blank binding")
	}
	if got := ev["h.go|emptyIfBad|map|<ident:name>"]; got.compared {
		t.Error("an `if st == registryFresh {}` with an empty body must not count as gate evidence")
	}
}

// TestManagerRegistryCallsiteManifest is the stale-checked helper-callsite
// manifest (#2114 A3, plan v99): EVERY lookupMapLocked/lookupProgramLocked
// callsite maps to its required/optional/raw outcome, and the manifest's
// gated bit is AST-verified against the enclosing function (a "required"
// entry must contain the registryFresh gate; an "optional"/"raw" entry must
// not). The manifest does not infer semantics — it forces explicit review
// when callsites change: a callsite added, removed, or moved fails here
// until the manifest and the leg mapping are updated.
func TestManagerRegistryCallsiteManifest(t *testing.T) {
	t.Parallel()

	got := collectRegistryCallsites(t, ".")
	want := map[string]string{}
	for _, e := range registryCallsiteManifest {
		key := fmt.Sprintf("%s|%s|%s|%s", e.file, e.fn, e.kind, e.arg)
		if _, dup := want[key]; dup {
			t.Fatalf("manifest has a duplicate entry: %s", key)
		}
		want[key] = e.role
	}

	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("callsite %s is NOT in the manifest (added/moved callsite — update registryCallsiteManifest and the §9 leg mapping)", key)
		}
	}
	for key := range want {
		if !got[key] {
			t.Errorf("manifest entry %s is STALE (no such callsite) — update registryCallsiteManifest", key)
		}
	}
	if len(got) != len(registryCallsiteManifest) {
		t.Fatalf("callsite count = %d, manifest = %d", len(got), len(registryCallsiteManifest))
	}

	// AST-verify the gated bit PER CALLSITE: a "required" entry must bind
	// the registryState return non-blank (the fresh gate follows);
	// "optional"/"raw" entries must blank it; "carveout" entries blank it
	// too (the pre-registry loaded rejection fires first on both unarmed
	// states, so the lookup never sees the fresh state — but the uniform
	// rule still routes it through the helper).
	gatedSet := collectRegistryGatedCallsites(t, ".")
	for _, e := range registryCallsiteManifest {
		key := fmt.Sprintf("%s|%s|%s|%s", e.file, e.fn, e.kind, e.arg)
		if _, ok := want[key]; !ok {
			continue // already reported above
		}
		gated := gatedSet[key]
		switch e.role {
		case "required":
			if !gated {
				t.Errorf("manifest entry %s is required but the callsite blanks the registryState return (no fresh gate)", key)
			}
		case "optional", "raw", "carveout":
			if gated {
				t.Errorf("manifest entry %s is %s but the callsite binds the registryState return (role drift — reclassify deliberately)", key, e.role)
			}
		default:
			t.Errorf("manifest entry %s has unknown role %q", key, e.role)
		}
	}
}
