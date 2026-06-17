Reading additional input from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed4a1-6db0-7080-87e9-40ae4b2c4d81
--------
user
You are a HOSTILE plan reviewer for a Go network-firewall project (xpf). Review the plan-of-action doc at docs/research/1919-wg-addr-route-prune/plan.md against the actual source in this worktree. This is RESEARCH ONLY — judge the PLAN, do not implement.

Context: issue #1919 — when an operator removes a WireGuard tunnel from config, the persistent wgN device keeps its manager-applied kernel addresses (and the issue claims FRR routes) because WG is excluded from the ownedNames removal diff in pkg/routing/tunnel.go (#1432 S2a persistent-device invariant) and address reconcile runs only for still-configured WG tunnels.

Read these files for ground truth:
- pkg/routing/tunnel.go (Apply ~163, applyWireguardTunLocked ~798, reconcileLinkAddrsLocked ~584, clearLocked ~1086, tunnelManager fields ~104)
- pkg/routing/tunnel_reconcile_test.go (existing WG tests ~356-435)
- pkg/config/types_routing.go (TunnelConfig ~292)
- pkg/frr/manager.go writeManagedSection (~487), pkg/daemon/daemon_ipmon.go assembleFRRConfig (~89)

HOSTILE MANDATE: Do NOT PLAN-KILL without a concrete, source-grounded counterexample (quote file:line). Do NOT rubber-stamp. Verify specifically:
1. Is Path A's wgConfigured diff correct and idempotent? Walk the prune loop across 3 commits (add, remove, remove-again). Does it ever double-prune or strand tracking?
2. Is the §1a FRR-routes scoping correct — does WG config truly synthesize NO FRR managed-section route? Or did the plan miss a path where wg addresses/allowed-ips become routes (grep pkg/frr, pkg/routing, pkg/daemon, userspace-dp)?
3. The retain-for-retry on AddrDel failure uses len(remaining)>0 from reconcileLinkAddrsLocked. But reconcileLinkAddrsLocked returns newApplied = successful-adds + present-and-wanted + failed-delete-link-locals. With an EMPTY desired set (nil addrs), what does it actually return on a failed AddrDel of a NON-link-local address? Trace tunnel.go:595-644 carefully — does a failed AddrDel of a regular (non-fe80) address get recorded in newApplied at all? If NOT, the retry signal is broken. THIS IS THE KEY CORRECTNESS QUESTION.
4. VRF unbind scope (A1) — is leaving the WG link VRF-bound after removal a real hazard?
5. Restart-adoption boundary (R5) — acceptable to defer?
6. Interaction with #1918 (merged probeICMP keepalive) — plan claims none. Verify WG never starts a keepalive.

Output verdict as one of: PLAN-READY / PLAN-READY-WITH-NITS / PLAN-NEEDS-MAJOR / PLAN-KILL. For each finding give file:line evidence and severity. Be specific about #3 — it is the likely real defect in this plan.
codex
I’ll review this as a plan audit only. I’m going to ground every objection in the local source and pay special attention to the AddrDel retry trace the plan depends on.
exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '80,230p;560,660p;780,880p;1060,1125p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
    80	// #848: `done` is closed by keepaliveLoop just before it returns.
    81	// Close() / stopAll drain on this channel so the netlink handle is not
    82	// closed while a keepalive goroutine is still in flight (use-after-close
    83	// on the shared netlink handle).
    84	type keepaliveRunner struct {
    85		cancel context.CancelFunc
    86		state  *KeepaliveState
    87		done   chan struct{}
    88	
    89		// Config identity at start time (#1884 A.7): the reconcile keeps an
    90		// unchanged runner alive across applies instead of restarting it
    91		// (which would reset probe state every commit).
    92		remote     string
    93		source     string // tunnel local endpoint IP probed-from (#1918 §5c)
    94		interval   int
    95		maxRetries int // normalized: <=0 config value stored as 3
    96	
    97		// linkGen is the per-tunnel generation token captured at start
    98		// (#1918 §6 Axis D, defense-in-depth). The runner reads it LOCK-FREE
    99		// (.Load()) before each netlink op and drops the action if it no
   100		// longer matches the manager's current generation — so a stale runner
   101		// cannot down/up a recreated link. The runner NEVER takes t.mu (AGY
   102		// r5 deadlock note: a tick blocked on t.mu while Apply blocks on the
   103		// drain would deadlock).
   104		linkGen  *atomic.Uint64
   105		startGen uint64
   106	}
   107	
   108	// matches reports whether the runner's identity equals the config's
   109	// NORMALIZED keepalive parameters. KeepaliveRetry <= 0 normalizes to 3
   110	// BEFORE comparison (#1884 r1 Codex F5: comparing a raw config 0
   111	// against the stored default 3 would restart the runner every apply).
   112	// The tunnel SOURCE is part of the identity (#1918 §5c): a source-only
   113	// change must restart the runner so the probe binds the new endpoint.
   114	func (r *keepaliveRunner) matches(tc *config.TunnelConfig) bool {
   115		retries := tc.KeepaliveRetry
   116		if retries <= 0 {
   117			retries = 3
   118		}
   119		return r.remote == tc.Destination &&
   120			r.source == tc.Source &&
   121			r.interval == tc.Keepalive &&
   122			r.maxRetries == retries
   123	}
   124	
   125	// TunnelStatus holds the status of a tunnel interface.
   126	type TunnelStatus struct {
   127		Name        string
   128		Source      string
   129		Destination string
   130		State       string // "up" or "down"
   131		Addresses   []string
   132		// KeepaliveUp is tri-state (#1918): non-nil true/false when liveness is
   133		// KNOWN (probe succeeded/failed), and nil when EITHER no keepalive is
   134		// configured OR liveness is currently UNKNOWN (ProbeUnsupported —
   135		// hold-on-unknown). The two nil cases are distinguished by
   136		// KeepaliveInfo: "" → not configured; "unknown (...)" → configured but
   137		// liveness unknown.
   138		KeepaliveUp   *bool
   139		KeepaliveInfo string // human-readable keepalive status
   140	}
   141	
   142	// tunnelManager owns GRE/IPIP tunnel lifecycle and per-tunnel keepalive
   143	// goroutines. The mu field replaces the tunnel slice of the former
   144	// shared Manager.ifaceMu; keepalives belong to this domain (their only
   145	// user is tunnel apply/clear), so mu protects both tunnels and the
   146	// keepalives map as one cohesive critical section.
   147	type tunnelManager struct {
   148		ops       linkOps
   149		vrfBinder vrfBinder
   150	
   151		// prober performs the keepalive ICMP echo. nil → the production
   152		// icmpProber (lazily resolved by keepaliveProber). Tests inject a
   153		// deterministic fake (#1918).
   154		prober tunnelProber
   155	
   156		mu         sync.Mutex
   157		tunnels    []string                    // tunnels successfully applied this round (GetStatus source)
   158		keepalives map[string]*keepaliveRunner // tunnel name -> runner
   159	
   160		// linkGen is the per-tunnel monotonic generation counter (#1918 §6
   161		// Axis D, defense-in-depth recreate guard). The MAP structure is
   162		// mutated only under mu (by Apply, via bumpLinkGenLocked); the counter
   163		// values are *atomic.Uint64 so a keepalive runner can Load() them
   164		// lock-free at tick time without ever taking mu (AGY r5 deadlock
   165		// note). Apply bumps the counter on a tunnel link create/recreate so a
   166		// stale runner captured at the old generation drops its LinkSet*.
   167		linkGen map[string]*atomic.Uint64
   168	
   169		// Reconcile-in-place state (#1884). All lazily initialized by Apply.
   170		//
   171		// ownedNames: ALL non-WireGuard tunnel names from the LAST Apply's
   172		// DESIRED set (plus names whose removal LinkDel failed, retained for
   173		// retry). The removal diff and the adoption decision both key off
   174		// this — NOT off the success-tracked t.tunnels, whose
   175		// failure-continue paths can leave a live kernel link untracked.
   176		ownedNames map[string]bool
   177		// appliedAddrs: per tunnel, the address set this manager itself
   178		// ensured (successful adds + present-and-wanted + link-local whose
   179		// stale-delete failed). Gates stale LINK-LOCAL deletion: a
   180		// configured fe80 we applied is removable; the kernel's autoconf
   181		// fe80 is never touched.
   182		appliedAddrs map[string]map[string]bool
   183		// appliedRI: per tunnel, the routing-instance whose VRF this
   184		// manager successfully bound — or directly OBSERVED as the link's
   185		// master for a step-0a `routing-instances <ri> interface` list
   186		// bind. Invariant (#1884 r6-r8): a claim is only ever written from
   187		// a successful bind or a master observation, never an intent.
   188		// Unbind on config-wants-none is identity-gated against
   189		// vrf-<claim>.
   190		appliedRI map[string]string
   191	}
   192	
   193	// ensureReconcileStateLocked lazily initializes the reconcile maps so
   194	// directly-constructed managers (tests, façade) need no constructor
   195	// changes. Caller MUST hold mu.
   196	func (t *tunnelManager) ensureReconcileStateLocked() {
   197		if t.ownedNames == nil {
   198			t.ownedNames = map[string]bool{}
   199		}
   200		if t.appliedAddrs == nil {
   201			t.appliedAddrs = map[string]map[string]bool{}
   202		}
   203		if t.appliedRI == nil {
   204			t.appliedRI = map[string]string{}
   205		}
   206		if t.keepalives == nil {
   207			t.keepalives = map[string]*keepaliveRunner{}
   208		}
   209		if t.linkGen == nil {
   210			t.linkGen = map[string]*atomic.Uint64{}
   211		}
   212	}
   213	
   214	// linkGenForLocked returns the (lazily created) generation counter for a
   215	// tunnel name. Caller MUST hold mu.
   216	func (t *tunnelManager) linkGenForLocked(name string) *atomic.Uint64 {
   217		g, ok := t.linkGen[name]
   218		if !ok {
   219			g = &atomic.Uint64{}
   220			t.linkGen[name] = g
   221		}
   222		return g
   223	}
   224	
   225	// bumpLinkGenLocked advances a tunnel's generation token. Called by
   226	// Apply whenever it CREATES or RECREATES the kernel link for a tunnel,
   227	// so any keepalive runner still holding the previous generation drops
   228	// its netlink op (#1918 §6 Axis D defense-in-depth). Caller MUST hold
   229	// mu.
   230	func (t *tunnelManager) bumpLinkGenLocked(name string) {
   560		// (EBUSY / transport hiccup) is TRANSIENT — it does NOT mean the link
   561		// is gone, so we must NOT drain the live keepalive runner and must NOT
   562		// fall through to a LinkAdd that would EEXIST. Abort and retry next
   563		// apply, exactly like a transient LinkDel failure below.
   564		willRecreate := false
   565		var existing netlink.Link
   566		e, lookupErr := t.ops.LinkByName(tc.Name)
   567		switch {
   568		case lookupErr == nil:
   569			existing = e
   570			willRecreate = !legacyTunnelMatches(e, desired)
   571		case isLinkNotFound(lookupErr):
   572			// Absent → the LinkAdd below is a (re)create.
   573			willRecreate = true
   574		default:
   575			// Transient lookup error: leave the runner and any live link
   576			// untouched; retry on the next apply.
   577			slog.Warn("tunnel lookup failed transiently; deferring apply",
   578				"name", tc.Name, "err", lookupErr)
   579			return
   580		}
   581		if willRecreate {
   582			// Drain the stale runner first; bump the generation so any runner
   583			// that somehow survives (future code paths) drops its netlink op.
   584			t.stopKeepaliveLocked(tc.Name)
   585			t.bumpLinkGenLocked(tc.Name)
   586		}
   587	
   588		var link netlink.Link
   589		created := false
   590		if existing != nil {
   591			if !willRecreate {
   592				link = existing // kernel-fetched, real ifindex (#1706)
   593				slog.Debug("tunnel reused", "name", tc.Name)
   594			} else {
   595				if delErr := t.ops.LinkDel(existing); delErr != nil {
   596					slog.Warn("failed to replace existing tunnel link",
   597						"name", tc.Name, "existing_type", existing.Type(), "err", delErr)
   598					// The recreate failed but the OLD link is still live. We
   599					// already drained its keepalive runner before the LinkDel
   600					// (F7 ordering). Restart it against the surviving link so a
   601					// transient LinkDel failure does not silently leave the
   602					// tunnel running with NO keepalive until the next successful
   603					// apply (Copilot PR #1947 r3). Safe because the link was NOT
   604					// recreated — the restarted runner captures the just-bumped
   605					// generation and probes the same device.
   606					if tc.Keepalive > 0 {
   607						t.startKeepalive(tc.Name, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
   608					}
   609					return
   610				}
   611				slog.Info("replaced tunnel link with changed parameters",
   612					"name", tc.Name, "existing_type", existing.Type())
   613			}
   614		}
   615		if link == nil {
   616			if addErr := t.ops.LinkAdd(desired); addErr != nil {
   617				slog.Warn("failed to create tunnel",
   618					"name", tc.Name, "mode", tc.Mode, "err", addErr)
   619				return
   620			}
   621			link = desired
   622			created = true
   623	
   624			// IPv6 GRE: disable encaplimit to avoid adding an IPv6
   625			// Destination Options extension header. Many transit networks
   626			// drop IPv6 packets with extension headers (RFC 7872). Runs
   627			// only on a real (re)create — it is a per-create device attr
   628			// and the 15s-bounded exec must not run per commit (#1884).
   629			if isIPv6 && (tc.Mode == "gre" || tc.Mode == "") {
   630				// Timeout-bounded (#1794/#1800): Apply runs under
   631				// applyConfigLocked's applySem (daemon_apply.go
   632				// ApplyTunnels), so a wedged `ip` would block every commit.
   633				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
   634				ipCmd := exec.CommandContext(ctx, "ip", "link", "set", tc.Name,
   635					"type", "ip6gre", "encaplimit", "none")
   636				// WaitDelay caps the post-SIGKILL pipe-drain window.
   637				ipCmd.WaitDelay = 5 * time.Second
   638				out, err := ipCmd.CombinedOutput()
   639				cancel()
   640				if err != nil {
   641					slog.Warn("failed to set tunnel encaplimit",
   642						"name", tc.Name, "err", err, "output", string(out))
   643				}
   644			}
   645			if tc.MTU > 0 {
   646				if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
   647					slog.Warn("failed to set tunnel mtu",
   648						"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
   649				}
   650			}
   651			slog.Info("tunnel created", "name", tc.Name,
   652				"src", tc.Source, "dst", tc.Destination)
   653		} else if tc.MTU > 0 && link.Attrs().MTU != tc.MTU {
   654			// Config-owned MTU reconcile on reuse (#1884 r5). No
   655			// adoption-default normalization here: kernel GRE/IPIP devices
   656			// have protocol-specific default MTUs (1476/1462/...), not the
   657			// TUN 1500.
   658			if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
   659				slog.Warn("failed to set tunnel mtu",
   660					"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
   780			} else {
   781				newApplied[key] = true
   782			}
   783		}
   784		return newApplied
   785	}
   786	
   787	// reconcileVRFClaimLocked runs the #1884 A.5 ordered claim procedure.
   788	// The claim invariant (r6-r8): t.appliedRI[name] is only ever written
   789	// from a SUCCESSFUL BindInterfaceToVRF or a direct observation of the
   790	// link's master — never from intent — so the identity-gated unbind
   791	// below can neither strand a master we own nor touch one we do not.
   792	//
   793	//  1. stanza RI nonempty: bind; on success claim = stanza RI (stanza
   794	//     wins over a coexisting 0a list bind — today's effective apply
   795	//     order); on failure fall through to observation.
   796	//  2. stanza failed or empty, RIListMember nonempty: never unbind (0a
   797	//     owns list binds — the VETO); claim transfers to the list RI only
   798	//     when the observed master IS vrf-<RIListMember>, else the prior
   799	//     claim is retained.
   800	//  3. config wants no RI: identity-gated unbind of vrf-<claim>. Claim
   801	//     clears on successful unbind / identity mismatch (master not
   802	//     ours) / VRF device not-found (kernel already freed the slaves);
   803	//     it is RETAINED on transient errors so the next apply retries.
   804	//
   805	// Caller MUST hold mu.
   806	func (t *tunnelManager) reconcileVRFClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
   807		name := tc.Name
   808		if tc.RoutingInstance != "" {
   809			if err := t.vrfBinder.BindInterfaceToVRF(name, tc.RoutingInstance); err != nil {
   810				slog.Warn("failed to bind tunnel to VRF",
   811					"name", name, "vrf", tc.RoutingInstance, "err", err)
   812				// r7/r8: a FAILED bind must not blind-write the claim (the
   813				// kernel may still carry the previous master, or a 0a list
   814				// bind). Observation may take the claim; else retain.
   815				t.observeListClaimLocked(tc, link)
   816				return
   817			}
   818			t.appliedRI[name] = tc.RoutingInstance
   819			return
   820		}
   821		if tc.RIListMember != "" {
   822			// Unbind VETO: a stanza→list move must never strip the 0a
   823			// bind (r4 convergent counterexample).
   824			t.observeListClaimLocked(tc, link)
   825			return
   826		}
   827	
   828		claim := t.appliedRI[name]
   829		if claim == "" {
   830			return
   831		}
   832		master := link.Attrs().MasterIndex
   833		if master == 0 {
   834			// Nothing is bound — whatever we once bound is already gone.
   835			delete(t.appliedRI, name)
   836			return
   837		}
   838		vrf, err := t.ops.LinkByName("vrf-" + claim)
   839		if err != nil {
   840			if isLinkNotFound(err) {
   841				// The VRF device is gone; deleting a master frees its
   842				// slaves, so the current master cannot be ours.
   843				delete(t.appliedRI, name)
   844				return
   845			}
   846			// Transient lookup error: retain the claim, retry next apply.
   847			return
   848		}
   849		if vrf.Attrs().Index != master {
   850			// Master is not the VRF we bound (someone else's bind).
   851			delete(t.appliedRI, name)
   852			return
   853		}
   854		if err := t.ops.LinkSetNoMaster(link); err != nil {
   855			slog.Warn("failed to unbind tunnel from VRF",
   856				"name", name, "vrf", claim, "err", err)
   857			return // retain claim; retry next apply
   858		}
   859		slog.Info("tunnel unbound from routing-instance",
   860			"name", name, "vrf", claim)
   861		delete(t.appliedRI, name)
   862	}
   863	
   864	// observeListClaimLocked transfers the appliedRI claim to the
   865	// routing-instance list member ONLY when the link's current master is
   866	// OBSERVED to be that RI's VRF device (#1884 r6/r8: a blind transfer
   867	// after a failed 0a bind would record an RI the kernel never took and
   868	// later strand the real master on a mismatch-clear). On any
   869	// non-observation the previous nonempty claim is retained. Caller MUST
   870	// hold mu.
   871	func (t *tunnelManager) observeListClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
   872		if tc.RIListMember == "" {
   873			return
   874		}
   875		master := link.Attrs().MasterIndex
   876		if master == 0 {
   877			return // 0a bind absent or failed: no observation, retain prior
   878		}
   879		vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
   880		if err != nil {
  1060		t.keepalives = make(map[string]*keepaliveRunner)
  1061		for name, runner := range runners {
  1062			runner.cancel()
  1063			<-runner.done
  1064			slog.Debug("stopped keepalive", "tunnel", name)
  1065		}
  1066	}
  1067	
  1068	// stopKeepaliveLocked cancels, drains, and REMOVES the keepalive
  1069	// runner for one tunnel, if any. Removing the map entry matters
  1070	// (#1884 SMR2-2): a cancelled runner left behind would make
  1071	// GetKeepaliveState report a dead probe and would let the apply
  1072	// reconcile "retain" a corpse. Caller MUST hold mu.
  1073	func (t *tunnelManager) stopKeepaliveLocked(name string) {
  1074		runner, ok := t.keepalives[name]
  1075		if !ok {
  1076			return
  1077		}
  1078		runner.cancel()
  1079		<-runner.done
  1080		delete(t.keepalives, name)
  1081		slog.Debug("stopped keepalive", "tunnel", name)
  1082	}
  1083	
  1084	// startKeepalive starts a keepalive probe goroutine for a tunnel.
  1085	// source is the tunnel local endpoint IP the probe binds to (#1918
  1086	// §5c); "" → wildcard. Caller MUST hold mu.
  1087	func (t *tunnelManager) startKeepalive(tunnelName, source, remoteAddr string, interval, maxRetries int) {
  1088		// Stop existing keepalive for this tunnel if any. Drain on done
  1089		// so the replacement doesn't race the old goroutine on the handle.
  1090		t.stopKeepaliveLocked(tunnelName)
  1091	
  1092		if maxRetries <= 0 {
  1093			maxRetries = 3
  1094		}
  1095	
  1096		state := &KeepaliveState{
  1097			Up:         true,
  1098			RemoteAddr: remoteAddr,
  1099			SourceAddr: source,
  1100			Interval:   interval,
  1101			MaxRetries: maxRetries,
  1102		}
  1103	
  1104		// Capture the current generation token (#1918 §6 Axis D
  1105		// defense-in-depth). The runner reads it LOCK-FREE — it never takes
  1106		// t.mu — so an Apply blocked on the drain can never deadlock a tick.
  1107		gen := t.linkGenForLocked(tunnelName)
  1108		startGen := gen.Load()
  1109	
  1110		ctx, cancel := context.WithCancel(context.Background())
  1111		done := make(chan struct{})
  1112		t.keepalives[tunnelName] = &keepaliveRunner{
  1113			cancel:     cancel,
  1114			state:      state,
  1115			done:       done,
  1116			remote:     remoteAddr,
  1117			source:     source,
  1118			interval:   interval,
  1119			maxRetries: maxRetries,
  1120			linkGen:    gen,
  1121			startGen:   startGen,
  1122		}
  1123	
  1124		prober := t.keepaliveProber()
  1125		go t.keepaliveLoop(ctx, done, tunnelName, state, prober, gen, startGen)

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel_reconcile_test.go | sed -n '330,460p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   330			t.Fatalf("Apply 2: %v", err)
   331		}
   332		if !ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   333			t.Fatal("address gone despite injected delete failure")
   334		}
   335	
   336		// Failed delete keeps the LL tracked (r2 Codex F4) ⇒ retried.
   337		delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
   338		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   339			t.Fatalf("Apply 3: %v", err)
   340		}
   341		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
   343		}
   344	}
   345	
   346	// --- #1905: WG branch shares the applied-address record ---------------
   347	
   348	func wgTC(addrs ...string) *config.TunnelConfig {
   349		return &config.TunnelConfig{Name: "wg0", Mode: "wireguard", Addresses: addrs}
   350	}
   351	
   352	// A CONFIGURED fe80 on the persistent wgN TUN, later removed from
   353	// config, must be reconciled away (pre-#1905 it leaked forever via the
   354	// nil applied-set sentinel) — while the kernel's autoconf fe80 on the
   355	// same device survives, exactly the GRE-branch split.
   356	func TestWireguardConfiguredLinkLocalRemoved(t *testing.T) {
   357		ops := newFakeLinkOps()
   358		tm, _ := newReconcileManager(ops)
   359		if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24", "fe80::8/64")}); err != nil {
   360			t.Fatalf("Apply 1: %v", err)
   361		}
   362		if !ops.hasAddr("wg0", "fe80::8/64") {
   363			t.Fatal("configured fe80 not applied")
   364		}
   365		// Simulate the kernel's autoconf link-local appearing too.
   366		kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
   367		ops.addrs["wg0"] = append(ops.addrs["wg0"], *kernelLL)
   368	
   369		if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24")}); err != nil {
   370			t.Fatalf("Apply 2: %v", err)
   371		}
   372		if ops.hasAddr("wg0", "fe80::8/64") {
   373			t.Fatal("configured fe80 leaked after removal from config (#1905)")
   374		}
   375		if !ops.hasAddr("wg0", "fe80::5054:ff:fe12:3456/64") {
   376			t.Fatal("kernel autoconf fe80 was deleted")
   377		}
   378		if !ops.hasAddr("wg0", "10.77.0.1/24") {
   379			t.Fatal("configured non-LL address lost")
   380		}
   381		// The persistent device must not have been recreated by any of this.
   382		if len(ops.delNames) != 0 {
   383			t.Fatalf("wg0 was deleted/recreated: %v", ops.delNames)
   384		}
   385	}
   386	
   387	// Adoption pass: an fe80 already on the device before this manager's
   388	// first apply (daemon restart over a persistent wgN) is untracked and
   389	// must never be deleted, even once it is absent from config.
   390	func TestWireguardForeignLinkLocalNeverDeleted(t *testing.T) {
   391		ops := newFakeLinkOps()
   392		seedAnchor(ops, "wg0", 7, 1412)
   393		preLL, _ := netlink.ParseAddr("fe80::dead/64")
   394		ops.addrs["wg0"] = append(ops.addrs["wg0"], *preLL)
   395		tm, _ := newReconcileManager(ops)
   396	
   397		for i := 0; i < 2; i++ { // adoption pass AND a tracked second pass
   398			if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24")}); err != nil {
   399				t.Fatalf("Apply %d: %v", i+1, err)
   400			}
   401			if !ops.hasAddr("wg0", "fe80::dead/64") {
   402				t.Fatalf("pre-existing fe80 deleted on apply %d", i+1)
   403			}
   404		}
   405	}
   406	
   407	// Failed fe80 stale-delete on the WG branch stays tracked and is
   408	// retried on the next apply (parity with the GRE-branch r2 Codex F4
   409	// retry).
   410	func TestWireguardLinkLocalDeleteFailureRetried(t *testing.T) {
   411		ops := newFakeLinkOps()
   412		tm, _ := newReconcileManager(ops)
   413		if err := tm.Apply([]*config.TunnelConfig{wgTC("fe80::8/64")}); err != nil {
   414			t.Fatalf("Apply 1: %v", err)
   415		}
   416	
   417		ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
   418		if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
   419			t.Fatalf("Apply 2: %v", err)
   420		}
   421		if !ops.hasAddr("wg0", "fe80::8/64") {
   422			t.Fatal("address gone despite injected delete failure")
   423		}
   424	
   425		delete(ops.addrDelFail, "wg0|fe80::8/64")
   426		if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
   427			t.Fatalf("Apply 3: %v", err)
   428		}
   429		if ops.hasAddr("wg0", "fe80::8/64") {
   430			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
   431		}
   432	}
   433	
   434	// --- §9 test 6: appliedRI claim state machine -------------------------
   435	
   436	func TestTunnelVRFStanzaBindAndUnbind(t *testing.T) {
   437		ops := newFakeLinkOps()
   438		seedVRF(ops, "red", 100)
   439		tm, _ := newReconcileManager(ops)
   440	
   441		tc := anchorTC("gr-0-0-0")
   442		tc.RoutingInstance = "red"
   443		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   444			t.Fatalf("Apply 1: %v", err)
   445		}
   446		if got := ops.links["gr-0-0-0"].Attrs().MasterIndex; got != 100 {
   447			t.Fatalf("stanza bind did not enslave: master=%d", got)
   448		}
   449	
   450		// Stanza removed, no list ⇒ identity-gated unbind of OUR master.
   451		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   452			t.Fatalf("Apply 2: %v", err)
   453		}
   454		if len(ops.noMaster) != 1 || ops.noMaster[0] != "gr-0-0-0" {
   455			t.Fatalf("expected exactly one LinkSetNoMaster, got %v", ops.noMaster)
   456		}
   457		if tm.appliedRI["gr-0-0-0"] != "" {
   458			t.Fatalf("claim not cleared after unbind: %q", tm.appliedRI["gr-0-0-0"])
   459		}
   460	

exec
/bin/bash -lc "nl -ba docs/research/1919-wg-addr-route-prune/plan.md | sed -n '1,260p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	# Plan-of-action — #1919: WireGuard tunnel removal leaks kernel addresses (+ FRR routes claim)
     2	
     3	- **Issue**: #1919 — routing: removing a WireGuard tunnel leaks its kernel
     4	  addresses + FRR routes (persistent wgN bypasses address reconcile)
     5	- **Revision**: r1 (DRAFT — pre-review)
     6	- **Branch**: `research/1919-wg-addr-route-prune` off `origin/master`
     7	  @ `ee3f336d3` (post-#1918, post-#1947)
     8	- **Status**: PLAN DRAFT — research-only; STOP at PLAN-READY
     9	- **Contract**: `/research`, NOT `/engineer`. No PR, no production source
    10	  touched. Deliverable = converged plan + 3 verdicts + issue comment.
    11	
    12	---
    13	
    14	## 1. Problem statement
    15	
    16	WireGuard TUN devices are intentionally **persistent** (#1432 S2a). In
    17	`pkg/routing/tunnel.go`, the reconcile-in-place `Apply` excludes
    18	`wireguard`-mode tunnels from the `desired` set and from `ownedNames`:
    19	
    20	```go
    21	// Apply, line 168-175
    22	desired := make(map[string]bool, len(tunnels))
    23	for _, tc := range tunnels {
    24	    if tc.Mode != "wireguard" {        // WG excluded from removal diff
    25	        desired[tc.Name] = true
    26	    }
    27	}
    28	```
    29	
    30	This is **correct** for the link itself — it avoids flapping `wgN` and
    31	tearing the live peer/session on every commit (#1432 S2a, AGY Hazard B).
    32	
    33	The bug: a WG tunnel's **addresses** are reconciled only inside
    34	`applyWireguardTunLocked` (`tunnel.go:880`), which runs once per **still-
    35	configured** WG tunnel via the per-tunnel loop:
    36	
    37	```go
    38	// Apply, line 208-219
    39	for _, tc := range tunnels {          // tunnels = CURRENT config only
    40	    if tc.Mode == "wireguard" {
    41	        if err := t.applyWireguardTunLocked(tc); err != nil { ... }
    42	        continue
    43	    }
    44	    ...
    45	}
    46	```
    47	
    48	When an operator **removes** a WG tunnel from config:
    49	
    50	- The `wgN` link is correctly kept (persistent), but
    51	- `tc` for it is **absent** from `tunnels`, so `applyWireguardTunLocked`
    52	  / `reconcileLinkAddrsLocked` is **never called for it again**, and
    53	- It is **not in `ownedNames`**, so the `Apply` removal loop
    54	  (`tunnel.go:188-204`) never visits it either.
    55	
    56	Net: the kernel IP addresses this manager previously assigned to that
    57	wgN device (e.g. `172.16.0.1/30`) are **never reconciled away** — they
    58	persist on the live persistent device forever (until `ip link del wgN`
    59	or daemon restart). The in-code comment at `tunnel.go:790-794` already
    60	acknowledges this as a known S2a limitation (AGY M1) deferred to #1434.
    61	
    62	### 1a. The FRR-route claim — IMPORTANT scoping correction
    63	
    64	The issue title says "+ FRR routes". Investigation (§3) shows the FRR
    65	managed section is **regenerated declaratively and fully every commit**
    66	(`pkg/frr/manager.go:writeManagedSection` strips the entire
    67	`! BEGIN BPFRX MANAGED CONFIG` … `! END` block and rewrites it from
    68	`assembleFRRConfig`, then `frr-reload.py --reload` does a full diff). And
    69	WireGuard config **does not synthesize any FRR routes** — `WgAllowedIPs`
    70	are a decap inner-src gate only (`types_routing.go:328`), not LPM/routing,
    71	and `assembleFRRConfig` (`daemon_ipmon.go:89-153`) never reads tunnel or
    72	WG config. So **explicitly-configured static routes** that point at a wgN
    73	interface are owned by `routing-options static`/`routing-instances`, and
    74	when the operator removes those route statements, the full-rewrite +
    75	`frr-reload.py --reload` full diff withdraws them on the next commit.
    76	
    77	**Two sub-cases must be stated precisely** (a reviewer-critical
    78	distinction — do not overclaim a leak that does not exist):
    79	
    80	- **(A) Operator removes the static route stanza too** → FRR withdraws
    81	  it via the normal declarative path. **No FRR leak.** The route would,
    82	  however, be left pointing at a still-up wgN carrying stale addresses
    83	  until this fix prunes the addresses — but the route object itself is
    84	  withdrawn by FRR.
    85	- **(B) Operator removes ONLY the `tunnel`/WG stanza but leaves a
    86	  `routing-options static route … next-hop <wgN-addr>` referencing the
    87	  pruned address** → the static route stays in FRR (still configured),
    88	  now dangling toward an interface whose connected address we just
    89	  removed. This is **operator misconfiguration**, not a manager leak;
    90	  FRR/kernel will mark the route unreachable once the connected prefix
    91	  is gone. The plan does NOT chase this — withdrawing operator-owned
    92	  static routes the operator still has in config would be wrong.
    93	
    94	**Plan conclusion on FRR routes**: the genuine, in-scope leak is
    95	**kernel addresses on the persistent wgN device**, plus the **kernel
    96	connected route** that the kernel auto-installs for each address (the
    97	connected route is removed automatically by the kernel when its address
    98	is `AddrDel`'d — it is not a separate object we manage). There is **no
    99	manager-owned FRR route to withdraw**. The plan will (a) fix the address
   100	leak, and (b) document in the PR + module docs that FRR static routes are
   101	operator-owned and self-heal via the declarative path, closing the "FRR
   102	routes" portion of the issue by clarification rather than code.
   103	
   104	A reviewer who insists on an FRR code path must produce a concrete code
   105	location where WG config synthesizes a managed-section route. None was
   106	found in `pkg/frr/` (config_render.go, manager.go, daemon_ipmon.go all
   107	walked). If one is produced during review, this plan escalates to add a
   108	withdrawal hook; until then, the address prune is the complete fix.
   109	
   110	---
   111	
   112	## 2. Affected code (walked)
   113	
   114	| Location | Role |
   115	|---|---|
   116	| `pkg/routing/tunnel.go:163-233` `Apply` | reconcile entry; builds `desired`/`next`/`oldOwned`; WG excluded from diff |
   117	| `pkg/routing/tunnel.go:188-204` removal loop | deletes non-WG tunnels gone from config; `delete(appliedAddrs,name)` |
   118	| `pkg/routing/tunnel.go:208-230` per-tunnel loop | runs `applyWireguardTunLocked` ONLY for still-configured WG |
   119	| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
   120	| `pkg/routing/tunnel.go:584-645` `reconcileLinkAddrsLocked` | symmetric add/del against desired addr set; link-local gate; returns new applied set |
   121	| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
   122	| `pkg/routing/tunnel.go:666-722` `reconcileVRFClaimLocked` | VRF claim/unbind (WG also binds VRF at :883-888 but NOT via this reconcile) |
   123	| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
   124	| `pkg/config/types_routing.go:292-335` `TunnelConfig` | WG fields; `WgAllowedIPs` decap-only |
   125	| `pkg/daemon/daemon_ipmon.go:89-153` `assembleFRRConfig` | sole FRR FullConfig constructor; no tunnel/WG input |
   126	| `pkg/frr/manager.go:487-545` `writeManagedSection` | declarative full strip+rewrite of managed block |
   127	| `pkg/routing/tunnel_reconcile_test.go` | existing WG tests: only link-local cases (356/390/410); NO removal test |
   128	
   129	### Blast radius
   130	
   131	- One file edited (`pkg/routing/tunnel.go`), one test file extended
   132	  (`pkg/routing/tunnel_reconcile_test.go`), plus module-doc note.
   133	- The fix is confined to the WG branch of `Apply`. It must NOT touch the
   134	  GRE/IPIP removal diff (already correct) nor the still-configured WG
   135	  apply (already reconciles addresses correctly via :880).
   136	- No wire-protocol change, no userspace-dp change, no FRR change.
   137	- Interaction with #1918 (merged, PR #1947): #1918 added `probeICMP`
   138	  real-liveness to the **GRE keepalive** path (`keepaliveLoop`,
   139	  `probeICMP` at :1024). WG tunnels never run keepalives
   140	  (`applyWireguardTunLocked` never calls `startKeepalive`). So the #1918
   141	  change does not interact with this fix; the rebase is clean (plan
   142	  already branched off post-#1918 master @ ee3f336d3). No conflict.
   143	
   144	---
   145	
   146	## 3. Root cause (precise)
   147	
   148	Two facts combine:
   149	
   150	1. WG names are deliberately excluded from `ownedNames` and `desired`
   151	   (`tunnel.go:172`), so the removal loop that prunes addresses for
   152	   GRE/IPIP-style tunnels (via `delete(appliedAddrs,name)` + `LinkDel`)
   153	   never fires for WG, AND
   154	2. address reconciliation for WG happens *only* inside
   155	   `applyWireguardTunLocked`, which is driven by the **current config
   156	   list** (`tunnels` arg) — so a removed WG tunnel is simply never
   157	   visited by any address-reconciling code again.
   158	
   159	The persistent-device design (correct) and the address-reconcile-only-
   160	when-configured design (correct for live tunnels) have a **gap exactly
   161	at removal**: nobody owns "this WG device used to be configured, is now
   162	gone from config, but the link must stay — strip its addresses."
   163	
   164	The `appliedAddrs[name]` map is the key asset already in place: it
   165	records exactly which addresses **this manager** applied to each device.
   166	On removal we want to reconcile that device against an **empty desired
   167	address set**, which `reconcileLinkAddrsLocked(link, name, nil,
   168	appliedAddrs[name], …)` already does correctly (delete present-and-not-
   169	wanted, respecting the link-local applied gate). We just need to *call*
   170	it on removal and then drop the tracking entry.
   171	
   172	---
   173	
   174	## 4. Design — Path Options
   175	
   176	The branch point is **how the manager detects "a WG tunnel was removed"
   177	and how it prunes addresses while keeping the link**.
   178	
   179	### Path A — Track previously-configured WG names; diff on removal (RECOMMENDED)
   180	
   181	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
   182	to `ownedNames` but WG-only, and **never** feeding the `LinkDel` removal
   183	loop). Each `Apply`:
   184	
   185	1. Build `wgDesired` = set of `tc.Name` for current `Mode=="wireguard"`.
   186	2. **Prune phase** (new), run alongside the existing GRE removal loop:
   187	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
   188	   - look up the link (`LinkByName`); if found, call
   189	     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
   190	     "wireguard tun")` → strips manager-applied addresses (empty desired
   191	     set), honoring the link-local applied gate (kernel autoconf fe80
   192	     never touched).
   193	   - **Keep the link** — never `LinkDel` (that is the #1432 invariant).
   194	   - Optionally VRF-unbind (see §4a) — keep narrow for now.
   195	   - `delete(t.appliedAddrs, name)` once pruned (idempotent: a second
   196	     commit finds `name` no longer in old `wgConfigured`, so no-op).
   197	   - If `LinkByName` fails (device already gone — manual `ip link del`),
   198	     just `delete(t.appliedAddrs, name)` and drop tracking.
   199	   - If `reconcileLinkAddrsLocked` leaves residual tracked addresses
   200	     because an `AddrDel` failed, **retain** the name in the next
   201	     `wgConfigured` so the next commit retries (mirrors GRE
   202	     removal-retry at :197). Detect residual via the returned applied
   203	     set being non-empty.
   204	3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
   205	   plus any retained-for-retry names.
   206	
   207	**Pros**: symmetric with the existing `ownedNames` retry pattern; reuses
   208	`reconcileLinkAddrsLocked` and `appliedAddrs` verbatim; idempotent;
   209	link preserved; minimal new state (one map). Tested pattern in this file.
   210	
   211	**Cons**: one more reconcile map to keep in sync across `clearLocked`
   212	(must reset it too) and `ensureReconcileStateLocked` (must lazily init).
   213	
   214	### Path B — Flush all addresses on any wgN that is up-but-unconfigured
   215	
   216	On each `Apply`, enumerate kernel links, find TUN devices matching the
   217	WG naming whose name is not in `wgDesired`, and flush manager-applied
   218	addresses. Rejected: requires WG-name heuristics (no stable WG-only
   219	marker on the netdev), risks touching foreign/adopted devices, and
   220	duplicates the `appliedAddrs` bookkeeping Path A already has. Higher
   221	blast radius, weaker safety.
   222	
   223	### Path C — Tear the link too on removal
   224	
   225	Rejected explicitly by #1432 S2a (AGY Hazard B): deleting wgN tears the
   226	live peer/session and flaps the device. The issue itself says keep the
   227	link. Out of scope; #1434 owns full teardown grammar.
   228	
   229	### Recommendation
   230	
   231	**Path A.** It is the minimal, symmetric, idempotent fix that reuses the
   232	exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
   233	already maintains, keeps the persistent link per #1432, and adds one
   234	narrowly-scoped state map with the same retry discipline as the existing
   235	GRE removal loop.
   236	
   237	### 4a. VRF unbind on WG removal — scope decision
   238	
   239	`applyWireguardTunLocked` VRF-binds at `:883-888` but does NOT use
   240	`reconcileVRFClaimLocked`/`appliedRI` (it binds directly, no claim
   241	tracked). So a removed WG tunnel that was VRF-bound leaves the link
   242	enslaved to `vrf-<ri>`. Two choices:
   243	
   244	- **A1 (recommended for this PR)**: prune **addresses only**; leave the
   245	  VRF master as-is. Rationale: the link persists by design; its VRF
   246	  membership is a property of the persistent device, not a leaked
   247	  address; and there is no `appliedRI` claim to safely identity-gate an
   248	  unbind (unbinding blind would risk stripping a master we do not own —
   249	  the exact hazard `reconcileVRFClaimLocked` was built to avoid). Note
   250	  this explicitly as a documented residual, tracked under #1434.
   251	- **A2**: extend WG to use `appliedRI`/`reconcileVRFClaimLocked` so
   252	  removal can identity-gated-unbind. Larger change; couples this fix to
   253	  the VRF-claim machinery WG deliberately bypasses. Defer.
   254	
   255	Decision: **A1** — addresses only, VRF residual documented. If a
   256	reviewer demands VRF unbind, escalate to A2 as a follow-up, not this PR.
   257	
   258	---
   259	
   260	## 5. Detailed implementation sketch (Path A)

exec
/bin/bash -lc 'pwd && git rev-parse --short HEAD && git status --short' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
1bbbc5650

codex
The initial read confirms the plan’s high-level root cause, but the line ranges need a tighter pass: the actual address reconcile function starts later than the quoted approximate range in the prompt output. I’m pulling the exact function bodies and all possible FRR/tunnel route paths now.
exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '230,360p;700,790p;790,930p;930,1045p;1125,1260p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   230	func (t *tunnelManager) bumpLinkGenLocked(name string) {
   231		t.linkGenForLocked(name).Add(1)
   232	}
   233	
   234	// keepaliveProber resolves the prober used by keepalive goroutines: the
   235	// injected test fake when set, else the production datagram-ICMP prober.
   236	func (t *tunnelManager) keepaliveProber() tunnelProber {
   237		if t.prober != nil {
   238			return t.prober
   239		}
   240		return icmpProber{}
   241	}
   242	
   243	// Apply reconciles the kernel tunnel devices against the desired
   244	// config WITHOUT the historical clear-all + delete-and-recreate
   245	// (#1884): an untouched tunnel keeps its netdev (stable ifindex — no
   246	// FRR route churn, no userspace-dp TUN-reader death per commit, see
   247	// #1881), tunnels removed from config are deleted via a set-diff
   248	// against the previous desired set, and a device is recreated only
   249	// when the existing kernel link is genuinely incompatible. Keepalive
   250	// probes (legacy non-anchor branch only) are reconciled by identity
   251	// instead of being restarted every apply.
   252	func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
   253		t.mu.Lock()
   254		defer t.mu.Unlock()
   255		t.ensureReconcileStateLocked()
   256	
   257		desired := make(map[string]bool, len(tunnels))
   258		for _, tc := range tunnels {
   259			// WireGuard TUNs stay untracked/persistent (#1432 S2a, AGY
   260			// Hazard B) and are excluded from the removal diff.
   261			if tc.Mode != "wireguard" {
   262				desired[tc.Name] = true
   263			}
   264		}
   265	
   266		// oldOwned is the ENTRY-TIME ownership snapshot — the adoption
   267		// authority for the per-tunnel loop below (#1884 r2 Codex F1: the
   268		// rewritten set would mark every desired tunnel "owned" and make
   269		// adoption unreachable). next starts as the desired set; removal
   270		// failures retain their names so the next Apply retries instead of
   271		// orphaning a live link (r2 Codex F5).
   272		oldOwned := t.ownedNames
   273		next := make(map[string]bool, len(desired))
   274		for name := range desired {
   275			next[name] = true
   276		}
   277		for name := range oldOwned {
   278			if desired[name] {
   279				continue
   280			}
   281			t.stopKeepaliveLocked(name)
   282			if link, err := t.ops.LinkByName(name); err == nil {
   283				if delErr := t.ops.LinkDel(link); delErr != nil {
   284					slog.Warn("failed to delete removed tunnel",
   285						"name", name, "err", delErr)
   286					next[name] = true // retain ownership; retry next apply
   287					continue
   288				}
   289				slog.Info("tunnel removed", "name", name)
   290			}
   291			delete(t.appliedAddrs, name)
   292			delete(t.appliedRI, name)
   293		}
   294		t.ownedNames = next
   295		t.tunnels = nil // success-tracked (GetStatus); rebuilt below
   296	
   297		for _, tc := range tunnels {
   298			// WireGuard TUNs are persistent (#1432 S2a, AGY Hazard B): never
   299			// delete-and-recreate on reload — that would flap wgN and destroy
   300			// its addresses + FRR routes every commit. applyWireguardTunLocked
   301			// reuses an existing wgN in place.
   302			if tc.Mode == "wireguard" {
   303				if err := t.applyWireguardTunLocked(tc); err != nil {
   304					slog.Warn("failed to apply wireguard tunnel",
   305						"name", tc.Name, "err", err)
   306				}
   307				continue
   308			}
   309			// Adoption = this manager did NOT own the name at the last
   310			// apply (daemon restart, wireguard→gre same-name flip, foreign
   311			// but compatible TUN). Decided from the entry-time snapshot for
   312			// BOTH the plain-reuse and the LinkAdd-EEXIST paths.
   313			adopting := !oldOwned[tc.Name]
   314			if tc.AnchorOnly {
   315				t.applyAnchorLocked(tc, adopting)
   316				continue
   317			}
   318			t.applyKernelTunnelLocked(tc)
   319		}
   320	
   321		return nil
   322	}
   323	
   324	// anchorReusable reports whether an existing link can serve as the
   325	// userspace-dp TUN anchor in place (#1884 A.3): it must be a TUN (not
   326	// TAP/dummy/gre), carry NO_PI (the Rust side opens IFF_TUN|IFF_NO_PI —
   327	// userspace-dp/src/slowpath.rs; a PI-enabled foreign TUN would break
   328	// attach where recreate heals it), and be persistent (a non-persistent
   329	// TUN held alive only by a foreign fd would evaporate when that fd
   330	// closes). Kernel readback reconstructs Mode/NO_PI/persist via
   331	// IFLA_TUN_*; the obsolete ONE_QUEUE flag is not reported and not
   332	// checked.
   333	func anchorReusable(link netlink.Link) bool {
   334		tt, ok := link.(*netlink.Tuntap)
   335		if !ok || tt.Mode != netlink.TUNTAP_MODE_TUN {
   336			return false
   337		}
   338		if tt.Flags&netlink.TUNTAP_NO_PI == 0 {
   339			return false
   340		}
   341		return !tt.NonPersist
   342	}
   343	
   344	// applyAnchorLocked reconciles one AnchorOnly TUN device (the
   345	// production userspace-dp path). Caller MUST hold mu.
   346	func (t *tunnelManager) applyAnchorLocked(tc *config.TunnelConfig, adopting bool) {
   347		// A leftover keepalive runner (legacy→anchor mode change) must not
   348		// keep probing: anchors never run keepalives (probes LinkSetDown
   349		// the device on failure — a behavior the anchor path never had).
   350		t.stopKeepaliveLocked(tc.Name)
   351	
   352		var link netlink.Link
   353		created := false
   354		if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
   355			if anchorReusable(existing) {
   356				// Operate on the kernel-fetched link (real ifindex and
   357				// attributes), never a fresh ifindex-less struct (#1706).
   358				link = existing
   359				slog.Debug("tunnel anchor reused", "name", tc.Name)
   360			} else {
   700			slog.Debug("skipping link up: keepalive holds tunnel down",
   701				"name", tc.Name)
   702		} else if err := t.ops.LinkSetUp(link); err != nil {
   703			slog.Warn("failed to bring up "+kind, "name", tc.Name, "err", err)
   704		}
   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
   706			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
   707		t.reconcileVRFClaimLocked(tc, link)
   708		t.tunnels = append(t.tunnels, tc.Name)
   709	}
   710	
   711	// reconcileLinkAddrsLocked symmetrically reconciles a link's addresses
   712	// against the configured set: add configured-but-missing, delete
   713	// present-but-unconfigured — EXCEPT link-local addresses, which are
   714	// deleted only when this manager itself applied them (`applied`
   715	// gate). The kernel's autoconf fe80 must never be deleted, while a
   716	// CONFIGURED fe80 removed from config must not leak forever (#1884 r1
   717	// Codex F2; extended to the WG branch in #1905). applied == nil (the
   718	// first apply for a link this manager has not tracked yet — restart
   719	// adoption) means no link-local deletion at all.
   720	//
   721	// Returns the new applied set: successful adds + present-and-wanted +
   722	// link-local addresses whose stale-delete FAILED (kept tracked so the
   723	// next apply retries — r2 Codex F4).
   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
   725		want := make(map[string]bool, len(addrs))
   726		for _, addrStr := range addrs {
   727			addr, parseErr := netlink.ParseAddr(addrStr)
   728			if parseErr != nil {
   729				slog.Warn("invalid "+kind+" address",
   730					"name", name, "addr", addrStr, "err", parseErr)
   731				continue
   732			}
   733			want[addr.IPNet.String()] = true
   734		}
   735		newApplied := make(map[string]bool, len(want))
   736		existing := map[string]bool{}
   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
   738			for i := range list {
   739				a := list[i]
   740				key := a.IPNet.String()
   741				existing[key] = true
   742				if want[key] {
   743					continue
   744				}
   745				if a.IP == nil {
   746					// Defensive: the pre-#1884 WG block only deleted
   747					// addresses with a non-nil IP; keep that byte-identical
   748					// (and never delete something we cannot classify).
   749					continue
   750				}
   751				if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
   752					// Kernel-managed or foreign link-local: never delete.
   753					continue
   754				}
   755				if delErr := t.ops.AddrDel(link, &a); delErr != nil {
   756					slog.Warn("failed to remove stale "+kind+" address",
   757						"name", name, "addr", key, "err", delErr)
   758					if a.IP != nil && a.IP.IsLinkLocalUnicast() {
   759						newApplied[key] = true // retry next apply
   760					}
   761				} else {
   762					slog.Info("removed stale "+kind+" address",
   763						"name", name, "addr", key)
   764				}
   765			}
   766		}
   767		for _, addrStr := range addrs {
   768			addr, parseErr := netlink.ParseAddr(addrStr)
   769			if parseErr != nil {
   770				continue
   771			}
   772			key := addr.IPNet.String()
   773			if existing[key] {
   774				newApplied[key] = true
   775				continue
   776			}
   777			if addErr := t.ops.AddrAdd(link, addr); addErr != nil {
   778				slog.Warn("failed to add "+kind+" address",
   779					"name", name, "addr", addrStr, "err", addErr)
   780			} else {
   781				newApplied[key] = true
   782			}
   783		}
   784		return newApplied
   785	}
   786	
   787	// reconcileVRFClaimLocked runs the #1884 A.5 ordered claim procedure.
   788	// The claim invariant (r6-r8): t.appliedRI[name] is only ever written
   789	// from a SUCCESSFUL BindInterfaceToVRF or a direct observation of the
   790	// link's master — never from intent — so the identity-gated unbind
   790	// link's master — never from intent — so the identity-gated unbind
   791	// below can neither strand a master we own nor touch one we do not.
   792	//
   793	//  1. stanza RI nonempty: bind; on success claim = stanza RI (stanza
   794	//     wins over a coexisting 0a list bind — today's effective apply
   795	//     order); on failure fall through to observation.
   796	//  2. stanza failed or empty, RIListMember nonempty: never unbind (0a
   797	//     owns list binds — the VETO); claim transfers to the list RI only
   798	//     when the observed master IS vrf-<RIListMember>, else the prior
   799	//     claim is retained.
   800	//  3. config wants no RI: identity-gated unbind of vrf-<claim>. Claim
   801	//     clears on successful unbind / identity mismatch (master not
   802	//     ours) / VRF device not-found (kernel already freed the slaves);
   803	//     it is RETAINED on transient errors so the next apply retries.
   804	//
   805	// Caller MUST hold mu.
   806	func (t *tunnelManager) reconcileVRFClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
   807		name := tc.Name
   808		if tc.RoutingInstance != "" {
   809			if err := t.vrfBinder.BindInterfaceToVRF(name, tc.RoutingInstance); err != nil {
   810				slog.Warn("failed to bind tunnel to VRF",
   811					"name", name, "vrf", tc.RoutingInstance, "err", err)
   812				// r7/r8: a FAILED bind must not blind-write the claim (the
   813				// kernel may still carry the previous master, or a 0a list
   814				// bind). Observation may take the claim; else retain.
   815				t.observeListClaimLocked(tc, link)
   816				return
   817			}
   818			t.appliedRI[name] = tc.RoutingInstance
   819			return
   820		}
   821		if tc.RIListMember != "" {
   822			// Unbind VETO: a stanza→list move must never strip the 0a
   823			// bind (r4 convergent counterexample).
   824			t.observeListClaimLocked(tc, link)
   825			return
   826		}
   827	
   828		claim := t.appliedRI[name]
   829		if claim == "" {
   830			return
   831		}
   832		master := link.Attrs().MasterIndex
   833		if master == 0 {
   834			// Nothing is bound — whatever we once bound is already gone.
   835			delete(t.appliedRI, name)
   836			return
   837		}
   838		vrf, err := t.ops.LinkByName("vrf-" + claim)
   839		if err != nil {
   840			if isLinkNotFound(err) {
   841				// The VRF device is gone; deleting a master frees its
   842				// slaves, so the current master cannot be ours.
   843				delete(t.appliedRI, name)
   844				return
   845			}
   846			// Transient lookup error: retain the claim, retry next apply.
   847			return
   848		}
   849		if vrf.Attrs().Index != master {
   850			// Master is not the VRF we bound (someone else's bind).
   851			delete(t.appliedRI, name)
   852			return
   853		}
   854		if err := t.ops.LinkSetNoMaster(link); err != nil {
   855			slog.Warn("failed to unbind tunnel from VRF",
   856				"name", name, "vrf", claim, "err", err)
   857			return // retain claim; retry next apply
   858		}
   859		slog.Info("tunnel unbound from routing-instance",
   860			"name", name, "vrf", claim)
   861		delete(t.appliedRI, name)
   862	}
   863	
   864	// observeListClaimLocked transfers the appliedRI claim to the
   865	// routing-instance list member ONLY when the link's current master is
   866	// OBSERVED to be that RI's VRF device (#1884 r6/r8: a blind transfer
   867	// after a failed 0a bind would record an RI the kernel never took and
   868	// later strand the real master on a mismatch-clear). On any
   869	// non-observation the previous nonempty claim is retained. Caller MUST
   870	// hold mu.
   871	func (t *tunnelManager) observeListClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
   872		if tc.RIListMember == "" {
   873			return
   874		}
   875		master := link.Attrs().MasterIndex
   876		if master == 0 {
   877			return // 0a bind absent or failed: no observation, retain prior
   878		}
   879		vrf, err := t.ops.LinkByName("vrf-" + tc.RIListMember)
   880		if err != nil {
   881			return // retain prior claim
   882		}
   883		if vrf.Attrs().Index == master {
   884			t.appliedRI[tc.Name] = tc.RIListMember
   885		}
   886	}
   887	
   888	// WG per-packet outer overhead (must mirror userspace-dp
   889	// afxdp/wg/mod.rs WG_OVERHEAD_V4/V6): outer IP + UDP(8) + WG data
   890	// header(16) + Poly1305 tag(16). Plus up to 15 bytes of §5.4.6 pad.
   891	const (
   892		wgOverheadV4 = 20 + 8 + 16 + 16 // 60
   893		wgOverheadV6 = 40 + 8 + 16 + 16 // 80
   894		wgPadWorst   = 15
   895	)
   896	
   897	// wgTunMTUForEndpoint computes the inner (wgN) MTU cap (#1432 S2a, AGY
   898	// Hazard A / H2). The kernel must never hand the WG control thread a
   899	// plaintext packet that, once encapped with the worst-case overhead
   900	// plus §5.4.6 pad, exceeds the outer MTU and forces outer IP
   901	// fragmentation. The overhead depends on the outer IP family (the WG
   902	// peer endpoint address): IPv6-outer is 20 bytes larger. The outer MTU
   903	// is assumed to be a standard 1500 (S2a single-tunnel); the control
   904	// thread also enforces an exact pad-aware guard (wg_control.rs), so this
   905	// is the first line, not the only one.
   906	func wgTunMTUForEndpoint(tc *config.TunnelConfig) int {
   907		const outerMTU = 1500
   908		// A configured v4 endpoint uses the v4 overhead; a v6 endpoint (or a
   909		// responder-only/roaming endpoint with no configured address, which
   910		// the Rust control thread may LEARN as v6 — Codex r4 MAJOR) uses the
   911		// larger v6 overhead so the kernel never hands the control thread an
   912		// inner packet that the v6-aware encap guard would then drop.
   913		overhead := wgOverheadV6
   914		if tc.WgEndpoint != "" {
   915			if host, _, err := net.SplitHostPort(tc.WgEndpoint); err == nil {
   916				if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
   917					overhead = wgOverheadV4
   918				}
   919			}
   920		}
   921		return outerMTU - overhead - wgPadWorst
   922	}
   923	
   924	// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
   925	// netdev for a WireGuard tunnel endpoint and configures its MTU,
   926	// addresses, and VRF binding. The device is intentionally NOT tracked
   927	// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
   928	// — flapping wgN destroys its addresses and FRR routes every commit).
   929	//
   930	// Known S2a limitation (AGY M1): because the device is untracked, a WG
   930	// Known S2a limitation (AGY M1): because the device is untracked, a WG
   931	// tunnel REMOVED from the config is not torn down by clearLocked and
   932	// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
   933	// accepts this in exchange for reload stability; multi-instance teardown
   934	// is owned by the S6 grammar work (#1434).
   935	//
   936	// The Rust control thread (coordinator/wg_control.rs) attaches to this
   937	// persistent device by name.
   938	func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
   939		mtu := wgTunMTUForEndpoint(tc)
   940		link, err := t.ops.LinkByName(tc.Name)
   941		// Copilot C3: only reuse an existing link if it is actually a TUN/TAP.
   942		// A name collision with some other interface type (e.g. a leftover
   943		// dummy) must be deleted and recreated, not mutated — otherwise we'd
   944		// bring up + address + VRF-bind the wrong device, and the Rust side's
   945		// open_tun on the same name would then fail.
   946		mustCreate := err != nil
   947		if err == nil {
   948			tt, isTuntap := link.(*netlink.Tuntap)
   949			if !isTuntap || tt.Mode != netlink.TUNTAP_MODE_TUN {
   950				// Not a TUN (a TAP, or some other type entirely). The Rust
   951				// side opens it with IFF_TUN, so a TAP would fail there;
   952				// delete + recreate as a TUN rather than mutate the wrong
   953				// device (Codex r3 MINOR).
   954				slog.Info("replacing non-TUN link before wireguard tun create",
   955					"name", tc.Name, "type", link.Type())
   956				if delErr := t.ops.LinkDel(link); delErr != nil {
   957					return fmt.Errorf("replace non-tun wireguard link %s: %w", tc.Name, delErr)
   958				}
   959				mustCreate = true
   960			}
   961		}
   962		if mustCreate {
   963			// Create a persistent TUN. NonPersist:false keeps the netdev
   964			// alive after the creating fd closes, so a reload that does not
   965			// touch this device leaves it (and its routes) intact.
   966			tun := &netlink.Tuntap{
   967				LinkAttrs:  netlink.LinkAttrs{Name: tc.Name, MTU: mtu},
   968				Mode:       netlink.TUNTAP_MODE_TUN,
   969				Flags:      netlink.TUNTAP_NO_PI,
   970				Queues:     1,
   971				NonPersist: false,
   972			}
   973			if addErr := t.ops.LinkAdd(tun); addErr != nil {
   974				return fmt.Errorf("create wireguard tun %s: %w", tc.Name, addErr)
   975			}
   976			closeTuntapFiles(tun.Fds)
   977			link = tun
   978			// vishvananda/netlink creates a TUN via TUNSETIFF and may return
   979			// before the generic LinkAttrs.MTU is applied, leaving the kernel
   980			// device at its default MTU on first apply (Codex r4 MAJOR).
   981			// Set the MTU explicitly after create so the inner cap is live
   982			// immediately, not only after a later reload.
   983			if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
   984				slog.Warn("failed to set wireguard tun mtu on create",
   985					"name", tc.Name, "mtu", mtu, "err", mtuErr)
   986			}
   987			slog.Info("wireguard tun created", "name", tc.Name, "mtu", mtu)
   988		} else {
   989			// Reuse in place; reconcile the MTU if the config changed it
   990			// (AGY M4 / Copilot C4 — a stale MTU on reuse, including a
   991			// pre-created device, would otherwise persist).
   992			if link.Attrs().MTU != mtu {
   993				if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
   994					slog.Warn("failed to update wireguard tun mtu",
   995						"name", tc.Name, "mtu", mtu, "err", mtuErr)
   996				} else {
   997					slog.Info("wireguard tun mtu updated", "name", tc.Name, "mtu", mtu)
   998				}
   999			}
  1000			slog.Debug("wireguard tun reused", "name", tc.Name)
  1001		}
  1002	
  1003		if err := t.ops.LinkSetUp(link); err != nil {
  1004			slog.Warn("failed to bring up wireguard tun", "name", tc.Name, "err", err)
  1005		}
  1006	
  1007		// Symmetric address reconciliation (Copilot C5): because the device
  1008		// is persistent and never recreated, addresses removed from the config
  1009		// would otherwise survive every reload and keep being routed. Shared
  1010		// helper (#1884) with the per-link applied-address record (#1905) —
  1011		// the same configured-vs-autoconf link-local split as the GRE/IPIP
  1012		// branch: a CONFIGURED fe80 later removed from config is deleted
  1013		// (this manager applied it), while the kernel's autoconf fe80 — and
  1014		// any fe80 already present before this daemon's first apply
  1015		// (restart adoption pass, applied == nil) — is never touched.
  1016		// Because the wgN device persists when removed from config (S2a,
  1017		// see above), its appliedAddrs entry is retained with it so a later
  1018		// re-add keeps accurate tracking; S6 teardown (#1434) owns deleting
  1019		// both.
  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
  1022	
  1023		if tc.RoutingInstance != "" {
  1024			if bindErr := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); bindErr != nil {
  1025				slog.Warn("failed to bind wireguard tun to VRF",
  1026					"name", tc.Name, "vrf", tc.RoutingInstance, "err", bindErr)
  1027			}
  1028		}
  1029		return nil
  1030	}
  1031	
  1032	// closeTuntapFiles closes the file descriptors returned by a Tuntap
  1033	// LinkAdd so they are not leaked.
  1034	func closeTuntapFiles(files []*os.File) {
  1035		for _, file := range files {
  1036			if file != nil {
  1037				_ = file.Close()
  1038			}
  1039		}
  1040	}
  1041	
  1042	// stopAll cancels all running keepalive goroutines and waits for them
  1043	// to exit. Acquires mu.
  1044	//
  1045	// #848: draining (not just cancelling) is required because
  1125		go t.keepaliveLoop(ctx, done, tunnelName, state, prober, gen, startGen)
  1126		slog.Info("started keepalive", "tunnel", tunnelName,
  1127			"source", source, "remote", remoteAddr, "interval", interval, "retries", maxRetries)
  1128	}
  1129	
  1130	// keepaliveProbeDeadline returns the per-probe round-trip budget: a
  1131	// fraction of the interval, capped at 800ms (R5). Keeps the probe well
  1132	// inside the tick so a slow/lost reply cannot overrun the next tick.
  1133	func keepaliveProbeDeadline(intervalSec int) time.Duration {
  1134		const maxDeadline = 800 * time.Millisecond
  1135		half := time.Duration(intervalSec) * time.Second / 2
  1136		if half <= 0 || half > maxDeadline {
  1137			return maxDeadline
  1138		}
  1139		return half
  1140	}
  1141	
  1142	// keepaliveLoop runs periodic ICMP echo probes to the tunnel underlay
  1143	// endpoint and drives the link admin state off REAL liveness (#1918).
  1144	// Closes `done` when it returns so stopAll can drain.
  1145	//
  1146	// Tick body is the §6 Axis D COMMIT-AFTER-SUCCESS sequence:
  1147	//  1. Under state.mu: classify the probe; commit pure counters
  1148	//     (Failures/LastSuccess/LastFailure/unknown bookkeeping); compute
  1149	//     the transition INTENT (wantUp/wantDown) WITHOUT writing Up; Unlock.
  1150	//     A racing GetStatus/Apply therefore never observes an uncommitted Up.
  1151	//  2. No intent → done (no netlink, no Up write).
  1152	//  3. LinkByName; on error do nothing (Up unchanged → retried next tick).
  1153	//  4. Lock-free gen.Load() guard: if the generation changed, the link
  1154	//     was recreated under us → DROP the action (do not down/up the
  1155	//     replacement). Never takes t.mu (AGY r5).
  1156	//  5. The single LinkSetUp/LinkSetDown, OUTSIDE state.mu, capturing err.
  1157	//  6. Commit Up ONLY on netlink success; on error leave Up unchanged so
  1158	//     the transition retries.
  1159	func (t *tunnelManager) keepaliveLoop(ctx context.Context, done chan struct{}, tunnelName string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64) {
  1160		defer close(done)
  1161		ticker := time.NewTicker(time.Duration(state.Interval) * time.Second)
  1162		defer ticker.Stop()
  1163	
  1164		for {
  1165			select {
  1166			case <-ctx.Done():
  1167				return
  1168			case <-ticker.C:
  1169				t.keepaliveTick(tunnelName, state, prober, gen, startGen)
  1170			}
  1171		}
  1172	}
  1173	
  1174	// keepaliveTick runs one §6 Axis D commit-after-success probe cycle. It
  1175	// is the per-tick body of keepaliveLoop, extracted so tests can drive a
  1176	// single deterministic tick without a real ticker. It NEVER takes t.mu
  1177	// (AGY r5): only state.mu (two short sections) and a lock-free gen.Load().
  1178	func (t *tunnelManager) keepaliveTick(tunnelName string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64) {
  1179		deadline := keepaliveProbeDeadline(state.Interval)
  1180		seq := nextSeq(state)
  1181		nonce := makeNonce()
  1182		result, kind, reason := prober.Probe(state.SourceAddr, state.RemoteAddr, seq, nonce, deadline)
  1183	
  1184		// ---- Step 1: classify + commit counters, compute intent ----
  1185		state.mu.Lock()
  1186		var wantUp, wantDown bool
  1187		switch result {
  1188		case ProbeAlive:
  1189			state.LastSuccess = time.Now()
  1190			state.clearUnknownLocked()
  1191			if !state.Up {
  1192				wantUp = true // recovery edge
  1193			}
  1194			state.Failures = 0
  1195		case ProbeDead:
  1196			state.LastFailure = time.Now()
  1197			state.clearUnknownLocked()
  1198			state.Failures++
  1199			if state.Up && state.Failures >= state.MaxRetries {
  1200				wantDown = true
  1201			}
  1202		case ProbeUnsupported:
  1203			// Hold-on-unknown (§6 Axis C, C1): do NOT touch Failures,
  1204			// do NOT transition the link. Surface as unknown; escalate a
  1205			// sustained TRANSIENT unknown after MaxRetries ticks. The prober's
  1206			// reason (real syscall/config detail) is recorded so the status and
  1207			// escalation log are actionable (Copilot PR #1947).
  1208			detail := reason
  1209			if detail == "" {
  1210				detail = classifyErrnoString(kind)
  1211			}
  1212			state.markUnknownLocked(tunnelName, kind, detail)
  1213		}
  1214		state.mu.Unlock()
  1215	
  1216		// ---- Step 2: no transition intent → nothing to do ----
  1217		if !wantUp && !wantDown {
  1218			return
  1219		}
  1220	
  1221		// ---- Step 3: resolve the link; error → retry next tick ----
  1222		link, err := t.ops.LinkByName(tunnelName)
  1223		if err != nil {
  1224			// Do NOT write Up; the guard in step 1 fires again next
  1225			// tick (Up unchanged). No spurious latch from a transient
  1226			// netlink lookup hiccup (§4.6).
  1227			slog.Debug("keepalive transition deferred: link lookup failed",
  1228				"tunnel", tunnelName, "err", err)
  1229			return
  1230		}
  1231	
  1232		// ---- Step 4: lock-free generation guard (defense-in-depth) --
  1233		if gen.Load() != startGen {
  1234			// The link was recreated by Apply since this runner started.
  1235			// Drop the action so we never down/up the replacement link.
  1236			slog.Debug("keepalive transition dropped: link generation changed",
  1237				"tunnel", tunnelName)
  1238			return
  1239		}
  1240	
  1241		// ---- Step 5: the single netlink op, OUTSIDE state.mu --------
  1242		var nlErr error
  1243		if wantUp {
  1244			nlErr = t.ops.LinkSetUp(link)
  1245		} else {
  1246			nlErr = t.ops.LinkSetDown(link)
  1247		}
  1248	
  1249		// ---- Step 6: commit Up only on netlink success -------------
  1250		if nlErr != nil {
  1251			// Up retains its pre-transition value → the transition is
  1252			// retried next tick until the kernel op succeeds. Never a
  1253			// lost transition (Codex r3 counterexample).
  1254			slog.Warn("keepalive netlink transition failed; will retry",
  1255				"tunnel", tunnelName, "want_up", wantUp, "err", nlErr)
  1256			return
  1257		}
  1258		state.mu.Lock()
  1259		if wantUp {
  1260			state.Up = true

exec
/bin/bash -lc "nl -ba pkg/config/types_routing.go | sed -n '260,360p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   260		LogNeighborChanges   bool   // log neighbor state transitions
   261		Dampening            bool   // enable route flap dampening
   262		DampeningHalfLife    int    // half-life in minutes (default 15)
   263		DampeningReuse       int    // reuse threshold (default 750)
   264		DampeningSuppress    int    // suppress threshold (default 2000)
   265		DampeningMaxSuppress int    // max suppress time in minutes (default 60)
   266		Neighbors            []*BGPNeighbor
   267		Export               []string // "connected", "static", "ospf", etc.
   268	}
   269	
   270	// BGPNeighbor defines a BGP peer.
   271	type BGPNeighbor struct {
   272		Address              string // peer IP
   273		PeerAS               uint32
   274		Description          string
   275		MultihopTTL          int      // 0 = directly connected
   276		Export               []string // per-group export policies (route-map out)
   277		FamilyInet           bool     // activate under address-family ipv4 unicast
   278		FamilyInet6          bool     // activate under address-family ipv6 unicast
   279		GroupName            string   // BGP group name (for display)
   280		AuthPassword         string   // TCP MD5 password for BGP session
   281		BFD                  bool     // enable BFD for this neighbor
   282		BFDInterval          int      // BFD minimum interval in ms (0 = default 300)
   283		BFDMultiplier        int      // BFD detect-multiplier (0 = default 3)
   284		RouteReflectorClient bool     // mark as route-reflector client
   285		DefaultOriginate     bool     // advertise default route to this neighbor
   286		AllowASIn            int      // allow own AS in path N times (0 = disabled)
   287		RemovePrivateAS      bool     // strip private AS numbers from updates
   288		PrefixLimitInet      int      // max IPv4 prefixes (0 = unlimited)
   289		PrefixLimitInet6     int      // max IPv6 prefixes (0 = unlimited)
   290	}
   291	
   292	// TunnelConfig defines a GRE, IPIP, or other tunnel interface.
   293	type TunnelConfig struct {
   294		Name            string   // Linux interface name (e.g. "gr-0-0-0", "ip-0-0-0")
   295		Mode            string   // "gre" or "ipip"
   296		Source          string   // local tunnel endpoint IP
   297		Destination     string   // remote tunnel endpoint IP
   298		Key             uint32   // GRE key, 0 = none
   299		TTL             int      // tunnel TTL, 0 = default 64
   300		Addresses       []string // IPs to assign to tunnel interface (CIDR)
   301		RoutingInstance string   // destination routing-instance (VRF)
   302		Keepalive       int      // keepalive interval in seconds (0 = disabled)
   303		KeepaliveRetry  int      // number of missed keepalives before declaring down (0 = default 3)
   304		AnchorOnly      bool     // create a dummy anchor instead of a kernel tunnel device
   305	
   306		// MTU is the config-desired link MTU for the tunnel device (#1884):
   307		// the owning interface's `mtu` statement (unit-level overrides
   308		// interface-level for unit tunnels, mirroring compiler_iface
   309		// precedence). 0 means unconfigured — the tunnel manager then never
   310		// writes MTU except the one-time TUN-default normalization when
   311		// ADOPTING an anchor it did not create (wireguard→gre same-name flip
   312		// repair). Populated by collectAppliedTunnels; the legacy
   313		// standalone-CLI apply path leaves it 0.
   314		MTU int
   315	
   316		// RIListMember is the routing-instance whose `interface` LIST names
   317		// this tunnel (after the daemon step-0a name normalization), or ""
   318		// (#1884). It is NOT a bind instruction — daemon_apply step 0a owns
   319		// list binds. The tunnel manager uses it as (a) an unbind VETO so a
   320		// stanza→list move never strips the 0a bind, and (b) the
   321		// observation-fallback claim target for later unbind-on-removal.
   322		// Populated by collectAppliedTunnels; the legacy CLI path leaves "".
   323		RIListMember string
   324	
   325		// WireGuard (#1432 S2a). Populated only when Mode == "wireguard".
   326		// Minimal generic surface (the #1703 "generic stanza") — not the
   327		// full Junos wireguard grammar (S6). The engine keys encap on
   328		// WgPeerPubkeyHex, NOT AllowedIPs LPM (cryptokey-routing safety).
   329		WgListenPort      uint16   // local UDP listen port for inbound WG
   330		WgLocalPrivkeyHex string   // local static X25519 private key (hex, 64 chars)
   331		WgPeerPubkeyHex   string   // peer static X25519 public key (hex)
   332		WgAllowedIPs      []string // peer AllowedIPs (CIDR); decap inner-src gate only
   333		WgEndpoint        string   // optional peer endpoint IP:port (initiator role)
   334		WgKeepaliveSecs   uint16   // optional persistent-keepalive seconds (0 = off)
   335	}
   336	
   337	// String redacts WgLocalPrivkeyHex so a `%v`/`%s`/slog format of a
   338	// TunnelConfig never leaks the WireGuard private key (#1432 S2a privkey
   339	// hygiene, AGY M2). The Rust side already zeroizes + redacts its copy;
   340	// this closes the Go-side cleartext-log exposure.
   341	func (tc *TunnelConfig) String() string {
   342		if tc == nil {
   343			return "<nil>"
   344		}
   345		priv := "<unset>"
   346		if tc.WgLocalPrivkeyHex != "" {
   347			priv = "<redacted>"
   348		}
   349		return fmt.Sprintf("TunnelConfig{Name:%s Mode:%s Source:%s Destination:%s "+
   350			"WgListenPort:%d WgLocalPrivkeyHex:%s WgPeerPubkeyHex:%s "+
   351			"WgAllowedIPs:%v WgEndpoint:%s WgKeepaliveSecs:%d}",
   352			tc.Name, tc.Mode, tc.Source, tc.Destination,
   353			tc.WgListenPort, priv, tc.WgPeerPubkeyHex,
   354			tc.WgAllowedIPs, tc.WgEndpoint, tc.WgKeepaliveSecs)
   355	}
   356	
   357	// RoutingInstanceConfig represents a VRF-based routing instance.
   358	type RoutingInstanceConfig struct {
   359		Name                      string
   360		Description               string

exec
/bin/bash -lc "nl -ba docs/research/1919-wg-addr-route-prune/plan.md | sed -n '260,520p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   260	## 5. Detailed implementation sketch (Path A)
   261	
   262	State (add to `tunnelManager`):
   263	```go
   264	// wgConfigured: WG tunnel names configured at the LAST Apply (plus
   265	// names whose address prune left residual tracked addrs, retained for
   266	// retry). NEVER feeds the LinkDel removal loop — WG links persist
   267	// (#1432 S2a). Drives the WG address-prune-on-removal diff (#1919).
   268	wgConfigured map[string]bool
   269	```
   270	
   271	`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
   272	
   273	`Apply`:
   274	```go
   275	wgDesired := map[string]bool{}
   276	for _, tc := range tunnels {
   277	    if tc.Mode == "wireguard" { wgDesired[tc.Name] = true }
   278	}
   279	oldWG := t.wgConfigured
   280	nextWG := map[string]bool{}
   281	for n := range wgDesired { nextWG[n] = true }
   282	// prune phase
   283	for name := range oldWG {
   284	    if wgDesired[name] { continue }
   285	    if link, err := t.ops.LinkByName(name); err == nil {
   286	        remaining := t.reconcileLinkAddrsLocked(link, name, nil,
   287	            t.appliedAddrs[name], "wireguard tun")
   288	        if len(remaining) > 0 {
   289	            t.appliedAddrs[name] = remaining
   290	            nextWG[name] = true // AddrDel failed → retry next apply
   291	            continue
   292	        }
   293	    }
   294	    delete(t.appliedAddrs, name)
   295	}
   296	// ... existing GRE removal loop unchanged ...
   297	// ... per-tunnel apply loop unchanged (still-configured WG re-tracked) ...
   298	t.wgConfigured = nextWG
   299	```
   300	
   301	Note: `nextWG` is rebuilt from `wgDesired` at entry; the per-tunnel loop
   302	already re-applies still-configured WG (no change there). The prune loop
   303	runs against `oldWG` so it sees exactly the names that disappeared.
   304	
   305	`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
   306	ClearTunnels still does not delete WG links (unchanged) — but on a full
   307	clear the operator intent is teardown; whether ClearTunnels should now
   308	also flush WG addresses is a **secondary decision** (§7 open question).
   309	Default: leave ClearTunnels behavior unchanged (it never managed WG
   310	addresses before); only reset the tracking map so a post-Clear Apply
   311	re-adopts cleanly.
   312	
   313	Idempotency proof: after the prune commit, `oldWG` (next round) no longer
   314	contains the removed name (we set `t.wgConfigured = nextWG` which only
   315	carries retained-for-retry names). A clean prune drops the name entirely
   316	→ next `Apply` sees it in neither `oldWG` nor `wgDesired` → no-op. A
   317	failed-AddrDel prune keeps it in `nextWG` → retried until clean. ✔
   318	
   319	---
   320	
   321	## 6. Tests (new, in `tunnel_reconcile_test.go`)
   322	
   323	Using the existing fake `linkOps` harness:
   324	
   325	1. **`TestWireguardRemovedFromConfigPrunesAddresses`**: Apply with a WG
   326	   tunnel carrying `172.16.0.1/30` (+ optional fe80 configured) → assert
   327	   AddrAdd called. Apply again with empty tunnel list → assert
   328	   (a) link is NOT deleted (no LinkDel for wgN), (b) AddrDel called for
   329	   `172.16.0.1/30`, (c) configured fe80 deleted, kernel autoconf fe80
   330	   untouched (reuse the link-local gate test fixtures at :349-435).
   331	3. **`TestWireguardRemovalPruneIdempotent`**: third Apply (still empty)
   332	   → assert NO further AddrDel / LinkByName churn for the pruned name
   333	   (name dropped from tracking).
   334	4. **`TestWireguardRemovalAddrDelFailureRetried`**: fake AddrDel returns
   335	   error on first removal Apply → assert name retained, second removal
   336	   Apply retries AddrDel.
   337	5. **`TestWireguardRemovalDeviceAlreadyGone`**: LinkByName returns
   338	   not-found on removal → assert no panic, tracking dropped, no-op next.
   339	6. **`TestWireguardReAddAfterRemovalTracksFresh`**: add → remove (prune)
   340	   → re-add same name with a NEW address → assert new addr applied and
   341	   old addr not re-leaked (appliedAddrs correctly reset/repopulated).
   342	7. **Regression guard**: existing `TestWireguardConfiguredLinkLocalRemoved`
   343	   and friends must still pass (still-configured reconcile unchanged).
   344	
   345	All tests assert via the fake's recorded `AddrAdd`/`AddrDel`/`LinkDel`
   346	call logs. No live netlink.
   347	
   348	---
   349	
   350	## 7. Open questions / decisions for reviewer
   351	
   352	1. **ClearTunnels + WG addresses**: should the explicit delete-everything
   353	   path also flush WG addresses (and/or delete the WG link)? Current
   354	   plan: NO change to ClearTunnels link behavior; only reset the new
   355	   tracking map. Rationale: ClearTunnels never managed WG before; #1434
   356	   owns teardown. Reviewer may want ClearTunnels to flush WG addresses
   357	   for symmetry — call it.
   358	2. **VRF unbind on WG removal** (§4a): A1 (addresses only) vs A2 (full
   359	   VRF-claim adoption for WG). Plan: A1, residual documented.
   360	3. **FRR routes** (§1a): plan asserts there is NO manager-owned FRR
   361	   route for WG to withdraw and closes that sub-claim by clarification.
   362	   Reviewer must produce a concrete WG→FRR-route code path to reopen it.
   363	4. **Live peer/session**: removal keeps the link AND (per current code)
   364	   the Rust wg_control thread keeps attached. Confirm intended:
   365	   pruning the inner addresses while the peer stays attached means the
   366	   device is up but unaddressed. Issue text says "keep the persistent
   367	   wgN link (and the live peer/session if that's intended — clarify)".
   368	   Plan position: keep link + peer attached (don't touch Rust); only
   369	   strip the Go-managed kernel addresses. This matches #1432 S2a's
   370	   "persistent device" intent and #1434's ownership of full teardown.
   371	
   372	---
   373	
   374	## 8. Risks & mitigations
   375	
   376	- **R1 — pruning an address still in use by a live flow**: removing a WG
   377	  tunnel from config IS the operator declaring it gone; stripping its
   378	  addresses is the intended effect. Mitigation: only addresses in
   379	  `appliedAddrs[name]` (manager-applied) are eligible; foreign/autoconf
   380	  link-local is gated out by `reconcileLinkAddrsLocked`.
   381	- **R2 — touching the wrong device** (Path B hazard): avoided by Path A
   382	  keying off the exact tracked name set, not netdev heuristics.
   383	- **R3 — retry storms on persistent AddrDel failure**: bounded by the
   384	  same retain-and-retry pattern GRE removal uses; each Apply does at
   385	  most one AddrDel attempt per residual address.
   386	- **R4 — interaction with #1918**: none (WG has no keepalive). Verified.
   387	- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
   388	  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
   389	  while the daemon was DOWN is not in `oldWG` → not pruned by this fix.
   390	  This is the **same restart-adoption limitation** the rest of the file
   391	  has (the manager only prunes what it tracked applying). Document as a
   392	  known boundary; full restart-time WG reconciliation is #1434 scope.
   393	  (A reviewer may ask for a restart-time sweep — explicitly defer.)
   394	
   395	---
   396	
   397	## 9. Validation plan
   398	
   399	- `make test` — Go unit tests (new + existing routing tests).
   400	- `go test ./pkg/routing/...` focused run.
   401	- `go vet ./pkg/routing/...`.
   402	- No smoke required for a control-plane address-reconcile change with no
   403	  dataplane/wire impact — but a manual incus check (configure WG tunnel
   404	  with an address, `ip addr show wgN`, remove from config + commit,
   405	  confirm address gone and link still present) is the acceptance demo
   406	  for the PR description. (Optional at `/engineer` time.)
   407	
   408	---
   409	
   410	## 10. Module-doc updates (part of the contract)
   411	
   412	- Update the `applyWireguardTunLocked` doc comment (`tunnel.go:784-797`)
   413	  to remove/replace the "leaks until ip link del or daemon restart"
   414	  S2a-limitation note (AGY M1) — it is now resolved for the
   415	  config-removal-while-running case; restate the remaining boundaries
   416	  (restart-time removal, VRF residual, link+peer kept).
   417	- Update any `docs/` tunnel/wireguard module doc that states the leak as
   418	  a known limitation. Grep `docs/` for "S2a", "wireguard", "AGY M1",
   419	  "leak" during `/engineer`; if none reference it, say so in review notes.
   420	- PR body: explicitly scope the "FRR routes" claim per §1a (clarified,
   421	  not code-fixed) so the issue's title is fully addressed.
   422	
   423	---
   424	
   425	## 11. Reviewer ledger
   426	
   427	See `reviewer-ids.md` for Codex / AGY task IDs per round. Convergence
   428	target: all three (Claude SMR + Codex + AGY) PLAN-READY on the final rev.
   429	
   430	---
   431	
   432	## Appendix — verbatim key code
   433	
   434	`Apply` WG exclusion (`tunnel.go:168-175`):
   435	```go
   436	desired := make(map[string]bool, len(tunnels))
   437	for _, tc := range tunnels {
   438	    if tc.Mode != "wireguard" {
   439	        desired[tc.Name] = true
   440	    }
   441	}
   442	```
   443	
   444	WG apply branch (`tunnel.go:208-219`):
   445	```go
   446	for _, tc := range tunnels {
   447	    if tc.Mode == "wireguard" {
   448	        if err := t.applyWireguardTunLocked(tc); err != nil {
   449	            slog.Warn("failed to apply wireguard tunnel", "name", tc.Name, "err", err)
   450	        }
   451	        continue
   452	    }
   453	    ...
   454	}
   455	```
   456	
   457	WG address reconcile (the asset we reuse on removal) (`tunnel.go:880-881`):
   458	```go
   459	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
   460	    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
   461	```
   462	
   463	Known-limitation comment to update (`tunnel.go:790-794`):
   464	```go
   465	// Known S2a limitation (AGY M1): because the device is untracked, a WG
   466	// tunnel REMOVED from the config is not torn down by clearLocked and
   467	// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
   468	// accepts this in exchange for reload stability; multi-instance teardown
   469	// is owned by the S6 grammar work (#1434).
   470	```

exec
/bin/bash -lc "nl -ba pkg/frr/manager.go | sed -n '450,560p'; nl -ba pkg/daemon/daemon_ipmon.go | sed -n '70,170p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   450		defer m.reloadMu.Unlock()
   451		// Re-arm guard (Codex code-r1 H1, runs BEFORE the unlock above by
   452		// LIFO order): the pre-cancel assumed this commit supersedes the
   453		// degraded state, but a failed write (early return below) or a
   454		// hard reload failure leaves degraded=true with the old episode
   455		// already cancelled — without this, stale-config removal would
   456		// never retry until the next commit or restart. ensureRetryLocked
   457		// is idempotent against the episode the degraded outcome itself
   458		// may have just scheduled.
   459		defer func() {
   460			if m.degraded.Load() {
   461				m.ensureRetryLocked(false)
   462			}
   463		}()
   464	
   465		if err := m.writeManagedSection(section); err != nil {
   466			return err
   467		}
   468		m.confGen++
   469		slog.Info("FRR config written", "path", m.frrConf, "generation", m.confGen)
   470	
   471		err := m.reloadLocked()
   472		m.noteReloadOutcomeLocked(err)
   473		if err != nil && !errors.Is(err, ErrFRRReloadDegraded) {
   474			slog.Warn("FRR reload failed", "err", err)
   475		}
   476		return err
   477	}
   478	
   479	// Clear removes the xpf managed section from frr.conf and reloads FRR.
   480	// Unlike the historical version it PROPAGATES the reload outcome
   481	// (including ErrFRRReloadDegraded) instead of discarding it — `xpfd
   482	// cleanup` logs it loudly while still exiting 0 (#1880).
   483	func (m *Manager) Clear() error {
   484		return m.commitManagedSection("")
   485	}
   486	
   487	// writeManagedSection replaces the xpf-managed section in frr.conf.
   488	// If section is empty, the managed block is removed entirely.
   489	func (m *Manager) writeManagedSection(section string) error {
   490		existing, err := os.ReadFile(m.frrConf)
   491		if err != nil {
   492			if os.IsNotExist(err) {
   493				existing = []byte("log syslog informational\n")
   494			} else {
   495				return fmt.Errorf("read frr.conf: %w", err)
   496			}
   497		}
   498	
   499		// Strip existing managed section.
   500		//
   501		// A correct file has a begin marker followed by an end marker. But a
   502		// prior torn write (os.WriteFile is not atomic — a crash or disk-full
   503		// mid-write can truncate after the begin marker) can leave an orphaned
   504		// markerBegin with no markerEnd. If we only stripped on the both-found
   505		// case, the orphan would survive: we would append a second managed block,
   506		// leaving two begin markers. The next write's strings.Index(markerEnd)
   507		// then matches the new block's end while content[:start] cuts from the
   508		// orphaned begin — deleting everything between them, which may include
   509		// unrelated FRR config the operator appended. So we treat a begin with no
   510		// end as a corrupt tail and discard it to EOF.
   511		content := string(existing)
   512		if start := strings.Index(content, markerBegin); start >= 0 {
   513			if end := strings.Index(content, markerEnd); end >= 0 {
   514				end += len(markerEnd)
   515				// Also consume the trailing newline
   516				if end < len(content) && content[end] == '\n' {
   517					end++
   518				}
   519				content = content[:start] + content[end:]
   520			} else {
   521				// Orphaned begin marker (torn write): discard from the begin
   522				// marker to EOF. Whatever followed an unterminated managed block
   523				// is xpf-generated partial config that must not be preserved, and
   524				// keeping the orphan begin would cause the next write to over-cut.
   525				content = content[:start]
   526			}
   527		}
   528	
   529		// Append new managed section
   530		if section != "" {
   531			content = strings.TrimRight(content, "\n") + "\n"
   532			content += markerBegin + "\n"
   533			content += section
   534			content += markerEnd + "\n"
   535		}
   536	
   537		// Write atomically: a temp file in the same directory followed by rename,
   538		// so a crash or disk-full can never leave frr.conf half-written (which is
   539		// what creates the orphaned-begin-marker state handled above in the first
   540		// place). rename(2) within a filesystem is atomic.
   541		if err := atomicWriteFile(m.frrConf, []byte(content), 0644); err != nil {
   542			return fmt.Errorf("write frr.conf: %w", err)
   543		}
   544		return nil
   545	}
   546	
   547	// atomicWriteFile durably replaces path via pkg/fsatomic (#1894,
   548	// DurableState class: frr.conf carries operator content outside the
   549	// managed section, so losing it to a power cut is data loss — and a
   550	// half-written file is what creates the orphaned-begin-marker state
   551	// handled in writeManagedSection).
   552	//
   553	// The two options reproduce this function's pre-#1894 semantics
   554	// verbatim (they were lifted from here, see pkg/fsatomic):
   555	//   - WithPreserveExisting: an existing target's mode/ownership is
   556	//     reapplied on the temp fd (fchmod/fchown before rename, no
   557	//     path race; chown only when the owner differs, failure surfaced),
   558	//     falling back to perm for a new file.
   559	//   - WithResolveSymlinks: a symlinked frr.conf is resolved and
   560	//     replaced at its target, preserving the operator's symlink.
    70	// set, so entries whose policy was removed or whose preferred-route
    71	// spec was edited must be dropped here — otherwise the commit would
    72	// republish the stale overlay to FRR and the snapshot until the
    73	// delayed actuator caught up. Unrelated commits (policy spec
    74	// unchanged) keep the active overlay intact (AGY r2-2).
    75	func (d *Daemon) commitOverlayForConfig(cfg *config.Config) []config.RouteOverlayEntry {
    76		if cfg == nil {
    77			return nil
    78		}
    79		return ipmon.FilterOverlayForConfig(d.ipmonActiveOverlay(), cfg.Services.IPMonitoring)
    80	}
    81	
    82	// assembleFRRConfig builds the complete frr.FullConfig for the given
    83	// compiled config plus the ip-monitoring overlay. It is the sole
    84	// constructor for BOTH the full apply path and the routes-only
    85	// actuator (the complete contract: static routes, generate-routes,
    86	// DHCP routes, policy export, backup-router, interface hints, RethMap,
    87	// IPv6 next-hop interfaces, ClusterMode, per-VRF instances, and the
    88	// overlay's PreferredRoutes).
    89	func (d *Daemon) assembleFRRConfig(cfg *config.Config, overlay []config.RouteOverlayEntry) *frr.FullConfig {
    90		// Collect interface bandwidths and point-to-point flags for FRR.
    91		ifaceBandwidths := make(map[string]uint64)
    92		ifaceP2P := make(map[string]bool)
    93		for name, ifc := range cfg.Interfaces.Interfaces {
    94			linuxName := config.LinuxIfName(name)
    95			if ifc.Bandwidth > 0 {
    96				ifaceBandwidths[linuxName] = ifc.Bandwidth
    97			}
    98			for _, unit := range ifc.Units {
    99				if unit.PointToPoint {
   100					ifaceP2P[linuxName] = true
   101				}
   102			}
   103		}
   104	
   105		fc := &frr.FullConfig{
   106			OSPF:                  cfg.Protocols.OSPF,
   107			OSPFv3:                cfg.Protocols.OSPFv3,
   108			BGP:                   cfg.Protocols.BGP,
   109			RIP:                   cfg.Protocols.RIP,
   110			ISIS:                  cfg.Protocols.ISIS,
   111			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
   112			Inet6StaticRoutes:     cfg.RoutingOptions.Inet6StaticRoutes,
   113			GenerateRoutes:        cfg.RoutingOptions.GenerateRoutes,
   114			DHCPRoutes:            d.collectDHCPRoutes(),
   115			PolicyOptions:         &cfg.PolicyOptions,
   116			ForwardingTableExport: cfg.RoutingOptions.ForwardingTableExport,
   117			BackupRouter:          cfg.System.BackupRouter,
   118			BackupRouterDst:       cfg.System.BackupRouterDst,
   119			InterfaceBandwidths:   ifaceBandwidths,
   120			InterfacePointToPoint: ifaceP2P,
   121			RethMap:               cfg.RethToPhysical(),
   122			IPv6NextHopInterfaces: inferIPv6StaticNextHopInterfaces(cfg),
   123			ClusterMode:           d.cluster != nil,
   124			PreferredRoutes:       overlay,
   125		}
   126		for _, ri := range cfg.RoutingInstances {
   127			vrfName := "vrf-" + ri.Name
   128			tableID := 0
   129			if ri.InstanceType == "forwarding" {
   130				// Forwarding instances have no VRF device; their statics
   131				// render into the instance's dedicated kernel table so the
   132				// kernel agrees with the FBF/PBR ip rules AND the userspace
   133				// dataplane's `<ri>.inet.0` snapshot table (#1827 PR-2
   134				// divergence fix — previously these leaked into the default
   135				// table).
   136				vrfName = ""
   137				tableID = ri.TableID
   138			}
   139			fc.Instances = append(fc.Instances, frr.InstanceConfig{
   140				Name:              ri.Name,
   141				VRFName:           vrfName,
   142				TableID:           tableID,
   143				OSPF:              ri.OSPF,
   144				OSPFv3:            ri.OSPFv3,
   145				BGP:               ri.BGP,
   146				RIP:               ri.RIP,
   147				ISIS:              ri.ISIS,
   148				StaticRoutes:      ri.StaticRoutes,
   149				Inet6StaticRoutes: ri.Inet6StaticRoutes,
   150			})
   151		}
   152		return fc
   153	}
   154	
   155	// applyFRRConfig applies an assembled FullConfig and handles the
   156	// shared post-ApplyFull consistent-hash sysctl. Both the full apply
   157	// path and the actuator go through here.
   158	func (d *Daemon) applyFRRConfig(fc *frr.FullConfig) {
   159		if d.frr == nil {
   160			return
   161		}
   162		// Warn-and-continue on FRR reload problems: an FRR hiccup must not
   163		// fail an otherwise-valid commit. Degraded (#1880) means the config
   164		// WAS applied additively and the manager's retry loop owns
   165		// convergence of stale-config removal; the gauge
   166		// xpf_frr_reload_degraded is 1 until it converges.
   167		if err := d.frr.ApplyFull(fc); err != nil {
   168			if errors.Is(err, frr.ErrFRRReloadDegraded) {
   169				slog.Warn("FRR reload degraded: additive vtysh -f applied; stale-config removal deferred to the in-manager retry", "err", err)
   170			} else {

codex
The key retry suspicion is real in source: `reconcileLinkAddrsLocked` only re-tracks failed stale deletes for link-local addresses. I’m checking the wider call graph now to make sure the verdict also covers FRR, VRF, restart adoption, and keepalive claims accurately.
exec
/bin/bash -lc 'rg -n "wireguard|WireGuard|WgAllowedIPs|WgKeepaliveSecs|TunnelConfig|AllowedIPs|StaticRoutes|Route|routes|route" pkg/frr pkg/routing pkg/daemon userspace-dp | head -n 240' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
userspace-dp/Cargo.toml:24:# WireGuard clean-room termination (docs/pr/wireguard-clean/plan.md):
userspace-dp/Cargo.toml:29:# WireGuard S1 (#1709): on-wire handshake framing + TAI64N. blake2 backs
pkg/daemon/daemon_ra.go:19:	for _, ra := range cfg.Protocols.RouterAdvertisement {
pkg/daemon/daemon_ra.go:84:				// RETH HA startup installs a stable router link-local on the active
pkg/frr/vtysh.go:11://   - Thin raw-output shells: GetBFDPeers, GetRouteMapList,
pkg/frr/vtysh.go:12://     GetISISAdjacencyDetail, GetISISDatabase, GetISISRoutes,
pkg/frr/vtysh.go:14://     GetOSPFRoutes, GetBGPNeighborReceivedRoutes,
pkg/frr/vtysh.go:15://     GetBGPNeighborAdvertisedRoutes, GetBGPNeighborDetail.
pkg/frr/vtysh.go:51:// frr-reload.py shell-outs route through. Production code uses
pkg/frr/vtysh.go:151:// GetRouteMapList returns the route-map configuration from FRR.
pkg/frr/vtysh.go:152:func (m *Manager) GetRouteMapList() (string, error) {
pkg/frr/vtysh.go:153:	return m.executor().Vtysh("show route-map")
pkg/frr/vtysh.go:166:// GetISISRoutes returns raw IS-IS route output.
pkg/frr/vtysh.go:167:func (m *Manager) GetISISRoutes() (string, error) {
pkg/frr/vtysh.go:168:	return m.executor().Vtysh("show isis route")
pkg/frr/vtysh.go:186:// GetOSPFRoutes returns raw OSPF route output.
pkg/frr/vtysh.go:187:func (m *Manager) GetOSPFRoutes() (string, error) {
pkg/frr/vtysh.go:188:	return m.executor().Vtysh("show ip ospf route")
pkg/frr/vtysh.go:191:// GetBGPNeighborReceivedRoutes returns received routes for a BGP neighbor.
pkg/frr/vtysh.go:192:func (m *Manager) GetBGPNeighborReceivedRoutes(ip string) (string, error) {
pkg/frr/vtysh.go:196:	return m.executor().Vtysh("show bgp neighbor " + ip + " received-routes")
pkg/frr/vtysh.go:199:// GetBGPNeighborAdvertisedRoutes returns advertised routes for a BGP neighbor.
pkg/frr/vtysh.go:200:func (m *Manager) GetBGPNeighborAdvertisedRoutes(ip string) (string, error) {
pkg/frr/vtysh.go:204:	return m.executor().Vtysh("show bgp neighbor " + ip + " advertised-routes")
pkg/routing/routing.go:1:// Package routing manages static routes, GRE/IPIP tunnels, VRFs, XFRM
pkg/routing/routing.go:2:// interfaces, policy-based / rib-group / next-table route leaking, bonds,
pkg/routing/routing.go:10://   - routeReader      (routes.go)     — kernel routing-table reads
pkg/routing/routing.go:41:	routes   *routeReader
pkg/routing/routing.go:61:	m.routes = &routeReader{ops: h}
pkg/routing/routing.go:113:// --- Route reads ---
pkg/routing/routing.go:115:// GetRoutesForTable reads routes from a specific kernel routing table.
pkg/routing/routing.go:116:func (m *Manager) GetRoutesForTable(tableID int) ([]RouteEntry, error) {
pkg/routing/routing.go:117:	return m.routes.GetRoutesForTable(tableID)
pkg/routing/routing.go:120:// GetRoutes reads the main kernel routing table.
pkg/routing/routing.go:121:func (m *Manager) GetRoutes() ([]RouteEntry, error) { return m.routes.GetRoutes() }
pkg/routing/routing.go:123:// GetVRFRoutes reads routes from a VRF's routing table by VRF device name.
pkg/routing/routing.go:124:func (m *Manager) GetVRFRoutes(vrfName string) ([]RouteEntry, error) {
pkg/routing/routing.go:125:	return m.routes.GetVRFRoutes(vrfName)
pkg/routing/routing.go:128:// GetTableRoutes returns routes for a Junos-style table name.
pkg/routing/routing.go:129:func (m *Manager) GetTableRoutes(tableName string) ([]RouteEntry, error) {
pkg/routing/routing.go:130:	return m.routes.GetTableRoutes(tableName)
pkg/routing/routing.go:133:// GetAllTableRoutes returns routes from the main table and all configured VRFs.
pkg/routing/routing.go:134:func (m *Manager) GetAllTableRoutes(instances []*config.RoutingInstanceConfig) ([]TableRoutes, error) {
pkg/routing/routing.go:135:	return m.routes.GetAllTableRoutes(instances)
pkg/routing/routing.go:143:func (m *Manager) ApplyTunnels(tunnels []*config.TunnelConfig) error {
pkg/routing/routing.go:170:// route leaking.
pkg/routing/routing.go:171:func (m *Manager) ApplyNextTableRules(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig) error {
pkg/routing/routing.go:172:	return m.nextTbl.Apply(routes, instances)
pkg/routing/routing.go:175:// ApplyRibGroupRules creates ip rules implementing rib-group route leaking.
pkg/routing/routing.go:186:// plus one pinned host route per RPM next-hop pin. It returns the
pkg/routing/routes.go:13:// RouteEntry represents a kernel routing table entry.
pkg/routing/routes.go:14:type RouteEntry struct {
pkg/routing/routes.go:22:// TableRoutes groups routes by their routing table name.
pkg/routing/routes.go:23:type TableRoutes struct {
pkg/routing/routes.go:25:	Entries []RouteEntry // routes in this table
pkg/routing/routes.go:28:// routeLister is the minimal netlink read surface the route reader
pkg/routing/routes.go:30:type routeLister interface {
pkg/routing/routes.go:31:	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
pkg/routing/routes.go:32:	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
pkg/routing/routes.go:37:// routeReader reads kernel routing tables and converts them to
pkg/routing/routes.go:38:// RouteEntry values. It is stateless apart from the borrowed netlink
pkg/routing/routes.go:40:type routeReader struct {
pkg/routing/routes.go:41:	ops routeLister
pkg/routing/routes.go:44:// GetRoutesForTable reads routes from a specific kernel routing table.
pkg/routing/routes.go:45:func (rr *routeReader) GetRoutesForTable(tableID int) ([]RouteEntry, error) {
pkg/routing/routes.go:46:	var entries []RouteEntry
pkg/routing/routes.go:49:		filter := &netlink.Route{Table: tableID}
pkg/routing/routes.go:50:		routes, err := rr.ops.RouteListFiltered(family, filter, netlink.RT_FILTER_TABLE)
pkg/routing/routes.go:54:		for _, r := range routes {
pkg/routing/routes.go:55:			entries = append(entries, rr.routeToEntry(r, family))
pkg/routing/routes.go:62:// GetRoutes reads the main kernel routing table.
pkg/routing/routes.go:63:func (rr *routeReader) GetRoutes() ([]RouteEntry, error) {
pkg/routing/routes.go:64:	var entries []RouteEntry
pkg/routing/routes.go:67:		routes, err := rr.ops.RouteList(nil, family)
pkg/routing/routes.go:71:		for _, r := range routes {
pkg/routing/routes.go:72:			entries = append(entries, rr.routeToEntry(r, family))
pkg/routing/routes.go:79:// GetVRFRoutes reads routes from a VRF's routing table by VRF device name.
pkg/routing/routes.go:80:func (rr *routeReader) GetVRFRoutes(vrfName string) ([]RouteEntry, error) {
pkg/routing/routes.go:94:	return rr.GetRoutesForTable(int(vrf.Table))
pkg/routing/routes.go:97:// GetTableRoutes returns routes for a Junos-style table name (e.g. "inet.0",
pkg/routing/routes.go:100:func (rr *routeReader) GetTableRoutes(tableName string) ([]RouteEntry, error) {
pkg/routing/routes.go:119:	var entries []RouteEntry
pkg/routing/routes.go:122:		entries, err = rr.GetRoutes()
pkg/routing/routes.go:124:		entries, err = rr.GetVRFRoutes(vrfName)
pkg/routing/routes.go:131:	var filtered []RouteEntry
pkg/routing/routes.go:141:// GetAllTableRoutes returns routes from the main table and all configured VRFs.
pkg/routing/routes.go:142:// IPv4 and IPv6 routes are split into separate inet.0/inet6.0 tables.
pkg/routing/routes.go:143:func (rr *routeReader) GetAllTableRoutes(instances []*config.RoutingInstanceConfig) ([]TableRoutes, error) {
pkg/routing/routes.go:144:	var tables []TableRoutes
pkg/routing/routes.go:147:	mainEntries, err := rr.GetRoutes()
pkg/routing/routes.go:158:		entries, err := rr.GetRoutesForTable(ri.TableID)
pkg/routing/routes.go:167:// routeToEntry converts a netlink route to a RouteEntry.
pkg/routing/routes.go:168:func (rr *routeReader) routeToEntry(r netlink.Route, family int) RouteEntry {
pkg/routing/routes.go:169:	entry := RouteEntry{
pkg/routing/routes.go:204:// rtProtoName maps a netlink route protocol to its xpf protocol name.
pkg/routing/routes.go:205:func rtProtoName(p netlink.RouteProtocol) string {
pkg/routing/routes.go:229:		return "static" // RTPROT_ZEBRA — FRR staticd-installed routes
pkg/frr/fbf_table_render_test.go:16:// dataplane filed the same routes under `<ri>.inet.0` and the FBF/PBR
pkg/frr/fbf_table_render_test.go:21:// TestGenerateStaticRouteInTable covers the new table-suffix emission.
pkg/frr/fbf_table_render_test.go:22:func TestGenerateStaticRouteInTable(t *testing.T) {
pkg/frr/fbf_table_render_test.go:26:	sr := &config.StaticRoute{
pkg/frr/fbf_table_render_test.go:30:	got := m.generateStaticRouteInTable(sr, "", 100, nil, nil)
pkg/frr/fbf_table_render_test.go:31:	if got != "ip route 0.0.0.0/0 172.16.80.1 table 100\n" {
pkg/frr/fbf_table_render_test.go:32:		t.Errorf("v4 table route = %q", got)
pkg/frr/fbf_table_render_test.go:38:	got = m.generateStaticRouteInTable(sr, "", 100, nil, nil)
pkg/frr/fbf_table_render_test.go:39:	if got != "ip route 0.0.0.0/0 172.16.80.1 5 table 100\n" {
pkg/frr/fbf_table_render_test.go:40:		t.Errorf("v4 table route with distance = %q", got)
pkg/frr/fbf_table_render_test.go:44:	sr6 := &config.StaticRoute{
pkg/frr/fbf_table_render_test.go:48:	got = m.generateStaticRouteInTable(sr6, "", 101, nil, nil)
pkg/frr/fbf_table_render_test.go:49:	if got != "ipv6 route ::/0 2001:db8:80::1 table 101\n" {
pkg/frr/fbf_table_render_test.go:50:		t.Errorf("v6 table route = %q", got)
pkg/frr/fbf_table_render_test.go:53:	// vrfName wins over tableID (virtual-router instances never emit
pkg/frr/fbf_table_render_test.go:55:	got = m.generateStaticRouteInTable(sr6, "vrf-BLUE", 101, nil, nil)
pkg/frr/fbf_table_render_test.go:56:	if got != "ipv6 route ::/0 2001:db8:80::1 vrf vrf-BLUE\n" {
pkg/frr/fbf_table_render_test.go:57:		t.Errorf("vrf route = %q", got)
pkg/frr/fbf_table_render_test.go:61:	got = m.generateStaticRouteInTable(sr6, "", 0, nil, nil)
pkg/frr/fbf_table_render_test.go:62:	if got != "ipv6 route ::/0 2001:db8:80::1\n" {
pkg/frr/fbf_table_render_test.go:63:		t.Errorf("default-table route = %q", got)
pkg/frr/fbf_table_render_test.go:66:	// Discard routes carry the table too.
pkg/frr/fbf_table_render_test.go:67:	discard := &config.StaticRoute{Destination: "10.66.0.0/16", Discard: true}
pkg/frr/fbf_table_render_test.go:68:	got = m.generateStaticRouteInTable(discard, "", 100, nil, nil)
pkg/frr/fbf_table_render_test.go:69:	if got != "ip route 10.66.0.0/16 Null0 table 100\n" {
pkg/frr/fbf_table_render_test.go:70:		t.Errorf("discard table route = %q", got)
pkg/frr/fbf_table_render_test.go:76:// keeps virtual-router instances on `vrf <name>`.
pkg/frr/fbf_table_render_test.go:84:		StaticRoutes: []*config.StaticRoute{
pkg/frr/fbf_table_render_test.go:91:				StaticRoutes: []*config.StaticRoute{
pkg/frr/fbf_table_render_test.go:94:				Inet6StaticRoutes: []*config.StaticRoute{
pkg/frr/fbf_table_render_test.go:101:				StaticRoutes: []*config.StaticRoute{
pkg/frr/fbf_table_render_test.go:117:		"ip route 0.0.0.0/0 172.16.50.1\n",           // master untouched
pkg/frr/fbf_table_render_test.go:118:		"ip route 0.0.0.0/0 172.16.80.1 table 100\n", // forwarding v4
pkg/frr/fbf_table_render_test.go:119:		"ipv6 route ::/0 2001:db8:80::1 table 100\n", // forwarding v6
pkg/frr/fbf_table_render_test.go:120:		"ip route 10.9.0.0/16 10.9.0.1 vrf vrf-BLUE", // virtual-router unchanged
pkg/frr/fbf_table_render_test.go:128:	// default-table route (the pre-PR-2 divergence/pollution).
pkg/frr/fbf_table_render_test.go:129:	if strings.Contains(got, "ip route 0.0.0.0/0 172.16.80.1\n") {
pkg/frr/fbf_table_render_test.go:134:// TestApplyFullPreferredRouteForwardingInstance: an ip-monitoring
pkg/frr/fbf_table_render_test.go:138:func TestApplyFullPreferredRouteForwardingInstance(t *testing.T) {
pkg/frr/fbf_table_render_test.go:149:				StaticRoutes: []*config.StaticRoute{
pkg/frr/fbf_table_render_test.go:154:		PreferredRoutes: []config.RouteOverlayEntry{
pkg/frr/fbf_table_render_test.go:163:	if !strings.Contains(got, "ip route 0.0.0.0/0 172.16.80.254 1 table 100\n") {
pkg/frr/fbf_table_render_test.go:164:		t.Errorf("forwarding-instance preferred route not rendered into table 100:\n%s", got)
pkg/frr/fbf_table_render_test.go:167:		t.Errorf("forwarding-instance preferred route rendered into a nonexistent VRF:\n%s", got)
pkg/daemon/daemon.go:115:	// successful route-overlay publish (#1844, Codex plan r2-1): the
pkg/daemon/daemon.go:118:	// otherwise cached flow routes stay pinned to pre-failover paths.
pkg/daemon/daemon.go:119:	// Mutated only in actuateRouteOverlayLocked under applySem.
pkg/daemon/daemon.go:200:	// Used by collectDHCPRoutes to exclude management routes from FRR.
pkg/daemon/daemon.go:211:	// blackholeRoutes tracks blackhole routes injected for inactive RG subnets.
pkg/daemon/daemon.go:212:	// When an RG goes BACKUP, we inject blackhole routes for its RETH subnets
pkg/daemon/daemon.go:213:	// to prevent FIB from routing return traffic via the default route (which
pkg/daemon/daemon.go:217:	blackholeRoutes map[int][]netlink.Route
pkg/daemon/daemon.go:271:	// sent for each inactive RG on startup. Prevents stale RA routes
pkg/daemon/daemon.go:428:		blackholeRoutes:            make(map[int][]netlink.Route),
pkg/routing/tunnel_keepalive.go:17:// bool return destroyed: a route-existence check is NOT a liveness
pkg/routing/tunnel_keepalive.go:62:// source is the tunnel's local endpoint IP (TunnelConfig.Source) bound
pkg/routing/tunnel_keepalive.go:64:// endpoint; "" → wildcard bind. dst is the underlay Destination, routed
pkg/routing/tunnel_keepalive.go:82:// the tunnel source IP (§5c). No SO_BINDTODEVICE — the probe routes in
pkg/routing/tunnel_keepalive.go:132:	// tunnel endpoint and the reply routes back to it. Empty source →
pkg/routing/tunnel_keepalive.go:171:		// Classify a write error (Codex PR #1947 r1 HIGH). A path/route
pkg/routing/tunnel_keepalive.go:172:		// problem (ENETUNREACH/EHOSTUNREACH/ENETDOWN — no route to the
pkg/routing/tunnel_keepalive.go:176:		// self-inflict a tunnel down. Route it through hold-on-unknown
pkg/routing/tunnel_keepalive.go:260:// (path/route unreachable — ENETUNREACH/EHOSTUNREACH/ENETDOWN — or an
pkg/routing/routeformat.go:10:// protoTag returns a single-letter Junos-style route protocol marker.
pkg/routing/routeformat.go:32:// FormatRouteTerse formats routes in Junos "show route terse" style.
pkg/routing/routeformat.go:33:func FormatRouteTerse(entries []RouteEntry) string {
pkg/routing/routeformat.go:52:// appendSplitAF splits routes into inet.0 and inet6.0 tables and appends them.
pkg/routing/routeformat.go:53:func appendSplitAF(tables []TableRoutes, prefix string, entries []RouteEntry) []TableRoutes {
pkg/routing/routeformat.go:54:	var v4, v6 []RouteEntry
pkg/routing/routeformat.go:69:		tables = append(tables, TableRoutes{Name: inetName, Entries: v4})
pkg/routing/routeformat.go:72:		tables = append(tables, TableRoutes{Name: inet6Name, Entries: v6})
pkg/routing/routeformat.go:77:// FormatRouteDestination formats matching routes across all tables in Junos style.
pkg/routing/routeformat.go:79:// matching route, it prints a Junos-style header and route entries.
pkg/routing/routeformat.go:81://   - "" (empty): default LPM — show routes whose prefix contains the destination
pkg/routing/routeformat.go:82://   - "exact": only show routes matching the exact prefix (network + mask)
pkg/routing/routeformat.go:83://   - "longer": show routes with a strictly more-specific prefix (longer mask)
pkg/routing/routeformat.go:84://   - "orlonger": show routes with equal or more-specific prefix (equal or longer mask)
pkg/routing/routeformat.go:85:func FormatRouteDestination(allTables []TableRoutes, destination, modifier string) string {
pkg/routing/routeformat.go:105:		var matches []RouteEntry
pkg/routing/routeformat.go:107:			_, routeNet, err := net.ParseCIDR(e.Destination)
pkg/routing/routeformat.go:111:			routeOnes, _ := routeNet.Mask.Size()
pkg/routing/routeformat.go:115:				// Route must match the exact prefix (network + mask length).
pkg/routing/routeformat.go:116:				if routeOnes == destOnes && destNet.IP.Equal(routeNet.IP) {
pkg/routing/routeformat.go:120:				// Route must be strictly more-specific (contained within dest, longer mask).
pkg/routing/routeformat.go:121:				if routeOnes > destOnes && destNet.Contains(routeNet.IP) {
pkg/routing/routeformat.go:125:				// Route must be equal or more-specific (contained within dest, equal or longer mask).
pkg/routing/routeformat.go:126:				if routeOnes >= destOnes && destNet.Contains(routeNet.IP) {
pkg/routing/routeformat.go:130:				// Default LPM behavior: show routes whose prefix contains the
pkg/routing/routeformat.go:131:				// destination. For a CIDR input, match routes that contain the
pkg/routing/routeformat.go:132:				// requested network (route prefix contains dest IP AND route mask
pkg/routing/routeformat.go:134:				if destBits > 0 && routeOnes <= destOnes && routeNet.Contains(destNet.IP) {
pkg/routing/routeformat.go:159:		return fmt.Sprintf("no routes matching %s\n", destination)
pkg/routing/routeformat.go:164:// FormatRouteSummary formats a Junos-style route summary across all tables.
pkg/routing/routeformat.go:167:func FormatRouteSummary(allTables []TableRoutes, routerID string) string {
pkg/routing/routeformat.go:169:	if routerID != "" {
pkg/routing/routeformat.go:170:		fmt.Fprintf(&buf, "Router ID: %s\n", routerID)
pkg/routing/routeformat.go:173:	totalRoutes := 0
pkg/routing/routeformat.go:183:		fmt.Fprintf(&buf, "\n%s: %d destinations, %d routes (%d active, 0 holddown, 0 hidden)\n",
pkg/routing/routeformat.go:186:		totalRoutes += len(table.Entries)
pkg/routing/routeformat.go:192:	if totalRoutes > 0 {
pkg/routing/routeformat.go:194:		fmt.Fprintf(&buf, "  %d routes, %d FIB (currently active)\n", totalRoutes, totalFIB)
pkg/routing/routeformat.go:208:		fmt.Fprintf(buf, "%21s%7d routes,%7d active\n", p+":", byProto[p], byProto[p])
pkg/routing/routeformat.go:212:// FormatAllRoutes formats all routes across all tables in Junos style.
pkg/routing/routeformat.go:213:func FormatAllRoutes(allTables []TableRoutes) string {
pkg/routing/routeformat.go:220:		sorted := make([]RouteEntry, len(table.Entries))
pkg/routing/routeformat.go:231:		return "no routes\n"
pkg/routing/routeformat.go:237:func formatTableJunos(buf *strings.Builder, tableName string, totalDests int, entries []RouteEntry) {
pkg/routing/routeformat.go:238:	fmt.Fprintf(buf, "\n%s: %d destinations, %d routes (%d active, 0 holddown, 0 hidden)\n",
pkg/routing/routeformat.go:240:	buf.WriteString("+ = Active Route, - = Last Active, * = Both\n\n")
pkg/frr/manager.go:7://     static routes, generate-routes, DHCP defaults,
pkg/frr/manager.go:8://     backup-router, cluster-mode defaults, ECMP).
pkg/frr/manager.go:15://     parseRouteJSON / FormatRouteDetail.
pkg/frr/manager.go:207://   - VRFName != "": a `virtual-router` instance backed by a kernel VRF
pkg/frr/manager.go:216:	// used by renderPreferredRoutes to resolve an overlay entry's
pkg/frr/manager.go:231:	StaticRoutes      []*config.StaticRoute
pkg/frr/manager.go:232:	Inet6StaticRoutes []*config.StaticRoute
pkg/frr/manager.go:235:// DHCPRoute represents a default route learned via DHCP.
pkg/frr/manager.go:236:type DHCPRoute struct {
pkg/frr/manager.go:249:	StaticRoutes      []*config.StaticRoute
pkg/frr/manager.go:250:	Inet6StaticRoutes []*config.StaticRoute // rib inet6.0 static routes
pkg/frr/manager.go:251:	GenerateRoutes    []*config.GenerateRoute
pkg/frr/manager.go:252:	DHCPRoutes        []DHCPRoute
pkg/frr/manager.go:259:	// BackupRouter is the fallback default gateway (system backup-router).
pkg/frr/manager.go:261:	BackupRouter    string // next-hop IP (e.g. "192.168.50.1")
pkg/frr/manager.go:262:	BackupRouterDst string // destination prefix (e.g. "192.168.0.0/16"), default "0.0.0.0/0"
pkg/frr/manager.go:273:	// Used to translate RETH interface names in static routes to kernel names.
pkg/frr/manager.go:277:	// global and per-instance static routes that omit an explicit interface.
pkg/frr/manager.go:291:	// ClusterMode adds a blackhole default route with high admin distance
pkg/frr/manager.go:293:	// WAN VIP moves to the peer, FRR withdraws the real default route
pkg/frr/manager.go:297:	// route (AD 5 or 200) always takes priority when present.
pkg/frr/manager.go:300:	// PreferredRoutes is the ip-monitoring effective-route overlay
pkg/frr/manager.go:301:	// (#1827 PR-1b): winner-resolved injected routes rendered as
pkg/frr/manager.go:305:	// the full apply path and the routes-only actuator, so an
pkg/frr/manager.go:307:	// route.
pkg/frr/manager.go:308:	PreferredRoutes []config.RouteOverlayEntry
pkg/frr/manager.go:316:// failover overlay (PreferredRoutes) from the managed section. They
pkg/frr/manager.go:321:// ApplyFull generates the complete FRR config including static routes,
pkg/frr/manager.go:322:// DHCP-learned defaults, per-VRF routes, and dynamic protocols, then
pkg/frr/manager.go:329://  1. global static routes
pkg/frr/manager.go:330://  2. generate-routes (blackhole)
pkg/frr/manager.go:331://  3. inet6 static routes
pkg/frr/manager.go:333://  5. backup-router (admin distance 250)
pkg/frr/manager.go:335://  7. ip-monitoring preferred routes (admin distance 1, #1827)

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '1040,1118p;1260,1325p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
  1040	}
  1041	
  1042	// stopAll cancels all running keepalive goroutines and waits for them
  1043	// to exit. Acquires mu.
  1044	//
  1045	// #848: draining (not just cancelling) is required because
  1046	// keepaliveLoop touches the netlink handle on bring-up/down. The
  1047	// façade Close() then closes the handle, so any in-flight tick that
  1048	// hadn't yet checked ctx.Done() would use-after-close. The done
  1049	// channel makes the drain explicit.
  1050	func (t *tunnelManager) stopAll() {
  1051		t.mu.Lock()
  1052		defer t.mu.Unlock()
  1053		t.stopAllKeepalivesLocked()
  1054	}
  1055	
  1056	// stopAllKeepalivesLocked cancels all keepalive goroutines and waits
  1057	// for them to exit. Caller MUST hold mu.
  1058	func (t *tunnelManager) stopAllKeepalivesLocked() {
  1059		runners := t.keepalives
  1060		t.keepalives = make(map[string]*keepaliveRunner)
  1061		for name, runner := range runners {
  1062			runner.cancel()
  1063			<-runner.done
  1064			slog.Debug("stopped keepalive", "tunnel", name)
  1065		}
  1066	}
  1067	
  1068	// stopKeepaliveLocked cancels, drains, and REMOVES the keepalive
  1069	// runner for one tunnel, if any. Removing the map entry matters
  1070	// (#1884 SMR2-2): a cancelled runner left behind would make
  1071	// GetKeepaliveState report a dead probe and would let the apply
  1072	// reconcile "retain" a corpse. Caller MUST hold mu.
  1073	func (t *tunnelManager) stopKeepaliveLocked(name string) {
  1074		runner, ok := t.keepalives[name]
  1075		if !ok {
  1076			return
  1077		}
  1078		runner.cancel()
  1079		<-runner.done
  1080		delete(t.keepalives, name)
  1081		slog.Debug("stopped keepalive", "tunnel", name)
  1082	}
  1083	
  1084	// startKeepalive starts a keepalive probe goroutine for a tunnel.
  1085	// source is the tunnel local endpoint IP the probe binds to (#1918
  1086	// §5c); "" → wildcard. Caller MUST hold mu.
  1087	func (t *tunnelManager) startKeepalive(tunnelName, source, remoteAddr string, interval, maxRetries int) {
  1088		// Stop existing keepalive for this tunnel if any. Drain on done
  1089		// so the replacement doesn't race the old goroutine on the handle.
  1090		t.stopKeepaliveLocked(tunnelName)
  1091	
  1092		if maxRetries <= 0 {
  1093			maxRetries = 3
  1094		}
  1095	
  1096		state := &KeepaliveState{
  1097			Up:         true,
  1098			RemoteAddr: remoteAddr,
  1099			SourceAddr: source,
  1100			Interval:   interval,
  1101			MaxRetries: maxRetries,
  1102		}
  1103	
  1104		// Capture the current generation token (#1918 §6 Axis D
  1105		// defense-in-depth). The runner reads it LOCK-FREE — it never takes
  1106		// t.mu — so an Apply blocked on the drain can never deadlock a tick.
  1107		gen := t.linkGenForLocked(tunnelName)
  1108		startGen := gen.Load()
  1109	
  1110		ctx, cancel := context.WithCancel(context.Background())
  1111		done := make(chan struct{})
  1112		t.keepalives[tunnelName] = &keepaliveRunner{
  1113			cancel:     cancel,
  1114			state:      state,
  1115			done:       done,
  1116			remote:     remoteAddr,
  1117			source:     source,
  1118			interval:   interval,
  1260			state.Up = true
  1261			state.Failures = 0
  1262			slog.Info("tunnel keepalive recovered", "tunnel", tunnelName,
  1263				"remote", state.RemoteAddr)
  1264		} else {
  1265			state.Up = false
  1266			slog.Warn("tunnel keepalive failed, marking down",
  1267				"tunnel", tunnelName, "remote", state.RemoteAddr,
  1268				"failures", state.Failures)
  1269		}
  1270		state.mu.Unlock()
  1271	}
  1272	
  1273	// nextSeq returns a fresh monotonic 16-bit sequence number for a probe
  1274	// (§5a). Wraps at 0xffff; the per-probe nonce disambiguates a wrapped
  1275	// collision. Mutates Failures-adjacent state under its own lock.
  1276	func nextSeq(state *KeepaliveState) int {
  1277		state.mu.Lock()
  1278		state.seq = (state.seq + 1) & 0xffff
  1279		s := state.seq
  1280		state.mu.Unlock()
  1281		return s
  1282	}
  1283	
  1284	// clearUnknownLocked resets the hold-on-unknown bookkeeping after a
  1285	// definitive Alive/Dead probe. Caller MUST hold state.mu.
  1286	func (s *KeepaliveState) clearUnknownLocked() {
  1287		s.Unknown = false
  1288		s.UnknownKind = UnsupportedNone
  1289		s.UnknownErrno = ""
  1290		s.unknownStreak = 0
  1291		s.warnedUnknown = false
  1292	}
  1293	
  1294	// markUnknownLocked records a ProbeUnsupported tick. Structural emits a
  1295	// one-shot Warn and holds indefinitely; transient holds but escalates to
  1296	// slog.Error after MaxRetries consecutive unknown ticks (§6 Axis C,
  1297	// transient escalation). Never changes Up or Failures. Caller MUST hold
  1298	// state.mu.
  1299	func (s *KeepaliveState) markUnknownLocked(tunnelName string, kind UnsupportedKind, errStr string) {
  1300		s.Unknown = true
  1301		s.UnknownKind = kind
  1302		s.UnknownErrno = errStr
  1303		s.unknownStreak++
  1304		switch kind {
  1305		case UnsupportedStructural:
  1306			if !s.warnedUnknown {
  1307				s.warnedUnknown = true
  1308				slog.Warn("tunnel keepalive cannot probe (ICMP unavailable); holding prior state",
  1309					"tunnel", tunnelName, "remote", s.RemoteAddr,
  1310					"hint", "set net.ipv4.ping_group_range or grant CAP_NET_RAW")
  1311			}
  1312		case UnsupportedTransient:
  1313			if s.unknownStreak >= s.MaxRetries && !s.warnedUnknown {
  1314				s.warnedUnknown = true
  1315				slog.Error("tunnel keepalive probe failing on local resource error; cannot verify peer liveness",
  1316					"tunnel", tunnelName, "remote", s.RemoteAddr,
  1317					"errno", errStr, "consecutive", s.unknownStreak)
  1318			}
  1319		}
  1320	}
  1321	
  1322	// classifyErrnoString renders a short label for the unknown kind used in
  1323	// the status string.
  1324	func classifyErrnoString(kind UnsupportedKind) string {
  1325		switch kind {

exec
/bin/bash -lc 'rg -n "startKeepalive|Keepalive|WgKeepalive|probeICMP|keepaliveLoop|applyWireguard" pkg/routing pkg/config pkg/daemon userspace-dp | head -n 220' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/tunnel_keepalive.go:71:// surfaced in KeepaliveInfo and the escalation log so the operator sees
pkg/routing/routing_test.go:894:// NOTE (#1918): the former TestProbeICMP asserted probeICMP("127.0.0.1")
pkg/routing/routing_test.go:895:// returns true (route exists) and probeICMP("not-an-ip") returns false.
pkg/routing/routing_test.go:898:// liveness check. probeICMP is deleted; the real prober (icmpProber) and
pkg/routing/routing_test.go:899:// its consumer (keepaliveLoop) are now covered by deterministic,
pkg/routing/routing_test.go:902:func TestKeepaliveState(t *testing.T) {
pkg/routing/routing_test.go:903:	state := &KeepaliveState{
pkg/routing/routing_test.go:941:func TestKeepaliveDefaults(t *testing.T) {
pkg/routing/routing_test.go:942:	// When KeepaliveRetry is 0, startKeepalive should default to 3
pkg/routing/routing_test.go:943:	// We can't call startKeepalive without a netlink handle, but we
pkg/routing/README.md:5:interfaces and exposes per-tunnel up/down state via `KeepaliveState`
pkg/routing/README.md:47:- `KeepaliveState` — `tunnel.go`. Per-tunnel probe status.
pkg/routing/README.md:118:- **Keepalives** (legacy branch only — anchors never probe): runners
pkg/routing/README.md:122:  `keepaliveLoop` is gated on `state.Up`, so re-upping would strand
pkg/routing/README.md:126:## Keepalive liveness probing (`tunnel_keepalive.go`, #1918)
pkg/routing/README.md:129:liveness check, not a route-existence check. (The pre-#1918 `probeICMP`
pkg/routing/README.md:153:  `Up` and reports `KeepaliveUp == nil` with `KeepaliveInfo = "unknown
pkg/routing/README.md:194:- Keepalive runner goroutines drain on the `done` channel before the
pkg/routing/tunnel.go:44:// KeepaliveState tracks the status of a GRE tunnel keepalive probe.
pkg/routing/tunnel.go:45:type KeepaliveState struct {
pkg/routing/tunnel.go:58:	// reports the link liveness as unknown (KeepaliveUp == nil) rather
pkg/routing/tunnel.go:80:// #848: `done` is closed by keepaliveLoop just before it returns.
pkg/routing/tunnel.go:86:	state  *KeepaliveState
pkg/routing/tunnel.go:109:// NORMALIZED keepalive parameters. KeepaliveRetry <= 0 normalizes to 3
pkg/routing/tunnel.go:115:	retries := tc.KeepaliveRetry
pkg/routing/tunnel.go:121:		r.interval == tc.Keepalive &&
pkg/routing/tunnel.go:132:	// KeepaliveUp is tri-state (#1918): non-nil true/false when liveness is
pkg/routing/tunnel.go:136:	// KeepaliveInfo: "" → not configured; "unknown (...)" → configured but
pkg/routing/tunnel.go:138:	KeepaliveUp   *bool
pkg/routing/tunnel.go:139:	KeepaliveInfo string // human-readable keepalive status
pkg/routing/tunnel.go:249:// when the existing kernel link is genuinely incompatible. Keepalive
pkg/routing/tunnel.go:281:		t.stopKeepaliveLocked(name)
pkg/routing/tunnel.go:300:		// its addresses + FRR routes every commit. applyWireguardTunLocked
pkg/routing/tunnel.go:303:			if err := t.applyWireguardTunLocked(tc); err != nil {
pkg/routing/tunnel.go:350:	t.stopKeepaliveLocked(tc.Name)
pkg/routing/tunnel.go:554:	// existed inside startKeepalive but ran AFTER the recreate. After the
pkg/routing/tunnel.go:584:		t.stopKeepaliveLocked(tc.Name)
pkg/routing/tunnel.go:606:				if tc.Keepalive > 0 {
pkg/routing/tunnel.go:607:					t.startKeepalive(tc.Name, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
pkg/routing/tunnel.go:664:	// Keepalive reconcile (#1884 A.7, LEGACY BRANCH ONLY — anchors
pkg/routing/tunnel.go:667:	// skip LinkSetUp below: keepaliveLoop's down-transition is gated
pkg/routing/tunnel.go:672:	restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
pkg/routing/tunnel.go:674:	if tc.Keepalive > 0 && hasRunner && !restartKA {
pkg/routing/tunnel.go:682:	if tc.Keepalive > 0 {
pkg/routing/tunnel.go:684:			// startKeepalive stops+drains any predecessor itself;
pkg/routing/tunnel.go:687:			t.startKeepalive(tc.Name, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
pkg/routing/tunnel.go:690:		t.stopKeepaliveLocked(tc.Name)
pkg/routing/tunnel.go:924:// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
pkg/routing/tunnel.go:938:func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
pkg/routing/tunnel.go:1046:// keepaliveLoop touches the netlink handle on bring-up/down. The
pkg/routing/tunnel.go:1053:	t.stopAllKeepalivesLocked()
pkg/routing/tunnel.go:1056:// stopAllKeepalivesLocked cancels all keepalive goroutines and waits
pkg/routing/tunnel.go:1058:func (t *tunnelManager) stopAllKeepalivesLocked() {
pkg/routing/tunnel.go:1068:// stopKeepaliveLocked cancels, drains, and REMOVES the keepalive
pkg/routing/tunnel.go:1071:// GetKeepaliveState report a dead probe and would let the apply
pkg/routing/tunnel.go:1073:func (t *tunnelManager) stopKeepaliveLocked(name string) {
pkg/routing/tunnel.go:1084:// startKeepalive starts a keepalive probe goroutine for a tunnel.
pkg/routing/tunnel.go:1087:func (t *tunnelManager) startKeepalive(tunnelName, source, remoteAddr string, interval, maxRetries int) {
pkg/routing/tunnel.go:1090:	t.stopKeepaliveLocked(tunnelName)
pkg/routing/tunnel.go:1096:	state := &KeepaliveState{
pkg/routing/tunnel.go:1125:	go t.keepaliveLoop(ctx, done, tunnelName, state, prober, gen, startGen)
pkg/routing/tunnel.go:1142:// keepaliveLoop runs periodic ICMP echo probes to the tunnel underlay
pkg/routing/tunnel.go:1159:func (t *tunnelManager) keepaliveLoop(ctx context.Context, done chan struct{}, tunnelName string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64) {
pkg/routing/tunnel.go:1175:// is the per-tick body of keepaliveLoop, extracted so tests can drive a
pkg/routing/tunnel.go:1178:func (t *tunnelManager) keepaliveTick(tunnelName string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64) {
pkg/routing/tunnel.go:1276:func nextSeq(state *KeepaliveState) int {
pkg/routing/tunnel.go:1286:func (s *KeepaliveState) clearUnknownLocked() {
pkg/routing/tunnel.go:1299:func (s *KeepaliveState) markUnknownLocked(tunnelName string, kind UnsupportedKind, errStr string) {
pkg/routing/tunnel.go:1335:// GetKeepaliveState returns the keepalive state for a tunnel, or nil
pkg/routing/tunnel.go:1339:// startKeepalive / stopAll mutations from Apply / Clear. The returned
pkg/routing/tunnel.go:1340:// *KeepaliveState pointer is safe to dereference outside the lock —
pkg/routing/tunnel.go:1343:func (t *tunnelManager) GetKeepaliveState(tunnelName string) *KeepaliveState {
pkg/routing/tunnel.go:1369:	t.stopAllKeepalivesLocked()
pkg/routing/tunnel.go:1395:	// (stopAllKeepalivesLocked above), so no live runner holds a stale
pkg/routing/tunnel.go:1445:		if ks := t.GetKeepaliveState(name); ks != nil {
pkg/routing/tunnel.go:1450:				// verify liveness. KeepaliveUp stays nil ("liveness
pkg/routing/tunnel.go:1454:				ts.KeepaliveUp = nil
pkg/routing/tunnel.go:1457:					ts.KeepaliveInfo = fmt.Sprintf(
pkg/routing/tunnel.go:1463:					ts.KeepaliveInfo = fmt.Sprintf(
pkg/routing/tunnel.go:1466:					ts.KeepaliveInfo = "unknown (ICMP probe unavailable)"
pkg/routing/tunnel.go:1470:				ts.KeepaliveUp = &up
pkg/routing/tunnel.go:1472:					ts.KeepaliveInfo = fmt.Sprintf("up (interval %ds, %d retries)",
pkg/routing/tunnel.go:1475:					ts.KeepaliveInfo = fmt.Sprintf("down (%d consecutive failures)",
pkg/routing/tunnel_reconcile_test.go:774:func TestLegacyKeepaliveRunnerRetainedAcrossApplies(t *testing.T) {
pkg/routing/tunnel_reconcile_test.go:778:	tc.Keepalive = 60
pkg/routing/tunnel_reconcile_test.go:779:	tc.KeepaliveRetry = 0 // normalizes to 3 — must not restart per apply
pkg/routing/tunnel_reconcile_test.go:799:	tc2.Keepalive = 30
pkg/routing/tunnel_reconcile_test.go:807:	// Keepalive removed ⇒ stopped and map entry deleted (SMR2-2).
pkg/routing/tunnel_reconcile_test.go:812:	if tm.GetKeepaliveState("gr-0-0-0") != nil {
pkg/routing/tunnel_reconcile_test.go:817:func TestLegacyKeepaliveDownSkipsLinkSetUp(t *testing.T) {
pkg/routing/tunnel_reconcile_test.go:821:	tc.Keepalive = 60
pkg/routing/tunnel_reconcile_test.go:829:	// Keepalive marked the tunnel down. An unrelated re-apply must NOT
pkg/routing/tunnel_reconcile_test.go:830:	// LinkSetUp the reused link: keepaliveLoop's down-transition is
pkg/routing/routing.go:153:// GetKeepaliveState returns the keepalive state for a tunnel, or nil if
pkg/routing/routing.go:155:func (m *Manager) GetKeepaliveState(tunnelName string) *KeepaliveState {
pkg/routing/routing.go:156:	return m.tunnel.GetKeepaliveState(tunnelName)
pkg/config/compiler_interfaces.go:180:							tc.Keepalive = n
pkg/config/compiler_interfaces.go:186:							tc.KeepaliveRetry = n
pkg/config/compiler_interfaces.go:274:								tc.Keepalive = n
pkg/config/compiler_interfaces.go:280:								tc.KeepaliveRetry = n
pkg/config/compiler_interfaces.go:721:					tc.WgKeepaliveSecs = uint16(n)
pkg/routing/tunnel_keepalive_test.go:132:// newKAState builds a KeepaliveState and a fresh gen token for tick
pkg/routing/tunnel_keepalive_test.go:134:func newKAState(up bool, maxRetries, interval int) (*KeepaliveState, *atomic.Uint64) {
pkg/routing/tunnel_keepalive_test.go:135:	return &KeepaliveState{
pkg/routing/tunnel_keepalive_test.go:144:func tickN(t *tunnelManager, name string, state *KeepaliveState, prober tunnelProber, gen *atomic.Uint64, startGen uint64, n int) {
pkg/routing/tunnel_keepalive_test.go:151:func TestKeepaliveAliveStaysUp(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:171:func TestKeepaliveDeadGoesDownOnce(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:204:func TestKeepaliveRecoversUpOnce(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:229:// --- §9 Unsupported(structural): never LinkSet*, KeepaliveUp nil, info "unknown" ---
pkg/routing/tunnel_keepalive_test.go:230:func TestKeepaliveStructuralUnsupportedHolds(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:252:func TestKeepaliveTransientUnsupportedEscalates(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:271:func TestKeepaliveLinkByNameErrorNoLatch(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:304:func TestKeepaliveLinkSetDownErrorRetries(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:334:func TestKeepaliveGenerationGuardDropsAction(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:354:func TestKeepaliveStatusNotBlockedByNetlink(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:360:	// Register the runner in the manager so GetKeepaliveState finds it.
pkg/routing/tunnel_keepalive_test.go:396:func TestKeepaliveSourceBindAndMatches(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:413:	same := &config.TunnelConfig{Destination: "203.0.113.1", Source: "198.51.100.1", Keepalive: 5, KeepaliveRetry: 3}
pkg/routing/tunnel_keepalive_test.go:417:	srcChanged := &config.TunnelConfig{Destination: "203.0.113.1", Source: "192.0.2.9", Keepalive: 5, KeepaliveRetry: 3}
pkg/routing/tunnel_keepalive_test.go:454:		Keepalive: 5, KeepaliveRetry: 3,
pkg/routing/tunnel_keepalive_test.go:467:// must propagate to KeepaliveInfo, not a generic label. ---
pkg/routing/tunnel_keepalive_test.go:468:func TestKeepaliveUnknownReasonSurfacedInStatus(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:495:			info = s.KeepaliveInfo
pkg/routing/tunnel_keepalive_test.go:496:			kaUp = s.KeepaliveUp
pkg/routing/tunnel_keepalive_test.go:500:		t.Fatalf("KeepaliveUp must be nil on unknown, got %v", *kaUp)
pkg/routing/tunnel_keepalive_test.go:519:		if s.Name == "gr1" && !strings.Contains(s.KeepaliveInfo, "cannot assign requested address") {
pkg/routing/tunnel_keepalive_test.go:520:			t.Fatalf("structural status must carry the reason, got %q", s.KeepaliveInfo)
pkg/routing/tunnel_keepalive_test.go:528:func TestApplyRecreateDelFailRestartsKeepalive(t *testing.T) {
pkg/routing/tunnel_keepalive_test.go:532:	// applyKernelTunnelLocked + stopKeepaliveLocked require mu in
pkg/routing/tunnel_keepalive_test.go:543:	// Seed with a pre-closed done so stopKeepaliveLocked's drain returns
pkg/routing/tunnel_keepalive_test.go:556:		Keepalive: 5, KeepaliveRetry: 3,
pkg/routing/tunnel_keepalive_test.go:566:	tm.stopKeepaliveLocked("gr0")
pkg/daemon/daemon_run.go:145:		// the dataplane snapshot, but applyWireguardTunLocked never ran,
pkg/daemon/daemon_ha_sync.go:688:			d.cluster.SetHeartbeatRestartNotifyFunc(d.sessionSync.SendLivenessKeepalive)
pkg/config/parser_routing_test.go:1807:func TestGRETunnelKeepaliveSetSyntax(t *testing.T) {
pkg/config/parser_routing_test.go:1837:	if tc.Keepalive != 10 {
pkg/config/parser_routing_test.go:1838:		t.Errorf("Keepalive = %d, want 10", tc.Keepalive)
pkg/config/parser_routing_test.go:1840:	if tc.KeepaliveRetry != 5 {
pkg/config/parser_routing_test.go:1841:		t.Errorf("KeepaliveRetry = %d, want 5", tc.KeepaliveRetry)
pkg/config/parser_routing_test.go:3300:	if tc.WgKeepaliveSecs != 25 {
pkg/config/parser_routing_test.go:3301:		t.Errorf("WgKeepaliveSecs = %d, want 25", tc.WgKeepaliveSecs)
pkg/config/schema_interfaces.go:342:		"keepalive":       {desc: "Keepalive interval", args: 1, placeholder: "<seconds>", children: nil},
pkg/config/schema_interfaces.go:343:		"keepalive-retry": {desc: "Keepalive retry count", args: 1, placeholder: "<number>", children: nil},
userspace-dp/src/afxdp/coordinator/wg_control.rs:230:    KeepaliveNoSession,
userspace-dp/src/afxdp/coordinator/wg_control.rs:405:                                    crate::afxdp::wg::timers::KeepaliveKind::Passive,
userspace-dp/src/afxdp/coordinator/wg_control.rs:586:        AttemptTrigger::KeepaliveNoSession => {
userspace-dp/src/afxdp/coordinator/wg_control.rs:701:            Some(InitiateReason::KeepaliveNoSession) => {
userspace-dp/src/afxdp/coordinator/wg_control.rs:702:                Some(AttemptTrigger::KeepaliveNoSession)
userspace-dp/src/afxdp/coordinator/wg_control.rs:736:    kind: crate::afxdp::wg::timers::KeepaliveKind,
userspace-dp/src/afxdp/coordinator/wg_control.rs:742:    use crate::afxdp::wg::timers::KeepaliveKind;
userspace-dp/src/afxdp/coordinator/wg_control.rs:749:                        KeepaliveKind::Passive => {
userspace-dp/src/afxdp/coordinator/wg_control.rs:752:                        KeepaliveKind::Persistent => {
userspace-dp/src/afxdp/coordinator/wg_control.rs:770:        // KeepaliveNoSession initiation; pace so we don't re-fire
userspace-dp/src/afxdp/coordinator/wg_control.rs:780:    kind: crate::afxdp::wg::timers::KeepaliveKind,
userspace-dp/src/afxdp/coordinator/wg_control.rs:784:        crate::afxdp::wg::timers::KeepaliveKind::Passive => {
userspace-dp/src/afxdp/coordinator/wg_control.rs:787:        crate::afxdp::wg::timers::KeepaliveKind::Persistent => {
pkg/config/types_routing.go:302:	Keepalive       int      // keepalive interval in seconds (0 = disabled)
pkg/config/types_routing.go:303:	KeepaliveRetry  int      // number of missed keepalives before declaring down (0 = default 3)
pkg/config/types_routing.go:334:	WgKeepaliveSecs   uint16   // optional persistent-keepalive seconds (0 = off)
pkg/config/types_routing.go:351:		"WgAllowedIPs:%v WgEndpoint:%s WgKeepaliveSecs:%d}",
pkg/config/types_routing.go:354:		tc.WgAllowedIPs, tc.WgEndpoint, tc.WgKeepaliveSecs)
userspace-dp/src/afxdp/wg/counters.rs:146:    /// Keepalives SENT: T6 passive (incl. the post-msg2
userspace-dp/src/afxdp/wg/timers.rs:37:pub(crate) enum KeepaliveKind {
userspace-dp/src/afxdp/wg/timers.rs:54:    KeepaliveNoSession,
userspace-dp/src/afxdp/wg/timers.rs:63:    pub(crate) send_keepalive: Option<KeepaliveKind>,
userspace-dp/src/afxdp/wg/timers.rs:277:                actions.send_keepalive = Some(KeepaliveKind::Passive);
userspace-dp/src/afxdp/wg/timers.rs:300:                    actions.send_keepalive = Some(KeepaliveKind::Persistent);
userspace-dp/src/afxdp/wg/timers.rs:302:                    actions.initiate = Some(InitiateReason::KeepaliveNoSession);
userspace-dp/src/afxdp/wg/engine.rs:741:    /// 32 bytes). Keepalives consume a tx counter and obey the same
userspace-dp/src/afxdp/wg/engine.rs:908:        // detector. Keepalives must not arm T7 — they are not data.
userspace-dp/src/afxdp/wg/engine.rs:914:            // symmetric with the decap side. Keepalives are counted by
userspace-dp/src/afxdp/wg/tests.rs:2547:    use super::super::timers::{InitiateReason, KeepaliveKind, WG_NO_DEADLINE_NS};
userspace-dp/src/afxdp/wg/tests.rs:2717:    /// Keepalive encode: 32-byte record, consumes a tx counter, does
userspace-dp/src/afxdp/wg/tests.rs:2828:        assert_eq!(a.send_keepalive, Some(KeepaliveKind::Passive));
userspace-dp/src/afxdp/wg/tests.rs:2901:            a.send_keepalive != Some(KeepaliveKind::Persistent),
userspace-dp/src/afxdp/wg/tests.rs:2912:        assert_eq!(a.send_keepalive, Some(KeepaliveKind::Persistent));
userspace-dp/src/afxdp/wg/tests.rs:2923:            Some(KeepaliveKind::Passive),
userspace-dp/src/afxdp/wg/tests.rs:2930:        assert_eq!(a.initiate, Some(InitiateReason::KeepaliveNoSession));
userspace-dp/src/afxdp/wg/tests.rs:2973:        assert_eq!(a.send_keepalive, Some(KeepaliveKind::Passive));

exec
/bin/bash -lc "rg -n \"collectAppliedTunnels|ApplyTunnels|TunnelConfig\\{|Mode:.*wireguard|WgAllowedIPs|WgEndpoint|WgPeer|wireguard\" pkg/daemon pkg/config pkg/routing cmd userspace-dp | head -n 260" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/README.md:95:  not own at the last apply (restart adoption; wireguard→gre same-name
pkg/routing/README.md:113:  `collectAppliedTunnels` with the exact step-0a name normalization)
cmd/cli/show.go:417:	case "wireguard":
cmd/cli/show.go:419:			return c.showText("wireguard-detail")
cmd/cli/show.go:421:		return c.showText("wireguard")
userspace-dp/src/protocol/snapshot.rs:340:    // See docs/pr/wireguard-clean/plan.md for the design.
userspace-dp/src/protocol/snapshot.rs:344:    /// (64 chars for 32 bytes). Empty when `mode != "wireguard"`.
userspace-dp/src/protocol/snapshot.rs:461:            mode: "wireguard".into(),
userspace-dp/src/protocol/snapshot.rs:481:        let with_key = r#"{"id":1,"mode":"wireguard","wg_local_privkey_hex":"a01010101010101010101010101010101010101010101010101010101010101a"}"#;
userspace-dp/src/protocol/snapshot.rs:494:            mode: "wireguard".into(),
pkg/routing/tunnel.go:261:		if tc.Mode != "wireguard" {
pkg/routing/tunnel.go:302:		if tc.Mode == "wireguard" {
pkg/routing/tunnel.go:304:				slog.Warn("failed to apply wireguard tunnel",
pkg/routing/tunnel.go:310:		// apply (daemon restart, wireguard→gre same-name flip, foreign
pkg/routing/tunnel.go:424://     default 1500 — repairs the wireguard→gre same-name flip, where
pkg/routing/tunnel.go:632:			// ApplyTunnels), so a wedged `ip` would block every commit.
pkg/routing/tunnel.go:914:	if tc.WgEndpoint != "" {
pkg/routing/tunnel.go:915:		if host, _, err := net.SplitHostPort(tc.WgEndpoint); err == nil {
pkg/routing/tunnel.go:954:			slog.Info("replacing non-TUN link before wireguard tun create",
pkg/routing/tunnel.go:957:				return fmt.Errorf("replace non-tun wireguard link %s: %w", tc.Name, delErr)
pkg/routing/tunnel.go:974:			return fmt.Errorf("create wireguard tun %s: %w", tc.Name, addErr)
pkg/routing/tunnel.go:984:			slog.Warn("failed to set wireguard tun mtu on create",
pkg/routing/tunnel.go:987:		slog.Info("wireguard tun created", "name", tc.Name, "mtu", mtu)
pkg/routing/tunnel.go:994:				slog.Warn("failed to update wireguard tun mtu",
pkg/routing/tunnel.go:997:				slog.Info("wireguard tun mtu updated", "name", tc.Name, "mtu", mtu)
pkg/routing/tunnel.go:1000:		slog.Debug("wireguard tun reused", "name", tc.Name)
pkg/routing/tunnel.go:1004:		slog.Warn("failed to bring up wireguard tun", "name", tc.Name, "err", err)
pkg/routing/tunnel.go:1021:		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
pkg/routing/tunnel.go:1025:			slog.Warn("failed to bind wireguard tun to VRF",
pkg/routing/tunnel_reconcile_test.go:70:	return &config.TunnelConfig{Name: name, AnchorOnly: true, Addresses: addrs}
pkg/routing/tunnel_reconcile_test.go:78:	tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}
pkg/routing/tunnel_reconcile_test.go:122:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:134:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:149:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:160:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:173:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:210:			if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:231:	both := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
pkg/routing/tunnel_reconcile_test.go:251:	both := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
pkg/routing/tunnel_reconcile_test.go:279:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:282:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.9.9.9/32")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:301:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:310:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:324:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:329:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:338:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:349:	return &config.TunnelConfig{Name: "wg0", Mode: "wireguard", Addresses: addrs}
pkg/routing/tunnel_reconcile_test.go:359:	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24", "fe80::8/64")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:369:	if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:398:		if err := tm.Apply([]*config.TunnelConfig{wgTC("10.77.0.1/24")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:413:	if err := tm.Apply([]*config.TunnelConfig{wgTC("fe80::8/64")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:418:	if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
pkg/routing/tunnel_reconcile_test.go:426:	if err := tm.Apply([]*config.TunnelConfig{wgTC()}); err != nil {
pkg/routing/tunnel_reconcile_test.go:443:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:451:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:462:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:477:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:483:	// ApplyTunnels. The veto must not strip it (r4 convergent).
pkg/routing/tunnel_reconcile_test.go:486:	if err := tm.Apply([]*config.TunnelConfig{listTC}); err != nil {
pkg/routing/tunnel_reconcile_test.go:498:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:515:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:531:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:541:	if err := tm.Apply([]*config.TunnelConfig{listTC}); err != nil {
pkg/routing/tunnel_reconcile_test.go:552:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:568:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:578:	if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
pkg/routing/tunnel_reconcile_test.go:587:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:604:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:616:	if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
pkg/routing/tunnel_reconcile_test.go:624:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:641:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:656:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:661:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:670:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:681:	return &config.TunnelConfig{Name: name, Mode: "gre", Source: src, Destination: dst}
pkg/routing/tunnel_reconcile_test.go:709:	if err := tm.Apply([]*config.TunnelConfig{legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:746:			if err := tm.Apply([]*config.TunnelConfig{tcase.tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:764:	if err := tm.Apply([]*config.TunnelConfig{legacyTC("gr-0-0-0", "192.0.2.1", "192.0.2.2")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:781:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:790:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:800:	if err := tm.Apply([]*config.TunnelConfig{tc2}); err != nil {
pkg/routing/tunnel_reconcile_test.go:809:	if err := tm.Apply([]*config.TunnelConfig{tc3}); err != nil {
pkg/routing/tunnel_reconcile_test.go:823:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:838:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:852:	tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0")}
pkg/routing/tunnel_reconcile_test.go:879:	tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}
pkg/routing/tunnel_reconcile_test.go:910:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:914:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:922:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:941:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:959:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:968:	if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
pkg/routing/tunnel_reconcile_test.go:986:	if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
pkg/routing/tunnel_reconcile_test.go:1027:	tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
pkg/config/compiler_interfaces.go:147:			tc := &TunnelConfig{
pkg/config/compiler_interfaces.go:196:				case "wireguard":
pkg/config/compiler_interfaces.go:233:				tc := &TunnelConfig{Name: linuxName, Mode: defaultMode}
pkg/config/compiler_interfaces.go:283:					case "wireguard":
pkg/config/compiler_interfaces.go:664:// `wireguard { ... }` node under a tunnel stanza (#1432 S2a). The
pkg/config/compiler_interfaces.go:668://	    mode wireguard;
pkg/config/compiler_interfaces.go:669://	    wireguard {
pkg/config/compiler_interfaces.go:681:// This is intentionally narrower than the eventual Junos wireguard
pkg/config/compiler_interfaces.go:708:				tc.WgPeerPubkeyHex = v
pkg/config/compiler_interfaces.go:712:				tc.WgAllowedIPs = append(tc.WgAllowedIPs, v)
pkg/config/compiler_interfaces.go:716:				tc.WgEndpoint = v
pkg/routing/iface_reuse_test.go:204:	tunnels := []*config.TunnelConfig{{
pkg/routing/routing.go:140:// ApplyTunnels creates GRE tunnel interfaces, brings them up, and assigns
pkg/routing/routing.go:143:func (m *Manager) ApplyTunnels(tunnels []*config.TunnelConfig) error {
pkg/routing/tunnel_keepalive_test.go:413:	same := &config.TunnelConfig{Destination: "203.0.113.1", Source: "198.51.100.1", Keepalive: 5, KeepaliveRetry: 3}
pkg/routing/tunnel_keepalive_test.go:417:	srcChanged := &config.TunnelConfig{Destination: "203.0.113.1", Source: "192.0.2.9", Keepalive: 5, KeepaliveRetry: 3}
pkg/routing/tunnel_keepalive_test.go:451:	tc := &config.TunnelConfig{
pkg/routing/tunnel_keepalive_test.go:553:	tc := &config.TunnelConfig{
pkg/config/types_test.go:203:					Tunnel: &TunnelConfig{Source: "10.0.0.1", Destination: "10.0.0.2"},
pkg/config/types_test.go:222:						0: {Number: 0, Tunnel: &TunnelConfig{Name: "gr-0-0-0", Source: "10.0.0.1"}},
pkg/config/types_test.go:223:						1: {Number: 1, Tunnel: &TunnelConfig{Name: "gr-0-0-0u1", Source: "10.0.0.3"}},
pkg/config/types_test.go:243:					50: {Number: 50, VlanID: 999, Tunnel: &TunnelConfig{Name: "gr-foo"}},
pkg/config/types_test.go:304:					Tunnel: &TunnelConfig{Source: "2001:db8::1", Destination: "2001:db8::2"},
userspace-dp/src/server/tests.rs:833:            mode: "wireguard".to_string(),
pkg/config/tunnelid.go:129:// explicit `mode wireguard` — the exact extraction the compiler uses
pkg/config/tunnelid.go:133:// is only ever gre/ipip, so wireguard is always explicit.
pkg/config/tunnelid.go:139:		if prop.Name() == "mode" && len(prop.Keys) >= 2 && prop.Keys[1] == "wireguard" {
pkg/daemon/tunnel_anchor_test.go:15:			Tunnel: &config.TunnelConfig{
pkg/daemon/tunnel_anchor_test.go:24:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:37:			Tunnel: &config.TunnelConfig{
pkg/daemon/tunnel_anchor_test.go:46:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:60:			Tunnel: &config.TunnelConfig{
pkg/daemon/tunnel_anchor_test.go:69:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:79:// and the Source!="" screen in collectAppliedTunnels must not drop it —
pkg/daemon/tunnel_anchor_test.go:87:			Tunnel: &config.TunnelConfig{
pkg/daemon/tunnel_anchor_test.go:89:				Mode:            "wireguard",
pkg/daemon/tunnel_anchor_test.go:91:				WgPeerPubkeyHex: "b0202020202020202020202020202020202020202020202020202020202020b2",
pkg/daemon/tunnel_anchor_test.go:96:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:98:		t.Fatalf("len(tunnels) = %d, want 1 (wireguard tunnel without source was dropped)", len(tunnels))
pkg/daemon/tunnel_anchor_test.go:100:	if tunnels[0].Mode != "wireguard" || tunnels[0].Name != "wg0" {
pkg/daemon/tunnel_anchor_test.go:104:	// wireguard exemption must not weaken the half-configured-GRE gate.
pkg/daemon/tunnel_anchor_test.go:106:		Tunnel: &config.TunnelConfig{Name: "gr-0-0-0", Mode: "gre"},
pkg/daemon/tunnel_anchor_test.go:108:	if got := len(collectAppliedTunnels(cfg)); got != 1 {
pkg/daemon/tunnel_anchor_test.go:113:// #1884: collectAppliedTunnels must plumb the config-desired MTU
pkg/daemon/tunnel_anchor_test.go:122:			Tunnel: &config.TunnelConfig{
pkg/daemon/tunnel_anchor_test.go:134:					Tunnel: &config.TunnelConfig{
pkg/daemon/tunnel_anchor_test.go:142:					Tunnel: &config.TunnelConfig{
pkg/daemon/tunnel_anchor_test.go:158:	tunnels := collectAppliedTunnels(cfg)
pkg/daemon/tunnel_anchor_test.go:162:	byName := map[string]*config.TunnelConfig{}
pkg/daemon/tunnel_anchor_test.go:191:// TunnelConfig.Name that ApplyTunnels actually creates. Non-tunnel
pkg/daemon/daemon_run.go:87:// the RIListMember scan in collectAppliedTunnels (#1884): the tunnel
pkg/daemon/daemon_run.go:94:// ApplyTunnels uses to create the kernel device — so a unit>0 member
pkg/daemon/daemon_run.go:116:func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
pkg/daemon/daemon_run.go:141:		// lives in WgEndpoint; the local side is just a listen port), so
pkg/daemon/daemon_run.go:144:		// this, `interfaces wgN tunnel mode wireguard` compiled and fed
pkg/daemon/daemon_run.go:151:		if ifc.Tunnel != nil && (ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard") {
userspace-dp/Cargo.toml:24:# WireGuard clean-room termination (docs/pr/wireguard-clean/plan.md):
userspace-dp/src/afxdp/mod.rs:129:// docs/pr/wireguard-clean/plan.md. Engine + tests only in this PR;
userspace-dp/src/afxdp/types/forwarding.rs:26:    /// per `mode == "wireguard"` endpoint. Shared (`Arc`) so workers
userspace-dp/src/afxdp/types/forwarding.rs:188:    // WireGuard (#1432 S2a). Populated only when mode == "wireguard".
userspace-dp/src/afxdp/types/forwarding.rs:218:                &if self.mode == "wireguard" {
pkg/daemon/daemon_apply.go:314:	// Name normalization is shared with collectAppliedTunnels'
pkg/daemon/daemon_apply.go:359:		if err := d.routing.ApplyTunnels(collectAppliedTunnels(cfg)); err != nil {
userspace-dp/src/afxdp/coordinator/mod.rs:57:        .filter(|ep| ep.mode == "wireguard")
userspace-dp/src/afxdp/coordinator/wg_control.rs:3://! One supervised aux thread per `mode == "wireguard"` tunnel endpoint,
userspace-dp/src/afxdp/coordinator/wg_control.rs:1221:                peers: vec![crate::afxdp::wg::WgPeerConfig {
pkg/config/tunnelid_test.go:44:		"set interfaces wg1408 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:45:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:63:		"set interfaces wg1408 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:64:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:88:		"set groups node1 interfaces wg1408 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:89:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:113:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:116:		"set interfaces wg341 tunnel mode wireguard",
pkg/config/tunnelid_test.go:136:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:138:		"set interfaces wg341 tunnel mode wireguard",
pkg/config/tunnelid_test.go:164:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:166:		"set interfaces wg34524 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:179:		"set interfaces wg0 unit 01 tunnel mode wireguard",
pkg/config/tunnelid_test.go:180:		"set interfaces wg341 tunnel mode wireguard",
pkg/config/tunnelid_test.go:206:		"set interfaces wg1408 unit 00 tunnel mode wireguard",
pkg/config/tunnelid_test.go:208:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:217:		"set interfaces wg1408 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:218:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:229:		"set interfaces wg1408 tunnel mode wireguard",
pkg/config/tunnelid_test.go:232:		"set interfaces wg78 unit 0 tunnel mode wireguard",
pkg/config/tunnelid_test.go:243:		"set interfaces wg0 unit 0 tunnel mode wireguard",
userspace-dp/src/afxdp/coordinator/tests.rs:2156:            mode: "wireguard".to_string(),
userspace-dp/src/afxdp/coordinator/tests.rs:2633:/// gre→wireguard (reachable because ids are name-derived) prunes the
userspace-dp/src/afxdp/coordinator/tests.rs:2636:fn gre1881_mode_flip_to_wireguard_prunes_gre_entry() {
userspace-dp/src/afxdp/coordinator/status.rs:646:    /// One row per `mode == "wireguard"` tunnel endpoint with a live
userspace-dp/src/afxdp/coordinator/status.rs:660:            .filter(|(_, ep)| ep.mode == "wireguard")
pkg/config/types_routing.go:311:	// ADOPTING an anchor it did not create (wireguard→gre same-name flip
pkg/config/types_routing.go:312:	// repair). Populated by collectAppliedTunnels; the legacy
pkg/config/types_routing.go:322:	// Populated by collectAppliedTunnels; the legacy CLI path leaves "".
pkg/config/types_routing.go:325:	// WireGuard (#1432 S2a). Populated only when Mode == "wireguard".
pkg/config/types_routing.go:327:	// full Junos wireguard grammar (S6). The engine keys encap on
pkg/config/types_routing.go:328:	// WgPeerPubkeyHex, NOT AllowedIPs LPM (cryptokey-routing safety).
pkg/config/types_routing.go:331:	WgPeerPubkeyHex   string   // peer static X25519 public key (hex)
pkg/config/types_routing.go:332:	WgAllowedIPs      []string // peer AllowedIPs (CIDR); decap inner-src gate only
pkg/config/types_routing.go:333:	WgEndpoint        string   // optional peer endpoint IP:port (initiator role)
pkg/config/types_routing.go:349:	return fmt.Sprintf("TunnelConfig{Name:%s Mode:%s Source:%s Destination:%s "+
pkg/config/types_routing.go:350:		"WgListenPort:%d WgLocalPrivkeyHex:%s WgPeerPubkeyHex:%s "+
pkg/config/types_routing.go:351:		"WgAllowedIPs:%v WgEndpoint:%s WgKeepaliveSecs:%d}",
pkg/config/types_routing.go:353:		tc.WgListenPort, priv, tc.WgPeerPubkeyHex,
pkg/config/types_routing.go:354:		tc.WgAllowedIPs, tc.WgEndpoint, tc.WgKeepaliveSecs)
pkg/config/schema.go:24://	schema_interfaces.go  interfaces (+ tunnel/wireguard constructors)
pkg/config/types.go:310:// `source` (the #1736 collectAppliedTunnels twin — the persistent wgN
pkg/config/types.go:317:			(ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard")
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:504:            if endpoint.mode != "wireguard" {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:655:        if endpoint.mode != "wireguard" {
userspace-dp/src/afxdp/coordinator/tunnel_supervision.rs:786:        if endpoint.mode != "wireguard" || !self.forwarding.wg_engines.contains_key(&id) {
pkg/config/schema_validate_interfaces_test.go:147:		name:     "wireguard-listen-port",
pkg/config/schema_validate_interfaces_test.go:149:		template: "set interfaces wg-0-0-0 tunnel wireguard listen-port %s",
pkg/config/schema_validate_interfaces_test.go:154:		name:     "wireguard-persistent-keepalive",
pkg/config/schema_validate_interfaces_test.go:156:		template: "set interfaces wg-0-0-0 tunnel wireguard peer persistent-keepalive %s",
pkg/config/schema_interfaces.go:5:// tunnel/wireguard subtree constructors it composes. The root
pkg/config/schema_interfaces.go:347:		"wireguard": wireguardSchemaNode(),
pkg/config/schema_interfaces.go:351:// wireguardSchemaNode returns the config-mode schema subtree for the
pkg/config/schema_interfaces.go:352:// `tunnel wireguard { ... }` stanza (#1432 S2a). Minimal generic
pkg/config/schema_interfaces.go:363:func wireguardSchemaNode() *schemaNode {
pkg/config/parser_routing_test.go:3076:// gate must not drop them (the #1736 collectAppliedTunnels twin). All
pkg/config/parser_routing_test.go:3080:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/parser_routing_test.go:3081:		"set interfaces wg0 tunnel wireguard listen-port 51820",
pkg/config/parser_routing_test.go:3250:// #1432 S2a: the minimal `tunnel wireguard { ... }` stanza compiles to
pkg/config/parser_routing_test.go:3254:		"set interfaces wg0 tunnel mode wireguard",
pkg/config/parser_routing_test.go:3255:		"set interfaces wg0 tunnel wireguard listen-port 51820",
pkg/config/parser_routing_test.go:3256:		"set interfaces wg0 tunnel wireguard private-key a01010101010101010101010101010101010101010101010101010101010101a",
pkg/config/parser_routing_test.go:3257:		"set interfaces wg0 tunnel wireguard peer public-key b02020202020202020202020202020202020202020202020202020202020202b",
pkg/config/parser_routing_test.go:3258:		"set interfaces wg0 tunnel wireguard peer allowed-ips 10.0.0.0/24",
pkg/config/parser_routing_test.go:3259:		"set interfaces wg0 tunnel wireguard peer allowed-ips 10.0.1.0/24",
pkg/config/parser_routing_test.go:3260:		"set interfaces wg0 tunnel wireguard peer endpoint 203.0.113.1:51820",
pkg/config/parser_routing_test.go:3261:		"set interfaces wg0 tunnel wireguard peer persistent-keepalive 25",
pkg/config/parser_routing_test.go:3282:	if tc.Mode != "wireguard" {
pkg/config/parser_routing_test.go:3283:		t.Errorf("Mode = %q, want wireguard", tc.Mode)
pkg/config/parser_routing_test.go:3291:	if tc.WgPeerPubkeyHex != "b02020202020202020202020202020202020202020202020202020202020202b" {
pkg/config/parser_routing_test.go:3292:		t.Errorf("WgPeerPubkeyHex = %q", tc.WgPeerPubkeyHex)
pkg/config/parser_routing_test.go:3294:	if len(tc.WgAllowedIPs) != 2 {
pkg/config/parser_routing_test.go:3295:		t.Errorf("WgAllowedIPs = %v, want 2 entries", tc.WgAllowedIPs)
pkg/config/parser_routing_test.go:3297:	if tc.WgEndpoint != "203.0.113.1:51820" {
pkg/config/parser_routing_test.go:3298:		t.Errorf("WgEndpoint = %q", tc.WgEndpoint)
userspace-dp/src/afxdp/frame/wg.rs:6://! `mode == "wireguard"` tunnel endpoint id directly (a route/connected
userspace-dp/src/afxdp/tunnel_tests.rs:169:        .mode = "wireguard".to_string();
userspace-dp/src/afxdp/frame/mod.rs:273:            Some("wireguard") => wg::wg_encap_frame(&out, meta, decision, forwarding),
userspace-dp/src/afxdp/forwarding_build/wg.rs:2://! S2a). Builds one `Arc<WgEngine>` per `mode == "wireguard"` tunnel
userspace-dp/src/afxdp/forwarding_build/wg.rs:33:use super::super::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
userspace-dp/src/afxdp/forwarding_build/wg.rs:45:        if endpoint.mode != "wireguard" {
userspace-dp/src/afxdp/forwarding_build/wg.rs:48:        let peer = WgPeerConfig {
userspace-dp/src/afxdp/forwarding_build/mod.rs:146:    // #1432 S2a: instantiate one WgEngine per mode=="wireguard" endpoint,
userspace-dp/src/afxdp/wg/timers.rs:284:        // authenticated traversal in EITHER direction (wireguard-go
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:20:        let is_wireguard = endpoint.mode == "wireguard";
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:26:        let (source, destination) = if is_wireguard {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:61:        if is_wireguard {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:105:        if is_wireguard {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:142:/// "wireguard", listen_port must be nonzero, both keys must decode.
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:153:    if row.mode != "wireguard" {
userspace-dp/src/afxdp/wg/session.rs:404:    fn reject_after_messages_constant_matches_wireguard_spec() {
userspace-dp/src/afxdp/wg/session.rs:410:    fn timer_constants_match_wireguard_spec() {
userspace-dp/src/afxdp/wg/peer.rs:53:    /// the dead-peer detector — matching wireguard-go, where all
userspace-dp/src/afxdp/wg/handshake.rs:6://! to what kernel WireGuard / wireguard-go / UniFi put on the wire:
userspace-dp/src/afxdp/wg/handshake.rs:99:    /// wireguard-go reject `len != MessageInitiationSize` / `MessageResponseSize`
userspace-dp/src/afxdp/wg/handshake.rs:212:    // (kernel WG / wireguard-go reject any other length).
userspace-dp/src/afxdp/wg/handshake.rs:218:    // reserved bytes = 0. wireguard-go / kernel WG read the full u32 and
userspace-dp/src/afxdp/wg/mod.rs:2://! dataplane. See `docs/pr/wireguard-clean/plan.md` for the design
userspace-dp/src/afxdp/wg/mod.rs:80:    WgEngineConfig, WgPeerConfig,
userspace-dp/src/afxdp/wg/mod.rs:132:/// initial transcript hash matches the kernel WireGuard / wireguard-go

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/forwarding_build/wg.rs | sed -n '1,100p'; nl -ba userspace-dp/src/afxdp/forwarding_build/tunnels.rs | sed -n '1,125p'; nl -ba userspace-dp/src/protocol/snapshot.rs | sed -n '330,380p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	//! WireGuard engine instantiation for `build_forwarding_state` (#1432
     2	//! S2a). Builds one `Arc<WgEngine>` per `mode == "wireguard"` tunnel
     3	//! endpoint and stores it in `ForwardingState.wg_engines`, keyed by
     4	//! tunnel_endpoint_id.
     5	//!
     6	//! ## Reload stability (plan §4.2)
     7	//!
     8	//! A fresh `WgEngine` per commit resets its `Tai64nClock` and drops all
     9	//! live transport sessions. A kernel WG peer rejects any handshake whose
    10	//! TAI64N is `<=` the last it accepted, so naively rebuilding the engine
    11	//! on every reload causes a re-handshake storm and can permanently
    12	//! black-hole a tunnel.
    13	//!
    14	//! Two cases, both driven off the `previous` `ForwardingState`:
    15	//!
    16	//!   - **Identity unchanged** — if the previous state holds an engine for
    17	//!     the same endpoint and the WG identity tuple (listen_port,
    18	//!     local_privkey, peer_pubkey, allowed_ips, endpoint, keepalive) is
    19	//!     byte-for-byte unchanged, **clone the existing `Arc<WgEngine>` and
    20	//!     do NOT call `reconcile_peers`.** Workers across the reload window
    21	//!     still hold the old `ForwardingState` Arc (and thus the same engine
    22	//!     Arc); mutating shared engine state here would be observed by those
    23	//!     workers. Cloning the Arc keeps the TAI64N clock and live sessions
    24	//!     and avoids any cross-reload engine mutation.
    25	//!
    26	//!   - **Identity changed (or new)** — construct a fresh `WgEngine` (which
    27	//!     reconciles the new peer set at construction) and **seed its TAI64N
    28	//!     high-water from the prior engine** so initiator-timestamp
    29	//!     monotonicity survives the rebuild. Live sessions are dropped (a
    30	//!     real config change re-handshakes once, seeded so the peer accepts
    31	//!     it); S5 adds session migration if needed.
    32	
    33	use super::super::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
    34	use super::super::*;
    35	use std::sync::Arc;
    36	
    37	pub(super) fn populate_wg_engines(
    38	    state: &mut ForwardingState,
    39	    previous: Option<&ForwardingState>,
    40	) {
    41	    if !state.has_wg_tunnels {
    42	        return;
    43	    }
    44	    for (&id, endpoint) in state.tunnel_endpoints.iter() {
    45	        if endpoint.mode != "wireguard" {
    46	            continue;
    47	        }
    48	        let peer = WgPeerConfig {
    49	            pubkey: endpoint.wg_peer_pubkey,
    50	            endpoint: endpoint.wg_endpoint,
    51	            persistent_keepalive: endpoint.wg_keepalive_secs,
    52	            allowed_ips: endpoint.wg_allowed_ips.clone(),
    53	        };
    54	        // Identity-stable reuse: same endpoint id with an unchanged WG
    55	        // identity tuple reuses the prior engine Arc verbatim.
    56	        if let Some(prev_state) = previous {
    57	            if let (Some(prev_engine), Some(prev_endpoint)) = (
    58	                prev_state.wg_engines.get(&id),
    59	                prev_state.tunnel_endpoints.get(&id),
    60	            ) {
    61	                if wg_identity_unchanged(prev_endpoint, endpoint) {
    62	                    state.wg_engines.insert(id, prev_engine.clone());
    63	                    continue;
    64	                }
    65	            }
    66	        }
    67	        // Config changed or new: fresh engine, seeded from the prior
    68	        // engine's TAI64N high-water (if any) so monotonicity survives.
    69	        let engine = WgEngine::new(WgEngineConfig {
    70	            local_private_key: *endpoint.wg_local_privkey,
    71	            listen_port: endpoint.wg_listen_port,
    72	            peers: vec![peer],
    73	        });
    74	        if let Some(prev_state) = previous {
    75	            if let Some(prev_engine) = prev_state.wg_engines.get(&id) {
    76	                if let Some(hw) = prev_engine.tai64n_high_water() {
    77	                    engine.seed_tai64n_high_water(hw);
    78	                }
    79	            }
    80	        }
    81	        state.wg_engines.insert(id, Arc::new(engine));
    82	    }
    83	}
    84	
    85	/// Whether two WG endpoints have a byte-identical WG identity tuple, so
    86	/// the engine Arc can be reused across a reload without `reconcile_peers`.
    87	fn wg_identity_unchanged(prev: &TunnelEndpoint, next: &TunnelEndpoint) -> bool {
    88	    prev.wg_listen_port == next.wg_listen_port
    89	        && *prev.wg_local_privkey == *next.wg_local_privkey
    90	        && prev.wg_peer_pubkey == next.wg_peer_pubkey
    91	        && prev.wg_allowed_ips == next.wg_allowed_ips
    92	        && prev.wg_endpoint == next.wg_endpoint
    93	        && prev.wg_keepalive_secs == next.wg_keepalive_secs
    94	}
     1	//! Tunnel-endpoint population for `build_forwarding_state`.
     2	//!
     3	//! Populates `state.tunnel_endpoints` and
     4	//! `state.tunnel_endpoint_by_ifindex`. Must run before the
     5	//! interfaces addresses pass, which reads
     6	//! `tunnel_endpoint_by_ifindex` when building
     7	//! `ConnectedRouteV4/V6.tunnel_endpoint_id`.
     8	
     9	use super::super::*;
    10	use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    11	
    12	pub(super) fn populate_tunnel_endpoints(
    13	    snapshot: &ConfigSnapshot,
    14	    state: &mut ForwardingState,
    15	) {
    16	    for endpoint in &snapshot.tunnel_endpoints {
    17	        if endpoint.id == 0 || endpoint.ifindex <= 0 {
    18	            continue;
    19	        }
    20	        let is_wireguard = endpoint.mode == "wireguard";
    21	        // GRE/IPIP require concrete outer source/destination. WireGuard
    22	        // carries the peer in `wg_endpoint` and may have neither
    23	        // (responder-only), so skip the parse-or-drop gate for WG and
    24	        // default the unused outer source/destination to an unspecified
    25	        // address (#1432 S2a).
    26	        let (source, destination) = if is_wireguard {
    27	            (
    28	                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    29	                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    30	            )
    31	        } else {
    32	            let Ok(source) = endpoint.source.parse::<IpAddr>() else {
    33	                continue;
    34	            };
    35	            let Ok(destination) = endpoint.destination.parse::<IpAddr>() else {
    36	                continue;
    37	            };
    38	            (source, destination)
    39	        };
    40	        let outer_family = match (endpoint.outer_family.as_str(), destination) {
    41	            ("inet6", _) => libc::AF_INET6,
    42	            ("inet", _) => libc::AF_INET,
    43	            (_, IpAddr::V6(_)) => libc::AF_INET6,
    44	            _ => libc::AF_INET,
    45	        };
    46	        let transport_table =
    47	            canonical_route_table(&endpoint.transport_table, outer_family == libc::AF_INET6);
    48	
    49	        // WireGuard field hydration (#1432 S2a). On any malformed key the
    50	        // endpoint is dropped — a WG tunnel with a bad local privkey or
    51	        // peer pubkey cannot function and must not silently install a
    52	        // half-configured engine. The hydration gates live in
    53	        // `hydrate_wg_identity` (#1866) so the coordinator's
    54	        // tombstone-respawn coherence check and the defer-branch prune
    55	        // can never drift from this path's semantics.
    56	        let mut wg_local_privkey = zeroize::Zeroizing::new([0u8; 32]);
    57	        let mut wg_peer_pubkey = [0u8; 32];
    58	        let mut wg_allowed_ips: Vec<ipnet::IpNet> = Vec::new();
    59	        let mut wg_endpoint: Option<SocketAddr> = None;
    60	        let mut wg_keepalive_secs = endpoint.wg_keepalive_secs;
    61	        if is_wireguard {
    62	            let Some(identity) = hydrate_wg_identity(endpoint) else {
    63	                continue;
    64	            };
    65	            wg_local_privkey = identity.local_privkey;
    66	            wg_peer_pubkey = identity.peer_pubkey;
    67	            wg_allowed_ips = identity.allowed_ips;
    68	            wg_endpoint = identity.endpoint;
    69	            wg_keepalive_secs = identity.keepalive_secs;
    70	        }
    71	
    72	        state.tunnel_endpoints.insert(
    73	            endpoint.id,
    74	            TunnelEndpoint {
    75	                id: endpoint.id,
    76	                logical_ifindex: endpoint.ifindex,
    77	                // #1865: attachment label for the telemetry-row name
    78	                // fallback (linux_name, else logical name — mirrors
    79	                // wg_tombstone_respawn_coherent's row_label).
    80	                interface_label: if endpoint.linux_name.is_empty() {
    81	                    endpoint.interface.clone()
    82	                } else {
    83	                    endpoint.linux_name.clone()
    84	                },
    85	                interface: endpoint.interface.clone(),
    86	                redundancy_group: endpoint.redundancy_group,
    87	                mode: endpoint.mode.clone(),
    88	                outer_family,
    89	                source,
    90	                destination,
    91	                key: endpoint.key,
    92	                ttl: endpoint.ttl.max(0) as u8,
    93	                transport_table,
    94	                wg_listen_port: endpoint.wg_listen_port,
    95	                wg_local_privkey,
    96	                wg_peer_pubkey,
    97	                wg_allowed_ips,
    98	                wg_endpoint,
    99	                wg_keepalive_secs,
   100	            },
   101	        );
   102	        state
   103	            .tunnel_endpoint_by_ifindex
   104	            .insert(endpoint.ifindex, endpoint.id);
   105	        if is_wireguard {
   106	            state.has_wg_tunnels = true;
   107	        }
   108	    }
   109	}
   110	
   111	/// #1866: the hydratable WG identity of one tunnel-endpoint snapshot
   112	/// row — the exact field set `wg_identity_unchanged`
   113	/// (`forwarding_build/wg.rs`) keys engine reuse on, hydrated with the
   114	/// exact gates `populate_tunnel_endpoints` applies. Single source of
   115	/// truth shared by the populate pass, the coordinator's
   116	/// tombstone-respawn coherence check, and the defer-branch prune.
   117	pub(in crate::afxdp) struct WgRowIdentity {
   118	    pub(in crate::afxdp) local_privkey: zeroize::Zeroizing<[u8; 32]>,
   119	    pub(in crate::afxdp) peer_pubkey: [u8; 32],
   120	    pub(in crate::afxdp) allowed_ips: Vec<ipnet::IpNet>,
   121	    pub(in crate::afxdp) endpoint: Option<SocketAddr>,
   122	    pub(in crate::afxdp) listen_port: u16,
   123	    pub(in crate::afxdp) keepalive_secs: u16,
   124	}
   125	
   330	    #[serde(default)]
   331	    pub destination: String,
   332	    #[serde(default)]
   333	    pub key: u32,
   334	    #[serde(default)]
   335	    pub ttl: i32,
   336	    #[serde(rename = "transport_table", default)]
   337	    pub transport_table: String,
   338	    // WireGuard fields. All `#[serde(default)]` so this stays
   339	    // wire-compatible with old daemons that don't populate them.
   340	    // See docs/pr/wireguard-clean/plan.md for the design.
   341	    #[serde(rename = "wg_listen_port", default)]
   342	    pub wg_listen_port: u16,
   343	    /// Local static private key for the WG interface, hex-encoded
   344	    /// (64 chars for 32 bytes). Empty when `mode != "wireguard"`.
   345	    ///
   346	    /// This field is intentionally `skip_serializing` so it CANNOT
   347	    /// be written back out via any `serde_json` round-trip. The
   348	    /// userspace dataplane persists a JSON snapshot of `ServerState`
   349	    /// to disk via `server::helpers::write_state`, which used to
   350	    /// include this private key in plaintext (Copilot inline review
   351	    /// caught this on the final pre-merge round). Deserialization
   352	    /// still works — the control plane delivers the key on the
   353	    /// control socket via the `default` path. The custom Debug impl
   354	    /// on `TunnelEndpointSnapshot` redacts this field to keep any
   355	    /// future accidental `{:?}` log line from leaking key material.
   356	    #[serde(rename = "wg_local_privkey_hex", default, skip_serializing)]
   357	    pub wg_local_privkey_hex: String,
   358	    /// Peer's static public key, hex-encoded. The WG engine uses
   359	    /// this as the encap key — not AllowedIPs LPM. See plan §
   360	    /// "Engine keying" for why this matters.
   361	    #[serde(rename = "wg_peer_pubkey_hex", default)]
   362	    pub wg_peer_pubkey_hex: String,
   363	    /// Peer AllowedIPs, as CIDR strings. Only consulted on the
   364	    /// decap path (inner src-IP gate); never used to choose a peer
   365	    /// on egress.
   366	    #[serde(rename = "wg_allowed_ips", default)]
   367	    pub wg_allowed_ips: Vec<String>,
   368	    /// Optional peer endpoint (`IP:port`) for initiator-role
   369	    /// handshakes. Empty for responder-only.
   370	    #[serde(rename = "wg_endpoint", default)]
   371	    pub wg_endpoint: String,
   372	    /// Optional persistent keepalive in seconds. 0 = off.
   373	    #[serde(rename = "wg_keepalive_secs", default)]
   374	    pub wg_keepalive_secs: u16,
   375	}
   376	
   377	impl std::fmt::Debug for TunnelEndpointSnapshot {
   378	    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
   379	        // Manually redact `wg_local_privkey_hex`. Use a placeholder
   380	        // that records only whether a key was set so debug logs

exec
/bin/bash -lc "nl -ba pkg/daemon/daemon_run.go | sed -n '110,175p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   110		if strings.HasSuffix(linuxName, ".0") {
   111			linuxName = strings.TrimSuffix(linuxName, ".0")
   112		}
   113		return linuxName
   114	}
   115	
   116	func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
   117		if cfg == nil {
   118			return nil
   119		}
   120		anchorOnly := dataplane.EffectiveType(cfg.System.DataplaneType) == dataplane.TypeUserspace
   121		// Linux interface name -> routing-instance whose `interface` list
   122		// names it, mirroring the step-0a bind loop (forwarding instances
   123		// skipped; shared normalization; later entries overwrite, matching
   124		// 0a's last-bind-wins iteration). Feeds TunnelConfig.RIListMember.
   125		riListMember := map[string]string{}
   126		tunMap := cfg.TunnelNameMap()
   127		for _, ri := range cfg.RoutingInstances {
   128			if ri == nil || ri.InstanceType == "forwarding" {
   129				continue
   130			}
   131			for _, ifaceName := range ri.Interfaces {
   132				riListMember[riMemberLinuxName(tunMap, ifaceName)] = ri.Name
   133			}
   134		}
   135		var tunnels []*config.TunnelConfig
   136		for _, ifc := range cfg.Interfaces.Interfaces {
   137			if ifc == nil {
   138				continue
   139			}
   140			// WireGuard tunnels carry no GRE-style local `source` (the peer
   141			// lives in WgEndpoint; the local side is just a listen port), so
   142			// the Source!="" gate that screens half-configured GRE/IPIP
   143			// stanzas must not drop them. Found live in #1736 S2b: without
   144			// this, `interfaces wgN tunnel mode wireguard` compiled and fed
   145			// the dataplane snapshot, but applyWireguardTunLocked never ran,
   146			// so the persistent wgN TUN was never created and the Rust
   147			// control thread's open_tun failed. The dataplane side already
   148			// special-cases the missing source
   149			// (pkg/dataplane/userspace/tunnels.go); this is the routing-side
   150			// twin.
   151			if ifc.Tunnel != nil && (ifc.Tunnel.Source != "" || ifc.Tunnel.Mode == "wireguard") {
   152				tc := *ifc.Tunnel
   153				tc.AnchorOnly = anchorOnly
   154				tc.MTU = ifc.MTU
   155				tc.RIListMember = riListMember[tc.Name]
   156				tunnels = append(tunnels, &tc)
   157			}
   158			for _, unit := range ifc.Units {
   159				if unit == nil || unit.Tunnel == nil {
   160					continue
   161				}
   162				tc := *unit.Tunnel
   163				tc.AnchorOnly = anchorOnly
   164				// Unit-level MTU overrides interface-level, mirroring the
   165				// compiler_iface precedence (#1884).
   166				tc.MTU = ifc.MTU
   167				if unit.MTU > 0 {
   168					tc.MTU = unit.MTU
   169				}
   170				tc.RIListMember = riListMember[tc.Name]
   171				tunnels = append(tunnels, &tc)
   172			}
   173		}
   174		return tunnels
   175	}

exec
/bin/bash -lc "nl -ba pkg/config/compiler_interfaces.go | sed -n '640,730p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   640								unit.DHCPv6Client = dc
   641							}
   642						}
   643					}
   644				}
   645	
   646				ifc.Units[unitNum] = unit
   647	
   648				// Collect tunnel addresses from unit config
   649				if unit.Tunnel != nil {
   650					// Per-unit tunnel: addresses belong to this specific tunnel
   651					unit.Tunnel.Addresses = append(unit.Tunnel.Addresses, unit.Addresses...)
   652				} else if ifc.Tunnel != nil {
   653					// Interface-level tunnel: all unit addresses go to shared tunnel
   654					ifc.Tunnel.Addresses = append(ifc.Tunnel.Addresses, unit.Addresses...)
   655				}
   656			}
   657	
   658			ifaces.Interfaces[ifName] = ifc
   659		}
   660		return nil
   661	}
   662	
   663	// parseTunnelWireguard fills the WireGuard fields on tc from a
   664	// `wireguard { ... }` node under a tunnel stanza (#1432 S2a). The
   665	// minimal generic grammar is:
   666	//
   667	//	tunnel {
   668	//	    mode wireguard;
   669	//	    wireguard {
   670	//	        listen-port 51820;
   671	//	        private-key <64-hex>;
   672	//	        peer {
   673	//	            public-key <64-hex>;
   674	//	            allowed-ips <cidr>;   # repeatable
   675	//	            endpoint <ip:port>;
   676	//	            persistent-keepalive <secs>;
   677	//	        }
   678	//	    }
   679	//	}
   680	//
   681	// This is intentionally narrower than the eventual Junos wireguard
   682	// grammar (S6); it compiles to the TunnelEndpointSnapshot Wg* DTO
   683	// fields without committing to that surface.
   684	func parseTunnelWireguard(tc *TunnelConfig, wgNode *Node) {
   685		for _, prop := range wgNode.Children {
   686			switch prop.Name() {
   687			case "listen-port":
   688				if v := nodeVal(prop); v != "" {
   689					if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
   690						tc.WgListenPort = uint16(n)
   691					}
   692				}
   693			case "private-key":
   694				if v := nodeVal(prop); v != "" {
   695					tc.WgLocalPrivkeyHex = v
   696				}
   697			case "peer":
   698				parseTunnelWireguardPeer(tc, prop)
   699			}
   700		}
   701	}
   702	
   703	func parseTunnelWireguardPeer(tc *TunnelConfig, peerNode *Node) {
   704		for _, prop := range peerNode.Children {
   705			switch prop.Name() {
   706			case "public-key":
   707				if v := nodeVal(prop); v != "" {
   708					tc.WgPeerPubkeyHex = v
   709				}
   710			case "allowed-ips":
   711				if v := nodeVal(prop); v != "" {
   712					tc.WgAllowedIPs = append(tc.WgAllowedIPs, v)
   713				}
   714			case "endpoint":
   715				if v := nodeVal(prop); v != "" {
   716					tc.WgEndpoint = v
   717				}
   718			case "persistent-keepalive":
   719				if v := nodeVal(prop); v != "" {
   720					if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 65535 {
   721						tc.WgKeepaliveSecs = uint16(n)
   722					}
   723				}
   724			}
   725		}
   726	}
   727	
   728	// parseMSSValue extracts MSS value from either "node { mss VALUE; }" or "node VALUE;" syntax.
   729	func parseMSSValue(node *Node) int {
   730		// Hierarchical: ipsec-vpn { mss 1360; } or gre-in { mss 1360; }

exec
/bin/bash -lc 'rg -n "allowed_ips|allowed_ips_cidrs|allowed|AllowedIPs|wg_allowed|peer_allowed|allowed_ips" userspace-dp/src pkg/daemon pkg/config pkg/frr pkg/routing' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/frr/README.md:8:This package is the only place in the codebase that's allowed to touch
pkg/config/freetext.go:92:				return fmt.Errorf("%s: value %q contains control characters (newlines and other control characters are not allowed in configuration values)", nodePath, k)
pkg/config/freetext.go:96:			return fmt.Errorf("%s: annotation %q contains control characters (newlines and other control characters are not allowed in annotations)", nodePath, n.Annotation)
userspace-dp/src/protocol/control.rs:537:    #[serde(rename = "decap_drops_allowed_ips", default)]
userspace-dp/src/protocol/control.rs:538:    pub decap_drops_allowed_ips: u64,
pkg/config/compiler_test.go:69:	// A regression to fail-fast (one family silently swallowed)
pkg/config/compiler_class_of_service.go:77:		// queue is explicitly allowed so `load merge` /
userspace-dp/src/protocol/binding.rs:557:    #[serde(rename = "direct_tx_disallowed_fallback_packets", default)]
userspace-dp/src/protocol/binding.rs:558:    pub direct_tx_disallowed_fallback_packets: u64,
pkg/config/schema_validators.go:177:func ValidateEnum(allowed []string) LeafValidator {
pkg/config/schema_validators.go:178:	sorted := append([]string(nil), allowed...)
pkg/config/schema_validators.go:210:			return fmt.Errorf("prefix length not allowed here (got %q; use a bare IP address)", raw)
pkg/config/types_routing.go:328:	// WgPeerPubkeyHex, NOT AllowedIPs LPM (cryptokey-routing safety).
pkg/config/types_routing.go:332:	WgAllowedIPs      []string // peer AllowedIPs (CIDR); decap inner-src gate only
pkg/config/types_routing.go:351:		"WgAllowedIPs:%v WgEndpoint:%s WgKeepaliveSecs:%d}",
pkg/config/types_routing.go:354:		tc.WgAllowedIPs, tc.WgEndpoint, tc.WgKeepaliveSecs)
pkg/config/value_type.go:44:	// ValueEnumOf is one of a fixed set of names. The allowed set lives
pkg/config/parser_routing_test.go:3258:		"set interfaces wg0 tunnel wireguard peer allowed-ips 10.0.0.0/24",
pkg/config/parser_routing_test.go:3259:		"set interfaces wg0 tunnel wireguard peer allowed-ips 10.0.1.0/24",
pkg/config/parser_routing_test.go:3294:	if len(tc.WgAllowedIPs) != 2 {
pkg/config/parser_routing_test.go:3295:		t.Errorf("WgAllowedIPs = %v, want 2 entries", tc.WgAllowedIPs)
userspace-dp/src/protocol/tests.rs:1452:        decap_drops_allowed_ips: 23,
pkg/config/schema_system.go:89:		// Atoi error swallowed (compileUserspaceDataplane), so
pkg/config/schema.go:38:	multi        bool                   // true = multiple leaf values allowed (e.g. source-address); false = replace on set
pkg/config/README.md:62:  `ValidateInteger(min,max)`, `ValidateEnum(allowed)`,
pkg/config/schema_interfaces.go:30:	// error swallowed → garbage silently means "MTU not set", the
pkg/config/schema_interfaces.go:80:		// swallowed (compiler_interfaces.go:293/:302) — garbage
pkg/config/schema_interfaces.go:353:// surface — listen-port / private-key / peer{public-key, allowed-ips,
pkg/config/schema_interfaces.go:380:				"allowed-ips": {desc: "Peer allowed IPs (CIDR)", args: 1, multi: true, placeholder: "<prefix>", children: nil},
userspace-dp/src/protocol/snapshot.rs:359:    /// this as the encap key — not AllowedIPs LPM. See plan §
userspace-dp/src/protocol/snapshot.rs:363:    /// Peer AllowedIPs, as CIDR strings. Only consulted on the
userspace-dp/src/protocol/snapshot.rs:366:    #[serde(rename = "wg_allowed_ips", default)]
userspace-dp/src/protocol/snapshot.rs:367:    pub wg_allowed_ips: Vec<String>,
userspace-dp/src/protocol/snapshot.rs:405:            .field("wg_allowed_ips", &self.wg_allowed_ips)
pkg/config/types_system.go:288:// LoginClassPermissions maps class names to their allowed permissions.
pkg/config/compiler_protocols.go:947:		return 0, fmt.Errorf("invalid scaled decimal %q: negative not allowed", orig)
pkg/daemon/frr_fullconfig_guard_test.go:13:// frrFullConfigAllowlist is the closed set of production files allowed
pkg/daemon/frr_fullconfig_guard_test.go:64:			if _, allowed := frrFullConfigAllowlist[rel]; allowed {
pkg/config/compiler_interfaces.go:674://	            allowed-ips <cidr>;   # repeatable
pkg/config/compiler_interfaces.go:710:		case "allowed-ips":
pkg/config/compiler_interfaces.go:712:				tc.WgAllowedIPs = append(tc.WgAllowedIPs, v)
pkg/daemon/linksetup.go:121:// allowedInterfaces is the userspace-dp binding allowlist; see
pkg/daemon/linksetup.go:123:func reapplyRSSIndirection(rssEnabled bool, userspaceWorkers int, allowedInterfaces []string) {
pkg/daemon/linksetup.go:124:	reapplyRSSIndirectionWith(rssEnabled, userspaceWorkers, allowedInterfaces, realRSSExecutor{})
pkg/daemon/linksetup.go:130:func reapplyRSSIndirectionWith(rssEnabled bool, userspaceWorkers int, allowedInterfaces []string, execer rssExecutor) {
pkg/daemon/linksetup.go:131:	applyRSSIndirection(rssEnabled, userspaceWorkers, allowedInterfaces, execer)
pkg/daemon/lo0_filter_test.go:39:		"allowed": {
pkg/daemon/lo0_filter_test.go:40:			Name:     "allowed",
pkg/daemon/lo0_filter_test.go:49:			{Name: "allowed", Except: true},
pkg/daemon/rss_indirection_test.go:796:// and swallowed (D3 is best-effort). Ensures the function returns
pkg/daemon/rss_indirection_test.go:798:func TestApplyRSSIndirectionOne_RestoreEthtoolXDefaultGenericError_LoggedAndSwallowed(t *testing.T) {
pkg/daemon/rss_indirection.go:122://   - `allowed` is the userspace-dp binding allowlist — the authoritative
pkg/daemon/rss_indirection.go:144:func applyRSSIndirection(enabled bool, workers int, allowed []string, execer rssExecutor) {
pkg/daemon/rss_indirection.go:153:		restoreDefaultRSSIndirection(allowed, execer)
pkg/daemon/rss_indirection.go:155:			"allowed_count", len(allowed))
pkg/daemon/rss_indirection.go:168:	if len(allowed) == 0 {
pkg/daemon/rss_indirection.go:179:	for _, iface := range allowed {
pkg/daemon/rss_indirection.go:204:func restoreDefaultRSSIndirection(allowed []string, execer rssExecutor) {
pkg/daemon/rss_indirection.go:205:	if len(allowed) == 0 {
pkg/daemon/rss_indirection.go:208:	for _, iface := range allowed {
pkg/daemon/rss_indirection.go:232:// Errors are logged and swallowed: D3 is best-effort.
pkg/daemon/coalescence.go:55:func applyCoalescence(adaptiveEnable bool, rxUsecs, txUsecs int, allowed []string, execer rssExecutor, capture *priorHostTunables) {
pkg/daemon/coalescence.go:56:	if len(allowed) == 0 {
pkg/daemon/coalescence.go:66:	for _, iface := range allowed {
pkg/daemon/coalescence.go:81:// mlx5 interface. Errors are logged and swallowed.
userspace-dp/src/server/tests.rs:841:            wg_allowed_ips: vec!["10.77.0.0/24".to_string()],
userspace-dp/src/slowpath.rs:194:        let allowed = self
userspace-dp/src/slowpath.rs:199:        if !allowed {
userspace-dp/src/fairness_eval/rss.rs:81:        RssExpectation::MaxWorkerFlowShare(max_allowed) => {
userspace-dp/src/fairness_eval/rss.rs:82:            if max_share <= *max_allowed {
userspace-dp/src/fairness_eval/rss.rs:85:                    format!("max_worker_flow_share={max_share:.4} <= expected {max_allowed:.4}"),
userspace-dp/src/fairness_eval/rss.rs:90:                    format!("max_worker_flow_share={max_share:.4} > expected {max_allowed:.4}"),
userspace-dp/src/fairness_eval/rss.rs:94:        RssExpectation::CstructMax(max_allowed) => {
userspace-dp/src/fairness_eval/rss.rs:95:            if cstruct <= *max_allowed {
userspace-dp/src/fairness_eval/rss.rs:98:                    format!("cstruct={cstruct:.4} <= expected {max_allowed:.4}"),
userspace-dp/src/fairness_eval/rss.rs:103:                    format!("cstruct={cstruct:.4} > expected {max_allowed:.4}"),
userspace-dp/src/session/tests.rs:876:fn upsert_synced_can_replace_live_local_session_when_allowed() {
userspace-dp/src/session/mod.rs:849:        // unless explicitly allowed (e.g. during HA activation).
userspace-dp/src/session/mod.rs:1392:    /// compare against, so in release builds it is retained as dead-code-allowed
userspace-dp/src/filter/tests.rs:2171:    let allowed = evaluate_filter(
userspace-dp/src/filter/tests.rs:2181:    assert_eq!(allowed.action, FilterAction::Accept);
userspace-dp/src/afxdp/ha.rs:121:        // RG activation is still allowed to be a narrow ownership transition,
userspace-dp/src/afxdp/coordinator/status.rs:753:                decap_drops_allowed_ips: c.decap_drops_allowed_ips.load(Ordering::Relaxed),
userspace-dp/src/afxdp/coordinator/wg_control.rs:32://!     AllowedIPs-gates the inner src) → write the plaintext inner IP to
userspace-dp/src/afxdp/coordinator/wg_control.rs:1030:                    // engine — the AllowedIPs gate inside try_decap is
userspace-dp/src/afxdp/coordinator/wg_control.rs:1225:                    allowed_ips: vec![],
userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:165:    binding.direct_tx_disallowed_fallback_packets = snap.direct_tx_disallowed_fallback_packets;
userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:340:    binding.direct_tx_disallowed_fallback_packets = 0;
userspace-dp/src/afxdp/cos/admission.rs:138:    // cap), but it allowed a single elephant to occupy the entire
userspace-dp/src/afxdp/cos/flow_hash.rs:28:/// partial reads (the kernel is allowed to return fewer bytes than
userspace-dp/src/afxdp/shared_ops.rs:320:            // path was still swallowed with `let _ =`; count it like the
userspace-dp/src/afxdp/coordinator/tests.rs:1446:    // Joiner must observe a clean Ok(()) — supervisor swallowed the panic.
userspace-dp/src/afxdp/coordinator/tests.rs:2160:            wg_allowed_ips: vec!["10.77.0.0/24".to_string()],
userspace-dp/src/afxdp/cos/queue_service/mod.rs:1342:            // is allowed to participate in surplus and consumes
userspace-dp/src/afxdp/types/forwarding.rs:195:    pub(in crate::afxdp) wg_allowed_ips: Vec<ipnet::IpNet>,
userspace-dp/src/afxdp/types/forwarding.rs:225:            .field("wg_allowed_ips", &self.wg_allowed_ips)
userspace-dp/src/afxdp/flow_cache_tests.rs:780:    // first-packet decision must be allowed to enter the cache
userspace-dp/src/afxdp/README.md:95:*allowed* CPU in that mask, so `CPUAffinity=2 3 4 5` puts workers
userspace-dp/src/afxdp/wg/counters.rs:95:    pub(crate) decap_drops_allowed_ips: AtomicU64,
userspace-dp/src/afxdp/wg/counters.rs:184:            DecapError::AllowedIpsViolation => &self.decap_drops_allowed_ips,
userspace-dp/src/afxdp/wg/counters.rs:294:        assert_eq!(c.decap_drops_allowed_ips.load(Ordering::Relaxed), 1);
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:58:        let mut wg_allowed_ips: Vec<ipnet::IpNet> = Vec::new();
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:67:            wg_allowed_ips = identity.allowed_ips;
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:97:                wg_allowed_ips,
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:120:    pub(in crate::afxdp) allowed_ips: Vec<ipnet::IpNet>,
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:134:            && self.allowed_ips == ep.wg_allowed_ips
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:143:/// Individually-invalid allowed-ips CIDRs are skipped (the row is
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:171:    let mut allowed_ips: Vec<ipnet::IpNet> = Vec::new();
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:172:    for cidr in &row.wg_allowed_ips {
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:174:            Ok(net) => allowed_ips.push(net),
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:195:        allowed_ips,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2014:fn wg_snapshot(listen_port: u16, allowed: &[&str], endpoint: &str) -> ConfigSnapshot {
userspace-dp/src/afxdp/forwarding_build/tests.rs:2025:            wg_allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
userspace-dp/src/afxdp/forwarding_build/tests.rs:2041:    assert_eq!(ep.wg_allowed_ips.len(), 1);
userspace-dp/src/afxdp/forwarding_build/tests.rs:2158:                wg_allowed_ips: vec!["10.0.0.0/24".into()],
userspace-dp/src/afxdp/forwarding_build/wg.rs:18://!     local_privkey, peer_pubkey, allowed_ips, endpoint, keepalive) is
userspace-dp/src/afxdp/forwarding_build/wg.rs:52:            allowed_ips: endpoint.wg_allowed_ips.clone(),
userspace-dp/src/afxdp/forwarding_build/wg.rs:91:        && prev.wg_allowed_ips == next.wg_allowed_ips
userspace-dp/src/afxdp/wg/allowed_ips.rs:1://! AllowedIPs LPM table.
userspace-dp/src/afxdp/wg/allowed_ips.rs:3://! WireGuard's AllowedIPs is a longest-prefix-match table from
userspace-dp/src/afxdp/wg/allowed_ips.rs:20://! overlapping AllowedIPs across peers can never route plaintext to
userspace-dp/src/afxdp/wg/allowed_ips.rs:24://! AllowedIPs is reconciled at config-commit time, not on the hot
userspace-dp/src/afxdp/wg/allowed_ips.rs:31:/// A single AllowedIPs entry: `(prefix, prefix_len, peer_index)`.
userspace-dp/src/afxdp/wg/allowed_ips.rs:138:    /// the inner src IP across the entire AllowedIPs trie resolves
userspace-dp/src/afxdp/wg/allowed_ips.rs:143:    /// prefixes" check. The distinction matters when AllowedIPs
userspace-dp/src/afxdp/wg/allowed_ips.rs:150:    /// allowed A to spoof source addresses inside B's prefix.
userspace-dp/src/afxdp/wg/allowed_ips.rs:172:mod allowed_ips_tests {
userspace-dp/src/afxdp/wg/allowed_ips.rs:208:        // The core safety property: a peer's AllowedIPs gate must
userspace-dp/src/afxdp/wg/session.rs:83:/// inbound data record before egress is allowed).
userspace-dp/src/afxdp/wg/session.rs:116:    /// the peer's AllowedIPs gate.
userspace-dp/src/afxdp/wg/peer.rs:12://! AllowedIPs trie is rebuilt fresh because its index space is
userspace-dp/src/afxdp/wg/peer.rs:39:    /// call site in `WgEngine::try_decap` after the AllowedIPs gate
userspace-dp/src/afxdp/wg/mod.rs:6://! Scope of this PR: engine, framing, allowed-IPs trie, helpers,
userspace-dp/src/afxdp/wg/mod.rs:14://! framing, encap, decap, AllowedIPs LPM, replay window, MSS math.
userspace-dp/src/afxdp/wg/mod.rs:35:pub(crate) mod allowed_ips;
userspace-dp/src/afxdp/icmp_embed/parse.rs:106:/// fragments (offset 0) are allowed. Returns the L4 offset relative
userspace-dp/src/afxdp/icmp_embed/parse.rs:278:    fn embedded_first_or_atomic_fragment_allowed() {
userspace-dp/src/afxdp/icmp_embed/parse.rs:280:        // the L4 header IS present in the quoted bytes — match allowed.
userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:524:    /// share, with explicit CPU-bound bypass allowed to claim surplus.
userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1148:    /// IDs allowed). The lease internally sizes its per-worker arrays
userspace-dp/src/afxdp/worker/README.md:61:  N pins to the N-th *allowed* CPU in that mask, so
userspace-dp/src/afxdp/wg/engine.rs:6://!   - The AllowedIPs LPM trie (used ONLY for inbound src-IP gate).
userspace-dp/src/afxdp/wg/engine.rs:12://!     consult AllowedIPs for peer selection. This is the
userspace-dp/src/afxdp/wg/engine.rs:17://!     AllowedIPs.
userspace-dp/src/afxdp/wg/engine.rs:55:use super::allowed_ips::AllowedIps;
userspace-dp/src/afxdp/wg/engine.rs:138:    /// Inner src IP is not in this peer's AllowedIPs — cryptokey-
userspace-dp/src/afxdp/wg/engine.rs:182:    pub(crate) allowed_ips: Vec<ipnet::IpNet>,
userspace-dp/src/afxdp/wg/engine.rs:246:    /// `peer_index` referenced from `allowed_ips`.
userspace-dp/src/afxdp/wg/engine.rs:250:    /// AllowedIPs LPM. Only consulted on the decap path.
userspace-dp/src/afxdp/wg/engine.rs:251:    pub(crate) allowed_ips: AllowedIps,
userspace-dp/src/afxdp/wg/engine.rs:259:            allowed_ips: AllowedIps::new(),
userspace-dp/src/afxdp/wg/engine.rs:501:    ///      then fail the AllowedIPs gate because the peer is no
userspace-dp/src/afxdp/wg/engine.rs:514:        let mut new_allowed = AllowedIps::new();
userspace-dp/src/afxdp/wg/engine.rs:543:            // pubkey lookup) and make `new_allowed` carry entries
userspace-dp/src/afxdp/wg/engine.rs:554:            for cidr in &cfg.allowed_ips {
userspace-dp/src/afxdp/wg/engine.rs:555:                new_allowed.insert(*cidr, idx);
userspace-dp/src/afxdp/wg/engine.rs:613:            allowed_ips: new_allowed,
userspace-dp/src/afxdp/wg/engine.rs:763:        // AllowedIPs to pick a peer on egress.
userspace-dp/src/afxdp/wg/engine.rs:1002:        // authenticates but fails AllowedIPs still flips the
userspace-dp/src/afxdp/wg/engine.rs:1033:        // BEFORE the inner-parse/AllowedIPs gates (Codex r1 M3 —
userspace-dp/src/afxdp/wg/engine.rs:1035:        // authenticates, before routing delivery; an AllowedIPs-
userspace-dp/src/afxdp/wg/engine.rs:1074:        // AllowedIPs gate on the inner src IP. WG spec §5.4.6:
userspace-dp/src/afxdp/wg/engine.rs:1097:            // AllowedIPs gate. Taking these from separate ArcSwap
userspace-dp/src/afxdp/wg/engine.rs:1101:            // snapshot with allowed_ips from the new one.
userspace-dp/src/afxdp/wg/engine.rs:1107:            if !table.allowed_ips.matches_for_peer(inner_src, peer_idx) {
userspace-dp/src/afxdp/wg/engine.rs:1253:/// Used for the AllowedIPs receive-side gate. Returns `None` for
userspace-dp/src/afxdp/wg/engine.rs:1374:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1384:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1422:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1432:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1463:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1473:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1508:                    allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1514:                    allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1525:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1535:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1564:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1574:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1625:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1635:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1683:                    allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1689:                    allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1700:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1710:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1722:            allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1764:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1773:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1779:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.2.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1786:            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1879:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1889:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:1896:            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:2038:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/engine.rs:2048:                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:6://! AllowedIPs / replay / VLAN / DSCP / MSS properties.
userspace-dp/src/afxdp/wg/tests.rs:8:use super::allowed_ips::AllowedIps;
userspace-dp/src/afxdp/wg/tests.rs:44:    init_allowed_for_resp: Vec<ipnet::IpNet>,
userspace-dp/src/afxdp/wg/tests.rs:45:    resp_allowed_for_init: Vec<ipnet::IpNet>,
userspace-dp/src/afxdp/wg/tests.rs:57:            allowed_ips: init_allowed_for_resp,
userspace-dp/src/afxdp/wg/tests.rs:67:            allowed_ips: resp_allowed_for_init,
userspace-dp/src/afxdp/wg/tests.rs:151:    let resp_allowed = vec!["10.0.0.0/24".parse().unwrap()];
userspace-dp/src/afxdp/wg/tests.rs:152:    let init_allowed = vec!["10.0.1.0/24".parse().unwrap()];
userspace-dp/src/afxdp/wg/tests.rs:154:        established_pair(init_allowed, resp_allowed);
userspace-dp/src/afxdp/wg/tests.rs:179:fn decap_rejects_inner_src_outside_allowed_ips() {
userspace-dp/src/afxdp/wg/tests.rs:180:    // The responder's peer (the initiator) is allowed 10.0.0.0/24.
userspace-dp/src/afxdp/wg/tests.rs:182:    // dropped by the AllowedIPs gate, NOT silently accepted.
userspace-dp/src/afxdp/wg/tests.rs:233:fn cryptokey_routing_overlapping_allowed_ips() {
userspace-dp/src/afxdp/wg/tests.rs:246:                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:252:                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:264:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:274:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:513:/// Cross-peer overlapping AllowedIPs MUST honor WG §5.4.6 global
userspace-dp/src/afxdp/wg/tests.rs:526:    // Initiator engine owns AllowedIPs for both peers: A=/8 (less
userspace-dp/src/afxdp/wg/tests.rs:536:                allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:542:                allowed_ips: vec!["10.1.1.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:554:            allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:564:            allowed_ips: vec!["10.1.1.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:571:    // rejected by the DECAP-side AllowedIPs gate. Drive the
userspace-dp/src/afxdp/wg/tests.rs:621:fn decap_zeros_plaintext_on_allowed_ips_violation() {
userspace-dp/src/afxdp/wg/tests.rs:622:    // Set the AllowedIPs trie so the responder's view of the
userspace-dp/src/afxdp/wg/tests.rs:625:    // AllowedIPs gate, must return AllowedIpsViolation AND wipe.
userspace-dp/src/afxdp/wg/tests.rs:720:        // src 10.0.0.5 → must match the responder's allowed_ips for the initiator.
userspace-dp/src/afxdp/wg/tests.rs:849:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:887:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:910:/// responder's session flips to confirmed and egress is allowed.
userspace-dp/src/afxdp/wg/tests.rs:925:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:935:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1045:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1065:        allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1087:        allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1117:        // Need a valid src for AllowedIPs gate to PASS so the
userspace-dp/src/afxdp/wg/tests.rs:1119:        // AllowedIPs gate. inner_src_ip reads bytes 12..16
userspace-dp/src/afxdp/wg/tests.rs:1215:fn allowed_ips_unit_check() {
userspace-dp/src/afxdp/wg/tests.rs:1325:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1335:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1416:    /// `0.0.0.0/0` so any inner src passes the AllowedIPs gate.
userspace-dp/src/afxdp/wg/tests.rs:1428:                allowed_ips: any_v4.clone(),
userspace-dp/src/afxdp/wg/tests.rs:1438:                allowed_ips: any_v4,
userspace-dp/src/afxdp/wg/tests.rs:1527:                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1553:                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1565:                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1764:            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1842:            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:1910:                allowed_ips: any_v4.clone(),
userspace-dp/src/afxdp/wg/tests.rs:1920:                allowed_ips: any_v4,
userspace-dp/src/afxdp/wg/tests.rs:1967:                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:2034:    // After the interval elapses, a fresh edge is allowed again.
userspace-dp/src/afxdp/wg/tests.rs:2072:            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:2120:            allowed_ips: vec![],
userspace-dp/src/afxdp/wg/tests.rs:2140:            allowed_ips: vec![],
userspace-dp/src/afxdp/wg/tests.rs:2155:            allowed_ips: vec![],
userspace-dp/src/afxdp/wg/tests.rs:2329:                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:2343:    /// AllowedIPs-violating inner → decap_drops_allowed_ips.
userspace-dp/src/afxdp/wg/tests.rs:2345:    fn allowed_ips_violation_counts() {
userspace-dp/src/afxdp/wg/tests.rs:2362:                .decap_drops_allowed_ips
userspace-dp/src/afxdp/wg/tests.rs:2473:            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:2518:                allowed_ips: any_v4.clone(),
userspace-dp/src/afxdp/wg/tests.rs:2528:                allowed_ips: any_v4,
userspace-dp/src/afxdp/wg/tests.rs:2785:    /// authenticated send clears it; an AllowedIPs-rejected but
userspace-dp/src/afxdp/wg/tests.rs:2994:                allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:3004:                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:3049:                allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
userspace-dp/src/afxdp/wg/tests.rs:3059:                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
userspace-dp/src/afxdp/tx/dispatch/mod.rs:585:                        DisallowedByRewriteMode,
userspace-dp/src/afxdp/tx/dispatch/mod.rs:616:                            Some(DirectTxFallbackReason::DisallowedByRewriteMode);
userspace-dp/src/afxdp/tx/dispatch/mod.rs:626:                            Some(DirectTxFallbackReason::DisallowedByRewriteMode);
userspace-dp/src/afxdp/tx/dispatch/mod.rs:764:                            Some(DirectTxFallbackReason::DisallowedByRewriteMode) => {
userspace-dp/src/afxdp/tx/dispatch/mod.rs:767:                                    .pending_direct_tx_disallowed_fallback_packets += 1;
userspace-dp/src/afxdp/worker/mod.rs:476:                pending_direct_tx_disallowed_fallback_packets: 0,
userspace-dp/src/afxdp/worker/mod.rs:617:                pending_direct_tx_disallowed_fallback_packets: 0,
userspace-dp/src/afxdp/worker/mod.rs:737:                pending_direct_tx_disallowed_fallback_packets: 0,
userspace-dp/src/afxdp/worker/mod.rs:1320:    pub(crate) direct_tx_disallowed_fallback_packets: u64,
userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs:1823:    // references allowed are the field definition + its initializer in
userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs:1830:    let allowed = [
userspace-dp/src/afxdp/types/shared_cos_lease/shared_cos_lease_tests.rs:1852:        if allowed.iter().any(|a| rel == *a) {
userspace-dp/src/afxdp/wg/handshake_session.rs:344:    ///     allowed the per-peer abort to remove the entry mid-read.)
userspace-dp/src/afxdp/neighbor.rs:520:/// swallowed on failure).
userspace-dp/src/afxdp/neighbor.rs:811:/// Enumerate the allowed CPUs described by `is_set` into the caller-provided
userspace-dp/src/afxdp/neighbor.rs:816:/// `is_set(cpu)` returns true if CPU index `cpu` is in the allowed mask.
userspace-dp/src/afxdp/neighbor.rs:820:/// Returns `None` when the allowed set is empty.
userspace-dp/src/afxdp/neighbor.rs:822:fn nth_allowed_cpu(
userspace-dp/src/afxdp/neighbor.rs:854:/// allowed CPUs, and pick the `worker_id % allowed_count`-th entry. With
userspace-dp/src/afxdp/neighbor.rs:855:/// no `CPUAffinity=` the allowed set is `0..N-1` and behaviour is
userspace-dp/src/afxdp/neighbor.rs:876:        let mut allowed = [0u16; libc::CPU_SETSIZE as usize];
userspace-dp/src/afxdp/neighbor.rs:878:            nth_allowed_cpu(worker_id, |cpu| libc::CPU_ISSET(cpu, &inherited), &mut allowed)
userspace-dp/src/afxdp/neighbor.rs:918:    use super::nth_allowed_cpu;
userspace-dp/src/afxdp/neighbor.rs:920:    /// Build an `is_set` closure that returns true iff `cpu` is in `allowed`.
userspace-dp/src/afxdp/neighbor.rs:921:    fn mask_from<const N: usize>(allowed: [usize; N]) -> impl Fn(usize) -> bool {
userspace-dp/src/afxdp/neighbor.rs:922:        move |cpu| allowed.contains(&cpu)
userspace-dp/src/afxdp/neighbor.rs:926:    fn nth_allowed_cpu_picks_nth_of_allowed_cpus() {
userspace-dp/src/afxdp/neighbor.rs:929:        assert_eq!(nth_allowed_cpu(0, &is_set, &mut buf), Some(2));
userspace-dp/src/afxdp/neighbor.rs:930:        assert_eq!(nth_allowed_cpu(1, &is_set, &mut buf), Some(3));
userspace-dp/src/afxdp/neighbor.rs:931:        assert_eq!(nth_allowed_cpu(2, &is_set, &mut buf), Some(4));
userspace-dp/src/afxdp/neighbor.rs:932:        assert_eq!(nth_allowed_cpu(3, &is_set, &mut buf), Some(5));
userspace-dp/src/afxdp/neighbor.rs:934:        assert_eq!(nth_allowed_cpu(4, &is_set, &mut buf), Some(2));
userspace-dp/src/afxdp/neighbor.rs:938:    fn nth_allowed_cpu_returns_none_when_mask_is_empty() {
userspace-dp/src/afxdp/neighbor.rs:941:        assert_eq!(nth_allowed_cpu(0, is_set, &mut buf), None);
userspace-dp/src/afxdp/neighbor.rs:942:        assert_eq!(nth_allowed_cpu(7, is_set, &mut buf), None);
userspace-dp/src/afxdp/neighbor.rs:1006:    fn nth_allowed_cpu_handles_sparse_masks() {
userspace-dp/src/afxdp/neighbor.rs:1009:        assert_eq!(nth_allowed_cpu(0, &is_set, &mut buf), Some(0));
userspace-dp/src/afxdp/neighbor.rs:1010:        assert_eq!(nth_allowed_cpu(1, &is_set, &mut buf), Some(7));
userspace-dp/src/afxdp/neighbor.rs:1011:        assert_eq!(nth_allowed_cpu(2, &is_set, &mut buf), Some(15));
userspace-dp/src/afxdp/neighbor.rs:1013:        assert_eq!(nth_allowed_cpu(3, &is_set, &mut buf), Some(0));
userspace-dp/src/afxdp/neighbor.rs:1020:    /// that the NEW behaviour picks the `worker_id`-th entry of the allowed
userspace-dp/src/afxdp/neighbor.rs:1023:    /// it — the other `nth_allowed_cpu_*` tests would still pass because
userspace-dp/src/afxdp/neighbor.rs:1026:    fn nth_allowed_cpu_regression_for_systemd_cpuaffinity_2_3_4_5() {
userspace-dp/src/afxdp/neighbor.rs:1027:        let allowed_cpus = [2usize, 3, 4, 5];
userspace-dp/src/afxdp/neighbor.rs:1028:        let is_set = mask_from(allowed_cpus);
userspace-dp/src/afxdp/neighbor.rs:1034:        // to allowed[0..3] = 2/3/4/5. The issue body verified this live
userspace-dp/src/afxdp/neighbor.rs:1037:        //     xpf-userspace-w cpus_allowed=0   <-- old worker 0
userspace-dp/src/afxdp/neighbor.rs:1038:        //     xpf-userspace-w cpus_allowed=1   <-- old worker 1
userspace-dp/src/afxdp/neighbor.rs:1039:        //     xpf-userspace-w cpus_allowed=2   <-- old worker 2
userspace-dp/src/afxdp/neighbor.rs:1040:        //     xpf-userspace-w cpus_allowed=3   <-- old worker 3
userspace-dp/src/afxdp/neighbor.rs:1042:        // Expected NEW behaviour: workers pin to cpus_allowed=2/3/4/5.
userspace-dp/src/afxdp/neighbor.rs:1043:        for (worker_id, old_absolute_cpu, new_allowed_cpu) in [
userspace-dp/src/afxdp/neighbor.rs:1049:            // Reconstruct the old formula verbatim. Uses the allowed-set
userspace-dp/src/afxdp/neighbor.rs:1051:            // systemd mask), not the allowed-set members.
userspace-dp/src/afxdp/neighbor.rs:1052:            let reconstructed_old = (worker_id as usize) % allowed_cpus.len();
userspace-dp/src/afxdp/neighbor.rs:1058:            let picked = nth_allowed_cpu(worker_id, &is_set, &mut buf)
userspace-dp/src/afxdp/neighbor.rs:1059:                .expect("allowed mask is non-empty");
userspace-dp/src/afxdp/neighbor.rs:1061:                picked, new_allowed_cpu,
userspace-dp/src/afxdp/neighbor.rs:1062:                "worker {worker_id} should pin to allowed CPU {new_allowed_cpu}, got {picked}",
userspace-dp/src/afxdp/neighbor.rs:1065:                allowed_cpus.contains(&picked),
userspace-dp/src/afxdp/neighbor.rs:1074:        // revert would pick 0/1 and fall outside the allowed set.
userspace-dp/src/afxdp/neighbor.rs:1077:        assert!(!allowed_cpus.contains(&old_worker_0));
userspace-dp/src/afxdp/neighbor.rs:1078:        assert!(!allowed_cpus.contains(&old_worker_1));
userspace-dp/src/afxdp/neighbor.rs:1080:            nth_allowed_cpu(0, &is_set, &mut buf).expect("allowed mask is non-empty");
userspace-dp/src/afxdp/neighbor.rs:1082:            nth_allowed_cpu(1, &is_set, &mut buf).expect("allowed mask is non-empty");
userspace-dp/src/afxdp/neighbor.rs:1083:        assert!(allowed_cpus.contains(&new_worker_0));
userspace-dp/src/afxdp/neighbor.rs:1084:        assert!(allowed_cpus.contains(&new_worker_1));
userspace-dp/src/afxdp/umem/debug_state.rs:175:        .pending_direct_tx_disallowed_fallback_packets
userspace-dp/src/afxdp/umem/debug_state.rs:180:            .direct_tx_disallowed_fallback_packets
userspace-dp/src/afxdp/umem/debug_state.rs:184:                    .pending_direct_tx_disallowed_fallback_packets,
userspace-dp/src/afxdp/umem/debug_state.rs:189:            .pending_direct_tx_disallowed_fallback_packets = 0;
userspace-dp/src/afxdp/worker/tx_counters.rs:37:    pub(crate) pending_direct_tx_disallowed_fallback_packets: u64,
userspace-dp/src/afxdp/worker/loop_body/mod.rs:223:                    // instead of being silently swallowed.
userspace-dp/src/afxdp/bpf_map/mod.rs:873:/// VERIFY counters above which only move under `debug-log`): a swallowed
userspace-dp/src/afxdp/frame/tcp.rs:180:/// the maximum allowed MSS value. Returns `true` iff the MSS was
userspace-dp/src/afxdp/umem/mod.rs:557:    pub(super) direct_tx_disallowed_fallback_packets: AtomicU64,
userspace-dp/src/afxdp/umem/mod.rs:782:            direct_tx_disallowed_fallback_packets: AtomicU64::new(0),
pkg/daemon/host_tunables.go:252:			// kernel's allowed list. Log once per failing node with
pkg/daemon/host_tunables.go:654:// Errors are logged and swallowed: restore must not block daemon
pkg/daemon/host_tunables.go:692:// Errors are logged and swallowed. Safe to call with a nil pointer
pkg/daemon/host_tunables.go:733:// swallowed. Safe with a nil pointer or empty map (no-op).
userspace-dp/src/afxdp/umem/snapshot.rs:188:            direct_tx_disallowed_fallback_packets: self
userspace-dp/src/afxdp/umem/snapshot.rs:189:                .direct_tx_disallowed_fallback_packets

exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/wg/engine.rs | sed -n '1,25p;240,255p;500,560p;755,770p;1068,1112p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	//! WgEngine: the per-WG-interface state container and API surface.
     2	//!
     3	//! The engine owns:
     4	//!   - The local static key (X25519 private).
     5	//!   - The peer table, keyed by peer pubkey.
     6	//!   - The AllowedIPs LPM trie (used ONLY for inbound src-IP gate).
     7	//!   - The session-by-receiver-index demux map for inbound.
     8	//!
     9	//! API shape:
    10	//!   - `try_encap` — egress fast path. Caller supplies peer pubkey
    11	//!     explicitly (from the forwarding decision). Engine does NOT
    12	//!     consult AllowedIPs for peer selection. This is the
    13	//!     cryptokey-routing safety property the prior PR violated.
    14	//!   - `try_decap` — ingress fast path. Engine demuxes by
    15	//!     `(receiver_index)`, finds the session, decrypts, then checks
    16	//!     the decrypted inner src IP against the owning peer's
    17	//!     AllowedIPs.
    18	//!   - `build_initiator_handshake` / `build_responder_handshake` —
    19	//!     slow path. Construct a snow `HandshakeState` configured with
    20	//!     the WG protocol prologue and (for the initiator) the peer's
    21	//!     remote static key. The caller pumps the handshake by feeding
    22	//!     wire bytes through `read_message` / `write_message`, converts
    23	//!     to a `StatelessTransportState` via `into_stateless_transport_mode`,
    24	//!     and installs the resulting session via `install_session`.
    25	//!
   240	/// three behind a single `ArcSwap<PeerTable>` gives the reader an
   241	/// atomic snapshot — every load returns an `Arc<PeerTable>` that is
   242	/// internally consistent for its lifetime, and the writer publishes
   243	/// the next snapshot in one release-store.
   244	pub(crate) struct PeerTable {
   245	    /// peer slab — one entry per configured peer. Indexed by the
   246	    /// `peer_index` referenced from `allowed_ips`.
   247	    pub(crate) peers: Vec<Arc<Peer>>,
   248	    /// peer_pubkey → index in `peers`.
   249	    pub(crate) peer_index_by_pubkey: FxHashMap<[u8; 32], u32>,
   250	    /// AllowedIPs LPM. Only consulted on the decap path.
   251	    pub(crate) allowed_ips: AllowedIps,
   252	}
   253	
   254	impl PeerTable {
   255	    fn empty() -> Self {
   500	    ///      successfully (the session Arc is still in the demux map),
   501	    ///      then fail the AllowedIPs gate because the peer is no
   502	    ///      longer in the index, and the demux entry would leak
   503	    ///      forever.
   504	    ///   3. `ArcSwap::store` publishes the new `PeerTable` in one
   505	    ///      release-store. Subsequent `.load()` calls observe either
   506	    ///      the entire old table or the entire new one — never a mix.
   507	    pub(crate) fn reconcile_peers(&self, configs: &[WgPeerConfig]) {
   508	        // Serialize concurrent reconciles. The lock does NOT gate the
   509	        // hot path (readers take only the ArcSwap load).
   510	        let _guard = self.reconcile_lock.lock().unwrap();
   511	        let old = self.table.load_full();
   512	        let mut new_peers: Vec<Arc<Peer>> = Vec::with_capacity(configs.len());
   513	        let mut new_index: FxHashMap<[u8; 32], u32> = FxHashMap::default();
   514	        let mut new_allowed = AllowedIps::new();
   515	        for (i, cfg) in configs.iter().enumerate() {
   516	            let idx = i as u32;
   517	            let existing = old
   518	                .peer_index_by_pubkey
   519	                .get(&cfg.pubkey)
   520	                .and_then(|old_idx| old.peers.get(*old_idx as usize).cloned());
   521	            let peer = match existing {
   522	                Some(p) => {
   523	                    // Apply mutable-field updates in place. The peer
   524	                    // Arc is reused so the (current, previous) session
   525	                    // pair survives the commit. Without this in-place
   526	                    // update, config changes to endpoint or persistent-
   527	                    // keepalive on an existing pubkey would be silently
   528	                    // ignored until the integration layer dropped and
   529	                    // recreated the peer (which it does not). Codex
   530	                    // final pre-merge finding 3.
   531	                    p.update_config(cfg.endpoint, cfg.persistent_keepalive);
   532	                    p
   533	                }
   534	                None => Arc::new(Peer::new(
   535	                    cfg.pubkey,
   536	                    cfg.endpoint,
   537	                    cfg.persistent_keepalive,
   538	                )),
   539	            };
   540	            new_peers.push(peer);
   541	            // r7 Codex/Claude nit: duplicate pubkeys in `configs`
   542	            // leave an orphan `Peer` in `new_peers` (unreachable via
   543	            // pubkey lookup) and make `new_allowed` carry entries
   544	            // indexed at the earlier duplicate's slot. The Go control
   545	            // plane is supposed to reject duplicate pubkeys at config
   546	            // validation; this `debug_assert` keeps the engine-side
   547	            // invariant visible during development without panicking
   548	            // production builds if the validation layer is bypassed.
   549	            let prior = new_index.insert(cfg.pubkey, idx);
   550	            debug_assert!(
   551	                prior.is_none(),
   552	                "duplicate peer pubkey in reconcile_peers configs (prior idx={prior:?}, new idx={idx})"
   553	            );
   554	            for cidr in &cfg.allowed_ips {
   555	                new_allowed.insert(*cidr, idx);
   556	            }
   557	        }
   558	        // Drain demux entries for peers that exist in `old` but not
   559	        // in `new`. Walk old peers and check absence from new_index.
   560	        // We collect `local_index` values under read locks on the
   755	        &self,
   756	        peer_pubkey: &[u8; 32],
   757	        inner_ip: &[u8],
   758	        out: &mut [u8],
   759	        is_keepalive: bool,
   760	    ) -> Result<EncapOutcome, EncapError> {
   761	        // Cryptokey-routing safety: the forwarding decision tells
   762	        // us which peer to encrypt to. We do NOT consult
   763	        // AllowedIPs to pick a peer on egress.
   764	        let peer = self
   765	            .peer_arc(peer_pubkey)
   766	            .ok_or_else(|| self.counters.count_encap_err(EncapError::UnknownPeer))?;
   767	        let Some(session) = peer.current.read().unwrap().clone() else {
   768	            // #1865: the no-current-session arm — distinct from the
   769	            // unconfirmed gate below (same wire error, different
   770	            // counter; AGY r2 #1736 mandated the split be visible).
  1068	        // "malformed inner" drops for a keepalive peer (Codex r1 F1 +
  1069	        // SMR r1 F1, independent convergence).
  1070	        if n == 0 {
  1071	            WgCounters::bump(&self.counters.decap_keepalives);
  1072	            return Err(DecapError::MalformedInner);
  1073	        }
  1074	        // AllowedIPs gate on the inner src IP. WG spec §5.4.6:
  1075	        // "After decryption, the receiver verifies that the source
  1076	        // IP of the inner packet belongs to the peer who sent it.
  1077	        // If not, drop." This is the cryptokey-routing safety
  1078	        // invariant on the receive side.
  1079	        //
  1080	        // Every error arm past `read_message` MUST zero `out[..n]`
  1081	        // before returning so the contract "on Err the caller MUST
  1082	        // NOT inspect `out`" is structurally enforced. We use a
  1083	        // single fall-through with the helper below; adding a new
  1084	        // post-AEAD error arm cannot accidentally skip the wipe.
  1085	        //
  1086	        // The plaintext is the padded form (WG §5.4.6 zero-padded
  1087	        // to a 16-byte multiple at the sender). We parse src IP
  1088	        // from the IPv4/IPv6 header's fixed offset, which is well
  1089	        // before any padding bytes. The returned `inner_ip_len`
  1090	        // truncates `n` down to the real inner-IP packet length;
  1091	        // see `inner_ip_len_after_decap` for the IPv4
  1092	        // `total_length` / IPv6 `payload_length` math. The caller
  1093	        // sees only the un-padded inner-IP packet.
  1094	        let outcome = (|| -> Result<(IpAddr, u32, usize), DecapError> {
  1095	            let inner_src = inner_src_ip(&out[..n]).ok_or(DecapError::MalformedInner)?;
  1096	            // Single atomic snapshot for both peer-index lookup and
  1097	            // AllowedIPs gate. Taking these from separate ArcSwap
  1098	            // loads would re-introduce the reconcile race window
  1099	            // — between the two loads, a config refresh could swap
  1100	            // the peer table and we'd pair a peer_idx from the old
  1101	            // snapshot with allowed_ips from the new one.
  1102	            let table = self.load_table();
  1103	            let peer_idx = *table
  1104	                .peer_index_by_pubkey
  1105	                .get(&session.peer_pubkey)
  1106	                .ok_or(DecapError::UnknownSession)?;
  1107	            if !table.allowed_ips.matches_for_peer(inner_src, peer_idx) {
  1108	                return Err(DecapError::AllowedIpsViolation);
  1109	            }
  1110	            let inner_len = inner_ip_len_after_decap(&out[..n])
  1111	                .ok_or(DecapError::MalformedInner)?;
  1112	            Ok((inner_src, peer_idx, inner_len))

exec
/bin/bash -lc 'rg -n "Tunnel|tunnel|wireguard|Wg|wg_|AllowedIPs|allowed_ips" pkg/frr pkg/daemon/daemon_ipmon.go pkg/daemon/frr_fullconfig_guard_test.go pkg/frr/README.md' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
exec
/bin/bash -lc "nl -ba pkg/daemon/frr_fullconfig_guard_test.go | sed -n '1,110p'; nl -ba pkg/frr/README.md | sed -n '1,40p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/frr/frr_test.go:100:		NextHops:    []config.NextHopEntry{{Interface: "tunnel0"}},
pkg/frr/frr_test.go:103:	want := "ip route 10.0.0.0/8 tunnel0\n"
pkg/frr/frr_test.go:910:				VRFName: "vrf-tunnel-vr",
pkg/frr/frr_test.go:964:	if !strings.Contains(got, "ip route 10.0.50.0/24 10.0.40.1 vrf vrf-tunnel-vr\n") {
pkg/frr/frr_test.go:965:		t.Errorf("missing tunnel-vr static route, got:\n%s", got)
pkg/frr/frr_test.go:1064:		NextHops:    []config.NextHopEntry{{Interface: "tunnel0.0"}},
pkg/frr/frr_test.go:1067:	want := "ip route 10.0.0.0/8 tunnel0\n"

 succeeded in 0ms:
     1	package daemon
     2	
     3	import (
     4		"go/ast"
     5		"go/parser"
     6		"go/token"
     7		"os"
     8		"path/filepath"
     9		"strings"
    10		"testing"
    11	)
    12	
    13	// frrFullConfigAllowlist is the closed set of production files allowed
    14	// to construct frr.FullConfig composite literals. The #1827 plan made
    15	// assembleFRRConfig the SOLE production constructor (one overlay, one
    16	// constructor, two triggers): any other construction site bypasses the
    17	// ip-monitoring effective-route overlay, so an active failover route
    18	// would be silently wiped from the FRR managed section the next time
    19	// that caller ran (AGY review on PR #1843, finding F1 — the legacy
    20	// frr.Apply/ApplyWithInstances bypasses were deleted under the same
    21	// finding).
    22	var frrFullConfigAllowlist = map[string]string{
    23		// The assembler itself.
    24		"pkg/daemon/daemon_ipmon.go": "assembleFRRConfig — the sole production constructor",
    25		// Legacy standalone-CLI fallback: per the file's package comment,
    26		// production xpfd always wires applyConfigFn so this path is
    27		// skipped; it exists only for a CLI spawned without a daemon
    28		// (no ipmon engine, hence no overlay to preserve). Pre-dates
    29		// #1827. Do NOT add new entries here — route through the
    30		// daemon's assembleFRRConfig instead.
    31		"pkg/cli/apply.go": "legacy standalone-CLI fallback (skipped when the daemon wires applyConfigFn)",
    32	}
    33	
    34	// TestFRRFullConfigConstructedOnlyByAssembler walks every production
    35	// (non-test) .go file under pkg/ and cmd/ and fails if a
    36	// frr.FullConfig (or, inside pkg/frr, a bare FullConfig) composite
    37	// literal appears outside the allowlist. Follows the
    38	// legacy_dataplane_canary_test.go AST-guard precedent.
    39	func TestFRRFullConfigConstructedOnlyByAssembler(t *testing.T) {
    40		t.Parallel()
    41	
    42		repoRoot := filepath.Join("..", "..")
    43		fset := token.NewFileSet()
    44		var offenders []string
    45	
    46		for _, top := range []string{"pkg", "cmd"} {
    47			root := filepath.Join(repoRoot, top)
    48			err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
    49				if err != nil {
    50					return err
    51				}
    52				if d.IsDir() {
    53					return nil
    54				}
    55				name := d.Name()
    56				if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
    57					return nil
    58				}
    59				rel, relErr := filepath.Rel(repoRoot, path)
    60				if relErr != nil {
    61					return relErr
    62				}
    63				rel = filepath.ToSlash(rel)
    64				if _, allowed := frrFullConfigAllowlist[rel]; allowed {
    65					return nil
    66				}
    67	
    68				file, perr := parser.ParseFile(fset, path, nil, parser.AllErrors)
    69				if perr != nil {
    70					t.Fatalf("parse %s: %v", rel, perr)
    71				}
    72				inFRRPackage := strings.HasPrefix(rel, "pkg/frr/")
    73	
    74				ast.Inspect(file, func(n ast.Node) bool {
    75					cl, ok := n.(*ast.CompositeLit)
    76					if !ok {
    77						return true
    78					}
    79					switch typ := cl.Type.(type) {
    80					case *ast.SelectorExpr:
    81						// frr.FullConfig{...} (any import alias would
    82						// still name the type FullConfig).
    83						if typ.Sel != nil && typ.Sel.Name == "FullConfig" {
    84							pos := fset.Position(cl.Pos())
    85							offenders = append(offenders,
    86								rel+":"+itoa(pos.Line)+": frr.FullConfig composite literal")
    87						}
    88					case *ast.Ident:
    89						// Bare FullConfig{...} inside pkg/frr itself.
    90						if inFRRPackage && typ.Name == "FullConfig" {
    91							pos := fset.Position(cl.Pos())
    92							offenders = append(offenders,
    93								rel+":"+itoa(pos.Line)+": FullConfig composite literal")
    94						}
    95					}
    96					return true
    97				})
    98				return nil
    99			})
   100			if err != nil {
   101				t.Fatalf("walk %s: %v", root, err)
   102			}
   103		}
   104	
   105		if len(offenders) > 0 {
   106			t.Fatalf("frr.FullConfig constructed outside assembleFRRConfig in production code:\n  %s\n"+
   107				"assembleFRRConfig (pkg/daemon/daemon_ipmon.go) is the SOLE production\n"+
   108				"constructor (#1827): it injects the ip-monitoring effective-route overlay\n"+
   109				"(PreferredRoutes), so a bypassing construction site silently wipes an\n"+
   110				"active failover route from the FRR managed section. Route the new caller\n"+
     1	# pkg/frr
     2	
     3	FRR (FRRouting) integration. Generates a managed section inside
     4	`/etc/frr/frr.conf` from the typed config (static routes, OSPF, BGP,
     5	ISIS, RIP, BFD profiles, multi-VRF instances) and queries protocol state
     6	via `vtysh`.
     7	
     8	This package is the only place in the codebase that's allowed to touch
     9	kernel routes — and it doesn't, directly. It writes config and reloads
    10	FRR, which then owns the kernel route table.
    11	
    12	`frr.conf` is DurableState (#1894): `atomicWriteFile` delegates to
    13	`fsatomic.WriteFileDurable` with `WithPreserveExisting` +
    14	`WithResolveSymlinks` (the #1883 mode/owner/symlink semantics were
    15	lifted into that package), gaining the parent-dir fsync the local
    16	writer lacked. The file carries operator content outside the managed
    17	section, so it must survive power loss.
    18	
    19	## File layout
    20	
    21	The package is split across five sibling `.go` files (no sub-packages,
    22	no filename prefixes):
    23	
    24	| File | Owns |
    25	|---|---|
    26	| `manager.go` | `Manager` struct + lifecycle (`New`, `ApplyFull`, `Clear`, `writeManagedSection`, `reload`), top-level types (`InstanceConfig`, `DHCPRoute`, `FullConfig`), package constants, and the zero-value-safe `executor()` accessor. The legacy `Apply`/`ApplyWithInstances` partial constructors were deleted (#1827 AGY F1, PR #1843): they bypassed `assembleFRRConfig` and would have wiped an active failover overlay. |
    27	| `config_render.go` | Non-protocol config rendering: `generateInterfaceSettings`, `generateStaticRoute` (+ `generateStaticRouteInTable`, the table-suffix variant for `instance-type forwarding` instances, #1827 PR-2), named `ApplyFull` extractors (`renderGenerateRoutes`, `renderDHCPDefaults`, `renderBackupRouter`, `renderPreferredRoutes` — the #1827 ip-monitoring overlay as distance-1 statics, emission step 7 — `renderClusterModeDefaults`), and `resolveECMP` (which has a documented side effect: mutates `fc.ConsistentHash`). |
    28	| `policy_render.go` | **Protocols + policy rendering** (despite the filename — `generateProtocols` for OSPF/OSPFv3/BGP/RIP/ISIS, `generatePolicyOptions` for prefix-lists/route-maps/communities, `resolveRedistribute`, BFD profile dedup). OSPFv2 area membership is rendered per-interface as `ip ospf area <id>` under `interface <name>` (matching the OSPFv3 idiom), never as a global `network <prefix> area` statement — see #1712. |
    29	| `vtysh.go` | `frrExecutor` interface (Vtysh / FrrReloadPy / VtyshLoad), `realExecutor` (production exec.Command implementation), `ExecVtysh`, and all raw-output Get* shells (`GetBFDPeers`, `GetRouteMapList`, `GetISIS*Detail`/`Database`/`Routes`, `GetOSPF*Detail`/`Database`/`Interface`/`Routes`, `GetBGPNeighbor*`). |
    30	| `status_parse.go` | Parsed Get* methods + their public types (`RIPRouteEntry`, `ISISAdjacency`, `OSPFNeighbor`, `BGPPeerSummary`, `BGPRoute`, `FRRRouteDetail`, `FRRNextHop`) + `parseRouteJSON`, `FormatRouteDetail`. |
    31	
    32	## Entry points
    33	
    34	- `Manager` — `manager.go`.
    35	- `New() *Manager` — `manager.go`. Defaults to `/etc/frr/frr.conf` and
    36	  to a real `os/exec`-backed `frrExecutor`.
    37	- `ApplyFull(fc *FullConfig) error` — `manager.go`. Apply full config
    38	  (idempotent diff against on-disk).
    39	- `FullConfig`, `InstanceConfig`, `DHCPRoute` — `manager.go`.
    40	- State queries: raw-text shells in `vtysh.go`, parsed `Get*` methods

exec
/bin/bash -lc "nl -ba pkg/frr/manager.go | sed -n '190,355p;355,450p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   190		return context.Background()
   191	}
   192	
   193	// executor returns m.exec if set, or a default realExecutor otherwise.
   194	// This preserves the contract that `var m frr.Manager; m.ExecVtysh(...)`
   195	// (a zero-value Manager) does not panic — useful for same-package tests
   196	// and historical callers that constructed a literal Manager.
   197	func (m *Manager) executor() frrExecutor {
   198		if m.exec == nil {
   199			return realExecutor{}
   200		}
   201		return m.exec
   202	}
   203	
   204	// InstanceConfig pairs routing config with a VRF name for per-instance generation.
   205	//
   206	// Two rendering modes (#1827 PR-2):
   207	//   - VRFName != "": a `virtual-router` instance backed by a kernel VRF
   208	//     device — statics render with a trailing `vrf <name>`.
   209	//   - VRFName == "" with TableID > 0: an `instance-type forwarding`
   210	//     instance — no VRF device exists; statics render with a trailing
   211	//     `table <id>` so the kernel table matches the FBF/PBR `ip rule`
   212	//     target and the userspace dataplane's `<ri>.inet.0` snapshot table
   213	//     (the FRR-vs-dataplane divergence fixed in #1827 PR-2).
   214	type InstanceConfig struct {
   215		// Name is the routing-instance name (without the "vrf-" prefix),
   216		// used by renderPreferredRoutes to resolve an overlay entry's
   217		// target instance. May be empty on legacy callers; lookup misses
   218		// fall back to the historical "vrf-<name>" rendering.
   219		Name string
   220		// VRFName is the kernel VRF device name ("vrf-<name>"), or "" for
   221		// forwarding instances (and, historically, the master table).
   222		VRFName string
   223		// TableID is the instance's kernel routing table; only consumed
   224		// when VRFName == "" (forwarding instances).
   225		TableID           int
   226		OSPF              *config.OSPFConfig
   227		OSPFv3            *config.OSPFv3Config
   228		BGP               *config.BGPConfig
   229		RIP               *config.RIPConfig
   230		ISIS              *config.ISISConfig
   231		StaticRoutes      []*config.StaticRoute
   232		Inet6StaticRoutes []*config.StaticRoute
   233	}
   234	
   235	// DHCPRoute represents a default route learned via DHCP.
   236	type DHCPRoute struct {
   237		Gateway   string // "10.0.2.1" or "fe80::1"
   238		Interface string // needed for IPv6 link-local gateways
   239		IsIPv6    bool
   240	}
   241	
   242	// FullConfig holds the complete routing config for a single FRR apply.
   243	type FullConfig struct {
   244		OSPF              *config.OSPFConfig
   245		OSPFv3            *config.OSPFv3Config
   246		BGP               *config.BGPConfig
   247		RIP               *config.RIPConfig
   248		ISIS              *config.ISISConfig
   249		StaticRoutes      []*config.StaticRoute
   250		Inet6StaticRoutes []*config.StaticRoute // rib inet6.0 static routes
   251		GenerateRoutes    []*config.GenerateRoute
   252		DHCPRoutes        []DHCPRoute
   253		Instances         []InstanceConfig
   254		PolicyOptions     *config.PolicyOptionsConfig
   255	
   256		// ForwardingTableExport is the export policy for the forwarding table (ECMP).
   257		ForwardingTableExport string
   258	
   259		// BackupRouter is the fallback default gateway (system backup-router).
   260		// Installed with admin distance 250 so it's only used when all other defaults fail.
   261		BackupRouter    string // next-hop IP (e.g. "192.168.50.1")
   262		BackupRouterDst string // destination prefix (e.g. "192.168.0.0/16"), default "0.0.0.0/0"
   263	
   264		// InterfaceBandwidths maps interface names to bandwidth in bits per second.
   265		// FRR emits "bandwidth <kbps>" in interface blocks (used by OSPF auto-cost).
   266		InterfaceBandwidths map[string]uint64
   267	
   268		// InterfacePointToPoint maps interface names to point-to-point flag.
   269		// When true and no explicit OSPF network-type is set, emits "ip ospf network point-to-point".
   270		InterfacePointToPoint map[string]bool
   271	
   272		// RethMap maps reth name → physical member name (e.g. "reth0" → "ge-0-0-1").
   273		// Used to translate RETH interface names in static routes to kernel names.
   274		RethMap map[string]string
   275	
   276		// IPv6NextHopInterfaces maps VRF name -> IPv6 next-hop -> interface for
   277		// global and per-instance static routes that omit an explicit interface.
   278		// Values may still be logical interface names (for example, "reth0.50");
   279		// any later translation to kernel/physical names is handled separately via
   280		// RethMap. The global table uses the empty-string VRF key.
   281		IPv6NextHopInterfaces map[string]map[string]string
   282	
   283		// ConsistentHash is set when the forwarding-table export policy uses
   284		// "load-balance consistent-hash". The daemon should set
   285		// net.ipv4.fib_multipath_hash_policy=1 for L4 ECMP hashing.
   286		//
   287		// NOTE: ApplyFull mutates this field as a side effect of resolveECMP().
   288		// See resolveECMP() in config_render.go.
   289		ConsistentHash bool
   290	
   291		// ClusterMode adds a blackhole default route with high admin distance
   292		// (250) as a safety net for active/active per-RG failover.  When the
   293		// WAN VIP moves to the peer, FRR withdraws the real default route
   294		// (next-hop unreachable).  The blackhole default makes bpf_fib_lookup
   295		// return BPF_FIB_LKUP_RET_BLACKHOLE instead of NOT_FWDED, triggering
   296		// zone-encoded fabric redirect for new connections.  The real default
   297		// route (AD 5 or 200) always takes priority when present.
   298		ClusterMode bool
   299	
   300		// PreferredRoutes is the ip-monitoring effective-route overlay
   301		// (#1827 PR-1b): winner-resolved injected routes rendered as
   302		// DISTANCE-1 statics (Static/1 — beats static AD 5 and DHCP AD
   303		// 200; that is what makes them "preferred"). Runtime state from
   304		// pkg/ipmon, supplied by the daemon's assembleFRRConfig for BOTH
   305		// the full apply path and the routes-only actuator, so an
   306		// unrelated operator commit can never wipe an active failover
   307		// route.
   308		PreferredRoutes []config.RouteOverlayEntry
   309	}
   310	
   311	// NOTE (#1827, AGY review on PR #1843 F1): the legacy Apply(ospf, bgp)
   312	// and ApplyWithInstances(...) convenience constructors were DELETED
   313	// here. They built a partial FullConfig inline, bypassing the daemon's
   314	// assembleFRRConfig — the sole production FullConfig constructor — so
   315	// any caller reaching them would have wiped an active ip-monitoring
   316	// failover overlay (PreferredRoutes) from the managed section. They
   317	// had zero callers (production or test) at removal time. New callers
   318	// must go through the daemon's assembleFRRConfig; pkg/daemon's
   319	// TestFRRFullConfigConstructedOnlyByAssembler guard enforces this.
   320	
   321	// ApplyFull generates the complete FRR config including static routes,
   322	// DHCP-learned defaults, per-VRF routes, and dynamic protocols, then
   323	// reloads FRR.
   324	//
   325	// Emission order (preserved as a contract — many FRR parsers depend on
   326	// it; in particular, interface bandwidth must precede OSPF so auto-cost
   327	// picks it up):
   328	//
   329	//  1. global static routes
   330	//  2. generate-routes (blackhole)
   331	//  3. inet6 static routes
   332	//  4. DHCP-learned defaults (admin distance 200)
   333	//  5. backup-router (admin distance 250)
   334	//  6. cluster-mode blackhole defaults (admin distance 250)
   335	//  7. ip-monitoring preferred routes (admin distance 1, #1827)
   336	//  8. per-VRF static routes
   337	//  9. policy-options (prefix-lists, route-maps, communities)
   338	//  10. interface settings (bandwidth, point-to-point)
   339	//  11. global dynamic protocols (OSPF/OSPFv3/BGP/RIP/ISIS)
   340	//  12. per-VRF dynamic protocols
   341	func (m *Manager) ApplyFull(fc *FullConfig) error {
   342		if fc == nil {
   343			return m.Clear()
   344		}
   345	
   346		hasContent := fc.OSPF != nil || fc.OSPFv3 != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil ||
   347			len(fc.StaticRoutes) > 0 || len(fc.Inet6StaticRoutes) > 0 || len(fc.GenerateRoutes) > 0 || len(fc.DHCPRoutes) > 0 || fc.BackupRouter != "" || fc.ClusterMode ||
   348			len(fc.PreferredRoutes) > 0
   349		for _, inst := range fc.Instances {
   350			if inst.OSPF != nil || inst.OSPFv3 != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil || len(inst.StaticRoutes) > 0 || len(inst.Inet6StaticRoutes) > 0 {
   351				hasContent = true
   352				break
   353			}
   354		}
   355		if !hasContent {
   355		if !hasContent {
   356			return m.Clear()
   357		}
   358	
   359		var b strings.Builder
   360		b.WriteString("! xpf managed config - do not edit\n")
   361		b.WriteString("!\n")
   362	
   363		// 1. Global static routes
   364		if len(fc.StaticRoutes) > 0 {
   365			for _, sr := range fc.StaticRoutes {
   366				b.WriteString(m.generateStaticRoute(sr, "", fc.RethMap, fc.IPv6NextHopInterfaces))
   367			}
   368			b.WriteString("!\n")
   369		}
   370	
   371		// 2. Generate (aggregate) routes — rendered as blackhole static routes
   372		renderGenerateRoutes(&b, fc)
   373	
   374		// 3. IPv6 RIB static routes (rib inet6.0)
   375		if len(fc.Inet6StaticRoutes) > 0 {
   376			for _, sr := range fc.Inet6StaticRoutes {
   377				b.WriteString(m.generateStaticRoute(sr, "", fc.RethMap, fc.IPv6NextHopInterfaces))
   378			}
   379			b.WriteString("!\n")
   380		}
   381	
   382		// 4. DHCP-learned default routes (admin distance 200).
   383		renderDHCPDefaults(&b, fc)
   384	
   385		// 5. Backup router: fallback default gateway with admin distance 250
   386		renderBackupRouter(&b, fc)
   387	
   388		// 6. Cluster mode: blackhole default route as fallback for fabric redirect.
   389		renderClusterModeDefaults(&b, fc)
   390	
   391		// 7. ip-monitoring preferred routes (admin distance 1, #1827).
   392		m.renderPreferredRoutes(&b, fc)
   393	
   394		// 8. Per-VRF static routes. Forwarding instances (VRFName == "",
   395		// TableID > 0) render into their dedicated kernel table instead of
   396		// the default one (#1827 PR-2 divergence fix).
   397		for _, inst := range fc.Instances {
   398			if len(inst.StaticRoutes) > 0 || len(inst.Inet6StaticRoutes) > 0 {
   399				for _, sr := range inst.StaticRoutes {
   400					b.WriteString(m.generateStaticRouteInTable(sr, inst.VRFName, inst.TableID, fc.RethMap, fc.IPv6NextHopInterfaces))
   401				}
   402				for _, sr := range inst.Inet6StaticRoutes {
   403					b.WriteString(m.generateStaticRouteInTable(sr, inst.VRFName, inst.TableID, fc.RethMap, fc.IPv6NextHopInterfaces))
   404				}
   405				b.WriteString("!\n")
   406			}
   407		}
   408	
   409		// 9. Policy options: prefix-lists and route-maps
   410		if fc.PolicyOptions != nil {
   411			b.WriteString(m.generatePolicyOptions(fc.PolicyOptions))
   412		}
   413	
   414		// Resolve forwarding-table export policy for ECMP. Sets fc.ConsistentHash
   415		// as a side effect when the policy uses "load-balance consistent-hash".
   416		ecmpMaxPaths := resolveECMP(fc)
   417	
   418		// 10. Interface-level settings (bandwidth, point-to-point)
   419		b.WriteString(m.generateInterfaceSettings(fc))
   420	
   421		// 11. Global dynamic protocols
   422		if fc.OSPF != nil || fc.OSPFv3 != nil || fc.BGP != nil || fc.RIP != nil || fc.ISIS != nil {
   423			b.WriteString(m.generateProtocols(fc.OSPF, fc.OSPFv3, fc.BGP, fc.RIP, fc.ISIS, "", ecmpMaxPaths, fc.PolicyOptions))
   424		}
   425	
   426		// 12. Per-VRF dynamic protocols
   427		for _, inst := range fc.Instances {
   428			if inst.OSPF != nil || inst.OSPFv3 != nil || inst.BGP != nil || inst.RIP != nil || inst.ISIS != nil {
   429				b.WriteString(m.generateProtocols(inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS, inst.VRFName, ecmpMaxPaths, fc.PolicyOptions))
   430			}
   431		}
   432	
   433		return m.commitManagedSection(b.String())
   434	}
   435	
   436	// commitManagedSection is the single write+reload critical section
   437	// (#1880). It signal-cancels any pending degraded-retry episode FIRST
   438	// (an in-flight retry's frr-reload.py process group dies within one
   439	// WaitDelay window, so the apply waits at most ~5s behind it), then
   440	// holds reloadMu across the managed-section write, the confGen bump,
   441	// and the reload — preserving single-writer semantics against the
   442	// retry goroutine.
   443	//
   444	// Return contract: nil = full diff convergence; ErrFRRReloadDegraded
   445	// (errors.Is) = additive fallback applied, retry scheduled when
   446	// enabled; other errors = nothing converged.
   447	func (m *Manager) commitManagedSection(section string) error {
   448		m.signalRetryCancel()
   449		m.reloadMu.Lock()
   450		defer m.reloadMu.Unlock()

codex
FRR scoping is holding so far: the only production `FullConfig` constructor is `assembleFRRConfig`, and the `FullConfig` type has no tunnel or WG fields. Static routes can reference interfaces, but that comes from configured static routes, not WG synthesis.
exec
/bin/bash -lc "nl -ba pkg/frr/config_render.go | sed -n '1,145p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
exec
/bin/bash -lc "rg -n \"func \\(m \\*Manager\\) generateStaticRoute|func \\(m \\*Manager\\) generateStaticRouteInTable|NextHops|Interface\" pkg/frr/config_render.go pkg/config/types_routing.go | head -n 140" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	// config_render.go holds the non-protocol FRR config rendering helpers:
     2	//
     3	//   - generateInterfaceSettings: per-interface bandwidth + point-to-point hints
     4	//     emitted before protocol config so OSPF auto-cost picks up bandwidth.
     5	//   - generateStaticRoute:       per-prefix `ip route` / `ipv6 route` emission
     6	//     with RETH name translation and IPv6 next-hop
     7	//     interface resolution.
     8	//   - renderGenerateRoutes:      blackhole static routes for `generate` routes.
     9	//   - renderDHCPDefaults:        DHCP-learned default routes (AD 200), with
    10	//     suppression when explicit static defaults exist.
    11	//   - renderBackupRouter:        backup-router default (AD 250).
    12	//   - renderClusterModeDefaults: cluster-mode blackhole defaults (AD 250).
    13	//   - resolveECMP:               forwarding-table export policy → ecmpMaxPaths
    14	//     and (side effect) fc.ConsistentHash.
    15	package frr
    16	
    17	import (
    18		"fmt"
    19		"sort"
    20		"strings"
    21	
    22		"github.com/psaab/xpf/pkg/config"
    23	)
    24	
    25	// generateInterfaceSettings emits FRR interface blocks for bandwidth and
    26	// point-to-point network type. These are emitted before protocol config so
    27	// OSPF auto-cost picks up the correct bandwidth.
    28	func (m *Manager) generateInterfaceSettings(fc *FullConfig) string {
    29		if len(fc.InterfaceBandwidths) == 0 && len(fc.InterfacePointToPoint) == 0 {
    30			return ""
    31		}
    32	
    33		// Build set of interfaces that have explicit OSPF NetworkType so we don't override.
    34		ospfNetworkType := make(map[string]bool)
    35		if fc.OSPF != nil {
    36			for _, area := range fc.OSPF.Areas {
    37				for _, iface := range area.Interfaces {
    38					if iface.NetworkType != "" {
    39						ospfNetworkType[iface.Name] = true
    40					}
    41				}
    42			}
    43		}
    44	
    45		// Collect all interface names that need settings.
    46		ifaces := make(map[string]bool)
    47		for name := range fc.InterfaceBandwidths {
    48			ifaces[name] = true
    49		}
    50		for name := range fc.InterfacePointToPoint {
    51			if fc.InterfacePointToPoint[name] && !ospfNetworkType[name] {
    52				ifaces[name] = true
    53			}
    54		}
    55	
    56		// Sort for deterministic output.
    57		names := make([]string, 0, len(ifaces))
    58		for name := range ifaces {
    59			names = append(names, name)
    60		}
    61		sort.Strings(names)
    62	
    63		var b strings.Builder
    64		for _, name := range names {
    65			fmt.Fprintf(&b, "interface %s\n", name)
    66			if bw, ok := fc.InterfaceBandwidths[name]; ok && bw > 0 {
    67				// FRR bandwidth command takes kbps
    68				kbps := bw / 1000
    69				if kbps == 0 {
    70					kbps = 1
    71				}
    72				fmt.Fprintf(&b, " bandwidth %d\n", kbps)
    73			}
    74			if fc.InterfacePointToPoint[name] && !ospfNetworkType[name] {
    75				b.WriteString(" ip ospf network point-to-point\n")
    76			}
    77			b.WriteString("exit\n!\n")
    78		}
    79		return b.String()
    80	}
    81	
    82	// generateStaticRoute produces FRR static route commands.
    83	// Multiple next-hops produce one line each (FRR creates ECMP).
    84	// Routes with NextTable are handled via ip rule (policy routing), not FRR.
    85	func (m *Manager) generateStaticRoute(sr *config.StaticRoute, vrfName string, rethMap map[string]string, ipv6NextHopInterfaces map[string]map[string]string) string {
    86		return m.generateStaticRouteInTable(sr, vrfName, 0, rethMap, ipv6NextHopInterfaces)
    87	}
    88	
    89	// generateStaticRouteInTable is generateStaticRoute with an optional
    90	// kernel routing-table override (#1827 PR-2). tableID > 0 emits a
    91	// trailing "table <id>" so the route is installed into that kernel
    92	// table instead of the default one — this is how `instance-type
    93	// forwarding` routing instances render: no VRF device exists, but
    94	// their routes belong in the instance's dedicated table (the same
    95	// table the FBF/PBR `ip rule`s point at and the same table the
    96	// userspace dataplane files under `<ri>.inet.0`). vrfName and tableID
    97	// are mutually exclusive: FRR only accepts `table` on default-VRF
    98	// statics, and forwarding instances always render with vrfName == "".
    99	func (m *Manager) generateStaticRouteInTable(sr *config.StaticRoute, vrfName string, tableID int, rethMap map[string]string, ipv6NextHopInterfaces map[string]map[string]string) string {
   100		if sr.NextTable != "" {
   101			return "" // handled via ip rule in routing package
   102		}
   103		isV6 := strings.Contains(sr.Destination, ":")
   104		prefix := "ip"
   105		if isV6 {
   106			prefix = "ipv6"
   107		}
   108	
   109		vrfPart := ""
   110		if vrfName != "" {
   111			vrfPart = " vrf " + vrfName
   112		} else if tableID > 0 {
   113			vrfPart = fmt.Sprintf(" table %d", tableID)
   114		}
   115	
   116		// Discard or no next-hops: single Null0 line.
   117		if sr.Discard || len(sr.NextHops) == 0 {
   118			nexthop := "Null0"
   119			if sr.Preference > 0 {
   120				return fmt.Sprintf("%s route %s %s %d%s\n", prefix, sr.Destination, nexthop, sr.Preference, vrfPart)
   121			}
   122			return fmt.Sprintf("%s route %s %s%s\n", prefix, sr.Destination, nexthop, vrfPart)
   123		}
   124	
   125		// One line per next-hop → FRR creates ECMP.
   126		var b strings.Builder
   127		for _, nh := range sr.NextHops {
   128			// Strip Junos default unit suffix ".0" (e.g. "wan0.0" → "wan0") for FRR
   129			// kernel names. VLAN suffixes like ".50" in "wan0.50" are real kernel
   130			// interface names and must NOT be stripped.
   131			ifName := nh.Interface
   132			if isV6 && ifName == "" && nh.Address != "" {
   133				ifName = ipv6NextHopInterfaces[vrfName][nh.Address]
   134			}
   135			if strings.HasSuffix(ifName, ".0") {
   136				ifName = ifName[:len(ifName)-2]
   137			}
   138			// Resolve RETH names to physical member names (e.g. "reth0.50" → "ge-0-0-1.50").
   139			// FRR needs kernel interface names, not Junos RETH names.
   140			if len(rethMap) > 0 && ifName != "" {
   141				parts := strings.SplitN(ifName, ".", 2)
   142				if phys, ok := rethMap[parts[0]]; ok {
   143					phys = config.LinuxIfName(phys)
   144					if len(parts) == 2 {
   145						ifName = phys + "." + parts[1]

 succeeded in 0ms:
pkg/config/types_routing.go:75:	InterfaceRoutesRibGroup   string // global interface-routes { rib-group inet <name>; }
pkg/config/types_routing.go:76:	InterfaceRoutesRibGroupV6 string // global interface-routes { rib-group inet6 <name>; }
pkg/config/types_routing.go:96:	Interface string // outgoing interface (for IPv6 link-local)
pkg/config/types_routing.go:102:	NextHops    []NextHopEntry // multiple next-hops = ECMP
pkg/config/types_routing.go:115:	RouterAdvertisement []*RAInterfaceConfig
pkg/config/types_routing.go:121:	Interfaces     []LLDPInterface // interfaces to enable LLDP on
pkg/config/types_routing.go:127:// LLDPInterface holds per-interface LLDP configuration.
pkg/config/types_routing.go:128:type LLDPInterface struct {
pkg/config/types_routing.go:143:	Interfaces []*OSPFv3Interface
pkg/config/types_routing.go:146:// OSPFv3Interface defines an interface participating in OSPFv3.
pkg/config/types_routing.go:147:type OSPFv3Interface struct {
pkg/config/types_routing.go:155:	Interfaces   []string // interfaces participating in RIP
pkg/config/types_routing.go:166:	Interfaces      []*ISISInterface
pkg/config/types_routing.go:174:// ISISInterface defines an interface participating in IS-IS.
pkg/config/types_routing.go:175:type ISISInterface struct {
pkg/config/types_routing.go:187:// RAInterfaceConfig configures Router Advertisement on an interface.
pkg/config/types_routing.go:188:type RAInterfaceConfig struct {
pkg/config/types_routing.go:189:	Interface       string
pkg/config/types_routing.go:227:	Interfaces   []*OSPFInterface
pkg/config/types_routing.go:237:// OSPFInterface defines an interface participating in OSPF.
pkg/config/types_routing.go:238:type OSPFInterface struct {
pkg/config/types_routing.go:362:	Interfaces                []string       // interfaces belonging to this instance
pkg/config/types_routing.go:371:	InterfaceRoutesRibGroup   string         // interface-routes { rib-group inet <name>; }
pkg/config/types_routing.go:372:	InterfaceRoutesRibGroupV6 string         // interface-routes { rib-group inet6 <name>; }
pkg/frr/config_render.go:3://   - generateInterfaceSettings: per-interface bandwidth + point-to-point hints
pkg/frr/config_render.go:25:// generateInterfaceSettings emits FRR interface blocks for bandwidth and
pkg/frr/config_render.go:28:func (m *Manager) generateInterfaceSettings(fc *FullConfig) string {
pkg/frr/config_render.go:29:	if len(fc.InterfaceBandwidths) == 0 && len(fc.InterfacePointToPoint) == 0 {
pkg/frr/config_render.go:37:			for _, iface := range area.Interfaces {
pkg/frr/config_render.go:47:	for name := range fc.InterfaceBandwidths {
pkg/frr/config_render.go:50:	for name := range fc.InterfacePointToPoint {
pkg/frr/config_render.go:51:		if fc.InterfacePointToPoint[name] && !ospfNetworkType[name] {
pkg/frr/config_render.go:66:		if bw, ok := fc.InterfaceBandwidths[name]; ok && bw > 0 {
pkg/frr/config_render.go:74:		if fc.InterfacePointToPoint[name] && !ospfNetworkType[name] {
pkg/frr/config_render.go:85:func (m *Manager) generateStaticRoute(sr *config.StaticRoute, vrfName string, rethMap map[string]string, ipv6NextHopInterfaces map[string]map[string]string) string {
pkg/frr/config_render.go:86:	return m.generateStaticRouteInTable(sr, vrfName, 0, rethMap, ipv6NextHopInterfaces)
pkg/frr/config_render.go:99:func (m *Manager) generateStaticRouteInTable(sr *config.StaticRoute, vrfName string, tableID int, rethMap map[string]string, ipv6NextHopInterfaces map[string]map[string]string) string {
pkg/frr/config_render.go:117:	if sr.Discard || len(sr.NextHops) == 0 {
pkg/frr/config_render.go:127:	for _, nh := range sr.NextHops {
pkg/frr/config_render.go:131:		ifName := nh.Interface
pkg/frr/config_render.go:133:			ifName = ipv6NextHopInterfaces[vrfName][nh.Address]
pkg/frr/config_render.go:220:			if dr.Interface != "" {
pkg/frr/config_render.go:221:				fmt.Fprintf(b, "ipv6 route ::/0 %s %s 200\n", dr.Gateway, dr.Interface)
pkg/frr/config_render.go:286:			NextHops:    []config.NextHopEntry{{Address: entry.NextHop}},
pkg/frr/config_render.go:288:		b.WriteString(m.generateStaticRouteInTable(sr, vrfName, tableID, fc.RethMap, fc.IPv6NextHopInterfaces))

exec
/bin/bash -lc "rg -n \"type StaticRoute|type NextHopEntry|StaticRoutes|NextHopEntry\" pkg/config/types_routing.go pkg/config -g'*.go' | head -n 120" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/config/types_routing.go:69:	StaticRoutes              []*StaticRoute
pkg/config/types_routing.go:70:	Inet6StaticRoutes         []*StaticRoute // rib inet6.0 static routes
pkg/config/types_routing.go:93:// NextHopEntry defines a single next-hop for a static route.
pkg/config/types_routing.go:94:type NextHopEntry struct {
pkg/config/types_routing.go:100:type StaticRoute struct {
pkg/config/types_routing.go:102:	NextHops    []NextHopEntry // multiple next-hops = ECMP
pkg/config/types_routing.go:363:	StaticRoutes              []*StaticRoute // per-instance static routes
pkg/config/types_routing.go:364:	Inet6StaticRoutes         []*StaticRoute // per-instance rib inet6.0 static routes
pkg/config/parser_ast_test.go:2303:	if len(dmzVR.StaticRoutes) != 1 {
pkg/config/parser_ast_test.go:2304:		t.Fatalf("dmz-vr StaticRoutes = %d, want 1", len(dmzVR.StaticRoutes))
pkg/config/parser_ast_test.go:2306:	if dmzVR.StaticRoutes[0].Destination != "0.0.0.0/0" {
pkg/config/parser_ast_test.go:2307:		t.Errorf("dmz-vr route destination = %q, want 0.0.0.0/0", dmzVR.StaticRoutes[0].Destination)
pkg/config/compiler_routing.go:32:				ro.Inet6StaticRoutes = compileStaticRoutes(ribStatic, ro.Inet6StaticRoutes)
pkg/config/compiler_routing.go:39:		ro.StaticRoutes = compileStaticRoutes(staticNode, ro.StaticRoutes)
pkg/config/compiler_routing.go:141:// compileStaticRoutes parses static route entries from a "static" node,
pkg/config/compiler_routing.go:143:func compileStaticRoutes(staticNode *Node, existing []*StaticRoute) []*StaticRoute {
pkg/config/compiler_routing.go:163:						route.NextHops = append(route.NextHops, NextHopEntry{Address: routeInst.node.Keys[i]})
pkg/config/compiler_routing.go:173:						nh := NextHopEntry{Address: routeInst.node.Keys[i]}
pkg/config/compiler_routing.go:198:				nh := NextHopEntry{}
pkg/config/compiler_routing.go:223:				nh := NextHopEntry{}
pkg/config/compiler_routing.go:304:				ri.StaticRoutes = ro.StaticRoutes
pkg/config/compiler_routing.go:305:				ri.Inet6StaticRoutes = ro.Inet6StaticRoutes
pkg/config/compiler_routing_rules_test.go:31:		cfg.RoutingOptions.StaticRoutes = mkNextTableRoutes(100)
pkg/config/compiler_routing_rules_test.go:41:		cfg.RoutingOptions.StaticRoutes = mkNextTableRoutes(60)
pkg/config/compiler_routing_rules_test.go:42:		cfg.RoutingOptions.Inet6StaticRoutes = mkNextTableRoutes(41)
pkg/config/compiler_routing_rules_test.go:104:		cfg.RoutingOptions.StaticRoutes = append(cfg.RoutingOptions.StaticRoutes,
pkg/config/fbf_fixture_test.go:59:	if len(fbf.StaticRoutes) != 1 || len(fbf.Inet6StaticRoutes) != 1 {
pkg/config/fbf_fixture_test.go:61:			fbf.StaticRoutes, fbf.Inet6StaticRoutes)
pkg/config/types_routing.go:69:	StaticRoutes              []*StaticRoute
pkg/config/types_routing.go:70:	Inet6StaticRoutes         []*StaticRoute // rib inet6.0 static routes
pkg/config/types_routing.go:93:// NextHopEntry defines a single next-hop for a static route.
pkg/config/types_routing.go:94:type NextHopEntry struct {
pkg/config/types_routing.go:100:type StaticRoute struct {
pkg/config/types_routing.go:102:	NextHops    []NextHopEntry // multiple next-hops = ECMP
pkg/config/types_routing.go:363:	StaticRoutes              []*StaticRoute // per-instance static routes
pkg/config/types_routing.go:364:	Inet6StaticRoutes         []*StaticRoute // per-instance rib inet6.0 static routes
pkg/config/parser_fbf_test.go:38:	if len(fbf.StaticRoutes) != 1 || fbf.StaticRoutes[0].Destination != "0.0.0.0/0" ||
pkg/config/parser_fbf_test.go:39:		len(fbf.StaticRoutes[0].NextHops) != 1 || fbf.StaticRoutes[0].NextHops[0].Address != "172.16.80.1" {
pkg/config/parser_fbf_test.go:40:		t.Fatalf("ISP-B statics = %+v, want single 0.0.0.0/0 via 172.16.80.1", fbf.StaticRoutes)
pkg/config/compiler.go:845:	for _, sr := range cfg.RoutingOptions.StaticRoutes {
pkg/config/compiler.go:1300:	for _, sr := range cfg.RoutingOptions.StaticRoutes {
pkg/config/compiler.go:1305:	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
pkg/config/parser_routing_test.go:26:	if len(cfg.RoutingOptions.StaticRoutes) != 4 {
pkg/config/parser_routing_test.go:27:		t.Fatalf("expected 4 static routes, got %d", len(cfg.RoutingOptions.StaticRoutes))
pkg/config/parser_routing_test.go:29:	r0 := cfg.RoutingOptions.StaticRoutes[0]
pkg/config/parser_routing_test.go:36:	r2 := cfg.RoutingOptions.StaticRoutes[2]
pkg/config/parser_routing_test.go:40:	r3 := cfg.RoutingOptions.StaticRoutes[3]
pkg/config/parser_routing_test.go:148:	if len(cfg2.RoutingOptions.StaticRoutes) != len(cfg.RoutingOptions.StaticRoutes) {
pkg/config/parser_routing_test.go:159:func TestECMPStaticRoutes(t *testing.T) {
pkg/config/parser_routing_test.go:172:	if len(cfg.RoutingOptions.StaticRoutes) != 2 {
pkg/config/parser_routing_test.go:173:		t.Fatalf("expected 2 routes, got %d", len(cfg.RoutingOptions.StaticRoutes))
pkg/config/parser_routing_test.go:175:	r0 := cfg.RoutingOptions.StaticRoutes[0]
pkg/config/parser_routing_test.go:185:	r1 := cfg.RoutingOptions.StaticRoutes[1]
pkg/config/parser_routing_test.go:207:	if len(hierCfg.RoutingOptions.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:208:		t.Fatalf("expected 1 route, got %d", len(hierCfg.RoutingOptions.StaticRoutes))
pkg/config/parser_routing_test.go:210:	hr := hierCfg.RoutingOptions.StaticRoutes[0]
pkg/config/parser_routing_test.go:219:func TestNextTableStaticRoutes(t *testing.T) {
pkg/config/parser_routing_test.go:232:	if len(cfg.RoutingOptions.StaticRoutes) != 2 {
pkg/config/parser_routing_test.go:233:		t.Fatalf("expected 2 routes, got %d", len(cfg.RoutingOptions.StaticRoutes))
pkg/config/parser_routing_test.go:235:	r0 := cfg.RoutingOptions.StaticRoutes[0]
pkg/config/parser_routing_test.go:245:	r1 := cfg.RoutingOptions.StaticRoutes[1]
pkg/config/parser_routing_test.go:273:	if len(hierCfg.RoutingOptions.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:274:		t.Fatalf("expected 1 inet route, got %d", len(hierCfg.RoutingOptions.StaticRoutes))
pkg/config/parser_routing_test.go:276:	if hierCfg.RoutingOptions.StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
pkg/config/parser_routing_test.go:277:		t.Errorf("inet next-table: got %q", hierCfg.RoutingOptions.StaticRoutes[0].NextTable)
pkg/config/parser_routing_test.go:279:	if len(hierCfg.RoutingOptions.Inet6StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:280:		t.Fatalf("expected 1 inet6 route, got %d", len(hierCfg.RoutingOptions.Inet6StaticRoutes))
pkg/config/parser_routing_test.go:282:	if hierCfg.RoutingOptions.Inet6StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
pkg/config/parser_routing_test.go:283:		t.Errorf("inet6 next-table: got %q", hierCfg.RoutingOptions.Inet6StaticRoutes[0].NextTable)
pkg/config/parser_routing_test.go:442:	if len(comcast.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:443:		t.Fatalf("Comcast static routes: expected 1, got %d", len(comcast.StaticRoutes))
pkg/config/parser_routing_test.go:445:	if len(comcast.StaticRoutes[0].NextHops) != 1 || comcast.StaticRoutes[0].NextHops[0].Address != "74.93.96.1" {
pkg/config/parser_routing_test.go:446:		t.Errorf("Comcast route next-hops: %v", comcast.StaticRoutes[0].NextHops)
pkg/config/parser_routing_test.go:448:	if comcast.StaticRoutes[0].Preference != 10 {
pkg/config/parser_routing_test.go:449:		t.Errorf("Comcast route preference: %d", comcast.StaticRoutes[0].Preference)
pkg/config/parser_routing_test.go:460:	if len(att.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:461:		t.Fatalf("ATT static routes: expected 1, got %d", len(att.StaticRoutes))
pkg/config/parser_routing_test.go:552:	if len(fwd.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:553:		t.Fatalf("vpn-fwd static routes: expected 1, got %d", len(fwd.StaticRoutes))
pkg/config/parser_routing_test.go:697:	if len(ri.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:698:		t.Fatalf("expected 1 static route, got %d", len(ri.StaticRoutes))
pkg/config/parser_routing_test.go:700:	if len(ri.StaticRoutes[0].NextHops) != 1 || ri.StaticRoutes[0].NextHops[0].Address != "10.0.2.1" {
pkg/config/parser_routing_test.go:701:		t.Errorf("next-hops: got %v, want [{10.0.2.1 }]", ri.StaticRoutes[0].NextHops)
pkg/config/parser_routing_test.go:986:	if len(ro.StaticRoutes) != 2 {
pkg/config/parser_routing_test.go:987:		t.Fatalf("got %d static routes, want 2", len(ro.StaticRoutes))
pkg/config/parser_routing_test.go:989:	if len(ro.Inet6StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:990:		t.Fatalf("got %d inet6 static routes, want 1", len(ro.Inet6StaticRoutes))
pkg/config/parser_routing_test.go:992:	v6 := ro.Inet6StaticRoutes[0]
pkg/config/parser_routing_test.go:2482:func TestIPv6NextTableStaticRoutes(t *testing.T) {
pkg/config/parser_routing_test.go:2496:	if len(cfg.RoutingOptions.Inet6StaticRoutes) != 2 {
pkg/config/parser_routing_test.go:2497:		t.Fatalf("Inet6StaticRoutes = %d, want 2", len(cfg.RoutingOptions.Inet6StaticRoutes))
pkg/config/parser_routing_test.go:2499:	r0 := cfg.RoutingOptions.Inet6StaticRoutes[0]
pkg/config/parser_routing_test.go:2506:	r1 := cfg.RoutingOptions.Inet6StaticRoutes[1]
pkg/config/parser_routing_test.go:2510:	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:2511:		t.Fatalf("StaticRoutes = %d, want 1", len(cfg.RoutingOptions.StaticRoutes))
pkg/config/parser_routing_test.go:2513:	if cfg.RoutingOptions.StaticRoutes[0].NextTable != "Comcast-GigabitPro" {
pkg/config/parser_routing_test.go:2514:		t.Errorf("v4 route next-table = %q", cfg.RoutingOptions.StaticRoutes[0].NextTable)
pkg/config/parser_routing_test.go:3152:	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:3153:		t.Fatalf("got %d static routes, want 1", len(cfg.RoutingOptions.StaticRoutes))
pkg/config/parser_routing_test.go:3155:	sr := cfg.RoutingOptions.StaticRoutes[0]
pkg/config/parser_routing_test.go:3192:	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:3193:		t.Fatalf("got %d static routes, want 1", len(cfg.RoutingOptions.StaticRoutes))
pkg/config/parser_routing_test.go:3195:	sr := cfg.RoutingOptions.StaticRoutes[0]
pkg/config/parser_routing_test.go:3231:	if len(ri.Inet6StaticRoutes) != 1 {
pkg/config/parser_routing_test.go:3232:		t.Fatalf("got %d inet6 static routes, want 1", len(ri.Inet6StaticRoutes))
pkg/config/parser_routing_test.go:3234:	sr := ri.Inet6StaticRoutes[0]

exec
/bin/bash -lc "nl -ba pkg/config/types_routing.go | sed -n '1,90p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	package config
     2	
     3	import "fmt"
     4	
     5	// Routing: routing-options, policy-options, dynamic protocols
     6	// (OSPF/OSPFv3/BGP/RIP/IS-IS/LLDP), router advertisement, tunnels, and
     7	// VRF routing instances.
     8	
     9	// PolicyOptionsConfig holds prefix-lists, communities, as-paths, and policy-statements for routing control.
    10	type PolicyOptionsConfig struct {
    11		PrefixLists      map[string]*PrefixList
    12		Communities      map[string]*CommunityDef
    13		ASPaths          map[string]*ASPathDef
    14		PolicyStatements map[string]*PolicyStatement
    15	}
    16	
    17	// ASPathDef defines a named AS-path regular expression for route matching.
    18	type ASPathDef struct {
    19		Name  string
    20		Regex string // AS-path regex pattern (e.g. "65000", "65[0-9]+")
    21	}
    22	
    23	// CommunityDef defines a named BGP community with member values.
    24	type CommunityDef struct {
    25		Name    string
    26		Members []string // e.g. "65000:100", "no-export", "no-advertise"
    27	}
    28	
    29	// PrefixList defines a named list of IP prefixes.
    30	type PrefixList struct {
    31		Name     string
    32		Prefixes []string // CIDR entries ("10.0.0.0/8", "2001:db8::/32")
    33	}
    34	
    35	// PolicyStatement defines a routing policy with terms.
    36	type PolicyStatement struct {
    37		Name          string
    38		Terms         []*PolicyTerm
    39		DefaultAction string // "accept", "reject", or "" (implicit reject)
    40	}
    41	
    42	// PolicyTerm is a single match+action clause within a policy-statement.
    43	type PolicyTerm struct {
    44		Name            string
    45		FromProtocol    string         // "direct", "static", "bgp", "ospf"
    46		PrefixList      string         // from prefix-list <name>
    47		FromCommunity   string         // from community <name> (match against community-list)
    48		FromASPath      string         // from as-path <name> (match against as-path access-list)
    49		RouteFilters    []*RouteFilter // prefix matching
    50		Action          string         // "accept", "reject"
    51		NextHop         string         // then next-hop (e.g. "peer-address", "self", IP)
    52		LoadBalance     string         // then load-balance (e.g. "consistent-hash", "per-packet")
    53		LocalPreference int            // BGP local-preference (0 = not set)
    54		Metric          int            // BGP MED/metric (0 = not set)
    55		MetricType      int            // OSPF metric type (1 or 2, 0 = not set)
    56		Community       string         // BGP community to set (e.g. "65000:100")
    57		Origin          string         // BGP origin: "igp", "egp", "incomplete"
    58	}
    59	
    60	// RouteFilter matches a prefix with a match type.
    61	type RouteFilter struct {
    62		Prefix    string // CIDR ("192.168.50.0/24")
    63		MatchType string // "exact", "longer", "orlonger", "upto"
    64		UptoLen   int    // for "upto" match type
    65	}
    66	
    67	// RoutingOptionsConfig holds static routing configuration.
    68	type RoutingOptionsConfig struct {
    69		StaticRoutes              []*StaticRoute
    70		Inet6StaticRoutes         []*StaticRoute // rib inet6.0 static routes
    71		GenerateRoutes            []*GenerateRoute
    72		ForwardingTableExport     string // forwarding-table { export <policy>; }
    73		AutonomousSystem          uint32 // autonomous-system <number>
    74		RibGroups                 map[string]*RibGroup
    75		InterfaceRoutesRibGroup   string // global interface-routes { rib-group inet <name>; }
    76		InterfaceRoutesRibGroupV6 string // global interface-routes { rib-group inet6 <name>; }
    77	}
    78	
    79	// GenerateRoute defines a Junos generate (aggregate) route.
    80	// In FRR, these become blackhole/reject static routes or BGP aggregate-address.
    81	type GenerateRoute struct {
    82		Prefix  string // route prefix (e.g. "192.168.0.0/16")
    83		Policy  string // contributing route policy (optional)
    84		Discard bool   // discard traffic to this route (blackhole)
    85	}
    86	
    87	// RibGroup defines a RIB group for route sharing between routing instances.
    88	type RibGroup struct {
    89		Name       string
    90		ImportRibs []string // import-rib [ rib1 rib2 ... ]

exec
/bin/bash -lc "nl -ba pkg/frr/config_render.go | sed -n '145,190p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
exec
/bin/bash -lc "nl -ba pkg/frr/frr_test.go | sed -n '92,108p;1058,1070p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   145						ifName = phys + "." + parts[1]
   146					} else {
   147						ifName = phys
   148					}
   149				}
   150			}
   151	
   152			var nexthop string
   153			switch {
   154			case nh.Address != "" && ifName != "":
   155				nexthop = nh.Address + " " + ifName
   156			case nh.Address != "":
   157				nexthop = nh.Address
   158			case ifName != "":
   159				nexthop = ifName
   160			default:
   161				continue
   162			}
   163			if sr.Preference > 0 {
   164				fmt.Fprintf(&b, "%s route %s %s %d%s\n", prefix, sr.Destination, nexthop, sr.Preference, vrfPart)
   165			} else {
   166				fmt.Fprintf(&b, "%s route %s %s%s\n", prefix, sr.Destination, nexthop, vrfPart)
   167			}
   168		}
   169		return b.String()
   170	}
   171	
   172	// renderGenerateRoutes emits one blackhole static route per generate-route
   173	// (Junos `routing-options generate route X`). v4 vs v6 is picked by the
   174	// presence of ":" in the prefix.
   175	func renderGenerateRoutes(b *strings.Builder, fc *FullConfig) {
   176		if len(fc.GenerateRoutes) == 0 {
   177			return
   178		}
   179		for _, gr := range fc.GenerateRoutes {
   180			if strings.Contains(gr.Prefix, ":") {
   181				fmt.Fprintf(b, "ipv6 route %s blackhole\n", gr.Prefix)
   182			} else {
   183				fmt.Fprintf(b, "ip route %s blackhole\n", gr.Prefix)
   184			}
   185		}
   186		b.WriteString("!\n")
   187	}
   188	
   189	// renderDHCPDefaults emits DHCP-learned default routes at admin distance 200.
   190	// Suppressed when an explicit static default route exists for the same

 succeeded in 0ms:
    92			t.Errorf("got %q, want %q", got, want)
    93		}
    94	}
    95	
    96	func TestGenerateStaticRoute_InterfaceOnly(t *testing.T) {
    97		m := New()
    98		sr := &config.StaticRoute{
    99			Destination: "10.0.0.0/8",
   100			NextHops:    []config.NextHopEntry{{Interface: "tunnel0"}},
   101		}
   102		got := m.generateStaticRoute(sr, "", nil, nil)
   103		want := "ip route 10.0.0.0/8 tunnel0\n"
   104		if got != want {
   105			t.Errorf("got %q, want %q", got, want)
   106		}
   107	}
   108	
  1058	}
  1059	
  1060	func TestGenerateStaticRoute_UnitSuffixStripped(t *testing.T) {
  1061		m := New()
  1062		sr := &config.StaticRoute{
  1063			Destination: "10.0.0.0/8",
  1064			NextHops:    []config.NextHopEntry{{Interface: "tunnel0.0"}},
  1065		}
  1066		got := m.generateStaticRoute(sr, "", nil, nil)
  1067		want := "ip route 10.0.0.0/8 tunnel0\n"
  1068		if got != want {
  1069			t.Errorf("got %q, want %q", got, want)
  1070		}

exec
/bin/bash -lc "nl -ba pkg/config/types_routing.go | sed -n '90,112p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
    90		ImportRibs []string // import-rib [ rib1 rib2 ... ]
    91	}
    92	
    93	// NextHopEntry defines a single next-hop for a static route.
    94	type NextHopEntry struct {
    95		Address   string // IP address (e.g. "10.0.1.1" or "fe80::1")
    96		Interface string // outgoing interface (for IPv6 link-local)
    97	}
    98	
    99	// StaticRoute defines a single static route.
   100	type StaticRoute struct {
   101		Destination string         // CIDR: "10.0.0.0/8" or "::/0"
   102		NextHops    []NextHopEntry // multiple next-hops = ECMP
   103		Discard     bool           // null route (blackhole)
   104		Preference  int            // route preference (admin distance), default 5
   105		NextTable   string         // routing instance name for inter-VRF route leaking (e.g. "Comcast.inet.0" → "Comcast")
   106	}
   107	
   108	// ProtocolsConfig holds dynamic routing protocol configuration.
   109	type ProtocolsConfig struct {
   110		OSPF                *OSPFConfig
   111		OSPFv3              *OSPFv3Config
   112		BGP                 *BGPConfig

exec
/bin/bash -lc "rg -n \"interface-routes|InterfaceRoutesRibGroup|connected route|ConnectedRoute|tunnel_endpoint_id|direct\" pkg/frr pkg/daemon pkg/routing userspace-dp/src/afxdp -g'*.go' -g'*.rs' | head -n 220" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/frr/vtysh.go:50:// frrExecutor is the package-private indirection that all vtysh and
pkg/frr/vtysh.go:103:// kills only the direct python process, which could leave a child
pkg/routing/routes.go:115:		// Treat as VRF name directly (backwards compat).
pkg/routing/routes.go:189:		entry.NextHop = "direct"
pkg/routing/routes.go:209:		return "redirect"
userspace-dp/src/afxdp/session_delta.rs:95:                ForwardingDisposition::FabricRedirect => "fabric_redirect",
userspace-dp/src/afxdp/session_delta.rs:104:            tunnel_endpoint_id: delta.decision.resolution.tunnel_endpoint_id,
userspace-dp/src/afxdp/session_delta.rs:138:            fabric_redirect: delta.fabric_redirect_sync
userspace-dp/src/afxdp/session_delta.rs:139:                || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
pkg/frr/manager.go:296:	// zone-encoded fabric redirect for new connections.  The real default
pkg/frr/manager.go:388:	// 6. Cluster mode: blackhole default route as fallback for fabric redirect.
pkg/frr/manager.go:537:	// Write atomically: a temp file in the same directory followed by rename,
pkg/frr/manager.go:563:// parent-directory fsync that was missing here, making the rename
pkg/frr/manager.go:640://     the slow cadence directly.
userspace-dp/src/afxdp/shared_ops.rs:31:/// publishes a fabric-redirect session TWICE — canonical forward key plus
userspace-dp/src/afxdp/shared_ops.rs:34:/// queued under `delta.FabricRedirect && !delta.FabricIngress`). Both
userspace-dp/src/afxdp/shared_ops.rs:65:    //   genuine NAT-vs-different-NAT (and NAT-vs-no-NAT direct)
userspace-dp/src/afxdp/shared_ops.rs:67:    //   (Codex code-r2: DNAT client->VIP=>backend vs direct
userspace-dp/src/afxdp/shared_ops.rs:603:        || forward_match.decision.resolution.disposition == ForwardingDisposition::FabricRedirect;
userspace-dp/src/afxdp/shared_ops.rs:612:        forward_match.decision.resolution.tunnel_endpoint_id != 0
userspace-dp/src/afxdp/shared_ops.rs:622:        // from prior FabricRedirect results.
userspace-dp/src/afxdp/shared_ops.rs:629:        resolution: redirect_session_resolution_for_metadata(forwarding, resolution, &metadata),
userspace-dp/src/afxdp/shared_ops.rs:695:        && let Some(redirect) =
userspace-dp/src/afxdp/shared_ops.rs:696:            super::forwarding::resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone)
userspace-dp/src/afxdp/shared_ops.rs:698:        return redirect;
pkg/routing/tunnel_keepalive.go:97:// when source==""). Indirection point for tests of the production
pkg/frr/policy_render.go:77:					if proto == "direct" {
pkg/frr/policy_render.go:152:				// instance (#1712). passive-interface directives are
pkg/frr/policy_render.go:643:				if proto == "direct" {
userspace-dp/src/afxdp/ha.rs:123:        // entries and restoring any redirect aliases that were removed during
userspace-dp/src/afxdp/ha.rs:270:        // ownership guard so XSK redirect state cannot get ahead of what
userspace-dp/src/afxdp/ha.rs:395:    /// #1873 R-D: purge every session whose stored tunnel_endpoint_id
userspace-dp/src/afxdp/ha.rs:420:                let id = entry.decision.resolution.tunnel_endpoint_id;
userspace-dp/src/afxdp/ha.rs:443:                        fabric_redirect_sync: false,
userspace-dp/src/afxdp/ha.rs:516:                ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/ha.rs:527:                fabric_redirect_sync: true,
pkg/frr/config_render.go:297:// fabric redirect for new connections. AD=250 ensures real defaults (AD=5,
pkg/routing/rules.go:47:// with next-table directives. This implements inter-VRF route leaking:
pkg/routing/rules.go:143:// leaking. When a routing instance has interface-routes with a rib-group
pkg/routing/rules.go:147:// Both IPv4 (InterfaceRoutesRibGroup) and IPv6 (InterfaceRoutesRibGroupV6)
pkg/routing/rules.go:151:// For example, if dmz-vr (table 101) has interface-routes rib-group "dmz-leak",
pkg/routing/rules.go:179:		rgNames := []string{inst.InterfaceRoutesRibGroup, inst.InterfaceRoutesRibGroupV6}
pkg/routing/rules.go:189:				slog.Warn("interface-routes references unknown rib-group",
userspace-dp/src/afxdp/types/tx.rs:27:    /// (`enqueue_cos_item`). 0 means "never CoS-enqueued" (direct TX
pkg/frr/status_parse.go:276:	DirectlyConnected bool   `json:"directlyConnected"`
pkg/frr/status_parse.go:362:				fmt.Fprintf(&b, "    Next-hop: directly connected via %s\n", nh.Interface)
userspace-dp/src/afxdp/ha_tests.rs:123:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/ha_tests.rs:162:    forwarding.connected_v4.push(ConnectedRouteV4 {
userspace-dp/src/afxdp/ha_tests.rs:165:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/tunnel.rs:29:/// directions — the fd is genuinely dead (anchor deleted/recreated).
userspace-dp/src/afxdp/tunnel.rs:104:    tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/tunnel.rs:108:    let Some(endpoint) = forwarding.tunnel_endpoints.get(&tunnel_endpoint_id) else {
userspace-dp/src/afxdp/tunnel.rs:123:    tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/tunnel.rs:167:        tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:178:                tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:211:                        tunnel_endpoint_id
userspace-dp/src/afxdp/tunnel.rs:218:                    tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:262:                            tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:288:    tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/tunnel.rs:309:            tunnel_endpoint_id,
userspace-dp/src/afxdp/tunnel.rs:325:    // #921: zone_id is now a u16 field on EgressInterface — direct
userspace-dp/src/afxdp/types/forwarding.rs:19:    pub(in crate::afxdp) connected_v4: Vec<ConnectedRouteV4>,
userspace-dp/src/afxdp/types/forwarding.rs:20:    pub(in crate::afxdp) connected_v6: Vec<ConnectedRouteV6>,
userspace-dp/src/afxdp/types/forwarding.rs:25:    /// WireGuard engines keyed by tunnel_endpoint_id (#1432 S2a). One
userspace-dp/src/afxdp/types/forwarding.rs:41:    /// read u16 directly; slow-path display sites translate via
userspace-dp/src/afxdp/types/forwarding.rs:93:    /// #1635: direct `(from_zone_id, to_zone_id) → slot` map for the
userspace-dp/src/afxdp/types/forwarding.rs:109:pub(in crate::afxdp) struct ConnectedRouteV4 {
userspace-dp/src/afxdp/types/forwarding.rs:112:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:116:pub(in crate::afxdp) struct ConnectedRouteV6 {
userspace-dp/src/afxdp/types/forwarding.rs:119:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:126:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:136:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:245:    FabricRedirect,
userspace-dp/src/afxdp/types/forwarding.rs:261:    ///   - `FabricRedirect`: Targets a fabric overlay binding. Cacheable
userspace-dp/src/afxdp/types/forwarding.rs:268:    ///     in which a cached `FabricRedirect` could point at a stale
userspace-dp/src/afxdp/types/forwarding.rs:289:            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/types/forwarding.rs:322:    ///   - `ForwardCandidate` / `FabricRedirect`: handled by the forward /
userspace-dp/src/afxdp/types/forwarding.rs:324:    ///     unfiltered `_from_frame` callers — the FabricRedirect-Owned
userspace-dp/src/afxdp/types/forwarding.rs:346:    pub(crate) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:363:                ForwardingDisposition::FabricRedirect => "fabric_redirect",
pkg/routing/routing_test.go:573:		{Name: "tunnel-vr", TableID: 100, InterfaceRoutesRibGroup: "self-only"},
pkg/routing/routing_test.go:574:		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
pkg/routing/routing_test.go:957:	// which is independently constructible — exercise it directly
pkg/routing/routing_test.go:968:	// Set some state directly
pkg/routing/routing_test.go:1058:		{Name: "Comcast-BCI", TableID: 100, InterfaceRoutesRibGroup: "Other-ISPS"},
pkg/routing/routing_test.go:1059:		{Name: "ATT", TableID: 101, InterfaceRoutesRibGroup: "Other-ISPS"},
pkg/routing/routing_test.go:1060:		{Name: "Atherton-Fiber", TableID: 102, InterfaceRoutesRibGroup: "Other-ISPS"},
pkg/routing/routing_test.go:1061:		{Name: "Other-GigabitPro", TableID: 103, InterfaceRoutesRibGroup: "Other-ISPS"},
pkg/routing/routing_test.go:1062:		{Name: "bv-firehouse-vpn", TableID: 104, InterfaceRoutesRibGroup: "Other-ISPS"},
pkg/routing/routing_test.go:1063:		{Name: "Comcast-GigabitPro", TableID: 105, InterfaceRoutesRibGroup: "Other-ISPS"},
pkg/routing/routing_test.go:1064:		{Name: "sfmix", TableID: 106, InterfaceRoutesRibGroup: "Other-ISPS"},
pkg/routing/routing_test.go:1075:		rg := ribGroups[inst.InterfaceRoutesRibGroup]
pkg/routing/routing_test.go:1090:	// Test that instances with only InterfaceRoutesRibGroupV6 are also detected
pkg/routing/routing_test.go:1099:		{Name: "vpn-vr", TableID: 100, InterfaceRoutesRibGroupV6: "v6-leak"},
pkg/routing/routing_test.go:1106:	rgName := inst.InterfaceRoutesRibGroupV6
userspace-dp/src/afxdp/bind.rs:96:/// fill/completion ring structs directly. Shared UMEM sockets own
pkg/daemon/legacy_dataplane_canary_synthetic_test.go:20:// so the production canary's directory walk does not see this
userspace-dp/src/afxdp/mod.rs:96:// session_glue is a directory module (afxdp/session_glue/{mod.rs, tests.rs}),
userspace-dp/src/afxdp/mod.rs:211:// raising to 16) because the latency goal of #920 directly
userspace-dp/src/afxdp/mod.rs:276: * recycles). The cost is one memcpy per redirected packet.
userspace-dp/src/afxdp/mod.rs:279: * with cpumap redirect (USERSPACE_CPUMAP), which frees the XSK frame
userspace-dp/src/afxdp/mod.rs:300:/// this period, heartbeat is written and the XDP shim redirects to XSK.
pkg/routing/tunnel.go:184:	// manager successfully bound — or directly OBSERVED as the link's
pkg/routing/tunnel.go:194:// directly-constructed managers (tests, façade) need no constructor
pkg/routing/tunnel.go:789:// from a SUCCESSFUL BindInterfaceToVRF or a direct observation of the
userspace-dp/src/afxdp/types/cos.rs:86:/// one-directional (`my_share.min(cap)` in `acquire_v8`), and the
userspace-dp/src/afxdp/types/cos.rs:178:/// directly governs that flow's fairness: colliding flows compete for
userspace-dp/src/afxdp/types/cos.rs:740:    /// available to hot-path helpers directly from
userspace-dp/src/afxdp/types/cos.rs:938:    /// and the settle_exact_*_scratch_submission_flow_fair direct paths).
userspace-dp/src/afxdp/types/cos.rs:956:    /// observed_bps directly from inst (skip-ramp).
userspace-dp/src/afxdp/types/cos.rs:976:    /// `test_support.rs`) must use `new_boxed`, which builds directly into a
userspace-dp/src/afxdp/types/cos.rs:997:    /// #1755 — heap constructor that builds `FlowFairState` directly into a
userspace-dp/src/afxdp/types/cos.rs:1067:            // Write each `VecDeque` directly into its slot rather than via
userspace-dp/src/afxdp/types/cos.rs:1242:    /// `enqueue_ns == 0` means "never CoS-stamped" (direct-TX
userspace-dp/src/afxdp/types/cos.rs:1408:    /// (apply_direct_exact_send_result for exact-owner-local,
userspace-dp/src/afxdp/types/cos.rs:1424:    /// CoS interface still had backlog. This is the direct diagnostic
userspace-dp/src/afxdp/types/cos.rs:1436:    /// zero is a direct signal the gate never fired.
pkg/frr/frr_test.go:707:						FromProtocol: "direct",
pkg/frr/frr_test.go:1241:				"directlyConnected": true,
pkg/frr/frr_test.go:1292:		t.Error("expected directly connected")
pkg/frr/frr_test.go:1332:		"Next-hop: directly connected via trust0",
pkg/frr/frr_test.go:1840:					{Name: "t1", FromProtocol: "direct", Action: "accept", PrefixList: "internal"},
pkg/frr/frr_test.go:1846:	want := " redistribute connected route-map export-connected\n"
pkg/frr/frr_test.go:1859:					{Name: "connected", FromProtocol: "direct", Action: "accept"},
pkg/frr/frr_test.go:1867:	if !strings.Contains(got, "redistribute connected route-map export-all\n") {
pkg/frr/frr_test.go:1868:		t.Errorf("missing connected route-map in:\n%s", got)
pkg/frr/frr_test.go:1882:			"export-direct": {
pkg/frr/frr_test.go:1883:				Name: "export-direct",
pkg/frr/frr_test.go:1885:					{Name: "t1", FromProtocol: "direct", PrefixList: "trusted-nets", Action: "accept"},
pkg/frr/frr_test.go:1893:		Export:   []string{"export-direct"},
pkg/frr/frr_test.go:1899:	if !strings.Contains(got, "redistribute connected route-map export-direct\n") {
pkg/frr/frr_test.go:1902:	// Should NOT have bare "redistribute export-direct"
pkg/frr/frr_test.go:1903:	if strings.Contains(got, "redistribute export-direct\n") {
pkg/frr/frr_test.go:1915:					{Name: "connected", FromProtocol: "direct", Action: "accept"},
pkg/frr/frr_test.go:1930:	if !strings.Contains(got, "redistribute connected route-map bgp-export\n") {
pkg/frr/frr_test.go:1931:		t.Errorf("missing connected route-map, got:\n%s", got)
pkg/frr/frr_test.go:1945:					{Name: "t1", FromProtocol: "direct", Action: "accept"},
pkg/frr/frr_test.go:1959:	if !strings.Contains(got, "redistribute connected route-map filter-connected\n") {
pkg/frr/frr_test.go:2072:						FromProtocol:  "direct",
pkg/frr/frr_test.go:2280:						FromProtocol: "direct",
pkg/frr/frr_test.go:2289:						FromProtocol: "direct",
pkg/frr/frr_test.go:2348:						FromProtocol: "direct",
pkg/daemon/direct_announce_test.go:13:		directAnnounceSchedule: []time.Duration{0, 5 * time.Millisecond, 15 * time.Millisecond},
pkg/daemon/direct_announce_test.go:17:	d.directSendGARPsFn = func(rgID int) {
pkg/daemon/direct_announce_test.go:43:		directAnnounceSchedule: []time.Duration{0, 25 * time.Millisecond},
pkg/daemon/direct_announce_test.go:47:	d.directSendGARPsFn = func(rgID int) {
pkg/daemon/direct_announce_test.go:68:		directAnnounceSchedule: []time.Duration{0, 30 * time.Millisecond, 60 * time.Millisecond},
pkg/daemon/direct_announce_test.go:72:	d.directSendGARPsFn = func(rgID int) {
userspace-dp/src/afxdp/cos/ecn.rs:13:/// `cos/admission.rs::tests` reference these masks directly.
pkg/frr/manager_reload_test.go:189:// retry starts directly at the slow cadence (skipping the fast rungs).
pkg/routing/tunnel_reconcile_test.go:990:	// Drive the unbind decision directly with a TRANSIENT (plain,
userspace-dp/src/afxdp/flow_cache_tests.rs:29:        fabric_redirect: false,
userspace-dp/src/afxdp/flow_cache_tests.rs:55:        tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:438:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:517:        entry.descriptor.fabric_redirect,
userspace-dp/src/afxdp/flow_cache_tests.rs:518:        decision.resolution.disposition == ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/flow_cache_tests.rs:602:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:761:// interface direction, drive `FlowCacheEntry::from_forward_decision`,
userspace-dp/src/afxdp/flow_cache_tests.rs:952:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:1257:fn fabric_redirect_cache_entry_uses_flow_owner_rg_for_epoch_invalidation() {
userspace-dp/src/afxdp/flow_cache_tests.rs:1273:            disposition: ForwardingDisposition::FabricRedirect,
userspace-dp/src/afxdp/flow_cache_tests.rs:1277:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/flow_cache_tests.rs:1328:    .expect("fabric redirect entry");
userspace-dp/src/afxdp/flow_cache_tests.rs:1332:    assert!(entry.descriptor.fabric_redirect);
userspace-dp/src/afxdp/types/runtime.rs:45:/// tunnel_endpoint_id in `Coordinator::tunnel_sources`. Mirrors
userspace-dp/src/afxdp/types/runtime.rs:73:/// tunnel_endpoint_id in `Coordinator::wg_control_threads`.
userspace-dp/src/afxdp/types/runtime.rs:336:    pub(in crate::afxdp) enqueue_direct: u64,
userspace-dp/src/afxdp/cos/fairness.rs:95:        // bucket creation). Initialize observed_bps directly from
userspace-dp/src/afxdp/cos/fairness.rs:176:        // Skip-ramp: first non-zero sample after 0 → set directly.
userspace-dp/src/afxdp/cos/fairness.rs:185:        // Set observed_bps directly to skip the skip-ramp path.
pkg/daemon/daemon_neighbor.go:147:	// onto cfg.RoutingOptions.StaticRoutes directly would write into that
pkg/daemon/daemon_neighbor.go:281:		// failover path also nudges peer neighbor caches directly.
pkg/routing/reth.go:13:// (VRRP runs directly on physical member interfaces), so Apply/Names
pkg/routing/reth.go:21:// directly on physical member interfaces.
pkg/routing/iface_reuse_test.go:199:	// reused directly; LinkAdd then fails EEXIST and the fallback lookup
pkg/routing/routeformat.go:250:		if e.NextHop != "" && e.NextHop != "direct" {
pkg/routing/routeformat.go:275:	case "redirect":
pkg/routing/routeformat.go:276:		return "Redirect"
pkg/daemon/daemon_neighbor_listener_test.go:134:// invoke shouldTriggerRegenWithProvider directly with the stub
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:114:            // Fall through to slow path for full HA resolution → fabric redirect.
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:161:            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
userspace-dp/src/afxdp/poll_descriptor/flow_cache_hit.rs:206:                if cached_decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
pkg/routing/probe_pin_test.go:404:	// be reported failed (the probe holds — safe direction); the stale
userspace-dp/src/afxdp/cos/tx_completion_tests.rs:20:// #915 Codex code-review MEDIUM: direct unit tests for the
userspace-dp/src/afxdp/cos/tx_completion_tests.rs:32:// acquire to succeed. This indirect observation lets us prove
userspace-dp/src/afxdp/cos/tx_completion_tests.rs:714:    // index into the slot vector), then wake directly (clears the
userspace-dp/src/afxdp/bpf_map_tests.rs:5:// flat bpf_map.rs into a directory; this file stays at the parent
userspace-dp/src/afxdp/bpf_map_tests.rs:12:fn local_delivery_decision(tunnel_endpoint_id: u16) -> SessionDecision {
userspace-dp/src/afxdp/bpf_map_tests.rs:19:            tunnel_endpoint_id,
userspace-dp/src/afxdp/bpf_map_tests.rs:109:fn session_map_redirect_keys_for_forward_session_include_nat_aliases() {
userspace-dp/src/afxdp/bpf_map_tests.rs:124:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/bpf_map_tests.rs:144:    let keys = session_map_redirect_keys_for_session(
userspace-dp/src/afxdp/bpf_map_tests.rs:158:fn session_map_redirect_keys_for_kernel_local_synced_session_delete_superset() {
userspace-dp/src/afxdp/bpf_map_tests.rs:173:            tunnel_endpoint_id: 0,
userspace-dp/src/afxdp/bpf_map_tests.rs:187:        session_map_redirect_keys_for_session(&key, decision, &metadata, SessionOrigin::SyncImport);
pkg/daemon/daemon_gc.go:19:// RuntimeDomainProvider directly (Sessions()/Telemetry()), so the
pkg/routing/rules_test.go:75:// without netlink. Constructs the domain manager directly, NOT the whole
pkg/routing/rules_test.go:92:		{Name: "tunnel-vr", TableID: 100, InterfaceRoutesRibGroup: "self-only"},
pkg/routing/rules_test.go:93:		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
pkg/routing/rules_test.go:133:// asserting a next-table directive becomes an ip rule pointing at the
pkg/routing/rules_test.go:245:				InterfaceRoutesRibGroup: rgName,
userspace-dp/src/afxdp/disposition.rs:5:// (drop, kernel handoff, fabric redirect).
userspace-dp/src/afxdp/disposition.rs:11:// the forwarding outcome itself (ForwardCandidate / FabricRedirect /
userspace-dp/src/afxdp/disposition.rs:123:/// `Cold(&BindingLiveState)` and write directly to atomics — they're
userspace-dp/src/afxdp/disposition.rs:334:        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect => {
userspace-dp/src/afxdp/frame/checksum.rs:706:        let direct = checksum16(&bytes);
userspace-dp/src/afxdp/frame/checksum.rs:708:        assert_eq!(direct, composed);
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:30:fn redirect_local_cos_request_to_owner_pushes_worker_command() {
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:54:    let redirected =
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:55:        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:57:    assert!(redirected.is_ok());
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:70:fn redirect_local_cos_request_to_owner_uses_interface_default_queue_owner_when_unset() {
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:94:    let redirected =
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:95:        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:97:    assert!(redirected.is_ok());
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:103:fn redirect_local_cos_request_to_owner_rejects_explicit_queue_miss() {
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:127:    let redirected =
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:128:        redirect_local_cos_request_to_owner(&cos_fast_interfaces, req, 2, &worker_commands_by_id);
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:130:    assert!(redirected.is_err());
userspace-dp/src/afxdp/cos/cross_binding_tests.rs:135:fn redirect_local_cos_request_to_owner_keeps_exact_queue_on_eligible_worker() {

exec
/bin/bash -lc "nl -ba pkg/frr/policy_render.go | sed -n '55,90p;630,655p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
    55	
    56	// knownRedistProtocols are the FRR redistribute protocol keywords.
    57	var knownRedistProtocols = map[string]bool{
    58		"connected": true, "static": true, "ospf": true, "bgp": true,
    59		"rip": true, "isis": true, "kernel": true,
    60	}
    61	
    62	// resolveRedistribute converts a Junos export value into FRR redistribute commands.
    63	// If the value is a known protocol name, it emits a bare "redistribute <proto>".
    64	// If it matches a policy-statement, it extracts protocols from the terms and emits
    65	// "redistribute <proto> route-map <name>" for each.
    66	func (m *Manager) resolveRedistribute(export string, po *config.PolicyOptionsConfig) string {
    67		if knownRedistProtocols[export] {
    68			return fmt.Sprintf(" redistribute %s\n", export)
    69		}
    70	
    71		if po != nil && po.PolicyStatements != nil {
    72			if ps, ok := po.PolicyStatements[export]; ok {
    73				protocols := make(map[string]bool)
    74				for _, term := range ps.Terms {
    75					if term.FromProtocol != "" {
    76						proto := term.FromProtocol
    77						if proto == "direct" {
    78							proto = "connected"
    79						}
    80						protocols[proto] = true
    81					}
    82				}
    83				if len(protocols) > 0 {
    84					sorted := make([]string, 0, len(protocols))
    85					for p := range protocols {
    86						sorted = append(sorted, p)
    87					}
    88					sort.Strings(sorted)
    89					var sb strings.Builder
    90					for _, proto := range sorted {
   630					if strings.Contains(term.RouteFilters[0].Prefix, ":") {
   631						fmt.Fprintf(&b, " match ipv6 address prefix-list %s\n", plName)
   632					} else {
   633						fmt.Fprintf(&b, " match ip address prefix-list %s\n", plName)
   634					}
   635				}
   636	
   637				if term.PrefixList != "" {
   638					fmt.Fprintf(&b, " match ip address prefix-list %s\n", term.PrefixList)
   639				}
   640	
   641				if term.FromProtocol != "" {
   642					proto := term.FromProtocol
   643					if proto == "direct" {
   644						proto = "connected"
   645					}
   646					fmt.Fprintf(&b, " match source-protocol %s\n", proto)
   647				}
   648	
   649				if term.FromCommunity != "" {
   650					fmt.Fprintf(&b, " match community %s\n", term.FromCommunity)
   651				}
   652	
   653				if term.FromASPath != "" {
   654					fmt.Fprintf(&b, " match as-path %s\n", term.FromASPath)
   655				}

exec
/bin/bash -lc "nl -ba pkg/routing/rules.go | sed -n '135,205p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
exec
/bin/bash -lc "nl -ba userspace-dp/src/afxdp/forwarding_build/interfaces.rs | sed -n '1,170p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	//! Interface-state population for `build_forwarding_state`.
     2	//!
     3	//! Two passes:
     4	//!
     5	//! 1. [`populate_interfaces`] — walks `snapshot.interfaces`,
     6	//!    populates `state.ifindex_to_*`, `state.ifindex_to_zone_id`,
     7	//!    `state.tunnel_interfaces`, `state.local_v[46]`,
     8	//!    `state.interface_nat_v[46]`, `state.connected_v[46]`. Returns
     9	//!    an [`IfaceIndex`] context with `name_to_ifindex` /
    10	//!    `linux_to_ifindex` / `mac_by_ifindex` carried across the
    11	//!    later egress, route, and fabric passes.
    12	//! 2. [`populate_egress`] — walks `snapshot.interfaces` a second
    13	//!    time to build per-interface `EgressInterface` entries with
    14	//!    the resolved `bind_ifindex`, MAC, and zone_id.
    15	
    16	use super::super::*;
    17	use ipnet::IpNet;
    18	use std::collections::BTreeMap;
    19	use std::net::{Ipv4Addr, Ipv6Addr};
    20	
    21	/// Carry context built by [`populate_interfaces`] for downstream
    22	/// passes (egress / fib / fabrics). Owned by the orchestrator;
    23	/// passed by `&` to consumers.
    24	pub(super) struct IfaceIndex {
    25	    pub name_to_ifindex: BTreeMap<String, i32>,
    26	    pub linux_to_ifindex: BTreeMap<String, i32>,
    27	    pub mac_by_ifindex: BTreeMap<i32, [u8; 6]>,
    28	}
    29	
    30	pub(super) fn populate_interfaces(
    31	    snapshot: &ConfigSnapshot,
    32	    state: &mut ForwardingState,
    33	    excluded_local_v4: &FastSet<Ipv4Addr>,
    34	    excluded_local_v6: &FastSet<Ipv6Addr>,
    35	) -> IfaceIndex {
    36	    let mut name_to_ifindex = BTreeMap::new();
    37	    let mut linux_to_ifindex = BTreeMap::new();
    38	    let mut mac_by_ifindex = BTreeMap::new();
    39	
    40	    for iface in &snapshot.interfaces {
    41	        if iface.ifindex <= 0 {
    42	            continue;
    43	        }
    44	        let label = if iface.linux_name.is_empty() {
    45	            iface.name.clone()
    46	        } else {
    47	            iface.linux_name.clone()
    48	        };
    49	        state.ifindex_to_name.insert(iface.ifindex, label);
    50	        state
    51	            .ifindex_to_config_name
    52	            .insert(iface.ifindex, iface.name.clone());
    53	        name_to_ifindex.insert(iface.name.clone(), iface.ifindex);
    54	        if !iface.linux_name.is_empty() {
    55	            linux_to_ifindex.insert(iface.linux_name.clone(), iface.ifindex);
    56	        }
    57	        if !iface.zone.is_empty() {
    58	            // #921: resolve zone NAME → u16 once at config build, so
    59	            // every read on the hot path is one HashMap lookup
    60	            // (ifindex → u16). Unknown / dropped zones map to 0 (the
    61	            // canonical "unknown" sentinel).
    62	            let zone_id = state.zone_name_to_id.get(&iface.zone).copied().unwrap_or(0);
    63	            state.ifindex_to_zone_id.insert(iface.ifindex, zone_id);
    64	            if iface.parent_ifindex > 0 {
    65	                match state.ifindex_to_zone_id.get(&iface.parent_ifindex) {
    66	                    Some(existing) if *existing != zone_id => {}
    67	                    _ => {
    68	                        state
    69	                            .ifindex_to_zone_id
    70	                            .insert(iface.parent_ifindex, zone_id);
    71	                    }
    72	                }
    73	            }
    74	        }
    75	        if iface.tunnel {
    76	            state.tunnel_interfaces.insert(iface.ifindex);
    77	        }
    78	        if let Some(mac) = parse_mac(&iface.hardware_addr) {
    79	            mac_by_ifindex.insert(iface.ifindex, mac);
    80	        }
    81	        let tunnel_endpoint_id = state
    82	            .tunnel_endpoint_by_ifindex
    83	            .get(&iface.ifindex)
    84	            .copied()
    85	            .unwrap_or(0);
    86	        for addr in &iface.addresses {
    87	            let Ok(net) = addr.address.parse::<IpNet>() else {
    88	                continue;
    89	            };
    90	            match net {
    91	                IpNet::V4(v4) => {
    92	                    if excluded_local_v4.contains(&v4.addr()) {
    93	                        state.interface_nat_v4.insert(v4.addr(), iface.ifindex);
    94	                    } else {
    95	                        state.local_v4.insert(v4.addr());
    96	                    }
    97	                    state.connected_v4.push(ConnectedRouteV4 {
    98	                        prefix: PrefixV4::from_net(v4),
    99	                        ifindex: iface.ifindex,
   100	                        tunnel_endpoint_id,
   101	                    });
   102	                }
   103	                IpNet::V6(v6) => {
   104	                    if excluded_local_v6.contains(&v6.addr()) {
   105	                        state.interface_nat_v6.insert(v6.addr(), iface.ifindex);
   106	                    } else {
   107	                        state.local_v6.insert(v6.addr());
   108	                    }
   109	                    state.connected_v6.push(ConnectedRouteV6 {
   110	                        prefix: PrefixV6::from_net(v6),
   111	                        ifindex: iface.ifindex,
   112	                        tunnel_endpoint_id,
   113	                    });
   114	                }
   115	            }
   116	        }
   117	    }
   118	
   119	    IfaceIndex {
   120	        name_to_ifindex,
   121	        linux_to_ifindex,
   122	        mac_by_ifindex,
   123	    }
   124	}
   125	
   126	pub(super) fn populate_egress(
   127	    snapshot: &ConfigSnapshot,
   128	    state: &mut ForwardingState,
   129	    iface_ctx: &IfaceIndex,
   130	) {
   131	    for iface in &snapshot.interfaces {
   132	        if iface.ifindex <= 0 {
   133	            continue;
   134	        }
   135	        let bind_ifindex = if iface.parent_ifindex > 0 {
   136	            iface.parent_ifindex
   137	        } else {
   138	            iface.ifindex
   139	        };
   140	        let ingress_key = (bind_ifindex, iface.vlan_id.max(0) as u16);
   141	        if iface.parent_ifindex > 0 {
   142	            state
   143	                .ingress_logical_ifindex
   144	                .insert(ingress_key, iface.ifindex);
   145	        } else {
   146	            state
   147	                .ingress_logical_ifindex
   148	                .entry(ingress_key)
   149	                .or_insert(iface.ifindex);
   150	        }
   151	        let src_mac = match parse_mac(&iface.hardware_addr)
   152	            .or_else(|| iface_ctx.mac_by_ifindex.get(&bind_ifindex).copied())
   153	            .or_else(|| iface.tunnel.then_some([0; 6]))
   154	        {
   155	            Some(mac) => mac,
   156	            None => continue,
   157	        };
   158	        // #921: resolve zone name → u16 at build time. 0 for
   159	        // unknown / dropped zones (consistent with ifindex_to_zone_id).
   160	        let zone_id = state.zone_name_to_id.get(&iface.zone).copied().unwrap_or(0);
   161	        state.egress.insert(
   162	            iface.ifindex,
   163	            EgressInterface {
   164	                bind_ifindex,
   165	                vlan_id: iface.vlan_id.max(0) as u16,
   166	                mtu: iface.mtu.max(0) as usize,
   167	                src_mac,
   168	                zone_id,
   169	                redundancy_group: iface.redundancy_group,
   170	                primary_v4: pick_interface_v4(iface),

 succeeded in 0ms:
   135	
   136	// ribGroupManager reconciles rib-group route-leak ip rules. Stateless
   137	// apart from the borrowed ruleOps.
   138	type ribGroupManager struct {
   139		ops ruleOps
   140	}
   141	
   142	// Apply creates Linux policy routing rules (ip rule) for rib-group route
   143	// leaking. When a routing instance has interface-routes with a rib-group
   144	// reference, the instance's routes are leaked to other tables listed in
   145	// the rib-group's import-rib list.
   146	//
   147	// Both IPv4 (InterfaceRoutesRibGroup) and IPv6 (InterfaceRoutesRibGroupV6)
   148	// rib-groups are handled. For each source table that needs leaking, both
   149	// IPv4 and IPv6 ip rules are created.
   150	//
   151	// For example, if dmz-vr (table 101) has interface-routes rib-group "dmz-leak",
   152	// and dmz-leak has import-rib [ dmz-vr.inet.0 inet.0 ], then an ip rule is
   153	// created to make table 101 visible to main table lookups:
   154	//
   155	//	ip rule add from all lookup 101 pref 33000
   156	func (rg *ribGroupManager) Apply(ribGroups map[string]*config.RibGroup, instances []*config.RoutingInstanceConfig) error {
   157		// Clean up old rib-group rules
   158		if err := rg.clear(); err != nil {
   159			slog.Warn("failed to clear old rib-group rules", "err", err)
   160		}
   161	
   162		if len(ribGroups) == 0 || len(instances) == 0 {
   163			return nil
   164		}
   165	
   166		// Build instance name → table ID map
   167		tableIDs := make(map[string]int)
   168		for _, inst := range instances {
   169			tableIDs[inst.Name] = inst.TableID
   170		}
   171	
   172		// Track which source tables we've already added rules for
   173		// (avoid duplicate rules if multiple rib-groups reference the same table)
   174		leakedTables := make(map[int]bool)
   175	
   176		prio := ribGroupRulePriority
   177		for _, inst := range instances {
   178			// Collect all rib-group names referenced by this instance (inet + inet6)
   179			rgNames := []string{inst.InterfaceRoutesRibGroup, inst.InterfaceRoutesRibGroupV6}
   180	
   181			sourceTable := inst.TableID
   182			needsLeak := false
   183			for _, rgName := range rgNames {
   184				if rgName == "" {
   185					continue
   186				}
   187				rgDef, ok := ribGroups[rgName]
   188				if !ok {
   189					slog.Warn("interface-routes references unknown rib-group",
   190						"instance", inst.Name, "rib-group", rgName)
   191					continue
   192				}
   193				for _, ribName := range rgDef.ImportRibs {
   194					targetTable := resolveRibTable(ribName, tableIDs)
   195					if targetTable != sourceTable {
   196						needsLeak = true
   197						break
   198					}
   199				}
   200				if needsLeak {
   201					break
   202				}
   203			}
   204			if !needsLeak {
   205				continue

exec
/bin/bash -lc 'rg -n "ConnectedRoute|connected_v4|tunnel_endpoint_id" userspace-dp/src/afxdp/forwarding_build userspace-dp/src/afxdp/types/forwarding.rs' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
userspace-dp/src/afxdp/types/forwarding.rs:19:    pub(in crate::afxdp) connected_v4: Vec<ConnectedRouteV4>,
userspace-dp/src/afxdp/types/forwarding.rs:20:    pub(in crate::afxdp) connected_v6: Vec<ConnectedRouteV6>,
userspace-dp/src/afxdp/types/forwarding.rs:25:    /// WireGuard engines keyed by tunnel_endpoint_id (#1432 S2a). One
userspace-dp/src/afxdp/types/forwarding.rs:109:pub(in crate::afxdp) struct ConnectedRouteV4 {
userspace-dp/src/afxdp/types/forwarding.rs:112:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:116:pub(in crate::afxdp) struct ConnectedRouteV6 {
userspace-dp/src/afxdp/types/forwarding.rs:119:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:126:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:136:    pub(in crate::afxdp) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/types/forwarding.rs:346:    pub(crate) tunnel_endpoint_id: u16,
userspace-dp/src/afxdp/forwarding_build/fib.rs:30:        .connected_v4
userspace-dp/src/afxdp/forwarding_build/fib.rs:44:            let (next_hop, ifindex, tunnel_endpoint_id) = resolve_route_target_v4(
userspace-dp/src/afxdp/forwarding_build/fib.rs:58:                    tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding_build/fib.rs:66:            let (next_hop, ifindex, tunnel_endpoint_id) = resolve_route_target_v6(
userspace-dp/src/afxdp/forwarding_build/fib.rs:80:                    tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding_build/fib.rs:182:    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
userspace-dp/src/afxdp/forwarding_build/fib.rs:183:    (next_hop, ifindex, tunnel_endpoint_id)
userspace-dp/src/afxdp/forwarding_build/fib.rs:216:    let (ifindex, tunnel_endpoint_id) = target.unwrap_or((0, 0));
userspace-dp/src/afxdp/forwarding_build/fib.rs:217:    (next_hop, ifindex, tunnel_endpoint_id)
userspace-dp/src/afxdp/forwarding_build/fib.rs:274:        .connected_v4
userspace-dp/src/afxdp/forwarding_build/fib.rs:277:        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
userspace-dp/src/afxdp/forwarding_build/fib.rs:288:        .map(|entry| (entry.ifindex, entry.tunnel_endpoint_id))
userspace-dp/src/afxdp/forwarding_build/mod.rs:378:            "FWD_STATE: snat_rules={} static_nat={} dnat_table={} nptv6={} connected_v4={} routes_v4={}",
userspace-dp/src/afxdp/forwarding_build/mod.rs:395:            state.connected_v4.len(),
userspace-dp/src/afxdp/forwarding_build/wg.rs:4://! tunnel_endpoint_id.
userspace-dp/src/afxdp/forwarding_build/tunnels.rs:7://! `ConnectedRouteV4/V6.tunnel_endpoint_id`.
userspace-dp/src/afxdp/forwarding_build/tests.rs:2312:            tunnel_endpoint_id: 824,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2332:        resolved.tunnel_endpoint_id, 824,
userspace-dp/src/afxdp/forwarding_build/tests.rs:2380:        tunnel_endpoint_id: 824,
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:81:        let tunnel_endpoint_id = state
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:97:                    state.connected_v4.push(ConnectedRouteV4 {
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:100:                        tunnel_endpoint_id,
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:109:                    state.connected_v6.push(ConnectedRouteV6 {
userspace-dp/src/afxdp/forwarding_build/interfaces.rs:112:                        tunnel_endpoint_id,

codex
One nuance for the FRR wording: there is a generic FRR “redistribute connected” path, so a stale kernel connected route from a stale WG address can be visible to FRR if the operator configured direct export. That still traces back to the leaked kernel address, not to a WG-generated static route.
exec
/bin/bash -lc "rg -n \"func \\(t \\*tunnelManager\\) clearLocked|clearLocked\\(\" pkg/routing/tunnel.go" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
1357:	return t.clearLocked()
1368:func (t *tunnelManager) clearLocked() error {

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '1340,1418p;1418,1490p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
  1340	// *KeepaliveState pointer is safe to dereference outside the lock —
  1341	// Go GC keeps the value alive even if a subsequent stopAll removes it
  1342	// from the map.
  1343	func (t *tunnelManager) GetKeepaliveState(tunnelName string) *KeepaliveState {
  1344		t.mu.Lock()
  1345		defer t.mu.Unlock()
  1346		runner, ok := t.keepalives[tunnelName]
  1347		if !ok {
  1348			return nil
  1349		}
  1350		return runner.state
  1351	}
  1352	
  1353	// Clear removes all previously created tunnel interfaces.
  1354	func (t *tunnelManager) Clear() error {
  1355		t.mu.Lock()
  1356		defer t.mu.Unlock()
  1357		return t.clearLocked()
  1358	}
  1359	
  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
  1361	// Apply no longer uses it (#1884 reconcile-in-place); it remains the
  1362	// explicit delete-everything path for ClearTunnels. It deletes the
  1363	// UNION of the success-tracked list and the ownership set: a
  1364	// per-tunnel apply failure leaves the name in ownedNames but not in
  1365	// t.tunnels (failure-continue before finishTunnelLocked), and the
  1366	// delete-everything contract must still cover that live link (Codex
  1367	// PR #1903 r1 MINOR).
  1368	func (t *tunnelManager) clearLocked() error {
  1369		t.stopAllKeepalivesLocked()
  1370		names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
  1371		for _, name := range t.tunnels {
  1372			names[name] = true
  1373		}
  1374		for name := range t.ownedNames {
  1375			names[name] = true
  1376		}
  1377		for name := range names {
  1378			link, err := t.ops.LinkByName(name)
  1379			if err != nil {
  1380				continue // already gone
  1381			}
  1382			if err := t.ops.LinkDel(link); err != nil {
  1383				slog.Warn("failed to delete tunnel", "name", name, "err", err)
  1384			} else {
  1385				slog.Info("tunnel removed", "name", name)
  1386			}
  1387		}
  1388		t.tunnels = nil
  1389		// Reset the reconcile state with the devices: a post-Clear Apply
  1390		// adopts whatever survives instead of trusting stale ownership.
  1391		t.ownedNames = nil
  1392		t.appliedAddrs = nil
  1393		t.appliedRI = nil
  1394		// clearLocked drains every keepalive runner first
  1395		// (stopAllKeepalivesLocked above), so no live runner holds a stale
  1396		// linkGen pointer; dropping the map is safe and prevents removed names
  1397		// from leaking generation counters (#1918).
  1398		t.linkGen = nil
  1399		return nil
  1400	}
  1401	
  1402	// GetStatus returns the status of managed tunnel interfaces.
  1403	func (t *tunnelManager) GetStatus() ([]TunnelStatus, error) {
  1404		// #848: snapshot tunnel names under mu, then iterate without the
  1405		// lock so a long netlink probe can't block applyConfig.
  1406		t.mu.Lock()
  1407		names := append([]string(nil), t.tunnels...)
  1408		t.mu.Unlock()
  1409	
  1410		var result []TunnelStatus
  1411		for _, name := range names {
  1412			ts := TunnelStatus{Name: name, State: "down"}
  1413	
  1414			link, err := t.ops.LinkByName(name)
  1415			if err != nil {
  1416				ts.State = "not found"
  1417				result = append(result, ts)
  1418				continue
  1418				continue
  1419			}
  1420	
  1421			if link.Attrs().Flags&net.FlagUp != 0 {
  1422				ts.State = "up"
  1423			}
  1424	
  1425			switch tun := link.(type) {
  1426			case *netlink.Gretun:
  1427				ts.Source = tun.Local.String()
  1428				ts.Destination = tun.Remote.String()
  1429			case *netlink.Iptun:
  1430				ts.Source = tun.Local.String()
  1431				ts.Destination = tun.Remote.String()
  1432			case *netlink.Ip6tnl:
  1433				ts.Source = tun.Local.String()
  1434				ts.Destination = tun.Remote.String()
  1435			}
  1436	
  1437			addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
  1438			if err == nil {
  1439				for _, a := range addrs {
  1440					ts.Addresses = append(ts.Addresses, a.IPNet.String())
  1441				}
  1442			}
  1443	
  1444			// Add keepalive info.
  1445			if ks := t.GetKeepaliveState(name); ks != nil {
  1446				ks.mu.Lock()
  1447				switch {
  1448				case ks.Unknown:
  1449					// Hold-on-unknown (#1918 §6 Axis C): the prober could not
  1450					// verify liveness. KeepaliveUp stays nil ("liveness
  1451					// unknown") — never reported up — and the info string tells
  1452					// the operator why so they can fix the sysctl/caps. A
  1453					// sustained transient unknown carries the escalated errno.
  1454					ts.KeepaliveUp = nil
  1455					switch {
  1456					case ks.UnknownKind == UnsupportedTransient:
  1457						ts.KeepaliveInfo = fmt.Sprintf(
  1458							"unknown (%s; %d consecutive)",
  1459							ks.UnknownErrno, ks.unknownStreak)
  1460					case ks.UnknownErrno != "":
  1461						// Structural with a captured reason (the real syscall/config
  1462						// detail): show it so the operator can fix the root cause.
  1463						ts.KeepaliveInfo = fmt.Sprintf(
  1464							"unknown (ICMP probe unavailable: %s)", ks.UnknownErrno)
  1465					default:
  1466						ts.KeepaliveInfo = "unknown (ICMP probe unavailable)"
  1467					}
  1468				default:
  1469					up := ks.Up
  1470					ts.KeepaliveUp = &up
  1471					if up {
  1472						ts.KeepaliveInfo = fmt.Sprintf("up (interval %ds, %d retries)",
  1473							ks.Interval, ks.MaxRetries)
  1474					} else {
  1475						ts.KeepaliveInfo = fmt.Sprintf("down (%d consecutive failures)",
  1476							ks.Failures)
  1477					}
  1478				}
  1479				ks.mu.Unlock()
  1480			}
  1481	
  1482			result = append(result, ts)
  1483		}
  1484		return result, nil
  1485	}

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '1328,1388p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
  1328		case UnsupportedStructural:
  1329			return "ICMP probe unavailable"
  1330		default:
  1331			return "unknown"
  1332		}
  1333	}
  1334	
  1335	// GetKeepaliveState returns the keepalive state for a tunnel, or nil
  1336	// if no keepalive is configured.
  1337	//
  1338	// #848: mu protects the keepalives map against concurrent
  1339	// startKeepalive / stopAll mutations from Apply / Clear. The returned
  1340	// *KeepaliveState pointer is safe to dereference outside the lock —
  1341	// Go GC keeps the value alive even if a subsequent stopAll removes it
  1342	// from the map.
  1343	func (t *tunnelManager) GetKeepaliveState(tunnelName string) *KeepaliveState {
  1344		t.mu.Lock()
  1345		defer t.mu.Unlock()
  1346		runner, ok := t.keepalives[tunnelName]
  1347		if !ok {
  1348			return nil
  1349		}
  1350		return runner.state
  1351	}
  1352	
  1353	// Clear removes all previously created tunnel interfaces.
  1354	func (t *tunnelManager) Clear() error {
  1355		t.mu.Lock()
  1356		defer t.mu.Unlock()
  1357		return t.clearLocked()
  1358	}
  1359	
  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
  1361	// Apply no longer uses it (#1884 reconcile-in-place); it remains the
  1362	// explicit delete-everything path for ClearTunnels. It deletes the
  1363	// UNION of the success-tracked list and the ownership set: a
  1364	// per-tunnel apply failure leaves the name in ownedNames but not in
  1365	// t.tunnels (failure-continue before finishTunnelLocked), and the
  1366	// delete-everything contract must still cover that live link (Codex
  1367	// PR #1903 r1 MINOR).
  1368	func (t *tunnelManager) clearLocked() error {
  1369		t.stopAllKeepalivesLocked()
  1370		names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
  1371		for _, name := range t.tunnels {
  1372			names[name] = true
  1373		}
  1374		for name := range t.ownedNames {
  1375			names[name] = true
  1376		}
  1377		for name := range names {
  1378			link, err := t.ops.LinkByName(name)
  1379			if err != nil {
  1380				continue // already gone
  1381			}
  1382			if err := t.ops.LinkDel(link); err != nil {
  1383				slog.Warn("failed to delete tunnel", "name", name, "err", err)
  1384			} else {
  1385				slog.Info("tunnel removed", "name", name)
  1386			}
  1387		}
  1388		t.tunnels = nil

exec
/bin/bash -lc "nl -ba pkg/routing/README.md | sed -n '80,130p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
    80	## Tunnel reconcile-in-place (#1884)
    81	
    82	`tunnelManager.Apply` reconciles instead of clear-all +
    83	delete-and-recreate: an untouched tunnel keeps its netdev (stable
    84	ifindex — no FRR route churn, no userspace-dp TUN-reader death per
    85	commit, see #1881/#1887), tunnels removed from config are deleted via a
    86	set-diff against the previous DESIRED set (`ownedNames`, retained on a
    87	failed delete for retry), and a device is recreated only when the
    88	existing kernel link is genuinely incompatible:
    89	
    90	- **Anchors** (production userspace path): reuse requires TUN mode +
    91	  `NO_PI` (the Rust reader opens `IFF_TUN|IFF_NO_PI`) + persistent.
    92	  MTU ownership: `tc.MTU > 0` (config) is reconciled on every reuse
    93	  (the compiler MTU stage restores ZONED interfaces only); `tc.MTU ==
    94	  0` is written exactly once when ADOPTING a device this manager did
    95	  not own at the last apply (restart adoption; wireguard→gre same-name
    96	  flip repair — the WG-reduced MTU must not leak into the userspace
    97	  snapshot's live-MTU reads).
    98	- **Legacy non-anchor** (standalone-CLI only): compare-then-decide on
    99	  the config-driven attrs (type/family, endpoints, defaulted TTL,
   100	  keys, ip6tnl proto); kernel-populated fields (PMtu, Tos, flags,
   101	  encap-limit — mutated by the post-create `encaplimit none` exec) are
   102	  deliberately NOT compared. Real changes delete+recreate; the
   103	  encaplimit exec runs only on (re)create.
   104	- **Addresses**: symmetric reconcile; stale LINK-LOCAL addresses are
   105	  deleted only if recorded in `appliedAddrs` (a configured fe80 we
   106	  applied), never the kernel's autoconf fe80; failed LL deletes stay
   107	  tracked for retry. The WG branch uses the same helper with the nil
   108	  sentinel (blanket LL skip — pre-existing WG semantics).
   109	- **VRF claims** (`appliedRI`): written ONLY from a successful
   110	  `BindInterfaceToVRF` or a direct observation that the link's master
   111	  is `vrf-<RIListMember>` (a step-0a routing-instance interface-list
   112	  bind) — never from intent. `TunnelConfig.RIListMember` (populated by
   113	  `collectAppliedTunnels` with the exact step-0a name normalization)
   114	  vetoes unbinding when the config list-binds the tunnel. Unbind on
   115	  config-wants-none is identity-gated: only when the current master IS
   116	  the claimed RI's `vrf-` device; transient errors retain the claim
   117	  for retry.
   118	- **Keepalives** (legacy branch only — anchors never probe): runners
   119	  are reconciled by normalized identity `(remote, source, interval,
   120	  retry<=0→3)` and survive unrelated applies; `LinkSetUp` is SKIPPED
   121	  when a retained runner holds the tunnel down (the down-transition in
   122	  `keepaliveLoop` is gated on `state.Up`, so re-upping would strand
   123	  the link admin UP). A change to the tunnel SOURCE restarts the runner
   124	  (#1918 §5c): the source is the probe bind address.
   125	
   126	## Keepalive liveness probing (`tunnel_keepalive.go`, #1918)
   127	
   128	The keepalive performs a **real ICMP echo round-trip** — it is a
   129	liveness check, not a route-existence check. (The pre-#1918 `probeICMP`
   130	opened a socket and returned `true` without sending anything, so a dead

codex
I’m also checking the fake netlink harness because the plan’s proposed retry test must actually catch the non-link-local failure bug. The existing tests only prove the link-local retry path, not the regular address case this plan needs.
exec
/bin/bash -lc "nl -ba pkg/routing/tunnel_reconcile_test.go | sed -n '1,120p;120,220p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	package routing
     2	
     3	import (
     4		"errors"
     5		"net"
     6		"testing"
     7	
     8		"github.com/psaab/xpf/pkg/config"
     9		"github.com/vishvananda/netlink"
    10	)
    11	
    12	// #1884 reconcile-in-place tests. tunnelManager.Apply must not delete
    13	// and recreate untouched tunnel devices on every apply (the gr-X flap
    14	// that killed the userspace-dp TUN readers per commit); removals are a
    15	// set-diff against the previous DESIRED set; reuse paths explicitly
    16	// reconcile addresses, VRF claims, MTU, and keepalives.
    17	
    18	// fakeVRFBinder mimics vrfManager.BindInterfaceToVRF against the
    19	// fakeLinkOps store: a successful bind sets the interface's
    20	// MasterIndex to the vrf-<ri> device's index (the daemon-prefixed VRF
    21	// naming, vrf.go BindInterfaceToVRF).
    22	type fakeVRFBinder struct {
    23		ops  *fakeLinkOps
    24		fail map[string]error // ri name -> bind error injection
    25	}
    26	
    27	func (b *fakeVRFBinder) BindInterfaceToVRF(ifaceName, instanceName string) error {
    28		if err, ok := b.fail[instanceName]; ok {
    29			return err
    30		}
    31		iface, ok := b.ops.links[ifaceName]
    32		if !ok {
    33			return errors.New("interface not found")
    34		}
    35		vrf, ok := b.ops.links["vrf-"+instanceName]
    36		if !ok {
    37			return errors.New("vrf not found")
    38		}
    39		iface.Attrs().MasterIndex = vrf.Attrs().Index
    40		return nil
    41	}
    42	
    43	func newReconcileManager(ops *fakeLinkOps) (*tunnelManager, *fakeVRFBinder) {
    44		binder := &fakeVRFBinder{ops: ops, fail: map[string]error{}}
    45		return &tunnelManager{
    46			ops:        ops,
    47			vrfBinder:  binder,
    48			keepalives: map[string]*keepaliveRunner{},
    49		}, binder
    50	}
    51	
    52	func seedVRF(ops *fakeLinkOps, ri string, index int) {
    53		ops.links["vrf-"+ri] = &netlink.Vrf{
    54			LinkAttrs: netlink.LinkAttrs{Name: "vrf-" + ri, Index: index},
    55		}
    56	}
    57	
    58	// seedAnchor seeds a kernel-shaped reusable anchor TUN.
    59	func seedAnchor(ops *fakeLinkOps, name string, index, mtu int) *netlink.Tuntap {
    60		tt := &netlink.Tuntap{
    61			LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, MTU: mtu},
    62			Mode:      netlink.TUNTAP_MODE_TUN,
    63			Flags:     netlink.TUNTAP_NO_PI,
    64		}
    65		ops.links[name] = tt
    66		return tt
    67	}
    68	
    69	func anchorTC(name string, addrs ...string) *config.TunnelConfig {
    70		return &config.TunnelConfig{Name: name, AnchorOnly: true, Addresses: addrs}
    71	}
    72	
    73	// --- §9 test 1: untouched tunnel ⇒ untouched netdev -----------------
    74	
    75	func TestTunnelApplySecondApplyNoChurn(t *testing.T) {
    76		ops := newFakeLinkOps()
    77		tm, _ := newReconcileManager(ops)
    78		tcs := []*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}
    79	
    80		if err := tm.Apply(tcs); err != nil {
    81			t.Fatalf("Apply 1: %v", err)
    82		}
    83		if len(ops.delNames) != 0 {
    84			t.Fatalf("first apply deleted links: %v", ops.delNames)
    85		}
    86		created := ops.links["gr-0-0-0"]
    87		if created == nil {
    88			t.Fatal("anchor not created")
    89		}
    90		addAddsAfterFirst := len(ops.addrLinks)
    91	
    92		if err := tm.Apply(tcs); err != nil {
    93			t.Fatalf("Apply 2: %v", err)
    94		}
    95		if len(ops.delNames) != 0 {
    96			t.Fatalf("second apply deleted links (the #1884 flap): %v", ops.delNames)
    97		}
    98		if ops.links["gr-0-0-0"] != created {
    99			t.Fatal("second apply replaced the anchor link object")
   100		}
   101		if got := len(ops.addrLinks); got != addAddsAfterFirst {
   102			t.Fatalf("second apply re-added addresses: AddrAdd count %d, want %d",
   103				got, addAddsAfterFirst)
   104		}
   105		if got := len(ops.addrDels["gr-0-0-0"]); got != 0 {
   106			t.Fatalf("second apply deleted addresses: %v", ops.addrDels["gr-0-0-0"])
   107		}
   108		if got := len(ops.mtuSet["gr-0-0-0"]); got != 0 {
   109			t.Fatalf("owned reuse with unconfigured MTU wrote MTU: %v", ops.mtuSet["gr-0-0-0"])
   110		}
   111	}
   112	
   113	// --- §9 test 2: restart adoption + MTU ownership ---------------------
   114	
   115	func TestTunnelAnchorRestartAdoptionNormalizesMTU(t *testing.T) {
   116		ops := newFakeLinkOps()
   117		seedAnchor(ops, "gr-0-0-0", 42, 1420) // WG-leftover-ish MTU
   118		tm, _ := newReconcileManager(ops)
   119	
   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
   121		// ⇒ one-time normalization to the TUN default.
   122		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   123			t.Fatalf("Apply: %v", err)
   124		}
   125		if len(ops.delNames) != 0 {
   126			t.Fatalf("adoption recreated the anchor: %v", ops.delNames)
   127		}
   128		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 1500 {
   129			t.Fatalf("adoption MTU writes = %v, want exactly [1500]", got)
   130		}
   131	
   132		// Owned reuse, tc.MTU == 0, MTU drifted out-of-band ⇒ NOT touched.
   133		ops.links["gr-0-0-0"].Attrs().MTU = 1400
   134		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   135			t.Fatalf("Apply 2: %v", err)
   136		}
   137		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 {
   138			t.Fatalf("owned reuse with tc.MTU==0 wrote MTU: %v", got)
   139		}
   140	}
   141	
   142	func TestTunnelAnchorConfiguredMTUReconciledOnReuse(t *testing.T) {
   143		ops := newFakeLinkOps()
   144		seedAnchor(ops, "gr-0-0-0", 42, 1420)
   145		tm, _ := newReconcileManager(ops)
   146	
   147		tc := anchorTC("gr-0-0-0")
   148		tc.MTU = 9000
   149		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   150			t.Fatalf("Apply: %v", err)
   151		}
   152		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 9000 {
   153			t.Fatalf("adoption with config MTU writes = %v, want [9000]", got)
   154		}
   155	
   156		// Owned reuse with config MTU and drift ⇒ reconciled (the compiler
   157		// stage only restores ZONED interfaces; unzoned tunnels have no
   158		// other MTU writer).
   159		ops.links["gr-0-0-0"].Attrs().MTU = 1400
   160		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   161			t.Fatalf("Apply 2: %v", err)
   162		}
   163		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 2 || got[1] != 9000 {
   164			t.Fatalf("owned reuse with config MTU writes = %v, want [9000 9000]", got)
   165		}
   166	}
   167	
   168	func TestTunnelAnchorCreateAppliesConfigMTU(t *testing.T) {
   169		ops := newFakeLinkOps()
   170		tm, _ := newReconcileManager(ops)
   171		tc := anchorTC("gr-0-0-0")
   172		tc.MTU = 9000
   173		if err := tm.Apply([]*config.TunnelConfig{tc}); err != nil {
   174			t.Fatalf("Apply: %v", err)
   175		}
   176		if got := ops.mtuSet["gr-0-0-0"]; len(got) != 1 || got[0] != 9000 {
   177			t.Fatalf("create with config MTU writes = %v, want [9000]", got)
   178		}
   179	}
   180	
   181	// --- §9 test 3: incompatible existing links are recreated ------------
   182	
   183	func TestTunnelAnchorIncompatibleLinksRecreated(t *testing.T) {
   184		cases := []struct {
   185			name string
   186			link netlink.Link
   187		}{
   188			{"dummy", &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9}}},
   189			{"pi-tun", &netlink.Tuntap{
   190				LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
   191				Mode:      netlink.TUNTAP_MODE_TUN, // no NO_PI flag
   192			}},
   193			{"tap", &netlink.Tuntap{
   194				LinkAttrs: netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
   195				Mode:      netlink.TUNTAP_MODE_TAP,
   196				Flags:     netlink.TUNTAP_NO_PI,
   197			}},
   198			{"non-persistent", &netlink.Tuntap{
   199				LinkAttrs:  netlink.LinkAttrs{Name: "gr-0-0-0", Index: 9},
   200				Mode:       netlink.TUNTAP_MODE_TUN,
   201				Flags:      netlink.TUNTAP_NO_PI,
   202				NonPersist: true,
   203			}},
   204		}
   205		for _, tcase := range cases {
   206			t.Run(tcase.name, func(t *testing.T) {
   207				ops := newFakeLinkOps()
   208				ops.links["gr-0-0-0"] = tcase.link
   209				tm, _ := newReconcileManager(ops)
   210				if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   211					t.Fatalf("Apply: %v", err)
   212				}
   213				if len(ops.delNames) != 1 || ops.delNames[0] != "gr-0-0-0" {
   214					t.Fatalf("incompatible link not deleted: delNames=%v", ops.delNames)
   215				}
   216				if ops.links["gr-0-0-0"] == tcase.link {
   217					t.Fatal("incompatible link not replaced")
   218				}
   219				if _, ok := ops.links["gr-0-0-0"].(*netlink.Tuntap); !ok {
   220					t.Fatalf("replacement is %T, want *netlink.Tuntap", ops.links["gr-0-0-0"])

exec
/bin/bash -lc 'rg -n "addrDelFail|AddrDel|addrAdd|delNames|LinkByName|seedAnchor|newFakeLinkOps|type fake" pkg/routing/tunnel_reconcile_test.go | head -n 140' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
22:type fakeVRFBinder struct {
58:// seedAnchor seeds a kernel-shaped reusable anchor TUN.
59:func seedAnchor(ops *fakeLinkOps, name string, index, mtu int) *netlink.Tuntap {
76:	ops := newFakeLinkOps()
83:	if len(ops.delNames) != 0 {
84:		t.Fatalf("first apply deleted links: %v", ops.delNames)
95:	if len(ops.delNames) != 0 {
96:		t.Fatalf("second apply deleted links (the #1884 flap): %v", ops.delNames)
116:	ops := newFakeLinkOps()
117:	seedAnchor(ops, "gr-0-0-0", 42, 1420) // WG-leftover-ish MTU
125:	if len(ops.delNames) != 0 {
126:		t.Fatalf("adoption recreated the anchor: %v", ops.delNames)
143:	ops := newFakeLinkOps()
144:	seedAnchor(ops, "gr-0-0-0", 42, 1420)
169:	ops := newFakeLinkOps()
207:			ops := newFakeLinkOps()
213:			if len(ops.delNames) != 1 || ops.delNames[0] != "gr-0-0-0" {
214:				t.Fatalf("incompatible link not deleted: delNames=%v", ops.delNames)
229:	ops := newFakeLinkOps()
249:	ops := newFakeLinkOps()
277:	ops := newFakeLinkOps()
285:	if len(ops.delNames) != 0 {
286:		t.Fatalf("address edit recreated the link: %v", ops.delNames)
297:	ops := newFakeLinkOps()
322:	ops := newFakeLinkOps()
328:	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
337:	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
357:	ops := newFakeLinkOps()
382:	if len(ops.delNames) != 0 {
383:		t.Fatalf("wg0 was deleted/recreated: %v", ops.delNames)
391:	ops := newFakeLinkOps()
392:	seedAnchor(ops, "wg0", 7, 1412)
411:	ops := newFakeLinkOps()
417:	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
425:	delete(ops.addrDelFail, "wg0|fe80::8/64")
437:	ops := newFakeLinkOps()
471:	ops := newFakeLinkOps()
507:	ops := newFakeLinkOps()
509:	anchor := seedAnchor(ops, "gr-0-0-0", 42, 1500)
524:	ops := newFakeLinkOps()
561:	ops := newFakeLinkOps()
596:	ops := newFakeLinkOps()
633:	ops := newFakeLinkOps()
650:	ops := newFakeLinkOps()
684:// kernelShapedGre mimics what LinkByName returns for a GRE device the
704:	ops := newFakeLinkOps()
712:	if len(ops.delNames) != 0 {
713:		t.Fatalf("identical legacy tunnel was recreated: %v", ops.delNames)
743:			ops := newFakeLinkOps()
749:			if len(ops.delNames) != 1 {
750:				t.Fatalf("changed attrs did not recreate: delNames=%v", ops.delNames)
757:	ops := newFakeLinkOps()
767:	if len(ops.delNames) != 0 {
775:	ops := newFakeLinkOps()
818:	ops := newFakeLinkOps()
850:	ops := newFakeLinkOps()
877:	ops := newFakeLinkOps()
891:	if len(ops.delNames) != 0 {
892:		t.Fatalf("restart adoption recreated the anchor: %v", ops.delNames)
902:	ops := newFakeLinkOps()
931:	ops := newFakeLinkOps()
953:	ops := newFakeLinkOps()
980:	ops := newFakeLinkOps()
1019:	ops := newFakeLinkOps()

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel_reconcile_test.go | sed -n '220,330p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   220					t.Fatalf("replacement is %T, want *netlink.Tuntap", ops.links["gr-0-0-0"])
   221				}
   222			})
   223		}
   224	}
   225	
   226	// --- §9 test 4: removal diff + retention on failed delete ------------
   227	
   228	func TestTunnelRemovedFromConfigDeleted(t *testing.T) {
   229		ops := newFakeLinkOps()
   230		tm, _ := newReconcileManager(ops)
   231		both := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
   232		if err := tm.Apply(both); err != nil {
   233			t.Fatalf("Apply 1: %v", err)
   234		}
   235		keepA := ops.links["gr-0-0-0"]
   236	
   237		if err := tm.Apply(both[:1]); err != nil {
   238			t.Fatalf("Apply 2: %v", err)
   239		}
   240		if _, ok := ops.links["gr-0-0-1"]; ok {
   241			t.Fatal("removed tunnel gr-0-0-1 still exists")
   242		}
   243		if ops.links["gr-0-0-0"] != keepA {
   244			t.Fatal("survivor gr-0-0-0 was churned by the removal")
   245		}
   246	}
   247	
   248	func TestTunnelRemovalRetriedAfterFailedDelete(t *testing.T) {
   249		ops := newFakeLinkOps()
   250		tm, _ := newReconcileManager(ops)
   251		both := []*config.TunnelConfig{anchorTC("gr-0-0-0"), anchorTC("gr-0-0-1")}
   252		if err := tm.Apply(both); err != nil {
   253			t.Fatalf("Apply 1: %v", err)
   254		}
   255	
   256		ops.delFail["gr-0-0-1"] = errors.New("EBUSY")
   257		if err := tm.Apply(both[:1]); err != nil {
   258			t.Fatalf("Apply 2: %v", err)
   259		}
   260		if _, ok := ops.links["gr-0-0-1"]; !ok {
   261			t.Fatal("link unexpectedly gone despite failed delete")
   262		}
   263	
   264		// Ownership retained ⇒ the NEXT apply retries and succeeds.
   265		delete(ops.delFail, "gr-0-0-1")
   266		if err := tm.Apply(both[:1]); err != nil {
   267			t.Fatalf("Apply 3: %v", err)
   268		}
   269		if _, ok := ops.links["gr-0-0-1"]; ok {
   270			t.Fatal("removal not retried after ownership retention (r2 Codex F5)")
   271		}
   272	}
   273	
   274	// --- §9 test 5: address reconcile + link-local rules ------------------
   275	
   276	func TestTunnelAddressEditReconcilesInPlace(t *testing.T) {
   277		ops := newFakeLinkOps()
   278		tm, _ := newReconcileManager(ops)
   279		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.1.2.3/32")}); err != nil {
   280			t.Fatalf("Apply 1: %v", err)
   281		}
   282		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "10.9.9.9/32")}); err != nil {
   283			t.Fatalf("Apply 2: %v", err)
   284		}
   285		if len(ops.delNames) != 0 {
   286			t.Fatalf("address edit recreated the link: %v", ops.delNames)
   287		}
   288		if ops.hasAddr("gr-0-0-0", "10.1.2.3/32") {
   289			t.Fatal("stale address not removed")
   290		}
   291		if !ops.hasAddr("gr-0-0-0", "10.9.9.9/32") {
   292			t.Fatal("new address not added")
   293		}
   294	}
   295	
   296	func TestTunnelLinkLocalRules(t *testing.T) {
   297		ops := newFakeLinkOps()
   298		tm, _ := newReconcileManager(ops)
   299	
   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
   301		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
   302			t.Fatalf("Apply 1: %v", err)
   303		}
   304		// Simulate the kernel's autoconf link-local appearing too.
   305		kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
   306		ops.addrs["gr-0-0-0"] = append(ops.addrs["gr-0-0-0"], *kernelLL)
   307	
   308		// Remove the configured fe80: it must be deleted (it is ours), the
   309		// kernel's autoconf fe80 must survive (r1 Codex F2 split).
   310		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   311			t.Fatalf("Apply 2: %v", err)
   312		}
   313		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   314			t.Fatal("configured fe80 leaked after removal from config")
   315		}
   316		if !ops.hasAddr("gr-0-0-0", "fe80::5054:ff:fe12:3456/64") {
   317			t.Fatal("kernel autoconf fe80 was deleted")
   318		}
   319	}
   320	
   321	func TestTunnelLinkLocalDeleteFailureRetried(t *testing.T) {
   322		ops := newFakeLinkOps()
   323		tm, _ := newReconcileManager(ops)
   324		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
   325			t.Fatalf("Apply 1: %v", err)
   326		}
   327	
   328		ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
   329		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   330			t.Fatalf("Apply 2: %v", err)

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel_reconcile_test.go | sed -n '300,345p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
   301		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
   302			t.Fatalf("Apply 1: %v", err)
   303		}
   304		// Simulate the kernel's autoconf link-local appearing too.
   305		kernelLL, _ := netlink.ParseAddr("fe80::5054:ff:fe12:3456/64")
   306		ops.addrs["gr-0-0-0"] = append(ops.addrs["gr-0-0-0"], *kernelLL)
   307	
   308		// Remove the configured fe80: it must be deleted (it is ours), the
   309		// kernel's autoconf fe80 must survive (r1 Codex F2 split).
   310		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   311			t.Fatalf("Apply 2: %v", err)
   312		}
   313		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   314			t.Fatal("configured fe80 leaked after removal from config")
   315		}
   316		if !ops.hasAddr("gr-0-0-0", "fe80::5054:ff:fe12:3456/64") {
   317			t.Fatal("kernel autoconf fe80 was deleted")
   318		}
   319	}
   320	
   321	func TestTunnelLinkLocalDeleteFailureRetried(t *testing.T) {
   322		ops := newFakeLinkOps()
   323		tm, _ := newReconcileManager(ops)
   324		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0", "fe80::8/64")}); err != nil {
   325			t.Fatalf("Apply 1: %v", err)
   326		}
   327	
   328		ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
   329		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   330			t.Fatalf("Apply 2: %v", err)
   331		}
   332		if !ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   333			t.Fatal("address gone despite injected delete failure")
   334		}
   335	
   336		// Failed delete keeps the LL tracked (r2 Codex F4) ⇒ retried.
   337		delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
   338		if err := tm.Apply([]*config.TunnelConfig{anchorTC("gr-0-0-0")}); err != nil {
   339			t.Fatalf("Apply 3: %v", err)
   340		}
   341		if ops.hasAddr("gr-0-0-0", "fe80::8/64") {
   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
   343		}
   344	}
   345	

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel_test_support_test.go | sed -n '1,220p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
nl: pkg/routing/tunnel_test_support_test.go: No such file or directory

exec
/bin/bash -lc "rg -n \"type fakeLinkOps|func newFakeLinkOps|func \\(f \\*fakeLinkOps\\) AddrDel|func \\(f \\*fakeLinkOps\\) AddrAdd|addrDelFail|addrDels\" pkg/routing -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/iface_reuse_test.go:17:type fakeLinkOps struct {
pkg/routing/iface_reuse_test.go:40:	// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
pkg/routing/iface_reuse_test.go:42:	addrDelFail map[string]error
pkg/routing/iface_reuse_test.go:57:	addrDels   map[string][]string
pkg/routing/iface_reuse_test.go:60:func newFakeLinkOps() *fakeLinkOps {
pkg/routing/iface_reuse_test.go:66:		addrDelFail: map[string]error{},
pkg/routing/iface_reuse_test.go:69:		addrDels:    map[string][]string{},
pkg/routing/iface_reuse_test.go:135:func (f *fakeLinkOps) AddrAdd(l netlink.Link, a *netlink.Addr) error {
pkg/routing/iface_reuse_test.go:143:func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
pkg/routing/iface_reuse_test.go:146:	if err, ok := f.addrDelFail[name+"|"+key]; ok {
pkg/routing/iface_reuse_test.go:149:	f.addrDels[name] = append(f.addrDels[name], key)
pkg/routing/tunnel_reconcile_test.go:105:	if got := len(ops.addrDels["gr-0-0-0"]); got != 0 {
pkg/routing/tunnel_reconcile_test.go:106:		t.Fatalf("second apply deleted addresses: %v", ops.addrDels["gr-0-0-0"])
pkg/routing/tunnel_reconcile_test.go:328:	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
pkg/routing/tunnel_reconcile_test.go:337:	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
pkg/routing/tunnel_reconcile_test.go:417:	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
pkg/routing/tunnel_reconcile_test.go:425:	delete(ops.addrDelFail, "wg0|fe80::8/64")

exec
/bin/bash -lc 'rg -n "type fakeLinkOps|addrDelFail|AddrDel" pkg/routing/*test*.go' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/tunnel_reconcile_test.go:328:	ops.addrDelFail["gr-0-0-0|fe80::8/64"] = errors.New("EBUSY")
pkg/routing/tunnel_reconcile_test.go:337:	delete(ops.addrDelFail, "gr-0-0-0|fe80::8/64")
pkg/routing/tunnel_reconcile_test.go:417:	ops.addrDelFail["wg0|fe80::8/64"] = errors.New("EBUSY")
pkg/routing/tunnel_reconcile_test.go:425:	delete(ops.addrDelFail, "wg0|fe80::8/64")
pkg/routing/tunnel_keepalive_test.go:91:func (o *kaOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
pkg/routing/iface_reuse_test.go:17:type fakeLinkOps struct {
pkg/routing/iface_reuse_test.go:40:	// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
pkg/routing/iface_reuse_test.go:42:	addrDelFail map[string]error
pkg/routing/iface_reuse_test.go:48:	// AddrAdd/AddrDel/AddrList for the #1884 reconcile tests.
pkg/routing/iface_reuse_test.go:66:		addrDelFail: map[string]error{},
pkg/routing/iface_reuse_test.go:143:func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
pkg/routing/iface_reuse_test.go:146:	if err, ok := f.addrDelFail[name+"|"+key]; ok {

exec
/bin/bash -lc "rg --files pkg/routing | rg 'test|support'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/probe_pin_test.go
pkg/routing/rules_test.go
pkg/routing/tunnel_keepalive_test.go
pkg/routing/tunnel_prober_test.go
pkg/routing/iface_reuse_test.go
pkg/routing/tunnel_reconcile_test.go
pkg/routing/routing_test.go

codex
The fake supports exactly the failure injection needed (`addrDelFail["name|ipnet"]`). A test with `10.x/…`, not only `fe80`, would expose that the proposed `len(remaining)>0` retry signal never fires.
exec
/bin/bash -lc "nl -ba pkg/routing/iface_reuse_test.go | sed -n '1,175p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	package routing
     2	
     3	import (
     4		"errors"
     5		"testing"
     6	
     7		"github.com/psaab/xpf/pkg/config"
     8		"github.com/vishvananda/netlink"
     9	)
    10	
    11	// fakeLinkOps is an in-memory linkOps for the #1706 tunnel/xfrm reuse
    12	// tests. It records which link object LinkSetUp/AddrAdd were invoked
    13	// against so the tests can prove the apply paths operate on the
    14	// kernel-fetched (indexed) link rather than a freshly-constructed,
    15	// ifindex-less one. LinkAdd can be made to fail (EEXIST) to drive the
    16	// "already exists" branches.
    17	type fakeLinkOps struct {
    18		links map[string]netlink.Link // name -> seeded existing link
    19	
    20		// addExisting makes LinkAdd report the link already exists.
    21		addExisting bool
    22	
    23		// byNameErrAfter, when > 0, makes LinkByName return an error once it
    24		// has been called this many times for the same name (used to drive a
    25		// transient second-lookup failure under the OLD double-lookup code).
    26		byNameCount    map[string]int
    27		byNameErrAfter int
    28	
    29		// hiddenUntil[name] = k makes LinkByName report not-found for the
    30		// first k calls, then return the seeded link. Models a link that the
    31		// pre-loop delete lookup misses but that exists by the time LinkAdd's
    32		// EEXIST fallback lookup runs — the only way the tunnel reuse path
    33		// (goto anchorReady) is reached.
    34		hiddenUntil map[string]int
    35	
    36		// delFail[name] makes LinkDel fail for that link name (#1884
    37		// removal-retention tests).
    38		delFail map[string]error
    39	
    40		// addrDelFail["name|ipnet"] makes AddrDel fail for that address on
    41		// that link (#1884 link-local retention tests).
    42		addrDelFail map[string]error
    43	
    44		// noMasterErr makes LinkSetNoMaster fail (claim retention tests).
    45		noMasterErr error
    46	
    47		// addrs is the per-link kernel address store backing
    48		// AddrAdd/AddrDel/AddrList for the #1884 reconcile tests.
    49		addrs map[string][]netlink.Addr
    50	
    51		// Recorded ops.
    52		setUpLinks []netlink.Link
    53		addrLinks  []netlink.Link
    54		delNames   []string
    55		noMaster   []string
    56		mtuSet     map[string][]int
    57		addrDels   map[string][]string
    58	}
    59	
    60	func newFakeLinkOps() *fakeLinkOps {
    61		return &fakeLinkOps{
    62			links:       map[string]netlink.Link{},
    63			byNameCount: map[string]int{},
    64			hiddenUntil: map[string]int{},
    65			delFail:     map[string]error{},
    66			addrDelFail: map[string]error{},
    67			addrs:       map[string][]netlink.Addr{},
    68			mtuSet:      map[string][]int{},
    69			addrDels:    map[string][]string{},
    70		}
    71	}
    72	
    73	func (f *fakeLinkOps) LinkByName(name string) (netlink.Link, error) {
    74		f.byNameCount[name]++
    75		if f.byNameErrAfter > 0 && f.byNameCount[name] > f.byNameErrAfter {
    76			return nil, errors.New("transient netlink error")
    77		}
    78		if hide, ok := f.hiddenUntil[name]; ok && f.byNameCount[name] <= hide {
    79			return nil, errLinkNotFound{errors.New("link not found")}
    80		}
    81		if l, ok := f.links[name]; ok {
    82			return l, nil
    83		}
    84		return nil, errLinkNotFound{errors.New("link not found")}
    85	}
    86	
    87	func (f *fakeLinkOps) LinkAdd(l netlink.Link) error {
    88		if f.addExisting {
    89			return errors.New("file exists")
    90		}
    91		f.links[l.Attrs().Name] = l
    92		return nil
    93	}
    94	
    95	func (f *fakeLinkOps) LinkDel(l netlink.Link) error {
    96		name := l.Attrs().Name
    97		if err, ok := f.delFail[name]; ok {
    98			return err
    99		}
   100		f.delNames = append(f.delNames, name)
   101		delete(f.links, name)
   102		delete(f.addrs, name)
   103		return nil
   104	}
   105	
   106	func (f *fakeLinkOps) LinkSetUp(l netlink.Link) error {
   107		// Mirror the real netlink handle: dereferencing a nil link panics.
   108		// A correct caller never passes nil here.
   109		_ = l.Attrs()
   110		f.setUpLinks = append(f.setUpLinks, l)
   111		return nil
   112	}
   113	
   114	func (f *fakeLinkOps) LinkSetDown(l netlink.Link) error      { return nil }
   115	func (f *fakeLinkOps) LinkSetMaster(l, m netlink.Link) error { return nil }
   116	
   117	func (f *fakeLinkOps) LinkSetNoMaster(l netlink.Link) error {
   118		if f.noMasterErr != nil {
   119			return f.noMasterErr
   120		}
   121		f.noMaster = append(f.noMaster, l.Attrs().Name)
   122		l.Attrs().MasterIndex = 0
   123		return nil
   124	}
   125	
   126	func (f *fakeLinkOps) LinkSetMTU(l netlink.Link, mtu int) error {
   127		name := l.Attrs().Name
   128		f.mtuSet[name] = append(f.mtuSet[name], mtu)
   129		l.Attrs().MTU = mtu
   130		return nil
   131	}
   132	
   133	func (f *fakeLinkOps) LinkList() ([]netlink.Link, error) { return nil, nil }
   134	
   135	func (f *fakeLinkOps) AddrAdd(l netlink.Link, a *netlink.Addr) error {
   136		_ = l.Attrs()
   137		f.addrLinks = append(f.addrLinks, l)
   138		name := l.Attrs().Name
   139		f.addrs[name] = append(f.addrs[name], *a)
   140		return nil
   141	}
   142	
   143	func (f *fakeLinkOps) AddrDel(l netlink.Link, a *netlink.Addr) error {
   144		name := l.Attrs().Name
   145		key := a.IPNet.String()
   146		if err, ok := f.addrDelFail[name+"|"+key]; ok {
   147			return err
   148		}
   149		f.addrDels[name] = append(f.addrDels[name], key)
   150		kept := f.addrs[name][:0]
   151		for _, existing := range f.addrs[name] {
   152			if existing.IPNet.String() != key {
   153				kept = append(kept, existing)
   154			}
   155		}
   156		f.addrs[name] = kept
   157		return nil
   158	}
   159	
   160	func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
   161		return append([]netlink.Addr(nil), f.addrs[l.Attrs().Name]...), nil
   162	}
   163	
   164	// hasAddr reports whether the fake kernel store holds ipnet on name.
   165	func (f *fakeLinkOps) hasAddr(name, ipnet string) bool {
   166		for _, a := range f.addrs[name] {
   167			if a.IPNet.String() == ipnet {
   168				return true
   169			}
   170		}
   171		return false
   172	}
   173	
   174	// noopVRFBinder satisfies vrfBinder without touching netlink.
   175	type noopVRFBinder struct{}

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '650,710p;711,785p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   650			}
   651			slog.Info("tunnel created", "name", tc.Name,
   652				"src", tc.Source, "dst", tc.Destination)
   653		} else if tc.MTU > 0 && link.Attrs().MTU != tc.MTU {
   654			// Config-owned MTU reconcile on reuse (#1884 r5). No
   655			// adoption-default normalization here: kernel GRE/IPIP devices
   656			// have protocol-specific default MTUs (1476/1462/...), not the
   657			// TUN 1500.
   658			if mtuErr := t.ops.LinkSetMTU(link, tc.MTU); mtuErr != nil {
   659				slog.Warn("failed to set tunnel mtu",
   660					"name", tc.Name, "mtu", tc.MTU, "err", mtuErr)
   661			}
   662		}
   663	
   664		// Keepalive reconcile (#1884 A.7, LEGACY BRANCH ONLY — anchors
   665		// never run probes). Identity-unchanged runners are retained so
   666		// probe state survives commits; the retained-and-DOWN case must
   667		// skip LinkSetUp below: keepaliveLoop's down-transition is gated
   668		// on state.Up==true, so re-upping the link here would strand it
   669		// admin UP forever while probes keep failing (r1 Codex F1 + AGY
   670		// converged trace).
   671		runner, hasRunner := t.keepalives[tc.Name]
   672		restartKA := tc.Keepalive > 0 && (!hasRunner || created || !runner.matches(tc))
   673		skipUp := false
   674		if tc.Keepalive > 0 && hasRunner && !restartKA {
   675			runner.state.mu.Lock()
   676			skipUp = !runner.state.Up
   677			runner.state.mu.Unlock()
   678		}
   679	
   680		t.finishTunnelLocked(tc, link, skipUp, "tunnel")
   681	
   682		if tc.Keepalive > 0 {
   683			if restartKA {
   684				// startKeepalive stops+drains any predecessor itself;
   685				// runs AFTER a recreate so the fresh runner probes the
   686				// new device. tc.Source is the bind endpoint (#1918 §5c).
   687				t.startKeepalive(tc.Name, tc.Source, tc.Destination, tc.Keepalive, tc.KeepaliveRetry)
   688			}
   689		} else if hasRunner {
   690			t.stopKeepaliveLocked(tc.Name)
   691		}
   692	}
   693	
   694	// finishTunnelLocked is the shared apply tail: admin-up (unless a
   695	// retained keepalive runner holds the tunnel down), symmetric address
   696	// reconciliation, VRF claim reconcile, and success tracking. Caller
   697	// MUST hold mu; link is the kernel-fetched (or just-created) device.
   698	func (t *tunnelManager) finishTunnelLocked(tc *config.TunnelConfig, link netlink.Link, skipUp bool, kind string) {
   699		if skipUp {
   700			slog.Debug("skipping link up: keepalive holds tunnel down",
   701				"name", tc.Name)
   702		} else if err := t.ops.LinkSetUp(link); err != nil {
   703			slog.Warn("failed to bring up "+kind, "name", tc.Name, "err", err)
   704		}
   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
   706			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
   707		t.reconcileVRFClaimLocked(tc, link)
   708		t.tunnels = append(t.tunnels, tc.Name)
   709	}
   710	
   711	// reconcileLinkAddrsLocked symmetrically reconciles a link's addresses
   712	// against the configured set: add configured-but-missing, delete
   713	// present-but-unconfigured — EXCEPT link-local addresses, which are
   714	// deleted only when this manager itself applied them (`applied`
   715	// gate). The kernel's autoconf fe80 must never be deleted, while a
   716	// CONFIGURED fe80 removed from config must not leak forever (#1884 r1
   717	// Codex F2; extended to the WG branch in #1905). applied == nil (the
   718	// first apply for a link this manager has not tracked yet — restart
   719	// adoption) means no link-local deletion at all.
   720	//
   721	// Returns the new applied set: successful adds + present-and-wanted +
   722	// link-local addresses whose stale-delete FAILED (kept tracked so the
   723	// next apply retries — r2 Codex F4).
   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
   725		want := make(map[string]bool, len(addrs))
   726		for _, addrStr := range addrs {
   727			addr, parseErr := netlink.ParseAddr(addrStr)
   728			if parseErr != nil {
   729				slog.Warn("invalid "+kind+" address",
   730					"name", name, "addr", addrStr, "err", parseErr)
   731				continue
   732			}
   733			want[addr.IPNet.String()] = true
   734		}
   735		newApplied := make(map[string]bool, len(want))
   736		existing := map[string]bool{}
   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
   738			for i := range list {
   739				a := list[i]
   740				key := a.IPNet.String()
   741				existing[key] = true
   742				if want[key] {
   743					continue
   744				}
   745				if a.IP == nil {
   746					// Defensive: the pre-#1884 WG block only deleted
   747					// addresses with a non-nil IP; keep that byte-identical
   748					// (and never delete something we cannot classify).
   749					continue
   750				}
   751				if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
   752					// Kernel-managed or foreign link-local: never delete.
   753					continue
   754				}
   755				if delErr := t.ops.AddrDel(link, &a); delErr != nil {
   756					slog.Warn("failed to remove stale "+kind+" address",
   757						"name", name, "addr", key, "err", delErr)
   758					if a.IP != nil && a.IP.IsLinkLocalUnicast() {
   759						newApplied[key] = true // retry next apply
   760					}
   761				} else {
   762					slog.Info("removed stale "+kind+" address",
   763						"name", name, "addr", key)
   764				}
   765			}
   766		}
   767		for _, addrStr := range addrs {
   768			addr, parseErr := netlink.ParseAddr(addrStr)
   769			if parseErr != nil {
   770				continue
   771			}
   772			key := addr.IPNet.String()
   773			if existing[key] {
   774				newApplied[key] = true
   775				continue
   776			}
   777			if addErr := t.ops.AddrAdd(link, addr); addErr != nil {
   778				slog.Warn("failed to add "+kind+" address",
   779					"name", name, "addr", addrStr, "err", addErr)
   780			} else {
   781				newApplied[key] = true
   782			}
   783		}
   784		return newApplied
   785	}

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '1020,1030p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '252,322p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
  1022	
  1023		if tc.RoutingInstance != "" {
  1024			if bindErr := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); bindErr != nil {
  1025				slog.Warn("failed to bind wireguard tun to VRF",
  1026					"name", tc.Name, "vrf", tc.RoutingInstance, "err", bindErr)
  1027			}
  1028		}
  1029		return nil
  1030	}

 succeeded in 0ms:
   252	func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
   253		t.mu.Lock()
   254		defer t.mu.Unlock()
   255		t.ensureReconcileStateLocked()
   256	
   257		desired := make(map[string]bool, len(tunnels))
   258		for _, tc := range tunnels {
   259			// WireGuard TUNs stay untracked/persistent (#1432 S2a, AGY
   260			// Hazard B) and are excluded from the removal diff.
   261			if tc.Mode != "wireguard" {
   262				desired[tc.Name] = true
   263			}
   264		}
   265	
   266		// oldOwned is the ENTRY-TIME ownership snapshot — the adoption
   267		// authority for the per-tunnel loop below (#1884 r2 Codex F1: the
   268		// rewritten set would mark every desired tunnel "owned" and make
   269		// adoption unreachable). next starts as the desired set; removal
   270		// failures retain their names so the next Apply retries instead of
   271		// orphaning a live link (r2 Codex F5).
   272		oldOwned := t.ownedNames
   273		next := make(map[string]bool, len(desired))
   274		for name := range desired {
   275			next[name] = true
   276		}
   277		for name := range oldOwned {
   278			if desired[name] {
   279				continue
   280			}
   281			t.stopKeepaliveLocked(name)
   282			if link, err := t.ops.LinkByName(name); err == nil {
   283				if delErr := t.ops.LinkDel(link); delErr != nil {
   284					slog.Warn("failed to delete removed tunnel",
   285						"name", name, "err", delErr)
   286					next[name] = true // retain ownership; retry next apply
   287					continue
   288				}
   289				slog.Info("tunnel removed", "name", name)
   290			}
   291			delete(t.appliedAddrs, name)
   292			delete(t.appliedRI, name)
   293		}
   294		t.ownedNames = next
   295		t.tunnels = nil // success-tracked (GetStatus); rebuilt below
   296	
   297		for _, tc := range tunnels {
   298			// WireGuard TUNs are persistent (#1432 S2a, AGY Hazard B): never
   299			// delete-and-recreate on reload — that would flap wgN and destroy
   300			// its addresses + FRR routes every commit. applyWireguardTunLocked
   301			// reuses an existing wgN in place.
   302			if tc.Mode == "wireguard" {
   303				if err := t.applyWireguardTunLocked(tc); err != nil {
   304					slog.Warn("failed to apply wireguard tunnel",
   305						"name", tc.Name, "err", err)
   306				}
   307				continue
   308			}
   309			// Adoption = this manager did NOT own the name at the last
   310			// apply (daemon restart, wireguard→gre same-name flip, foreign
   311			// but compatible TUN). Decided from the entry-time snapshot for
   312			// BOTH the plain-reuse and the LinkAdd-EEXIST paths.
   313			adopting := !oldOwned[tc.Name]
   314			if tc.AnchorOnly {
   315				t.applyAnchorLocked(tc, adopting)
   316				continue
   317			}
   318			t.applyKernelTunnelLocked(tc)
   319		}
   320	
   321		return nil
   322	}

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '548,582p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   548		// #1918 §6 Axis D F7 — drain-before-recreate. Decide up front whether
   549		// this apply will recreate (delete + re-add) the kernel link. If so,
   550		// CANCEL + DRAIN any existing keepalive runner BEFORE the LinkDel /
   551		// LinkAdd, so no stale runner goroutine can be mid-LinkSet* while the
   552		// link is recreated and the kernel reuses its ifindex (the F7
   553		// counterexample). The drain is the real serializer; it already
   554		// existed inside startKeepalive but ran AFTER the recreate. After the
   555		// drain the old runner's goroutine has returned and cannot issue any
   556		// further LinkSet*. linkGen is the defense-in-depth backstop.
   557		//
   558		// A lookup error must be classified (Codex PR #1947 r1 HIGH): only a
   559		// genuine NOT-FOUND means "absent → create". Any OTHER lookup error
   560		// (EBUSY / transport hiccup) is TRANSIENT — it does NOT mean the link
   561		// is gone, so we must NOT drain the live keepalive runner and must NOT
   562		// fall through to a LinkAdd that would EEXIST. Abort and retry next
   563		// apply, exactly like a transient LinkDel failure below.
   564		willRecreate := false
   565		var existing netlink.Link
   566		e, lookupErr := t.ops.LinkByName(tc.Name)
   567		switch {
   568		case lookupErr == nil:
   569			existing = e
   570			willRecreate = !legacyTunnelMatches(e, desired)
   571		case isLinkNotFound(lookupErr):
   572			// Absent → the LinkAdd below is a (re)create.
   573			willRecreate = true
   574		default:
   575			// Transient lookup error: leave the runner and any live link
   576			// untouched; retry on the next apply.
   577			slog.Warn("tunnel lookup failed transiently; deferring apply",
   578				"name", tc.Name, "err", lookupErr)
   579			return
   580		}
   581		if willRecreate {
   582			// Drain the stale runner first; bump the generation so any runner

exec
/bin/bash -lc "nl -ba pkg/routing/netlink_errors.go | sed -n '1,120p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
nl: pkg/routing/netlink_errors.go: No such file or directory

exec
/bin/bash -lc "rg -n \"func isLinkNotFound|isLinkNotFound\\(\" pkg/routing -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {

exec
/bin/bash -lc 'rg --files pkg/routing | xargs rg -n "isLinkNotFound|not found|ErrNotFound"' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
pkg/routing/tunnel.go:1416:			ts.State = "not found"
pkg/routing/probe_pin_test.go:45:	return fmt.Errorf("rule not found: prio %d", r.Priority)
pkg/routing/probe_pin_test.go:73:	return fmt.Errorf("route not found: table %d", r.Table)
pkg/routing/probe_pin_test.go:94:		return nil, fmt.Errorf("link %q not found", name)
pkg/routing/rules.go:414:			slog.Warn("PBR: routing-instance not found",
pkg/routing/iface_reuse_test.go:79:		return nil, errLinkNotFound{errors.New("link not found")}
pkg/routing/iface_reuse_test.go:84:	return nil, errLinkNotFound{errors.New("link not found")}
pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
pkg/routing/routing_test.go:41:	return nil, errLinkNotFound{errors.New("link not found")}
pkg/routing/routing_test.go:64:		return errors.New("link not found")
pkg/routing/routing_test.go:514:	return nil, errLinkNotFound{errors.New("link not found")}
pkg/routing/vrf.go:131:		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
pkg/routing/vrf.go:135:		return fmt.Errorf("VRF %s not found: %w", vrfName, err)
pkg/routing/vrf.go:145:// manager generates its own "not found" errors (e.g. from fakes in
pkg/routing/vrf.go:151:// isLinkNotFound reports whether err is a "link not found" error
pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
pkg/routing/bond.go:77:				slog.Warn("bond member not found",
pkg/routing/routes.go:88:		return nil, fmt.Errorf("VRF %q not found: %w", vrfName, err)
pkg/routing/probe_pin.go:191:			slog.Warn("probe pin: egress interface not found",
pkg/routing/tunnel_reconcile_test.go:33:		return errors.New("interface not found")
pkg/routing/tunnel_reconcile_test.go:37:		return errors.New("vrf not found")

exec
/bin/bash -lc "nl -ba docs/research/1919-wg-addr-route-prune/plan.md | sed -n '179,205p;273,299p;313,318p;334,336p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   179	### Path A — Track previously-configured WG names; diff on removal (RECOMMENDED)
   180	
   181	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
   182	to `ownedNames` but WG-only, and **never** feeding the `LinkDel` removal
   183	loop). Each `Apply`:
   184	
   185	1. Build `wgDesired` = set of `tc.Name` for current `Mode=="wireguard"`.
   186	2. **Prune phase** (new), run alongside the existing GRE removal loop:
   187	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
   188	   - look up the link (`LinkByName`); if found, call
   189	     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
   190	     "wireguard tun")` → strips manager-applied addresses (empty desired
   191	     set), honoring the link-local applied gate (kernel autoconf fe80
   192	     never touched).
   193	   - **Keep the link** — never `LinkDel` (that is the #1432 invariant).
   194	   - Optionally VRF-unbind (see §4a) — keep narrow for now.
   195	   - `delete(t.appliedAddrs, name)` once pruned (idempotent: a second
   196	     commit finds `name` no longer in old `wgConfigured`, so no-op).
   197	   - If `LinkByName` fails (device already gone — manual `ip link del`),
   198	     just `delete(t.appliedAddrs, name)` and drop tracking.
   199	   - If `reconcileLinkAddrsLocked` leaves residual tracked addresses
   200	     because an `AddrDel` failed, **retain** the name in the next
   201	     `wgConfigured` so the next commit retries (mirrors GRE
   202	     removal-retry at :197). Detect residual via the returned applied
   203	     set being non-empty.
   204	3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
   205	   plus any retained-for-retry names.
   273	`Apply`:
   274	```go
   275	wgDesired := map[string]bool{}
   276	for _, tc := range tunnels {
   277	    if tc.Mode == "wireguard" { wgDesired[tc.Name] = true }
   278	}
   279	oldWG := t.wgConfigured
   280	nextWG := map[string]bool{}
   281	for n := range wgDesired { nextWG[n] = true }
   282	// prune phase
   283	for name := range oldWG {
   284	    if wgDesired[name] { continue }
   285	    if link, err := t.ops.LinkByName(name); err == nil {
   286	        remaining := t.reconcileLinkAddrsLocked(link, name, nil,
   287	            t.appliedAddrs[name], "wireguard tun")
   288	        if len(remaining) > 0 {
   289	            t.appliedAddrs[name] = remaining
   290	            nextWG[name] = true // AddrDel failed → retry next apply
   291	            continue
   292	        }
   293	    }
   294	    delete(t.appliedAddrs, name)
   295	}
   296	// ... existing GRE removal loop unchanged ...
   297	// ... per-tunnel apply loop unchanged (still-configured WG re-tracked) ...
   298	t.wgConfigured = nextWG
   299	```
   313	Idempotency proof: after the prune commit, `oldWG` (next round) no longer
   314	contains the removed name (we set `t.wgConfigured = nextWG` which only
   315	carries retained-for-retry names). A clean prune drops the name entirely
   316	→ next `Apply` sees it in neither `oldWG` nor `wgDesired` → no-op. A
   317	failed-AddrDel prune keeps it in `nextWG` → retried until clean. ✔
   318	
   334	4. **`TestWireguardRemovalAddrDelFailureRetried`**: fake AddrDel returns
   335	   error on first removal Apply → assert name retained, second removal
   336	   Apply retries AddrDel.

exec
/bin/bash -lc "nl -ba pkg/routing/vrf.go | sed -n '145,165p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   145	// manager generates its own "not found" errors (e.g. from fakes in
   146	// tests, or from any path not going through the netlink library).
   147	// netlink.LinkNotFoundError cannot be constructed outside the
   148	// netlink package because its embedded error field is unexported.
   149	type errLinkNotFound struct{ error }
   150	
   151	// isLinkNotFound reports whether err is a "link not found" error
   152	// from either the netlink library or the internal sentinel. Other
   153	// errors (EINVAL, EBUSY, transport failure) must NOT be treated as
   154	// absence.
   155	func isLinkNotFound(err error) bool {
   156		if err == nil {
   157			return false
   158		}
   159		var nlNotFound netlink.LinkNotFoundError
   160		if errors.As(err, &nlNotFound) {
   161			return true
   162		}
   163		var internal errLinkNotFound
   164		return errors.As(err, &internal)
   165	}

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '277,293p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   277		for name := range oldOwned {
   278			if desired[name] {
   279				continue
   280			}
   281			t.stopKeepaliveLocked(name)
   282			if link, err := t.ops.LinkByName(name); err == nil {
   283				if delErr := t.ops.LinkDel(link); delErr != nil {
   284					slog.Warn("failed to delete removed tunnel",
   285						"name", name, "err", delErr)
   286					next[name] = true // retain ownership; retry next apply
   287					continue
   288				}
   289				slog.Info("tunnel removed", "name", name)
   290			}
   291			delete(t.appliedAddrs, name)
   292			delete(t.appliedRI, name)
   293		}

exec
/bin/bash -lc "rg -n \"LinkByName\\(name\\)|LinkByName\\(tc.Name\\)|lookup failed transiently|transient lookup|not-found\" docs/research/1919-wg-addr-route-prune/plan.md pkg/routing/tunnel.go" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/tunnel.go:282:		if link, err := t.ops.LinkByName(name); err == nil {
pkg/routing/tunnel.go:354:	if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {
pkg/routing/tunnel.go:384:			existing, lkErr := t.ops.LinkByName(tc.Name)
pkg/routing/tunnel.go:566:	e, lookupErr := t.ops.LinkByName(tc.Name)
pkg/routing/tunnel.go:577:		slog.Warn("tunnel lookup failed transiently; deferring apply",
pkg/routing/tunnel.go:802://     ours) / VRF device not-found (kernel already freed the slaves);
pkg/routing/tunnel.go:940:	link, err := t.ops.LinkByName(tc.Name)
pkg/routing/tunnel.go:1378:		link, err := t.ops.LinkByName(name)
pkg/routing/tunnel.go:1414:		link, err := t.ops.LinkByName(name)
docs/research/1919-wg-addr-route-prune/plan.md:285:    if link, err := t.ops.LinkByName(name); err == nil {
docs/research/1919-wg-addr-route-prune/plan.md:338:   not-found on removal → assert no panic, tracking dropped, no-op next.

exec
/bin/bash -lc "nl -ba pkg/routing/vrf.go | sed -n '110,140p;166,188p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   110	// serialized reconciles avoid TOCTOU between concurrent callers.
   111	func (v *vrfManager) Reconcile(desired []VRFSpec) error {
   112		v.mu.Lock()
   113		defer v.mu.Unlock()
   114		newVrfs, err := reconcileVRFs(v.ops, v.vrfs, desired)
   115		v.vrfs = newVrfs
   116		return err
   117	}
   118	
   119	// BindInterfaceToVRF binds a network interface to a VRF device.
   120	//
   121	// This method takes NO lock — it is a pure netlink operation
   122	// (LinkByName + LinkSetMaster) and touches no vrfManager field. That
   123	// lock-free property is what makes it safe for the tunnel domain to
   124	// call while holding its own lock (see tunnel.go), with no lock
   125	// ordering cycle.
   126	func (v *vrfManager) BindInterfaceToVRF(ifaceName, instanceName string) error {
   127		vrfName := "vrf-" + instanceName
   128	
   129		iface, err := v.ops.LinkByName(ifaceName)
   130		if err != nil {
   131			return fmt.Errorf("interface %s not found: %w", ifaceName, err)
   132		}
   133		vrf, err := v.ops.LinkByName(vrfName)
   134		if err != nil {
   135			return fmt.Errorf("VRF %s not found: %w", vrfName, err)
   136		}
   137		if err := v.ops.LinkSetMaster(iface, vrf); err != nil {
   138			return fmt.Errorf("bind %s to VRF %s: %w", ifaceName, vrfName, err)
   139		}
   140		slog.Info("interface bound to VRF", "interface", ifaceName, "vrf", vrfName)
   166	
   167	// reconcileVRFs is the pure core of Reconcile, parameterised on a
   168	// vrfOps so tests can inject a fake. Returns the new tracked set and
   169	// the first error encountered (others are logged).
   170	//
   171	// Ownership semantics: xpfd is authoritative for the ENTIRE "vrf-*"
   172	// kernel namespace. A VRF is "ours" by virtue of name prefix; if its
   173	// logical name appears in desired, reconcileVRFs ADOPTS it into
   174	// v.vrfs (handles the post-restart case). #847 orphan reap: any
   175	// kernel "vrf-*" device NOT in desired AND NOT in v.vrfs is also
   176	// deleted, so operators must NOT pre-create vrf-<name> outside
   177	// xpfd config.
   178	//
   179	// Partial-failure contract: if LinkAdd succeeds but a follow-up
   180	// (LinkByName / LinkSetUp) fails, the VRF is still recorded in the
   181	// tracked set. Similarly, LinkDel failures retain ownership. This
   182	// ensures a future reconcile can retry.
   183	func reconcileVRFs(ops vrfOps, tracked []string, desired []VRFSpec) ([]string, error) {
   184		desiredByName := make(map[string]int, len(desired))
   185		for _, spec := range desired {
   186			desiredByName["vrf-"+spec.Name] = spec.TableID
   187		}
   188		managed := make(map[string]bool, len(tracked))

exec
/bin/bash -lc "nl -ba pkg/routing/tunnel.go | sed -n '176,190p;806,862p;1020,1028p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   176		ownedNames map[string]bool
   177		// appliedAddrs: per tunnel, the address set this manager itself
   178		// ensured (successful adds + present-and-wanted + link-local whose
   179		// stale-delete failed). Gates stale LINK-LOCAL deletion: a
   180		// configured fe80 we applied is removable; the kernel's autoconf
   181		// fe80 is never touched.
   182		appliedAddrs map[string]map[string]bool
   183		// appliedRI: per tunnel, the routing-instance whose VRF this
   184		// manager successfully bound — or directly OBSERVED as the link's
   185		// master for a step-0a `routing-instances <ri> interface` list
   186		// bind. Invariant (#1884 r6-r8): a claim is only ever written from
   187		// a successful bind or a master observation, never an intent.
   188		// Unbind on config-wants-none is identity-gated against
   189		// vrf-<claim>.
   190		appliedRI map[string]string
   806	func (t *tunnelManager) reconcileVRFClaimLocked(tc *config.TunnelConfig, link netlink.Link) {
   807		name := tc.Name
   808		if tc.RoutingInstance != "" {
   809			if err := t.vrfBinder.BindInterfaceToVRF(name, tc.RoutingInstance); err != nil {
   810				slog.Warn("failed to bind tunnel to VRF",
   811					"name", name, "vrf", tc.RoutingInstance, "err", err)
   812				// r7/r8: a FAILED bind must not blind-write the claim (the
   813				// kernel may still carry the previous master, or a 0a list
   814				// bind). Observation may take the claim; else retain.
   815				t.observeListClaimLocked(tc, link)
   816				return
   817			}
   818			t.appliedRI[name] = tc.RoutingInstance
   819			return
   820		}
   821		if tc.RIListMember != "" {
   822			// Unbind VETO: a stanza→list move must never strip the 0a
   823			// bind (r4 convergent counterexample).
   824			t.observeListClaimLocked(tc, link)
   825			return
   826		}
   827	
   828		claim := t.appliedRI[name]
   829		if claim == "" {
   830			return
   831		}
   832		master := link.Attrs().MasterIndex
   833		if master == 0 {
   834			// Nothing is bound — whatever we once bound is already gone.
   835			delete(t.appliedRI, name)
   836			return
   837		}
   838		vrf, err := t.ops.LinkByName("vrf-" + claim)
   839		if err != nil {
   840			if isLinkNotFound(err) {
   841				// The VRF device is gone; deleting a master frees its
   842				// slaves, so the current master cannot be ours.
   843				delete(t.appliedRI, name)
   844				return
   845			}
   846			// Transient lookup error: retain the claim, retry next apply.
   847			return
   848		}
   849		if vrf.Attrs().Index != master {
   850			// Master is not the VRF we bound (someone else's bind).
   851			delete(t.appliedRI, name)
   852			return
   853		}
   854		if err := t.ops.LinkSetNoMaster(link); err != nil {
   855			slog.Warn("failed to unbind tunnel from VRF",
   856				"name", name, "vrf", claim, "err", err)
   857			return // retain claim; retry next apply
   858		}
   859		slog.Info("tunnel unbound from routing-instance",
   860			"name", name, "vrf", claim)
   861		delete(t.appliedRI, name)
   862	}
  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
  1022	
  1023		if tc.RoutingInstance != "" {
  1024			if bindErr := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); bindErr != nil {
  1025				slog.Warn("failed to bind wireguard tun to VRF",
  1026					"name", tc.Name, "vrf", tc.RoutingInstance, "err", bindErr)
  1027			}
  1028		}

exec
/bin/bash -lc "nl -ba docs/research/1919-wg-addr-route-prune/plan.md | sed -n '237,256p;358,359p'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   237	### 4a. VRF unbind on WG removal — scope decision
   238	
   239	`applyWireguardTunLocked` VRF-binds at `:883-888` but does NOT use
   240	`reconcileVRFClaimLocked`/`appliedRI` (it binds directly, no claim
   241	tracked). So a removed WG tunnel that was VRF-bound leaves the link
   242	enslaved to `vrf-<ri>`. Two choices:
   243	
   244	- **A1 (recommended for this PR)**: prune **addresses only**; leave the
   245	  VRF master as-is. Rationale: the link persists by design; its VRF
   246	  membership is a property of the persistent device, not a leaked
   247	  address; and there is no `appliedRI` claim to safely identity-gate an
   248	  unbind (unbinding blind would risk stripping a master we do not own —
   249	  the exact hazard `reconcileVRFClaimLocked` was built to avoid). Note
   250	  this explicitly as a documented residual, tracked under #1434.
   251	- **A2**: extend WG to use `appliedRI`/`reconcileVRFClaimLocked` so
   252	  removal can identity-gated-unbind. Larger change; couples this fix to
   253	  the VRF-claim machinery WG deliberately bypasses. Defer.
   254	
   255	Decision: **A1** — addresses only, VRF residual documented. If a
   256	reviewer demands VRF unbind, escalate to A2 as a follow-up, not this PR.
   358	2. **VRF unbind on WG removal** (§4a): A1 (addresses only) vs A2 (full
   359	   VRF-claim adoption for WG). Plan: A1, residual documented.

exec
/bin/bash -lc 'rg -n "MasterIndex|LinkSetMaster|LinkSetNoMaster|BindInterfaceToVRF" pkg/routing/vrf.go pkg/routing/tunnel.go pkg/routing/tunnel_reconcile_test.go | head -n 120' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
pkg/routing/tunnel_reconcile_test.go:18:// fakeVRFBinder mimics vrfManager.BindInterfaceToVRF against the
pkg/routing/tunnel_reconcile_test.go:20:// MasterIndex to the vrf-<ri> device's index (the daemon-prefixed VRF
pkg/routing/tunnel_reconcile_test.go:21:// naming, vrf.go BindInterfaceToVRF).
pkg/routing/tunnel_reconcile_test.go:27:func (b *fakeVRFBinder) BindInterfaceToVRF(ifaceName, instanceName string) error {
pkg/routing/tunnel_reconcile_test.go:39:	iface.Attrs().MasterIndex = vrf.Attrs().Index
pkg/routing/tunnel_reconcile_test.go:446:	if got := ops.links["gr-0-0-0"].Attrs().MasterIndex; got != 100 {
pkg/routing/tunnel_reconcile_test.go:455:		t.Fatalf("expected exactly one LinkSetNoMaster, got %v", ops.noMaster)
pkg/routing/tunnel_reconcile_test.go:510:	anchor.Attrs().MasterIndex = 200 // 0a-style bind, not ours
pkg/routing/tunnel_reconcile_test.go:538:	ops.links["gr-0-0-0"].Attrs().MasterIndex = 200
pkg/routing/tunnel_reconcile_test.go:612:	ops.links["gr-0-0-0"].Attrs().MasterIndex = 300
pkg/routing/tunnel_reconcile_test.go:913:	ops.links["gr-0-0-0"].Attrs().MasterIndex = 200 // 0a bind
pkg/routing/tunnel_reconcile_test.go:947:	if got := ops.links["gr-0-0-0"].Attrs().MasterIndex; got != 100 {
pkg/routing/tunnel_reconcile_test.go:967:	ops.links["gr-0-0-0"].Attrs().MasterIndex = 100 // stale-looking master
pkg/routing/tunnel.go:27:	LinkSetMaster(netlink.Link, netlink.Link) error
pkg/routing/tunnel.go:28:	LinkSetNoMaster(netlink.Link) error
pkg/routing/tunnel.go:38:// BindInterfaceToVRF takes no lock, so calling it while holding the
pkg/routing/tunnel.go:41:	BindInterfaceToVRF(ifaceName, instanceName string) error
pkg/routing/tunnel.go:789:// from a SUCCESSFUL BindInterfaceToVRF or a direct observation of the
pkg/routing/tunnel.go:809:		if err := t.vrfBinder.BindInterfaceToVRF(name, tc.RoutingInstance); err != nil {
pkg/routing/tunnel.go:832:	master := link.Attrs().MasterIndex
pkg/routing/tunnel.go:854:	if err := t.ops.LinkSetNoMaster(link); err != nil {
pkg/routing/tunnel.go:875:	master := link.Attrs().MasterIndex
pkg/routing/tunnel.go:1024:		if bindErr := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); bindErr != nil {
pkg/routing/vrf.go:27:	LinkSetMaster(netlink.Link, netlink.Link) error
pkg/routing/vrf.go:119:// BindInterfaceToVRF binds a network interface to a VRF device.
pkg/routing/vrf.go:122:// (LinkByName + LinkSetMaster) and touches no vrfManager field. That
pkg/routing/vrf.go:126:func (v *vrfManager) BindInterfaceToVRF(ifaceName, instanceName string) error {
pkg/routing/vrf.go:137:	if err := v.ops.LinkSetMaster(iface, vrf); err != nil {

codex
**Verdict: PLAN-NEEDS-MAJOR**

**Findings**

- **MAJOR: Path A’s retry signal is broken for regular addresses.** The plan’s removal sketch relies on `len(remaining)>0` after `reconcileLinkAddrsLocked(..., nil, ...)` to retain `wgConfigured` for retry ([plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285), [plan.md:288](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:288)). But source only re-adds a failed stale delete to `newApplied` if the address is link-local: `if a.IP.IsLinkLocalUnicast() { newApplied[key] = true }` ([tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755), [tunnel.go:758](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:758)). With empty desired addrs, a failed `AddrDel` for `172.16.0.1/30` returns an empty map, so Path A deletes tracking and does not retry ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:293)). The fake confirms failed `AddrDel` leaves the address present ([iface_reuse_test.go:143](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/iface_reuse_test.go:143)). This must be fixed before implementation. The proposed retry test must use a non-link-local address, not only `fe80`.

- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.

- **MEDIUM: The plan overclaims “manager-applied addresses only.”** `appliedAddrs` only gates stale link-local deletion. For non-link-local stale addresses, `reconcileLinkAddrsLocked` deletes them regardless of whether they are in `applied` ([tunnel.go:751](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751), [tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755)). That may match existing configured-WG behavior, but the plan should stop claiming the removal path is strictly applied-address scoped unless it adds an explicit filter.

- **FRR scoping is mostly correct.** I found no WG config path that synthesizes a managed FRR static route. `assembleFRRConfig` is the sole production `FullConfig` constructor and fills FRR from static routes, protocols, DHCP, policy, interface hints, and instances, not tunnels ([frr_fullconfig_guard_test.go:13](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/daemon/frr_fullconfig_guard_test.go:13), [daemon_ipmon.go:89](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/daemon/daemon_ipmon.go:89), [daemon_ipmon.go:105](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/daemon/daemon_ipmon.go:105)). `WgAllowedIPs` is documented as decap-only ([types_routing.go:325](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/config/types_routing.go:325)); userspace confirms AllowedIPs is not egress routing ([engine.rs:1](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/userspace-dp/src/afxdp/wg/engine.rs:1), [engine.rs:761](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/userspace-dp/src/afxdp/wg/engine.rs:761)). Nuance: FRR can redistribute connected routes via generic policy (`direct` → `connected`) ([policy_render.go:62](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/frr/policy_render.go:62)). That is still caused by the leaked kernel connected route, not a WG-managed FRR static route.

- **VRF A1 is a real residual, but acceptable as a scoped deferral.** WG binds directly via `BindInterfaceToVRF` ([tunnel.go:1023](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:1023)) and does not write `appliedRI`; identity-gated unbind exists only in `reconcileVRFClaimLocked` ([tunnel.go:183](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:183), [tunnel.go:828](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:828)). Leaving the persistent link enslaved can surprise later manual/re-add use, but blind unbind is unsafe. Documenting it for #1434 is reasonable.

- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.

- **#1918 interaction claim is correct for Go tunnel keepalives.** `Apply` sends WG configs to `applyWireguardTunLocked` and `continue`s ([tunnel.go:297](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:297)); `startKeepalive` is only in the legacy non-WG path ([tunnel.go:664](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:664), [tunnel.go:682](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:682)). Minor wording nit: WG has protocol persistent keepalive fields, but that is Rust WG behavior, not the #1918 ICMP/link-admin keepalive.

Clean add → remove → remove-again is idempotent only when all deletes and lookup succeed. The non-link-local `AddrDel` failure path breaks the plan’s central retry invariant, so this is not ready.
tokens used
155,858
**Verdict: PLAN-NEEDS-MAJOR**

**Findings**

- **MAJOR: Path A’s retry signal is broken for regular addresses.** The plan’s removal sketch relies on `len(remaining)>0` after `reconcileLinkAddrsLocked(..., nil, ...)` to retain `wgConfigured` for retry ([plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285), [plan.md:288](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:288)). But source only re-adds a failed stale delete to `newApplied` if the address is link-local: `if a.IP.IsLinkLocalUnicast() { newApplied[key] = true }` ([tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755), [tunnel.go:758](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:758)). With empty desired addrs, a failed `AddrDel` for `172.16.0.1/30` returns an empty map, so Path A deletes tracking and does not retry ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:293)). The fake confirms failed `AddrDel` leaves the address present ([iface_reuse_test.go:143](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/iface_reuse_test.go:143)). This must be fixed before implementation. The proposed retry test must use a non-link-local address, not only `fe80`.

- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.

- **MEDIUM: The plan overclaims “manager-applied addresses only.”** `appliedAddrs` only gates stale link-local deletion. For non-link-local stale addresses, `reconcileLinkAddrsLocked` deletes them regardless of whether they are in `applied` ([tunnel.go:751](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751), [tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755)). That may match existing configured-WG behavior, but the plan should stop claiming the removal path is strictly applied-address scoped unless it adds an explicit filter.

- **FRR scoping is mostly correct.** I found no WG config path that synthesizes a managed FRR static route. `assembleFRRConfig` is the sole production `FullConfig` constructor and fills FRR from static routes, protocols, DHCP, policy, interface hints, and instances, not tunnels ([frr_fullconfig_guard_test.go:13](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/daemon/frr_fullconfig_guard_test.go:13), [daemon_ipmon.go:89](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/daemon/daemon_ipmon.go:89), [daemon_ipmon.go:105](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/daemon/daemon_ipmon.go:105)). `WgAllowedIPs` is documented as decap-only ([types_routing.go:325](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/config/types_routing.go:325)); userspace confirms AllowedIPs is not egress routing ([engine.rs:1](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/userspace-dp/src/afxdp/wg/engine.rs:1), [engine.rs:761](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/userspace-dp/src/afxdp/wg/engine.rs:761)). Nuance: FRR can redistribute connected routes via generic policy (`direct` → `connected`) ([policy_render.go:62](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/frr/policy_render.go:62)). That is still caused by the leaked kernel connected route, not a WG-managed FRR static route.

- **VRF A1 is a real residual, but acceptable as a scoped deferral.** WG binds directly via `BindInterfaceToVRF` ([tunnel.go:1023](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:1023)) and does not write `appliedRI`; identity-gated unbind exists only in `reconcileVRFClaimLocked` ([tunnel.go:183](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:183), [tunnel.go:828](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:828)). Leaving the persistent link enslaved can surprise later manual/re-add use, but blind unbind is unsafe. Documenting it for #1434 is reasonable.

- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.

- **#1918 interaction claim is correct for Go tunnel keepalives.** `Apply` sends WG configs to `applyWireguardTunLocked` and `continue`s ([tunnel.go:297](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:297)); `startKeepalive` is only in the legacy non-WG path ([tunnel.go:664](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:664), [tunnel.go:682](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:682)). Minor wording nit: WG has protocol persistent keepalive fields, but that is Rust WG behavior, not the #1918 ICMP/link-admin keepalive.

Clean add → remove → remove-again is idempotent only when all deletes and lookup succeed. The non-link-local `AddrDel` failure path breaks the plan’s central retry invariant, so this is not ready.
