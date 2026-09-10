#!/usr/bin/env python3
"""#9412 mutation matrix (generated from the #9546 runner) — two languages, per-mutant legs.

A runner that gates in ONE language scores every cross-language mutant as an
ESCAPE, because nothing it ran could have failed. So each mutant names the
leg(s) that can kill it, and only those legs are scored.

Discipline (each rule burned a lane in this campaign):
  - APPLIED is proven in both directions: the target's count before, after,
    and the replacement's count rising. Occurrence-indexed edits hit ONE site.
  - A build break is VOID(build) — except a Rust `const _` offset assert or a
    Go compile-time pin firing, which none of these mutants is designed to trip.
  - Every run is bounded; a timeout panic or an overrun is VOID(hang).
  - Real ENOSPC only: a PASSING pkg/configstore test emits
    `injected: no space left on device`, so that line is excluded (#9500).
  - The target cells must EXECUTE (Go `run`, not `skip`; Rust named `... ok`
    or `... FAILED`) or the verdict is VOID — a skipped cell scores every
    mutant as SURVIVED (#9337).
  - Go verdicts come from `go test -json` Action=="fail" with the NAME matched.
"""
import json, os, re, subprocess, sys

REPO = "/var/tmp/wt-9412b"
GO_PKGS = ["./pkg/dataplane/userspace/", "./pkg/daemon/", "./pkg/cluster/"]
RUST_FILTERS = ["9412", "event_stream::codec::tests", "tests_session_delta_json", "synced_sessions_do_not_emit_deltas"]
TIMEOUT = 1500
MIN_GO = 1000
PRIV = ["sudo", "-n", "env", "XPF_REQUIRE_MEMLOCK_GUARDS=1", "PATH=/usr/bin:/bin", "HOME=/root"]

B = "pkg/dataplane/bpf_session_value.go"
T = "pkg/dataplane/types.go"
H = "bpf/headers/xpf_conntrack.h"
P = "userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs"
C = "userspace-dp/src/protocol/control.rs"

CONV = "\t\tRoutingDomain:  v.RoutingDomain,\n"
ROWCALL = "        routing_domain: conntrack_row_routing_domain(key, metadata),\n"

# (name, legs, edits, target-cell regex)
#   edit = (file, find, replace, occurrence) ; occurrence None = the only one.
RS = "userspace-dp/src/"  # the Rust source root the mutant paths are relative to
MUTANTS = [
    # ---------------- Rust: primary producer
    ("R1 WIRING: the close-state emission call is severed in lookup",
     ["rust"], [(RS + "session/lookup.rs", "        if closed_this_packet {\n            self.emit_close_state_update(&actual_key, close_class_before);\n        }\n", "", None)],
     r"a_close_on_the_primary_produces_a_sync_delta_9412|a_close_emits_one_update_per_class_transition_9412"),
    ("R2 no transition dedupe: every closing packet emits",
     ["rust"], [(RS + "session/mod.rs", "        if class_after == class_before {\n            return;\n        }\n", "", None)],
     r"a_close_emits_one_update_per_class_transition_9412"),
    ("R3 a reverse-half FIN is not resolved to the forward entry",
     ["rust"], [(RS + "session/mod.rs", "        let forward_key = if matched.metadata.is_reverse {", "        let forward_key = if false && matched.metadata.is_reverse {", None)],
     r"a_close_emits_one_update_per_class_transition_9412"),
    ("R4 a peer-synced copy echoes an Update back to its owner",
     ["rust"], [(RS + "session/mod.rs", "        if forward.metadata.is_reverse || forward.origin.is_peer_synced() {", "        if forward.metadata.is_reverse {", None)],
     r"synced_sessions_do_not_emit_deltas"),
    ("R11 the resync re-export stamps 0 instead of the live class",
     ["rust"], [(RS + "session/install.rs", "        let tcp_close_class = self.close_class_wire_for(&key);\n", "        let tcp_close_class = 0 * self.close_class_wire_for(&key);\n", None)],
     r"a_resync_reexport_carries_the_live_close_class_9412"),
    # ---------------- Rust: transport
    ("R8 the open-layout frame omits the trailing close-class byte",
     ["rust"], [(RS + "event_stream/codec/session_sync.rs", "        buf[pos] = tcp_close_class;\n        pos += 1;\n", "", None)],
     r"shared_golden_9412|open_carries_the_close_class_9412"),
    ("R9 an Update is encoded as an OPEN frame type",
     ["rust"], [(RS + "event_stream/codec/session_sync.rs", "        Self::encode_session_record(\n            MSG_SESSION_UPDATE,", "        Self::encode_session_record(\n            MSG_SESSION_OPEN,", None)],
     r"shared_golden_9412|update_syncs_without_an_rt_flow_create_9412"),
    ("R10 an Update emits an RT_FLOW SESSION_CREATE",
     ["rust"], [(RS + "afxdp/session_delta.rs", "            if delta.kind == SessionDeltaKind::Open && delta.metadata.log_session_init {", "            if (delta.kind == SessionDeltaKind::Open || delta.kind == SessionDeltaKind::Update) && delta.metadata.log_session_init {", None)],
     r"update_syncs_without_an_rt_flow_create_9412"),
    ("R10b BOTH gates admit an Update: the SESSION_CREATE caller gate AND the emitter's own kind gate",
     ["rust"], [(RS + "afxdp/session_delta.rs", "            if delta.kind == SessionDeltaKind::Open && delta.metadata.log_session_init {", "            if (delta.kind == SessionDeltaKind::Open || delta.kind == SessionDeltaKind::Update) && delta.metadata.log_session_init {", None),
                (RS + "event_stream/rt_flow.rs", "        if delta.kind != SessionDeltaKind::Open {\n            return;\n        }\n", "        if delta.kind != SessionDeltaKind::Open && delta.kind != SessionDeltaKind::Update {\n            return;\n        }\n", None)],
     r"update_syncs_without_an_rt_flow_create_9412"),
    ("R13 the JSON leg drops the close class",
     ["rust"], [(RS + "afxdp/session_delta.rs", "        tcp_close_class: delta.tcp_close_class,\n", "        tcp_close_class: 0 * delta.tcp_close_class,\n", None)],
     r"session_delta_info_carries_the_close_class_and_names_an_update_9412"),
    # ---------------- Rust: standby import
    ("R14 the wire import drops the request's class",
     ["rust"], [(RS + "server/helpers/session_sync.rs", "        tcp_close_class: req.tcp_close_class,\n", "        tcp_close_class: 0 * req.tcp_close_class,\n", None)],
     r"reaps_on_the_(closing|time_wait|rst)_window_9412"),
    ("R12 the shared install mapping drops the class",
     ["rust"], [(RS + "afxdp/worker/synced_entry.rs", "            tcp_close_class: self.tcp_close_class,\n", "            tcp_close_class: 0 * self.tcp_close_class,\n", None)],
     r"reaps_on_the_(closing|time_wait|rst)_window_9412"),
    ("R5 the install ignores the peer-stated class",
     ["rust"], [(RS + "session/install.rs", "            TcpCloseClass::from_wire(wire_close_class)\n", "            TcpCloseClass::from_wire(0 * wire_close_class)\n", None)],
     r"reaps_on_the_(closing|time_wait|rst)_window_9412"),
    ("R6 an imported TIME_WAIT is collapsed to CLOSING",
     ["rust"], [(RS + "session/install.rs", "                fin_peer: matches!(wire_close, Some(TcpCloseClass::TimeWait)),\n", "                fin_peer: false,\n", None)],
     r"an_imported_time_wait_session_reaps_on_the_time_wait_window_9412|an_import_reads_back_as_the_peer_stated_class_9412"),
    ("R15 the Rust SessionSyncRequest wire key is renamed on one side",
     ["rust", "go"], [(RS + "protocol/control.rs", '    #[serde(rename = "tcp_close_class", default)]\n    pub tcp_close_class: u8,\n}', '    #[serde(rename = "close_class", default)]\n    pub tcp_close_class: u8,\n}', None)],
     r"reaps_on_the_(closing|time_wait|rst)_window_9412|TestCloseClassWireKeyLockstepWithRust9412"),
    ("R16 one-sided protocol bump (Rust left at 12)",
     ["go"], [(RS + "protocol/control.rs", "pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 13;", "pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 12;", None)],
     r"Lockstep|MixedVersion|9054"),
    # ---------------- Go hops
    ("G1 the event-stream decode drops the byte",
     ["go"], [("pkg/dataplane/userspace/eventstream.go", "\t\td.TCPCloseClass = payload[off]\n", "\t\t_ = payload[off]\n", None)],
     r"TestDecodeSessionEventCarriesTheCloseClass9412|TestSessionUpdateGoldenFrameDecodes9412"),
    ("G2 the walker drops an \"update\" event",
     ["go"], [("pkg/daemon/daemon_ha_userspace_stream.go", '\t\tcase "open", "update":\n', '\t\tcase "open":\n', None)],
     r"TestAnUpdateDeltaIsSyncedWithItsCloseClass9412"),
    ("G3 the v4 convert drops the class",
     ["go"], [("pkg/daemon/daemon_ha_userspace_convert.go", "\tval.TCPCloseClass = delta.TCPCloseClass\n", "\t_ = delta.TCPCloseClass\n", 1)],
     r"TestConvertCarriesTheCloseClass9412|TestAnUpdateDeltaIsSyncedWithItsCloseClass9412"),
    ("G4 the v4 cluster encode writes 0",
     ["go"], [("pkg/cluster/sync_protocol.go", "\tbuf[off] = val.TCPCloseClass\n", "\tbuf[off] = 0\n", 1)],
     r"TestTheCloseClassCrossesTheClusterWire9412"),
    ("G5 the v6 cluster decode drops the byte",
     ["go"], [("pkg/cluster/sync_protocol.go", "\t\tval.TCPCloseClass = payload[off]\n", "\t\t_ = payload[off]\n", 2)],
     r"TestTheCloseClassCrossesTheClusterWire9412"),
    ("G6 the v4 sync request drops the class",
     ["go"], [("pkg/dataplane/userspace/manager_sessionsync_request.go", "req.TCPCloseClass = val.TCPCloseClass\n", "_ = val.TCPCloseClass\n", 1)],
     r"TestSessionSyncRequestCarriesTheCloseClass9412"),
    ("G7 the Go SessionSyncRequest json tag is renamed on one side",
     ["go"], [("pkg/dataplane/userspace/protocol_ha.go", '\tTCPCloseClass uint8 `json:"tcp_close_class,omitempty"`\n', '\tTCPCloseClass uint8 `json:"close_class,omitempty"`\n', 1)],
     r"TestCloseClassWireKeyLockstepWithRust9412|TestSessionSyncRequestCarriesTheCloseClass9412"),
    # ---------------- Go F1: the sender-side close-class memo (the live failure's cause 1)
    ("F1a WIRING: the v4 stamp never consults the memo",
     ["go"], [("pkg/cluster/sync_conn_gen.go", "\tstampCloseClassLocked(s.closeClassSentV4, key, val.SessionID, &val.TCPCloseClass)\n", "", None)],
     r"TestSweepResendKeepsTheAnnouncedCloseClass9412|TestBulkResendKeepsTheAnnouncedCloseClass9412"),
    ("F1b WIRING: the v6 stamp never consults the memo",
     ["go"], [("pkg/cluster/sync_conn_gen.go", "\tstampCloseClassLocked(s.closeClassSentV6, key, val.SessionID, &val.TCPCloseClass)\n", "", None)],
     r"TestSweepResendKeepsTheAnnouncedCloseClassV6_9412"),
    ("F1c tuple-only keying: a reused tuple inherits the old class",
     ["go"], [("pkg/cluster/sync_close_class_9412.go", "\tif ok && rec.sessionID != sessionID {\n", "\tif false && ok && rec.sessionID != sessionID {\n", None)],
     r"TestReusedTupleNeverInheritsTheOldCloseClass9412"),
    ("F1d SessionID 0 is treated as an identity",
     ["go"], [("pkg/cluster/sync_close_class_9412.go", "\tif sessionID == 0 {\n", "\tif false && sessionID == 0 {\n", None)],
     r"TestNoSessionIdentityNeverRecordsOrApplies9412"),
    ("F1e a delete does not evict the memo",
     ["go"], [("pkg/cluster/sync_conn_gen.go", "\tdelete(s.closeClassSentV4, key)\n", "", None)],
     r"TestDeleteEvictsTheCloseClassMemo9412"),
    ("F1f the memo fills only a class-0 frame, so a lower class regresses",
     ["go"], [("pkg/cluster/sync_close_class_9412.go", "\tif ok && rec.class > *class {\n", "\tif ok && *class == 0 {\n", None)],
     r"TestCloseClassNeverRegressesWithinAnIncarnation9412"),
    ("F1g the memo is unbounded",
     ["go"], [("pkg/cluster/sync_close_class_9412.go", "\tif !ok && len(m) >= genGuardMapCap {\n", "\tif false && !ok && len(m) >= genGuardMapCap {\n", None)],
     r"TestCloseClassMemoIsBoundedAtTheGenerationCap9412"),
    ("F1h at the cap an existing record stops progressing",
     ["go"], [("pkg/cluster/sync_close_class_9412.go", "\tif !ok && len(m) >= genGuardMapCap {\n", "\tif len(m) >= genGuardMapCap {\n", None)],
     r"TestCloseClassMemoIsBoundedAtTheGenerationCap9412"),
    ("F1i the receiver admits a strictly-older generation (the adversarial order)",
     ["go"], [("pkg/cluster/sync_conn_gen.go", "\tstored, ok := s.recvGenV4[key]\n\tif ok && stored != 0 && incoming != 0 && incoming < stored {\n", "\tstored, ok := s.recvGenV4[key]\n\tif false && ok && stored != 0 && incoming != 0 && incoming < stored {\n", None)],
     r"TestLateOldIncarnationCloseFrameIsRefused9412"),
    # ---------------- Rust F3 + promote: the reverse companion and the promote republish
    ("F3 the synthesized reverse companion drops the forward class",
     ["rust"], [(RS + "afxdp/shared_ops.rs", "tcp_close_class: entry.tcp_close_class,", "tcp_close_class: 0 * entry.tcp_close_class,", None)],
     r"reverse_companion_inherits_forward_close_class_9412"),
    ("P1 the promote republish stamps 0 instead of the live class",
     ["rust"], [(RS + "afxdp/session_glue/promote.rs", "tcp_close_class: sessions.close_class_wire_for(key),", "tcp_close_class: 0 * sessions.close_class_wire_for(key),", None)],
     r"promote_republishes_the_live_close_class_9412"),
]

def apply(edits):
    backups, ok = {}, True
    for f, find, repl, occ in edits:
        path = os.path.join(REPO, f)
        s = backups.get(f) if f in backups else open(path).read()
        if f not in backups:
            backups[f] = s
        cur = open(path).read()
        n = cur.count(find)
        if occ is None:
            if n != 1:
                print(f"  APPLY FAILED: {f} target count {n}, want 1"); ok = False; break
            new = cur.replace(find, repl)
        else:
            if n < occ:
                print(f"  APPLY FAILED: {f} has {n} occurrences, want >= {occ}"); ok = False; break
            idx = -1
            for _ in range(occ):
                idx = cur.index(find, idx + 1)
            new = cur[:idx] + repl + cur[idx + len(find):]
        if new.count(find) != n - 1:
            print(f"  APPLY FAILED: {f} target {n} -> {new.count(find)}, want {n-1}"); ok = False; break
        if repl.strip() and new.count(repl) <= cur.count(repl):
            print(f"  APPLY FAILED: {f} replacement did not rise"); ok = False; break
        open(path, "w").write(new)
        print(f"  applied: {f} target {n} -> {n-1}")
    return backups, ok


def restore(backups):
    for f in backups:
        head = subprocess.run(["git", "show", f"HEAD:{f}"], cwd=REPO, capture_output=True, text=True, check=True).stdout
        open(os.path.join(REPO, f), "w").write(head)
        if subprocess.run(["git", "diff", "--quiet", "--", f], cwd=REPO).returncode != 0:
            raise SystemExit(f"RESTORE FAILED for {f}: tree differs from HEAD")


def run_go(target, priv=False):
    cmd = (PRIV if priv else []) + ["go", "test", "-json", "-count=1", f"-timeout={TIMEOUT-200}s"] + GO_PKGS
    if priv:
        cmd = PRIV + ["go", "test", "-json", "-count=1", f"-timeout={TIMEOUT-200}s",
                      "./pkg/dataplane/userspace/", "-run", "9546|9146"]
    try:
        p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return "VOID(hang)", []
    blob = p.stdout + p.stderr
    if [l for l in blob.splitlines() if "no space left on device" in l and "injected:" not in l]:
        return "VOID(enospc)", []
    if "panic: test timed out" in blob:
        return "VOID(hang)", []
    if "[build failed]" in blob or "build failed" in p.stderr:
        return "VOID(build)", []
    ran, failed, skipped = set(), set(), set()
    for line in p.stdout.splitlines():
        try:
            e = json.loads(line)
        except Exception:
            continue
        t, a = e.get("Test"), e.get("Action")
        if not t:
            continue
        if a == "run": ran.add(t)
        elif a == "fail": failed.add(t)
        elif a == "skip": skipped.add(t)
    tgt = re.compile(target)
    tran = {t for t in ran if tgt.search(t)}
    tskip = {t for t in skipped if tgt.search(t)}
    if not priv and len(ran) < MIN_GO:
        return f"VOID(collected {len(ran)})", []
    # `go test -json` emits `run` BEFORE `skip`, so executed = ran - skipped.
    texec = tran - tskip
    if not texec:
        return f"VOID(no target cell executed; skipped={sorted(tskip)[:3]})", []
    if priv and tskip:
        # The privileged leg exists FOR the BPF cells; a skip there IS the
        # #9337 void. The unprivileged leg is expected to skip them.
        return f"VOID(privileged target cells skipped: {sorted(tskip)[:3]})", []
    killers = sorted(t for t in failed if tgt.search(t))
    return ("KILLED" if killers else ("SURVIVED" if not failed else "KILLED(collateral only)")), killers or sorted(failed)[:4]


def run_rust(target):
    tgt = re.compile(target)
    executed, killers = set(), []
    for flt in RUST_FILTERS:
        try:
            p = subprocess.run(["nice", "-n", "5", "cargo", "test", "-j", "6", flt], cwd=os.path.join(REPO, "userspace-dp"),
                               capture_output=True, text=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            return "VOID(hang)", []
        blob = p.stdout + p.stderr
        # A COMPILE failure is `error[E....]` or `could not compile`. A TEST
        # failure makes cargo print `error: test failed, to rerun pass ...`, so
        # matching a bare `^error:` misread every Rust KILL as VOID(build) —
        # which is how J3-J5 first scored. Confirmed by reproducing J3: that one
        # line, no compile marker, and exactly the target cell FAILED.
        if "could not compile" in blob or re.search(r"^error\[E\d+\]", blob, re.M):
            return "VOID(build)", []
        for m in re.finditer(r"^test (\S+) \.\.\. (ok|FAILED)$", blob, re.M):
            name, res = m.group(1), m.group(2)
            if tgt.search(name):
                executed.add(name)
                if res == "FAILED":
                    killers.append(name)
    if not executed:
        return "VOID(target cells did not execute)", []
    return ("KILLED" if killers else "SURVIVED"), sorted(set(killers))


def main():
    if subprocess.run(["git", "status", "--porcelain"], cwd=REPO, capture_output=True, text=True).stdout.strip():
        print("ABORT: commit before running the matrix (tree is dirty)"); return 2
    if "--check" in sys.argv:
        bad = 0
        for name, legs, edits, target in MUTANTS:
            for f, find, repl, occ in edits:
                n = open(os.path.join(REPO, f)).read().count(find)
                okc = (n == 1) if occ is None else (n >= occ)
                bad += 0 if okc else 1
                print(f"{'ok ' if okc else 'BAD'} {n:2d}x  {name}  [{f}]")
        return 1 if bad else 0
    print("=== BASELINE ===")
    for leg in ("go", "rust"):
        v, k = run_go(r"9412|8892|Lockstep|6691|9054|MixedVersion") if leg == "go" else run_rust(r"9412|event_stream::codec::tests|tests_session_delta_json|synced_sessions_do_not_emit_deltas")
        print(f"  {leg}: {v} {k if v != 'SURVIVED' else ''}")
        if v != "SURVIVED":
            print("BASELINE NOT CLEAN — refusing to score"); return 2

    results = []
    for name, legs, edits, target in MUTANTS:
        print(f"\n=== {name} ===")
        backups, ok = apply(edits)
        if not ok:
            restore(backups); results.append((name, "VOID(not applied)", [])); continue
        verdicts = []
        try:
            for leg in legs:
                if leg == "rust":
                    verdicts.append(("rust",) + run_rust(target))
                elif leg == "priv":
                    verdicts.append(("priv",) + run_go(target, priv=True))
                else:
                    verdicts.append(("go",) + run_go(target))
        finally:
            restore(backups)
        for leg, v, k in verdicts:
            print(f"  [{leg}] {v} {k}")
        kills = [v for _, v, _ in verdicts if v.startswith("KILLED")]
        voids = [v for _, v, _ in verdicts if v.startswith("VOID")]
        final = "KILLED" if kills else ("VOID" if voids else "SURVIVED")
        results.append((name, final, verdicts))

    print("\n=== MATRIX ===")
    for name, final, verdicts in results:
        print(f"{final:9s} {name}")
        for leg, v, k in verdicts:
            print(f"{'':9s}   [{leg}] {v} {k}")
    return 0


sys.exit(main())
