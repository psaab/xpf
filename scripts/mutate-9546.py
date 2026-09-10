#!/usr/bin/env python3
"""#9546 mutation matrix — two languages, per-mutant legs.

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

REPO = "/var/tmp/wt-9546"
GO_PKGS = ["./pkg/dataplane/", "./pkg/dataplane/userspace/"]
RUST_FILTERS = ["routing_domain_row_9546", "bpf_map"]
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
MUTANTS = [
    ("J1 Go mirror READ severed (V4 sessionValue drops RoutingDomain)",
     ["go", "priv"], [(B, CONV, "", 2)], r"9546|9146"),
    ("J2 Go mirror WRITE severed (V6 toBPF drops RoutingDomain)",
     ["go"], [(B, CONV, "", 3)], r"9546"),
    ("J3 Rust V4 builder writes routing_domain: 0",
     ["rust"], [(P, ROWCALL, "        routing_domain: 0,\n", 1)], r"built_v4_forward_row_carries_the_domain_9546"),
    ("J4 Rust reverse over-correction: reverse rows encode the key domain",
     ["rust"], [(P, "    if metadata.is_reverse {\n", "    if false && metadata.is_reverse {\n", None)],
     r"reverse_row_states_absence|built_reverse_row_states_absence"),
    ("J5 Rust under-correction: every row states absence",
     ["rust"], [(P, "        crate::session::routing_domain_to_wire(key.routing_domain)\n",
                 "        crate::session::ROUTING_DOMAIN_WIRE_ABSENT + 0 * key.routing_domain\n", None)],
     r"forward_row_states_the_tenant_domain|default_marker|built_v[46]_forward_row"),
    ("J6 size-PRESERVING Go offset drift (field moves 144->148, sizeof stays 152)",
     ["go"], [(B, "\t_             [2]byte // pad: C aligns __u32 routing_domain to a 4-byte boundary (#9546)\n",
                 "\t_             [6]byte // MUTANT\n", 1),
              (B, "\tRoutingDomain uint32\n\t_             [4]byte // pad: C tail-pads the struct to its 8-byte alignment (#6082)\n}",
                 "\tRoutingDomain uint32\n}", 1)],
     r"TestRoutingDomainOffsets9546|ConntrackCHeaderFieldOffsets6984|MatchesConntrackABI"),
    # J7 keeps the field NAME, so #6984 must catch it on the OFFSET assertion.
    # An earlier draft renamed it, which would have been "killed" by the
    # member-not-found branch instead — a kill by the wrong branch reads as a
    # working guard and proves nothing about the offset pin.
    ("J7 C header transposition (routing_domain above ingress_vlan_id, sizeof stays 152)",
     ["go"], [(H,
       "\t__u16 ingress_vlan_id;\n"
       "\t/* #9546: the session's ROUTING DOMAIN in the #7239 wire encoding\n"
       "\t * (0 = not stated, 1 = default instance, else a reserved-band domain).\n"
       "\t * The Go delete paths read it back so a helper delete names the domain the\n"
       "\t * row was installed under (#9146 singular, #9364 batch); before this field\n"
       "\t * existed the mirror dropped it and both were inert. Appended AFTER\n"
       "\t * ingress_vlan_id so no existing offset moves: a __u32 needs a 4-byte\n"
       "\t * boundary, so it skips the 2 unused pad bytes and lands at 144, and the\n"
       "\t * 8-byte alignment grows sizeof 144 -> 152. */\n"
       "\t__u32 routing_domain;\n};",
       "\t__u32 routing_domain;\n\t__u16 ingress_vlan_id;\n};", None)],
     r"ConntrackCHeaderFieldOffsets6984"),
    ("J8 one-sided protocol bump (Rust left at 11)",
     ["go"], [(C, "pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 12;",
                 "pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 11;", None)],
     r"Lockstep|MovedWithTheWire9054|MixedVersionMatrix"),
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
    for f, s in backups.items():
        open(os.path.join(REPO, f), "w").write(s)


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
            p = subprocess.run(["cargo", "test", flt], cwd=os.path.join(REPO, "userspace-dp"),
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
    print("=== BASELINE ===")
    base = {}
    for leg in ("go", "rust", "priv"):
        if leg == "go":
            v, k = run_go(r"9546|8892|Lockstep|6984")
        elif leg == "priv":
            v, k = run_go(r"9546|9146", priv=True)
        else:
            v, k = run_rust(r"9546|bpf_conntrack_struct_sizes_match_c")
        base[leg] = v
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
