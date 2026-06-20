# Plan: ra — stop re-enabling addr_gen_mode / link-cycling RETH to create RA link-locals (#2034)

**Status: DRAFT v1 (draft-fanout, not yet adversarially reviewed)**

Branch: `research/2034-ra-linklocal-addrgen`
Plan path: `docs/research/2034-ra-linklocal-addrgen/plan.md`
Base: origin/master @ c4e7c77cd (issue verified against 7b01afeb5)

---

## 1. Issue framing

`pkg/ra/sender.go:ensureLinkLocal()` is called from `sender.start()`
(`sender.go:69`) every time an RA sender goroutine is (re)started for an
interface. When the interface has no IPv6 link-local address yet, the
fallback path does this (sender.go:386-423):

1. Writes `/proc/sys/net/ipv6/conf/<if>/addr_gen_mode = 0` (EUI-64 mode),
   returning an error if the write fails.
2. Writes `/proc/sys/net/ipv6/conf/<if>/accept_dad = 0`, **ignoring the
   write error**.
3. `netlink.LinkSetDown(link)` → `sleep 50ms` → `netlink.LinkSetUp(link)`
   to make the kernel auto-generate a link-local.
4. Polls up to 2s for the kernel-generated LLA, then (if found) deletes and
   re-adds it with `IFA_F_NODAD`.

It **never restores `addr_gen_mode`** to its prior value.

This collides head-on with the RETH IPv6 knob contract. `setRethIPv6Knobs()`
(`pkg/daemon/daemon_apply.go:35`) deliberately sets `addr_gen_mode = 1`
(stable-privacy / suppress kernel EUI-64 LLA) on every RETH member during
apply, precisely so the kernel does **not** spew auto link-locals that
generate continuous MLDv2 reports and that diverge from daemon-managed
addressing. Starting an RA sender on a RETH interface silently undoes that
contract for the lifetime of the process and across all subsequent link
events.

The same path also performs an **unguarded link DOWN/UP** on a dataplane
interface. On the AF_XDP userspace dataplane a link cycle is a heavyweight,
carefully-orchestrated operation (`PrepareLinkCycle` / `NotifyLinkCycle`
rebind in `daemon_apply.go`); an out-of-band link bounce from inside the RA
manager — which has no coordination with the dataplane rebind — can drop
forwarding and, on a RETH/HA interface, perturb VRRP/VIP/stable-LLA state
that the apply path just reconciled.

### Why it usually "works" today (and why that's the trap)
The daemon's apply path *already* adds a NODAD link-local to every RETH
member that needs one, via `ensureRethLinkLocal()`
(`pkg/daemon/daemon_reth.go:267`) and `addStableRethLinkLocal()` /
`addStableLLToInterface()` (`pkg/daemon/daemon_ha_vip.go:288/332`). Both
use a clean `netlink.AddrAdd` of an EUI-64 (or stable) `fe80::` with
`IFA_F_NODAD` — **no sysctl toggle, no link cycle**. In the normal ordering
(apply runs, then RA `Apply` runs) the interface already has a link-local,
so `ensureLinkLocal`'s loop at sender.go:380-384 returns early and the
destructive fallback never executes. The bug bites only when the RA sender
reaches the interface *before* the LLA exists: cold boot races, RA started
on a non-RETH interface that had its LLA suppressed for another reason,
`WithdrawOnce` temp senders on a freshly-renamed interface, or any future
reordering. It is a latent landmine, not a constant failure — which is
exactly why it survived review.

---

## 2. Honest scope and value

This is a **correctness / contract-integrity** fix, not a performance fix.
The blast radius is small and the slow-path nature is unambiguous:

- One function (`ensureLinkLocal`, ~55 lines), one call site
  (`sender.start`), one package boundary to respect (`pkg/ra` may import
  `pkg/config` only — it cannot import `pkg/daemon` or `pkg/cluster`
  without an import cycle / layering inversion).
- Slow path: runs once per sender start (config apply, failover apply,
  withdraw-once), never per-packet / per-tick.
- No wire-format, no AST, no byte-order surface.

Value: it removes a way for a routine "start RA on a RETH zone" to silently
(a) re-enable kernel EUI-64 LLA generation that the RETH contract suppresses
and (b) bounce a live dataplane/HA interface. Both are HA/failover-sensitive
and hard to attribute after the fact (the symptom is "stray fe80:: + MLDv2
chatter reappears after a link event," or "brief forwarding/VRRP blip when a
zone's RA config is applied"). It also closes an ignored-error gap
(`accept_dad`).

**If reviewers conclude the perf gain/scope is too small to justify the
churn, PLAN-KILL is acceptable.** (See the self-SMR: the counter-argument is
that the early-return makes the destructive path unreachable in practice, so
this could be argued down to a comment + an `accept_dad` error check.) The
plan below argues it is worth doing because the destructive path is still
*reachable* (race / future reorder) and the safe primitive already exists in
the daemon — we are converging two helpers onto one well-reviewed technique,
which lowers long-term risk rather than adding surface.

---

## 3. What is already shipped (do not rebuild)

- `ensureRethLinkLocal(ifName)` — `pkg/daemon/daemon_reth.go:267`. EUI-64
  `fe80::` from MAC, `netlink.AddrAdd` with `IFA_F_NODAD`, idempotent
  (returns early if an LLA already exists). This is the *exact* technique
  #2034 asks `ensureLinkLocal` to adopt. **Reference implementation.**
- `addStableRethLinkLocal` / `addStableLLToInterface` —
  `pkg/daemon/daemon_ha_vip.go:288/332`. Stable (node-agnostic) router LLA,
  NODAD, EEXIST-tolerant. Managed like a VIP (master-only).
- `removeAutoLinkLocal` — `pkg/daemon/daemon_reth.go:237`. Cleans up stale
  kernel LLAs while preserving the stable router LLA.
- `setRethIPv6Knobs` (`addr_gen_mode=1` + `accept_dad=0`) and
  `setVLANSubAddrGenMode` — `pkg/daemon/daemon_apply.go:35/46`. The
  suppression contract this issue protects.
- The fsatomic canary allowlist (`pkg/fsatomic/canary_test.go:47`) currently
  exempts `ra::ensureLinkLocal` because it does procfs writes. **If we remove
  the procfs writes, this allowlist entry must be deleted** (otherwise the
  canary's "no stale allowlist" intent silently rots). The daemon helper we
  mirror does *not* need a canary entry because `AddrAdd` is netlink, not a
  file write.
- RA source-LLA selection already prefers an explicitly configured LLA, and
  for RETH falls back to the stable RETH LLA (`daemon_ra.go:70-97`,
  `config.RAInterfaceConfig.SourceLinkLocal`). The sender's
  `start()` honors `SourceLinkLocal` as its NDP bind address (sender.go:76).

---

## 4. Concrete design (code-level)

The fix is to make `ensureLinkLocal` add the link-local the same way the
daemon already does — a NODAD `AddrAdd` — and to never touch
`addr_gen_mode` or cycle the link. Three viable paths; **Path A is
recommended.**

### Path A (recommended): self-contained netlink AddrAdd inside `pkg/ra`

Rewrite the fallback (sender.go:386-423) so it mirrors
`ensureRethLinkLocal`, kept inside `pkg/ra` (no new dependency):

```
// after the "already have one" early return:
mac := iface.HardwareAddr          // *net.Interface already carries the MAC
if len(mac) != 6 {
    return fmt.Errorf("ensure link-local: interface %s has no usable MAC", iface.Name)
}
ll := net.IP{0xfe, 0x80, 0,0,0,0,0,0,
    mac[0]^0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
addr := &netlink.Addr{
    IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(64, 128)},
    Flags: unix.IFA_F_NODAD,
}
if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
    return fmt.Errorf("add link-local %s on %s: %w", ll, iface.Name, err)
}
slog.Info("ra: added link-local for RA sender", "interface", iface.Name, "addr", ll)
return nil
```

Net effect:
- **No `addr_gen_mode` write at all** → RETH `addr_gen_mode=1` contract is
  preserved by construction (nothing to restore because nothing is mutated).
- **No `accept_dad` write** → the ignored-error concern is moot; we set
  `IFA_F_NODAD` on the address itself, which is the precise, address-scoped
  way to skip DAD (and matches what the daemon helpers do). This also matches
  the README "IPv6 NODAD is set ... so it doesn't fight the kernel's own DAD"
  intent.
- **No link DOWN/UP.**
- Remove the `os`/`time`-for-sleep usage that only the destructive path
  needed (keep `time` if still used elsewhere — it is, for RA timers).
- Delete the `ra::ensureLinkLocal` allowlist entry in canary_test.go.
- README + sender.go doc comment updated to describe the new mechanism.

Mask choice: the daemon's `ensureRethLinkLocal` uses `/64`;
`addStableLLToInterface` uses `/128`. For an LLA used as an NDP *source* a
`/64` link-scoped prefix is the conventional, kernel-default choice and
matches `ensureRethLinkLocal`. Use `/64` for parity (OQ-4).

### Path B: lift the helper into a shared low-level package and call it from both

Move an `EnsureLinkLocalNODAD(ifName)` primitive into a small neutral
package (e.g. `pkg/netutil` or extend an existing low-level helper) that
both `pkg/daemon` and `pkg/ra` import. Eliminates the duplicated EUI-64 math
entirely (single source of truth) and lets the daemon's
`ensureRethLinkLocal` / `ensureLinkLocal` converge.

- Pro: one implementation, one place to fix future bugs (e.g. MAC-less
  interfaces, stable-LLA awareness).
- Con: larger diff, new package or new home for the helper, touches
  daemon (which is the heavily-guarded apply path), and risks dragging in
  the stable-RETH-LLA awareness (`cluster.IsStableRethLinkLocal`) that the
  daemon variant has but `pkg/ra` must not depend on. More review surface
  for marginal gain. Defer to a follow-up if the duplication ever bites
  twice.

### Path C: minimal — keep the toggle but save/restore + treat accept_dad as error

Read the current `addr_gen_mode`, set 0, do the toggle, then restore the
saved value on *every* exit path (defer); make the `accept_dad` write a
hard error.

- Pro: smallest behavioral change if some environment genuinely needs the
  kernel to auto-generate the LLA (Path A assumes we can always synthesize
  EUI-64 ourselves, which requires a 6-byte MAC).
- Con: keeps the link cycle (the dataplane-interruption half of the bug),
  keeps the procfs writes (keeps the canary allowlist), and a save/restore
  around a link bounce is genuinely racy (a concurrent apply could read the
  restored-or-not value mid-flight). This is strictly worse than Path A for
  the stated goals; documented only as the literal reading of the issue's
  "if unavoidable, restore the prior value." **Recommend against.**

### Recommendation
**Path A now**, optionally **Path B as a later consolidation** if a third
caller appears. Path A is the smallest change that fully satisfies all four
fix-direction bullets (no addr_gen_mode mutation; reuse the proven NODAD
AddrAdd technique; no spurious link cycle; no ignored accept_dad error)
without crossing the package boundary.

### Edge case: MAC-less interfaces
`ensureRethLinkLocal` simply returns when MAC length != 6. For `pkg/ra`,
Path A should **return an error** (not silently succeed) when no usable MAC
is present, because the caller (`start`) needs *some* LLA to bind the NDP
socket; today the `start()` retry loop (sender.go:83-93) and the explicit
`SourceLinkLocal` config provide the recovery path. Confirm the failure is
soft-logged at the call site (sender.go:69-71 already only `slog.Warn`s the
error), so a MAC-less interface degrades to "RA may fail to bind" rather
than a hard daemon failure — same as today.

---

## 5. Public API preservation

- `ensureLinkLocal` is unexported and has exactly one caller — signature can
  stay `func ensureLinkLocal(iface *net.Interface) error`. **No exported API
  change.**
- `ra.Manager` surface (`Apply`/`Withdraw`/`WithdrawOnce`/`ResendBurst`/
  `Status`) is untouched.
- `config.RAInterfaceConfig.SourceLinkLocal` behavior unchanged.
- If Path B is chosen, a new exported `netutil.EnsureLinkLocalNODAD` is
  added and `daemon.ensureRethLinkLocal` could become a thin wrapper — that
  is additive, but it touches the daemon and is out of scope for the first
  increment.

---

## 6. Hidden invariants this must not break

- **HA / failover ordering.** The apply path (`applyConfigLocked`)
  reconciles RETH MAC, VIPs, stable LLAs, and *then* RA `Apply`/`ResendBurst`
  runs. `ensureLinkLocal` must not perform a link cycle — a bounce here would
  un-reconcile VIPs/stable-LLAs that step 2.6b just restored and would race
  the AF_XDP `NotifyLinkCycle` rebind. Path A removes the cycle entirely.
  Must verify `make test-failover` still passes (RA sender starts during
  failover apply).
- **RETH addr_gen_mode=1 suppression contract** (`setRethIPv6Knobs`,
  `setVLANSubAddrGenMode`). Path A never writes addr_gen_mode → contract
  preserved by construction. Add a regression assertion that the RA path
  does not write addr_gen_mode (see test plan).
- **NODAD discipline.** The virtual RETH MAC is shared across nodes; DAD on
  an LLA derived from it can DADFAIL on the peer's identical address. The
  fix must add the LLA with `IFA_F_NODAD` (it does) — same reason
  `clearDadFailed` and the daemon helpers all use NODAD.
- **Stable-LLA coexistence.** On a RETH master the daemon may already have
  added the *stable* router LLA (`StableRethLinkLocal`). Path A's early
  return (`a.IP.IsLinkLocalUnicast()`) treats *any* link-local as
  sufficient, so it will not add a second EUI-64 LLA when the stable one is
  present — matching today's behavior and `removeAutoLinkLocal`'s preserve
  rule. Confirm the early-return predicate is unchanged.
- **Hot-path allocation.** N/A — slow path; one small `net.IP`/`netlink.Addr`
  allocation per sender start. No per-packet/per-tick allocation introduced.
- **Boot-class.** No interaction with `computeBootClass` / bootstrap;
  RA senders are started post-apply.
- **Byte-order.** N/A (no `__be32`/cilium-ebpf map serialization here; the
  EUI-64 bytes are written in canonical IPv6 order, same as the daemon
  helper).
- **Dual-AST.** N/A (no parser/config-schema change).
- **fsatomic canary.** Removing the procfs writes obsoletes the
  `ra::ensureLinkLocal` allowlist entry — it MUST be deleted, or the canary's
  invariant ("only listed funcs may do raw file writes; list stays minimal")
  drifts. This is itself a guarded invariant (canary_test.go).

---

## 7. Risk table (4-class)

| Class | Risk | Likelihood | Mitigation |
|-------|------|-----------|------------|
| **Correctness** | EUI-64 we synthesize differs from what the kernel/daemon would pick, causing a mismatch with `SourceLinkLocal` or the NDP bind | Low | Use identical EUI-64 math + `/64` as `ensureRethLinkLocal`; `start()` already prefers `SourceLinkLocal` and falls back to "any link-local"; unit-test the EUI-64 derivation against the daemon helper's output |
| **Correctness** | Removing the link cycle means an interface that genuinely had no LLA *and* no MAC now never gets one | Low | Return an explicit error (logged at call site); the explicit `SourceLinkLocal` config and the `start()` retry loop are the existing escape; document in README |
| **HA / failover** | RA `Apply` during failover no longer bounces the link, changing timing of LLA availability for the NDP bind | Low | The daemon adds the RETH LLA *before* RA Apply in the same apply pass; `make test-failover` must pass; verify NDP bind still succeeds within the existing 10×200ms retry |
| **HA / failover** | Stable-LLA vs EUI-64-LLA ordering on master changes which fe80:: the RA sources from | Low | Early-return on *any* LLA is unchanged; `SourceLinkLocal` (set to the stable LLA for RETH) takes precedence in `start()` |
| **Dataplane** | (Eliminated) out-of-band link cycle interrupting AF_XDP forwarding | n/a after fix | Path A removes the cycle; this risk *exists today* and the fix removes it |
| **Perf** | None — slow path | n/a | — |
| **Maintainability** | Two EUI-64 implementations (ra + daemon) drift | Medium | Path A leaves a duplicate (accept, comment cross-reference); Path B consolidates later if a 3rd caller appears |
| **Test/CI** | Forgetting to delete the canary allowlist entry → stale exemption | Medium | Explicit step in plan; canary test will still pass with a stale entry, so this needs a manual review checklist item |

---

## 8. Test plan

### Unit (pkg/ra) — primary validation, no lab required
1. **EUI-64 derivation test**: feed a known MAC, assert the synthesized
   `fe80::` matches the byte pattern (`mac[0]^0x02 ... ff fe ...`) and equals
   the daemon helper's output for the same MAC (copy the expected vector;
   don't import daemon).
2. **Idempotence / early-return**: an interface that already has any
   link-local must take the early return and perform no AddrAdd.
3. **No-procfs assertion**: this is the load-bearing regression. The
   destructive path wrote two procfs files; the new path must write none.
   Options:
   - (a) Inject a seam: factor the netlink/file operations behind a tiny
     interface so the test can assert "addr_gen_mode write count == 0."
   - (b) Lighter: rely on the fsatomic canary — after removing the procfs
     writes, *delete* the allowlist entry and let the canary fail if any
     file write remains in `ensureLinkLocal`. (The canary already scans for
     raw writes; a leftover write with no allowlist entry fails CI.) This is
     the cheapest durable guard and is recommended as the primary "no
     addr_gen_mode write" regression.
4. **MAC-less interface**: returns an error, does not panic, does not write
   addr_gen_mode.

Note: `AddrAdd`/`LinkByName` need a real netlink socket, so the AddrAdd
success path is hard to unit-test in CI without CAP_NET_ADMIN / a netns.
Cover the *derivation* and *early-return* logic in pure unit tests (extract
the EUI-64 computation into a pure helper); cover the live AddrAdd on the VM.

### Integration / lab
5. **Standalone VM smoke** (`make test-vm` / `make test-deploy`): configure
   IPv6 RA on a non-RETH zone, restart, confirm an LLA exists and RA is sent,
   `addr_gen_mode` unchanged from default. Low cost.
6. **Loss userspace cluster** (`make cluster-deploy`): apply RA on a RETH
   zone, then `cat /proc/sys/net/ipv6/conf/<reth-member>/addr_gen_mode`
   stays `1` after RA Apply (today it would flip to 0). Confirm no link
   cycle in journal (no "link down/up" / no AF_XDP rebind triggered by RA).
7. **`make test-failover`** (MANDATORY — touches RA which runs in the
   failover apply path): zero-drop failover, no spurious link cycle, RA
   resumes on the new master. Per CLAUDE.md any change touching cluster/
   failover code MUST pass this before commit.

### Does it need the lab / multi-increment?
- **Lab:** YES for full confidence — the AddrAdd success path and the
  RETH/failover interactions are only observable on the cluster. But the
  *core logic* (EUI-64 derivation, early-return, no-procfs) is unit-testable
  off-lab, so the change is reviewable and largely validated before the lab
  run.
- **Multi-increment:** NO. Path A is a single small PR. Path B (shared
  helper) would be a separate, optional consolidation PR — not required.

---

## 9. Out of scope

- Consolidating EUI-64 link-local derivation across `pkg/ra` and
  `pkg/daemon` into a shared package (Path B) — a follow-up if a 3rd caller
  appears.
- Any change to `setRethIPv6Knobs` / the addr_gen_mode=1 suppression policy
  itself (we are *protecting* it, not changing it).
- RA timing, prefix, DNS, NAT64, or wire-format behavior.
- The `WithdrawOnce` temp-sender lifecycle (it benefits from the fix for
  free but its design is unchanged).
- Stable-RETH-LLA management (`addStableRethLinkLocal`) — unchanged.

---

## 10. Open questions (for adversarial review)

1. **Is the destructive fallback ever actually reached in production?** If
   the daemon always adds the RETH LLA before RA `Apply`, the early return
   makes the fallback dead code in the RETH case — in which case is the right
   fix "delete the fallback and return an error if there's still no LLA," or
   "keep a *safe* fallback (Path A AddrAdd)"? (Determines whether Path A or a
   stricter "no fallback" variant is correct.)
2. **Non-RETH interfaces.** On a plain (non-RETH) IPv6 zone, does the kernel
   already auto-generate an LLA (addr_gen_mode default), so `ensureLinkLocal`
   *never* needed the fallback there either? If so, the fallback only ever
   mattered for the RETH-suppressed case — narrowing the scope further. Need
   to confirm the default addr_gen_mode on the relevant NIC drivers
   (virtio/mlx5).
3. **`WithdrawOnce` on a freshly-renamed interface.** WithdrawOnce starts a
   temp sender on possibly-just-renamed interfaces during secondary boot. Can
   it hit `ensureLinkLocal` before the daemon has added any LLA? If yes, Path
   A's AddrAdd is the safe behavior there too — but does adding an EUI-64 LLA
   on a *secondary* node (that will immediately send a goodbye RA and stop)
   leave a stray address behind? Should WithdrawOnce skip `ensureLinkLocal`
   entirely?
4. **Mask: /64 vs /128.** `ensureRethLinkLocal` uses /64; `addStableLLToInterface`
   uses /128. Which is correct for an NDP *source* LLA, and does the choice
   affect on-link route generation or the NDP bind? (Recommend /64 for parity
   with the EUI-64 helper, but confirm.)
5. **EEXIST semantics.** If a stable LLA and an EUI-64 LLA could both be
   desired, does tolerating EEXIST mask a real "wrong LLA already present"
   condition? (Probably fine — early-return on any LLA means we won't even
   reach AddrAdd if one exists — but confirm the early-return + EEXIST belt-
   and-suspenders is intentional, not redundant masking.)
6. **Canary allowlist removal.** Confirm the fsatomic canary actually fails
   on a leftover raw file write once the allowlist entry is removed (i.e.
   that deleting the entry is a real regression guard, not a no-op). If the
   canary only scans specific write APIs, verify `os.WriteFile` in
   `ensureLinkLocal` was the thing it was catching.
7. **Driver behavior on link-up without addr_gen_mode toggle.** Some NIC
   drivers reset IPv6 conf on link events; confirm that *not* toggling the
   link doesn't leave the interface in a state where the explicitly-added
   NODAD LLA is wiped by a later, unrelated link event (the daemon re-adds
   on link-cycle recovery, but the RA path won't).

---

## 11. Claude self-SMR (hostile)

**Strongest objection to my own plan:** The destructive fallback is likely
*already unreachable* in the only case that matters. The daemon's apply path
adds a NODAD link-local to every RETH member with IPv6 *before* RA `Apply`
runs (daemon_apply.go:795-797, plus stable-LLA reconcile), and on non-RETH
interfaces the kernel auto-generates an LLA by default (addr_gen_mode
default). So `ensureLinkLocal`'s early return at sender.go:380-384 fires in
practice and the addr_gen_mode/link-cycle code never executes. If that's
true, this issue is a *latent* landmine, not a live bug, and a hostile
reviewer could reasonably say: "the cheapest correct fix is to replace the
whole fallback with an error return (or a Path A AddrAdd) **and** add the
no-procfs regression — but the urgency is low, and we should not spend a
failover-lab run on a path that never executes."

**My rebuttal:** Even if unreachable on the happy path, the fallback is
reachable on (a) cold-boot ordering races, (b) `WithdrawOnce` temp senders
on just-renamed interfaces, and (c) any future reordering of apply vs RA. A
landmine that re-enables a suppressed kernel feature and bounces a dataplane
NIC is worth disarming, and Path A converges on a primitive the daemon has
already proven — it *reduces* net risk and code surface. The cost is one
small unit-tested function plus a mandatory `test-failover` run (which any RA
touch requires anyway). It is not worth a Path B refactor right now.

**Disposition: PLAN-DRAFTED-ready-for-review.**

Single small PR (Path A). Not multi-increment, not inherently lab-bound for
*review* (core logic is unit-testable off-lab), but the **merge gate
requires a lab `make test-failover` run** because the changed code executes
in the failover apply path — per CLAUDE.md. If adversarial review concludes
the fallback is provably dead code and the team prefers minimal churn, the
acceptable downgraded outcome is "Path A minus the fallback, plus the
accept_dad/canary cleanup" — and if even that is deemed not worth the churn,
**PLAN-KILL is acceptable** (the early-return makes it benign today).

Secondary disposition flag for the orchestrator: **LIKELY-DEFER-LAB** only in
the sense that the *final merge gate* needs the loss cluster + test-failover;
the plan itself is ready for adversarial (Codex/AGY/Copilot) review now.
