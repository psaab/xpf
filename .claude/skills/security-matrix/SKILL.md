---
name: security-matrix
description: Verify the core security/forwarding matrix on real traffic — plain forwarding at max throughput, trust→untrust ALLOW, untrust→trust BLOCK, trust→trust ALLOW — with captured proof, then document the evidence.
user-invocable: true
---

# Security Matrix Smoke Skill

Prove, with **real captured traffic on current master** (never assertions), the
four things an operator actually cares about for a firewall:

1. **Plain forwarding at max throughput** — line-rate, 0 retransmits.
2. **trust → untrust ALLOW** — outbound permitted traffic forwards.
3. **untrust → trust BLOCK** — inbound disallowed traffic is dropped/rejected.
4. **trust → trust ALLOW** — intra-zone permitted traffic forwards.

Plus a **negative control** (delete the permit → confirm it now blocks) so every
"ALLOW" is demonstrably policy-driven, not just open routing.

This is the directional **policy-correctness** complement to `/perf-test`
(throughput) and `/failover-test` (HA). Run it after any change touching the
policy compiler, zones, the dataplane policy/forward path, NAT, the reject
action, or segmentation.

## Arguments

- `/security-matrix` — full matrix (throughput + all 4 directional cases + negative control). Default.
- `/security-matrix throughput` — only case 1 (loss cluster max throughput).
- `/security-matrix directional` — only cases 2-4 + negative control (standalone 3-zone).
- `/security-matrix <sha>` — deploy + test a specific ref (default: current origin/master).

## Two environments (use BOTH for the full matrix)

| Case | Environment | Why |
|------|-------------|-----|
| 1. Max throughput | **loss HA cluster** (`loss:xpf-userspace-fw0/1`) | mlx5 SR-IOV VFs, native XDP, AF_XDP zero-copy → line-rate (~23 Gbit/s). The virtio standalone caps ~2 Gbit/s (single worker), so it is NOT a max-throughput env. |
| 2-4. Directional policy | **standalone 3-zone VM** (`xpf-fwd` + `trust-host`/`untrust-host`/`dmz-host`) | Purpose-built: one host per zone on dedicated bridges → clean trust/untrust/intra-zone policy tests. |

The two envs are independent → the throughput run and the directional run can
proceed in parallel (different clusters, different locks).

> **Env caveat (2026-06-21): the standalone virtio DUT can intermittently fail
> to forward transit on ANY binary** — the virtio AF_XDP copy-mode RX
> black-hole (#1928/#1961; open worktrees `1928-virtio-copy-xsk-rx`,
> `1961-virtio-xsk-delivery`, `2040-rxfix`) recurs: packets leave the source
> host but the DUT kernel sees 0 transit on the ingress interface and the XSK
> gets 0 RX, so cases 2-4 read 100% loss / 0 sessions. **Before declaring a
> directional FAIL, build+deploy a known-good control (current `origin/master`)
> and run the same ping** — if master fails identically, the failure is the env
> RX black-hole, NOT the PR (record it inconclusive, not a regression). Two more
> recurring traps verified live: (a) the live VM name is **`bpfrx-fw`** with
> `bpfrx-*` bridges (setup.sh's `xpf-fwd`/`xpf-fw` names are stale drift), and
> (b) **`xpf-fwd` keeps coming back co-resident holding the SAME gateway IPs**
> (10.0.1.10/10.0.2.10) — re-do the #1961 isolation (`incus stop xpf-fwd`,
> re-ARP) every run. When the standalone can't forward, validate a policy/dp
> change via its **mechanism** (commit→arm / fail-closed disarm-before-publish +
> unit/regression tests, as done for #2124/#2169) and/or run real directional
> traffic on a **native-XDP env** (the loss mlx5 cluster) instead.

## CRITICAL invariants (learned the hard way)

- **Deploy current master FIRST.** A stale binary is the #1 false result.
  Verify the deployed `xpfd`/helper sha matches the build (the standalone VM and
  the loss cluster both run whatever was last pushed — usually NOT current
  master). `cli -c "show version"` / `md5sum`.
- **Capture on the DESTINATION host, not the firewall.** AF_XDP zero-copy TX is
  **invisible to tcpdump on the firewall's own interface** (it bypasses the
  kernel stack). Run `tcpdump` on the peer/destination container — it sees the
  frame on the wire normally. This is why a reject-reply / forwarded packet can
  look "missing" if you capture on the DUT.
- **DUT isolation (the #1961 ARP-race lesson).** If more than one firewall VM
  shares the trust/untrust bridges and answers the same gateway IP, ARP races
  send traffic to the wrong box and invalidate every forwarding/block result.
  Before the directional run, ensure `xpf-fwd` is the **sole** responder for
  10.0.1.10 / 10.0.2.10: check `incus config device list bpfrx-fw0` vs
  `xpf-fwd` for shared bridges; if `bpfrx-fw0` (or any other fw) is co-resident,
  `incus stop` it for the duration (and restart it after). Confirm with
  `ip neigh flush all; ping -c2 <gw>; ip neigh` → MAC resolves to xpf-fwd.
- **Wait for xpfd SOLIDLY up after deploy** before testing. `cluster-deploy`
  restarts the daemon; a command issued too soon hits
  `connection refused`. Poll `cli -c "show chassis cluster status"` (cluster) /
  `systemctl is-active xpfd` + `cli -c "show security policies"` (standalone)
  until it answers, then settle ~10s.
- **Detached smoke = script file, no-pipe RC, never `cmd | grep; echo $?`.**
  A piped exit-capture returns *grep's* status (0) and FALSE-PASSES a test that
  actually failed. Write a `/tmp/*.sh` script (nested-quote `nohup bash -c '...'`
  mangles redirects); capture `rc=$?` immediately after the command (no pipe),
  grep the saved raw log afterward.
- **Use `sg incus-admin -c "incus ..."`** if bare `incus` hits permission errors.
- **Revert everything.** Restore any config you changed (`rollback`), restart
  any VM you stopped, remove scratch worktrees. Leave the env as found.

## Topology reference

Standalone 3-zone (`xpf-fwd`):
```
trust   zone: ge-0-0-0 10.0.1.10   — trust-host   10.0.1.102
untrust zone: ge-0-0-1 10.0.2.10   — untrust-host 10.0.2.102
dmz     zone: ge-0-0-2 10.0.30.10  — dmz-host     10.0.30.101
```
Loss cluster max-throughput target: **172.16.80.200 / 2001:559:8585:80::200**
(reth0.80 WAN AF_XDP fast path). NEVER use 172.16.100.x — that is a different
`loss:` uplink capped at ~9-10 Gb/s (the misdiagnosed "ceiling" of #1578).

## Procedure

### Step 0 — deploy current master to both envs

Create a scratch worktree off origin/master (NEVER build/deploy from the main
checkout, and NEVER `git checkout` there):
```bash
git -C /home/ps/git/bpfrx worktree add --detach /var/tmp/worktrees/secmatrix origin/master
```
- **Loss cluster:** `make cluster-deploy` from the worktree (self-locks).
- **Standalone:** `make test-deploy` from the worktree (pushes + sha-verifies the
  helper since #1962/#1980). Verify the deployed sha == build sha.

### Step 1 — plain forwarding at max throughput (loss cluster)

Run detached (script file + no-pipe RC). After deploy + wait-for-up:
```bash
H=loss:cluster-userspace-host
for fam in v4 v6; do
  tgt=$([ $fam = v4 ] && echo 172.16.80.200 || echo 2001:559:8585:80::200)
  incus exec "$H" -- iperf3 -c "$tgt" -t 10 -P 12 -p 5201       # push
  incus exec "$H" -- iperf3 -c "$tgt" -t 10 -P 12 -p 5201 -R    # reverse
done
```
**PASS:** all 4 cells (v4/v6 × push/reverse) near line rate (~22-23 Gbit/s) with
**0 retransmits** on the `[SUM] ... sender` line. A reverse cap with healthy push
is a TX-path regression → FAIL.

### Step 2 — directional policy matrix (standalone, DUT-isolated)

After DUT isolation + deploy + wait-for-up, read the live policy
(`cli -c "show security policies"`) so tests match reality, then for each case
generate real traffic and capture on the destination. Confirm with the
session table (`show security flow session`), policy hit-counts
(`show security policies hit-count`), and TTL decrement (64→63 proves L3 transit
through the DUT).

**A. trust → untrust ALLOW** — from `trust-host` to `untrust-host` (10.0.2.102):
TCP connect (nc/curl/iperf) + `ping` → MUST SUCCEED. Proof: packets arrive at
untrust-host (tcpdump), session created on xpf-fwd, TTL decremented.

**B. untrust → trust BLOCK** — from `untrust-host` to `trust-host` (10.0.1.102):
a *disallowed* app (a TCP port NOT permitted by the inbound policy — e.g. 9999
or SSH when only http/ping are permitted) → MUST BE BLOCKED. Proof: tcpdump on
trust-host shows the SYN does **not** arrive (0 pkts), the deny/reject counter
increments. If the inbound policy uses **`reject`** (not `deny`), also capture on
**untrust-host** → a TCP **RST** (or ICMP unreachable for non-TCP) comes back
(validates the active-reject action). Show that the *permitted* inbound apps
(e.g. `ping`) DO pass — proving policy-specific blocking, not total breakage.

**C. trust → trust ALLOW (intra-zone)** — exercise intra-zone trust traffic that
routes through the DUT (so TTL decrements). If the trust zone has a single
subnet, add a temporary second trust-zone subnet/host (or a routed second IP)
so traffic goes trust→DUT→trust. MUST SUCCEED. Proof: session created + TTL
decrement.

**D. NEGATIVE CONTROL** — delete (or flip to deny) the permit exercised in C
(or A), re-run the same traffic → MUST now BLOCK + deny counter increments →
then `rollback` to restore. This proves the ALLOW is policy-driven.

### Step 3 — document

Write `docs/smoke/security-matrix-<YYYY-MM-DD>.md` with the deployed master sha,
the env/isolation actions, and the **actual evidence** for each case (iperf
`[SUM]` lines + retrans; tcpdump lines; session-table rows; counter deltas; TTL
values; the RST observed for the reject case). Log a one-line entry in `_Log.md`.
Report PASS/FAIL per case. If any case is inconclusive (e.g. capture env limit),
say so explicitly and track it as a follow-up — never paper over it.

## Pass criteria summary

| Case | PASS |
|------|------|
| 1 max throughput | ~line rate (~22-23 Gb/s) all 4 cells, 0 retrans |
| 2 trust→untrust ALLOW | traffic reaches untrust-host, session created, TTL−1 |
| 3 untrust→trust BLOCK | 0 pkts reach trust-host, deny/reject counter++, RST back if reject |
| 4 trust→trust ALLOW | traffic transits, session created, TTL−1 |
| neg control | same traffic blocks after policy removed; restored |

## Reference: a real full PASS (current master `5fa964c13`, 2026-06-20)

Full evidence: `docs/smoke/security-matrix-2026-06-20.md`. Summary:

- **1 throughput** (loss cluster, iperf3 -P12): v4 push **23.3** / rev **22.7**,
  v6 push **23.1** / rev **22.5** Gbit/s — **0 retransmits** all cells.
- **2 trust→untrust ALLOW**: HTTP 200, ttl 64→63, SNAT to 10.0.2.10, 0 drops/deny.
- **3 untrust→trust BLOCK**: ports 23/3389/9999 → Connection refused, **RST
  captured returning to source** (validates #2089 reject), 0 pkts at dest,
  Policy deny 0→8; permitted ping/http still pass.
- **4 trust→trust ALLOW** (intra-zone, 2nd trust subnet): ttl 64→63, source
  preserved (no SNAT), 0 deny.
- **negative control**: delete permit → 100% loss, 0 pkts dest, deny 0→6; restored.

Findings filed from this run: #2117 (port-22 reject emits no RST while other
ports do), #2118 (per-policy hit-count table reads 0 — aggregate deny/session
counters are authoritative). Both display/edge nuances; blocking + forwarding
themselves are correct.
