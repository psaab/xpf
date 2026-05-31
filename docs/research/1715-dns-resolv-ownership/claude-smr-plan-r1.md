# Claude-SMR HOSTILE plan review — #1715 r1

Reviewer: Claude (domain SMR: Linux systemd/DNS lifecycle, Go control-plane
concurrency, SW design patterns). Posture: HOSTILE.

**Verdict: PLAN-NEEDS-MAJOR.** The diagnosis is correct and verified, but
the recommended *implementation shape* (hybrid A/B + DHCP `installDNS`
writing `/etc/resolv.conf` directly from its own goroutine) reintroduces
the very multi-owner concurrency it claims to fix. Converges with AGY.

## Diagnosis — VERIFIED CORRECT (quoted evidence)

1. **Apply-order race** — `daemon_apply.go:885-888`: `applySystemDNS`
   (886) then `applyDNSService` (888). `applySystemDNS` ends in
   `restartResolved()` (`daemon_system.go:271,274-279`); `applyDNSService`
   runs `systemctl disable --now systemd-resolved` (`:428`) when
   `DNSEnabled==false`. `compiler_system.go:328` only sets `DNSEnabled`
   true when a `services dns` stanza exists — fw0 has none. So every
   apply: start resolved → immediately disable it → stub dir gone →
   symlink dangling. CONFIRMED on live fw0 (resolved inactive+disabled,
   `/run/systemd/resolve` absent).

2. **installDNS dead for v4** — `dhcp.go:728-730` is the ONLY call site,
   gated `v6opts.UpdateDNS`. `daemon_dhcp.go:65-70` (DHCPv4Options)
   never sets `UpdateDNS`. fxp0 is DHCPv4 → `installDNS` never runs on
   fw0. The issue body framed installDNS-through-symlink-ENOENT as the
   v4 cause; the real v4 cause is the apply-order race. Plan §2c states
   this correctly. Good — but it means the v4 path is *doubly* broken
   (never wired AND would fail through the symlink if it were).

## FATAL design flaws in the recommendation (must fix before READY)

### F1 — Hybrid A/B is a hidden third owner (CRITICAL)
Plan §6 "keep a hybrid escape hatch": if `DNSEnabled==true`, use the
resolved-owner branch; else managed file. But the DHCP `installDNS`
path (§5 Option A) unconditionally does Lstat→Remove-symlink→write-file.
`dhcp.Manager` has NO access to `cfg`/`DNSEnabled` (constructor
`dhcp.New(stateDir, onAddressChange)` at `dhcp.go:103` — no config
handle). So under the hybrid, an operator who sets `services dns`
(expecting resolved) + a DHCPv6 `dns-server` req-option gets resolved
*enabled* by `applyDNSService`, then the async DHCP goroutine
**deletes the resolved symlink and writes a plain file**, silently
breaking the resolved setup. This is the same multi-owner bug in new
clothes. The hybrid cannot coexist with a config-blind DHCP writer.

### F2 — DHCP writes `/etc/resolv.conf` outside the apply lock (CRITICAL)
`applyConfig` serializes everything under `applySem`
(`daemon_apply.go:69-70`). `installDNS` runs in the per-interface DHCP
goroutine (`runDHCPv6` :728) holding NO such lock. Two writers to the
same file with no shared mutex = clobber race even with temp+Rename
(Rename is atomic per-call but the *decision* of what to write is not
serialized). v4 lease + v6 lease + a config commit can all race; last
writer wins, and each writer only knows its own slice of the truth.

### F3 — Dual-stack clobber, no merge state (CRITICAL)
v4 and v6 run in separate goroutines. If `installDNS` writes only its
own lease's servers, a v6 renewal wipes the v4 servers and vice versa.
`dhcp.Manager` holds per-`clientKey` leases (`m.leases`, keyed
iface+family) but `installDNS(lease)` takes a single lease — it has the
state to merge but the plan's signature doesn't. The plan acknowledges
precedence in §9 but the §5 design (installDNS per-lease) contradicts it.

### F4 — Boot/commit blank-write data loss (HIGH)
`daemon_run.go`: first `applyConfig` runs at startup BEFORE DHCP clients
start. With static `name-server` empty, the managed-file branch writes
an empty resolv.conf. Worse, on fw0 the static `name-server 1.1.1.1`
*is* set, so this specific box is fine — but a box relying purely on
DHCP-learned DNS would get a blank file on every commit (since
`dhcpLeaseChangeRequiresRecompile` is false for mgmt ifaces, the lease
DNS never re-enters the config path). The reconciler MUST read live
leases + static config together, not just `cfg`.

## Remediation (converges with AGY) — required plan shape

1. **Commit to pure Option A. Drop the hybrid.** Default and only
   non-opt-in model: xpf owns `/etc/resolv.conf` as a managed plain
   file; `systemd-resolved` is `disable --now` (and likely masked to
   defeat socket-activation re-creating the stub). The `services dns`
   stanza, if we keep a resolved mode at all, must be a *fully separate*
   branch where DHCP does NOT write the file — but simplest is to NOT
   ship Option B in this PR and document "resolved not supported; xpf
   owns resolv.conf". Revisit B only if an operator needs it.
2. **One `reconcileDNS(cfg)` under `applySem`.** Collapse
   `applySystemDNS` + `applyDNSService` into a single function called
   from `applyConfigLocked`. It (a) renders from static `name-server` +
   domain + live DHCP leases (read via `dhcpMgr.Leases()`/`LeaseFor`),
   (b) Lstat-guards + atomically writes the managed file, (c)
   deterministically disables/masks resolved, (d) removes legacy
   `bpfrx.conf`. Idempotent compare-before-write.
3. **DHCP never writes resolv.conf.** Delete the `installDNS` file write;
   instead the DHCP path stores DNS in the lease and fires the EXISTING
   debounced `onAddressChange` callback (`dhcp.go:1172-1181`,
   `daemon_dhcp.go:36-41`). Route that callback to `reconcileDNS` (or a
   recompile that calls it) so the single locked reconciler does the
   merge. This reuses infra already present — minimal new surface.
   Wire v4 DNS into the lease (the v4 `UpdateDNS` gap) so v4 leases
   contribute.
4. **Boot reconcile**: call `reconcileDNS` early in daemon init AND
   ensure it merges leases so a commit before/after a lease never
   blanks the file.

## #1713 coordination
Agree with §7: SEQUENCE, not one PR. #1713 extracts
`pkg/daemon/system/dns.go` + fixes the `Domains=` `else-if` drop
(`daemon_system.go:253-256`). #1715 builds `RenderResolvConf` +
`reconcileDNS` on that seam. If #1713 hasn't landed, #1715 absorbs its
one-line fix. #1715 must not regress it. Reasonable.

## Minor
- §10 AC#1 should assert resolved is masked (not just disabled) if we
  go the mask route — pin the decision in the plan, don't defer all of
  it.
- The `.resolv.conf.systemd-resolved.bak` is a base-image artifact, not
  xpf's — plan §2a notes this; do NOT manage/remove it (out of scope).
- Precedence question in §11 should be RESOLVED in the plan before
  READY: recommend static `name-server` first, then DHCP v4, then v6,
  de-duplicated — so static config is authoritative and DHCP augments.

## Bottom line
Diagnosis solid; the fix must drop the hybrid, centralize on ONE locked
reconciler that merges static+v4+v6, and make DHCP notify-not-write.
With those, this is PLAN-READY material. As written (r1), the hybrid +
config-blind DHCP writer is a correctness regression. **NEEDS-MAJOR.**
