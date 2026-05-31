# Codex hostile plan review for #1715 r2

Reviewer: Codex, hostile Linux systemd/DNS + Go control-plane concurrency pass.

Verdict: **PLAN-NEEDS-MAJOR**.

Do not kill the plan. The pure Option A direction is viable and is the right
shape: one daemon-owned `/etc/resolv.conf` file, no DHCP writer, no resolved
owner. But r2 is not implementation-ready because it still contradicts itself
about `system services dns`, overclaims the boot-DHCP-only behavior, and leaves
the DHCP callback locking API underspecified enough to deadlock or silently skip
DNS refresh on management-only DHCP.

## Source verification

The diagnosis is real. Current apply order starts resolved for system DNS, then
may immediately stop it for absent `services dns`:

```text
pkg/daemon/daemon_apply.go:68-70
68: func (d *Daemon) applyConfig(cfg *config.Config) {
69:     _ = d.applySem.Acquire(context.Background(), 1)
70:     defer d.applySem.Release(1)

pkg/daemon/daemon_apply.go:885-888
885: // 9. Apply system DNS and NTP configuration
886: d.applySystemDNS(cfg)
887: d.applySystemNTP(cfg)
888: d.applyDNSService(cfg)
```

`applySystemDNS` writes the resolved drop-in and restarts resolved:

```text
pkg/daemon/daemon_system.go:235-271
235: func (d *Daemon) applySystemDNS(cfg *config.Config) {
236:     const dropinDir = "/etc/systemd/resolved.conf.d"
237:     const dropinPath = dropinDir + "/xpf.conf"
...
264:     os.MkdirAll(dropinDir, 0755)
265:     if err := os.WriteFile(dropinPath, []byte(b.String()), 0644); err != nil {
...
271:     restartResolved()
```

`applyDNSService` then enables or disables resolved solely from `DNSEnabled`:

```text
pkg/daemon/daemon_system.go:420-429
420: // applyDNSService manages systemd-resolved based on system { services { dns } }.
421: func (d *Daemon) applyDNSService(cfg *config.Config) {
422:     if cfg.System.Services == nil {
423:         return
424:     }
425:     if cfg.System.Services.DNSEnabled {
426:         exec.Command("systemctl", "enable", "--now", "systemd-resolved").Run()
427:     } else {
428:         exec.Command("systemctl", "disable", "--now", "systemd-resolved").Run()
429:     }
```

And `DNSEnabled` is only set by a `system services dns` stanza:

```text
pkg/config/compiler_system.go:323-328
323: // DNS service
324: if dnsNode := svcNode.FindChild("dns"); dnsNode != nil {
325:     if sys.Services == nil {
326:         sys.Services = &SystemServicesConfig{}
327:     }
328:     sys.Services.DNSEnabled = true
```

So for `system name-server` with no `system services dns`, the resolved stub
symlink can be made valid and then torn down in the same apply. That exactly
matches r2's apply-order diagnosis.

The DHCP writer diagnosis is also correct. `installDNS` writes
`/etc/resolv.conf` directly and follows symlinks:

```text
pkg/dhcp/dhcp.go:453-466
453: // installDNS writes DHCP-learned nameservers to /etc/resolv.conf.
454: func (m *Manager) installDNS(lease *Lease) {
...
463:     if err := os.WriteFile("/etc/resolv.conf", []byte(buf.String()), 0644); err != nil {
464:         slog.Warn("DHCP: failed to install DNS", "err", err)
465:     }
466: }
```

The only call site is DHCPv6:

```text
pkg/dhcp/dhcp.go:728-730
728: if v6opts != nil && v6opts.UpdateDNS {
729:     m.installDNS(lease)
730: }
```

DHCPv4 options have no `UpdateDNS` field and the daemon never tries to set one:

```text
pkg/dhcp/dhcp.go:56-62
56: // DHCPv4Options holds client behavior options for DHCPv4.
57: type DHCPv4Options struct {
58:     LeaseTime              int
59:     RetransmissionAttempt  int
60:     RetransmissionInterval int
61:     ForceDiscover          bool
62: }

pkg/daemon/daemon_dhcp.go:63-70
63: if unit.DHCP {
64:     if unit.DHCPOptions != nil {
65:         dm.SetDHCPv4Options(dhcpIface, &dhcp.DHCPv4Options{
66:             LeaseTime:              unit.DHCPOptions.LeaseTime,
67:             RetransmissionAttempt:  unit.DHCPOptions.RetransmissionAttempt,
68:             RetransmissionInterval: unit.DHCPOptions.RetransmissionInterval,
69:             ForceDiscover:          unit.DHCPOptions.ForceDiscover,
70:         })
```

DHCPv6 does set `UpdateDNS` from req-options:

```text
pkg/daemon/daemon_dhcp.go:84-87
84: dm.SetDHCPv6Options(dhcpIface, &dhcp.DHCPv6Options{
85:     Stateless:  unit.DHCPv6Client.ClientType == "stateless",
86:     UpdateDNS:  slices.Contains(unit.DHCPv6Client.ReqOptions, "dns-server"),
87:     IATypes:    unit.DHCPv6Client.ClientIATypes,
```

`dhcp.Manager` is config-blind, so it cannot correctly select a resolved owner
versus file owner by itself:

```text
pkg/dhcp/dhcp.go:100-103
100: // New creates a DHCP manager. stateDir is where DUID files are persisted.
101: // The onAddressChange callback is called (debounced by 2 seconds) when a
102: // lease changes an interface address.
103: func New(stateDir string, onAddressChange func()) (*Manager, error) {
```

The central merge feasibility exists. Lease records carry family and DNS:

```text
pkg/dhcp/dhcp.go:35-42
35: // Lease holds the result of a DHCP negotiation.
36: type Lease struct {
37:     Interface string
38:     Family    AddressFamily
39:     Address   netip.Prefix
40:     Gateway   netip.Addr
41:     DNS       []netip.Addr
42:     LeaseTime time.Duration
```

`Leases()` returns a snapshot of all current leases:

```text
pkg/dhcp/dhcp.go:427-437
427: // Leases returns a snapshot of all current DHCP leases.
428: func (m *Manager) Leases() []*Lease {
429:     m.mu.Lock()
430:     defer m.mu.Unlock()
...
432:     result := make([]*Lease, 0, len(m.leases))
433:     for _, l := range m.leases {
434:         lc := *l
435:         result = append(result, &lc)
436:     }
437:     return result
```

Note: r2 says "wire v4 DNS into the lease"; that is already true in current
code. DHCPv4 extracts ACK DNS into `lease.DNS`:

```text
pkg/dhcp/dhcp.go:657-662
657: // DNS
658: dnsServers := ack.DNS()
659: for _, dns := range dnsServers {
660:     if a, ok := netip.AddrFromSlice(dns.To4()); ok {
661:         lease.DNS = append(lease.DNS, a)
662:     }
```

The missing v4 piece is not lease extraction; it is that the old file writer is
never called for v4. Under r2, no family should call a file writer.

## F1-F4 judgment

### F1 hidden third owner

Closed only if r2 really means pure Option A. Deleting `installDNS` and routing
DHCP through a central daemon reconciler kills the config-blind DHCP owner.
Masking/stopping resolved kills the resolved owner. One reconciler under
`applySem` leaves one writer.

But r2 is internally inconsistent and that keeps F1 open as written. It says
pure Option A:

```text
docs/research/1715-dns-resolv-ownership/plan.md:201-206
201: 1. **Pure Option A only — drop the hybrid in this PR.** xpf owns
202:    `/etc/resolv.conf` as a managed plain file. `systemd-resolved` is
203:    `disable --now` + **masked**
...
205:    `services dns` resolved path or treat it as a separate future PR."
206:    Do NOT ship Option B's resolved-owner branch here.
```

Then it reintroduces the hybrid:

```text
docs/research/1715-dns-resolv-ownership/plan.md:242-245
242: 4. Resolved's advanced features (split-DNS, DNSSEC stub) are unused on
243:    this appliance; `system services dns` (DNSEnabled, the dns-proxy
244:    path) remains the explicit opt-in to the resolved-owner branch
245:    (hybrid), so we don't regress operators who want it.

docs/research/1715-dns-resolv-ownership/plan.md:313-314
313: 6. `system services dns` opt-in still selects the resolved-owner branch
314:    with exactly one owner (no file+drop-in conflict).
```

That is not a wording nit. An implementor following acceptance criterion 6 can
ship the resolved branch that r2 explicitly killed. The plan must remove the
resolved-owner acceptance criterion and replace it with the warning/no-op or
commit-reject behavior it later describes:

```text
docs/research/1715-dns-resolv-ownership/plan.md:247-253
247: **No hybrid in this PR** (killed round 1, §5b). If `system services dns`
248: is configured, the simplest correct behavior is a commit-check warning
249: ("`services dns` resolved-owner mode not supported; xpf manages
250: `/etc/resolv.conf` directly") rather than a config-blind DHCP path that
251: fights resolved.
```

Current validation only warns for `dns-proxy`, not bare `system services dns`:

```text
pkg/config/compiler.go:875-876
875: if cfg.System.Services != nil && cfg.System.Services.DNSProxyConfigured {
876:     warnings = append(warnings, "system services dns dns-proxy configured but DNS proxy/forwarder runtime is not implemented")
```

So the commit-warning path in r2 is not yet specified precisely enough. For
pure Option A, `DNSEnabled` must no longer select resolved at runtime. Either
warn on any `DNSEnabled`, or reject it. Do not leave it as an opt-in branch.

### F2 async-write race

Conceptually closed: DHCP no longer writes `/etc/resolv.conf`, and the central
writer is under `applySem`.

The remaining hole is API shape. Current DHCP callback sometimes calls
`applyConfig`, which acquires `applySem`, and sometimes does not apply at all:

```text
pkg/daemon/daemon_dhcp.go:36-47
36: dm, err := dhcp.New(stateDir, func() {
...
40:     if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
41:         if d.dhcpLeaseChangeRequiresRecompile(activeCfg) {
42:             slog.Info("DHCP address changed, recompiling dataplane")
43:             d.applyConfig(activeCfg)
44:         } else {
45:             slog.Info("DHCP address changed on management-only interface, refreshing management routes")
46:             d.applyMgmtVRFRoutes()
47:         }
```

r2 says "directly or via the recompile path" under `applySem`. That is not
enough. The implementation must define two functions:

- `reconcileDNSLocked(cfg)` may only be called by `applyConfigLocked` while
  `applySem` is already held.
- `reconcileDNSFromDHCP()` acquires `applySem`, reads `ActiveConfig()`, then
  calls `reconcileDNSLocked(cfg)`.

Do not let `reconcileDNSLocked` call `applyConfig`, and do not let
`applyConfigLocked` call a wrapper that tries to acquire `applySem` again.
The contract matters because the lock is non-reentrant:

```text
pkg/daemon/daemon_apply.go:157-159
157: // applyConfigLocked runs the actual reconcile pipeline. MUST be
158: // called with d.applySem held.
159: func (d *Daemon) applyConfigLocked(cfg *config.Config) error {
```

If the DHCP path relies on the existing management-only branch, DHCP DNS will
not reconcile at all for management-only interfaces. That is exactly the fw0
class of interface.

### F3 dual-stack clobber

Closed by the proposed central merge. The current data model supports it:
`Lease.Family` exists and `Leases()` returns all leases. Merging static, then
v4, then v6 with de-duplication is the right invariant.

Implementation detail: `Leases()` shallow-copies the `Lease` struct, so the
`DNS` slice header is copied but not the backing array. Current code replaces
leases in the map and does not mutate `lease.DNS` after publication, so this is
probably fine. If implementation starts mutating lease DNS in place, this
becomes a data race. Keep leases immutable after storing or deep-copy DNS in
`Leases()`.

### F4 boot/commit blank-write

Commit-time blanking is closed if the reconciler always reads live leases and
the DHCP callback always runs DNS reconcile under `applySem`.

Cold boot is not closed as claimed. Current startup applies config before DHCP
clients are started:

```text
pkg/daemon/daemon_run.go:366-370
366: // Apply current config — needed even in config-only mode so that
367: // VRFs, interfaces, and routing are configured before cluster comms.
368: if cfg := d.store.ActiveConfig(); cfg != nil {
369:     slog.Info("applying active configuration")
370:     d.applyConfig(cfg)

pkg/daemon/daemon_run.go:569-575
569: // Start DHCP clients for interfaces configured with dhcp/dhcpv6.
570: // This must happen after BPF load + config compile so HOST_INBOUND_DHCP
571: // flags are active before DHCP packets start flowing.
572: if !d.opts.NoDataplane {
573:     if cfg := d.store.ActiveConfig(); cfg != nil {
574:         d.startDHCPClients(ctx, cfg)
575:     }
```

On a DHCP-only box with no static `system name-server`, the first
`reconcileDNS(cfg)` has no live DHCP leases because DHCP clients do not exist
yet. r2 claims this cannot blank the file:

```text
docs/research/1715-dns-resolv-ownership/plan.md:222-225
222: 4. **Boot reconcile + merge**: `reconcileDNS` runs early in daemon init
223:    AND merges leases, so neither boot nor a later unrelated commit ever
224:    blanks the file. Because it reads live leases (not just `cfg`), a
225:    DHCP-only box stays resolvable across commits.
```

The "across commits" part can be true after a lease exists. The "boot" part is
false unless the plan adds one of these explicit rules:

- If the merged nameserver set is empty, do not replace an existing non-dangling
  file with an empty managed file; only repair the known-bad resolved stub
  symlink and accept no DNS until DHCP obtains a lease.
- Persist DHCP DNS leases and load them before startup reconcile.
- Move a DNS-only reconcile after DHCP startup as well, while accepting that
  early boot has no DHCP DNS source.

The plan cannot claim "boot reconcile repairs before anything needs DNS" for a
DHCP-only DNS source that is not available until after DHCP starts. That is a
false invariant, and false invariants are worse than missing ones.

## New holes and required edits

1. **Remove the resolved-owner branch from r2.** Lines 242-245, 296-297, and
   313-314 still describe a hybrid branch. They must be deleted or rewritten as
   "warn/reject `system services dns`; runtime still uses managed
   `/etc/resolv.conf`; resolved stays disabled+masked." This is required to
   close F1.

2. **Specify the DHCP DNS reconcile entrypoint.** The callback must always
   trigger DNS reconcile, including the management-only branch, and that reconcile
   must acquire `applySem` exactly once. The current callback otherwise skips DNS
   on lines 45-46. This is required to close F2 and F4 for fw0-like setups.

3. **Fix the boot blank-write claim.** Current startup ordering proves there
   are no DHCP leases at initial apply. Either add an empty-merge policy or stop
   claiming that boot cannot produce a blank/comment-only file on DHCP-only
   systems.

4. **Update the test plan.** r2 says DHCP never writes and `installDNS` is
   removed, but the test plan still says:

```text
docs/research/1715-dns-resolv-ownership/plan.md:275-276
275: - DHCP install test: `installDNS` through a symlinked path replaces the
276:   symlink atomically and does not ENOENT; v4 + v6 both wired.
```

   That test belongs to r1. For r2, test the daemon reconciler: seed fake
   `dhcp.Leases()` with v4+v6 DNS, verify symlink replacement, static>v4>v6
   ordering, de-duplication, and no direct DHCP write path.

5. **Define exact systemd operations.** "disable --now + mask" should specify
   whether implementation runs `systemctl disable --now systemd-resolved.service`
   then `systemctl mask systemd-resolved.service`, or also handles related
   sockets. Masking the service is probably enough to defeat socket activation,
   but the plan should require warnings on failure and idempotent behavior. Do
   not let a failed `systemctl` silently leave resolved as a second owner.

6. **Require same-directory temp files.** Atomic `Rename` only gives the wanted
   property if the temp file is on the same filesystem as `/etc/resolv.conf`.
   The plan should say temp file in `/etc` with mode `0644`, then rename over the
   real path after `Lstat`/remove.

## Final judgment

Pure Option A closes the original class of bugs if implemented strictly:
one daemon-owned file, one lock, one merge, DHCP never writes, resolved never
owns. r2 is not ready because it still contains enough hybrid language and
callback ambiguity to let an implementor recreate the three-owner failure. Fix
the contradictory `system services dns` semantics, the DHCP callback lock
contract, the cold-boot empty-merge policy, and the stale tests, then this can
move to PLAN-READY.
