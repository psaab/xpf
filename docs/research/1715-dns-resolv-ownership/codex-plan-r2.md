# Codex round-2 convergence review — xpf #1715

Verdict: PLAN-NEEDS-MAJOR

Reviewed `docs/research/1715-dns-resolv-ownership/plan.md` revision r3 in full, then checked the requested source anchors:

- `pkg/daemon/daemon_apply.go:69-70` confirms `applyConfig` acquires `applySem`.
- `pkg/daemon/daemon_apply.go:157-159` documents `applyConfigLocked` as requiring `applySem`.
- `pkg/daemon/daemon_apply.go:885-888` confirms the current split `applySystemDNS` / `applyDNSService` ordering.
- `pkg/daemon/daemon_dhcp.go:40-47` confirms the management-only DHCP callback branch currently runs `applyMgmtVRFRoutes()` without DNS reconciliation.
- `pkg/dhcp/dhcp.go:657-662` confirms DHCPv4 already extracts DNS into `lease.DNS`.
- `pkg/dhcp/dhcp.go:728-729` confirms the old DHCPv6 `installDNS` write path still exists in source and must be removed by the implementation.
- `pkg/dhcp/dhcp.go:1172` confirms the debounced DHCP address-change callback entrypoint.
- `pkg/config/compiler.go:875-876` confirms the existing `dns-proxy` warning site where the new `system services dns` warning can be added.

## Round-1 required edits

The six round-1 edits are addressed in the converged sections:

1. Section 6 rationale point 4 and AC#6 now say `system services dns` does not select a resolved-owner runtime branch, emits a commit-check warning, deletes `applyDNSService`, and always keeps resolved disabled+masked.
2. Section 5b defines the lock contract: `reconcileDNSLocked(cfg)` is called only with `applySem` held, `reconcileDNSFromDHCP()` acquires `applySem` exactly once and reads `store.ActiveConfig()`, and the DHCP callback must run DNS reconciliation on every address change including the management-only branch.
3. Section 5b now has an explicit empty-merge boot policy: repair dangling/resolved-stub symlinks, do not clobber an existing good non-dangling file, and do not claim DHCP-only DNS is available before a lease arrives.
4. The test plan replaces the stale r1 `installDNS` framing with tests that assert no direct DHCP file-write path remains, v4/v6/static DNS are merged, and the management-only DHCP callback triggers DNS refresh.
5. Section 5b specifies exact systemd operations: `systemctl disable --now systemd-resolved.service`, then `systemctl mask systemd-resolved.service`, with WARN logging on non-zero exit and no silent assumption that resolved is off.
6. Section 5b specifies same-directory temp files in `/etc`, `os.Lstat`, symlink removal, and `os.Rename` over `/etc/resolv.conf`.

## Blocking contradiction

The plan still contains stale hybrid/resolved-owner instructions outside the converged sections:

- `plan.md:163-170` says Option D is the "recommended vehicle" and that `reconcileDNS(cfg)` should "pick owner model from config" and choose between `{write managed file + disable resolved}` and `{write drop-in + enable resolved}`.
- `plan.md:361-362` says: "when `DNSEnabled == true`, do NOT also write the plain file (would fight resolved) — exactly one owner."

That directly contradicts the r3 convergence text in `plan.md:200-206`, `plan.md:290-299`, and AC#6 at `plan.md:381-384`, which require pure Option A: `DNSEnabled` never selects a resolved branch, `applyDNSService` is deleted, `reconcileDNS` always writes/owns `/etc/resolv.conf`, and resolved remains disabled+masked.

Concrete counterexample: with a config containing `system services dns` (`DNSEnabled == true`), AC#6 requires a managed real `/etc/resolv.conf` and resolved disabled+masked. The stale §9 gotcha requires not writing the plain file for that same config, implying a resolved-owner branch. An implementor following §9 or the "recommended vehicle" wording in §5 Option D can reintroduce the exact hybrid this revision claims to have killed.

Required edit before PLAN-READY: purge or rewrite `plan.md:163-170` and `plan.md:361-362` so every normative section says the same thing: for #1715, `system services dns` produces only a commit warning; runtime always owns the plain file and always disables+masks resolved. Option B may remain as a rejected alternative, but no "recommended vehicle", risk, gotcha, test, or acceptance text may describe a config-selected resolved-owner branch.
