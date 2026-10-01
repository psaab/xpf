# DNS ownership: xpf manages /etc/resolv.conf (#1715)

xpf owns `/etc/resolv.conf` as a **managed plain file**. systemd-resolved
is **disabled and masked** — xpf does not delegate name resolution to it.
This is consistent with the rest of xpf, which already owns all
interfaces, FRR routing, and systemd-networkd configuration.

## What xpf does

A single reconciler (`reconcileDNS`, `pkg/daemon/daemon_dns.go`) is the
**only writer** of `/etc/resolv.conf`. On every config apply, at daemon
startup, and on every DHCP address change it:

1. Merges nameservers from:
   - static `system name-server` (authoritative, listed first),
   - then DHCPv4-learned servers,
   - then DHCPv6-learned servers,
   - de-duplicated, DHCP augments static (never overrides),
   - **excluding any lease learned on an interface that belongs to a
     routing instance** (#9138 — see "Routing-instance scoping" below).
2. Renders `/etc/resolv.conf` (resolv.conf(5) format) with one
   `nameserver` line per server and a single `search` line combining
   `system domain-name` (first) with `system domain-search`.
3. Writes it atomically: a temp file in `/etc` is renamed over the
   target. `rename(2)` replaces a symlink without following it, so a
   pre-existing dangling/stub `resolv.conf` symlink is swapped for a real
   file with no window where the file is missing. If `/etc/resolv.conf`
   is a bind mount (common in containers/CI) the rename fails
   `EXDEV`/`EBUSY` and xpf falls back to an in-place write.
4. Disables + masks `systemd-resolved.service`. Masking also defeats its
   socket-activation units, so resolved cannot be re-started to recreate
   the `/run/systemd/resolve/stub-resolv.conf` target. This step is
   idempotent and quiet: on a systemd-less host (no `/run/systemd/system`,
   e.g. containers/CI) it is a no-op, and once the unit is already
   `masked` it does nothing (so commits / DHCP changes do not spam a
   false "second owner" warning).
5. Removes stale resolved drop-ins (`bpfrx.conf` legacy + `xpf.conf`).

The reconciler runs under the daemon's `applySem` (apply serialization
lock), so it never races a concurrent commit or a DHCP-driven reconcile.

### Routing-instance scoping (#9138)

A DHCP lease learned on an interface that belongs to a **routing instance**
does not contribute nameservers. Before #9138 `mergeDNSInput` walked every
lease the manager held with no interface, zone, VRF or trust filter — and
this section, together with the module header it documents, described the
merge policy in detail while mentioning no scoping at all, so the dimension
was **unconsidered, not rejected**.

**Why.** `/etc/resolv.conf` is the whole resolver for this host (resolved is
masked) and the host resolves from the **default** routing context. A
nameserver reachable only inside a tenant VRF is therefore a **dead entry**:
glibc consults `nameserver` lines in order, so every lookup that reaches it
burns a full resolver timeout before falling through. That is the certain
cost.

The reason it is a filter and not a footnote is the other one. DHCP is the
only path by which a network the firewall does not trust writes into the
firewall's own **host** configuration, and putting an interface in a routing
instance is the operator declaring that network separate. What the host
resolves is bounded but not nothing: NTP peers, syslog and
archival-transfer destinations, DDNS update servers, and the IPsec
`dynamic-hostname` family hint.

**What is NOT excluded**, and why the distinction matters:

- **The default context.** A DHCP client on a WAN link in the default
  instance still contributes. That is the supported CPE deployment and
  matches Junos, where DHCP-learned DNS is global. The exposure on such a
  link is inherent to running a DHCP client there; a routing instance is not
  what creates it, and dropping this would break every standalone box.
- **The management interfaces.** `fxp0`/`em*`/`fab*` live in the
  **synthesized** management VRF, which is *not* a routing instance. The
  predicate is routing-instance membership, so bootstrap DNS is untouched. A
  naive "exclude anything in a VRF" rule would take it with them.
- **Static `system name-server`.** Always authoritative, never filtered — and
  it is the escape hatch. An operator who leaks an instance's routes into the
  default table and genuinely wants that resolver names it statically.

**Shared authority.** The filter reads `dhcpLeaseRoutingInstances`
(`pkg/daemon/daemon_flow.go`), the same map `collectDHCPRoutes` uses to tag a
DHCP-learned route with its instance. They are the same question about the
same objects, so answering it once is what stops the two lease consumers
drifting — and it makes this filter inherit the #9135 lease-key-shape rule
rather than re-derive it. A filter keyed on the raw config token would be
**inert for the canonical Junos slash spelling**, exactly as the #8963 remedy
was.

### Management-DHCP DNS routing (#11385)

Management DHCP nameservers remain in `/etc/resolv.conf`, but host lookups
must not send them through the unrelated main-table default route. For every
valid nameserver on a live lease for a published management-VRF interface,
the daemon installs a destination-scoped pair:

- `ip rule to <server>/32|/128 iif lo lookup 999 pref 2500`
- an otherwise-identical `unreachable` rule at preference 2501

The first rule sends locally generated host lookups for that exact server
through the lease's management-table route. The shadow makes a missing
table-999 route fail closed rather than falling through to a WAN default.
The merge publishes a management nameserver only after it observes the
complete lookup/shadow pair; a failed install or rule-table read suppresses
that DHCP entry. Both rules are reconciled on config apply and DHCP changes,
so changing or withdrawing the lease removes the old nameserver rules. They
run after the priority-2000 VRF-miss terminator: a tenant-VRF-bound local
lookup cannot escape its VRF through a management nameserver rule.

### Input-validation render belt (#4902, #5010)

`system name-server`, `system domain-name`, and `system domain-search`
are rendered **verbatim** into `/etc/resolv.conf` (`nameserver <v>` /
`search <v>...`) and the resolved drop-in (`DNS=` / `Domains=`). Each of
these leaves carries a strict commit-check validator (`name-server` →
`ValidateIPAddress`; `domain-*` → `ValidateDNSDomain`), but #1960
downgrades commit rejection to a **warning** on the tolerant load /
peer-sync path — so the commit gate is not the last line of defence.

`mergeDNSInput` therefore **re-validates every value at render** and
**fail-closed skips** any that no longer parses (an IP with an embedded
space would inject a second resolver token; a domain with a space would
inject an extra search token). A skipped value is logged (`skipping
invalid name-server` / `... domain-*`) and simply omitted from the merged
input; valid siblings still render. This is the render-side half of the
#4902 double boundary — #5010 closed the `name-server` gap so all three
DNS leaves now have both a commit validator and a render belt.

## Boot-time behavior

The boot config apply runs **before** DHCP clients start, so there are no
DHCP leases yet. If there are **no nameservers** to install at boot (no
static `name-server`, no leases — a search-only render is not a usable
resolver), xpf:

- **repairs** a dangling / stub / missing `/etc/resolv.conf` by writing a
  valid managed file, but
- **does not clobber** a pre-existing good (regular-file) `resolv.conf`.

The boot guard keys off the nameserver set, not "all DNS fields empty",
so a config carrying only `domain-name` / `domain-search` (no static
`name-server`) does not blank a good resolver file at boot.

DHCP-learned servers are merged deterministically: DHCPv4 before DHCPv6,
and within a family sorted by interface name, so resolver priority is
stable across daemon restarts regardless of internal lease map ordering.

DNS for a DHCP-only box becomes available when the first lease arrives and
fires the reconciler. After boot, an empty merge (operator deleted all
`name-server`, and the DHCP manager holds no lease) is treated as a real
"clear DNS": the header-only file is written so stale servers do not leak.

A lease stops contributing DNS when its DHCP client is stopped or the
interface is deconfigured (which removes it from the manager). On a
transient renewal/rebind failure the manager deliberately keeps the last
lease — and keeps using its address — until a fresh DORA succeeds, so the
lease's DNS is retained for as long as the box is still bound to that
address (a firewall must not blackhole its own management resolver
mid-renewal). DNS therefore clears when no held lease and no static
`name-server` remain, not on a momentary renewal hiccup.

## `system services dns`

`system services dns` no longer selects a systemd-resolved owner runtime
branch. The stanza is accepted but emits a commit-check warning; the
runtime still owns `/etc/resolv.conf` directly with resolved
disabled+masked. There is exactly one DNS owner.

## Failure handling (#6792)

Every step of the reconcile — disable+mask `systemd-resolved`, remove stale
resolved drop-ins, write the managed `/etc/resolv.conf` — used to log at WARN
and continue, and neither `reconcile` nor `reconcileDNSLocked` returned
anything, so nothing could propagate. **A commit reported success while leaving
one of two states the operator did not ask for:**

- **dual resolver** — the disable+mask failed, `systemd-resolved` keeps running,
  and xpf still writes `/etc/resolv.conf`. xpf's own networkd `.network` files
  carry `UseDNS=yes`, so a surviving resolved is independently fed DHCP
  nameservers;
- **stale `/etc/resolv.conf`** — the write failed *after* the mask and drop-in
  removal had already run, so resolved is gone and the file is not current.

There is no retry, no ticker and no metric behind either, so an unreported
failure persisted until the next commit happened to succeed.

The reconcile now ACCUMULATES its failures and returns them.
`applyTailReconciles` joins the result into the commit error alongside
`lo0Err` / `hostInboundErr` — its two siblings in that same function, which
already fail the commit closed (#3392, #3333). `reconcileDNS` sat between them
as a bare statement and was the only reconciler there whose error could not
propagate.

Two properties are deliberately preserved:

- **Accumulate, do not return early.** The pre-#6792 control flow is correct: a
  mask failure still writes `/etc/resolv.conf`, because a static file wins over
  an inactive stub. Returning at the first failure would make a systemd hiccup
  *also* cost the resolver file. Only the reporting changed.
- **The two SUCCESS early returns still carry accumulated errors.** The boot
  empty-merge policy and the idempotence skip both run *after* the mask and
  drop-in steps. Returning a bare `nil` there would report success for exactly
  the steady-state pass where nothing else changed and a mask failure was the
  only news — i.e. every pass on a converged system.

`disableMaskResolved` was already idempotent and quiet — it returns success on a
systemd-less host, when the unit is already `masked`, and when it is
`not-found` — so a non-nil error genuinely means the desired end state was not
reached. Failing the commit on it does not affect hosts without resolved.

The DHCP-lease callback (`reconcileDNSFromDHCP`) logs instead of returning:
there is no commit to fail, the end state is the same, and the next commit or
lease change re-drives the idempotent reconcile.

## Operator notes

- To inspect: `cat /etc/resolv.conf` (a real file beginning with
  `# Generated by xpfd`), `getent hosts <name>`,
  `systemctl is-enabled systemd-resolved` → `masked`.
- If `/etc/resolv.conf` is deleted or broken, the next commit or DHCP
  renewal (and the next daemon restart) restores it.
- **Re-enabling systemd-resolved** (future resolved-owner mode, not
  shipped): `systemctl unmask systemd-resolved` then `enable --now`. The
  mask is sticky across reboots, so this is required before any
  resolved-based setup. A resolved-owner mode would push DHCP DNS via
  `resolvectl` (never file writes) and is out of scope for #1715.

## History

Before #1715 there were three conflicting DNS owners:

- `applySystemDNS` wrote a systemd-resolved drop-in and restarted
  resolved;
- two lines later `applyDNSService` disabled resolved when no
  `system services dns` stanza was set (the default) — tearing down
  `/run/systemd/resolve` while the base-image `/etc/resolv.conf` symlink
  still pointed at the resolved stub, leaving a **dangling symlink** and
  no resolver;
- the DHCP `installDNS` path wrote `/etc/resolv.conf` through that
  dangling symlink and failed silently.

#1715 collapses all of this into the single managed-file reconciler
described above. The pure `RenderResolvedDropin` renderer (#1713) remains
in `pkg/daemon/system` for a possible future resolved-owner mode but is no
longer wired into the apply path.
