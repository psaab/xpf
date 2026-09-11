# System login & authentication

This is the operator contract for `system login user` and
`system root-authentication` password handling. It documents how a
configured login password reaches the OS account database, the
commit-time validation of the hash, and the declarative reconciliation
behaviour when a password directive is removed — for both per-user
accounts (#1944) and `root` (#5276).

## Per-user console login password

```
set system login user <name> class operator
set system login user <name> authentication encrypted-password "<crypt-hash>"
```

On commit, xpf:

1. Creates the OS account (`useradd`) if it does not already exist.
2. Writes `<crypt-hash>` to `/etc/shadow` for `<name>` via
   `chpasswd -e` (the same idiom `root-authentication` uses), so the
   operator can log in on the **serial console** (and via SSH password
   if `sshd` permits). Without this, a freshly created account has a
   locked password field and cannot log in on the console at all — only
   SSH-key login (`authentication ssh-ed25519 …`) worked previously.

The password directive takes a **pre-computed crypt(3) hash**, never
plaintext — exactly like `root-authentication encrypted-password`. xpf
does not hash plaintext for you.

## Login class (RBAC) and commit-time validation (#2008 H6)

```
set system login user <name> class <class>
```

The `class` value is **validated at commit** against the set of
system-defined Junos login classes xpf supports **UNION any custom
`system login class <name>` defined in the same candidate tree** (#4304 S-2,
see below). An unrecognized class that is neither built-in nor defined
(e.g. `superuser`, `admin` with no matching `class` definition) is still
hard-rejected by the `#1319` typed-leaf gate, closing the previous
commit-accepts-any-string hole. The system-defined classes are:

| Class | Permissions |
|---|---|
| `super-user` | everything (incl. destructive maintenance) |
| `operator` | view, clear, control (request/test) — **not** maintenance |
| `read-only` | view only |
| `config-viewer` | view only (can display config; cannot enter `configure` to modify) |
| `unauthorized` | nothing |

`super-user` is the only class that holds the destructive **maintenance**
permission (`PermMaint`), which it reaches through `PermAll`. `operator` has
`control` (so it can run benign `request`/`test` commands) but **not**
maintenance, mirroring Junos where the predefined `operator` class lacks the
`maintenance` permission and therefore cannot reboot or zeroize the box (#4108).

RBAC is enforced at runtime by `checkPermission` (`pkg/cli/permissions.go`),
invoked by the dispatch layer before each top-level command. The accepted
enum is **derived from** `LoginClassPermissions`
(`config.ValidLoginClasses()`), so the commit-time validator and the
runtime RBAC table can never drift apart: adding a class in one place
without the other is impossible. An empty/unset class keeps the legacy
allow-everything behavior (no class configured = no RBAC restriction) —
see the next section for the narrow, and only, way that state is reached.

### Which class you get: identity and the default (#6701)

The **in-process console shell's** class comes from the **OS credential of the
invoking process**, never from the environment. "The CLI" unqualified was wrong
here (#6706 review r11): the remote `cli` client still has no class of its own —
its OS credential only renders the prompt (`cmd/cli/main.go` `resolveUsername`).
Since #5278 that no longer means the path is ungoverned: the **server** derives
the caller's identity from the kernel (the uid owning the peer socket, resolved
through the same passwd rules) and enforces the class itself, so a remote `cli`
session is bounded whether or not the client checks anything. See **Scope**
below. `pkg/osident.Current()` reads the **real uid**
(`os.Getuid`) and resolves it through the passwd database; the resolved name
is matched against `system login user <name>`. `pkg/daemon`
`applyCLILoginClass` performs the lookup once, at shell start, and logs the
outcome (identity, uid, resolved class, reason) so an operator locked out by
their own config can see why in the journal.

Before #6701 the identity was `os.Getenv("USER")` and a non-match was handed
**`super-user`**. Both halves were exploitable, and either alone sufficed:
every `system login user` is provisioned with a real shell account
(`useradd -m -s /bin/bash`, #5278), so an operator restricted to
`class read-only` could run `USER=nobody xpf` — or unset the variable — and
receive the highest class in the system. The `!found` branch also promoted any
OS account that merely existed on the box but was absent from `system login`.

The decision, in order:

| Caller | Class |
|---|---|
| resolved name matches a `system login user` with a class | **that class** |
| **non-root** account listed with **no** class | `unauthorized` |
| uid 0 **with** an explicit `system login user root class <c>` | **`<c>`** — an explicit restriction is honoured |
| uid 0 listed with **no** class | `super-user` — an omission is not an instruction; see below |
| uid 0, no matching `system login user` | `super-user` (Junos root default) |
| OS account absent from `system login` | `unauthorized` |
| **non-root** uid with no passwd entry (unidentifiable) | `unauthorized` |
| **non-root** uid shared by several passwd accounts (ambiguous) | `unauthorized` — see below |
| **non-root** uid, passwd database unreadable | `unauthorized` |
| **uid 0** unidentifiable by any of those three | `super-user` — the root default; a class configured for an ALIAS is not applied |
| no `system login` stanza at all | **unset** — legacy allow-everything |

All three unidentifiable cases deny identically, but the journal line names
which one it was: "has no passwd entry", "is shared by more than one passwd
account", "the passwd database could not be read". They send the operator to
three different fixes, and reporting one as another sends them hunting for an
account that is in fact present.

**Why uid 0 listed with no class is not denied, when a non-root account in the
same shape is.** The two are different questions. For a non-root account
`system login` is the authority on what it may do, and saying nothing is not
permission. For uid 0 it is neither an instruction nor enforceable:
`set system login user root authentication ssh-ed25519 "…"` is an ordinary way
to give root a key and expresses no intent to restrict anything, so denying on
it would demote the **console** shell to `unauthorized` — a lockout of the
lifeline caused by a purely additive config. And uid 0 owns the config database,
the daemon process and the on-disk secrets, so a CLI denial is advisory
regardless. An **explicit** class on `user root` is a different matter and is
honoured.

**uid 0 restriction is advisory.** Honouring `system login user root class <c>`
prevents accidents; it is not a containment boundary, because uid 0 can edit the
config database directly. If uid 0 resolves through a passwd **alias** (a second
passwd row for uid 0, the classic `toor`), the resolved name is consulted first
and the literal `root` second, so an explicit restriction written for `root`
still applies to the aliased identity rather than being silently skipped. When
**both** rows exist the uid is ambiguous (below) and only the literal `root` is
consulted, which is deterministic and still the console lifeline.

**A uid shared by several accounts fails closed.** The kernel gives xpf a
number, not a name. If `/etc/passwd` maps that number to more than one account —

```
admin:x:2001:2001::/home/admin:/bin/bash
bob:x:2001:2001::/home/bob:/bin/bash
```

```
set system login user admin class super-user
set system login user bob   class read-only
```

— then bob's shell and admin's shell are indistinguishable to any consumer of
the credential, and resolving the uid to "whichever passwd row comes first"
(what `os/user` does) hands bob `super-user`. That is a privilege escalation
**between two legitimate accounts**, so it is not disposed of by "a duplicate-uid
passwd file is a broken host". xpf refuses to name such a caller: the identity is
unresolved and the class is `unauthorized`. The fix is to give the accounts
distinct uids.

xpf never creates the situation itself — `reconcileSystemUsers` invokes
`useradd` **without** `-o`, so a duplicate uid is rejected by the tool — but a
pre-existing, hand-edited or directory-supplied alias is outside its control,
and an authorization decision must not depend on that.

uid 0 is exempt from the denial for the usual reason: `root` + `toor` is a
supported layout, uid 0 is not a boundary xpf can enforce, and locking the
console out over it would be the larger failure. An ambiguous uid 0 keeps the
Junos root default and still honours an explicit `system login user root
class <c>`.

**Why the passwd database is read directly instead of through `os/user`.** The
appliance binaries are built `CGO_ENABLED=0` (Makefile), which selects the Go
standard library's pure-Go `os/user`. In that implementation `user.LookupId(uid)`
returns the cached `user.Current()` when the uid matches — it always matches,
since xpf asks about its own uid — and pure-Go `current()` **fabricates** a user
from `$USER` and `$HOME`, with a nil error, whenever the real passwd lookup
fails. On a box where the caller's uid has no passwd row (a minimal container,
an NSS/LDAP outage, a deleted account, an unreadable `/etc/passwd`),
`USER=admin HOME=/tmp cli` therefore resolved to the account name `admin` — the
#6701 hole reopened one layer below the call sites #6701 audited.

`pkg/osident` scans `/etc/passwd` itself instead. Under the shipped build that
is exactly what the standard library would have done for any uid that HAS a row
(pure-Go `os/user` reads the same file and consults no NSS), so resolved names
are unchanged; what changes is that a uid **without** one is now unidentified
rather than whatever the caller put in `$USER`. A cgo-enabled developer build
loses NSS name resolution — which affects the RBAC **class decision**, not just
the displayed prompt: an NSS-only account (LDAP, SSSD) resolves to unidentified
and is denied. That is a narrowing for every **non-root** uid. At uid 0 it is a
**promotion**, for the same reason as the table row above: an unnamed uid 0
takes the root default, so losing the name of an aliased root that carried an
explicit restrictive class hands it `super-user`. uid 0 is essentially always a
local passwd row, so this corrects the claim rather than describing a reachable
production regression, and the shipped build is `CGO_ENABLED=0` either way.
`TestNoOsUserInIdentityResolution_6701` keeps `os/user` out of the package.

The same narrowing reaches a second route worth naming explicitly. Host-account
provisioning gates `useradd` on `id -- <name>` failing
(`pkg/daemon/daemon_system.go`), so an operator account that exists only in a
directory service never gets a local passwd row — and therefore now resolves to
`unauthorized` on the CLI. This is sound: before #6701 that population was
"authenticated" by `$USER`, which is to say not authenticated at all. An
operator who needs CLI access for such an account should be given a local
`system login user` entry.

`unauthorized` is used rather than an unset class deliberately. The empty
string is the legacy no-RBAC mode: `checkPermission` returns `nil` (allow
everything) and `showConfigRedacted` returns `false` (render PSKs, SNMP
communities and authentication-keys in cleartext). Failing closed therefore has
to **name** a class. `unauthorized` resolves to an empty-but-present permission
set, so `checkPermission` denies every command by name and `showConfigRedacted`
masks secrets.

That safety depends on one property in a different function: `resolveClassPerms`
consults the system-defined table **first**. A config carrying
`system login class unauthorized { permissions all; }` would otherwise turn the
fail-closed default into a full-power one for every unidentifiable caller. Such
a definition is rejected at commit (see built-in shadowing below), but the
tolerant load / peer-sync path only warns, so the runtime precedence is what
actually holds — pinned by
`TestUnauthorizedClassCannotBeWidened_6701`.

The uid-0 default is Junos parity and is the console lifeline: uid 0 already
owns the config database, the daemon process and the on-disk secrets, so it is
not a boundary xpf could enforce. It applies **only** when `system login` says
nothing about root — an explicit `system login user root class <c>` wins,
because a configured restriction silently ignored is exactly the defect class
#6701 removes.

**Scope.** This is the on-box CLI boundary — the class a console session is
bound to. It is no longer the ONLY boundary: since #5278 the gRPC listener
(`127.0.0.1:50051`) derives the caller's identity server-side from the kernel
and enforces the class itself, so a shell user who speaks gRPC directly no
longer bypasses the model by skipping `checkPermission`. The remote `cli`
client is still not itself an authorization boundary — it carries no class and
makes no decision — but the server it speaks to is.

The class **name** is resolved once, at shell start, and is not re-evaluated
mid-session. That matches Junos (your class is bound at login). The class's
**permissions** are not bound: `resolveClassPerms` (`pkg/cli/permissions.go`)
reads `store.ActiveConfig()` on every check, so a custom class's permission set
is whatever the **currently active** config says.

An earlier revision called that "not an escalation path" on the grounds that
"changing `system login` requires `configure`, which none of the restricted
classes hold". The premise is false for **custom** classes, which may carry
`configure` (see below), and the conclusion does not follow. Measured by driving
the real store and checker: a session bound to a custom class holding
`[view configure]` is denied `request system reboot` and gets
`showConfigRedacted == true`; after that same session commits
`set system login class <its-own-class> permissions all`, the identical checks
return **allowed** and **false** — secrets in cleartext — with no re-login.

The accurate statement of the boundary is the asymmetry:

| Change | Takes effect mid-session? |
|---|---|
| widening the bound class's permissions | **yes**, immediately |
| narrowing the bound class's permissions | **yes**, immediately |
| moving the user to a different class | no — the class NAME is bound |
| deleting the user from `system login` | no — same reason |

The widening row is not a boundary being crossed that could not be crossed
otherwise: a class holding `configure` can already author a `super-user` account
and use it. What is worth stating plainly is that it happens **immediately and
in the same session**, and that the narrowing row is what makes a mid-session
revocation of a class's permissions actually effective.

### Where the class is enforced — per control surface (#5561)

The class evaluator is shared (`config.ResolveClassPermissions` /
`config.ClassHasPermission`), but each control surface must *call* it, and
until #5561 only the CLI did. That mattered because a login user is a real
shell account — the daemon creates each one with `useradd -m -s /bin/bash` —
so the holder can bypass a CLI-side check simply by not using the CLI.

| Surface | Enforcement |
|---|---|
| Console / SSH CLI | `checkPermission`, **client-side** — it runs in the CLI process, so it binds only callers who use the CLI. It is not the boundary; it is the surface that gives a good error message before a round trip. |
| HTTP REST (`127.0.0.1:8080`) | **Server-side** since #5561: the mutation surface derives the caller's UID from the kernel socket table, maps it to this account, and evaluates the class before the handler runs. See `pkg/api/README.md` "Server-side authorization". |
| gRPC (`127.0.0.1:50051`) | **Server-side** since #5278: a `stats.Handler` resolves the connection's peer UID at connection setup and unary + stream interceptors evaluate the class before any handler runs, through the same `pkg/authz` decision the REST leg uses. Unlike REST it gates **every** RPC (reads included) and there is no `api-auth` credential, so an unattributed caller has nothing to fall back to. See `pkg/grpcapi/README.md` "Server-side authorization". |

On the REST surface the class is evaluated against a **server-derived**
identity, so it is a real boundary rather than an advisory one:

- The caller's UID comes from the kernel (`/proc/net/tcp{,6}`), not from
  anything the request carries, and is fixed at connect rather than at request
  time so the caller cannot choose when — or whether — it resolves. Concurrent
  lookups share one table read, so the identity does not cost a kernel hash-table
  walk per connection.
- **UID 0 is authorized unconditionally** — root owns the config DB on disk, so
  a denial would be theater.
- A local UID that is **not** a configured `system login user` is **denied** the
  mutation surface. Note the contrast with the CLI, where an unset class means
  "no restriction": on a network-reachable API the absence of a class means the
  RBAC model says nothing about that account, which is a reason to deny. Grant
  it explicitly with `set system login user <account> class <class>` if it needs
  access.
- A UID shared by **two passwd accounts** is denied on BOTH surfaces. The kernel
  reports only the number, so the two callers are indistinguishable and naming
  one of them would hand that account's class to the other. See "unidentifiable"
  in the class table above — the REST gate and the CLI resolve this through the
  same code since #6645, and a divergence here was a privilege escalation
  between two legitimate accounts.
- **The class table above governs both surfaces, with one exception**: the row
  "uid 0 **with** an explicit `system login user root class <c>`" is honoured by
  the CLI and NOT by the REST gate, which authorizes uid 0 unconditionally (see
  "UID 0 is authorized unconditionally" above). Root can write the config
  database directly, so the two are equivalent in effect; the table is the CLI's
  answer, and this bullet is the REST caveat.
- A local caller the server cannot identify is **denied**, and an `api-auth`
  credential does not substitute for it. In fact **no caller this host can PLACE
  ever reaches the credential check**: the credential speaks only for a caller
  this host cannot place (the remote administrator #4047 requires it for). Read
  "can place" rather than "is local" — a process in a container on this same box
  has its own socket table and interface list, so it is local to the machine yet
  unplaceable by the daemon, and the credential governs it. That is the design,
  not a gap in it; `pkg/api/README.md` "Residuals" states the bound. Otherwise a
  restricted account that also knew the shared secret could escape its class,
  either by making its own identity unreadable or simply by not being in the
  login model. That holds even for an address that appeared on this host a
  moment ago — the "is this caller on our box" question is answered from a
  cached snapshot for speed, but the answer that would let the credential speak
  is re-derived from a fresh interface enumeration before it is acted on, so a
  caller connecting from a just-added VRRP VIP or DHCP lease is still governed
  by its class rather than by the shared secret.
- A `system login user` whose **name the daemon would refuse to provision** is
  denied. A strict commit rejects an invalid name at the schema, but the
  tolerant load and peer-sync paths (#1960) downgrade that to a warning and keep
  the stanza active, and account reconciliation then skips it — so the account
  was never created by xpf. Handing that stanza's class to whatever OS account
  happens to bear the name would grant authority from a config the runtime
  declined to realize, so `config.LoginUserClass` applies the same validator and
  resolves such a user exactly like an absent one. This cannot deny anyone xpf
  actually provisioned: provisioning runs the identical check. If an operator
  sees an unexpected denial here, the fix is to rename the user to a valid login
  name and commit — which is also what makes the shell account appear.
- Read-only endpoints, `/health` and `/metrics` are unaffected.
- The authorization is re-made **after** the caller has supplied its request
  body, not only when its headers arrive. A caller cannot hold a mutation open
  on a stale verdict by dribbling the body: a `commit` demoting its class, or a
  `delete system services web-management ... api-auth` revoking its credential,
  reaches the request before the mutation runs. See `pkg/api/README.md`
  "Every input to the decision is read after the last thing that can block".

### Custom login classes (accept-with-advisory, #4304 S-2)

Real vSRX configs define their own RBAC classes:

```
set system login class noc-admin permissions all
set system login class noc-admin idle-timeout 30
set system login user bob class noc-admin
```

Before #4304 the `class` leaf was a **fixed enum** over the built-ins only, so
`class noc-admin` was **hard-rejected at commit** — which blocked the WHOLE
config from committing. xpf now **recognizes** the custom `login class <name>`
definition (`permissions`, `idle-timeout`, `allow-commands`, `deny-commands`,
`allow-configuration`, `deny-configuration`), feeds the defined names into the
`class` validator (a tree-aware cross-reference, `validateLoginClassRef`), and
maps the Junos `permissions` token set onto xpf's coarse permission model at
compile (`LoginClass.MappedPermissions`, consulted at runtime by
`resolveClassPerms`).

The `permissions` tokens are validated at commit (#9490) against the Junos
login-class permission flag set, plus xpf's `super-user` alias. A misspelled
flag used to commit and silently fold to view-only, so the class was not the
one written. A config persisted before the gate still loads, because the
tolerant path does not run the schema validators.

Because xpf's runtime RBAC is **coarse** (view/clear/control/config/maintenance/
all) it cannot faithfully represent every fine-grained Junos permission or the
per-command allow/deny regexes. The **permission mapping** is therefore
**accept-with-advisory** — the commit succeeds and the compiler emits a
per-class advisory (`show system commit` / warnings) describing exactly what
maps and what does not. That is the treatment for everything below EXCEPT the
restrictive `deny-commands` / `deny-configuration` regexes, which are refused
outright (#5831, see the next section):

- `all` / `super-user` → `super-user` (PermAll); `maintenance` → maintenance;
  `clear` → clear; `control` / `reset` → control; `configure` → configure;
  `view` / `view-configuration` → view.
- **No privilege escalation** — the mapping never grants more than the Junos
  token permits. Two Junos tokens are deceptive and are folded conservatively:
  `reset` permits restarting software *daemons* (`restart <process>`), **not**
  rebooting/halting/zeroizing the box, so it maps to **control**, never
  `maintenance` (the destructive box verbs). `rollback` permits reverting to a
  prior commit only, not arbitrary `set`/`delete`, so it folds to the
  **view-only floor**, never `configure`.
- **Every other** recognized token (a subsystem read like `network` /
  `interface` / `routing` / `firewall`, a `*-control` write token, `shell`,
  `secret`, …) folds **down** to a **view-only floor**. Under-granting is
  deliberate: the coarse model must never silently grant config / control /
  maintenance from a narrow subsystem token.
- `idle-timeout` is **recognized but NOT enforced** by the coarse gate
  (dropping a session-lifetime knob cannot make the class more permissive); the
  advisory names it.
- **All four regex sub-statements are ENFORCED** since #7172 — `allow-commands`
  and `allow-configuration` as ALLOWLISTS, `deny-commands` and
  `deny-configuration` as denials, on both the CLI and the gRPC surface. Both
  directions changed on upgrade; see below.

### The four regex sub-statements are ENFORCED (#7172)

All four — `allow-commands`, `deny-commands`, `allow-configuration`,
`deny-configuration` — are evaluated on every dispatch surface: the on-box CLI's
operational and configuration paths, the gRPC listener the remote `cli` speaks
to, and the REST API.

> **This sentence was a LIVE OVERCLAIM until #9154, and the shape of the error
> is worth keeping.** It said "every dispatch surface" and then enumerated two,
> and the `*-configuration` pair was in force on exactly ONE of them — the
> console. The gRPC listener the shipped `cli` binary speaks to, and the REST
> API, both mutated configuration without consulting them, so an operator who
> gave someone broad `permissions` while withholding specific configuration
> authority had that withholding enforced only if the person happened to log in
> at the console. **The documented way to administer the box was the way around
> the restriction**, and an operator reading this page had no way to discover it.
>
> The three surfaces now share ONE decision — `config.AuthorizeConfigMutation`
> — rather than three callers of a common resolver. #7172 cut 6 had already
> moved the RESOLUTION into `pkg/config` for exactly this reason ("so this gate,
> the operational gate and the gRPC gate all read one implementation"); the
> DECISION stayed behind in `pkg/cli`, where the other two could not reach it.
> A rule enforced by whichever caller remembers to call it is the shape that
> produced the gap.
>
> **`load` remains a stated gap on every surface.** It applies arbitrary content
> whose paths are not known until parsed, so enforcing a path regex against it
> means matching every path the loaded content touches — a different mechanism
> from a verb gate, not something these gates quietly cover. `commit` and
> `rollback` act on the candidate as a whole and carry no path to match.

> **UPGRADE NOTE — read this before upgrading if any class carries these
> statements. Two behaviours change in opposite directions.**

#### 1. A `deny-*` class was REJECTED at commit and now commits — and takes effect

Between #5831/#6838 and #7172, a class carrying `deny-commands` or
`deny-configuration` was **hard-rejected** at `commit` / `commit-check`, and
folded to a `{view, configure}` repair floor on the tolerant load path. That was
correct while xpf could not enforce the regex: accepting the statement would
have left the denied verbs allowed while the config said otherwise — a
restriction that does not restrict, which is worse than a refusal.

xpf enforces it now, so the refusal is gone and so is the fold. An operator who
has been carrying such a config through the rejection will find that it commits
**and that the denial is real**.

```
set system login class limited permissions all
set system login class limited deny-commands "request system zeroize"
```

Before: refused at commit. After: commits, and `limited` cannot zeroize — on the
console, over `cli`, or over gRPC.

The fold is gone with it. It existed to resolve an *unenforceable* statement in
the restrictive direction; with the regex enforced, folding would narrow the
class a second time on top of its own pattern. A class's `permissions` are now
exactly what was written.

#### 2. An `allow-*` regex is an ALLOWLIST, and it was inert until now

This is the direction that can lock someone out, and it is silent.
`allow-commands` and `allow-configuration` committed cleanly and were documented
as **recognized, not enforced**. They are enforced now, and an allow regex does
not merely *add* — anything it does not match is **denied**:

```
set system login class ops permissions all
set system login class ops allow-commands "show interfaces"
```

Before: `ops` could run everything its permission bits allowed. After: `ops` can
run `show interfaces` and **nothing else** — not `show version`, not
`configure`. Audit for `allow-commands` / `allow-configuration` before
upgrading; a class that carries one is narrowed to it.

Nothing changes for a class carrying none of the four. The regexes are consulted
only for a class that configured them, and every fail-closed path below is
likewise scoped to those classes alone.

#### Precedence: three tiers, and "allow wins" is not the whole rule

Both surfaces evaluate the pair through one shared matcher. The tiers are
Juniper's, except tier 3:

| case | winner | source |
|---|---|---|
| the **identical pattern** in both leaves | **allow** | Juniper, stated outright |
| **different** patterns, different matched lengths | the **longest matched substring**, whichever leaf it came from | Juniper, with the `commit` / `commit synchronize` worked example |
| different patterns, **equal** matched lengths | **deny** | **xpf's interpretation of an underspecified rule** — not Junos behaviour |

Tier 2 means a longer **deny** beats a shorter **allow**. "Allow always wins" is
false, and implementing it would be a fail-open: `allow-commands "commit"` beside
`deny-commands "commit synchronize"` must deny `commit synchronize`.

Tier 1 giving allow the win reads like a fail-open and is not one — it is the
deny-with-exceptions idiom the feature exists to support, and it is Junos
parity. Tier 3 is ours, chosen fail-closed, and is flagged as ours so anyone
with a real Junos box knows which sentence to go and check.

Matching is **partial**, not anchored: `allow-commands "show interfaces"` admits
`show interfaces terse`. Juniper's guidance to use anchors for complex patterns
is only coherent if the default is partial, and the anchored spelling works
too.

> **An anchor cuts in OPPOSITE directions for allow and for deny (#9022).**
>
> Partial matching makes an **allow** wider than its text — `allow-commands
> "show interfaces"` admits `show interfaces terse`, which is the permissive
> direction and is the one operators notice.
>
> It used to make an **anchored deny narrower** than operators intend, and that
> is the direction nobody notices, because the command still runs. With
> `deny-commands "^show log$"`, every argument form ESCAPED:
>
> ```
>   show log            canonical "show log"           DENIED
>   show log 100        canonical "show log 100"       ALLOWED  <- same journalctl command
>   show log messages   canonical "show log messages"  ALLOWED
> ```
>
> `show log` accepts arguments (`AcceptsArgs` in the operational tree), so the
> canonical string carried them and the `$` no longer matched. **This is fixed.**
> Each side of the rule is now matched against BOTH the full canonical string
> and the argument-free command prefix, and the longer match for that side is
> what the precedence tiers see. All three rows above now deny.
>
> **The widening is per-side, not "deny if either matches".** That distinction
> is what preserves deny-with-exceptions:
>
> ```
> deny-commands  "^show log$"
> allow-commands "^show log 100$"
>
>   show log        DENIED   (deny matches; no allow does)
>   show log 100    ALLOWED  (deny matches 8 chars on the prefix, allow matches
>                             12 on the full string — tier 2 gives it to allow)
>   show log 200    DENIED   (not the allowed exception)
> ```
>
> A blunt "deny when either form matches a deny pattern" closes the hole and
> breaks that idiom, denying the form the operator explicitly allowed.
>
> **An anchored deny still binds to ITS OWN command, not to a subtree.**
> `deny-commands "^show configuration$"` does not deny `show configuration
> system`, because that is a DISTINCT command node with its own handler (`show
> configuration` is not `AcceptsArgs`; it has 16 declared children). That is the
> same property as `^show version$` not denying `show route`, and widening it
> would mean an anchored rule silently covered a whole subtree. To deny a
> subtree, write the deny unanchored: `deny-commands "show configuration"`.
>
> The line the fix draws is *the same command with arguments* versus *a
> different command*: `show log 100` runs the very handler `show log` runs
> (`journalctl -u xpfd -n 100`), while `show configuration system` runs another
> one. That is why the widening uses the resolved KEYWORD RUN and not "the first
> two words".
>
> Distinct again from the #8289 case, which was already covered: appending a
> *sibling keyword* rather than an argument (`show version configuration` under
> `deny-commands "^show version$"`) yields an unresolvable canonical command and
> **fails closed**.
>
> **Both control surfaces now agree for an anchored rule.** The remote ShowText
> path prices commands by topic through argument-free canonical strings, so it
> always denied correctly; the console did not. An operator who verified a deny
> rule over the remote CLI therefore got the wrong answer about the console.
> `TestAnchoredDenyAgreesAcrossSurfaces9022` asserts the agreement rather than
> each side separately. The separate ARGUMENT-TEXT gap recorded in
> `pkg/grpcapi/authz_command_table_topics.go` (a regex written against argument
> text matches on the box and not remotely) is unchanged and still open.

#### An EMPTY pattern is not an absent one

`deny-commands ""` and a valueless `deny-commands` both flatten to the empty
string, and an empty POSIX regex matches at every position — so an empty deny
**denies every command**, the most restrictive thing an operator can write. An
absent deny denies nothing. The compiler records leaf **presence** separately
from value for exactly this reason; a value test would wave the empty case
through.

The same applies to `allow-commands ""`, for a subtler reason: an empty allow
matches everything, so alone it is indistinguishable from an absent allow — but
beside `deny-commands ""` the two patterns are **identical**, which is tier 1,
where allow wins and the class is allowed everything. Read the empty allow as
absent and the same config denies everything instead.

#### Fail-closed paths, all scoped to classes that configured regexes

- a class whose regex does not **compile** is denied. Patterns are validated at
  commit, so reaching evaluation with an uncompilable one means the config
  arrived by a path that did not validate.
- a command that cannot be **canonicalized** is denied on the CLI path: not
  knowing which command is held, we cannot know a deny regex fails to match it.
- an RPC with no **canonical command** is denied on the gRPC path — a
  config-mode method, a routing-status RPC with no `cmdtree` command, an unknown
  `ShowText` topic, or a prefix-form `SystemAction` verb.

#### The two surfaces do not match the same string

The on-box gate matches the full canonicalized line, **argument values and the
output pipe included**. The gRPC gate matches the canonical command **path**,
because the remote `cli` parses the line client-side and only a typed RPC
crosses the wire — `ping 10.0.0.1` arrives as `Ping{Host:"10.0.0.1"}`.

The canonicalized line holds only words the command tree models. Every value
slot takes exactly one value, so a word appended after a value
(`show route table secret-vrf bypass`) is refused as uncanonicalizable, not
carried into the matched string. Before #9505 it was carried: the handler
dropped the word and ran the command, and an anchored deny against the
value-carrying command did not match. Commands whose options may come in any
order (`show security flow session`, `ping`, `monitor traffic`, …) are declared
as option lists, so each option is resolved and canonicalized rather than
refused.

The output pipe is not command-tree grammar, so it is not canonicalized with the
command (#9628). The words before the first `|` are canonicalized and the pipe is
matched as typed, so a deny on `display set` still sees it. A pipe verb the CLI
does not implement is refused. The command WITHOUT its pipe is matched as well,
so `^show version$` also denies `show version | match .`.

So a deny written against a **path** (`request system reboot`) is enforced
identically on both. A deny written against **argument text**
(`show route table secret-vrf`) is enforced on the box and **not** over gRPC.
A pattern that can never fire on the gRPC surface is reported for the class, so
this is visible rather than inferred.

The same holds for each alternative of a combined pattern (#9340). Take
`^(show route table secret-vrf|request system reboot)$`. It is enforced on both
surfaces for `request system reboot` and only on the box for
`show route table secret-vrf`, and the commit output names that alternative.
Before #9340 the enforceable half silenced the warning for the whole pattern.
The alternatives come from the parsed pattern: alternations and optional groups,
however they are spelled or anchored. So the report does not depend on how the
rule was written. A pattern with more than 64 alternatives is not split and
keeps the whole-pattern answer.

"Can fire" means the deny pattern is what refuses a command. A class with an
`allow-commands` pattern also refuses every command outside its allow list.
Before #9340, those refusals counted as the deny firing, so allow `^show` with
deny `^show route table secret-vrf` reported nothing, although that deny decides
nothing on the gRPC surface.

#### The `*-regexps` family is NOT implemented (#7971)

Junos has a **second**, parallel family of command/configuration restrictions:

```
allow-commands-regexps / deny-commands-regexps
allow-configuration-regexps / deny-configuration-regexps
```

**xpf does not implement it, and it is REFUSED at commit** — as of #7971, and
not before. An operator following Juniper's documentation and writing
`set system login class limited deny-commands-regexps "..."` sees the commit
refused with a message naming the leaf, the precedence difference, and the
supported alternative. That is intended, not a bug; express the restriction
with a narrower `permissions` set or with the plain family.

> **Correction (#7971).** This section previously said the family was refused
> *because* there was no schema leaf: "There is no schema leaf, so a `-regexps`
> statement is rejected at commit as an unknown leaf rather than accepted and
> ignored — the safe posture." **That inference was wrong and the stated posture
> was the opposite of the behaviour.** `closedWorld` is opt-in per subtree
> (`pkg/config/schema.go`) and `system login class` does not set it, so
> `SchemaValidate` leaves an unmodeled keyword to the compiler, which drops it.
> Measured on the real commit path, with the supported `deny-commands` as the
> accept-side control:
>
> ```
> deny-commands-regexps "^set system"  -> ACCEPT, nothing retained
> deny-commands         "^set system"  -> ACCEPT, DenyCommands retained
> ```
>
> Both committed clean; only one did anything. For an access control that is the
> fail-OPEN direction — the operator authors a restriction, sees success, and is
> not restricted — and it is strictly worse than the missing feature, which is at
> least visible. The four leaves are now modeled in `setSchema` **solely so they
> are rejected** (`pkg/config/schema_login_regexps_7971.go`), with
> `login_regexps_rejected_7971_test.go` pinning both the refusal and the
> accept-side control. Absence of a schema leaf does not imply rejection; only
> `closedWorld` does.

It is called out separately from the unmodelled leaves above because it is not
merely absent — **it inverts the precedence rule of the family xpf does
implement**:

| family | when a command matches both an allow and a deny |
|---|---|
| plain (`allow-commands` / `deny-commands`) | **allow wins** |
| `*-regexps` | **deny wins** |

The matching subject differs too: Juniper documents each `-regexps` string as
evaluated against the **full path** of the command, which is why it is
described as faster than the plain statements.

Both differences matter for whoever implements this. The natural approach —
reuse the precedence logic that "already handles allow vs deny" — produces
**silently wrong semantics in the unsafe direction**: a `deny-commands-regexps`
that loses to an `allow-commands-regexps` is a privilege escalation, introduced
by a change that looks like straightforward reuse of tested code. So precedence
must be **per-family data, not a constant**, and the test that binds it needs a
config carrying *both* families with a command matching an allow in one and a
deny in the other — a single-family fixture cannot tell a per-family rule from a
shared one.

**Decision (#7971): won't-do for now**, recorded as a row in
[`docs/feature-gaps.md`](feature-gaps.md) §22 rather than left implicit. The row
states the precedence inversion as the reason reuse is unsafe, so the next
reader does not wire the leaves to the plain family's evaluator. It also records
the part that is easy to miss: because the absent family is the deny-precedence
one, xpf has **no** deny-wins restriction family at all, and the plain family's
allow-over-deny combined with unanchored partial matching (below) lets a wide
allow silently re-permit a narrow deny. The gap is a safety gap, not only a
parity gap.

Modeling the four leaves to REJECT them is deliberately not a step toward
implementing the family: nothing in `schema_login_regexps_7971.go` consumes
`LoginRegexFamily`, and it must stay that way until the precedence and
full-path-matching differences above are both handled in the same change.

`pkg/config/login_regex.go` already records this distinction in its header
comment for exactly that reason. Note that the file's presence does **not** mean
the family is available: it compiles the *plain* family's patterns, and the
`-regexps` precedence note there is a warning left for a future implementer,
not a live code path.

#### `load` is a named gap

`deny-configuration` is matched against configuration-mutation verbs. `load
merge` / `load override` carry their content in a file or a terminal stream that
is not parsed at the time the verb is gated, so a verb gate cannot match against
it. Restricting what an operator may `load` needs a different mechanism.

### Write the body as a block or as `set` — never packed on the line (#6662)

Junos accepts a statement written on the instance line; xpf compiles the body
only from a **nested block** or a flat **`set`** statement:

```
system { login { user alice { class ops; } } }      # OK — class = "ops"
set system login user alice class ops               # OK — class = "ops"
system { login { user alice class ops; } }          # REJECTED at commit
```

Before #6662 the third form compiled a user with an **empty class** and the
commit **succeeded**. The mechanism is documented in
`docs/config-schema.md` ("Packed statements"): `namedInstances` resolves the
instance name across both AST shapes but leaves the body on `Keys`, and the
login compiler walks `.Children`, which is empty.

An empty class is precisely the legacy allow-everything mode, so a
`class read-only` operator hand-migrating a vSRX config got a CLI that allowed
every command and rendered secrets in cleartext — with `show configuration`
echoing their intent back. Rejecting is load-bearing because the downstream
safety nets all read fields the packed drop leaves empty. The `deny-commands` /
`deny-configuration` gate above is the sharpest case: it keys off
`LoginClass.DenyLeavesPresent`, so a packed body means the commit it would have
**refused** is accepted instead, and the restriction the operator wrote is
discarded without a word. The field the bug empties is the field the check
reads.

This applies to the whole stanza, at every level:

| Statement | Packed spelling | Result |
|---|---|---|
| `login class <n>` — `permissions`, `idle-timeout`, `allow-commands`, `deny-commands`, `allow-configuration`, `deny-configuration`, `login-alarms`, `login-tip` | `class ops permissions view;` | **rejected** |
| `login user <n>` — `uid`, `class`, `authentication` | `user alice class ops;` | **rejected** |
| `login user <n> authentication` (a block) written inline inside a nested user body | `user alice { authentication ssh-rsa "…"; }` | **rejected** |
| the instance on the **`login`** statement line | `system { login user alice class ops; }` | **rejected** |
| `login` itself on the **`system`** statement line | `system login user alice class ops;` | **rejected** |

#### The `system` and `login` lines too (#6706)

The two ANCESTOR levels of the path drop the same way, and they were the
dangerous ones. `system login` compiles only when the path descends into a
nested block at **every** step:

```
system { login { user alice { class ops; } } }   # OK
system { login user alice { class ops; } }       # REJECTED — instance on the `login` line
system login { user alice { class ops; } }       # REJECTED — `login` on the `system` line
system login user alice class ops;               # REJECTED — the whole path on one line
```

Before #6706 all three of the rejected forms **committed green** and compiled
nothing. The cost differs by level, and the message says which:

| Packed at | Compiles to | Runtime |
|---|---|---|
| the instance line | a user with an **empty class** | fail-**closed**: `ResolveLoginClass` maps it to `unauthorized` |
| the `login` line | `System.Login` present but **empty** | fail-**closed** for non-root (`unauthorized`), root keeps its default |
| the `system` line | `System.Login == nil` | fail-**closed** since #6706: `LoginDroppedByPacking` suppresses the legacy early return, so a non-root caller gets `unauthorized` and root keeps its default. (Before #6706 this row WAS fail-OPEN — empty class, every command allowed, secrets in cleartext.) It applies to content-free prefixes too, e.g. `system login;`; whether it should is #6972 |

At every level, zero configured users also means `reconcileAbsentLoginUsers`
sees an empty desired set and **deprovisions every xpf-managed operator
account** on the next apply.

`system login;` and `system login user;` name no user and no class, so there is
no authored instance to report as dropped and they are **accepted** — rejecting
them would be an outage of its own. They are **not** equivalent between the two
spellings, though, and an earlier revision said they "declare nothing in either
spelling", which is false (#6706 review r11): `system { login; }` compiles a
non-nil empty `LoginConfig` and denies every non-root caller, while the packed
`system login;` compiles `System.Login == nil` and reaches the legacy
allow-everything mode. Deactivated config (`inactive:`) is pruned before any
gate runs and is unaffected.

The tolerant load / peer-sync path **warns** instead of rejecting (#1960
no-brick), so a node that persisted such a config under an older binary still
boots. An earlier revision claimed the resolver kept that from being an RBAC
hole because "a matched user with an empty class resolves to `unauthorized`".
That is true only of the `login`-line packing, where `System.Login` is non-nil
but empty. At the `system` line the stanza compiles to **nil**, there is no
matched user, and `applyCLILoginClass` used to take its
`cfg.System.Login == nil` early return — leaving the shell with **no class at
all**: every command permitted and secrets in cleartext, on a config that reads
as restrictive.

What closes it is `Config.System.LoginDroppedByPacking` (#6706 review r11): the
compiler records that a `system login` path was authored packed — for every
packed shape, including the two short prefixes above that the gate deliberately
does not report — and `applyCLILoginClass` refuses the legacy unset-class mode
when it is set, resolving through `ResolveLoginClass` instead. Non-root callers
get `unauthorized`; uid 0 keeps the console lifeline. A config that never
configured RBAC is untouched: the flag is false, the early return still fires,
and the legacy contract is unchanged.

`login-alarms` and `login-tip` are accepted by the grammar but have no compiler
arm in **either** spelling — a pre-existing accept-but-ignore gap, not a packed
drop.

### Command-to-permission mapping

Gating is on the resolved **top-level** command word:

| Command | Required permission |
|---|---|
| `show`, `ping`, `traceroute`, `monitor` | view |
| `clear` | clear |
| `request`, `test` | control |
| `request system {reboot,halt,power-off,zeroize}`, `request chassis cluster failover` | **maintenance** (super-user only) |
| `configure` | config |
| anything else | super-user (all) |

**Privileged-subcommand exception — destructive maintenance (#4108 F21).**
Most `request` verbs are `control`-level, but the four `request system` verbs
that take the box down or wipe it — `reboot`, `halt`, `power-off`, `zeroize` —
and `request chassis cluster failover` are gated at the super-user-only
**maintenance** (`PermMaint`) level. On Junos the predefined `operator` class
has no `maintenance` permission and so cannot reboot/zeroize; xpf matches that:
`operator` (which holds `control`) is **denied** these verbs, while its benign
`request` commands (`request security …`, `request system software`,
`request system dynamic-dns`, rescue-config save, etc.) stay `control` and
remain available. The exception lives in `requiredPermission` →
`requestSubcommandIsMaintenance` (`pkg/cli/permissions.go`) and resolves the
subcommand with the same prefix matcher the dispatcher uses, so an abbreviated
`request system zero` or `request sys reboot` is gated identically to the
fully-spelled form and cannot bypass the gate. `super-user` reaches these verbs
through `PermAll`, so `PermMaint` need not appear in its permission list.

**Audit trail (#4108 F8).** When one of these destructive verbs runs, the gRPC
`SystemAction` handler writes a fsynced `system_action` entry (verb + timestamp)
to the configstore audit journal (`.config.journal`) **before** executing, so an
attributable record is durable on disk before the action runs (the `journald`
line is not). For `reboot`/`halt`/`power-off` the record persists across the
reboot. For `zeroize`, the wipe now **deliberately removes `.config.journal`**
(#4576 — a completed factory reset must not hand its audit log, commit history,
or comments to the next tenant); the durable cross-wipe trail is therefore the
pre-execution fsync (an *interrupted* wipe still leaves the record on disk) plus
any remote syslog collector. See the configstore README "Audit journal" section
for the record format.

**Factory-reset erasure (#4576).** `zeroize` erases the xpf configuration
**state** so the prior tenant's committed config + secrets are not reloaded on
the next boot (RMA / resale / re-tenant). The wipe removes the `.configdb` SSOT
(`active.json`, `candidate.json`, `rollback.N.json`) and **`master.key` first**
(so an interrupted wipe cannot leave AES-GCM ciphertext behind next to the key
that decrypts it), the numbered text rollback slots `<config>.N` (full config
text with cleartext secret leaves — reloaded at boot by `loadRollbackHistory`),
the top-level `.conf` files (live config + `rescue.conf`), `.config.journal`
(+ rotated segments), and the self-signed REST-API TLS pair under `tls/`
(`tls/key.pem` — the device-generated localhost HTTPS private key — and
`tls/cert.pem`, #4599; xpf-generated, not tenant config, and regenerated on
absence by `generateSelfSignedCertAt` on the next boot). A wipe that cannot
fully erase this state returns an error rather than reporting a clean factory
reset.

**Config-root scope guard (#5684).** The wipe target is the daemon's configured
config root — `filepath.Dir(store.ConfigPath())`, the directory of the `-config`
path (#5280/#5554), so a non-default `-config /srv/xpf/site.conf` erases
`/srv/xpf`, not a hardcoded `/etc/xpf`. But `filepath.Dir` on a
custom/adversarial `-config` can resolve to a directory xpf does not own: a
config file placed directly in a shared directory (`-config /etc/xpf.conf` →
`/etc`; `-config /srv/site.conf` → `/srv`) or a directory-shaped `-config`
(`-config /srv/firewall`, where `filepath.Dir` climbs to the **parent** `/srv`).
Because the config-state sweep globs `*.conf` / `rollback*` and `RemoveAll`s
`<root>/.configdb` and `<root>/tls`, an unowned root would turn a factory reset
into a **broad deletion of sibling files** in that shared/parent directory.
`configstore.ValidateFactoryResetRoot` closes this: it refuses a config root
that is non-absolute (a relative/empty `-config` resolves to the daemon's
working directory) or equal to the filesystem root or a well-known shared/system
directory (`FactoryResetForbiddenRoots`: `/`, `/etc`, `/srv`, `/home`, `/var`,
`/usr`, …). The check is lexical on `filepath.Clean` (so a trailing slash and
`..` traversal normalize first). The default `/etc/xpf` and any dedicated
subdirectory pass. The guard runs at both resolution points
(`(*Server).zeroizeConfigRoot`, `(*CLI).zeroizeConfigRoot`) — so a bad root
fails **closed before any wipe leg runs**, erasing nothing — and, as
defense-in-depth, again inside **each** config-state wipe primitive before it
touches disk: the CLI's `configstore.FactoryResetConfigDir` and the gRPC
`grpcapi.zeroizeConfigDir` (the latter is the more destructive one — it
`RemoveAll`s `<root>/tls` and `<root>/.configdb`), so neither primitive trusts
its caller to have handed it an xpf-owned root.

**Rendered service-config erasure (#4585).** The wipe erases that
SSOT/rollback/journal state directly, but the prior tenant's secrets are ALSO
rendered into service configs xpfd writes **outside** `/etc/xpf`. `zeroize` now
erases those at wipe time too (`zeroizeRenderedConfigs`, same key-first /
error-surfacing discipline):

- **`/etc/frr/frr.conf`** — mode **0644 world-readable**; the `! BEGIN/END BPFRX
  MANAGED CONFIG` section carries BGP-MD5 / OSPF / IS-IS authentication keys.
  Only that section is stripped (`frr.StripManagedSectionFile`, disk-only — no
  FRR reload); operator content outside the markers is preserved and a purely
  operator-managed `frr.conf` is left untouched.
- **`/etc/swanctl/conf.d/xpf.conf`** — the IKE PSKs live in this single
  xpf-owned snippet; it is removed outright.
- **`/etc/kea/kea-dhcp{4,6}.conf`** — xpf owns these whole files; removed outright.

Beyond those exact paths, each rendered directory (`/etc/frr`,
`/etc/swanctl/conf.d`, `/etc/kea`) is **swept for crash-leaked `fsatomic` write
temps** (`.<base>.tmp-<rand>`, #5509) — the rendered-config sibling of the
`/etc/xpf` sweep (#5475). All three renders are written via `pkg/fsatomic`
(`frr.WriteFileDurable`, `ipsec.WriteFileAtomic`, `dhcpserver.WriteFileAtomic`),
which drops a `.<base>.tmp-<rand>` temp holding the **full cleartext render**
(routing-auth keys, IKE PSKs, Kea credentials) before its atomic rename. A
daemon hard-killed mid-write leaves that temp behind; `fsatomic` self-heals a
leaked temp on the *next* write to that base, but a factory reset + reboot has no
next write, so an exact-path-only removal (`StripManagedSectionFile` /
`os.Remove`) would let the temp — and its secrets — survive to the next tenant.
The sweep is scoped to those xpf-owned rendered directories, matches only the
narrow temp shape (so a legitimate service config or operator snippet in the same
directory is untouched), and treats an absent/unmanaged directory as a clean
no-op.

This must be done by the wipe itself, not deferred to the reconcile on the
completing reboot: a post-zeroize boot has **no committed config**, so the
daemon enters **#1922 bootstrap mode** (or, on an HA node, a normal boot with a
`nil` active config) and **SKIPS** the boot-time `applyConfig` that would
otherwise reconcile FRR/IPsec/Kea to empty (bootstrap suppresses the apply, and
the normal-boot apply is gated on `ActiveConfig() != nil`). Without the direct
wipe the rendered secrets would be a **persistent** residual across the reboot —
a re-tenanted device would keep the prior tenant's routing-auth keys in a
world-readable file — not the transient one earlier notes assumed. FRR /
strongSwan / Kea regenerate their configs from the now-empty xpf config on the
next `commit`, and the daemon still boots cleanly (bootstrap does not touch
those services). A failure to erase any of them surfaces as an error rather than
a clean factory-reset report.

**Provisioned login-account teardown (#4598).** The two erasures above remove
config + rendered-config secrets, but the OS **login accounts** xpf provisioned
also live **outside** `/etc/xpf` and **survive** the wipe — and they are the
*biggest* re-tenant leak because they grant **interactive login + sudo**, not
just a config-secret read:

- **`/etc/shadow` password hashes** (`reconcileUserPassword`),
- **SSH `authorized_keys`** under `/home/<user>/.ssh` (`applySystemLogin`),
- **`/etc/sudoers.d/xpf-<user>`** NOPASSWD grants (`reconcileSudoers`).

They persist for the same reason the rendered configs do: `applySystemLogin`
runs only inside the boot-time `applyConfig`, which a post-zeroize boot **SKIPS**
(bootstrap / `nil` active config), and even a full reconcile early-returns on an
empty config and never `userdel`s. So `zeroize` now tears them down at wipe time
too (`zeroizeLoginAccounts`, same error-surfacing discipline):

- **Sudoers.** The entire `/etc/sudoers.d/xpf-*` namespace is removed
  unconditionally (nothing is desired at factory reset), so no passwordless-root
  grant survives even if a marker is missing. Operator-authored drop-ins without
  the `xpf-` prefix are **left untouched**.
- **Users.** A `userdel -r` (removes the `/etc/shadow` + `/etc/passwd` entry and
  the home tree, incl. `authorized_keys`) fires **only** for an account that has
  a **provenance marker** in `/var/lib/xpf/provisioned-users/<user>` **and** whose
  current `/etc/passwd` UID still equals the marker's recorded UID — the same
  UID-keyed ownership marker used for the declarative D2 lock (#1944 §5.4).
  `authorized_keys` is removed *before* `userdel` so the SSH-key vector dies even
  if `userdel` fails; on a `userdel` failure the marker is **retained** so a
  retried `zeroize` re-attempts, and the failure is surfaced (the device is not
  reported safe to re-tenant while a live account remains).
- **All three marker roots are erased (#5841).** The account loop above
  enumerates only `provisioned-users`, but the #5841 split records
  password/key ownership in two **sibling** roots
  (`/var/lib/xpf/provisioned-passwords`, `/var/lib/xpf/provisioned-keys`). A
  factory reset erases those too (`zeroizeSweepResourceMarkerRoot`): a surviving
  per-account UID marker is #5869/#5871-class residue, and because
  `reconcileAbsentLoginUsers` **unions all three roots**, a re-tenant's
  reused-UID account (useradd hands the first non-system user UID 1000)
  colliding with a surviving marker would be deprovisioned — its password
  locked, its `authorized_keys` deleted — despite xpf never provisioning it, the
  exact overclaim #5841 kills, resurrected on a "factory-reset" box. The sweep
  removes every marker in the two resource roots (keeping only names **retained**
  for a fail-closed registry retry, so an account's three markers stay together)
  and drops the roots, so no marker survives in **any** of the three roots —
  mirroring the daemon's own `forgetProvenance`.
- **Key-only accounts' `authorized_keys` is removed too (#6190).** The account
  loop removes `authorized_keys` only for accounts in the `provisioned-users`
  registry, but a **key-only** account — a pre-existing operator/prior-tenant
  account xpf only added an SSH key to (`system login user <name> authentication
  ssh-*` with **no** `encrypted-password`) — gets a `provisioned-keys` marker and
  **no** registry marker (`applySystemLogin` writes `markProvisioned` only in the
  useradd branch; `reconcileUserPassword` only on a password apply). The registry
  loop never iterates it, so before #6190 the marker was swept (#5841/#6183) but
  the xpf-written `/home/<name>/.ssh/authorized_keys` **file** was not — the prior
  tenant kept SSH login on that account after a "factory reset", the #4598
  credential-leak class, **asymmetric** with the day-2 path
  (`reconcileAbsentLoginUsers` enumerates the **union** `provisionedNames()` and
  `deprovisionLoginUser` **does** remove that key file, gated on
  `keyProvisioned`). `zeroizeSweepProvisionedKeys` closes the asymmetry: it
  removes the xpf-written key **file** for every account with a `provisioned-keys`
  marker (the union delta the registry loop misses), **UID-gated and
  fail-closed** — the file is removed only when the live `/etc/passwd` UID equals
  the keys marker's recorded UID (a proven **UID-mismatch** is an out-of-band
  recreate whose `authorized_keys` belongs to someone else → left intact, marker
  retained), an unreadable passwd / unparseable marker **fails closed** (retain,
  surface the error), and an account whose registry teardown was **retained** is
  skipped entirely so its marker and key file stay consistent. `root` is never a
  key-only account (`applyRootAuth` writes the registry marker alongside the key
  marker) and its keys live at `/root/.ssh`, so this sweep never touches a
  `/home/root` key file — root is revoked in place by `zeroizeRootLoginAccount`.
  An **operator's own** (unmarked) `authorized_keys` is never touched — only what
  xpf wrote. On a **real key-removal error** (an immutable file, an
  `ENOTDIR`/`ENOTEMPTY` path shape, an I/O error) the key **file survives**, so
  the keys marker is **retained** and the error surfaced (`reset incomplete`), so
  a retried reset re-enumerates the account and re-attempts — mirroring the day-2
  `deprovisionLoginUser` contract, which keeps the markers and retries on a real
  `authorized_keys` removal error (#6201). The account-registry teardown may drop
  its marker after a key-removal error only because `userdel -r` backstops the
  removal by deleting the whole home tree; this key-only sweep has **no** such
  backstop, so dropping the marker while the key survives would strand the prior
  tenant's SSH key with no retry evidence (`zeroizeRemoveKeyFileThenMarker` gates
  both the proven-owned and genuinely-absent branches).
- **Ownership uncertainty fails CLOSED (#5496).** Deciding "is this the account
  xpf provisioned?" needs two reads — the live UID (`/etc/passwd`) and the
  recorded UID (the marker). If **either** cannot be resolved — `/etc/passwd`
  unreadable, a **malformed UID**, or an **unreadable/unparseable marker** —
  ownership is **UNKNOWN, not proven absent**. The teardown then makes **no**
  destructive change, **retains** the marker (durable evidence for a safe
  retry), and **surfaces** the error so the reset is reported **incomplete**.
  The earlier code conflated an unresolved read/parse with proof-of-absence (or
  a stale marker), erasing the marker and returning a clean result while a live
  xpf-provisioned **password** account survived — now un-rediscoverable because
  its retry marker was destroyed. A **proven UID-mismatch** is likewise reported
  (unresolved) and its marker retained, absent an explicit durable stale-marker
  policy. This is the factory-reset sibling of the day-2 login fail-closed rule
  (#5493) — the same `lookupUIDGIDErr` three-state discipline at a distinct
  locus.

**Never-touch safety invariant.** The teardown must never nuke a non-xpf account
or strand access:

- An **operator's own account** (created out of band, no xpf marker) is never
  iterated — its keys, sudoers, and login stay intact.
- **System accounts** (and an **unmanaged-root** appliance's `root`) have no
  marker and are never iterated — untouched by the teardown.
- **`root` on a managed-root appliance IS revoked (#5520).** Since #5276 the
  daemon writes a genuine provenance marker for `root`
  (`markProvisioned("root", 0)`), so `root` reaches the teardown. It must NOT
  take the generic path — root's `authorized_keys` is at **`/root/.ssh`**, not
  `/home/root/.ssh` (which the generic path would miss, leaving the prior
  tenant's root SSH key live), and **`userdel -r root` fails on UID 0** and can
  abort the whole reset. So `root` is special-cased and revoked **in place**
  (`zeroizeRootLoginAccount`): remove `/root/.ssh/authorized_keys` **and** lock
  the root password (`passwd -l root`), **never** `userdel`. Fail-closed like
  the rest — the marker is retained and the reset reported incomplete unless
  both revocations succeed. A factory reset MUST revoke root; a
  decommissioned/RMA'd appliance that kept prior-operator root login would be a
  false factory reset.
- An **out-of-band `userdel`+recreate** with a different UID (marker UID ≠ live
  UID) is left alone — the current owner is someone else, exactly the #1944
  leave-then-rejoin-vs-recreate distinction. Since #5496 this mismatch is also
  **reported** and its marker **retained** (rather than silently erased with a
  clean-reset report), so the anomaly is re-examined on a retry.

**Local config-archive erasure (#5186).** The three erasures above cover the
config SSOT/rollback/journal state, the rendered service configs, and the login
accounts — but they missed the last on-box generation of config secrets: the
**local configuration archive** at **`/var/lib/xpf/archive`**. `writeArchive`
drops timestamped `config-<ts>.<seq>.conf` snapshots there (Junos `system
archival`), each a **0600 copy of the full committed config TEXT** with the same
cleartext secret leaves as a rollback slot (IKE PSK, WireGuard private keys, SNMP
communities, BGP-MD5). A pre-#5186 `zeroize` left the archive untouched, so a
re-tenanted / RMA'd / resold device still handed the next owner the prior
tenant's archived secrets — a false factory reset. `zeroize` now erases it at
wipe time too (`configstore.FactoryResetArchiveDir`, same error-surfacing +
final-fsync durability discipline as the config-state wipe), and **both** the
gRPC `performZeroizeWipe` and the on-box CLI `request system zeroize` route
through that single shared primitive so they wipe the same archive.

- **Ownership guard.** Only the **xpf-owned default** path
  (`configstore.DefaultArchiveDir` = `/var/lib/xpf/archive`) is erased. An
  operator-configured **custom** archive directory — a remote mount, an NFS
  export, or a compliance/audit retention store — is **NOT** xpf's to destroy;
  blindly deleting it could wipe records the operator is required to keep. Such a
  path cannot be proven xpf-owned, so it is **skipped with a warning** rather
  than deleted (never a fail-closed delete). This mirrors how the config-state
  wipe proves ownership by its fixed default appliance path and how the
  login-account teardown refuses to touch a non-xpf-owned account.
- **Error surfacing.** A deletion or final directory-fsync failure is surfaced
  (folded into the wipe result / returned by the CLI), so a `zeroize` that could
  not fully erase the archive is never reported as a clean factory reset.
- **In-flight archive-writer fence + join (#5869).** Erasing the directory is not
  enough: auto-archive launches a **fire-and-forget writer goroutine** per commit
  (`commitWithDescriptionLocked`), and `writeArchive` starts with
  `os.MkdirAll(archiveDir)`. The #5281 terminal reset generation gates the
  daemon's config writers but **not** that configstore-owned goroutine, so a
  writer scheduled just before a `zeroize` could resume **after**
  `FactoryResetArchiveDir` removed the directory and **recreate** a
  `config-<ts>.<seq>.conf` snapshot of the **prior tenant's** full config text —
  re-tenant secret residue, a zeroize that did not actually erase everything. The
  daemon's factory-reset transaction (`daemon.factoryReset`) now calls
  `store.QuiesceArchival()` **after** entering the reset generation and **before**
  the wipe: it sets a one-way **archive fence** (a new/not-yet-written writer
  no-ops instead of recreating the archive) and **joins** every in-flight writer
  (`archiveWG.Wait()`) that has already begun, so once it returns no writer can
  recreate the directory the wipe is about to erase. The join is the load-bearing
  half — it closes the write-after-wipe window a fence alone cannot. On a
  **fail-closed recoverable wipe** the daemon stays up and resumes normal work, so
  it also `ResumeArchival()`s (clears the fence); on a **successful** wipe the
  daemon is stopped and the fence stays latched.
  - **Synchronous `Store.ArchiveConfig` is fenced too (#6185).** The same fence
    now also gates the **synchronous** archive path. `Store.ArchiveConfig` has
    **zero** production callers today, but if it were ever wired to an operator
    command (e.g. `request system configuration archive`) an unfenced call could
    run **after** the fence was set and the archive dir erased, `os.MkdirAll` it
    back, and drop a prior-tenant snapshot — reopening the residue for that path.
    It now (1) **no-ops** when the fence is set and (2) registers itself in
    `archiveWG` when it is not, so a concurrent `QuiesceArchival` **joins** an
    in-flight synchronous write before the wipe, exactly like the async writer.

**Privileged-subcommand exception — `monitor traffic` (#4067).** Almost
every command is gated on the top-level word alone, but `monitor traffic`
spawns a **root `tcpdump` live packet capture** on a data interface, so it
is gated at the **control** level (the same bucket as the `request` /
shell-out family) instead of the plain `view` level the rest of `monitor`
(interface stats, terminal-only `packet-drop`) uses. A `read-only` /
`config-viewer` class — intended only to VIEW config and status — is
therefore **denied** `monitor traffic`; `operator` and `super-user` are
allowed. This mirrors Junos, which gates `monitor traffic` behind the
maintenance permission, not plain read-only. The exception lives in
`requiredPermission` (`pkg/cli/permissions.go`) and resolves the subcommand
with the same prefix matcher the dispatcher uses, so an abbreviated `monitor
tr` is gated identically to the fully-spelled form and cannot bypass the
gate. Other `monitor` subcommands and read-only `show` commands are
unaffected.

**Privileged-subcommand exception — `monitor security flow {file,start}`
(#5038).** The file-backed flow trace makes the **root daemon create, append
to, and rotate a file on disk** (`openTraceFile` / `rotateTraceFile`,
`pkg/cli/monitor.go`). At `view` level a `read-only` class could point that
write at, and rotate-rename, an arbitrary existing regular inode — corrupting
or displacing a privileged log. `monitor security flow file <name>` and
`monitor security flow start` are therefore gated at the **control** level
too (same `requiredPermission` prefix-resolved gate as `monitor traffic`), so
a view-only class cannot trigger the root write at all. The status form (bare
`monitor security flow`), `filter` (in-memory), `stop`, and the terminal-only
`monitor security packet-drop` stay `view`. Defense in depth: traces are also
confined to a dedicated root-owned (0700) directory `/var/log/xpf-flow-trace`
rather than the shared `/var/log`, so even a control-level operator's trace
filename can never resolve onto — or rotate/rename — a system-log inode such
as `/var/log/auth.log`.

**Filter option-injection hardening — `monitor traffic ... matching` (#4524).**
The `matching <filter>` clause greedily consumes every token up to the next
grammar keyword and passes them to the root `tcpdump` capture. Without an
end-of-options guard a filter such as `matching -w /etc/cron.d/x` or
`matching -z <cmd>` reaches tcpdump as the `-w` (arbitrary file write) or `-z`
(post-rotate command execution) **option** under glibc getopt argv
permutation — escalating a control-level capture privilege to root
file-write / command-exec, and violating the capture-only contract even for
`super-user`. `buildMonitorTrafficArgv` (`pkg/cli/cli_request.go`) now inserts
an explicit `--` end-of-options separator before the filter tokens (mirroring
the diagcmd ping/traceroute #2084 treatment), so getopt stops scanning for
options and every filter token is parsed as part of the pcap filter
**expression** — an injected `-w`/`-z` becomes a filter operand that libpcap
rejects at compile time rather than a tcpdump option. A defense-in-depth
`validateMonitorFilter` check additionally rejects any option-looking filter
token (a term beginning with `-`, other than a bare `-`) up front with a clear
error. Legitimate pcap filters (`host 10.0.0.1 and port 22`, `tcp port 80`,
`not arp`) are unaffected.

**Secret redaction in `show configuration` (#4099).** The on-box interactive
CLI config-render show paths — `show configuration` (hierarchical / `| display
set` / `| display json` / `| display xml` / `| display inheritance`, including
path-scoped subtrees), `show system rollback <N> [| display set | compare]`,
`show system login` / `internet-options` / `root-authentication`, `show system
configuration rescue`, and the config-mode `show` / `show | compare` — mask
secret leaves (IKE pre-shared-keys, SNMP communities, BGP/OSPF
authentication-keys, WireGuard private keys, encrypted passwords, DDNS
tokens/keys) with `##SECRET-DATA##` for **every login class except
`super-user`**. This mirrors Junos (which never renders a cleartext secret in
`show configuration` for any class) and the always-redacted REST/gRPC
`ShowConfig` path (#4051): a VIEW-only `read-only`, `config-viewer`, or
`operator` login can no longer harvest cleartext firewall secrets through the
console. The redaction predicate is `CLI.showConfigRedacted()`
(`pkg/cli/permissions.go`): it routes rendering through the `*Redacted`
configstore methods (the same `RedactedClone` renderers REST/gRPC use) for any
class **without** `PermAll`.

`super-user` still reads cleartext — it is the console root that already has
direct config-DB filesystem access, so masking it would only obstruct the
operator copying a secret while providing no protection (the deliberate #4057
allowance). An **unset/empty** class (no `system login` configured — the legacy
no-RBAC allow-everything mode) is likewise treated as privileged and reads
cleartext, so a deployment with no login classes is bit-identical to before the
change. An **unknown** class fails **closed** (redacted). Config mode requires
`PermConfig` (super-user only today), so the config-mode candidate show paths
render cleartext in practice; they are wired through the same gate as
defense-in-depth should a lower class ever gain config-view access. The raw
`rescue.conf` text (a full cleartext-secret config dump, #4056) is reparsed +
redacted before display and fails **closed** — a parse error returns an error
rather than the cleartext bytes.

**Reading the CANDIDATE configuration requires `PermConfig` (#9324).**

`ConfigTarget`'s proto3 **zero value is `CANDIDATE`**, and both config-read
surfaces were priced `PermView`. A read-only caller that omitted the target
therefore received another session's **uncommitted** configuration. Measured
against a session holding a staged edit:

```
REST show, no ?target        -> "... security-zone SECRET-WIP-ZONE ..."
REST show, ?target=active    -> "system { host-name COMMITTED-ACTIVE; }"
REST compare (no selector)   -> "+ security-zone SECRET-WIP-ZONE"
```

Two failure modes. **Disclosure:** topology, zones, policies and address books
of work in progress (secrets are separately redacted, so this is not #4099).
**Silent wrong answer:** on an idle box the same call returns an EMPTY string, so
a config-backup client written without `?target=active` archives either nothing
or somebody's draft and cannot tell which.

The rule now, on both surfaces:

| request | permission |
| --- | --- |
| `ShowConfig` with `Target: ACTIVE`; `GET /api/v1/config/show` with no `?target` or `?target=active`; `GET /api/v1/config/export` | `PermView` |
| `ShowConfig` with `Target: CANDIDATE` **or omitted**; `GET /api/v1/config/show?target=candidate`; `GET /api/v1/config/compare` (any `?rollback`) | **`PermConfig`** |

That is the Junos reading: operational `show configuration` renders the
**committed** configuration, and seeing a candidate is a configure-mode activity
a class without `configure` cannot reach.

**Why the two surfaces are fixed differently.** REST's `?target` is a string, so
an ABSENT parameter is distinguishable from an explicit one: the default there is
now `active` (matching `GET /api/v1/config/export`, which has always rendered
ACTIVE), and an unrecognised `?target` is a 400 rather than a fall-through. gRPC
cannot do that — proto3 does not distinguish an omitted enum from an explicit
zero, so defaulting to ACTIVE would also rewrite an *explicit* `CANDIDATE`
request, which `cmd/cli` sends for its config-mode view. Renumbering the enum to
add an `UNSPECIFIED` sentinel is a wire **redefinition** and a rolling-upgrade
hazard. So gRPC is fixed by **price** alone, and both surfaces agree on that
price.

`GET /api/v1/config/show-rollback` was checked and is **unaffected**: it reads the
committed rollback archive (`ShowRollbackRedacted` → `rollbackEntry`), not the
candidate, so it stays `PermView`.

Enforcement lives at the two choke points that already adjudicate — `readAuthz`
(`pkg/api/authz.go`) and the gRPC principal interceptor beside
`authorizeRPCConfigMutation` (`pkg/grpcapi/authz.go`) — not in the handlers, so a
new target-taking route cannot be added with its read ungated.

**SNMP community masking in status commands (#4111).** The #4099 redaction
above covers the config-render surfaces (they route through the `RedactedClone`
renderers). Two **operational status** commands, however, format the typed
active config directly and so bypassed that path: `show system services`
(`showSystemServices`, `pkg/cli/cli_show_system.go`) printed `Community: <name>
(<auth>)`, and `show snmp` (`showSNMP`, `pkg/cli/show_services_snmp.go`) printed
`  <name>: <auth>`. Both are PermView `show` commands reachable by
`read-only` / `config-viewer` / `operator`, so the SNMP community string — a
read/write credential — leaked in cleartext to view-only classes. They now
reuse the same `CLI.showConfigRedacted()` predicate: for any class without
`PermAll` the community **name** is masked to `##SECRET-DATA##` while the
authorization **mode** (`read-only` / `read-write`) stays visible; `super-user`
and the unset/legacy class still read the cleartext name (parity with the #4099
config-render decision above) — **on the in-process console CLI only; see the
next paragraph for `cli`**. The TSIG key already showed `(secret redacted)` and
SNMPv3 renders auth/priv protocol names only, so the community name was the
last cleartext SNMP secret on these two surfaces.

**The same masking on the REST and gRPC surfaces (#5315, #6532).** The CLI is
not the only place that formats the typed active config by hand. The REST
show-text handler (`pkg/api/show_text.go`) rendered the same community and was
masked in #5315; the gRPC `ShowText{Topic:"snmp"}` renderer
(`pkg/grpcapi/server_show_dhcp_lldp_snmp.go`) was left in the clear until
#6532. Both mask **unconditionally**, unlike the CLI: neither surface carries a
login class to gate on, so there is no privileged caller to exempt — the same
call the sibling gRPC `ShowConfig` raw-AST redaction makes (#4051). The gRPC
one is not merely loopback-bound: `ShowText` is on the cluster-fabric allowlist
(#4122), so that render was reachable from the peer chassis over the fabric IP
(see `docs/architecture.md`).

All four render sites now share one implementation of the masking rule,
`config.SNMPCommunityDisplayName(name, redact)` (`pkg/config/types_system.go`,
next to the `SNMPCommunity` marshal redaction). The CLI passes
`redact=showConfigRedacted()` so its per-class behaviour is unchanged; REST and
gRPC pass `redact=true`. The reason a helper exists rather than an inline `if`
at each site: the community is the **one** operator secret not covered by the
`config.Secret` newtype's `String()` redaction (#2053) — it stays a plain
string because it is the `Communities` map key — so every manual renderer has
to remember to mask it, and three independent copies of that one-line rule are
exactly how the gRPC surface stayed in the clear through two hardening passes.

> [!IMPORTANT]
> **`cli show snmp` is masked for EVERY caller, including `super-user`
> (#6532).** The #4111 super-user cleartext allowance above survives only on
> the **in-process console CLI** (`pkg/cli`, which knows the login class). The
> remote `cli` binary — the primary operator interface — dispatches `show snmp`
> straight to the gRPC RPC (`cmd/cli/show.go`, `c.showText("snmp")`), and
> `cmd/cli` has no login-class awareness at all, so there is no class to
> exempt: it renders `##SECRET-DATA##` for every caller.
>
> Scope, precisely — the two sibling commands do **not** behave this way,
> because neither renders a community at all:
>
> - `cli show snmp v3` uses the `snmp-v3` topic, which prints only the USM
>   user table (user, auth protocol, privacy protocol). No community, so no
>   placeholder. The USM auth/privacy PASSWORDS were never rendered by it —
>   they are `config.Secret`-typed and masked by the newtype (#2053).
> - `cli show system services` uses the `system-services` topic, whose
>   renderer omits SNMP entirely (it lists the gRPC/REST endpoints). The
>   community masking described for #4111's `show system services` therefore
>   applies to the **console** CLI only; the remote command never showed a
>   community in the first place.
>
> This is a deliberate posture change, not an oversight. Threading a login
> class into `pkg/grpcapi` is not possible today (the package has no class
> plumbing) and would be actively wrong on the fabric listener, where the
> caller is the peer chassis rather than a user. Masking unconditionally is
> also what the sibling `ShowConfig` already does (#4051), so `cli show
> configuration snmp` was ALREADY masked for every class before #6532 — the
> two remote read-back paths now agree instead of contradicting each other.
>
> Operational consequence to be aware of: an operator has **no remote
> read-back path** for a configured community. Recover it from the console
> CLI as `super-user`, or from the DR archive (`request system configuration
> rescue`) — note that a redacted export is deliberately not restorable
> (#4060). The community remains fully functional on the wire; only its
> display is masked.

### Generating a hash

```
openssl passwd -6                       # prompts; emits a $6$ sha512crypt hash
mkpasswd -m sha512crypt                  # same, from the whois package
openssl passwd -6 -salt "$(head -c12 /dev/urandom | base64 | tr -d '+/=')"
```

Paste the resulting `$6$…` string into `encrypted-password`. yescrypt
(`$y$…`) and bcrypt (`$2b$…`) hashes are also accepted.

## Accepted hash formats (commit-check)

The value is validated at commit time by a shared validator
(`ValidateCryptHash`, used for both per-user and root authentication).

**Accepted:**

- A modular crypt(3) hash `$<id>$<salt>$<checksum>` with a non-empty
  salt and a non-empty final checksum, where `<id>` is one of
  `1, 2a, 2b, 2y, 5, 6, 7, y, gy`. Parameter fields are allowed
  (e.g. `$6$rounds=656000$salt$hash`, `$y$j9T$salt$hash`).
- An optional leading `!` or `!!` (the locked-but-restorable form),
  e.g. `!$6$salt$hash`.
- A bare lock sentinel: `*`, `!`, or `!!`. This is the intentional Unix
  way to lock an account, and the **only** way to lock root via config
  (`set system root-authentication encrypted-password "*"`).

**Rejected at commit:**

- **Plaintext** — pasting a cleartext password is hard-rejected. This is
  absolute: even a 13-character alphanumeric string (which a legacy DES
  crypt would resemble) is rejected, because xpf does not accept legacy
  DES hashes.
- An empty value, an unknown `$<id>$`, an empty salt, an empty checksum
  (`$6$salt$`), or a value containing `:` or a control character.

### Strict vs lenient paths

- **Operator commit / commit-check**: a bad value **hard-fails** the
  commit (the `#1319` typed-leaf gate). The plaintext footgun is closed
  at the entry point.
- **Boot / peer-sync**: an already-persisted or peer-synced value that
  fails validation is **downgraded to a warning** rather than failing
  boot, so a bad stored value can never brick the daemon.

## Removing the directive locks the account (declarative)

When you remove `authentication encrypted-password` from a user that xpf
provisioned, on the next commit xpf **locks** that account's password
(`<user>:!` via `chpasswd -e`) instead of leaving the old hash in
`/etc/shadow`. Removing the directive therefore disables password login
rather than orphaning a live credential. Re-adding the directive
restores the password.

This password reconciliation is **declarative**. SSH keys
(`authorized_keys`) remain additive and independent of the password — a
live password is a higher-severity orphan than a stale key. The
super-user sudo grant (`/etc/sudoers.d/xpf-<name>`) is **also
declarative** and reconciled on every apply (see below): a class
downgrade or user removal revokes it (#3889).

## Super-user sudo grants are reconciled and revoked (#3889)

A login user with `class super-user` is granted passwordless root via a
NOPASSWD drop-in `/etc/sudoers.d/xpf-<name>`. That grant is reconciled
against the **current** config on every commit by `reconcileSudoers`
(`pkg/daemon/daemon_system.go`), mirroring the networkd/rsyslog
stale-file reconcilers:

1. Write `xpf-<name>` for each user that is a super-user **now**.
2. Sweep `/etc/sudoers.d/xpf-*` and **REMOVE** any drop-in whose user is
   no longer a super-user. This covers both a **class downgrade**
   (`super-user` → `operator`/`read-only`) and a **user removal** from
   the config — in either case the passwordless-root grant is revoked on
   the next apply. Before #3889 the write had no removal branch, so a
   demoted or deleted admin kept passwordless root forever.

Only files with the `xpf-` prefix are written, kept, or removed; any
operator-authored file in `/etc/sudoers.d` is left untouched. The
reconcile runs **unconditionally** — even when `system login` has no
users (the "all users removed" case), so stale grants are still swept.
Writes are **DurableState** (`fsatomic.WriteFileDurable`, `0440`) and
the generated file is validated with `visudo -cf` (best-effort, root
only) before being trusted; a rejected drop-in is removed rather than
left as a lockout landmine, because a single malformed file in
`/etc/sudoers.d` breaks **all** sudo invocations. `root` is never
granted an xpf-managed drop-in.

## Removing a login user revokes its host credentials (#5128)

Deleting a whole `system login user` from config — not just its
`encrypted-password` directive — revokes that account's host access on
the next commit. Before #5128 only the sudo grant was swept
(`reconcileSudoers`); the account, its password, and its
`authorized_keys` all survived, so a deprovisioned operator could still
SSH in by password or key. `reconcileAbsentLoginUsers`
(`pkg/daemon/login_password.go`) closes that gap and, like
`reconcileSudoers`, runs **unconditionally** on every apply (including
the "all users removed" case):

1. Enumerate the **union** of the three ownership roots (`provisionedNames`,
   #5841) — every account xpf provisioned any resource for (registry,
   password, or key marker).
2. For each such username **no longer present** in
   `system login { user ... }`, and **only** while a marker's recorded UID
   still equals the account's current `/etc/passwd` UID: **lock** the
   password (`<user>:!` via `chpasswd -e`, idempotent — skipped if already
   locked) **iff** xpf set it (`passwordProvisioned`) and **remove** the
   xpf-managed `/home/<user>/.ssh/authorized_keys` **iff** xpf wrote it
   (`keyProvisioned`), then drop all provenance markers so xpf forgets the
   account. An operator-managed credential xpf did not provision is left
   intact (#5841).

The path is scoped and fail-closed:

- An **out-of-band account** (no marker) is never enumerated, so it is
  never touched.
- A marker whose UID no longer matches the live account (deleted +
  recreated out of band with a different UID) is treated as **not ours**:
  the account is left intact and only the stale marker is cleaned.
- On a `/etc/passwd` **read** error the marker is **retained** and the
  deprovision is skipped, so the next apply retries (#5493). A transient
  mount/permission/I/O failure reading the identity database is
  **unknown**, not proof the account is gone — only a *readable* passwd
  that does **not** contain the name is the genuine out-of-band `userdel`
  that legitimately drops the marker. Distinguishing the two is what keeps
  a read hiccup from permanently abandoning a removed user's still-live
  password and keys: once passwd is readable again the marker would be
  gone, so the account would never be enumerated (or revoked) again. This
  mirrors the `/etc/shadow` fail-closed rule below.
- On a `/etc/shadow` read error, a `chpasswd` failure, or an
  `authorized_keys` removal failure, the marker is **retained** so the
  next apply retries — a credential is never forgotten while it may still
  be live.
- On an **ownership marker** read error (or an unreadable marker **root**
  during enumeration) the deprovision is **skipped**, the markers are
  **retained**, and the failure is **returned** (#6798). An unreadable
  marker is not proof the credential is not ours: acting on it would revoke
  an operator's credential, while silently skipping it reported convergence
  for a removal that never happened. See "Unreadable ownership inventories
  are not empty ones (#6798)" below.
- `root` is never deprovisioned **by this login-user path** — it is
  reconciled separately by `applyRootAuth` (see "Root credentials are
  revoked on removal (#5276)" below).

Unlike the `zeroize` teardown (#4598), which `userdel -r`s the whole
account, ordinary removal only **locks** the password and removes the
managed key file. That fully revokes login (password and key) while
being reversible: re-adding the user to config recreates the account and
re-provisions it. Note the distinction from the section above: removing
just the **`encrypted-password` directive** (user still present) locks
the password but leaves `authorized_keys`; removing the **whole user**
revokes both.

### Emptying a retained user's SSH keys revokes the key file (#5106)

`reconcileAbsentLoginUsers` only fires for a user that has been **removed**
from config. A user that is **retained** but has had its **last**
`authentication ssh-rsa`/key removed (key list now empty) was NOT covered:
`applySystemLogin` wrote `authorized_keys` only inside `if len(user.SSHKeys)
> 0`, so an emptied key list left the stale key file installed and the
revoked key still permitted login. `applySystemLogin` now reconciles the
empty-key-list case in the matching `else` branch: when a configured user
has no keys, it removes the xpf-managed
`/home/<user>/.ssh/authorized_keys` so key-based login is revoked. The
removal is gated on the **SSH-key** provenance marker (`keyProvisioned`,
#5841) — xpf only deletes a key file **it wrote** wholesale, never a
pre-existing / out-of-band user's operator-installed keys, and **not** merely
because xpf set the account's password — and is idempotent (an already-absent
file is a no-op; the key marker is dropped once the file is gone). The password
directive and the SSH keys remain independent: this branch touches only
`authorized_keys`, and removing the `encrypted-password` directive still only
locks the password.

### Scope — only xpf-managed accounts

The per-user lock-on-removal applies **only to the exact account xpf
provisioned**, and never to accounts absent from config (xpf does not
deprovision/`userdel` accounts). `root` is handled by its own
`applyRootAuth` reconcile (see "Root credentials are revoked on removal
(#5276)"), not this per-user path. Provenance is tracked by UID-keyed marker
files whose content is the account's numeric **UID**: an account **registry**
entry under `/var/lib/xpf/provisioned-users/<name>` (written on `useradd` and a
successful password apply), plus **resource-specific** password- and
SSH-key-ownership markers that gate the respective revocations (#5841, see
"Resource-specific, atomic credential ownership" above).

- **Leave then rejoin the same account**: the UID is unchanged, so the
  marker matches and the lock fires — the old password is revoked.
- **`userdel` + out-of-band recreate with a new UID**: the marker's UID
  no longer matches, so xpf leaves the out-of-band account untouched
  (and opportunistically removes the stale marker).
- **Edge case**: if an out-of-band recreate happens to reuse the *exact
  same name and UID* xpf recorded, xpf treats it as the original managed
  account and may lock it. Re-add `encrypted-password` to restore.

A transient `/etc/shadow` read error never causes a lock (the lock
decision fails closed on a read error), so a read hiccup can never lock
out an operator.

## Root credentials are revoked on removal (#5276)

`system root-authentication` (`encrypted-password` + `ssh-*` keys) gets
the **same** declarative revocation the per-user path has. Before #5276
`applyRootAuth` was **write-only**: it returned immediately when the
stanza was nil and had only positive branches for a nonempty password or
key list. Removing the stanza (or emptying a leaf) left the prior
`/etc/shadow` root hash and `/root/.ssh/authorized_keys` **live**, so
offboarding/rotation/compromise never revoked root access despite a
green commit — while non-root users already locked a removed password
and removed the last managed key.

`applyRootAuth` (`pkg/daemon/daemon_system.go`) now reconciles root
against the current config on every apply, reusing the per-user
machinery keyed on the account name `root` / **UID 0**:

- **Password** — delegated to `reconcileUserPassword` with a synthetic
  `root` login user. A configured `encrypted-password` is applied via
  `chpasswd -e` (with the same apply-boundary `ValidateCryptHash`
  re-check) and records the provenance marker; an **absent** password
  (stanza removed OR the `encrypted-password` leaf emptied) **LOCKS** the
  root shadow field (`root:!`) — but **only** when xpf itself provisioned
  root's credentials (marker present) and the field is not already
  locked, and **never** on a shadow read error.
- **Keys** — a configured key list is written wholesale to
  `/root/.ssh/authorized_keys` and records the provenance marker; an
  **empty** key list (stanza removed OR the `ssh-*` leaf emptied)
  **REMOVES** the xpf-managed `authorized_keys` — but **only** when the
  provenance marker is present, so an **operator-installed** key file xpf
  never wrote is left untouched (provenance-scoped removal, never a
  hand-placed key).

Provenance uses the **same resource-specific** UID-keyed markers as the
per-user path, with UID 0 (#5841): a root **password** marker
(`passwordProvisioned("root", 0)`) gates the password lock, a root **key**
marker (`keyProvisioned("root", 0)`) gates the key removal, and the account
**registry** entry (`markProvisioned("root", 0)`) keeps root enumerated by the
factory-reset teardown. A **keys-only** `root-authentication` (no
`encrypted-password`) writes only the key + registry markers, so it is
revocable **and** can never lock an out-of-band root password. The non-root
`reconcileAbsentLoginUsers` / `applySystemLogin` loops still **skip** `root`
entirely — root is
governed solely by this dedicated `applyRootAuth` path.

**Safety.** The marker gate is the fresh-boot lifeline: an appliance that
**never** configured `root-authentication` has no marker, so root is
**never** locked and console/recovery access is preserved — the same
`_never revoke what xpf did not provision_` invariant the per-user path
enforces. On typical images root's shadow field is already `!`
(distro-locked), so `isLockedShadow` makes the lock a no-op there.
Re-adding `root-authentication` restores the password/keys. Since #5841 the
prior residual edge is closed: a **keys-only** root-authentication writes no
password marker, so removing it revokes only the keys and **never** locks an
out-of-band root password xpf did not set (the password lock is gated on the
password marker, not the account/key marker).

**Idempotent.** Re-applying with the stanza still absent re-locks nothing
(the shadow field is already `!` → `pwNoop`) and removes nothing (the key
file is already gone → `os.Remove` `NotExist` no-op).

## Resource-specific, atomic credential ownership (#5841)

Before #5841 a **single** per-account provenance marker
(`/var/lib/xpf/provisioned-users/<name>`) carried the whole ownership
contract, which was wrong in two security-relevant ways:

- **Coarse (overclaim).** The one marker was treated as proof that xpf
  owned **both** the password and the SSH key. So if xpf provisioned only
  a user's **password** (marker present) while the operator kept their own
  `authorized_keys`, emptying that user's key list — or removing the user —
  let the emptied-key / deprovision reconcilers **delete an operator key
  file xpf never wrote**. For `root`, a keys-only `root-authentication`
  could likewise lock an out-of-band root **password**.
- **Best-effort (underclaim).** The marker was written **after** a
  successful credential mutation, and a marker-write failure was **logged
  and swallowed**. That left a live credential xpf had set but could no
  longer identify — so a later directive removal could **not** lock/clean
  it, and it survived a factory reset un-rediscoverable.

Ownership is now tracked **per resource**, in sibling marker roots that use
the **same UID-file format** as the account registry:

| Root | Meaning | Gates |
|---|---|---|
| `/var/lib/xpf/provisioned-users/<name>` | account/enumeration **registry** — which accounts xpf manages | `reconcileAbsentLoginUsers` + factory-reset teardown enumeration |
| `/var/lib/xpf/provisioned-passwords/<name>` | xpf set the `/etc/shadow` **password** | the declarative D2 password **lock** (`passwordProvisioned`) |
| `/var/lib/xpf/provisioned-keys/<name>` | xpf wrote the **`authorized_keys`** | the key-file **removal** (`keyProvisioned`) |

- **Resource-specific revocation.** The password lock consults **only** the
  password marker; the key removal consults **only** the key marker. Setting
  a password never claims the key file, so an operator-installed
  `authorized_keys` is left untouched. This holds for `root` too — a
  keys-only stanza writes only the key (and registry) marker, never the
  password marker, so it can never lock an out-of-band root password.
- **Marker-first atomicity (fail-visible).** Each resource marker is written
  **before** its credential mutation. If the durable marker cannot be
  written, the mutation is **skipped** (logged, retried next apply) rather
  than performed and swallowed — so xpf never leaves a mutated-but-unmarked
  credential. Because the applies are idempotent (`chpasswd` reads
  `/etc/shadow`; the key write compares content), a transient marker failure
  simply defers to the next commit.
- **…and the claim is WITHDRAWN when the mutation fails (#6797).** Marker-first
  alone has the mirror hazard: if the mutation then fails, the marker outlives
  it and asserts ownership of a credential xpf never wrote. That matters more
  than it sounds, because the markers gate a **revocation**, not a write — the
  key marker gates `os.Remove(authorized_keys)`, the password marker gates the
  D2 lock. A stale claim therefore does not lose something of ours; it **deletes
  an operator's pre-existing key file**, or **locks an account whose password
  xpf never set**.

  Reversing the order would only trade overclaim for underclaim, so the apply
  path claims ownership through `claimOwnership` / `rollback`
  (`login_password.go`): the claim records whether the marker **already** named
  this exact account, and on mutation failure it withdraws the marker only if
  **this pass created it**. A claim an earlier apply legitimately made is
  preserved — withdrawing that one would orphan a credential xpf really owns.
  Applied at all three marker-first sites: the user key write, the user password
  `chpasswd`, and the root key write. The `useradd` path is unaffected — it is
  marker-**after** by construction (xpf genuinely created the account).
- **Union enumeration.** `reconcileAbsentLoginUsers` deprovisions the
  **union** of all three roots (`provisionedNames`), so a pre-existing
  account xpf only added an SSH key to (key marker, no registry entry) is
  still revoked when removed from config — while its password (which xpf
  never set) is left alone.
- **Registry format unchanged.** The account registry
  (`/var/lib/xpf/provisioned-users`) keeps its exact location and UID-file
  format, so the factory-reset teardown (`pkg/grpcapi` `zeroize`, #4598/#5520)
  that enumerates it and `userdel`s xpf-provisioned accounts is untouched.
- **Marker override seam.** The two resource roots are computed as siblings
  of `provisionedUsersDir`, so pointing that one package var at a throwaway
  tree relocates all three roots together in tests.

## A failed credential reconcile FAILS THE COMMIT (#6790)

Every reconciler on this page runs from the apply tail
(`applyTailReconciles`, `pkg/daemon/daemon_apply_tail.go`, steps 11–13):

| step | reconciler | owns |
|------|------------|------|
| 11   | `applySystemLogin`         | OS accounts, per-user password, `authorized_keys` |
| 11b  | `reconcileSudoers`         | `/etc/sudoers.d/xpf-<user>` NOPASSWD grants |
| 11c  | `reconcileAbsentLoginUsers`| revocation for users removed from config |
| 12   | `applySSHConfig`           | the sshd drop-in (`PermitRootLogin`, ciphers, …) |
| 13   | `applyRootAuth`            | root's `/etc/shadow` password + `/root/.ssh/authorized_keys` |

All five were called as `_ = d.<reconciler>(cfg)`. #5874 had already made
them **return** their accumulated failures, but only the daemon-stop
cancel closeout (`applyHostAuthorizationCloseout`) collected those
returns. On the ordinary commit path the returns were **discarded**, so
a commit reported **success** while:

- the configured operator's account was never created, or their
  `authorized_keys` was never installed;
- a super-user's sudo grant was never written — or, on the revoke side,
  a **demoted** operator's stale NOPASSWD grant was never removed;
- a **removed** `system login user` kept a live password and
  `authorized_keys` (the deprovision fails closed and retains its
  markers to retry, but nothing told the operator the revocation had not
  happened);
- the sshd drop-in failed validation and was reverted, so sshd kept the
  **pre-commit** `PermitRootLogin` posture;
- root's password or `authorized_keys` did not converge to the committed
  `system root-authentication`.

Since #6790 the tail **captures** all five returns and joins them into
the commit result, exactly as its siblings in the same function already
do — `applyLo0Filter` (#3392), `applyHostInboundFilter` (#3333) and
`reconcileDNSLocked` (#6792). The prior justification, "the next boot
re-renders these from the active config so a transient failure
converges" (the #2926 next-boot contract), does not hold here:

- These are **revocations**, not renderings. The credential stays live
  until the next reboot — unbounded on an appliance — and there is no
  dirty-retry owner, ticker, or metric between now and then.
- The same commit **advances the durable config**, so the next boot
  renders from a config that already says the user is gone while the box
  still grants them access.
- A green commit is the operator's only signal that
  `delete system login user bob` took effect, and it was unconditional.

Fail-closed, **not** fail-fast: every step still runs, so an sshd reload
failure never skips root-auth reconciliation. Only the commit *result*
changes. The config itself is already promoted at this point (as with
every other tail failure), so the operator sees a failed commit against
an advanced config and re-commits to retry — the same semantics
`networkd`/`nft`/DNS failures have had for several releases.

The void-returning steps around them (`applySystemNTP`, `applyHostname`,
`applySyslogFiles`, …) are deliberately **not** included: those really do
re-render from the active config on the next apply or boot and carry no
revocation semantics.

Cells: `pkg/daemon/apply_credential_failclosed_6790_test.go` drives the
real `applyTailReconciles` with one owner injected to fail per cell, plus
a healthy control and a both-ends cell proving an early failure does not
skip a later owner.

### What a credential failure does to each apply caller (#1960 no-brick)

`applyTailReconciles`' return reaches `applyConfigLocked`, which has five
call sites. Two of them CLASSIFY the error rather than just reporting it,
so the question that matters is whether a credential failure can make a
node reject a config:

| call site | what a non-nil return does now | config promoted? |
|---|---|---|
| `daemon_apply.go:182` `applyActiveConfigResult` | the feed manager (#5646) does not advance its published-hash, so the next identical refetch retries | yes — unchanged |
| `daemon_apply.go:191` `applyConfigUnderSem` (boot / DHCP callback / feed / config-poll / rollback) | `slog.Warn` + return; `MarkActiveApplied()` is SKIPPED | yes — unchanged |
| `daemon_apply_commit.go:254` `applyAndSyncCommitted` (operator commit) | the operator's commit reports failure; the peer push still happens; `MarkActiveApplied()` skipped | yes — `Store.Commit` promoted it upstream |
| `daemon_apply_commit.go:522` `syncAndApply` (**peer-sync recv**) | the error is returned to `handleConfigSync`, which logs it and returns it so the config high-water does NOT advance and the primary re-pushes | yes — `SyncApply` promoted it BEFORE the apply |
| `daemon_apply_commit.go:766` commit-confirmed auto-rollback | `slog.Error` only (background timer, no return path); the rollback target is applied unconditionally | yes — `PromoteRollback` already ran |

The peer-sync path is `syncAndApply`, and it does **not** reject. Both it
and `applyAndSyncCommitted` route the error through
`applyErrSkipsPeerSync`, which names exactly two fatal classes — a
required-protocol-gate error (dataplane DISARMED, #2138) and a context
CANCELLATION (the #2926 daemon-stop abort). Cancellation only: #7618 removed
`context.DeadlineExceeded` from that set, because the apply context is
cancel-only and a deadline there could only ever be a per-command budget. Everything else is the
non-fatal best-effort class that **must** keep syncing, because the config
is already committed + active and the dataplane armed; suppressing the
sync there is the divergence #4034 fixed. In `syncAndApply` the same
classifier decides whether to DISCARD the peer-promoted config, and on the
non-fatal branch it sets `armedActive = true` and returns the error
alongside the live config.

So a credential reconcile failure on a standby:

- does **not** roll back or reject the peer-synced config — it stays
  active and armed;
- does **not** suppress the primary→standby push on the commit side;
- **does** leave the applied-digest unstamped, so the primary's next
  re-push re-enters `syncAndApply` and RETRIES instead of taking
  `handleConfigSync`'s converged shortcut (#4957/#6296).

That is a retry, not a brick, and it is the same behaviour
`networkdErr`, `dhcpServerErr`, `hostInboundErr`, `lo0Err` and `dnsErr`
have had in this join since #3333/#3392/#4034/#6792 — the #4034 and #5564
comments name "host-inbound/lo0 nft, networkd" as precisely this class.

No `lenient*` compile opt is needed or possible: `pkg/config/compiler_opts.go`
"carries per-call compilation policy", and every flag in it downgrades the
severity of a COMPILE-time validator. These are RECONCILE-time failures
raised after compilation, inside `applyConfigLocked`; there is no compile
gate to downgrade, and the tolerant path already does not reject.

`TestCredentialFailuresDoNotSkipThePeerSync6790` pins all five owners
against the REAL errors the reconcilers produce, and
`TestApplyErrSkipsPeerSyncStillCatchesTheFatalClasses6790` is its paired
positive control so the classifier cannot degrade to "nothing is fatal".

#### The command-deadline gap, closed in #7618

`exec.CommandContext` has **two** error shapes at a deadline, and they used to
be classified differently for no good reason:

- the process **started** and was killed at the deadline → `*exec.ExitError`
  ("signal: killed"), which is not a context error → always correctly
  non-fatal;
- the context expired **before fork/exec completed** → `Start` returns
  `ctx.Err()`, so the caller gets a **bare `context.DeadlineExceeded`** →
  which `applyErrSkipsPeerSync` classified FATAL, suppressing the push (or
  discarding a peer-promoted config).

Which shape you get depends on whether fork/exec wins the race with the
deadline — i.e. on machine load. This was observed for real: the cell that
originally drove a live command against a short deadline passed unloaded and
failed under a loaded full-package run.

**#7618 removed `context.DeadlineExceeded` from the fatal set**, so both shapes
are now non-fatal and the standby still receives the config. The clause had no
true positive: the apply context is cancel-only end to end (`cmd/xpfd/main.go`
passes `context.Background()`, `Run` wraps it in `signal.NotifyContext`, and
`daemon_run.go` derives `applyCancelContext` with `context.WithCancel`), and
both callers reach the pipeline as
`applyConfigLocked(d.applyCancelCtx(), ...)`, so a #2926 abort always arrives
as `context.Canceled`. `TestApplyCancelContextIsCancelOnly7618` binds that
premise, so giving the chain a deadline reds a named cell rather than silently
re-opening the gap.

The exposure while it was open was bounded rather than permanent: the skip path
never claims the #5863 (epoch × generation) marker, so the 30s
`configSyncReconcileLoop` re-pushes, and a discarded peer config drives the
#7328 nack/re-arm. Still a window in which a failover served stale config for a
reason unrelated to the config.

The gap is **not** specific to the credential reconcilers. Every apply-path
command runner builds its own short context — `nftApplyPayload` (5s,
feeding `lo0Err`/`hostInboundErr` since #3392/#3333) and `daemon_dns.go`'s
`systemctl disable/mask` (feeding `dnsErr` since #6792) — so the same
misclassification already reaches the same classifier through operands that
predate #6790. #6790 adds members to an already-exposed population rather
than creating the exposure, and fixing the classifier changes behaviour for
those older operands, so it is tracked separately as #7618.

Until then it is a tripwire, not folklore:
`TestACommandDeadlineIsMisclassifiedAsADaemonStopAbort6790` asserts the
CURRENT (wrong) classification, so the fix reds a named cell and must
invert it and this section together.

## Unreadable ownership inventories are not empty ones (#6798)

Every ownership read above answers one question — *did xpf provision this?* —
and until #6798 it answered with a value that could not distinguish **"no"**
from **"could not tell"**:

| Read | Absent (a determination) | Unreadable (proves nothing) | Collapsed to |
|---|---|---|---|
| `os.ReadFile(<marker>)` | `ENOENT` — not ours | `EACCES` / `EIO` / `EISDIR` | `false` |
| `os.ReadDir(<marker root>)` | `ENOENT` — nothing provisioned | `EACCES` / `ENOTDIR` | no names |
| `os.ReadDir(/etc/sudoers.d)` | `ENOENT` — no grants exist | `EACCES` / `ENOTDIR` | `entries, _ :=` |

Because both spellings arrived as the same value, every revocation gate read
"could not tell" as **"not ours, skip"** and then returned `nil` — reporting
**convergence**. A removed administrator kept their password, `authorized_keys`,
and passwordless sudo grant while the apply reported success, and the #5874
cancellation closeout (which exists to observe exactly this
monotonic-revocation gap) saw nothing to report. `reconcileAbsentLoginUsers`
made it worst: an entirely unreadable inventory yields **no names**, which its
`len(names) == 0` early return treated as *"nothing was ever provisioned"* —
indistinguishable from a fresh install.

The governing invariant is now: **only proven absence may release ownership
work.** Unknown ownership retains the debt and never converges.

- **`readProvenanceMarker` returns `(bool, error)`.** Only `ENOENT` is absence
  (`false, nil`); every other read error is returned. A UID mismatch or a
  corrupt marker stays a *determination* (`false, nil`) — the bytes were read,
  they simply are not this account's — and is still cleaned inline. There is
  deliberately **no** bool-only wrapper: one would reintroduce the collapse.
- **Report, but never revoke.** On an unreadable marker each gate keeps
  ownership `false` and **skips the revocation**, then returns the error.
  Revoking on an unproven claim is #6797's overclaim from the other side, and
  for `root`'s `authorized_keys` it is a total lockout. So the gates are
  fail-closed in **both** directions: the credential is untouched *and* the
  apply does not converge. Applied at `applySystemLogin`'s emptied-key branch,
  `reconcileUserPassword`'s `pwLock` branch, `applyRootAuth`'s revoke arm, and
  `deprovisionLoginUser`.
- **`provisionedNames` returns `(names, error)` and keeps sweeping.** An
  unreadable root is reported, but the roots that *did* read still contribute
  their names — revoking what we can see is strictly better than revoking
  nothing, and the returned error carries the debt.
  `reconcileAbsentLoginUsers` joins it into its accumulated error instead of
  returning `nil` on the empty set.
- **`reconcileSudoers` reports its `ReadDir` failure.** An absent
  `/etc/sudoers.d` stays a clean `nil` (no drop-in can exist in a directory
  that does not), but an unreadable one is accumulated — otherwise the
  revocation sweep iterates nothing and a demoted admin keeps passwordless
  root.
- **`claimOwnership` treats an unreadable marker as PRE-EXISTING.** `preExisting`
  gates only `rollback()`, which *removes* the marker — i.e. it releases
  ownership. Unable to prove xpf did not already own the credential, it must not
  withdraw: dropping a genuine claim orphans a live credential xpf can then
  never lock or revoke (the #5841 underclaim). The cost of erring this way is
  at most a stale marker, which the next apply reconciles.
- **Retry debt is retained.** Markers are never dropped on an unreadable read.
  Dropping one would be permanent abandonment: once the root is readable again
  the account is no longer enumerated, so its credentials stay live forever.
  This is the same three-state discipline #5493 applied to an unreadable
  `/etc/passwd` — *unknown → retry*, never *absent → abandon*.

### Where the operator sees it

The four reconcilers that report an unreadable inventory (`applySystemLogin`,
`reconcileSudoers`, `reconcileAbsentLoginUsers`, `applyRootAuth`) are reached
from **two** callers, and since #6790 *both* of them surface the failure:

- **The normal apply tail** (`applyTailReconciles`, steps 11–13) **captures**
  these returns and joins them into the commit result — see "A failed
  credential reconcile FAILS THE COMMIT (#6790)" above. Before #6790 they were
  discarded (`_ = d.reconcileSudoers(cfg)`) on the #2926 next-boot-convergence
  argument, so a commit over an unreadable inventory reported success. It now
  fails, naming the account and the unreadable path.
- **The #5874/M35 daemon-stop cancel closeout** (`hostAuthCloseoutOwners`)
  collects them too, and that is the case where next-boot convergence does
  *not* happen — the daemon is stopping and staying stopped.
  `summarizeHostAuthCloseout` names the owning reconciler, so a cancel that
  previously reported **clean** over an unreadable inventory now fails visibly
  with e.g. `host-auth closeout owner "absent-login-users": read ownership
  inventory /var/lib/xpf/provisioned-keys: ... not a directory`.

That second path is the invariant R58 names — *unknown ownership inventory
state must retain debt and prevent a successful closeout* — and it is bound by
`TestHostAuthCloseoutSurfacesUnreadableInventory_6798`.

### Why this does not brick a tolerant load or peer sync (#1960)

#6798 adds no commit-time gate of its own; what makes its errors commit-failing
is #6790's capture above. The no-brick guarantee therefore rests on the **shape
of the rejection set**, not on any caller discarding a return:
`applyErrSkipsPeerSync` (`pkg/daemon/daemon_apply_commit.go`) closes that set
over exactly two fatal classes — a required-protocol-gate error
(`compileErrorMustAbortApply`, which leaves the dataplane **disarmed**) and a
context CANCELLATION from a daemon-stop abort (#7618: cancellation only; a
deadline is a per-command budget and still syncs). Every *other* error
still syncs, "because the config is committed + active and the dataplane
armed". An inventory-read failure is neither class, so on the peer-sync receive
path (`syncAndApply`) the config stays **active and armed** and the failure is
surfaced rather than swallowed. No `lenient*` option in
`pkg/config/compiler_opts.go` is owed.

One caveat, and it must not be dropped when this paragraph is quoted: the
"neither class" statement holds for these errors' **ordinary failure shapes**,
not unconditionally. #7618 records that `exec.CommandContext` has **two**
deadline shapes — if the context expires *before* fork/exec, `Start` returns a
**bare `context.DeadlineExceeded`**, which `applyErrSkipsPeerSync` cannot
distinguish from a #2926 daemon-stop abort and therefore classes FATAL, taking
`syncAndApply`'s `return nil, applyErr` arm with `armedActive` false.

That shape is **pre-existing and wider than #6798**: `runCommandStdinTimeout`
(`pkg/daemon/exec_timeout.go`) builds a fresh `context.WithTimeout(
context.Background(), externalCommandTimeout)` on the line immediately before
`exec.CommandContext`, so reaching the bare-`ctx.Err()` arm needs the goroutine
descheduled for the entire timeout between two adjacent statements — reachable
in a loaded test with a short injected deadline, not in production at 15s. The
same exposure already reaches the same classifier through `nftApplyPayload`
(5s) and the DNS `systemctl` calls, which predate both #6790 and #6798. It is
tripwired by `TestACommandDeadlineIsMisclassifiedAsADaemonStopAbort6790`, which
asserts the CURRENT (wrong) classification so the fix must invert the test and
that section together.

What #6798 **adds** does not reach it at all: these errors originate in
`os.ReadFile` / `os.ReadDir` and carry `EACCES`/`EIO`/`EISDIR`/`ENOTDIR`, never
a `context.DeadlineExceeded`. The credential reconcilers' *command* failures
(`chpasswd`) were already in that population before #6798 — this change neither
widens nor narrows it.

There is **no `show` surface** that renders credential-ownership state, so the
#6534 "a fail-closed exclusion owes a show-surface annotation" rule does not
apply here: nothing in `show` claims these credentials are revoked, and this
change makes a previously *silent* failure *visible* rather than dropping an
object the operator can still see rendered as enforced.

## Idempotency

The password apply reads `/etc/shadow` directly and skips `chpasswd`
when the on-disk hash already equals the configured hash, so an
unchanged re-commit does not churn the account. It fails **open** toward
applying (any read error / missing entry / mismatch → apply), so a first
commit never silently skips the password.

## #1916 interaction (file-atomic writes)

The password path is a `chpasswd` **process** invocation (which performs
its own `lckpwdf`-protected shadow update), not a direct file write, so
the #1916 fsatomic file-write wrapper does not apply to it.

The sudoers drop-in (now written by `reconcileSudoers`, #3889) and the
`authorized_keys` write in `applySystemLogin` ARE direct file writes and
were migrated to **DurableState** in #1916
(`fsatomic.WriteFileDurable`): a torn sudoers file is a management-access
hazard, and SSH keys must survive a power cut. The
`authorized_keys` writes additionally use `fsatomic.WithOwner(uid, gid)`
(owner resolved cgo-free via `lookupUIDGID`) so the file is installed
already-correctly-owned — a plain durable write would replace the inode
with a root-owned temp, and a crash before the post-rename `chown` would
leave root-owned `0600` keys that sshd refuses (EACCES → lockout). If the
owner cannot be resolved the write is SKIPPED (retried next apply) rather
than degrading to that unsafe root-owned path. The enclosing `.ssh`
directory is created with `fsatomic.MkdirAllDurable` so the directory
entry itself also survives a power cut. All three provenance markers — the
account registry and the #5841 password/key resource markers — are likewise
DurableState (`writeProvenanceMarker`), and each is written **before** its
credential mutation (marker-first) so a marker-write failure skips the
mutation rather than leaving it unmarked.
