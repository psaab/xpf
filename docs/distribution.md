# xpf signed, hosted distribution (#1924)

Signed appliance images + a signed apt repo + a one-command installer, so an
operator fetches and verifies from a trusted, signed source instead of copying
files by hand. Spec: `docs/research/1924-signed-hosted-dist/plan.md`. Tooling:
`scripts/dist/`.

This document is the contract for the distribution mechanism. It is complete
as a MECHANISM; two operator decisions (below) are supplied at release time as
config inputs and are NOT hardcoded.

## Trust model (read this first)

Two independent trust roots, by design:

| Artifact | Tool | Public key (pinned) | Consumer |
|---|---|---|---|
| Appliance image (qcow2 + incus metadata) + its `.manifest` / `.pkgs` sidecars, via `xpf-<ver>.SHA256SUMS` | **minisign** (Ed25519) | `scripts/dist/xpf-image.pub` (+ configured overlap keys) | `validate.py`, `xpf-deploy.py fetch`, `publish.py gate_provenance` + the operator |
| `install.sh` | **minisign** (Ed25519) | `scripts/dist/xpf-image.pub` (+ configured overlap keys) | `publish.py gate_images` + the operator (Tier B, before running it) |
| `latest.json` (per-channel pointer) | **minisign** (Ed25519) | `scripts/dist/xpf-image.pub` (+ configured overlap keys) | `xpf-deploy.py fetch` (the channel default, #6504), `publish.py gate_latest` + the operator |
| Apt repository (`Release`/`InRelease`) | **OpenPGP** | `scripts/dist/xpf-archive-keyring.asc` | `apt` itself |

minisign and OpenPGP are NOT redundant — they authenticate different artifacts
to different consumers. apt mandates OpenPGP for `Release`; the image consumers
are scripts we control, so they accept one or more explicitly pinned keys;
the trust set comes from the source repository, never from the image host.

**Root of trust for the image pubkey:** the in-repo checked-in copy obtained
via `git clone` / GitHub — **independent of any hosting URL**. The copy served
from the dist host is a convenience, never the root. To verify `install.sh`
before running it (Tier B), get the active image public-key set from the source repo, NOT from
`XPF_IMAGE_BASE_URL`.

## The two operator inputs (decide at release time)

1. **Hosting target.**
   - `XPF_IMAGE_BASE_URL` — serves the image artifacts, their `.minisig`
     signatures, `install.sh`, and `latest.json`. Any static HTTPS host works,
     **including GitHub Releases** (flat assets are fine for images).
   - `XPF_APT_BASE_URL` — serves the `dists/`+`pool/` apt tree. Requires a
     directory-serving host (static bucket / GitHub Pages / file server).
     **GitHub Releases CANNOT serve this** (flat assets only).
   - Plus the retention policy (keep last N versions per channel) and the
     channel layout (`stable`, `edge`).

2. **Signing identity.**
   - The minisign image keypair and the OpenPGP archive key: who holds the
     secret keys, the rotation cadence, and where the public keys are pinned.
   - `XPF_SIGN_SECKEY` is a PATH to the minisign secret key (never the bytes).
   - `XPF_GPG_KEY` is the OpenPGP key id/fingerprint that signs `Release`.

Until these are decided, `scripts/dist/*.placeholder` ship as placeholders
whose secret keys were shredded at generation (held by no one). With a
placeholder in place, verification FAILS — the correct fail-safe. See
`scripts/dist/README.md` for the go-live steps.

## Publisher runbook

```bash
# 1. Build a signed image; XPF_SIGN_SECKEY is the legacy/canonical signer.
# For overlap, add new keys with XPF_SIGN_SECKEYS via make dist-sign (see below).
XPF_SIGN_SECKEY=/secure/xpf-image.sec make image
#    -> dist/xpf-<ver>.qcow2, .incus-metadata.tar.gz,
#       .SHA256SUMS, .SHA256SUMS.minisig[.<key-id>], xpf-image.pub

# 2. Build the signed apt repo (flat default; reprepro opt-in).
XPF_GPG_KEY=<keyid> make dist-repo
#    or: XPF_APT_TOOL=reprepro XPF_GPG_KEY=<keyid> make dist-repo
# `make deb` names packages `0.0.N+g<sha>`; the flat builder accepts `+` in
# those package paths.

# 3. Write + sign the per-channel freshness pointer.
XPF_SIGN_SECKEY=/secure/xpf-image.sec \
  python3 scripts/dist/publish.py make-latest --channel stable --version <ver>

# 4. Stamp install.sh (SUBSTITUTE the real archive key + apt base URL +
#    default channel), THEN sign the STAMPED copy. Never sign the placeholder:
#    the publish gate refuses an installer that still carries the placeholder
#    key or an unsubstituted %%…%% marker, and REQUIRES install.sh be present
#    (the Tier-A one-liner URL 404s without it — pass --no-installer to opt
#    out). The stamp bakes the apt base URL so the piped one-liner needs no env.
XPF_APT_BASE_URL=https://dl.example.com/xpf/apt \
  python3 scripts/dist/publish.py stamp-installer \
    --out dist/install.sh --channel stable
#    (uses scripts/dist/xpf-archive-keyring.asc; --archive-key PATH to override)
minisign -S -s /secure/xpf-image.sec -m dist/install.sh \
         -x dist/install.sh.minisig

# 5. Fail-closed publish (refuses unsigned artifacts; uploads per URL).
XPF_IMAGE_BASE_URL=https://dl.example.com/xpf \
XPF_APT_BASE_URL=https://dl.example.com/xpf/apt \
XPF_PUBLISH_CMD=/path/to/publish-shim \
  make dist-publish
```

`XPF_PUBLISH_CMD` is a thin backend shim invoked exactly as
`$XPF_PUBLISH_CMD <local-dir> <dest-base-url>`, once per URL (image tree →
`XPF_IMAGE_BASE_URL`, apt tree → `XPF_APT_BASE_URL`). It must be idempotent and
exit non-zero on failure. Example shims: `rsync -a "$1/" "$2/"`,
`aws s3 sync "$1" "$2"`, a `gh release upload` wrapper. No backend is
hardcoded.

### Channel + retention

`stable` and `edge` are distinct apt suites and distinct `dist/<channel>/`
image pointers. Retention is a publisher policy (keep last N per channel);
per-version manifests mean retaining old versions never orphans their signed
checksums.

The apt pool is isolated PER SUITE (`pool/<suite>/<component>/x/xpf`, #4201):
each suite's `Packages` index is generated by scanning ONLY that suite's pool,
so a `stable` rebuild after an `edge` build never indexes the edge `.deb`. A
shared component-only pool would have let a signed edge build appear in
`stable`'s `Packages` (validly signed, so `publish.py gate_apt` passed) and a
`stable` subscriber's `apt upgrade` could then pull it — the stable/edge split
is the operator's only blast-radius control for the package path. The reprepro
publisher isolates suites in its own database and is unaffected. `selftest.sh`
(§5c) asserts the isolation.

The installer does not rely on APT's warning for a Release whose Suite differs
from the requested source suite. After `apt-get update`, it checks the xpf
source's signed index-target metadata and refuses to install unless both
`Suite` and `Codename` match the selected `stable` or `edge` channel. A valid
archive signature alone does not bind the host to the operator-selected
channel.

### Freshness / anti-rollback

- Apt `Release`/`InRelease` carries `Valid-Until` (default 1 year,
  `XPF_APT_VALID_DAYS`). A SHORT window with manual/air-gap signing would
  expire the repo between releases — keep it long for a manual cadence, or run
  an automated re-sign job.
- Images: `latest.json` (signed) names the current version per channel, and
  `xpf-deploy.py fetch` **consumes** it: with no `--version` it fetches
  `<channel>/latest.json`, minisign-verifies it against any configured image
  trust key, and then fetches + verifies exactly the version it names (#6504).
  Until then the pointer had no reader outside `publish.py`'s own gate, so a
  day-zero operator could not ask for "current stable" without already knowing
  a version string.

  The pointer is authenticated, not trusted: a verified signature says WHO
  wrote the bytes, so the version it yields still goes through the same
  filename-safety validation an operator's `--version` does, and a pointer
  whose `channel` field disagrees with the channel it was served from is
  refused (the same key signs every channel, so a mis-synced or swapped
  pointer verifies perfectly). The resolved version then feeds the existing
  anti-rollback watermark at `${XDG_STATE_HOME}/xpf/image-watermark.json`
  exactly as an explicit `--version` does.
- Each version's signed `xpf-<ver>.SHA256SUMS` covers the qcow2, the incus
  metadata, the `.manifest` provenance sidecar, AND the `xpf-<ver>.pkgs`
  image inventory (guest kernel + installed package versions, #6500), so
  the traceability record is authenticated by the same signature as the
  bytes it describes. `publish.py` refuses a release missing any of them.
  `xpf-deploy.py fetch` reads the sidecar's `validated` field from VERIFIED
  bytes before it downloads the image, and refuses `validated: false` (a
  `--skip-validate` bake) unless `--allow-unvalidated` is passed (#9325). A
  sidecar the signed sums list but the mirror withholds is refused regardless;
  a release whose signed sums list no sidecar at all predates it and gets a
  warning. `image-roll` applies the same rule to the manifest it verifies.
  `xpf-deploy.py fetch` records a best-effort monotonic version watermark at
  `${XDG_STATE_HOME:-~/.local/state}/xpf/image-watermark.json` (per
  `--channel`, default `stable`) and REFUSES a version older than the recorded
  one. `--allow-rollback` permits a deliberate version downgrade; it never
  bypasses freshness validation when the version comes from `latest.json`.
  The signed `latest.json` date is an independent freshness check: fetch and
  `publish.py` refuse a missing/invalid timestamp, one more than 90 days old,
  or one over five minutes in the future. `make-latest` verifies the prior
  signed pointer and refuses a version rollback or a non-advancing date
  (republishing the same version is allowed only with a newer date). Therefore
  an old, validly signed pointer replayed to a fresh workstation fails without
  a watermark. This bounds cross-host/time replay; it is not TUF-grade freeze
  protection, and a pointer within the 90-day window can still be replayed.
  Version ordering is FAIL-CLOSED (#8969): a version the comparator cannot
  order — a non-numeric release component such as `1.2.x`, or any spelling
  `validate_version` accepts but semver does not define — sorts BELOW the
  watermark and is refused. Debian's tilde pre-release (`1.2.3~rc1`) and
  git-describe's hyphen (`1.2.3-rc1`) are ordered identically, both BEFORE
  their base release. Semver build metadata is ignored for precedence
  (`1.0.0+build.7` ranks equal to `1.0.0`, per semver 11.4) — all three
  spellings are advertised as accepted by `validate_version`.
  The watermark check runs TWICE — once before the download and once after
  verification — and BOTH are refusals (#9238). The late one used to be only
  the condition for *writing* the watermark, so when it failed the fetch fell
  through and published anyway: two overlapping fetches could end with the
  watermark naming v2 and the image the alias actually resolves to being v1,
  with no forged signature and no `--allow-rollback` involved. It now aborts
  before the alias import / golden replacement, naming both versions. The late
  read, the comparison and the publish are also serialized by an exclusive
  flock on `<state>/xpf/.image-watermark.lock`, so a concurrent fetch cannot
  advance the watermark between the check and the publish; the lock is
  best-effort in the same sense as the golden lock, and its absence is
  reported rather than assumed.

### Key rotation

The archive keyring ships BOTH inline in `install.sh` (new installs) AND in the
`xpf` package payload at `/usr/share/keyrings/xpf-archive-keyring.asc` (via
`debian/rules`). During a dual-sign window, a normal `apt upgrade`
delivers the rotated key to EXISTING hosts before the old key retires.

Image-key rotation supports overlap instead of a flag day. Keep both the old
and new public keys in the source-repo trust set. Consumers accept any trusted
key from repeatable `--pubkey` options or `XPF_IMAGE_PUBKEYS` (an
`os.pathsep`-separated list); the singular `XPF_IMAGE_PUBKEY` remains valid.

Keep the OLD signing key first through the overlap: use it as
`XPF_SIGN_SECKEY` and list new keys in `XPF_SIGN_SECKEYS`, or put the old
key first in a repeated `--seckey` sequence. This preserves the legacy
`.minisig` signature for old-key-only checkouts. Each additional signature is
published as `.minisig.<minisign-key-id>` so new-key-only checkouts can find it.
Fetch consumers accept any one trusted signature; publish gates require valid
signatures from every configured key, including each `latest.json` pointer.

For example, keep the keys out of the repository and make an overlap release:

```bash
# Keep the old key canonical; add the new key for overlap sidecars.
XPF_SIGN_SECKEY=/secure/old.sec XPF_SIGN_SECKEYS=/secure/new.sec make dist-sign

# Sign a directly-signed file such as install.sh with both keys.
python3 scripts/dist/sign.py sign-file \
  --seckey /secure/old.sec --seckey /secure/new.sec dist/install.sh

# Sign the channel pointer with the same pair.
XPF_SIGN_SECKEY=/secure/old.sec XPF_SIGN_SECKEYS=/secure/new.sec \
  python3 scripts/dist/publish.py make-latest --channel stable \
  --version <ver> --dist dist

# Verify during overlap using source-repo public keys, never host-provided keys.
python3 scripts/dist/sign.py verify-file --pubkey scripts/dist/xpf-image.pub \
  --pubkey scripts/dist/xpf-image-next.pub --sig dist/install.sh.minisig \
  dist/install.sh
```

Set `XPF_IMAGE_PUBKEYS=/path/old.pub:/path/new.pub` on `publish.py` and
operators' fetch/image-roll commands during overlap, or repeat `--pubkey` on
those commands. Fetch consumers accept any one configured key; publish gates
require signatures from every configured key. After every operator checkout
trusts the new key, stop signing with the old key and remove it from the trust set.

`publish.py gate_apt` cross-checks that these three key sources AGREE by
fingerprint (#4203) — previously each was only checked for placeholder-ness
independently, so a stale `install.sh` embedding an old-but-real, retired key
published cleanly and bricked every new Tier-A install at `apt-get update`.
It verifies `InRelease` with the repo archive pubkey, then extracts
`/usr/share/keyrings/xpf-archive-keyring.asc` from each pooled `.deb`; that
payload keyring, not the repo-side file, is the key-agreement input (#10737).
The gate captures the InRelease signer's primary fingerprint and requires the
signer to be covered by each packaged keyring; when `install.sh` is in the
publish set, its embedded key must be a SUBSET of each packaged keyring (a
superset is allowed during dual-sign) and cover the signer (so a fresh install's
first `apt-get update`, before the packaged keyring lands, verifies the repo).
Any mismatch fails the publish. `selftest.sh` (§5d) exercises the gate.

## Operator runbook

### Install (Tier A — one-liner)

```bash
curl -fsSL https://dl.example.com/xpf/install.sh | sudo sh
```

`sudo` is required — the installer mutates the host (keyring, apt source, apt
install), so a non-root run refuses before touching anything. The apt base URL
+ default channel are BAKED into `install.sh` at publish time
(`publish.py stamp-installer`); a piped run needs no environment. Set
`XPF_APT_BASE_URL` only to override the baked value or when running an unbaked
copy.

Trust level: TLS + first-fetch trust of `install.sh` (the same level
Tailscale/Docker/rustup accept). `install.sh` first VALIDATES all inputs
(root, arch/distro/kernel — refuses kernel < 6.18, use the appliance image on
older hosts — the archive key, and the apt URL/channel) BEFORE any mutation,
then installs the pinned archive keyring, writes the deb822 apt source, and
`apt install xpf-appliance`. If the `apt` step fails it removes the apt source
it wrote, so a failed install never leaves a dangling repo that breaks
`apt update`.

### Install (Tier B — verify before run)

```bash
# Get the trusted image pubkeys from the SOURCE REPO, never the dist host.
git clone https://github.com/psaab/xpf
curl -fsSLO https://dl.example.com/xpf/install.sh
curl -fsSLO https://dl.example.com/xpf/install.sh.minisig
# During overlap, also fetch the key-addressed sidecar; replace <KEY-ID>
# with the final field from the new source-repo public-key comment:
# curl -fsSLO https://dl.example.com/xpf/install.sh.minisig.<KEY-ID>
# During overlap, also add --pubkey xpf/scripts/dist/xpf-image-next.pub; the
# verifier then locates and checks that key-addressed signature sidecar.
python3 xpf/scripts/dist/sign.py verify-file \
  --pubkey xpf/scripts/dist/xpf-image.pub --sig install.sh.minisig install.sh
# read install.sh, then (the fetched installer is baked — no env needed):
sudo sh install.sh
```

### Verify + import an image

```bash
# downloads + verifies the EXACT bytes against the signed manifest, then
# imports to a local incus alias
xpf-deploy.py fetch --version <ver> --image-url https://dl.example.com/xpf

# libvirt/KVM: verify the qcow2 AND install it to the golden path that
# `deploy --hypervisor libvirt` reads (/var/lib/libvirt/images/<image>.qcow2,
# basename from --alias, default xpf-appliance) so fetch and deploy connect:
xpf-deploy.py fetch --version <ver> --image-url ... --qcow2-only --install-libvirt
xpf-deploy.py --hypervisor libvirt deploy <appliance.yaml>

# Verify only (no install): fetch prints the command to stage the
# qcow2 privately, verify that staged copy against its signed digest,
# and install the same verified copy to the golden path.
xpf-deploy.py fetch --version <ver> --image-url ... --qcow2-only
```

**The digest that `--qcow2-only` / `--no-import` prints is the SIGNED one
(#9170).** These flags do not consume the image — they hand the operator a
command to run later. Since `--out` stays writable by local processes, the
command copies the qcow2 to a fresh private temporary directory, verifies that
staged copy against the signed digest, then installs that same staged file
(#10757). A swap before or during the copy is rejected by the staged check; a
swap after the copy cannot change the installed bytes. The digest comes from
the signed manifest entry that authorised the artifact
(`sign.verify_image_artifact` returns it), never from a re-hash of the public
`--out` file after verification. The in-process import paths use the same
private-staging principle (`_verified_private_artifacts`, #5817).

`deploy --hypervisor libvirt` never boots the golden directly — it creates a
per-VM copy-on-write overlay backed read-only by the golden. `--install-libvirt`
is the one step that moves the *verified* qcow2 to the shared golden path; both
sides derive that path from the same helper so they cannot drift.

**Golden immutability — re-fetch over an in-use golden is REFUSED (#5043).**
The golden is a *shared, read-only backing store*: each per-VM overlay is
`qemu-img create -b <golden>` and depends on the golden's bytes never changing.
Overwriting it in place while overlays back onto it shifts the backing bytes
under every live overlay and corrupts them — and because an HA pair usually
shares one golden, a single re-fetch would poison *both* nodes' disks. So
`fetch --install-libvirt` refuses to overwrite a golden that still has
dependent overlays (it scans `/var/lib/libvirt/images/*.qcow2` and checks each
one's `qemu-img info` backing file). First install (no golden yet) and a
re-fetch after the dependents are gone both proceed normally.

**Two holes in that guard, closed together (#6760 + #6761).** They are one code
path — the probe, the classifier, the replacement and the overlay creator — and
fixing either alone leaves it unsafe.

*An unprobeable sibling is not evidence of safety (#6760).* The backing probe
returned "no backing file" for four different outcomes: `qemu-img` absent,
`qemu-img` exited non-zero, unparseable JSON, and a genuine absence. The
classifier read that as *not a dependent overlay*, so a file the tool could not
read was assumed safe and the golden was overwritten under it. A running
domain's overlay is the realistic instance — `qemu-img` can fail on an image a
live VM holds open. The probe now distinguishes **indeterminate** from
**no-backing**, and an indeterminate sibling BLOCKS the install with its own
message (investigate the file) separate from a known dependant (destroy the VM).

*A `qemu-img` that cannot be run is indeterminate too (#9325).* An earlier
revision kept a missing `qemu-img` as determinate-none, on the argument that the
tool cannot have created an overlay without it. That argument is about the
invoking process's history, not about the sibling on disk: an overlay created
before `qemu-img` left `PATH` (a restricted unit `PATH`, sudo's `secure_path`, an
upgrade in flight), or by another tool, still backs onto the golden. Measured,
the change moves exactly one state:

| state | before | after |
|---|---|---|
| fresh host, no golden yet | proceed | proceed |
| golden present, no sibling `.qcow2` | proceed | proceed |
| golden present + a sibling overlay | proceed | **refused** |

*The replacement is atomic and locked (#6761).* It was an unlocked
check-then-in-place-copy, which fails two ways. An overlay created between the
check and the copy backs onto bytes that are about to be swapped and nothing
looks again (TOCTOU); and an **interrupted** in-place copy leaves a truncated
golden, corrupting every existing overlay with no concurrency involved at all.
The new image is now written to a sibling temp file -- an unpredictable name
created `O_EXCL` by `mkstemp` and written through its descriptor, so a planted
symlink cannot redirect it (#9325) -- and moved into place with an
atomic rename, so the golden is either wholly the old image or wholly the new
one — under an exclusive `flock` on `<images-dir>/.xpf-golden.lock` that
`libvirt_disk` takes as well. Both sides must hold the same lock: locking only
the replacement would close nothing. To roll a new
image onto hosts with live VMs, EITHER:

- destroy the dependent VM(s) first so no overlay references the old golden —
  `xpf-deploy.py --hypervisor libvirt destroy <appliance.yaml>` per VM — then
  re-run `fetch --install-libvirt`; OR
- install the new image under a *fresh tag* so existing overlays keep their
  immutable backing —
  `fetch --install-libvirt --alias xpf-<newver>` — and point the deploy YAML at
  `image: xpf-<newver>`. New VMs boot from the new golden; already-deployed VMs
  keep running on the old one until you redeploy them.

### CAUTION — interface takeover (#1879)

`xpfd` owns and renames every interface on the host. A bare-metal `apt install
xpf-appliance` on a remote box can cut your management path if the fxp0 mapping
is wrong. Seed a safe day-0 config (fxp0 = mgmt DHCP) before relying on remote
access, or use console.

### Upgrades

`apt upgrade xpf-appliance` triggers the #1917 postinst cut-over:
- **Standalone node:** a verified STOP→FLIP→START with a bounded, measured
  DATAPLANE blip (mgmt/SSH is not forward-switched). Use
  `XPF_NO_POSTINST_CUT=1 apt-get upgrade` to stage only and run `xpfd upgrade`
  at a chosen time.
- **HA node** (`/etc/xpf/node-id` present): stage only — `apt upgrade` does NOT
  cut. Cut with `xpfd upgrade --rolling` so the cluster keeps forwarding. Do
  not `apt upgrade` both nodes expecting auto-rolling.

This is #1917's existing, reviewed mechanism — #1924 does not change it.

## Self-test (no real key, no host)

```bash
make dist-selftest      # = scripts/dist/selftest.sh
```

Generates a throwaway keypair, signs, verifies, proves tamper-detection (4
ways), builds a flat signed apt repo + verifies `InRelease` (and that a
tampered `InRelease` fails), asserts per-suite channel isolation (§5c, a stable
rebuild after edge does not list edge), exercises the publish key-agreement gate
(§5d, rejects a non-signer `install.sh`, a signer absent from the packaged
keyring, and a stale-but-real pooled `.deb` keyring even while repo-side
verification uses the current key), checks that the kernel-promote `OnFailure=`
recovery unit ships in the `.deb` (§5e), and dry-runs `install.sh`. Exits
non-zero if any positive check fails or any tamper/negative check passes.
