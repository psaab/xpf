#!/usr/bin/env python3
"""xpf signed-distribution publish gate (#1924 §5.5).

Fail-CLOSED: refuses to publish (exits non-zero, uploads nothing) unless every
artifact in the publish set is properly signed:

  (a) each image manifest (xpf-<ver>.SHA256SUMS) has a verifying .minisig
      against the pinned image pubkey, AND the qcow2/metadata it lists are
      present and hash-match, AND its signed xpf-<ver>.manifest provenance
      sidecar says `validated: true` (#4904 A — a --skip-validate bake binds
      validated:false and is REFUSED: an unvalidated dev/emergency image must
      never carry a release signature past this fail-closed boundary);
  (b) the apt InRelease verifies against the archive pubkey (when an apt tree
      is being published);
  (c) install.sh is PRESENT (required by default — the Tier-A one-liner URL
      404s without it; opt out with --no-installer), carries NO placeholder
      key and NO unsubstituted %%…%% marker (it must be stamped first), and
      has a verifying install.sh.minisig;
  (d) the TARGET channel's latest.json verifies against the image pubkey AND
      names a version present in the image set, AND every OTHER channel's
      latest.json present in the tree also carries a verifying signature — the
      whole dist tree is uploaded, so a stale/unsigned pointer for a non-target
      channel must not ship unverified (HB165 H-13).

The bake may be fail-OPEN (a dev bake without a key still produces artifacts),
but PUBLISH is fail-CLOSED — an unsigned dev bake can never reach the channel.

To close a TOCTOU window (#4904 C), when an upload will actually happen the
whole tree is first copied into a PRIVATE immutable staging snapshot; the gate
hashes and the backend uploads the SAME snapshot bytes, so a concurrent writer
replacing an artifact/sidecar/install.sh after the gate cannot swap the
uploaded content.

After the gate passes, dispatch the operator's backend exactly once per URL:

  $XPF_PUBLISH_CMD <local-dir> <dest-base-url>     # idempotent, exit!=0 on fail

  image tree (dist/, sigs, install.sh, latest.json) -> XPF_IMAGE_BASE_URL
  apt tree    (dist/apt/dists + pool)               -> XPF_APT_BASE_URL

XPF_PUBLISH_CMD is a thin shim the operator supplies (rsync / aws s3 sync /
gh release upload wrapper). No backend is hardcoded.

The two operator decisions (hosting URLs, signing identity) are config inputs:
XPF_IMAGE_BASE_URL / XPF_APT_BASE_URL and the pinned pubkeys / signing keys.

Usage:
  publish.py --channel stable [--dist DIR] [--no-image] [--no-apt]
             [--no-installer] [--dry-run]
  publish.py make-latest --channel stable --version V [--dist DIR]   # sign latest.json
  publish.py stamp-installer --out dist/install.sh [--apt-base-url URL]
             [--channel stable] [--archive-key PATH]  # bake key+URL then sign
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import image_inventory  # noqa: E402  (#6500 inventory format)
import sign  # noqa: E402


def info(m):
    print(f"==> {m}")


def die(m):
    sys.exit(f"PUBLISH ERROR: {m}")


def image_pubkey():
    """Resolve the minisign IMAGE pubkey ONCE, honoring XPF_IMAGE_PUBKEY
    (Codex-r2-3). Fail-CLOSED on the placeholder (Codex-r2-2): the gate must
    never verify against a key whose secret is held by no one."""
    pub = os.environ.get("XPF_IMAGE_PUBKEY") or sign.DEFAULT_IMAGE_PUBKEY
    if sign.is_placeholder_pubkey(pub):
        die("image pubkey is the #1924 PLACEHOLDER — cannot verify image "
            "signatures. Supply the real key (XPF_IMAGE_PUBKEY / "
            "scripts/dist/xpf-image.pub) before publishing.")
    if not os.path.isfile(pub):
        die(f"image pubkey not found: {pub}")
    return pub


# Image artifact basenames we sweep for orphans (Codex-r2-1): any of these in
# `dist` that is NOT covered by a verified manifest blocks the publish, because
# the whole dist tree is uploaded.
IMAGE_ARTIFACT_SUFFIXES = (".qcow2", ".incus-metadata.tar.gz")


def _is_allowed_publish_file(name, at_top):
    """Default-deny allowlist for NON-image files in the image publish tree
    (HB165 H-5). The whole dist tree is uploaded RECURSIVELY, so a file that is
    neither a verified image artifact nor an expected sidecar must NOT ride
    along — an unsigned `dist/deb/*.deb` (or any stray file) is the motivating
    case: `make image` stages debs under the publish root and the suffix-shaped
    orphan sweep skipped every non-`.qcow2`/`.incus-metadata.tar.gz` file.

    Allowed (everything else is refused):
      - `*.minisig` / `*.SHA256SUMS` — inert signature + checksum material,
        anywhere in the tree;
      - top-level bake outputs: `install.sh` (its minisign signature is
        verified in gate_images), `xpf-image.pub` (the pinned pubkey convenience
        copy), `xpf-<ver>.manifest` (build metadata read by
        `xpf-deploy image-roll`), and `xpf-<ver>.pkgs` (the #6500 image
        inventory — guest kernel + installed package versions — covered by the
        signed SHA256SUMS and REQUIRED by gate_provenance);
      - a per-channel `latest.json` in a channel subdir — gate_latest verifies
        its signature.
    """
    if name.endswith((".minisig", ".SHA256SUMS")):
        return True
    if at_top:
        return (name in ("install.sh", "xpf-image.pub")
                or name.endswith((".manifest", ".pkgs")))
    return name == "latest.json"


def archive_pubkey():
    """Resolve the OpenPGP archive pubkey path (override or pinned, else
    placeholder). gpg verifies InRelease against an ephemeral keyring built
    from this file so we never depend on the publisher's global gpg keyring."""
    override = os.environ.get("XPF_ARCHIVE_PUBKEY")
    if override:
        return override
    real = os.path.join(HERE, "xpf-archive-keyring.asc")
    if os.path.isfile(real):
        return real
    return os.path.join(HERE, "xpf-archive-keyring.asc.placeholder")


def _is_placeholder(path):
    try:
        with open(path) as f:
            return "PLACEHOLDER-xpf-archive-keyring" in f.read()
    except OSError:
        return False


INSTALLSH_SRC = os.path.join(HERE, "install.sh")
PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)
MARKER_RE = re.compile(r"%%[A-Za-z0-9_]+%%")

# The apt base URL is baked LITERALLY into install.sh inside a single-quoted
# shell string (`XPF_APT_BASE_URL_BAKED='%%XPF_APT_BASE_URL%%'`) that is then
# SIGNED with minisign and piped to `sudo sh` on a fresh host (the Tier-A
# `curl … | sudo sh` one-liner). The value is a lower-trust config input
# (--apt-base-url / XPF_APT_BASE_URL) that crosses the signing trust boundary:
# a single quote breaks out of the literal and the tail becomes signed,
# root-executed shell — command injection / supply-chain root (#5685, M40). It
# also flows unquoted-in-a-heredoc into the deb822 `URIs:` line and into info()
# output. So validate it to a strict https URL with NO shell metacharacter,
# whitespace, control byte, or percent-escape BEFORE stamping, and fail CLOSED
# on any violation — the signature must never attest to an injected command.
#
# An apt base URL is a bare `dists/`+`pool/` directory host, so it needs only
# scheme + host[:port] + path; it never carries userinfo, a query, a fragment,
# or a percent-escape. The netloc/path allowlists MIRROR the validate_identifier
# / validate_version fail-closed idiom in scripts/deploy/xpf-deploy.py, widened
# to the small unreserved-URL charset (`._~-` plus `/` in the path and `:` for a
# port) — nothing in that charset can host a shell breakout.
_SAFE_APT_URL_NETLOC = re.compile(
    r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?\Z")
_SAFE_APT_URL_PATH = re.compile(r"(/[A-Za-z0-9._~-]*)*\Z")
# Characters that must never appear in the value: shell metacharacters, quoting
# characters, whitespace, and `%`/`=` (a `%%` pair would also defeat install.sh's
# unsubstituted-marker guard). Belt-and-suspenders alongside the structural
# allowlists below — this scan yields a precise "which byte" fail-closed message.
_APT_URL_FORBIDDEN = set("$\"'\\`;&|<>(){}[]*?!#@%=+, \t\r\n\v\f")


def validate_apt_url(value, field="apt base URL"):
    """Reject an apt base URL that could inject shell when baked into (and then
    SIGNED with) install.sh — the #5685 / M40 supply-chain sink.

    Fail-CLOSED (die()s, so the release aborts) unless `value` is a strict,
    well-formed https URL with NO shell metacharacter, whitespace, control byte,
    userinfo, query, fragment, or percent-escape. Returns the value on success.
    Mirrors the validate_identifier / validate_version discipline in
    scripts/deploy/xpf-deploy.py, with a URL-appropriate charset."""
    if not isinstance(value, str) or not value:
        die(f"{field} is required and must be a non-empty string")
    # 1. per-character denylist: no shell metacharacter / whitespace / control
    #    byte / percent-escape survives into the signed single-quoted literal.
    for ch in value:
        if ch in _APT_URL_FORBIDDEN or ord(ch) < 0x20 or ord(ch) == 0x7f:
            die(f"{field} {value!r} contains a forbidden character {ch!r} — it "
                "is baked into signed, root-executed shell (install.sh); reject "
                "anything that could break out of the shell string context "
                "(#5685).")
    # 2. structural allowlist: https scheme, a valid host[:port], an allowlisted
    #    path, and NO userinfo / query / fragment.
    from urllib.parse import urlsplit
    parts = urlsplit(value)
    if parts.scheme != "https":
        die(f"{field} {value!r} must use the https scheme (got "
            f"{parts.scheme or '<none>'!r}) — the installer bakes it into a "
            "signed root shell; only https is accepted (#5685).")
    if "@" in parts.netloc or not _SAFE_APT_URL_NETLOC.match(parts.netloc):
        die(f"{field} {value!r} has an invalid host — expected a bare "
            "host[:port] with no userinfo (#5685).")
    if parts.query or parts.fragment:
        die(f"{field} {value!r} must not carry a query or fragment — an apt "
            "base URL is a bare dists/+pool/ directory host (#5685).")
    if parts.path and not _SAFE_APT_URL_PATH.match(parts.path):
        die(f"{field} {value!r} has an invalid path — allow only "
            "'/'-separated [A-Za-z0-9._~-] components (#5685).")
    return value


def _installer_key_block(text):
    """Return install.sh's embedded ASCII-armored ARCHIVE_KEY block, or None.
    Isolating the block matters: the placeholder token also appears OUTSIDE the
    key (in the is_placeholder_key grep pattern), so a whole-file substring
    scan cannot tell a stamped installer from an unstamped one — the check must
    look at the key block alone."""
    m = PGP_BLOCK_RE.search(text)
    return m.group(0) if m else None


def _read_real_archive_key(path):
    """Return the ASCII-armored archive PUBLIC KEY block from `path`, refusing
    the placeholder. The stamp bakes this block into install.sh in place of the
    placeholder key so a fresh install can verify the apt repo."""
    if not os.path.isfile(path):
        die(f"archive key not found: {path} — commit the real "
            "scripts/dist/xpf-archive-keyring.asc (drop the .placeholder) or "
            "pass --archive-key <path> before stamping install.sh.")
    if _is_placeholder(path):
        die(f"archive key {path} is the #1924 PLACEHOLDER — refusing to stamp "
            "an installer that cannot verify the repo. Supply the real key.")
    with open(path) as f:
        text = f.read()
    m = PGP_BLOCK_RE.search(text)
    if not m:
        die(f"archive key {path} has no PGP PUBLIC KEY BLOCK — expected an "
            "ASCII-armored OpenPGP public key.")
    return m.group(0)


def stamp_installer(out, src=INSTALLSH_SRC, archive_key=None, apt_url=None,
                    channel="stable"):
    """Bake the real archive key + apt base URL + default channel into
    install.sh (H-2/H-14), producing the publishable installer at `out`. The
    piped Tier-A one-liner then needs no env. This is the substitute half of
    the substitute-THEN-sign flow: sign `out` with minisign afterwards. The
    output is asserted to carry no placeholder key and no unsubstituted %%…%%
    marker, so publish gate_images accepts it."""
    if not apt_url:
        die("apt base URL required — set XPF_APT_BASE_URL or pass "
            "--apt-base-url. It is baked into install.sh so the Tier-A "
            "one-liner needs no env.")
    # The apt URL crosses the signing trust boundary (it is baked into the
    # about-to-be-signed install.sh, run as root). Validate it BEFORE any
    # substitution so a malformed/injected value aborts the release (#5685).
    validate_apt_url(apt_url)
    if channel not in ("stable", "edge"):
        die(f"channel must be stable|edge (got {channel!r}).")
    if archive_key is None:
        archive_key = archive_pubkey()
    key_block = _read_real_archive_key(archive_key)

    if not os.path.isfile(src):
        die(f"installer source not found: {src}")
    with open(src) as f:
        text = f.read()
    src_block = _installer_key_block(text)
    if src_block is None:
        die(f"{src} has no PGP PUBLIC KEY BLOCK to substitute.")
    if "PLACEHOLDER-xpf-archive-keyring" not in src_block:
        die(f"{src} key block is not the placeholder (already stamped?) — "
            "refusing to re-stamp an installer of unclear key provenance.")
    for marker in ("%%XPF_APT_BASE_URL%%", "%%XPF_CHANNEL%%"):
        if marker not in text:
            die(f"{src} is missing the {marker} substitution marker — cannot "
                "bake the installer. Restore the marker.")

    # 1. swap the placeholder PGP block for the real armored key (once). A
    #    function replacement keeps backslashes in the key literal.
    text, n = PGP_BLOCK_RE.subn(lambda _m: key_block, text, count=1)
    if n != 1:
        die(f"{src} has no PGP PUBLIC KEY BLOCK to substitute.")
    # 2. bake the apt base URL + default channel (literal token replace).
    text = text.replace("%%XPF_APT_BASE_URL%%", apt_url)
    text = text.replace("%%XPF_CHANNEL%%", channel)

    # 3. fail-closed: assert NOTHING unsubstituted survived. Check the KEY
    #    BLOCK (not the whole file — the placeholder token also lives in the
    #    is_placeholder_key grep pattern, which correctly stays).
    out_block = _installer_key_block(text)
    if out_block is None or "PLACEHOLDER-xpf-archive-keyring" in out_block:
        die("internal: placeholder archive key survived stamping.")
    leftover = MARKER_RE.search(text)
    if leftover:
        die(f"internal: unsubstituted marker {leftover.group(0)} survived "
            "stamping — refusing to write a half-baked installer.")

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w") as f:
        f.write(text)
    os.chmod(out, 0o755)
    info(f"stamped installer -> {out} (apt={apt_url} channel={channel}; real "
         "archive key baked). Sign it next, then publish.")


def _primary_fprs_from_gpg_colons(colon_text):
    """Extract the set of PRIMARY key fingerprints from `gpg --with-colons`
    output. The `fpr:` line immediately following a `pub:` record is the
    primary key's fingerprint; `fpr:` lines after `sub:` records (subkeys) are
    ignored so we compare primary fingerprints consistently with the InRelease
    signer's primary fpr (the last VALIDSIG field)."""
    fprs = set()
    want = False
    for line in colon_text.splitlines():
        f = line.split(":")
        if not f:
            continue
        if f[0] == "pub":
            want = True
        elif f[0] == "sub":
            want = False
        elif f[0] == "fpr" and want:
            if len(f) > 9 and f[9]:
                fprs.add(f[9])
            want = False
    return fprs


def _key_fingerprints(key_source):
    """Return the set of PRIMARY key fingerprints in an armored key file by
    importing it into an ephemeral keyring (matching gate_apt's import style)
    so we never touch the publisher's global gpg keyring."""
    import tempfile
    with tempfile.TemporaryDirectory() as gnupghome:
        os.chmod(gnupghome, 0o700)
        env = dict(os.environ, GNUPGHOME=gnupghome)
        r = subprocess.run(["gpg", "--batch", "--import", key_source],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"could not import key {key_source} for fingerprint "
                f"cross-check: {r.stderr.strip()}")
        r = subprocess.run(
            ["gpg", "--batch", "--with-colons", "--fingerprint", "--list-keys"],
            env=env, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"could not list fingerprints for {key_source}: "
                f"{r.stderr.strip()}")
        return _primary_fprs_from_gpg_colons(r.stdout)


def _extract_installsh_key(installsh_path):
    """Return install.sh's embedded ASCII-armored OpenPGP key block (the exact
    bytes between the PGP BEGIN/END markers), or None if there is no block. The
    block sits in a single-quoted heredoc so it is literal armor with no shell
    interpolation."""
    try:
        with open(installsh_path) as f:
            text = f.read()
    except OSError:
        return None
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = "-----END PGP PUBLIC KEY BLOCK-----"
    i = text.find(begin)
    j = text.find(end)
    if i == -1 or j == -1 or j < i:
        return None
    return text[i:j + len(end)] + "\n"


def _gate_key_agreement(dist, signer_fprs, packaged_keyrings):
    """H-15: cross-check the installer's embedded key, the keyring in each
    pooled package payload, and the InRelease signer AGREE by fingerprint.
    The archive key file used to verify InRelease is only a publish-time input;
    it is not necessarily the keyring the package will install on hosts.

    Requires (fingerprints are PRIMARY key fprs):
      - the InRelease signer(s) S are covered by each packaged keyring K
        (existing hosts verify the repo on `apt upgrade`); and, when install.sh
        is in the publish set,
      - install.sh's embedded key set I is a SUBSET of each K (a keyring
        superset is allowed during a documented dual-sign window), and
      - the InRelease signer(s) S are covered by I so a fresh Tier-A install's
        `apt-get update` (which runs against install.sh's embedded key BEFORE
        the packaged keyring lands) verifies the published repo.
    """
    if not signer_fprs:
        die("could not determine the InRelease signer fingerprint — refusing "
            "to publish without confirming key agreement.")
    if not packaged_keyrings:
        die("no pooled package ships /usr/share/keyrings/"
            "xpf-archive-keyring.asc — cannot cross-check the InRelease "
            "signer against the keyring installed on hosts.")
    for package, keyring_fprs in packaged_keyrings:
        if not keyring_fprs:
            die(f"pooled package {package} keyring has no importable keys — "
                "cannot cross-check the InRelease signer.")
        if not signer_fprs <= keyring_fprs:
            die(f"InRelease signer {sorted(signer_fprs)} is NOT in the "
                f"packaged keyring from pooled package {package} "
                f"{sorted(keyring_fprs)} — the repo is signed by a key the "
                "shipped keyring does not carry; existing hosts would fail "
                "apt update. Ship the signing key in the keyring or re-sign "
                "the repo.")

    installsh = os.path.join(dist, "install.sh")
    if not os.path.isfile(installsh):
        info("key-agreement: install.sh not in publish set — "
             "installer cross-check skipped (signer vs packaged keyrings OK)")
        return
    armored = _extract_installsh_key(installsh)
    if armored is None:
        die("install.sh is in the publish set but has no embedded PGP key "
            "block to cross-check against the packaged keyring/InRelease signer.")
    if "PLACEHOLDER-xpf-archive-keyring" in armored:
        die("install.sh embeds the #1924 PLACEHOLDER archive key — cannot "
            "cross-check key agreement. Substitute the real key first.")
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".asc", delete=False) as tf:
        tf.write(armored)
        keypath = tf.name
    try:
        inst_fprs = _key_fingerprints(keypath)
    finally:
        os.unlink(keypath)
    if not inst_fprs:
        die("install.sh embedded key could not be parsed for fingerprints — "
            "refusing to publish without confirming key agreement.")
    for package, keyring_fprs in packaged_keyrings:
        if not inst_fprs <= keyring_fprs:
            die(f"install.sh embedded key {sorted(inst_fprs)} is NOT a subset "
                f"of the packaged keyring from pooled package {package} "
                f"{sorted(keyring_fprs)} — the installer trusts a key the "
                "shipped keyring lacks (stale installer or un-rotated "
                "keyring). Re-embed the current archive key in install.sh "
                "(a keyring superset is allowed during dual-sign).")
    if not signer_fprs <= inst_fprs:
        die(f"InRelease signer {sorted(signer_fprs)} is NOT covered by "
            f"install.sh's embedded key {sorted(inst_fprs)} — a fresh Tier-A "
            "install would fail `apt-get update` against the published repo "
            "(stale install.sh key). Re-embed the signing key in install.sh "
            "before publishing.")
    info(f"key-agreement OK (installer {sorted(inst_fprs)} subset of "
         f"packaged keyring; InRelease signer {sorted(signer_fprs)} covered "
         "by installer + packaged keyring)")


def list_versions(dist):
    """Discover baked versions from manifests in `dist`. FAIL-CLOSED
    (Codex-H1/AGY-A2): if ANY xpf-*.SHA256SUMS lacks a .minisig, refuse the
    whole publish — the upload step pushes the entire dist tree, so an
    unsigned dev bake sitting next to a signed one would otherwise be
    uploaded. Do not silently skip the unsigned one."""
    out = {}
    for m in sorted(glob.glob(os.path.join(dist, "xpf-*.SHA256SUMS"))):
        if not os.path.isfile(m + ".minisig"):
            die(f"unsigned manifest in the publish set: {os.path.basename(m)} "
                "has no .minisig. The whole dist tree is uploaded — refusing to "
                "publish an unsigned artifact. Sign it or remove it.")
        base = os.path.basename(m)
        ver = base[len("xpf-"):-len(".SHA256SUMS")]
        out[ver] = m
    return out


def gate_images(dist, require_installer=True):
    """(a)+(c): every signed image manifest verifies, covers EXACTLY the bake's
    four-file set (#9920: a manifest that merely OMITS qcow2/metadata used to
    sail through — listed-only checks plus a present-only orphan sweep), and the
    listed files hash-match; EVERY image artifact in dist is covered by a
    verified manifest (no orphans); install.sh is PRESENT (unless
    require_installer is False), has a verifying signature, is not the
    placeholder, and carries no unsubstituted %%…%% marker."""
    versions = list_versions(dist)
    if not versions:
        die(f"no signed image manifests (xpf-*.SHA256SUMS + .minisig) in {dist} "
            "— nothing publishable. Set XPF_SIGN_SECKEY and re-bake.")
    pub = image_pubkey()
    covered = set()
    for ver, manifest in sorted(versions.items()):
        sig = manifest + ".minisig"
        try:
            # Verify + parse from the VERIFIED bytes (Codex-L6 + AGY-r3-F3
            # TOCTOU): never parse a live manifest that could be swapped after
            # the signature check.
            checks = sign.verify_manifest_map(manifest, sig, pub)
        except sign.SignError as e:
            die(f"image manifest {os.path.basename(manifest)} failed verify: {e}")
        # #9920 F-063: the SIGNED SET must be exactly the bake's four-file set
        # (SSOT: sign.bake_set_basenames). verify_manifest_map authenticates
        # whatever the manifest lists, the loop below only checks listed files,
        # and the orphan sweep only fires for files PRESENT but uncovered — so
        # a genuinely-signed manifest that OMITS qcow2 (or the metadata
        # tarball) published a partial set. Membership is names, not bytes:
        # qcow2-only consumers still fetch + verify per-file downstream.
        expected = set(sign.bake_set_basenames(ver))
        if set(checks) != expected:
            missing = sorted(expected - set(checks))
            extra = sorted(set(checks) - expected)
            die(f"image set {ver} manifest {os.path.basename(manifest)} does "
                f"not cover the bake's four-file set (#9920): "
                f"missing={missing or 'none'} extra={extra or 'none'} — "
                "refusing to publish a partial set. Re-bake.")
        for base in checks:
            path = os.path.join(dist, base)
            if not os.path.isfile(path):
                die(f"manifest {os.path.basename(manifest)} lists {base} but it "
                    f"is absent from {dist} — refusing to publish a partial set.")
            try:
                sign.verify_image_artifact(path, manifest, sig, pub)
            except sign.SignError as e:
                die(f"image artifact {base} failed verify: {e}")
            covered.add(base)
        info(f"image set {ver}: signature + {len(checks)} file hashes OK")
    # Default-deny sweep (Codex-r2-1 / r3 + HB165 H-5): the WHOLE dist tree is
    # uploaded RECURSIVELY (rsync -a / aws s3 sync), so walk the tree — not just
    # the top level — and refuse EVERY file that is neither a verified image
    # artifact nor an expected sidecar (see _is_allowed_publish_file). A
    # suffix-shaped allowlist let unsigned non-image files (a dist/deb/*.deb)
    # ride to the image URL; default-deny closes that. The apt pool is gated
    # separately (gate_apt) so skip apt/.
    apt_dir = os.path.join(dist, "apt")
    for root, dirs, files in os.walk(dist):
        if root == apt_dir or root.startswith(apt_dir + os.sep):
            dirs[:] = []
            continue
        # Reject symlinks under the image publish root (Codex-r4): os.walk
        # does not follow dir symlinks, but a backend that dereferences them
        # (some sync tools) could upload nested unverified bytes the sweep
        # never saw. Refuse any symlink (dir or file) outside apt/.
        for d in list(dirs):
            if os.path.islink(os.path.join(root, d)):
                rel = os.path.relpath(os.path.join(root, d), dist)
                die(f"symlinked directory in the image publish set: {rel} — "
                    "refusing (a dereferencing backend could upload "
                    "unverified bytes).")
        at_top = os.path.abspath(root) == os.path.abspath(dist)
        for name in sorted(files):
            full = os.path.join(root, name)
            if os.path.islink(full):
                rel = os.path.relpath(full, dist)
                die(f"symlink in the image publish set: {rel} — refusing "
                    "(a dereferencing backend could upload unverified bytes).")
            rel = os.path.relpath(full, dist)
            if name.endswith(IMAGE_ARTIFACT_SUFFIXES):
                # Image artifacts live ONLY at the top level (the bake writes
                # dist/xpf-<ver>.*). A nested one (e.g. dist/stable/xpf-evil.qcow2)
                # can never be a verified artifact — a manifest binds BASENAMES,
                # so a nested duplicate basename would also escape a basename-only
                # `covered` check. Refuse any image artifact below the top level.
                if not at_top:
                    die(f"image artifact outside the top-level dist dir: {rel} — "
                        "images belong at dist/xpf-<ver>.*; refusing to publish "
                        "unverified nested bytes.")
                if name not in covered:
                    die(f"orphan image artifact in the publish set: {rel} is not "
                        "listed in any verified manifest — refusing to publish "
                        "unverified bytes. Remove it or sign a manifest covering "
                        "it.")
                continue
            # Default-deny (HB165 H-5): the whole dist tree is uploaded, so a
            # file that is neither a verified image artifact nor an expected
            # signed/metadata sidecar must NOT ride along. The motivating case
            # is an unsigned dist/deb/*.deb — the suffix-shaped sweep skipped
            # every non-image file, so a deb staged under the publish root
            # shipped to the image URL with no signature. Refuse anything
            # unrecognised.
            if not _is_allowed_publish_file(name, at_top):
                die(f"unexpected file in the image publish set: {rel} — the "
                    "whole dist tree is uploaded, so every file must be a "
                    "verified image artifact or an expected sidecar "
                    "(*.SHA256SUMS, *.minisig, install.sh, latest.json, "
                    "xpf-image.pub, xpf-<ver>.manifest). Refusing to publish "
                    "unverified bytes — build .deb packages OUTSIDE dist/ (see "
                    "DEB_OUT) and remove any stray file.")
    # (c) install.sh — PRESENT (mandatory unless --no-installer), stamped
    # (no placeholder key, no unsubstituted marker), AND signed. Presence is
    # mandatory by default because a missing installer makes the Tier-A
    # one-liner URL 404 (H-14): shipping no install.sh must not silently pass.
    installsh = os.path.join(dist, "install.sh")
    if not os.path.isfile(installsh):
        if require_installer:
            die("install.sh is MISSING from the image publish set — the Tier-A "
                "one-liner (curl … | sudo sh) URL would 404. Stamp + sign it "
                "(`publish.py stamp-installer --out dist/install.sh` then "
                "`minisign -S`), or pass --no-installer to publish images "
                "without the one-liner.")
        info("install.sh absent (--no-installer) — Tier-A one-liner unavailable")
        return versions, pub
    with open(installsh) as f:
        content = f.read()
    # Inspect the KEY BLOCK, not the whole file: the placeholder token also
    # appears in the is_placeholder_key grep pattern (which correctly stays in
    # a stamped installer), so a whole-file substring scan would reject even a
    # properly stamped install.sh.
    key_block = _installer_key_block(content)
    if key_block is None:
        die("install.sh in the publish set has no ASCII-armored archive key "
            "block — refusing to publish a malformed installer.")
    if "PLACEHOLDER-xpf-archive-keyring" in key_block:
        die("install.sh in the publish set still embeds the PLACEHOLDER "
            "archive key — refusing to publish an installer that cannot "
            "verify the repo. Stamp it first (`publish.py stamp-installer`).")
    # H-2: refuse an installer whose apt base URL / channel was never baked —
    # a piped `curl … | sudo sh` cannot deliver these via env, so an
    # unsubstituted marker means a 100%-failing one-liner. Mirror the
    # placeholder-KEY refusal above.
    for marker in ("%%XPF_APT_BASE_URL%%", "%%XPF_CHANNEL%%"):
        if marker in content:
            die(f"install.sh in the publish set still carries the unsubstituted "
                f"{marker} marker — the piped one-liner cannot receive it via "
                "env. Run `publish.py stamp-installer` to bake the apt base URL "
                "+ channel before signing/publishing.")
    isig = installsh + ".minisig"
    if not os.path.isfile(isig):
        die("install.sh is in the publish set but install.sh.minisig is "
            "missing — sign it before publishing.")
    try:
        sign.verify_signature(installsh, isig, pub)
        info("install.sh signature OK")
    except sign.SignError as e:
        die(f"install.sh signature failed verify: {e}")
    return versions, pub


def gate_provenance(dist, versions, pub):
    """#4904 A/B: refuse to publish an image set that did not pass the in-guest
    verify-dataplane validation gate OR whose Ubuntu base was not anchored to a
    reviewed trust-anchor digest.

    A --skip-validate bake still produces a fully signed manifest/signature set
    that is byte-shape-indistinguishable from a validated release, so the
    fail-closed publish gate would happily ship a dev/emergency image that never
    booted or verified the dataplane. bake.py now binds a signed `validated:
    true|false` provenance field into the xpf-<ver>.manifest sidecar (covered by
    the signed xpf-<ver>.SHA256SUMS, #5042); this gate REQUIRES validated: true.

    Symmetrically (#5815), an XPF_ALLOW_UNPINNED_BASE=1 dev bake signs
    `base_image_pinned: false` into that same sidecar — its own authenticated
    metadata says the Ubuntu base was NOT anchored to a reviewed digest (#4904
    B). This gate ALSO REQUIRES base_image_pinned: true, so a signed-but-unpinned
    image cannot be released via the normal path. There is deliberately no
    override — a signed unpinned image is not releasable.

    #6500 adds the third leg: the signed record must say what the image
    actually SHIPS. The manifest must carry `guest_kernel` (the kernel the
    IMAGE runs, not `bake_host_kernel`), and the version must carry an
    `xpf-<ver>.pkgs` inventory sidecar — covered by the same signed SHA256SUMS
    — that parses as a real inventory and agrees with the manifest about the
    kernel. A hollow inventory is refused, not accepted as best-effort.

    Fail-CLOSED: every version MUST carry a provenance sidecar that is (a) listed
    in — and hash-matches — the signed manifest, (b) says validated: true, AND
    (c) says base_image_pinned: true. A missing sidecar, an unsigned/mismatched
    sidecar, validated != true, or base_image_pinned != true all refuse the
    publish. A sidecar MISSING base_image_pinned (an old/tampered manifest that
    does not assert pinning) is also refused — a sidecar that does not assert
    pinning is not publishable."""
    for ver, sums in sorted(versions.items()):
        sig = sums + ".minisig"
        sidecar = os.path.join(dist, f"xpf-{ver}.manifest")
        if not os.path.isfile(sidecar):
            die(f"image set {ver} has no provenance sidecar xpf-{ver}.manifest "
                f"in {dist} — cannot confirm it passed the in-guest "
                "verify-dataplane gate. Refusing to publish (the sidecar is "
                "written + signed by scripts/image/bake.py; re-bake).")
        try:
            # Verify the sidecar against the SIGNED checksum manifest and read
            # the VERIFIED bytes (TOCTOU-safe) — the same primitive the deployer
            # mixed-base gate uses (#5042). Fails closed if the sidecar is not
            # covered by the signed manifest or its hash does not match.
            data = sign.verify_listed_artifact_bytes(sidecar, sums, sig, pub)
        except sign.SignError as e:
            die(f"provenance sidecar xpf-{ver}.manifest failed verify against "
                f"the signed manifest {os.path.basename(sums)}: {e}")
        fields = sign.parse_sidecar_fields(data.decode("utf-8", "replace"))
        validated = fields.get("validated")
        if validated != "true":
            die(f"image set {ver} provenance says validated={validated!r} (not "
                "'true') — this bake did NOT pass the in-guest verify-dataplane "
                "gate (built with --skip-validate, or an older bake predating "
                "the #4904 provenance field). Refusing to publish an "
                "UNVALIDATED image with a release signature. Re-bake WITHOUT "
                "--skip-validate.")
        # #5815: the signed sidecar also asserts whether the Ubuntu base was
        # anchored to a reviewed trust-anchor digest (base_image_pinned, #4904
        # B). An XPF_ALLOW_UNPINNED_BASE=1 dev bake signs base_image_pinned:
        # false — its OWN authenticated metadata says the base is not pinned —
        # yet is otherwise byte-shape-identical to a release. Enforce it here
        # symmetrically with validated (already-authenticated field, no new
        # trust surface). Fail-CLOSED on a MISSING key too: an old/tampered
        # sidecar that does not assert pinning is NOT publishable.
        base_pinned = fields.get("base_image_pinned")
        if base_pinned != "true":
            die(f"image set {ver} provenance says base_image_pinned="
                f"{base_pinned!r} (not 'true') — the Ubuntu base was NOT "
                "anchored to a reviewed trust-anchor digest (built with "
                "XPF_ALLOW_UNPINNED_BASE=1, or an older/tampered bake that does "
                "not assert pinning). Refusing to publish an UNPINNED image with "
                "a release signature: a signed dev/unpinned bake is not "
                "releasable. Re-bake against a PINNED_BASE_SHA256 base WITHOUT "
                "XPF_ALLOW_UNPINNED_BASE.")
        # #6500: the traceability record must actually say what the image
        # ships. `bake_host_kernel` names the BUILD HOST's kernel and answers a
        # different question; without guest_kernel + the package inventory,
        # "does release X ship openssl 3.x.y (CVE-YYYY)?" and "which kernel
        # does X carry, so I can plan a LANE-1 arm?" both require booting or
        # mounting the image. Fail-CLOSED, exactly like validated /
        # base_image_pinned: a missing field, a missing sidecar, a sidecar not
        # covered by the signed manifest, or a HOLLOW one all refuse.
        #
        # A hollow record is refused deliberately, not tolerated as
        # best-effort: a present-but-empty inventory satisfies a presence check
        # and answers nothing, which is strictly worse than an absent one
        # because it argues against anyone re-examining it.
        gkern = fields.get("guest_kernel")
        if not gkern:
            die(f"image set {ver} provenance records no guest_kernel — the "
                "signed manifest cannot say which kernel the image ships (the "
                "exact artifact the #1930 LANE-1 channel promotes; "
                "bake_host_kernel is the BUILD HOST's and answers a different "
                "question). Refusing to publish an image whose traceability "
                "record cannot describe it. Re-bake (#6500).")
        pkgs_name = image_inventory.sidecar_name(ver)
        pkgs_path = os.path.join(dist, pkgs_name)
        if not os.path.isfile(pkgs_path):
            die(f"image set {ver} has no inventory sidecar {pkgs_name} in "
                f"{dist} — the signed record cannot list the package versions "
                "the image ships, so a CVE-triage question needs the image "
                "booted or mounted. Refusing to publish (the sidecar is "
                "written + signed by scripts/image/bake.py; re-bake).")
        try:
            pkgs_data = sign.verify_listed_artifact_bytes(pkgs_path, sums, sig, pub)
        except sign.SignError as e:
            die(f"inventory sidecar {pkgs_name} failed verify against the "
                f"signed manifest {os.path.basename(sums)}: {e}")
        try:
            inv_kern, inv_pkgs = image_inventory.parse(
                pkgs_data.decode("utf-8", "replace"))
        except image_inventory.InventoryError as e:
            die(f"inventory sidecar {pkgs_name} is not a usable inventory: {e}. "
                "Refusing to publish.")
        # The two authenticated records must AGREE about the kernel. They are
        # written from the same in-guest read, so a divergence means one of
        # them was edited after the bake — and both are inside the signature,
        # so it means the whole signed set was re-assembled.
        if inv_kern != gkern:
            die(f"image set {ver}: the manifest says guest_kernel={gkern!r} but "
                f"the inventory sidecar says {inv_kern!r}. Both are covered by "
                "the same signature, so these cannot disagree on an untampered "
                "bake. Refusing to publish.")
        info(f"image set {ver}: provenance validated=true base_image_pinned=true "
             f"guest_kernel={gkern} inventory={len(inv_pkgs)} packages")


def _gate_one_latest(dist, channel, pub, require_present):
    """Verify one channel's signed latest.json. `require_present`, when not
    None, is the set of versions the pointer's `version` MUST name (the target
    channel's freshness contract); pass None to enforce only the signature (a
    non-target channel may legitimately point at a version outside THIS
    publish's dist set)."""
    latest = os.path.join(dist, channel, "latest.json")
    if not os.path.isfile(latest):
        die(f"{channel}/latest.json missing — run "
            f"`publish.py make-latest --channel {channel} --version <V>` first.")
    sig = latest + ".minisig"
    if not os.path.isfile(sig):
        die(f"{channel}/latest.json.minisig missing — the freshness pointer "
            "must be signed.")
    # Verify + parse from the VERIFIED bytes (AGY-r3-F1 TOCTOU): do not re-open
    # the live latest.json after the signature check.
    try:
        data = json.loads(sign.verify_and_read(latest, sig, pub).decode())
    except sign.SignError as e:
        die(f"{channel}/latest.json signature failed verify: {e}")
    except (ValueError, UnicodeDecodeError) as e:
        die(f"{channel}/latest.json is not valid JSON after verify: {e}")
    ver = data.get("version")
    if require_present is not None and ver not in require_present:
        die(f"{channel}/latest.json names version {ver!r} which is NOT in the "
            f"publish set {sorted(require_present)} — refusing to advertise a "
            "missing version.")
    info(f"latest.json OK (channel {channel} -> {ver})")


def gate_latest(dist, channel, versions, pub):
    """(d): the TARGET channel's latest.json verifies and names a present
    version, AND every OTHER dist/<chan>/latest.json in the tree also carries a
    verifying signature (HB165 H-13). The whole dist tree is uploaded, so a
    stale/tampered/unsigned pointer for a non-target channel would otherwise
    ship unverified — mirror gate_apt's per-suite InRelease posture and gate
    EVERY channel's freshness pointer, not just `--channel`'s."""
    # Target channel: mandatory + must name a version present in this publish.
    _gate_one_latest(dist, channel, pub, require_present=versions)
    # Every other channel pointer present in the tree: signature only.
    for entry in sorted(os.listdir(dist)):
        cdir = os.path.join(dist, entry)
        if entry == channel or not os.path.isdir(cdir):
            continue
        if os.path.isfile(os.path.join(cdir, "latest.json")):
            _gate_one_latest(dist, entry, pub, require_present=None)


def gate_apt(dist, channel):
    """(b): the apt InRelease verifies against the archive key. The whole
    apt/ tree is uploaded (rsync/s3 sync), so EVERY suite present under
    dists/ — not just the target `channel` — must carry a verifying
    InRelease (AGY-r3-F2). The target channel must exist."""
    apt_root = os.path.join(dist, "apt")
    # Reject symlinks anywhere under apt/ (Codex-r5): the apt tree is uploaded
    # as part of the dist root, and a dereferencing backend could follow a
    # symlink to publish unverified bytes — the same class as the image-sweep
    # symlink rejection, through the apt subtree.
    if os.path.isdir(apt_root):
        for root, dirs, files in os.walk(apt_root):
            for nm in list(dirs) + files:
                if os.path.islink(os.path.join(root, nm)):
                    rel = os.path.relpath(os.path.join(root, nm), dist)
                    die(f"symlink in the apt publish set: {rel} — refusing "
                        "(a dereferencing backend could upload unverified bytes).")
    distsdir = os.path.join(dist, "apt", "dists")
    target = os.path.join(distsdir, channel, "InRelease")
    if not os.path.isfile(target):
        die(f"apt InRelease for the target suite {channel} missing "
            f"({target}) — build a SIGNED repo (XPF_GPG_KEY) first.")
    pub = archive_pubkey()
    if _is_placeholder(pub):
        die("archive pubkey is the #1924 PLACEHOLDER — cannot verify InRelease. "
            "Supply the real archive key (XPF_ARCHIVE_PUBKEY / "
            "scripts/dist/xpf-archive-keyring.asc) before publishing.")
    suites = sorted(d for d in os.listdir(distsdir)
                    if os.path.isdir(os.path.join(distsdir, d)))
    # Verify against an ephemeral keyring built only from the pinned pubkey.
    import tempfile
    with tempfile.TemporaryDirectory() as gnupghome:
        os.chmod(gnupghome, 0o700)
        env = dict(os.environ, GNUPGHOME=gnupghome)
        r = subprocess.run(["gpg", "--batch", "--import", pub],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"could not import archive pubkey {pub}: {r.stderr.strip()}")
        signer_fprs = set()
        for suite in suites:
            inrel = os.path.join(distsdir, suite, "InRelease")
            if not os.path.isfile(inrel):
                die(f"suite {suite} under dists/ has no InRelease — the whole "
                    "apt tree is uploaded, so every suite must be signed. "
                    "Rebuild or remove it.")
            # --status-fd 1 emits a machine-readable VALIDSIG line whose LAST
            # field is the signer's PRIMARY key fingerprint (#4203 key
            # agreement). rc still reflects verify success/failure.
            r = subprocess.run(["gpg", "--batch", "--status-fd", "1",
                                "--verify", inrel],
                               env=env, capture_output=True, text=True)
            if r.returncode != 0:
                die(f"apt InRelease ({suite}) signature FAILED: {r.stderr.strip()}")
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "VALIDSIG":
                    signer_fprs.add(parts[-1])
            info(f"apt InRelease ({suite}) signature OK")
    # The pooled .deb must not carry the PLACEHOLDER archive keyring
    # (Codex-r2-2): a package built before the real key existed would, once
    # installed, overwrite a host's real /usr/share/keyrings key with the
    # placeholder and break `apt update`. Also collect the exact keyrings that
    # will be installed; the repo's verification key above is not proof of the
    # package payload (issue #10737).
    pool = os.path.join(dist, "apt", "pool")
    packaged_keyrings = []
    if os.path.isdir(pool):
        import tempfile as _tf
        for root, _dirs, files in os.walk(pool):
            for fn in files:
                if not fn.endswith(".deb"):
                    continue
                debp = os.path.join(root, fn)
                with _tf.TemporaryDirectory() as td:
                    r = subprocess.run(["dpkg-deb", "-x", debp, td],
                                       capture_output=True, text=True)
                    if r.returncode != 0:
                        # Fail-CLOSED (Codex-r3): an uninspectable pooled .deb
                        # must NOT be published — we cannot confirm it does not
                        # ship the placeholder keyring.
                        die(f"cannot extract pooled package {fn} for inspection "
                            f"(dpkg-deb rc={r.returncode}): {r.stderr.strip()} — "
                            "refusing to publish an uninspectable package.")
                    kp = os.path.join(td, "usr/share/keyrings/"
                                      "xpf-archive-keyring.asc")
                    if os.path.isfile(kp):
                        if _is_placeholder(kp):
                            die(f"pooled package {fn} ships the PLACEHOLDER "
                                "archive keyring — refusing to publish (it "
                                "would clobber a host's real key on upgrade). "
                                "Rebuild the .deb after dropping in "
                                "scripts/dist/xpf-archive-keyring.asc.")
                        packaged_keyrings.append((fn, _key_fingerprints(kp)))
    # H-15 (#4203): compare against the keyring in the actual pooled package,
    # not just the repo-side archive key used to verify InRelease.
    _gate_key_agreement(dist, signer_fprs, packaged_keyrings)


def make_latest(dist, channel, version):
    """Write + sign the per-channel latest.json freshness pointer (§5.6)."""
    manifest = os.path.join(dist, f"xpf-{version}.SHA256SUMS")
    if not os.path.isfile(manifest):
        die(f"no manifest for version {version} in {dist}")
    seckey = os.environ.get("XPF_SIGN_SECKEY")
    if not seckey:
        die("XPF_SIGN_SECKEY (path to the minisign secret key) is required to "
            "sign latest.json.")
    cdir = os.path.join(dist, channel)
    os.makedirs(cdir, exist_ok=True)
    latest = os.path.join(cdir, "latest.json")
    data = {
        "channel": channel,
        "version": version,
        "manifest": f"xpf-{version}.SHA256SUMS",
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(latest, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    sign.sign_manifest(latest, seckey, comment=f"xpf {channel} latest {version}")
    info(f"wrote + signed {latest} -> {version}")


def _fsync_tree(root):
    """fsync every regular file and directory under `root` so the snapshot's
    bytes are durable before dispatch (the backend may run in a separate
    process that reopens the files)."""
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p):
                continue
            try:
                fd = os.open(p, os.O_RDONLY)
            except OSError:
                continue
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        try:
            dfd = os.open(dirpath, os.O_RDONLY)
        except OSError:
            continue
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _snapshot_dist(dist):
    """#4904 C (TOCTOU): copy the publish tree into a PRIVATE 0700 staging dir
    and fsync it, returning (staging_root, snapshot_dir).

    gate_images hashes artifacts + verifies install.sh against the live `dist`
    tree and returns keeping NO snapshot/lock; dispatch then hands the SAME
    mutable path to the backend, which REOPENS the files. A concurrent
    bake/cleanup/writer can replace an artifact, sidecar, or the Tier-A
    install.sh AFTER the gate but BEFORE the backend reads it, so a gate-pass log
    accompanies DIFFERENT uploaded bytes (including an unsigned installer).
    Snapshotting first — then gating AND dispatching ONLY the snapshot — makes
    the bytes gated the exact bytes uploaded.

    Symlinks are copied AS symlinks (symlinks=True) so the gate's symlink
    refusal still fires on them, rather than silently dereferencing a link into
    a real file that would ride along unseen."""
    import shutil as _sh
    import tempfile as _tf
    staging = _tf.mkdtemp(prefix="xpf-publish-snap-")
    os.chmod(staging, 0o700)
    snap = os.path.join(staging, "dist")
    _sh.copytree(dist, snap, symlinks=True)
    _fsync_tree(snap)
    return staging, snap


def dispatch(cmd, local_dir, base_url, dry):
    info(f"publish: {cmd} {local_dir} {base_url}")
    if dry:
        print(f"  (dry-run) {cmd} {local_dir} {base_url}")
        return
    r = subprocess.run([cmd, local_dir, base_url])
    if r.returncode != 0:
        die(f"XPF_PUBLISH_CMD failed (rc={r.returncode}) for {base_url}")


def main(argv):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    ml = sub.add_parser("make-latest")
    ml.add_argument("--channel", default="stable")
    ml.add_argument("--version", required=True)
    ml.add_argument("--dist", default=os.path.join(ROOT, "dist"))

    st = sub.add_parser("stamp-installer",
                        help="bake the real archive key + apt base URL + "
                             "channel into install.sh (substitute-then-sign)")
    st.add_argument("--out", required=True,
                    help="output path for the baked installer (e.g. dist/install.sh)")
    st.add_argument("--src", default=INSTALLSH_SRC)
    st.add_argument("--archive-key", default=None,
                    help="ASCII-armored archive pubkey (default: the pinned "
                         "scripts/dist/xpf-archive-keyring.asc)")
    st.add_argument("--apt-base-url", default=os.environ.get("XPF_APT_BASE_URL"))
    st.add_argument("--channel", default=os.environ.get("XPF_CHANNEL", "stable"))

    p.add_argument("--channel", default="stable")
    p.add_argument("--dist", default=os.path.join(ROOT, "dist"))
    p.add_argument("--no-image", action="store_true")
    p.add_argument("--no-apt", action="store_true")
    p.add_argument("--no-installer", action="store_true",
                   help="publish images WITHOUT install.sh (Tier-A one-liner "
                        "unavailable); default REQUIRES a stamped+signed one")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "make-latest":
        make_latest(a.dist, a.channel, a.version)
        return 0

    if a.cmd == "stamp-installer":
        stamp_installer(a.out, src=a.src, archive_key=a.archive_key,
                        apt_url=a.apt_base_url, channel=a.channel)
        return 0

    dist = a.dist
    if not os.path.isdir(dist):
        die(f"dist dir not found: {dist}")

    # An image-only publish (--no-apt) dispatches the WHOLE dist root, which
    # includes dist/apt if present — so apt bytes would ship UNGATED
    # (Codex-r4). Refuse --no-apt when an apt tree exists; either gate it too
    # or publish from a tree without apt/.
    if a.no_apt and not a.no_image and os.path.isdir(os.path.join(dist, "apt")):
        die("--no-apt but dist/apt exists: an image publish uploads the whole "
            "dist tree (including apt/), so the apt repo would ship UNGATED. "
            "Drop --no-apt (gate apt too), or move dist/apt out of the publish "
            "root.")

    pubcmd = os.environ.get("XPF_PUBLISH_CMD")
    # #4904 C: when we will actually upload, snapshot the tree into a private
    # immutable staging dir FIRST, then gate + dispatch ONLY the snapshot, so a
    # concurrent writer cannot swap the uploaded bytes out from under a
    # gate-pass. A gate-only / --dry-run run uploads nothing, so it gates the
    # live tree directly (no full copy — the qcow2 set can be multi-GB).
    will_dispatch = bool(pubcmd) and not a.dry_run
    staging = None
    try:
        gate_dir = dist
        if will_dispatch:
            staging, gate_dir = _snapshot_dist(dist)

        # ── fail-closed gate (against the immutable snapshot when dispatching) ──
        if not a.no_image:
            versions, pub = gate_images(gate_dir,
                                        require_installer=not a.no_installer)
            gate_provenance(gate_dir, versions, pub)
            gate_latest(gate_dir, a.channel, versions, pub)
        if not a.no_apt:
            gate_apt(gate_dir, a.channel)

        if not pubcmd:
            info("gate PASSED. XPF_PUBLISH_CMD unset — nothing uploaded. Set it "
                 "to the backend shim ($CMD <local-dir> <dest-base-url>) to "
                 "publish.")
            return 0

        # Dispatch the SNAPSHOT (gate_dir), never the mutable `dist`.
        if not a.no_image:
            img_url = os.environ.get("XPF_IMAGE_BASE_URL") or die(
                "XPF_IMAGE_BASE_URL required to publish the image tree.")
            dispatch(pubcmd, gate_dir, img_url, a.dry_run)
        if not a.no_apt:
            apt_url = os.environ.get("XPF_APT_BASE_URL") or die(
                "XPF_APT_BASE_URL required to publish the apt tree.")
            dispatch(pubcmd, os.path.join(gate_dir, "apt"), apt_url, a.dry_run)
        info("publish complete.")
        return 0
    finally:
        if staging:
            import shutil as _sh
            _sh.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
