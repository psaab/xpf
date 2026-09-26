#!/usr/bin/env python3
"""xpf signed-distribution signing/verification helpers (#1924).

Shared by the image bake (scripts/image/bake.py), the image validation
gate (scripts/image/validate.py), the deployer fetch path
(scripts/deploy/xpf-deploy.py), and the publish gate
(scripts/dist/publish.py). Implements the IMAGE trust root:

  minisign over a PER-VERSION checksum manifest (xpf-<ver>.SHA256SUMS),
  then PER-FILE hash verification of the exact bytes being consumed.

Design contract (docs/research/1924-signed-hosted-dist/plan.md §5.1/§5.2):

- The signing tool is `minisign` (Ed25519). We shell out to the system
  binary rather than reimplement Ed25519 — `require_minisign()` preflights
  it with an apt-install hint.
- Secret keys are referenced by PATH via XPF_SIGN_SECKEY / XPF_SIGN_SECKEYS
  or explicit arguments; key bytes are NEVER embedded, logged, or committed.
- The default public key is scripts/dist/xpf-image.pub. Rotation can pin an
  explicit set through XPF_IMAGE_PUBKEYS or repeated --pubkey options; trust
  roots come from the in-repo git copy, never a hosting URL.
- Verification is PER-FILE: the signed manifest authenticates a {basename:
  sha256} map; each consumer hashes the EXACT file it is about to use and
  compares to the manifest entry for that file's basename. A file absent
  from the manifest, or a hash mismatch, FAILS. Files listed but not
  fetched are simply not checked (so a qcow2-only libvirt fetch verifies).
"""
# #9920 F-063: the sign-manifest CLI (the `make dist-sign` recovery path) is
#fail-CLOSED for bake manifests: it refuses an xpf-<ver>.SHA256SUMS whose
#file set is not exactly the bake's four-file set for <ver>, or whose
#sidecar does not assert validated/base_image_pinned/guest_kernel — BEFORE
#writing anything. The library functions below stay permissive (bake.py and
#the publish-negative fixtures call them directly); publish.py remains the
#full downstream gate.

import base64
import datetime
import hashlib
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

LATEST_MAX_AGE_SECONDS = 90 * 24 * 60 * 60
LATEST_FUTURE_SKEW_SECONDS = 5 * 60
# Checked-in default public key for image artifacts. XPF_IMAGE_PUBKEY keeps
# its legacy singular override; XPF_IMAGE_PUBKEYS supplies a rotation set.
# Until OQ-2 supplies a real key, only `xpf-image.pub.placeholder` ships (its
# secret was shredded at generation, held by no one — so verify FAILS until
# the operator drops in the real `xpf-image.pub`, the correct fail-safe).
HERE = os.path.dirname(os.path.abspath(__file__))


def default_image_pubkey():
    real = os.path.join(HERE, "xpf-image.pub")
    if os.path.isfile(real):
        return real
    return os.path.join(HERE, "xpf-image.pub.placeholder")


DEFAULT_IMAGE_PUBKEY = default_image_pubkey()


class SignError(Exception):
    """Signing/verification failure — fatal to the caller's gate."""



# ── Bounded remote fetch (#10853) ─────────────────────────────────────
#
# Every image fetch was an unbounded `curl -fsSL`: no scheme restriction, no
# redirect-downgrade protection, no timeout, no size cap. A hostile/slow
# mirror could hang a fetch/bake indefinitely or fill the disk with an
# oversized qcow2 before signature verification. Integrity remains protected
# by the signed manifest/pinned base digest; this bounds availability impact.
FETCH_CONNECT_TIMEOUT_S = 30
FETCH_MAX_TIME_SMALL_S = 120
FETCH_MAX_TIME_LARGE_S = 1800
FETCH_MAX_BYTES_SMALL = 8 * 1024 * 1024
FETCH_MAX_BYTES_METADATA = 64 * 1024 * 1024
FETCH_MAX_BYTES_BASE_IMAGE = 16 * 1024 * 1024 * 1024
FETCH_MAX_BYTES_QCOW2 = 64 * 1024 * 1024 * 1024
_FETCH_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_FETCH_MAX_URL_LEN = 4096


def validate_fetch_url(url, field="fetch URL"):
    """Validate an operator-controlled fetch base URL (#10853).

    Production URLs must use HTTPS. Local HTTP and file URLs remain available
    for development mirrors and hermetic tests. Reject userinfo, query,
    fragment, whitespace/control bytes, malformed hosts and non-local file
    URLs; artifact names are appended to the base, so query/fragment syntax
    would otherwise alter the requested resource.
    """
    if not isinstance(url, str) or not url:
        raise SignError(f"{field} must be a non-empty URL (#10853).")
    if len(url) > _FETCH_MAX_URL_LEN:
        raise SignError(f"{field} exceeds {_FETCH_MAX_URL_LEN} characters (#10853).")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7f for ch in url):
        raise SignError(f"{field} contains whitespace or a control byte (#10853).")
    try:
        parts = urlsplit(url)
    except ValueError as e:
        raise SignError(f"{field} is malformed: {e} (#10853).") from e
    scheme = parts.scheme.lower()
    if parts.query or parts.fragment:
        raise SignError(f"{field} must not include a query or fragment (#10853).")
    if scheme in ("https", "http"):
        if not parts.netloc or "@" in parts.netloc:
            raise SignError(f"{field} must have a bare host and no userinfo (#10853).")
        try:
            host = parts.hostname
            parts.port  # validates malformed/out-of-range ports
        except ValueError as e:
            raise SignError(f"{field} has an invalid host or port: {e} (#10853).") from e
        if not host:
            raise SignError(f"{field} must have a host (#10853).")
        if scheme == "http" and host.lower() not in _FETCH_LOOPBACK_HOSTS:
            raise SignError(
                f"{field} must use HTTPS outside loopback development hosts (#10853).")
    elif scheme == "file":
        if parts.netloc not in ("", "localhost") or not parts.path:
            raise SignError(f"{field} must be a local file URL with a path (#10853).")
    else:
        raise SignError(f"{field} must use HTTPS (#10853).")
    return url


def curl_fetch_argv(url, dest=None, *, max_bytes=FETCH_MAX_BYTES_SMALL,
                    max_time=FETCH_MAX_TIME_SMALL_S):
    """Build curl argv with redirect, time and byte bounds (#10853)."""
    scheme = urlsplit(url).scheme.lower()
    if scheme == "https":
        protocols = ["--proto", "=https", "--proto-redir", "=https"]
    elif scheme == "http":
        protocols = ["--proto", "=http,https", "--proto-redir", "=https"]
    elif scheme == "file":
        protocols = ["--proto", "=file", "--proto-redir", "=file"]
    else:
        raise SignError(f"unsupported fetch URL scheme {scheme!r} (#10853).")
    argv = ["curl", "-fsSL"] + protocols + [
        "--connect-timeout", str(FETCH_CONNECT_TIMEOUT_S),
        "--max-time", str(int(max_time)),
        "--max-filesize", str(int(max_bytes))]
    if dest is not None:
        argv.extend(["-o", dest])
    argv.append(url)
    return argv


def fetch_caps_for(basename):
    """Return the static (byte, time) backstop for a fetch target (#10853)."""
    if basename.endswith(".qcow2"):
        return FETCH_MAX_BYTES_QCOW2, FETCH_MAX_TIME_LARGE_S
    if basename.endswith(".incus-metadata.tar.gz"):
        return FETCH_MAX_BYTES_METADATA, FETCH_MAX_TIME_LARGE_S
    if basename.endswith(".img"):
        return FETCH_MAX_BYTES_BASE_IMAGE, FETCH_MAX_TIME_LARGE_S
    return FETCH_MAX_BYTES_SMALL, FETCH_MAX_TIME_SMALL_S


def fetch_file_limit(max_bytes):
    """Return a child pre-exec hook enforcing a hard file-size ceiling.

    curl's --max-filesize rejects a known oversized response before transfer,
    but libcurl documents that it cannot enforce that option when a server
    omits Content-Length. RLIMIT_FSIZE caps writes to the exclusive temp even
    for chunked/unknown-length responses; curl then fails and the caller
    removes the partial file. Respect any stricter inherited process limit.
    """
    max_bytes = int(max_bytes)
    if max_bytes <= 0:
        raise SignError(f"download byte ceiling must be positive, got {max_bytes}")

    def apply_limit():
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = max_bytes
        if soft != resource.RLIM_INFINITY:
            limit = min(limit, soft)
        if hard != resource.RLIM_INFINITY:
            limit = min(limit, hard)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard))

    return apply_limit


def _key_paths(value):
    """Normalize one public-key path or an ordered collection of paths."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [os.fspath(p) for p in value if p]
    value = os.fspath(value)
    return [p for p in value.split(os.pathsep) if p] if os.pathsep in value else [value]


def resolve_image_pubkeys(pubkey_path=None):
    """Resolve the trusted image-key set; legacy singular configuration remains valid.

    XPF_IMAGE_PUBKEYS is an os.pathsep-separated ordered set. XPF_IMAGE_PUBKEY
    may still be used alone and is placed first when both variables are set,
    preserving the legacy canonical signer during overlap.
    """
    if pubkey_path is None:
        singular = os.environ.get("XPF_IMAGE_PUBKEY")
        keys = _key_paths(singular)
        keys.extend(_key_paths(os.environ.get("XPF_IMAGE_PUBKEYS")))
        if not keys:
            keys = [DEFAULT_IMAGE_PUBKEY]
    else:
        keys = _key_paths(pubkey_path)
    unique = []
    seen = set()
    for key in keys:
        full = os.path.abspath(key)
        if full in seen:
            continue
        seen.add(full)
        if not os.path.isfile(full):
            raise SignError(
                f"image public key not found: {key} "
                "(set XPF_IMAGE_PUBKEY or XPF_IMAGE_PUBKEYS, or ship scripts/dist/xpf-image.pub).")
        require_real_pubkey(full)
        unique.append(full)
    if not unique:
        raise SignError("no image public keys configured")
    return unique


def _key_id(path):
    """Read minisign's eight-byte key id from a public-key or signature file."""
    try:
        with open(path, "rt", encoding="ascii") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("untrusted comment:", "trusted comment:")):
                    continue
                raw = base64.b64decode(line, validate=True)
                if len(raw) >= 10:
                    return raw[2:10][::-1].hex().upper()
    except (OSError, UnicodeError, ValueError):
        pass
    return None


def minisign_key_id(path):
    """Return a minisign key id, or None for a malformed signature."""
    return _key_id(path)


def signature_paths(signed_path, pubkey_path=None):
    """Return canonical and key-addressed minisign sidecars for trusted keys.

    Multi-key signing keeps the first signature at the legacy `.minisig` path;
    each additional signature is `.minisig.<key-id>`, allowing a checkout
    pinned only to a newly rotated key to find its signature without listing
    the publish directory.
    """
    canonical = signed_path + ".minisig"
    paths = [canonical]
    for key in resolve_image_pubkeys(pubkey_path):
        key_id = _key_id(key)
        if key_id:
            paths.append(canonical + "." + key_id)
    return list(dict.fromkeys(paths))

# The bake's four-file signed set (#9920 F-063 SSOT). bake.py builds its
# write_manifest file list from bake_set_basenames(), and the sign-manifest
# CLI requires its inputs to equal this set for xpf-*.SHA256SUMS manifests —
# one literal, so a bake that gains a fifth artifact cannot silently desync
# from the re-sign gate (it would false-red until both move together, which
# is the point: the two must move in one PR).
BAKE_SET_TEMPLATES = (
    "xpf-{ver}.qcow2",
    "xpf-{ver}.incus-metadata.tar.gz",
    "xpf-{ver}.manifest",
    "xpf-{ver}.pkgs",
)


def bake_set_basenames(ver):
    """The four basenames bake.py covers with xpf-<ver>.SHA256SUMS."""
    return [t.format(ver=ver) for t in BAKE_SET_TEMPLATES]


def is_bake_manifest(manifest_path):
    """True when `manifest_path` names a per-version bake manifest — the only
    manifest shape publish discovers (publish.list_versions globs
    xpf-*.SHA256SUMS). The strict gate applies exactly to these."""
    base = os.path.basename(manifest_path)
    return base.startswith("xpf-") and base.endswith(".SHA256SUMS")


# Version allowlist MIRRORS scripts/image/bake.py:validate_version (#5992),
# which itself mirrors scripts/deploy/xpf-deploy.py:validate_version and
# pkg/upgrade.ValidateVersion. Mirrored (not imported: bake imports THIS
# module, so importing bake would cycle) with charset parity asserted in
# scripts/dist/test_dist_resign_9920.py. Raises SignError instead of dying —
# the strict gate needs a catchable refusal, and this module never exits
# outside _main.
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*\Z")


def validate_version(value, field):
    """Reject a version that could escape the artifact output directory when
    substituted into `xpf-<ver>.qcow2` (and siblings). Fail-closed on a path
    separator, `..`, absolute path, leading `.`/`-`, whitespace, `%`, or any
    char outside [A-Za-z0-9._+~-]. Accepts git-describe / semver versions."""
    if not isinstance(value, str) or not value:
        raise SignError(f"{field} is required and must be a non-empty string")
    if os.path.isabs(value):
        raise SignError(f"{field} '{value}' must not be an absolute path")
    if "/" in value or "\\" in value or os.sep in value \
            or (os.altsep and os.altsep in value):
        raise SignError(
            f"{field} '{value}' must not contain a path separator")
    if value.startswith("-"):
        raise SignError(
            f"{field} '{value}' must not start with '-' "
            "(would be read as a CLI flag)")
    if not _SAFE_VERSION.match(value):
        raise SignError(
            f"{field} '{value}' is not a safe version — allow only "
            "[A-Za-z0-9][A-Za-z0-9._+~-]* (no separators, '..', '%', spaces, or "
            "shell metacharacters), so it cannot escape the artifact output "
            "directory (#5992)")
    return value


def parse_latest_date(value):
    """Parse the canonical UTC timestamp in a signed latest.json pointer."""
    if not isinstance(value, str):
        raise SignError("date is missing or is not a string")
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SignError(
            "date must use YYYY-MM-DDTHH:MM:SSZ format") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise SignError("date must use canonical YYYY-MM-DDTHH:MM:SSZ format")
    return parsed.replace(tzinfo=datetime.timezone.utc).timestamp()


def validate_latest_date(value, now=None):
    """Require a latest.json date no more than 90 days old or 5 minutes ahead."""
    issued = parse_latest_date(value)
    now = time.time() if now is None else now
    if issued > now + LATEST_FUTURE_SKEW_SECONDS:
        raise SignError("date is more than 5 minutes in the future")
    if now - issued > LATEST_MAX_AGE_SECONDS:
        raise SignError("date is older than the 90-day freshness window")
    return issued


def parse_sidecar_fields(text):
    """Parse a bake `.manifest` sidecar (key: value lines) into a dict, keys
    verbatim. Moved from publish._parse_manifest_fields (#9920): the strict
    sign-manifest gate and gate_provenance must split lines identically, and
    publish already imports this module, so this is the cycle-free home."""
    d = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        d[k.strip()] = v.strip()
    return d


def assert_bake_set(manifest_path, files):
    """#9920 F-063: refuse to sign an xpf-<ver>.SHA256SUMS manifest whose file
    set is not exactly the bake's four-file set for <ver>, or whose
    xpf-<ver>.manifest sidecar does not assert validated/base_image_pinned/
    guest_kernel (the same three properties gate_provenance enforces).

    Call BEFORE write_and_sign_manifest: every refusal raises SignError (the CLI maps
    it to `ERROR:` + exit 1) with the manifest and any pre-existing .minisig
    left byte-identical. The gate checks:
      - the exact four-file bake set and sibling directory;
      - the provenance flags below;
      - when a recorded manifest already exists, every live file's bytes match
        its recorded SHA256 before any re-sign.
    What this is NOT:
      - it never verifies the OLD signature (a rotation may lack the old key;
        the actor here is the publisher/operator, not a remote party);
      - it does not check the inventory leg (hollow/mismatched pkgs stays
        publish's job — publish remains the full downstream gate).
    """

    base = os.path.basename(manifest_path)
    if not is_bake_manifest(manifest_path):
        raise SignError(
            f"{base}: not an xpf-<ver>.SHA256SUMS bake manifest — refusing to "
            "apply the bake-set gate to it (#9920)")
    ver = base[len("xpf-"):-len(".SHA256SUMS")]
    validate_version(ver, f"version in {base}")
    expected = bake_set_basenames(ver)
    got = [os.path.basename(f) for f in files]
    if sorted(got) != sorted(expected):
        raise SignError(
            f"{base}: refusing to sign a file set that is not the bake's "
            f"four-file set for version {ver!r}: got {sorted(got)}, want "
            f"{sorted(expected)} (#9920: re-sign must not launder a reduced "
            "set — re-bake or restore the missing files)")
    # Same basenames from mixed directories would hash foreign bytes under
    # bake names, so all four must sit beside the manifest they are signed
    # under (the bake always writes them that way).
    want_dir = os.path.dirname(os.path.abspath(manifest_path))
    for f in files:
        if os.path.dirname(os.path.abspath(f)) != want_dir:
            raise SignError(
                f"{base}: {f!r} is not beside the manifest in {want_dir} — "
                f"refusing to sign a scattered set as the bake set for "
                f"{ver!r} (#9920)")
    sidecar_base = f"xpf-{ver}.manifest"
    sidecar_path = {os.path.basename(f): f for f in files}[sidecar_base]
    try:
        with open(sidecar_path, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        raise SignError(
            f"{base}: cannot read provenance sidecar {sidecar_base}: {e} "
            "(#9920)") from e
    fields = parse_sidecar_fields(raw.decode("utf-8", "replace"))
    validated = fields.get("validated")
    if validated != "true":
        raise SignError(
            f"{base}: provenance sidecar says validated={validated!r} (not "
            "'true') — refusing to sign an unvalidated bake set (#9920; "
            "re-bake WITHOUT --skip-validate)")
    base_pinned = fields.get("base_image_pinned")
    if base_pinned != "true":
        raise SignError(
            f"{base}: provenance sidecar says base_image_pinned="
            f"{base_pinned!r} (not 'true') — refusing to sign an unpinned "
            "bake set (#9920)")
    if not fields.get("guest_kernel"):
        raise SignError(
            f"{base}: provenance sidecar records no guest_kernel — refusing "
            "to sign a set whose traceability record cannot describe it "
            "(#9920; re-bake)")
    # On re-sign, bind the live bytes to the hashes already recorded in the
    # existing manifest. The initial sign has no manifest yet, so there is
    # nothing to compare and the normal write path creates the record.
    if os.path.exists(manifest_path):
        try:
            recorded = parse_manifest(manifest_path)
        except (OSError, SignError) as e:
            raise SignError(
                f"{base}: cannot read recorded hashes for re-sign: {e} "
                "(#10120)") from e
        for path in files:
            name = os.path.basename(path)
            expected_hash = recorded.get(name)
            if expected_hash is None:
                raise SignError(
                    f"{base}: no recorded hash for {name} — refusing to "
                    f"re-sign (#10120)")
            actual_hash = sha256_file(path)
            if actual_hash != expected_hash:
                raise SignError(
                    f"{base}: {name} bytes differ from recorded hash — "
                    "refusing to re-sign (#10120)")
        return recorded


def require_minisign():
    """Ensure the minisign binary is present; raise with an install hint."""
    exe = shutil.which("minisign")
    if not exe:
        raise SignError(
            "minisign not found — install it (apt-get install minisign) to "
            "sign or verify image artifacts (#1924).")
    return exe


def is_placeholder_pubkey(pubkey_path):
    """True if `pubkey_path` is the shipped placeholder (its secret was
    shredded at generation, so it can never authenticate a real release)."""
    return os.path.basename(pubkey_path).endswith(".placeholder")


def require_real_pubkey(pubkey_path):
    """Fail-CLOSED if the image pubkey is the placeholder (Codex-M4). The
    placeholder exists only so the mechanism + tests have a key-path shape;
    a real verify against it would either always fail (no holder of its
    secret) or — worse — pass if an attacker re-signed with a self-generated
    placeholder secret. Refuse it explicitly, mirroring the apt-key
    placeholder refusal in publish.py."""
    if is_placeholder_pubkey(pubkey_path):
        raise SignError(
            f"image public key {os.path.basename(pubkey_path)} is the #1924 "
            "PLACEHOLDER — refusing to verify against it. Supply the real key "
            "(XPF_IMAGE_PUBKEY or XPF_IMAGE_PUBKEYS, or scripts/dist/xpf-image.pub) — see "
            "scripts/dist/README.md.")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(manifest_path, files, recorded_hashes=None,
                   recorded_sizes=None, with_sizes=False):
    """Write the signed sha256sum-format manifest by basename.

    #10853: each artifact may have a following signed `# size <name> <bytes>`
    comment so a fetcher can cap its transfer BEFORE hash verification. The
    comment preserves compatibility with ordinary `sha256sum -c` readers.
    Frozen bake artifacts pass their hash-time snapshots rather than rereading
    writable live paths; the default remains the legacy manifest format.
    """
    if recorded_sizes is not None and recorded_hashes is None:
        raise SignError("recorded_sizes requires recorded_hashes")
    seen = set()
    lines = []
    for path in files:
        base = os.path.basename(path)
        if base in seen:
            raise SignError(f"duplicate basename in manifest set: {base}")
        seen.add(base)
        if recorded_hashes is None:
            digest = sha256_file(path)
        else:
            try:
                digest = recorded_hashes[base]
            except KeyError as e:
                raise SignError(
                    f"no recorded hash for {base} while writing manifest") from e
        if recorded_sizes is not None:
            try:
                size = recorded_sizes[base]
            except KeyError as e:
                raise SignError(
                    f"no recorded size for {base} while writing manifest") from e
        elif with_sizes:
            size = os.path.getsize(path)
        else:
            size = None
        lines.append(f"{digest}  {base}\n")
        if size is not None:
            lines.append(f"# size {base} {size}\n")
    with open(manifest_path, "w") as f:
        f.writelines(lines)
    return manifest_path


def _seckey_paths(value):
    if isinstance(value, (list, tuple)):
        return [os.fspath(path) for path in value]
    return [os.fspath(value)]


def sign_manifest(manifest_path, seckey_path, comment=None, sig_path=None):
    """Sign with ordered minisign keys, preserving the legacy first sidecar.

    The first key writes `<file>.minisig`; later keys write
    `<file>.minisig.<key-id>`. During overlap, keep the old key first so
    legacy clients that read only .minisig continue to verify. Returns the legacy
    path for a single key and every generated path for multiple keys.
    """
    exe = require_minisign()
    if sig_path is None:
        sig_path = manifest_path + ".minisig"
    seckeys = _seckey_paths(seckey_path)
    if not seckeys:
        raise SignError("at least one minisign secret key is required")
    sig_dir = os.path.dirname(os.path.abspath(sig_path))
    staged = []
    targets = []
    key_ids = set()
    try:
        for index, seckey in enumerate(seckeys):
            fd, tmp_sig = tempfile.mkstemp(
                prefix="." + os.path.basename(sig_path) + ".",
                suffix=".tmp", dir=sig_dir)
            os.close(fd)
            os.unlink(tmp_sig)
            argv = [exe, "-S", "-s", seckey, "-m", manifest_path,
                    "-x", tmp_sig]
            if comment:
                argv += ["-t", comment]
            r = subprocess.run(argv, input="\n", capture_output=True, text=True)
            if r.returncode != 0:
                raise SignError(
                    f"minisign sign failed (rc={r.returncode}): "
                    f"{r.stderr.strip()} (a password-protected key cannot sign "
                    "unattended — OQ-2 requires a passwordless image-signing "
                    "key or an interactive signer).")
            key_id = _key_id(tmp_sig)
            if not key_id:
                raise SignError(f"could not read minisign key id from {tmp_sig}")
            if key_id in key_ids:
                raise SignError(f"duplicate minisign signing key id: {key_id}")
            key_ids.add(key_id)
            target = sig_path if index == 0 else sig_path + "." + key_id
            staged.append(tmp_sig)
            targets.append(target)
        for source, target in zip(staged, targets):
            os.replace(source, target)
        staged.clear()
        keep = set(targets)
        sig_base = os.path.basename(sig_path)
        for entry in os.scandir(sig_dir):
            if (entry.name.startswith(sig_base + ".")
                    and re.fullmatch(re.escape(sig_base) + r"\.[0-9A-Fa-f]{16}",
                                     entry.name)
                    and entry.path not in keep):
                try:
                    os.unlink(entry.path)
                except OSError:
                    pass
    finally:
        for path in staged:
            try:
                os.unlink(path)
            except OSError:
                pass
    return targets[0] if len(targets) == 1 else targets


def write_and_sign_manifest(manifest_path, files, seckey_path, comment=None,
                            recorded_hashes=None, recorded_sizes=None):
    """Write + sign `manifest_path` and its one-or-many signatures atomically.

    When re-signing a size-bearing manifest, preserve its already-recorded
    signed sizes alongside the hashes; otherwise a routine key rotation would
    silently drop #10853's pre-download bounds.
    """
    manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
    base = os.path.basename(manifest_path)
    tmp_manifest = None
    tmp_sigs = []
    if (recorded_sizes is None and recorded_hashes is not None
            and os.path.isfile(manifest_path)):
        prior = parse_manifest_sizes(manifest_path)
        if (set(prior) == set(recorded_hashes)
                and all(size is not None for _digest, size in prior.values())):
            recorded_sizes = {
                name: size for name, (_digest, size) in prior.items()
            }
    try:
        fd, tmp_manifest = tempfile.mkstemp(prefix="." + base + ".",
                                            suffix=".tmp", dir=manifest_dir)
        os.close(fd)
        write_manifest(tmp_manifest, files, recorded_hashes=recorded_hashes,
                       recorded_sizes=recorded_sizes)
        if os.path.exists(manifest_path):
            shutil.copymode(manifest_path, tmp_manifest)
        tmp_sig = tmp_manifest + ".minisig"
        generated = sign_manifest(tmp_manifest, seckey_path, comment,
                                  sig_path=tmp_sig)
        tmp_sigs = generated if isinstance(generated, list) else [generated]
        final_sigs = []
        for source in tmp_sigs:
            target = manifest_path + ".minisig" + source[len(tmp_sig):]
            if os.path.exists(target):
                shutil.copymode(target, source)
            final_sigs.append(target)
        os.replace(tmp_manifest, manifest_path)
        tmp_manifest = None
        for source, target in zip(tmp_sigs, final_sigs):
            os.replace(source, target)
        tmp_sigs = []
        _remove_stale_signatures(manifest_path + ".minisig", final_sigs)
    finally:
        for path in ([tmp_manifest] if tmp_manifest else []) + tmp_sigs:
            try:
                os.unlink(path)
            except OSError:
                pass
    return manifest_path + ".minisig"


def _remove_stale_signatures(sig_path, keep):
    directory = os.path.dirname(os.path.abspath(sig_path))
    base = os.path.basename(sig_path)
    keep = {os.path.abspath(path) for path in keep}
    for entry in os.scandir(directory):
        if (entry.name.startswith(base + ".")
                and re.fullmatch(re.escape(base) + r"\.[0-9A-Fa-f]{16}",
                                 entry.name)
                and os.path.abspath(entry.path) not in keep):
            try:
                os.unlink(entry.path)
            except OSError:
                pass


def verify_signature(manifest_path, sig_path, pubkey_path=None):
    """Verify a signature against any configured key and matching sidecars."""
    pubkeys = resolve_image_pubkeys(pubkey_path)
    candidates = [sig_path]
    if os.path.abspath(sig_path) == os.path.abspath(manifest_path + ".minisig"):
        candidates = signature_paths(manifest_path, pubkeys)
    errors = []
    exe = require_minisign()
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        for pub in pubkeys:
            r = subprocess.run(
                [exe, "-V", "-p", pub, "-m", manifest_path, "-x", candidate],
                capture_output=True, text=True)
            if r.returncode == 0:
                return
            errors.append(r.stderr.strip() or r.stdout.strip())
    if not errors:
        raise SignError(f"no minisign signature found for {os.path.basename(manifest_path)}")
    raise SignError(
        f"minisign signature verification FAILED for "
        f"{os.path.basename(manifest_path)}: {'; '.join(errors)}")

def _manifest_entries(manifest_path):
    """Return {basename: (sha256, signed size or None)} from a manifest."""
    entries = {}
    sizes = {}
    with open(manifest_path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue
            if line.startswith("# size "):
                parts = line.split()
                if len(parts) != 4 or parts[:2] != ["#", "size"]:
                    raise SignError(
                        f"{manifest_path}:{lineno}: malformed size field: {raw!r}")
                _marker, _size, name, value = parts
                if (not name or "/" in name or "\\" in name or
                        name in (".", "..")):
                    raise SignError(
                        f"{manifest_path}:{lineno}: size field must name a "
                        f"bare basename, got {name!r}")
                if not value.isascii() or not value.isdigit() or int(value) <= 0:
                    raise SignError(
                        f"{manifest_path}:{lineno}: size must be a positive "
                        f"decimal byte count, got {value!r}")
                if name in sizes:
                    raise SignError(
                        f"{manifest_path}:{lineno}: duplicate size field for {name}")
                sizes[name] = int(value)
                continue
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                raise SignError(
                    f"{manifest_path}:{lineno}: malformed manifest line: {raw!r}")
            digest, name = parts
            name = name.lstrip("*")  # sha256sum binary-mode marker
            if "/" in name or "\\" in name or name in ("", ".", ".."):
                raise SignError(
                    f"{manifest_path}:{lineno}: manifest entry must be a bare "
                    f"basename, got {name!r}")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
                raise SignError(
                    f"{manifest_path}:{lineno}: not a sha256 hex digest: {digest!r}")
            if name in entries:
                raise SignError(
                    f"{manifest_path}:{lineno}: duplicate basename in manifest: {name}")
            entries[name] = (digest.lower(), None)
    if not entries:
        raise SignError(f"{manifest_path}: manifest has no entries")
    for name, size in sizes.items():
        if name not in entries:
            raise SignError(
                f"{manifest_path}: size field references unlisted artifact {name!r}")
        entries[name] = (entries[name][0], size)
    return entries


def parse_manifest(manifest_path):
    """Parse SHA256 values from a sha256sum-format manifest."""
    return {name: digest for name, (digest, _size)
            in _manifest_entries(manifest_path).items()}


def parse_manifest_sizes(manifest_path):
    """Parse {basename: (sha256, size|None)} from a checksum manifest."""
    return _manifest_entries(manifest_path)


def _resolve_pubkeys(pubkey_path):
    return resolve_image_pubkeys(pubkey_path)


def _resolve_pubkey(pubkey_path):
    """Compatibility helper for callers that still need the primary key."""
    return _resolve_pubkeys(pubkey_path)[0]


def verify_and_read(signed_path, sig_path, pubkey_path=None,
                    require_all=False):
    """Verify signed bytes and return the privately staged content.

    By default, any configured key is sufficient for consumers. Publisher
    gates set require_all=True to require a signature from every configured
    key, and require the canonical .minisig to belong to the first key so
    legacy clients continue to verify during overlap. The signed file and all
    signatures are copied into private staging before verification.
    """
    pubkeys = _resolve_pubkeys(pubkey_path)
    exe = require_minisign()
    import shutil as _sh
    import tempfile as _tf
    tmp = _tf.mkdtemp(prefix="xpf-verify-")
    try:
        os.chmod(tmp, 0o700)
        f_copy = os.path.join(tmp, os.path.basename(signed_path))
        _sh.copyfile(signed_path, f_copy)
        canonical = os.path.abspath(signed_path + ".minisig")
        sources = [sig_path] + signature_paths(signed_path, pubkeys)
        sources = list(dict.fromkeys(sources))
        copied = []
        for index, source in enumerate(sources):
            if not os.path.isfile(source):
                continue
            source_abs = os.path.abspath(source)
            if source_abs == canonical:
                dest = f_copy + ".minisig"
            elif source_abs.startswith(canonical + "."):
                dest = f_copy + ".minisig" + source_abs[len(canonical):]
            else:
                dest = os.path.join(tmp, f"extra-{index}.minisig")
            _sh.copyfile(source, dest)
            copied.append(dest)
        if not copied:
            raise SignError(f"no minisign signature found for {os.path.basename(signed_path)}")
        if require_all:
            canonical = os.path.abspath(signed_path + ".minisig")
            if os.path.abspath(sig_path) == canonical:
                canonical_copy = f_copy + ".minisig"
                if not os.path.isfile(canonical_copy):
                    raise SignError(
                        f"canonical signature missing for {os.path.basename(signed_path)}")
                result = subprocess.run(
                    [exe, "-V", "-p", pubkeys[0], "-m", f_copy,
                     "-x", canonical_copy], capture_output=True, text=True)
                if result.returncode != 0:
                    detail = result.stderr.strip() or result.stdout.strip()
                    raise SignError(
                        "canonical .minisig must verify with the first configured "
                        f"key {os.path.basename(pubkeys[0])}: {detail}")
            failures = []
            for pub in pubkeys:
                verified = False
                details = []
                for signature in copied:
                    result = subprocess.run(
                        [exe, "-V", "-p", pub, "-m", f_copy, "-x", signature],
                        capture_output=True, text=True)
                    if result.returncode == 0:
                        verified = True
                        break
                    details.append(result.stderr.strip() or result.stdout.strip())
                if not verified:
                    failures.append(
                        f"{os.path.basename(pub)}: " + "; ".join(details))
            if failures:
                raise SignError(
                    "signature missing or invalid for configured key(s): " +
                    "; ".join(failures))
            with open(f_copy, "rb") as fh:
                return fh.read()
        errors = []
        for signature in copied:
            try:
                verify_signature(f_copy, signature, pubkeys)
                with open(f_copy, "rb") as fh:
                    return fh.read()
            except SignError as e:
                errors.append(str(e))
        raise SignError("; ".join(errors))
    finally:
        _sh.rmtree(tmp, ignore_errors=True)

def verify_manifest_map(manifest_path, sig_path, pubkey_path=None,
                        require_all=False):
    """Verify a signed manifest and parse its verified basename/hash map."""
    data = verify_and_read(manifest_path, sig_path, pubkey_path,
                           require_all=require_all)
    import tempfile as _tf
    tmp = _tf.mkdtemp(prefix="xpf-manifest-")
    try:
        os.chmod(tmp, 0o700)
        p = os.path.join(tmp, "m")
        with open(p, "wb") as fh:
            fh.write(data)
        return parse_manifest(p)
    finally:
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)


def verify_manifest_map_with_sizes(manifest_path, sig_path, pubkey_path=None,
                                   require_all=False):
    """Verify and parse the signed hashes and per-artifact sizes (#10853)."""
    data = verify_and_read(manifest_path, sig_path, pubkey_path,
                           require_all=require_all)
    import tempfile as _tf
    tmp = _tf.mkdtemp(prefix="xpf-manifest-")
    try:
        os.chmod(tmp, 0o700)
        path = os.path.join(tmp, "m")
        with open(path, "wb") as fh:
            fh.write(data)
        return parse_manifest_sizes(path)
    finally:
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)


def verify_image_artifact(path, manifest_path, sig_path, pubkey_path=None):
    """Verify ONE artifact `path` against a signed manifest and RETURN the
    signed digest that authorised it.

    1. verify+parse the manifest from its VERIFIED bytes (TOCTOU-safe).
    2. hash the EXACT `path` and compare to the manifest entry for its
       basename. Missing entry or mismatch -> raise.

    Binds the bytes the caller is about to import/use, not a cwd-relative
    `sha256sum -c` (which could pass against a stale local copy).

    #9170: the return value is the manifest's hex digest, not a bare `True`.
    A caller that needs to PRINT or re-check that digest — `xpf-deploy.py
    fetch --no-import`, which hands the operator a `sha256sum -c` line to run
    later — must take it from HERE. Re-hashing the file afterwards binds the
    bytes at hash time rather than the bytes that passed the signature, and
    the artifact typically sits in a public `--out` another local process can
    write. The value was already computed inside this call; discarding it was
    what forced the second read.
    """
    manifest = verify_manifest_map(manifest_path, sig_path, pubkey_path)
    base = os.path.basename(path)
    if base not in manifest:
        raise SignError(
            f"{base} is not listed in the signed manifest "
            f"{os.path.basename(manifest_path)} — refusing to trust it.")
    actual = sha256_file(path)
    if actual != manifest[base]:
        raise SignError(
            f"{base}: SHA256 MISMATCH — manifest {manifest[base]}, actual "
            f"{actual}. The file does not match the signed checksum.")
    return manifest[base]


def verify_listed_artifact_bytes(path, manifest_path, sig_path, pubkey_path=None):
    """Verify ONE manifest-listed artifact `path` against a signed manifest and
    return its VERIFIED bytes (TOCTOU-safe).

    Like verify_image_artifact, but for a file the caller must READ and act on
    (not merely trust in place): the returned bytes come from a private 0700
    copy whose sha256 was compared to the signed manifest entry, so a
    concurrent swap of the on-disk `path` AFTER the check cannot feed
    unverified bytes to the caller (the Codex-M5/AGY-A4 TOCTOU class the
    verify_and_read primitive already guards for directly-signed files).

    Use this for an artifact that is COVERED by the signed checksum manifest
    but is not itself minisigned — e.g. the mixed-base protocol sidecar
    xpf-<ver>.manifest (#5042), whose ha-protocol / session-sync fields drive
    the deployer's HA session-safety gate and therefore must be read from
    signed bytes."""
    manifest = verify_manifest_map(manifest_path, sig_path, pubkey_path)
    base = os.path.basename(path)
    if base not in manifest:
        raise SignError(
            f"{base} is not listed in the signed manifest "
            f"{os.path.basename(manifest_path)} — refusing to trust it.")
    import shutil as _sh
    import tempfile as _tf
    tmp = _tf.mkdtemp(prefix="xpf-listed-")
    try:
        os.chmod(tmp, 0o700)
        copy = os.path.join(tmp, base)
        _sh.copyfile(path, copy)
        actual = sha256_file(copy)
        if actual != manifest[base]:
            raise SignError(
                f"{base}: SHA256 MISMATCH — manifest {manifest[base]}, actual "
                f"{actual}. The file does not match the signed checksum.")
        with open(copy, "rb") as fh:
            return fh.read()
    finally:
        _sh.rmtree(tmp, ignore_errors=True)


# ── CLI shim for the test gate + manual use ──────────────────────────────
def _main(argv):
    import argparse
    p = argparse.ArgumentParser(description="xpf image signing helper (#1924)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sign-manifest", help="write+sign a per-version manifest")
    s.add_argument("--manifest", required=True)
    s.add_argument("--seckey", action="append", required=True,
                   help="minisign secret key (repeat to dual-sign during rotation)")
    s.add_argument("--comment", default=None)
    s.add_argument("files", nargs="+")

    sf = sub.add_parser("sign-file", help="sign a directly-signed publish file")
    sf.add_argument("--seckey", action="append", required=True,
                    help="minisign secret key (repeat to dual-sign)")
    sf.add_argument("--comment", default=None)
    sf.add_argument("--sig", default=None)
    sf.add_argument("file")

    vf = sub.add_parser("verify-file", help="verify a directly-signed publish file")
    vf.add_argument("--sig", default=None)
    vf.add_argument("--pubkey", action="append", default=None,
                    help="trusted image public key (repeat to accept rotation overlap)")
    vf.add_argument("file")

    v = sub.add_parser("verify", help="verify ONE artifact against a signed manifest")
    v.add_argument("--manifest", required=True)
    v.add_argument("--sig", default=None)
    v.add_argument("--pubkey", action="append", default=None,
                   help="trusted image public key (repeat to accept rotation overlap)")
    v.add_argument("file")

    a = p.parse_args(argv)
    try:
        if a.cmd == "sign-file":
            signatures = sign_manifest(a.file, a.seckey, a.comment, a.sig)
            print(f"signed: {a.file} -> {signatures}")
            return 0
        if a.cmd == "verify-file":
            verify_signature(a.file, a.sig or (a.file + ".minisig"), a.pubkey)
            print(f"OK: {os.path.basename(a.file)} signature verified")
            return 0
        if a.cmd == "sign-manifest":
            # #9920 F-063: fail-CLOSED for bake manifests. An xpf-<ver>.SHA256SUMS
            # feeds publish discovery, so its set + provenance flags are asserted
            # BEFORE anything is written. Other basenames are fixture scratch
            # (never published) and stay permissive: a scratch-signed reduced
            # manifest copied over a bake name is refused downstream —
            # gate_images requires the signed set to equal the bake four-file
            # set (parent review #10119).
            recorded_hashes = None
            if is_bake_manifest(a.manifest):
                recorded_hashes = assert_bake_set(a.manifest, a.files)
            sig = write_and_sign_manifest(
                a.manifest, a.files, a.seckey, a.comment,
                recorded_hashes=recorded_hashes)
            print(f"signed: {a.manifest} -> {sig}")
            return 0
        if a.cmd == "verify":
            sig = a.sig or (a.manifest + ".minisig")
            verify_image_artifact(a.file, a.manifest, sig, a.pubkey)
            print(f"OK: {os.path.basename(a.file)} verified against "
                  f"{os.path.basename(a.manifest)}")
            return 0
    except SignError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        # #9920 F-064: a missing/unreadable input is an operator error with an
        # actionable message, not an unhandled traceback.
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
