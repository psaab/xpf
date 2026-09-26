#!/bin/sh
# xpf signed-distribution self-test (#1924) — the local roundtrip gate.
#
# Proves, end to end, with a THROWAWAY keypair (generated in a temp dir,
# never committed) and NO hosting:
#   1. sign a per-version manifest over fake qcow2 + metadata;
#   2. verify each artifact against the signed manifest (PASS);
#   3. tamper-detection: a modified artifact, a tampered manifest, a
#      tampered signature, and a wrong pubkey each MUST FAIL verify;
#   4. build a flat signed apt repo over a fake .deb and verify InRelease;
#   5. install.sh --dry-run preflight/source rendering.
#
# Exit 0 only if every positive check passes AND every tamper check fails.
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DIST="$ROOT/scripts/dist"
PY=python3
PASS=0
FAIL=0

ok()   { echo "  PASS: $*"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); }
info() { echo "==> $*"; }

command -v minisign >/dev/null 2>&1 || { echo "SKIP: minisign not installed (apt-get install minisign)"; exit 77; }
command -v gpg >/dev/null 2>&1 || { echo "SKIP: gpg not installed"; exit 77; }
command -v apt-ftparchive >/dev/null 2>&1 || { echo "SKIP: apt-ftparchive not installed (apt-utils)"; exit 77; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/xpf-dist-selftest.XXXXXX")
GNUPGHOME="$WORK/gnupg"; export GNUPGHOME
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

VER="0.0.0-selftest"
OUT="$WORK/dist"
mkdir -p "$OUT"

# ── throwaway image keypair ───────────────────────────────────────────────
info "1. generate throwaway minisign image keypair (passwordless)"
minisign -G -W -p "$WORK/img.pub" -s "$WORK/img.sec" >/dev/null 2>&1
WRONGPUB="$WORK/wrong.pub"
minisign -G -W -p "$WRONGPUB" -s "$WORK/wrong.sec" >/dev/null 2>&1

# ── fake artifacts + signed manifest ──────────────────────────────────────
info "2. create fake artifacts + signed per-version manifest"
QCOW="$OUT/xpf-$VER.qcow2"
META="$OUT/xpf-$VER.incus-metadata.tar.gz"
head -c 4096 /dev/urandom > "$QCOW"
head -c 1024 /dev/urandom > "$META"
MANIFEST="$OUT/xpf-$VER.SHA256SUMS"
# #4904 A: the signed provenance sidecar (xpf-<ver>.manifest). Real bakes bind
# `validated: true|false` here and cover it with the signed SHA256SUMS (#5042);
# publish.py's gate_provenance REQUIRES validated: true. Model that in the
# baseline signed set so the positive publish cases below exercise the real
# shape (validated:false is exercised as a negative in section 8i).
SIDECAR="$OUT/xpf-$VER.manifest"
# #6500: the signed record must also say what the image SHIPS — the manifest's
# `guest_kernel` (the IMAGE's kernel, not the build host's bake_host_kernel)
# and an xpf-<ver>.pkgs inventory sidecar covered by the same SHA256SUMS.
# gate_provenance requires both, fail-closed, so the baseline signed set below
# must carry them or every POSITIVE publish case would fail for the wrong
# reason. The negatives are exercised in section 8j.
GUEST_KERNEL="7.0.0-15-generic"
# prov_sidecar <path> <validated> [guest_kernel; "-" omits the line]
prov_sidecar() {
    _gk=${3:-$GUEST_KERNEL}
    printf 'version: %s\nbase_image_pinned: true\nvalidated: %s\n' "$VER" "$2" > "$1"
    [ "$_gk" = "-" ] || printf 'guest_kernel: %s\n' "$_gk" >> "$1"
}
# make_pkgs <path> [package count] — an inventory in the real format. The
# default count clears image_inventory.MIN_PACKAGES; a small count models the
# HOLLOW record the gate must refuse.
make_pkgs() {
    _n=${2:-60}
    {
        echo "# xpf appliance image inventory"
        echo "guest_kernel: ${3:-$GUEST_KERNEL}"
        echo "packages:"
        _i=0
        while [ "$_i" -lt "$_n" ]; do echo "pkg$_i=1.0-$_i"; _i=$((_i + 1)); done
        echo "xpf=$VER"
    } > "$1"
}
PKGS="$OUT/xpf-$VER.pkgs"
prov_sidecar "$SIDECAR" true
make_pkgs "$PKGS"
XPF_IMAGE_PUBKEY="$WORK/img.pub" \
  $PY "$DIST/sign.py" sign-manifest --manifest "$MANIFEST" \
      --seckey "$WORK/img.sec" --comment "selftest" "$QCOW" "$META" "$SIDECAR" \
      "$PKGS" >/dev/null
[ -f "$MANIFEST.minisig" ] && ok "manifest signed" || bad "manifest not signed"

verify() {  # verify <file> with pubkey; prints OK/err, returns rc
    XPF_IMAGE_PUBKEY="$1" $PY "$DIST/sign.py" verify \
        --manifest "$MANIFEST" --pubkey "$1" "$2" >/dev/null 2>&1
}

# ── 3. positive verification ──────────────────────────────────────────────
info "3. positive verification (must PASS)"
verify "$WORK/img.pub" "$QCOW"  && ok "qcow2 verifies"     || bad "qcow2 should verify"
verify "$WORK/img.pub" "$META"  && ok "metadata verifies"  || bad "metadata should verify"

# Per-file: qcow2-only operator can verify without metadata present.
QONLY="$WORK/qonly"; mkdir -p "$QONLY"
cp "$QCOW" "$MANIFEST" "$MANIFEST.minisig" "$QONLY/"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" verify \
     --manifest "$QONLY/xpf-$VER.SHA256SUMS" --pubkey "$WORK/img.pub" \
     "$QONLY/xpf-$VER.qcow2" >/dev/null 2>&1; then
    ok "qcow2-only verifies without metadata present"
else
    bad "qcow2-only should verify (per-file)"
fi

# ── 4. tamper-detection (each MUST FAIL) ──────────────────────────────────
info "4. tamper-detection (each MUST FAIL verify)"

# 4a. modified artifact
TQ="$WORK/tamper"; mkdir -p "$TQ"
cp "$MANIFEST" "$MANIFEST.minisig" "$TQ/"
head -c 4096 /dev/urandom > "$TQ/xpf-$VER.qcow2"   # different bytes
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" verify \
     --manifest "$TQ/xpf-$VER.SHA256SUMS" --pubkey "$WORK/img.pub" \
     "$TQ/xpf-$VER.qcow2" >/dev/null 2>&1; then
    bad "modified qcow2 MUST fail verify but PASSED"
else
    ok "modified qcow2 fails verify"
fi

# 4b. tampered manifest (flip a hash) — signature must no longer match
TM="$WORK/tmanifest"; mkdir -p "$TM"
cp "$QCOW" "$META" "$MANIFEST.minisig" "$TM/"
sed 's/^./0/' "$MANIFEST" > "$TM/xpf-$VER.SHA256SUMS"   # corrupt first hex char
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" verify \
     --manifest "$TM/xpf-$VER.SHA256SUMS" \
     --sig "$TM/xpf-$VER.SHA256SUMS.minisig" --pubkey "$WORK/img.pub" \
     "$TM/xpf-$VER.qcow2" >/dev/null 2>&1; then
    bad "tampered manifest MUST fail verify but PASSED"
else
    ok "tampered manifest fails verify"
fi

# 4c. tampered signature
TS="$WORK/tsig"; mkdir -p "$TS"
cp "$QCOW" "$META" "$MANIFEST" "$TS/"
sed '$ s/.$/X/' "$MANIFEST.minisig" > "$TS/xpf-$VER.SHA256SUMS.minisig" 2>/dev/null \
  || tr 'A' 'B' < "$MANIFEST.minisig" > "$TS/xpf-$VER.SHA256SUMS.minisig"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" verify \
     --manifest "$TS/xpf-$VER.SHA256SUMS" --pubkey "$WORK/img.pub" \
     "$TS/xpf-$VER.qcow2" >/dev/null 2>&1; then
    bad "tampered signature MUST fail verify but PASSED"
else
    ok "tampered signature fails verify"
fi

# 4d. wrong pubkey
if verify "$WRONGPUB" "$QCOW"; then
    bad "wrong pubkey MUST fail verify but PASSED"
else
    ok "wrong pubkey fails verify"
fi

# ── 5. flat signed apt repo + InRelease verify ─────────────────────────────
info "5. flat signed apt repo build + InRelease verify"
# Throwaway gpg archive key (unattended, no passphrase).
cat > "$WORK/gpg-batch" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: xpf selftest archive
Name-Email: selftest@xpf.invalid
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$WORK/gpg-batch" >/dev/null 2>&1
GPGKEY=$(gpg --batch --list-keys --with-colons selftest@xpf.invalid | awk -F: '/^fpr:/{print $10; exit}')
[ -n "$GPGKEY" ] && ok "archive key generated ($GPGKEY)" || { bad "archive key gen failed"; }
ARCHASC="$WORK/archive.asc"
gpg --batch --armor --export selftest@xpf.invalid > "$ARCHASC"

# Fake .deb carries the keyring payload checked by publish.py; apt-ftparchive
# only needs control metadata.
DEBDIR="$WORK/pkg"; mkdir -p "$DEBDIR/DEBIAN"
cat > "$DEBDIR/DEBIAN/control" <<EOF
Package: xpf-appliance
Version: $VER
Architecture: amd64
Maintainer: selftest <selftest@xpf.invalid>
Description: xpf selftest fake package
EOF
mkdir -p "$DEBDIR/usr/share/keyrings"
cp "$ARCHASC" "$DEBDIR/usr/share/keyrings/xpf-archive-keyring.asc"
mkdir -p "$ROOT/dist-deb"
FAKEDEB="$ROOT/dist-deb/xpf-appliance_${VER}_amd64.selftest.deb"
dpkg-deb --build "$DEBDIR" "$FAKEDEB" >/dev/null 2>&1
cleanup_deb() { rm -f "$FAKEDEB"; }
trap 'cleanup; cleanup_deb' EXIT INT TERM

if XPF_GPG_KEY="$GPGKEY" XPF_APT_VALID_DAYS=365 \
   sh "$DIST/build-apt-repo.sh" --out "$OUT" --suite stable --debs "$FAKEDEB" >/dev/null 2>&1; then
    ok "flat signed apt repo built"
else
    bad "apt repo build failed"
fi

INREL="$OUT/apt/dists/stable/InRelease"
if [ -f "$INREL" ] && gpg --batch --verify "$INREL" >/dev/null 2>&1; then
    ok "InRelease signature verifies"
else
    bad "InRelease missing or signature failed"
fi
# Valid-Until must actually be emitted (Codex-M3 regression).
if grep -q "^Valid-Until:" "$OUT/apt/dists/stable/Release"; then
    ok "Release carries Valid-Until"
else
    bad "Release missing Valid-Until (ValidTime knob regression)"
fi
# Negative: a tampered InRelease must fail.
if [ -f "$INREL" ]; then
    cp "$INREL" "$WORK/InRelease.tampered"
    sed 's/Codename: stable/Codename: EVIL/' "$INREL" > "$WORK/InRelease.tampered" || true
    if gpg --batch --verify "$WORK/InRelease.tampered" >/dev/null 2>&1; then
        bad "tampered InRelease MUST fail verify but PASSED"
    else
        ok "tampered InRelease fails verify"
    fi
fi

# ── 5b. publish gate fail-closed (Codex-H1 / AGY-A2) ──────────────────────
info "5b. publish gate fail-closed on an unsigned manifest"
PG="$WORK/pgate"; mkdir -p "$PG"
printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  xpf-9.9.9.qcow2\n' \
    > "$PG/xpf-9.9.9.SHA256SUMS"   # NO .minisig
if $PY "$DIST/publish.py" --dist "$PG" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse an unsigned manifest but PASSED"
else
    ok "publish refuses an unsigned manifest"
fi

# Orphan image artifact NOT covered by any manifest (Codex-r2-1).
PGO="$WORK/pgorphan"; mkdir -p "$PGO"
cp "$QCOW" "$META" "$SIDECAR" "$PKGS" "$MANIFEST" "$MANIFEST.minisig" "$PGO/"
head -c 64 /dev/urandom > "$PGO/xpf-9.9.9.qcow2"   # orphan, no manifest covers it
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$PGO" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse an orphan image artifact but PASSED"
else
    ok "publish refuses an orphan image artifact"
fi

# Symlink under the image publish root (Codex-r4).
PGS="$WORK/pgsym"; mkdir -p "$PGS"
cp "$QCOW" "$META" "$SIDECAR" "$PKGS" "$MANIFEST" "$MANIFEST.minisig" "$PGS/"
ln -s /etc/passwd "$PGS/sneaky.qcow2"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$PGS" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse a symlink in the image set but PASSED"
else
    ok "publish refuses a symlink in the image set"
fi

# ── 5c. apt channel isolation (#4201, HB165 H-4) ──────────────────────────
info "5c. apt channel isolation: a stable rebuild after edge must not list edge"
EDGEDEB="$ROOT/dist-deb/xpf-appliance_0.0.0-edge.selftest.deb"
EDGEDIR="$WORK/pkg-edge"; mkdir -p "$EDGEDIR/DEBIAN"
cat > "$EDGEDIR/DEBIAN/control" <<EOF
Package: xpf-appliance
Version: 0.0.0-edge
Architecture: amd64
Maintainer: selftest <selftest@xpf.invalid>
Description: xpf selftest edge package
EOF
dpkg-deb --build "$EDGEDIR" "$EDGEDEB" >/dev/null 2>&1
trap 'cleanup; cleanup_deb; rm -f "$EDGEDEB"' EXIT INT TERM
XPF_GPG_KEY="$GPGKEY" sh "$DIST/build-apt-repo.sh" --out "$OUT" --suite edge \
    --debs "$EDGEDEB" >/dev/null 2>&1 || bad "edge repo build failed"
# Rebuild stable AFTER edge exists — the exact H-4 trigger.
XPF_GPG_KEY="$GPGKEY" sh "$DIST/build-apt-repo.sh" --out "$OUT" --suite stable \
    --debs "$FAKEDEB" >/dev/null 2>&1 || bad "stable rebuild failed"
SPKG="$OUT/apt/dists/stable/main/binary-amd64/Packages"
if grep -q "Version: 0.0.0-edge" "$SPKG"; then
    bad "stable Packages lists the EDGE version (channel bleed)"
else
    ok "stable Packages does not list the edge version (isolated per-suite pool)"
fi
if grep -q "^Filename: pool/stable/main/x/xpf/" "$SPKG"; then
    ok "stable Filename points at the suite-scoped pool"
else
    bad "stable Filename is not suite-scoped"
fi

# ── 5d. publish key-agreement gate (#4203, HB165 H-15) ────────────────────
info "5d. publish key-agreement: installer/keyring/InRelease signer must match"
mk_installsh() {  # mk_installsh <dest-install.sh> <armored-key-file>
    { echo '#!/bin/sh'
      echo "ARCHIVE_KEY=\$(cat <<'KEYEOF'"
      cat "$2"
      echo "KEYEOF"
      echo ")"
    } > "$1"
}
# Positive: install.sh embeds the SIGNER key -> gate passes.
KAOK="$WORK/kagree-ok"; mkdir -p "$KAOK"; cp -r "$OUT/apt" "$KAOK/apt"
mk_installsh "$KAOK/install.sh" "$ARCHASC"
if XPF_ARCHIVE_PUBKEY="$ARCHASC" $PY "$DIST/publish.py" \
     --dist "$KAOK" --channel stable --no-image >/dev/null 2>&1; then
    ok "publish passes when install.sh embeds the signer key"
else
    bad "publish should PASS when install.sh embeds the signer key"
fi
# Negative: a DIFFERENT (stale) embedded key must be rejected.
cat > "$WORK/gpg-batch2" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: xpf selftest stale
Name-Email: stale@xpf.invalid
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$WORK/gpg-batch2" >/dev/null 2>&1
gpg --batch --armor --export stale@xpf.invalid > "$WORK/stale.asc"
KABAD="$WORK/kagree-bad"; mkdir -p "$KABAD"; cp -r "$OUT/apt" "$KABAD/apt"
mk_installsh "$KABAD/install.sh" "$WORK/stale.asc"
if XPF_ARCHIVE_PUBKEY="$ARCHASC" $PY "$DIST/publish.py" \
     --dist "$KABAD" --channel stable --no-image >/dev/null 2>&1; then
    bad "publish MUST reject a stale install.sh key but PASSED"
else
    ok "publish rejects install.sh embedding a non-signer key"
fi
# Regression (#10737): the repo-side archive pubkey and installer are current,
# but a real, stale keyring in the pooled .deb would brick upgraded hosts. The
# failure must identify the packaged payload, not reject an unrelated gate.
cp "$WORK/stale.asc" "$DEBDIR/usr/share/keyrings/xpf-archive-keyring.asc"
STALEDEB="$WORK/xpf-appliance-stale.deb"
dpkg-deb --build "$DEBDIR" "$STALEDEB" >/dev/null 2>&1
KAPAYLOAD="$WORK/kagree-stale-payload"; mkdir -p "$KAPAYLOAD"
if XPF_GPG_KEY="$GPGKEY" XPF_APT_VALID_DAYS=365 \
   sh "$DIST/build-apt-repo.sh" --out "$KAPAYLOAD" --suite stable \
      --debs "$STALEDEB" >/dev/null 2>&1; then
    mk_installsh "$KAPAYLOAD/install.sh" "$ARCHASC"
    if XPF_ARCHIVE_PUBKEY="$ARCHASC" $PY "$DIST/publish.py" \
         --dist "$KAPAYLOAD" --channel stable --no-image \
         >"$WORK/stale-payload.out" 2>&1; then
        bad "publish MUST reject a stale pooled .deb keyring but PASSED"
    elif grep -q "packaged keyring from pooled package" \
             "$WORK/stale-payload.out"; then
        ok "publish rejects a stale keyring inside the pooled .deb"
    else
        bad "publish failed for the wrong reason on a stale pooled keyring"
        cat "$WORK/stale-payload.out" >&2
    fi
else
    bad "could not build a signed apt fixture with a stale pooled keyring"
fi

# Negative: InRelease signer absent from the packaged keyring must be rejected.
if XPF_ARCHIVE_PUBKEY="$WORK/stale.asc" $PY "$DIST/publish.py" \
     --dist "$KAOK" --channel stable --no-image >/dev/null 2>&1; then
    bad "publish MUST reject a signer absent from the keyring but PASSED"
else
    ok "publish rejects an InRelease signer absent from the packaged keyring"
fi

# ── 5e. deb ships the kernel-promote OnFailure= recovery unit (#4202, H-6) ─
info "5e. packaging: the promote unit's OnFailure= recovery unit ships in the .deb"
PROMOTE="$ROOT/scripts/image/xpf-kernel-promote.service"
ONFAIL=$(sed -n 's/^OnFailure=//p' "$PROMOTE" | head -n1)
if [ -n "$ONFAIL" ] && [ -f "$ROOT/scripts/image/$ONFAIL" ] \
   && grep -q "cp scripts/image/$ONFAIL" "$ROOT/debian/rules" \
   && grep -q "name=${ONFAIL%.service}" "$ROOT/debian/rules"; then
    ok "debian/rules stages the OnFailure= recovery unit ($ONFAIL)"
else
    bad "debian/rules does NOT stage the promote OnFailure= unit ($ONFAIL) — dangling recovery reference"
fi

# ── 6. install.sh dry-run ──────────────────────────────────────────────────
info "6. install.sh --dry-run (preflight + source rendering)"
if XPF_DRY_RUN=1 XPF_APT_BASE_URL="https://example.invalid/apt" XPF_CHANNEL=stable \
   sh "$DIST/install.sh" >"$WORK/install.out" 2>&1; then
    if grep -q "preflight OK" "$WORK/install.out" \
       && grep -q "Suites: stable" "$WORK/install.out"; then
        ok "install.sh dry-run preflight + source render OK"
    else
        bad "install.sh dry-run output missing expected lines"; cat "$WORK/install.out" >&2
    fi
else
    # Dry-run on THIS host may legitimately fail preflight (kernel < 6.18 etc.).
    # That is a valid PASS for the preflight logic — assert it failed for a
    # preflight reason, not a script error.
    if grep -q "ERROR:" "$WORK/install.out" && \
       grep -qE "kernel|arch|distro|os-release" "$WORK/install.out"; then
        ok "install.sh dry-run preflight correctly refused this host"
    else
        bad "install.sh dry-run errored unexpectedly"; cat "$WORK/install.out" >&2
    fi
fi

# ── 7. install.sh publish-time bake (H-2 / H-14) ───────────────────────────
info "7. install.sh stamp (bake key + apt URL) + baked-default render"
# A fabricated non-placeholder armored block is enough: stamp checks BEGIN/END
# + not-placeholder, and gate_images verifies install.sh's MINISIGN signature
# (independent of the OpenPGP archive key baked here).
AKEY="$WORK/archive.asc"
cat > "$AKEY" <<'EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZmFakeArchiveKeyForSelftestOnlyNotARealKeyAAAAAAAAAAAAAAAAAAAA
=SelF
-----END PGP PUBLIC KEY BLOCK-----
EOF
BAKED="$WORK/install.baked.sh"
if $PY "$DIST/publish.py" stamp-installer --out "$BAKED" \
     --archive-key "$AKEY" --apt-base-url "https://dl.selftest.invalid/apt" \
     --channel stable >/dev/null 2>&1; then
    ok "stamp-installer bakes install.sh"
else
    bad "stamp-installer failed"
fi
if ! grep -q "%%XPF_APT_BASE_URL%%" "$BAKED" 2>/dev/null \
   && ! grep -q "%%XPF_CHANNEL%%" "$BAKED" 2>/dev/null; then
    ok "baked install.sh has no unsubstituted marker"
else
    bad "baked install.sh still carries a %% marker"
fi
# Baked install.sh renders the baked apt URL with NO env (the H-2 fix — a piped
# one-liner cannot deliver env). Accept a rendered baked URI OR a host preflight
# refusal, but NEVER a missing-URL die.
if XPF_DRY_RUN=1 sh "$BAKED" >"$WORK/baked.out" 2>&1; then
    if grep -q "URIs: https://dl.selftest.invalid/apt" "$WORK/baked.out"; then
        ok "baked install.sh renders the baked apt URL with no env"
    else
        bad "baked install.sh did not render the baked URL"; cat "$WORK/baked.out" >&2
    fi
else
    if grep -q "URIs: https://dl.selftest.invalid/apt" "$WORK/baked.out" \
       || grep -qE "kernel|arch|distro|os-release" "$WORK/baked.out"; then
        ok "baked install.sh reached the baked URL (or host preflight refused)"
    else
        bad "baked install.sh errored without the baked URL"; cat "$WORK/baked.out" >&2
    fi
fi
# stamp refuses a placeholder archive key.
if $PY "$DIST/publish.py" stamp-installer --out "$WORK/np.sh" \
     --archive-key "$DIST/xpf-archive-keyring.asc.placeholder" \
     --apt-base-url "https://x.invalid/apt" >/dev/null 2>&1; then
    bad "stamp MUST refuse a placeholder archive key but PASSED"
else
    ok "stamp refuses a placeholder archive key"
fi
# stamp refuses a malicious apt URL that would inject shell into the SIGNED,
# root-run install.sh (#5685 / M40). A single quote breaks out of install.sh's
# single-quoted literal; the value must be validated before stamping.
INJ="$WORK/inj.sh"
if $PY "$DIST/publish.py" stamp-installer --out "$INJ" \
     --archive-key "$AKEY" \
     --apt-base-url "https://x.invalid/apt'; touch $WORK/pwned #" \
     >/dev/null 2>&1; then
    bad "stamp MUST refuse a shell-injecting apt URL but PASSED"
elif [ -f "$INJ" ] && grep -q "touch $WORK/pwned" "$INJ" 2>/dev/null; then
    bad "shell-injecting apt URL was baked into install.sh (#5685 gate missing)"
else
    ok "stamp refuses a shell-injecting apt URL (#5685)"
fi
rm -f "$WORK/pwned"

# ── 8. publish gate: install.sh mandatory + stamped + signed ────────────────
info "8. publish gate — install.sh mandatory, stamped, signed"
GD="$WORK/gate"; mkdir -p "$GD"
cp "$QCOW" "$META" "$SIDECAR" "$PKGS" "$MANIFEST" "$MANIFEST.minisig" "$GD/"
XPF_SIGN_SECKEY="$WORK/img.sec" $PY "$DIST/publish.py" make-latest \
    --channel stable --version "$VER" --dist "$GD" >/dev/null 2>&1
# 8a. install.sh MISSING -> refuse (mandatory).
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GD" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST require install.sh but PASSED with it missing"
else
    ok "publish requires install.sh (mandatory)"
fi
# 8b. unstamped install.sh (placeholder key) -> refuse.
cp "$DIST/install.sh" "$GD/install.sh"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GD" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse an unstamped install.sh but PASSED"
else
    ok "publish refuses an unstamped (placeholder) install.sh"
fi
# 8c. stamped install.sh with an unsubstituted apt-URL marker -> refuse (H-2).
$PY "$DIST/publish.py" stamp-installer --out "$GD/install.sh" \
    --archive-key "$AKEY" --apt-base-url "https://dl.selftest.invalid/apt" \
    --channel stable >/dev/null 2>&1
sed 's#https://dl.selftest.invalid/apt#%%XPF_APT_BASE_URL%%#' "$GD/install.sh" \
    > "$WORK/marker.sh" && cp "$WORK/marker.sh" "$GD/install.sh"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GD" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse an unsubstituted apt-URL marker but PASSED"
else
    ok "publish refuses an unsubstituted apt-URL marker"
fi
# 8d. stamped but UNSIGNED -> refuse (missing .minisig).
$PY "$DIST/publish.py" stamp-installer --out "$GD/install.sh" \
    --archive-key "$AKEY" --apt-base-url "https://dl.selftest.invalid/apt" \
    --channel stable >/dev/null 2>&1
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GD" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse a stamped-but-unsigned install.sh but PASSED"
else
    ok "publish refuses a stamped-but-unsigned install.sh"
fi
# 8e. stamped + SIGNED -> full gate PASSES.
minisign -S -W -s "$WORK/img.sec" -m "$GD/install.sh" \
    -x "$GD/install.sh.minisig" >/dev/null 2>&1
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GD" --channel stable --no-apt >/dev/null 2>&1; then
    ok "publish gate PASSES a stamped + signed install.sh"
else
    bad "publish gate MUST pass a stamped + signed install.sh but FAILED"
fi
# 8f. --no-installer opts out of the requirement.
rm -f "$GD/install.sh" "$GD/install.sh.minisig"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GD" --channel stable --no-apt --no-installer >/dev/null 2>&1; then
    ok "publish --no-installer opts out of the install.sh requirement"
else
    bad "publish --no-installer MUST pass without install.sh but FAILED"
fi

# ── 8g. HB165 H-5: default-deny sweep refuses a stray non-image file ────────
info "8g. publish default-deny sweep refuses a stray file under dist/ (HB165 H-5)"
GOOD="$WORK/hb165"; mkdir -p "$GOOD"
cp "$QCOW" "$META" "$SIDECAR" "$PKGS" "$MANIFEST" "$MANIFEST.minisig" "$GOOD/"
XPF_SIGN_SECKEY="$WORK/img.sec" $PY "$DIST/publish.py" make-latest \
    --channel stable --version "$VER" --dist "$GOOD" >/dev/null 2>&1
$PY "$DIST/publish.py" stamp-installer --out "$GOOD/install.sh" \
    --archive-key "$AKEY" --apt-base-url "https://dl.selftest.invalid/apt" \
    --channel stable >/dev/null 2>&1
minisign -S -W -s "$WORK/img.sec" -m "$GOOD/install.sh" \
    -x "$GOOD/install.sh.minisig" >/dev/null 2>&1
# Baseline: the clean signed set (image + manifest + install.sh + latest.json)
# passes the default-deny sweep.
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GOOD" --channel stable --no-apt >/dev/null 2>&1; then
    ok "clean signed image set passes the default-deny sweep"
else
    bad "clean signed image set MUST pass the default-deny sweep but FAILED"
fi
# H-5: an unsigned .deb staged under the publish root must be REFUSED — the
# whole dist/ tree is uploaded to the image URL, and the old suffix-shaped
# sweep skipped every non-image file.
mkdir -p "$GOOD/deb"
printf 'not-a-real-signed-package\n' > "$GOOD/deb/xpf_0.0.0_amd64.deb"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GOOD" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse an unsigned .deb under dist/ but PASSED (H-5)"
else
    ok "publish refuses an unsigned .deb under the image publish root (H-5)"
fi
rm -rf "$GOOD/deb"

# ── 8h. HB165 H-13: every channel's latest.json is signature-gated ──────────
info "8h. publish signature-gates every channel's latest.json (HB165 H-13)"
# An UNSIGNED edge pointer beside the signed stable pointer must be refused,
# even when publishing --channel stable (the whole tree is uploaded).
mkdir -p "$GOOD/edge"
printf '{"channel":"edge","version":"%s"}\n' "$VER" > "$GOOD/edge/latest.json"
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GOOD" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse an unsigned edge latest.json but PASSED (H-13)"
else
    ok "publish refuses an unsigned non-target channel latest.json (H-13)"
fi
# A properly SIGNED edge pointer passes the whole gate.
XPF_SIGN_SECKEY="$WORK/img.sec" $PY "$DIST/publish.py" make-latest \
    --channel edge --version "$VER" --dist "$GOOD" >/dev/null 2>&1
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$GOOD" --channel stable --no-apt >/dev/null 2>&1; then
    ok "publish passes when the edge latest.json is properly signed (H-13)"
else
    bad "publish MUST pass a signed edge latest.json but FAILED (H-13)"
fi

# #9920 F-063: sign a manifest WITHOUT the sign.py gate — for fixtures that
# MODEL a signed-but-bad set reaching publish. sign-manifest now refuses
# non-conforming xpf-*.SHA256SUMS by design, so these legs build the manifest
# with sha256sum + minisign directly (the primitives sign.py wraps). publish
# must still refuse such sets: they model old tooling / a key-holder's output.
# direct_sign <dir> <ver> <artifact>... — writes xpf-<ver>.SHA256SUMS + .minisig.
direct_sign() {
    _dd=$1; _vv=$2; shift 2
    _names=
    for _f in "$@"; do _names="$_names $(basename "$_f")"; done
    # Word-split of basenames is intentional.
    # shellcheck disable=SC2086
    (cd "$_dd" && sha256sum $_names > "xpf-$_vv.SHA256SUMS")
    minisign -S -W -s "$WORK/img.sec" -m "$_dd/xpf-$_vv.SHA256SUMS" \
        -x "$_dd/xpf-$_vv.SHA256SUMS.minisig" >/dev/null 2>&1
}

# ── 8i. #4904 A: publish REFUSES a --skip-validate (validated:false) image ──
info "8i. publish provenance gate — validated:false is refused"
PROV="$WORK/prov"; mkdir -p "$PROV"
cp "$QCOW" "$META" "$PROV/"
# A signed image set that is byte-shape-identical to a release but whose signed
# provenance sidecar says validated:false (a --skip-validate bake).
# It carries a COMPLETE #6500 inventory on purpose: this leg must be refused
# for validated:false, not for a missing inventory. A negative that can be
# satisfied by the wrong cause stops testing what it names.
prov_sidecar "$PROV/xpf-$VER.manifest" false
make_pkgs "$PROV/xpf-$VER.pkgs"
# #9920: validated:false is refused by sign-manifest itself now, so this
# publish-negative fixture is built with the direct primitives.
direct_sign "$PROV" "$VER" "$PROV/xpf-$VER.qcow2" \
    "$PROV/xpf-$VER.incus-metadata.tar.gz" "$PROV/xpf-$VER.manifest" \
    "$PROV/xpf-$VER.pkgs"
XPF_SIGN_SECKEY="$WORK/img.sec" $PY "$DIST/publish.py" make-latest \
    --channel stable --version "$VER" --dist "$PROV" >/dev/null 2>&1
$PY "$DIST/publish.py" stamp-installer --out "$PROV/install.sh" \
    --archive-key "$AKEY" --apt-base-url "https://dl.selftest.invalid/apt" \
    --channel stable >/dev/null 2>&1
minisign -S -W -s "$WORK/img.sec" -m "$PROV/install.sh" \
    -x "$PROV/install.sh.minisig" >/dev/null 2>&1
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$PROV" --channel stable --no-apt >/dev/null 2>&1; then
    bad "publish MUST refuse a validated:false image but PASSED (#4904 A)"
else
    ok "publish refuses a validated:false (--skip-validate) image (#4904 A)"
fi
prov_sidecar "$PROV/xpf-$VER.manifest" true
# A content change after the first signature is a drift, even when the flag
# is repaired. #10120 requires a fresh bake/sign rather than laundering the
# changed sidecar through re-sign.
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" sign-manifest \
     --manifest "$PROV/xpf-$VER.SHA256SUMS" --seckey "$WORK/img.sec" \
     --comment "selftest-drift" "$PROV/xpf-$VER.qcow2" \
     "$PROV/xpf-$VER.incus-metadata.tar.gz" "$PROV/xpf-$VER.manifest" \
     "$PROV/xpf-$VER.pkgs" >/dev/null 2>&1; then
    bad "re-sign MUST refuse repaired-but-drifted sidecar (#10120)"
else
    ok "re-sign refuses repaired-but-drifted sidecar (#10120)"
fi
# A fresh manifest is the positive path after that deliberate drift.
rm -f "$PROV/xpf-$VER.SHA256SUMS" "$PROV/xpf-$VER.SHA256SUMS.minisig"
XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" sign-manifest \
    --manifest "$PROV/xpf-$VER.SHA256SUMS" --seckey "$WORK/img.sec" \
    --comment "selftest-validated" "$PROV/xpf-$VER.qcow2" \
    "$PROV/xpf-$VER.incus-metadata.tar.gz" "$PROV/xpf-$VER.manifest" \
    "$PROV/xpf-$VER.pkgs" >/dev/null
if XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
     --dist "$PROV" --channel stable --no-apt >/dev/null 2>&1; then
    ok "publish passes the same set once validated:true (#4904 A control)"
else
    bad "publish MUST pass a validated:true image but FAILED (#4904 A control)"
fi

# ── 8j. #6500: the signed record must say what the image SHIPS ──────────────
# Four refusals, each with the OTHER three inputs intact, so a leg cannot be
# satisfied by the wrong cause; then one positive control proving the whole
# set publishes once every input is right.
info "8j. publish inventory gate — guest_kernel + xpf-<ver>.pkgs are required (#6500)"
INV="$WORK/inv"; mkdir -p "$INV"
# resign_inv <extra-artifacts...> — rebuild + sign INV's manifest.
resign_inv() {
    XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/sign.py" sign-manifest \
        --manifest "$INV/xpf-$VER.SHA256SUMS" --seckey "$WORK/img.sec" \
        --comment "selftest-inventory" "$INV/xpf-$VER.qcow2" \
        "$INV/xpf-$VER.incus-metadata.tar.gz" "$INV/xpf-$VER.manifest" \
        "$@" >/dev/null
}
inv_publish() {
    XPF_IMAGE_PUBKEY="$WORK/img.pub" $PY "$DIST/publish.py" \
        --dist "$INV" --channel stable --no-apt >/dev/null 2>&1
}
inv_reset() {
    rm -rf "$INV"; mkdir -p "$INV"
    cp "$QCOW" "$META" "$INV/"
    prov_sidecar "$INV/xpf-$VER.manifest" true
    make_pkgs "$INV/xpf-$VER.pkgs"
    # make-latest requires the version's SHA256SUMS to exist, so sign the
    # complete set first; each case below re-signs after mutating one input.
    resign_inv "$INV/xpf-$VER.pkgs"
    XPF_SIGN_SECKEY="$WORK/img.sec" $PY "$DIST/publish.py" make-latest \
        --channel stable --version "$VER" --dist "$INV" >/dev/null 2>&1
    $PY "$DIST/publish.py" stamp-installer --out "$INV/install.sh" \
        --archive-key "$AKEY" --apt-base-url "https://dl.selftest.invalid/apt" \
        --channel stable >/dev/null 2>&1
    minisign -S -W -s "$WORK/img.sec" -m "$INV/install.sh" \
        -x "$INV/install.sh.minisig" >/dev/null 2>&1
}

# 8j-1: manifest with NO guest_kernel (an older bake) — inventory sidecar present.
inv_reset
prov_sidecar "$INV/xpf-$VER.manifest" true -
# #9920: no-guest_kernel is refused by sign-manifest itself now.
direct_sign "$INV" "$VER" "$INV/xpf-$VER.qcow2" \
    "$INV/xpf-$VER.incus-metadata.tar.gz" "$INV/xpf-$VER.manifest" \
    "$INV/xpf-$VER.pkgs"
if inv_publish; then
    bad "publish MUST refuse a manifest with no guest_kernel but PASSED (#6500)"
else
    ok "publish refuses a manifest with no guest_kernel (#6500)"
fi

# 8j-2: guest_kernel present, inventory sidecar ABSENT.
inv_reset
rm -f "$INV/xpf-$VER.pkgs"
# #9920: a reduced set is refused by sign-manifest itself now.
direct_sign "$INV" "$VER" "$INV/xpf-$VER.qcow2" \
    "$INV/xpf-$VER.incus-metadata.tar.gz" "$INV/xpf-$VER.manifest"
if inv_publish; then
    bad "publish MUST refuse a set with no xpf-<ver>.pkgs but PASSED (#6500)"
else
    ok "publish refuses a set with no inventory sidecar (#6500)"
fi

# 8j-3: sidecar present and signed but HOLLOW (below the package floor). A
# present-but-empty record satisfies a presence check and answers nothing.
inv_reset
make_pkgs "$INV/xpf-$VER.pkgs" 3
# #10120: changing the already-recorded inventory also drifts bytes; use the
# low-level primitive to model a signed bad set reaching publish.
direct_sign "$INV" "$VER" "$INV/xpf-$VER.qcow2" \
    "$INV/xpf-$VER.incus-metadata.tar.gz" "$INV/xpf-$VER.manifest" \
    "$INV/xpf-$VER.pkgs"
if inv_publish; then
    bad "publish MUST refuse a HOLLOW inventory but PASSED (#6500)"
else
    ok "publish refuses a hollow inventory (below the package floor) (#6500)"
fi

# 8j-4: the two authenticated records DISAGREE about the kernel.
inv_reset
make_pkgs "$INV/xpf-$VER.pkgs" 60 "9.9.9-other"
direct_sign "$INV" "$VER" "$INV/xpf-$VER.qcow2" \
    "$INV/xpf-$VER.incus-metadata.tar.gz" "$INV/xpf-$VER.manifest" \
    "$INV/xpf-$VER.pkgs"
if inv_publish; then
    bad "publish MUST refuse a manifest/inventory kernel mismatch but PASSED (#6500)"
else
    ok "publish refuses a manifest/inventory guest_kernel mismatch (#6500)"
fi

# 8j-5: positive control — every input right, the same tree publishes.
inv_reset
resign_inv "$INV/xpf-$VER.pkgs"
if inv_publish; then
    ok "publish passes a complete inventory set (#6500 control)"
else
    bad "publish MUST pass a complete inventory set but FAILED (#6500 control)"
fi

# ── 8k. #6504: the signed channel pointer has a CONSUMER ───────────────────
# publish.py has always produced, signed and gated latest.json, and
# docs/distribution.md named "our scripts" as its consumers — while no script
# read it. This leg closes the loop END TO END with the real tools: publish.py
# writes and signs the pointer, then `xpf-deploy.py fetch` with NO --version
# resolves it, verifies it against the pinned pubkey, and fetches + verifies
# the artifacts it names. A drift between the producer's JSON and the
# consumer's parse fails here rather than at a customer's first fetch.
info "8k. xpf-deploy fetch consumes the signed latest.json pointer (#6504)"
FT="$WORK/fetch-src"; FD="$WORK/fetch-dst"; mkdir -p "$FT" "$FD"
cp "$QCOW" "$META" "$SIDECAR" "$PKGS" "$MANIFEST" "$MANIFEST.minisig" "$FT/"
XPF_SIGN_SECKEY="$WORK/img.sec" $PY "$DIST/publish.py" make-latest \
    --channel stable --version "$VER" --dist "$FT" >/dev/null 2>&1
# XDG_STATE_HOME is redirected: `fetch` advances an anti-rollback watermark and
# a self-test must never touch the operator's real state.
fetch_stable() {
    XPF_IMAGE_PUBKEY="$WORK/img.pub" XDG_STATE_HOME="$WORK/state" \
        $PY "$ROOT/scripts/deploy/xpf-deploy.py" fetch \
            --image-url "file://$FT" --channel stable --out "$1" --no-import
}
rm -rf "$FD"; mkdir -p "$FD"
if out=$(fetch_stable "$FD" 2>&1); then
    if [ -f "$FD/xpf-$VER.qcow2" ] && [ -f "$FD/xpf-$VER.incus-metadata.tar.gz" ]; then
        ok "fetch with no --version resolved the channel and verified the artifacts (#6504)"
    else
        bad "fetch resolved the channel but did not land the artifacts (#6504)"
    fi
else
    bad "fetch MUST resolve stable/latest.json with no --version but FAILED (#6504): $out"
fi

# A TAMPERED pointer must be refused. The signature stays put and only the
# bytes change — the stale-mirror / swapped-object case, which is the whole
# reason the pointer is signed.
#
# The tamper edits the DATE, deliberately NOT the version. Rewriting the
# version to something unpublished also makes the fetch fail, but for the
# WRONG reason — the artifacts it names are simply absent — so that leg would
# have passed with the signature check ripped out entirely. (Confirmed: it
# did, until this fixture changed.) Editing a field the fetch never uses
# leaves the signature as the ONLY thing that can refuse it.
rm -rf "$FD"; mkdir -p "$FD"
sed 's/"date": "[^"]*"/"date": "1999-01-01T00:00:00Z"/' \
    "$FT/stable/latest.json" > "$FT/stable/latest.json.new"
if cmp -s "$FT/stable/latest.json" "$FT/stable/latest.json.new"; then
    bad "8k tamper fixture changed NOTHING — the leg would pass vacuously (#6504)"
fi
mv "$FT/stable/latest.json.new" "$FT/stable/latest.json"
if fetch_stable "$FD" >/dev/null 2>&1; then
    bad "fetch MUST refuse a tampered latest.json but PASSED (#6504)"
else
    ok "fetch refuses a tampered latest.json (#6504)"
fi

# ── 8l. #9920 F-064: dist-sign attempts every manifest, names failures ──────
# The recipe's status used to be the LAST iteration's: a failed rotation
# reported success and left the tree half-signed. This leg drives the REAL
# `make dist-sign` recipe text (via -f $ROOT/Makefile) in a fixture dir, so
# the worktree is never mutated: dist-sign hardcodes relative dist/ +
# scripts/dist/sign.py, which resolve under the -C directory.
info "8l. dist-sign accumulates failures and names each (#9920 F-064)"
FIX9920="$WORK/fix9920"; mkdir -p "$FIX9920/dist" "$FIX9920/scripts/dist"
ln -s "$DIST/sign.py" "$FIX9920/scripts/dist/sign.py"
mk_9920_set() { # <ver>: honest 4-file set + UNSIGNED manifest in fixture dist/
    _v=$1
    echo "qcow-$_v" > "$FIX9920/dist/xpf-$_v.qcow2"
    echo "meta-$_v" > "$FIX9920/dist/xpf-$_v.incus-metadata.tar.gz"
    printf 'version: %s\nbase_image_pinned: true\nvalidated: true\nguest_kernel: 7.0.0-15-generic\n' "$_v" > "$FIX9920/dist/xpf-$_v.manifest"
    make_pkgs "$FIX9920/dist/xpf-$_v.pkgs"
    (cd "$FIX9920/dist" && sha256sum "xpf-$_v.qcow2" "xpf-$_v.incus-metadata.tar.gz" "xpf-$_v.manifest" "xpf-$_v.pkgs" > "xpf-$_v.SHA256SUMS")
}
run_distsign() { # real recipe, fixture dir; transcript in $FIX9920/out
    make --no-print-directory -C "$FIX9920" -f "$ROOT/Makefile" dist-sign \
        XPF_SIGN_SECKEY="$WORK/img.sec" >"$FIX9920/out" 2>&1
}
# 8l-a: first-broken (deleted artifact) + second-honest. The recipe must FAIL,
# name the broken manifest, leave it unsigned, and STILL sign the honest one.
mk_9920_set "8l-broken"
mk_9920_set "8l-honest"
rm "$FIX9920/dist/xpf-8l-broken.qcow2"
if run_distsign; then
    bad "dist-sign MUST fail when one manifest is broken but PASSED (#9920 F-064)"
else
    ok "dist-sign fails when one manifest is broken (#9920 F-064)"
fi
if grep -q "dist-sign: dist/xpf-8l-broken.SHA256SUMS: FAILED" "$FIX9920/out"; then
    ok "dist-sign names the broken manifest (#9920 F-064)"
else
    bad "dist-sign did NOT name the broken manifest (#9920 F-064)"
fi
if [ ! -f "$FIX9920/dist/xpf-8l-broken.SHA256SUMS.minisig" ]; then
    ok "dist-sign leaves the broken manifest unsigned (#9920 F-064)"
else
    bad "dist-sign SIGNED the broken manifest (#9920 F-064)"
fi
if [ -f "$FIX9920/dist/xpf-8l-honest.SHA256SUMS.minisig" ]; then
    ok "dist-sign still signs the honest manifest after a failure (#9920 F-064)"
else
    bad "dist-sign did NOT sign the honest manifest after a failure (#9920 F-064)"
fi
# 8l-b: all-honest control — the same recipe passes and both outputs verify.
rm -rf "$FIX9920/dist"; mkdir -p "$FIX9920/dist"
mk_9920_set "8l-ok1"
mk_9920_set "8l-ok2"
if run_distsign; then
    ok "dist-sign passes an all-honest tree (#9920 F-064 control)"
else
    bad "dist-sign MUST pass an all-honest tree but FAILED (#9920 F-064 control)"
fi
for _v in 8l-ok1 8l-ok2; do
    if minisign -V -p "$WORK/img.pub" -m "$FIX9920/dist/xpf-$_v.SHA256SUMS" -x "$FIX9920/dist/xpf-$_v.SHA256SUMS.minisig" >/dev/null 2>&1; then
        ok "dist-sign output verifies: xpf-$_v (#9920 F-064 control)"
    else
        bad "dist-sign output does NOT verify: xpf-$_v (#9920 F-064 control)"
    fi
done

# ── 9. install.sh H-16: validate-before-mutate + cleanup-on-failure ─────────
info "9. install.sh validate-before-mutate + cleanup-on-failure (H-16)"
H16="$WORK/h16"; mkdir -p "$H16/bin" "$H16/keyrings" "$H16/sources"
printf '#!/bin/sh\necho 0\n' > "$H16/bin/id"; chmod +x "$H16/bin/id"
printf '#!/bin/sh\nexit 0\n' > "$H16/bin/systemctl"; chmod +x "$H16/bin/systemctl"
printf '#!/bin/sh\nexit 100\n' > "$H16/bin/apt-get"; chmod +x "$H16/bin/apt-get"  # simulate install failure
# 9a. non-dry install whose apt step FAILS after write_source -> the trap must
#     remove the apt source (else a dangling repo bricks apt update). Redirect
#     the system paths so the test never touches the real host.
sed -e "s#^KEYRING=/usr/share/keyrings/xpf-archive-keyring.asc#KEYRING=$H16/keyrings/k.asc#" \
    -e "s#^SRC=/etc/apt/sources.list.d/xpf.sources#SRC=$H16/sources/xpf.sources#" \
    "$BAKED" > "$H16/install.sh"
PATH="$H16/bin:$PATH" sh "$H16/install.sh" >/dev/null 2>&1 || true
if [ ! -f "$H16/sources/xpf.sources" ]; then
    ok "cleanup-on-failure removed the dangling apt source"
else
    bad "cleanup-on-failure did NOT remove the apt source"
fi
# 9b. real key but NO apt URL (marker restored, no env) -> validate() must die
#     BEFORE writing the keyring (host untouched).
rm -f "$H16/keyrings/k.asc" "$H16/sources/xpf.sources"
sed -e "s#^KEYRING=/usr/share/keyrings/xpf-archive-keyring.asc#KEYRING=$H16/keyrings/k.asc#" \
    -e "s#^SRC=/etc/apt/sources.list.d/xpf.sources#SRC=$H16/sources/xpf.sources#" \
    -e "s#^XPF_APT_BASE_URL_BAKED=.*#XPF_APT_BASE_URL_BAKED='%%XPF_APT_BASE_URL%%'#" \
    "$BAKED" > "$H16/nourl.sh"
PATH="$H16/bin:$PATH" sh "$H16/nourl.sh" >"$H16/nourl.out" 2>&1 || true
if [ ! -f "$H16/keyrings/k.asc" ] && grep -q "XPF_APT_BASE_URL is required" "$H16/nourl.out"; then
    ok "validate-before-mutate: missing URL fails with the host untouched"
else
    bad "validate-before-mutate: keyring written before validation failed"; cat "$H16/nourl.out" >&2
fi

# ── tally ──────────────────────────────────────────────────────────────────
echo
echo "==> selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "==> #1924 signed-distribution roundtrip OK (throwaway key; no real key, no host)"
