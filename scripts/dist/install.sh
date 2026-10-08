#!/bin/sh
# xpf appliance installer (#1924 §5.4) — Tailscale-style one-command install.
#
#   curl -fsSL <XPF_IMAGE_BASE_URL>/install.sh | sudo sh   # Tier A (one-liner)
#
# The apt base URL + default channel + archive key are BAKED into this script
# at publish time (scripts/dist/publish.py stamp-installer), so the piped
# one-liner needs no env — `sudo sh` is required because it mutates the host.
#
# Tier B (verify-before-run): get the active image public keys from the SOURCE
# REPO (git clone / GitHub — the out-of-band trust root, NEVER from the dist
# host). Use `scripts/dist/sign.py verify-file` with repeated --pubkey options
# to accept rotation overlap; fetch each required key-addressed .minisig sidecar,
# then read this script and run it.
#
# What it does:
#   1. PREFLIGHT: amd64 + Debian-family + kernel >= 6.18 + active systemd-networkd.
#      xpf does NOT install or enable systemd-networkd; enable and start it
#      before installing xpf. xpf also does NOT install a kernel.
#   2. Install the pinned apt archive keyring to /usr/share/keyrings (inline).
#   3. Write /etc/apt/sources.list.d/xpf.sources (deb822, Signed-By).
#   4. apt-get update, bind the signed Release Suite/Codename to CHANNEL, write
#      the managed APT channel pin, then install xpf-appliance.
#   5. Print next steps + the interface-takeover caveat (#1879).
#
# Config inputs (the operator decisions — NOT hardcoded):
#   XPF_APT_BASE_URL   apt repo base (dists/+pool/ host). Baked at publish
#                      time; set to override, or when running an unbaked copy.
#   XPF_CHANNEL        stable (default) | edge. Baked at publish time.
#   XPF_DRY_RUN=1      print the actions, mutate nothing (CI / review).
#
# The archive keyring below is a PLACEHOLDER (its secret is held by no one).
# The release build (publish.py stamp-installer) substitutes the real
# ASCII-armored archive public key between the BEGIN/END markers AND bakes
# the apt base URL + default channel into the %%…%% markers below. The SAME
# keyring also ships in the xpf package (/usr/share/keyrings via debian/rules)
# so existing hosts get rotated keys via `apt upgrade` even though they never
# re-run this script.
set -eu

# ── publish-time substitution markers ────────────────────────────────────
# publish.py stamp-installer replaces the two %%…%% tokens below with the real
# apt repo base URL and default channel, so a piped `curl … | sudo sh` needs
# NO env. The "unsubstituted?" guard keys on the `%%` shape (a real URL or
# channel never contains `%%`), so a global substitution that also touched a
# literal marker copy elsewhere cannot silently defeat it. Precedence for each
# value: env override > baked marker > default (channel) / die (URL).
XPF_APT_BASE_URL_BAKED='%%XPF_APT_BASE_URL%%'
XPF_CHANNEL_BAKED='%%XPF_CHANNEL%%'
case "$XPF_APT_BASE_URL_BAKED" in
    *'%%'*) _baked_url='' ;;                 # unsubstituted marker -> ignore
    *)      _baked_url="$XPF_APT_BASE_URL_BAKED" ;;
esac
case "$XPF_CHANNEL_BAKED" in
    *'%%'*) _baked_channel='' ;;             # unsubstituted marker -> ignore
    *)      _baked_channel="$XPF_CHANNEL_BAKED" ;;
esac

XPF_APT_BASE_URL="${XPF_APT_BASE_URL:-$_baked_url}"
CHANNEL="${XPF_CHANNEL:-${_baked_channel:-stable}}"
DRY="${XPF_DRY_RUN:-0}"

# Cleanup-on-failure state: remove the apt source written by this run and
# restore/remove the managed channel pin if the installer does not finish.
SRC_WRITTEN=0
INSTALL_OK=0
PIN_WRITTEN=0
PIN_BACKUP=''
PIN_TEMP=''
KEYRING_WRITTEN=0
KEYRING_BACKUP=''
KEYRING_TEMP=''
# /usr/share/keyrings (NOT /etc/apt/keyrings): the xpf package ships the same
# keyring here as a package-owned (non-conffile) file, so this bootstrap write
# and the later `apt install` agree without a dpkg conffile prompt, and key
# rotation lands seamlessly on `apt upgrade` (AGY-A1).
KEYRING=/usr/share/keyrings/xpf-archive-keyring.asc
SRC=/etc/apt/sources.list.d/xpf.sources
PIN=/etc/apt/preferences.d/xpf-channel.pref
PIN_MARKER="# xpf appliance channel pin; Managed by install.sh (#11133)"

# cleanup_on_fail removes the apt source written by this run, restores the
# prior managed channel pin, and restores the keyring only while its live bytes
# still match this installer's write. An unmarked preference is never changed.
cleanup_on_fail() {
    _rc=$?
    if [ "$INSTALL_OK" != "1" ] && [ "$DRY" != "1" ]; then
        if [ "$SRC_WRITTEN" = "1" ]; then
            info "install failed (rc=$_rc) — removing $SRC so it does not break apt update"
            rm -f "$SRC" || _rc=1
        fi
        if [ -n "$PIN_TEMP" ]; then
            rm -f "$PIN_TEMP" || _rc=1
        fi
        if [ "$PIN_WRITTEN" = "1" ]; then
            if [ -n "$PIN_BACKUP" ]; then
                info "install failed (rc=$_rc) — restoring previous $PIN"
                if mv -f "$PIN_BACKUP" "$PIN"; then
                    PIN_BACKUP=''
                else
                    echo "xpf-install ERROR: could not restore previous $PIN" >&2
                    _rc=1
                fi
            else
                info "install failed (rc=$_rc) — removing new $PIN"
                rm -f "$PIN" || _rc=1
            fi
        elif [ -n "$PIN_BACKUP" ]; then
            rm -f "$PIN_BACKUP" || _rc=1
        fi
        if [ -n "$KEYRING_TEMP" ]; then
            rm -f "$KEYRING_TEMP" || _rc=1
        fi
        if [ "$KEYRING_WRITTEN" = "1" ]; then
            if [ -f "$KEYRING" ] && [ ! -L "$KEYRING" ] \
                && printf '%s\n' "$ARCHIVE_KEY" | cmp -s - "$KEYRING"; then
                if [ -n "$KEYRING_BACKUP" ]; then
                    info "install failed (rc=$_rc) — restoring previous $KEYRING"
                    if mv -f "$KEYRING_BACKUP" "$KEYRING"; then
                        KEYRING_BACKUP=''
                    else
                        echo "xpf-install ERROR: could not restore previous $KEYRING" >&2
                        _rc=1
                    fi
                else
                    info "install failed (rc=$_rc) — removing new $KEYRING"
                    rm -f "$KEYRING" || _rc=1
                fi
            else
                info "install failed (rc=$_rc) — $KEYRING changed after bootstrap; leaving it intact"
                if [ -n "$KEYRING_BACKUP" ]; then
                    rm -f "$KEYRING_BACKUP" || _rc=1
                    KEYRING_BACKUP=''
                fi
            fi
        elif [ -n "$KEYRING_BACKUP" ]; then
            rm -f "$KEYRING_BACKUP" || _rc=1
        fi
    else
        [ -z "$PIN_TEMP" ] || rm -f "$PIN_TEMP" || _rc=1
        [ -z "$PIN_BACKUP" ] || rm -f "$PIN_BACKUP" || _rc=1
        [ -z "$KEYRING_TEMP" ] || rm -f "$KEYRING_TEMP" || _rc=1
        [ -z "$KEYRING_BACKUP" ] || rm -f "$KEYRING_BACKUP" || _rc=1
    fi
    exit "$_rc"
}
trap cleanup_on_fail EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP


die() { echo "xpf-install ERROR: $*" >&2; exit 1; }
info() { echo "xpf-install: $*"; }
run() {
    if [ "$DRY" = "1" ]; then echo "  (dry-run) $*"; else eval "$*"; fi
}


# ── embedded archive public key (PLACEHOLDER until release) ──────────────
# Replace the block between the markers with the real ASCII-armored key.
ARCHIVE_KEY=$(cat <<'KEYEOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

PLACEHOLDER-xpf-archive-keyring-not-yet-issued
This is a #1924 placeholder. The release build substitutes the real
ASCII-armored OpenPGP archive public key here. With this placeholder in
place, `apt-get update` will reject the repo's signature — which is the
correct fail-safe until a real key is issued (OQ-2).
-----END PGP PUBLIC KEY BLOCK-----
KEYEOF
)

is_placeholder_key() {
    printf '%s' "$ARCHIVE_KEY" | grep -q "PLACEHOLDER-xpf-archive-keyring"
}

# Parse the embedded public key with an isolated GnuPG home. Never import it
# into the operator's keyring; malformed-but-armored keys must fail preflight.
validate_archive_key() {
    command -v gpg >/dev/null 2>&1 \
        || die "gpg is required to validate the embedded archive public key."
    _key_home=$(mktemp -d "${TMPDIR:-/tmp}/xpf-archive-key-check.XXXXXX") \
        || die "cannot create temporary home to validate archive key."
    _key_info=$(printf '%s\n' "$ARCHIVE_KEY" |
        GNUPGHOME="$_key_home" gpg --batch --quiet --with-colons --show-keys - 2>/dev/null) || {
        rm -rf "$_key_home"
        die "archive key is not a parseable OpenPGP public key."
    }
    if ! printf '%s\n' "$_key_info" | grep -q '^pub:'; then
        rm -rf "$_key_home"
        die "archive key contains no OpenPGP public key."
    fi
    if printf '%s\n' "$_key_info" | grep -Eq '^(sec|ssb):'; then
        rm -rf "$_key_home"
        die "archive key contains secret OpenPGP key material."
    fi
    rm -rf "$_key_home" || die "cannot clean temporary archive-key validation home."
}


# ── apt base URL validation (F-065 / #9921) ─────────────────────────────────
# Mirror of publish.py validate_apt_url (#5685/M40): the URL is interpolated
# into the deb822 `URIs:` line of a root-owned apt source
# (/etc/apt/sources.list.d/xpf.sources), so anything but a strict https URL
# with no shell metacharacter / whitespace / control byte / userinfo / query /
# fragment / percent-escape is refused with die() BEFORE any host mutation.
# The env override and the baked marker flow through the same variable, so this
# one call covers both. Structural edge behavior is pinned against publish.py
# by scripts/dist/test_install_url_validate_9921.py (dual-drive parity
# battery): the two validators must agree accept/reject on every case.
validate_apt_url() {
    _url="$1"
    [ -n "$_url" ] || die "XPF_APT_BASE_URL is required."
    # Diagnostics echo a control-stripped copy (publish.py's !r discipline):
    # the operator's own value must not launder terminal control bytes through
    # our error message. Validation below always runs on the raw value.
    _safe_url=$(printf '%s' "$_url" | LC_ALL=C tr -d '[:cntrl:]')
    # 1. No control, whitespace, or DEL byte may survive into the deb822 line
    #    (newline/CR/tab included — the F-065 injection vector). Non-ASCII
    #    bytes that pass [:print:] under a UTF-8 locale still die at the ASCII
    #    structural allowlist below. LC_ALL=C is best-effort (dash only honors
    #    the startup locale): soundness does not depend on it, because no
    #    metacharacter, slash, colon, control, or whitespace byte can ever
    #    match the alpha/numeric ranges below in any locale.
    case "${LC_ALL+set}" in set) _lc_had=1; _lc_saved=$LC_ALL;; *) _lc_had=0;; esac
    LC_ALL=C
    case "$_url" in *[![:print:]]*)
        die "XPF_APT_BASE_URL '$_safe_url' contains a forbidden control/whitespace byte — \
it is interpolated into a root-owned apt source; refusing (#9921)." ;;
    esac
    # 2. Per-character denylist (single-char arms: no bracket-expression quoting
    #    subtleties): shell metacharacters, quoting characters, and %/=+, plus
    #    space (a %% pair would also defeat the unsubstituted-marker guard).
    #    ?/#/@ dying here enforces no-query/no-fragment/no-userinfo.
    # shellcheck disable=SC1003  # Single quote is a literal denied character.
    case "$_url" in
        *'$'*|*'"'*|*"'"*|*'\\'*|*'`'*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*|*'('*|*')'*|*'*'*|*'?'*|*'!'*|*'#'*|*'@'*|*'%'*|*'='*|*'+'*|*','*|*' '*)
            die "XPF_APT_BASE_URL '$_safe_url' contains a forbidden character (shell \
metacharacter, whitespace, or %/=+,) — refusing (#9921)." ;;
    esac
    # 3. Structural allowlist: https scheme (matched case-insensitively —
    #    publish.py's urlsplit lowercases the scheme, so a stamped uppercase
    #    URL must keep installing), a bare host[:port], and an allowlisted
    #    path. userinfo/query/fragment cannot be present (arm 2).
    case "$_url" in
        [Hh][Tt][Tt][Pp][Ss]://*) _rest=${_url#*://} ;;
        *) die "XPF_APT_BASE_URL '$_safe_url' must use the https scheme (#9921)." ;;
    esac
    case "$_rest" in
        */*) _hostport=${_rest%%/*}; _path=/${_rest#*/} ;;
        *) _hostport=$_rest; _path= ;;
    esac
    case "$_hostport" in
        *:*)
            _h=${_hostport%%:*}; _p=${_hostport#*:}
            case "$_p" in ""|*[!0-9]*|??????*)
                die "XPF_APT_BASE_URL '$_safe_url' has an invalid port — expected 1-5 digits (#9921)." ;;
            esac
            ;;
        *) _h=$_hostport ;;
    esac
    case "$_h" in ""|[!A-Za-z0-9]*|*[!A-Za-z0-9])
        die "XPF_APT_BASE_URL '$_safe_url' has an invalid host — expected a bare host[:port] \
with no userinfo (#9921)." ;;
    esac
    case "$_h" in *[!A-Za-z0-9.-]*)
        die "XPF_APT_BASE_URL '$_safe_url' has an invalid host — expected [A-Za-z0-9.-] (#9921)." ;;
    esac
    case "$_path" in *[!/A-Za-z0-9._~-]*)
        die "XPF_APT_BASE_URL '$_safe_url' has an invalid path — allow only '/'-\
separated [A-Za-z0-9._~-] components (#9921)." ;;
    esac
    if [ "$_lc_had" = "1" ]; then LC_ALL=$_lc_saved; else unset LC_ALL; fi
}

# ── 1. preflight ─────────────────────────────────────────────────────────
preflight() {
    info "preflight: arch, distro, kernel, networkd"
    arch=$(uname -m)
    [ "$arch" = "x86_64" ] || die "unsupported arch '$arch' — xpf ships amd64 only."

    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-} ${ID_LIKE:-}" in
            *debian*|*ubuntu*) : ;;
            *) die "unsupported distro '${ID:-?}' — xpf needs a Debian-family host." ;;
        esac
    else
        die "no /etc/os-release — cannot confirm a Debian-family host."
    fi

    # kernel >= 6.18 (the AF_XDP verifier floor). Compare major.minor.
    kver=$(uname -r)
    kmaj=$(echo "$kver" | cut -d. -f1)
    kmin=$(echo "$kver" | cut -d. -f2)
    case "$kmaj$kmin" in *[!0-9]*) die "cannot parse kernel version '$kver'";; esac
    if [ "$kmaj" -lt 6 ] || { [ "$kmaj" -eq 6 ] && [ "$kmin" -lt 18 ]; }; then
        die "kernel $kver < 6.18 — xpf requires kernel >= 6.18 + a native-XDP NIC. \
Upgrade the host kernel, or deploy the appliance image (docs/install-images.md), \
which ships its own >= 6.18 kernel."
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemd not found — xpf requires systemd + active systemd-networkd."
    fi
    # xpfd renames and cycles the management NIC during bootstrap; networkd
    # must already be running because the xpf package does not install or
    # enable it.
    if ! systemctl is-active --quiet systemd-networkd.service; then
        die "systemd-networkd.service must be installed and active before installing xpf. \
The xpf package does not install or enable it; enable/start networkd and retry."
    fi
    info "preflight OK (arch=$arch kernel=$kver)"
}

# ── validate ALL inputs BEFORE any host mutation (H-16) ────────────────────
# Everything here is read-only (preflight probes; the rest are pure checks) so
# a bad input fails CLEANLY with the host untouched — no half-configured host
# with a keyring written but no working apt source.
validate() {
    [ "$(id -u)" = "0" ] || [ "$DRY" = "1" ] || die "run as root (or sudo)."
    # Pure input checks BEFORE host probes (F-065/#9921): a malformed URL or
    # channel dies identically on every host without reaching preflight.
    [ -n "${XPF_APT_BASE_URL:-}" ] || die "XPF_APT_BASE_URL is required (the \
apt repo base URL — a dists/+pool/ directory host). It is baked into install.sh \
at publish time; set it explicitly to override, or when running an unbaked copy."
    validate_apt_url "$XPF_APT_BASE_URL"
    case "$CHANNEL" in stable|edge) ;; *) die "XPF_CHANNEL must be stable|edge";; esac
    preflight
    # archive key must be the real one (a release build substitutes it).
    if is_placeholder_key; then
        if [ "$DRY" = "1" ]; then
            info "WARNING (dry-run): archive key is the #1924 PLACEHOLDER — a \
real install would fail at apt update until the release key is issued (OQ-2)."
        else
            die "archive key is the #1924 PLACEHOLDER — refusing to install a \
keyring that cannot verify the repo. A release build substitutes the real key."
        fi
    else
        validate_archive_key
    fi
}

# ── 2. keyring ─────────────────────────────────────────────────────────────
install_keyring() {
    if [ "$DRY" != "1" ]; then
        [ ! -L "$KEYRING" ] || die "refusing to replace symlink at $KEYRING"
        if [ -e "$KEYRING" ]; then
            [ -f "$KEYRING" ] \
                || die "refusing to replace non-regular keyring path at $KEYRING"
        fi
    fi
    _keyring_dir=$(dirname "$KEYRING")
    run "install -d -m 0755 \"$_keyring_dir\""
    if [ "$DRY" = "1" ]; then
        echo "  (dry-run) write $KEYRING (mode 0644) from embedded key"
    else
        umask 022
        KEYRING_TEMP=$(mktemp "$_keyring_dir/.xpf-archive-keyring.asc.tmp.XXXXXX")
        printf '%s\n' "$ARCHIVE_KEY" > "$KEYRING_TEMP"
        chmod 0644 "$KEYRING_TEMP"
        if [ -e "$KEYRING" ]; then
            KEYRING_BACKUP=$(mktemp "$_keyring_dir/.xpf-archive-keyring.asc.backup.XXXXXX")
            cp -p "$KEYRING" "$KEYRING_BACKUP"
        fi
        sync "$KEYRING_TEMP" || die "cannot sync temporary archive keyring."
        # Arm rollback before the rename so an unsuccessful move is reversible.
        KEYRING_WRITTEN=1
        mv -f "$KEYRING_TEMP" "$KEYRING"
        KEYRING_TEMP=''
        sync "$_keyring_dir" || die "cannot sync archive-keyring directory."
    fi
}

# ── 3. apt source ──────────────────────────────────────────────────────────
# Inputs are already validated in validate(); this function only WRITES.
write_source() {
    info "writing apt source -> $SRC (suite=$CHANNEL uri=$XPF_APT_BASE_URL)"
    body=$(cat <<EOF
# xpf appliance apt source (#1924). Managed by install.sh.
Types: deb
URIs: $XPF_APT_BASE_URL
Suites: $CHANNEL
Components: main
Architectures: amd64
Signed-By: $KEYRING
EOF
)
    if [ "$DRY" = "1" ]; then
        echo "  (dry-run) $SRC contents:"; printf '%s\n' "$body" | sed 's/^/      /'
    else
        printf '%s\n' "$body" > "$SRC"
        SRC_WRITTEN=1   # arm the cleanup trap (H-16)
    fi
}

# Persist the selected channel for later apt upgrades. The selected identity
# rule is first so it wins over the single-field deny rules; those separately
# catch a mismatched or malformed Release that omits Suite or Codename.
write_channel_pin() {
    body=$(cat <<EOF
$PIN_MARKER

Package: xpf*
Pin: release a=$CHANNEL,n=$CHANNEL
Pin-Priority: 990

Package: xpf*
Pin: release a=*
Pin-Priority: -1

Package: xpf*
Pin: release n=*
Pin-Priority: -1
EOF
)
    if [ "$DRY" = "1" ]; then
        info "dry-run: would write managed apt channel pin -> $PIN (channel=$CHANNEL)"
        return
    fi

    if [ -L "$PIN" ]; then
        die "refusing to replace symlink at $PIN"
    fi
    if [ -e "$PIN" ]; then
        [ -f "$PIN" ] \
            || die "refusing to replace non-regular preferences path at $PIN"
        grep -Fqx "$PIN_MARKER" "$PIN" \
            || die "refusing to replace unmanaged apt preferences file $PIN"
    fi

    _pin_dir=$(dirname "$PIN")
    install -d -m 0755 "$_pin_dir"
    PIN_TEMP=$(mktemp "$_pin_dir/.xpf-channel.pref.tmp.XXXXXX")
    printf '%s\n' "$body" > "$PIN_TEMP"
    chmod 0644 "$PIN_TEMP"
    if [ -e "$PIN" ]; then
        PIN_BACKUP=$(mktemp "$_pin_dir/.xpf-channel.pref.backup.XXXXXX")
        cp -p "$PIN" "$PIN_BACKUP"
    fi
    mv -f "$PIN_TEMP" "$PIN"
    PIN_TEMP=''
    PIN_WRITTEN=1
    info "wrote managed apt channel pin -> $PIN (channel=$CHANNEL)"
}

# ── 4. bind apt metadata to the selected channel ────────────────────────────
# APT verifies the archive signature, but normally only warns when the signed
# Release at dists/$CHANNEL advertises another Suite; it still makes those
# packages candidates. Inspect apt's post-update index targets for THIS source
# entry and require both signed Release identity fields to match the requested
# channel before installing anything.
verify_channel() {
    _targets=$(apt-get indextargets) \
        || die "cannot inspect apt index targets after update; refusing install."
    printf '%s\n' "$_targets" | awk -v source="$SRC:1" -v channel="$CHANNEL" '
        BEGIN { RS = ""; FS = "\n"; found = 0; mismatch = 0 }
        {
            entry = suite = codename = ""
            for (i = 1; i <= NF; i++) {
                if (index($i, "Sourcesentry: ") == 1)
                    entry = substr($i, 15)
                else if (index($i, "Suite: ") == 1)
                    suite = substr($i, 8)
                else if (index($i, "Codename: ") == 1)
                    codename = substr($i, 11)
            }
            if (entry == source) {
                found++
                if (suite != channel || codename != channel)
                    mismatch = 1
            }
        }
        END {
            if (!found) {
                print "xpf-install ERROR: apt reported no index targets for the xpf source."
                exit 1
            }
            if (mismatch) {
                print "xpf-install ERROR: signed apt Release Suite/Codename does not match selected channel."
                exit 1
            }
        }' || die "apt repository is not bound to selected channel '$CHANNEL'; refusing install."
    info "apt Release Suite/Codename match selected channel '$CHANNEL'"
}

# ── 5. install ─────────────────────────────────────────────────────────────
do_install() {
    info "apt-get update, bind channel, and install xpf-appliance"
    run "apt-get update"
    if [ "$DRY" = "1" ]; then
        info "dry-run: skipping post-update apt channel binding check"
        write_channel_pin
    else
        verify_channel
        write_channel_pin
    fi
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y xpf-appliance"
}

# ── 6. next steps ──────────────────────────────────────────────────────────
next_steps() {
    cat <<'EOF'

xpf-install: done. Next steps:
  - Seed a day-0 config:  see docs/distribution.md and docs/deploy-quickstart.md
  - Operate:              cli   (Junos-style CLI)
  - Status:               systemctl status xpfd

  CAUTION (#1879 interface takeover): xpfd OWNS and RENAMES every interface
  on this host. On a remote box, an incorrect fxp0 mapping can cut your
  management path. Seed a safe day-0 config (fxp0 = mgmt DHCP) BEFORE relying
  on remote access, or use console.

  Upgrades: `apt upgrade xpf-appliance` cuts the dataplane on a STANDALONE
  node (a bounded blip; mgmt/SSH is not cut). Use XPF_NO_POSTINST_CUT=1
  apt-get upgrade to stage-only and run `xpfd upgrade` at a chosen time. HA
  nodes stage only; cut with `xpfd upgrade --rolling`.
EOF
}

main() {
    validate        # ALL input checks first — no host mutation yet (H-16)
    install_keyring # ── mutation begins here ──
    write_source
    do_install
    INSTALL_OK=1    # commit the source/pin; cleanup only removes pin backups
    next_steps
}

# Sourcing hook for hermetic unit tests
# (scripts/dist/test_install_url_validate_9921.py): with
# XPF_INSTALL_SOURCE_ONLY=1 the real functions can be sourced without running
# the installer. Same idiom as xpf-day0-config's XPF_DAY0_SOURCE_ONLY, but
# WITHOUT its `exit 0` — install.sh must propagate main's status (#9921).
if [ "${XPF_INSTALL_SOURCE_ONLY:-}" != "1" ]; then
    main "$@"
fi
