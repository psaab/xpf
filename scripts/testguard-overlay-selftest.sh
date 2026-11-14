#!/usr/bin/env bash
# #19084: a ROOT run under testguard-run.sh executes in a throwaway view of
# the whole root filesystem (scripts/testguard-root-view.sh). This selftest
# drives both root paths, the user-namespace path (no VM proof) and the
# VM-proof path, with stand-in commands, and checks the host before and after:
#
#   [seeds]        rewrites, chmods, deletes and creations in /etc, /var/lib,
#                  /var/log, /run, /srv, /opt, /root and /tmp are all visible
#                  to the command (in-process and from a child) and none
#                  reaches the host (R18 R2);
#   [F1-symlink]   the same through a directory symlink in /var/log that
#                  resolves to /srv (Codex F1);
#   [F2-cwd]       a command started in a host directory runs in that
#                  directory INSIDE the view: a relative write stays private;
#   [F2-fds]       descriptors the caller left open are closed before exec;
#   [pass-through] writes under TMPDIR do reach the host (build output must
#                  not land in the tmpfs upper);
#   [read-only]    a disposable vfat image, loop-mounted and proven WRITABLE
#                  first (overlayfs cannot take vfat as a lower layer), is
#                  read-only in the view; skipped, as coverage unavailable,
#                  without busybox mkdosfs or a loop device;
#   [dev-private]  the view's /dev is the private nodev tmpfs, holding no
#                  device node outside the allowlist, and every overlay in
#                  the view is nodev (Codex P1 on 468f7d2371);
#   [dev-late-block] a block node created on the HOST after the view was
#                  built is not visible in it, and no block node is (the old
#                  mask covered only the nodes present at setup);
#   [dev-nodev]    a block node created INSIDE the view's /dev cannot be
#                  opened;
#   [nodev-overlay] a block node on host storage outside /dev, backed by a
#                  disposable loop device, cannot be opened in the view;
#   [dev-chardev]  the allowlisted character devices work, and the host
#                  inode of one cannot be changed (utimes) from the view;
#   [dev-pts]      /dev/pts is a fresh devpts instance, not the host's;
#   [dev-shm]      /dev/shm is a fresh tmpfs: a write there stays private;
#   [procfs-alias] a procfs mounted anywhere but /proc refuses the run;
#   [procfs-pass-through] so does one selected as a pass-through
#                  (GOCACHE=/srv/hostproc), checked before the skip;
#   [pass-through-refused] a pass-through below a system tree (/etc/x)
#                  refuses the run before it is created;
#   [tmpdir-refused] so does a TMPDIR below /etc, which is created first of
#                  all the pass-through, so it is checked first too;
#   [F3-id]        an `id` that fails refuses the run (exit 2, no command);
#   [F4-vm]        on a non-VM this selftest refuses before seeding anything;
#   [proof-untouched] the runner's shared VM proof is never touched;
#   [unsupported]  a mount of a type the wrapper cannot place refuses the run;
#   [R1-detach]    on the VM-proof path, a command that detaches the root
#                  view FAILS the run; on the user-namespace path it cannot;
#   [detector]     the residue check still FAILS a run that changes a
#                  watched state path through the writable pass-through.
#
# Root only. Otherwise it exits 77 (SKIP, with the reason) so a non-root run
# never reads as a pass: scripts/run-selftests.sh reports it as a named SKIP,
# and `make vm-test-root` (test-testguard-overlay) runs it as root, where the
# Makefile target fails on anything but 0. It seeds host trees (removing them
# on exit), so it refuses (exit 2) on anything that is not a VM, checked
# read-only BEFORE any of that (Codex F4).
#
# It never touches the runner's VM proof, which other lanes' root legs on
# the same runner depend on (R19 F3 on 41dcb74e6d: deleting it for the first
# path, with no lock, broke them for that window, and a kill inside it left
# it deleted). The user-namespace cases ask testguard-run.sh to ignore the
# proof (XPF_TESTGUARD_NO_VM_PROOF=1, downgrade-only). The VM-proof cases run
# when the runner is already marked (`make vm-test-root` marks it first) and
# are reported as skipped, coverage unavailable, otherwise.
set -u
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" != 0 ]; then
	echo "SKIP: testguard-overlay-selftest needs root; it runs in the disposable VM leg (make vm-test-root)"
	exit 77
fi
# #19084 Codex F4: VM eligibility first, read-only. The same predicate as
# scripts/mark-test-vm.sh, which this selftest calls later.
virt=$(systemd-detect-virt --vm 2>/dev/null || true)
if [ -z "$virt" ] || [ "$virt" = none ]; then
	echo "testguard-overlay-selftest: REFUSED: not a virtual machine (systemd-detect-virt --vm: '${virt:-}'); it seeds host trees, so it runs only in a disposable VM (#19084)" >&2
	exit 2
fi
# Every host mutation below is announced here first. The [F4-vm] cell runs
# this script nested on a "non-VM" and requires the trace to stay empty.
trace() { [ -z "${TG_SELFTEST_TRACE:-}" ] || printf '%s\n' "$*" >>"$TG_SELFTEST_TRACE"; }

pass=0 fail=0
ok() { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

export TMPDIR=${TMPDIR:-/var/tmp}
tag="tg-sel.$$"
proof=/run/xpf-testguard-vm-boot-id
W=$(mktemp -d "$TMPDIR/tg-overlay.XXXXXX")
seeds="/etc/$tag.seed /var/lib/$tag /var/log/$tag.log /run/$tag /srv/$tag /opt/$tag /root/$tag /tmp/$tag
/etc/$tag.new /var/log/$tag-f1 /srv/$tag-f1 /etc/$tag-cwd /srv/$tag-fd /srv/$tag-unsup /srv/$tag-vfat /srv/$tag-hostproc /etc/$tag-cache
/etc/$tag-tmp /srv/$tag-blk /dev/$tag-late /dev/$tag-inside /dev/shm/$tag.shm"
# [proof-untouched]: the runner's VM proof, as other lanes see it, is recorded
# here and must be byte-, mode- and mtime-identical at the end (R19 F3).
proof_state() { stat -c '%F %a %U %s %Y' "$proof" 2>&1; cat "$proof" 2>&1; }
proof_at_start=$(proof_state)
loopdev=
cleanup() {
	for p in $seeds; do rm -rf "$p"; done
	[ -z "$loopdev" ] || losetup -d "$loopdev" 2>/dev/null
	rm -rf "$W"
}
trap cleanup EXIT

# host_state: type, mode, size, mtime and sha256 of every path given, so a
# chmod, a same-size rewrite or an unlink on the host all show.
host_state() {
	for p in "$@"; do
		if [ -e "$p" ] || [ -L "$p" ]; then
			stat -c '%F %a %s %Y %n' "$p"
			[ -f "$p" ] && sha256sum "$p"
		else
			echo "absent $p"
		fi
	done 2>&1
}

mkfake() { # $1 name, then the body; exits 7 if a check inside fails
	local f="$W/$1"
	shift
	printf '#!/bin/sh\nfail() { echo "CHECK: $*" >&2; exit 7; }\n%s\n' "$*" >"$f"
	chmod +x "$f"
}

# ── [seeds] ──────────────────────────────────────────────────────────────
seed_files="/etc/$tag.seed /var/lib/$tag/seed /srv/$tag/seed /opt/$tag/seed /root/$tag/seed /tmp/$tag/seed"
seed_new="/etc/$tag.new /var/lib/$tag/sub /var/log/$tag.log /run/$tag /srv/$tag/new /opt/$tag/new /root/$tag/new /tmp/$tag/new"
mkfake seeds "
for f in $seed_files; do
	[ \"\$(cat \$f)\" = seed ] || fail \"\$f: the host's content is not readable in the view\"
	printf 'rewritten\n' > \$f && chmod 0640 \$f || fail \"\$f: cannot rewrite\"
done
rm -f /var/lib/$tag/seed
printf 'new\n' > /etc/$tag.new
mkdir -p /var/lib/$tag/sub /run/$tag && printf 'new\n' > /var/lib/$tag/sub/new && printf 'new\n' > /run/$tag/new
printf 'new\n' > /var/log/$tag.log
for d in /srv/$tag /opt/$tag /root/$tag /tmp/$tag; do printf 'new\n' > \$d/new || fail \"\$d: cannot create\"; done
[ ! -e /var/lib/$tag/seed ] || fail 'the unlink is not visible'
for f in /etc/$tag.seed /srv/$tag/seed /opt/$tag/seed /root/$tag/seed /tmp/$tag/seed; do
	[ \"\$(sh -c \"cat \$f\")\" = rewritten ] || fail \"\$f: a child does not see the rewrite\"
	[ \"\$(stat -c %a \$f)\" = 640 ] || fail \"\$f: the chmod is not visible\"
done
for f in /etc/$tag.new /var/lib/$tag/sub/new /run/$tag/new /var/log/$tag.log /srv/$tag/new /tmp/$tag/new; do
	[ \"\$(sh -c \"cat \$f\")\" = new ] || fail \"\$f: a child does not see the new file\"
done"
seed_hosts() {
	mkdir -p "/var/lib/$tag" "/srv/$tag" "/opt/$tag" "/root/$tag" "/tmp/$tag"
	for f in $seed_files; do printf 'seed\n' >"$f"; chmod 0600 "$f"; done
}

# ── [F1-symlink] ─────────────────────────────────────────────────────────
mkfake f1 "
f=/var/log/$tag-f1/target.log
[ \"\$(cat \$f)\" = orig ] || fail 'the symlinked target is not readable'
chmod 0600 \$f && printf 'more\n' >> \$f && printf 'new\n' > /var/log/$tag-f1/new || fail 'cannot write through the symlink'
[ \"\$(stat -c %a \$f)\" = 600 ] || fail 'the chmod through the symlink is not visible'
[ \"\$(sh -c \"cat /var/log/$tag-f1/new\")\" = new ] || fail 'a child does not see the new file'"
seed_f1() {
	mkdir -p "/srv/$tag-f1"
	printf 'orig\n' >"/srv/$tag-f1/target.log"
	chmod 0644 "/srv/$tag-f1/target.log"
	ln -sfn "/srv/$tag-f1" "/var/log/$tag-f1"
}

# ── [F2-cwd] ─────────────────────────────────────────────────────────────
# The relative writes come FIRST, before any check can exit: a cwd that still
# names the host directory must show up as a host change, not only as a
# wrong pwd.
mkfake cwd "
seen=\$(cat ./seed)
printf 'rewritten\n' > ./seed && printf 'new\n' > ./new || fail 'cannot write relative to the cwd'
[ \"\$(pwd -P)\" = /etc/$tag-cwd ] || fail \"the command runs in \$(pwd -P), not in /etc/$tag-cwd\"
[ \"\$seen\" = cwd-seed ] || fail 'a relative read does not see the host file'
[ \"\$(cat ./new)\" = new ] || fail 'the relative write is not visible'"

# ── [F2-fds] ─────────────────────────────────────────────────────────────
mkfake fds "
for n in 6 7; do [ ! -e /proc/self/fd/\$n ] || { echo leaked >&7; fail \"descriptor \$n from the caller is still open\"; }; done"

# ── [pass-through] ───────────────────────────────────────────────────────
mkfake pass "
printf 'kept\n' > $W/pass.out && [ \"\$(cat $W/pass.out)\" = kept ] || fail 'cannot write under TMPDIR'"

# ── [read-only] ──────────────────────────────────────────────────────────
# A disposable vfat image, not the host's /boot/efi: an ambient mount that is
# already read-only would let a view that forgot its remount pass (Codex P2 on
# 41dcb74e6d). The fixture proves itself writable before each run.
vfat=/srv/$tag-vfat
vfat_img=
if command -v busybox >/dev/null 2>&1; then
	vfat_img="$W/vfat.img"
	truncate -s 8M "$vfat_img" && busybox mkdosfs "$vfat_img" >/dev/null 2>&1 || vfat_img=
fi
mkfake ro "
ls '$vfat' >/dev/null || fail 'the vfat mount is not readable'
if touch '$vfat/$tag' 2>/dev/null; then fail 'the vfat mount is writable in the view'; fi"

# ── the private /dev (Codex P1 on 468f7d2371) ────────────────────────────
# mountinfo as "mountpoint options fstype source", one line per mount.
mounts_awk='{for (i = 7; i <= NF; i++) if ($i == "-") break; print $5, $6, $(i + 1), $(i + 2)}'
mkfake devprivate "
mi=\$(awk '$mounts_awk' /proc/self/mountinfo)
echo \"\$mi\" | grep -q '^/dev [^ ]* tmpfs testguard-dev\$' || fail '/dev is not the private testguard tmpfs'
echo \"\$mi\" | awk '\$1 == \"/dev\" {print \$2}' | tr , '\n' | grep -qx nodev || fail 'the private /dev is not nodev'
for n in \$(find /dev \( -type b -o -type c \) -print); do
	case \$n in
	/dev/null | /dev/zero | /dev/full | /dev/random | /dev/urandom | /dev/tty | /dev/net/tun | /dev/pts/*) ;;
	*) fail \"\$n is a device node outside the allowlist\" ;;
	esac
done
echo \"\$mi\" | awk '\$3 == \"overlay\"' | grep -q . || fail 'FIXTURE: no overlay in the view'
echo \"\$mi\" | awk '\$3 == \"overlay\" {print \$1, \$2}' | while read -r mp opts; do
	echo \",\$opts,\" | grep -q ',nodev,' || fail \"the overlay at \$mp is not nodev\"
done || exit 7"

# A disposable loop device backs the block nodes below, so a node that could
# be opened reaches only this image. Without one these cells are skipped as
# coverage unavailable.
blk_maj='' blk_min=''
if command -v losetup >/dev/null 2>&1; then
	truncate -s 1M "$W/blk.img"
	trace "loop device"
	loopdev=$(losetup -f --show "$W/blk.img" 2>/dev/null) || loopdev=
	if [ -n "$loopdev" ]; then
		blk_maj=$((16#$(stat -c %t "$loopdev")))
		blk_min=$((16#$(stat -c %T "$loopdev")))
	fi
fi

# [dev-late-block]: the command signals that the view is up, the host then
# creates a block node in ITS /dev, and the command looks for it.
mkfake latedev "
touch $W/late.ready
i=0
while [ ! -e $W/late.go ]; do
	sleep 0.1; i=\$((i + 1)); [ \$i -lt 600 ] || fail 'FIXTURE: the host never created the late node'
done
[ ! -e /dev/$tag-late ] || fail '/dev/$tag-late, created on the host after the view was built, is visible in the view'
[ ! -e '${loopdev:-/nonexistent}' ] || fail 'the host loop device ${loopdev} is visible in the view'
[ ! -e /dev/block ] || fail '/dev/block, the host udev alias tree, is visible in the view'
b=\$(find /dev -type b 2>/dev/null | tr '\n' ' ')
[ -z \"\$b\" ] || fail \"block nodes in the view's /dev: \$b\""

# [dev-nodev]: a block node made inside the view's /dev for the loop device.
mkfake devnodev "
mknod /dev/$tag-inside b $blk_maj $blk_min 2>/dev/null || exit 5 # no CAP_MKNOD (user namespace): nothing to open
if ( exec 3<>/dev/$tag-inside ) 2>/dev/null; then fail 'a block node created in the view /dev can be opened'; fi
rm -f /dev/$tag-inside"

# [nodev-overlay]: a block node the host keeps on its root filesystem.
mkfake nodevov "
[ -b /srv/$tag-blk ] || fail 'FIXTURE: the host block node /srv/$tag-blk is not visible'
if ( exec 3<>/srv/$tag-blk ) 2>/dev/null; then fail 'a block node on host storage outside /dev opens read-write in the view'; fi
if ( exec 3</srv/$tag-blk ) 2>/dev/null; then fail 'a block node on host storage outside /dev opens read-only in the view'; fi"

# [dev-chardev]
mkfake devchar "
echo x >/dev/null || fail 'cannot write /dev/null'
[ \"\$(head -c 16 /dev/zero | wc -c)\" = 16 ] || fail 'cannot read /dev/zero'
[ \"\$(head -c 16 /dev/urandom | wc -c)\" = 16 ] || fail 'cannot read /dev/urandom'
if (echo x >/dev/full) 2>/dev/null; then fail '/dev/full accepted a write'; fi
[ -L /dev/fd ] && [ -e /dev/stdin ] || fail '/dev/fd or /dev/stdin is missing'
if touch -m -d @0 /dev/full 2>/dev/null; then fail 'the view changed the times of the host inode of /dev/full'; fi"

# [dev-pts]: the host's devpts device number, read outside the view.
host_pts_dev=$(stat -c %d /dev/pts)
mkfake devpts "
( exec 5<>/dev/ptmx ) || fail 'cannot open /dev/ptmx'
[ \"\$(stat -c %d /dev/pts)\" != '$host_pts_dev' ] || fail '/dev/pts is the host devpts instance'"

# [dev-shm]
mkfake devshm "
mi=\$(awk '$mounts_awk' /proc/self/mountinfo)
[ \"\$(echo \"\$mi\" | awk '\$1 == \"/dev/shm\"' | wc -l)\" = 1 ] || fail '/dev/shm has more than one mount in the view'
echo \"\$mi\" | grep -q '^/dev/shm [^ ]* tmpfs testguard-shm\$' || fail '/dev/shm is not the private testguard tmpfs'
printf 'shm\n' >/dev/shm/$tag.shm && [ \"\$(cat /dev/shm/$tag.shm)\" = shm ] || fail 'cannot write /dev/shm'"

run_tg() { # $1 cwd, then the command; sets out and rc
	out=$(cd "$1" && shift && bash "$here/testguard-run.sh" "$@" 2>&1)
	rc=$?
}

branch_cases() { # $1 label
	local b=$1 before after
	trace "seed $b"

	seed_hosts
	before=$(host_state $seed_files $seed_new)
	run_tg / "$W/seeds"
	[ "$rc" = 0 ] && ok "[seeds] $b: every change was visible to the command and a child" ||
		bad "[seeds] $b: testguard-run exited $rc (7 = a change was not visible): $out"
	after=$(host_state $seed_files $seed_new)
	[ "$before" = "$after" ] && ok "[seeds] $b: the host's seeds in /etc /var/lib /srv /opt /root /tmp are unchanged and nothing new appeared" ||
		bad "[seeds] $b: the host changed: $(diff <(echo "$before") <(echo "$after") | grep '^[<>]' | tr '\n' ' ')"
	for p in $seed_files $seed_new; do rm -rf "$p"; done

	seed_f1
	before=$(host_state "/srv/$tag-f1/target.log" "/srv/$tag-f1/new")
	run_tg / "$W/f1"
	[ "$rc" = 0 ] && ok "[F1-symlink] $b: writes through /var/log/$tag-f1 -> /srv were visible inside" ||
		bad "[F1-symlink] $b: testguard-run exited $rc: $out"
	after=$(host_state "/srv/$tag-f1/target.log" "/srv/$tag-f1/new")
	[ "$before" = "$after" ] && ok "[F1-symlink] $b: the symlink's host target kept its mode, bytes and mtime" ||
		bad "[F1-symlink] $b: the host target changed: before [$before] after [$after]"
	rm -rf "/var/log/$tag-f1" "/srv/$tag-f1"

	mkdir -p "/etc/$tag-cwd"
	printf 'cwd-seed\n' >"/etc/$tag-cwd/seed"
	before=$(host_state "/etc/$tag-cwd/seed" "/etc/$tag-cwd/new")
	run_tg "/etc/$tag-cwd" "$W/cwd"
	[ "$rc" = 0 ] && ok "[F2-cwd] $b: the command ran in its cwd inside the view" ||
		bad "[F2-cwd] $b: testguard-run exited $rc: $out"
	after=$(host_state "/etc/$tag-cwd/seed" "/etc/$tag-cwd/new")
	[ "$before" = "$after" ] && ok "[F2-cwd] $b: relative writes from a host cwd stayed private" ||
		bad "[F2-cwd] $b: the host cwd changed: before [$before] after [$after]"
	rm -rf "/etc/$tag-cwd"

	mkdir -p "/srv/$tag-fd"
	printf 'fd-seed\n' >"/srv/$tag-fd/file"
	before=$(host_state "/srv/$tag-fd/file")
	out=$(bash -c 'exec 7>>"$1" 6<"$2"; shift 2; exec bash "$@"' _ "/srv/$tag-fd/file" "/srv/$tag-fd" "$here/testguard-run.sh" "$W/fds" 2>&1)
	rc=$?
	[ "$rc" = 0 ] && ok "[F2-fds] $b: descriptors 6 and 7 from the caller were closed before exec" ||
		bad "[F2-fds] $b: testguard-run exited $rc: $out"
	after=$(host_state "/srv/$tag-fd/file")
	[ "$before" = "$after" ] && ok "[F2-fds] $b: nothing was written through an inherited descriptor" ||
		bad "[F2-fds] $b: the host file changed: before [$before] after [$after]"
	rm -rf "/srv/$tag-fd"

	rm -f "$W/pass.out"
	run_tg / "$W/pass"
	if [ "$rc" = 0 ] && [ "$(cat "$W/pass.out" 2>/dev/null)" = kept ]; then
		ok "[pass-through] $b: a write under TMPDIR reached the host"
	else
		bad "[pass-through] $b: rc $rc, host file: '$(cat "$W/pass.out" 2>&1)': $out"
	fi

	if [ -n "$vfat_img" ]; then
		mkdir -p "$vfat"
		# 98: the fixture was not writable before the run (no control);
		# 97: the command's write reached the fixture; 99: no loop mount.
		out=$(unshare -m --propagation private bash -c '
			mount -o loop "$2" "$1" || exit 99
			touch "$1/writable-before" && rm -f "$1/writable-before" || exit 98
			bash "$3" "$4"; rc=$?
			[ -e "$1/$5" ] && exit 97
			exit "$rc"' _ "$vfat" "$vfat_img" "$here/testguard-run.sh" "$W/ro" "$tag" 2>&1)
		rc=$?
		case $rc in
		0) ok "[read-only] $b: a writable vfat fixture is read-only in the view" ;;
		99) echo "  skip [read-only] $b: coverage unavailable (no loop mount for the vfat fixture): $out" ;;
		*) bad "[read-only] $b: exit $rc (97 = the write reached the fixture, 98 = fixture not writable): $out" ;;
		esac
	else
		echo "  skip [read-only] $b: coverage unavailable (no busybox mkdosfs for a vfat fixture)"
	fi

	run_tg / "$W/devprivate"
	[ "$rc" = 0 ] && ok "[dev-private] $b: /dev is the private nodev tmpfs with only allowlisted devices, and every overlay is nodev" ||
		bad "[dev-private] $b: testguard-run exited $rc: $out"

	if [ -n "$loopdev" ]; then
		rm -f "$W/late.ready" "$W/late.go"
		(cd / && bash "$here/testguard-run.sh" "$W/latedev") >"$W/late.out" 2>&1 &
		lpid=$!
		i=0
		while [ ! -e "$W/late.ready" ] && kill -0 "$lpid" 2>/dev/null && [ $i -lt 600 ]; do
			sleep 0.1
			i=$((i + 1))
		done
		trace "seed late block node $b"
		mknod "/dev/$tag-late" b "$blk_maj" "$blk_min" 2>/dev/null
		late_made=$([ -b "/dev/$tag-late" ] && echo yes || echo no)
		touch "$W/late.go"
		wait "$lpid"
		rc=$?
		rm -f "/dev/$tag-late"
		if [ "$late_made" != yes ]; then
			bad "[dev-late-block] $b: FIXTURE: the host could not create /dev/$tag-late"
		elif [ "$rc" = 0 ]; then
			ok "[dev-late-block] $b: a block node created on the host after setup is not in the view, and no block node is"
		else
			bad "[dev-late-block] $b: testguard-run exited $rc: $(cat "$W/late.out")"
		fi

		run_tg / "$W/devnodev"
		case $rc in
		0) ok "[dev-nodev] $b: a block node created inside the view's /dev cannot be opened" ;;
		5) echo "  skip [dev-nodev] $b: this path cannot create a device node (no CAP_MKNOD in its user namespace), so there is nothing to open" ;;
		*) bad "[dev-nodev] $b: testguard-run exited $rc: $out" ;;
		esac

		trace "seed host block node $b"
		mknod "/srv/$tag-blk" b "$blk_maj" "$blk_min"
		run_tg / "$W/nodevov"
		[ "$rc" = 0 ] && ok "[nodev-overlay] $b: a block node on host storage outside /dev cannot be opened" ||
			bad "[nodev-overlay] $b: testguard-run exited $rc: $out"
		rm -f "/srv/$tag-blk"
	else
		echo "  skip [dev-late-block] [dev-nodev] [nodev-overlay] $b: coverage unavailable (no loop device for a disposable block node)"
	fi

	before=$(stat -c '%a %X %Y %Z' /dev/full)
	run_tg / "$W/devchar"
	after=$(stat -c '%a %X %Y %Z' /dev/full)
	if [ "$rc" = 0 ] && [ "$before" = "$after" ]; then
		ok "[dev-chardev] $b: the allowlisted devices work, and the host inode of /dev/full is unchanged"
	else
		bad "[dev-chardev] $b: exit $rc, host /dev/full [$before] -> [$after]: $out"
	fi

	run_tg / "$W/devpts"
	[ "$rc" = 0 ] && ok "[dev-pts] $b: /dev/pts is a fresh devpts instance, and /dev/ptmx opens" ||
		bad "[dev-pts] $b: testguard-run exited $rc: $out"

	rm -f "/dev/shm/$tag.shm"
	run_tg / "$W/devshm"
	if [ "$rc" = 0 ] && [ ! -e "/dev/shm/$tag.shm" ]; then
		ok "[dev-shm] $b: /dev/shm is a fresh tmpfs, and a write there did not reach the host"
	else
		bad "[dev-shm] $b: exit $rc, host /dev/shm/$tag.shm: $([ -e "/dev/shm/$tag.shm" ] && echo present || echo absent): $out"
	fi
	rm -f "/dev/shm/$tag.shm"
}

# ── user-namespace path: the proof ignored, never deleted ────────────────
export XPF_TESTGUARD_NO_VM_PROOF=1
branch_cases "user-namespace path"

# [R1-detach] control: there the inherited mounts are locked, so the command
# cannot detach the view, and the run passes.
mkfake detach 'umount -l / 2>/dev/null; exit 0'
run_tg / "$W/detach"
[ "$rc" = 0 ] && ok "[R1-detach] user-namespace path: a command cannot detach the locked view; the run passes" ||
	bad "[R1-detach] user-namespace path: exit $rc, want 0: $out"

# ── [F3-id]: an `id` that fails refuses the run ──────────────────────────
mkdir -p "$W/badid"
printf '#!/bin/sh\nexit 1\n' >"$W/badid/id"
chmod +x "$W/badid/id"
mkfake marker "touch $W/f3.marker"
rm -f "$W/f3.marker"
out=$(PATH="$W/badid:$PATH" bash "$here/testguard-run.sh" "$W/marker" 2>&1)
rc=$?
if [ "$rc" = 2 ] && [ ! -e "$W/f3.marker" ]; then
	ok "[F3-id] a failing id refuses the run (exit 2) and the command never runs"
else
	bad "[F3-id] exit $rc (want 2), command ran: $([ -e "$W/f3.marker" ] && echo yes || echo no): $out"
fi

# ── [unsupported]: a mount the wrapper cannot place refuses the run ──────
trace "seed unsupported"
mkdir -p "/srv/$tag-unsup"
rm -f "$W/f3.marker"
out=$(unshare -m --propagation private bash -c 'mount -t ramfs tg-unsupported "$1" || exit 99; shift; exec bash "$@"' _ \
	"/srv/$tag-unsup" "$here/testguard-run.sh" "$W/marker" 2>&1)
rc=$?
if [ "$rc" = 2 ] && [ ! -e "$W/f3.marker" ] && [[ $out == *"/srv/$tag-unsup is ramfs"* ]]; then
	ok "[unsupported] a ramfs mount the wrapper cannot place refuses the run (exit 2), naming it"
else
	bad "[unsupported] exit $rc (want 2; 99 = fixture mount failed), command ran: $([ -e "$W/f3.marker" ] && echo yes || echo no): $out"
fi
rm -rf "/srv/$tag-unsup"

# ── [pass-through-refused]: a pass-through below /etc refuses the run ────
# R19 F4: the system-tree check matches whole trees, not only exact roots,
# and it runs before the directory is created.
rm -f "$W/f3.marker"
out=$(GOCACHE="/etc/$tag-cache" bash "$here/testguard-run.sh" "$W/marker" 2>&1)
rc=$?
if [ "$rc" = 2 ] && [ ! -e "$W/f3.marker" ] && [ ! -e "/etc/$tag-cache" ] && [[ $out == *"would expose a host system tree"* ]]; then
	ok "[pass-through-refused] GOCACHE below /etc refuses the run (exit 2) without creating it"
else
	bad "[pass-through-refused] exit $rc (want 2), command ran: $([ -e "$W/f3.marker" ] && echo yes || echo no), /etc/$tag-cache created: $([ -e "/etc/$tag-cache" ] && echo yes || echo no): $out"
fi
rm -rf "/etc/$tag-cache"

# ── [procfs-alias]: a host procfs alias refuses the run ──────────────────
trace "seed procfs-alias"
mkdir -p "/srv/$tag-hostproc"
rm -f "$W/f3.marker"
out=$(unshare -m --propagation private bash -c 'mount -t proc proc "$1" || exit 99; shift; exec bash "$@"' _ \
	"/srv/$tag-hostproc" "$here/testguard-run.sh" "$W/marker" 2>&1)
rc=$?
if [ "$rc" = 2 ] && [ ! -e "$W/f3.marker" ] && [[ $out == *"/srv/$tag-hostproc is a procfs other than /proc"* ]]; then
	ok "[procfs-alias] a procfs alias at /srv refuses the run (exit 2), naming it"
else
	bad "[procfs-alias] exit $rc (want 2; 99 = fixture mount failed), command ran: $([ -e "$W/f3.marker" ] && echo yes || echo no): $out"
fi

# ── [procfs-pass-through]: the same alias, selected as GOCACHE ───────────
# Codex P1 on 468f7d2371: the pass-through skip ran before the procfs check,
# so the alias was bound in writable with the pass-through.
rm -f "$W/f3.marker"
out=$(unshare -m --propagation private bash -c 'mount -t proc proc "$1" || exit 99; GOCACHE=$1 exec bash "$2" "$3"' _ \
	"/srv/$tag-hostproc" "$here/testguard-run.sh" "$W/marker" 2>&1)
rc=$?
if [ "$rc" = 2 ] && [ ! -e "$W/f3.marker" ] && [[ $out == *"/srv/$tag-hostproc is a procfs other than /proc"* ]]; then
	ok "[procfs-pass-through] a procfs alias selected as GOCACHE refuses the run (exit 2), naming it"
else
	bad "[procfs-pass-through] exit $rc (want 2; 99 = fixture mount failed), command ran: $([ -e "$W/f3.marker" ] && echo yes || echo no): $out"
fi
rm -rf "/srv/$tag-hostproc"

# ── [tmpdir-refused]: a TMPDIR below /etc refuses before it is created ───
# Codex P2 on 468f7d2371: the scratch was created before any check.
rm -f "$W/f3.marker"
out=$(TMPDIR="/etc/$tag-tmp" bash "$here/testguard-run.sh" "$W/marker" 2>&1)
rc=$?
if [ "$rc" = 2 ] && [ ! -e "$W/f3.marker" ] && [ ! -e "/etc/$tag-tmp" ] && [[ $out == *"would expose a host system tree"* ]]; then
	ok "[tmpdir-refused] TMPDIR below /etc refuses the run (exit 2) without creating it"
else
	bad "[tmpdir-refused] exit $rc (want 2), command ran: $([ -e "$W/f3.marker" ] && echo yes || echo no), /etc/$tag-tmp created: $([ -e "/etc/$tag-tmp" ] && echo yes || echo no): $out"
fi
rm -rf "/etc/$tag-tmp"

# ── [F4-vm]: on a non-VM this selftest touches nothing ───────────────────
if [ -z "${TG_SELFTEST_NESTED:-}" ]; then
	mkdir -p "$W/nonvm"
	printf '#!/bin/sh\necho none\nexit 1\n' >"$W/nonvm/systemd-detect-virt"
	chmod +x "$W/nonvm/systemd-detect-virt"
	before=$(host_state "$proof")
	out=$(PATH="$W/nonvm:$PATH" TG_SELFTEST_NESTED=1 TG_SELFTEST_TRACE="$W/f4.trace" bash "$0" 2>&1)
	rc=$?
	after=$(host_state "$proof")
	if [ "$rc" = 2 ] && [ ! -s "$W/f4.trace" ] && [ "$before" = "$after" ]; then
		ok "[F4-vm] on a non-VM the selftest refuses (exit 2) before touching the proof or seeding"
	else
		bad "[F4-vm] exit $rc (want 2), host actions before the refusal: [$(tr '\n' ' ' <"$W/f4.trace" 2>/dev/null)], proof [$before] -> [$after]: $out"
	fi
fi

# ── VM-proof path: only on a runner that is already marked ───────────────
unset XPF_TESTGUARD_NO_VM_PROOF
proof_ok=0
if [ -f "$proof" ] && [ ! -L "$proof" ] && [ "$(stat -c '%u %a' "$proof" 2>/dev/null)" = "0 444" ] &&
	[ "$(cat "$proof")" = "$(cat /proc/sys/kernel/random/boot_id)" ]; then
	proof_ok=1
fi
if [ "$proof_ok" != 1 ]; then
	echo "  skip VM-proof path: coverage unavailable, this runner has no VM proof for this boot (make vm-test-root marks it before running this selftest)"
else
	branch_cases "VM-proof path"
	run_tg / "$W/detach"
	if [ "$rc" = 1 ] && [[ $out == *"root view is no longer mounted"* ]]; then
		ok "[R1-detach] VM-proof path: a command that detaches the root view FAILS the run (exit 1)"
	else
		bad "[R1-detach] VM-proof path: exit $rc, want 1 with the root-view FAIL: $out"
	fi
fi

# ── [detector]: the residue check still sees a pass-through state change ─
mkdir -p "$W/state"
printf 'seed\n' >"$W/state/xpf.sources"
mkfake uncovered "rm -f $W/state/xpf.sources"
XPF_RESIDUE_EXTRA_STATE_PATHS="$W/state" bash "$here/testguard-run.sh" "$W/uncovered" >/dev/null 2>&1
rc=$?
[ "$rc" = 1 ] && ok "[detector] a root run that deletes a watched state file through the pass-through FAILS (exit 1)" ||
	bad "[detector] exit $rc, want 1"

if [ "$(proof_state)" = "$proof_at_start" ]; then
	ok "[proof-untouched] the runner's VM proof is exactly as it was before the selftest"
else
	bad "[proof-untouched] the VM proof changed: [$proof_at_start] -> [$(proof_state)]"
fi

printf '\ntestguard-overlay-selftest: passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
