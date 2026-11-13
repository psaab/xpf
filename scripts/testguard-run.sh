#!/usr/bin/env bash
# Run a command with private net+mount namespaces and an observable PID 1
# baseline for internal/testguard. The parent PID 1 keeps the original
# namespaces; the child enters both namespaces before exec. Host residue is
# measured read-only before and after and reported without cleanup.
set -euo pipefail
if (($# == 0)); then
	echo "usage: testguard-run.sh command [args...]" >&2
	exit 2
fi
root=$(cd "$(dirname "$0")/.." && pwd)
shim_dir="$root/test/support/host-bin-shims"
real_path=
IFS=: read -r -a path_entries <<<"$PATH"
for entry in "${path_entries[@]}"; do
	[[ -n "$entry" && "$entry" != "$shim_dir" ]] || continue
	real_path="${real_path:+$real_path:}$entry"
done
if [[ -n "$real_path" ]]; then
	PATH="$shim_dir:$real_path"
else
	PATH="$shim_dir"
fi
export PATH
# #19084 Codex F3: the effective UID decides whether the run gets the root
# view below, so it is resolved ONCE and validated. An `id` that fails, prints
# nothing or disagrees with the shell's own EUID is not read as "unprivileged":
# that would run a real-root command with no protection at all.
euid=$(id -u 2>/dev/null) || euid=
if [[ ! $euid =~ ^[0-9]+$ || $euid != "$EUID" ]]; then
	echo "testguard-run: REFUSED: cannot determine the effective UID (id -u gave '$euid', the shell says $EUID); refusing rather than treat the run as unprivileged (#19084)" >&2
	exit 2
fi
# The caller's working directory, re-established inside the root view.
cwd=$(pwd -P 2>/dev/null) || cwd=
# #19066: inside these namespaces a further private namespace is always
# creatable, so a test that could not get one has a broken mechanism, not an
# unlucky environment. Netns cells report that through
# testguard.NetnsUnavailable, which FAILS under XPF_REQUIRE_NETNS instead of
# skipping. Before this, 10 re-exec cells skipped as "netns unavailable" on
# every run while the package guard was refusing their child.
export XPF_REQUIRE_NETNS=1

command=$1
shift
if [[ "$command" == go || "$command" == "$shim_dir/go" ]]; then
	go_bin=$(PATH="$real_path" command -v go) || {
		echo "testguard-run: real Go binary not found" >&2
		exit 127
	}
	set -- "$go_bin" "$@"
else
	set -- "$command" "$@"
fi
scratch=${TMPDIR:-/var/worktrees/.cache/tmpdir}
mkdir -p "$scratch"
work=$(mktemp -d "$scratch/testguard-run.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
"$root/scripts/host-residue-snapshot.sh" "$work/before.txt"
set +e
proof=/run/xpf-testguard-vm-boot-id
current_boot=$(cat /proc/sys/kernel/random/boot_id)
proof_boot=
if [[ -f "$proof" && ! -L "$proof" ]] &&
	[[ $(stat -c '%u %a' "$proof" 2>/dev/null || true) == "0 444" ]]; then
	proof_boot=$(cat "$proof")
fi
# #18559: inside the private net namespace, bring loopback UP before the
# command runs. A fresh namespace starts with `lo` DOWN and every package of
# one `go test ./...` shares it, so before this a cell that serves or dials
# 127.0.0.1 passed or failed by TEST ORDER: it passed only if a fixture that
# raises lo itself (pkg/cluster's ensureLoopbackRoutable18038,
# #18952/#18960; pkg/daemon's sync-pair repairs, #18933/#18935) had already
# run. Loopback is private
# to the namespace, so isolation from the host is unchanged. A failure to
# raise it is reported, not hidden.
inner='ip link set lo up 2>/dev/null || echo "testguard-run: could not bring loopback up in the test namespace" >&2; exec "$@"'
# #19084: a ROOT run executes inside a throwaway view of the WHOLE root
# filesystem (scripts/testguard-root-view.sh). A private mount namespace alone
# isolates nothing on disk: a root test that writes or unlinks /etc/... does it
# on the host's root filesystem. Redirecting production paths one by one
# missed some (R18's 46-file seeded probe: 7 deleted or rewritten after the
# redirects), and so did covering a fixed list of trees: a directory symlink
# in a covered tree that resolved outside it, or any uncovered tree (/srv,
# /opt, /root, /tmp, ...), still reached the host (Codex F1, R18 R2 on
# 11eaccc637). So "/" itself is an overlay whose lower layer is the host's
# root filesystem and whose upper layer is a tmpfs that exists only in this
# namespace; every other mount is overlaid too, bound in read-only, bound in
# as a pseudo filesystem, or the run is refused (exit 2). Tests still READ
# the host's files and read back what they write, in-process and from child
# processes. The only writable host storage is the pass-through allowlist
# below. Host daemons are outside the namespace and keep the real files.
#
# The view is built by real root BEFORE any user namespace exists: inside the
# user namespace of the no-VM-proof path the inherited mounts are locked, and
# overlayfs cannot clone a lower tree with locked submounts (/run has several).
# Non-root runs are unchanged: they cannot write the host's system trees.
# The residue check below stays as the detector.
cover=()
inner_cmd=$inner
if [[ $euid == 0 ]]; then
	[[ -n $cwd ]] || { echo "testguard-run: REFUSED: cannot resolve the working directory for the root view (#19084)" >&2; exit 2; }
	# The writable pass-through: the checkout, the TMPDIR scratch (and this
	# run's work dir in it), and Go's build cache, module cache and build
	# temp. Nothing else on the host is writable from inside the view.
	pass_raw=("$root" "$scratch")
	go_vars=()
	if gobin=$(PATH="$real_path" command -v go 2>/dev/null); then
		mapfile -t go_vars < <(PATH="$real_path" "$gobin" env GOCACHE GOMODCACHE GOTMPDIR 2>/dev/null)
	fi
	pass_raw+=("${GOCACHE:-${go_vars[0]:-}}" "${GOMODCACHE:-${go_vars[1]:-}}" "${GOTMPDIR:-${go_vars[2]:-}}")
	pass=()
	for p in "${pass_raw[@]}"; do
		[[ -n $p && $p != off ]] || continue
		mkdir -p "$p" 2>/dev/null && p=$(realpath -e "$p" 2>/dev/null) || {
			echo "testguard-run: REFUSED: cannot resolve the pass-through directory '$p' (#19084)" >&2
			exit 2
		}
		case $p in
		/ | /etc | /usr | /var | /var/lib | /var/log | /run | /boot | /proc | /sys | /dev | /home | /root | /srv | /opt | /bin | /sbin | /lib | /lib64 | /mnt | /media | /proc/* | /sys/* | /dev/* | /run/*)
			echo "testguard-run: REFUSED: pass-through directory $p would expose a host system tree; point TMPDIR/GOCACHE/GOMODCACHE/GOTMPDIR elsewhere (#19084)" >&2
			exit 2
			;;
		esac
		pass+=("$p")
	done
	mkdir -p "$work/overlay"
	cover=(unshare -m --propagation private bash "$root/scripts/testguard-root-view.sh" "$work/overlay" "$cwd" "${pass[@]}" --)
	# R18 R1: in the VM-proof branch the command keeps real root, so it can
	# detach mounts in its own namespace. The host's root filesystem is not
	# attached there (the view pivoted away from it), but a detached view is
	# no longer the run's view, so after the command the run's namespace must
	# still have the testguard root overlay at "/", or the run FAILS.
	# Detection only: a command with real root can also mount host block
	# devices or enter host namespaces, which no check here can stop.
	inner_cmd='ip link set lo up 2>/dev/null || echo "testguard-run: could not bring loopback up in the test namespace" >&2; "$@"; rc=$?; grep -qE "^[^ ]+ [^ ]+ [^ ]+ / / .* - overlay testguard-root( |\$)" /proc/self/mountinfo 2>/dev/null || { echo "testguard-run: FAIL: the root view is no longer mounted at / in the run'"'"'s namespace after the command (the command detached it?); its writes may not have been contained (#19084 R18 R1)" >&2; [ "$rc" -eq 0 ] && rc=1; }; exit "$rc"'
fi
if [[ $euid == 0 && -n "$current_boot" && "$proof_boot" == "$current_boot" ]]; then
	# The VM proof permits the privileged lane to retain its VM capabilities
	# (for BPF/memlock tests); namespace identity is still independently
	# checked by testguard in the child.
	XPF_SACRIFICIAL_HOST=1 "${cover[@]}" \
		unshare -pf --fork --mount-proc sh -c '(unshare -nm sh -c "$0" testguard-run "$@")' "$inner_cmd" "$@"
else
	# A caller-supplied intent sentinel is not proof; do not propagate it on
	# the workstation path.
	env -u XPF_SACRIFICIAL_HOST "${cover[@]}" \
		unshare -Urp --fork --mount-proc sh -c '(unshare -nm sh -c "$0" testguard-run "$@")' "$inner_cmd" "$@"
fi
rc=$?
set -e
"$root/scripts/host-residue-snapshot.sh" "$work/after.txt"
if ! cmp -s "$work/before.txt" "$work/after.txt"; then
	echo "HOST RESIDUE DIFFERENCE (report-only; no cleanup performed):"
	diff -u "$work/before.txt" "$work/after.txt" || true
fi
# #19066: a difference in the production state paths FAILS the run, with
# status 1 when the tests themselves passed. NOT 3: go-test-json.sh,
# go-test-watch.sh and the Makefile read 3 as VOID (a go-test timeout), which
# would turn a host mutation into "undetermined", and a rerun would come back
# clean because the files are already gone (#19066 R18). The rest of the
# report stays report-only (systemd session scopes come and go with other
# users of the host); these paths have no other writer on a test host, so a
# difference there is a test that wrote or deleted production state.
state_sections() { awk '/^--- state(-content)? /{on=1} /^--- / && !/^--- state(-content)? /{on=0} on' "$1"; }
if ! cmp -s <(state_sections "$work/before.txt") <(state_sections "$work/after.txt"); then
	echo "testguard-run: FAIL: the run changed production state paths on the host (no cleanup performed):" >&2
	diff -u <(state_sections "$work/before.txt") <(state_sections "$work/after.txt") >&2 || true
	[[ "$rc" -eq 0 ]] && rc=1
fi
exit "$rc"
