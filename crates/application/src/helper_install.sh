# Invoked with fixed paths and a SHA-256 from the embedded desktop payload.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
source_dir=$1
expected=$2
expected_old=$3
target=/usr/local/libexec/vam-server
control=/var/lib/vpn-appliance-manager/control
check='vpnctl-helper protocol=2 schema=1 instance_archives_v1 drop_peer_v1 dns_blocking_v1'
fail() { echo "Helper update: $*" >&2; exit 1; }
protected_dir() {
    [ ! -L "$1" ] && [ -d "$1" ] || fail "unsafe directory $1"
    [ "$(stat -c %u "$1")" = 0 ] || fail "directory is not owned by root: $1"
    [ -z "$(find "$1" -maxdepth 0 -perm /022 -print)" ] || fail "directory is writable by other users: $1"
}
protected_file() {
    [ ! -L "$1" ] && [ -f "$1" ] || fail "unsafe file $1"
    [ "$(stat -c %u "$1")" = 0 ] || fail "file is not owned by root: $1"
    [ -z "$(find "$1" -maxdepth 0 -perm /022 -print)" ] || fail "file is writable by other users: $1"
}
for dir in /usr /usr/local /usr/local/libexec /var /var/lib /var/lib/vpn-appliance-manager "$control"; do protected_dir "$dir"; done
protected_file "$target"
# Root-owned directory makes these lock files immune to unprivileged substitution.
for lock in /usr/local/libexec/.vam-server-update.lock "$control/mutation.lock"; do
    if [ -e "$lock" ] || [ -L "$lock" ]; then protected_file "$lock"; fi
done
exec 8>/usr/local/libexec/.vam-server-update.lock
flock -w 40 8 || fail 'another helper update is in progress; reconnect to retry'
exec 9<>"$control/mutation.lock"
flock -w 40 9 || fail 'a server operation is in progress; reconnect to retry'
work=$(mktemp -d /usr/local/libexec/.vam-server-update.XXXXXXXXXX)
installed=0
completed=0
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$installed" = 1 ] && [ "$completed" = 0 ]; then
        if cp -p "$backup" "$work/rollback" && mv -fT "$work/rollback" "$target" && sync -f /usr/local/libexec; then
            echo 'Helper update failed; previous helper restored.' >&2
        else
            echo "Helper rollback failed; restore $backup to $target before reconnecting." >&2
        fi
    fi
    rm -rf -- "$work" "$source_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
# Copy first, then hash the immutable root-owned candidate, never execute the upload.
cp -- "$source_dir/vam-server" "$work/candidate"
chmod 0700 "$work/candidate"
actual=$(sha256sum "$work/candidate"); actual=${actual%% *}
[ "$actual" = "$expected" ] || fail 'payload checksum mismatch; installed helper unchanged'
reported=$("$work/candidate" self-check) || fail 'candidate cannot run; installed helper unchanged'
[ "$reported" = "$check" ] || fail 'candidate cannot run or has incompatible capabilities; installed helper unchanged'
old=$(sha256sum "$target"); old=${old%% *}
if [ "$old" = "$expected" ]; then completed=1; echo helper_already_current; exit 0; fi
# A different desktop may have installed a capable (or newer) helper since Info.
# Never overwrite that helper just because its executable checksum differs.
if current=$("$target" self-check 2>/dev/null); then
    case "$current" in
        'vpnctl-helper protocol=2 schema=1 '*)
            capable=1
            for capability in instance_archives_v1 drop_peer_v1 dns_blocking_v1; do
                case " $current " in *" $capability "*) ;; *) capable=0 ;; esac
            done
            if [ "$capable" = 1 ]; then completed=1; echo helper_already_current; exit 0; fi
            ;;
        'vpnctl-helper '*) fail 'installed helper compatibility changed; reconnect before retrying' ;;
    esac
fi
[ "$old" = "$expected_old" ] || fail 'installed helper changed during repair; reconnect before retrying'
backup="/usr/local/libexec/vam-server.backup-$old"
if [ -e "$backup" ] || [ -L "$backup" ]; then
    protected_file "$backup"
    saved=$(sha256sum "$backup"); saved=${saved%% *}
    [ "$saved" = "$old" ] || fail 'existing recovery backup checksum mismatch'
else
    cp -p "$target" "$work/backup"
    sync -f "$work/backup"
    mv -T "$work/backup" "$backup"
fi
chmod 0755 "$work/candidate"
sync -f "$work/candidate"
# Mark before rename so a signal between rename and the next command also rolls back.
installed=1
mv -fT "$work/candidate" "$target"
sync -f /usr/local/libexec
reported=$("$target" self-check) || fail 'installed helper exited with an error'
[ "$reported" = "$check" ] || fail 'installed helper failed its check'
completed=1
echo helper_updated
