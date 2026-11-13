#!/usr/bin/env bash
# Run only inside a disposable Linux container, as root. Never on a managed host.
set -euo pipefail
[ "${VPNCTL_DISPOSABLE_INSTALLER_TEST:-}" = 1 ] || { echo 'Requires a disposable container' >&2; exit 1; }
installer=${VPNCTL_TEST_INSTALLER:-/workspace/crates/application/src/helper_install.sh}
target=/usr/local/libexec/vam-server
control=/var/lib/vpn-appliance-manager/control
mkdir -p /usr/local/libexec "$control"
chmod 0755 /usr/local/libexec /var/lib/vpn-appliance-manager "$control"
printf 'retained desired configuration\n' > "$control/test-manifest"
manifest_hash=$(sha256sum "$control/test-manifest")
make_old() {
  rm -f "$target" /usr/local/libexec/vam-server.backup-*
  printf '#!/bin/sh\necho old-helper\n' > "$target"
  chmod 0755 "$target"
  old_hash=$(sha256sum "$target"); old_hash=${old_hash%% *}
}
make_candidate() {
  stage=$(mktemp -d /tmp/vpnctl-helper.XXXXXXXXXX)
  cat > "$stage/vam-server" <<'CANDIDATE'
#!/bin/sh
printf '%s\n' 'vpnctl-helper protocol=2 schema=1 instance_archives_v1 drop_peer_v1 dns_blocking_v1'
CANDIDATE
  digest=$(sha256sum "$stage/vam-server"); digest=${digest%% *}
}
assert_old() { [ "$(sha256sum "$target" | cut -d ' ' -f 1)" = "$old_hash" ]; }
make_old; make_candidate
sh "$installer" "$stage" "$digest" "$old_hash"
[ ! -e "$stage" ]; [ -f "/usr/local/libexec/vam-server.backup-$old_hash" ]
[ "$(sha256sum "$target" | cut -d ' ' -f 1)" = "$digest" ]
echo 'PASS: atomic installation, backup and cleanup'
make_candidate
sh "$installer" "$stage" "$digest" "$old_hash" | grep -q helper_already_current
echo 'PASS: repeated installation is idempotent'
make_old; make_candidate
if sh "$installer" "$stage" "${digest//?/0}" "$old_hash"; then exit 1; fi
assert_old; [ ! -e "$stage" ]
echo 'PASS: corrupt payload preserves installed helper'
make_old; make_candidate
printf '#!/bin/sh\nexit 1\n' > "$stage/vam-server"
digest=$(sha256sum "$stage/vam-server"); digest=${digest%% *}
if sh "$installer" "$stage" "$digest" "$old_hash"; then exit 1; fi
assert_old
echo 'PASS: unusable executable preserves installed helper'
make_old; make_candidate
# Candidate passes in private staging, then fails after the atomic rename.
printf '\n[ "$0" != /usr/local/libexec/vam-server ]\n' >> "$stage/vam-server"
digest=$(sha256sum "$stage/vam-server"); digest=${digest%% *}
if sh "$installer" "$stage" "$digest" "$old_hash"; then exit 1; fi
assert_old
echo 'PASS: failed post-install check restores previous executable'
make_old; make_candidate
rm "$target"; ln -s /bin/sh "$target"
if sh "$installer" "$stage" "$digest" "$old_hash"; then exit 1; fi
[ -L "$target" ]; rm "$target"; rm -rf "$stage"
echo 'PASS: symlink target is refused'
make_old; make_candidate
# Another desktop installed a helper with a capability superset after our probe.
cat > "$target" <<'NEWER'
#!/bin/sh
echo 'vpnctl-helper protocol=2 schema=1 future_feature_v1 dns_blocking_v1 drop_peer_v1 instance_archives_v1'
NEWER
chmod 0755 "$target"
newer_hash=$(sha256sum "$target"); newer_hash=${newer_hash%% *}
sh "$installer" "$stage" "$digest" "$old_hash" | grep -q helper_already_current
[ "$(sha256sum "$target" | cut -d ' ' -f 1)" = "$newer_hash" ]
echo 'PASS: concurrent capable helper is never downgraded'
make_old; make_candidate
printf '# concurrent external change\n' >> "$target"
changed_hash=$(sha256sum "$target"); changed_hash=${changed_hash%% *}
if sh "$installer" "$stage" "$digest" "$old_hash"; then exit 1; fi
[ "$(sha256sum "$target" | cut -d ' ' -f 1)" = "$changed_hash" ]
echo 'PASS: unrecognized concurrent executable change is refused'
[ "$(sha256sum "$control/test-manifest")" = "$manifest_hash" ]
echo 'PASS: authority data remains unchanged'
# Optional actual statically linked release binary, from the matching source build.
if [ -n "${VPNCTL_TEST_HELPER:-}" ]; then
  make_old; stage=$(mktemp -d /tmp/vpnctl-helper.XXXXXXXXXX)
  cp "$VPNCTL_TEST_HELPER" "$stage/vam-server"
  digest=$(sha256sum "$stage/vam-server"); digest=${digest%% *}
  sh "$installer" "$stage" "$digest" "$old_hash"
  "$target" self-check
  echo 'PASS: real bundled helper installation and ABI check'
fi
