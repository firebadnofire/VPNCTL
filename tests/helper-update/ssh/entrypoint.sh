set -euo pipefail
mkdir -p /run/sshd /usr/local/libexec
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key; fi
if [ ! -s /etc/machine-id ]; then tr -d '-' </proc/sys/kernel/random/uuid > /etc/machine-id; fi
install -d -m 0700 -o testuser -g testuser /home/testuser/.ssh
install -m 0600 -o testuser -g testuser /keys/authorized_key /home/testuser/.ssh/authorized_keys
install -m 0755 /payload/vam-server /usr/local/libexec/vam-server-fixture-real
install -m 0755 /fixture/old-helper.sh /usr/local/libexec/vam-server
cat > /etc/ssh/sshd_config <<'SSH'
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers testuser
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PrintMotd no
LogLevel ERROR
Subsystem sftp internal-sftp
SSH
exec /usr/sbin/sshd -D -e
