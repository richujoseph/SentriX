#!/bin/sh
# Lab SSH target with password login enabled, for scanning and brute-force scenarios.
# Only reachable on the internal compose network; never publish its port.
set -e

: "${SSH_USER:?SSH_USER is required}"
: "${SSH_PASSWORD:?SSH_PASSWORD is required}"

id "$SSH_USER" >/dev/null 2>&1 || adduser -D -s /bin/sh "$SSH_USER"
echo "$SSH_USER:$SSH_PASSWORD" | chpasswd

cat > /etc/ssh/sshd_config.d/lab.conf <<CONF
PasswordAuthentication yes
PermitRootLogin no
CONF

exec /usr/sbin/sshd -D -e
