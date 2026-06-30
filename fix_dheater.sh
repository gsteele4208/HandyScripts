#!/bin/bash

# ============================================================================
# Disable vulnerable Diffie-Hellman Key Exchange algorithms
# Ubuntu 24.04
# ============================================================================

set -e

CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak.$(date +%F-%H%M%S)"

echo "Backing up sshd_config..."
cp "$CONFIG" "$BACKUP"

echo "Backup saved to $BACKUP"

# Remove existing KexAlgorithms lines
sed -i '/^[[:space:]]*KexAlgorithms/d' "$CONFIG"

cat <<EOF >> "$CONFIG"

# Hardened Key Exchange Algorithms
# Mitigation for D(HE)ater DoS vulnerability
KexAlgorithms sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256

EOF

echo "Testing SSH configuration..."

sshd -t

if [ $? -eq 0 ]; then
    echo "Configuration valid."
    systemctl restart ssh
    echo "SSH restarted successfully."
else
    echo "Configuration invalid!"
    echo "Restoring backup..."
    cp "$BACKUP" "$CONFIG"
    exit 1
fi

echo
echo "Enabled Key Exchange Algorithms:"
sshd -T | grep kexalgorithms

echo
echo "Done."
