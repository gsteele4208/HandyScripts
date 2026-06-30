#!/usr/bin/env bash
#
# fix_dheater.sh — Remediate D(HE)ater on Ubuntu 24.04 (OpenSSH)
# Finding OID: 1.3.6.1.4.1.25623.1.0.117839
# CVEs: CVE-2002-20001, CVE-2022-40735, CVE-2024-41996
#
# Approach: disable finite-field Diffie-Hellman key exchange (the attack
# surface) and keep only curve25519 / ECDH / post-quantum KEX. The allowed
# list is built from what the local sshd actually supports, so we never
# write an algorithm name the daemon will reject.
#
set -euo pipefail

DROPIN="/etc/ssh/sshd_config.d/99-dheater-hardening.conf"
TS="$(date +%Y%m%d-%H%M%S)"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo $0)" >&2
  exit 1
fi

echo "[*] Querying supported KEX algorithms..."
# Keep only algorithms that are NOT finite-field DH and NOT sha1-based.
ALLOWED="$(ssh -Q kex \
  | grep -v -E 'diffie-hellman' \
  | grep -v -E 'sha1$' \
  | paste -sd, -)"

if [[ -z "$ALLOWED" ]]; then
  echo "[!] Could not derive a safe KEX list. Aborting, nothing changed." >&2
  exit 1
fi

echo "[*] Safe KEX set:"
echo "    ${ALLOWED//,/, }"

# Back up an existing drop-in if present.
if [[ -f "$DROPIN" ]]; then
  cp -a "$DROPIN" "${DROPIN}.bak.${TS}"
  echo "[*] Backed up existing drop-in to ${DROPIN}.bak.${TS}"
fi

echo "[*] Writing $DROPIN"
cat > "$DROPIN" <<EOF
# Managed by fix_dheater.sh — generated ${TS}
# Mitigates D(HE)ater (CVE-2002-20001, CVE-2022-40735, CVE-2024-41996)
# by removing finite-field Diffie-Hellman key exchange.
KexAlgorithms ${ALLOWED}
EOF
chmod 0644 "$DROPIN"

echo "[*] Validating full sshd configuration..."
if ! sshd -t; then
  echo "[!] Validation FAILED. Removing drop-in, sshd untouched." >&2
  rm -f "$DROPIN"
  [[ -f "${DROPIN}.bak.${TS}" ]] && mv "${DROPIN}.bak.${TS}" "$DROPIN"
  exit 1
fi
echo "[*] Config valid."

echo "[*] Effective KexAlgorithms after change:"
sshd -T | grep -i '^kexalgorithms'

echo "[*] Reloading sshd (existing sessions stay connected)..."
systemctl reload ssh 2>/dev/null || systemctl reload sshd

echo
echo "[+] Done. D(HE)ater remediation applied via $DROPIN"
echo "    Verify from another host:  ssh -vv user@host 2>&1 | grep -i 'kex:'"
echo "    Rollback:  rm $DROPIN && systemctl reload ssh"
