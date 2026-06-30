#!/usr/bin/env bash
#
# fix_dheater.sh — SSH hardening for Ubuntu 24.04 (OpenSSH)
#
# Remediates:
#   [1] D(HE)ater DoS — OID: 1.3.6.1.4.1.25623.1.0.117839
#       CVE-2002-20001, CVE-2022-40735, CVE-2024-41996
#       Fix: remove all finite-field Diffie-Hellman KEX algorithms
#
#   [2] Weak MAC Algorithms — OID: 1.3.6.1.4.1.25623.1.0.105610
#       Fix: remove MD5-based, 96-bit, 64-bit, and 'none' MACs
#
# Safe to run multiple times on the same machine.
# Builds allowed lists dynamically from what the local sshd supports.
#
set -euo pipefail

MAIN_CONFIG="/etc/ssh/sshd_config"
DROPIN="/etc/ssh/sshd_config.d/99-ssh-hardening.conf"
TS="$(date +%Y%m%d-%H%M%S)"

# ── Preflight ────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "[!] Run as root (sudo $0)" >&2
  exit 1
fi

if ! command -v sshd &>/dev/null; then
  echo "[!] sshd not found. Is OpenSSH server installed?" >&2
  exit 1
fi

# ── Clean up any conflicting directives in the main config ──────────────────
# Handles machines where a previous (failed) script appended bad lines.

for DIRECTIVE in KexAlgorithms MACs; do
  DIRTY_LINES="$(grep -n "^\s*${DIRECTIVE}" "$MAIN_CONFIG" 2>/dev/null | cut -d: -f1 || true)"
  if [[ -n "$DIRTY_LINES" ]]; then
    echo "[*] Found existing ${DIRECTIVE} in $MAIN_CONFIG — commenting out:"
    # Backup main config once (first time we find something dirty)
    if [[ ! -f "${MAIN_CONFIG}.bak.${TS}" ]]; then
      cp -a "$MAIN_CONFIG" "${MAIN_CONFIG}.bak.${TS}"
      echo "[*] Main config backed up to ${MAIN_CONFIG}.bak.${TS}"
    fi
    while IFS= read -r linenum; do
      echo "    Line $linenum: $(sed -n "${linenum}p" "$MAIN_CONFIG")"
      sed -i "${linenum}s/^/#  [disabled by fix_dheater.sh ${TS}] /" "$MAIN_CONFIG"
    done <<< "$DIRTY_LINES"
  else
    echo "[*] No existing ${DIRECTIVE} lines in main config. Clean."
  fi
done

# ── Remove any previous drop-in from this script ────────────────────────────

if [[ -f "$DROPIN" ]]; then
  cp -a "$DROPIN" "${DROPIN}.bak.${TS}"
  echo "[*] Previous drop-in backed up to ${DROPIN}.bak.${TS}"
  rm -f "$DROPIN"
fi

# ── Build safe KEX list ──────────────────────────────────────────────────────
# Remove: all finite-field DH (D(HE)ater attack surface) and SHA-1 KEX

echo "[*] Querying supported KEX algorithms..."
ALLOWED_KEX="$(ssh -Q kex \
  | grep -v -E '^diffie-hellman' \
  | grep -v -E 'sha1$' \
  | paste -sd, -)"

if [[ -z "$ALLOWED_KEX" ]]; then
  echo "[!] Could not derive a safe KEX list — aborting." >&2
  exit 1
fi

echo "[*] Safe KEX list:"
echo "    ${ALLOWED_KEX//,/$'\n'    }"

# ── Build safe MAC list ──────────────────────────────────────────────────────
# Remove: MD5-based, 96-bit truncated, 64-bit (umac-64), and 'none'
# Keep:   HMAC-SHA2-256/512 and umac-128 variants (ETM preferred)

echo "[*] Querying supported MAC algorithms..."
ALLOWED_MAC="$(ssh -Q mac \
  | grep -v -E 'md5' \
  | grep -v -E '96$|96-' \
  | grep -v -E 'umac-64' \
  | grep -v -E '^none$' \
  | paste -sd, -)"

if [[ -z "$ALLOWED_MAC" ]]; then
  echo "[!] Could not derive a safe MAC list — aborting." >&2
  exit 1
fi

echo "[*] Safe MAC list:"
echo "    ${ALLOWED_MAC//,/$'\n'    }"

# ── Write the drop-in ───────────────────────────────────────────────────────

mkdir -p /etc/ssh/sshd_config.d
cat > "$DROPIN" <<EOF
# Managed by fix_dheater.sh — generated ${TS}
#
# [1] Mitigates D(HE)ater (CVE-2002-20001, CVE-2022-40735, CVE-2024-41996)
#     Removes all finite-field Diffie-Hellman key exchange algorithms.
KexAlgorithms ${ALLOWED_KEX}

# [2] Mitigates Weak MAC Algorithms (OID: 1.3.6.1.4.1.25623.1.0.105610)
#     Removes MD5, 96-bit, 64-bit (umac-64), and 'none' MAC algorithms.
MACs ${ALLOWED_MAC}

# Rollback: rm ${DROPIN} && systemctl reload ssh
EOF
chmod 0644 "$DROPIN"
echo "[*] Written: $DROPIN"

# ── Validate before touching the running service ────────────────────────────

echo "[*] Validating full sshd configuration..."
if ! sshd -t 2>&1; then
  echo
  echo "[!] Validation FAILED. Rolling back — sshd is untouched." >&2
  rm -f "$DROPIN"
  [[ -f "${DROPIN}.bak.${TS}" ]] && mv "${DROPIN}.bak.${TS}" "$DROPIN"
  exit 1
fi

echo "[*] Config valid."
echo
echo "[*] Effective settings after change:"
sshd -T | grep -iE '^(kexalgorithms|macs)'

# ── Reload ───────────────────────────────────────────────────────────────────

echo
echo "[*] Reloading sshd (existing sessions stay connected)..."
if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
  echo
  echo "[+] All remediations applied successfully."
  echo "    Drop-in : $DROPIN"
  echo "    Rollback: rm $DROPIN && systemctl reload ssh"
  echo "    Verify  : ssh -vv user@host 2>&1 | grep -iE '(kex:|mac:)'"
  echo
  echo "    *** Keep this session open and test a new SSH connection before logging out ***"
else
  echo "[!] sshd reload failed. Config is valid but service not refreshed." >&2
  echo "    Try manually: systemctl restart ssh" >&2
  exit 1
fi
