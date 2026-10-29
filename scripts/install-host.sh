#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer with sudo." >&2
  exit 1
fi

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
APP_USER=eagles
HELPER=/usr/local/sbin/security-dashboard-helper

id "${APP_USER}" >/dev/null
command -v node >/dev/null
command -v npm >/dev/null
command -v nft >/dev/null
test -x "${REPO_ROOT}/node_modules/.bin/vite"
test -d "${REPO_ROOT}/dist"

install -d -o root -g root -m 0750 /etc/security-dashboard
install -o root -g root -m 0644 "${REPO_ROOT}/config/protected-networks.txt" /etc/security-dashboard/protected-networks.txt
install -o root -g root -m 0750 "${REPO_ROOT}/scripts/security-dashboard-helper.py" "${HELPER}"
install -d -o root -g eagles -m 0750 /var/lib/security-dashboard
install -d -o root -g root -m 0750 /var/log/security-dashboard
install -d -o "${APP_USER}" -g "${APP_USER}" -m 0750 /var/lib/security-dashboard/app
if [[ -f /etc/sudoers.d/security-dashboard ]]; then
  rm -f /etc/sudoers.d/security-dashboard
fi
install -o root -g root -m 0644 "${REPO_ROOT}/ops/security-dashboard-helper.service" /etc/systemd/system/security-dashboard-helper.service
install -o root -g root -m 0644 "${REPO_ROOT}/ops/security-dashboard.service" /etc/systemd/system/security-dashboard.service
install -o root -g root -m 0644 "${REPO_ROOT}/ops/security-dashboard-restore.service" /etc/systemd/system/security-dashboard-restore.service
install -o root -g root -m 0644 "${REPO_ROOT}/ops/security-dashboard-enforce.service" /etc/systemd/system/security-dashboard-enforce.service
install -o root -g root -m 0644 "${REPO_ROOT}/ops/security-dashboard-enforce.timer" /etc/systemd/system/security-dashboard-enforce.timer


if command -v cscli >/dev/null && cscli allowlists --help >/dev/null 2>&1; then
  "${REPO_ROOT}/scripts/apply-crowdsec-allowlist.sh"
fi

systemctl daemon-reload
systemctl enable --now security-dashboard-helper.service
systemctl restart security-dashboard-helper.service
systemctl enable --now security-dashboard-restore.service
systemctl restart security-dashboard-restore.service
systemctl enable --now security-dashboard-enforce.timer
systemctl enable --now security-dashboard.service
systemctl restart security-dashboard.service

echo "Security Dashboard installed at http://127.0.0.1:4311"
