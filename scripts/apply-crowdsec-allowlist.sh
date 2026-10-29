#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this allowlist operation as root." >&2
  exit 1
fi

NETWORK_FILE=/etc/security-dashboard/protected-networks.txt
LIST_NAME=security-dashboard-trusted
command -v cscli >/dev/null
test -r "${NETWORK_FILE}"

if ! cscli allowlists inspect "${LIST_NAME}" >/dev/null 2>&1; then
  cscli allowlists create "${LIST_NAME}" --description "iNET and Cloudflare origin-proxy ranges protected from new CrowdSec decisions"
fi

while IFS= read -r network || [[ -n ${network} ]]; do
  network="${network%%#*}"
  network="$(printf '%s' "${network}" | tr -d '[:space:]')"
  [[ -z ${network} ]] && continue
  if ! cscli allowlists inspect "${LIST_NAME}" -o json | python3 -c 'import json,sys; target=sys.argv[1]; data=json.load(sys.stdin); sys.exit(0 if any(item.get("value") == target for item in data.get("items", [])) else 1)' "${network}"; then
    cscli allowlists add "${LIST_NAME}" "${network}" --comment "Protected origin proxy range"
  fi
done <"${NETWORK_FILE}"

echo "CrowdSec trusted-proxy allowlist is configured. CrowdSec may remove matching active decisions; future dashboard unbans remain manual-only."
