# Eagles Host Security Dashboard

Loopback-only host security dashboard for the local Nginx, CrowdSec, Fail2ban, and nftables telemetry. The UI/API listens only on `127.0.0.1:4311`; use a local browser or an SSH tunnel. OneShield edge events are intentionally not connected.

The host collector and open dashboard refresh every 30 seconds. Returning to a backgrounded dashboard tab triggers an immediate refresh; the manual Refresh control remains available.

## Development

```sh
npm install
npm run build
npm test
npm start
```

The collector reads Nginx access logs as the `adm` group, obtains security state through a root-owned narrow helper, and stores aggregates plus 90-day per-IP signal history in SQLite. Raw access-log request lines are not copied into the database.

## Install on this host

Build the current checkout first, then run:

```sh
sudo ./scripts/install-host.sh
```

The installer creates a persistent CrowdSec allowlist for the configured iNET and Cloudflare ranges, installs a root-owned helper on a peer-credential-checked Unix socket, restores persistent nftables blocks at boot, starts a 30-second enforcement collector, and enables the local dashboard service. CrowdSec may remove existing decisions that match a newly added allowlist; the installer does not otherwise change CrowdSec/Fail2ban ban durations. Manual unban is the only dashboard path that removes persistent dashboard enforcement.

`config/protected-networks.txt` is the authoritative dashboard protection list. Refresh Cloudflare's published IP ranges before changing those CIDRs. Addresses in this file are excluded from dashboard-created persistent blocks.

The root helper keeps persistent block state in `/var/lib/security-dashboard/blocks.json` and records manual actions in `/var/log/security-dashboard/audit.log`. All bans remain until a manual unban; there is no expiry or automatic unban.

When audit tracking is initialized on an existing host, current persistent entries are recorded as `existing_block_observed`; their original ban timestamps are not fabricated.
