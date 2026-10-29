# Standalone Host Security Dashboard

## Summary

Build a read-only-by-default dashboard with explicit manual ban/unban controls at `/home/eagles/dockerz/security-dashboard`, separate from SIS and CyberPanel. Keep the app loopback-only at `http://127.0.0.1:4311`; access to its controls follows your choice of host-user access, without a separate login.

## Implementation

- Use the approved operational layout: host-wide, source-separated trends; active bans with country, source, reason, 24-hour and 90-day signal counts, and last seen; plus manual ban/unban controls. Retain per-IP history for up to 90 days after unban.
- Read Nginx logs, CrowdSec decisions/detections, Fail2ban state, and available firewall counters. Keep requests, suspicious signals, detections, active bans, and confirmed blocks distinct. Use local GeoIP data only; mark unavailable data rather than guessing. Show OneShield edge events as disconnected and identify displayed counts as origin-only.
- Refresh host collection and the open dashboard every 30 seconds; refresh promptly when a backgrounded dashboard tab becomes visible again.
- Preserve every automatic or manual ban in a dedicated, persistent nftables enforcement set across decision expiry and service restarts. CrowdSec’s documented default decision duration is four hours, so its expiry must not remove the persistent enforcement entry. Keep existing source-level expiry policies otherwise unchanged. [CrowdSec decision management](https://docs.crowdsec.net/u/user_guides/decisions_mgmt/)
- Provide a manual unban action that removes the persistent entry and clears matching active CrowdSec/Fail2ban bans; a later new detection may ban that IP again. Never automatically unban or expire an enforced ban. Reject ban requests for loopback, host-owned, or currently configured trusted/allowlisted addresses.
- Run collection and enforcement through a narrow, root-owned helper; keep the UI/API unprivileged, with only the host’s existing firewall framework modified. Record ban/unban actions and their source in an audit log.

## Interfaces and Verification

- Add read-only API routes for summary, trends, current bans, and source health, plus explicit ban and unban routes.
- Test that automatic detections persist past CrowdSec expiry, survive restart, and are removed only by manual unban; verify Fail2ban handling, protected-IP rejection, IPv4/IPv6 enforcement, and loopback-only binding.
- Verify the rendered local dashboard at desktop and mobile sizes; use representative host data without fabricated counts. Confirm unavailable edge data is clearly labeled.

## Assumptions

- Automatic detections may ban; all bans remain enforced until manually unbanned.
- This does not enable OneShield or alter its configuration, and does not change the existing CrowdSec decision durations.
- The app is implemented in this repository and installed on the host as a loopback-only service at `http://127.0.0.1:4311`.
