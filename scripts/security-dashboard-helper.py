#!/usr/bin/python3
import fcntl
import ipaddress
import json
import os
import pwd
import re
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import time
import grp
from datetime import datetime, timezone
from pathlib import Path

STATE_PATH = Path(os.environ.get("DASHBOARD_STATE_PATH", "/var/lib/security-dashboard/blocks.json"))
AUDIT_PATH = Path(os.environ.get("DASHBOARD_AUDIT_PATH", "/var/log/security-dashboard/audit.log"))
PROTECTED_PATH = Path(os.environ.get("DASHBOARD_PROTECTED_NETS", "/etc/security-dashboard/protected-networks.txt"))
TABLE = "eagles_security_dashboard"
IPV4_SET = "ipv4_blocked"
IPV6_SET = "ipv6_blocked"
CSCLI = "/usr/bin/cscli"
F2B = "/usr/bin/fail2ban-client"
NFT = "/usr/sbin/nft"
LOCK_PATH = "/run/lock/security-dashboard-helper.lock"
SOCKET_PATH = Path(os.environ.get("DASHBOARD_HELPER_SOCKET", "/run/security-dashboard/dashboard.sock"))
APP_UID = pwd.getpwnam("eagles").pw_uid
APP_GID = grp.getgrnam("eagles").gr_gid


def run(argv, timeout=20, check=True):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result


def run_json(argv, timeout=60):
    result = run(argv, timeout=timeout)
    return json.loads(result.stdout or "[]")


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("A single IPv4 or IPv6 address is required")


def local_addresses():
    result = run(["/usr/sbin/ip", "-j", "address", "show"], check=False)
    addresses = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
    if result.returncode == 0:
        try:
            for link in json.loads(result.stdout):
                for item in link.get("addr_info", []):
                    local = item.get("local")
                    if local:
                        address = ipaddress.ip_address(local.split("%", 1)[0])
                        addresses.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}"))
        except (ValueError, TypeError, json.JSONDecodeError):
            pass
    return addresses


def configured_nets():
    networks = local_addresses()
    if PROTECTED_PATH.exists():
        for raw in PROTECTED_PATH.read_text(encoding="utf-8").splitlines():
            value = raw.split("#", 1)[0].strip()
            if value:
                try:
                    networks.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    continue

    whitelist_file = Path("/etc/crowdsec/parsers/s02-enrich/whitelists.yaml")
    if whitelist_file.exists():
        section = ""
        for raw in whitelist_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line in {"ip:", "cidr:"}:
                section = line[:-1]
            elif line.startswith("-") and section in {"ip", "cidr"}:
                value = line[1:].strip().strip("\"'")
                try:
                    networks.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    continue
            elif line and not line.startswith("-"):
                section = ""

    nginx = run(["/usr/sbin/nginx", "-T"], timeout=30, check=False)
    if nginx.returncode == 0:
        for match in re.finditer(r"^\s*set_real_ip_from\s+([^;\s]+)\s*;", nginx.stdout, re.MULTILINE):
            try:
                networks.append(ipaddress.ip_network(match.group(1), strict=False))
            except ValueError:
                continue
    unique = {str(network): network for network in networks}
    return list(unique.values())


def is_protected(ip, networks):
    address = ipaddress.ip_address(ip)
    return any(address.version == network.version and address in network for network in networks)


def ensure_firewall():
    if os.environ.get("DASHBOARD_SKIP_FIREWALL") == "1":
        return
    existing = run([NFT, "list", "table", "inet", TABLE], check=False)
    if existing.returncode == 0:
        text = existing.stdout
        required = [IPV4_SET, IPV6_SET, "input_guard", "forward_guard", "blocked_ipv4_packets", "blocked_ipv6_packets"]
        if any(token not in text for token in required):
            raise RuntimeError(f"nftables table inet {TABLE} exists but does not match the dashboard schema; refusing to modify it")
        return

    rules = f"""add table inet {TABLE}
add set inet {TABLE} {IPV4_SET} {{ type ipv4_addr; }}
add set inet {TABLE} {IPV6_SET} {{ type ipv6_addr; }}
add counter inet {TABLE} blocked_ipv4_packets
add counter inet {TABLE} blocked_ipv6_packets
add chain inet {TABLE} input_guard {{ type filter hook input priority -20; policy accept; }}
add chain inet {TABLE} forward_guard {{ type filter hook forward priority -20; policy accept; }}
add rule inet {TABLE} input_guard ip saddr @{IPV4_SET} counter name blocked_ipv4_packets drop
add rule inet {TABLE} input_guard ip6 saddr @{IPV6_SET} counter name blocked_ipv6_packets drop
add rule inet {TABLE} forward_guard ip saddr @{IPV4_SET} counter name blocked_ipv4_packets drop
add rule inet {TABLE} forward_guard ip6 saddr @{IPV6_SET} counter name blocked_ipv6_packets drop
"""
    result = subprocess.run([NFT, "-f", "-"], input=rules, text=True, capture_output=True, timeout=20, check=False)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "unable to create nftables table").strip())


def nft_element(operation, ip):
    if os.environ.get("DASHBOARD_SKIP_FIREWALL") == "1":
        return
    address = ipaddress.ip_address(ip)
    set_name = IPV4_SET if address.version == 4 else IPV6_SET
    result = run([NFT, operation, "element", "inet", TABLE, set_name, "{", str(address), "}"], check=False)
    if result.returncode != 0 and operation == "add" and "File exists" in result.stderr:
        return
    if result.returncode != 0 and operation == "delete" and ("No such file" in result.stderr or "does not exist" in result.stderr):
        return
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "nftables element operation failed").strip())


def empty_state():
    return {"version": 1, "bans": {}, "last_alert_check": None}


def read_state():
    if not STATE_PATH.exists():
        return empty_state()
    data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("bans"), dict):
        raise RuntimeError("Persistent ban state has an unknown schema; refusing to continue")
    clean = empty_state()
    last_alert_check = data.get("last_alert_check")
    if isinstance(last_alert_check, (int, float)) and last_alert_check > 0:
        clean["last_alert_check"] = int(last_alert_check)
    for key, value in data["bans"].items():
        ip = valid_ip(key)
        if isinstance(value, dict):
            clean["bans"][ip] = value
    return clean


def write_state(state):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd, tmp = tempfile.mkstemp(prefix=".blocks-", dir=str(STATE_PATH.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, STATE_PATH)
        os.chmod(STATE_PATH, 0o600)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def audit(action, ip, reason, source):
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    record = {"time": datetime.now(timezone.utc).isoformat(), "action": action, "ip": ip, "source": source, "reason": reason[:160]}
    fd = os.open(AUDIT_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def audit_existing_blocks():
    state = read_state()
    observed = set()
    if AUDIT_PATH.exists():
        for line in AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("action") == "existing_block_observed":
                observed.add(record.get("ip"))

    added = 0
    for ip, item in state["bans"].items():
        if ip in observed:
            continue
        sources = item.get("sources") or (["Manual dashboard"] if item.get("manual") else ["Unknown source"])
        reasons = item.get("reasons") or ["Persistent block present when audit tracking was initialized"]
        audit("existing_block_observed", ip, "; ".join(reasons), ", ".join(sources))
        added += 1
    return {"ok": True, "observed_existing_blocks": added}


def parse_decisions():
    result = run([CSCLI, "decisions", "list", "-o", "json", "--no-simu"], timeout=30, check=False)
    if result.returncode != 0:
        return None, (result.stderr or result.stdout or "CrowdSec unavailable").strip()
    try:
        return json.loads(result.stdout or "[]"), None
    except json.JSONDecodeError as error:
        return None, f"CrowdSec returned invalid JSON: {error}"


def parse_alerts(since):
    result = run([CSCLI, "alerts", "list", "-o", "json", "--since", since, "--limit", "0"], timeout=60, check=False)
    if result.returncode != 0:
        return None, (result.stderr or result.stdout or "CrowdSec alerts unavailable").strip()
    try:
        data = json.loads(result.stdout or "[]")
        return data if isinstance(data, list) else [], None
    except json.JSONDecodeError as error:
        return None, f"CrowdSec returned invalid alert JSON: {error}"


def fail2ban_state():
    status = run([F2B, "status"], timeout=15, check=False)
    if status.returncode != 0:
        return None, (status.stderr or status.stdout or "Fail2ban unavailable").strip()
    match = re.search(r"Jail list:\s*(.*)", status.stdout)
    jails = [value.strip() for value in (match.group(1) if match else "").split(",") if value.strip()]
    result = []
    for jail in jails:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", jail):
            continue
        detail = run([F2B, "status", jail], timeout=15, check=False)
        if detail.returncode != 0:
            continue
        banned = re.search(r"Banned IP list:\s*(.*)", detail.stdout)
        for raw_ip in (banned.group(1) if banned else "").split():
            try:
                ip = valid_ip(raw_ip)
            except ValueError:
                continue
            result.append({"ip": ip, "source": f"Fail2ban {jail}", "reason": f"Fail2ban jail: {jail}", "jail": jail})
    return {"jails": jails, "bans": result}, None


def decision_entries(data):
    entries = []
    for alert in data or []:
        alert_decisions = alert.get("decisions") or []
        alert_ip = None
        for event in alert.get("events") or []:
            for meta in event.get("meta") or []:
                if meta.get("key") == "source_ip":
                    alert_ip = meta.get("value")
                    break
            if alert_ip:
                break
        for decision in alert_decisions:
            if decision.get("type") != "ban" or str(decision.get("scope", "Ip")).lower() != "ip":
                continue
            try:
                ip = valid_ip(decision.get("value") or alert_ip)
            except (ValueError, TypeError):
                continue
            entries.append({
                "ip": ip,
                "source": crowdsec_source(decision),
                "reason": str(decision.get("scenario") or "CrowdSec decision"),
                "scenario": str(decision.get("scenario") or ""),
                "decision_id": decision.get("id"),
            })
    return entries


def active_decisions(data):
    entries = []
    for alert in data or []:
        alert_ip = None
        for event in alert.get("events") or []:
            for meta in event.get("meta") or []:
                if meta.get("key") == "source_ip":
                    alert_ip = meta.get("value")
                    break
            if alert_ip:
                break
        for decision in alert.get("decisions") or []:
            if decision.get("type") != "ban" or str(decision.get("scope", "Ip")).lower() != "ip":
                continue
            try:
                ip = valid_ip(decision.get("value") or alert_ip)
            except (ValueError, TypeError):
                continue
            entries.append({"ip": ip, "source": crowdsec_source(decision),
                            "reason": str(decision.get("scenario") or "CrowdSec decision"),
                            "scenario": str(decision.get("scenario") or ""),
                            "decision_id": decision.get("id"), "duration": decision.get("duration")})
    return entries


def crowdsec_source(decision):
    origin = str(decision.get("origin") or "detection").strip()
    return "CrowdSec" if origin.lower() == "crowdsec" else f"CrowdSec {origin}"


def counter_packets(family, table, name):
    result = run([NFT, "list", "counter", family, table, name], check=False)
    if result.returncode != 0:
        return None
    match = re.search(r"packets\s+(\d+)\s+bytes\s+(\d+)", result.stdout)
    return {"packets": int(match.group(1)), "bytes": int(match.group(2))} if match else None


def firewall_counters():
    values = []
    for family, table, counter in [
        ("inet", TABLE, "blocked_ipv4_packets"),
        ("inet", TABLE, "blocked_ipv6_packets"),
        ("ip", "crowdsec", "crowdsec-blacklists-crowdsec"),
        ("ip6", "crowdsec6", "crowdsec6-blacklists-crowdsec6"),
    ]:
        value = counter_packets(family, table, counter)
        if value is not None:
            values.append(value["packets"])
    return sum(values) if values else None


def merge_bans(state, decisions, fail2ban, networks):
    merged = {}
    for ip, item in state["bans"].items():
        merged[ip] = {**item, "ip": ip, "active": True, "persistent": True,
                      "protected": is_protected(ip, networks),
                      "sources": list(item.get("sources", [])), "reasons": list(item.get("reasons", []))}
    for entry in decisions:
        ip = entry["ip"]
        protected = is_protected(ip, networks)
        target = merged.setdefault(ip, {"ip": ip, "first_seen": datetime.now(timezone.utc).isoformat(),
                                        "last_seen": datetime.now(timezone.utc).isoformat(), "manual": False,
                                        "sources": [], "reasons": [], "active": True, "persistent": False,
                                        "protected": protected})
        target["sources"] = sorted(set(target.get("sources", []) + [entry["source"]]))
        target["reasons"] = sorted(set(target.get("reasons", []) + [entry["reason"]]))
        target["protected"] = protected
        target["active"] = True
    for entry in (fail2ban or {}).get("bans", []):
        ip = entry["ip"]
        protected = is_protected(ip, networks)
        target = merged.setdefault(ip, {"ip": ip, "first_seen": datetime.now(timezone.utc).isoformat(),
                                        "last_seen": datetime.now(timezone.utc).isoformat(), "manual": False,
                                        "sources": [], "reasons": [], "active": True, "persistent": False,
                                        "protected": protected})
        target["sources"] = sorted(set(target.get("sources", []) + [entry["source"]]))
        target["reasons"] = sorted(set(target.get("reasons", []) + [entry["reason"]]))
        target["protected"] = protected
        target["active"] = True
    return list(merged.values())


def add_persistent(state, entry, networks, source_kind):
    ip = valid_ip(entry["ip"])
    if is_protected(ip, networks):
        return False, "protected"
    now = datetime.now(timezone.utc).isoformat()
    item = state["bans"].get(ip, {"first_seen": now, "sources": [], "reasons": [], "manual": False})
    item["last_seen"] = now
    item["sources"] = sorted(set(item.get("sources", []) + [entry["source"]]))
    item["reasons"] = sorted(set(item.get("reasons", []) + [entry["reason"]]))
    if source_kind == "manual":
        item["manual"] = True
    state["bans"][ip] = item
    nft_element("add", ip)
    return True, "persisted"


def source_status(decisions_error, alerts_error, fail2ban_error, firewall_enabled):
    return {
        "crowdsec": {"status": "unavailable" if decisions_error else "ok", "error": decisions_error},
        "crowdsecAlerts": {"status": "unavailable" if alerts_error else "ok", "error": alerts_error},
        "fail2ban": {"status": "unavailable" if fail2ban_error else "ok", "error": fail2ban_error},
        "firewall": {"status": "ok" if firewall_enabled else "unavailable",
                     "error": None if firewall_enabled else "dashboard nftables table not initialized"},
        "oneShield": {"status": "not_connected", "error": "Edge event feed is not configured; origin telemetry only"},
    }


def collect(sync_only=False):
    decisions, decisions_error = parse_decisions()
    state = read_state()
    now = int(time.time())
    alerts = []
    alerts_error = None
    if not sync_only:
        previous_alert_check = state.get("last_alert_check")
        since_seconds = 90 * 24 * 60 * 60 if previous_alert_check is None else min(
            90 * 24 * 60 * 60,
            max(120, now - int(previous_alert_check) + 60),
        )
        alerts, alerts_error = parse_alerts(f"{since_seconds}s")
    fail2ban, fail2ban_error = fail2ban_state()
    networks = configured_nets()
    firewall_enabled = os.environ.get("DASHBOARD_SKIP_FIREWALL") != "1"
    if firewall_enabled:
        ensure_firewall()
    added = []
    automatic_audits = {}
    for entry in active_decisions(decisions):
        was_persistent = entry["ip"] in state["bans"]
        ok, _ = add_persistent(state, entry, networks, "automatic")
        if ok:
            added.append(entry["ip"])
            if not was_persistent:
                automatic_audits.setdefault(entry["ip"], entry)
    for entry in (fail2ban or {}).get("bans", []):
        was_persistent = entry["ip"] in state["bans"]
        ok, _ = add_persistent(state, entry, networks, "automatic")
        if ok:
            added.append(entry["ip"])
            if not was_persistent:
                automatic_audits.setdefault(entry["ip"], entry)
    if not sync_only and alerts_error is None:
        state["last_alert_check"] = now
    write_state(state)
    for ip, entry in automatic_audits.items():
        audit("ban", ip, entry["reason"], entry["source"])
    bans = merge_bans(state, active_decisions(decisions), fail2ban, networks)
    statuses = source_status(decisions_error, alerts_error, fail2ban_error, firewall_enabled)
    return {
        "bans": bans,
        "decisions": active_decisions(decisions),
        "alerts": alerts or [],
        "fail2ban": fail2ban,
        "firewall_packets": firewall_counters() if firewall_enabled else None,
        "protected_networks": [str(network) for network in networks],
        "sources": statuses,
        "persisted_new": sorted(set(added)),
    }


def manual_ban(payload):
    ip = valid_ip(payload.get("ip", ""))
    reason = str(payload.get("reason", "")).strip()
    if not 3 <= len(reason) <= 160 or any(ord(ch) < 32 for ch in reason):
        raise ValueError("Reason must be 3 to 160 printable characters")
    networks = configured_nets()
    if is_protected(ip, networks):
        raise ValueError("This address is in a protected or trusted network and cannot be banned")
    ensure_firewall()
    state = read_state()
    ok, _ = add_persistent(state, {"ip": ip, "source": "Manual dashboard ban", "reason": reason}, networks, "manual")
    if not ok:
        raise ValueError("This address is protected")
    write_state(state)
    audit("ban", ip, reason, "manual dashboard")
    return {"ok": True, "ip": ip, "persistent": True, "manual_unban_required": True}


def manual_unban(payload):
    ip = valid_ip(payload.get("ip", ""))
    reason = str(payload.get("reason", "Manual unban")).strip()[:160]
    ensure_firewall()
    state = read_state()
    cs = run([CSCLI, "decisions", "delete", "--ip", ip], timeout=30, check=False)
    status = run([F2B, "status"], timeout=15, check=False)
    match = re.search(r"Jail list:\s*(.*)", status.stdout or "")
    jails = [value.strip() for value in (match.group(1) if match else "").split(",") if value.strip()]
    jail_results = []
    if status.returncode == 0:
        for jail in jails:
            if re.fullmatch(r"[A-Za-z0-9_.-]+", jail):
                jail_results.append(run([F2B, "set", jail, "unbanip", ip], timeout=15, check=False).returncode == 0)
    source_cleanup_ok = cs.returncode == 0 and status.returncode == 0 and all(jail_results)
    if not source_cleanup_ok:
        audit("unban_failed", ip, reason, "manual dashboard")
        return {"ok": False, "ip": ip, "removed_persistent": False,
                "crowdsec_command_ok": cs.returncode == 0,
                "fail2ban_status_ok": status.returncode == 0,
                "fail2ban_jails_checked": len(jails), "fail2ban_commands_ok": all(jail_results)}

    was_present = ip in state["bans"]
    nft_element("delete", ip)
    state["bans"].pop(ip, None)
    write_state(state)
    audit("unban", ip, reason, "manual dashboard")
    return {"ok": True, "ip": ip, "removed_persistent": was_present,
            "crowdsec_command_ok": cs.returncode == 0,
            "fail2ban_status_ok": status.returncode == 0,
            "fail2ban_jails_checked": len(jails), "fail2ban_commands_ok": all(jail_results)}


def restore():
    ensure_firewall()
    state = read_state()
    for ip in state["bans"]:
        networks = configured_nets()
        if is_protected(ip, networks):
            continue
        nft_element("add", ip)
    return {"ok": True, "restored": len(state["bans"])}


def perform(operation, payload):
    if operation == "collect":
        return collect()
    if operation == "sync":
        return collect(sync_only=True)
    if operation == "ban":
        return manual_ban(payload)
    if operation == "unban":
        return manual_unban(payload)
    if operation == "restore":
        return restore()
    raise ValueError("Supported operations: collect, ban, unban, restore")


class DashboardRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", credentials)
        if uid != APP_UID:
            self.wfile.write(b'{"error":"Dashboard helper peer is not authorized"}\n')
            return

        raw = self.rfile.readline(8193)
        if not raw or len(raw) > 8192 or not raw.endswith(b"\n"):
            self.wfile.write(b'{"error":"Invalid or oversized helper request"}\n')
            return
        try:
            request = json.loads(raw)
            operation = request.get("operation")
            if operation not in {"collect", "ban", "unban"}:
                raise ValueError("Unsupported helper operation")
            payload = request.get("payload") or {}
            with open(LOCK_PATH, "a", encoding="utf-8") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                response = perform(operation, payload)
        except Exception as error:
            response = {"error": str(error)}
        self.wfile.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")


class DashboardControlServer(socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True


def serve():
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        SOCKET_PATH.unlink()
    server = DashboardControlServer(str(SOCKET_PATH), DashboardRequestHandler)
    os.chmod(SOCKET_PATH, 0o660)
    os.chown(SOCKET_PATH, 0, APP_GID)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()


def main():
    operation = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        if operation == "serve":
            serve()
            return 0
        with open(LOCK_PATH, "a", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            payload = json.load(sys.stdin) if not sys.stdin.isatty() and operation in {"ban", "unban"} else {}
            if operation == "replay-alerts":
                state = read_state()
                state["last_alert_check"] = None
                write_state(state)
                result = {"ok": True, "alert_history_replay": True}
            elif operation == "audit-existing":
                result = audit_existing_blocks()
            else:
                result = perform(operation, payload)
            print(json.dumps(result, separators=(",", ":")))
    except Exception as error:
        print(json.dumps({"error": str(error)}, separators=(",", ":")), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
