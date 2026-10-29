import importlib.util
import ipaddress
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "security-dashboard-helper.py"
SPEC = importlib.util.spec_from_file_location("security_dashboard_helper", HELPER_PATH)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class PersistentEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="security-dashboard-helper-")
        root = Path(self.temp.name)
        helper.STATE_PATH = root / "blocks.json"
        helper.AUDIT_PATH = root / "audit.log"
        helper.LOCK_PATH = root / "helper.lock"
        helper.PROTECTED_PATH = root / "protected.txt"
        helper.PROTECTED_PATH.write_text("203.0.113.0/24\n", encoding="utf-8")
        self.networks = [ipaddress.ip_network("203.0.113.0/24")]
        self.nft_calls = []
        self.environment = mock.patch.dict(os.environ, {"DASHBOARD_SKIP_FIREWALL": "1"})
        self.environment.start()
        self.configured = mock.patch.object(helper, "configured_nets", return_value=self.networks)
        self.configured.start()
        self.nft = mock.patch.object(helper, "nft_element", side_effect=lambda op, ip: self.nft_calls.append((op, ip)))
        self.nft.start()

    def tearDown(self):
        self.nft.stop()
        self.configured.stop()
        self.environment.stop()
        self.temp.cleanup()

    def test_persists_ipv4_and_ipv6_without_expiry_and_restores_after_restart(self):
        helper.manual_ban({"ip": "198.51.100.8", "reason": "Repeated exploit probes"})
        helper.manual_ban({"ip": "2001:db8::8", "reason": "Repeated exploit probes"})

        state = helper.read_state()
        self.assertEqual(set(state["bans"]), {"198.51.100.8", "2001:db8::8"})
        self.assertTrue(all(item["manual"] for item in state["bans"].values()))
        self.assertEqual({call[0] for call in self.nft_calls}, {"add"})

        self.nft_calls.clear()
        helper.restore()
        self.assertEqual({ip for _, ip in self.nft_calls}, {"198.51.100.8", "2001:db8::8"})
        first_audit = helper.AUDIT_PATH.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(json.loads(first_audit).get("action"), "ban")

    def test_protected_network_cannot_be_banned(self):
        with self.assertRaisesRegex(ValueError, "protected"):
            helper.manual_ban({"ip": "203.0.113.24", "reason": "Trusted proxy"})
        self.assertFalse(helper.STATE_PATH.exists())
        self.assertEqual(self.nft_calls, [])

    def test_only_explicit_manual_unban_removes_persistent_entry(self):
        helper.manual_ban({"ip": "198.51.100.8", "reason": "Repeated exploit probes"})

        def fake_run(argv, **_kwargs):
            if argv == [helper.F2B, "status"]:
                return SimpleNamespace(returncode=0, stdout="Jail list: sshd\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(helper, "run", side_effect=fake_run):
            result = helper.manual_unban({"ip": "198.51.100.8", "reason": "Reviewed"})

        self.assertTrue(result["removed_persistent"])
        self.assertNotIn("198.51.100.8", helper.read_state()["bans"])
        self.assertIn(("delete", "198.51.100.8"), self.nft_calls)

    def test_failed_source_cleanup_keeps_the_persistent_ban(self):
        helper.manual_ban({"ip": "198.51.100.8", "reason": "Repeated exploit probes"})

        def fake_run(argv, **_kwargs):
            if argv == [helper.F2B, "status"]:
                return SimpleNamespace(returncode=0, stdout="Jail list: sshd\n", stderr="")
            if argv[:3] == [helper.F2B, "set", "sshd"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="unban failed")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(helper, "run", side_effect=fake_run):
            result = helper.manual_unban({"ip": "198.51.100.8", "reason": "Reviewed"})

        self.assertFalse(result["ok"])
        self.assertFalse(result["removed_persistent"])
        self.assertIn("198.51.100.8", helper.read_state()["bans"])
        self.assertNotIn(("delete", "198.51.100.8"), self.nft_calls)
        records = [json.loads(line) for line in helper.AUDIT_PATH.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(records[-1]["action"], "unban_failed")

    def test_automatic_bans_survive_source_expiry_and_only_manual_unban_removes_them(self):
        crowdsec = [{
            "decisions": [{
                "type": "ban", "scope": "Ip", "value": "198.51.100.9",
                "origin": "crowdsec", "scenario": "crowdsecurity/http-probing",
            }],
            "events": [],
        }]
        fail2ban = {"jails": ["sshd"], "bans": [{
            "ip": "2001:db8::9", "source": "Fail2ban sshd", "reason": "Fail2ban jail: sshd",
        }]}
        with mock.patch.object(helper, "parse_decisions", side_effect=[(crowdsec, None), ([], None)]), \
             mock.patch.object(helper, "fail2ban_state", side_effect=[(fail2ban, None), ({"jails": ["sshd"], "bans": []}, None)]), \
             mock.patch.object(helper, "ensure_firewall"), \
             mock.patch.object(helper, "firewall_counters", return_value=0):
            helper.collect(sync_only=True)
            self.assertEqual(set(helper.read_state()["bans"]), {"198.51.100.9", "2001:db8::9"})
            self.nft_calls.clear()
            helper.collect(sync_only=True)
            self.assertEqual(set(helper.read_state()["bans"]), {"198.51.100.9", "2001:db8::9"})
            self.assertNotIn(("delete", "198.51.100.9"), self.nft_calls)
            self.assertNotIn(("delete", "2001:db8::9"), self.nft_calls)

        records = [json.loads(line) for line in helper.AUDIT_PATH.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual({record["action"] for record in records}, {"ban"})
        self.assertEqual({record["source"] for record in records}, {"CrowdSec", "Fail2ban sshd"})

        self.nft_calls.clear()
        helper.restore()
        self.assertEqual({ip for operation, ip in self.nft_calls if operation == "add"}, {"198.51.100.9", "2001:db8::9"})

        def successful_cleanup(argv, **_kwargs):
            if argv == [helper.F2B, "status"]:
                return SimpleNamespace(returncode=0, stdout="Jail list: sshd\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch.object(helper, "run", side_effect=successful_cleanup):
            result = helper.manual_unban({"ip": "198.51.100.9", "reason": "Reviewed"})
        self.assertTrue(result["ok"])
        self.assertNotIn("198.51.100.9", helper.read_state()["bans"])
        self.assertIn("2001:db8::9", helper.read_state()["bans"])
        self.assertIn(("delete", "198.51.100.9"), self.nft_calls)

    def test_existing_enforcement_is_audited_as_observed_without_rewriting_history(self):
        helper.manual_ban({"ip": "198.51.100.8", "reason": "Repeated exploit probes"})
        helper.AUDIT_PATH.unlink()

        result = helper.audit_existing_blocks()
        again = helper.audit_existing_blocks()
        records = [json.loads(line) for line in helper.AUDIT_PATH.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(result["observed_existing_blocks"], 1)
        self.assertEqual(again["observed_existing_blocks"], 0)
        self.assertEqual(records[0]["action"], "existing_block_observed")
        self.assertEqual(records[0]["source"], "Manual dashboard ban")

    def test_local_control_socket_accepts_only_the_app_operations(self):
        helper.SOCKET_PATH = Path(self.temp.name) / "dashboard.sock"
        server = helper.DashboardControlServer(str(helper.SOCKET_PATH), helper.DashboardRequestHandler)
        os.chmod(helper.SOCKET_PATH, 0o660)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            with mock.patch.object(helper, "perform", return_value={"ok": True, "bans": []}):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(str(helper.SOCKET_PATH))
                client.sendall(b'{"operation":"collect","payload":{}}\n')
                response = client.makefile("rb").readline()
                client.close()
            self.assertEqual(json.loads(response), {"ok": True, "bans": []})

            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(helper.SOCKET_PATH))
            client.sendall(b'{"operation":"restore"}\n')
            response = json.loads(client.makefile("rb").readline())
            client.close()
            self.assertEqual(response, {"error": "Unsupported helper operation"})
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

    def test_enforcement_timer_does_not_consume_dashboard_alert_history(self):
        state = helper.empty_state()
        state["last_alert_check"] = 123456
        helper.write_state(state)
        with mock.patch.object(helper, "parse_decisions", return_value=([], None)), \
             mock.patch.object(helper, "fail2ban_state", return_value=({"jails": [], "bans": []}, None)), \
             mock.patch.object(helper, "configured_nets", return_value=[]):
            result = helper.collect(sync_only=True)

        self.assertEqual(result["alerts"], [])
        self.assertEqual(helper.read_state()["last_alert_check"], 123456)

    def test_automatic_crowdsec_and_fail2ban_bans_are_audited_once_with_sources(self):
        crowdsec = [{
            "decisions": [{
                "type": "ban", "scope": "Ip", "value": "198.51.100.9",
                "origin": "crowdsec", "scenario": "crowdsecurity/http-probing",
            }],
            "events": [],
        }]
        fail2ban = {"jails": ["sshd"], "bans": [{
            "ip": "2001:db8::9", "source": "Fail2ban sshd", "reason": "Fail2ban jail: sshd",
        }]}
        with mock.patch.object(helper, "parse_decisions", return_value=(crowdsec, None)), \
             mock.patch.object(helper, "fail2ban_state", return_value=(fail2ban, None)), \
             mock.patch.object(helper, "ensure_firewall"), \
             mock.patch.object(helper, "firewall_counters", return_value=0):
            helper.collect(sync_only=True)
            helper.collect(sync_only=True)

        records = [json.loads(line) for line in helper.AUDIT_PATH.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual({record["action"] for record in records}, {"ban"})
        self.assertEqual({record["source"] for record in records}, {"CrowdSec", "Fail2ban sshd"})


if __name__ == "__main__":
    unittest.main()
