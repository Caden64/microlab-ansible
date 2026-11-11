"""Localhost-only behavior tests for the recursion fixture forwarder zone.

The tests start a tiny mock Technitium HTTP API, run the real
``roles/technitium_dns/tasks/fixture_zone.yml`` task file through
``ansible-playbook`` on localhost, and inspect both the rendered mutation
requests and the resulting mock state. Nothing contacts a real host, DNS
server, firewall, CA, or the internet.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
ZONE = "fixture.microlab.internal"
MARKER = "micolab-managed:fixture-forwarder"
UPSTREAM = "127.0.0.1:5353"
OLD_UPSTREAM = "127.0.0.1:5300"
ACL = ["10.64.0.0/24"]


def find_ansible_playbook() -> str | None:
    candidates = [os.environ.get("ANSIBLE_PLAYBOOK")]
    candidates.extend(
        [
            shutil.which("ansible-playbook"),
            "/tmp/opencode/ansvenv/bin/ansible-playbook",
            "/tmp/ansvenv217/bin/ansible-playbook",
            "/tmp/ansvenv/bin/ansible-playbook",
        ]
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def fwd(
    forwarder: str,
    comments: str = "",
    *,
    protocol: str = "Udp",
    priority: int = 0,
    name: str = ZONE,
) -> dict:
    return {
        "name": name,
        "type": "FWD",
        "ttl": 0,
        "comments": comments,
        "rData": {
            "protocol": protocol,
            "forwarder": forwarder,
            "priority": priority,
            "dnssecValidation": False,
            "proxyType": "DefaultProxy",
        },
    }


class MockState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.zones: dict[str, dict] = {}
        self.records: list[dict] = []
        self.options: dict[str, dict] = {}
        self.posts: list[tuple[str, dict]] = []

    def add_zone(self, name: str = ZONE, *, zone_type: str = "Forwarder") -> None:
        self.zones[name] = {
            "name": name,
            "type": zone_type,
            "internal": False,
            "disabled": False,
        }
        self.options.setdefault(
            name, {"queryAccess": "Allow", "queryAccessNetworkACL": []}
        )

    def add_record(self, record: dict) -> None:
        self.records.append(record)

    def mutation_posts(self) -> list[tuple[str, dict]]:
        return [
            (path, body)
            for path, body in self.posts
            if path
            in {
                "/api/zones/create",
                "/api/zones/options/set",
                "/api/zones/records/add",
                "/api/zones/records/update",
                "/api/zones/records/delete",
            }
        ]

    def reset_posts(self) -> None:
        self.posts.clear()


class MockHandler(BaseHTTPRequestHandler):
    state: MockState

    def log_message(self, *args) -> None:
        pass

    def _send(self, payload: dict, code: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _form(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode()
        return {key: values[0] for key, values in parse_qs(raw).items()}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        state = self.state
        with state.lock:
            if parsed.path == "/api/zones/list":
                name_filter = query.get("filterName", [""])[0]
                zones = [
                    zone
                    for zone in state.zones.values()
                    if not name_filter or fnmatch.fnmatch(zone["name"], name_filter)
                ]
                self._send({"status": "ok", "response": {"zones": zones}})
            elif parsed.path == "/api/zones/records/get":
                zone_name = query.get("zone", [query.get("domain", [""])[0]])[0]
                flattened = []
                for record in state.records:
                    if record["name"] == zone_name or record["name"].endswith(
                        "." + zone_name
                    ):
                        flattened.append(dict(record))
                self._send(
                    {
                        "status": "ok",
                        "response": {
                            "zone": state.zones.get(zone_name, {}),
                            "records": flattened,
                        },
                    }
                )
            elif parsed.path == "/api/zones/options/get":
                zone_name = query.get("zone", [""])[0]
                self._send(
                    {
                        "status": "ok",
                        "response": state.options.get(zone_name, {}),
                    }
                )
            elif parsed.path == "/api/status":
                self._send({"status": "ok"})
            elif parsed.path == "/api/_state":
                self._send(
                    {
                        "status": "ok",
                        "zones": state.zones,
                        "records": state.records,
                        "options": state.options,
                        "posts": state.posts,
                    }
                )
            else:
                self._send(
                    {"status": "error", "errorMessage": "not found"}, 404
                )

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        form = self._form()
        state = self.state
        with state.lock:
            state.posts.append((parsed.path, form))
            if parsed.path == "/api/user/login":
                self._send({"status": "ok", "token": "test-token"})
            elif parsed.path == "/api/user/logout":
                self._send({"status": "ok"})
            elif parsed.path == "/api/zones/create":
                zone_name = form.get("zone", "")
                if zone_name in state.zones:
                    self._send(
                        {
                            "status": "error",
                            "errorMessage": "Zone already exists: " + zone_name,
                        },
                        400,
                    )
                    return
                state.add_zone(zone_name)
                if form.get("initializeForwarder", "true").lower() == "true":
                    state.add_record(
                        fwd(
                            form.get("forwarder", ""),
                            form.get("comments", ""),
                            protocol=form.get("protocol", "Udp"),
                        )
                    )
                self._send({"status": "ok", "response": {"domain": zone_name}})
            elif parsed.path == "/api/zones/options/set":
                zone_name = form.get("zone", "")
                options = state.options.setdefault(zone_name, {})
                if "queryAccess" in form:
                    options["queryAccess"] = form["queryAccess"]
                if "queryAccessNetworkACL" in form:
                    raw = form["queryAccessNetworkACL"]
                    options["queryAccessNetworkACL"] = [
                        item for item in raw.split(",") if item
                    ]
                self._send({"status": "ok", "response": {}})
            elif parsed.path == "/api/zones/records/add":
                zone_name = form.get("zone", form.get("domain", ""))
                record_type = form.get("type", "").upper()
                if record_type != "FWD":
                    self._send(
                        {
                            "status": "error",
                            "errorMessage": "mock only implements FWD add",
                        },
                        400,
                    )
                    return
                existing = [
                    record
                    for record in state.records
                    if record["type"] == "FWD"
                    and record["name"] == form.get("domain", zone_name)
                    and record["rData"]["forwarder"] == form.get("forwarder", "")
                ]
                if existing and form.get("overwrite", "false").lower() != "true":
                    self._send(
                        {
                            "status": "error",
                            "errorMessage": "Record already exists.",
                        },
                        400,
                    )
                    return
                state.add_record(
                    fwd(
                        form.get("forwarder", ""),
                        form.get("comments", ""),
                        protocol=form.get("protocol", "Udp"),
                        priority=int(form.get("forwarderPriority", "0") or 0),
                        name=form.get("domain", zone_name),
                    )
                )
                self._send({"status": "ok", "response": {}})
            elif parsed.path == "/api/zones/records/update":
                record_type = form.get("type", "").upper()
                if record_type != "FWD":
                    self._send(
                        {
                            "status": "error",
                            "errorMessage": "mock only implements FWD update",
                        },
                        400,
                    )
                    return
                old_forwarder = form.get("forwarder", "")
                updated = False
                for record in state.records:
                    if (
                        record["type"] == "FWD"
                        and record["name"] == form.get("domain", ZONE)
                        and record["rData"]["forwarder"] == old_forwarder
                    ):
                        record["rData"]["forwarder"] = form.get(
                            "newForwarder", old_forwarder
                        )
                        record["rData"]["protocol"] = form.get(
                            "newProtocol", record["rData"].get("protocol", "Udp")
                        )
                        record["comments"] = form.get("comments", record.get("comments", ""))
                        record["ttl"] = int(form.get("ttl", record.get("ttl", 0)) or 0)
                        updated = True
                if not updated:
                    self._send(
                        {
                            "status": "error",
                            "errorMessage": "Cannot update record: no such record exists.",
                        },
                        400,
                    )
                    return
                self._send({"status": "ok", "response": {}})
            elif parsed.path == "/api/zones/records/delete":
                old_forwarder = form.get("forwarder", "")
                state.records[:] = [
                    record
                    for record in state.records
                    if not (
                        record["type"] == "FWD"
                        and record["rData"]["forwarder"] == old_forwarder
                    )
                ]
                self._send({"status": "ok", "response": {}})
            else:
                self._send(
                    {"status": "error", "errorMessage": "not found"}, 404
                )


class FixtureZonePlaybookTests(unittest.TestCase):
    PLAYBOOK = """---
- name: disposable fixture forwarder ownership test
  hosts: localhost
  connection: local
  gather_facts: false
  become: false
  vars:
    micolab_technitium_token: test-token
    micolab_technitium_service_name: microlab-test-noop
    micolab_dns_api_base: "http://127.0.0.1:{port}"
    micolab_dns_fixture_zone: "{zone}"
    micolab_dns_fixture_upstream: "{upstream}"
    micolab_dns_fixture_upstream_verified: true
    micolab_dns_fixture_name: dialog.{zone}
    micolab_dns_fixture_expected_ip: 192.0.2.80
    micolab_dns_fixture_zone_marker: "{marker}"
    micolab_dns_fixture_zone_state_path: "{state_path}"
    micolab_dns_required_recursion_acl: {acl}
  tasks:
    - name: run the fixture zone ownership tasks
      ansible.builtin.include_role:
        name: technitium_dns
        tasks_from: fixture_zone
"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ansible = find_ansible_playbook()
        if cls.ansible is None:
            raise unittest.SkipTest("ansible-playbook is not installed")

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="micolab-fixture-zone-")
        self.root = Path(self.tmp.name)
        self.state_path = self.root / "fixture-zone.state"
        self.state = MockState()
        handler = type("FixtureMockHandler", (MockHandler,), {"state": self.state})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()
        self.inventory = self.root / "inventory.yml"
        self.inventory.write_text(
            "all:\n"
            "  children:\n"
            "    microlab_management:\n"
            "      hosts:\n"
            "        localhost:\n"
            "          ansible_connection: local\n"
            f"          ansible_python_interpreter: {sys.executable}\n"
            "          ansible_become: false\n",
            encoding="utf-8",
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake_systemctl = self.bin / "systemctl"
        fake_systemctl.write_text(
            "#!/bin/sh\n"
            "case \"$*\" in\n"
            "  *show*)\n"
            "    printf 'LoadState=loaded\\nActiveState=active\\n'\n"
            "    printf 'SubState=running\\nUnitFileState=enabled\\n'\n"
            "    exit 0\n"
            "    ;;\n"
            "  *is-active*) echo active; exit 0 ;;\n"
            "  *is-enabled*) echo enabled; exit 0 ;;\n"
            "  *) exit 0 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake_systemctl.chmod(0o755)
        self.playbook = self.root / "play.yml"
        self.write_playbook()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def write_playbook(self, upstream: str = UPSTREAM) -> None:
        self.playbook.write_text(
            self.PLAYBOOK.format(
                port=self.port,
                zone=ZONE,
                upstream=upstream,
                marker=MARKER,
                state_path=self.state_path,
                acl=json.dumps(ACL),
            ),
            encoding="utf-8",
        )

    def write_marker(self, zone: str = ZONE) -> None:
        self.state_path.write_text(
            f"schema=1\nowner={MARKER}\nzone={zone}\n", encoding="utf-8"
        )

    def run_playbook(self, upstream: str = UPSTREAM) -> subprocess.CompletedProcess:
        self.write_playbook(upstream)
        self.state.reset_posts()
        env = dict(os.environ)
        env["ANSIBLE_STDOUT_CALLBACK"] = "default"
        env["PATH"] = str(self.bin) + os.pathsep + env.get("PATH", "")
        env.pop("ANSIBLE_CONFIG", None)
        return subprocess.run(
            [
                self.ansible,
                "-i",
                str(self.inventory),
                str(self.playbook),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            env=env,
        )

    @staticmethod
    def changed(result: subprocess.CompletedProcess) -> int:
        matches = re.findall(r"changed=(\d+)", result.stdout)
        if not matches:
            raise AssertionError(result.stdout + result.stderr)
        return int(matches[-1])

    def assert_success(self, result: subprocess.CompletedProcess) -> None:
        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout[-6000:] + result.stderr[-3000:],
        )

    def assert_failure(self, result: subprocess.CompletedProcess, text: str) -> None:
        self.assertNotEqual(result.returncode, 0, msg=result.stdout[-6000:])
        self.assertIn(text, result.stdout + result.stderr)

    def test_actual_mock_unchanged_rerun_is_zero_mutation(self) -> None:
        self.state.add_zone()
        self.state.add_record(fwd(UPSTREAM, MARKER))
        self.state.add_record(
            {
                "name": "note." + ZONE,
                "type": "TXT",
                "ttl": 60,
                "comments": "",
                "rData": {"text": "preserve-me"},
            }
        )
        self.state.options[ZONE] = {
            "queryAccess": "UseSpecifiedNetworkACL",
            "queryAccessNetworkACL": list(ACL),
        }

        first = self.run_playbook()
        self.assert_success(first)
        self.assertEqual(self.changed(first), 0, first.stdout)
        self.assertEqual(self.state.mutation_posts(), [])

        second = self.run_playbook()
        self.assert_success(second)
        self.assertEqual(self.changed(second), 0, second.stdout)
        self.assertEqual(self.state.mutation_posts(), [])
        self.assertEqual(self.state.records[0]["rData"]["forwarder"], UPSTREAM)
        self.assertTrue(
            any(record["type"] == "TXT" for record in self.state.records)
        )

    def test_owned_upstream_update_is_the_only_intended_mutation(self) -> None:
        human_note = "operator note\n" + MARKER
        self.state.add_zone()
        self.state.add_record(fwd(OLD_UPSTREAM, human_note, priority=7))
        self.state.options[ZONE] = {
            "queryAccess": "UseSpecifiedNetworkACL",
            "queryAccessNetworkACL": list(ACL),
        }

        first = self.run_playbook()
        self.assert_success(first)
        self.assertGreaterEqual(self.changed(first), 1, first.stdout)
        posts = self.state.mutation_posts()
        self.assertEqual([path for path, _ in posts], ["/api/zones/records/update"])
        update = posts[0][1]
        self.assertEqual(update["forwarder"], OLD_UPSTREAM)
        self.assertEqual(update["newForwarder"], UPSTREAM)
        self.assertEqual(update["forwarderPriority"], "7")
        self.assertEqual(update["comments"], human_note)
        self.assertEqual(
            self.state.records[0]["rData"]["forwarder"], UPSTREAM
        )

        second = self.run_playbook()
        self.assert_success(second)
        self.assertEqual(self.changed(second), 0, second.stdout)
        self.assertEqual(self.state.mutation_posts(), [])

    def test_unowned_zone_conflict_mutates_nothing(self) -> None:
        self.state.add_zone()
        self.state.add_record(fwd(UPSTREAM))
        self.state.options[ZONE] = {
            "queryAccess": "Allow",
            "queryAccessNetworkACL": [],
        }

        result = self.run_playbook()
        self.assert_failure(result, "unowned FWD record")
        self.assertEqual(self.state.mutation_posts(), [])
        self.assertEqual(self.state.records[0]["comments"], "")
        self.assertEqual(self.state.options[ZONE]["queryAccess"], "Allow")

    def test_multiple_unknown_forwarders_are_preserved_on_fail_closed(self) -> None:
        self.state.add_zone()
        self.state.add_record(fwd("127.0.0.1:5300"))
        self.state.add_record(fwd("127.0.0.1:5301"))

        result = self.run_playbook()
        self.assert_failure(result, "unowned FWD record")
        self.assertEqual(self.state.mutation_posts(), [])
        self.assertEqual(
            sorted(record["rData"]["forwarder"] for record in self.state.records),
            ["127.0.0.1:5300", "127.0.0.1:5301"],
        )

    def test_query_acl_is_changed_only_for_an_owned_zone(self) -> None:
        self.state.add_zone()
        self.state.add_record(fwd(UPSTREAM, MARKER))
        self.state.options[ZONE] = {
            "queryAccess": "Allow",
            "queryAccessNetworkACL": [],
        }

        first = self.run_playbook()
        self.assert_success(first)
        self.assertGreaterEqual(self.changed(first), 1, first.stdout)
        self.assertEqual(
            [path for path, _ in self.state.mutation_posts()],
            ["/api/zones/options/set"],
        )
        self.assertEqual(
            self.state.options[ZONE]["queryAccess"], "UseSpecifiedNetworkACL"
        )
        self.assertEqual(self.state.options[ZONE]["queryAccessNetworkACL"], ACL)

        second = self.run_playbook()
        self.assert_success(second)
        self.assertEqual(self.changed(second), 0, second.stdout)
        self.assertEqual(self.state.mutation_posts(), [])

    def test_crash_after_create_before_fwd_resumes_only_with_matching_marker(self) -> None:
        self.state.add_zone()
        self.state.options[ZONE] = {
            "queryAccess": "UseSpecifiedNetworkACL",
            "queryAccessNetworkACL": list(ACL),
        }
        self.write_marker()

        first = self.run_playbook()
        self.assert_success(first)
        self.assertGreaterEqual(self.changed(first), 1, first.stdout)
        self.assertEqual(
            [path for path, _ in self.state.mutation_posts()],
            ["/api/zones/records/add"],
        )
        self.assertEqual(self.state.records[0]["comments"], MARKER)
        self.assertEqual(self.state.records[0]["rData"]["forwarder"], UPSTREAM)

        second = self.run_playbook()
        self.assert_success(second)
        self.assertEqual(self.changed(second), 0, second.stdout)
        self.assertEqual(self.state.mutation_posts(), [])

    def test_empty_zone_without_matching_marker_fails_closed(self) -> None:
        self.state.add_zone()
        self.state.options[ZONE] = {
            "queryAccess": "UseSpecifiedNetworkACL",
            "queryAccessNetworkACL": list(ACL),
        }
        self.write_marker(zone="other." + ZONE)

        result = self.run_playbook()
        self.assert_failure(result, "local creation marker is absent or does not")
        self.assertEqual(self.state.mutation_posts(), [])
        self.assertEqual(self.state.records, [])

    def test_contradictory_duplicate_or_extra_marker_lines_fail_closed(self) -> None:
        self.state.add_zone()
        self.state.options[ZONE] = {
            "queryAccess": "UseSpecifiedNetworkACL",
            "queryAccessNetworkACL": list(ACL),
        }
        exact = f"schema=1\nowner={MARKER}\nzone={ZONE}\n"
        variants = {
            "contradictory-prefix": (
                "schema=2\nowner=human\nzone=other.internal\n" + exact
            ),
            "duplicate-line": exact + f"zone={ZONE}\n",
            "conflicting-zone": exact + "zone=other.internal\n",
            "extra-line": exact + "note=extra\n",
            "blank-line": f"schema=1\n\nowner={MARKER}\nzone={ZONE}\n",
            "reordered": f"owner={MARKER}\nschema=1\nzone={ZONE}\n",
            "missing-line": f"schema=1\nowner={MARKER}\n",
        }
        for label, content in variants.items():
            with self.subTest(label):
                self.state.records = []
                self.state_path.write_text(content, encoding="utf-8")
                result = self.run_playbook()
                self.assert_failure(
                    result, "local creation marker is absent or does not"
                )
                self.assertEqual(self.state.mutation_posts(), [])
                self.assertEqual(self.state.records, [])
                self.assertEqual(
                    self.state_path.read_text(encoding="utf-8"), content
                )

    def test_absent_zone_is_created_empty_then_receives_one_owned_fwd(self) -> None:
        first = self.run_playbook()
        self.assert_success(first)
        self.assertGreater(self.changed(first), 0, first.stdout)
        paths = [path for path, _ in self.state.mutation_posts()]
        self.assertIn("/api/zones/create", paths)
        self.assertIn("/api/zones/records/add", paths)
        self.assertLess(paths.index("/api/zones/create"), paths.index("/api/zones/records/add"))
        create = self.state.mutation_posts()[0][1]
        self.assertEqual(create["initializeForwarder"], "false")
        self.assertEqual(len(self.state.records), 1)
        self.assertEqual(self.state.records[0]["comments"], MARKER)
        self.assertEqual(self.state.records[0]["rData"]["forwarder"], UPSTREAM)
        self.assertEqual(
            self.state.options[ZONE]["queryAccess"], "UseSpecifiedNetworkACL"
        )
        self.assertEqual(self.state.options[ZONE]["queryAccessNetworkACL"], ACL)

        second = self.run_playbook()
        self.assert_success(second)
        self.assertEqual(self.changed(second), 0, second.stdout)
        self.assertEqual(self.state.mutation_posts(), [])


if __name__ == "__main__":
    unittest.main()
