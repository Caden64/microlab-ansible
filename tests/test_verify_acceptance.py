"""Runtime and Ansible integration tests for the verify role repairs.

These tests do not contact a real host, Forgejo, Caddy, step-ca, or a public
DNS service. They use disposable local objects:

* a real TLS Git smart-HTTP server on 127.0.0.1 with a private CA that is not
  installed in the system trust store, so every successful HTTPS Git operation
  proves the role's explicit ``http.sslCAInfo``/``http.sslVerify`` pinning;
* a fake ``ssh`` transport that executes real ``git-upload-pack`` and
  ``git-receive-pack`` against local bare repositories;
* real local ``git`` staging, commit, push, remote-ref verification, and branch
  deletion, including a deletion-denied hook;
* a real DoT TLS server whose DNS response can be an answer, REFUSED, a wrong
  answer, or malformed data, exercised through the actual external_acl shell;
  the query name and expected IP come from the shared DNS recursion fixture,
  while DoH keeps the authoritative infrastructure query;
* real local removal failures, injected by a read-only bind mount in an
  unprivileged mount namespace, to prove a failed local removal is never
  reported as removed.

The end-to-end acceptance tests run ``ansible-playbook`` in a private user
namespace so the role's root-owned workspace tasks execute without sudo.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = Path("/tmp/opencode")
if not TMP_ROOT.is_dir() or not os.access(TMP_ROOT, os.W_OK):
    TMP_ROOT = Path(tempfile.gettempdir())

try:
    import yaml
except ImportError:  # pragma: no cover - environment guard
    yaml = None

DOT_PROBE = ROOT / "roles/verify/files/dot_probe.py"
EXTERNAL_ACL = ROOT / "roles/verify/tasks/external_acl.yml"
GIT_ACCEPTANCE = ROOT / "roles/verify/tasks/git_acceptance.yml"


def find_ansible_playbook():
    candidates = [
        os.environ.get("ANSIBLE_PLAYBOOK"),
        shutil.which("ansible-playbook"),
        "/tmp/opencode/ansvenv/bin/ansible-playbook",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def run_checked(*args, **kwargs):
    return subprocess.run(
        args,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **kwargs,
    )


def _mkdir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def make_ca_and_server_cert(root: Path, *, ip="127.0.0.1"):
    """Create a private CA and a server certificate with an IP SAN.

    The CA includes key identifiers because OpenSSL 3 rejects test leaves that
    omit an authority key identifier during strict verification.
    """
    ca_key = root / "ca.key"
    ca_crt = root / "ca.crt"
    run_checked(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "1",
        "-subj", "/CN=MicroLab Test Root",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
        "-addext", "authorityKeyIdentifier=keyid:always",
    )
    server_key = root / "server.key"
    server_csr = root / "server.csr"
    server_crt = root / "server.crt"
    ext = root / "server.ext"
    ext.write_text(
        "subjectAltName=IP:{}\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n".format(ip),
        encoding="utf-8",
    )
    run_checked(
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(server_key), "-out", str(server_csr),
        "-subj", "/CN={}".format(ip),
    )
    run_checked(
        "openssl", "x509", "-req", "-in", str(server_csr),
        "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(server_crt), "-days", "1", "-extfile", str(ext),
    )
    return ca_crt, server_crt, server_key


def load_dot_probe_module():
    spec = importlib.util.spec_from_file_location("micolab_dot_probe", DOT_PROBE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def flatten_tasks(tasks):
    for task in tasks:
        if not isinstance(task, dict):
            continue
        yield task
        for key in ("block", "always", "rescue"):
            if key in task:
                yield from flatten_tasks(task[key])


def external_acl_shell():
    tasks = yaml.safe_load(EXTERNAL_ACL.read_text(encoding="utf-8"))
    task = next(
        task
        for task in flatten_tasks(tasks)
        if task.get("name") == "Run every external ACL probe on its delegated inventory host"
    )
    return task["ansible.builtin.shell"]


class DotResponseServer:
    """A real TLS DoT listener that returns a controlled DNS response."""

    def __init__(self, ca_crt, server_crt, server_key, *, mode, answer_ip=None, rcode=0):
        self.mode = mode
        self.answer_ip = answer_ip
        self.rcode = rcode
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(server_crt, server_key)
        self.ca_crt = ca_crt
        self.query_name = None
        self.query_names = []
        self.peers = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.error = None
        self.thread.start()

    @staticmethod
    def _query_name(query):
        offset = 12
        labels = []
        while offset < len(query):
            length = query[offset]
            if length == 0 or length & 0xC0:
                break
            labels.append(query[offset + 1:offset + 1 + length].decode("ascii"))
            offset += 1 + length
        return ".".join(labels)

    def _response(self, query):
        self.query_name = self._query_name(query)
        self.query_names.append(self.query_name)
        query_id = struct.unpack("!H", query[:2])[0]
        flags = 0x8180 | self.rcode
        response = struct.pack("!HHHHHH", query_id, flags, 1, 1 if self.answer_ip else 0, 0, 0)
        response += query[12:]
        if self.answer_ip:
            response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(self.answer_ip)
        return response

    def _serve(self):
        # Serve until closed: a denied DoT probe sends the fixture query and
        # then the global-recursion query on separate connections.
        while True:
            try:
                connection, peer = self.listener.accept()
            except OSError:
                return
            self.peers.append(peer[0])
            self._serve_one(connection)

    def _serve_one(self, connection):
        try:
            if self.mode == "plain":
                connection.sendall(b"not tls")
                connection.close()
                return
            if self.mode == "malformed":
                with self.context.wrap_socket(connection, server_side=True) as tls:
                    tls.recv(2)
                    tls.recv(512)
                    payload = b"\x00\x03abc"
                    tls.sendall(payload)
                return
            with self.context.wrap_socket(connection, server_side=True) as tls:
                header = tls.recv(2)
                length = struct.unpack("!H", header)[0]
                query = b""
                while len(query) < length:
                    chunk = tls.recv(length - len(query))
                    if not chunk:
                        return
                    query += chunk
                response = self._response(query)
                tls.sendall(struct.pack("!H", len(response)) + response)
        except Exception as exc:  # pragma: no cover - diagnostic only
            self.error = exc

    def close(self):
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=5)


def run_external_acl_script(script, env, *, fake_curl_dir=None):
    full_env = dict(os.environ)
    full_env.update(env)
    if fake_curl_dir:
        full_env["PATH"] = "{}:{}".format(fake_curl_dir, full_env.get("PATH", ""))
    return subprocess.run(
        ["bash"],
        input=script,
        env=full_env,
        text=True,
        capture_output=True,
        timeout=30,
    )


@unittest.skipUnless(yaml is not None, "PyYAML is required")
class GitAcceptanceWiringTests(unittest.TestCase):
    def test_assert_loop_is_task_level_not_a_module_parameter(self):
        tasks = yaml.safe_load(GIT_ACCEPTANCE.read_text(encoding="utf-8"))
        for task in flatten_tasks(tasks):
            for key, value in task.items():
                if key.endswith("assert") and isinstance(value, dict):
                    self.assertNotIn("loop", value, msg="loop nested inside assert: {}".format(task.get("name")))

    def test_every_https_git_operation_uses_the_same_pinned_tls_args(self):
        tasks = yaml.safe_load(GIT_ACCEPTANCE.read_text(encoding="utf-8"))
        tls_fact = next(
            task
            for task in flatten_tasks(tasks)
            if task.get("name") == "Compose the pinned Git transport inputs"
        )["ansible.builtin.set_fact"]
        self.assertEqual(
            tls_fact["micolab_verify_git_https_tls_args"],
            ["-c", "http.sslCAInfo={{ micolab_verify_tls_root }}", "-c", "http.sslVerify=true"],
        )

        https_operations = []
        for task in flatten_tasks(tasks):
            command = task.get("ansible.builtin.command")
            if not command:
                continue
            argv = command.get("argv")
            if not isinstance(argv, str):
                continue
            if "micolab_verify_git_https_tls_args" in argv:
                https_operations.append(task.get("name"))
        # clone, push, remote check, anonymous check, and both cleanup commands
        self.assertGreaterEqual(len(https_operations), 6)
        self.assertIn("Clone the disposable repository over HTTPS", https_operations)
        self.assertIn("Push the unique HTTPS test branch", https_operations)
        self.assertIn("Delete the HTTPS test branch from the remote", https_operations)

    def test_https_cleanup_is_gated_on_observed_absent_remote_ref(self):
        text = GIT_ACCEPTANCE.read_text(encoding="utf-8")
        self.assertIn("Verify the HTTPS test branch is absent from the remote", text)
        self.assertIn("Verify the SSH test branch is absent from the remote", text)
        self.assertIn("micolab_verify_git_https_remote_check", text)
        self.assertIn("micolab_verify_git_ssh_remote_check", text)
        self.assertNotIn("sslVerify=false", text)

    def test_local_removal_failures_are_ignored_but_statted_for_absence(self):
        tasks = yaml.safe_load(GIT_ACCEPTANCE.read_text(encoding="utf-8"))
        by_name = {
            task.get("name"): task
            for task in flatten_tasks(tasks)
        }
        for name in (
            "Remove the HTTPS askpass helper",
            "Remove the private Git acceptance workspace",
        ):
            task = by_name[name]
            self.assertIs(task.get("ignore_errors"), True, msg=name)
            # failed_when: false would erase a real removal failure.
            self.assertNotIn("failed_when", task, msg=name)

        for name in (
            "Verify the HTTPS askpass helper is absent after removal",
            "Verify the private Git acceptance workspace is absent after removal",
        ):
            self.assertIn(name, by_name)

        fact = by_name["Set the local removal states from the observed filesystem"][
            "ansible.builtin.set_fact"
        ]
        for key in (
            "micolab_verify_git_credentials_removed",
            "micolab_verify_git_workspace_removed",
        ):
            expression = fact[key]
            self.assertIn("stat.exists is defined", expression, msg=key)
            self.assertIn("not (", expression, msg=key)
            self.assertNotIn("removal.failed", expression, msg=key)

        fail_msg = by_name[
            "Require Git acceptance to finish with proven remote and local cleanup"
        ]["ansible.builtin.assert"]["fail_msg"]
        self.assertIn("askpass.sh", fail_msg)
        self.assertIn("do not delete a broader directory", fail_msg)


@unittest.skipUnless(yaml is not None, "PyYAML is required")
class DotProbeClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="verify-dot-", dir=str(TMP_ROOT))
        cls.root = Path(cls.tmp.name)
        cls.ca, cls.crt, cls.key = make_ca_and_server_cert(cls.root)
        cls.module = load_dot_probe_module()
        cls.script = external_acl_shell()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def probe_env(self, port, expect):
        return {
            "CHECK": "dot",
            "EXPECT": expect,
            "CA_FILE": str(self.ca),
            "TIMEOUT": "2",
            "TARGET_HOST": "127.0.0.1",
            "MGMT_IP": "127.0.0.1",
            "HTTPS_PORT": "443",
            "DOH_HOST": "127.0.0.1",
            "DOH_PATH": "/dns-query",
            "PROBE_NAME": "ns1.microlab.hnh",
            "PROBE_IP": "10.0.0.5",
            "DOT_PROBE": str(DOT_PROBE),
            "DOT_HOST": "127.0.0.1",
            "DOT_PORT": str(port),
            "DOT_QUERY_NAME": "fixture.microlab.test",
            "DOT_EXPECT_IP": "198.51.100.7",
            "DOT_RECURSION_DENIED_NAME": "microlab-recursion-acl-probe.invalid",
            "SOURCE_ADDRESS": "127.0.0.1",
        }

    def serve(self, **kwargs):
        server = DotResponseServer(self.ca, self.crt, self.key, **kwargs)
        self.addCleanup(server.close)
        return server

    def test_allowed_query_returns_expected_answer(self):
        server = self.serve(mode="dns", answer_ip="198.51.100.7")
        result = run_external_acl_script(self.script, self.probe_env(server.port, "allowed"))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("dot allowed validated", result.stdout)
        self.assertEqual(server.query_name, "fixture.microlab.test")

    def test_positive_dns_refused_counts_as_denial(self):
        server = self.serve(mode="dns", rcode=5)
        result = run_external_acl_script(self.script, self.probe_env(server.port, "denied"))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn(
            "fixture_zone_query_acl=dns_refused global_recursion_acl=dns_refused",
            result.stdout,
        )
        # Both refusals come from the fixture zone query ACL and an
        # out-of-zone recursion query, never from the authoritative ns1 name.
        self.assertEqual(
            server.query_names,
            ["fixture.microlab.test", "microlab-recursion-acl-probe.invalid"],
        )
        self.assertEqual(server.peers, ["127.0.0.1", "127.0.0.1"])

    def test_authoritative_answer_is_not_a_dot_denial(self):
        # An authoritative-only client that queries ns1.<zone> gets a real A
        # answer; that must never be accepted as recursion denial.
        server = self.serve(mode="dns", answer_ip="198.51.100.7")
        result = run_external_acl_script(self.script, self.probe_env(server.port, "denied"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inconclusive", result.stderr)
        self.assertNotIn("dot denied source=", result.stdout)

    def test_unused_port_is_inconclusive_not_a_denial(self):
        placeholder = socket.socket()
        placeholder.bind(("127.0.0.1", 0))
        port = placeholder.getsockname()[1]
        placeholder.close()
        result = run_external_acl_script(self.script, self.probe_env(port, "denied"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inconclusive", result.stderr)
        self.assertIn("tcp_refused", result.stderr)
        self.assertNotIn("dot denied source=", result.stdout)

    def test_wrong_answer_is_not_a_denial(self):
        server = self.serve(mode="dns", answer_ip="10.0.0.9")
        result = run_external_acl_script(self.script, self.probe_env(server.port, "denied"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong_answer", result.stderr)
        self.assertIn("inconclusive", result.stderr)

    def test_malformed_dns_is_not_a_denial(self):
        server = self.serve(mode="malformed")
        result = run_external_acl_script(self.script, self.probe_env(server.port, "denied"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("protocol", result.stderr)
        self.assertIn("inconclusive", result.stderr)

    def test_tls_error_is_not_a_denial(self):
        plain = socket.socket()
        plain.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        plain.bind(("127.0.0.1", 0))
        plain.listen(1)
        port = plain.getsockname()[1]

        def serve_plain():
            connection, _ = plain.accept()
            connection.sendall(b"not tls")
            connection.close()
            plain.close()

        thread = threading.Thread(target=serve_plain, daemon=True)
        thread.start()
        result = run_external_acl_script(self.script, self.probe_env(port, "denied"))
        thread.join(timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tls_handshake", result.stderr)
        self.assertIn("TLS error", result.stderr)

    def test_probe_exposes_distinct_transport_categories(self):
        original = self.module.socket.create_connection

        def fake_connect(exc):
            def connect(*_args, **_kwargs):
                raise exc
            return connect

        cases = [
            (socket.timeout("timed out"), "tcp_connect_timeout"),
            (ConnectionRefusedError("refused"), "tcp_refused"),
            (OSError("network unreachable"), "tcp_unreachable"),
        ]
        try:
            for exc, expected in cases:
                with self.subTest(expected=expected):
                    status = self.root / "status-{}.json".format(expected)
                    self.module.socket.create_connection = fake_connect(exc)
                    args = [
                        "dot_probe.py",
                        "--connect-host", "127.0.0.1",
                        "--port", "853",
                        "--server-name", "127.0.0.1",
                        "--ca-file", str(self.ca),
                        "--name", "ns.example",
                        "--expect", "10.0.0.5",
                        "--timeout", "1",
                        "--status-file", str(status),
                    ]
                    old_argv = __import__("sys").argv
                    __import__("sys").argv = args
                    try:
                        rc = self.module.main()
                    finally:
                        __import__("sys").argv = old_argv
                    self.assertNotEqual(rc, 0)
                    self.assertEqual(json.loads(status.read_text())["category"], expected)
        finally:
            self.module.socket.create_connection = original


@unittest.skipUnless(yaml is not None, "PyYAML is required")
class ExternalAclFixtureIntegrationTests(unittest.TestCase):
    """DoT must query the DNS role fixture while DoH stays authoritative."""

    @classmethod
    def setUpClass(cls):
        cls.tasks = yaml.safe_load(EXTERNAL_ACL.read_text(encoding="utf-8"))
        cls.defaults = yaml.safe_load(
            (ROOT / "roles/verify/defaults/main.yml").read_text(encoding="utf-8")
        )
        cls.probe = next(
            task
            for task in flatten_tasks(cls.tasks)
            if task.get("name")
            == "Run every external ACL probe on its delegated inventory host"
        )

    def test_dot_query_uses_the_shared_recursion_fixture(self):
        env = self.probe["environment"]
        self.assertEqual(
            env["DOT_QUERY_NAME"], "{{ micolab_verify_dns_fixture_name }}"
        )
        self.assertEqual(
            env["DOT_EXPECT_IP"], "{{ micolab_verify_dns_fixture_expected_ip }}"
        )
        # DoH keeps the infrastructure authoritative query.
        self.assertEqual(
            env["PROBE_NAME"], "{{ micolab_verify_dns_probe_name }}"
        )
        self.assertEqual(
            env["PROBE_IP"],
            "{{ micolab_verify_expected_a_records[micolab_verify_dns_probe_name]"
            " | default(micolab_verify_mgmt_ip) }}",
        )

        script = self.probe["ansible.builtin.shell"]
        self.assertIn('run_dot fixture "$DOT_QUERY_NAME" "$DOT_EXPECT_IP"', script)
        self.assertIn('run_dot global-recursion "$DOT_RECURSION_DENIED_NAME" ""', script)
        self.assertIn('--source-address "$SOURCE_ADDRESS"', script)
        self.assertEqual(
            env["DOT_RECURSION_DENIED_NAME"],
            "{{ micolab_verify_dns_recursion_denied_name }}",
        )
        # Certificate/SNI validation stays on the DNS hostname, independent of
        # the queried fixture name.
        self.assertIn('--server-name "$DOT_HOST"', script)
        dot_branch = script.split("dot)", 1)[1]
        self.assertNotIn("$PROBE_NAME", dot_branch)
        self.assertNotIn("$PROBE_IP", dot_branch)

        # The shared variables bridge into the verify defaults without being
        # redefined by this role.
        from jinja2 import Environment

        shared = {
            "micolab_dns_fixture_name": "fixture.microlab.test",
            "micolab_dns_fixture_expected_ip": "198.51.100.7",
        }
        environment = Environment()
        name = environment.from_string(
            self.defaults["micolab_verify_dns_fixture_name"]
        ).render(**shared)
        address = environment.from_string(
            self.defaults["micolab_verify_dns_fixture_expected_ip"]
        ).render(**shared)
        self.assertEqual(name, "fixture.microlab.test")
        self.assertEqual(address, "198.51.100.7")

    def test_source_cidr_defaults_resolve_from_the_dns_role_interface(self):
        from jinja2 import Environment

        environment = Environment()
        environment.filters["unique"] = lambda values: list(dict.fromkeys(values))
        shared = {
            "micolab_admin_cidrs": ["10.10.0.0/16"],
            "micolab_client_cidrs": ["10.20.0.0/16"],
            "micolab_dns_recursion_allow_cidrs": ["10.40.0.0/16"],
            "micolab_dns_authoritative_only_cidrs": ["10.30.0.0/16"],
        }
        resolved = {
            key: environment.from_string(self.defaults[key]).render(**shared)
            for key in (
                "micolab_verify_dns_recursion_allowed_cidrs",
                "micolab_verify_dns_firewall_admitted_cidrs",
                "micolab_verify_dns_authoritative_only_cidrs",
            )
        }
        for cidr in (
            "10.10.0.0/16",
            "10.20.0.0/16",
            "10.40.0.0/16",
        ):
            self.assertIn(cidr, resolved["micolab_verify_dns_recursion_allowed_cidrs"])
        for cidr in (
            "10.10.0.0/16",
            "10.20.0.0/16",
            "10.30.0.0/16",
        ):
            self.assertIn(cidr, resolved["micolab_verify_dns_firewall_admitted_cidrs"])
        self.assertIn(
            "10.30.0.0/16",
            resolved["micolab_verify_dns_authoritative_only_cidrs"],
        )

    def test_dot_probe_assertions_require_classified_firewall_admitted_sources(self):
        assert_task = next(
            task
            for task in flatten_tasks(self.tasks)
            if task.get("name")
            == "Require the recursion fixture and classified sources for DoT probes"
        )
        text = json.dumps(assert_task)
        self.assertIn("micolab_verify_probe_classification_errors", text)
        self.assertIn("micolab_verify_dns_authoritative_only_cidrs", text)
        self.assertIn("micolab_verify_dns_recursion_allowed_cidrs", text)
        self.assertIn("micolab_verify_dns_firewall_admitted_cidrs", text)
        self.assertIn("micolab_verify_dns_fixture_name", text)
        self.assertIn("micolab_verify_dns_fixture_expected_ip", text)


class ProbeClassificationTests(unittest.TestCase):
    """Unit tests for the verify role's source-class validation."""

    @classmethod
    def setUpClass(cls):
        path = ROOT / "roles/verify/filter_plugins/microlab_verify_net.py"
        spec = importlib.util.spec_from_file_location("micolab_verify_net", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        cls.module = module
        cls.firewall = ["10.10.0.0/16", "10.20.0.0/16", "10.30.0.0/16"]
        cls.recursion = ["10.10.0.0/16", "10.20.0.0/16"]
        cls.authoritative = ["10.30.0.0/16"]

    def errors(self, probes):
        return self.module.probe_classification_errors(
            probes, self.firewall, self.recursion, self.authoritative
        )

    def test_allowed_and_denied_sources_are_classified(self):
        probes = [
            {
                "name": "dot-allowed",
                "check": "dot",
                "expect": "allowed",
                "access": "recursion-allowed",
                "source_address": "10.20.0.5",
            },
            {
                "name": "dot-denied",
                "check": "dot",
                "expect": "denied",
                "access": "recursion-denied",
                "source_address": "10.30.0.5",
            },
        ]
        self.assertEqual(self.errors(probes), [])
        self.assertEqual(
            self.module.source_class(
                "10.30.0.5", self.firewall, self.recursion, self.authoritative
            ),
            "recursion-denied",
        )

    def test_denied_source_in_recursion_network_is_rejected(self):
        probes = [
            {
                "name": "dot-denied",
                "check": "dot",
                "expect": "denied",
                "access": "recursion-denied",
                "source_address": "10.20.0.5",
            }
        ]
        errors = self.errors(probes)
        self.assertTrue(any("authoritative_only" in error for error in errors), errors)
        self.assertTrue(any("recursion-allowed" in error for error in errors), errors)

    def test_allowed_source_in_authoritative_only_network_is_rejected(self):
        probes = [
            {
                "name": "dot-allowed",
                "check": "dot",
                "expect": "allowed",
                "access": "recursion-allowed",
                "source_address": "10.30.0.5",
            }
        ]
        errors = self.errors(probes)
        self.assertTrue(
            any("authoritative_only_cidrs" in error for error in errors), errors
        )

    def test_source_outside_firewall_dns_nets_is_rejected(self):
        probes = [
            {
                "name": "dot-denied",
                "check": "dot",
                "expect": "denied",
                "access": "recursion-denied",
                "source_address": "192.0.2.5",
            }
        ]
        errors = self.errors(probes)
        self.assertTrue(any("outside the firewall" in error for error in errors), errors)
        self.assertEqual(
            self.module.source_class(
                "192.0.2.5", self.firewall, self.recursion, self.authoritative
            ),
            "firewall-denied",
        )

    def test_missing_source_and_access_mismatch_are_rejected(self):
        probes = [
            {"name": "missing", "check": "dot", "expect": "denied"},
            {
                "name": "mismatch",
                "check": "dot",
                "expect": "allowed",
                "access": "recursion-denied",
                "source_address": "10.20.0.5",
            },
        ]
        errors = self.errors(probes)
        self.assertTrue(any("missing" in error for error in errors), errors)
        self.assertTrue(any("mismatch" in error for error in errors), errors)

    def test_non_dot_probes_are_not_classified_here(self):
        probes = [
            {"name": "doh-allowed", "check": "doh", "expect": "allowed"},
            {"name": "admin-denied", "check": "dns_admin", "expect": "denied"},
        ]
        self.assertEqual(self.errors(probes), [])


@unittest.skipUnless(yaml is not None, "PyYAML is required")
class DohClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="verify-doh-", dir=str(TMP_ROOT))
        cls.root = Path(cls.tmp.name)
        cls.ca, _crt, _key = make_ca_and_server_cert(cls.root)
        cls.script = external_acl_shell()
        cls.bin = cls.root / "bin"
        cls.bin.mkdir()
        curl = cls.bin / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            "out=''\n"
            "while [ $# -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    -o) out=\"$2\"; shift 2 ;;\n"
            "    *) shift ;;\n"
            "  esac\n"
            "done\n"
            "if [ -n \"$out\" ] && [ -n \"${FAKE_DOH_BODY:-}\" ]; then\n"
            "  printf '%s' \"$FAKE_DOH_BODY\" > \"$out\"\n"
            "fi\n"
            "printf '%s' \"${FAKE_DOH_CODE:-000}\"\n",
            encoding="utf-8",
        )
        curl.chmod(0o700)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def probe_env(self, expect, code, body=""):
        return {
            "CHECK": "doh",
            "EXPECT": expect,
            "CA_FILE": str(self.ca),
            "TIMEOUT": "2",
            "TARGET_HOST": "127.0.0.1",
            "MGMT_IP": "127.0.0.1",
            "HTTPS_PORT": "443",
            "DOH_HOST": "127.0.0.1",
            "DOH_PATH": "/dns-query",
            "PROBE_NAME": "ns.example",
            "PROBE_IP": "10.0.0.5",
            "DOT_PROBE": str(DOT_PROBE),
            "DOT_HOST": "127.0.0.1",
            "DOT_PORT": "853",
            "FAKE_DOH_CODE": code,
            "FAKE_DOH_BODY": body,
        }

    def test_allowed_doh_requires_expected_answer(self):
        body = json.dumps({"Status": 0, "Answer": [{"type": 1, "data": "10.0.0.5"}]})
        result = run_external_acl_script(
            self.script, self.probe_env("allowed", "200", body), fake_curl_dir=self.bin
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        wrong = json.dumps({"Status": 0, "Answer": [{"type": 1, "data": "10.0.0.9"}]})
        result = run_external_acl_script(
            self.script, self.probe_env("allowed", "200", wrong), fake_curl_dir=self.bin
        )
        self.assertNotEqual(result.returncode, 0)

    def test_only_explicit_403_counts_as_doh_denial(self):
        for code in ("403",):
            with self.subTest(code=code):
                result = run_external_acl_script(
                    self.script, self.probe_env("denied", code), fake_curl_dir=self.bin
                )
                self.assertEqual(result.returncode, 0, msg=result.stderr)
                self.assertIn("doh denied observed_http=403", result.stdout)

        for code in ("000", "401", "404", "500", "200"):
            with self.subTest(code=code):
                result = run_external_acl_script(
                    self.script, self.probe_env("denied", code), fake_curl_dir=self.bin
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("inconclusive", result.stderr)


class GitSmartHTTPSHandler(BaseHTTPRequestHandler):
    """Serve real git smart HTTP over TLS with optional basic auth."""

    protocol_version = "HTTP/1.0"
    project_root = None
    user = "verify-user"
    token = "s3cret-token"
    private = True
    request_log = None
    lock = threading.Lock()

    def log_message(self, _format, *_args):
        pass

    def _authorized(self):
        wanted = "Basic " + base64.b64encode(
            "{}:{}".format(self.user, self.token).encode()
        ).decode()
        return self.headers.get("Authorization") == wanted

    def _simple(self, code):
        self.send_response(code)
        if code == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="git"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        parsed = urllib.parse.urlsplit(self.path)
        authorized = self._authorized()
        with self.lock:
            with open(self.request_log, "a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "method": self.command,
                            "path": parsed.path,
                            "query": parsed.query,
                            "authorized": authorized,
                        }
                    )
                    + "\n"
                )
        if ".git" not in parsed.path:
            self._simple(200 if (authorized or not self.private) else 401)
            return
        if self.private and not authorized:
            self._simple(401)
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        env = os.environ.copy()
        env.update(
            {
                "GIT_PROJECT_ROOT": str(self.project_root),
                "GIT_HTTP_EXPORT_ALL": "1",
                "PATH_INFO": parsed.path,
                "QUERY_STRING": parsed.query,
                "REQUEST_METHOD": self.command,
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": str(len(body)),
                "REMOTE_ADDR": self.client_address[0],
                "REMOTE_USER": self.user if authorized else "",
                "SERVER_PROTOCOL": "HTTP/1.0",
                "SERVER_NAME": "127.0.0.1",
                "SERVER_PORT": str(self.server.server_port),
                "GATEWAY_INTERFACE": "CGI/1.1",
            }
        )
        process = subprocess.run(
            ["git", "http-backend"], input=body, env=env, capture_output=True
        )
        raw = process.stdout
        head, separator, payload = raw.partition(b"\r\n\r\n")
        status = 200
        headers = []
        if separator:
            for line in head.split(b"\r\n"):
                key, _, value = line.partition(b":")
                if key.lower() == b"status":
                    status = int(value.strip().split()[0])
                elif key:
                    headers.append((key, value.strip()))
        else:
            payload = raw
        self.send_response(status)
        for key, value in headers:
            self.send_header(key.decode(), value.decode())
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """Ignore client aborts used by the wrong-CA acceptance test."""

    def handle_error(self, request, client_address):
        error = sys.exc_info()[1]
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


@unittest.skipUnless(
    yaml is not None and find_ansible_playbook() is not None and shutil.which("unshare"),
    "PyYAML, ansible-playbook, and unshare are required for local acceptance",
)
class GitAcceptanceAnsibleIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ("git", "openssl"):
            if not shutil.which(tool):
                raise unittest.SkipTest("{} is required".format(tool))
        if subprocess.run(
            ["unshare", "-r", "true"], capture_output=True
        ).returncode != 0:
            raise unittest.SkipTest("unprivileged user namespaces are unavailable")
        cls.ansible = find_ansible_playbook()
        cls.tmp = tempfile.TemporaryDirectory(prefix="verify-git-", dir=str(TMP_ROOT))
        cls.root = Path(cls.tmp.name)
        cls.ca, cls.crt, cls.key = make_ca_and_server_cert(cls.root)
        cls.other_ca, _other_crt, _other_key = make_ca_and_server_cert(
            _mkdir(cls.root / "other")
        )
        cls.gitroot = cls.root / "gitroot"
        cls.gitroot.mkdir()
        cls.request_log = cls.root / "http.log"
        cls.request_log.write_text("", encoding="utf-8")

        handler = type(
            "ConfiguredGitHandler",
            (GitSmartHTTPSHandler,),
            {
                "project_root": cls.gitroot,
                "private": True,
                "request_log": cls.request_log,
            },
        )
        cls.server = QuietThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.crt, cls.key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        cls.bin = cls.root / "bin"
        cls.bin.mkdir()
        fake_ssh = cls.bin / "ssh"
        fake_ssh.write_text(
            "#!/bin/sh\n"
            "for last do :; done\n"
            "case \"$last\" in\n"
            "  git-upload-pack\\ *|git-receive-pack\\ *)\n"
            "    op=${last%% *}\n"
            "    path=${last#* }\n"
            "    path=$(printf '%s' \"$path\" | tr -d \"'\")\n"
            "    if [ \"$op\" = \"git-receive-pack\" ] && [ \"${MOCK_FAIL_RECEIVE:-0}\" = \"1\" ]; then\n"
            "      echo \"mock ssh: receive-pack refused\" >&2\n"
            "      exit 255\n"
            "    fi\n"
            "    if [ \"$op\" = \"git-upload-pack\" ] && [ \"${MOCK_FAIL_UPLOAD:-0}\" = \"1\" ]; then\n"
            "      echo \"mock ssh: upload-pack refused\" >&2\n"
            "      exit 255\n"
            "    fi\n"
            "    if [ -n \"${MOCK_CLEANUP_BLOCKER:-}\" ]; then\n"
            "      if [ ! -e \"$MOCK_CLEANUP_BLOCKER\" ]; then\n"
            "        : > \"$MOCK_CLEANUP_BLOCKER\" 2>/dev/null || true\n"
            "      fi\n"
            "      if mount --bind \"$MOCK_CLEANUP_BLOCKER\" \"$MOCK_CLEANUP_BLOCKER\" 2>/dev/null; then\n"
            "        mount -o remount,ro,bind \"$MOCK_CLEANUP_BLOCKER\" 2>/dev/null || true\n"
            "      fi\n"
            "    fi\n"
            "    exec \"$op\" \"$MOCK_SSH_PROJECT_ROOT/$path\"\n"
            "    ;;\n"
            "  *) echo \"mock ssh: unexpected command $last\" >&2; exit 255 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        fake_ssh.chmod(0o700)
        cls.fake_key = cls.root / "fake_key"
        cls.fake_key.write_text("disposable test marker\n", encoding="utf-8")
        cls.known_hosts = cls.root / "known_hosts"
        cls.known_hosts.write_text(
            "[127.0.0.1]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly\n",
            encoding="utf-8",
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setup_repo(self, suffix, *, reject_delete=False):
        name = "owner/{}.git".format(suffix)
        bare = self.gitroot / name
        bare.parent.mkdir(parents=True, exist_ok=True)
        run_checked("git", "init", "--bare", str(bare))
        run_checked("git", "-C", str(bare), "config", "http.receivepack", "true")
        seed = self.root / "{}-seed".format(suffix)
        run_checked("git", "init", str(seed))
        (seed / "README.md").write_text("seed\n", encoding="utf-8")
        run_checked("git", "-C", str(seed), "add", "README.md")
        run_checked(
            "git", "-C", str(seed), "-c", "user.name=seed", "-c",
            "user.email=seed@example.invalid", "commit", "-m", "seed",
        )
        run_checked("git", "-C", str(seed), "push", str(bare), "HEAD:refs/heads/main")

        hook_log = self.root / "{}-hook.log".format(suffix)
        hook = bare / "hooks" / "pre-receive"
        lines = [
            "#!/bin/sh",
            'exec >>"{}" 2>&1'.format(hook_log),
            "while read old new ref; do",
            '  echo "$old $new $ref"',
        ]
        if reject_delete:
            lines.extend(
                [
                    '  if [ "$new" = "0000000000000000000000000000000000000000" ]; then',
                    '    echo "deletion denied by test hook" >&2',
                    "    exit 1",
                    "  fi",
                ]
            )
        lines.extend(["done", "exit 0"])
        hook.write_text("\n".join(lines) + "\n", encoding="utf-8")
        hook.chmod(0o755)
        return name, bare, hook_log

    def run_acceptance(
        self, https_repo, ssh_repo, *, tls_root=None, env_extra=None, workspace=None
    ):
        self.request_log.write_text("", encoding="utf-8")
        workspace = workspace or self.root / "workspace-{}".format(uuid.uuid4().hex)
        play = self.root / "play-{}.yml".format(uuid.uuid4().hex)
        play.write_text(
            "---\n"
            "- name: disposable Git acceptance\n"
            "  hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: true\n"
            "  become: false\n"
            "  vars:\n"
            "    micolab_verify_git_repo: {https_repo}\n"
            "    micolab_verify_git_ssh_repo: {ssh_repo}\n"
            "    micolab_verify_git_host: 127.0.0.1\n"
            '    micolab_verify_https_suffix: ":{port}"\n'
            "    micolab_verify_https_port: {port}\n"
            "    micolab_verify_git_https_username: verify-user\n"
            "    micolab_verify_git_https_token: s3cret-token\n"
            "    micolab_verify_git_visibility: private\n"
            "    micolab_verify_enable_ssh: true\n"
            "    micolab_verify_ssh_private_key: {key}\n"
            "    micolab_verify_known_hosts: {known}\n"
            "    micolab_verify_ssh_port: 22\n"
            "    micolab_verify_git_test_root: {workspace}\n"
            "    micolab_verify_git_test_author_name: MicroLab Verify\n"
            "    micolab_verify_git_test_author_email: verify@micolab.invalid\n"
            "    micolab_verify_git_test_commit_message: microlab verification commit\n"
            "    micolab_verify_tls_root: {ca}\n"
            "    micolab_verify_accept_unexecuted_git_acceptance: false\n"
            "  tasks:\n"
            "    - name: run the real acceptance tasks\n"
            "      ansible.builtin.import_tasks: {tasks}\n".format(
                https_repo=https_repo,
                ssh_repo=ssh_repo,
                port=self.port,
                key=self.fake_key,
                known=self.known_hosts,
                workspace=workspace,
                ca=tls_root or self.ca,
                tasks=GIT_ACCEPTANCE,
            ),
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["PATH"] = "{}:{}".format(self.bin, env.get("PATH", ""))
        env["MOCK_SSH_PROJECT_ROOT"] = str(self.gitroot)
        if env_extra:
            env.update(env_extra)
        unshare_args = ["unshare", "-r"]
        if env_extra and env_extra.get("MOCK_CLEANUP_BLOCKER"):
            unshare_args.append("-m")
        return subprocess.run(
            unshare_args
            + [self.ansible, "-i", "localhost,", "-c", "local", str(play)],
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )

    def hook_lines(self, log):
        if not log.exists():
            return []
        return [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def assert_workspace_clean(self, _result):
        # Every run uses a unique workspace below this test root. Assert none
        # survived, including the credential helper inside it.
        leftovers = list(self.root.glob("workspace-*"))
        self.assertEqual(leftovers, [], msg="Git acceptance workspace was not removed")
        self.assertEqual(list(self.root.glob("workspace-*/askpass.sh")), [])

    def test_success_runs_real_git_and_proves_cleanup(self):
        https_name, https_bare, https_log = self.setup_repo("https-" + uuid.uuid4().hex[:8])
        ssh_name, ssh_bare, ssh_log = self.setup_repo("ssh-" + uuid.uuid4().hex[:8])
        result = self.run_acceptance(https_name, ssh_name)
        self.assertEqual(result.returncode, 0, msg=result.stdout[-4000:] + result.stderr[-2000:])

        # Both workflows pushed a commit whose tree contains the explicitly
        # staged file. This fails if the role writes and commits without add.
        for log, bare, marker in (
            (https_log, https_bare, "MicroLab HTTPS acceptance"),
            (ssh_log, ssh_bare, "MicroLab SSH acceptance"),
        ):
            lines = self.hook_lines(log)
            created = [
                line.split()[1]
                for line in lines
                if not line.split()[1].startswith("0000")
            ]
            self.assertEqual(len(created), 1, msg=lines)
            tree = subprocess.run(
                ["git", "-C", str(bare), "rev-parse", f"{created[0]}^{{tree}}"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            listing = subprocess.run(
                ["git", "-C", str(bare), "ls-tree", "-r", "-z", tree],
                check=True, capture_output=True,
            ).stdout
            entries = [entry for entry in listing.split(b"\0") if entry]
            self.assertEqual(len(entries), 1, msg=entries)
            _mode, _type, sha_and_path = entries[0].split(b" ", 2)
            path = sha_and_path.split(b"\t", 1)[1]
            self.assertEqual(path, b"microlab" + b"-" + b"verify.txt")
            content = subprocess.run(
                ["git", "-C", str(bare), "cat-file", "-p",
                 "{}:{}".format(tree, path.decode())],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertIn(marker, content)
            self.assertIn("microlab-verify-", content)
            self.assertTrue(
                any(
                    line.split()[1].startswith("0000")
                    for line in lines
                ),
                msg="remote branch was not deleted: {}".format(lines),
            )
            refs = subprocess.run(
                ["git", "-C", str(bare), "for-each-ref", "refs/heads"],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertNotIn("microlab-verify-", refs)

        self.assert_workspace_clean(result)
        requests = [
            json.loads(line)
            for line in self.request_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        repo_requests = [r for r in requests if ".git" in r["path"]]
        self.assertTrue(any(r["authorized"] for r in repo_requests), msg=requests)
        self.assertTrue(any(not r["authorized"] for r in requests), msg=requests)

        # The private CA is not in the system trust store. Every HTTPS Git
        # operation (clone, push, remote check, anonymous check, delete) had to
        # use the pinned root for this whole run to succeed.
        askpass = self.root / "direct-askpass.sh"
        askpass.write_text(
            "#!/bin/sh\ncase \"$1\" in *sername*) echo verify-user;; *) echo s3cret-token;; esac\n",
            encoding="utf-8",
        )
        askpass.chmod(0o700)
        direct = subprocess.run(
            ["git", "-c", "http.sslVerify=true", "ls-remote",
             "https://127.0.0.1:{}/{}/".format(self.port, https_name)],
            env={
                **os.environ,
                "GIT_ASKPASS": str(askpass),
                "GIT_ASKPASS_REQUIRE": "force",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(direct.returncode, 0, msg="test CA unexpectedly system-trusted")
        self.assertRegex(
            direct.stderr.lower(),
            r"certificate|ssl|cert",
            msg="expected a certificate failure without the pinned root",
        )

    def test_deletion_denied_fails_with_actionable_refs_and_cleans_local_state(self):
        https_name, https_bare, https_log = self.setup_repo(
            "https-deny-" + uuid.uuid4().hex[:8], reject_delete=True
        )
        ssh_name, ssh_bare, ssh_log = self.setup_repo("ssh-ok-" + uuid.uuid4().hex[:8])
        result = self.run_acceptance(https_name, ssh_name)
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr
        self.assertIn("HTTPS cleanup: failed", combined)
        self.assertIn("git push origin --delete", combined)
        self.assertNotIn("s3cret-token", combined)
        self.assert_workspace_clean(result)

        lines = self.hook_lines(https_log)
        branches = [line.split()[2] for line in lines if "microlab-verify-" in line]
        self.assertTrue(branches)
        branch = sorted(set(branches))[0].split("/")[-1]
        self.assertIn(branch, combined)
        self.assertIn("deletion denied by test hook", https_log.read_text(encoding="utf-8"))
        refs = subprocess.run(
            ["git", "-C", str(https_bare), "for-each-ref", "refs/heads"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.assertIn(branch, refs, msg="deletion-denied branch must remain for manual cleanup")

        ssh_refs = subprocess.run(
            ["git", "-C", str(ssh_bare), "for-each-ref", "refs/heads"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.assertNotIn("microlab-verify-", ssh_refs)

    def test_ssh_push_failure_cleans_https_and_handles_absent_ssh_ref(self):
        https_name, https_bare, https_log = self.setup_repo("https-ok-" + uuid.uuid4().hex[:8])
        ssh_name, ssh_bare, ssh_log = self.setup_repo("ssh-reject-" + uuid.uuid4().hex[:8])
        result = self.run_acceptance(
            https_name, ssh_name, env_extra={"MOCK_FAIL_RECEIVE": "1"}
        )
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr
        self.assertIn("SSH cleanup: deleted", combined)
        self.assertIn("HTTPS cleanup: deleted", combined)
        self.assertNotIn("s3cret-token", combined)
        self.assert_workspace_clean(result)

        https_refs = subprocess.run(
            ["git", "-C", str(https_bare), "for-each-ref", "refs/heads"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.assertNotIn("microlab-verify-", https_refs)
        ssh_refs = subprocess.run(
            ["git", "-C", str(ssh_bare), "for-each-ref", "refs/heads"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.assertNotIn("micolab-verify-", ssh_refs)
        self.assertEqual(self.hook_lines(ssh_log), [])

    def test_wrong_custom_ca_fails_and_cleans_workspace(self):
        https_name, https_bare, https_log = self.setup_repo("https-ca-" + uuid.uuid4().hex[:8])
        ssh_name, ssh_bare, ssh_log = self.setup_repo("ssh-ca-" + uuid.uuid4().hex[:8])
        result = self.run_acceptance(https_name, ssh_name, tls_root=self.other_ca)
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr
        self.assertIn("Git acceptance did not finish cleanly", combined)
        self.assertIn("Clone the disposable repository over HTTPS", combined)
        self.assertNotIn("s3cret-token", combined)
        self.assert_workspace_clean(result)
        self.assertEqual(self.hook_lines(https_log), [])
        self.assertEqual(self.hook_lines(ssh_log), [])

    def require_mount_namespace(self):
        if not shutil.which("mount"):
            self.skipTest("mount is required for local removal fault injection")
        probe = subprocess.run(
            ["unshare", "-r", "-m", "true"], capture_output=True
        )
        if probe.returncode != 0:
            self.skipTest("an unprivileged mount namespace is unavailable")

    def test_removal_denial_is_reported_and_never_marked_removed(self):
        """A real removal failure must not become credentials_removed=True.

        The fake SSH receive-pack hook bind-mounts the generated askpass helper
        (read-only) inside the play's mount namespace. Both cleanup removals
        then fail for real; the role must preserve the failures, run both
        tasks, and prove absence with stat instead of trusting a suppressed
        failure.
        """
        self.require_mount_namespace()
        https_name, _https_bare, _https_log = self.setup_repo(
            "https-fault-" + uuid.uuid4().hex[:8]
        )
        ssh_name, _ssh_bare, _ssh_log = self.setup_repo(
            "ssh-fault-" + uuid.uuid4().hex[:8]
        )
        workspace = self.root / "workspace-fault-{}".format(uuid.uuid4().hex)
        self.addCleanup(shutil.rmtree, workspace, True)
        result = self.run_acceptance(
            https_name,
            ssh_name,
            workspace=workspace,
            env_extra={"MOCK_CLEANUP_BLOCKER": str(workspace / "askpass.sh")},
        )
        combined = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Git acceptance did not finish cleanly", combined)
        self.assertIn("credentials removed: False", combined)
        self.assertIn("workspace removed: False", combined)
        self.assertIn("Inspect those exact paths", combined)
        self.assertIn("Unlinking failed", combined)
        self.assertIn("rmtree failed", combined)
        self.assertIn("Device or resource busy", combined)
        # Both ignored removal tasks must still have been attempted.
        self.assertIn("Remove the HTTPS askpass helper", result.stdout)
        self.assertIn("Remove the private Git acceptance workspace", result.stdout)
        self.assertNotIn("s3cret-token", combined)
        self.assertTrue((workspace / "askpass.sh").exists())
        self.assertTrue(workspace.is_dir())

    def test_workspace_removal_denial_does_not_clear_credential_removal(self):
        """A workspace-only removal failure keeps credentials=True but fails.

        The blocker is created by the SSH receive-pack hook after the askpass
        removal succeeds. The credential helper is therefore proven absent,
        while the workspace stat still exists; acceptance must remain failed.
        """
        self.require_mount_namespace()
        https_name, _https_bare, _https_log = self.setup_repo(
            "https-block-" + uuid.uuid4().hex[:8]
        )
        ssh_name, _ssh_bare, _ssh_log = self.setup_repo(
            "ssh-block-" + uuid.uuid4().hex[:8]
        )
        workspace = self.root / "workspace-block-{}".format(uuid.uuid4().hex)
        self.addCleanup(shutil.rmtree, workspace, True)
        result = self.run_acceptance(
            https_name,
            ssh_name,
            workspace=workspace,
            env_extra={
                "MOCK_CLEANUP_BLOCKER": str(workspace / "cleanup-blocker")
            },
        )
        combined = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Git acceptance did not finish cleanly", combined)
        self.assertIn("credentials removed: True", combined)
        self.assertIn("workspace removed: False", combined)
        self.assertIn("Inspect those exact paths", combined)
        self.assertNotIn("s3cret-token", combined)
        self.assertFalse((workspace / "askpass.sh").exists())
        self.assertTrue(workspace.is_dir())


if __name__ == "__main__":
    unittest.main()
