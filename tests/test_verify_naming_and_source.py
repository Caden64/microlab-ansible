"""Rendered-command and real-socket tests for the verify role naming and DoT
source-binding repairs.

Nothing here contacts a real host or a public DNS service:

* ``ansible-playbook`` runs the real role task files (``targets.yml``,
  ``dns_records.yml``, ``encrypted_dns.yml``, ``external_acl.yml``) with the
  repository's real ``group_vars/all.yml`` and the example inventory's
  management group vars. ``dig`` and ``curl`` are replaced by argv loggers on
  ``PATH`` so the *rendered* argv is asserted exactly, not by substring.
* DoT is a real TLS listener on loopback whose response depends on the real
  peer address of the accepted socket, so source binding is proven by what the
  server saw (127.0.0.2 vs 127.0.0.3), not by what the client claims.
"""

from __future__ import annotations

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
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = Path("/tmp/opencode")
if not TMP_ROOT.is_dir() or not os.access(TMP_ROOT, os.W_OK):
    TMP_ROOT = Path(tempfile.gettempdir())

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

DOT_PROBE = ROOT / "roles/verify/files/dot_probe.py"
EXTERNAL_ACL = ROOT / "roles/verify/tasks/external_acl.yml"

MGMT_IP = "10.0.0.5"
FIXTURE_NAME = "probe.fixture.test"
FIXTURE_ZONE = "fixture.test"
FIXTURE_IP = "198.51.100.7"
DENIED_NAME = "microlab-recursion-acl-probe.invalid"
ALLOWED_SRC = "127.0.0.2"
DENIED_SRC = "127.0.0.3"
SPLIT_SRC = "127.0.0.4"  # fixture zone ACL denies, global recursion allows


def find_ansible_playbook():
    for candidate in (
        os.environ.get("ANSIBLE_PLAYBOOK"),
        shutil.which("ansible-playbook"),
        "/tmp/opencode/ansvenv/bin/ansible-playbook",
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def _run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_ca_and_cert(root: Path, san: str):
    ca_key, ca_crt = root / "ca.key", root / "ca.crt"
    _run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "1",
        "-subj", "/CN=MicroLab Naming Test Root",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
        "-addext", "authorityKeyIdentifier=keyid:always",
    )
    key, csr, crt, ext = (root / n for n in ("srv.key", "srv.csr", "srv.crt", "srv.ext"))
    ext.write_text(
        "subjectAltName={}\nbasicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n".format(san),
        encoding="utf-8",
    )
    _run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(csr), "-subj", "/CN=dns.microlab.hnh")
    _run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt),
         "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(crt), "-days", "1",
         "-extfile", str(ext))
    return ca_crt, crt, key


def qname(query):
    offset, labels = 12, []
    while offset < len(query) and query[offset]:
        length = query[offset]
        labels.append(query[offset + 1:offset + 1 + length].decode("ascii"))
        offset += 1 + length
    return ".".join(labels)


class PolicyDotServer:
    """Multi-connection DoT server; the answer depends on the real peer IP.

    policy(peer_ip, qname, rd) -> (rcode, answer_ip_or_None)
    Every accepted connection is logged with peer, SNI, qname, and RD.
    """

    def __init__(self, crt, key, policy, *, host="127.0.0.1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.policy = policy
        self.log = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(crt, key)
        self._sni = threading.local()

        def sni(_sock, name, _ctx):
            self._sni.name = name

        self.context.sni_callback = sni
        self.stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop:
            try:
                conn, peer = self.listener.accept()
            except OSError:
                return
            try:
                self._sni.name = None
                with self.context.wrap_socket(conn, server_side=True) as tls:
                    length = struct.unpack("!H", tls.recv(2))[0]
                    query = b""
                    while len(query) < length:
                        query += tls.recv(length - len(query))
                    name = qname(query)
                    rd = bool(struct.unpack("!H", query[2:4])[0] & 0x0100)
                    self.log.append({"peer": peer[0], "sni": self._sni.name,
                                     "qname": name, "rd": rd})
                    rcode, answer = self.policy(peer[0], name, rd)
                    qid = struct.unpack("!H", query[:2])[0]
                    resp = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1,
                                       1 if answer else 0, 0, 0) + query[12:]
                    if answer:
                        resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answer)
                    tls.sendall(struct.pack("!H", len(resp)) + resp)
            except Exception:  # pragma: no cover - diagnostic only
                continue

    def close(self):
        self.stop = True
        try:
            self.listener.close()
        except OSError:
            pass
        self.thread.join(timeout=5)


def lab_policy(peer, name, rd):
    """Technitium-like policy for the three source classes.

    ALLOWED_SRC: recursion-allowed; fixture answers; out-of-zone recursion has
    no upstream (offline) -> SERVFAIL.
    DENIED_SRC: authoritative-only; fixture zone ACL and global recursion ACL
    both REFUSED.
    SPLIT_SRC: fixture zone query ACL REFUSED but global recursion allowed
    (the case a fixture-only test would misreport) -> out-of-zone SERVFAIL.
    """
    if name == FIXTURE_NAME:
        return (0, FIXTURE_IP) if peer == ALLOWED_SRC else (5, None)
    if peer in (ALLOWED_SRC, SPLIT_SRC):
        return (2, None)
    return (5, None)


def external_acl_shell():
    tasks = yaml.safe_load(EXTERNAL_ACL.read_text(encoding="utf-8"))

    def flat(items):
        for task in items:
            yield task
            for key in ("block", "always", "rescue"):
                yield from flat(task.get(key, []))

    return next(t for t in flat(tasks)
                if t.get("name") == "Run every external ACL probe on its delegated inventory host"
                )["ansible.builtin.shell"]


def loopback_alias_usable(address):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((address, 0))
        return True
    except OSError:
        return False


def ipv6_loopback_usable():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.bind(("::1", 0))
        return True
    except OSError:
        return False


@unittest.skipUnless(yaml is not None and shutil.which("openssl"), "PyYAML and openssl required")
@unittest.skipUnless(
    all(loopback_alias_usable(a) for a in (ALLOWED_SRC, DENIED_SRC, SPLIT_SRC)),
    "127.0.0.2-4 must be bindable loopback addresses",
)
class DotSourceBindingShellTests(unittest.TestCase):
    """The real external_acl shell + real dot_probe + real loopback sockets."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="verify-src-", dir=str(TMP_ROOT))
        cls.root = Path(cls.tmp.name)
        cls.ca, cls.crt, cls.key = make_ca_and_cert(
            cls.root, "DNS:dns.microlab.hnh,IP:127.0.0.1,IP:::1"
        )
        cls.script = external_acl_shell()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def server(self, host="127.0.0.1"):
        server = PolicyDotServer(self.crt, self.key, lab_policy, host=host)
        self.addCleanup(server.close)
        return server

    def run_shell(self, port, expect, source):
        env = dict(os.environ)
        env.update({
            "CHECK": "dot", "EXPECT": expect, "CA_FILE": str(self.ca),
            "TIMEOUT": "3", "TARGET_HOST": "unused", "MGMT_IP": "127.0.0.1",
            "HTTPS_PORT": "443", "DOH_HOST": "unused", "DOH_PATH": "/dns-query",
            "PROBE_NAME": "ns1.microlab.hnh", "PROBE_IP": MGMT_IP,
            "DOT_PROBE": str(DOT_PROBE), "DOT_HOST": "dns.microlab.hnh",
            "DOT_PORT": str(port), "DOT_QUERY_NAME": FIXTURE_NAME,
            "DOT_EXPECT_IP": FIXTURE_IP, "DOT_RECURSION_DENIED_NAME": DENIED_NAME,
            "SOURCE_ADDRESS": source,
        })
        return subprocess.run(["bash"], input=self.script, env=env, text=True,
                              capture_output=True, timeout=60)

    def test_allowed_source_is_bound_and_seen_by_server(self):
        server = self.server()
        result = self.run_shell(server.port, "allowed", ALLOWED_SRC)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("dot allowed validated source=127.0.0.2", result.stdout)
        self.assertEqual(server.log, [{"peer": ALLOWED_SRC, "sni": "dns.microlab.hnh",
                                       "qname": FIXTURE_NAME, "rd": True}])

    def test_denied_source_needs_fixture_and_global_recursion_refused(self):
        server = self.server()
        result = self.run_shell(server.port, "denied", DENIED_SRC)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn(
            "dot denied source=127.0.0.3 fixture_zone_query_acl=dns_refused "
            "global_recursion_acl=dns_refused", result.stdout)
        self.assertEqual(
            [(e["peer"], e["qname"], e["rd"]) for e in server.log],
            [(DENIED_SRC, FIXTURE_NAME, True), (DENIED_SRC, DENIED_NAME, True)],
        )

    def test_fixture_refused_alone_is_not_global_recursion_proof(self):
        # The fixture zone ACL refuses SPLIT_SRC but the global recursion
        # policy lets it recurse (offline -> SERVFAIL). That must fail.
        server = self.server()
        result = self.run_shell(server.port, "denied", SPLIT_SRC)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("[global-recursion-acl]", result.stderr)
        self.assertIn("dns_rcode", result.stderr)
        self.assertNotIn("dot denied source=", result.stdout)

    def test_actual_source_decides_the_class_not_the_declaration(self):
        server = self.server()
        # Declared allowed but bound to the authoritative-only source.
        result = self.run_shell(server.port, "allowed", DENIED_SRC)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dns_refused", result.stderr)
        # Declared denied but bound to the recursion-allowed source.
        result = self.run_shell(server.port, "denied", ALLOWED_SRC)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("[fixture-zone-query-acl]", result.stderr)
        self.assertEqual({e["peer"] for e in server.log}, {DENIED_SRC, ALLOWED_SRC})

    def test_unavailable_source_fails_without_connecting(self):
        server = self.server()
        for expect in ("allowed", "denied"):
            with self.subTest(expect=expect):
                result = self.run_shell(server.port, expect, "192.0.2.77")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("category=source_unavailable", result.stderr)
                self.assertNotIn("dns_refused", result.stdout)
        self.assertEqual(server.log, [])

    def test_invalid_missing_and_wrong_family_sources_fail(self):
        server = self.server()
        cases = [("not-an-ip", "category=source_invalid"),
                 ("", "no source_address"),
                 ("::1", "category=source_family")]
        for source, marker in cases:
            for expect in ("allowed", "denied"):
                with self.subTest(source=source, expect=expect):
                    result = self.run_shell(server.port, expect, source)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(marker, result.stderr)
                    self.assertNotIn("dot denied source=", result.stdout)
        self.assertEqual(server.log, [])

    def test_probe_status_records_requested_and_observed_source(self):
        server = self.server()
        status = self.root / "status-{}.json".format(uuid.uuid4().hex)
        rc = subprocess.run(
            [sys.executable, str(DOT_PROBE), "--connect-host", "127.0.0.1",
             "--port", str(server.port), "--server-name", "dns.microlab.hnh",
             "--ca-file", str(self.ca), "--source-address", DENIED_SRC,
             "--name", FIXTURE_NAME, "--timeout", "3", "--status-file", str(status)],
            capture_output=True, text=True, timeout=30).returncode
        data = json.loads(status.read_text())
        self.assertEqual(rc, 16)
        self.assertEqual(data["category"], "dns_refused")
        self.assertEqual(data["requested_source"], DENIED_SRC)
        self.assertEqual(data["observed_source"], DENIED_SRC)
        self.assertEqual(data["observed_peer"], "127.0.0.1")

    @unittest.skipUnless(ipv6_loopback_usable(), "IPv6 loopback unavailable")
    def test_ipv6_source_binds_an_ipv6_socket(self):
        server = self.server(host="::1")
        status = self.root / "status6-{}.json".format(uuid.uuid4().hex)
        result = subprocess.run(
            [sys.executable, str(DOT_PROBE), "--connect-host", "::1",
             "--port", str(server.port), "--server-name", "dns.microlab.hnh",
             "--ca-file", str(self.ca), "--source-address", "::1",
             "--name", FIXTURE_NAME, "--timeout", "3", "--status-file", str(status)],
            capture_output=True, text=True, timeout=30)
        data = json.loads(status.read_text())
        # ::1 is not ALLOWED_SRC in the policy, so the fixture is REFUSED; the
        # point is that the IPv6 socket was bound and seen by the server.
        self.assertEqual(data["category"], "dns_refused", msg=result.stderr)
        self.assertEqual(data["observed_source"], "::1")
        self.assertEqual(server.log[0]["peer"], "::1")
        # An IPv4 source against an IPv6-only target is a family error.
        status.unlink()
        subprocess.run(
            [sys.executable, str(DOT_PROBE), "--connect-host", "::1",
             "--port", str(server.port), "--server-name", "dns.microlab.hnh",
             "--ca-file", str(self.ca), "--source-address", ALLOWED_SRC,
             "--name", FIXTURE_NAME, "--timeout", "3", "--status-file", str(status)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(json.loads(status.read_text())["category"], "source_family")
        self.assertEqual(len(server.log), 1)


FAKE_DIG = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["ARGV_LOG"], "a", encoding="utf-8") as h:
    h.write(json.dumps(["dig"] + sys.argv[1:]) + "\n")
args = sys.argv[1:]
rtype, name = args[3], args[4]
if rtype == "A" and name.endswith("." + os.environ["FAKE_DOMAIN"]):
    print(os.environ["FAKE_A"])
elif rtype == "NS" and name == os.environ["FAKE_NS_ZONE"]:
    print(os.environ["FAKE_NS"])
"""

FAKE_CURL = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ.get("ARGV_LOG", "/dev/null"), "a", encoding="utf-8") as h:
    h.write(json.dumps(["curl"] + sys.argv[1:]) + "\n")
args = sys.argv[1:]
out = args[args.index("-o") + 1] if "-o" in args else None
check, expect = os.environ.get("CHECK", "local-doh"), os.environ.get("EXPECT", "allowed")
body = json.dumps({"Status": 0, "Answer": [{"type": 1, "data": os.environ.get("FAKE_DOH_A", os.environ.get("PROBE_IP", ""))}]})
if check == "local-doh":
    sys.stdout.write(body)
    sys.exit(0)
code = "403" if expect == "denied" else "200"
if out:
    open(out, "w", encoding="utf-8").write(body)
sys.stdout.write(code)
"""


class RolePlaybookMixin:
    """Run real role task files through ansible-playbook with argv logging."""

    @classmethod
    def setUpClass(cls):
        cls.ansible = find_ansible_playbook()
        cls.tmp = tempfile.TemporaryDirectory(prefix="verify-render-", dir=str(TMP_ROOT))
        cls.root = Path(cls.tmp.name)
        cls.ca, cls.crt, cls.key = make_ca_and_cert(
            cls.root, "DNS:dns.microlab.hnh,IP:127.0.0.1"
        )
        cls.bin = cls.root / "bin"
        cls.bin.mkdir()
        for name, text in (("dig", FAKE_DIG), ("curl", FAKE_CURL)):
            path = cls.bin / name
            path.write_text(text.replace("/usr/bin/env python3", sys.executable, 1), encoding="utf-8")
            path.chmod(0o755)
        # Playbook dir with the repository's real shared group vars and the
        # example inventory's management group vars.
        (cls.root / "group_vars" / "microlab_management").mkdir(parents=True)
        (cls.root / "group_vars" / "all.yml").symlink_to(ROOT / "group_vars/all.yml")
        (cls.root / "group_vars" / "microlab_management" / "main.yml").symlink_to(
            ROOT / "inventories/example/group_vars/microlab_management/main.yml")
        (cls.root / "ansible.cfg").write_text(
            "[defaults]\nroles_path = {}\nhost_key_checking = False\n"
            "retry_files_enabled = False\n[privilege_escalation]\nbecome = False\n".format(ROOT / "roles"),
            encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def inventory(self, extra_hosts=""):
        path = self.root / "inv-{}.ini".format(uuid.uuid4().hex)
        path.write_text(
            "[microlab_management]\n"
            "mgmt ansible_host={ip} ansible_connection=local ansible_python_interpreter={py}\n"
            "[probes]\n{extra}\n".format(ip=self.mgmt_ip, py=sys.executable, extra=extra_hosts),
            encoding="utf-8")
        return path

    mgmt_ip = MGMT_IP

    def play(self, tasks_from, extra_vars=None, env_extra=None, inventory=None):
        argv_log = self.root / "argv-{}.log".format(uuid.uuid4().hex)
        argv_log.write_text("", encoding="utf-8")
        play = self.root / "play-{}.yml".format(uuid.uuid4().hex)
        includes = "".join(
            "    - ansible.builtin.include_role:\n"
            "        name: verify\n"
            "        tasks_from: {}\n".format(t) for t in tasks_from)
        play.write_text(
            "---\n- hosts: microlab_management\n  gather_facts: false\n  tasks:\n" + includes,
            encoding="utf-8")
        env = dict(os.environ)
        env.update({
            "PATH": "{}:{}".format(self.bin, env.get("PATH", "")),
            "ARGV_LOG": str(argv_log),
            "ANSIBLE_CONFIG": str(self.root / "ansible.cfg"),
            "FAKE_DOMAIN": "microlab.hnh", "FAKE_A": self.mgmt_ip,
            "FAKE_NS_ZONE": "hnh", "FAKE_NS": "ns1.microlab.hnh.",
            "FAKE_DOH_A": self.mgmt_ip,
        })
        env.update(env_extra or {})
        cmd = [self.ansible, "-i", str(inventory or self.inventory()), str(play)]
        # The real group_vars derive micolab_verify_expected_a_records from
        # micolab_dns_addresses (an inventory value; the example has REPLACE
        # placeholders), keyed by <service>.microlab.hnh.
        variables = {"micolab_dns_addresses": {k: self.mgmt_ip for k in ("ns1", "ca", "dns", "git")}}
        variables.update(extra_vars or {})
        for key, value in variables.items():
            cmd += ["-e", json.dumps({key: value})]
        result = subprocess.run(cmd, cwd=self.root, env=env, capture_output=True,
                                text=True, timeout=240)
        argv = [json.loads(l) for l in argv_log.read_text().splitlines() if l.strip()]
        return result, argv



@unittest.skipUnless(
    yaml is not None and find_ansible_playbook() and shutil.which("openssl"),
    "PyYAML, ansible-playbook and openssl are required",
)
class RenderedRoleCommandTests(RolePlaybookMixin, unittest.TestCase):
    """Assert the exact argv the real role tasks rendered."""

    @staticmethod
    def dig(rtype, name):
        return ["dig", "+short", "+time=2", "+tries=1", rtype, name, "@127.0.0.1", "-p", "53"]

    def test_records_render_service_domain_names_and_zone_apex_ns(self):
        result, argv = self.play(["targets.yml", "dns_records.yml"])
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        services = ["ns1", "ca", "dns", "git"]
        expected = (
            [self.dig("A", s + ".microlab.hnh") for s in services]
            + [self.dig("AAAA", s + ".microlab.hnh") for s in services]
            + [self.dig("NS", "hnh")]
        )
        self.assertEqual(argv, expected)

    def test_conflicting_legacy_zone_fqdn_fails_before_any_query(self):
        result, argv = self.play(
            ["targets.yml", "dns_records.yml"],
            extra_vars={"micolab_dns_zone_fqdn": "micolab.hnh"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refuse a conflicting legacy micolab_dns_zone_fqdn", result.stdout)
        self.assertEqual(argv, [])

    def test_missing_or_mismatched_domain_and_zone_fail_closed(self):
        for extra in ({"micolab_domain": ""},
                      {"micolab_dns_zone": "example"},
                      {"micolab_dns_zone": ""}):
            with self.subTest(extra=extra):
                result, argv = self.play(["targets.yml", "dns_records.yml"], extra_vars=extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(argv, [])

    def test_wrong_ns_answer_fails(self):
        result, _argv = self.play(["targets.yml", "dns_records.yml"],
                                  env_extra={"FAKE_NS": "ns1.micolab.hnh."})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must publish NS", result.stdout)

    def test_doh_and_dot_render_service_domain_names(self):
        # git gets its own address so the expected answer can only come from
        # the micolab_verify_expected_a_records key git.microlab.hnh.
        git_ip = "10.0.0.9"
        server = PolicyDotServer(self.crt, self.key, lambda p, n, rd: (0, git_ip))
        self.addCleanup(server.close)
        addresses = {k: self.mgmt_ip for k in ("ns1", "ca", "dns")}
        addresses["git"] = git_ip
        result, argv = self.play(
            ["targets.yml", "encrypted_dns.yml"],
            extra_vars={"micolab_verify_tls_root": str(self.ca),
                        "micolab_verify_dot_port": server.port,
                        "micolab_dns_addresses": addresses},
            env_extra={"FAKE_DOH_A": git_ip})
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertEqual(argv, [[
            "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
            "--cacert", str(self.ca),
            "--resolve", "dns.microlab.hnh:443:127.0.0.1",
            "-H", "accept: application/dns-json",
            "https://dns.microlab.hnh/dns-query?name=git.microlab.hnh&type=A",
        ]])
        self.assertEqual(server.log, [{"peer": "127.0.0.1", "sni": "dns.microlab.hnh",
                                       "qname": "git.microlab.hnh", "rd": True}])


@unittest.skipUnless(
    yaml is not None and find_ansible_playbook() and shutil.which("openssl")
    and all(loopback_alias_usable(a) for a in (ALLOWED_SRC, DENIED_SRC)),
    "PyYAML, ansible-playbook, openssl and 127.0.0.2/3 are required",
)
class ExternalAclPlaybookSourceTests(RolePlaybookMixin, unittest.TestCase):
    """Run the real external_acl.yml with delegated local probe hosts.

    The management address is 127.0.0.1 so the DoT socket reaches the local
    policy server; the probe hosts use local connections. The probe list,
    CIDRs and source_address go through the role's validation and are passed
    to the real dot_probe via the task environment.
    """

    mgmt_ip = "127.0.0.1"

    def probes(self, denied_source=DENIED_SRC):
        probes = []
        for check in ("dns_admin", "ca_management", "doh"):
            probes += [{"name": check + "-allowed", "host": "probe-a", "check": check, "expect": "allowed"},
                       {"name": check + "-denied", "host": "probe-d", "check": check, "expect": "denied"}]
        probes += [
            {"name": "dot-allowed", "host": "probe-a", "check": "dot", "expect": "allowed",
             "source_address": ALLOWED_SRC, "access": "recursion-allowed"},
            {"name": "dot-denied", "host": "probe-d", "check": "dot", "expect": "denied",
             "source_address": denied_source, "access": "recursion-denied"},
        ]
        return probes

    def run_acl(self, policy=lab_policy, **overrides):
        server = PolicyDotServer(self.crt, self.key, policy)
        self.addCleanup(server.close)
        stage = self.root / "stage-{}.py".format(uuid.uuid4().hex)
        extra = {
            "micolab_verify_tls_root": str(self.ca),
            "micolab_verify_dot_port": server.port,
            "micolab_verify_dot_probe_stage_path": str(stage),
            "micolab_verify_external_probe_timeout": 3,
            "micolab_admin_cidrs": [ALLOWED_SRC + "/32"],
            "micolab_client_cidrs": [],
            "micolab_dns_recursion_allow_cidrs": [],
            "micolab_dns_authoritative_only_cidrs": [DENIED_SRC + "/32", "10.255.255.0/24"],
            "micolab_dns_fixture_name": FIXTURE_NAME,
            "micolab_dns_fixture_zone": FIXTURE_ZONE,
            "micolab_dns_fixture_expected_ip": FIXTURE_IP,
            "micolab_verify_external_acl_probes": self.probes(),
        }
        extra.update(overrides)
        inv = self.inventory(
            "probe-a ansible_connection=local ansible_python_interpreter={py}\n"
            "probe-d ansible_connection=local ansible_python_interpreter={py}\n".format(py=sys.executable))
        result, argv = self.play(["targets.yml", "external_acl.yml"], extra_vars=extra, inventory=inv)
        self.assertFalse(stage.exists(), "staged DoT probe was not removed")
        return result, server

    def test_playbook_passes_source_and_server_sees_bound_addresses(self):
        result, server = self.run_acl()
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertEqual(
            [(e["peer"], e["qname"], e["sni"]) for e in server.log],
            [(ALLOWED_SRC, FIXTURE_NAME, "dns.microlab.hnh"),
             (DENIED_SRC, FIXTURE_NAME, "dns.microlab.hnh"),
             (DENIED_SRC, DENIED_NAME, "dns.microlab.hnh")],
        )

    def test_playbook_rejects_unavailable_declared_source(self):
        result, server = self.run_acl(
            micolab_verify_external_acl_probes=self.probes(denied_source="10.255.255.7"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source_unavailable", result.stdout)
        self.assertNotIn((("10.255.255.7")), [e["peer"] for e in server.log])

    def test_playbook_rejects_fixture_only_refusal(self):
        # Fixture zone ACL refuses DENIED_SRC but global recursion lets it
        # recurse: the denied DoT probe must fail.
        def policy(peer, name, rd):
            if name == FIXTURE_NAME:
                return (0, FIXTURE_IP) if peer == ALLOWED_SRC else (5, None)
            return (2, None)

        result, _server = self.run_acl(policy=policy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("global-recursion-acl", result.stdout)

    def test_recursion_denied_name_inside_local_zones_is_rejected(self):
        for name in ("probe.microlab.hnh", "x.hnh", "other.fixture.test"):
            with self.subTest(name=name):
                result, server = self.run_acl(micolab_verify_dns_recursion_denied_name=name)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Require a global-recursion probe name outside every local zone", result.stdout)
                self.assertEqual(server.log, [])

    def test_ipv6_dot_source_is_rejected_for_ipv4_target(self):
        probes = self.probes()
        probes[-1]["source_address"] = "::1"
        result, server = self.run_acl(micolab_verify_external_acl_probes=probes,
                                      micolab_dns_authoritative_only_cidrs=["::1/128", DENIED_SRC + "/32"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an IPv4", result.stdout)
        self.assertEqual(server.log, [])



if __name__ == "__main__":
    unittest.main()
