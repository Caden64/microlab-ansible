"""Regression tests for the Caddy, site-ordering, and verify repairs.

These tests render the real Caddyfile template, validate it with the upstream
Caddy binary when one is available, and inspect the real task wiring. They do
not contact a host, a CA, a DNS server, or a Forgejo instance.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

try:
    import yaml
except ImportError:  # pragma: no cover - environment guard
    yaml = None

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:  # pragma: no cover - environment guard
    Environment = None
    FileSystemLoader = None


CADDY_VARS = {
    "micolab_caddy_admin_host": "127.0.0.1",
    "micolab_caddy_admin_port": 2019,
    "micolab_caddy_storage_dir": "/var/lib/caddy/.local/share/caddy",
    "micolab_caddy_http_port": 80,
    "micolab_caddy_https_port": 443,
    "micolab_caddy_acme_directory_effective": "https://127.0.0.1:4443/acme/acme/directory",
    "micolab_caddy_acme_trusted_roots": "/usr/local/share/ca-certificates/microlab-root.crt",
    "micolab_caddy_upstream_trust_directive": "tls_trust_pool file",
    "micolab_caddy_ca_host": "ca.microlab.hnh",
    "micolab_caddy_management_cidrs": ["10.10.0.0/16"],
    "micolab_caddy_ca_upstream_host": "127.0.0.1",
    "micolab_caddy_ca_upstream_port": 4443,
    "micolab_caddy_dns_host": "dns.microlab.hnh",
    "micolab_caddy_dns_client_cidrs": ["10.20.0.0/16"],
    "micolab_caddy_dns_upstream_host": "127.0.0.1",
    "micolab_caddy_dns_upstream_port": 8053,
    "micolab_caddy_admin_upstream_host": "127.0.0.1",
    "micolab_caddy_admin_upstream_port": 5380,
    "micolab_caddy_admin_cidrs": ["10.30.0.0/16"],
    "micolab_caddy_git_host": "git.microlab.hnh",
    "micolab_caddy_forgejo_upstream_host": "127.0.0.1",
    "micolab_caddy_forgejo_upstream_port": 3000,
}


@unittest.skipUnless(
    yaml is not None and Environment is not None,
    "PyYAML and Jinja2 are required",
)
class CaddyfileRenderTests(unittest.TestCase):
    def render(self, *, enable_ca: bool, enable_dns: bool, enable_git: bool) -> str:
        env = Environment(
            loader=FileSystemLoader(str(ROOT / "roles/caddy/templates")),
            autoescape=False,
            keep_trailing_newline=True,
        )
        # Ansible provides the ``bool`` filter; plain Jinja2 does not.
        env.filters["bool"] = bool
        values = dict(CADDY_VARS)
        values.update(
            {
                "micolab_caddy_enable_ca": enable_ca,
                "micolab_caddy_enable_dns": enable_dns,
                "micolab_caddy_enable_git": enable_git,
            }
        )
        return env.get_template("Caddyfile.j2").render(**values)

    def dns_block(self) -> str:
        text = self.render(enable_ca=True, enable_dns=True, enable_git=False)
        match = re.search(r"(?ms)^dns\.microlab\.hnh \{\n(.*?)^\}", text)
        self.assertIsNotNone(match, msg=text)
        return match.group(0)

    def test_dns_block_has_exact_doh_and_admin_fallback(self) -> None:
        block = self.dns_block()
        self.assertIn("@doh path /dns-query", block)
        self.assertIn("reverse_proxy http://127.0.0.1:8053", block)
        self.assertIn("@doh_denied not remote_ip", block)
        self.assertIn("10.20.0.0/16", block)
        self.assertIn("reverse_proxy http://127.0.0.1:5380", block)
        self.assertIn("@admin_denied not remote_ip", block)
        self.assertIn("10.30.0.0/16", block)
        self.assertNotIn("respond 404", block)
        self.assertEqual(block.count("header_up X-Real-IP {remote_host}"), 2)
        self.assertEqual(block.count("header_up X-Forwarded-For {remote_host}"), 2)

        doh_section, admin_section = block.split("handle {", 1)
        self.assertIn("10.20.0.0/16", doh_section)
        self.assertNotIn("10.30.0.0/16", doh_section)
        self.assertIn("10.30.0.0/16", admin_section)
        self.assertNotIn("10.20.0.0/16", admin_section)
        self.assertIn("header_up X-Forwarded-Proto {scheme}", admin_section)
        self.assertIn("header_up X-Forwarded-Host {host}", admin_section)

    def test_acme_directory_is_exact_for_every_scenario(self) -> None:
        for ca, dns, git in [
            (True, False, False),
            (True, True, False),
            (True, True, True),
        ]:
            with self.subTest(ca=ca, dns=dns, git=git):
                text = self.render(enable_ca=ca, enable_dns=dns, enable_git=git)
                self.assertIn(
                    "dir https://127.0.0.1:4443/acme/acme/directory", text
                )
                self.assertNotIn("microlab-caddy", text)
                self.assertNotIn("micolab-caddy", text)

    def test_initial_render_has_ca_and_dns_but_no_git(self) -> None:
        text = self.render(enable_ca=True, enable_dns=True, enable_git=False)
        self.assertIn("ca.microlab.hnh {", text)
        self.assertIn("dns.microlab.hnh {", text)
        self.assertNotIn("git.microlab.hnh {", text)

    def test_caddy_validate_accepts_every_scenario(self) -> None:
        caddy = os.environ.get("CADDY_BIN") or shutil.which("caddy")
        if not caddy:
            self.skipTest("set CADDY_BIN or install caddy to run upstream validation")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca = root / "root.crt"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(root / "root.key"),
                    "-out",
                    str(ca),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=MicroLab Test Root",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for name, scenario in {
                "initial": (True, True, False),
                "ready": (True, True, False),
                "final": (True, True, True),
            }.items():
                with self.subTest(scenario=name):
                    text = self.render(
                        enable_ca=scenario[0],
                        enable_dns=scenario[1],
                        enable_git=scenario[2],
                    )
                    text = text.replace(
                        "/usr/local/share/ca-certificates/microlab-root.crt",
                        str(ca),
                    )
                    config = root / f"{name}.Caddyfile"
                    config.write_text(text, encoding="utf-8")
                    env = dict(os.environ)
                    env["XDG_DATA_HOME"] = str(root / "storage")
                    env["XDG_CONFIG_HOME"] = str(root / "storage")
                    (root / "storage").mkdir(exist_ok=True)
                    result = subprocess.run(
                        [caddy, "validate", "--config", str(config), "--adapter", "caddyfile"],
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, msg=result.stdout)


@unittest.skipUnless(yaml is not None, "PyYAML is required")
class CaddyTaskWiringTests(unittest.TestCase):
    def load_tasks(self, relative: str):
        return yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))

    def test_release_directory_is_created_before_unarchive(self) -> None:
        tasks = self.load_tasks("roles/caddy/tasks/main.yml")
        names = [task.get("name", "") for task in tasks]
        create = names.index("Create the pinned Caddy release directory")
        extract = names.index("Extract the pinned Caddy release")
        self.assertLess(create, extract)
        path = tasks[create]["ansible.builtin.file"]["path"]
        self.assertIn("micolab_caddy_install_root", path)
        self.assertIn("micolab_caddy_version", path)

    def test_no_alternative_acme_provisioner_adoption(self) -> None:
        text = (ROOT / "roles/caddy/tasks/main.yml").read_text(encoding="utf-8")
        self.assertNotIn("micolab_caddy_acme_names | first", text)
        self.assertNotIn("Select the configured or sole live ACME provisioner", text)
        self.assertIn("micolab_caddy_acme_provisioner == 'acme'", text)
        self.assertIn("micolab_caddy_acme_directory_required", text)
        self.assertIn("'acme' in micolab_caddy_acme_names", text)

    def test_doh_probe_is_a_separate_readiness_file(self) -> None:
        main = (ROOT / "roles/caddy/tasks/main.yml").read_text(encoding="utf-8")
        health = (ROOT / "roles/caddy/tasks/health_doh.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("include_tasks: health_doh.yml", main)
        self.assertIn("micolab_caddy_verify_doh", main)
        self.assertIn("/dns-query", health)
        self.assertIn("micolab_caddy_verify_doh", health)


@unittest.skipUnless(yaml is not None, "PyYAML is required")
class SiteOrderingTests(unittest.TestCase):
    def test_caddy_phases_render_dns_and_defer_doh(self) -> None:
        tasks = yaml.safe_load(
            (ROOT / "playbooks/site.yml").read_text(encoding="utf-8")
        )[1]["tasks"]
        names = [task.get("name", "") for task in tasks]

        first = next(t for t in tasks if t.get("name", "").startswith("Phase 5:"))
        self.assertEqual(first["vars"]["micolab_caddy_enable_dns"], True)
        self.assertEqual(first["vars"]["micolab_caddy_enable_git"], False)
        self.assertEqual(first["vars"]["micolab_caddy_verify_doh"], False)

        ready = next(t for t in tasks if t.get("name", "").startswith("Phase 6b:"))
        self.assertEqual(ready["ansible.builtin.include_role"]["tasks_from"], "health_doh")
        self.assertEqual(ready["vars"]["micolab_caddy_verify_doh"], True)

        tls = next(i for i, n in enumerate(names) if n.startswith("Phase 6:"))
        ready_index = next(i for i, n in enumerate(names) if n.startswith("Phase 6b:"))
        forgejo = next(i for i, n in enumerate(names) if n.startswith("Phase 7:"))
        self.assertLess(tls, ready_index)
        self.assertLess(ready_index, forgejo)

        final = next(t for t in tasks if t.get("name", "").startswith("Phase 8:"))
        self.assertEqual(final["vars"]["micolab_caddy_enable_git"], True)

    def test_challenge_group_is_consistent(self) -> None:
        group_vars = yaml.safe_load(
            (ROOT / "group_vars/all.yml").read_text(encoding="utf-8")
        )
        self.assertEqual(group_vars["micolab_challenge_group"], "microlab_challenge")
        self.assertIn(
            "micolab_challenge_group",
            group_vars["micolab_verify_challenge_group"],
        )
        text = (ROOT / "roles/verify/defaults/main.yml").read_text(encoding="utf-8")
        self.assertIn("micolab_challenge_group | default('microlab_challenge')", text)
        self.assertNotIn('micolab_verify_challenge_group: "micolab_challenge"', text)


@unittest.skipUnless(yaml is not None, "PyYAML is required")
class VerifyAcceptanceTests(unittest.TestCase):
    def load_tasks(self, relative: str):
        return yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))

    def flatten(self, tasks):
        for task in tasks:
            if not isinstance(task, dict):
                continue
            yield task
            for key in ("block", "always", "rescue"):
                if key in task:
                    yield from self.flatten(task[key])

    def test_ssh_acceptance_is_required_by_default(self) -> None:
        defaults = yaml.safe_load(
            (ROOT / "roles/verify/defaults/main.yml").read_text(encoding="utf-8")
        )
        self.assertIs(defaults["micolab_verify_enable_ssh"], True)
        self.assertIs(defaults["micolab_verify_accept_unexecuted_git_acceptance"], False)
        self.assertIs(defaults["micolab_verify_accept_unverified_external_acl"], False)

    def test_git_acceptance_clones_pushes_and_cleans_up(self) -> None:
        tasks = list(
            self.flatten(self.load_tasks("roles/verify/tasks/git_acceptance.yml"))
        )
        text = json.dumps(tasks)
        self.assertIn("clone", text)
        self.assertIn("push", text)
        self.assertIn("--delete", text)
        self.assertIn("askpass.sh", text)
        self.assertIn("micolab_verify_git_visibility", text)
        self.assertIn("micolab_verify_git_branch", text)
        self.assertIn("micolab_verify_accept_unexecuted_git_acceptance", text)

    def test_git_token_never_appears_in_command_argv(self) -> None:
        tasks = self.load_tasks("roles/verify/tasks/git_acceptance.yml")
        for task in self.flatten(tasks):
            command = task.get("ansible.builtin.command")
            if not command:
                continue
            argv = json.dumps(command.get("argv", []))
            self.assertNotIn("micolab_verify_git_https_token", argv)
            self.assertNotIn("micolab_verify_git_https_password", argv)

    def test_askpass_script_reads_credentials_from_environment(self) -> None:
        tasks = self.load_tasks("roles/verify/tasks/git_acceptance.yml")
        copy_task = next(
            task
            for task in self.flatten(tasks)
            if task.get("name") == "Write the HTTPS askpass helper without embedding credentials"
        )
        script = copy_task["ansible.builtin.copy"]["content"]
        self.assertNotIn("micolab_verify_git_https_token", script)
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            os.chmod(path, 0o700)
            env = dict(os.environ)
            env["MICOLAB_GIT_USERNAME"] = "verify-user"
            env["MICOLAB_GIT_TOKEN"] = "s3cret-token"
            username = subprocess.run(
                [path, "Username for 'https://git.microlab.hnh':"],
                env=env,
                stdout=subprocess.PIPE,
                text=True,
                check=True,
            ).stdout.strip()
            password = subprocess.run(
                [path, "Password for 'https://git.microlab.hnh':"],
                env=env,
                stdout=subprocess.PIPE,
                text=True,
                check=True,
            ).stdout.strip()
            self.assertEqual(username, "verify-user")
            self.assertEqual(password, "s3cret-token")
        finally:
            os.unlink(path)

    def test_external_acl_probes_are_executed_and_two_sided(self) -> None:
        tasks = list(
            self.flatten(self.load_tasks("roles/verify/tasks/external_acl.yml"))
        )
        text = json.dumps(tasks)
        for value in ["dns_admin", "ca_management", "doh", "dot"]:
            self.assertIn(value, text)
        self.assertIn("'allowed'", text)
        self.assertIn("'denied'", text)
        self.assertIn("delegate_to", text)
        self.assertIn("micolab_verify_external_acl_probes", text)
        self.assertNotIn("Report required external ACL probes", text)

        probe = next(
            task
            for task in tasks
            if task.get("name")
            == "Run every external ACL probe on its delegated inventory host"
        )
        script = probe["ansible.builtin.shell"]
        self.assertIn("set -euo pipefail", script)
        self.assertIn("test -r \"$ca\"", script)
        result = subprocess.run(
            ["bash", "-n"], input=script, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_overall_acceptance_is_recorded_and_overrides_are_noncomplete(self) -> None:
        main = (ROOT / "roles/verify/tasks/main.yml").read_text(encoding="utf-8")
        self.assertIn("micolab_verify_overall_state", main)
        self.assertIn("'complete'", main)
        self.assertIn("'noncomplete'", main)
        self.assertIn("micolab_verify_acceptance_file", main)
        self.assertIn("micolab_verify_accept_unexecuted_git_acceptance | bool", main)
        self.assertIn("micolab_verify_accept_unverified_external_acl | bool", main)


if __name__ == "__main__":
    unittest.main()
