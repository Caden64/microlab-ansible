"""Disposable CLI onboarding checks: no real inventory, keys, network or hosts.

Copy only public implementation files to a temporary checkout. Tiny synthetic
artifacts replace publisher bytes. Every Ansible/SSH process is intercepted;
these tests establish CLI handoffs, never actual installation/acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class SetupExperienceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="microlab-onboarding-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "checkout"
        self.repo.mkdir()
        # Never copy private site inventory, user secrets, or downloaded artifacts.
        for name in ("scripts", "config", "playbooks", "group_vars"):
            if (ROOT / name).exists():
                shutil.copytree(ROOT / name, self.repo / name,
                                ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / "inventories/example", self.repo / "inventories/example")
        shutil.copy2(ROOT / "inventories/vault.yml.example",
                     self.repo / "inventories/vault.yml.example")
        if (ROOT / "microlab").is_file():
            shutil.copy2(ROOT / "microlab", self.repo / "microlab")
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.log = self.base / "subprocess.jsonl"
        stub = self.bin / "ansible-playbook"
        stub.write_text(
            "#!" + sys.executable + "\n" + r'''import base64, json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['MICROLAB_TEST_LOG'], 'a') as f:
    f.write(json.dumps({'tool': name, 'argv': sys.argv[1:]})+'\n')
if name == 'ansible-vault':
    if 'encrypt' in sys.argv:
        content = sys.stdin.buffer.read()
        pathlib.Path(sys.argv[sys.argv.index('--output')+1]).write_bytes(
            b'$ANSIBLE_VAULT;1.1;AES256\n' + base64.b64encode(content))
    elif 'view' in sys.argv:
        content = pathlib.Path(sys.argv[-1]).read_bytes().split(b'\n', 1)[1]
        sys.stdout.buffer.write(base64.b64decode(content))
elif name == 'ansible-inventory':
    sys.stdout.write(pathlib.Path(os.environ['MICROLAB_TEST_HOSTVARS']).read_text())
elif name != 'ansible-playbook':
    sys.exit('Unexpected external command in disposable onboarding test')
sys.exit(int(os.environ.get('MICROLAB_TEST_EXIT', '0')))
'''
        )
        stub.chmod(0o755)
        for name in ("ansible", "ansible-inventory", "ansible-vault", "ssh", "scp", "curl", "wget"):
            shutil.copy2(stub, self.bin / name)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        MICROLAB_TEST_LOG=str(self.log), HOME=str(self.base / "home"),
                        PYTHONDONTWRITEBYTECODE="1")
        Path(self.env["HOME"]).mkdir()
        self.env.pop("ANSIBLE_VAULT_IDENTITY_LIST", None)
        password = self.base / "test-vault-password"
        password.write_text("disposable-test-only")
        self.env["ANSIBLE_VAULT_PASSWORD_FILE"] = str(password)
        self.hostvars = self.base / "resolved-inventory.json"
        self.env["MICROLAB_TEST_HOSTVARS"] = str(self.hostvars)

    def cli(self, *args, code=0):
        executable = self.repo / "microlab"
        self.assertTrue(executable.is_file(),
                        "Integration gap: shared executable ./microlab has not landed")
        self.assertTrue(os.access(executable, os.X_OK), "./microlab must be executable")
        result = subprocess.run([str(executable), *map(str, args)], cwd=self.repo,
                                env=self.env, text=True, capture_output=True, timeout=20)
        if code is not None:
            self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def filled_inventory(self):
        inventory = self.repo / "inventories/filled/hosts.yml"
        variables = inventory.parent / "group_vars/microlab_management/main.yml"
        variables.parent.mkdir(parents=True)
        inventory.write_text(yaml.safe_dump({"all": {"children": {
            "microlab_management": {"hosts": {"infra": {
                "ansible_host": "10.72.78.73", "ansible_user": "operator",
                "ansible_ssh_private_key_file": str(self.base / "no-real-key")}}},
            "microlab_challenge": {"hosts": {"workload": {"ansible_host": "10.72.78.72"}}}
        }}}))
        variables.write_text(yaml.safe_dump({
            "micolab_expected_architecture": "arm64",
            # Synthetic TEST identity; the actual site's admin source is unknown.
            "micolab_admin_cidrs": ["10.72.78.250/32"],
            "micolab_client_cidrs": ["10.72.78.0/24"],
            "micolab_dns_addresses": dict.fromkeys(("ns1", "ca", "dns", "git"), "10.72.78.73"),
            "operator_custom_value": "preserve-me",
        }))
        vault = variables.with_name("vault.yml")
        secrets = {key: "test-secret-must-not-be-printed" for key in (
            "micolab_technitium_admin_password", "micolab_technitium_tls_cert_password",
            "micolab_forgejo_secret_key", "micolab_forgejo_internal_token",
            "micolab_forgejo_jwt_secret", "micolab_forgejo_lfs_jwt_secret",
            "micolab_forgejo_admin_password")}
        vault.write_bytes(b"$ANSIBLE_VAULT;1.1;AES256\n" +
                          base64.b64encode(yaml.safe_dump(secrets).encode()))
        return inventory, variables, vault

    def mock_artifacts(self, arch="arm64"):
        """Install a tiny lock/cache in the copied checkout, never run bytes."""
        directory = self.base / "mock-artifacts"
        directory.mkdir()
        lock_path = self.repo / "config/artifacts.lock.json"
        lock = json.loads(lock_path.read_text())
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = struct.pack("<H", 183 if arch == "arm64" else 62)
        for name, arches in lock["artifacts"].items():
            entry = arches[arch]
            destination = directory / entry["filename"]
            if name == "forgejo":
                destination.write_bytes(header)
            else:
                with tarfile.open(destination, "w:gz") as archive:
                    content = b"mock managed DLL" if name == "technitium" else bytes(header)
                    member = tarfile.TarInfo(entry["member"])
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
            entry["sha256"] = hashlib.sha256(destination.read_bytes()).hexdigest()
            entry["publisher_hash"] = {"sha256": entry["sha256"]}
            # Any accidental download fails without a private target or public fetch.
            entry["url"] = "https://127.0.0.1:1/not-a-download"
        lock_path.write_text(json.dumps(lock))
        return directory

    def test_executable_exposes_shared_commands(self):
        result = self.cli("--help")
        for command in ("setup", "artifacts", "deploy", "verify", "status"):
            self.assertIn(command, result.stdout)
        self.assertEqual(self.calls(), [])

    def test_command_help_is_local(self):
        for command in ("setup", "artifacts", "deploy", "verify", "status"):
            with self.subTest(command=command):
                self.assertIn("usage", self.cli(command, "--help").stdout.lower())
        self.assertEqual(self.calls(), [])

    def resolved_inventory(self, inventory, variables, vault, *, ca=True, tokens=False):
        hosts = yaml.safe_load(inventory.read_text())["all"]["children"]
        infra_name, infra = next(iter(hosts["microlab_management"]["hosts"].items()))
        workload_name, workload = next(iter(hosts["microlab_challenge"]["hosts"].items()))
        values = yaml.safe_load(variables.read_text())
        values.update(yaml.safe_load(base64.b64decode(vault.read_bytes().split(b"\n", 1)[1])))
        values.update(infra)
        values["micolab_staged_artifacts"] = [{"name": "test-only"}]
        if ca:
            for key in ("root_cert", "intermediate_cert", "intermediate_key"):
                source = self.base / (key + ".not-a-real-certificate")
                source.write_text("mock local file; cryptographic validation belongs to Ansible")
                values["microlab_step_ca_" + key + "_src"] = str(source)
            for key in ("root_fingerprint_sha256", "intermediate_key_password",
                        "technitium_jwk_key", "technitium_jwk_encrypted_key"):
                values["microlab_step_ca_" + key] = "test-secret-must-not-be-printed"
        if tokens:
            values["micolab_technitium_api_token"] = "test-secret-must-not-be-printed"
            values["micolab_technitium_enrollment_token"] = "test-secret-must-not-be-printed"
        self.hostvars.write_text(json.dumps({
            "microlab_management": {"hosts": [infra_name]},
            "microlab_challenge": {"hosts": [workload_name]},
            "_meta": {"hostvars": {infra_name: values, workload_name: workload}},
        }))

    def test_fresh_setup_same_subnet_then_mock_artifact_staging(self):
        inventory = self.repo / "inventories/new/hosts.yml"
        result = self.cli("setup", "--inventory", inventory,
                          "--infra-ip", "10.72.78.73", "--rctf-ip", "10.72.78.72",
                          "--ssh-user", "operator", "--ssh-key", self.base / "no-real-key",
                          "--arch", "arm64", "--admin-cidr", "10.72.78.250/32",
                          "--client-cidr", "10.72.78.0/24")
        self.assertNotIn("test-secret-must-not-be-printed", result.stdout + result.stderr)
        self.assertNotIn("ansible-playbook", [c["tool"] for c in self.calls()])
        hosts = yaml.safe_load(inventory.read_text())["all"]["children"]
        self.assertEqual(len(hosts["microlab_management"]["hosts"]), 1)
        self.assertEqual(len(hosts["microlab_challenge"]["hosts"]), 1)
        group = inventory.parent / "group_vars/microlab_management"
        setup = yaml.safe_load((group / "setup.yml").read_text())
        self.assertEqual(setup["micolab_admin_cidrs"], ["10.72.78.250/32"])
        self.assertEqual(setup["micolab_client_cidrs"], ["10.72.78.0/24"])
        self.assertEqual(setup["micolab_dns_addresses"],
                         dict.fromkeys(("ns1", "ca", "dns", "git"), "10.72.78.73"))
        self.assertTrue((group / "setup-vault.yml").read_bytes().startswith(b"$ANSIBLE_VAULT;"))
        # The launcher chooses repo/artifacts; pre-populate only synthetic bytes.
        artifacts = self.mock_artifacts()
        shutil.copytree(artifacts, self.repo / "artifacts", dirs_exist_ok=True)
        before = {p: p.read_bytes() for p in (self.repo / "artifacts").iterdir()}
        self.cli("artifacts", "--inventory", inventory)
        self.cli("artifacts", "--inventory", inventory)
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertTrue((group / "zz_microlab_artifacts.yml").is_file())
        status = self.cli("status", "--inventory", inventory)
        self.assertIn("UNVERIFIED", status.stdout)
        self.assertEqual([c["tool"] for c in self.calls()], ["ansible-vault"])
        # Complete the fresh-directory CLI path with mocked target execution.
        # These CA files are inert fixtures, not real certificates or keys.
        self.resolved_inventory(inventory, group / "setup.yml", group / "setup-vault.yml")
        bootstrap = self.cli("deploy", "--inventory", inventory, "--no-become-prompt")
        self.assertIn("incomplete", bootstrap.stdout.lower())
        self.resolved_inventory(inventory, group / "setup.yml", group / "setup-vault.yml", tokens=True)
        self.cli("deploy", "--inventory", inventory, "--no-become-prompt")
        self.cli("verify", "--inventory", inventory, "--no-become-prompt")
        calls = [c for c in self.calls() if c["tool"] == "ansible-playbook"]
        self.assertEqual(len(calls), 3)
        for call, play in zip(calls, ("bootstrap", "deploy", "verify"), strict=True):
            self.assertIn(str(self.repo / "playbooks" / (play + ".yml")), call["argv"])
            self.assertNotIn("microlab-rctf", call["argv"][call["argv"].index("--limit") + 1])
        self.assertIn("UNVERIFIED", self.cli("status", "--inventory", inventory).stdout)

    def test_existing_filled_inventory_and_vault_remain_byte_exact(self):
        inventory, variables, vault = self.filled_inventory()
        before = {p: p.read_bytes() for p in (inventory, variables, vault)}
        # Even supplied alternatives must not reset existing user values.
        self.cli("setup", "--inventory", inventory, "--infra-ip", "192.0.2.73",
                 "--rctf-ip", "192.0.2.72", "--admin-cidr", "192.0.2.250/32")
        self.cli("setup", "--inventory", inventory)
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertTrue(all(c["tool"] == "ansible-vault" for c in self.calls()))

    def test_missing_admin_is_a_local_checkpoint_without_partial_inventory(self):
        inventory = self.repo / "inventories/new/hosts.yml"
        result = self.cli("setup", "--inventory", inventory,
                          "--infra-ip", "10.72.78.73", "--rctf-ip", "10.72.78.72",
                          "--ssh-user", "operator", "--ssh-key", self.base / "no-real-key",
                          "--arch", "arm64", "--client-cidr", "10.72.78.0/24", code=2)
        self.assertIn("admin", result.stderr.lower())
        self.assertFalse(inventory.exists())
        self.assertEqual(self.calls(), [])

    def test_client_subnet_is_not_accepted_as_admin_identity(self):
        inventory, variables, vault = self.filled_inventory()
        self.resolved_inventory(inventory, variables, vault)
        data = json.loads(self.hostvars.read_text())
        data["_meta"]["hostvars"]["infra"]["micolab_admin_cidrs"] = ["10.72.78.0/24"]
        self.hostvars.write_text(json.dumps(data))
        result = self.cli("deploy", "--inventory", inventory, code=2)
        self.assertIn("player subnet", result.stderr)
        self.assertFalse(any(c["tool"] == "ansible-playbook" for c in self.calls()))

    def test_missing_ca_material_blocks_before_any_playbook(self):
        inventory, variables, vault = self.filled_inventory()
        self.resolved_inventory(inventory, variables, vault, ca=False)
        result = self.cli("deploy", "--inventory", inventory, code=2)
        self.assertIn("./microlab ca-init", result.stderr)
        self.assertNotIn("test-secret-must-not-be-printed", result.stdout + result.stderr)
        self.assertFalse(any(c["tool"] == "ansible-playbook" for c in self.calls()))

    def test_bootstrap_resume_and_full_acceptance_are_distinct_handoffs(self):
        inventory, variables, vault = self.filled_inventory()
        self.resolved_inventory(inventory, variables, vault, tokens=False)
        result = self.cli("deploy", "--inventory", inventory, "--no-become-prompt")
        self.assertIn("checkpoint", result.stdout.lower())
        self.assertIn("incomplete", result.stdout.lower())
        self.resolved_inventory(inventory, variables, vault, tokens=True)
        self.cli("deploy", "--inventory", inventory, "--no-become-prompt")
        self.cli("verify", "--inventory", inventory, "--no-become-prompt")
        calls = [c for c in self.calls() if c["tool"] == "ansible-playbook"]
        for call, expected in zip(calls, ("bootstrap.yml", "deploy.yml", "verify.yml"), strict=True):
            self.assertIn(str(self.repo / "playbooks" / expected), call["argv"])
            self.assertEqual(call["argv"][call["argv"].index("--limit") + 1], "localhost,infra")
            self.assertNotIn("test-secret-must-not-be-printed", json.dumps(call))
        self.assertEqual(len(calls), 3)

    def test_failed_ansible_run_preserves_exit_status_and_does_not_claim_success(self):
        inventory, variables, vault = self.filled_inventory()
        self.resolved_inventory(inventory, variables, vault, tokens=True)
        # Fail only playbook, keeping local inventory resolution valid.
        stub = self.bin / "ansible-playbook"
        stub.write_text("#!" + sys.executable + "\nraise SystemExit(7)\n")
        result = self.cli("deploy", "--inventory", inventory, code=7)
        self.assertNotIn("Deployment playbook completed", result.stdout)

    def test_status_does_not_decrypt_or_contact_hosts(self):
        inventory, _, _ = self.filled_inventory()
        result = self.cli("status", "--inventory", inventory)
        self.assertIn("UNVERIFIED", result.stdout)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
