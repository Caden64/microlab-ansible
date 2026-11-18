"""Controller-only tests: ephemeral inventories, no SSH or real playbook runs."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("setup_controller", SOURCE / "scripts/microlab.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class SetupCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inventory = self.root / "inventories/site/hosts.yml"
        self.vault_password = self.root / "vault-password"
        self.vault_password.write_text("ephemeral-test-password\n")
        self.vault_password.chmod(0o600)
        self.root_patch = patch.object(cli, "ROOT", self.root)
        self.root_patch.start()
        self.env_patch = patch.dict(os.environ, {"ANSIBLE_VAULT_PASSWORD_FILE": str(self.vault_password)})
        self.env_patch.start()
        self.out, self.err = io.StringIO(), io.StringIO()
        self.args = ["setup", "--inventory", str(self.inventory), "--infra-ip", "10.72.78.73", "--rctf-ip", "10.72.78.72", "--ssh-user", "operator", "--ssh-key", "/tmp/test-controller-key", "--arch", "aarch64", "--admin-cidr", "10.72.78.21/32", "--client-cidr", "10.72.78.0/24"]

    def tearDown(self):
        self.env_patch.stop()
        self.root_patch.stop()
        self.temp.cleanup()

    def run_cli(self, args):
        # All target commands in this class are mocked; emulate an interactive
        # controller when checking protected become-prompt flags.
        terminal = patch.object(cli.sys.stdin, "isatty", return_value=True) if args and args[0] in ("deploy", "verify") else contextlib.nullcontext()
        with contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.err), terminal:
            return cli.main(args)

    def save(self, data):
        self.inventory.parent.mkdir(parents=True, exist_ok=True)
        self.inventory.write_text(yaml.safe_dump(data, sort_keys=False))

    def inventory_data(self, infra="infra-alias", challenge="rctf-alias"):
        return {"all": {"children": {
            cli.MANAGEMENT: {"hosts": {infra: {"ansible_host": "10.72.78.73", "ansible_user": "operator", "ansible_ssh_private_key_file": "/tmp/test-controller-key"}}},
            cli.CHALLENGE: {"hosts": {challenge: {"ansible_host": "10.72.78.72"}}},
        }}}

    def fake_encrypt(self, values, destination):
        self.generated = values
        cli.exclusive_write(destination, b"$ANSIBLE_VAULT;test-ciphertext\n")

    def create(self):
        with patch.object(cli.Vault, "encrypt", autospec=True, side_effect=lambda _, v, p: self.fake_encrypt(v, p)):
            return self.run_cli(self.args)

    def test_initial_creation_two_hosts_shared_subnet_and_permissions(self):
        self.assertEqual(self.create(), 0, self.err.getvalue())
        data = yaml.safe_load(self.inventory.read_text())
        self.assertEqual(cli.topology(data)[1]["ansible_host"], "10.72.78.73")
        vars_file = self.inventory.parent / "group_vars/microlab_management/setup.yml"
        values = yaml.safe_load(vars_file.read_text())
        self.assertEqual(values["micolab_expected_architecture"], "arm64")
        self.assertEqual(set(values["micolab_dns_addresses"].values()), {"10.72.78.73"})
        self.assertEqual(values["micolab_admin_cidrs"], ["10.72.78.21/32"])
        self.assertEqual(values["micolab_client_cidrs"], ["10.72.78.0/24"])
        self.assertEqual(len(set(self.generated.values())), len(cli.SECRET_KEYS))
        self.assertEqual(self.inventory.stat().st_mode & 0o777, 0o600)
        for value in self.generated.values():
            self.assertNotIn(value, self.out.getvalue() + self.err.getvalue() + vars_file.read_text())

    def test_existing_complete_inventory_is_byte_for_byte_untouched(self):
        self.save(self.inventory_data())
        original = self.inventory.read_bytes()
        self.assertEqual(self.create(), 0, self.err.getvalue())
        self.assertEqual(self.inventory.read_bytes(), original)

    def test_partial_inventory_merge_requires_review_retains_unknowns(self):
        data = self.inventory_data()
        del data["all"]["children"][cli.CHALLENGE]
        data["all"]["vars"] = {"user_defined_setting": "keep-this"}
        self.save(data)
        original = self.inventory.read_bytes()
        self.assertEqual(self.create(), 2)
        self.assertEqual(self.inventory.read_bytes(), original)
        with patch.object(cli.sys.stdin, "isatty", return_value=True), patch("builtins.input", return_value="MERGE"):
            self.assertEqual(self.create(), 0, self.err.getvalue())
        self.assertEqual(yaml.safe_load(self.inventory.read_text())["all"]["vars"]["user_defined_setting"], "keep-this")
        self.assertEqual((self.inventory.parent / "hosts.pre-setup.yml").read_bytes(), original)

    def test_missing_admin_never_invented(self):
        args = self.args[:]
        offset = args.index("--admin-cidr")
        del args[offset:offset+2]
        with patch.object(cli.sys.stdin, "isatty", return_value=False):
            self.assertEqual(self.run_cli(args), 2)
        self.assertFalse(self.inventory.exists())
        self.assertIn("admin workstation", self.err.getvalue())

    def test_whole_player_subnet_cannot_be_admin(self):
        args = ["10.72.78.0/24" if value == "10.72.78.21/32" else value for value in self.args]
        self.assertEqual(self.run_cli(args), 2)
        self.assertFalse(self.inventory.exists())

    def test_different_aliases_same_ip_refused(self):
        data = self.inventory_data()
        data["all"]["children"][cli.CHALLENGE]["hosts"]["rctf-alias"]["ansible_host"] = "10.72.78.73"
        self.save(data)
        self.assertEqual(self.create(), 2)
        self.assertIn("different hosts", self.err.getvalue())

    def test_malformed_yaml_never_leaks_secret(self):
        self.inventory.parent.mkdir(parents=True)
        self.inventory.write_text("password: [TOP_SECRET_ERROR_CANARY\n")
        self.assertEqual(self.run_cli(["setup", "--inventory", str(self.inventory)]), 2)
        self.assertNotIn("TOP_SECRET_ERROR_CANARY", self.err.getvalue())

    def test_invalid_ip_and_arch_do_not_echo_inputs(self):
        for option in ("--infra-ip", "--arch", "--admin-cidr"):
            args = self.args[:]
            args[args.index(option) + 1] = "SECRET_INVALID_INPUT"
            self.assertEqual(self.run_cli(args), 2)
            self.assertNotIn("SECRET_INVALID_INPUT", self.err.getvalue())
            self.assertFalse(self.inventory.exists())

    def test_encrypted_values_and_legacy_vault_names_are_retained(self):
        self.save(self.inventory_data())
        directory = self.inventory.parent / "group_vars/microlab_management"
        directory.mkdir(parents=True)
        old = directory / "vault.yml"
        old.write_text("$ANSIBLE_VAULT;old-private-ciphertext\n")
        before = old.read_bytes()
        values = {"vault_" + key: "EXISTING_SECRET_" + str(i) for i, key in enumerate(cli.SECRET_KEYS)}
        with patch.object(cli.Vault, "read", return_value=values), patch.object(cli.Vault, "encrypt") as encrypt:
            self.assertEqual(self.run_cli(self.args), 0, self.err.getvalue())
        encrypt.assert_not_called()
        self.assertEqual(old.read_bytes(), before)
        generated = yaml.safe_load(next(p for p in directory.glob("*.yml") if p != old).read_text())
        self.assertEqual(generated[cli.SECRET_KEYS[0]], "{{ vault_" + cli.SECRET_KEYS[0] + " }}")
        self.assertNotIn("EXISTING_SECRET", self.out.getvalue() + self.err.getvalue())

    def test_inline_vault_and_unknown_keys_survive_no_rewrite(self):
        self.save(self.inventory_data())
        directory = self.inventory.parent / "group_vars/microlab_management"
        directory.mkdir(parents=True)
        inline = directory / "main.yml"
        inline.write_text("custom_unknown: preserved\nmicolab_technitium_admin_password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  abcd\n")
        original = inline.read_bytes()
        self.assertEqual(self.create(), 0, self.err.getvalue())
        self.assertNotIn("micolab_technitium_admin_password", self.generated)
        self.assertEqual(inline.read_bytes(), original)

    def test_status_does_not_run_subprocess_or_claim_installed(self):
        self.save(self.inventory_data())
        with patch.object(cli.subprocess, "run") as run:
            self.assertEqual(self.run_cli(["status", "--inventory", str(self.inventory)]), 0)
        run.assert_not_called()
        self.assertIn("UNVERIFIED", self.out.getvalue())

    def test_ca_init_refuses_when_inventory_already_has_ca_settings(self):
        self.save(self.inventory_data())
        directory = self.inventory.parent / "group_vars/microlab_management"
        directory.mkdir(parents=True)
        (directory / "mine.yml").write_text("microlab_step_ca_root_fingerprint_sha256: abc\n")
        with patch.object(cli, "controller_step") as step:
            self.assertEqual(self.run_cli(["ca-init", "--inventory", str(self.inventory)]), 2)
        step.assert_not_called()
        self.assertIn("already has CA settings", self.err.getvalue())
        self.assertFalse((self.inventory.parent / "ca").exists())
        self.assertFalse((directory / "ca.yml").exists())

    def test_ca_init_never_replaces_an_existing_ca_directory(self):
        self.save(self.inventory_data())
        (self.inventory.parent / "ca").mkdir()
        with patch.object(cli, "controller_step") as step:
            self.assertEqual(self.run_cli(["ca-init", "--inventory", str(self.inventory)]), 2)
        step.assert_not_called()
        self.assertIn("never replaces CA material", self.err.getvalue())

    def test_jwe_compact_matches_step_ca_encrypted_key_shape(self):
        serialized = '{"protected":"aaa","encrypted_key":"bbb","iv":"ccc","ciphertext":"ddd","tag":"eee"}'
        self.assertEqual(cli.jwe_compact(serialized), "aaa.bbb.ccc.ddd.eee")
        with self.assertRaises(cli.Checkpoint):
            cli.jwe_compact('{"protected":"aaa","iv":"ccc"}')

    @unittest.skipUnless(os.environ.get("MICROLAB_STEP_CLI_ARCHIVE") and shutil.which("ansible-vault") and shutil.which("openssl"),
                         "set MICROLAB_STEP_CLI_ARCHIVE to the pinned controller step CLI archive")
    def test_ca_init_creates_material_the_role_accepts(self):
        self.save(self.inventory_data())
        cache = self.root / "artifacts"
        cache.mkdir()
        import platform
        arch = cli.CONTROLLER_ARCH[platform.machine()]
        shutil.copyfile(os.environ["MICROLAB_STEP_CLI_ARCHIVE"], cache / ("step-cli-0.31.0-%s.tar.gz" % arch))
        self.assertEqual(self.run_cli(["ca-init", "--inventory", str(self.inventory)]), 0, self.err.getvalue())
        ca = self.inventory.parent / "ca"
        plain = yaml.safe_load((self.inventory.parent / "group_vars/microlab_management/ca.yml").read_text())
        self.assertTrue(plain["microlab_step_ca_initial_deploy"])
        self.assertNotIn("d", plain["microlab_step_ca_technitium_jwk_key"])
        self.assertEqual(plain["microlab_step_ca_root_cert_src"], str(ca / "root_ca.crt"))
        # The root key is kept apart for removal and never referenced by inventory.
        self.assertTrue((ca / "offline-root/root_ca_key").is_file())
        self.assertNotIn("root_ca_key", (self.inventory.parent / "group_vars/microlab_management/ca.yml").read_text())
        for vaulted in (self.inventory.parent / "group_vars/microlab_management/ca-vault.yml",
                        ca / "technitium-provisioner-password.vault.yml", ca / "offline-root/root-key-password.vault.yml"):
            self.assertTrue(vaulted.read_bytes().startswith(b"$ANSIBLE_VAULT;"), vaulted)
        secret = yaml.safe_load(subprocess.run(["ansible-vault", "view", str(self.inventory.parent / "group_vars/microlab_management/ca-vault.yml")],
                                               check=True, stdout=subprocess.PIPE).stdout)
        fingerprint = cli.check_material(ca / "root_ca.crt", ca / "intermediate_ca.crt", ca / "intermediate_ca_key",
                                         secret["microlab_step_ca_intermediate_key_password"])
        self.assertEqual(fingerprint, plain["microlab_step_ca_root_fingerprint_sha256"])
        self.assertEqual(secret["microlab_step_ca_technitium_jwk_encrypted_key"].count("."), 4)
        self.assertEqual(oct((ca / "intermediate_ca_key").stat().st_mode & 0o777), "0o600")

    def test_status_reports_past_encrypted_setup_vault_without_opening_it(self):
        # Setup itself writes an encrypted sidecar; status must stay useful after it.
        self.save(self.inventory_data())
        directory = self.inventory.parent / "group_vars/microlab_management"
        directory.mkdir(parents=True)
        (directory / "setup-vault.yml").write_text("$ANSIBLE_VAULT;1.1;AES256\nabcd\n")
        (directory / "zz_microlab_artifacts.yml").write_text("micolab_staged_artifacts: [{name: technitium}]\n")
        with patch.object(cli.subprocess, "run") as run:
            self.assertEqual(self.run_cli(["status", "--inventory", str(self.inventory)]), 0)
        run.assert_not_called()
        output = self.out.getvalue()
        self.assertNotIn("Encrypted configuration needs", output)
        self.assertIn("artifact declarations: present", output)
        self.assertIn("pending: microlab_step_ca_root_cert_src", output)
        self.assertIn("not visible without Vault", output)
        self.assertIn("encrypted vars files: 1 present, not opened", output)

    def test_placeholder_group_values_completed_without_replacing_file(self):
        self.save(self.inventory_data())
        directory = self.inventory.parent / "group_vars/microlab_management"
        directory.mkdir(parents=True)
        manual = directory / "z-user-values.yml"
        manual.write_text("micolab_admin_cidrs: [REPLACE_ADMIN]\nmicolab_client_cidrs: []\nmicolab_expected_architecture: REPLACE_ARCH\nmicolab_technitium_admin_password: ''\nunknown: retained\n")
        original = manual.read_bytes()
        self.assertEqual(self.create(), 0, self.err.getvalue())
        with patch.object(cli.Vault, "read", return_value=self.generated):
            values = cli.local_vars(self.inventory, yaml.safe_load(self.inventory.read_text()), "infra-alias", cli.Vault())
        self.assertEqual(values["micolab_technitium_admin_password"], self.generated["micolab_technitium_admin_password"])
        self.assertEqual(values["micolab_admin_cidrs"], ["10.72.78.21/32"])
        self.assertEqual(values["unknown"], "retained")
        self.assertEqual(manual.read_bytes(), original)

    def test_flat_group_vars_not_hidden_by_new_directory(self):
        self.save(self.inventory_data())
        directory = self.inventory.parent / "group_vars"
        directory.mkdir()
        manual = directory / "microlab_management.yml"
        manual.write_text("unknown: retained\n")
        self.assertEqual(self.create(), 0, self.err.getvalue())
        self.assertFalse((directory / cli.MANAGEMENT).exists())
        self.assertTrue((self.inventory.parent / "host_vars/infra-alias").is_dir())
        self.assertEqual(manual.read_text(), "unknown: retained\n")

    def test_flat_host_vars_requires_protected_manual_merge(self):
        self.save(self.inventory_data())
        directory = self.inventory.parent / "host_vars"
        directory.mkdir()
        manual = directory / "infra-alias.yml"
        manual.write_text("unknown: retained\n")
        self.assertEqual(self.create(), 2)
        self.assertIn("protected manual merge", self.err.getvalue())
        self.assertFalse((directory / "infra-alias").exists())
        self.assertEqual(manual.read_text(), "unknown: retained\n")

    def test_duplicate_keys_refused_without_data_loss_or_echo(self):
        self.inventory.parent.mkdir(parents=True)
        self.inventory.write_text("secret: FIRST_SECRET\nsecret: SECOND_SECRET\n")
        original = self.inventory.read_bytes()
        self.assertEqual(self.run_cli(["setup", "--inventory", str(self.inventory)]), 2)
        self.assertEqual(self.inventory.read_bytes(), original)
        self.assertNotIn("FIRST_SECRET", self.err.getvalue())
        self.assertNotIn("SECOND_SECRET", self.err.getvalue())

    def test_artifact_contract(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/microlab_artifacts.py").touch()
        with patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(self.run_cli(["artifacts", "--inventory", str(self.inventory)]), 0)
        command = run.call_args.args[0]
        self.assertEqual(command[2:], ["--inventory", str(self.inventory), "--directory", str(self.root / "artifacts")])

    def test_artifact_offline_check_flags_and_exit_status_forwarded(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/microlab_artifacts.py").touch()
        with patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)) as run:
            self.assertEqual(self.run_cli(["artifacts", "--offline", "--check", "--inventory", str(self.inventory)]), 7)
        self.assertEqual(run.call_args.args[0][-2:], ["--offline", "--check"])

    def ready_values(self):
        ca = self.root / "offline-issued-public-and-intermediate-material"
        ca.touch()
        return {**dict.fromkeys(cli.CA_PATHS, str(ca)), **dict.fromkeys(cli.CA_VALUES, "protected-test-value"),
                **dict.fromkeys(cli.SECRET_KEYS, "protected-test-value"),
                "micolab_expected_architecture": "arm64", "micolab_admin_cidrs": ["10.72.78.21/32"],
                "micolab_client_cidrs": ["10.72.78.0/24"], "micolab_staged_artifacts": [{"name": "test"}]}

    def test_playbook_routing_and_infra_only_limit(self):
        (self.root / "playbooks").mkdir()
        for name in ("bootstrap", "deploy", "verify"):
            (self.root / "playbooks" / (name + ".yml")).touch()
        for command, credentials, expected in (("deploy", False, "bootstrap"), ("deploy", True, "deploy"), ("verify", True, "verify")):
            values = self.ready_values()
            if credentials:
                values.update(dict.fromkeys(cli.TOKENS, "PROTECTED_DO_NOT_LOG"))
            with patch.object(cli, "inspection", return_value=("infra-alias", values)), patch.object(cli, "need_tool"), patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
                self.assertEqual(self.run_cli([command, "--inventory", str(self.inventory)]), 0, self.err.getvalue())
            invocation = run.call_args.args[0]
            self.assertIn(str(self.root / "playbooks" / (expected + ".yml")), invocation)
            self.assertEqual(invocation[invocation.index("--limit") + 1], "localhost,infra-alias")
            self.assertIn("--ask-become-pass", invocation)
            self.assertNotIn("PROTECTED_DO_NOT_LOG", " ".join(invocation) + self.out.getvalue() + self.err.getvalue())

    def test_offline_ca_missing_blocks_before_any_playbook(self):
        values = self.ready_values()
        del values[cli.CA_PATHS[0]]
        with patch.object(cli, "inspection", return_value=("infra-alias", values)), patch.object(cli, "need_tool"), patch.object(cli.subprocess, "run") as run:
            self.assertEqual(self.run_cli(["deploy", "--inventory", str(self.inventory)]), 2)
        run.assert_not_called()
        self.assertIn("./microlab ca-init", self.err.getvalue())

    def test_consumed_enrollment_token_never_routes_to_bootstrap(self):
        (self.root / "playbooks").mkdir()
        (self.root / "playbooks/deploy.yml").touch()
        values = self.ready_values()
        values[cli.TOKENS[0]] = "PRIVATE_PERSISTENT_API_TOKEN"
        with patch.object(cli, "inspection", return_value=("infra-alias", values)), patch.object(cli, "need_tool"), patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(self.run_cli(["deploy", "--inventory", str(self.inventory)]), 2)
            run.assert_not_called()
            self.assertEqual(self.run_cli(["deploy", "--stage", "services", "--inventory", str(self.inventory)]), 0)
            self.assertIn(str(self.root / "playbooks/deploy.yml"), run.call_args.args[0])
        self.assertNotIn("PRIVATE_PERSISTENT_API_TOKEN", self.out.getvalue() + self.err.getvalue())

    def test_explicit_bootstrap_and_services_credential_checkpoint(self):
        (self.root / "playbooks").mkdir()
        (self.root / "playbooks/bootstrap.yml").touch()
        values = self.ready_values()
        with patch.object(cli, "inspection", return_value=("infra-alias", values)), patch.object(cli, "need_tool"), patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(self.run_cli(["deploy", "--stage", "services"]), 2)
            run.assert_not_called()
            self.assertEqual(self.run_cli(["deploy", "--stage", "bootstrap"]), 0)
            self.assertIn(str(self.root / "playbooks/bootstrap.yml"), run.call_args.args[0])

    def test_missing_phase_never_falls_back_to_site(self):
        with patch.object(cli, "inspection", return_value=("infra", self.ready_values())), patch.object(cli, "need_tool"), patch.object(cli.subprocess, "run") as run:
            self.assertEqual(self.run_cli(["deploy", "--inventory", str(self.inventory)]), 2)
        run.assert_not_called()
        self.assertIn("No fallback", self.err.getvalue())

    def test_noninteractive_vault_never_falls_back_to_echoed_password(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(cli.sys.stdin, "isatty", return_value=False), patch.object(cli, "need_tool"), patch.object(cli.subprocess, "run") as run:
            with self.assertRaisesRegex(cli.Checkpoint, "protected input"):
                cli.runtime_vars(self.inventory)
        run.assert_not_called()

    @unittest.skipUnless(shutil.which("ansible-vault"), "requires local Ansible Vault")
    def test_real_vault_roundtrip_rerun_does_not_rotate(self):
        self.assertEqual(self.run_cli(self.args), 0, self.err.getvalue())
        encrypted = self.inventory.parent / "group_vars/microlab_management/setup-vault.yml"
        original = encrypted.read_bytes()
        self.assertTrue(original.startswith(b"$ANSIBLE_VAULT;"))
        with cli.Vault() as vault:
            before = vault.read(encrypted)
        self.assertEqual(self.run_cli(self.args), 0, self.err.getvalue())
        self.assertEqual(encrypted.read_bytes(), original)
        self.assertFalse((encrypted.parent / "setup-vault-2.yml").exists())
        self.assertEqual(len(set(before.values())), len(cli.SECRET_KEYS))


if __name__ == "__main__":
    unittest.main()
