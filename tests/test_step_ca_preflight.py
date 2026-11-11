"""Single-host integration tests for the step_ca preflight.

These tests run the role's actual ``tasks/source_preflight.yml``,
``tasks/preflight.yml``, and first-deploy ``tasks/deploy_material.yml`` through
``ansible-playbook`` on localhost. They do not contact a host or a CA service.
A throwaway root/intermediate CA is generated with OpenSSL, and target trees are
built in temporary directories so the tests exercise stat/find results, symlink
handling, OpenSSL validation, and the badgerv2 database policy instead of
feeding pre-classified booleans to the filter.

Scope limit: controller and target are the same localhost, so these tests
cannot detect a task that observes a controller path on the target or vice
versa. ``tests/test_step_ca_cross_host.py`` exercises that split with an
isolated target filesystem. Neither file runs the full configure/service path.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.stepca_material import (  # noqa: E402
    OPENSSL,
    PASSWORD,
    TMP_ROOT,
    file_digest,
    generate_ca_material,
    tree_snapshot,
)

PLAYBOOK = ROOT / "tests/ansible/preflight.yml"
FILTER_PLUGINS = ROOT / "roles/step_ca/filter_plugins"
ANSIBLE_PLAYBOOK = os.environ.get(
    "ANSIBLE_PLAYBOOK",
    shutil.which("ansible-playbook") or "/tmp/opencode/ansvenv/bin/ansible-playbook",
)


@unittest.skipUnless(
    Path(ANSIBLE_PLAYBOOK).exists() and OPENSSL is not None,
    "ansible-playbook and openssl are required for preflight integration tests",
)
class StepCaPreflightIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="stepca-preflight-src-")
        cls.source = Path(cls.tmp.name) / "source"
        cls.source.mkdir()
        material = generate_ca_material(cls.source)
        cls.root_key = material.root_key
        cls.root_cert = material.root_cert
        cls.intermediate_key = material.intermediate_key
        cls.intermediate_csr = material.intermediate_csr
        cls.intermediate_cert = material.intermediate_cert
        cls.password_file = material.password_file
        cls.fingerprint_normalized = material.fingerprint_normalized
        cls.owner = pwd.getpwuid(os.getuid()).pw_name
        cls.group = grp.getgrgid(os.getgid()).gr_name

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def make_target(self, dirs: tuple[str, ...] = ("config", "certs", "secrets", "db")) -> Path:
        target = Path(tempfile.mkdtemp(prefix="stepca-target-", dir=str(TMP_ROOT)))
        self.addCleanup(shutil.rmtree, target, True)
        for name in dirs:
            (target / name).mkdir()
        return target

    def install_material(self, target: Path, omit: str | None = None) -> None:
        if omit != "root":
            shutil.copy2(self.root_cert, target / "certs/root_ca.crt")
        if omit != "crt":
            shutil.copy2(self.intermediate_cert, target / "certs/intermediate_ca.crt")
        if omit != "key":
            shutil.copy2(self.intermediate_key, target / "secrets/intermediate_ca_key")
        if omit != "password":
            shutil.copy2(self.password_file, target / "secrets/password")

    def write_badger_db(self, target: Path) -> None:
        db = target / "db"
        (db / "MANIFEST").write_bytes(b"badger-v2-manifest\n")
        (db / "KEYREGISTRY").write_bytes(b"badger-v2-keyregistry\n")
        (db / "000000.vlog").write_bytes(b"badger-v2-value-log\n")

    def write_config(self, target: Path) -> None:
        (target / "config/ca.json").write_text('{"test": true}\n')

    def run_preflight(
        self,
        target: Path,
        *,
        initial_deploy: bool = False,
        recover_missing_config: bool = False,
        source: Path | None = None,
        fingerprint: str | None = None,
    ) -> subprocess.CompletedProcess:
        source = source or self.source
        fingerprint = fingerprint or self.fingerprint_normalized
        variables = {
            "microlab_step_ca_home": str(target),
            "microlab_step_ca_config_dir": str(target / "config"),
            "microlab_step_ca_certs_dir": str(target / "certs"),
            "microlab_step_ca_secrets_dir": str(target / "secrets"),
            "microlab_step_ca_db_dir": str(target / "db"),
            "microlab_step_ca_config_file": str(target / "config/ca.json"),
            "microlab_step_ca_root_cert_dest": str(target / "certs/root_ca.crt"),
            "microlab_step_ca_intermediate_cert_dest": str(
                target / "certs/intermediate_ca.crt"
            ),
            "microlab_step_ca_intermediate_key_dest": str(
                target / "secrets/intermediate_ca_key"
            ),
            "microlab_step_ca_password_dest": str(target / "secrets/password"),
            "microlab_step_ca_root_cert_src": str(source / "root_ca.crt"),
            "microlab_step_ca_intermediate_cert_src": str(
                source / "intermediate_ca.crt"
            ),
            "microlab_step_ca_intermediate_key_src": str(
                source / "intermediate_ca_key"
            ),
            "microlab_step_ca_intermediate_key_password": PASSWORD,
            "microlab_step_ca_root_fingerprint_sha256": fingerprint,
            "microlab_step_ca_root_fingerprint_normalized": fingerprint,
            "microlab_step_ca_initial_deploy": initial_deploy,
            "microlab_step_ca_recover_missing_config": recover_missing_config,
            "microlab_step_ca_db_type": "badgerv2",
            "microlab_step_ca_user": self.owner,
            "microlab_step_ca_group": self.group,
            "microlab_step_ca_root_cert_owner": self.owner,
            "microlab_step_ca_root_cert_group": self.group,
        }
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            prefix="stepca-vars-",
            suffix=".json",
            dir=str(TMP_ROOT),
            delete=False,
        )
        try:
            json.dump(variables, handle)
            handle.close()
            env = os.environ.copy()
            env.update(
                {
                    "ANSIBLE_BECOME": "false",
                    "ANSIBLE_FILTER_PLUGINS": str(FILTER_PLUGINS),
                    "ANSIBLE_LOCALHOST_WARNING": "false",
                    "ANSIBLE_INVENTORY_UNPARSED_WARNING": "false",
                }
            )
            return subprocess.run(
                [
                    ANSIBLE_PLAYBOOK,
                    "-i",
                    "localhost,",
                    "-c",
                    "local",
                    str(PLAYBOOK),
                    "-e",
                    "@" + handle.name,
                ],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
            )
        finally:
            Path(handle.name).unlink(missing_ok=True)

    def assert_ok(
        self, result: subprocess.CompletedProcess, action: str
    ) -> None:
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=output)
        self.assertIn(f'"action": "{action}"', result.stdout, msg=output)

    def assert_fail(self, result: subprocess.CompletedProcess, text: str) -> None:
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, msg=output)
        self.assertIn(text, output)

    def test_fresh_empty_target_with_valid_sources_initializes(self) -> None:
        target = self.make_target()
        result = self.run_preflight(target, initial_deploy=True)
        self.assert_ok(result, "initial-deploy")
        # The harness runs the same guarded deploy include as configure.yml.
        self.assertTrue((target / "certs/root_ca.crt").is_file())
        self.assertTrue((target / "certs/intermediate_ca.crt").is_file())
        self.assertTrue((target / "secrets/intermediate_ca_key").is_file())
        self.assertTrue((target / "secrets/password").is_file())

    def test_fresh_empty_target_without_database_directory_initializes(self) -> None:
        target = self.make_target(("config", "certs", "secrets"))
        result = self.run_preflight(target, initial_deploy=True)
        self.assert_ok(result, "initial-deploy")
        self.assertIn('"action": "initial-deploy"', result.stdout)

    def test_initial_deploy_rejects_incomplete_controller_sources(self) -> None:
        bad_source = Path(tempfile.mkdtemp(prefix="stepca-badsrc-", dir=str(TMP_ROOT)))
        self.addCleanup(shutil.rmtree, bad_source, True)
        shutil.copy2(self.root_cert, bad_source / "root_ca.crt")
        shutil.copy2(self.intermediate_cert, bad_source / "intermediate_ca.crt")
        (bad_source / "intermediate_ca_key").write_bytes(b"")
        target = self.make_target()
        result = self.run_preflight(
            target, initial_deploy=True, source=bad_source
        )
        self.assert_fail(result, "complete, regular, non-empty")

    def test_partial_target_initial_deploy_fails(self) -> None:
        target = self.make_target()
        shutil.copy2(self.root_cert, target / "certs/root_ca.crt")
        result = self.run_preflight(target, initial_deploy=True)
        self.assert_fail(result, "not a partial target")

    def test_recovery_rejects_missing_material(self) -> None:
        target = self.make_target()
        self.install_material(target, omit="password")
        self.write_badger_db(target)
        result = self.run_preflight(target, recover_missing_config=True)
        self.assert_fail(result, "configuration-only recovery requires")

    def test_recovery_rejects_wrong_password_without_writing(self) -> None:
        target = self.make_target()
        self.install_material(target)
        self.write_badger_db(target)
        (target / "secrets/password").write_text("wrong-password\n")
        result = self.run_preflight(target, recover_missing_config=True)
        self.assert_fail(result, "does not match the intermediate certificate")

    def test_recovery_rejects_fingerprint_mismatch_without_writing(self) -> None:
        target = self.make_target()
        self.install_material(target)
        self.write_badger_db(target)
        result = self.run_preflight(
            target,
            recover_missing_config=True,
            fingerprint="00" * 32,
        )
        self.assert_fail(result, "does not match the pinned SHA-256 fingerprint")

    def test_recovery_rejects_zero_byte_material(self) -> None:
        target = self.make_target()
        self.install_material(target)
        self.write_badger_db(target)
        (target / "secrets/intermediate_ca_key").write_bytes(b"")
        result = self.run_preflight(target, recover_missing_config=True)
        self.assert_fail(result, "empty, symlinks")

    def test_recovery_rejects_symlinked_material(self) -> None:
        target = self.make_target()
        self.install_material(target)
        self.write_badger_db(target)
        linked = target / "certs/intermediate_ca.crt"
        linked.unlink()
        linked.symlink_to(self.intermediate_cert)
        result = self.run_preflight(target, recover_missing_config=True)
        self.assert_fail(result, "empty, symlinks")

    def test_recovery_rejects_empty_subdirectory_database(self) -> None:
        target = self.make_target()
        self.install_material(target)
        (target / "db/000").mkdir()
        result = self.run_preflight(target, recover_missing_config=True)
        self.assert_fail(result, "empty subdirectory")

    def test_recovery_rejects_arbitrary_nondata_database_entries(self) -> None:
        target = self.make_target()
        self.install_material(target)
        (target / "db/notes.txt").write_text("not a database\n")
        result = self.run_preflight(target, recover_missing_config=True)
        self.assert_fail(result, "arbitrary")

    def test_complete_recovery_passes_without_touching_key_or_db(self) -> None:
        target = self.make_target()
        self.install_material(target)
        self.write_badger_db(target)
        before = tree_snapshot(
            [
                target / "secrets/intermediate_ca_key",
                target / "secrets/password",
                target / "db",
            ]
        )
        result = self.run_preflight(target, recover_missing_config=True)
        self.assert_ok(result, "recover-config")
        after = tree_snapshot(
            [
                target / "secrets/intermediate_ca_key",
                target / "secrets/password",
                target / "db",
            ]
        )
        self.assertEqual(before, after)
        self.assertFalse((target / "config/ca.json").exists())

    def test_ordinary_rerun_is_stable(self) -> None:
        target = self.make_target()
        self.install_material(target)
        self.write_badger_db(target)
        self.write_config(target)
        before = tree_snapshot(
            [
                target / "certs",
                target / "secrets/intermediate_ca_key",
                target / "secrets/password",
                target / "db",
            ]
        )
        first = self.run_preflight(target)
        second = self.run_preflight(target)
        self.assert_ok(first, "normal")
        self.assert_ok(second, "normal")
        self.assertIn("changed=0", first.stdout)
        self.assertIn("changed=0", second.stdout)
        after = tree_snapshot(
            [
                target / "certs",
                target / "secrets/intermediate_ca_key",
                target / "secrets/password",
                target / "db",
            ]
        )
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
