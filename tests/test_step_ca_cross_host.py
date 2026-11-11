"""Cross-host tests for the step_ca controller/target split.

``tests/test_step_ca_preflight.py`` runs both halves on one localhost, so the
controller and target share a filesystem and cannot catch a task that observes
the controller path on the target (or vice versa).

These tests run the same role task files through Ansible with two logical hosts:

* the controller is an ordinary ``connection: local`` host;
* the target uses the test-only ``stepca_isolated`` connection, which executes
  modules inside a bubblewrap mount namespace. The controller source directory
  is masked or overlaid, so the target genuinely sees different bytes.

The sandbox is test infrastructure, not a real remote host. These tests prove
task delegation and filesystem selection through Ansible; they do not exercise
the full configure/service path, SSH transport, or a live CA. The role's own
``deploy_material`` include runs for first-deployment cases so the deployed
bytes can be compared with the controller source.
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
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.stepca_material import (  # noqa: E402
    OPENSSL,
    TMP_ROOT,
    CaMaterial,
    file_digest,
    generate_ca_material,
)

PLAYBOOK = ROOT / "tests/ansible/cross_host_preflight.yml"
CONNECTION_PLUGINS = ROOT / "tests/plugins/connection"
FILTER_PLUGINS = ROOT / "roles/step_ca/filter_plugins"
ANSIBLE_PLAYBOOK = os.environ.get(
    "ANSIBLE_PLAYBOOK",
    shutil.which("ansible-playbook") or "/tmp/opencode/ansvenv/bin/ansible-playbook",
)
BWRAP = os.environ.get("STEPCA_SANDBOX_BWRAP", shutil.which("bwrap") or "/usr/bin/bwrap")

# This path intentionally does not exist on the controller; the sandbox creates
# it under a private tmpfs. The random suffix keeps a stray host path from
# making the test pass or fail for the wrong reason. That makes the old
# `microlab_step_ca_home is exists` controller-side condition observably wrong.
SANDBOX_HOME = "/srv/stepca-target-" + uuid.uuid4().hex[:12]


def sandbox_available() -> bool:
    if OPENSSL is None or not Path(ANSIBLE_PLAYBOOK).exists():
        return False
    if not Path(BWRAP).exists() or not Path("/srv").is_dir():
        return False
    probe = subprocess.run(
        [
            BWRAP,
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--",
            "/bin/true",
        ],
        capture_output=True,
        text=True,
    )
    return probe.returncode == 0


@unittest.skipUnless(
    sandbox_available(),
    "ansible-playbook, openssl, and a working bubblewrap are required for "
    "cross-host preflight tests",
)
class StepCaCrossHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="stepca-cross-host-")
        cls.base = Path(cls.tmp.name)
        cls.controller_source = cls.base / "controller-source"
        cls.controller_source.mkdir()
        cls.material = generate_ca_material(cls.controller_source)
        cls.owner = pwd.getpwuid(os.getuid()).pw_name
        cls.group = grp.getgrgid(os.getgid()).gr_name
        cls.controller_digests = {
            name: file_digest(cls.controller_source / name)
            for name in ("root_ca.crt", "intermediate_ca.crt", "intermediate_ca_key")
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def make_target(
        self, dirs: tuple[str, ...] = ("config", "certs", "secrets", "db")
    ) -> Path:
        target = Path(tempfile.mkdtemp(prefix="stepca-sandbox-target-", dir=str(TMP_ROOT)))
        self.addCleanup(shutil.rmtree, target, True)
        for name in dirs:
            (target / name).mkdir()
        (target / ".ansible-tmp").mkdir()
        (target / ".tmp").mkdir()
        return target

    def write_badger_db(self, target: Path) -> None:
        db = target / "db"
        (db / "MANIFEST").write_bytes(b"badger-v2-manifest\n")
        (db / "KEYREGISTRY").write_bytes(b"badger-v2-keyregistry\n")
        (db / "000000.vlog").write_bytes(b"badger-v2-value-log\n")

    def install_from_material(
        self, target: Path, material: CaMaterial, *, password: str | None = None
    ) -> None:
        shutil.copy2(material.root_cert, target / "certs/root_ca.crt")
        shutil.copy2(material.intermediate_cert, target / "certs/intermediate_ca.crt")
        shutil.copy2(material.intermediate_key, target / "secrets/intermediate_ca_key")
        if password is None:
            shutil.copy2(material.password_file, target / "secrets/password")
        else:
            (target / "secrets/password").write_text(password + "\n")

    def write_config(self, target: Path) -> None:
        (target / "config/ca.json").write_text('{"test": true}\n')

    def run_cross_host(
        self,
        target: Path,
        *,
        initial_deploy: bool = False,
        recover_missing_config: bool = False,
        masks: list[str] | None = None,
        extra_binds: list[list[str]] | None = None,
        source_paths: dict[str, str] | None = None,
        skip_source_preflight: bool = False,
    ) -> subprocess.CompletedProcess:
        binds = [[str(target), SANDBOX_HOME]]
        binds.extend(extra_binds or [])
        environment = {
            "STEPCA_SANDBOX_BINDS": json.dumps(binds),
            "STEPCA_SANDBOX_MASKS": json.dumps(masks or []),
            "STEPCA_SANDBOX_TMPFS": json.dumps(["/srv"]),
            "STEPCA_SANDBOX_DIRS": json.dumps([SANDBOX_HOME]),
            "STEPCA_SANDBOX_TMPDIR": SANDBOX_HOME + "/.tmp",
        }
        sources = {
            "microlab_step_ca_root_cert_src": str(
                self.controller_source / "root_ca.crt"
            ),
            "microlab_step_ca_intermediate_cert_src": str(
                self.controller_source / "intermediate_ca.crt"
            ),
            "microlab_step_ca_intermediate_key_src": str(
                self.controller_source / "intermediate_ca_key"
            ),
        }
        sources.update(source_paths or {})
        variables = {
            "microlab_step_ca_home": SANDBOX_HOME,
            "microlab_step_ca_config_dir": SANDBOX_HOME + "/config",
            "microlab_step_ca_certs_dir": SANDBOX_HOME + "/certs",
            "microlab_step_ca_secrets_dir": SANDBOX_HOME + "/secrets",
            "microlab_step_ca_db_dir": SANDBOX_HOME + "/db",
            "microlab_step_ca_config_file": SANDBOX_HOME + "/config/ca.json",
            "microlab_step_ca_root_cert_dest": SANDBOX_HOME + "/certs/root_ca.crt",
            "microlab_step_ca_intermediate_cert_dest": SANDBOX_HOME
            + "/certs/intermediate_ca.crt",
            "microlab_step_ca_intermediate_key_dest": SANDBOX_HOME
            + "/secrets/intermediate_ca_key",
            "microlab_step_ca_password_dest": SANDBOX_HOME + "/secrets/password",
            "microlab_step_ca_root_cert_src": sources[
                "microlab_step_ca_root_cert_src"
            ],
            "microlab_step_ca_intermediate_cert_src": sources[
                "microlab_step_ca_intermediate_cert_src"
            ],
            "microlab_step_ca_intermediate_key_src": sources[
                "microlab_step_ca_intermediate_key_src"
            ],
            "microlab_step_ca_intermediate_key_password": self.material.password,
            "microlab_step_ca_root_fingerprint_sha256": (
                self.material.fingerprint_normalized
            ),
            "microlab_step_ca_root_fingerprint_normalized": (
                self.material.fingerprint_normalized
            ),
            "microlab_test_skip_source_preflight": skip_source_preflight,
            "microlab_step_ca_initial_deploy": initial_deploy,
            "microlab_step_ca_recover_missing_config": recover_missing_config,
            "microlab_step_ca_db_type": "badgerv2",
            "microlab_step_ca_user": self.owner,
            "microlab_step_ca_group": self.group,
            "microlab_step_ca_root_cert_owner": self.owner,
            "microlab_step_ca_root_cert_group": self.group,
        }
        inventory = self.base / "inventory"
        inventory.write_text(
            "[stepca_target]\n"
            "target "
            "ansible_connection=stepca_isolated "
            "ansible_pipelining=true "
            f"ansible_remote_tmp={SANDBOX_HOME}/.ansible-tmp "
            "ansible_python_interpreter=/usr/bin/python3 "
            "ansible_become=false\n"
            "[local]\n"
            f"localhost ansible_connection=local "
            f"ansible_python_interpreter={sys.executable}\n"
        )
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            prefix="stepca-cross-vars-",
            suffix=".json",
            dir=str(TMP_ROOT),
            delete=False,
        )
        try:
            json.dump(variables, handle)
            handle.close()
            env = os.environ.copy()
            env.update(environment)
            env.update(
                {
                    "ANSIBLE_CONNECTION_PLUGINS": str(CONNECTION_PLUGINS),
                    "ANSIBLE_FILTER_PLUGINS": str(FILTER_PLUGINS),
                    "ANSIBLE_BECOME": "false",
                    "ANSIBLE_LOCALHOST_WARNING": "false",
                    "ANSIBLE_INVENTORY_UNPARSED_WARNING": "false",
                }
            )
            return subprocess.run(
                [
                    ANSIBLE_PLAYBOOK,
                    "-i",
                    str(inventory),
                    str(PLAYBOOK),
                    "-e",
                    "@" + handle.name,
                ],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=240,
            )
        finally:
            Path(handle.name).unlink(missing_ok=True)

    def assert_ok(self, result: subprocess.CompletedProcess, action: str) -> None:
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=output)
        self.assertIn(f'"action": "{action}"', result.stdout, msg=output)

    def assert_fail(self, result: subprocess.CompletedProcess, text: str) -> None:
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, msg=output)
        self.assertIn(text, output)

    # --- controller-only sources -------------------------------------------

    def test_source_only_on_controller_validates_and_deploys(self) -> None:
        target = self.make_target(("config", "certs", "secrets"))
        result = self.run_cross_host(
            target,
            initial_deploy=True,
            masks=[str(self.controller_source)],
        )
        self.assert_ok(result, "initial-deploy")
        # The target could not see the controller directory at all.
        self.assertIn("target_source_exists=False", result.stdout)
        for name, destination in (
            ("root_ca.crt", target / "certs/root_ca.crt"),
            ("intermediate_ca.crt", target / "certs/intermediate_ca.crt"),
            ("intermediate_ca_key", target / "secrets/intermediate_ca_key"),
        ):
            self.assertTrue(destination.is_file())
            self.assertEqual(file_digest(destination), self.controller_digests[name])

    def test_same_name_target_source_cannot_override_controller_bytes(self) -> None:
        target = self.make_target(("config", "certs", "secrets"))
        mirror = self.base / "target-view-of-source"
        mirror.mkdir()
        other = generate_ca_material(self.base / "other-ca")
        shutil.copy2(other.root_cert, mirror / "root_ca.crt")
        shutil.copy2(other.intermediate_cert, mirror / "intermediate_ca.crt")
        shutil.copy2(other.intermediate_key, mirror / "intermediate_ca_key")
        self.assertNotEqual(
            file_digest(mirror / "root_ca.crt"), self.controller_digests["root_ca.crt"]
        )
        result = self.run_cross_host(
            target,
            initial_deploy=True,
            extra_binds=[[str(mirror), str(self.controller_source)]],
        )
        # The target genuinely saw different bytes at the source path...
        self.assertIn("target_source_exists=True", result.stdout)
        # ...yet validation used the controller bytes and the deployment copied
        # those bytes, not the same-named target files.
        self.assert_ok(result, "initial-deploy")
        self.assertEqual(
            file_digest(target / "certs/root_ca.crt"),
            self.controller_digests["root_ca.crt"],
        )
        self.assertEqual(
            file_digest(target / "certs/intermediate_ca.crt"),
            self.controller_digests["intermediate_ca.crt"],
        )
        self.assertEqual(
            file_digest(target / "secrets/intermediate_ca_key"),
            self.controller_digests["intermediate_ca_key"],
        )

    def test_relative_controller_source_paths_are_rejected(self) -> None:
        target = self.make_target(("config", "certs", "secrets"))
        result = self.run_cross_host(
            target,
            initial_deploy=True,
            source_paths={
                "microlab_step_ca_root_cert_src": "controller-source/root_ca.crt"
            },
        )
        self.assert_fail(result, "absolute controller paths")

    # --- target-only state -------------------------------------------------

    def test_target_preflight_rejects_unvalidated_sources(self) -> None:
        target = self.make_target(("config", "certs", "secrets"))
        result = self.run_cross_host(
            target,
            initial_deploy=True,
            masks=[str(self.controller_source)],
            skip_source_preflight=True,
        )
        self.assert_fail(result, "tasks/source_preflight.yml")

    def test_target_only_root_escrow_file_is_detected(self) -> None:
        # /srv/stepca-target never exists on the controller, so the old
        # `microlab_step_ca_home is exists` condition would skip this scan.
        self.assertFalse(Path(SANDBOX_HOME).exists())
        for filename in ("root_ca_private.pem", "root_ca_private_key"):
            with self.subTest(filename=filename):
                target = self.make_target(("config", "certs", "secrets"))
                (target / "secrets" / filename).write_text("escrowed-root-key\n")
                result = self.run_cross_host(
                    target,
                    initial_deploy=True,
                    masks=[str(self.controller_source)],
                )
                self.assert_fail(result, "Root private key material was found")
                self.assertNotIn("initial-deploy", result.stdout)

    def test_target_only_documented_root_key_path_is_detected(self) -> None:
        target = self.make_target(("config", "certs", "secrets"))
        (target / "secrets/root_ca_key").write_text("escrowed-root-key\n")
        result = self.run_cross_host(target, initial_deploy=True)
        self.assert_fail(result, "A root private key was found at")

    def test_target_material_validation_stays_on_target(self) -> None:
        target = self.make_target()
        self.install_from_material(target, self.material, password="wrong-password")
        self.write_badger_db(target)
        self.write_config(target)
        # The controller sources are valid, so a check that accidentally ran on
        # the controller would pass. The target password file must fail.
        result = self.run_cross_host(target)
        self.assert_fail(
            result, "deployed intermediate private key does not match"
        )


if __name__ == "__main__":
    unittest.main()
