"""Regression tests for the step_ca state matrix and Technitium path rules.

These tests import the role filter plugins directly (they are pure standard
library) and also assert the safety-critical wiring in the Ansible task files.
They never contact a CA, a host, or a Technitium instance.
"""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


step_state = load_module(
    "step_ca_state", ROOT / "roles/step_ca/filter_plugins/step_ca_state.py"
)
technitium_paths = load_module(
    "technitium_paths",
    ROOT / "roles/technitium_tls/filter_plugins/technitium_paths.py",
)


def state(**overrides) -> dict:
    values = {
        "config_exists": False,
        "root_exists": False,
        "crt_exists": False,
        "key_exists": False,
        "password_exists": False,
        "db_exists": False,
        "db_nonempty": False,
        "initial_deploy": False,
        "recover_missing_config": False,
    }
    values.update(overrides)
    return values


COMPLETE_MATERIAL = {
    "root_exists": True,
    "crt_exists": True,
    "key_exists": True,
    "password_exists": True,
}


class StepCaStateTests(unittest.TestCase):
    def assert_action(self, expected: str, **overrides) -> dict:
        result = step_state.classify_step_ca_state(state(**overrides))
        self.assertEqual(
            result["action"], expected, msg=f"{overrides} -> {result}"
        )
        return result

    def test_normal_redeploy_requires_all_durable_state(self) -> None:
        self.assert_action(
            "normal",
            config_exists=True,
            db_exists=True,
            db_nonempty=True,
            **COMPLETE_MATERIAL,
        )

    def test_config_with_missing_material_fails_closed(self) -> None:
        result = self.assert_action(
            "fail",
            config_exists=True,
            db_exists=True,
            db_nonempty=True,
            root_exists=True,
            crt_exists=True,
            key_exists=True,
        )
        self.assertIn("Restore", result["reason"])

    def test_config_with_empty_database_fails_closed(self) -> None:
        self.assert_action(
            "fail",
            config_exists=True,
            db_exists=True,
            db_nonempty=False,
            **COMPLETE_MATERIAL,
        )

    def test_configuration_only_recovery_requires_nonempty_database(self) -> None:
        self.assert_action(
            "recover-config",
            recover_missing_config=True,
            db_exists=True,
            db_nonempty=True,
            **COMPLETE_MATERIAL,
        )

    def test_configuration_only_recovery_rejects_missing_database(self) -> None:
        result = self.assert_action(
            "fail",
            recover_missing_config=True,
            db_exists=False,
            db_nonempty=False,
            **COMPLETE_MATERIAL,
        )
        self.assertIn("empty database", result["reason"])

    def test_configuration_only_recovery_rejects_empty_database(self) -> None:
        self.assert_action(
            "fail",
            recover_missing_config=True,
            db_exists=True,
            db_nonempty=False,
            **COMPLETE_MATERIAL,
        )

    def test_configuration_only_recovery_rejects_missing_material(self) -> None:
        self.assert_action(
            "fail",
            recover_missing_config=True,
            db_exists=True,
            db_nonempty=True,
            root_exists=True,
            crt_exists=True,
            key_exists=True,
        )

    def test_first_deployment_remains_separate(self) -> None:
        self.assert_action(
            "initial-deploy",
            initial_deploy=True,
            db_exists=False,
            db_nonempty=False,
            **COMPLETE_MATERIAL,
        )
        self.assert_action(
            "initial-deploy",
            initial_deploy=True,
            db_exists=True,
            db_nonempty=False,
            **COMPLETE_MATERIAL,
        )

    def test_first_deployment_rejects_existing_database(self) -> None:
        result = self.assert_action(
            "fail",
            initial_deploy=True,
            db_exists=True,
            db_nonempty=True,
            **COMPLETE_MATERIAL,
        )
        self.assertIn("not a first deployment", result["reason"])

    def test_first_deployment_rejects_incomplete_material(self) -> None:
        self.assert_action(
            "fail",
            initial_deploy=True,
            root_exists=True,
            crt_exists=True,
            key_exists=True,
        )

    def test_neither_flag_fails_closed(self) -> None:
        self.assert_action(
            "fail",
            db_exists=True,
            db_nonempty=True,
            **COMPLETE_MATERIAL,
        )

    def test_both_flags_are_ambiguous_and_fail(self) -> None:
        result = self.assert_action(
            "fail",
            initial_deploy=True,
            recover_missing_config=True,
            db_exists=True,
            db_nonempty=True,
            **COMPLETE_MATERIAL,
        )
        self.assertIn("mutually exclusive", result["reason"])

    def test_unexpected_partial_state_fails_closed(self) -> None:
        self.assert_action(
            "fail",
            root_exists=True,
            db_exists=True,
            db_nonempty=True,
        )

    def test_empty_target_initial_deploy_with_valid_sources_is_allowed(self) -> None:
        result = self.assert_action(
            "initial-deploy",
            initial_deploy=True,
            source_material_valid=True,
        )
        self.assertTrue(result["material_none"])

    def test_empty_target_initial_deploy_rejects_invalid_sources(self) -> None:
        result = self.assert_action(
            "fail",
            initial_deploy=True,
            source_material_valid=False,
        )
        self.assertIn("controller source preflight", result["reason"])

    def test_partial_target_initial_deploy_never_becomes_a_new_ca(self) -> None:
        result = self.assert_action(
            "fail",
            initial_deploy=True,
            root_exists=True,
            crt_exists=True,
            key_exists=True,
            password_exists=True,
            password_valid=False,
        )
        self.assertIn("never replace partial material", result["reason"])

    def test_zero_byte_or_symlinked_material_is_not_complete(self) -> None:
        for prefix in ("root", "crt", "key", "password"):
            with self.subTest(prefix=prefix):
                overrides = {f"{prefix}_exists": True, f"{prefix}_valid": False}
                self.assert_action(
                    "fail",
                    initial_deploy=True,
                    **overrides,
                )

    def test_zero_byte_config_is_not_missing(self) -> None:
        result = self.assert_action(
            "fail",
            config_exists=True,
            config_valid=False,
            db_exists=True,
            db_nonempty=True,
            **COMPLETE_MATERIAL,
        )
        self.assertIn("not a regular non-empty file", result["reason"])

    def test_badgerv2_structure_is_required_for_recovery(self) -> None:
        good_files = [
            {"name": "MANIFEST", "isreg": True, "size": 32},
            {"name": "KEYREGISTRY", "isreg": True, "size": 20},
            {"name": "000000.vlog", "isreg": True, "size": 4096},
        ]
        result = self.assert_action(
            "recover-config",
            recover_missing_config=True,
            db_exists=True,
            db_type="badgerv2",
            db_files=good_files,
            **COMPLETE_MATERIAL,
        )
        self.assertTrue(result["has_durable_database"])

        for description, files in [
            ("empty directory", []),
            ("empty subdirectory", [{"name": "d", "isdir": True, "size": 4096}]),
            ("arbitrary file", [{"name": "notes.txt", "isreg": True, "size": 10}]),
            (
                "manifest without table",
                [{"name": "MANIFEST", "isreg": True, "size": 32}],
            ),
            (
                "zero-byte manifest",
                [
                    {"name": "MANIFEST", "isreg": True, "size": 0},
                    {"name": "000000.vlog", "isreg": True, "size": 4096},
                ],
            ),
        ]:
            with self.subTest(description=description):
                result = self.assert_action(
                    "fail",
                    recover_missing_config=True,
                    db_exists=True,
                    db_type="badgerv2",
                    db_files=files,
                    **COMPLETE_MATERIAL,
                )
                self.assertIn("database", result["reason"])

    def test_database_backend_policy_is_explicit(self) -> None:
        result = step_state.classify_step_ca_state(
            state(
                initial_deploy=True,
                db_exists=True,
                db_type="bbolt",
                db_files=[{"name": "MANIFEST", "isreg": True, "size": 32}],
            )
        )
        self.assertEqual(result["action"], "fail")
        self.assertIn("only accepts badgerv2", result["reason"])


class TechnitiumPathTests(unittest.TestCase):
    CASES = [
        ("/etc/dns/tls/dns.pfx", "/etc/dns", "tls/dns.pfx"),
        ("tls/dns.pfx", "/etc/dns", "tls/dns.pfx"),
        ("./tls/dns.pfx", "/etc/dns", "tls/dns.pfx"),
        ("/etc/dns/tls/dns.pfx", "/etc/dns/", "tls/dns.pfx"),
        ("/etc/technitium/dns.pfx", "/etc/dns", "/etc/technitium/dns.pfx"),
        ("/etc/dns2/dns.pfx", "/etc/dns", "/etc/dns2/dns.pfx"),
        ("/etc/dns", "/etc/dns", "/etc/dns"),
        ("", "/etc/dns", ""),
    ]

    def test_matches_technitium_relative_storage(self) -> None:
        for path, config_dir, expected in self.CASES:
            with self.subTest(path=path, config_dir=config_dir):
                self.assertEqual(
                    technitium_paths.technitium_api_path(path, config_dir),
                    expected,
                )

    def test_normalisation_is_idempotent(self) -> None:
        for path, config_dir, expected in self.CASES:
            with self.subTest(path=path, config_dir=config_dir):
                once = technitium_paths.technitium_api_path(path, config_dir)
                twice = technitium_paths.technitium_api_path(once, config_dir)
                self.assertEqual(once, twice)
                self.assertEqual(twice, expected)


class StepCaWiringTests(unittest.TestCase):
    def test_provisioners_response_is_unwrapped_and_bounded(self) -> None:
        text = (ROOT / "roles/step_ca/tasks/service.yml").read_text()
        self.assertIn("/provisioners?limit=100", text)
        self.assertIn(".get('provisioners', [])", text)
        self.assertIn(".get('nextCursor', '')", text)
        self.assertIn(
            "(microlab_step_ca_live_provisioners_next | default('')) | length == 0",
            text,
        )
        # The raw object must never be mapped as if it were a bare list.
        self.assertNotIn(
            "microlab_step_ca_provisioners.stdout\n         | from_json\n"
            "         | map(attribute='name')",
            text,
        )

    def test_configuration_recovery_is_separate_from_first_deployment(self) -> None:
        preflight = (
            ROOT / "roles/step_ca/tasks/preflight.yml"
        ).read_text()
        configure = (ROOT / "roles/step_ca/tasks/configure.yml").read_text()
        deploy = (
            ROOT / "roles/step_ca/tasks/deploy_material.yml"
        ).read_text()
        self.assertIn("step_ca_state", preflight)
        self.assertIn("microlab_step_ca_db_contents.files", preflight)
        self.assertIn("db_type", preflight)
        self.assertIn(
            "microlab_step_ca_state.action in ['normal', 'initial-deploy', "
            "'recover-config']",
            preflight,
        )
        # Recovery re-renders config only; the material deploy file is reached
        # exclusively through the explicit initial-deploy transition.
        self.assertIn(
            "microlab_step_ca_state.action == 'initial-deploy'", configure
        )
        self.assertIn("microlab_step_ca_state.action != 'recover-config'", configure)
        self.assertIn("verify_material.yml", deploy)
        self.assertNotIn("microlab_step_ca_partial_state", configure)
        self.assertNotIn("microlab_step_ca_required_state_missing", configure)

    def test_controller_source_preflight_is_delegated_and_ordered(self) -> None:
        main = (ROOT / "roles/step_ca/tasks/main.yml").read_text()
        source = (ROOT / "roles/step_ca/tasks/source_preflight.yml").read_text()
        preflight = (ROOT / "roles/step_ca/tasks/preflight.yml").read_text()

        # Source validation runs on the controller before install.yml writes
        # anything to the target.
        self.assertLess(
            main.index("import_tasks: source_preflight.yml"),
            main.index("import_tasks: install.yml"),
        )
        self.assertIn("delegate_to: localhost", source)
        self.assertIn("become: false", source)
        self.assertIn("apply:", source)
        self.assertIn("startswith('/')", source)
        self.assertIn("microlab_step_ca_sources_preflighted", preflight)

        # The controller-only stat/verify chain must not be back in the target
        # preflight, and the target root-key scan must use registered target
        # facts rather than the controller-side `is exists` test.
        self.assertNotIn("microlab_step_ca_source_stat", preflight)
        self.assertNotIn("when: microlab_step_ca_home is exists", preflight)
        self.assertNotIn("- microlab_step_ca_home is exists", preflight)
        self.assertIn("microlab_step_ca_home_exists", preflight)
        self.assertIn('"*root*private*"', preflight)

    def test_caddy_acme_provisioner_default_is_acme(self) -> None:
        defaults = (ROOT / "roles/step_ca/defaults/main.yml").read_text()
        group_vars = (ROOT / "group_vars/all.yml").read_text()
        self.assertIn("microlab_step_ca_caddy_provisioner_name: acme", defaults)
        self.assertIn("micolab_step_ca_caddy_provisioner_name: acme", group_vars)
        self.assertNotIn("caddy_provisioner_name: microlab-caddy", defaults)
        validate = (ROOT / "roles/step_ca/tasks/validate.yml").read_text()
        self.assertIn(
            "microlab_step_ca_caddy_provisioner_name == 'acme'", validate
        )

    def test_jwk_uses_explicit_server_only_template(self) -> None:
        ca_template = (ROOT / "roles/step_ca/templates/ca.json.j2").read_text()
        leaf_template = (
            ROOT / "roles/step_ca/files/technitium-x509.template.json"
        ).read_text()
        self.assertIn("technitium-x509.template.json", ca_template)
        self.assertIn('"options"', ca_template)
        self.assertIn('"x509"', ca_template)
        self.assertIn('"extKeyUsage": ["serverAuth"]', leaf_template)
        self.assertNotIn("clientAuth", leaf_template)
        self.assertIn('"sans": {{ toJson .SANs }}', leaf_template)


class TechnitiumWiringTests(unittest.TestCase):
    def test_helper_config_directory_is_created_before_env_template(self) -> None:
        text = (
            ROOT / "roles/technitium_tls/tasks/install_helper.yml"
        ).read_text()
        create_at = text.index(
            "Create the protected Technitium TLS configuration directory"
        )
        template_at = text.index("Write the protected renewal environment")
        self.assertLess(create_at, template_at)
        self.assertIn(
            'path: "{{ microlab_technitium_renewal_env_file | dirname }}"', text
        )
        self.assertIn('mode: "0700"', text)

    def test_runtime_lock_and_status_are_durable(self) -> None:
        service = (
            ROOT / "roles/technitium_tls/templates/"
            "technitium-tls-renew.service.j2"
        ).read_text()
        defaults = (
            ROOT / "roles/technitium_tls/defaults/main.yml"
        ).read_text()
        self.assertIn("StateDirectory={{ microlab_technitium_state_directory_name }}", service)
        self.assertIn("StateDirectoryMode=0750", service)
        self.assertNotIn("RuntimeDirectory=", service)
        self.assertIn('microlab_technitium_state_dir: "/var/lib/', defaults)
        self.assertIn(
            'microlab_technitium_lock_file: "{{ microlab_technitium_state_dir }}/renew.lock"',
            defaults,
        )
        self.assertIn(
            'microlab_technitium_status_file: "{{ microlab_technitium_state_dir }}/status.json"',
            defaults,
        )

    def test_api_path_comparison_is_normalised(self) -> None:
        text = (
            ROOT / "roles/technitium_tls/tasks/configure_api.yml"
        ).read_text()
        self.assertIn("technitium_api_path", text)
        self.assertIn("microlab_technitium_pfx_api_path", text)
        self.assertIn("microlab_technitium_current_settings_normalized", text)
        self.assertIn("microlab_technitium_verified_settings_normalized", text)
        self.assertNotIn(
            'dnsTlsCertificatePath: "{{ microlab_technitium_pfx_path }}"', text
        )

    def test_verify_budget_covers_technitium_watcher(self) -> None:
        defaults = (
            ROOT / "roles/technitium_tls/defaults/main.yml"
        ).read_text()
        retries = int(re.search(r"microlab_technitium_verify_retries: (\d+)", defaults).group(1))
        delay = int(re.search(r"microlab_technitium_verify_delay: (\d+)", defaults).group(1))
        self.assertGreaterEqual((retries - 1) * delay, 60)


if __name__ == "__main__":
    unittest.main()
