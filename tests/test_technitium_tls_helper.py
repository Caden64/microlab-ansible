"""Tests for the offline Technitium TLS renewal helper.

These tests exercise the helper's certificate validation, locking, atomic PFX
publication, and publication-retry behavior without contacting a CA, a DNS
server, or a systemd unit.
"""

from __future__ import annotations

import dataclasses
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HELPER_PATH = (
    Path(__file__).resolve().parents[1]
    / "roles"
    / "technitium_tls"
    / "files"
    / "technitium-tls-renew"
)


def load_helper():
    loader = importlib.machinery.SourceFileLoader("technitium_tls_renew", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves string annotations through sys.modules on 3.14+.
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


helper = load_helper()


def openssl_available() -> bool:
    return shutil_which("openssl") is not None


def shutil_which(binary: str):
    from shutil import which

    return which(binary)


def run_openssl(*args: str, cwd: str) -> None:
    subprocess.run(
        ["openssl", *args],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def generate_pki(directory: str) -> dict[str, str]:
    """Create a throwaway root and a seven-day-style server leaf."""

    root_key = os.path.join(directory, "root.key")
    root_crt = os.path.join(directory, "root.crt")
    leaf_key = os.path.join(directory, "leaf.key")
    leaf_csr = os.path.join(directory, "leaf.csr")
    leaf_crt = os.path.join(directory, "leaf.crt")
    ext = os.path.join(directory, "leaf.ext")
    run_openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        root_key,
        "-out",
        root_crt,
        "-days",
        "2",
        "-subj",
        "/CN=Test MicroLab Root",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        cwd=directory,
    )
    run_openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        leaf_key,
        "-out",
        leaf_csr,
        "-subj",
        "/CN=dns.microlab.hnh",
        cwd=directory,
    )
    Path(ext).write_text(
        "\n".join(
            [
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "extendedKeyUsage=serverAuth",
                "subjectAltName=DNS:dns.microlab.hnh",
                "",
            ]
        ),
        encoding="ascii",
    )
    run_openssl(
        "x509",
        "-req",
        "-in",
        leaf_csr,
        "-CA",
        root_crt,
        "-CAkey",
        root_key,
        "-CAcreateserial",
        "-out",
        leaf_crt,
        "-days",
        "2",
        "-extfile",
        ext,
        cwd=directory,
    )
    return {
        "root_crt": root_crt,
        "root_key": root_key,
        "leaf_crt": leaf_crt,
        "leaf_key": leaf_key,
    }


def issue_leaf(
    directory: str,
    pki: dict[str, str],
    *,
    stem: str,
    eku: str = "serverAuth",
    san: str = "DNS:dns.microlab.hnh",
    common_name: str = "dns.microlab.hnh",
    days: str = "2",
) -> dict[str, str]:
    """Issue another leaf with an explicit EKU/SAN for negative tests."""

    key = os.path.join(directory, f"{stem}.key")
    csr = os.path.join(directory, f"{stem}.csr")
    crt = os.path.join(directory, f"{stem}.crt")
    ext = os.path.join(directory, f"{stem}.ext")
    run_openssl(
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", csr,
        "-subj", f"/CN={common_name}", cwd=directory,
    )
    Path(ext).write_text(
        "\n".join(
            [
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                f"extendedKeyUsage={eku}",
                f"subjectAltName={san}",
                "",
            ]
        ),
        encoding="ascii",
    )
    run_openssl(
        "x509", "-req", "-in", csr,
        "-CA", pki["root_crt"], "-CAkey", pki["root_key"],
        "-CAcreateserial", "-out", crt, "-days", days,
        "-extfile", ext, cwd=directory,
    )
    return {"crt": crt, "key": key}


def make_config(directory: str, pki: dict[str, str], **overrides) -> object:
    password_file = os.path.join(directory, "pfx.pass")
    Path(password_file).write_text("test-password\n", encoding="ascii")
    values = {
        "ca_url": "https://127.0.0.1:4443",
        "ca_root": pki["root_crt"],
        "ca_chain": pki["root_crt"],
        "cert_path": pki["leaf_crt"],
        "key_path": pki["leaf_key"],
        "pfx_path": os.path.join(directory, "technitium.pfx"),
        "pfx_password_file": password_file,
        "cert_name": "dns.microlab.hnh",
        "api_url": "http://127.0.0.1:5380",
        "api_token": "test-token",
        "pfx_owner": "root",
        "pfx_group": "root",
        "pfx_mode": "0640",
        "renew_before": 72 * 3600,
        "alert_before": 24 * 3600,
        "publication_retries": 3,
        "verify_retries": 1,
        "verify_delay": 0.0,
        "lock_file": os.path.join(directory, "renew.lock"),
        "status_file": os.path.join(directory, "status.json"),
        "dot_port": 853,
    }
    values.update(overrides)
    return helper.Config(**values)


@unittest.skipUnless(openssl_available(), "openssl is required for helper tests")
class CertificateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pki = generate_pki(self.tmp.name)
        self.cfg = make_config(self.tmp.name, self.pki)

    def test_valid_certificate_and_key_match(self) -> None:
        info = helper.validate_certificate(self.cfg)
        self.assertEqual(info.dns_sans, ("dns.microlab.hnh",))
        self.assertEqual(info.ip_sans, ())
        self.assertTrue(
            any(
                "TLS Web Server Authentication" in item or "serverAuth" in item
                for item in info.eku
            )
        )

    def test_mixed_server_and_client_eku_is_rejected(self) -> None:
        leaf = issue_leaf(
            self.tmp.name, self.pki, stem="mixed",
            eku="serverAuth,clientAuth",
        )
        cfg = dataclasses.replace(
            self.cfg, cert_path=leaf["crt"], key_path=leaf["key"]
        )
        with self.assertRaisesRegex(helper.RenewalError, "clientAuth"):
            helper.validate_certificate(cfg)
        with self.assertRaisesRegex(helper.RenewalError, "clientAuth"):
            helper.validate_live_certificate(
                cfg, helper.cert_info(leaf["crt"])
            )

    def test_client_auth_only_eku_is_rejected(self) -> None:
        leaf = issue_leaf(
            self.tmp.name, self.pki, stem="client-only",
            eku="clientAuth",
        )
        cfg = dataclasses.replace(
            self.cfg, cert_path=leaf["crt"], key_path=leaf["key"]
        )
        with self.assertRaisesRegex(helper.RenewalError, "serverAuth"):
            helper.validate_certificate(cfg)

    def test_server_only_live_certificate_is_accepted(self) -> None:
        info = helper.cert_info(self.cfg.cert_path)
        helper.validate_live_certificate(self.cfg, info)
        self.assertEqual(helper.parse_eku_output(
            "X509v3 Extended Key Usage: critical\n"
            "    TLS Web Server Authentication\n"
        ), ("serverAuth",))

    def test_live_certificate_with_unexpected_san_is_rejected(self) -> None:
        leaf = issue_leaf(
            self.tmp.name, self.pki, stem="extra-live",
            san="DNS:dns.microlab.hnh,DNS:evil.microlab.hnh",
        )
        with self.assertRaisesRegex(helper.RenewalError, "SANs"):
            helper.validate_live_certificate(
                self.cfg, helper.cert_info(leaf["crt"])
            )

    def test_live_certificate_with_ip_san_is_rejected(self) -> None:
        leaf = issue_leaf(
            self.tmp.name, self.pki, stem="ip-live",
            san="DNS:dns.microlab.hnh,IP:127.0.0.1",
        )
        with self.assertRaisesRegex(helper.RenewalError, "IP SANs"):
            helper.validate_live_certificate(
                self.cfg, helper.cert_info(leaf["crt"])
            )

    def test_extra_dns_name_is_rejected(self) -> None:
        ext = os.path.join(self.tmp.name, "extra.ext")
        Path(ext).write_text(
            "\n".join(
                [
                    "basicConstraints=critical,CA:FALSE",
                    "keyUsage=critical,digitalSignature,keyEncipherment",
                    "extendedKeyUsage=serverAuth",
                    "subjectAltName=DNS:dns.microlab.hnh,DNS:evil.microlab.hnh",
                    "",
                ]
            ),
            encoding="ascii",
        )
        other_key = os.path.join(self.tmp.name, "other.key")
        other_csr = os.path.join(self.tmp.name, "other.csr")
        other_crt = os.path.join(self.tmp.name, "other.crt")
        run_openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", other_key, "-out", other_csr,
            "-subj", "/CN=dns.microlab.hnh", cwd=self.tmp.name,
        )
        run_openssl(
            "x509", "-req", "-in", other_csr,
            "-CA", self.pki["root_crt"], "-CAkey", self.pki["root_key"],
            "-CAcreateserial", "-out", other_crt, "-days", "2",
            "-extfile", ext, cwd=self.tmp.name,
        )
        cfg = dataclasses.replace(
            self.cfg, cert_path=other_crt, key_path=other_key
        )
        with self.assertRaisesRegex(helper.RenewalError, "unexpected DNS SANs"):
            helper.validate_certificate(cfg)

    def test_expired_certificate_is_not_renewed(self) -> None:
        info = helper.cert_info(self.cfg.cert_path)
        expired = dataclasses.replace(info, not_after=time.time() - 1)
        called = {"renew": 0}

        def renew() -> None:
            called["renew"] += 1

        with self.assertRaises(helper.ReEnrollmentRequired):
            helper.renew_if_due(
                self.cfg, expired, renew_fn=renew, now=time.time()
            )
        self.assertEqual(called["renew"], 0)

    def test_early_renewal_only_when_inside_window(self) -> None:
        info = helper.cert_info(self.cfg.cert_path)
        called = {"renew": 0}

        def renew() -> None:
            called["renew"] += 1

        self.assertFalse(
            helper.renew_if_due(
                self.cfg,
                dataclasses.replace(info, not_after=time.time() + 100 * 3600),
                renew_fn=renew,
                now=time.time(),
            )
        )
        self.assertEqual(called["renew"], 0)
        self.assertTrue(
            helper.renew_if_due(
                self.cfg,
                dataclasses.replace(info, not_after=time.time() + 3600),
                renew_fn=renew,
                now=time.time(),
            )
        )
        self.assertEqual(called["renew"], 1)

    def test_atomic_pfx_publication_is_valid_and_leaves_no_temporary_files(self) -> None:
        helper.publish_pfx(self.cfg)
        self.assertTrue(os.path.isfile(self.cfg.pfx_path))
        self.assertEqual(
            helper.served_pfx_fingerprint(self.cfg),
            helper.cert_info(self.cfg.cert_path).fingerprint,
        )
        self.assertEqual(
            os.stat(self.cfg.pfx_path).st_mode & 0o777, int(self.cfg.pfx_mode, 8)
        )
        leftovers = [
            name for name in os.listdir(self.tmp.name)
            if name.startswith(".technitium-")
        ]
        self.assertEqual(leftovers, [])

    def test_rotated_pfx_password_forces_republish(self) -> None:
        helper.publish_pfx(self.cfg)
        info = helper.cert_info(self.cfg.cert_path)
        self.assertFalse(helper.publication_needed(self.cfg, info))
        Path(self.cfg.pfx_password_file).write_text("different-password\n", encoding="ascii")
        self.assertTrue(helper.publication_needed(self.cfg, info))


class PathAndConfigTests(unittest.TestCase):
    def test_path_normalisation_matches_technitium_storage(self) -> None:
        cases = [
            ("/etc/dns/tls/dns.pfx", "/etc/dns", "tls/dns.pfx"),
            ("tls/dns.pfx", "/etc/dns", "tls/dns.pfx"),
            ("./tls/dns.pfx", "/etc/dns", "tls/dns.pfx"),
            ("/etc/dns/tls/dns.pfx", "/etc/dns/", "tls/dns.pfx"),
            ("/etc/technitium/tls/dns.pfx", "/etc/dns", "/etc/technitium/tls/dns.pfx"),
            ("/etc/dns2/tls/dns.pfx", "/etc/dns", "/etc/dns2/tls/dns.pfx"),
            ("/etc/dns", "/etc/dns", "/etc/dns"),
        ]
        for path, config_dir, expected in cases:
            with self.subTest(path=path, config_dir=config_dir):
                self.assertEqual(
                    helper.technitium_api_path(path, config_dir), expected
                )
                # Normalising an already-normalised value is a no-op.
                self.assertEqual(
                    helper.technitium_api_path(expected, config_dir), expected
                )

    def test_settings_body_posts_canonical_path_and_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pki = generate_pki(directory)
            cfg = make_config(directory, pki)
            cfg = dataclasses.replace(
                cfg,
                pfx_path="/etc/dns/tls/dns.pfx",
                technitium_config_dir="/etc/dns",
            )
            body = helper.dot_settings_body(cfg)
            self.assertEqual(body["dnsTlsCertificatePath"], "tls/dns.pfx")
            self.assertEqual(body["dnsTlsCertificatePassword"], "test-password")

            outside = dataclasses.replace(
                cfg,
                pfx_path="/srv/technitium-tls/dns.pfx",
            )
            self.assertEqual(
                helper.dot_settings_body(outside)["dnsTlsCertificatePath"],
                "/srv/technitium-tls/dns.pfx",
            )

    def test_load_config_default_budget_covers_60s_watcher(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory, "renewal.env")
            env.write_text(
                "\n".join(
                    [
                        "CA_URL=https://127.0.0.1:4443",
                        f"CA_ROOT={directory}/root.crt",
                        f"CERT_PATH={directory}/dns.crt",
                        f"KEY_PATH={directory}/dns.key",
                        f"PFX_PATH={directory}/dns.pfx",
                        f"PFX_PASSWORD_FILE={directory}/pfx.pass",
                        "CERT_NAME=dns.microlab.hnh",
                        "TECHNITIUM_CONFIG_DIR=/srv/technitium",
                        "API_URL=http://127.0.0.1:5380",
                        "API_TOKEN=token",
                        "",
                    ]
                ),
                encoding="ascii",
            )
            cfg = helper.load_config(str(env))
        self.assertEqual(cfg.verify_retries, 15)
        self.assertEqual(cfg.verify_delay, 5)
        self.assertEqual(cfg.technitium_config_dir, "/srv/technitium")
        self.assertGreaterEqual(
            (cfg.verify_retries - 1) * cfg.verify_delay, 60
        )


class LockTests(unittest.TestCase):
    def test_lock_is_exclusive_and_can_be_released(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock_path = os.path.join(directory, "renew.lock")
            first = helper.acquire_lock(lock_path)
            try:
                with self.assertRaises(helper.LockBusy):
                    helper.acquire_lock(lock_path)
            finally:
                helper.release_lock(first)
            second = helper.acquire_lock(lock_path)
            helper.release_lock(second)


class PublicationRetryTests(unittest.TestCase):
    def _config(self, directory: str) -> object:
        return helper.Config(
            ca_url="https://127.0.0.1:4443",
            ca_root="/nonexistent/root.crt",
            cert_path="/nonexistent/leaf.crt",
            key_path="/nonexistent/leaf.key",
            pfx_path=os.path.join(directory, "technitium.pfx"),
            pfx_password_file=os.path.join(directory, "password"),
            cert_name="dns.microlab.hnh",
            api_url="http://127.0.0.1:5380",
            api_token="token",
            publication_retries=3,
            verify_retries=1,
            verify_delay=0,
            lock_file=os.path.join(directory, "lock"),
            status_file=os.path.join(directory, "status.json"),
        )

    def test_publication_retries_until_live_serial_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = self._config(directory)
            calls = {"publish": 0, "apply": 0, "live": 0}

            def publish() -> None:
                calls["publish"] += 1

            def apply() -> None:
                calls["apply"] += 1

            def live() -> str:
                calls["live"] += 1
                return "OLD" if calls["live"] < 3 else "NEW"

            attempts = helper.ensure_publication(
                cfg,
                "NEW",
                publish_fn=publish,
                apply_fn=apply,
                live_fn=live,
                sleep_fn=lambda _: None,
            )
            self.assertEqual(attempts, 3)
            self.assertEqual(calls, {"publish": 3, "apply": 3, "live": 3})

    def test_publication_fails_after_budget_and_reports_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = self._config(directory)
            calls = {"publish": 0, "apply": 0, "live": 0}

            def publish() -> None:
                calls["publish"] += 1

            def apply() -> None:
                calls["apply"] += 1

            def live() -> str:
                calls["live"] += 1
                return "OLD"

            with self.assertRaisesRegex(
                helper.PublicationError, "after 3 attempts"
            ):
                helper.ensure_publication(
                    cfg,
                    "NEW",
                    publish_fn=publish,
                    apply_fn=apply,
                    live_fn=live,
                    sleep_fn=lambda _: None,
                )
            self.assertEqual(calls, {"publish": 3, "apply": 3, "live": 3})

    def test_live_budget_uses_verify_retries_without_republishing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = dataclasses.replace(
                self._config(directory),
                publication_retries=2,
                verify_retries=3,
                verify_delay=5,
            )
            calls = {"publish": 0, "apply": 0, "live": 0}
            sleeps: list[float] = []

            def publish() -> None:
                calls["publish"] += 1

            def apply() -> None:
                calls["apply"] += 1

            def live() -> str:
                calls["live"] += 1
                return "NEW" if calls["live"] == 3 else "OLD"

            attempts = helper.ensure_publication(
                cfg,
                "NEW",
                publish_fn=publish,
                apply_fn=apply,
                live_fn=live,
                sleep_fn=sleeps.append,
            )
            # One publish cycle, then three live polls covering the watcher
            # window. The PFX must not be republished on every poll.
            self.assertEqual(attempts, 1)
            self.assertEqual(calls, {"publish": 1, "apply": 1, "live": 3})
            self.assertEqual(sleeps, [5, 5])

    def test_repeated_live_failure_exhausts_full_budget_before_republish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = dataclasses.replace(
                self._config(directory),
                publication_retries=2,
                verify_retries=3,
                verify_delay=1,
            )
            calls = {"publish": 0, "apply": 0, "live": 0}

            def publish() -> None:
                calls["publish"] += 1

            def apply() -> None:
                calls["apply"] += 1

            def live() -> str:
                calls["live"] += 1
                return "OLD"

            with self.assertRaisesRegex(
                helper.PublicationError, "after 2 attempts"
            ):
                helper.ensure_publication(
                    cfg,
                    "NEW",
                    publish_fn=publish,
                    apply_fn=apply,
                    live_fn=live,
                    sleep_fn=lambda _: None,
                )
            # 3 polls per publication attempt, 2 attempts.
            self.assertEqual(calls, {"publish": 2, "apply": 2, "live": 6})

    def test_successful_first_attempt_reports_zero_retries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cfg = self._config(directory)
            attempts = helper.ensure_publication(
                cfg,
                "SERIAL",
                publish_fn=lambda: None,
                apply_fn=lambda: None,
                live_fn=lambda: "SERIAL",
                sleep_fn=lambda _: None,
            )
            self.assertEqual(attempts, 1)


class DurationTests(unittest.TestCase):
    def test_parse_compact_duration(self) -> None:
        self.assertEqual(helper.parse_duration("72h"), 72 * 3600)
        self.assertEqual(helper.parse_duration("1h30m"), 5400)
        self.assertEqual(helper.parse_duration("30s"), 30)
        with self.assertRaises(helper.RenewalError):
            helper.parse_duration("7 days")


if __name__ == "__main__":
    unittest.main()
