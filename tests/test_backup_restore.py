"""Safe regression tests for backup/restore helpers.

These tests build dummy archives, dummy SQLite-shaped files, and fake
systemctl executables in temporary directories.  They never touch a real
service, secret, CA, or host.
"""

from __future__ import annotations

import grp
import hashlib
import importlib
import io
import json
import os
import pwd
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "playbooks/files"
sys.path.insert(0, str(HELPERS))

guard = importlib.import_module("micolab_archive_guard")
backup = importlib.import_module("micolab_backup_capture")
restore = importlib.import_module("micolab_restore_commit")
lockmod = importlib.import_module("micolab_lock")


ALLOWED = [
    "/var/lib/forgejo",
    "/etc/forgejo/app.ini",
    "/etc/step-ca",
    "/etc/dns",
    "/var/lib/caddy",
    "/etc/technitium-tls",
]
REQUIRED_FILES = [
    "var/lib/forgejo/data/forgejo.db",
    "etc/forgejo/app.ini",
    "etc/technitium-tls/renewal.env",
]
REQUIRED_DIRS = [
    "var/lib/forgejo/data/forgejo-repositories",
    "var/lib/caddy",
    "etc/step-ca",
    "etc/dns",
    "etc/technitium-tls",
]


def tar_member(
    name: str,
    kind: str = "file",
    content: bytes = b"x",
    linkname: str = "",
    mode: int = 0o640,
) -> tuple[tarfile.TarInfo, io.BytesIO | None]:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = os.getuid()
    info.gid = os.getgid()
    info.mtime = 1
    if kind == "dir":
        info.type = tarfile.DIRTYPE
        info.mode = 0o750
        return info, None
    if kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = linkname
        return info, None
    if kind == "hardlink":
        info.type = tarfile.LNKTYPE
        info.linkname = linkname
        return info, None
    if kind == "fifo":
        info.type = tarfile.FIFOTYPE
        return info, None
    info.size = len(content)
    return info, io.BytesIO(content)


def write_tar(path: Path, members: list[tuple[tarfile.TarInfo, io.BytesIO | None]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for info, payload in members:
            archive.addfile(info, payload)


def safe_members() -> list[tuple[tarfile.TarInfo, io.BytesIO | None]]:
    return [
        tar_member("var/lib/forgejo", "dir"),
        tar_member("var/lib/forgejo/data", "dir"),
        tar_member("var/lib/forgejo/data/forgejo.db", content=b"sqlite"),
        tar_member("var/lib/forgejo/data/forgejo-repositories", "dir"),
        tar_member("var/lib/forgejo/data/forgejo-repositories/repo", content=b"repo"),
        tar_member("etc/forgejo/app.ini", content=b"[server]\n"),
        tar_member("etc/step-ca", "dir"),
        tar_member("etc/step-ca/config", content=b"ca"),
        tar_member("etc/dns", "dir"),
        tar_member("etc/dns/config", content=b"dns"),
        tar_member("var/lib/caddy", "dir"),
        tar_member("var/lib/caddy/state", content=b"caddy"),
        tar_member("etc/technitium-tls", "dir"),
        tar_member("etc/technitium-tls/renewal.env", content=b"API_TOKEN=x\n"),
        tar_member(
            "var/lib/forgejo/data/link",
            "symlink",
            linkname="forgejo.db",
        ),
        tar_member(
            "var/lib/forgejo/data/hard",
            "hardlink",
            linkname="var/lib/forgejo/data/forgejo.db",
        ),
    ]


class ArchiveGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.archive = Path(self.temp.name, "archive.tar.gz")
        write_tar(self.archive, safe_members())
        self.digest = guard.sha256_file(str(self.archive))

    def validate(self, **overrides):
        params = {
            "allowed_roots": ALLOWED,
            "required_members": [],
            "required_files": REQUIRED_FILES,
            "required_dirs": REQUIRED_DIRS,
            "forbidden_patterns": guard.DEFAULT_FORBIDDEN_PATTERNS,
            "expected_sha256": self.digest,
        }
        params.update(overrides)
        return guard.validate_archive(str(self.archive), **params)

    def rewrite(self, extra):
        write_tar(self.archive, safe_members() + extra)
        self.digest = guard.sha256_file(str(self.archive))

    def test_safe_archive_passes(self) -> None:
        result = self.validate()
        self.assertTrue(result["ok"], result)

    def test_extra_cron_payload_is_rejected(self) -> None:
        self.rewrite([tar_member("etc/cron.d/payload", content=b"* * * * * root sh")])
        result = self.validate()
        self.assertFalse(result["ok"])
        self.assertTrue(
            any("outside the restore allowlist" in item for item in result["violations"]),
            result,
        )

    def test_absolute_and_parent_members_are_rejected(self) -> None:
        for name in ["/etc/passwd", "../etc/passwd", "var/lib/forgejo/../../etc/passwd"]:
            with self.subTest(name=name):
                write_tar(self.archive, safe_members() + [tar_member(name)])
                self.digest = guard.sha256_file(str(self.archive))
                result = self.validate()
                self.assertFalse(result["ok"], result)

    def test_symlink_target_outside_allowlist_is_rejected(self) -> None:
        for target in ["/etc/shadow", "../../../etc/shadow"]:
            with self.subTest(target=target):
                write_tar(
                    self.archive,
                    safe_members()
                    + [
                        tar_member(
                            "var/lib/forgejo/escape",
                            "symlink",
                            linkname=target,
                        )
                    ],
                )
                self.digest = guard.sha256_file(str(self.archive))
                result = self.validate()
                self.assertFalse(result["ok"], result)
                self.assertTrue(
                    any("target escapes the allowlist" in item for item in result["violations"]),
                    result,
                )

    def test_hardlink_target_outside_allowlist_is_rejected(self) -> None:
        self.rewrite(
            [
                tar_member(
                    "var/lib/forgejo/data/shadow",
                    "hardlink",
                    linkname="/etc/shadow",
                )
            ]
        )
        result = self.validate()
        self.assertFalse(result["ok"], result)

    def test_special_file_is_rejected(self) -> None:
        self.rewrite([tar_member("var/lib/forgejo/fifo", "fifo")])
        result = self.validate()
        self.assertFalse(result["ok"])
        self.assertTrue(any("special file" in item for item in result["violations"]))

    def test_member_below_symlink_ancestor_is_rejected(self) -> None:
        self.rewrite(
            [
                tar_member(
                    "var/lib/forgejo/linkdir",
                    "symlink",
                    linkname="/var/lib/caddy",
                ),
                tar_member("var/lib/forgejo/linkdir/payload", content=b"bad"),
            ]
        )
        result = self.validate()
        self.assertFalse(result["ok"])
        self.assertTrue(
            any("below non-directory" in item for item in result["violations"]),
            result,
        )

    def test_root_ca_private_variants_are_rejected(self) -> None:
        for name in [
            "etc/step-ca/root_ca_private",
            "etc/step-ca/root_ca_private.pem",
            "etc/step-ca/root_ca_private-key",
            "etc/step-ca/root_ca_key",
            "etc/step-ca/root_ca_key.pem",
            "etc/step-ca/root_ca.key",
            "etc/step-ca/root_ca.key.pem",
            "etc/step-ca/offline-root/key",
            "etc/step-ca/offline-root-backup/key",
            "etc/step-ca/offline_root/key",
        ]:
            with self.subTest(name=name):
                write_tar(self.archive, safe_members() + [tar_member(name)])
                self.digest = guard.sha256_file(str(self.archive))
                result = self.validate()
                self.assertFalse(result["ok"], result)
                self.assertTrue(
                    any(
                        "forbidden offline-root" in item
                        for item in result["violations"]
                    ),
                    result,
                )

    def test_missing_required_member_is_rejected(self) -> None:
        members = [
            item
            for item in safe_members()
            if item[0].name != "var/lib/forgejo/data/forgejo.db"
        ]
        write_tar(self.archive, members)
        self.digest = guard.sha256_file(str(self.archive))
        result = self.validate()
        self.assertFalse(result["ok"])
        self.assertIn("var/lib/forgejo/data/forgejo.db", result["required_missing"])

    def test_checksum_mismatch_is_rejected(self) -> None:
        result = self.validate(expected_sha256="0" * 64)
        self.assertFalse(result["ok"])
        self.assertTrue(any("SHA-256" in item for item in result["violations"]))


class BackupCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake_bin = (self.root / "bin").resolve()
        self.fake_bin.mkdir()
        self.log = self.root / "systemctl.log"
        self.state = self.root / "systemd-state"
        self.state.mkdir()
        self.systemctl = self.fake_bin / "systemctl"
        self.systemctl.write_text(
            "#!/bin/sh\n"
            f"state={self.state}\n"
            f"log={self.log}\n"
            'case "$1" in\n'
            "  is-active)\n"
            '    if [ -f "$state/$2.active" ]; then echo active; exit 0; fi\n'
            "    echo inactive; exit 3 ;;\n"
            "  stop)\n"
            '    rm -f "$state/$2.active"; printf "stop %s\\n" "$2" >> "$log"; exit 0 ;;\n'
            "  start)\n"
            '    touch "$state/$2.active"; printf "start %s\\n" "$2" >> "$log"; exit 0 ;;\n'
            "  *)\n"
            '    printf "%s\\n" "$*" >> "$log"; exit 0 ;;\n'
            "esac\n"
        )
        self.systemctl.chmod(0o755)
        self._populate_state(self.root)
        (self.root / "srv").mkdir()

    @staticmethod
    def _populate_state(root: Path) -> None:
        files = {
            "var/lib/forgejo/data/forgejo.db": b"sqlite",
            "etc/forgejo/app.ini": b"[server]\n",
            "etc/step-ca/config": b"ca",
            "etc/dns/config": b"dns",
            "var/lib/caddy/state": b"caddy",
            "etc/technitium-tls/renewal.env": b"API_TOKEN=x\n",
        }
        dirs = [
            "var/lib/forgejo/data/forgejo-repositories",
            "var/lib/caddy",
            "etc/step-ca",
            "etc/dns",
            "etc/technitium-tls",
        ]
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        for relative in dirs:
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "var/lib/forgejo/data/forgejo-repositories/repo").write_bytes(b"repo")

    def spec(self, **overrides):
        values = {
            "archive": "/srv/backup.tar.gz",
            "root_prefix": str(self.root),
            "include_paths": ALLOWED,
            "exclude_patterns": ["*/root_ca_private*"],
            "forbidden_patterns": guard.DEFAULT_FORBIDDEN_PATTERNS,
            "required_members": [],
            "required_files": REQUIRED_FILES,
            "required_dirs": REQUIRED_DIRS,
            "services": [],
            "active_before": {},
            "wal_path": "/var/lib/forgejo/data/forgejo.db-wal",
            "lock_file": "/var/lib/technitium-lock/renew.lock",
            "lock_timeout_seconds": 0,
            "systemctl": str(self.systemctl),
            "tar": "tar",
            "manifest": {"host": "test"},
        }
        values.update(overrides)
        return values

    def test_capture_is_restrictive_and_records_clean_wal(self) -> None:
        result = backup.capture(self.spec())
        archive = self.root / "srv/backup.tar.gz"
        self.assertTrue(archive.is_file())
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "srv/backup.tar.gz.sha256").stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            (self.root / "srv/backup.tar.gz.manifest.json").stat().st_mode & 0o777,
            0o600,
        )
        self.assertFalse(result["wal_present_after_quiesce"])
        self.assertEqual(result["sha256"], guard.sha256_file(str(archive)))
        names = {member.name for member in guard.read_members(str(archive))}
        self.assertIn("var/lib/forgejo/data/forgejo.db", names)
        self.assertNotIn("var/lib/forgejo/data/forgejo.db-wal", names)

    def test_wal_is_required_when_present_after_quiesce(self) -> None:
        (self.root / "var/lib/forgejo/data/forgejo.db-wal").write_bytes(b"wal")
        result = backup.capture(self.spec())
        self.assertTrue(result["wal_present_after_quiesce"])
        names = {member.name for member in guard.read_members(str(self.root / "srv/backup.tar.gz"))}
        self.assertIn("var/lib/forgejo/data/forgejo.db-wal", names)

    def test_partial_archive_is_removed_when_validation_fails(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.capture(
                self.spec(required_files=REQUIRED_FILES + ["var/lib/forgejo/data/missing.db"])
            )
        self.assertFalse((self.root / "srv/backup.tar.gz").exists())
        self.assertFalse((self.root / "srv/backup.tar.gz.sha256").exists())
        self.assertFalse((self.root / "srv/backup.tar.gz.manifest.json").exists())

    def test_escrow_material_is_excluded_and_unexcluded_escrow_fails(self) -> None:
        (self.root / "etc/step-ca/root_ca_private.pem").write_bytes(b"secret")
        backup.capture(self.spec())
        names = {member.name for member in guard.read_members(str(self.root / "srv/backup.tar.gz"))}
        self.assertNotIn("etc/step-ca/root_ca_private.pem", names)

        shutil.rmtree(self.root / "srv")
        (self.root / "srv").mkdir()
        with self.assertRaises(backup.BackupError):
            backup.capture(self.spec(exclude_patterns=[], archive="/srv/fail.tar.gz"))
        self.assertFalse((self.root / "srv/fail.tar.gz").exists())

    def test_unescaped_escrow_fails_before_archive_write_after_quiesce(self) -> None:
        (self.root / "etc/step-ca/root_ca_private.pem").write_bytes(b"secret")
        (self.state / "forgejo.active").touch()
        with self.assertRaises(backup.BackupError):
            backup.capture(
                self.spec(
                    archive="/srv/escrow.tar.gz",
                    exclude_patterns=[],
                    services=["forgejo"],
                    active_before={"forgejo": True},
                )
            )
        self.assertFalse((self.root / "srv/escrow.tar.gz").exists())
        lines = self.log.read_text().splitlines()
        self.assertIn("stop forgejo", lines)
        self.assertFalse(any("start " in line for line in lines))

    def test_archive_inside_included_tree_is_refused(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.capture(
                self.spec(archive="/var/lib/forgejo/backup.tar.gz")
            )
        self.assertFalse((self.root / "var/lib/forgejo/backup.tar.gz").exists())

    def test_symlink_alias_into_included_tree_is_refused(self) -> None:
        link = self.root / "alias"
        link.symlink_to(self.root / "var/lib/forgejo", target_is_directory=True)
        with self.assertRaises(backup.BackupError):
            backup.capture(self.spec(archive="/alias/backup.tar.gz"))
        self.assertFalse((self.root / "var/lib/forgejo/backup.tar.gz").exists())

    def test_lock_inode_is_not_replaced_and_busy_lock_is_respected(self) -> None:
        lock_path = self.root / "var/lib/technitium-lock/renew.lock"
        lock_path.parent.mkdir(parents=True)
        lock_path.write_text("")
        before = lock_path.stat().st_ino
        backup.capture(self.spec())
        self.assertEqual(lock_path.stat().st_ino, before)

        shutil.rmtree(self.root / "srv")
        (self.root / "srv").mkdir()
        with lockmod.DurableLock(str(lock_path), timeout=0):
            with self.assertRaises(lockmod.LockTimeout):
                backup.capture(
                    self.spec(archive="/srv/busy.tar.gz", lock_timeout_seconds=0)
                )
        self.assertFalse((self.root / "srv/busy.tar.gz").exists())

    def test_services_are_stopped_but_not_started_by_the_capture_helper(self) -> None:
        (self.state / "forgejo.active").touch()
        backup.capture(
            self.spec(services=["forgejo", "caddy"], active_before={"forgejo": True, "caddy": False})
        )
        lines = self.log.read_text().splitlines()
        self.assertIn("stop forgejo", lines)
        self.assertNotIn("stop caddy", lines)
        self.assertFalse(any("start " in line for line in lines))


class RestoreCommitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake_bin = (self.root / "bin").resolve()
        self.fake_bin.mkdir()
        self.log = self.root / "systemctl.log"
        self.state = self.root / "systemd-state"
        self.state.mkdir()
        self.systemctl = self.fake_bin / "systemctl"
        self.systemctl.write_text(
            "#!/bin/sh\n"
            f"state={self.state}\n"
            f"log={self.log}\n"
            'case "$1" in\n'
            "  is-active)\n"
            '    if [ -f "$state/$2.active" ]; then echo active; exit 0; fi\n'
            "    echo inactive; exit 3 ;;\n"
            "  stop)\n"
            '    rm -f "$state/$2.active"; printf "stop %s\\n" "$2" >> "$log"; exit 0 ;;\n'
            "  start)\n"
            '    touch "$state/$2.active"; printf "start %s\\n" "$2" >> "$log"; exit 0 ;;\n'
            "  *)\n"
            '    printf "%s\\n" "$*" >> "$log"; exit 0 ;;\n'
            "esac\n"
        )
        self.systemctl.chmod(0o755)
        for service in ("forgejo", "caddy"):
            (self.state / f"{service}.active").touch()
        self.source = self.root / "source"
        self.target = self.root / "target"
        self._populate(self.source)
        self._populate(self.target, old=True)
        (self.root / "srv").mkdir()
        self.archive = self.root / "srv/restore.tar.gz"
        self._make_archive(self.source, self.archive)
        self._stage_archive()
        self.lock = self.target / "var/lib/technitium-lock/renew.lock"

    def _stage_archive(self) -> None:
        staged = self.target / "srv/restore.tar.gz"
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.archive, staged)
        os.chmod(staged, 0o600)
        self.checksum = guard.sha256_file(str(staged))

    @staticmethod
    def _populate(root: Path, old: bool = False) -> None:
        marker = b"old" if old else b"new"
        files = {
            "var/lib/forgejo/data/forgejo.db": marker,
            "etc/forgejo/app.ini": b"[server]\n" + marker,
            "etc/step-ca/config": b"ca",
            "etc/dns/config": b"dns",
            "var/lib/caddy/state": b"caddy",
            "etc/technitium-tls/renewal.env": b"API_TOKEN=x\n",
        }
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            os.chmod(path, 0o640)
        for relative in REQUIRED_DIRS:
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "var/lib/forgejo/data/forgejo-repositories/repo").write_bytes(b"repo")

    def _make_archive(self, root: Path, archive: Path) -> None:
        paths = [str(root / relative.lstrip("/")) for relative in ALLOWED]
        subprocess.run(
            [
                "tar",
                "--create",
                "--gzip",
                "--file",
                str(archive),
                "--numeric-owner",
                "--acls",
                "--xattrs",
                "-C",
                str(root),
            ]
            + [path[len(str(root)) + 1 :] for path in paths],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.chmod(archive, 0o600)

    def spec(self, **overrides):
        values = {
            "archive": "/srv/restore.tar.gz",
            "checksum": self.checksum,
            "root_prefix": str(self.target),
            "allowed_roots": ALLOWED,
            "install_paths": ALLOWED,
            "required_members": [],
            "required_files": REQUIRED_FILES,
            "required_dirs": REQUIRED_DIRS,
            "forbidden_patterns": guard.DEFAULT_FORBIDDEN_PATTERNS,
            "quarantine_root": "/var/lib/microlab/restore-quarantine/test",
            "staging_root": "/var/lib/microlab/restore-staging/test",
            "services": ["forgejo", "caddy"],
            "systemctl": str(self.systemctl),
            "tar": "tar",
            "lock_file": "/var/lib/technitium-lock/renew.lock",
            "lock_timeout_seconds": 0,
        }
        values.update(overrides)
        return values

    def test_restore_quarantines_and_preserves_modes_xattrs_and_acls(self) -> None:
        if shutil.which("setfacl") is None or shutil.which("getfacl") is None:
            self.skipTest("ACL tools are not installed")
        source_file = self.source / "etc/forgejo/app.ini"
        os.chmod(source_file, 0o640)
        try:
            os.setxattr(source_file, b"user.microlab-test", b"value")
            has_xattr = True
        except OSError:
            has_xattr = False
        subprocess.run(
            ["setfacl", "-m", f"u:{os.getuid()}:r--", str(source_file)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._make_archive(self.source, self.archive)
        self._stage_archive()

        lock_parent = self.lock.parent
        lock_parent.mkdir(parents=True)
        self.lock.write_text("")
        lock_inode = self.lock.stat().st_ino

        result = restore.restore(self.spec())
        self.assertTrue(result["ok"])
        self.assertEqual(self.lock.stat().st_ino, lock_inode)

        restored = self.target / "etc/forgejo/app.ini"
        self.assertEqual(restored.read_bytes(), b"[server]\nnew")
        self.assertEqual(restored.stat().st_mode & 0o777, 0o640)
        if has_xattr:
            self.assertEqual(os.getxattr(restored, b"user.microlab-test"), b"value")
        acl = subprocess.run(
            ["getfacl", "-c", str(restored)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout
        user_name = pwd.getpwuid(os.getuid()).pw_name
        self.assertTrue(
            f"user:{os.getuid()}:r--" in acl or f"user:{user_name}:r--" in acl,
            acl,
        )

        quarantine = self.target / "var/lib/microlab/restore-quarantine/test"
        self.assertEqual(quarantine.stat().st_mode & 0o777, 0o700)
        old = quarantine / "etc/forgejo/app.ini"
        self.assertTrue(old.is_file())
        self.assertEqual(old.parent.parent.stat().st_mode & 0o777, 0o700)
        self.assertIn(b"old", old.read_bytes())
        self.assertFalse((self.target / "var/lib/microlab/restore-staging/test").exists())

        lines = self.log.read_text().splitlines()
        self.assertEqual(lines, ["stop forgejo", "stop caddy"])
        self.assertFalse(any("start " in line for line in lines))

    def test_malicious_extra_member_is_rejected_before_any_change(self) -> None:
        with tarfile.open(self.archive, "w:gz") as archive:
            for info, payload in safe_members():
                archive.addfile(info, payload)
            info, payload = tar_member("etc/cron.d/payload", content=b"bad")
            archive.addfile(info, payload)
        self._stage_archive()
        old = (self.target / "etc/forgejo/app.ini").read_bytes()
        with self.assertRaises(restore.RestoreError):
            restore.restore(self.spec())
        self.assertEqual((self.target / "etc/forgejo/app.ini").read_bytes(), old)
        self.assertFalse((self.target / "var/lib/microlab/restore-quarantine/test").exists())
        self.assertFalse(self.log.exists())

    def test_checksum_mismatch_is_rejected_before_any_change(self) -> None:
        with self.assertRaises(restore.RestoreError):
            restore.restore(self.spec(checksum="0" * 64))
        self.assertFalse((self.target / "var/lib/microlab/restore-quarantine/test").exists())
        self.assertFalse(self.log.exists())

    def test_world_readable_archive_is_rejected(self) -> None:
        staged = self.target / "srv/restore.tar.gz"
        os.chmod(staged, 0o644)
        with self.assertRaises(restore.RestoreError):
            restore.restore(self.spec())
        self.assertFalse(self.log.exists())

    def test_busy_lock_is_rejected_before_services_stop(self) -> None:
        self.lock.parent.mkdir(parents=True)
        self.lock.write_text("")
        with lockmod.DurableLock(str(self.lock), timeout=0):
            with self.assertRaises(restore.RestoreError):
                restore.restore(self.spec(lock_timeout_seconds=0))
        self.assertFalse(self.log.exists())
        self.assertFalse((self.target / "var/lib/microlab/restore-quarantine/test").exists())

    def test_lock_or_quarantine_inside_restored_state_is_rejected(self) -> None:
        with self.assertRaises(restore.RestoreError):
            restore.restore(
                self.spec(quarantine_root="/var/lib/forgejo/quarantine")
            )
        self.assertFalse(self.log.exists())


class PlaybookWiringTests(unittest.TestCase):
    def test_backup_playbook_quiesces_renewal_and_uses_canonical_containment(self) -> None:
        text = (ROOT / "playbooks/backup.yml").read_text()
        self.assertIn("micolab_backup_renewal_lock_file_effective", text)
        self.assertIn("Stop the renewal timer before taking the durable lock", text)
        self.assertIn("micolab_backup_renewal_timer_enabled_before", text)
        self.assertIn("micolab_backup_renewal_timer_active_before", text)
        self.assertIn("realpath", text)
        self.assertIn("inside any archived tree", text)
        self.assertIn("micolab_backup_capture.py", text)
        self.assertNotIn("microlab_backup_capture.py", text)
        self.assertIn("root_ca_private[^/]*", text)
        self.assertIn("always:", text)

    def test_playbooks_read_role_owned_path_interfaces(self) -> None:
        backup = (ROOT / "playbooks/backup.yml").read_text()
        restore = (ROOT / "playbooks/restore.yml").read_text()
        interface = (ROOT / "playbooks/vars/technitium_tls_interface.yml").read_text()
        for text in (backup, restore):
            for variable in (
                "micolab_forgejo_data_dir",
                "micolab_forgejo_config_file",
                "micolab_caddy_state_dir",
                "microlab_step_ca_home",
                "micolab_technitium_interface_config_dir",
            ):
                self.assertIn(variable, text, variable)
            self.assertIn("vars/technitium_tls_interface.yml", text)
        for variable in (
            "microlab_technitium_config_dir",
            "microlab_technitium_lock_file",
            "microlab_technitium_timer_unit",
            "microlab_technitium_renewal_env_file",
            "microlab_technitium_state_dir",
            "microlab_technitium_cert_dir",
        ):
            self.assertIn(variable, interface, variable)

    def test_dry_run_and_check_mode_wiring_stays_read_only(self) -> None:
        backup = (ROOT / "playbooks/backup.yml").read_text()
        restore = (ROOT / "playbooks/restore.yml").read_text()
        self.assertIn("when: not ansible_check_mode", backup)
        self.assertIn("when:\n        - micolab_restore_commit | default(false) | bool\n        - not ansible_check_mode", restore)
        self.assertIn("Stop the renewal timer before taking the durable lock", backup)
        self.assertIn("Extract, quarantine, and install approved state under the lock", restore)
        # The old direct extraction to / must not return.
        self.assertNotIn("-xpzf", restore)
        self.assertIn("RESTORE-ISOLATED-MICROLAB", restore)
        self.assertIn("isolated-restore-target", restore)
        self.assertIn("micolab_restore_production_group", restore)

    def test_backup_containment_predicate_is_not_reversed(self) -> None:
        backup = (ROOT / "playbooks/backup.yml").read_text()
        self.assertIn("not micolab_backup_destination_real.startswith(item.value ~ '/')", backup)
        self.assertIn("not micolab_backup_archive_real.startswith(item.value ~ '/')", backup)
        self.assertNotIn(
            "micolab_backup_include_paths_effective | select('match', '^' ~ (micolab_backup_destination",
            backup,
        )

    def test_restore_playbook_uses_guard_and_staging_helper(self) -> None:
        text = (ROOT / "playbooks/restore.yml").read_text()
        self.assertIn("micolab_archive_guard.py", text)
        self.assertIn("micolab_restore_commit.py", text)
        self.assertNotIn("microlab_archive_guard.py", text)
        self.assertNotIn("microlab_restore_commit.py", text)
        self.assertIn("micolab_restore_guard_spec_b64", text)
        self.assertIn("root_ca_private[^/]*", text)
        self.assertIn("recurse: true", text)
        # Recursive ownership must not carry a mode that would chmod the tree.
        for block in text.split("- name:"):
            if "recurse: true" in block:
                self.assertNotIn("mode:", block, block[:300])

    def test_restore_helper_preserves_metadata_and_holds_lock(self) -> None:
        text = (ROOT / "playbooks/files/micolab_restore_commit.py").read_text()
        self.assertIn("--numeric-owner", text)
        self.assertIn("--acls", text)
        self.assertIn("--xattrs", text)
        self.assertIn("DurableLock", text)
        self.assertIn("verify_staging", text)
        self.assertNotIn('"-C",\n                "/"', text)

    def test_docs_cover_preupgrade_and_rollback_rehearsal(self) -> None:
        text = (ROOT / "docs/backup-restore.md").read_text()
        for phrase in [
            "pre-upgrade",
            "matching binary",
            "rollback rehearsal",
            "root_ca_private*",
            "renew.lock",
            "staging",
            "WAL",
        ]:
            self.assertIn(phrase, text, phrase)


if __name__ == "__main__":
    unittest.main()


def find_ansible_playbook() -> str | None:
    """Return an ansible-playbook binary without assuming a system package."""

    candidates = [os.environ.get("ANSIBLE_PLAYBOOK")]
    candidates.extend(
        [
            shutil.which("ansible-playbook"),
            "/tmp/ansvenv217/bin/ansible-playbook",
            "/tmp/ansvenv/bin/ansible-playbook",
        ]
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def run_playbook_file(
    playbook_path: Path,
    extra: dict | None = None,
    tags: str | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess:
    """Run one real playbook file against a localhost-only temporary inventory."""

    binary = find_ansible_playbook()
    if binary is None:
        raise unittest.SkipTest("ansible-playbook is not installed")
    workdir = tempfile.mkdtemp(prefix="micolab-ansible-")
    try:
        inventory = Path(workdir, "inventory.yml")
        inventory.write_text(
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
        command = [binary, "-i", str(inventory), str(playbook_path)]
        if tags:
            command.extend(["--tags", tags])
        if extra is not None:
            variables = Path(workdir, "vars.json")
            variables.write_text(json.dumps(extra), encoding="utf-8")
            command.extend(["-e", f"@{variables}"])
        env = dict(os.environ)
        env["ANSIBLE_STDOUT_CALLBACK"] = "default"
        env.pop("ANSIBLE_CONFIG", None)
        return subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_local_playbook(
    playbook: str,
    extra: dict | None = None,
    tags: str | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess:
    """Run one real playbook from this repository."""

    return run_playbook_file(ROOT / playbook, extra=extra, tags=tags, timeout=timeout)


def task_result(process: subprocess.CompletedProcess, name: str) -> dict:
    """Extract one task result dict from the default Ansible output."""

    marker = f"TASK [{name}]"
    position = process.stdout.find(marker)
    if position < 0:
        raise AssertionError(
            f"task {name!r} did not run\nSTDOUT:\n{process.stdout}\nSTDERR:\n{process.stderr}"
        )
    arrow = process.stdout.find("=>", position)
    if arrow < 0:
        raise AssertionError(f"task {name!r} produced no result\n{process.stdout}")
    start = process.stdout.find("{", arrow)
    if start < 0:
        raise AssertionError(f"task {name!r} result is not an object\n{process.stdout}")
    result, _ = json.JSONDecoder().raw_decode(process.stdout[start:])
    return result


ROLE_DEFAULTS_FILE = ROOT / "roles/technitium_tls/defaults/main.yml"
SITE_GROUP_VARS_FILE = ROOT / "group_vars/all.yml"

# The exact interface fields the backup/restore playbooks must resolve.  The
# values are rendered from roles/technitium_tls/defaults/main.yml by Ansible,
# not hard-coded in this test.
ROLE_RENDER_FIELDS = {
    "cert_dir": "microlab_technitium_cert_dir",
    "cert_path": "microlab_technitium_cert_path",
    "key_path": "microlab_technitium_key_path",
    "pfx_path": "microlab_technitium_pfx_path",
    "pfx_password_file": "microlab_technitium_pfx_password_file",
    "pfx_password_sha256": "microlab_technitium_pfx_password | hash('sha256')",
    "config_dir": "microlab_technitium_config_dir",
    "ca_root_cert": "microlab_technitium_ca_root_cert",
    "ca_chain_cert": "microlab_technitium_ca_chain_cert",
    "state_directory_name": "microlab_technitium_state_directory_name",
    "state_dir": "microlab_technitium_state_dir",
    "lock_file": "microlab_technitium_lock_file",
    "status_file": "microlab_technitium_status_file",
    "renewal_env_file": "microlab_technitium_renewal_env_file",
    "helper_path": "microlab_technitium_helper_path",
    "service_unit": "microlab_technitium_service_unit",
    "timer_unit": "microlab_technitium_timer_unit",
}


def render_actual_role_defaults(extra: dict | None = None) -> dict:
    """Render roles/technitium_tls/defaults/main.yml with real Ansible.

    The temporary play loads the actual role defaults and the repository's
    group_vars so the same aliases are present as during a site run.  Extra
    vars retain their normal highest precedence.  Nothing from the role's tasks
    executes and no host state is touched.
    """

    workdir = tempfile.mkdtemp(prefix="micolab-role-render-")
    try:
        playbook = Path(workdir, "render_role_defaults.yml")
        msg = "\n".join(
            f'          {name}: "{{{{ {expression} }}}}"'
            for name, expression in ROLE_RENDER_FIELDS.items()
        )
        playbook.write_text(
            "---\n"
            "- name: Render the real Technitium TLS role defaults\n"
            "  hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  vars_files:\n"
            f"    - {ROLE_DEFAULTS_FILE}\n"
            f"    - {SITE_GROUP_VARS_FILE}\n"
            "  tasks:\n"
            "    - name: Report actual role effective interface\n"
            "      ansible.builtin.debug:\n"
            "        msg:\n"
            f"{msg}\n",
            encoding="utf-8",
        )
        process = run_playbook_file(playbook, extra=extra)
        if process.returncode != 0:
            raise AssertionError(
                "role default rendering failed\n"
                f"{process.stdout}\n{process.stderr}"
            )
        result = task_result(process, "Report actual role effective interface")
        if result.get("failed", False):
            raise AssertionError(result)
        return result["msg"]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


class AnsibleInterfaceResolutionTests(unittest.TestCase):
    """Compare real Ansible role-default rendering with playbook resolution."""

    REPORT_TASKS = {
        "backup": "Report the resolved backup renewal interface",
        "restore": "Report the resolved restore renewal interface",
    }

    EFFECTIVE_FIELDS = {
        "cert_dir": "technitium_cert_dir_effective",
        "cert_path": "technitium_cert_path_effective",
        "key_path": "technitium_key_path_effective",
        "pfx_path": "technitium_pfx_path_effective",
        "pfx_password_file": "technitium_pfx_password_file_effective",
        "config_dir": "dns_dir_effective",
        "ca_root_cert": "technitium_ca_root_cert_effective",
        "ca_chain_cert": "technitium_ca_chain_cert_effective",
        "state_directory_name": "technitium_state_directory_name_effective",
        "state_dir": "technitium_state_dir_effective",
        "lock_file": "renewal_lock_file_effective",
        "renewal_env_file": "renewal_env_file_effective",
        "timer_unit": "renewal_timer_unit_effective",
    }

    @staticmethod
    def prefix(kind: str) -> str:
        return f"micolab_{kind}_"

    def report_process(self, kind: str, extra: dict | None = None):
        variables = dict(extra or {})
        variables["micolab_report_effective_interface"] = True
        return run_local_playbook(
            f"playbooks/{kind}.yml",
            extra=variables,
            tags="micolab-interface-report",
        )

    def resolve(self, kind: str, extra: dict | None = None) -> dict:
        process = self.report_process(kind, extra)
        self.assertEqual(
            process.returncode,
            0,
            f"{kind} interface resolution failed\n{process.stdout}\n{process.stderr}",
        )
        result = task_result(process, self.REPORT_TASKS[kind])
        self.assertEqual(result.get("failed", False), False, result)
        return result["msg"]

    def both(self, extra: dict | None = None) -> dict[str, dict]:
        return {kind: self.resolve(kind, extra) for kind in ("backup", "restore")}

    @staticmethod
    def reported_interface(values: dict) -> dict:
        return {
            field: values[f"micolab_technitium_interface_{field}"]
            for field in ROLE_RENDER_FIELDS
        }

    def assert_matches_the_real_role(self, extra: dict | None = None):
        """Assert role defaults, shared interface, and effective settings agree."""

        role = render_actual_role_defaults(extra)
        playbooks = self.both(extra)
        for kind, values in playbooks.items():
            p = self.prefix(kind)
            with self.subTest(kind=kind):
                self.assertEqual(
                    self.reported_interface(values),
                    role,
                    f"{kind} interface does not match the real role defaults",
                )
                for field, suffix in self.EFFECTIVE_FIELDS.items():
                    self.assertEqual(
                        values[f"{p}{suffix}"],
                        role[field],
                        f"{kind} effective {suffix} does not match role {field}",
                    )
        return role, playbooks

    def test_defaults_render_like_the_actual_role_defaults(self) -> None:
        role, playbooks = self.assert_matches_the_real_role()
        # A couple of concrete anchors keep failures readable; the authority is
        # the role-default render above, not a duplicated expected matrix.
        self.assertEqual(role["cert_dir"], "/etc/dns/tls")
        self.assertEqual(role["state_dir"], "/var/lib/technitium-tls")
        self.assertEqual(role["lock_file"], "/var/lib/technitium-tls/renew.lock")
        for kind, values in playbooks.items():
            p = self.prefix(kind)
            with self.subTest(kind=kind):
                env_file = role["renewal_env_file"]
                config_dir = env_file.rsplit("/", 1)[0]
                material = values[f"{p}renewal_material_paths_effective"]
                self.assertEqual(material, [
                    role["pfx_path"],
                    role["cert_path"],
                    role["key_path"],
                    role["pfx_password_file"],
                    role["ca_root_cert"],
                    role["ca_chain_cert"],
                ])
                self.assertIn(config_dir, values[f"{p}include_paths_effective"])
                for path in [env_file] + material:
                    self.assertIn(path.lstrip("/"), values[f"{p}required_files_effective"])
                self.assertIn(
                    config_dir.lstrip("/"),
                    values[f"{p}required_dirs_effective"],
                )
                for path in [config_dir] + material:
                    self.assertIn(
                        path,
                        values[f"{p}required_coverage_paths_effective"],
                    )
                self.assertEqual(
                    values[f"{p}renewal_lock_file_effective"],
                    role["lock_file"],
                )
                self.assertEqual(
                    values[f"{p}renewal_timer_unit_effective"],
                    role["timer_unit"],
                )

    def test_canonical_overrides_render_like_the_actual_role_defaults(self) -> None:
        extra = {
            "microlab_technitium_cert_dir": "/srv/canonical/tls",
            "microlab_technitium_cert_path": "/srv/canonical/pem/dns.crt",
            "microlab_technitium_key_path": "/srv/canonical/pem/dns.key",
            "microlab_technitium_pfx_path": "/srv/canonical/pfx/dns.pfx",
            "microlab_technitium_pfx_password_file": "/srv/canonical/pfx/pfx.pass",
            "microlab_technitium_pfx_password": "canonical-secret",
            "microlab_technitium_tls_cert_password": "alias-secret",
            "microlab_technitium_config_dir": "/srv/canonical/dns",
            "microlab_technitium_ca_root_cert": "/srv/canonical/root.crt",
            "microlab_technitium_ca_chain_cert": "/srv/canonical/chain.crt",
            "microlab_technitium_state_directory_name": "canonical-state",
            "microlab_technitium_state_dir": "/srv/canonical/state",
            "microlab_technitium_lock_file": "/srv/canonical/state/custom.lock",
            "microlab_technitium_status_file": "/srv/canonical/state/status.json",
            "microlab_technitium_renewal_env_file": "/srv/canonical/env/renewal.env",
            "microlab_technitium_helper_path": "/srv/canonical/bin/renew",
            "microlab_technitium_service_unit": "canonical-renew.service",
            "microlab_technitium_timer_unit": "canonical-renew.timer",
        }
        role, _ = self.assert_matches_the_real_role(extra)
        self.assertEqual(role["cert_path"], "/srv/canonical/pem/dns.crt")
        self.assertEqual(role["key_path"], "/srv/canonical/pem/dns.key")
        self.assertEqual(role["pfx_path"], "/srv/canonical/pfx/dns.pfx")
        self.assertEqual(
            role["pfx_password_sha256"],
            hashlib.sha256(b"canonical-secret").hexdigest(),
        )

    def test_shared_alias_and_canonical_cert_dir_keep_actual_mixed_precedence(self) -> None:
        # This is the real role result, not a nicer single-directory
        # convention: the explicit cert_dir drives the PEM and pfx.pass, while
        # the supported shared key/PFX aliases still win over derived paths.
        extra = {
            "microlab_technitium_cert_dir": "/srv/tls",
            "micolab_technitium_tls_cert_path": "/etc/dns/tls/dns.pfx",
            "micolab_technitium_tls_key_path": "/etc/dns/tls/dns.key",
            "microlab_technitium_tls_cert_password": "alias-secret",
            "micolab_technitium_config_dir": "/srv/dns",
        }
        role, playbooks = self.assert_matches_the_real_role(extra)
        self.assertEqual(role["cert_dir"], "/srv/tls")
        self.assertEqual(role["cert_path"], "/srv/tls/dns.crt")
        self.assertEqual(role["key_path"], "/etc/dns/tls/dns.key")
        self.assertEqual(role["pfx_path"], "/etc/dns/tls/dns.pfx")
        self.assertEqual(role["pfx_password_file"], "/srv/tls/pfx.pass")
        self.assertEqual(role["config_dir"], "/srv/dns")
        for kind, values in playbooks.items():
            p = self.prefix(kind)
            self.assertEqual(values[f"{p}renewal_material_paths_effective"][:4], [
                "/etc/dns/tls/dns.pfx",
                "/srv/tls/dns.crt",
                "/etc/dns/tls/dns.key",
                "/srv/tls/pfx.pass",
            ])

    def test_shared_alias_alone_derives_cert_dir_like_the_real_role(self) -> None:
        extra = {
            "micolab_technitium_tls_cert_path": "/opt/shared/custom.pfx",
            "micolab_technitium_tls_key_path": "/opt/shared/custom.key",
            "micolab_technitium_tls_cert_password": "shared-secret",
        }
        role, _ = self.assert_matches_the_real_role(extra)
        self.assertEqual(role["cert_dir"], "/opt/shared")
        self.assertEqual(role["cert_path"], "/opt/shared/dns.crt")
        self.assertEqual(role["key_path"], "/opt/shared/custom.key")
        self.assertEqual(role["pfx_path"], "/opt/shared/custom.pfx")
        self.assertEqual(role["pfx_password_file"], "/opt/shared/pfx.pass")

    def test_derived_state_and_cert_directories_match_the_real_role(self) -> None:
        extra = {
            "microlab_technitium_state_directory_name": "site-state",
            "microlab_technitium_cert_dir": "/srv/pki/site-tls",
        }
        role, _ = self.assert_matches_the_real_role(extra)
        self.assertEqual(role["state_directory_name"], "site-state")
        self.assertEqual(role["state_dir"], "/var/lib/site-state")
        self.assertEqual(role["lock_file"], "/var/lib/site-state/renew.lock")
        self.assertEqual(role["cert_dir"], "/srv/pki/site-tls")
        self.assertEqual(role["cert_path"], "/srv/pki/site-tls/dns.crt")
        # group_vars supplies the supported shared aliases, and those still win
        # over cert_dir for key/PFX exactly as they do in the role.
        self.assertEqual(role["key_path"], "/etc/dns/tls/dns.key")
        self.assertEqual(role["pfx_path"], "/etc/dns/tls/dns.pfx")
        self.assertEqual(role["pfx_password_file"], "/srv/pki/site-tls/pfx.pass")

    def test_unsupported_role_aliases_fail_closed(self) -> None:
        cases = {
            "micolab_technitium_lock_file": "/wrong/renew.lock",
            "micolab_technitium_state_dir": "/wrong/state",
            "micolab_technitium_state_directory_name": "wrong-state",
            "micolab_technitium_renewal_env_file": "/wrong/renewal.env",
            "micolab_technitium_timer_unit": "wrong.timer",
            "micolab_technitium_cert_dir": "/wrong/tls",
            "micolab_technitium_cert_path": "/wrong/dns.crt",
            "micolab_technitium_pfx_password_file": "/wrong/pfx.pass",
            "micolab_technitium_ca_root_cert": "/wrong/root.crt",
            "micolab_technitium_ca_chain_cert": "/wrong/chain.crt",
        }
        for variable, value in cases.items():
            for kind in ("backup", "restore"):
                with self.subTest(variable=variable, kind=kind):
                    process = self.report_process(kind, {variable: value})
                    self.assertNotEqual(process.returncode, 0, process.stdout)
                    self.assertIn(variable, process.stdout)
                    self.assertIn("canonical microlab_technitium_*", process.stdout)

    def test_enabled_false_cannot_bypass_unconditional_renewal_safeguards(self) -> None:
        cases = [
            ("backup", "micolab_technitium_enabled", False),
            ("restore", "micolab_technitium_enabled", False),
            ("backup", "micolab_backup_renewal_enabled", False),
            ("backup", "micolab_backup_require_renewal_timer", False),
            ("restore", "micolab_restore_renewal_enabled", False),
        ]
        for kind, variable, value in cases:
            with self.subTest(variable=variable, kind=kind):
                process = self.report_process(kind, {variable: value})
                self.assertNotEqual(process.returncode, 0, process.stdout)
                self.assertIn(variable, process.stdout)
                self.assertIn("no supported enabled=false bypass", process.stdout)


class AnsibleHelperWiringTests(unittest.TestCase):
    """Execute the real copy/guard/commit tasks against throwaway roots."""

    ALLOWED = ALLOWED
    REQUIRED_FILES = REQUIRED_FILES
    REQUIRED_DIRS = REQUIRED_DIRS

    @classmethod
    def setUpClass(cls) -> None:
        if find_ansible_playbook() is None:
            raise unittest.SkipTest("ansible-playbook is not installed")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="micolab-wiring-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def populate(self, root: Path, marker: bytes = b"new") -> None:
        files = {
            "var/lib/forgejo/data/forgejo.db": b"sqlite-" + marker,
            "etc/forgejo/app.ini": b"[server]\n" + marker + b"\n",
            "etc/step-ca/config": b"ca-" + marker,
            "etc/step-ca/certs/root_ca.crt": b"root",
            "etc/step-ca/certs/intermediate_ca.crt": b"chain",
            "etc/dns/config": b"dns-" + marker,
            "etc/dns/tls/dns.pfx": b"pfx",
            "etc/dns/tls/dns.crt": b"crt",
            "etc/dns/tls/dns.key": b"key",
            "etc/dns/tls/pfx.pass": b"pass",
            "var/lib/caddy/state": b"caddy-" + marker,
            "etc/technitium-tls/renewal.env": b"API_TOKEN=x\n",
        }
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            os.chmod(path, 0o640)
        for relative in self.REQUIRED_DIRS + [
            "var/lib/forgejo/data",
            "etc/step-ca/certs",
            "etc/dns/tls",
        ]:
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "var/lib/forgejo/data/forgejo-repositories/repo").write_bytes(b"repo")
        (root / "srv").mkdir(parents=True, exist_ok=True)
        (root / "bin").mkdir(parents=True, exist_ok=True)

    def fake_systemctl(self, root: Path, log: Path) -> Path:
        systemctl = root / "bin/systemctl"
        systemctl.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{log}"\n'
            'case "$1" in\n'
            "  is-active) exit 3 ;;\n"
            "esac\n"
            "exit 0\n",
            encoding="utf-8",
        )
        systemctl.chmod(0o755)
        return systemctl

    def run_backup(self, root: Path, helper_dir: Path, systemctl: Path) -> subprocess.CompletedProcess:
        variables = {
            "micolab_backup_helper_dir": str(helper_dir),
            "micolab_backup_helper_owner": pwd.getpwuid(os.getuid()).pw_name,
            "micolab_backup_helper_group": grp.getgrgid(os.getgid()).gr_name,
            "micolab_backup_root_prefix": str(root),
            "micolab_backup_destination": "/srv",
            "micolab_backup_archive_name": "backup.tar.gz",
            "micolab_backup_confirm": True,
            "micolab_backup_services": [],
            "micolab_backup_active_map": {},
            "micolab_backup_systemctl_binary": str(systemctl),
        }
        process = run_local_playbook(
            "playbooks/backup.yml",
            extra=variables,
            tags="micolab-helper-integration",
        )
        self.assertEqual(
            process.returncode,
            0,
            f"backup wiring failed\n{process.stdout}\n{process.stderr}",
        )
        return process

    def test_backup_playbook_installs_and_invokes_actual_helper_names(self) -> None:
        root = self.base / "root"
        helper_dir = self.base / "helpers"
        log = self.base / "systemctl.log"
        self.populate(root)
        systemctl = self.fake_systemctl(root, log)

        self.run_backup(root, helper_dir, systemctl)

        installed = {
            path.name for path in helper_dir.iterdir() if path.is_file()
        }
        self.assertEqual(
            installed,
            {
                "micolab_lock.py",
                "micolab_archive_guard.py",
                "micolab_backup_capture.py",
            },
        )
        archive = root / "srv/backup.tar.gz"
        self.assertTrue(archive.is_file())
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        digest = guard.sha256_file(str(archive))
        self.assertEqual(
            (root / "srv/backup.tar.gz.sha256").read_text().split()[0],
            digest,
        )
        lock = root / "var/lib/technitium-tls/renew.lock"
        self.assertTrue(lock.is_file(), "derived durable renewal lock was not used")
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_guard_and_commit_tasks_execute_installed_paths_and_quarantine_old_state(self) -> None:
        source = self.base / "source"
        helper_dir = self.base / "helpers"
        log = self.base / "systemctl.log"
        self.populate(source, marker=b"new")
        systemctl = self.fake_systemctl(source, log)
        self.run_backup(source, helper_dir, systemctl)
        archive_bytes = (source / "srv/backup.tar.gz").read_bytes()

        target = self.base / "target"
        self.populate(target, marker=b"old")
        target_log = self.base / "target-systemctl.log"
        target_systemctl = self.fake_systemctl(target, target_log)
        staged = target / "srv/restore.tar.gz"
        staged.write_bytes(archive_bytes)
        os.chmod(staged, 0o600)
        digest = guard.sha256_file(str(staged))

        guard_variables = {
            "micolab_restore_archive": str(staged),
            "micolab_restore_checksum": digest,
        }
        guard_process = run_local_playbook(
            "playbooks/restore.yml",
            extra=guard_variables,
            tags="micolab-guard-integration",
        )
        self.assertEqual(
            guard_process.returncode,
            0,
            f"guard wiring failed\n{guard_process.stdout}\n{guard_process.stderr}",
        )
        self.assertIn(
            "TASK [Validate every archive member and link target against the allowlist]",
            guard_process.stdout,
        )

        commit_variables = {
            "micolab_restore_archive": "/srv/restore.tar.gz",
            "micolab_restore_checksum": digest,
            "micolab_restore_root_prefix": str(target),
            "micolab_restore_helper_dir": str(helper_dir),
            "micolab_restore_helper_owner": pwd.getpwuid(os.getuid()).pw_name,
            "micolab_restore_helper_group": grp.getgrgid(os.getgid()).gr_name,
            "micolab_restore_services": ["forgejo", "caddy"],
            "micolab_restore_systemctl_binary": str(target_systemctl),
            "micolab_restore_confirm": "RESTORE-ISOLATED-MICROLAB",
            "micolab_restore_isolated": True,
            "micolab_restore_commit": True,
            "micolab_restore_apply_ownership": False,
        }
        commit_process = run_local_playbook(
            "playbooks/restore.yml",
            extra=commit_variables,
            tags="micolab-helper-integration",
        )
        self.assertEqual(
            commit_process.returncode,
            0,
            f"restore commit wiring failed\n{commit_process.stdout}\n{commit_process.stderr}",
        )
        self.assertIn(
            "TASK [Extract, quarantine, and install approved state under the lock]",
            commit_process.stdout,
        )

        self.assertIn(b"[server]\nnew", (target / "etc/forgejo/app.ini").read_bytes())
        self.assertIn(b"sqlite-new", (target / "var/lib/forgejo/data/forgejo.db").read_bytes())
        quarantine = target / "var/lib/microlab/restore-quarantine"
        old_files = list(quarantine.rglob("app.ini"))
        self.assertTrue(old_files, "old state was not quarantined")
        self.assertIn(b"old", old_files[0].read_bytes())
        lines = target_log.read_text().splitlines()
        self.assertIn("stop forgejo", lines)
        self.assertIn("stop caddy", lines)
        self.assertFalse(any(line.startswith("start ") for line in lines))
        lock = target / "var/lib/technitium-tls/renew.lock"
        self.assertTrue(lock.is_file(), "restore did not hold the derived durable lock")
        installed = {path.name for path in helper_dir.iterdir() if path.is_file()}
        self.assertIn("micolab_restore_commit.py", installed)
        self.assertNotIn("microlab_restore_commit.py", installed)

    def test_guard_task_rejects_an_extra_member_through_the_playbook(self) -> None:
        archive = self.base / "malicious.tar.gz"
        write_tar(
            archive,
            safe_members() + [tar_member("etc/cron.d/payload", content=b"bad")],
        )
        digest = guard.sha256_file(str(archive))
        variables = {
            "micolab_restore_archive": str(archive),
            "micolab_restore_checksum": digest,
            "micolab_restore_include_paths": ALLOWED,
            "micolab_restore_required_files": REQUIRED_FILES,
            "micolab_restore_required_dirs": REQUIRED_DIRS,
        }
        process = run_local_playbook(
            "playbooks/restore.yml",
            extra=variables,
            tags="micolab-guard-integration",
        )
        self.assertNotEqual(process.returncode, 0, process.stdout)
        self.assertIn("outside the restore allowlist", process.stdout)

    def test_unsupported_renewal_override_fails_before_backup_mutation(self) -> None:
        root = self.base / "root"
        helper_dir = self.base / "helpers"
        log = self.base / "systemctl.log"
        self.populate(root)
        systemctl = self.fake_systemctl(root, log)
        variables = {
            "micolab_backup_helper_dir": str(helper_dir),
            "micolab_backup_helper_owner": pwd.getpwuid(os.getuid()).pw_name,
            "micolab_backup_helper_group": grp.getgrgid(os.getgid()).gr_name,
            "micolab_backup_root_prefix": str(root),
            "micolab_backup_destination": "/srv",
            "micolab_backup_archive_name": "backup.tar.gz",
            "micolab_backup_confirm": True,
            "micolab_backup_services": [],
            "micolab_backup_active_map": {},
            "micolab_backup_systemctl_binary": str(systemctl),
            "micolab_technitium_lock_file": "/wrong/renew.lock",
        }
        process = run_local_playbook(
            "playbooks/backup.yml",
            extra=variables,
            tags="micolab-helper-integration",
        )
        self.assertNotEqual(process.returncode, 0, process.stdout)
        self.assertIn("micolab_technitium_lock_file", process.stdout)
        self.assertIn("canonical microlab_technitium_*", process.stdout)
        self.assertFalse(helper_dir.exists(), "helper install ran before the interface refusal")
        self.assertFalse((root / "srv/backup.tar.gz").exists())

    def test_unsupported_renewal_override_fails_before_restore_mutation(self) -> None:
        target = self.base / "target"
        helper_dir = self.base / "restore-helpers"
        log = self.base / "restore-systemctl.log"
        self.populate(target, marker=b"old")
        systemctl = self.fake_systemctl(target, log)
        variables = {
            "micolab_restore_helper_dir": str(helper_dir),
            "micolab_restore_helper_owner": pwd.getpwuid(os.getuid()).pw_name,
            "micolab_restore_helper_group": grp.getgrgid(os.getgid()).gr_name,
            "micolab_restore_services": ["forgejo", "caddy"],
            "micolab_restore_systemctl_binary": str(systemctl),
            "micolab_restore_confirm": "RESTORE-ISOLATED-MICROLAB",
            "micolab_restore_isolated": True,
            "micolab_restore_commit": True,
            "micolab_restore_apply_ownership": False,
            "micolab_restore_renewal_lock_file": "/wrong/renew.lock",
        }
        process = run_local_playbook(
            "playbooks/restore.yml",
            extra=variables,
            tags="micolab-helper-integration",
        )
        self.assertNotEqual(process.returncode, 0, process.stdout)
        self.assertIn("micolab_restore_renewal_lock_file", process.stdout)
        self.assertIn("no supported enabled=false bypass", process.stdout)
        self.assertFalse(helper_dir.exists(), "helper install ran before the interface refusal")
        self.assertFalse(log.exists(), "a service was stopped before the interface refusal")
        self.assertFalse((target / "var/lib/microlab/restore-quarantine").exists())
