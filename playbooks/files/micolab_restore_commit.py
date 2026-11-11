#!/usr/bin/env python3
"""Commit a validated backup to an isolated target while holding the renewal lock.

The helper is deliberately the only process that mutates restored state.  It:

1. re-verifies the archive SHA-256 and every archive member/link target against
   the canonical restore allowlist;
2. takes the same durable ``flock`` used by the Technitium renewal helper and
   keeps it for the whole critical section;
3. stops every configured service and leaves it stopped;
4. extracts the archive into a root-only staging directory using
   ``--numeric-owner --acls --xattrs``;
5. moves existing state to a timestamped quarantine; and
6. installs only the configured allowlisted top-level paths, preserving the
   archived modes, ACLs, xattrs, and numeric ownership.

It never extracts directly to ``/`` and never recursively chmods restored
state.  A caller may normalize ownership separately by name without touching
modes.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from typing import Any

import micolab_archive_guard as guard
from micolab_lock import DurableLock, LockTimeout


class RestoreError(Exception):
    """The restore could not be completed safely."""


def resolve(root_prefix: str, path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise RestoreError(f"path is not absolute: {path!r}")
    if root_prefix == "/":
        return path
    return os.path.join(root_prefix, path.lstrip("/"))


def logical_root(path: str) -> str:
    return guard.canonical_absolute_root(path)


def run_checked(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, check=True, **kwargs)
    except FileNotFoundError as exc:
        raise RestoreError(f"required executable not found: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        detail = (stderr or "").strip()
        raise RestoreError(
            f"command failed ({exc.returncode}): {' '.join(argv)}"
            + (f": {detail}" if detail else "")
        ) from exc


def remove_path(path: str) -> None:
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        os.unlink(path)


def move_path(source: str, destination: str) -> None:
    """Rename, or copy with archive semantics across filesystems."""

    if os.path.lexists(destination):
        raise RestoreError(f"refusing to overwrite {destination}")
    try:
        os.rename(source, destination)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    try:
        run_checked(
            ["cp", "-a", "--", source, destination],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception:
        if os.path.lexists(destination):
            try:
                remove_path(destination)
            except OSError:
                pass
        raise
    remove_path(source)


def make_private_dir(path: str) -> None:
    if os.path.lexists(path):
        raise RestoreError(f"protected work directory already exists: {path}")
    os.makedirs(path, mode=0o700)
    os.chmod(path, 0o700)


def service_is_active(systemctl_binary: str, service: str) -> bool:
    try:
        completed = subprocess.run(
            [systemctl_binary, "is-active", service],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RestoreError(f"required executable not found: {systemctl_binary}") from exc
    return completed.stdout.decode("utf-8", "replace").strip() in (
        "active",
        "activating",
        "reloading",
    )


def stop_services(services: list[str], systemctl_binary: str) -> list[str]:
    stopped: list[str] = []
    for service in services:
        run_checked(
            [systemctl_binary, "stop", service],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stopped.append(service)
    still_active = [
        service for service in services if service_is_active(systemctl_binary, service)
    ]
    if still_active:
        raise RestoreError(
            "services are still active after the stop: " + ", ".join(still_active)
        )
    return stopped




def tar_environment() -> dict[str, str]:
    """Return a tar environment without caller-controlled option injection."""

    env = dict(os.environ)
    env.pop("TAR_OPTIONS", None)
    env.pop("POSIXLY_CORRECT", None)
    return env


def validate_spec(spec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise RestoreError("specification must be a JSON object")
    archive = spec.get("archive")
    if not isinstance(archive, str) or not archive.startswith("/"):
        raise RestoreError("archive must be an absolute path")
    checksum = str(spec.get("checksum", "")).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise RestoreError("checksum must be exactly 64 hexadecimal characters")

    root_prefix = spec.get("root_prefix", "/")
    if not isinstance(root_prefix, str) or not root_prefix.startswith("/"):
        raise RestoreError("root_prefix must be an absolute path")
    if not os.path.isdir(root_prefix):
        raise RestoreError(f"root_prefix is not a directory: {root_prefix}")

    allowed = [logical_root(path) for path in spec.get("allowed_roots", [])]
    install = [
        logical_root(path)
        for path in spec.get("install_paths", spec.get("allowed_roots", []))
    ]
    if not allowed:
        raise RestoreError("allowed_roots must not be empty")
    if any(root == "/" for root in allowed):
        raise RestoreError("the filesystem root is not a restore allowlist entry")
    if len(set(allowed)) != len(allowed):
        raise RestoreError("allowed_roots contains duplicates")
    for index, root in enumerate(allowed):
        for other_index, other in enumerate(allowed):
            if index >= other_index:
                continue
            if guard.is_within(root, other) or guard.is_within(other, root):
                raise RestoreError(
                    f"allowed_roots must not nest: {root} and {other}"
                )
    if sorted(allowed) != sorted(install):
        raise RestoreError(
            "install_paths must exactly match allowed_roots; "
            "the restore allowlist is the install set"
        )
    actual_roots = [os.path.realpath(resolve(root_prefix, root)) for root in allowed]
    if any(root == "/" for root in actual_roots):
        raise RestoreError("a restore allowlist entry resolves to /")
    for index, root in enumerate(actual_roots):
        for other_index, other in enumerate(actual_roots):
            if index >= other_index:
                continue
            if (
                root == other
                or root.startswith(other + os.sep)
                or other.startswith(root + os.sep)
            ):
                raise RestoreError(
                    f"resolved allowlist roots overlap: {allowed[index]} and "
                    f"{allowed[other_index]}"
                )

    for key in ("quarantine_root", "staging_root"):
        value = spec.get(key)
        if not isinstance(value, str) or not value.startswith("/"):
            raise RestoreError(f"{key} must be an absolute path")
        logical_root(value)
    quarantine = logical_root(spec["quarantine_root"])
    staging = logical_root(spec["staging_root"])
    if quarantine == "/" or staging == "/":
        raise RestoreError("quarantine_root and staging_root must not be /")
    if quarantine == staging:
        raise RestoreError("quarantine_root and staging_root must differ")
    if guard.is_within(quarantine, staging) or guard.is_within(staging, quarantine):
        raise RestoreError("quarantine_root and staging_root must not nest")
    archive_root = logical_root(archive)
    if guard.is_within(archive_root, staging) or guard.is_within(archive_root, quarantine):
        raise RestoreError(
            "archive must not be inside the staging or quarantine directory"
        )

    protected = [archive, quarantine, staging]
    lock_file = spec.get("lock_file", "")
    if lock_file:
        if not isinstance(lock_file, str) or not lock_file.startswith("/"):
            raise RestoreError("lock_file must be empty or absolute")
        lock_root = logical_root(lock_file)
        if lock_root == "/":
            raise RestoreError("lock_file must not be /")
        if lock_root == archive_root:
            raise RestoreError("lock_file must not be the archive itself")
        if guard.is_within(lock_root, staging) or guard.is_within(lock_root, quarantine):
            raise RestoreError("lock_file must not be inside quarantine or staging")
        protected.append(lock_root)
    for value in protected:
        for install_root in install:
            if guard.is_within(logical_root(value), install_root):
                raise RestoreError(
                    f"{value} must not be inside restored state {install_root}"
                )

    def actual_within(path: str, root: str) -> bool:
        real_path = os.path.realpath(path)
        real_root = os.path.realpath(root)
        return real_path == real_root or real_path.startswith(real_root + os.sep)

    actual_quarantine = resolve(root_prefix, quarantine)
    actual_staging = resolve(root_prefix, staging)
    actual_archive = resolve(root_prefix, archive)
    actual_lock = resolve(root_prefix, lock_file) if lock_file else ""
    for label, value in (
        ("archive", actual_archive),
        ("quarantine_root", actual_quarantine),
        ("staging_root", actual_staging),
    ):
        for index, install_root in enumerate(install):
            if actual_within(value, resolve(root_prefix, install_root)):
                raise RestoreError(
                    f"{label} resolves inside restored state {allowed[index]}"
                )
    if actual_lock:
        for index, install_root in enumerate(install):
            if actual_within(actual_lock, resolve(root_prefix, install_root)):
                raise RestoreError(
                    f"lock_file resolves inside restored state {allowed[index]}"
                )
    if actual_within(actual_quarantine, actual_staging) or actual_within(
        actual_staging, actual_quarantine
    ):
        raise RestoreError("resolved quarantine and staging roots overlap")
    if actual_within(actual_archive, actual_staging) or actual_within(
        actual_archive, actual_quarantine
    ):
        raise RestoreError("resolved archive is inside staging or quarantine")
    if actual_lock and (
        actual_within(actual_lock, actual_staging)
        or actual_within(actual_lock, actual_quarantine)
    ):
        raise RestoreError("resolved lock_file is inside staging or quarantine")
    if actual_lock and os.path.realpath(actual_lock) == os.path.realpath(actual_archive):
        raise RestoreError("resolved lock_file must not be the archive")

    services = spec.get("services")
    if not isinstance(services, list) or not services:
        raise RestoreError("services must be a non-empty list")
    if any(not isinstance(service, str) or not service for service in services):
        raise RestoreError("service names must be non-empty strings")

    return {
        "archive": archive,
        "checksum": checksum,
        "root_prefix": root_prefix,
        "allowed": allowed,
        "install": install,
        "quarantine": quarantine,
        "staging": staging,
        "services": list(services),
        "lock_file": lock_file,
        "lock_timeout_seconds": float(spec.get("lock_timeout_seconds", 600)),
        "systemctl": spec.get("systemctl", "systemctl"),
        "tar": spec.get("tar", "tar"),
        "required_members": list(spec.get("required_members", [])),
        "required_files": list(spec.get("required_files", [])),
        "required_dirs": list(spec.get("required_dirs", [])),
        "forbidden_patterns": list(
            spec.get("forbidden_patterns", guard.DEFAULT_FORBIDDEN_PATTERNS)
        ),
    }


def allowed_or_structural_parent(logical: str, allowed: list[str]) -> bool:
    if any(guard.is_within(logical, root) for root in allowed):
        return True
    # tar creates implicit parent directories for an allowlisted file such as
    # /etc/forgejo/app.ini.  They are structural only and are never installed
    # as a top-level restore path.
    return any(root.startswith(logical + "/") for root in allowed)


def verify_staging(staging: str, allowed: list[str], forbidden: list[str]) -> None:
    """Defense-in-depth checks after extraction, before installation."""

    real_staging = os.path.realpath(staging)

    def walk_error(exc: OSError) -> None:
        raise RestoreError(f"cannot inspect extracted tree: {exc}")

    for directory, dirnames, filenames in os.walk(
        staging, followlinks=False, onerror=walk_error
    ):
        for name in list(dirnames) + list(filenames):
            actual = os.path.join(directory, name)
            try:
                info = os.lstat(actual)
            except OSError as exc:
                raise RestoreError(f"cannot inspect extracted path {actual}: {exc}") from exc
            if stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
                raise RestoreError(f"extracted special device is not allowed: {actual}")
            if stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode):
                raise RestoreError(f"extracted special file is not allowed: {actual}")

            logical = "/" + os.path.relpath(actual, staging)
            logical = logical.replace(os.sep, "/")
            if not allowed_or_structural_parent(logical, allowed):
                raise RestoreError(f"extracted path is outside the allowlist: {logical}")
            if (
                not any(guard.is_within(logical, root) for root in allowed)
                and not os.path.isdir(actual)
            ):
                raise RestoreError(
                    f"structural parent is not a directory in the archive: {logical}"
                )

            if os.path.islink(actual):
                target_text = os.readlink(actual)
                if target_text.startswith("/"):
                    target = os.path.normpath(target_text).replace(os.sep, "/")
                else:
                    target = os.path.normpath(
                        os.path.join(os.path.dirname(logical), target_text)
                    ).replace(os.sep, "/")
                if not any(guard.is_within(target, root) for root in allowed):
                    raise RestoreError(
                        f"extracted symlink target escapes the allowlist: "
                        f"{logical} -> {target}"
                    )
                if guard.forbidden_hits(target.lstrip("/"), forbidden):
                    raise RestoreError(
                        f"extracted symlink target is forbidden material: "
                        f"{logical} -> {target}"
                    )
            else:
                real_actual = os.path.realpath(actual)
                if not (
                    real_actual == real_staging
                    or real_actual.startswith(real_staging + os.sep)
                ):
                    raise RestoreError(
                        f"extracted path escapes the staging directory: {logical}"
                    )


def rollback_quarantine(moved: list[tuple[str, str]]) -> None:
    for original, quarantined in reversed(moved):
        if os.path.lexists(quarantined) and not os.path.lexists(original):
            try:
                os.makedirs(os.path.dirname(original), exist_ok=True)
                move_path(quarantined, original)
            except (OSError, RestoreError):
                pass


def rollback_installed(installed: list[tuple[str, str]], staging: str) -> None:
    for target, source in reversed(installed):
        if not os.path.lexists(target):
            continue
        try:
            os.makedirs(os.path.dirname(source), exist_ok=True)
            if not os.path.lexists(source):
                move_path(target, source)
        except (OSError, RestoreError):
            pass


def restore(spec: dict[str, Any]) -> dict[str, Any]:
    parsed = validate_spec(spec)
    root_prefix = parsed["root_prefix"]
    archive = resolve(root_prefix, parsed["archive"])
    if os.path.islink(archive):
        raise RestoreError(f"archive must not be a symlink: {parsed['archive']}")
    if not os.path.isfile(archive):
        raise RestoreError(f"archive is not a regular file: {parsed['archive']}")
    if os.stat(archive).st_mode & 0o007:
        raise RestoreError(
            f"archive is world-accessible; chmod 0600 or stricter: {parsed['archive']}"
        )

    # Validate fully before stopping services or moving any state.
    result = guard.validate_archive(
        archive,
        allowed_roots=parsed["allowed"],
        required_members=parsed["required_members"],
        required_files=parsed["required_files"],
        required_dirs=parsed["required_dirs"],
        forbidden_patterns=parsed["forbidden_patterns"],
        expected_sha256=parsed["checksum"],
    )
    if not result["ok"]:
        details = list(result["violations"])
        if result["required_missing"]:
            details.append(
                "missing required members: " + ", ".join(result["required_missing"])
            )
        raise RestoreError("archive validation failed: " + "; ".join(details))

    quarantine = resolve(root_prefix, parsed["quarantine"])
    staging = resolve(root_prefix, parsed["staging"])
    lock_path = (
        resolve(root_prefix, parsed["lock_file"]) if parsed["lock_file"] else ""
    )
    if os.path.lexists(quarantine):
        raise RestoreError(f"quarantine path already exists: {parsed['quarantine']}")
    if os.path.lexists(staging):
        raise RestoreError(f"staging path already exists: {parsed['staging']}")

    moved: list[tuple[str, str]] = []
    installed: list[tuple[str, str]] = []
    installed_paths: list[str] = []
    staging_created = False
    try:
        with DurableLock(
            lock_path,
            timeout=parsed["lock_timeout_seconds"],
        ) as lock:
            try:
                stopped = stop_services(parsed["services"], parsed["systemctl"])

                old_umask = os.umask(0o077)
                try:
                    make_private_dir(quarantine)
                    make_private_dir(staging)
                    staging_created = True
                    run_checked(
                        [
                            parsed["tar"],
                            "-x",
                            "-p",
                            "-z",
                            "-f",
                            archive,
                            "-C",
                            staging,
                            "--numeric-owner",
                            "--acls",
                            "--xattrs",
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=tar_environment(),
                    )
                finally:
                    os.umask(old_umask)
                os.chmod(staging, 0o700)

                verify_staging(staging, parsed["allowed"], parsed["forbidden_patterns"])

                old_umask = os.umask(0o077)
                try:
                    for logical in parsed["install"]:
                        original = resolve(root_prefix, logical)
                        if not os.path.lexists(original):
                            continue
                        quarantined = os.path.join(quarantine, logical.lstrip("/"))
                        os.makedirs(
                            os.path.dirname(quarantined), exist_ok=True, mode=0o700
                        )
                        os.chmod(os.path.dirname(quarantined), 0o700)
                        move_path(original, quarantined)
                        moved.append((original, quarantined))
                finally:
                    os.umask(old_umask)

                for logical in parsed["install"]:
                    source = os.path.join(staging, logical.lstrip("/"))
                    if not os.path.lexists(source):
                        continue
                    target = resolve(root_prefix, logical)
                    os.makedirs(
                        os.path.dirname(target),
                        exist_ok=True,
                        mode=0o755,
                    )
                    if os.path.lexists(target):
                        raise RestoreError(
                            f"restored target still exists after quarantine: {logical}"
                        )
                    move_path(source, target)
                    installed.append((target, source))
                    installed_paths.append(logical)

                run_checked(["sync"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                shutil.rmtree(staging)
                staging_created = False

                return {
                    "ok": True,
                    "quarantine": parsed["quarantine"],
                    "installed": installed_paths,
                    "staging_removed": parsed["staging"],
                    "services_stopped": stopped,
                    "lock_file": parsed["lock_file"],
                    "lock_held_seconds": round(lock.held_seconds, 3),
                    "member_count": result["member_count"],
                }
            except Exception:
                # Rollback is part of the critical section: keep the renewal
                # lock until the previous state is back in place.
                rollback_installed(installed, staging)
                rollback_quarantine(moved)
                if staging_created and os.path.isdir(staging):
                    try:
                        os.chmod(staging, 0o700)
                    except OSError:
                        pass
                raise
    except LockTimeout as exc:
        raise RestoreError(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--spec-file",
        default="-",
        help="JSON specification file, or - for stdin",
    )
    args = parser.parse_args(argv)
    try:
        if args.spec_file == "-":
            spec = json.load(sys.stdin)
        else:
            with open(args.spec_file, "r", encoding="utf-8") as handle:
                spec = json.load(handle)
        result = restore(spec)
    except (RestoreError, LockTimeout, OSError, ValueError, guard.GuardError) as exc:
        print(f"restore commit failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
