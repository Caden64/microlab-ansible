#!/usr/bin/env python3
"""Create one quiesced, validated MicroLab backup archive.

This helper exists so the durable renewal lock is held for the *whole*
critical section: wait for any in-flight Technitium renewal, stop the state
owners, sync, create the archive, validate every member, and write the
checksum sidecar and manifest.  The Ansible playbook restarts only the
services that were active, in an ``always`` block, and independently restores
the renewal timer state.

Archive creation deliberately opens the output with ``O_CREAT|O_EXCL`` and
mode ``0600`` before tar writes a byte, under ``umask 077``.  A failure removes
any archive/sidecar/manifest this process created; it never removes a
pre-existing file.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from typing import Any

import micolab_archive_guard as guard
from micolab_lock import DurableLock, LockTimeout


class BackupError(Exception):
    """The backup could not be completed safely."""


def resolve(root_prefix: str, path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise BackupError(f"path is not absolute: {path!r}")
    if root_prefix == "/":
        return path
    return os.path.join(root_prefix, path.lstrip("/"))


def is_within_actual(path: str, root: str) -> bool:
    real_path = os.path.realpath(path)
    real_root = os.path.realpath(root)
    if real_root == "/":
        return real_path.startswith("/")
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def run_checked(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, check=True, **kwargs)
    except FileNotFoundError as exc:
        raise BackupError(f"required executable not found: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        detail = (stderr or "").strip()
        raise BackupError(
            f"command failed ({exc.returncode}): {' '.join(argv)}"
            + (f": {detail}" if detail else "")
        ) from exc


def write_exclusive(path: str, content: str, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise




def tar_environment() -> dict[str, str]:
    """Return a tar environment without caller-controlled option injection."""

    env = dict(os.environ)
    env.pop("TAR_OPTIONS", None)
    env.pop("POSIXLY_CORRECT", None)
    return env


def create_archive(
    archive: str,
    include_paths: list[str],
    exclude_patterns: list[str],
    tar_binary: str,
    root_prefix: str,
) -> str:
    """Create the archive exclusively and return its SHA-256."""

    parent = os.path.dirname(archive)
    if not os.path.isdir(parent):
        raise BackupError(f"archive destination directory is missing: {parent}")
    if os.path.lexists(archive):
        raise BackupError(f"refusing to overwrite existing archive: {archive}")

    argv = [
        tar_binary,
        "--create",
        "--gzip",
        "--file",
        "-",
        "--numeric-owner",
        "--acls",
        "--xattrs",
    ]
    for pattern in exclude_patterns:
        argv.append(f"--exclude={pattern}")
    argv.extend(["-C", root_prefix, "--"])
    argv.extend(path.lstrip("/") for path in include_paths)

    old_umask = os.umask(0o077)
    fd: int | None = None
    created = False
    try:
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        completed = subprocess.run(
            argv,
            stdout=fd,
            stderr=subprocess.PIPE,
            check=False,
            env=tar_environment(),
        )
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()
            raise BackupError(
                f"tar failed ({completed.returncode})"
                + (f": {detail}" if detail else "")
            )
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        os.close(fd)
        fd = None

        if not os.path.isfile(archive) or os.path.getsize(archive) == 0:
            raise BackupError("tar produced an empty archive")
        os.chmod(archive, 0o600)
        return guard.sha256_file(archive)
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created:
            try:
                os.unlink(archive)
            except OSError:
                pass
        raise
    finally:
        os.umask(old_umask)


def service_is_active(systemctl_binary: str, service: str) -> bool:
    try:
        completed = subprocess.run(
            [systemctl_binary, "is-active", service],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BackupError(f"required executable not found: {systemctl_binary}") from exc
    return completed.stdout.decode("utf-8", "replace").strip() in (
        "active",
        "activating",
        "reloading",
    )


def stop_services(
    services: list[str],
    active_before: dict[str, bool],
    systemctl_binary: str,
) -> list[str]:
    stopped: list[str] = []
    for service in services:
        expected = bool(active_before.get(service, False))
        if service_is_active(systemctl_binary, service) != expected:
            raise BackupError(
                f"service {service} changed state after preflight; refusing to "
                "archive an inconsistent host. Rerun the backup."
            )
        if not expected:
            continue
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
        raise BackupError(
            "services are still active after the stop: " + ", ".join(still_active)
        )
    return stopped


def validate_spec(spec: dict[str, Any]) -> None:
    if not isinstance(spec, dict):
        raise BackupError("specification must be a JSON object")
    archive = spec.get("archive")
    if not isinstance(archive, str) or not archive.startswith("/"):
        raise BackupError("archive must be an absolute path")
    includes = spec.get("include_paths")
    if not isinstance(includes, list) or not includes:
        raise BackupError("include_paths must be a non-empty list")
    for path in includes:
        if not isinstance(path, str) or not path.startswith("/"):
            raise BackupError(f"include path is not absolute: {path!r}")
    if len(set(includes)) != len(includes):
        raise BackupError("include_paths contains duplicates")
    services = spec.get("services")
    if not isinstance(services, list):
        raise BackupError("services must be a list")
    if any(not isinstance(service, str) or not service for service in services):
        raise BackupError("service names must be non-empty strings")
    active = spec.get("active_before")
    if not isinstance(active, dict):
        raise BackupError("active_before must be an object")
    missing = [service for service in services if service not in active]
    if missing:
        raise BackupError(
            "active_before is missing configured services: " + ", ".join(missing)
        )
    lock_file = spec.get("lock_file", "")
    if lock_file and (not isinstance(lock_file, str) or not lock_file.startswith("/")):
        raise BackupError("lock_file must be empty or absolute")
    if lock_file == "/":
        raise BackupError("lock_file must not be /")




def find_forbidden_on_disk(
    includes: list[str],
    actual_includes: list[str],
    forbidden_patterns: list[str],
    exclude_patterns: list[str],
) -> list[str]:
    """Find escrow names that would be archived, before tar writes any bytes."""

    def excluded(logical: str) -> bool:
        relative = logical.lstrip("/")
        return any(
            fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(logical, pattern)
            for pattern in exclude_patterns
        )

    hits: list[str] = []
    for logical_root, actual_root in zip(includes, actual_includes):
        logical_root = "/" + logical_root.strip("/") if logical_root != "/" else "/"
        if guard.forbidden_hits(logical_root.lstrip("/"), forbidden_patterns):
            hits.append(logical_root)
        if os.path.isfile(actual_root) and not os.path.isdir(actual_root):
            candidates = [(logical_root, actual_root)]
        else:
            candidates = []

            def walk_error(exc: OSError) -> None:
                raise BackupError(f"cannot scan {exc.filename or actual_root}: {exc}")

            for directory, dirnames, filenames in os.walk(
                actual_root, followlinks=False, onerror=walk_error
            ):
                relative = os.path.relpath(directory, actual_root)
                base = logical_root.rstrip("/")
                for name in list(dirnames) + list(filenames):
                    logical = (
                        f"{base}/{name}"
                        if relative == "."
                        else f"{base}/{relative.replace(os.sep, '/')}/{name}"
                    )
                    candidates.append((logical, os.path.join(directory, name)))
        for logical, actual in candidates:
            if excluded(logical):
                continue
            if guard.forbidden_hits(logical.lstrip("/"), forbidden_patterns):
                hits.append(logical)
            if os.path.islink(actual):
                try:
                    target = os.readlink(actual)
                except OSError:
                    continue
                target_name = os.path.basename(target.rstrip("/"))
                if guard.forbidden_hits(target_name, forbidden_patterns):
                    hits.append(f"{logical} -> {target}")
    return hits


def capture(spec: dict[str, Any]) -> dict[str, Any]:
    validate_spec(spec)
    root_prefix = spec.get("root_prefix", "/")
    if not isinstance(root_prefix, str) or not root_prefix.startswith("/"):
        raise BackupError("root_prefix must be an absolute path")
    if not os.path.isdir(root_prefix):
        raise BackupError(f"root_prefix is not a directory: {root_prefix}")

    archive_logical = spec["archive"]
    archive = resolve(root_prefix, archive_logical)
    for suffix in (".sha256", ".manifest.json"):
        if os.path.lexists(archive + suffix):
            raise BackupError(
                f"refusing to reuse stale sidecar or manifest: {archive_logical}{suffix}"
            )
    includes = list(spec["include_paths"])
    actual_includes = [resolve(root_prefix, path) for path in includes]
    for logical, actual in zip(includes, actual_includes):
        if not os.path.exists(actual):
            raise BackupError(f"include path is missing: {logical}")
        if not (os.path.isdir(actual) or os.path.isfile(actual)):
            raise BackupError(f"include path is not a regular file or directory: {logical}")
        if is_within_actual(archive, actual):
            raise BackupError(
                f"archive {archive_logical} is inside archived tree {logical}"
            )
    for index, logical in enumerate(includes):
        for other_index, other in enumerate(includes):
            if index >= other_index:
                continue
            if is_within_actual(actual_includes[index], actual_includes[other_index]) or is_within_actual(
                actual_includes[other_index], actual_includes[index]
            ):
                raise BackupError(
                    f"include paths overlap: {logical} and {other}; archive each tree once"
                )

    services = list(spec["services"])
    active_before = {str(key): bool(value) for key, value in spec["active_before"].items()}
    exclude_patterns = list(spec.get("exclude_patterns", []))
    required_members = list(spec.get("required_members", []))
    required_files = list(spec.get("required_files", []))
    required_dirs = list(spec.get("required_dirs", []))
    forbidden_patterns = list(
        spec.get("forbidden_patterns", guard.DEFAULT_FORBIDDEN_PATTERNS)
    )
    tar_binary = spec.get("tar", "tar")
    systemctl_binary = spec.get("systemctl", "systemctl")
    wal_logical = spec.get("wal_path")
    lock_logical = spec.get("lock_file", "")
    lock_timeout = float(spec.get("lock_timeout_seconds", 300))

    created_archive = False
    sidecar_path = archive + ".sha256"
    manifest_path = archive + ".manifest.json"
    created_sidecar = False
    created_manifest = False

    try:
        with DurableLock(
            resolve(root_prefix, lock_logical) if lock_logical else "",
            timeout=lock_timeout,
        ) as lock:
            stopped = stop_services(services, active_before, systemctl_binary)
            escrow_hits = find_forbidden_on_disk(
                includes, actual_includes, forbidden_patterns, exclude_patterns
            )
            if escrow_hits:
                raise BackupError(
                    "offline root escrow material exists in included state; "
                    "refusing to create an archive: "
                    + ", ".join(sorted(set(escrow_hits)))
                )
            run_checked(
                ["sync"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            wal_present = False
            wal_member: str | None = None
            if wal_logical:
                if not isinstance(wal_logical, str) or not wal_logical.startswith("/"):
                    raise BackupError("wal_path must be an absolute path")
                wal_present = os.path.lexists(resolve(root_prefix, wal_logical))
                wal_member = wal_logical.lstrip("/")

            digest = create_archive(
                archive,
                includes,
                exclude_patterns,
                tar_binary,
                root_prefix,
            )
            created_archive = True

            required_files_effective = list(required_files)
            if wal_present and wal_member not in required_files_effective:
                required_files_effective.append(wal_member)

            result = guard.validate_archive(
                archive,
                allowed_roots=includes,
                required_members=required_members,
                required_files=required_files_effective,
                required_dirs=required_dirs,
                forbidden_patterns=forbidden_patterns,
                expected_sha256=digest,
            )
            if not result["ok"]:
                details = list(result["violations"])
                if result["required_missing"]:
                    details.append(
                        "missing required members: "
                        + ", ".join(result["required_missing"])
                    )
                raise BackupError("archive validation failed: " + "; ".join(details))

            manifest = dict(spec.get("manifest") or {})
            manifest.update(
                {
                    "archive": archive_logical,
                    "sha256": digest,
                    "wal_present_after_quiesce": wal_present,
                    "wal_path": wal_logical,
                    "lock_file": lock_logical,
                    "lock_held_seconds": round(lock.held_seconds, 3),
                    "included": includes,
                    "excluded": exclude_patterns,
                    "services_stopped": stopped,
                    "services_not_active": [
                        service for service in services if not active_before.get(service)
                    ],
                    "member_count": result["member_count"],
                }
            )
            created_sidecar = False
            created_manifest = False
            write_exclusive(
                sidecar_path,
                f"{digest}  {os.path.basename(archive)}\n",
            )
            created_sidecar = True
            write_exclusive(
                manifest_path,
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            )
            created_manifest = True

            return {
                "ok": True,
                "archive": archive_logical,
                "sha256": digest,
                "member_count": result["member_count"],
                "wal_present_after_quiesce": wal_present,
                "lock_file": lock_logical,
                "lock_held_seconds": round(lock.held_seconds, 3),
                "services_stopped": stopped,
                "sidecar": archive_logical + ".sha256",
                "manifest": archive_logical + ".manifest.json",
            }
    except Exception:
        if created_archive:
            try:
                os.unlink(archive)
            except OSError:
                pass
        if created_sidecar:
            try:
                os.unlink(sidecar_path)
            except OSError:
                pass
        if created_manifest:
            try:
                os.unlink(manifest_path)
            except OSError:
                pass
        raise


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
        result = capture(spec)
    except (BackupError, LockTimeout, OSError, ValueError, guard.GuardError) as exc:
        print(f"backup capture failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
